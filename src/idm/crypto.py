"""加密和签名工具模块.

提供签名验证、密钥管理等功能。
"""

import base64
import hashlib
import json
from typing import Optional, Tuple
from datetime import datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes
from cryptography.exceptions import InvalidSignature

from .config import config
from .logger import get_logger

logger = get_logger(__name__)


class CryptoManager:
    """加密管理器.
    
    管理密钥对生成、签名验证等加密操作。
    """
    
    def __init__(self):
        """初始化加密管理器."""
        self._private_key: Optional[PrivateKeyTypes] = None
        self._public_key: Optional[PublicKeyTypes] = None
        self._load_or_create_keys()
        
    def _load_or_create_keys(self) -> None:
        """加载或创建IDM密钥对."""
        config.ensure_directories()
        
        if config.IDM_KEY_PATH.exists() and config.IDM_PUBLIC_KEY_PATH.exists():
            # 加载已有密钥
            logger.info("Loading existing IDM keys...")
            with open(config.IDM_KEY_PATH, "rb") as f:
                self._private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None
                )
            with open(config.IDM_PUBLIC_KEY_PATH, "rb") as f:
                self._public_key = serialization.load_pem_public_key(f.read())
            logger.info("IDM keys loaded successfully")
        else:
            # 生成新密钥对
            logger.info("Generating new IDM key pair...")
            self._generate_key_pair()
            
    def _generate_key_pair(self) -> None:
        """生成RSA密钥对."""
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self._public_key = self._private_key.public_key()
        
        # 保存私钥
        private_pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(config.IDM_KEY_PATH, "wb") as f:
            f.write(private_pem)
            
        # 保存公钥
        public_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(config.IDM_PUBLIC_KEY_PATH, "wb") as f:
            f.write(public_pem)
            
        logger.info(f"IDM key pair saved to {config.CERTS_DIR}")
        
    @property
    def idm_did(self) -> str:
        """获取IDM的DID标识."""
        return config.IDM_DID
        
    @property
    def idm_key_id(self) -> str:
        """获取IDM的密钥ID."""
        return f"{config.IDM_DID}#keys-1"
        
    def load_agent_public_key(self, pem_str: str) -> PublicKeyTypes:
        """从PEM字符串加载Agent公钥.
        
        Args:
            pem_str: PEM格式的公钥字符串
            
        Returns:
            RSA公钥对象
        """
        try:
            public_key = serialization.load_pem_public_key(pem_str.encode())
            return public_key
        except Exception as e:
            logger.error(f"Failed to load agent public key: {e}")
            raise ValueError(f"Invalid public key format: {e}")
            
    def verify_signature(
        self, 
        public_key: RSAPublicKey, 
        message: str, 
        signature: str,
        encoding: str = "base64"
    ) -> bool:
        """验证签名.
        
        Args:
            public_key: Agent公钥
            message: 原始消息
            signature: 签名值
            encoding: 签名编码格式
            
        Returns:
            签名是否有效
        """
        try:
            # 解码签名
            if encoding == "base64":
                signature_bytes = base64.b64decode(signature)
            else:
                signature_bytes = signature.encode()
                
            # 验证签名
            public_key.verify(
                signature_bytes,
                message.encode(),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            logger.info("Signature verified successfully")
            return True
        except InvalidSignature:
            logger.error("Signature verification failed: Invalid signature")
            return False
        except Exception as e:
            logger.error(f"Signature verification error: {e}")
            return False
            
    def sign_data(self, data: str) -> str:
        """使用IDM私钥签名数据.
        
        Args:
            data: 待签名数据
            
        Returns:
            Base64编码的签名值
        """
        if self._private_key is None:
            raise RuntimeError("Private key not initialized")
            
        try:
            # 使用类型断言确保是RSA私钥
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
            if not isinstance(self._private_key, RSAPrivateKey):
                raise TypeError("Private key is not an RSA key")
                
            signature = self._private_key.sign(
                data.encode(),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return base64.b64encode(signature).decode()
        except Exception as e:
            logger.error(f"Signing failed: {e}")
            raise
            
    def sign_vc(self, vc_dict: dict) -> str:
        """签名VC证书.
        
        对VC的声明部分进行签名。
        
        Args:
            vc_dict: VC字典
            
        Returns:
            Base64编码的签名值
        """
        # 构造待签名字符串（排除proof部分）
        vc_to_sign = {
            "context": vc_dict["context"],
            "id": vc_dict["id"],
            "type": vc_dict["type"],
            "issuer": vc_dict["issuer"],
            "valid_from": vc_dict["valid_from"],
            "valid_until": vc_dict["valid_until"],
            "claims": vc_dict["claims"]
        }
        
        # 使用JSON字符串作为签名内容
        message = json.dumps(vc_to_sign, sort_keys=True, ensure_ascii=False)
        signature = self.sign_data(message)
        logger.info(f"VC signed: id={vc_dict['id']}")
        return signature


# 全局加密管理器实例
crypto_manager = CryptoManager()
