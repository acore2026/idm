"""Agent ID生成器模块.

提供唯一的Agent DID生成服务。
"""

import base64
import hashlib
import time
from typing import Optional

from .config import config
from .logger import get_logger

logger = get_logger(__name__)


class AgentIDGenerator:
    """Agent ID生成器.
    
    根据公钥和时间戳生成唯一的Agent DID。
    """
    
    @classmethod
    def generate(cls, public_key: str, timestamp: int) -> str:
        """生成Agent DID.
        
        使用公钥加盐（时间戳）后哈希，确保同一公钥在不同时间
        生成的ID也不同。
        
        Args:
            public_key: Agent公钥(PEM格式)
            timestamp: 申请时间戳
            
        Returns:
            Agent DID，格式为 did:acn:<hash>
            hash长度控制在10位以内
        """
        # 构造待哈希字符串: 公钥 + 时间戳盐值
        salted_key = f"{public_key}:{timestamp}"
        
        # SHA256哈希
        hash_obj = hashlib.sha256(salted_key.encode())
        hash_bytes = hash_obj.digest()
        
        # Base64编码并截取前10位
        # 使用URL安全的base64编码
        hash_b64 = base64.urlsafe_b64encode(hash_bytes).decode()
        short_hash = hash_b64[:config.AGENT_ID_HASH_LENGTH]
        
        # 构造DID
        agent_did = f"{config.AGENT_ID_PREFIX}:{short_hash}"
        
        logger.info(f"Generated Agent ID: {agent_did}")
        logger.info(f"  - Input timestamp: {timestamp}")
        logger.info(f"  - Hash length: {len(short_hash)}")
        
        return agent_did
        
    @classmethod
    def generate_udid_format(
        cls,
        agent_name: str,
        rid: str = "678",
        schid: str = "0",
        user_id: str = "30001"
    ) -> str:
        """生成UDID格式的Agent ID.
        
        用于VC中的agent_id字段。
        
        Args:
            agent_name: Agent名称
            rid: 区域ID
            schid: 子信道ID
            user_id: 用户ID
            
        Returns:
            UDID格式的Agent ID
        """
        # 格式: did:udid:NewType.rid<rid>.schid<schid>.userid<user_id>@6gc.mnc015.mcc234.3gppnetwork
        udid = f"did:udid:NewType.rid{rid}.schid{schid}.userid{user_id}@6gc.mnc015.mcc234.3gppnetwork"
        return udid


# 便捷函数
def generate_agent_id(public_key: str, timestamp: int) -> str:
    """生成Agent DID的便捷函数.
    
    Args:
        public_key: Agent公钥
        timestamp: 时间戳
        
    Returns:
        Agent DID
    """
    return AgentIDGenerator.generate(public_key, timestamp)
