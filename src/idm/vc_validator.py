"""VC验证器模块.

提供可验证凭证(VC)的验证服务，包括签名验证、有效期检查等。
"""

import base64
import hashlib
import json
from datetime import datetime
from typing import List, Tuple, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

from .config import config
from .crypto import crypto_manager
from .logger import get_logger
from .models import VC, VCValidationResult
from .cert_manager import CertificateManager

logger = get_logger(__name__)


class VCValidator:
    """VC验证器.
    
    验证VC证书的有效性，包括：
    1. 签名验证
    2. 颁发者DID是否存在
    3. 有效期检查
    4. 字段完整性
    5. 格式校验
    """
    
    REQUIRED_FIELDS = ["context", "id", "type", "issuer", "valid_from", "valid_until", "claims", "proof"]
    REQUIRED_PROOF_FIELDS = ["creator", "signature_value"]
    
    KNOWN_EXTERNAL_ISSUERS = tuple(CertificateManager.ISSUER_CERT_RULES.keys())

    @staticmethod
    def _summarize_signature_input(message: str) -> dict:
        """构造验签原文摘要，便于和签发端对比."""
        return crypto_manager.summarize_vc_signing_message(message)

    @staticmethod
    def _public_key_fingerprint(public_key: object) -> str:
        """计算公钥指纹，便于定位证书/密钥是否配套."""
        try:
            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            return hashlib.sha256(public_key_bytes).hexdigest()
        except Exception as exc:
            return f"unavailable:{exc}"

    @classmethod
    def _build_signature_candidates(cls, vc_payload: dict, external_issuer: bool) -> List[Tuple[str, str]]:
        """生成候选验签原文.

        外部机构优先尝试 IDM 规则，再兼容第三方通用规则。
        """
        candidates = [
            ("idm_default_noascii", crypto_manager.build_vc_signing_message(vc_payload, ensure_ascii=False))
        ]
        if external_issuer:
            candidates.append(
                ("external_ascii_compact", crypto_manager.build_external_vc_signing_message(vc_payload))
            )
        return candidates
    
    @classmethod
    def validate_vc(cls, vc: VC, check_issuer_exists: bool = True) -> VCValidationResult:
        """验证单个VC.
        
        Args:
            vc: VC对象
            check_issuer_exists: 是否检查颁发者存在
            
        Returns:
            验证结果
        """
        errors = []
        
        logger.info(f"Validating VC: {vc.id}")
        
        # 1. 字段存在性检查
        field_errors = cls._check_required_fields(vc)
        errors.extend(field_errors)
        
        # 2. 格式校验
        format_errors = cls._check_format(vc)
        errors.extend(format_errors)
        
        # 3. 有效期检查
        validity_errors = cls._check_validity_period(vc)
        errors.extend(validity_errors)
        
        # 4. 颁发者DID存在性检查
        if check_issuer_exists:
            issuer_errors = cls._check_issuer_exists(vc)
            errors.extend(issuer_errors)
        
        # 5. 签名验证（如果前面的检查都通过）
        if not errors:
            signature_errors = cls._verify_signature(vc)
            errors.extend(signature_errors)
        
        is_valid = len(errors) == 0
        
        if is_valid:
            logger.info(f"VC validation passed: {vc.id}")
        else:
            logger.warning(f"VC validation failed: {vc.id}, errors: {errors}")
        
        return VCValidationResult(
            vc_id=vc.id,
            valid=is_valid,
            errors=errors
        )
    
    @classmethod
    def _check_required_fields(cls, vc: VC) -> List[str]:
        """检查必需字段是否存在."""
        errors = []
        
        # 检查主字段
        for field in cls.REQUIRED_FIELDS:
            value = getattr(vc, field, None)
            if value is None or (isinstance(value, list) and len(value) == 0):
                errors.append(f"Missing required field: {field}")
        
        # 检查proof字段
        if vc.proof:
            for field in cls.REQUIRED_PROOF_FIELDS:
                value = getattr(vc.proof, field, None)
                if not value:
                    errors.append(f"Missing required proof field: {field}")
        
        return errors
    
    @classmethod
    def _check_format(cls, vc: VC) -> List[str]:
        """检查格式正确性."""
        errors = []
        
        # 检查context是否为列表
        if not isinstance(vc.context, list):
            errors.append("Field 'context' must be a list")
        
        # 检查type是否为列表
        if not isinstance(vc.type, list):
            errors.append("Field 'type' must be a list")
        
        # 检查issuer格式（应该是DID格式）
        if not vc.issuer.startswith("did:"):
            errors.append(f"Invalid issuer format: {vc.issuer}, must start with 'did:'")
        
        # 检查时间格式
        try:
            datetime.fromisoformat(vc.valid_from.replace("Z", "+00:00"))
        except ValueError:
            errors.append(f"Invalid valid_from format: {vc.valid_from}")
        
        try:
            datetime.fromisoformat(vc.valid_until.replace("Z", "+00:00"))
        except ValueError:
            errors.append(f"Invalid valid_until format: {vc.valid_until}")
        
        return errors
    
    @classmethod
    def _check_validity_period(cls, vc: VC) -> List[str]:
        """检查有效期."""
        errors = []
        
        try:
            from datetime import timezone
            now = datetime.now(timezone.utc)
            valid_from = datetime.fromisoformat(vc.valid_from.replace("Z", "+00:00"))
            valid_until = datetime.fromisoformat(vc.valid_until.replace("Z", "+00:00"))
            
            # 检查是否已生效
            if now < valid_from:
                errors.append(f"VC not yet valid: valid_from={vc.valid_from}")
            
            # 检查是否已过期
            if now > valid_until:
                errors.append(f"VC expired: valid_until={vc.valid_until}")
            
            # 检查有效期是否合理（valid_until > valid_from）
            if valid_until <= valid_from:
                errors.append("valid_until must be later than valid_from")
                
        except Exception as e:
            errors.append(f"Error checking validity period: {e}")
        
        return errors
    
    @classmethod
    def _check_issuer_exists(cls, vc: VC) -> List[str]:
        """检查颁发者DID是否存在."""
        errors = []
        
        # 检查是否是IDM颁发的
        if vc.issuer == config.IDM_DID:
            return errors
        
        # 检查是否是已知的外部颁发者（在证书映射中）
        for issuer_prefix in cls.KNOWN_EXTERNAL_ISSUERS:
            if vc.issuer.startswith(issuer_prefix):
                # 外部颁发者，不检查profile，由签名验证保证
                return errors
        
        # 对于其他颁发者，检查是否是已知的Agent Profile
        from .profile_manager import ProfileManager
        profile = ProfileManager.load_profile(vc.issuer)
        if profile is None:
            errors.append(f"Issuer does not exist: {vc.issuer}")
        
        return errors
    
    @classmethod
    def _load_issuer_public_key(cls, issuer_did: str) -> Optional[object]:
        """根据 issuer DID 从证书文件加载颁发者的公钥.
        
        Args:
            issuer_did: 颁发者DID
            
        Returns:
            公钥对象或None
        """
        try:
            cert_path = CertificateManager.get_certificate_path_for_issuer(issuer_did)
            if cert_path is None:
                logger.warning(f"No certificate mapping found for issuer: {issuer_did}")
                return None

            # 加载证书
            with open(cert_path, "rb") as f:
                cert_bytes = f.read()
                logger.info(
                    f"Loading issuer certificate bytes: issuer={issuer_did}, path={cert_path}, bytes={len(cert_bytes)}"
                )
                cert = x509.load_pem_x509_certificate(cert_bytes)
            cert_fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            logger.info(
                "Loaded issuer certificate metadata: "
                f"issuer={issuer_did}, subject={cert.subject.rfc4514_string()}, "
                f"serial={cert.serial_number}, cert_sha256={cert_fingerprint}"
            )
            
            public_key = cert.public_key()
            logger.info(
                "Loaded public key for issuer "
                f"{issuer_did} from {cert_path.name}, public_key_sha256={cls._public_key_fingerprint(public_key)}"
            )
            return public_key
            
        except Exception as e:
            logger.error(f"Failed to load public key for issuer {issuer_did}: {e}")
            return None
    
    @classmethod
    def _verify_signature(cls, vc: VC) -> List[str]:
        """验证VC签名."""
        errors = []
        
        try:
            vc_to_verify = crypto_manager.build_vc_signing_payload(
                {
                    "context": vc.context,
                    "id": vc.id,
                    "type": vc.type,
                    "issuer": vc.issuer,
                    "valid_from": vc.valid_from,
                    "valid_until": vc.valid_until,
                    "claims": vc.claims,
                }
            )
            
            # 获取签名
            signature_b64 = vc.proof.signature_value
            signature_bytes = base64.b64decode(signature_b64)
            logger.info(
                "Decoded VC signature: "
                f"vc_id={vc.id}, b64_length={len(signature_b64)}, bytes={len(signature_bytes)}, "
                f"signature_sha256={hashlib.sha256(signature_bytes).hexdigest()}"
            )
            
            # 获取签名者的公钥
            external_issuer = not vc.proof.creator.startswith(config.IDM_DID)
            if not external_issuer:
                # IDM 生成的 VC0/VC 使用 IDM 公钥验签
                logger.info(f"Using IDM public key for VC: {vc.id}")
                public_key = crypto_manager._public_key
                logger.info(
                    "IDM public key selected for verification: "
                    f"vc_id={vc.id}, public_key_sha256={cls._public_key_fingerprint(public_key)}"
                )
            else:
                # 从证书加载外部颁发者的公钥
                logger.info(f"Loading public key for external issuer: {vc.issuer}")
                public_key = cls._load_issuer_public_key(vc.issuer)
                if public_key is None:
                    errors.append(f"Could not load public key for issuer: {vc.issuer}")
                    return errors
                logger.info(
                    "External issuer public key resolved successfully: "
                    f"vc_id={vc.id}, issuer={vc.issuer}, public_key_sha256={cls._public_key_fingerprint(public_key)}"
                )

            candidates = cls._build_signature_candidates(vc_to_verify, external_issuer=external_issuer)
            logger.info(
                "Prepared VC verification payload: "
                f"vc_id={vc.id}, issuer={vc.issuer}, creator={vc.proof.creator}, "
                f"claims_keys={sorted(vc.claims.keys()) if isinstance(vc.claims, dict) else 'n/a'}, "
                f"candidate_count={len(candidates)}"
            )

            matched_strategy = None
            last_summary = None
            for strategy_name, message in candidates:
                message_summary = cls._summarize_signature_input(message)
                last_summary = message_summary
                logger.info(
                    "VC verification signing input summary: "
                    f"vc_id={vc.id}, strategy={strategy_name}, length={message_summary['length']}, "
                    f"sha256={message_summary['sha256']}, preview={message_summary['preview']!r}, "
                    f"tail={message_summary['tail']!r}"
                )
                try:
                    public_key.verify(
                        signature_bytes,
                        message.encode("utf-8"),
                        ec.ECDSA(hashes.SHA256())
                    )
                    matched_strategy = strategy_name
                    break
                except InvalidSignature:
                    logger.info(
                        "Signature candidate did not match: "
                        f"vc_id={vc.id}, strategy={strategy_name}, sha256={message_summary['sha256']}"
                    )

            if matched_strategy:
                logger.info(
                    f"Signature verified successfully for VC: {vc.id}, strategy={matched_strategy}"
                )
            else:
                logger.error(
                    "Signature verification failed for VC: "
                    f"id={vc.id}, issuer={vc.issuer}, creator={vc.proof.creator}, "
                    f"signing_input_sha256={last_summary['sha256'] if last_summary else 'n/a'}, "
                    f"public_key_sha256={cls._public_key_fingerprint(public_key)}, "
                    f"signature_sha256={hashlib.sha256(signature_bytes).hexdigest()}, "
                    f"tried_strategies={[name for name, _ in candidates]}"
                )
                errors.append("Invalid signature")
            
        except Exception as e:
            logger.error(f"Unexpected VC signature verification error for VC {vc.id}: {e}")
            errors.append(f"Signature verification error: {e}")
        
        return errors
    
    @classmethod
    def validate_vcs(cls, vcs: List[VC], agent_id: str) -> Tuple[List[str], List[VCValidationResult]]:
        """批量验证VC.
        
        Args:
            vcs: VC列表
            agent_id: Agent DID
            
        Returns:
            (通过的VC ID列表, 所有VC的验证结果列表)
        """
        logger.info(f"Batch validating {len(vcs)} VCs for agent: {agent_id}")
        
        valid_vc_ids = []
        results = []
        
        for vc in vcs:
            result = cls.validate_vc(vc)
            results.append(result)
            
            if result.valid:
                valid_vc_ids.append(vc.id)
        
        logger.info(f"Batch validation completed: {len(valid_vc_ids)}/{len(vcs)} VCs passed")
        
        return valid_vc_ids, results
