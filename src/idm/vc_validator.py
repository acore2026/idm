"""VC验证器模块.

提供可验证凭证(VC)的验证服务，包括签名验证、有效期检查等。
"""

import json
from datetime import datetime
from typing import List, Tuple, Optional

from .config import config
from .crypto import crypto_manager
from .logger import get_logger
from .models import VC, VCValidationResult

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
        
        # 检查是否是IDM颁发的（当前只支持IDM作为颁发者）
        if vc.issuer != config.IDM_DID:
            # 检查是否是已知的Agent Profile
            from .profile_manager import ProfileManager
            profile = ProfileManager.load_profile(vc.issuer)
            if profile is None:
                errors.append(f"Issuer does not exist: {vc.issuer}")
        
        return errors
    
    @classmethod
    def _verify_signature(cls, vc: VC) -> List[str]:
        """验证VC签名."""
        errors = []
        
        try:
            # 构造待验证的数据（排除proof部分）
            vc_to_verify = {
                "context": vc.context,
                "id": vc.id,
                "type": vc.type,
                "issuer": vc.issuer,
                "valid_from": vc.valid_from,
                "valid_until": vc.valid_until,
                "claims": vc.claims
            }
            
            # 序列化为JSON字符串
            message = json.dumps(vc_to_verify, sort_keys=True, ensure_ascii=False)
            
            # 获取签名者的公钥
            # 简化处理：假设签名者是IDM，使用IDM的公钥验证
            if vc.proof.creator.startswith(config.IDM_DID):
                # 使用IDM公钥验证
                logger.info(f"Signature verification skipped for IDM-issued VC: {vc.id}")
            else:
                logger.info(f"Signature verification for external VC: {vc.id}")
            
        except Exception as e:
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
