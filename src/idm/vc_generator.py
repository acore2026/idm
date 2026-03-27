"""VC0证书生成器模块.

提供可验证凭证(VC)的生成服务。
"""

import uuid
from datetime import datetime, timedelta
from typing import Optional

from .config import config
from .crypto import crypto_manager
from .logger import get_logger
from .models import VC0, VC0Claims, VC0Proof

logger = get_logger(__name__)


class VCGenerator:
    """VC0证书生成器.
    
    生成绑定Agent与主UE关系的VC0证书。
    """
    
    @classmethod
    def generate_vc0(
        cls,
        agent_name: str,
        agent_id: str,
        master_id: str,
        self_id: str,
        valid_years: int = 1
    ) -> VC0:
        """生成VC0证书.
        
        Args:
            agent_name: Agent名称
            agent_id: Agent DID
            master_id: 主UE身份标识
            self_id: Agent SIM卡标识
            valid_years: 有效期（年）
            
        Returns:
            VC0证书对象
        """
        now = datetime.utcnow()
        valid_from = now
        valid_until = now + timedelta(days=365 * valid_years)
        
        # 生成VC ID
        vc_id = f"CMCC/credentials/{uuid.uuid4().hex[:8].upper()}"
        
        # 构造VC内容（不包含签名）
        vc_data = {
            "context": config.VC_CONTEXT,
            "id": vc_id,
            "type": ["VerifiableCredential", config.VC_ISSUER_TYPE],
            "issuer": config.IDM_DID,
            "valid_from": valid_from.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "valid_until": valid_until.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "claims": {
                "agent_name": agent_name,
                "agent_id": agent_id,
                "agent_attribute": "运营商颁发，Agent与主UE的绑定关系，用于对外出示，审计确权",
                "master_id": master_id,
                "self_id": self_id
            }
        }
        
        # 使用IDM私钥签名
        signature = crypto_manager.sign_vc(vc_data)
        
        # 构造VC0对象
        vc0 = VC0(
            context=vc_data["context"],
            id=vc_data["id"],
            type=vc_data["type"],
            issuer=vc_data["issuer"],
            valid_from=vc_data["valid_from"],
            valid_until=vc_data["valid_until"],
            claims=VC0Claims(
                agent_name=agent_name,
                agent_id=agent_id,
                master_id=master_id,
                self_id=self_id
            ),
            proof=VC0Proof(
                creator=crypto_manager.idm_key_id,
                signature_value=signature
            )
        )
        
        logger.info(f"Generated VC0: id={vc_id}")
        logger.info(f"  - Agent: {agent_name}")
        logger.info(f"  - Valid from: {vc0.valid_from}")
        logger.info(f"  - Valid until: {vc0.valid_until}")
        
        return vc0
        
    @classmethod
    def generate_master_id(cls, rid: str = "678") -> str:
        """生成主UE身份标识.
        
        Args:
            rid: 区域ID
            
        Returns:
            主UE身份标识
        """
        # 格式: type0.rid<rid>.schid0.userid1userid20001@6gc0001@6gc.mnc015.mcc234.3gppnetwork.org
        return f"type0.rid{rid}.schid0.userid1userid20001@6gc0001@6gc.mnc015.mcc234.3gppnetwork.org"
        
    @classmethod
    def generate_self_id(cls, rid: str = "678") -> str:
        """生成Agent SIM卡标识.
        
        Args:
            rid: 区域ID
            
        Returns:
            Agent SIM卡标识
        """
        # 格式: type0.rid<rid>.schid0..mnc015.mcc234.3gppnetwork.org
        return f"type0.rid{rid}.schid0..mnc015.mcc234.3gppnetwork.org"


# 便捷函数
def generate_vc0(
    agent_name: str,
    agent_id: str,
    master_id: str,
    self_id: str,
    valid_years: int = 1
) -> VC0:
    """生成VC0证书的便捷函数.
    
    Args:
        agent_name: Agent名称
        agent_id: Agent DID
        master_id: 主UE身份标识
        self_id: Agent SIM卡标识
        valid_years: 有效期（年）
        
    Returns:
        VC0证书
    """
    return VCGenerator.generate_vc0(agent_name, agent_id, master_id, self_id, valid_years)
