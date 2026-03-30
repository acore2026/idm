"""Agent ID生成器模块.

提供唯一的Agent DID生成服务。
"""

import base64
import hashlib
import random
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
    def generate(cls, owner: str) -> str:
        """生成Agent DID (UDID格式).
        
        生成UDID格式的Agent ID: did:udid:type2.rid<rid>.achid<achid>.uerid<电话号码+5位随机数>@6gc.mnc015.mcc234.3gppnetwork.org
        
        Args:
            owner: 用户电话号码
            
        Returns:
            Agent DID，UDID格式
        """
        return cls.generate_udid_format(agent_name="", owner=owner)
        
    @classmethod
    def generate_udid_format(
        cls,
        agent_name: str,
        owner: str,
        rid: str = "678",
        achid: str = "0"
    ) -> str:
        """生成UDID格式的Agent ID.
        
        用于VC中的agent_id字段。
        
        Args:
            agent_name: Agent名称
            owner: 用户电话号码
            rid: 区域ID
            achid: Agent信道ID
            
        Returns:
            UDID格式的Agent ID，格式为: did:udid:type2.rid<rid>.achid<achid>.uerid<电话号码+五位随机数>@6gc.mnc015.mcc234.3gppnetwork.org
        """
        # 生成5位随机数
        random_suffix = random.randint(10000, 99999)
        
        # 构造uerid: 电话号码 + 5位随机数
        uerid = f"{owner}{random_suffix}"
        
        # 格式: did:udid:type2.rid<rid>.achid<achid>.uerid<uerid>@6gc.mnc015.mcc234.3gppnetwork.org
        udid = f"did:udid:type2.rid{rid}.achid{achid}.uerid{uerid}@6gc.mnc015.mcc234.3gppnetwork.org"
        
        logger.info(f"Generated UDID format Agent ID: {udid}")
        logger.info(f"  - Owner (phone): {owner}")
        logger.info(f"  - Random suffix: {random_suffix}")
        
        return udid


# 便捷函数
def generate_agent_id(owner: str) -> str:
    """生成Agent DID的便捷函数.
    
    Args:
        owner: 用户电话号码
        
    Returns:
        Agent DID (UDID格式)
    """
    return AgentIDGenerator.generate(owner)
