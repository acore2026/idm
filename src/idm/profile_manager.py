"""Agent Profile管理模块.

提供Agent Profile的存储和查询服务。
"""

import json
from pathlib import Path
from typing import Optional, List
from datetime import datetime

from .config import config
from .logger import get_logger
from .models import AgentProfile, VC0, VerificationKey, PublicKeyJwk

logger = get_logger(__name__)


class ProfileManager:
    """Profile管理器.
    
    管理Agent Profile的CRUD操作。
    """
    
    @classmethod
    def save_profile(cls, profile: AgentProfile) -> Path:
        """保存Agent Profile.
        
        Args:
            profile: Agent Profile对象
            
        Returns:
            保存的文件路径
        """
        config.ensure_directories()
        
        file_path = config.get_profile_path(profile.agent_id)
        
        # 更新更新时间
        profile.updated_at = datetime.utcnow().isoformat() + "Z"
        
        # 保存到JSON文件
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(profile.model_dump(), f, indent=2, ensure_ascii=False)
            
        logger.info(f"Profile saved: {file_path}")
        logger.info(f"  - Agent ID: {profile.agent_id}")
        
        return file_path
        
    @classmethod
    def load_profile(cls, agent_id: str) -> Optional[AgentProfile]:
        """加载Agent Profile.
        
        Args:
            agent_id: Agent DID
            
        Returns:
            Agent Profile对象，不存在则返回None
        """
        file_path = config.get_profile_path(agent_id)
        
        if not file_path.exists():
            logger.warning(f"Profile not found: {agent_id}")
            return None
            
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            profile = AgentProfile(**data)
            logger.info(f"Profile loaded: {agent_id}")
            return profile
        except Exception as e:
            logger.error(f"Failed to load profile: {e}")
            return None
            
    @classmethod
    def list_profiles(cls) -> List[str]:
        """列出所有Agent ID.
        
        Returns:
            Agent ID列表
        """
        config.ensure_directories()
        
        profiles = []
        for file_path in config.PROFILES_DIR.glob("*.json"):
            # 从文件名还原agent_id
            agent_id = file_path.stem.replace("_", ":")
            profiles.append(agent_id)
            
        return profiles
        
    @classmethod
    def create_profile(
        cls,
        agent_id: str,
        public_key_pem: str,
        vc0: VC0,
        controller: Optional[str] = None
    ) -> AgentProfile:
        """创建新的Agent Profile.
        
        Args:
            agent_id: Agent DID
            public_key_pem: Agent公钥(PEM格式)
            vc0: VC0证书
            controller: 管理者UE身份，默认使用master_id
            
        Returns:
            创建的Agent Profile
        """
        if controller is None:
            controller = vc0.claims.master_id
            
        # 构造验证密钥信息
        # 将PEM公钥转换为JWK格式（简化版）
        verification_key = VerificationKey(
            id=f"{agent_id}#key1",
            type="JsonWebKey",
            controller=agent_id.replace("did:acn:", ""),
            publicKeyJwk=PublicKeyJwk(
                crv="Ed25519",  # 默认使用Ed25519
                x="VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ",  # 占位符
                kty="OKP",
                kid="_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A"  # 占位符
            )
        )
        
        profile = AgentProfile(
            agent_id=agent_id,
            controller=controller,
            verification_relationships=[verification_key],
            vc0=vc0,
            vc0_authorization_mode="Authorizationtemplate ID1"
        )
        
        # 保存Profile
        cls.save_profile(profile)
        
        logger.info(f"Profile created for agent: {agent_id}")
        logger.info(f"  - Controller: {controller}")
        
        return profile


# 便捷函数
def save_profile(profile: AgentProfile) -> Path:
    """保存Profile的便捷函数."""
    return ProfileManager.save_profile(profile)


def load_profile(agent_id: str) -> Optional[AgentProfile]:
    """加载Profile的便捷函数."""
    return ProfileManager.load_profile(agent_id)
