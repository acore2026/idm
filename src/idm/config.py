"""IDM系统配置文件模块.

提供IDM系统的配置管理，支持环境变量和配置文件。
"""

import os
from pathlib import Path
from typing import Optional


class Config:
    """IDM系统配置类.
    
    Attributes:
        IDM_HOST: IDM服务监听地址
        IDM_PORT: IDM服务监听端口
        IDM_DID: IDM的DID标识
        IDM_KEY_PATH: IDM私钥文件路径
        IDM_PUBLIC_KEY_PATH: IDM公钥文件路径
        PROFILES_DIR: Agent Profile存储目录
        LOGS_DIR: 日志存储目录
        CERTS_DIR: 证书存储目录
        VC_VALIDITY_YEARS: VC有效期（年）
        AGENT_ID_PREFIX: Agent ID前缀
    """
    
    # 项目根目录
    # `config.py` lives in `src/idm/`, so the project root is three levels up.
    BASE_DIR: Path = Path(__file__).resolve().parents[2]
    
    # 服务配置
    IDM_HOST: str = os.getenv("IDM_HOST", "0.0.0.0")
    IDM_PORT: int = int(os.getenv("IDM_PORT", "9020"))
    
    # IDM DID标识（固定值）
    IDM_DID: str = os.getenv(
        "IDM_DID", 
        "did:udid:idm@6gc.mnc015.mcc234.3gppnetwork.org"
    )
    
    # IDM密钥对路径
    IDM_KEY_PATH: Path = BASE_DIR / "certs" / "idm_private_key.pem"
    IDM_PUBLIC_KEY_PATH: Path = BASE_DIR / "certs" / "idm_public_key.pem"
    
    # 存储目录
    PROFILES_DIR: Path = BASE_DIR / "profiles"
    LOGS_DIR: Path = BASE_DIR / "logs"
    CERTS_DIR: Path = BASE_DIR / "certs"
    
    # VC配置
    VC_CONTEXT: list = ["3gpp-ts-33.xxx-v20.0.0"]
    VC_VALIDITY_YEARS: int = 1
    VC_ISSUER_TYPE: str = "BindingSIMCredential"
    
    # Agent ID配置
    AGENT_ID_PREFIX: str = "did:acn"
    AGENT_ID_HASH_LENGTH: int = 10
    
    # 日志配置
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    @classmethod
    def ensure_directories(cls) -> None:
        """确保必要的目录存在."""
        cls.PROFILES_DIR.mkdir(parents=True, exist_ok=True)
        cls.LOGS_DIR.mkdir(parents=True, exist_ok=True)
        cls.CERTS_DIR.mkdir(parents=True, exist_ok=True)
        
    @classmethod
    def get_profile_path(cls, agent_id: str) -> Path:
        """获取Agent Profile文件路径.
        
        使用uerid（电话号码+随机数）作为文件名。
        从UDID格式 did:udid:type2.rid<rid>.achid<achid>.uerid<uerid>@... 中提取uerid。
        
        Args:
            agent_id: Agent的DID标识 (UDID格式)
            
        Returns:
            Profile文件路径
        """
        # 从UDID格式中提取uerid
        # 格式: did:udid:type2.rid678.achid0.uerid1368888888800123@6gc.mnc015.mcc234.3gppnetwork.org
        try:
            # 找到uerid部分
            if "uerid" in agent_id:
                # 提取uerid到@之间的部分
                uerid_start = agent_id.find("uerid") + 5  # "uerid"长度是5
                uerid_end = agent_id.find("@", uerid_start)
                if uerid_end > uerid_start:
                    uerid = agent_id[uerid_start:uerid_end]
                    return cls.PROFILES_DIR / f"{uerid}.json"
        except Exception:
            pass
        
        # 如果无法提取uerid，使用安全的文件名
        safe_id = agent_id.replace(":", "_").replace("/", "_")
        return cls.PROFILES_DIR / f"{safe_id}.json"


config = Config()
