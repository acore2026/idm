"""IDM模块包初始化."""

from .config import config
from .logger import get_logger
from .models import (
    IdentityApplicationRequest,
    IdentityApplicationResponse,
    VC0,
    AgentProfile
)
from .crypto import crypto_manager
from .agent_id import generate_agent_id
from .vc_generator import generate_vc0
from .profile_manager import save_profile, load_profile
from .idm_service import idm_service

__all__ = [
    "config",
    "get_logger",
    "IdentityApplicationRequest",
    "IdentityApplicationResponse",
    "VC0",
    "AgentProfile",
    "crypto_manager",
    "generate_agent_id",
    "generate_vc0",
    "save_profile",
    "load_profile",
    "idm_service"
]

__version__ = "1.0.0"
