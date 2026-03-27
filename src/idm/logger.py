"""日志配置模块.

提供统一的日志配置和管理功能。
"""

import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional

from .config import config


class LoggerManager:
    """日志管理器.
    
    统一管理IDM系统的日志配置，支持控制台和文件输出。
    """
    
    _logger: Optional[logging.Logger] = None
    _initialized: bool = False
    
    @classmethod
    def get_logger(cls, name: str = "idm") -> logging.Logger:
        """获取logger实例.
        
        Args:
            name: Logger名称
            
        Returns:
            Logger实例
        """
        if not cls._initialized:
            cls._setup_logger()
        return logging.getLogger(name)
    
    @classmethod
    def _setup_logger(cls) -> None:
        """配置日志系统."""
        # 确保日志目录存在
        config.ensure_directories()
        
        # 创建logger
        logger = logging.getLogger("idm")
        logger.setLevel(getattr(logging, config.LOG_LEVEL.upper()))
        
        # 清除已有handler
        logger.handlers.clear()
        
        # 控制台Handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG)
        console_format = logging.Formatter(config.LOG_FORMAT)
        console_handler.setFormatter(console_format)
        logger.addHandler(console_handler)
        
        # 文件Handler
        log_file = config.LOGS_DIR / f"idm_{datetime.now().strftime('%Y%m%d')}.log"
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter(config.LOG_FORMAT)
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)
        
        cls._logger = logger
        cls._initialized = True
        
    @classmethod
    def log_message_received(cls, endpoint: str, method: str, body: dict) -> None:
        """记录接收到的消息.
        
        Args:
            endpoint: 请求端点
            method: 请求方法
            body: 请求体
        """
        logger = cls.get_logger()
        logger.info(f"=== Received Request ===")
        logger.info(f"Endpoint: {endpoint}")
        logger.info(f"Method: {method}")
        logger.info(f"Body: {body}")
        
    @classmethod
    def log_message_sent(cls, endpoint: str, response: dict) -> None:
        """记录发送的响应消息.
        
        Args:
            endpoint: 请求端点
            response: 响应体
        """
        logger = cls.get_logger()
        logger.info(f"=== Sending Response ===")
        logger.info(f"Endpoint: {endpoint}")
        logger.info(f"Response: {response}")
        
    @classmethod
    def log_state_change(cls, entity: str, from_state: str, to_state: str, details: str = "") -> None:
        """记录状态转换.
        
        Args:
            entity: 实体名称
            from_state: 原状态
            to_state: 新状态
            details: 详细信息
        """
        logger = cls.get_logger()
        logger.info(f"=== State Change ===")
        logger.info(f"Entity: {entity}")
        logger.info(f"From: {from_state} -> To: {to_state}")
        if details:
            logger.info(f"Details: {details}")


def get_logger(name: str = "idm") -> logging.Logger:
    """获取logger实例的便捷函数.
    
    Args:
        name: Logger名称
        
    Returns:
        Logger实例
    """
    return LoggerManager.get_logger(name)
