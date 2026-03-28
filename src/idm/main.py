"""IDM FastAPI应用入口.

提供HTTP API服务，默认监听127.0.0.1:9020。
"""

import argparse
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager

from .config import config
from .logger import get_logger, LoggerManager
from .models import (
    IdentityApplicationRequest, 
    IdentityApplicationResponse,
    AgentDeletionRequest,
    AgentDeletionResponse,
    VCVerificationRequest,
    VCVerificationResponse,
    ErrorResponse
)
from .idm_service import idm_service

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理."""
    # 启动时
    logger.info("=" * 60)
    logger.info("IDM Service Starting...")
    logger.info("=" * 60)
    config.ensure_directories()
    logger.info(f"IDM DID: {config.IDM_DID}")
    logger.info(f"Listening on: {config.IDM_HOST}:{config.IDM_PORT}")
    logger.info(f"Profiles directory: {config.PROFILES_DIR}")
    logger.info(f"Logs directory: {config.LOGS_DIR}")
    logger.info("=" * 60)
    yield
    # 关闭时
    logger.info("IDM Service Shutting down...")


# 创建FastAPI应用
app = FastAPI(
    title="ACN IDM Service",
    description="Identity Management Service for ACN System",
    version="1.0.0",
    lifespan=lifespan
)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """全局异常处理器."""
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"error": "Internal Server Error", "detail": str(exc)}
    )


@app.post(
    "/idm/v1/identity-applications",
    response_model=IdentityApplicationResponse,
    summary="申请Agent身份",
    description="接收ACN Agent的身份申请请求，验证签名后颁发Agent DID和VC0证书"
)
async def apply_identity(request: IdentityApplicationRequest) -> IdentityApplicationResponse:
    """处理身份申请请求.
    
    请求流程：
    1. 接收请求并记录
    2. 验证签名
    3. 生成Agent ID
    4. 生成VC0
    5. 创建Profile
    6. 返回结果
    
    Args:
        request: 身份申请请求体
        
    Returns:
        包含Agent ID和VC0的响应
        
    Raises:
        HTTPException: 验证失败或其他错误
    """
    # 记录接收到的消息
    LoggerManager.log_message_received(
        endpoint="/idm/v1/identity-applications",
        method="POST",
        body=request.model_dump()
    )
    
    try:
        # 处理申请
        response = idm_service.process_identity_application(request)
        
        # 记录发送的响应
        LoggerManager.log_message_sent(
            endpoint="/idm/v1/identity-applications",
            response=response.model_dump()
        )
        
        return response
        
    except ValueError as e:
        logger.error(f"Validation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Processing error: {e}")
        raise HTTPException(status_code=500, detail="Internal processing error")


@app.get(
    "/idm/v1/health",
    summary="健康检查",
    description="检查IDM服务状态"
)
async def health_check():
    """健康检查端点."""
    return {
        "status": "healthy",
        "service": "IDM",
        "did": config.IDM_DID
    }


@app.get(
    "/idm/v1/profiles",
    summary="列出所有Agent",
    description="获取所有已注册的Agent ID列表"
)
async def list_profiles():
    """列出所有Agent Profile."""
    from .profile_manager import ProfileManager
    agent_ids = ProfileManager.list_profiles()
    return {"agent_ids": agent_ids, "count": len(agent_ids)}


@app.get(
    "/idm/v1/profiles/{agent_id}",
    summary="获取Agent Profile",
    description="获取指定Agent的Profile信息"
)
async def get_profile(agent_id: str):
    """获取Agent Profile."""
    from .profile_manager import ProfileManager
    profile = ProfileManager.load_profile(agent_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found")
    return profile.model_dump()


@app.post(
    "/acn-agent/v1/agent-deletions",
    response_model=AgentDeletionResponse,
    summary="注销Agent身份",
    description="接收ACN Agent的身份注销请求，验证签名后删除Profile并通知AgentGW"
)
async def delete_agent(request: AgentDeletionRequest) -> AgentDeletionResponse:
    """处理身份注销请求.
    
    请求流程：
    1. 接收注销请求
    2. 加载Agent Profile
    3. 验证签名
    4. 删除Profile和历史记录
    5. 转发给AgentGW
    6. 返回结果
    
    Args:
        request: 身份注销请求体
        
    Returns:
        注销结果响应
    """
    # 记录接收到的消息
    LoggerManager.log_message_received(
        endpoint="/acn-agent/v1/agent-deletions",
        method="POST",
        body=request.model_dump()
    )
    
    try:
        # 处理注销
        response = idm_service.delete_agent_identity(request)
        
        # 记录发送的响应
        LoggerManager.log_message_sent(
            endpoint="/acn-agent/v1/agent-deletions",
            response=response.model_dump()
        )
        
        return response
        
    except ValueError as e:
        logger.error(f"Validation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Processing error: {e}")
        raise HTTPException(status_code=500, detail="Internal processing error")


@app.post(
    "/idm/v1/vc-verifications",
    response_model=VCVerificationResponse,
    summary="校验VC证书",
    description="接收AgentGW的VC校验请求，验证证书有效性并更新Agent Profile"
)
async def verify_vcs(request: VCVerificationRequest) -> VCVerificationResponse:
    """处理VC校验请求.
    
    校验流程：
    1. 验证Agent是否存在
    2. 校验每个VC的签名、颁发者、有效期、字段完整性
    3. 更新Agent Profile（添加有效VC）
    4. 返回校验结果
    
    Args:
        request: VC校验请求体
        
    Returns:
        校验结果响应，包含通过的VC ID列表
    """
    # 记录接收到的消息
    LoggerManager.log_message_received(
        endpoint="/idm/v1/vc-verifications",
        method="POST",
        body=request.model_dump()
    )
    
    try:
        # 处理VC校验
        response = idm_service.verify_vcs(request)
        
        # 记录发送的响应
        LoggerManager.log_message_sent(
            endpoint="/idm/v1/vc-verifications",
            response=response.model_dump()
        )
        
        return response
        
    except ValueError as e:
        logger.error(f"Validation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Processing error: {e}")
        raise HTTPException(status_code=500, detail="Internal processing error")


def main(host: str | None = None, port: int | None = None):
    """主入口函数.

    Args:
        host: 可选监听地址，未提供时使用配置默认值
        port: 可选监听端口，未提供时使用配置默认值
    """
    uvicorn.run(
        "src.idm.main:app",
        host=host or config.IDM_HOST,
        port=port or config.IDM_PORT,
        reload=False,
        log_level="info"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the IDM service")
    parser.add_argument("--host", default=None, help="Bind address, defaults to config value")
    parser.add_argument("--port", type=int, default=None, help="Bind port, defaults to config value")
    args = parser.parse_args()
    main(host=args.host, port=args.port)
