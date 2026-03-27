@echo off
REM IDM服务启动脚本 (Windows)

echo ==========================================
echo   ACN IDM Service Starter (Windows)
echo ==========================================

REM 获取脚本所在目录
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

REM 检查Python环境
echo [1/5] Checking Python environment...
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed
    exit /b 1
)
for /f "tokens=*" %%a in ('python --version') do echo Found: %%a

REM 创建虚拟环境（如果不存在）
echo [2/5] Setting up virtual environment...
if not exist "venv" (
    python -m venv venv
    echo Created virtual environment
)

REM 激活虚拟环境
call venv\Scripts\activate.bat

REM 安装依赖
echo [3/5] Installing dependencies...
pip install -q --upgrade pip
pip install -q -r requirements.txt

REM 确保目录存在
echo [4/5] Preparing directories...
if not exist "profiles" mkdir profiles
if not exist "logs" mkdir logs
if not exist "certs" mkdir certs

REM 生成IDM密钥对（如果不存在）
if not exist "certs\idm_private_key.pem" (
    echo Generating IDM key pair...
    python -c "from src.idm.crypto import crypto_manager; print('Keys ready')"
)

REM 启动服务
echo [5/5] Starting IDM service...
echo ==========================================
echo   IDM Service is starting...
echo   - Host: 0.0.0.0
echo   - Port: 9020
echo   - API Docs: http://localhost:9020/docs
echo   - Health Check: http://localhost:9020/idm/v1/health
echo ==========================================
echo.

REM 使用uvicorn启动
python -m uvicorn src.idm.main:app --host 0.0.0.0 --port 9020 --reload
