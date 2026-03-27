#!/bin/bash
# IDM服务启动脚本 (Linux/Mac)

echo "=========================================="
echo "  ACN IDM Service Starter"
echo "=========================================="

# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 检查Python环境
echo "[1/5] Checking Python environment..."
if ! command -v python3 &> /dev/null; then
    echo "Error: Python3 is not installed"
    exit 1
fi

PYTHON_VERSION=$(python3 --version)
echo "Found: $PYTHON_VERSION"

# 创建虚拟环境（如果不存在）
echo "[2/5] Setting up virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "Created virtual environment"
fi

# 激活虚拟环境
source venv/bin/activate

# 安装依赖
echo "[3/5] Installing dependencies..."
pip install -q --upgrade pip
pip install -q -r requirements.txt

# 确保目录存在
echo "[4/5] Preparing directories..."
mkdir -p profiles logs certs

# 生成IDM密钥对（如果不存在）
if [ ! -f "certs/idm_private_key.pem" ]; then
    echo "Generating IDM key pair..."
    python3 -c "from src.idm.crypto import crypto_manager; print('Keys ready')"
fi

# 启动服务
echo "[5/5] Starting IDM service..."
echo "=========================================="
echo "  IDM Service is starting..."
echo "  - Host: 0.0.0.0"
echo "  - Port: 9020"
echo "  - API Docs: http://localhost:9020/docs"
echo "  - Health Check: http://localhost:9020/idm/v1/health"
echo "=========================================="
echo ""

# 使用uvicorn启动
python3 -m uvicorn src.idm.main:app --host 0.0.0.0 --port 9020 --reload
