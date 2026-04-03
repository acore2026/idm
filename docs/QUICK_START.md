# 快速开始指南

本指南帮助您快速启动和运行IDM服务。

## 环境准备

### 系统要求

- **操作系统**：Linux、macOS 或 Windows 10+
- **Python**：3.8 或更高版本
- **内存**：至少 512MB 可用内存
- **磁盘**：至少 100MB 可用空间

### 检查Python安装

```bash
python3 --version  # Linux/macOS
python --version   # Windows
```

应显示类似 `Python 3.8.10` 或更高的版本号。

## 安装与启动

### 方式一：使用启动脚本（推荐）

#### Linux/macOS

```bash
# 1. 克隆或解压项目到本地目录
cd /path/to/idm-acn

# 2. 给予启动脚本执行权限
chmod +x start_idm.sh

# 3. 运行启动脚本
./start_idm.sh
```

如果你只想直接启动服务，请运行 `./start_idm.sh`，它会默认监听 `0.0.0.0:9020`，并在端口被占用或存在旧 PID 时先结束旧进程，再以后台方式启动。

#### Windows

```cmd
# 1. 进入项目目录
cd C:\path\to\idm-acn

# 2. 运行启动脚本
start.bat
```

脚本会自动：
- 检查Python环境
- 创建虚拟环境（如不存在）
- 安装依赖包
- 创建必要目录
- 生成IDM密钥对（如不存在）
- 启动服务

### 方式二：手动安装

#### 1. 创建虚拟环境

```bash
# Linux/macOS
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate.bat
```

#### 2. 安装依赖

```bash
pip install -r requirements.txt
```

#### 3. 创建目录

```bash
# Linux/macOS
mkdir -p profiles logs certs

# Windows
mkdir profiles logs certs
```

#### 4. 启动服务

```bash
python -m uvicorn src.idm.main:app --host 0.0.0.0 --port 9020
```

或使用自动重载模式（开发环境）：

```bash
python -m uvicorn src.idm.main:app --host 0.0.0.0 --port 9020 --reload
```

## 验证安装

### 1. 健康检查

打开浏览器或使用curl访问：

```bash
curl http://localhost:9020/idm/v1/health
```

应返回：

```json
{
    "status": "healthy",
    "service": "IDM",
    "did": "did:udid:idm@6gc.mnc015.mcc234.3gppnetwork.org"
}
```

### 2. 查看API文档

打开浏览器访问：

```
http://localhost:9020/docs
```

这是自动生成的Swagger UI文档，可以：
- 查看所有API端点
- 了解请求/响应格式
- 在线测试API

## 发送测试请求

### 使用curl

```bash
curl -X POST "http://localhost:9020/idm/v1/identity-applications" \
  -H "Content-Type: application/json" \
  -d '{
    "owner": "test_owner",
    "name": "TestAgent",
    "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----",
    "description": "Test agent for development",
    "timestamp": 1711185600,
    "signature": "base64_encoded_signature",
    "signature_encoding": "base64",
    "metadata": {
      "region": "CN",
      "os": "Linux",
      "version": "1.0.0"
    }
  }'
```

签名串为 `owner:name:timestamp`，使用 ECDSA + SHA-256 签名后再进行 Base64 编码。

**注意**：`metadata` 字段为可选，可包含任意自定义属性。

### 使用Python脚本

```python
import requests
import json

url = "http://localhost:9020/idm/v1/identity-applications"

payload = {
    "owner": "test_owner",
    "name": "TestAgent",
    "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----",
    "description": "Test agent",
    "timestamp": 1711185600,
    "signature": "base64_encoded_signature",
    "signature_encoding": "base64",
    "metadata": {
        "region": "CN",
        "os": "Linux",
        "version": "1.0.0"
    }
}

response = requests.post(url, json=payload)
print(json.dumps(response.json(), indent=2))
```

签名串为 `owner:name:timestamp`，使用 ECDSA + SHA-256 签名后再进行 Base64 编码。

## 常见问题

### Q: 启动脚本提示"Python is not installed"

**A**: 确保Python已安装并添加到系统PATH。检查：

```bash
which python3  # Linux/macOS
where python   # Windows
```

### Q: 端口9020被占用

**A**: 可以修改端口：

```bash
# 设置环境变量后启动
export IDM_PORT=9021  # Linux/macOS
set IDM_PORT=9021     # Windows

# 或使用uvicorn参数
python -m uvicorn src.idm.main:app --host 0.0.0.0 --port 9021
```

### Q: 如何查看日志

**A**: 日志文件位于 `logs/` 目录：

```bash
tail -f logs/idm_*.log  # Linux/macOS
type logs\idm_*.log     # Windows
```

### Q: 如何停止服务

**A**: 在终端按 `Ctrl+C` 即可停止服务。

## 下一步

- 查看 [ARCHITECTURE.md](ARCHITECTURE.md) 了解系统架构
- 查看 [API.md](API.md) 了解详细API接口
- 运行测试： `python src/tests/test_idm.py`
