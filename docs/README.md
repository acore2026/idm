# ACN IDM 身份管理系统

## 项目简介

IDM（Identity Management）是ACN（Agent Communication Network）系统的身份管理组件，负责：

- **Agent ID生成颁发**：为ACN Agent生成唯一的DID身份标识
- **VC0生成**：颁发绑定Agent与主UE关系的可验证凭证
- **VC校验**：验证可验证凭证的签名和有效性
- **Agent Profile存储**：管理Agent配置文件的存储和查询

## 功能特性

- 基于FastAPI的RESTful API服务
- ECDSA非对称加密签名验证
- DID身份标识生成（did:acn格式）
- W3C标准VC0证书生成
- Agent Profile本地存储
- 完整的日志记录
- 支持Windows和Linux双平台
- 详细的API文档和测试用例

## 项目结构

```
idm-acn/
├── src/
│   ├── idm/                    # IDM核心模块
│   │   ├── __init__.py
│   │   ├── config.py           # 配置管理
│   │   ├── logger.py           # 日志配置
│   │   ├── models.py           # Pydantic数据模型
│   │   ├── crypto.py           # 加密签名工具
│   │   ├── agent_id.py         # Agent ID生成器
│   │   ├── vc_generator.py     # VC0证书生成器
│   │   ├── profile_manager.py  # Profile存储管理
│   │   ├── idm_service.py      # IDM业务服务
│   │   └── main.py             # FastAPI入口
│   └── tests/
│       ├── __init__.py
│       └── test_idm.py         # 测试用例
├── docs/                       # 文档目录
├── profiles/                   # Agent Profile存储
├── logs/                       # 日志目录
├── certs/                      # 证书目录
├── requirements.txt            # Python依赖
├── start_idm.sh                # Linux启动脚本
└── start.bat                   # Windows启动脚本
```

## 快速开始

### 环境要求

- Python 3.8+
- pip

### 安装步骤

#### Linux/macOS

```bash
# 1. 进入项目目录
cd idm-acn

# 2. 运行启动脚本
./start_idm.sh
```

#### Windows

```cmd
# 1. 进入项目目录
cd idm-acn

# 2. 运行启动脚本
start.bat
```

### 手动启动

```bash
# 1. 创建虚拟环境
python -m venv venv

# 2. 激活虚拟环境
# Linux/macOS:
source venv/bin/activate
# Windows:
venv\Scripts\activate.bat

# 3. 安装依赖
pip install -r requirements.txt

# 4. 启动服务
python -m uvicorn src.idm.main:app --host 0.0.0.0 --port 9020
```

### 服务访问

服务启动后，可通过以下地址访问：

- **API文档**：http://localhost:9020/docs
- **健康检查**：http://localhost:9020/idm/v1/health
- **身份申请**：http://localhost:9020/idm/v1/identity-applications

## API接口

### 1. 申请Agent身份

**端点**：`POST /idm/v1/identity-applications`

**请求体**：

```json
{
    "owner": "xxxxx",
    "name": "AliceAgent",
    "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...\n-----END PUBLIC KEY-----",
    "description": "AgentModel-X, SN123456",
    "timestamp": 1711185600,
    "signature": "base64_encoded_signature",
    "signature_encoding": "base64",
    "metadata": {
        "region": "CN",
        "os": "Linux",
        "version": "1.0.0"
    }
}
```

**metadata说明**：

`metadata` 字段为可选字段，可以包含任意自定义属性（如 `device_id`、`network` 等）。原有字段 `region`、`os`、`version` 也改为可选。

**签名说明**：

签名串为 `owner:name:timestamp`，使用 Agent 的 ECDSA 私钥对该字符串进行 SHA-256 签名，结果以 Base64 编码后放入 `signature`。

**响应**：

```json
{
    "result": "success",
    "agent_id": "did:acn:aB3dE5fG7h",
    "vc0": {
        "context": ["3gpp-ts-33.xxx-v20.0.0"],
        "id": "CMCC/credentials/3732",
        "type": ["VerifiableCredential", "BindingSIMCredential"],
        "issuer": "did:udid:idm@6gc.mnc015.mcc234.3gppnetwork.org",
        "valid_from": "2024-01-01T00:00:00Z",
        "valid_until": "2025-01-01T00:00:00Z",
        "claims": {
            "agent_name": "AliceAgent",
            "agent_id": "did:udid:type2.rid678.achid0.uerid1368888888800123@6gc.mnc015.mcc234.3gppnetwork.org",
            "agent_attribute": "运营商颁发，Agent与主UE的绑定关系，用于对外出示，审计确权",
            "master_id": "type0.rid678.schid0.userid1userid20001@6gc0001@6gc.mnc015.mcc234.3gppnetwork.org",
            "self_id": "type0.rid678.schid0..mnc015.mcc234.3gppnetwork.org"
        },
        "proof": {
            "creator": "did:udid:idm@6gc.mnc015.mcc234.3gppnetwork.org#keys-1",
            "signature_value": "base64_encoded_signature"
        }
    }
}
```

### 2. 健康检查

**端点**：`GET /idm/v1/health`

**响应**：

```json
{
    "status": "healthy",
    "service": "IDM",
    "did": "did:udid:idm@6gc.mnc015.mcc234.3gppnetwork.org"
}
```

### 3. 列出所有Agent

**端点**：`GET /idm/v1/profiles`

**响应**：

```json
{
    "agent_ids": ["did:acn:xxx", "did:acn:yyy"],
    "count": 2
}
```

### 4. 获取Agent Profile

**端点**：`GET /idm/v1/profiles/{agent_id}`

**响应**：Agent Profile详细信息

### 5. 注销Agent身份

**端点**：`POST /idm/v1/agent-deletions`

**功能**：ACN Agent（无人机、机器狗等）撤销已颁发的Agent DID，IDM校验签名后删除Profile和历史记录，并通知AgentGW（端口9001）进行身份撤销。

**请求体**：

```json
{
    "agent_id": "did:acn:agent:987654321",
    "reason": "retired",
    "timestamp": "2024-03-23T12:00:00Z",
    "signature": "base64_encoded_signature",
    "signature_encoding": "base64"
}
```

**签名说明**：

签名串为 `agent_id:reason:timestamp`，使用 Agent 的 ECDSA 私钥对该字符串进行 SHA-256 签名，结果以 Base64 编码后放入 `signature`。

**响应**：

本接口会在完成本地删除后，将 Agent GW（9001）的响应内容带回给 ACN Agent。

```json
{
    "result": "success",
    "agent_id": "did:acn:agent:987654321",
    "message": "AgentGW deletion acknowledged",
    "forwarded_to_agent_gw": true,
    "agent_gw_response": {
        "success": true,
        "status_code": 200,
        "body": {
            "result": "success",
            "message": "AgentGW deletion acknowledged"
        }
    }
}
```

### 6. 校验VC证书

**端点**：`POST /idm/v1/vc-verifications`

**功能**：AgentGW发送能力VC给IDM进行校验，校验内容包括签名验证、颁发者DID存在性、有效期、字段完整性、格式校验。通过后更新Agent Profile并返回校验结果。

**请求体**：

```json
{
    "agent_id": "did:acn:agent:987654321",
    "vc_list": [
        {
            "context": ["3gpp-ts-33.xxx-v20.0.0"],
            "id": "CMCC/credentials/3732",
            "type": ["VerifiableCredential", "CapabilityCredential"],
            "issuer": "did:udid:idm@6gc.mnc015.mcc234.3gppnetwork.org",
            "valid_from": "2024-01-01T00:00:00Z",
            "valid_until": "2025-01-01T00:00:00Z",
            "claims": {
                "agent_name": "AliceAgent",
                "agent_id": "did:acn:agent:987654321",
                "capability": "surveillance"
            },
            "proof": {
                "creator": "did:udid:idm@6gc.mnc015.mcc234.3gppnetwork.org#keys-1",
                "signature_value": "base64_encoded_signature"
            }
        }
    ]
}
```

**响应**：

```json
{
    "valid": true,
    "vc_ids": [
        "CMCC/credentials/3732",
        "CMCC/credentials/3733"
    ],
    "invalid_vcs": null
}
```

## 测试

### 运行单元测试

```bash
# 进入项目目录
cd idm-acn

# 激活虚拟环境
source venv/bin/activate  # Linux/macOS
# 或
venv\Scripts\activate.bat  # Windows

# 运行测试
python -m pytest src/tests/test_idm.py -v

# 或使用unittest
python -m unittest src/tests/test_idm.py -v
```

### 运行集成测试

项目包含完整的Mock ACN Agent测试：

```bash
python src/tests/test_idm.py
```

## 配置说明

配置文件位于 `src/idm/config.py`，支持以下配置项：

| 配置项 | 环境变量 | 默认值 | 说明 |
|--------|----------|--------|------|
| IDM_HOST | IDM_HOST | 0.0.0.0 | 服务监听地址 |
| IDM_PORT | IDM_PORT | 9020 | 服务监听端口 |
| IDM_DID | IDM_DID | did:udid:... | IDM的DID标识 |
| LOG_LEVEL | LOG_LEVEL | INFO | 日志级别 |

## 日志

日志文件存储在 `logs/` 目录下，按日期命名：
- `idm_YYYYMMDD.log`

日志包含：
- 请求/响应消息内容
- 关键状态转换
- 错误信息

## 文档

详细文档见 `docs/` 目录：

- [QUICK_START.md](docs/QUICK_START.md) - 快速开始指南
- [ARCHITECTURE.md](docs/ARCHITECTURE.md) - 系统架构设计
- [API.md](docs/API.md) - API接口文档

## 许可证

MIT License

## 联系方式

如有问题，请提交Issue或联系维护团队。
