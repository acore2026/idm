# 系统架构设计文档

## 1. 系统概述

### 1.1 架构图

```mermaid
graph TB
    subgraph "ACN System"
        AGENT[ACN Agent<br/>Port: 9010]
        IDM[IDM Service<br/>Port: 9020]
        AGENT_GW[AgentGW]
        WEB_UI[WebUI]
    end
    
    AGENT -->|HTTP POST| IDM
    AGENT_GW -.->|Future| IDM
    WEB_UI -.->|Future| IDM
    
    IDM -->|Store| PROFILES[(Agent Profiles)]
    IDM -->|Log| LOGS[(Logs)]
    IDM -->|Keys| CERTS[(Certificates)]
```

### 1.2 部署架构

```mermaid
graph LR
    subgraph "Terminal 1"
        AGENT[ACN Agent]
        IDM[IDM Service]
        AGENT_GW[AgentGW]
        WEB_UI[WebUI]
    end
    
    subgraph "Terminal 2"
        REMOTE_AGENT[Remote Agent]
    end
    
    REMOTE_AGENT -->|Request Identity| IDM
```

## 2. 组件说明

### 2.1 IDM服务组件

```mermaid
classDiagram
    class IDMService {
        +process_identity_application()
        +verify_vc()
    }
    
    class CryptoManager {
        -_private_key
        -_public_key
        +verify_signature()
        +sign_data()
        +sign_vc()
    }
    
    class AgentIDGenerator {
        +generate()
        +generate_udid_format()
    }
    
    class VCGenerator {
        +generate_vc0()
    }
    
    class ProfileManager {
        +save_profile()
        +load_profile()
        +create_profile()
    }
    
    IDMService --> CryptoManager
    IDMService --> AgentIDGenerator
    IDMService --> VCGenerator
    IDMService --> ProfileManager
```

## 3. 业务流程

### 3.1 身份申请流程

```mermaid
sequenceDiagram
    participant Agent as ACN Agent
    participant IDM as IDM Service
    participant Crypto as CryptoManager
    participant IDGen as AgentIDGenerator
    participant VCGen as VCGenerator
    participant PM as ProfileManager
    
    Agent->>IDM: POST /identity-applications
    Note over Agent,IDM: Request with public_key & signature
    
    IDM->>Crypto: verify_signature()
    Crypto-->>IDM: Signature Valid
    
    IDM->>IDGen: generate()
    IDGen-->>IDM: Agent DID
    
    IDM->>VCGen: generate_vc0()
    VCGen->>Crypto: sign_vc()
    Crypto-->>VCGen: Signature
    VCGen-->>IDM: VC0 Certificate
    
    IDM->>PM: create_profile()
    PM-->>IDM: Profile Created
    
    IDM-->>Agent: Response with agent_id & vc0
```

### 3.2 状态转换图

```mermaid
stateDiagram-v2
    [*] --> INIT
    INIT --> RECEIVED : Receive Request
    
    RECEIVED --> SIGNATURE_VERIFIED : Verify Signature
    RECEIVED --> SIGNATURE_VERIFICATION_FAILED : Invalid Signature
    
    SIGNATURE_VERIFIED --> AGENT_ID_GENERATED : Generate Agent ID
    
    AGENT_ID_GENERATED --> VC0_GENERATED : Generate VC0
    
    VC0_GENERATED --> PROFILE_CREATED : Create Profile
    
    PROFILE_CREATED --> COMPLETED : Return Response
    
    SIGNATURE_VERIFICATION_FAILED --> [*]
    COMPLETED --> [*]
```

## 4. 数据模型

### 4.1 请求/响应模型

```mermaid
classDiagram
    class IdentityApplicationRequest {
        +str owner
        +str name
        +str public_key
        +str description
        +int timestamp
        +str signature
        +str signature_encoding
        +Metadata metadata
    }
    
    class Metadata {
        +str region
        +str os
        +str version
    }
    
    class IdentityApplicationResponse {
        +str result
        +str agent_id
        +VC0 vc0
    }
    
    class VC0 {
        +List~str~ context
        +str id
        +List~str~ type
        +str issuer
        +str valid_from
        +str valid_until
        +VC0Claims claims
        +VC0Proof proof
    }
    
    class VC0Claims {
        +str agent_name
        +str agent_id
        +str agent_attribute
        +str master_id
        +str self_id
    }
    
    class VC0Proof {
        +str creator
        +str signature_value
    }
    
    IdentityApplicationRequest --> Metadata
    IdentityApplicationResponse --> VC0
    VC0 --> VC0Claims
    VC0 --> VC0Proof
```

### 4.2 Agent Profile模型

```mermaid
classDiagram
    class AgentProfile {
        +str agent_id
        +str controller
        +List~VerificationKey~ verification_relationships
        +VC0 vc0
        +str vc0_authorization_mode
        +str created_at
        +str updated_at
    }
    
    class VerificationKey {
        +str id
        +str type
        +str controller
        +PublicKeyJwk publicKeyJwk
    }
    
    class PublicKeyJwk {
        +str crv
        +str x
        +str kty
        +str kid
    }
    
    AgentProfile --> VerificationKey
    VerificationKey --> PublicKeyJwk
```

## 5. 目录结构

```
idm-acn/
├── src/
│   ├── idm/                    # 核心业务逻辑
│   │   ├── config.py           # 配置管理
│   │   ├── logger.py           # 日志配置
│   │   ├── models.py           # Pydantic模型定义
│   │   ├── crypto.py           # 加密签名模块
│   │   ├── agent_id.py         # Agent ID生成
│   │   ├── vc_generator.py     # VC生成
│   │   ├── profile_manager.py  # Profile管理
│   │   ├── idm_service.py      # 业务服务
│   │   └── main.py             # FastAPI入口
│   └── tests/                  # 测试模块
├── docs/                       # 文档
├── profiles/                   # Agent数据存储
├── logs/                       # 日志文件
├── certs/                      # IDM密钥证书
└── requirements.txt            # 依赖包
```

## 6. 关键算法

### 6.1 Agent ID生成算法

```python
# 算法描述
1. 接收: public_key (PEM格式), timestamp
2. 构造: salted_key = public_key + ":" + timestamp
3. 哈希: hash = SHA256(salted_key)
4. 编码: hash_b64 = Base64URL(hash)
5. 截取: short_hash = hash_b64[:10]
6. 返回: "did:acn:" + short_hash
```

特点：
- 同一公钥不同时间生成不同ID
- hash部分控制在10位以内
- URL安全的Base64编码

### 6.2 签名验证流程

```python
# 签名消息构造
message = f"{owner}:{name}:{timestamp}"

# 验证
public_key.verify(
    signature_bytes,
    message.encode(),
    ec.ECDSA(hashes.SHA256())
)
```

### 6.3 VC签名算法

```python
# 待签内容（排除proof部分）
vc_to_sign = {
    "context": vc["context"],
    "id": vc["id"],
    "type": vc["type"],
    "issuer": vc["issuer"],
    "valid_from": vc["valid_from"],
    "valid_until": vc["valid_until"],
    "claims": vc["claims"]
}

# 序列化后签名
message = json.dumps(vc_to_sign, sort_keys=True)
signature = IDM_private_key.sign(message)
```

## 7. 安全考虑

### 7.1 密钥管理

- IDM私钥存储在本地文件系统
- 使用PEM格式，PKCS#8编码
- 私钥文件权限应设置为600（仅所有者可读写）

### 7.2 签名验证

- 使用ECDSA P-256 + SHA256
- Base64编码的DER签名值
- 严格验证签名时间戳有效性

### 7.3 数据存储

- Agent Profile以JSON格式存储
- 每个Agent独立文件
- 文件名使用安全的编码转换

## 8. 扩展性设计

### 8.1 模块化设计

- 各功能模块独立（crypto, agent_id, vc, profile）
- 通过接口交互，便于替换实现
- 依赖注入模式

### 8.2 配置化

- 支持环境变量配置
- 可配置的DID前缀
- 可调整的VC有效期

### 8.3 日志记录

- 结构化日志
- 关键状态转换记录
- 完整的请求/响应追踪

## 9. 部署建议

### 9.1 生产环境

- 使用HTTPS/TLS
- 配置反向代理（Nginx）
- 设置日志轮转
- 监控服务健康状态

### 9.2 开发环境

- 使用 `--reload` 模式
- 开启DEBUG日志级别
- 本地测试使用Mock Agent
