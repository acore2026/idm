"""数据模型定义模块.

定义IDM系统中使用的所有数据模型。
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime


class Metadata(BaseModel):
    """Agent元数据模型."""
    region: str
    os: str
    version: str


class IdentityApplicationRequest(BaseModel):
    """身份申请请求模型.
    
    Attributes:
        owner: Agent所有者
        name: Agent名称
        public_key: Agent公钥
        description: Agent描述
        timestamp: 时间戳字符串
        signature: 签名
        signature_encoding: 签名编码格式
        metadata: 元数据
    """
    owner: str = Field(..., description="Agent所有者")
    name: str = Field(..., description="Agent名称")
    public_key: str = Field(..., description="Agent公钥(PEM格式)")
    description: str = Field(..., description="Agent描述")
    timestamp: str = Field(..., description="申请时间戳")
    signature: str = Field(..., description="签名值")
    signature_encoding: str = Field(default="base64", description="签名编码格式")
    metadata: Metadata = Field(..., description="元数据")
    
    class Config:
        json_schema_extra = {
            "example": {
                "owner": "xxxxx",
                "name": "AliceAgent",
                "public_key": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...",
                "description": "AgentModel-X, SN123456",
                "timestamp": "1711185600",
                "signature": "xxxxxxx",
                "signature_encoding": "base64",
                "metadata": {
                    "region": "CN",
                    "os": "Linux",
                    "version": "1.0.0"
                }
            }
        }


class VC0Claims(BaseModel):
    """VC0证书声明模型."""
    agent_name: str = Field(..., description="Agent名称")
    agent_id: str = Field(..., description="Agent DID")
    agent_attribute: str = Field(
        default="运营商颁发，Agent与主UE的绑定关系，用于对外出示，审计确权",
        description="Agent属性描述"
    )
    master_id: str = Field(..., description="主UE身份标识")
    self_id: str = Field(..., description="Agent SIM卡标识")


class VC0Proof(BaseModel):
    """VC0证书证明模型."""
    creator: str = Field(..., description="签名者DID")
    signature_value: str = Field(..., description="签名值")


class VC0(BaseModel):
    """VC0证书模型.
    
    Attributes:
        context: 上下文
        id: VC唯一标识
        type: VC类型
        issuer: 颁发者DID
        valid_from: 生效时间
        valid_until: 过期时间
        claims: 声明内容
        proof: 证明信息
    """
    context: List[str] = Field(default=["3gpp-ts-33.xxx-v20.0.0"], description="上下文")
    id: str = Field(..., description="VC唯一标识")
    type: List[str] = Field(default=["VerifiableCredential", "BindingSIMCredential"], description="VC类型")
    issuer: str = Field(..., description="颁发者DID")
    valid_from: str = Field(..., description="生效时间")
    valid_until: str = Field(..., description="过期时间")
    claims: VC0Claims = Field(..., description="声明内容")
    proof: VC0Proof = Field(..., description="证明信息")


class PublicKeyJwk(BaseModel):
    """JWK公钥模型."""
    crv: str = Field(..., description="曲线类型")
    x: str = Field(..., description="公钥X坐标")
    kty: str = Field(..., description="密钥类型")
    kid: str = Field(..., description="密钥ID")


class VerificationKey(BaseModel):
    """验证密钥信息模型."""
    id: str = Field(..., description="密钥唯一标识")
    type: str = Field(default="JsonWebKey", description="密钥类型")
    controller: str = Field(..., description="控制器DID")
    publicKeyJwk: PublicKeyJwk = Field(..., description="JWK公钥信息")


class AgentProfile(BaseModel):
    """Agent Profile模型.
    
    Attributes:
        agent_id: Agent DID
        controller: 管理者UE身份
        verification_relationships: 验证密钥信息列表
        vc0: VC0证书
        vc0_authorization_mode: 授权模式
        vc_list: 已验证的VC列表（可选）
        created_at: 创建时间
        updated_at: 更新时间
    """
    agent_id: str = Field(..., description="Agent DID")
    controller: str = Field(..., description="管理者UE身份标识")
    verification_relationships: List[VerificationKey] = Field(..., description="验证密钥信息")
    vc0: VC0 = Field(..., description="VC0证书")
    vc0_authorization_mode: str = Field(default="Authorizationtemplate ID1", description="授权模式")
    vc_list: Optional[List[Dict[str, Any]]] = Field(default=None, description="已验证的VC列表")
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z", description="创建时间")
    updated_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z", description="更新时间")


class IdentityApplicationResponse(BaseModel):
    """身份申请响应模型.
    
    Attributes:
        result: 结果状态
        agent_id: Agent DID
        vc0: VC0证书
    """
    result: str = Field(..., description="结果状态")
    agent_id: str = Field(..., description="Agent DID")
    vc0: VC0 = Field(..., description="VC0证书")
    
    class Config:
        json_schema_extra = {
            "example": {
                "result": "success",
                "agent_id": "did:acn:z6Mki...",
                "vc0": {
                    "context": ["3gpp-ts-33.xxx-v20.0.0"],
                    "id": "CMCC/credentials/3732",
                    "type": ["VerifiableCredential", "BindingSIMCredential"],
                    "issuer": "did:udid:NewTypeOperator.rid678@6gc.mnc015.mcc234.3gppnetwork",
                    "valid_from": "2024-01-01T00:00:00Z",
                    "valid_until": "2025-01-01T00:00:00Z",
                    "claims": {
                        "agent_name": "Alice的个人助理",
                        "agent_id": "did:udid:NewType.rid678.schid0.userid30001@6gc.mnc015.mcc234.3gppnetwork",
                        "agent_attribute": "运营商颁发，Agent与主UE的绑定关系，用于对外出示，审计确权",
                        "master_id": "type0.rid678.schid0.userid1userid20001@6gc0001@6gc.mnc015.mcc234.3gppnetwork.org",
                        "self_id": "type0.rid678.schid0..mnc015.mcc234.3gppnetwork.org"
                    },
                    "proof": {
                        "creator": "did:udid:NewTypeOperator.rid678@6gc.mnc015.mcc234.3gppnetwork#keys-1",
                        "signature_value": "uill9900"
                    }
                }
            }
        }


class ErrorResponse(BaseModel):
    """错误响应模型."""
    error: str = Field(..., description="错误信息")
    detail: Optional[str] = Field(None, description="详细错误信息")


# ==================== 身份注销模型 ====================

class AgentDeletionRequest(BaseModel):
    """身份注销请求模型.
    
    Attributes:
        agent_id: 要注销的Agent DID
        reason: 注销原因
        timestamp: 注销时间戳（ISO 8601格式）
        signature: 签名值
        signature_encoding: 签名编码格式
    """
    agent_id: str = Field(..., description="要注销的Agent DID")
    reason: str = Field(..., description="注销原因，如'retired'")
    timestamp: str = Field(..., description="注销时间戳（ISO 8601格式）")
    signature: str = Field(..., description="签名值")
    signature_encoding: str = Field(default="base64", description="签名编码格式")
    
    class Config:
        json_schema_extra = {
            "example": {
                "agent_id": "did:acn:agent:987654321",
                "reason": "retired",
                "timestamp": "2024-03-23T12:00:00Z",
                "signature": "xxxxxxx",
                "signature_encoding": "base64"
            }
        }


class AgentDeletionResponse(BaseModel):
    """身份注销响应模型.
    
    Attributes:
        result: 处理结果
        agent_id: 被注销的Agent DID
        message: 详细信息
        forwarded_to_agent_gw: 是否成功转发给AgentGW
    """
    result: str = Field(..., description="处理结果，'success'表示成功")
    agent_id: str = Field(..., description="被注销的Agent DID")
    message: str = Field(..., description="详细信息")
    forwarded_to_agent_gw: bool = Field(default=False, description="是否成功转发给AgentGW")
    
    class Config:
        json_schema_extra = {
            "example": {
                "result": "success",
                "agent_id": "did:acn:agent:987654321",
                "message": "Agent profile and history deleted successfully",
                "forwarded_to_agent_gw": True
            }
        }


# ==================== VC校验模型 ====================

class VCClaims(BaseModel):
    """通用VC声明模型."""
    agent_name: Optional[str] = Field(None, description="Agent名称")
    agent_id: Optional[str] = Field(None, description="Agent DID")
    capability: Optional[str] = Field(None, description="能力描述")
    permissions: Optional[List[str]] = Field(None, description="权限列表")


class VCProof(BaseModel):
    """通用VC证明模型."""
    creator: str = Field(..., description="签名者DID")
    signature_value: str = Field(..., description="签名值")


class VC(BaseModel):
    """通用可验证凭证模型.
    
    用于VC校验接口，支持各种类型的VC。
    """
    context: List[str] = Field(..., description="上下文")
    id: str = Field(..., description="VC唯一标识")
    type: List[str] = Field(..., description="VC类型")
    issuer: str = Field(..., description="颁发者DID")
    valid_from: str = Field(..., description="生效时间（ISO 8601）")
    valid_until: str = Field(..., description="过期时间（ISO 8601）")
    claims: Dict[str, Any] = Field(..., description="声明内容")
    proof: VCProof = Field(..., description="证明信息")
    
    class Config:
        json_schema_extra = {
            "example": {
                "context": ["3gpp-ts-33.xxx-v20.0.0"],
                "id": "CMCC/credentials/3733",
                "type": ["VerifiableCredential", "CapabilityCredential"],
                "issuer": "did:udid:NewTypeOperator.rid678@6gc.mnc015.mcc234.3gppnetwork",
                "valid_from": "2024-01-01T00:00:00Z",
                "valid_until": "2025-01-01T00:00:00Z",
                "claims": {
                    "agent_name": "AliceAgent",
                    "agent_id": "did:acn:agent:987654321",
                    "capability": "surveillance",
                    "permissions": ["read", "write"]
                },
                "proof": {
                    "creator": "did:udid:NewTypeOperator.rid678@6gc.mnc015.mcc234.3gppnetwork#keys-1",
                    "signature_value": "xxxxxxx"
                }
            }
        }


class VCVerificationRequest(BaseModel):
    """VC校验请求模型.
    
    Attributes:
        agent_id: Agent DID
        vcs: 待校验的VC列表
    """
    agent_id: str = Field(..., description="Agent DID")
    vcs: List[VC] = Field(..., description="待校验的VC列表")
    
    class Config:
        json_schema_extra = {
            "example": {
                "agent_id": "did:acn:agent:987654321",
                "vcs": [
                    {
                        "context": ["3gpp-ts-33.xxx-v20.0.0"],
                        "id": "CMCC/credentials/3732",
                        "type": ["VerifiableCredential", "BindingSIMCredential"],
                        "issuer": "did:udid:NewTypeOperator.rid678@6gc.mnc015.mcc234.3gppnetwork",
                        "valid_from": "2024-01-01T00:00:00Z",
                        "valid_until": "2025-01-01T00:00:00Z",
                        "claims": {
                            "agent_name": "AliceAgent",
                            "agent_id": "did:acn:agent:987654321"
                        },
                        "proof": {
                            "creator": "did:udid:NewTypeOperator.rid678@6gc.mnc015.mcc234.3gppnetwork#keys-1",
                            "signature_value": "xxxxxxx"
                        }
                    }
                ]
            }
        }


class VCVerificationResponse(BaseModel):
    """VC校验响应模型.
    
    Attributes:
        valid: 校验是否全部通过
        vc_ids: 通过的VC ID列表
        invalid_vcs: 未通过的VC列表及原因（可选）
    """
    valid: bool = Field(..., description="校验是否全部通过")
    vc_ids: List[str] = Field(default=[], description="通过的VC ID列表")
    invalid_vcs: Optional[List[Dict[str, Any]]] = Field(None, description="未通过的VC及原因")
    
    class Config:
        json_schema_extra = {
            "example": {
                "valid": True,
                "vc_ids": [
                    "CMCC/credentials/3732",
                    "CMCC/credentials/3733",
                    "CMCC/credentials/3734"
                ],
                "invalid_vcs": None
            }
        }


class VCValidationResult(BaseModel):
    """单个VC校验结果模型.
    
    Attributes:
        vc_id: VC ID
        valid: 是否有效
        errors: 错误信息列表
    """
    vc_id: str = Field(..., description="VC ID")
    valid: bool = Field(..., description="是否有效")
    errors: List[str] = Field(default=[], description="错误信息列表")
