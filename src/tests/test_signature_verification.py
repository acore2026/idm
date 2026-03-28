"""验证签名测试模块.

用于验证特定请求的签名有效性。
"""

import base64
import json
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.exceptions import InvalidSignature


def verify_ecdsa_signature(
    public_key_pem: str,
    message: str,
    signature_b64: str,
    signature_encoding: str = "base64"
) -> bool:
    """验证ECDSA签名.
    
    Args:
        public_key_pem: EC公钥PEM格式
        message: 原始消息
        signature_b64: Base64编码的签名
        signature_encoding: 签名编码格式
        
    Returns:
        签名是否有效
    """
    try:
        # 加载EC公钥
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        
        # 解码签名
        if signature_encoding == "base64":
            signature_bytes = base64.b64decode(signature_b64)
        else:
            signature_bytes = signature_b64.encode()
        
        # 验证签名 (ECDSA使用SHA256)
        public_key.verify(
            signature_bytes,
            message.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        print("✓ 签名验证通过")
        return True
        
    except InvalidSignature:
        print("✗ 签名验证失败: 签名无效")
        return False
    except Exception as e:
        print(f"✗ 签名验证错误: {e}")
        return False


def test_signature_verification():
    """测试提供的签名验证."""
    
    print("=" * 60)
    print("签名验证测试")
    print("=" * 60)
    
    # 请求数据
    body = {
        "owner": "13800138000",
        "name": "AliceAgent",
        "public_key": """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExdwJJPdZPiMUjMyleUmQpFwkLkdB
zX03ndMHZ/OAKgamjS4wVyO3r5QjZQMCIaGm2AnOCSvPvZndbXSvqZjaHA==
-----END PUBLIC KEY-----
""",
        "description": "AgentModel-X, SN123456",
        "timestamp": "2026-03-27T14:27:53Z",
        "metadata": {
            "region": "CN",
            "os": "Linux",
            "version": "1.0.0"
        },
        "signature": "MEUCIAei1fnvcljH2ST33qh3IvPZ92LO0H+/Ck/TOD20twguAiEAlqQOQSxwedSuxZ6Gr4ddi/cFEAps1Mxp64bxfw2Wlh4=",
        "signature_encoding": "base64"
    }
    
    print("\n【步骤 1】解析请求数据")
    print(f"  所有者: {body['owner']}")
    print(f"  Agent名称: {body['name']}")
    print(f"  描述: {body['description']}")
    print(f"  时间戳: {body['timestamp']}")
    print(f"  签名编码: {body['signature_encoding']}")
    
    print("\n【步骤 2】加载公钥")
    try:
        public_key = serialization.load_pem_public_key(
            body['public_key'].encode()
        )
        key_type = type(public_key).__name__
        print(f"  公钥类型: {key_type}")
        print(f"  公钥曲线: {public_key.curve.name}")
        print("  ✓ 公钥加载成功")
    except Exception as e:
        print(f"  ✗ 公钥加载失败: {e}")
        return
    
    print("\n【步骤 3】构造待验证消息")
    # 根据idm_service.py的验证逻辑，消息就是timestamp
    message_to_verify = body['timestamp']
    print(f"  待验证消息: {message_to_verify}")
    
    print("\n【步骤 4】解码签名")
    try:
        signature_bytes = base64.b64decode(body['signature'])
        print(f"  签名长度: {len(signature_bytes)} bytes")
        print("  ✓ 签名解码成功")
    except Exception as e:
        print(f"  ✗ 签名解码失败: {e}")
        return
    
    print("\n【步骤 5】验证签名")
    try:
        public_key.verify(
            signature_bytes,
            message_to_verify.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        print("  ✓ 签名验证成功!")
        result = True
    except InvalidSignature:
        print("  ✗ 签名无效")
        result = False
    except Exception as e:
        print(f"  ✗ 验证错误: {e}")
        result = False
    
    print("\n" + "=" * 60)
    if result:
        print("测试结果: PASSED")
    else:
        print("测试结果: FAILED")
    print("=" * 60)
    
    return result


def test_with_different_message_formats():
    """尝试不同的消息格式验证."""
    
    print("\n" + "=" * 60)
    print("尝试不同的消息构造方式")
    print("=" * 60)
    
    body = {
        "owner": "13800138000",
        "name": "AliceAgent",
        "public_key": """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExdwJJPdZPiMUjMyleUmQpFwkLkdB
zX03ndMHZ/OAKgamjS4wVyO3r5QjZQMCIaGm2AnOCSvPvZndbXSvqZjaHA==
-----END PUBLIC KEY-----
""",
        "timestamp": "2026-03-27T14:27:53Z",
        "signature": "MEUCIAei1fnvcljH2ST33qh3IvPZ92LO0H+/Ck/TOD20twguAiEAlqQOQSxwedSuxZ6Gr4ddi/cFEAps1Mxp64bxfw2Wlh4=",
    }
    
    public_key = serialization.load_pem_public_key(
        body['public_key'].encode()
    )
    signature_bytes = base64.b64decode(body['signature'])
    
    # 尝试不同的消息格式
    message_formats = [
        ("仅时间戳", body['timestamp']),
        ("owner:name:timestamp", f"{body['owner']}:{body['name']}:{body['timestamp']}"),
        ("timestamp:name:owner", f"{body['timestamp']}:{body['name']}:{body['owner']}"),
        ("JSON完整body", json.dumps(body, sort_keys=True, ensure_ascii=False)),
        ("name:owner:timestamp", f"{body['name']}:{body['owner']}:{body['timestamp']}"),
        ("owner|name|timestamp", f"{body['owner']}|{body['name']}|{body['timestamp']}"),
    ]
    
    for format_name, message in message_formats:
        print(f"\n尝试格式: {format_name}")
        print(f"  消息内容: {message[:80]}..." if len(message) > 80 else f"  消息内容: {message}")
        try:
            public_key.verify(
                signature_bytes,
                message.encode(),
                ec.ECDSA(hashes.SHA256())
            )
            print(f"  ✓ 匹配成功!")
        except InvalidSignature:
            print(f"  ✗ 不匹配")
        except Exception as e:
            print(f"  ✗ 错误: {e}")


if __name__ == "__main__":
    # 运行主测试
    test_signature_verification()
    
    # 尝试其他消息格式
    test_with_different_message_formats()
