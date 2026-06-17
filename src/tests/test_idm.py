"""IDM系统测试模块.

包含IDM服务的单元测试和集成测试。
"""

import json
import base64
import asyncio
import unittest
from unittest.mock import Mock, patch
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from idm.config import config
from idm.crypto import CryptoManager, crypto_manager
from idm.agent_id import AgentIDGenerator
from idm.vc_generator import VCGenerator
from idm.profile_manager import ProfileManager
from idm.idm_service import IDMService
from idm.models import IdentityApplicationRequest, Metadata, VCVerificationRequest
from idm.main import upload_certificate as upload_certificate_endpoint
from idm.main import delete_certificate as delete_certificate_endpoint
from idm.main import app
from idm.models import CertificateDeleteRequest


class TestCrypto(unittest.TestCase):
    """加密模块测试."""
    
    def setUp(self):
        """测试前准备."""
        self.crypto = crypto_manager
        
    def test_idm_key_generation(self):
        """测试IDM密钥生成."""
        self.assertIsNotNone(self.crypto._private_key)
        self.assertIsNotNone(self.crypto._public_key)
        self.assertTrue(config.IDM_KEY_PATH.exists())
        self.assertTrue(config.IDM_PUBLIC_KEY_PATH.exists())
        
    def test_sign_and_verify(self):
        """测试签名和验证."""
        # 生成测试密钥对
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        
        # 签名
        message = "test message"
        signature = private_key.sign(
            message.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        signature_b64 = base64.b64encode(signature).decode()
        
        # 验证
        result = self.crypto.verify_signature(
            public_key=public_key,
            message=message,
            signature=signature_b64,
            encoding="base64"
        )
        self.assertTrue(result)
        
    def test_invalid_signature(self):
        """测试无效签名."""
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        
        result = self.crypto.verify_signature(
            public_key=public_key,
            message="test",
            signature="invalid_signature",
            encoding="base64"
        )
        self.assertFalse(result)


class TestAgentID(unittest.TestCase):
    """Agent ID生成测试."""
    
    def test_generate_agent_id(self):
        """测试Agent ID生成."""
        owner = "13688888888"
        with patch("idm.agent_id.random.randint", side_effect=[10000, 10001]):
            agent_id = AgentIDGenerator.generate(owner)
            agent_id2 = AgentIDGenerator.generate(owner)
        
        # 验证格式
        self.assertTrue(agent_id.startswith("did:udid:type2.rid678.achid0.userid"))
        self.assertIn(owner, agent_id)
        self.assertTrue(agent_id.endswith("@6gc.mnc015.mcc234.3gppnetwork.org"))
        
        # 验证唯一性（不同随机后缀）
        self.assertNotEqual(agent_id, agent_id2)
        
    def test_agent_id_length(self):
        """测试UDID中的userid长度."""
        owner = "13688888888"
        with patch("idm.agent_id.random.randint", return_value=12345):
            agent_id = AgentIDGenerator.generate(owner)

        userid = agent_id.split("userid", 1)[1].split("@", 1)[0]
        self.assertEqual(userid, f"{owner}12345")
        self.assertEqual(len(userid), 16)
        
    def test_udid_format(self):
        """测试UDID格式."""
        owner = "13688888888"
        udid = AgentIDGenerator.generate_udid_format("TestAgent", owner)
        self.assertTrue(udid.startswith("did:udid:"))
        self.assertIn("type2.rid678.achid0.userid", udid)
        self.assertIn(owner, udid)
        self.assertTrue(udid.endswith("@6gc.mnc015.mcc234.3gppnetwork.org"))
        
    def test_udid_format_with_phone_number(self):
        """测试UDID格式包含电话号码和随机数."""
        owner = "13688888888"
        udid1 = AgentIDGenerator.generate_udid_format("TestAgent", owner)
        udid2 = AgentIDGenerator.generate_udid_format("TestAgent", owner)
        
        # 验证基本格式
        self.assertTrue(udid1.startswith("did:udid:type2.rid678.achid0.userid"))
        self.assertTrue(udid2.startswith("did:udid:type2.rid678.achid0.userid"))
        
        # 验证包含电话号码前缀
        self.assertIn(owner, udid1)
        self.assertIn(owner, udid2)
        
        # 验证两个ID不同（因为随机数不同）
        self.assertNotEqual(udid1, udid2)
        
        # 验证格式正确性: did:udid:type2.rid678.achid0.userid<电话号码+5位随机数>@6gc.mnc015.mcc234.3gppnetwork.org
        # 电话号码11位 + 随机数5位 = 16位
        import re
        pattern = r"^did:udid:type2\.rid678\.achid0\.userid\d{16}@6gc\.mnc015\.mcc234\.3gppnetwork\.org$"
        self.assertRegex(udid1, pattern)
        self.assertRegex(udid2, pattern)
        
        # 打印生成的UDID供检查
        print(f"\nGenerated UDID 1: {udid1}")
        print(f"Generated UDID 2: {udid2}")


class TestVCGenerator(unittest.TestCase):
    """VC0生成测试."""
    
    def test_generate_vc0(self):
        """测试VC0生成."""
        vc0 = VCGenerator.generate_vc0(
            agent_name="TestAgent",
            agent_id="did:test:123",
            master_id="type0.test.master",
            self_id="type0.test.self"
        )
        
        self.assertEqual(vc0.claims.agent_name, "TestAgent")
        self.assertEqual(vc0.issuer, config.IDM_DID)
        self.assertEqual(vc0.type, ["VerifiableCredential", "BindingSIMCredential"])
        self.assertIsNotNone(vc0.proof.signature_value)
        
    def test_vc0_validity(self):
        """测试VC0有效期."""
        from datetime import datetime
        
        vc0 = VCGenerator.generate_vc0(
            agent_name="TestAgent",
            agent_id="did:test:123",
            master_id="type0.test.master",
            self_id="type0.test.self",
            valid_years=1
        )
        
        valid_from = datetime.fromisoformat(vc0.valid_from.replace("Z", "+00:00"))
        valid_until = datetime.fromisoformat(vc0.valid_until.replace("Z", "+00:00"))
        
        # 验证有效期为1年
        diff = valid_until - valid_from
        self.assertGreater(diff.days, 360)  # 约1年


class TestProfileManager(unittest.TestCase):
    """Profile管理测试."""
    
    def setUp(self):
        """测试前准备."""
        config.ensure_directories()
        
    def test_create_and_load_profile(self):
        """测试创建和加载Profile."""
        # 创建测试VC0
        vc0 = VCGenerator.generate_vc0(
            agent_name="TestAgent",
            agent_id="did:test:123",
            master_id="type0.test.master",
            self_id="type0.test.self"
        )
        
        # 创建Profile
        profile = ProfileManager.create_profile(
            agent_id="did:test:123",
            public_key_pem="test_key",
            vc0=vc0
        )
        
        self.assertEqual(profile.agent_id, "did:test:123")
        self.assertIsNotNone(profile.verification_relationships)
        
        # 加载Profile
        loaded = ProfileManager.load_profile("did:test:123")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.agent_id, profile.agent_id)
        
    def test_list_profiles(self):
        """测试列出Profiles."""
        profiles = ProfileManager.list_profiles()
        self.assertIsInstance(profiles, list)


class TestIDMService(unittest.TestCase):
    """IDM服务集成测试."""
    
    def setUp(self):
        """测试前准备."""
        self.service = IDMService()
        
        # 生成测试密钥对
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        
        # 导出公钥PEM
        self.public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
    def _sign_message(self, message: str) -> str:
        """辅助方法：签名消息."""
        signature = self.private_key.sign(
            message.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        return base64.b64encode(signature).decode()
        
    def test_process_valid_application(self):
        """测试处理有效申请."""
        timestamp = str(int(datetime.now().timestamp()))
        message = timestamp
        signature = self._sign_message(message)
        
        request = IdentityApplicationRequest(
            owner="test_owner",
            name="TestAgent",
            public_key=self.public_key_pem,
            description="Test agent",
            timestamp=timestamp,
            signature=signature,
            metadata=Metadata(region="CN", os="Linux", version="1.0.0")
        )
        
        response = self.service.process_identity_application(request)
        
        self.assertEqual(response.result, "success")
        self.assertTrue(response.agent_id.startswith("did:udid:"))
        self.assertIsNotNone(response.vc0)
        
    def test_process_invalid_signature(self):
        """测试处理无效签名."""
        request = IdentityApplicationRequest(
            owner="test_owner",
            name="TestAgent",
            public_key=self.public_key_pem,
            description="Test agent",
            timestamp=str(int(datetime.now().timestamp())),
            signature="invalid_signature",
            metadata=Metadata(region="CN", os="Linux", version="1.0.0")
        )
        
        with self.assertRaises(ValueError) as context:
            self.service.process_identity_application(request)
            
        self.assertIn("Signature", str(context.exception))


class MockACNAgent:
    """模拟ACN Agent用于测试."""
    
    def __init__(self):
        """初始化模拟Agent."""
        # 生成密钥对
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        
        # 导出公钥PEM
        self.public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        # 用于存储申请的Agent ID
        self.agent_id = None
        
    def create_application_request(
        self,
        owner: str = "Alice",
        name: str = "AliceAgent",
        description: str = "Alice's personal assistant"
    ) -> dict:
        """创建身份申请请求.
        
        Args:
            owner: 所有者
            name: Agent名称
            description: 描述
            
        Returns:
            申请请求字典
        """
        timestamp = str(int(datetime.now().timestamp()))
        
        # 构造签名消息（仅对时间戳签名，与服务端一致）
        message = timestamp
        
        # 签名
        signature = self.private_key.sign(
            message.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        signature_b64 = base64.b64encode(signature).decode()
        
        return {
            "owner": owner,
            "name": name,
            "public_key": self.public_key_pem,
            "description": description,
            "timestamp": timestamp,
            "signature": signature_b64,
            "signature_encoding": "base64",
            "metadata": {
                "region": "CN",
                "os": "Linux",
                "version": "1.0.0"
            }
        }
    
    def create_deletion_request(self, agent_id: str, reason: str = "retired") -> dict:
        """创建身份注销请求.
        
        Args:
            agent_id: Agent DID
            reason: 注销原因
            
        Returns:
            注销请求字典
        """
        from datetime import datetime
        timestamp = datetime.utcnow().isoformat() + "Z"
        
        # 构造签名消息（仅对时间戳签名，与服务端一致）
        message = timestamp
        
        # 签名
        signature = self.private_key.sign(
            message.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        signature_b64 = base64.b64encode(signature).decode()
        
        return {
            "agent_id": agent_id,
            "reason": reason,
            "timestamp": timestamp,
            "signature": signature_b64,
            "signature_encoding": "base64"
        }


def run_mock_test():
    """运行模拟Agent测试."""
    print("\n" + "=" * 60)
    print("Running Mock ACN Agent Test")
    print("=" * 60)
    
    # 创建模拟Agent
    agent = MockACNAgent()
    
    # 创建申请请求
    request_data = agent.create_application_request()
    
    print("\nRequest Data:")
    print(json.dumps(request_data, indent=2, ensure_ascii=False))
    
    # 转换为模型对象
    request = IdentityApplicationRequest(**request_data)
    
    # 调用IDM服务
    service = IDMService()
    
    try:
        response = service.process_identity_application(request)
        
        print("\nResponse Data:")
        print(json.dumps(response.model_dump(), indent=2, ensure_ascii=False))
        
        print("\n" + "=" * 60)
        print("Test PASSED!")
        print("=" * 60)
        
    except Exception as e:
        print(f"\nTest FAILED: {e}")
        raise


class TestAgentDeletion(unittest.TestCase):
    """身份注销功能测试."""
    
    def setUp(self):
        """测试前准备."""
        self.service = IDMService()
        self.agent = MockACNAgent()
        
        # 先创建一个Agent
        request_data = self.agent.create_application_request()
        request = IdentityApplicationRequest(**request_data)
        response = self.service.process_identity_application(request)
        # Profile使用response中的agent_id（did:acn格式）存储
        self.agent_id = response.agent_id
        
    def test_delete_agent_success(self):
        """测试成功注销Agent."""
        from idm.models import AgentDeletionRequest
        import importlib
        from unittest.mock import patch

        idm_service_module = importlib.import_module("idm.idm_service")
        mock_httpx = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "result": "success",
            "message": "AgentGW deletion acknowledged"
        }
        mock_httpx.post.return_value = mock_response

        # 创建注销请求（使用Profile中存储的UDID格式ID）
        deletion_data = self.agent.create_deletion_request(self.agent_id, "retired")
        deletion_request = AgentDeletionRequest(**deletion_data)

        with patch.object(idm_service_module, "httpx", mock_httpx):
            response = self.service.delete_agent_identity(deletion_request)

        # 验证结果
        self.assertEqual(response.result, "success")
        self.assertEqual(response.agent_id, self.agent_id)
        self.assertTrue(response.forwarded_to_agent_gw)
        self.assertIsNotNone(response.agent_gw_response)
        self.assertTrue(response.agent_gw_response.success)
        
    def test_delete_agent_forwards_gateway_response(self):
        """测试注销请求会携带 Agent GW 的响应返回."""
        from idm.models import AgentDeletionRequest
        import importlib
        from unittest.mock import patch

        idm_service_module = importlib.import_module("idm.idm_service")
        mock_httpx = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "result": "success",
            "message": "AgentGW deletion acknowledged"
        }
        mock_httpx.post.return_value = mock_response

        deletion_data = self.agent.create_deletion_request(self.agent_id, "retired")
        deletion_request = AgentDeletionRequest(**deletion_data)

        with patch.object(idm_service_module, "httpx", mock_httpx):
            response = self.service.delete_agent_identity(deletion_request)

        self.assertEqual(response.result, "success")
        self.assertEqual(response.agent_id, self.agent_id)
        self.assertTrue(response.forwarded_to_agent_gw)
        self.assertIsNotNone(response.agent_gw_response)
        self.assertTrue(response.agent_gw_response.success)
        self.assertEqual(response.agent_gw_response.status_code, 200)
        self.assertEqual(response.agent_gw_response.body, {
            "result": "success",
            "message": "AgentGW deletion acknowledged"
        })
        self.assertEqual(response.message, "AgentGW deletion acknowledged")
        
    def test_delete_nonexistent_agent(self):
        """测试注销不存在的Agent."""
        from idm.models import AgentDeletionRequest
        
        # 创建注销请求（使用不存在的Agent ID）
        deletion_data = {
            "agent_id": "did:acn:nonexistent",
            "reason": "retired",
            "timestamp": "2024-03-23T12:00:00Z",
            "signature": "dummy_signature",
            "signature_encoding": "base64"
        }
        deletion_request = AgentDeletionRequest(**deletion_data)
        
        # 应该抛出异常
        with self.assertRaises(ValueError):
            self.service.delete_agent_identity(deletion_request)


class TestVCVerification(unittest.TestCase):
    """VC校验功能测试."""
    
    def setUp(self):
        """测试前准备."""
        self.service = IDMService()
        self.agent = MockACNAgent()
        
        # 先创建一个Agent
        request_data = self.agent.create_application_request()
        request = IdentityApplicationRequest(**request_data)
        response = self.service.process_identity_application(request)
        # Profile使用response中的agent_id（did:acn格式）存储
        self.agent_id = response.agent_id

    def _build_signed_idm_vc(self, vc_id: str, valid_from: str, valid_until: str):
        from idm.models import VC

        vc_data = {
            "context": ["3gpp-ts-33.xxx-v20.0.0"],
            "id": vc_id,
            "type": ["VerifiableCredential", "TestCredential"],
            "issuer": config.IDM_DID,
            "valid_from": valid_from,
            "valid_until": valid_until,
            "claims": {
                "agent_id": self.agent_id,
                "agent_attribute": "6G业务开通"
            }
        }
        signature = crypto_manager.sign_vc(vc_data)
        return VC(
            **vc_data,
            proof={
                "creator": crypto_manager.idm_key_id,
                "signature_value": signature
            }
        )
        
    def test_verify_valid_vcs(self):
        """测试校验有效的VC."""
        from idm.models import VCVerificationRequest
        from datetime import datetime, timedelta
        
        # 创建有效的VC
        vc = self._build_signed_idm_vc(
            vc_id="CMCC/credentials/TEST001",
            valid_from=(datetime.utcnow() - timedelta(days=1)).isoformat() + "Z",
            valid_until=(datetime.utcnow() + timedelta(days=365)).isoformat() + "Z"
        )
        
        # 创建校验请求
        request = VCVerificationRequest(
            agent_id=self.agent_id,
            vc_list=[vc]
        )
        
        # 执行校验
        response = self.service.verify_vcs(request)
        
        # 验证结果
        self.assertTrue(response.valid)
        self.assertIn("CMCC/credentials/TEST001", response.vc_ids)
        
    def test_verify_expired_vc(self):
        """测试校验已过期的VC."""
        from idm.models import VCVerificationRequest
        from datetime import datetime, timedelta
        
        # 创建已过期的VC
        vc = self._build_signed_idm_vc(
            vc_id="CMCC/credentials/EXPIRED001",
            valid_from=(datetime.utcnow() - timedelta(days=365)).isoformat() + "Z",
            valid_until=(datetime.utcnow() - timedelta(days=1)).isoformat() + "Z"
        )
        
        # 创建校验请求
        request = VCVerificationRequest(
            agent_id=self.agent_id,
            vc_list=[vc]
        )
        
        # 执行校验
        response = self.service.verify_vcs(request)
        
        # 验证结果 - 应该无效
        self.assertFalse(response.valid)
        self.assertNotIn("CMCC/credentials/EXPIRED001", response.vc_ids)

    def test_verify_generated_vc0(self):
        """测试 IDM 生成的 VC0 可以通过验签."""
        request_data = self.agent.create_application_request(owner="Bob", name="BobAgent")
        request = IdentityApplicationRequest(**request_data)
        response = self.service.process_identity_application(request)

        vc0_request = VCVerificationRequest(
            agent_id=response.agent_id,
            vc_list=[response.vc0.model_dump()]
        )

        verification_response = self.service.verify_vcs(vc0_request)
        self.assertTrue(verification_response.valid)
        self.assertIn(response.vc0.id, verification_response.vc_ids)

    def test_migrated_huawei_vc_sample_rejects_old_signature(self):
        """测试迁移为 userid 后，旧 Huawei VC 样例签名会失效."""
        from idm.models import VCVerificationRequest

        sample_agent_id = "did:udid:type2.rid678.achid0.userid1380013800028185@6gc.mnc015.mcc234.3gppnetwork.org"
        sample_profile = ProfileManager.load_profile(self.agent_id)
        self.assertIsNotNone(sample_profile)
        sample_profile.agent_id = sample_agent_id
        ProfileManager.save_profile(sample_profile)

        request = VCVerificationRequest(
            agent_id=sample_agent_id,
            vc_list=[
                {
                    "context": ["3gpp-ts-33.xxx-v20.0.0"],
                    "id": "huawei/credentials/3385",
                    "type": ["VerifiableCredential", "BindingSIMCredential"],
                    "issuer": "did:huaweiissuer@6gc.mnc015.mcc234.3gppnetwork",
                    "valid_from": "2026-04-23T07:07:25.072836+00:00",
                    "valid_until": "2027-04-24T07:07:25.072836+00:00",
                    "claims": {
                        "agent_name": "AliceAgent",
                        "agent_id": "did:udid:type2.rid678.achid0.userid1380013800028185@6gc.mnc015.mcc234.3gppnetwork.org",
                        "agent_attribute": "可疑人员识别",
                        "authorization_mode": "Mode2",
                    },
                    "proof": {
                        "creator": "did:huaweiissuer@6gc.mnc015.mcc234.3gppnetwork#keys-1",
                        "signature_value": "MEYCIQCiXVzN0ocUZT1XHRrTO3vTjvis8/pt+FK0RtXted1c+wIhAMjkBjEpkkg1y7qkJYMrXn2OudpMGaOnH6EbTab85Jlj",
                    },
                }
            ],
        )

        response = self.service.verify_vcs(request)

        self.assertFalse(response.valid)
        self.assertNotIn("huawei/credentials/3385", response.vc_ids)
        self.assertEqual(response.invalid_vcs[0]["vc_id"], "huawei/credentials/3385")
        self.assertIn("Invalid signature", response.invalid_vcs[0]["errors"])

    def test_verify_external_vc_signed_with_ascii_json_rule(self):
        """测试外部机构按 sort_keys+compact+ASCII 规则签名的 VC 可以通过验签."""
        from idm.models import VC

        private_key = ec.generate_private_key(ec.SECP256R1())
        certificate = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Huawei")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Huawei")]))
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow().replace(year=datetime.utcnow().year + 1))
            .sign(private_key, hashes.SHA256())
        )

        cert_path = config.CERTS_DIR / "Huawei_cert.crt"
        original_cert = cert_path.read_bytes() if cert_path.exists() else None
        cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))

        try:
            vc_data = {
                "context": ["3gpp-ts-33.xxx-v20.0.0"],
                "id": "huawei/credentials/ASCII001",
                "type": ["VerifiableCredential", "BindingSIMCredential"],
                "issuer": "did:huaweiissuer@6gc.mnc015.mcc234.3gppnetwork",
                "valid_from": "2026-04-23T07:07:25.072836+00:00",
                "valid_until": "2027-04-24T07:07:25.072836+00:00",
                "claims": {
                    "agent_name": "AliceAgent",
                    "agent_id": self.agent_id,
                    "agent_attribute": "可疑人员识别",
                    "authorization_mode": "Mode2",
                },
            }
            message = json.dumps(
                vc_data,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            signature = base64.b64encode(
                private_key.sign(message, ec.ECDSA(hashes.SHA256()))
            ).decode()

            vc = VC(
                **vc_data,
                proof={
                    "creator": "did:huaweiissuer@6gc.mnc015.mcc234.3gppnetwork#keys-1",
                    "signature_value": signature,
                }
            )

            response = self.service.verify_vcs(
                VCVerificationRequest(agent_id=self.agent_id, vc_list=[vc])
            )

            self.assertTrue(response.valid)
            self.assertEqual(response.vc_ids, ["huawei/credentials/ASCII001"])
        finally:
            if original_cert is None:
                cert_path.unlink(missing_ok=True)
            else:
                cert_path.write_bytes(original_cert)


class TestCertificateUploadAndVerification(unittest.TestCase):
    """第三方证书上传、删除和 VC 校验联调测试."""

    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.temp_root = Path(self.temp_dir.name)

        config_cls = type(config)
        self.original_profiles_dir = config_cls.PROFILES_DIR
        self.original_logs_dir = config_cls.LOGS_DIR
        self.original_certs_dir = config_cls.CERTS_DIR
        self.original_registry_path = config_cls.CERT_REGISTRY_PATH

        config_cls.PROFILES_DIR = self.temp_root / "profiles"
        config_cls.LOGS_DIR = self.temp_root / "logs"
        config_cls.CERTS_DIR = self.temp_root / "certs"
        config_cls.CERT_REGISTRY_PATH = config_cls.CERTS_DIR / "uploaded_cert_registry.json"
        config.ensure_directories()

        self.service = IDMService()
        self.agent = MockACNAgent()
        self.agent_id = self._create_agent()

    def tearDown(self):
        config_cls = type(config)
        config_cls.PROFILES_DIR = self.original_profiles_dir
        config_cls.LOGS_DIR = self.original_logs_dir
        config_cls.CERTS_DIR = self.original_certs_dir
        config_cls.CERT_REGISTRY_PATH = self.original_registry_path
        self.temp_dir.cleanup()

    def _create_agent(self) -> str:
        request_data = self.agent.create_application_request()
        request = IdentityApplicationRequest(**request_data)
        response = self.service.process_identity_application(request)
        return response.agent_id

    def _build_external_cert_and_vc(self, cert_name: str):
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Robot Factory Test")
        ])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow().replace(year=datetime.utcnow().year + 1))
            .sign(private_key, hashes.SHA256())
        )
        cert_bytes = certificate.public_bytes(serialization.Encoding.PEM)

        from datetime import timedelta

        vc_payload = {
            "context": ["3gpp-ts-33.xxx-v20.0.0"],
            "id": "ThirdParty/credentials/ROBOT001",
            "type": ["VerifiableCredential", "CapabilityCredential"],
            "issuer": "did:robotfactoryissuer:test",
            "valid_from": (datetime.utcnow() - timedelta(days=1)).isoformat() + "Z",
            "valid_until": (datetime.utcnow() + timedelta(days=365)).isoformat() + "Z",
            "claims": {
                "agent_id": self.agent_id,
                "capability": "robot-control"
            }
        }
        message = json.dumps(vc_payload, sort_keys=True, separators=(",", ":"))
        signature = private_key.sign(
            message.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        vc_payload["proof"] = {
            "creator": "did:robotfactoryissuer:test#keys-1",
            "signature_value": base64.b64encode(signature).decode()
        }

        return cert_bytes, cert_name, vc_payload

    def _make_upload_file(self, filename: str, payload: bytes):
        class FakeUploadFile:
            def __init__(self, name: str, content: bytes):
                self.filename = name
                self._content = content

            async def read(self):
                return self._content

        return FakeUploadFile(filename, payload)

    def test_upload_delete_and_vc_verification_flow(self):
        cert_id = "cert-13478187"
        cert_bytes, cert_name, vc_payload = self._build_external_cert_and_vc(
            "Robot_Factory_Cert.crt"
        )

        verify_request = {
            "agent_id": self.agent_id,
            "vc_list": [vc_payload]
        }

        missing_cert_response = self.service.verify_vcs(
            VCVerificationRequest(**verify_request)
        )
        self.assertFalse(missing_cert_response.valid)
        self.assertIn(
            "Could not load public key for issuer: did:robotfactoryissuer:test",
            missing_cert_response.invalid_vcs[0]["errors"]
        )

        cert_path = self.service.upload_certificate(cert_id, cert_name, cert_bytes)
        self.assertTrue(cert_path.exists())
        self.assertTrue((config.CERTS_DIR / cert_name).exists())

        verified_response = self.service.verify_vcs(
            VCVerificationRequest(**verify_request)
        )
        self.assertTrue(verified_response.valid)
        self.assertIn(vc_payload["id"], verified_response.vc_ids)

        deleted_path = self.service.delete_certificate(cert_id, cert_name)
        self.assertEqual(deleted_path, config.CERTS_DIR / cert_name)
        self.assertFalse((config.CERTS_DIR / cert_name).exists())

        deleted_verify_response = self.service.verify_vcs(
            VCVerificationRequest(**verify_request)
        )
        self.assertFalse(deleted_verify_response.valid)

    def test_certificate_endpoints_smoke(self):
        cert_id = "cert-endpoint-001"
        cert_bytes, cert_name, _ = self._build_external_cert_and_vc("Huawei_cert.crt")

        upload_response = asyncio.run(
            upload_certificate_endpoint(
                file=self._make_upload_file(cert_name, cert_bytes),
                certID=cert_id,
                certName=cert_name,
            )
        )
        self.assertEqual(upload_response.status, "ok")
        self.assertEqual(upload_response.certID, cert_id)
        self.assertTrue((config.CERTS_DIR / cert_name).exists())

        delete_response = asyncio.run(
            delete_certificate_endpoint(
                CertificateDeleteRequest(certID=cert_id, certName=cert_name)
            )
        )
        self.assertEqual(delete_response.status, "ok")
        self.assertFalse((config.CERTS_DIR / cert_name).exists())

    def test_certificate_routes_registered(self):
        route_map = {
            (method, route.path)
            for route in app.routes
            for method in (route.methods or set())
        }
        self.assertIn(("POST", "/idm/v1/cert-upload"), route_map)
        self.assertIn(("POST", "/idm/v1/cert-delete"), route_map)


def run_deletion_test():
    """运行身份注销测试."""
    print("\n" + "=" * 60)
    print("Running Agent Deletion Test")
    print("=" * 60)
    
    # 创建模拟Agent
    agent = MockACNAgent()
    service = IDMService()
    
    # 先申请身份
    print("\nStep 1: Applying for identity...")
    request_data = agent.create_application_request()
    from idm.models import IdentityApplicationRequest
    request = IdentityApplicationRequest(**request_data)
    response = service.process_identity_application(request)
    # Profile使用response中的agent_id（did:acn格式）存储
    agent_id = response.agent_id
    print(f"Agent created: {agent_id}")
    
    # 然后注销身份
    print("\nStep 2: Deleting agent identity...")
    deletion_data = agent.create_deletion_request(agent_id, "retired")
    from idm.models import AgentDeletionRequest
    deletion_request = AgentDeletionRequest(**deletion_data)
    
    try:
        deletion_response = service.delete_agent_identity(deletion_request)
        print(f"\nDeletion Response:")
        print(json.dumps(deletion_response.model_dump(), indent=2, ensure_ascii=False))
        print("\n" + "=" * 60)
        print("Deletion Test PASSED!")
        print("=" * 60)
    except Exception as e:
        print(f"\nDeletion Test FAILED: {e}")
        raise


def run_vc_verification_test():
    """运行VC校验测试."""
    print("\n" + "=" * 60)
    print("Running VC Verification Test")
    print("=" * 60)
    
    # 创建模拟Agent
    agent = MockACNAgent()
    service = IDMService()
    
    # 先申请身份
    print("\nStep 1: Applying for identity...")
    request_data = agent.create_application_request()
    from idm.models import IdentityApplicationRequest, VCVerificationRequest, VC
    from datetime import datetime, timedelta
    
    request = IdentityApplicationRequest(**request_data)
    response = service.process_identity_application(request)
    # Profile使用response中的agent_id（did:acn格式）存储
    agent_id = response.agent_id
    print(f"Agent created: {agent_id}")
    
    # 创建VC校验请求
    print("\nStep 2: Verifying VC...")
    vc = VC(
        context=["3gpp-ts-33.xxx-v20.0.0"],
        id="CMCC/credentials/TEST001",
        type=["VerifiableCredential", "CapabilityCredential"],
        issuer="did:udid:idm@6gc.mnc015.mcc234.3gppnetwork.org",
        valid_from=(datetime.utcnow() - timedelta(days=1)).isoformat() + "Z",
        valid_until=(datetime.utcnow() + timedelta(days=365)).isoformat() + "Z",
        claims={"agent_id": agent_id, "capability": "surveillance"},
        proof={
            "creator": "did:udid:idm@6gc.mnc015.mcc234.3gppnetwork.org#keys-1",
            "signature_value": "dummy_signature"
        }
    )
    
    vc_request = VCVerificationRequest(
        agent_id=agent_id,
        vc_list=[vc]
    )
    
    try:
        vc_response = service.verify_vcs(vc_request)
        print(f"\nVC Verification Response:")
        print(json.dumps(vc_response.model_dump(), indent=2, ensure_ascii=False))
        print("\n" + "=" * 60)
        print("VC Verification Test PASSED!")
        print("=" * 60)
    except Exception as e:
        print(f"\nVC Verification Test FAILED: {e}")
        raise


if __name__ == "__main__":
    # 运行模拟测试
    run_mock_test()
    
    # 运行身份注销测试
    run_deletion_test()
    
    # 运行VC校验测试
    run_vc_verification_test()
    
    # 运行单元测试
    print("\n" + "=" * 60)
    print("Running Unit Tests")
    print("=" * 60 + "\n")
    unittest.main(verbosity=2)
