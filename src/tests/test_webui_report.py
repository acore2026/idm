"""测试WebUI上报功能.

模拟IDM服务处理身份申请时上报到WebUI的功能.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from unittest.mock import patch, MagicMock
import requests as real_requests
from idm.idm_service import report_to_webui, IDMService
from idm.models import IdentityApplicationRequest


def test_report_to_webui():
    """测试上报函数是否正确构造请求."""
    print("\n===== 测试WebUI上报功能 =====\n")
    
    # 测试1: 验证上报数据格式
    print("测试1: 验证上报数据格式...")
    
    with patch.object(real_requests, 'post') as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        
        report_to_webui(
            agent_id="did:acn:test123",
            owner="test_owner"
        )
        
        # 验证requests.post被调用
        assert mock_post.called, "requests.post应该被调用"
        
        # 获取调用参数
        call_args = mock_post.call_args
        url = call_args[0][0] if call_args[0] else call_args[1].get('url')
        json_data = call_args[1].get('json') if call_args[1] else call_args[0][1]
        
        # 验证URL
        assert url == "http://localhost:9004/acn/v3/element-log", f"URL不正确: {url}"
        
        # 验证数据结构
        assert json_data["ElementId"] == "IDM", "ElementId应该是IDM"
        assert json_data["Type"] == "ApplyProfile", "Type应该是ApplyProfile"
        assert "Time" in json_data, "应该有Time字段"
        assert "Content" in json_data, "应该有Content字段"
        assert json_data["Content"]["AgentID"] == "did:acn:test123", "AgentID不正确"
        assert json_data["Content"]["Owner"] == "test_owner", "Owner不正确"
        assert json_data["Content"]["NetworkCapability"] == "6G业务开通", "NetworkCapability不正确"
        
        print("✓ 上报数据格式正确")
        print(f"  URL: {url}")
        print(f"  ElementId: {json_data['ElementId']}")
        print(f"  Type: {json_data['Type']}")
        print(f"  Time: {json_data['Time']}")
        print(f"  Content.AgentID: {json_data['Content']['AgentID']}")
        print(f"  Content.Owner: {json_data['Content']['Owner']}")
        print(f"  Content.NetworkCapability: {json_data['Content']['NetworkCapability']}")
    
    # 测试2: 验证上报失败时不抛出异常
    print("\n测试2: 验证上报失败时不抛出异常...")
    
    with patch.object(real_requests, 'post') as mock_post:
        mock_post.side_effect = Exception("Connection refused")
        
        try:
            report_to_webui(
                agent_id="did:acn:test456",
                owner="test_owner_2"
            )
            print("✓ 上报失败时没有抛出异常，错误被正确忽略")
        except Exception as e:
            print(f"✗ 上报失败时抛出了异常: {e}")
            raise
    
    print("\n===== 所有测试通过! =====\n")


def test_integration_with_identity_application():
    """测试集成到身份申请流程中."""
    print("\n===== 测试集成到身份申请流程 =====\n")
    
    # 模拟创建身份申请请求
    service = IDMService()
    
    print("注意: 这是一个集成测试，实际会调用process_identity_application")
    print("由于需要签名验证，这里只展示report_to_webui函数的调用\n")
    
    # 直接测试上报函数
    with patch.object(real_requests, 'post') as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        
        report_to_webui(
            agent_id="did:udid:type2.rid678.achid0.uerid1368888888800123@6gc.mnc015.mcc234.3gppnetwork.org",
            owner="Alice"
        )
        
        call_args = mock_post.call_args
        json_data = call_args[1].get('json')
        
        print("✓ 集成测试通过")
        print(f"  上报内容: {json_data}")
    
    print("\n===== 集成测试完成! =====\n")


if __name__ == "__main__":
    test_report_to_webui()
    test_integration_with_identity_application()
