"""
Slack 平台诊断拒绝不完整或未经明确确认的工作区与机器人身份。
"""

from unittest.mock import Mock

import pytest


@pytest.mark.parametrize(("status", "payload"), [
    (302, {"ok": True, "team_id": "T1", "bot_id": "B1"}),
    (200, {"ok": False, "team_id": "T1", "bot_id": "B1"}),
    (200, {"ok": True, "user_id": "U1", "team_id": "T1"}),
    (200, {"ok": True, "bot_id": "B1", "enterprise_id": "E1"}),
    (200, {"ok": True, "team_id": "T1", "bot_id": "B1", "is_enterprise_install": True}),
])
def test_slack_claims_require_explicit_workspace_bot_and_success(monkeypatch, status, payload):
    """
    跳转、业务错误、企业安装或身份字段缺失均不能确认工作区机器人。
    """
    from app.modules.slack.slack import Slack

    http = Mock()
    response = Mock(status_code=status)
    response.json.return_value = payload
    http.return_value.post_res.return_value = response
    monkeypatch.setattr("app.modules.slack.slack.RequestUtils", http)

    assert Slack.probe_workspace_identity("xoxb-fixture") is None
    http.return_value.post_res.assert_called_once_with("https://slack.com/api/auth.test", allow_redirects=False)
    response.close.assert_called_once()
