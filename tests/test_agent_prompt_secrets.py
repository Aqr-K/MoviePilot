from app.agent.prompt import PromptManager
from app.core.config import settings


def test_moviepilot_info_does_not_expose_api_token_or_database_password(monkeypatch) -> None:
    """系统提示词中的运行信息不能暴露 API 令牌或数据库密码。"""
    monkeypatch.setattr(settings, "API_TOKEN", "prompt-secret-token")
    monkeypatch.setattr(settings, "DB_TYPE", "postgresql")
    monkeypatch.setattr(settings, "DB_POSTGRESQL_HOST", "db.example.local")
    monkeypatch.setattr(settings, "DB_POSTGRESQL_PORT", "5432")
    monkeypatch.setattr(settings, "DB_POSTGRESQL_DATABASE", "moviepilot")
    monkeypatch.setattr(settings, "DB_POSTGRESQL_USERNAME", "moviepilot_user")
    monkeypatch.setattr(settings, "DB_POSTGRESQL_PASSWORD", "prompt-db-password")

    manager = PromptManager()
    moviepilot_info = manager._get_moviepilot_info()

    assert "prompt-secret-token" not in moviepilot_info
    assert "prompt-db-password" not in moviepilot_info
    assert "moviepilot_user:prompt-db-password" not in moviepilot_info
    assert "API认证: 由内部工具自动处理" in moviepilot_info
    assert "凭据由内部工具读取" in moviepilot_info
