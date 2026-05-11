import unittest
from unittest.mock import Mock, patch

from app.modules.zspace.zspace import ZSpace


class _FakeResponse:
    def __init__(self, payload: dict | list):
        self._payload = payload

    def json(self):
        return self._payload


class ZSpaceMediaServerTest(unittest.TestCase):
    def test_reconnect_uses_username_password_login(self):
        request_utils = Mock()
        request_utils.post_res.return_value = _FakeResponse({
            "AccessToken": "zspace-token",
            "User": {"Id": "user-id"},
        })
        request_utils.get_res.side_effect = [
            _FakeResponse([]),
            _FakeResponse({"Id": "server-id"}),
        ]

        with patch("app.modules.zspace.zspace.RequestUtils", return_value=request_utils):
            client = ZSpace(
                host="http://zspace.local",
                username="admin",
                password="secret",
            )

        self.assertEqual(client._apikey, "zspace-token")
        self.assertEqual(client.user, "user-id")
        self.assertEqual(client.serverid, "server-id")

    def test_get_user_falls_back_to_current_login_user(self):
        client = ZSpace.__new__(ZSpace)
        client._host = "http://zspace.local/"
        client._apikey = "zspace-token"
        client._username = "admin"
        client.user = "current-user-id"
        client._ZSpace__get_current_user = Mock(return_value={"Id": "current-user-id", "Name": "admin"})

        with patch("app.modules.zspace.zspace.RequestUtils") as request_utils_cls:
            request_utils_cls.return_value.get_res.return_value = _FakeResponse({"invalid": True})
            user_id = client.get_user("admin")

        self.assertEqual(user_id, "current-user-id")

    def test_authenticate_does_not_require_existing_api_key(self):
        with patch("app.modules.zspace.zspace.RequestUtils") as request_utils_cls:
            request_utils_cls.return_value.post_res.return_value = _FakeResponse({
                "AccessToken": "user-token",
                "User": {"Id": "user-id"},
            })

            client = ZSpace.__new__(ZSpace)
            client._host = "http://zspace.local/"
            client._apikey = None

            token = client.authenticate("user", "password")

        self.assertEqual(token, "user-token")
        headers = request_utils_cls.call_args.kwargs.get("headers") or {}
        self.assertEqual(
            headers.get("X-Emby-Authorization"),
            'MediaBrowser Client="MoviePilot", Device="requests", DeviceId="1", Version="1.0.0"',
        )


if __name__ == "__main__":
    unittest.main()
