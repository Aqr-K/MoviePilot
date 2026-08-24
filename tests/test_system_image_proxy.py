import asyncio
import io
from unittest.mock import AsyncMock, Mock, patch

import pytest
from PIL import Image

import app.adapters.media.image as image_module
from app.api.endpoints import system as system_endpoint
from app.adapters.media.image import ImageHelper


def _image_bytes(image_format: str, trailing: bytes = b"") -> bytes:
    buffer = io.BytesIO()
    Image.new("RGB", (2, 2), color=(32, 96, 160)).save(buffer, format=image_format)
    return buffer.getvalue() + trailing


@pytest.mark.parametrize(
    ("image_format", "expected_mime"),
    [
        ("PNG", "image/png"),
        ("JPEG", "image/jpeg"),
        ("GIF", "image/gif"),
        ("WEBP", "image/webp"),
        ("PCX", "image/x-pcx"),
        ("PPM", "image/x-portable-anymap"),
    ],
)
def test_get_image_mime_type_uses_pillow_detected_format(
    image_format: str,
    expected_mime: str,
):
    assert ImageHelper.get_image_mime_type(_image_bytes(image_format)) == expected_mime


def test_get_image_mime_type_rejects_non_image_pillow_mime():
    assert ImageHelper.get_image_mime_type(_image_bytes("EPS")) is None


def test_get_image_mime_type_rejects_scriptable_svg_mime():
    with patch.dict(Image.MIME, {"PNG": "image/svg+xml"}):
        assert ImageHelper.get_image_mime_type(_image_bytes("PNG")) is None


def test_fetch_image_with_mime_type_only_reads_cached_format_header():
    content = _image_bytes("PNG")
    image_helper = ImageHelper()

    with patch.object(
        image_helper.file_cache,
        "get",
        return_value=content,
    ), patch.object(
        image_helper,
        "get_image_mime_type",
        return_value="image/png",
    ) as get_mime_type:
        result = image_helper.fetch_image_with_mime_type(
            "https://images.example/wallpaper.png"
        )

    assert result == (content, "image/png")
    get_mime_type.assert_called_once_with(content, verify=False)


def test_fetch_image_with_mime_type_validates_network_content_once():
    content = _image_bytes("PNG")
    image_helper = ImageHelper()
    response = Mock(status_code=200, content=content)
    request = Mock()
    request.get_res.return_value = response

    with patch.object(
        image_helper.file_cache,
        "get",
        return_value=None,
    ), patch.object(
        image_helper.file_cache,
        "set",
    ), patch(
        "app.adapters.media.image.RequestUtils",
        return_value=request,
    ), patch.object(
        image_helper,
        "get_image_mime_type",
        return_value="image/png",
    ) as get_mime_type:
        result = image_helper.fetch_image_with_mime_type(
            "https://images.example/wallpaper.png"
        )

    assert result == (content, "image/png")
    get_mime_type.assert_called_once_with(content)


def test_async_fetch_image_with_mime_type_only_reads_cached_format_header():
    content = _image_bytes("PNG")
    image_helper = ImageHelper()

    with patch.object(
        image_helper.async_file_cache,
        "get",
        new=AsyncMock(return_value=content),
    ), patch.object(
        image_helper,
        "get_image_mime_type",
        return_value="image/png",
    ) as get_mime_type:
        result = asyncio.run(
            image_helper.async_fetch_image_with_mime_type(
                "https://images.example/wallpaper.png"
            )
        )

    assert result == (content, "image/png")
    get_mime_type.assert_called_once_with(content, verify=False)


def test_async_fetch_image_with_mime_type_validates_network_content_once():
    content = _image_bytes("PNG")
    image_helper = ImageHelper()
    response = Mock(status_code=200, content=content)
    request = Mock()
    request.get_res = AsyncMock(return_value=response)

    with patch.object(
        image_helper.async_file_cache,
        "get",
        new=AsyncMock(return_value=None),
    ), patch.object(
        image_helper.async_file_cache,
        "set",
        new=AsyncMock(),
    ), patch(
        "app.adapters.media.image.AsyncRequestUtils",
        return_value=request,
    ), patch.object(
        image_helper,
        "get_image_mime_type",
        return_value="image/png",
    ) as get_mime_type:
        result = asyncio.run(
            image_helper.async_fetch_image_with_mime_type(
                "https://images.example/wallpaper.png"
            )
        )

    assert result == (content, "image/png")
    get_mime_type.assert_called_once_with(content)


def test_fetch_image_does_not_trust_active_url_suffix():
    content = _image_bytes("PNG", b"<script>window.xss = true</script>")
    image_helper = Mock()
    image_helper.async_fetch_image_with_mime_type = AsyncMock(
        return_value=(content, "image/png")
    )

    with patch.object(
        system_endpoint.SecurityUtils,
        "is_safe_image_url_async",
        new=AsyncMock(return_value=True),
    ), patch.object(system_endpoint, "ImageHelper", return_value=image_helper):
        response = asyncio.run(
            system_endpoint.fetch_image(
                url="https://images.example/wallpaper.html",
                allowed_domains={"images.example"},
            )
        )

    assert response is not None
    assert response.headers["content-type"] == "image/png"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.body == content


def test_fetch_image_rejects_unverified_content():
    image_helper = Mock()
    image_helper.async_fetch_image_with_mime_type = AsyncMock(return_value=None)

    with patch.object(
        system_endpoint.SecurityUtils,
        "is_safe_image_url_async",
        new=AsyncMock(return_value=True),
    ), patch.object(system_endpoint, "ImageHelper", return_value=image_helper):
        response = asyncio.run(
            system_endpoint.fetch_image(
                url="https://images.example/wallpaper.png",
                allowed_domains={"images.example"},
            )
        )

    assert response is None


def test_async_fetch_image_with_mime_type_offloads_cached_format_detection(monkeypatch):
    """异步获取图片命中缓存时，Pillow 格式识别必须卸载到线程池，不能阻塞事件循环。"""
    content = _image_bytes("PNG")
    image_helper = ImageHelper()
    calls = []

    async def fake_run_in_threadpool(func, *args, **kwargs):
        calls.append((func, args, kwargs))
        return func(*args, **kwargs)

    monkeypatch.setattr(image_module, "run_in_threadpool", fake_run_in_threadpool)

    with patch.object(
        image_helper.async_file_cache,
        "get",
        new=AsyncMock(return_value=content),
    ):
        result = asyncio.run(
            image_helper.async_fetch_image_with_mime_type(
                "https://images.example/wallpaper.png"
            )
        )

    assert result == (content, "image/png")
    assert calls == [(image_helper.get_image_mime_type, (content,), {"verify": False})]


def test_async_fetch_image_with_mime_type_offloads_network_format_detection(monkeypatch):
    """异步获取图片走网络请求时，Pillow 格式识别同样必须卸载到线程池。"""
    content = _image_bytes("PNG")
    image_helper = ImageHelper()
    response = Mock(status_code=200, content=content)
    request = Mock()
    request.get_res = AsyncMock(return_value=response)
    calls = []

    async def fake_run_in_threadpool(func, *args, **kwargs):
        calls.append((func, args, kwargs))
        return func(*args, **kwargs)

    monkeypatch.setattr(image_module, "run_in_threadpool", fake_run_in_threadpool)

    with patch.object(
        image_helper.async_file_cache,
        "get",
        new=AsyncMock(return_value=None),
    ), patch.object(
        image_helper.async_file_cache,
        "set",
        new=AsyncMock(),
    ), patch(
        "app.adapters.media.image.AsyncRequestUtils",
        return_value=request,
    ):
        result = asyncio.run(
            image_helper.async_fetch_image_with_mime_type(
                "https://images.example/wallpaper.png"
            )
        )

    assert result == (content, "image/png")
    assert calls == [(image_helper.get_image_mime_type, (content,), {})]


def test_proxy_img_offloads_media_server_cookie_lookup(monkeypatch):
    """图片代理端点获取媒体服务器 Cookie 时必须卸载到线程池，不能阻塞事件循环。"""
    calls = []

    async def fake_run_sync(func, *args):
        calls.append((func, args))
        return func(*args)

    monkeypatch.setattr(system_endpoint.anyio.to_thread, "run_sync", fake_run_sync)

    fake_media_server_chain = Mock()
    fake_media_server_chain.get_image_cookies.return_value = {"cookie": "value"}
    monkeypatch.setattr(
        system_endpoint,
        "MediaServerChain",
        Mock(return_value=fake_media_server_chain),
    )
    monkeypatch.setattr(
        system_endpoint,
        "fetch_image",
        AsyncMock(return_value=system_endpoint.Response(status_code=200)),
    )

    asyncio.run(
        system_endpoint.proxy_img(
            imgurl="https://img.example/a.png",
            use_cookies=True,
            _=Mock(),
        )
    )

    fake_media_server_chain.get_image_cookies.assert_called_once_with(
        None, "https://img.example/a.png"
    )
    assert calls == [
        (fake_media_server_chain.get_image_cookies, (None, "https://img.example/a.png"))
    ]
    system_endpoint.fetch_image.assert_awaited_once_with(
        url="https://img.example/a.png",
        proxy=False,
        use_cache=False,
        cookies={"cookie": "value"},
        if_none_match=None,
        allowed_domains=set(system_endpoint.settings.SECURITY_IMAGE_DOMAINS),
    )


def test_fetch_image_adds_nosniff_to_not_modified_response():
    content = _image_bytes("JPEG")
    image_helper = Mock()
    image_helper.async_fetch_image_with_mime_type = AsyncMock(
        return_value=(content, "image/jpeg")
    )
    etag = system_endpoint.HashUtils.md5(content)

    with patch.object(
        system_endpoint.SecurityUtils,
        "is_safe_image_url_async",
        new=AsyncMock(return_value=True),
    ), patch.object(system_endpoint, "ImageHelper", return_value=image_helper):
        response = asyncio.run(
            system_endpoint.fetch_image(
                url="https://images.example/wallpaper.jpg",
                if_none_match=etag,
                allowed_domains={"images.example"},
            )
        )

    assert response is not None
    assert response.status_code == 304
    assert response.headers["content-type"] == "image/jpeg"
    assert response.headers["x-content-type-options"] == "nosniff"
