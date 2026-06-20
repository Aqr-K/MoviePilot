import unittest
from unittest.mock import Mock

from app.chain.mediaserver import MediaServerChain
from app.schemas import MediaServerLibrary, MediaServerPlayItem
from app.utils.security import SecurityUtils


class MediaServerImageSigningTest(unittest.TestCase):
    @staticmethod
    def _build_chain(result):
        """
        构造只带媒服门面的 MediaServerChain，避免单测初始化真实模块管理器。
        门面化后 MediaServerChain 经 self.mediaservermanager.mediaserver_* 分发（取代 run_module），
        故此处 mock 门面的各媒服方法统一返回 result。
        """
        chain = MediaServerChain.__new__(MediaServerChain)
        manager = Mock()
        for name in ("mediaserver_librarys", "mediaserver_latest", "mediaserver_latest_images",
                     "mediaserver_playing", "mediaserver_items", "mediaserver_iteminfo",
                     "mediaserver_tv_episodes", "mediaserver_play_url", "mediaserver_image_cookies"):
            getattr(manager, name).return_value = result
        chain.mediaservermanager = manager
        return chain

    def test_librarys_signs_image_fields(self):
        """
        媒体库接口返回前需要给 image 和 image_list 加签。
        """
        image = "http://192.168.1.50:8096/Items/lib/Images/Primary"
        image_list = [
            "http://192.168.1.50:32400/library/metadata/1/thumb/1",
        ]
        chain = self._build_chain(
            [
                MediaServerLibrary(
                    id="lib",
                    image=image,
                    image_list=image_list,
                )
            ]
        )

        result = chain.librarys(server="jellyfin")

        self.assertEqual(SecurityUtils.verify_signed_url(result[0].image), image)
        self.assertEqual(
            SecurityUtils.verify_signed_url(result[0].image_list[0]),
            image_list[0],
        )

    def test_latest_signs_play_item_images(self):
        """
        最近入库接口返回前需要给条目图片加签。
        """
        image = "http://192.168.1.50:8096/Items/item/Images/Backdrop"
        chain = self._build_chain([MediaServerPlayItem(id="item", image=image)])

        result = chain.latest(server="jellyfin")

        self.assertEqual(SecurityUtils.verify_signed_url(result[0].image), image)

    def test_latest_wallpapers_signs_urls(self):
        """
        媒体服务器壁纸 URL 返回前也需要加签。
        """
        wallpaper = "http://192.168.1.50:8096/Items/item/Images/Backdrop"
        chain = self._build_chain([wallpaper])

        result = chain.get_latest_wallpapers()

        self.assertEqual(SecurityUtils.verify_signed_url(result[0]), wallpaper)
