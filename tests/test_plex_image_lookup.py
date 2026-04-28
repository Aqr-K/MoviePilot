import unittest
from unittest.mock import Mock

from app.modules.plex.plex import Plex


class PlexImageLookupTest(unittest.TestCase):
    def test_get_remote_image_by_id_uses_item_arts_for_children_key(self):
        plex = Plex.__new__(Plex)
        plex._host = "http://192.168.8.254:32400/"
        plex._playhost = None
        plex._token = "plex-token"
        plex._plex = Mock()
        plex._plex.fetchItems.side_effect = AssertionError("should not use raw fetchItems with /children key")

        item = Mock()
        item.TYPE = "show"
        item.art = "/library/metadata/29242/art/1"
        item.parentKey = None
        item.arts.return_value = [Mock(key="https://image.tmdb.org/t/p/original/test.jpg")]
        plex._plex.fetchItem.return_value = item

        image_url = plex.get_remote_image_by_id(
            item_id="/library/metadata/29242/children",
            image_type="Backdrop",
            plex_url=False,
        )

        self.assertEqual(image_url, "https://image.tmdb.org/t/p/original/test.jpg")
        item.arts.assert_called_once_with()
        plex._plex.fetchItem.assert_called_once_with(ekey="/library/metadata/29242/children")

    def test_get_remote_image_by_id_falls_back_to_local_art_url(self):
        plex = Plex.__new__(Plex)
        plex._host = "http://192.168.8.254:32400/"
        plex._playhost = None
        plex._token = "plex-token"
        plex._plex = Mock()

        item = Mock()
        item.TYPE = "show"
        item.art = "/library/metadata/29242/art/1"
        item.parentKey = None
        item.arts.return_value = []
        plex._plex.fetchItem.return_value = item

        image_url = plex.get_remote_image_by_id(
            item_id="/library/metadata/29242/children",
            image_type="Backdrop",
        )

        self.assertEqual(
            image_url,
            "http://192.168.8.254:32400/library/metadata/29242/art/1?X-Plex-Token=plex-token",
        )


if __name__ == "__main__":
    unittest.main()
