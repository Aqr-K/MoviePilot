from typing import Any, List, Optional

from app.managers.base import AsyncDispatchMixin, PluginDispatchManager


class MediaRecognizeManager(AsyncDispatchMixin, PluginDispatchManager):
    """
    媒体识别 / 数据源（MediaRecognize 域）统一入口（单例）。

    对外提供一组识别操作方法（契约见 app.modules.IMediaRecognize），按方法名分两步分发：先经各已启用
    插件注册的同名方法，再到系统数据源后端模块（内建 TheMovieDb/Douban/Bangumi/TheTvDb 及插件经
    provides_data_sources() 注册的源）。每次分发实时查询当前运行的后端，自动纳入运行期注册/卸载的源。

    分发内核见基类：同步两步 dispatch（PluginDispatchManager）+ 异步两步 async_dispatch（AsyncDispatchMixin，
    同步后端经线程池执行避免阻塞事件循环）。

    识别为管道域：recognize_media 等方法的结果在数据源之间流转、逐源精化（结果可作为下一源入参时透传）；
    search_* 列表方法跨源合并；首个非空非列表结果短路。后端按需实现子集，按方法名分发自然只命中实现者。

    对外方法的参数原样转发到后端（各方法的参数见下方说明及 app.modules.IMediaRecognize）。
    """

    # ------------------------------------------------------------------ #
    # IMediaRecognize 对外面：按方法名转发到 dispatch / async_dispatch。
    # ------------------------------------------------------------------ #

    def recognize_media(self, *args, **kwargs) -> Any:
        """
        识别媒体信息（跨数据源管道，逐源精化结果）。

        :param meta: 文件元数据
        :param mtype: 媒体类型
        :param tmdbid: TheMovieDb ID
        :param doubanid: 豆瓣 ID
        :param bangumiid: Bangumi ID
        :return: 识别到的媒体信息
        """
        return self.dispatch("recognize_media", *args, **kwargs)

    def search_medias(self, *args, **kwargs) -> Optional[List[Any]]:
        """
        按元数据搜索媒体信息（跨数据源合并结果）。

        :param meta: 文件元数据
        :return: 媒体信息列表
        """
        return self.dispatch("search_medias", *args, **kwargs)

    async def async_search_medias(self, *args, **kwargs) -> Optional[List[Any]]:
        """
        search_medias 的异步版本。

        :param meta: 文件元数据
        :return: 媒体信息列表
        """
        return await self.async_dispatch("async_search_medias", *args, **kwargs)

    def search_persons(self, *args, **kwargs) -> Optional[List[Any]]:
        """
        按名称搜索人物（跨数据源合并结果）。

        :param name: 人物名称
        :return: 人物信息列表
        """
        return self.dispatch("search_persons", *args, **kwargs)

    async def async_search_persons(self, *args, **kwargs) -> Optional[List[Any]]:
        """
        search_persons 的异步版本。

        :param name: 人物名称
        :return: 人物信息列表
        """
        return await self.async_dispatch("async_search_persons", *args, **kwargs)

    def search_collections(self, *args, **kwargs) -> Optional[List[Any]]:
        """
        按名称搜索系列/合集（跨数据源合并结果）。

        :param name: 系列/合集名称
        :return: 媒体信息列表
        """
        return self.dispatch("search_collections", *args, **kwargs)

    async def async_search_collections(self, *args, **kwargs) -> Optional[List[Any]]:
        """
        search_collections 的异步版本。

        :param name: 系列/合集名称
        :return: 媒体信息列表
        """
        return await self.async_dispatch("async_search_collections", *args, **kwargs)

    def obtain_images(self, *args, **kwargs) -> Any:
        """
        补充获取媒体图片（跨数据源精化）。

        :param mediainfo: 媒体信息
        :return: 补充图片后的媒体信息
        """
        return self.dispatch("obtain_images", *args, **kwargs)

    async def async_obtain_images(self, *args, **kwargs) -> Any:
        """
        obtain_images 的异步版本。

        :param mediainfo: 媒体信息
        :return: 补充图片后的媒体信息
        """
        return await self.async_dispatch("async_obtain_images", *args, **kwargs)
