"""字符串模块方法协议的可检查契约清单。"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol


class ModuleResultAggregation(StrEnum):
    """描述多模块结果沿调用链的聚合方式。"""

    LEGACY = "legacy"
    PIPELINE = "pipeline"
    FIRST_NON_EMPTY = "first_non_empty"
    ORDERED_LIST_MERGE = "ordered_list_merge"
    ORDERED_MAPPING_MERGE = "ordered_mapping_merge"


class ModuleResultShape(StrEnum):
    """描述模块 provider 返回值的基础 Python 形状。"""

    ANY = "any"
    LIST = "list"
    STRING = "string"
    MAPPING = "mapping"
    BOOLEAN = "boolean"
    BYTES = "bytes"


class ModuleExecutionMode(StrEnum):
    """描述 provider 可以采用的执行形态。"""

    SYNC_OR_ASYNC = "sync_or_async"


class ModuleErrorPolicy(StrEnum):
    """描述单个 provider 失败后的兼容处理策略。"""

    ISOLATE_PROVIDER = "isolate_provider"


class ModuleCapability(Protocol):
    """宿主和新插件可用于声明动态能力的最小 Protocol。"""

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """执行模块能力并返回契约声明的结果。"""


@dataclass(frozen=True, slots=True)
class ModuleMethodContract:
    """记录模块方法的输入、结果、执行与兼容错误协议。"""

    family: str
    aggregation: ModuleResultAggregation = ModuleResultAggregation.LEGACY
    version: int = 1
    input_contract: str = "legacy_args"
    result_contract: str = "Any"
    result_shape: ModuleResultShape = ModuleResultShape.ANY
    required_parameters: tuple[str, ...] = ()
    execution: ModuleExecutionMode = ModuleExecutionMode.SYNC_OR_ASYNC
    timeout_policy: str = "caller_budget"
    error_policy: ModuleErrorPolicy = ModuleErrorPolicy.ISOLATE_PROVIDER
    public_to_plugins: bool = True
    supports_sync: bool = True
    supports_async: bool = True
    plugin_short_circuit: bool = True


@dataclass(frozen=True, slots=True)
class MultiSourceCapabilityContract:
    """记录一个多来源能力的应答来源、让出方式、收窄开关与结果取用规则。"""

    method: str
    sources: tuple[str, ...]
    abstain: str
    narrowing: tuple[tuple[str, str], ...]
    arbitration: str


_DEFAULT_CONTRACT = ModuleMethodContract(family="legacy")

# 由多类来源共同应答的能力，其应答协议不体现在方法签名上，登记于此供实现方与调用方共同遵循。
_MULTI_SOURCE_CONTRACTS = {
    "media_exists": MultiSourceCapabilityContract(
        method="media_exists",
        sources=(
            "媒体服务器：Emby、Jellyfin、Plex、TrimeMedia、Ugreen、ZSpace、Navidrome，按各自库中的条目应答",
            "文件系统：medialibrary 按标准媒体库结构扫描已入库文件应答",
        ),
        abstain=(
            "返回 None 表示本来源不认领，既涵盖库中没有该媒体，也涵盖被收窄开关排除在外；"
            "调度据此继续询问下一来源"
        ),
        narrowing=(
            ("server", "媒体服务器专有：仅同名媒体服务器应答，其余媒体服务器与文件系统来源全部让出"),
            ("itemid", "媒体服务器专有：媒体服务器条目 ID，文件系统来源收到后直接忽略"),
            ("LOCAL_EXISTS_SEARCH", "文件系统专有：关闭时文件系统来源一律让出，媒体服务器来源不受影响"),
        ),
        arbitration=(
            "电视剧收齐全部来源答案后按季号取已存在集的并集，媒体库标识沿用最高优先级来源；"
            "电影与音乐取首个非空答案；"
            "同一模块下的多台同类型服务器由模块自行仲裁，对外只出一个答案"
        ),
    ),
    "match_media": MultiSourceCapabilityContract(
        method="match_media",
        sources=(
            "TMDB：TheMovieDbModule 按 source=TMDB 应答",
            "豆瓣：DoubanModule 按 source=Douban 应答",
            "插件：模块自带 match_media 实现按 source 自认领应答",
        ),
        abstain=(
            "返回 None 表示本来源不认领，既涵盖 source 非本来源，也涵盖本来源未匹配到媒体信息；"
            "调度据此继续询问下一来源"
        ),
        narrowing=(
            ("source", "唯一收窄键：非本来源一律让出"),
        ),
        arbitration="首个非空答案即为最终答案；插件提供者先于内建模块被询问",
    ),
    "person_detail": MultiSourceCapabilityContract(
        method="person_detail",
        sources=(
            "TMDB：TheMovieDbModule 按 source=TMDB 应答",
            "豆瓣：DoubanModule 按 source=Douban 应答",
            "Bangumi：BangumiModule 按 source=Bangumi 应答",
            "AniList：AniListModule 按 source=AniList 应答",
            "插件：模块自带 person_detail 实现按 source 自认领应答",
        ),
        abstain=(
            "返回 None 表示本来源不认领，既涵盖 source 非本来源，也涵盖收窄开关排除在外；"
            "返回空列表会被视为已认领而短路，因此非本来源必须返回 None；"
            "调度据此继续询问下一来源"
        ),
        narrowing=(
            ("source", "唯一收窄键：非本来源一律让出"),
        ),
        arbitration="首个非空答案即为最终答案；插件提供者先于内建模块被询问",
    ),
    "person_credits": MultiSourceCapabilityContract(
        method="person_credits",
        sources=(
            "TMDB：TheMovieDbModule 按 source=TMDB 应答",
            "豆瓣：DoubanModule 按 source=Douban 应答",
            "Bangumi：BangumiModule 按 source=Bangumi 应答",
            "AniList：AniListModule 按 source=AniList 应答",
            "插件：模块自带 person_credits 实现按 source 自认领应答",
        ),
        abstain=(
            "返回 None 表示本来源不认领，既涵盖 source 非本来源，也涵盖收窄开关排除在外；"
            "返回空列表会被视为已认领而短路，因此非本来源必须返回 None；"
            "调度据此继续询问下一来源"
        ),
        narrowing=(
            ("source", "唯一收窄键：非本来源一律让出"),
        ),
        arbitration="首个非空答案即为最终答案；插件提供者先于内建模块被询问",
    ),
    "media_credits": MultiSourceCapabilityContract(
        method="media_credits",
        sources=(
            "TMDB：TheMovieDbModule 按 source=TMDB 应答",
            "豆瓣：DoubanModule 按 source=Douban 应答",
            "Bangumi：BangumiModule 按 source=Bangumi 应答",
            "AniList：AniListModule 按 source=AniList 应答",
            "插件：模块自带 media_credits 实现按 source 自认领应答",
        ),
        abstain=(
            "返回 None 表示本来源不认领，既涵盖 source 非本来源，也涵盖 media_id 为空或无法转换为"
            "本来源要求的ID类型；返回空列表会被视为已认领而短路，因此非本来源必须返回 None；"
            "调度据此继续询问下一来源"
        ),
        narrowing=(
            ("source", "唯一收窄键：非本来源一律让出"),
        ),
        arbitration="首个非空答案即为最终答案；插件提供者先于内建模块被询问",
    ),
    "media_recommend": MultiSourceCapabilityContract(
        method="media_recommend",
        sources=(
            "TMDB：TheMovieDbModule 按 source=TMDB 应答",
            "豆瓣：DoubanModule 按 source=Douban 应答",
            "Bangumi：BangumiModule 按 source=Bangumi 应答",
            "AniList：AniListModule 按 source=AniList 应答",
            "插件：模块自带 media_recommend 实现按 source 自认领应答",
        ),
        abstain=(
            "返回 None 表示本来源不认领，既涵盖 source 非本来源，也涵盖 media_id 为空或无法转换为"
            "本来源要求的ID类型；返回空列表会被视为已认领而短路，因此非本来源必须返回 None；"
            "调度据此继续询问下一来源"
        ),
        narrowing=(
            ("source", "唯一收窄键：非本来源一律让出"),
        ),
        arbitration="首个非空答案即为最终答案；插件提供者先于内建模块被询问",
    ),
    "media_similar": MultiSourceCapabilityContract(
        method="media_similar",
        sources=(
            "TMDB：TheMovieDbModule 按 source=TMDB 应答，是当前唯一内建实现来源",
            "插件：模块自带 media_similar 实现按 source 自认领应答",
        ),
        abstain=(
            "返回 None 表示本来源不认领，既涵盖 source 非本来源，也涵盖 media_id 为空或无法转换为"
            "本来源要求的ID类型；返回空列表会被视为已认领而短路，因此非本来源必须返回 None；"
            "调度据此继续询问下一来源；豆瓣、Bangumi、AniList 均未实现本方法，不会进入能力索引"
        ),
        narrowing=(
            ("source", "唯一收窄键：非本来源一律让出"),
        ),
        arbitration="首个非空答案即为最终答案；插件提供者先于内建模块被询问",
    ),
    "media_detail": MultiSourceCapabilityContract(
        method="media_detail",
        sources=(
            "TMDB：TheMovieDbModule 按 source=TMDB 应答，接受 mtype 与 season",
            "豆瓣：DoubanModule 按 source=Douban 应答，接受 mtype，不支持 season",
            "Bangumi：BangumiModule 按 source=Bangumi 应答，不支持 mtype、season",
            "AniList：AniListModule 按 source=AniList 应答，不支持 mtype、season",
            "TVDB：TheTvDbModule 按 source=TVDB 应答，不支持 mtype、season；本模块只有同步原生"
            "实现，async_media_detail 经 run_in_threadpool 包装同步方法",
            "插件：模块自带 media_detail 实现按 source 自认领应答",
        ),
        abstain=(
            "返回 None 表示本来源不认领，既涵盖 source 非本来源，也涵盖 media_id 为空或无法转换为"
            "本来源要求的ID类型；调度据此继续询问下一来源"
        ),
        narrowing=(
            ("source", "唯一收窄键：非本来源一律让出，其余不支持的参数各来源就地丢弃"),
        ),
        arbitration="首个非空答案即为最终答案；插件提供者先于内建模块被询问",
    ),
    "discover": MultiSourceCapabilityContract(
        method="discover",
        sources=(
            "TMDB：TheMovieDbModule 按 source=TMDB 应答，筛选条件原样转发给 tmdb_discover",
            "豆瓣：DoubanModule 按 source=Douban 应答，筛选条件原样转发给 douban_discover",
            "Bangumi：BangumiModule 按 source=Bangumi 应答，筛选条件原样转发给 bangumi_discover",
            "AniList：AniListModule 按 source=AniList 应答，筛选条件原样转发给 anilist_discover",
            "插件：模块自带 discover 实现按 source 自认领应答",
        ),
        abstain=(
            "返回 None 表示本来源不认领，仅涵盖 source 非本来源；"
            "筛选条件（criteria）按各来源原方法签名原样转发，本契约不为任何条件补默认值，"
            "本来源必填条件缺失时由被委托的原方法自身抛出异常，而非静默返回 None 或默认结果；"
            "调度据此继续询问下一来源"
        ),
        narrowing=(
            ("source", "唯一收窄键：非本来源一律让出，其余条件原样转发不做归一"),
        ),
        arbitration="首个非空答案即为最终答案；插件提供者先于内建模块被询问",
    ),
    "discover_board": MultiSourceCapabilityContract(
        method="discover_board",
        sources=(
            "豆瓣：DoubanModule 按 source=Douban 应答，支持 movie_showing/movie_hot/movie_top250/"
            "tv_hot/tv_animation/tv_weekly_chinese/tv_weekly_global 共7个榜单，接受 page 与 count",
            "TMDB：TheMovieDbModule 按 source=TMDB 应答，仅支持 trending 榜单，只接受 page",
            "Bangumi：BangumiModule 按 source=Bangumi 应答，仅支持 calendar 榜单，不接受分页参数",
            "AniList：AniListModule 按 source=AniList 应答，支持 trending/popular_this_season 两个"
            "榜单，接受 page 与 count",
            "插件：模块自带 discover_board 实现按 source 自认领应答",
        ),
        abstain=(
            "返回 None 表示本来源不认领，既涵盖 source 非本来源，也涵盖 board 未命中本来源榜单白名单；"
            "白名单校验先于方法查找完成，未登记标识不会触发任意方法调用；"
            "返回空列表会被视为已认领而短路，因此非本来源与未登记榜单都必须返回 None；"
            "调度据此继续询问下一来源"
        ),
        narrowing=(
            ("source", "收窄键之一：非本来源一律让出"),
            ("board", "收窄键之一：须命中本来源榜单白名单，否则让出；"
                      "各来源只下传自己认得的分页参数，其余就地丢弃"),
        ),
        arbitration="首个非空答案即为最终答案；插件提供者先于内建模块被询问",
    ),
}

# 首批登记高频能力族。方法名仍保持开放字符串，以兼容第三方插件自定义模块能力；
# 未命中项继续使用冻结的 legacy 规则，并由架构快照记录新增调用位置。
_METHOD_CONTRACTS = {
    "recognize_media": ModuleMethodContract(
        family="media-recognition", input_contract="MediaRecognitionRequest",
        result_contract="MediaInfo | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY,
        required_parameters=("meta", "mtype", "media_source", "media_id", "episode_group", "cache"),
    ),
    "async_recognize_media": ModuleMethodContract(
        family="media-recognition", input_contract="MediaRecognitionRequest",
        result_contract="MediaInfo | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY,
        required_parameters=("meta", "mtype", "media_source", "media_id", "episode_group", "cache"),
    ),
    "search_medias": ModuleMethodContract(
        family="media-recognition", input_contract="MediaSearchRequest",
        result_contract="list[MediaInfo]", result_shape=ModuleResultShape.LIST,
        aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE,
        required_parameters=("meta", "media_source"),
    ),
    "async_search_medias": ModuleMethodContract(
        family="media-recognition", input_contract="MediaSearchRequest",
        result_contract="list[MediaInfo]", result_shape=ModuleResultShape.LIST,
        aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE,
        required_parameters=("meta", "media_source"),
    ),
    "obtain_images": ModuleMethodContract(
        family="media-recognition", input_contract="MediaInfo",
        result_contract="MediaInfo | None", aggregation=ModuleResultAggregation.PIPELINE,
        required_parameters=("mediainfo",),
    ),
    "async_obtain_images": ModuleMethodContract(
        family="media-recognition", input_contract="MediaInfo",
        result_contract="MediaInfo | None", aggregation=ModuleResultAggregation.PIPELINE,
    ),
    "media_category": ModuleMethodContract(
        family="media-recognition", input_contract="MediaCategoryRequest",
        result_contract="dict[str, list] | None", result_shape=ModuleResultShape.MAPPING,
        aggregation=ModuleResultAggregation.FIRST_NON_EMPTY,
    ),
    "media_exists": ModuleMethodContract(
        family="media-library",
        input_contract="mediainfo, itemid=None, server=None",
        result_contract="ExistMediaInfo | None",
    ),
    "match_media": ModuleMethodContract(
        family="media-metadata",
        input_contract="source, name=None, mtype=None, year=None, season=None, imdbid=None",
        result_contract="dict | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY,
    ),
    "async_match_media": ModuleMethodContract(
        family="media-metadata",
        input_contract="source, name=None, mtype=None, year=None, season=None, imdbid=None",
        result_contract="dict | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY,
    ),
    "person_detail": ModuleMethodContract(
        family="media-metadata", input_contract="source, person_id=None",
        result_contract="MediaPerson | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY,
    ),
    "async_person_detail": ModuleMethodContract(
        family="media-metadata", input_contract="source, person_id=None",
        result_contract="MediaPerson | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY,
    ),
    "person_credits": ModuleMethodContract(
        family="media-metadata", input_contract="source, person_id=None, page=1, count=None",
        result_contract="list[MediaInfo] | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY,
    ),
    "async_person_credits": ModuleMethodContract(
        family="media-metadata", input_contract="source, person_id=None, page=1, count=None",
        result_contract="list[MediaInfo] | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY,
    ),
    "media_credits": ModuleMethodContract(
        family="media-metadata",
        input_contract="source, media_id=None, mtype=None, page=1, count=None",
        result_contract="list[MediaPerson] | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY,
    ),
    "async_media_credits": ModuleMethodContract(
        family="media-metadata",
        input_contract="source, media_id=None, mtype=None, page=1, count=None",
        result_contract="list[MediaPerson] | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY,
    ),
    "media_recommend": ModuleMethodContract(
        family="media-metadata",
        input_contract="source, media_id=None, mtype=None, page=1, count=None",
        result_contract="list[MediaInfo] | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY,
    ),
    "async_media_recommend": ModuleMethodContract(
        family="media-metadata",
        input_contract="source, media_id=None, mtype=None, page=1, count=None",
        result_contract="list[MediaInfo] | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY,
    ),
    "media_similar": ModuleMethodContract(
        family="media-metadata", input_contract="source, media_id=None, mtype=None",
        result_contract="list[MediaInfo] | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY,
    ),
    "async_media_similar": ModuleMethodContract(
        family="media-metadata", input_contract="source, media_id=None, mtype=None",
        result_contract="list[MediaInfo] | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY,
    ),
    "media_detail": ModuleMethodContract(
        family="media-metadata",
        input_contract="source, media_id=None, mtype=None, season=None",
        result_contract="dict | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY,
    ),
    "async_media_detail": ModuleMethodContract(
        family="media-metadata",
        input_contract="source, media_id=None, mtype=None, season=None",
        result_contract="dict | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY,
    ),
    "discover": ModuleMethodContract(
        family="media-discovery", input_contract="source, **criteria",
        result_contract="list[MediaInfo] | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY,
    ),
    "async_discover": ModuleMethodContract(
        family="media-discovery", input_contract="source, **criteria",
        result_contract="list[MediaInfo] | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY,
    ),
    "discover_board": ModuleMethodContract(
        family="media-discovery", input_contract="source, board=None, page=1, count=30",
        result_contract="list[MediaInfo] | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY,
    ),
    "async_discover_board": ModuleMethodContract(
        family="media-discovery", input_contract="source, board=None, page=1, count=30",
        result_contract="list[MediaInfo] | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY,
    ),
    "mediaserver_items": ModuleMethodContract(family="media-server", input_contract="MediaServerItemsRequest", result_contract="Iterable[MediaServerItem] | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("server", "library_id", "start_index", "limit")),
    "mediaserver_iteminfo": ModuleMethodContract(family="media-server", input_contract="MediaServerItemRequest", result_contract="MediaServerItem | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("server", "item_id")),
    "mediaserver_play_url": ModuleMethodContract(family="media-server", input_contract="MediaServerPlayRequest", result_contract="str | None", result_shape=ModuleResultShape.STRING, aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("server", "item_id")),
    "mediaserver_tv_episodes": ModuleMethodContract(family="media-server", input_contract="MediaServerEpisodesRequest", result_contract="list[MediaServerPlayItem]", aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("server", "item_id")),
    "media_statistic": ModuleMethodContract(family="media-server", input_contract="MediaStatisticRequest", result_contract="list[Statistic]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("server",)),
    "mediaserver_image_cookies": ModuleMethodContract(family="media-server", input_contract="MediaServerImageCookiesRequest", result_contract="str | dict | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("server", "image_url")),
    "mediaserver_items_count": ModuleMethodContract(family="media-server", input_contract="MediaServerItemsCountRequest", result_contract="int | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("server", "library_id")),
    "mediaserver_latest": ModuleMethodContract(family="media-server", input_contract="MediaServerRecentRequest", result_contract="list[MediaServerPlayItem]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("server", "count", "username")),
    "mediaserver_latest_images": ModuleMethodContract(family="media-server", input_contract="MediaServerRecentImagesRequest", result_contract="list[str]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("server", "count", "remote", "username")),
    "mediaserver_librarys": ModuleMethodContract(family="media-server", input_contract="MediaServerLibrariesRequest", result_contract="list[MediaServerLibrary]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("server", "username", "hidden")),
    "mediaserver_playing": ModuleMethodContract(family="media-server", input_contract="MediaServerRecentRequest", result_contract="list[MediaServerPlayItem]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("server", "count", "username")),
    "mediaserver_season_episode_ids": ModuleMethodContract(family="media-server", input_contract="MediaServerSeasonEpisodesRequest", result_contract="dict[int, str] | None", result_shape=ModuleResultShape.MAPPING, aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("server", "item_id", "season")),
    "any_files": ModuleMethodContract(family="storage", input_contract="StorageAnyFilesRequest", result_contract="bool | None", result_shape=ModuleResultShape.BOOLEAN, aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("fileitem", "extensions")),
    "create_folder": ModuleMethodContract(family="storage", input_contract="StorageCreateFolderRequest", result_contract="FileItem | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("fileitem", "name")),
    "delete_file": ModuleMethodContract(family="storage", input_contract="StorageDeleteRequest", result_contract="bool | None", result_shape=ModuleResultShape.BOOLEAN, aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("fileitem",)),
    "download_file": ModuleMethodContract(family="storage", input_contract="StorageDownloadRequest", result_contract="FileItem | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("fileitem", "path")),
    "upload_file": ModuleMethodContract(family="storage", input_contract="StorageUploadRequest", result_contract="FileItem | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("fileitem", "path", "new_name")),
    "list_files": ModuleMethodContract(family="storage", input_contract="StorageListRequest", result_contract="list[FileItem]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("fileitem", "recursion")),
    "media_files": ModuleMethodContract(family="storage", input_contract="MediaFilesRequest", result_contract="list[FileItem]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("mediainfo",)),
    "get_file_item": ModuleMethodContract(family="storage", input_contract="StorageItemRequest", result_contract="FileItem | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("storage", "path")),
    "get_folder": ModuleMethodContract(family="storage", input_contract="StorageFolderRequest", result_contract="FileItem | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("storage", "path")),
    "get_parent_item": ModuleMethodContract(family="storage", input_contract="StorageParentRequest", result_contract="FileItem | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("fileitem",)),
    "rename_file": ModuleMethodContract(family="storage", input_contract="StorageRenameRequest", result_contract="bool | FileItem", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("fileitem", "name")),
    "storage_manage": ModuleMethodContract(family="storage", input_contract="StorageManageRequest", result_contract="StorageProviderResult", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("storage", "action")),
    "snapshot_storage": ModuleMethodContract(family="storage", input_contract="StorageSnapshotRequest", result_contract="dict[str, dict] | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("storage", "path", "last_snapshot_time", "max_depth", "previous_snapshot")),
    "transfer": ModuleMethodContract(family="storage", input_contract="TransferRequest", result_contract="TransferInfo | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("fileitem", "meta", "mediainfo", "target_directory", "target_storage", "target_path", "transfer_type", "scrape", "library_type_folder", "library_category_folder", "episodes_info", "source_oper", "target_oper", "preview")),
    "load_category_config": ModuleMethodContract(family="category", input_contract="CategoryConfigReadRequest", result_contract="CategoryConfig | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY),
    "save_category_config": ModuleMethodContract(family="category", input_contract="CategoryConfigWriteRequest", result_contract="bool | None", result_shape=ModuleResultShape.BOOLEAN, aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("config",)),
    "get_search_page_size": ModuleMethodContract(family="site", input_contract="SiteSearchPageSizeRequest", result_contract="int | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("site", "keyword")),
    "refresh_userdata": ModuleMethodContract(family="site", input_contract="SiteUserDataRequest", result_contract="SiteUserData | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("site",)),
    "site_subtitle_links": ModuleMethodContract(family="site", input_contract="SiteSubtitleLinksRequest", result_contract="list[str]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("context",)),
    "metadata_img": ModuleMethodContract(family="metadata", input_contract="MetadataImageRequest", result_contract="dict[str, str] | None", result_shape=ModuleResultShape.MAPPING, aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("mediainfo", "season", "episode")),
    "metadata_nfo": ModuleMethodContract(family="metadata", input_contract="MetadataNfoRequest", result_contract="str | None", result_shape=ModuleResultShape.STRING, aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("meta", "mediainfo", "season", "episode")),
    "obtain_specific_image": ModuleMethodContract(family="metadata", input_contract="SpecificImageRequest", result_contract="str | None", result_shape=ModuleResultShape.STRING, aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("mediaid", "mtype", "image_type", "image_prefix", "season", "episode")),
    "recommend_name": ModuleMethodContract(family="metadata", input_contract="RecommendNameRequest", result_contract="str | None", result_shape=ModuleResultShape.STRING, aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("meta", "mediainfo", "episodes_info")),
    "user_authenticate": ModuleMethodContract(family="authentication", input_contract="UserAuthenticationRequest", result_contract="AuthCredentials | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("credentials",)),
    "tvdb_info": ModuleMethodContract(family="tvdb", input_contract="TvdbInfoRequest", result_contract="dict | None", result_shape=ModuleResultShape.MAPPING, aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("tvdbid",)),
    "search_tvdb": ModuleMethodContract(family="tvdb", input_contract="TvdbSearchRequest", result_contract="list[dict]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("title",)),
    "movie_hot": ModuleMethodContract(family="media-discovery", input_contract="MediaRankingRequest", result_contract="list[MediaInfo]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("page", "count")),
    "async_movie_hot": ModuleMethodContract(family="media-discovery", input_contract="MediaRankingRequest", result_contract="list[MediaInfo]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("page", "count")),
    "movie_showing": ModuleMethodContract(family="media-discovery", input_contract="MediaRankingRequest", result_contract="list[MediaInfo]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("page", "count")),
    "async_movie_showing": ModuleMethodContract(family="media-discovery", input_contract="MediaRankingRequest", result_contract="list[MediaInfo]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("page", "count")),
    "movie_top250": ModuleMethodContract(family="media-discovery", input_contract="MediaRankingRequest", result_contract="list[MediaInfo]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("page", "count")),
    "async_movie_top250": ModuleMethodContract(family="media-discovery", input_contract="MediaRankingRequest", result_contract="list[MediaInfo]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("page", "count")),
    "search_collections": ModuleMethodContract(family="media-discovery", input_contract="CollectionSearchRequest", result_contract="list[MediaInfo]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("name", "media_source")),
    "async_search_collections": ModuleMethodContract(family="media-discovery", input_contract="CollectionSearchRequest", result_contract="list[MediaInfo]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("name", "media_source")),
    "search_persons": ModuleMethodContract(family="media-discovery", input_contract="PersonSearchRequest", result_contract="list[MediaPerson]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("name", "media_source")),
    "async_search_persons": ModuleMethodContract(family="media-discovery", input_contract="PersonSearchRequest", result_contract="list[MediaPerson]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("name", "media_source")),
    "search_subtitles": ModuleMethodContract(family="media-discovery", input_contract="SubtitleSearchRequest", result_contract="list[SubtitleInfo]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("site", "keyword", "page")),
    "async_search_subtitles": ModuleMethodContract(family="media-discovery", input_contract="SubtitleSearchRequest", result_contract="list[SubtitleInfo]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("site", "keyword", "page")),
    "search_torrents": ModuleMethodContract(family="media-discovery", input_contract="TorrentSearchRequest", result_contract="list[TorrentInfo]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("site", "keyword", "mtype", "page")),
    "async_search_torrents": ModuleMethodContract(family="media-discovery", input_contract="TorrentSearchRequest", result_contract="list[TorrentInfo]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("site", "keyword", "mtype", "page")),
    "tv_animation": ModuleMethodContract(family="media-discovery", input_contract="MediaRankingRequest", result_contract="list[MediaInfo]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("page", "count")),
    "async_tv_animation": ModuleMethodContract(family="media-discovery", input_contract="MediaRankingRequest", result_contract="list[MediaInfo]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("page", "count")),
    "tv_hot": ModuleMethodContract(family="media-discovery", input_contract="MediaRankingRequest", result_contract="list[MediaInfo]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("page", "count")),
    "async_tv_hot": ModuleMethodContract(family="media-discovery", input_contract="MediaRankingRequest", result_contract="list[MediaInfo]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("page", "count")),
    "tv_weekly_chinese": ModuleMethodContract(family="media-discovery", input_contract="MediaRankingRequest", result_contract="list[MediaInfo]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("page", "count")),
    "async_tv_weekly_chinese": ModuleMethodContract(family="media-discovery", input_contract="MediaRankingRequest", result_contract="list[MediaInfo]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("page", "count")),
    "tv_weekly_global": ModuleMethodContract(family="media-discovery", input_contract="MediaRankingRequest", result_contract="list[MediaInfo]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("page", "count")),
    "async_tv_weekly_global": ModuleMethodContract(family="media-discovery", input_contract="MediaRankingRequest", result_contract="list[MediaInfo]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("page", "count")),
    "douban_discover": ModuleMethodContract(family="douban", input_contract="DoubanDiscoverRequest", result_contract="list[MediaInfo]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("mtype", "sort", "tags", "page", "count")),
    "async_douban_discover": ModuleMethodContract(family="douban", input_contract="DoubanDiscoverRequest", result_contract="list[MediaInfo]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("mtype", "sort", "tags", "page", "count")),
    "douban_movie_credits": ModuleMethodContract(family="douban", input_contract="DoubanMediaRequest", result_contract="list[MediaPerson]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("doubanid",)),
    "async_douban_movie_credits": ModuleMethodContract(family="douban", input_contract="DoubanMediaRequest", result_contract="list[MediaPerson]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("doubanid",)),
    "douban_movie_recommend": ModuleMethodContract(family="douban", input_contract="DoubanMediaRequest", result_contract="list[MediaInfo]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("doubanid",)),
    "async_douban_movie_recommend": ModuleMethodContract(family="douban", input_contract="DoubanMediaRequest", result_contract="list[MediaInfo]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("doubanid",)),
    "douban_person_credits": ModuleMethodContract(family="douban", input_contract="DoubanPersonCreditsRequest", result_contract="list[MediaInfo]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("person_id", "page")),
    "async_douban_person_credits": ModuleMethodContract(family="douban", input_contract="DoubanPersonCreditsRequest", result_contract="list[MediaInfo]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("person_id", "page")),
    "douban_person_detail": ModuleMethodContract(family="douban", input_contract="DoubanPersonRequest", result_contract="MediaPerson | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("person_id",)),
    "async_douban_person_detail": ModuleMethodContract(family="douban", input_contract="DoubanPersonRequest", result_contract="MediaPerson | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("person_id",)),
    "douban_tv_credits": ModuleMethodContract(family="douban", input_contract="DoubanMediaRequest", result_contract="list[MediaPerson]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("doubanid",)),
    "async_douban_tv_credits": ModuleMethodContract(family="douban", input_contract="DoubanMediaRequest", result_contract="list[MediaPerson]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("doubanid",)),
    "douban_tv_recommend": ModuleMethodContract(family="douban", input_contract="DoubanMediaRequest", result_contract="list[MediaInfo]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("doubanid",)),
    "async_douban_tv_recommend": ModuleMethodContract(family="douban", input_contract="DoubanMediaRequest", result_contract="list[MediaInfo]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("doubanid",)),
    "send_message": ModuleMethodContract(family="messaging", input_contract="MessageSendRequest", result_contract="Message | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY),
    "finalize_message": ModuleMethodContract(family="messaging", input_contract="MessageFinalizeRequest", result_contract="Message | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("response",)),
    "register_commands": ModuleMethodContract(family="messaging", input_contract="CommandRegistrationRequest", result_contract="None", required_parameters=("commands",)),
    "scheduler_job": ModuleMethodContract(family="scheduling", input_contract="SchedulerJobRequest", result_contract="None"),
    "webhook_parser": ModuleMethodContract(family="integration", input_contract="WebhookRequest", result_contract="WebhookEventInfo | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("body", "form", "args")),
    "download_discord_file_bytes": ModuleMethodContract(family="messaging", input_contract="MessageFileDownloadRequest", result_contract="bytes | None", result_shape=ModuleResultShape.BYTES, aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("file_ref", "source")),
    "download_feishu_file_bytes": ModuleMethodContract(family="messaging", input_contract="MessageFileDownloadRequest", result_contract="bytes | None", result_shape=ModuleResultShape.BYTES, aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("file_ref", "source")),
    "download_feishu_image_to_data_url": ModuleMethodContract(family="messaging", input_contract="MessageImageDownloadRequest", result_contract="str | None", result_shape=ModuleResultShape.STRING, aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("image_ref", "source")),
    "download_qq_file_bytes": ModuleMethodContract(family="messaging", input_contract="MessageFileDownloadRequest", result_contract="bytes | None", result_shape=ModuleResultShape.BYTES, aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("file_ref", "source")),
    "download_slack_file_bytes": ModuleMethodContract(family="messaging", input_contract="MessageFileDownloadRequest", result_contract="bytes | None", result_shape=ModuleResultShape.BYTES, aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("file_ref", "source")),
    "download_slack_file_to_data_url": ModuleMethodContract(family="messaging", input_contract="MessageFileDownloadRequest", result_contract="str | None", result_shape=ModuleResultShape.STRING, aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("file_url", "source")),
    "download_synologychat_file_bytes": ModuleMethodContract(family="messaging", input_contract="MessageFileDownloadRequest", result_contract="bytes | None", result_shape=ModuleResultShape.BYTES, aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("file_ref", "source")),
    "download_telegram_file_bytes": ModuleMethodContract(family="messaging", input_contract="MessageFileDownloadRequest", result_contract="bytes | None", result_shape=ModuleResultShape.BYTES, aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("file_id", "source")),
    "download_telegram_file_to_base64": ModuleMethodContract(family="messaging", input_contract="MessageFileDownloadRequest", result_contract="str | None", result_shape=ModuleResultShape.STRING, aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("file_id", "source")),
    "download_vocechat_file_bytes": ModuleMethodContract(family="messaging", input_contract="MessageFileDownloadRequest", result_contract="bytes | None", result_shape=ModuleResultShape.BYTES, aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("file_ref", "source")),
    "download_vocechat_image_to_data_url": ModuleMethodContract(family="messaging", input_contract="MessageImageDownloadRequest", result_contract="str | None", result_shape=ModuleResultShape.STRING, aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("image_ref", "source")),
    "download_wechat_image_to_data_url": ModuleMethodContract(family="messaging", input_contract="MessageImageDownloadRequest", result_contract="str | None", result_shape=ModuleResultShape.STRING, aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("image_ref", "source")),
    "download_wechat_media_bytes": ModuleMethodContract(family="messaging", input_contract="MessageMediaDownloadRequest", result_contract="bytes | None", result_shape=ModuleResultShape.BYTES, aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("media_ref", "source")),
    "downloader_info": ModuleMethodContract(family="downloader", input_contract="DownloaderInfoRequest", result_contract="list[DownloaderInfo]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("downloader",)),
    "list_torrents": ModuleMethodContract(family="downloader", input_contract="TorrentListRequest", result_contract="list[DownloaderTorrent]", result_shape=ModuleResultShape.LIST, aggregation=ModuleResultAggregation.ORDERED_LIST_MERGE, required_parameters=("status", "hashs", "downloader", "include_all_tags")),
    "torrent_files": ModuleMethodContract(family="downloader", input_contract="TorrentFilesRequest", result_contract="DownloaderFileCollection | None", required_parameters=("tid", "downloader")),
    "get_torrent_trackers": ModuleMethodContract(family="downloader", input_contract="TorrentTrackersRequest", result_contract="dict[str, list[str]] | None", result_shape=ModuleResultShape.MAPPING, aggregation=ModuleResultAggregation.ORDERED_MAPPING_MERGE, required_parameters=("hash_string", "downloader")),
    "download": ModuleMethodContract(family="downloader", input_contract="DownloadTaskRequest", result_contract="DownloadTaskResult | None", aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("content", "download_dir", "cookie", "episodes", "category", "label", "downloader")),
    "remove_torrents": ModuleMethodContract(family="downloader", input_contract="TorrentRemoveRequest", result_contract="bool | None", result_shape=ModuleResultShape.BOOLEAN, aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("hashs", "delete_file", "downloader")),
    "set_torrents_tag": ModuleMethodContract(family="downloader", input_contract="TorrentTagRequest", result_contract="bool | None", result_shape=ModuleResultShape.BOOLEAN, aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("hashs", "tags", "downloader")),
    "start_torrents": ModuleMethodContract(family="downloader", input_contract="TorrentControlRequest", result_contract="bool | None", result_shape=ModuleResultShape.BOOLEAN, aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("hashs", "downloader")),
    "stop_torrents": ModuleMethodContract(family="downloader", input_contract="TorrentControlRequest", result_contract="bool | None", result_shape=ModuleResultShape.BOOLEAN, aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("hashs", "downloader")),
    "update_torrent": ModuleMethodContract(family="downloader", input_contract="TorrentUpdateRequest", result_contract="dict[str, bool] | None", result_shape=ModuleResultShape.MAPPING, aggregation=ModuleResultAggregation.FIRST_NON_EMPTY, required_parameters=("hash_string", "downloader", "download_limit", "upload_limit", "tracker_list", "save_path", "category", "ratio_limit", "seeding_time_limit")),
}

_PREFIX_CONTRACTS = (
    ("music_", ModuleMethodContract(family="music")),
    ("torrent_", ModuleMethodContract(family="downloader")),
)


# 宿主静态扫描到的全部字符串能力名。第三方插件仍可声明未在这里出现的自定义方法，
# 自定义方法继续走开放的 legacy contract；宿主新增调用则必须先进入本清单。
_OBSERVED_HOST_METHODS = (
    'anilist_credits',
    'anilist_discover',
    'anilist_info',
    'anilist_person_credits',
    'anilist_person_detail',
    'anilist_popular_this_season',
    'anilist_recommendations',
    'anilist_trending',
    'any_files',
    'async_anilist_credits',
    'async_anilist_discover',
    'async_anilist_info',
    'async_anilist_person_credits',
    'async_anilist_person_detail',
    'async_anilist_popular_this_season',
    'async_anilist_recommendations',
    'async_anilist_trending',
    'async_bangumi_calendar',
    'async_bangumi_credits',
    'async_bangumi_discover',
    'async_bangumi_info',
    'async_bangumi_person_credits',
    'async_bangumi_person_detail',
    'async_bangumi_recommend',
    'async_douban_discover',
    'async_douban_info',
    'async_douban_movie_credits',
    'async_douban_movie_recommend',
    'async_douban_person_credits',
    'async_douban_person_detail',
    'async_douban_tv_credits',
    'async_douban_tv_recommend',
    'async_identify_music_by_fingerprint',
    'async_match_doubaninfo',
    'async_match_music_album',
    'async_match_tmdbinfo',
    'async_movie_hot',
    'async_movie_showing',
    'async_movie_top250',
    'async_obtain_images',
    'async_recognize_media',
    'async_refresh_torrents',
    'async_search_collections',
    'async_search_medias',
    'async_search_persons',
    'async_search_subtitles',
    'async_search_torrents',
    'async_tmdb_collection',
    'async_tmdb_discover',
    'async_tmdb_episodes',
    'async_tmdb_group_seasons',
    'async_tmdb_info',
    'async_tmdb_movie_credits',
    'async_tmdb_movie_recommend',
    'async_tmdb_movie_similar',
    'async_tmdb_person_credits',
    'async_tmdb_person_detail',
    'async_tmdb_seasons',
    'async_tmdb_trending',
    'async_tmdb_tv_credits',
    'async_tmdb_tv_recommend',
    'async_tmdb_tv_similar',
    'async_tv_animation',
    'async_tv_hot',
    'async_tv_weekly_chinese',
    'async_tv_weekly_global',
    'async_update_recognize_cache',
    'bangumi_calendar',
    'bangumi_credits',
    'bangumi_discover',
    'bangumi_info',
    'bangumi_person_credits',
    'bangumi_person_detail',
    'bangumi_recommend',
    'channel_manage',
    'clear_cache',
    'create_folder',
    'delete_file',
    'delete_message',
    'douban_discover',
    'douban_info',
    'douban_movie_credits',
    'douban_movie_recommend',
    'douban_person_credits',
    'douban_person_detail',
    'douban_tv_credits',
    'douban_tv_recommend',
    'download',
    'download_added',
    'download_discord_file_bytes',
    'download_feishu_file_bytes',
    'download_feishu_image_to_data_url',
    'download_file',
    'download_qq_file_bytes',
    'download_slack_file_bytes',
    'download_slack_file_to_data_url',
    'download_synologychat_file_bytes',
    'download_telegram_file_bytes',
    'download_telegram_file_to_base64',
    'download_vocechat_file_bytes',
    'download_vocechat_image_to_data_url',
    'download_wechat_image_to_data_url',
    'download_wechat_media_bytes',
    'downloader_info',
    'edit_message',
    'filter_torrents',
    'finalize_message',
    'get_file_item',
    'get_folder',
    'get_parent_item',
    'get_search_page_size',
    'get_torrent_trackers',
    'identify_music_by_fingerprint',
    'list_files',
    'list_torrents',
    'load_category_config',
    'mark_message_processing_finished',
    'mark_message_processing_started',
    'match_doubaninfo',
    'match_music_album',
    'match_tmdbinfo',
    'media_category',
    'media_exists',
    'media_files',
    'media_statistic',
    'mediaserver_image_cookies',
    'mediaserver_iteminfo',
    'mediaserver_items',
    'mediaserver_items_count',
    'mediaserver_latest',
    'mediaserver_latest_images',
    'mediaserver_librarys',
    'mediaserver_play_url',
    'mediaserver_playing',
    'mediaserver_season_episode_ids',
    'mediaserver_tv_episodes',
    'message_parser',
    'metadata_img',
    'metadata_nfo',
    'movie_hot',
    'movie_showing',
    'movie_top250',
    'music_album',
    'music_album_related',
    'music_artist',
    'music_artist_albums',
    'music_artist_related',
    'music_cache_clear',
    'music_cache_delete',
    'music_cache_items',
    'music_chart',
    'music_discover',
    'music_fresh_releases',
    'music_lyrics',
    'obtain_images',
    'obtain_specific_image',
    'recognize_media',
    'recommend_name',
    'refresh_torrents',
    'refresh_userdata',
    'register_commands',
    'remove_torrents',
    'rename_file',
    'save_category_config',
    'scheduler_job',
    'search_collections',
    'search_medias',
    'search_music',
    'search_persons',
    'search_subtitles',
    'search_torrents',
    'search_tvdb',
    'send_direct_message',
    'set_torrents_tag',
    'site_subtitle_links',
    'snapshot_storage',
    'start_torrents',
    'stop_torrents',
    'storage_manage',
    'tmdb_cache_clear',
    'tmdb_cache_delete',
    'tmdb_cache_items',
    'tmdb_collection',
    'tmdb_discover',
    'tmdb_episodes',
    'tmdb_group_seasons',
    'tmdb_info',
    'tmdb_movie_credits',
    'tmdb_movie_recommend',
    'tmdb_movie_similar',
    'tmdb_person_credits',
    'tmdb_person_detail',
    'tmdb_seasons',
    'tmdb_trending',
    'tmdb_tv_credits',
    'tmdb_tv_recommend',
    'tmdb_tv_similar',
    'torrent_files',
    'transfer',
    'transfer_completed',
    'tv_animation',
    'tv_hot',
    'tv_weekly_chinese',
    'tv_weekly_global',
    'tvdb_info',
    'tvdb_slug',
    'update_recognize_cache',
    'update_torrent',
    'upload_file',
    'user_authenticate',
    'webhook_parser',
)

_FAMILY_IO_CONTRACTS = {
    "anilist": ("AniListKeywordArguments", "AniListProviderResult"),
    "authentication": ("AuthenticationKeywordArguments", "AuthenticationResult"),
    "bangumi": ("BangumiKeywordArguments", "BangumiProviderResult"),
    "category": ("CategoryKeywordArguments", "CategoryProviderResult"),
    "douban": ("DoubanKeywordArguments", "DoubanProviderResult"),
    "downloader": ("DownloaderKeywordArguments", "DownloaderProviderResult"),
    "integration": ("IntegrationKeywordArguments", "IntegrationProviderResult"),
    "media-discovery": ("MediaDiscoveryKeywordArguments", "MediaDiscoveryProviderResult"),
    "media-recognition": ("MediaRecognitionKeywordArguments", "MediaRecognitionProviderResult"),
    "media-server": ("MediaServerKeywordArguments", "MediaServerProviderResult"),
    "messaging": ("MessagingKeywordArguments", "MessagingProviderResult"),
    "metadata": ("MetadataKeywordArguments", "MetadataProviderResult"),
    "music": ("MusicKeywordArguments", "MusicProviderResult"),
    "site": ("SiteKeywordArguments", "SiteProviderResult"),
    "storage": ("StorageKeywordArguments", "StorageProviderResult"),
    "tmdb": ("TmdbKeywordArguments", "TmdbProviderResult"),
    "tvdb": ("TvdbKeywordArguments", "TvdbProviderResult"),
}


def _infer_observed_family(method: str) -> str:
    """按稳定能力前缀把已观察宿主方法归入可审计的输入/结果族。"""
    for prefix, contract in _PREFIX_CONTRACTS:
        if method.startswith(prefix):
            return contract.family
    if method.startswith(("mediaserver_", "media_exists", "media_statistic")):
        return "media-server"
    if method.startswith((
        "download", "torrent_", "list_torrents", "refresh_torrents",
        "remove_torrents", "start_torrents", "stop_torrents",
        "set_torrents_tag", "update_torrent", "get_torrent_trackers",
        "downloader_info", "filter_torrents", "transfer_completed",
    )):
        return "downloader"
    if method.startswith((
        "channel_", "delete_message", "edit_message", "finalize_message",
        "mark_message_", "message_parser", "register_commands",
        "send_direct_message", "send_message",
    )):
        return "messaging"
    if method.startswith((
        "any_files", "create_folder", "delete_file", "get_file_item",
        "get_folder", "get_parent_item", "list_files", "media_files",
        "rename_file", "snapshot_storage", "storage_manage", "transfer",
        "upload_file",
    )):
        return "storage"
    if method.startswith((
        "metadata_", "obtain_specific_image", "recommend_name",
    )):
        return "metadata"
    if method.startswith((
        "async_identify_music", "async_match_music", "identify_music",
        "match_music", "search_music",
    )):
        return "music"
    if method.startswith((
        "async_match_", "async_obtain_images", "async_recognize_media",
        "async_update_recognize_cache", "match_", "obtain_images",
        "recognize_media", "update_recognize_cache",
    )):
        return "media-recognition"
    if method.startswith((
        "async_movie_", "async_search_", "async_tv_", "movie_",
        "search_collections", "search_medias", "search_persons",
        "search_subtitles", "search_torrents", "tv_",
    )):
        return "media-discovery"
    if method in {"clear_cache", "load_category_config", "save_category_config"}:
        return "category"
    if method in {"get_search_page_size", "refresh_userdata", "site_subtitle_links"}:
        return "site"
    if method == "user_authenticate":
        return "authentication"
    return "integration"


# 多来源能力契约已把数据源降为方法参数（见 _MULTI_SOURCE_CONTRACTS），这些源前缀方法名
# 是重构前的单来源实现细节，不应各自再登记一份族契约，继续退回未分类 legacy 契约。
_SOURCE_PREFIXED_LEGACY_METHODS = frozenset({
    "tmdb_collection",
    "async_tmdb_episodes",
    "douban_info",
    "bangumi_info",
    "anilist_info",
    "tvdb_slug",
})


def _register_observed_host_contracts() -> None:
    """为全部宿主字符串调用登记完整 V2 字段，保留未知插件方法的 legacy fallback。"""
    for method in _OBSERVED_HOST_METHODS:
        if method in _METHOD_CONTRACTS or method in _SOURCE_PREFIXED_LEGACY_METHODS:
            continue
        family = _infer_observed_family(method)
        input_contract, result_contract = _FAMILY_IO_CONTRACTS[family]
        _METHOD_CONTRACTS[method] = ModuleMethodContract(
            family=family,
            input_contract=input_contract,
            result_contract=result_contract,
        )


_register_observed_host_contracts()



def get_module_method_contract(method: str) -> ModuleMethodContract:
    """返回方法的显式能力族契约，未知方法保持既有 legacy 协议。"""
    if contract := _METHOD_CONTRACTS.get(method):
        return contract
    for prefix, contract in _PREFIX_CONTRACTS:
        if method.startswith(prefix):
            return contract
    return _DEFAULT_CONTRACT


def get_multi_source_contract(method: str) -> MultiSourceCapabilityContract | None:
    """返回方法的多来源应答契约，单一来源能力返回 ``None``。"""
    return _MULTI_SOURCE_CONTRACTS.get(method)


def is_explicit_module_method(method: str) -> bool:
    """判断方法是否已进入首批显式能力族清单。"""
    return get_module_method_contract(method) is not _DEFAULT_CONTRACT


def diagnose_module_callable(method: str, callback: Callable[..., Any]) -> tuple[str, ...]:
    """诊断显式能力的基础签名；兼容阶段只返回问题，不拒绝 provider。"""
    contract = get_module_method_contract(method)
    if contract is _DEFAULT_CONTRACT:
        return ()
    try:
        parameters = inspect.signature(callback).parameters
    except (TypeError, ValueError):
        return ("signature-unavailable",)
    missing = tuple(
        name
        for name in contract.required_parameters
        if name not in parameters
        and not any(
            parameter.kind is inspect.Parameter.VAR_KEYWORD
            for parameter in parameters.values()
        )
    )
    return tuple(f"missing-parameter:{name}" for name in missing)


def diagnose_module_result(method: str, result: Any) -> tuple[str, ...]:
    """诊断显式模块结果的基础形状，兼容阶段只告警而不改写返回值。"""
    shape = get_module_method_contract(method).result_shape
    if shape is ModuleResultShape.ANY or result is None:
        return ()
    matches = {
        ModuleResultShape.LIST: isinstance(result, list),
        ModuleResultShape.STRING: isinstance(result, str),
        ModuleResultShape.MAPPING: isinstance(result, dict),
        ModuleResultShape.BOOLEAN: isinstance(result, bool),
        ModuleResultShape.BYTES: isinstance(result, bytes),
    }
    if matches.get(shape, True):
        return ()
    return (f"unexpected-result:{shape.value}:{type(result).__name__}",)


def list_explicit_module_contracts() -> dict[str, ModuleMethodContract]:
    """返回显式方法清单的副本，供架构基线和 SDK 文档使用。"""
    return dict(_METHOD_CONTRACTS)
