from dataclasses import dataclass
from typing import Dict, Set


@dataclass(frozen=True, slots=True)
class ModuleAlias:
    """描述一个旧模块路径到 canonical 模块的精确映射。"""

    target: str
    replacement: str
    introduced: str
    owner: str
    is_package: bool = False


@dataclass(frozen=True, slots=True)
class SymbolAlias:
    """描述合成兼容包公开符号的精确来源。"""

    target_module: str
    target_name: str
    replacement: str


# 只登记已经删除旧物理源码、并完成 canonical 路径验证的模块。
MODULE_ALIASES: Dict[str, ModuleAlias] = {
    "app.log": ModuleAlias(
        target="app.sdk.logging",
        replacement="app.sdk.logging",
        introduced="v3.0.0",
        owner="sdk",
    ),
    "app.domain.string": ModuleAlias(
        target="app.sdk.string",
        replacement="app.sdk.utilities",
        introduced="v3.0.0",
        owner="sdk",
    ),
    "app.db.agentchat_oper": ModuleAlias(
        target="app.db.oper.agentchat",
        replacement="app.db.oper.agentchat",
        introduced="v3.0.0",
        owner="db",
    ),
    "app.db.agenttask_oper": ModuleAlias(
        target="app.db.oper.agenttask",
        replacement="app.db.oper.agenttask",
        introduced="v3.0.0",
        owner="db",
    ),
    "app.db.downloadfailure_oper": ModuleAlias(
        target="app.db.oper.downloadfailure",
        replacement="app.db.oper.downloadfailure",
        introduced="v3.0.0",
        owner="db",
    ),
    "app.db.downloadhistory_oper": ModuleAlias(
        target="app.db.oper.downloadhistory",
        replacement="app.db.oper.downloadhistory",
        introduced="v3.0.0",
        owner="db",
    ),
    "app.db.init": ModuleAlias(
        target="app.startup.database_initializer",
        replacement="app.startup.database_initializer",
        introduced="v3.0.0",
        owner="startup",
    ),
    "app.db.mediaserver_oper": ModuleAlias(
        target="app.db.oper.mediaserver",
        replacement="app.db.oper.mediaserver",
        introduced="v3.0.0",
        owner="db",
    ),
    "app.db.message_oper": ModuleAlias(
        target="app.db.oper.message",
        replacement="app.db.oper.message",
        introduced="v3.0.0",
        owner="db",
    ),
    "app.db.plugindata_oper": ModuleAlias(
        target="app.db.oper.plugindata",
        replacement="app.db.oper.plugindata",
        introduced="v3.0.0",
        owner="db",
    ),
    "app.db.site_oper": ModuleAlias(
        target="app.db.oper.site",
        replacement="app.db.oper.site",
        introduced="v3.0.0",
        owner="db",
    ),
    "app.db.subscribe_oper": ModuleAlias(
        target="app.sdk._legacy.subscribe",
        replacement="app.application.subscribe.add_subscribe",
        introduced="v3.0.0",
        owner="sdk",
    ),
    "app.db.subscribehistory_oper": ModuleAlias(
        target="app.db.oper.subscribehistory",
        replacement="app.db.oper.subscribehistory",
        introduced="v3.0.0",
        owner="db",
    ),
    "app.db.systemconfig_oper": ModuleAlias(
        target="app.db.oper.systemconfig",
        replacement="app.db.oper.systemconfig",
        introduced="v3.0.0",
        owner="db",
    ),
    "app.db.transferhistory_oper": ModuleAlias(
        target="app.sdk._legacy.history",
        replacement="app.application.history",
        introduced="v3.0.0",
        owner="sdk",
    ),
    "app.db.transferpending_oper": ModuleAlias(
        target="app.db.oper.transferpending",
        replacement="app.db.oper.transferpending",
        introduced="v3.0.0",
        owner="db",
    ),
    "app.db.user_oper": ModuleAlias(
        target="app.sdk._legacy.user",
        replacement="app.db.oper.user 或 app.api.deps",
        introduced="v3.0.0",
        owner="sdk",
    ),
    "app.db.userconfig_oper": ModuleAlias(
        target="app.db.oper.userconfig",
        replacement="app.db.oper.userconfig",
        introduced="v3.0.0",
        owner="db",
    ),
    "app.db.workflow_oper": ModuleAlias(
        target="app.db.oper.workflow",
        replacement="app.db.oper.workflow",
        introduced="v3.0.0",
        owner="db",
    ),
    "app.modules.qbittorrent": ModuleAlias(
        target="app.modules.downloaders.qbittorrent",
        replacement="app.modules.downloaders.qbittorrent",
        introduced="v3.0.0",
        owner="modules",
        is_package=True,
    ),
    "app.modules.qbittorrent.qbittorrent": ModuleAlias(
        target="app.modules.downloaders.qbittorrent.qbittorrent",
        replacement="app.modules.downloaders.qbittorrent.qbittorrent",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.transmission": ModuleAlias(
        target="app.modules.downloaders.transmission",
        replacement="app.modules.downloaders.transmission",
        introduced="v3.0.0",
        owner="modules",
        is_package=True,
    ),
    "app.modules.transmission.transmission": ModuleAlias(
        target="app.modules.downloaders.transmission.transmission",
        replacement="app.modules.downloaders.transmission.transmission",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.rtorrent": ModuleAlias(
        target="app.modules.downloaders.rtorrent",
        replacement="app.modules.downloaders.rtorrent",
        introduced="v3.0.0",
        owner="modules",
        is_package=True,
    ),
    "app.modules.rtorrent.rtorrent": ModuleAlias(
        target="app.modules.downloaders.rtorrent.rtorrent",
        replacement="app.modules.downloaders.rtorrent.rtorrent",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.emby": ModuleAlias(
        target="app.modules.mediaservers.emby",
        replacement="app.modules.mediaservers.emby",
        introduced="v3.0.0",
        owner="modules",
        is_package=True,
    ),
    "app.modules.emby.emby": ModuleAlias(
        target="app.modules.mediaservers.emby.emby",
        replacement="app.modules.mediaservers.emby.emby",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.jellyfin": ModuleAlias(
        target="app.modules.mediaservers.jellyfin",
        replacement="app.modules.mediaservers.jellyfin",
        introduced="v3.0.0",
        owner="modules",
        is_package=True,
    ),
    "app.modules.jellyfin.jellyfin": ModuleAlias(
        target="app.modules.mediaservers.jellyfin.jellyfin",
        replacement="app.modules.mediaservers.jellyfin.jellyfin",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.plex": ModuleAlias(
        target="app.modules.mediaservers.plex",
        replacement="app.modules.mediaservers.plex",
        introduced="v3.0.0",
        owner="modules",
        is_package=True,
    ),
    "app.modules.plex.plex": ModuleAlias(
        target="app.modules.mediaservers.plex.plex",
        replacement="app.modules.mediaservers.plex.plex",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.navidrome": ModuleAlias(
        target="app.modules.mediaservers.navidrome",
        replacement="app.modules.mediaservers.navidrome",
        introduced="v3.0.0",
        owner="modules",
        is_package=True,
    ),
    "app.modules.navidrome.navidrome": ModuleAlias(
        target="app.modules.mediaservers.navidrome.navidrome",
        replacement="app.modules.mediaservers.navidrome.navidrome",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.trimemedia": ModuleAlias(
        target="app.modules.mediaservers.trimemedia",
        replacement="app.modules.mediaservers.trimemedia",
        introduced="v3.0.0",
        owner="modules",
        is_package=True,
    ),
    "app.modules.trimemedia.api": ModuleAlias(
        target="app.modules.mediaservers.trimemedia.api",
        replacement="app.modules.mediaservers.trimemedia.api",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.trimemedia.trimemedia": ModuleAlias(
        target="app.modules.mediaservers.trimemedia.trimemedia",
        replacement="app.modules.mediaservers.trimemedia.trimemedia",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.ugreen": ModuleAlias(
        target="app.modules.mediaservers.ugreen",
        replacement="app.modules.mediaservers.ugreen",
        introduced="v3.0.0",
        owner="modules",
        is_package=True,
    ),
    "app.modules.ugreen.api": ModuleAlias(
        target="app.modules.mediaservers.ugreen.api",
        replacement="app.modules.mediaservers.ugreen.api",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.ugreen.crypto": ModuleAlias(
        target="app.modules.mediaservers.ugreen.crypto",
        replacement="app.modules.mediaservers.ugreen.crypto",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.ugreen.ugreen": ModuleAlias(
        target="app.modules.mediaservers.ugreen.ugreen",
        replacement="app.modules.mediaservers.ugreen.ugreen",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.zspace": ModuleAlias(
        target="app.modules.mediaservers.zspace",
        replacement="app.modules.mediaservers.zspace",
        introduced="v3.0.0",
        owner="modules",
        is_package=True,
    ),
    "app.modules.zspace.zspace": ModuleAlias(
        target="app.modules.mediaservers.zspace.zspace",
        replacement="app.modules.mediaservers.zspace.zspace",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.filemanager.fsproxy": ModuleAlias(
        target="app.adapters.storage.proxy",
        replacement="app.adapters.storage.proxy",
        introduced="v3.0.0",
        owner="adapters",
    ),
    "app.modules.filemanager.fsworker": ModuleAlias(
        target="app.adapters.storage.worker",
        replacement="app.adapters.storage.worker",
        introduced="v3.0.0",
        owner="adapters",
    ),
    "app.modules.filemanager.storages": ModuleAlias(
        target="app.modules.storages",
        replacement="app.modules.storages",
        introduced="v3.0.0",
        owner="adapters",
        is_package=True,
    ),
    "app.modules.filemanager.storages.base": ModuleAlias(
        target="app.modules.storages.base",
        replacement="app.modules.storages.base",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.filemanager.storages.alipan": ModuleAlias(
        target="app.modules.storages.alipan",
        replacement="app.modules.storages.alipan",
        introduced="v3.0.0",
        owner="adapters",
    ),
    "app.modules.filemanager.storages.alist": ModuleAlias(
        target="app.modules.storages.alist",
        replacement="app.modules.storages.alist",
        introduced="v3.0.0",
        owner="adapters",
    ),
    "app.modules.filemanager.storages.alistgo": ModuleAlias(
        target="app.modules.storages.alistgo",
        replacement="app.modules.storages.alistgo",
        introduced="v3.0.0",
        owner="adapters",
    ),
    "app.modules.filemanager.storages.local": ModuleAlias(
        target="app.modules.storages.local",
        replacement="app.modules.storages.local",
        introduced="v3.0.0",
        owner="adapters",
    ),
    "app.modules.filemanager.storages.rclone": ModuleAlias(
        target="app.modules.storages.rclone",
        replacement="app.modules.storages.rclone",
        introduced="v3.0.0",
        owner="adapters",
    ),
    "app.modules.filemanager.storages.smb": ModuleAlias(
        target="app.modules.storages.smb",
        replacement="app.modules.storages.smb",
        introduced="v3.0.0",
        owner="adapters",
    ),
    "app.modules.filemanager.storages.u115": ModuleAlias(
        target="app.modules.storages.u115",
        replacement="app.modules.storages.u115",
        introduced="v3.0.0",
        owner="adapters",
    ),
    "app.modules.telegram": ModuleAlias(
        target="app.modules.notifications.telegram",
        replacement="app.modules.notifications.telegram",
        introduced="v3.0.0",
        owner="modules",
        is_package=True,
    ),
    "app.modules.telegram.compat": ModuleAlias(
        target="app.modules.notifications.telegram.compat",
        replacement="app.modules.notifications.telegram.compat",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.telegram.telegram": ModuleAlias(
        target="app.modules.notifications.telegram.telegram",
        replacement="app.modules.notifications.telegram.telegram",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.slack": ModuleAlias(
        target="app.modules.notifications.slack",
        replacement="app.modules.notifications.slack",
        introduced="v3.0.0",
        owner="modules",
        is_package=True,
    ),
    "app.modules.slack.slack": ModuleAlias(
        target="app.modules.notifications.slack.slack",
        replacement="app.modules.notifications.slack.slack",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.wechat": ModuleAlias(
        target="app.modules.notifications.wechat",
        replacement="app.modules.notifications.wechat",
        introduced="v3.0.0",
        owner="modules",
        is_package=True,
    ),
    "app.modules.wechat.WXBizMsgCrypt3": ModuleAlias(
        target="app.modules.notifications.wechat.WXBizMsgCrypt3",
        replacement="app.modules.notifications.wechat.WXBizMsgCrypt3",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.wechat.wechat": ModuleAlias(
        target="app.modules.notifications.wechat.wechat",
        replacement="app.modules.notifications.wechat.wechat",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.wechat.wechatbot": ModuleAlias(
        target="app.modules.notifications.wechat.wechatbot",
        replacement="app.modules.notifications.wechat.wechatbot",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.wechatclawbot": ModuleAlias(
        target="app.modules.notifications.wechatclawbot",
        replacement="app.modules.notifications.wechatclawbot",
        introduced="v3.0.0",
        owner="modules",
        is_package=True,
    ),
    "app.modules.wechatclawbot.wechatclawbot": ModuleAlias(
        target="app.modules.notifications.wechatclawbot.wechatclawbot",
        replacement="app.modules.notifications.wechatclawbot.wechatclawbot",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.discord": ModuleAlias(
        target="app.modules.notifications.discord",
        replacement="app.modules.notifications.discord",
        introduced="v3.0.0",
        owner="modules",
        is_package=True,
    ),
    "app.modules.discord.discord": ModuleAlias(
        target="app.modules.notifications.discord.discord",
        replacement="app.modules.notifications.discord.discord",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.feishu": ModuleAlias(
        target="app.modules.notifications.feishu",
        replacement="app.modules.notifications.feishu",
        introduced="v3.0.0",
        owner="modules",
        is_package=True,
    ),
    "app.modules.feishu.feishu": ModuleAlias(
        target="app.modules.notifications.feishu.feishu",
        replacement="app.modules.notifications.feishu.feishu",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.qqbot": ModuleAlias(
        target="app.modules.notifications.qqbot",
        replacement="app.modules.notifications.qqbot",
        introduced="v3.0.0",
        owner="modules",
        is_package=True,
    ),
    "app.modules.qqbot.api": ModuleAlias(
        target="app.modules.notifications.qqbot.api",
        replacement="app.modules.notifications.qqbot.api",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.qqbot.gateway": ModuleAlias(
        target="app.modules.notifications.qqbot.gateway",
        replacement="app.modules.notifications.qqbot.gateway",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.qqbot.qqbot": ModuleAlias(
        target="app.modules.notifications.qqbot.qqbot",
        replacement="app.modules.notifications.qqbot.qqbot",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.synologychat": ModuleAlias(
        target="app.modules.notifications.synologychat",
        replacement="app.modules.notifications.synologychat",
        introduced="v3.0.0",
        owner="modules",
        is_package=True,
    ),
    "app.modules.synologychat.synologychat": ModuleAlias(
        target="app.modules.notifications.synologychat.synologychat",
        replacement="app.modules.notifications.synologychat.synologychat",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.vocechat": ModuleAlias(
        target="app.modules.notifications.vocechat",
        replacement="app.modules.notifications.vocechat",
        introduced="v3.0.0",
        owner="modules",
        is_package=True,
    ),
    "app.modules.vocechat.vocechat": ModuleAlias(
        target="app.modules.notifications.vocechat.vocechat",
        replacement="app.modules.notifications.vocechat.vocechat",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.webpush": ModuleAlias(
        target="app.modules.notifications.webpush",
        replacement="app.modules.notifications.webpush",
        introduced="v3.0.0",
        owner="modules",
        is_package=True,
    ),
    "app.modules.filemanager.transhandler": ModuleAlias(
        target="app.application.transfer.handler",
        replacement="app.application.transfer.handler",
        introduced="v3.0.0",
        owner="application",
    ),
    "app.modules.themoviedb": ModuleAlias(
        target="app.modules.recognizers.themoviedb",
        replacement="app.modules.recognizers.themoviedb",
        introduced="v3.0.0",
        owner="modules",
        is_package=True,
    ),
    "app.modules.themoviedb.category": ModuleAlias(
        target="app.modules.recognizers.themoviedb.category",
        replacement="app.modules.recognizers.themoviedb.category",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.themoviedb.scraper": ModuleAlias(
        target="app.modules.recognizers.themoviedb.scraper",
        replacement="app.modules.recognizers.themoviedb.scraper",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.themoviedb.tmdb_cache": ModuleAlias(
        target="app.modules.recognizers.themoviedb.tmdb_cache",
        replacement="app.modules.recognizers.themoviedb.tmdb_cache",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.themoviedb.tmdbapi": ModuleAlias(
        target="app.modules.recognizers.themoviedb.tmdbapi",
        replacement="app.modules.recognizers.themoviedb.tmdbapi",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.themoviedb.tmdbv3api": ModuleAlias(
        target="app.modules.recognizers.themoviedb.tmdbv3api",
        replacement="app.modules.recognizers.themoviedb.tmdbv3api",
        introduced="v3.0.0",
        owner="modules",
        is_package=True,
    ),
    "app.modules.themoviedb.tmdbv3api.as_obj": ModuleAlias(
        target="app.modules.recognizers.themoviedb.tmdbv3api.as_obj",
        replacement="app.modules.recognizers.themoviedb.tmdbv3api.as_obj",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.themoviedb.tmdbv3api.exceptions": ModuleAlias(
        target="app.modules.recognizers.themoviedb.tmdbv3api.exceptions",
        replacement="app.modules.recognizers.themoviedb.tmdbv3api.exceptions",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.themoviedb.tmdbv3api.objs": ModuleAlias(
        target="app.modules.recognizers.themoviedb.tmdbv3api.objs",
        replacement="app.modules.recognizers.themoviedb.tmdbv3api.objs",
        introduced="v3.0.0",
        owner="modules",
        is_package=True,
    ),
    "app.modules.themoviedb.tmdbv3api.tmdb": ModuleAlias(
        target="app.modules.recognizers.themoviedb.tmdbv3api.tmdb",
        replacement="app.modules.recognizers.themoviedb.tmdbv3api.tmdb",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.themoviedb.tmdbv3api.objs.account": ModuleAlias(
        target="app.modules.recognizers.themoviedb.tmdbv3api.objs.account",
        replacement="app.modules.recognizers.themoviedb.tmdbv3api.objs.account",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.themoviedb.tmdbv3api.objs.auth": ModuleAlias(
        target="app.modules.recognizers.themoviedb.tmdbv3api.objs.auth",
        replacement="app.modules.recognizers.themoviedb.tmdbv3api.objs.auth",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.themoviedb.tmdbv3api.objs.certification": ModuleAlias(
        target="app.modules.recognizers.themoviedb.tmdbv3api.objs.certification",
        replacement="app.modules.recognizers.themoviedb.tmdbv3api.objs.certification",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.themoviedb.tmdbv3api.objs.change": ModuleAlias(
        target="app.modules.recognizers.themoviedb.tmdbv3api.objs.change",
        replacement="app.modules.recognizers.themoviedb.tmdbv3api.objs.change",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.themoviedb.tmdbv3api.objs.collection": ModuleAlias(
        target="app.modules.recognizers.themoviedb.tmdbv3api.objs.collection",
        replacement="app.modules.recognizers.themoviedb.tmdbv3api.objs.collection",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.themoviedb.tmdbv3api.objs.company": ModuleAlias(
        target="app.modules.recognizers.themoviedb.tmdbv3api.objs.company",
        replacement="app.modules.recognizers.themoviedb.tmdbv3api.objs.company",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.themoviedb.tmdbv3api.objs.configuration": ModuleAlias(
        target="app.modules.recognizers.themoviedb.tmdbv3api.objs.configuration",
        replacement="app.modules.recognizers.themoviedb.tmdbv3api.objs.configuration",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.themoviedb.tmdbv3api.objs.credit": ModuleAlias(
        target="app.modules.recognizers.themoviedb.tmdbv3api.objs.credit",
        replacement="app.modules.recognizers.themoviedb.tmdbv3api.objs.credit",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.themoviedb.tmdbv3api.objs.discover": ModuleAlias(
        target="app.modules.recognizers.themoviedb.tmdbv3api.objs.discover",
        replacement="app.modules.recognizers.themoviedb.tmdbv3api.objs.discover",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.themoviedb.tmdbv3api.objs.episode": ModuleAlias(
        target="app.modules.recognizers.themoviedb.tmdbv3api.objs.episode",
        replacement="app.modules.recognizers.themoviedb.tmdbv3api.objs.episode",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.themoviedb.tmdbv3api.objs.find": ModuleAlias(
        target="app.modules.recognizers.themoviedb.tmdbv3api.objs.find",
        replacement="app.modules.recognizers.themoviedb.tmdbv3api.objs.find",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.themoviedb.tmdbv3api.objs.genre": ModuleAlias(
        target="app.modules.recognizers.themoviedb.tmdbv3api.objs.genre",
        replacement="app.modules.recognizers.themoviedb.tmdbv3api.objs.genre",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.themoviedb.tmdbv3api.objs.group": ModuleAlias(
        target="app.modules.recognizers.themoviedb.tmdbv3api.objs.group",
        replacement="app.modules.recognizers.themoviedb.tmdbv3api.objs.group",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.themoviedb.tmdbv3api.objs.keyword": ModuleAlias(
        target="app.modules.recognizers.themoviedb.tmdbv3api.objs.keyword",
        replacement="app.modules.recognizers.themoviedb.tmdbv3api.objs.keyword",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.themoviedb.tmdbv3api.objs.list": ModuleAlias(
        target="app.modules.recognizers.themoviedb.tmdbv3api.objs.list",
        replacement="app.modules.recognizers.themoviedb.tmdbv3api.objs.list",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.themoviedb.tmdbv3api.objs.movie": ModuleAlias(
        target="app.modules.recognizers.themoviedb.tmdbv3api.objs.movie",
        replacement="app.modules.recognizers.themoviedb.tmdbv3api.objs.movie",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.themoviedb.tmdbv3api.objs.network": ModuleAlias(
        target="app.modules.recognizers.themoviedb.tmdbv3api.objs.network",
        replacement="app.modules.recognizers.themoviedb.tmdbv3api.objs.network",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.themoviedb.tmdbv3api.objs.person": ModuleAlias(
        target="app.modules.recognizers.themoviedb.tmdbv3api.objs.person",
        replacement="app.modules.recognizers.themoviedb.tmdbv3api.objs.person",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.themoviedb.tmdbv3api.objs.provider": ModuleAlias(
        target="app.modules.recognizers.themoviedb.tmdbv3api.objs.provider",
        replacement="app.modules.recognizers.themoviedb.tmdbv3api.objs.provider",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.themoviedb.tmdbv3api.objs.review": ModuleAlias(
        target="app.modules.recognizers.themoviedb.tmdbv3api.objs.review",
        replacement="app.modules.recognizers.themoviedb.tmdbv3api.objs.review",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.themoviedb.tmdbv3api.objs.search": ModuleAlias(
        target="app.modules.recognizers.themoviedb.tmdbv3api.objs.search",
        replacement="app.modules.recognizers.themoviedb.tmdbv3api.objs.search",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.themoviedb.tmdbv3api.objs.season": ModuleAlias(
        target="app.modules.recognizers.themoviedb.tmdbv3api.objs.season",
        replacement="app.modules.recognizers.themoviedb.tmdbv3api.objs.season",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.themoviedb.tmdbv3api.objs.trending": ModuleAlias(
        target="app.modules.recognizers.themoviedb.tmdbv3api.objs.trending",
        replacement="app.modules.recognizers.themoviedb.tmdbv3api.objs.trending",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.themoviedb.tmdbv3api.objs.tv": ModuleAlias(
        target="app.modules.recognizers.themoviedb.tmdbv3api.objs.tv",
        replacement="app.modules.recognizers.themoviedb.tmdbv3api.objs.tv",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.douban": ModuleAlias(
        target="app.modules.recognizers.douban",
        replacement="app.modules.recognizers.douban",
        introduced="v3.0.0",
        owner="modules",
        is_package=True,
    ),
    "app.modules.douban.apiv2": ModuleAlias(
        target="app.modules.recognizers.douban.apiv2",
        replacement="app.modules.recognizers.douban.apiv2",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.douban.scraper": ModuleAlias(
        target="app.modules.recognizers.douban.scraper",
        replacement="app.modules.recognizers.douban.scraper",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.bangumi": ModuleAlias(
        target="app.modules.recognizers.bangumi",
        replacement="app.modules.recognizers.bangumi",
        introduced="v3.0.0",
        owner="modules",
        is_package=True,
    ),
    "app.modules.bangumi.bangumi": ModuleAlias(
        target="app.modules.recognizers.bangumi.bangumi",
        replacement="app.modules.recognizers.bangumi.bangumi",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.anilist": ModuleAlias(
        target="app.modules.recognizers.anilist",
        replacement="app.modules.recognizers.anilist",
        introduced="v3.0.0",
        owner="modules",
        is_package=True,
    ),
    "app.modules.anilist.anilist": ModuleAlias(
        target="app.modules.recognizers.anilist.anilist",
        replacement="app.modules.recognizers.anilist.anilist",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.thetvdb": ModuleAlias(
        target="app.modules.recognizers.thetvdb",
        replacement="app.modules.recognizers.thetvdb",
        introduced="v3.0.0",
        owner="modules",
        is_package=True,
    ),
    "app.modules.thetvdb.tvdb_v4_official": ModuleAlias(
        target="app.modules.recognizers.thetvdb.tvdb_v4_official",
        replacement="app.modules.recognizers.thetvdb.tvdb_v4_official",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.musicbrainz": ModuleAlias(
        target="app.modules.recognizers.musicbrainz",
        replacement="app.modules.recognizers.musicbrainz",
        introduced="v3.0.0",
        owner="modules",
        is_package=True,
    ),
    "app.modules.musicbrainz.api": ModuleAlias(
        target="app.modules.recognizers.musicbrainz.api",
        replacement="app.modules.recognizers.musicbrainz.api",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.musicbrainz.music_cache": ModuleAlias(
        target="app.modules.recognizers.musicbrainz.music_cache",
        replacement="app.modules.recognizers.musicbrainz.music_cache",
        introduced="v3.0.0",
        owner="modules",
    ),
    "app.modules.theaudiodb": ModuleAlias(
        target="app.modules.recognizers.theaudiodb",
        replacement="app.modules.recognizers.theaudiodb",
        introduced="v3.0.0",
        owner="modules",
        is_package=True,
    ),
    "app.utils.crypto": ModuleAlias(
        target="app.foundation.crypto",
        replacement="app.sdk.utilities",
        introduced="v3.0.0",
        owner="foundation",
    ),
    "app.utils.dom": ModuleAlias(
        target="app.foundation.dom",
        replacement="app.sdk.utilities",
        introduced="v3.0.0",
        owner="foundation",
    ),
    "app.utils.identity": ModuleAlias(
        target="app.foundation.identity",
        replacement="app.foundation.identity",
        introduced="v3.0.0",
        owner="foundation",
    ),
    "app.utils.ip": ModuleAlias(
        target="app.adapters.network.ip",
        replacement="app.sdk.network",
        introduced="v3.0.0",
        owner="adapters",
    ),
    "app.utils.jieba": ModuleAlias(
        target="app.foundation.text",
        replacement="app.sdk.utilities",
        introduced="v3.0.0",
        owner="foundation",
    ),
    "app.utils.object": ModuleAlias(
        target="app.foundation.reflection",
        replacement="app.sdk.utilities",
        introduced="v3.0.0",
        owner="foundation",
    ),
    "app.utils.otp": ModuleAlias(
        target="app.application.security.otp",
        replacement="app.sdk.utilities",
        introduced="v3.0.0",
        owner="application",
    ),
    "app.utils.singleton": ModuleAlias(
        target="app.foundation.singleton",
        replacement="app.sdk.utilities",
        introduced="v3.0.0",
        owner="foundation",
    ),
    "app.utils.structures": ModuleAlias(
        target="app.foundation.collections",
        replacement="app.foundation.collections",
        introduced="v3.0.0",
        owner="foundation",
    ),
    "app.utils.timer": ModuleAlias(
        target="app.runtime.scheduling",
        replacement="app.sdk.utilities",
        introduced="v3.0.0",
        owner="runtime",
    ),
    "app.utils.tokens": ModuleAlias(
        target="app.domain.tokens",
        replacement="app.sdk.media",
        introduced="v3.0.0",
        owner="domain",
    ),
    "app.utils.zhconv": ModuleAlias(
        target="app.foundation.text",
        replacement="app.foundation.text",
        introduced="v3.0.0",
        owner="foundation",
    ),
    "app.utils.stdio": ModuleAlias(
        target="app.adapters.system.stdio",
        replacement="app.adapters.system.stdio",
        introduced="v3.0.0",
        owner="adapters",
    ),
    "app.utils.system": ModuleAlias(
        target="app.adapters.system.host",
        replacement="app.sdk.utilities",
        introduced="v3.0.0",
        owner="adapters",
    ),
    "app.utils.coalesce": ModuleAlias(
        target="app.runtime.coalesce",
        replacement="app.runtime.coalesce",
        introduced="v3.0.0",
        owner="runtime",
    ),
    "app.utils.common": ModuleAlias(
        target="app.sdk.utilities",
        replacement="app.sdk.utilities",
        introduced="v3.0.0",
        owner="sdk",
    ),
    "app.utils.debounce": ModuleAlias(
        target="app.runtime.debounce",
        replacement="app.runtime.debounce",
        introduced="v3.0.0",
        owner="runtime",
    ),
    "app.utils.gc": ModuleAlias(
        target="app.runtime.gc",
        replacement="app.runtime.gc",
        introduced="v3.0.0",
        owner="runtime",
    ),
    "app.utils.http": ModuleAlias(
        target="app.adapters.network.http",
        replacement="app.sdk.network",
        introduced="v3.0.0",
        owner="foundation",
    ),
    "app.utils.limit": ModuleAlias(
        target="app.runtime.rate",
        replacement="app.runtime.rate",
        introduced="v3.0.0",
        owner="runtime",
    ),
    "app.utils.media": ModuleAlias(
        target="app.sdk.media",
        replacement="app.sdk.media",
        introduced="v3.0.0",
        owner="sdk",
    ),
    "app.utils.mixins": ModuleAlias(
        target="app.runtime.reload",
        replacement="app.runtime.reload",
        introduced="v3.0.0",
        owner="runtime",
    ),
    "app.utils.rust_accel": ModuleAlias(
        target="app.adapters.system.rust",
        replacement="app.adapters.system.rust",
        introduced="v3.0.0",
        owner="adapters",
    ),
    "app.utils.security": ModuleAlias(
        target="app.application.security.url",
        replacement="app.sdk.network",
        introduced="v3.0.0",
        owner="application",
    ),
    "app.utils.site": ModuleAlias(
        target="app.domain.site",
        replacement="app.sdk.network",
        introduced="v3.0.0",
        owner="domain",
    ),
    "app.utils.string": ModuleAlias(
        target="app.sdk.string",
        replacement="app.sdk.utilities",
        introduced="v3.0.0",
        owner="sdk",
    ),
    "app.utils.url": ModuleAlias(
        target="app.foundation.url",
        replacement="app.sdk.network",
        introduced="v3.0.0",
        owner="foundation",
    ),
    "app.utils.web": ModuleAlias(
        target="app.adapters.external.location",
        replacement="app.sdk.network",
        introduced="v3.0.0",
        owner="adapters",
    ),
    "app.core.auth": ModuleAlias(
        target="app.application.security.auth",
        replacement="app.application.security.auth",
        introduced="v3.0.0",
        owner="application",
    ),
    "app.core.auth_bridge": ModuleAlias(
        target="app.application.security.auth",
        replacement="app.application.security.auth",
        introduced="v3.0.0",
        owner="application",
    ),
    "app.core.cache": ModuleAlias(
        target="app.sdk.cache",
        replacement="app.sdk.cache",
        introduced="v3.0.0",
        owner="sdk",
    ),
    "app.core.config": ModuleAlias(
        target="app.runtime.config",
        replacement="app.sdk.config",
        introduced="v3.0.0",
        owner="runtime",
    ),
    "app.core.context": ModuleAlias(
        target="app.domain.context",
        replacement="app.sdk.media",
        introduced="v3.0.0",
        owner="domain",
    ),
    "app.core.event": ModuleAlias(
        target="app.runtime.events",
        replacement="app.sdk.events",
        introduced="v3.0.0",
        owner="runtime",
    ),
    "app.core.meta.customization": ModuleAlias(
        target="app.domain.meta.customization",
        replacement="app.sdk.media",
        introduced="v3.0.0",
        owner="domain",
    ),
    "app.core.meta.infopath": ModuleAlias(
        target="app.domain.meta.infopath",
        replacement="app.sdk.media",
        introduced="v3.0.0",
        owner="domain",
    ),
    "app.core.meta.metaanime": ModuleAlias(
        target="app.domain.meta.metaanime",
        replacement="app.sdk.media",
        introduced="v3.0.0",
        owner="domain",
    ),
    "app.core.meta.metabase": ModuleAlias(
        target="app.domain.meta.metabase",
        replacement="app.sdk.media",
        introduced="v3.0.0",
        owner="domain",
    ),
    "app.core.meta.metamusic": ModuleAlias(
        target="app.domain.meta.metamusic",
        replacement="app.sdk.media",
        introduced="v3.0.0",
        owner="domain",
    ),
    "app.core.meta.metavideo": ModuleAlias(
        target="app.domain.meta.metavideo",
        replacement="app.sdk.media",
        introduced="v3.0.0",
        owner="domain",
    ),
    "app.core.meta.releasegroup": ModuleAlias(
        target="app.domain.meta.releasegroup",
        replacement="app.sdk.media",
        introduced="v3.0.0",
        owner="domain",
    ),
    "app.core.meta.streamingplatform": ModuleAlias(
        target="app.domain.meta.streamingplatform",
        replacement="app.sdk.media",
        introduced="v3.0.0",
        owner="domain",
    ),
    "app.core.meta.words": ModuleAlias(
        target="app.domain.meta.words",
        replacement="app.sdk.media",
        introduced="v3.0.0",
        owner="domain",
    ),
    "app.core.metainfo": ModuleAlias(
        target="app.domain.metainfo",
        replacement="app.sdk.media",
        introduced="v3.0.0",
        owner="domain",
    ),
    "app.core.module": ModuleAlias(
        target="app.runtime.extensions.module_manager",
        replacement="app.sdk.plugins",
        introduced="v3.0.0",
        owner="runtime",
    ),
    "app.core.plugin": ModuleAlias(
        target="app.runtime.extensions.plugin_manager",
        replacement="app.sdk.plugins",
        introduced="v3.0.0",
        owner="runtime",
    ),
    "app.core.security": ModuleAlias(
        target="app.application.security.access",
        replacement="app.application.security.access",
        introduced="v3.0.0",
        owner="application",
    ),
    "app.helper.agent": ModuleAlias(
        target="app.application.messaging.agent", replacement="app.application.messaging.agent",
        introduced="v3.0.0", owner="application",
    ),
    "app.helper.audio": ModuleAlias(
        target="app.application.audio", replacement="app.application.audio",
        introduced="v3.0.0", owner="application",
    ),
    "app.helper.browser": ModuleAlias(
        target="app.adapters.network.browser", replacement="app.adapters.network.browser",
        introduced="v3.0.0", owner="adapters",
    ),
    "app.helper.cloudflare": ModuleAlias(
        target="app.adapters.network.cloudflare", replacement="app.adapters.network.cloudflare",
        introduced="v3.0.0", owner="adapters",
    ),
    "app.helper.cookie": ModuleAlias(
        target="app.application.security.cookie", replacement="app.application.security.cookie",
        introduced="v3.0.0", owner="application",
    ),
    "app.helper.cookiecloud": ModuleAlias(
        target="app.adapters.external.cookiecloud", replacement="app.adapters.external.cookiecloud",
        introduced="v3.0.0", owner="adapters",
    ),
    "app.helper.directory": ModuleAlias(
        target="app.application.directory", replacement="app.application.directory",
        introduced="v3.0.0", owner="application",
    ),
    "app.helper.display": ModuleAlias(
        target="app.adapters.system.display", replacement="app.adapters.system.display",
        introduced="v3.0.0", owner="adapters",
    ),
    "app.helper.doh": ModuleAlias(
        target="app.adapters.network.doh", replacement="app.adapters.network.doh",
        introduced="v3.0.0", owner="adapters",
    ),
    "app.helper.downloader": ModuleAlias(
        target="app.application.downloader", replacement="app.sdk.services",
        introduced="v3.0.0", owner="application",
    ),
    "app.helper.format": ModuleAlias(
        target="app.application.formatting", replacement="app.application.formatting",
        introduced="v3.0.0", owner="application",
    ),
    "app.helper.image": ModuleAlias(
        target="app.application.image", replacement="app.application.image",
        introduced="v3.0.0", owner="application",
    ),
    "app.helper.interaction": ModuleAlias(
        target="app.application.messaging.interaction", replacement="app.application.messaging.interaction",
        introduced="v3.0.0", owner="application",
    ),
    "app.helper.locale": ModuleAlias(
        target="app.runtime.localization", replacement="app.sdk.utilities",
        introduced="v3.0.0", owner="runtime",
    ),
    "app.helper.market": ModuleAlias(
        target="app.adapters.external.market",
        replacement="app.adapters.external.market",
        introduced="v3.0.0", owner="adapters",
    ),
    "app.helper.mediaserver": ModuleAlias(
        target="app.application.mediaserver", replacement="app.sdk.services",
        introduced="v3.0.0", owner="application",
    ),
    "app.helper.message": ModuleAlias(
        target="app.application.messaging.message", replacement="app.application.messaging.message",
        introduced="v3.0.0", owner="application",
    ),
    "app.helper.module": ModuleAlias(
        target="app.foundation.reflection", replacement="app.foundation.reflection",
        introduced="v3.0.0", owner="foundation",
    ),
    "app.helper.nfo": ModuleAlias(
        target="app.domain.scraper", replacement="app.sdk.media",
        introduced="v3.0.0", owner="domain",
    ),
    "app.helper.notification": ModuleAlias(
        target="app.application.notification", replacement="app.sdk.services",
        introduced="v3.0.0", owner="application",
    ),
    "app.helper.ocr": ModuleAlias(
        target="app.adapters.external.ocr", replacement="app.adapters.external.ocr",
        introduced="v3.0.0", owner="adapters",
    ),
    "app.helper.package": ModuleAlias(
        target="app.adapters.system.package",
        replacement="app.adapters.system.package",
        introduced="v3.0.0", owner="adapters",
    ),
    "app.helper.passkey": ModuleAlias(
        target="app.application.security.passkey", replacement="app.application.security.passkey",
        introduced="v3.0.0", owner="application",
    ),
    "app.helper.plugin": ModuleAlias(
        target="app.adapters.external.market",
        replacement="app.adapters.external.market",
        introduced="v3.0.0", owner="adapters",
    ),
    "app.helper.progress": ModuleAlias(
        target="app.runtime.progress", replacement="app.runtime.progress",
        introduced="v3.0.0", owner="runtime",
    ),
    "app.helper.redis": ModuleAlias(
        target="app.adapters.cache.redis", replacement="app.adapters.cache.redis",
        introduced="v3.0.0", owner="adapters",
    ),
    "app.helper.resource": ModuleAlias(
        target="app.adapters.system.resource",
        replacement="app.adapters.system.resource",
        introduced="v3.0.0", owner="adapters",
    ),
    "app.helper.rss": ModuleAlias(
        target="app.application.rss", replacement="app.sdk.network",
        introduced="v3.0.0", owner="application",
    ),
    "app.helper.rule": ModuleAlias(
        target="app.application.filter", replacement="app.sdk.services",
        introduced="v3.0.0", owner="application",
    ),
    "app.helper.scraper": ModuleAlias(
        target="app.domain.scraper", replacement="app.domain.scraper",
        introduced="v3.0.0", owner="domain",
    ),
    "app.helper.server": ModuleAlias(
        target="app.adapters.external.server", replacement="app.adapters.external.server",
        introduced="v3.0.0", owner="adapters",
    ),
    "app.helper.service": ModuleAlias(
        target="app.runtime.extensions.service_registry",
        replacement="app.sdk.services",
        introduced="v3.0.0", owner="runtime",
    ),
    "app.helper.sites": ModuleAlias(
        target="app.application.site.sites", replacement="app.sdk.network",
        introduced="v3.0.0", owner="application",
    ),
    "app.helper.skill": ModuleAlias(
        target="app.agent.skills.registry",
        replacement="app.agent.skills.registry",
        introduced="v3.0.0", owner="agent",
    ),
    "app.helper.storage": ModuleAlias(
        target="app.adapters.storage.config", replacement="app.sdk.services",
        introduced="v3.0.0", owner="adapters",
    ),
    "app.helper.system": ModuleAlias(
        target="app.runtime.state", replacement="app.sdk.services",
        introduced="v3.0.0", owner="runtime",
    ),
    "app.helper.thread": ModuleAlias(
        target="app.runtime.thread", replacement="app.runtime.thread",
        introduced="v3.0.0", owner="runtime",
    ),
    "app.helper.torrent": ModuleAlias(
        target="app.application.torrent", replacement="app.application.torrent",
        introduced="v3.0.0", owner="application",
    ),
    "app.helper.transferhistory": ModuleAlias(
        target="app.application.history",
        replacement="app.application.history",
        introduced="v3.0.0", owner="application",
    ),
    "app.helper.twofa": ModuleAlias(
        target="app.application.security.twofactor", replacement="app.application.security.twofactor",
        introduced="v3.0.0", owner="application",
    ),
    "app.helper.webpush": ModuleAlias(
        target="app.api.endpoints.message", replacement="app.api.endpoints.message",
        introduced="v3.0.0", owner="api",
    ),
    "app.helper.wallpaper": ModuleAlias(
        target="app.application.image", replacement="app.application.image",
        introduced="v3.0.0", owner="application",
    ),
    "app.helper.llm": ModuleAlias(
        target="app.agent.llm", replacement="app.agent.llm",
        introduced="v3.0.0", owner="agent", is_package=True,
    ),
    "app.helper.llm.capability": ModuleAlias(
        target="app.agent.llm.capability", replacement="app.agent.llm.capability",
        introduced="v3.0.0", owner="agent",
    ),
    "app.helper.llm.helper": ModuleAlias(
        target="app.agent.llm.helper", replacement="app.agent.llm.helper",
        introduced="v3.0.0", owner="agent",
    ),
    "app.helper.llm.provider": ModuleAlias(
        target="app.agent.llm.provider", replacement="app.agent.llm.provider",
        introduced="v3.0.0", owner="agent",
    ),
    "app.helper.llm.server_tools": ModuleAlias(
        target="app.agent.llm.server_tools", replacement="app.agent.llm.server_tools",
        introduced="v3.0.0", owner="agent",
    ),
}

# 需要合成包级符号的旧路径单独登记；它们不是 canonical 模块别名。
PACKAGE_ALIASES: Dict[str, ModuleAlias] = {
    "app.core.meta": ModuleAlias(
        target="app.domain.meta",
        replacement="app.sdk.media",
        introduced="v3.0.0",
        owner="domain",
        is_package=True,
    ),
}

# 旧父包完全迁空后才登记；迁移中的物理父包继续由 PathFinder 处理。
VIRTUAL_PACKAGES: Set[str] = {"app.core", "app.helper", "app.utils"}

# 旧包 __init__.py 曾公开的符号在这里显式声明，禁止模糊转发。
PACKAGE_EXPORTS: Dict[str, Dict[str, SymbolAlias]] = {
    "app.core.meta": {
        "MetaBase": SymbolAlias(
            target_module="app.domain.meta.metabase",
            target_name="MetaBase",
            replacement="app.sdk.media.MetaBase",
        ),
        "MetaVideo": SymbolAlias(
            target_module="app.domain.meta.metavideo",
            target_name="MetaVideo",
            replacement="app.sdk.media.MetaVideo",
        ),
        "MetaAnime": SymbolAlias(
            target_module="app.domain.meta.metaanime",
            target_name="MetaAnime",
            replacement="app.sdk.media.MetaAnime",
        ),
        "MetaMusic": SymbolAlias(
            target_module="app.domain.meta.metamusic",
            target_name="MetaMusic",
            replacement="app.sdk.media.MetaMusic",
        ),
        "MusicNameContext": SymbolAlias(
            target_module="app.domain.meta.metamusic",
            target_name="MusicNameContext",
            replacement="app.sdk.media.MusicNameContext",
        ),
        "MusicNameParseResult": SymbolAlias(
            target_module="app.domain.meta.metamusic",
            target_name="MusicNameParseResult",
            replacement="app.sdk.media.MusicNameParseResult",
        ),
        "MusicNameParser": SymbolAlias(
            target_module="app.domain.meta.metamusic",
            target_name="MusicNameParser",
            replacement="app.sdk.media.MusicNameParser",
        ),
        "MusicNamePattern": SymbolAlias(
            target_module="app.domain.meta.metamusic",
            target_name="MusicNamePattern",
            replacement="app.sdk.media.MusicNamePattern",
        ),
        "MusicNamePatternMatch": SymbolAlias(
            target_module="app.domain.meta.metamusic",
            target_name="MusicNamePatternMatch",
            replacement="app.sdk.media.MusicNamePatternMatch",
        ),
        "MusicNameRegistry": SymbolAlias(
            target_module="app.domain.meta.metamusic",
            target_name="MusicNameRegistry",
            replacement="app.sdk.media.MusicNameRegistry",
        ),
    },
}

# 物理模块仍存在、仅部分公开符号迁走时，由导入器在标准 Loader 执行后叠加惰性符号路由。
# canonical 源码不反向依赖兼容层，目标符号也只在旧调用方真正取用时加载。
SYMBOL_ALIASES: Dict[str, Dict[str, SymbolAlias]] = {
    "app.domain.media": {
        name: SymbolAlias(
            target_module="app.schemas.media",
            target_name=name,
            replacement=f"app.schemas.media.{name}",
        )
        for name in (
            "MEDIA_SOURCE_ALIASES",
            "MEDIA_SOURCE_PREFIXES",
            "normalize_media_source",
            "parse_media_key",
            "resolve_media_identity",
            "normalize_media_identity_payload",
            "build_media_key",
        )
    },
    "app.schemas": {
        name: SymbolAlias(
            target_module="app.sdk._legacy.transfer",
            target_name=name,
            replacement=f"app.application.transfer.{name}",
        )
        for name in ("TransferTask", "TransferQueue")
    },
    "app.schemas.transfer": {
        name: SymbolAlias(
            target_module="app.sdk._legacy.transfer",
            target_name=name,
            replacement=f"app.application.transfer.{name}",
        )
        for name in ("TransferTask", "TransferQueue")
    },
}
