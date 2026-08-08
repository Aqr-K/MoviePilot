import time
from typing import List

from app import schemas
from app.core.config import settings
from app.core.plugin_source import get_plugin_source
from app.log import logger
from app.utils.plugin_repo import is_local_repo_url
from app.utils.string import StringUtils


def install_plugin_missing_dependencies() -> List[str]:
    """
    安装插件中缺失或不兼容的依赖项
    """
    pluginhelper = get_plugin_source()
    # 第一步：获取需要安装的依赖项列表
    missing_dependencies = pluginhelper.find_missing_dependencies()
    if not missing_dependencies:
        return missing_dependencies
    logger.debug(f"检测到缺失的依赖项: {missing_dependencies}")
    logger.info(f"开始安装缺失的依赖项，共 {len(missing_dependencies)} 个...")
    # 第二步：安装依赖项并返回结果
    total_start_time = time.time()
    success, message = pluginhelper.install_dependencies(missing_dependencies)
    total_elapsed_time = time.time() - total_start_time
    if success:
        logger.info(f"已完成 {len(missing_dependencies)} 个依赖项安装，总耗时：{total_elapsed_time:.2f} 秒")
    else:
        logger.warning(f"存在缺失依赖项安装失败，请尝试手动安装，总耗时：{total_elapsed_time:.2f} 秒")
    return missing_dependencies


def process_plugins_list(higher_version_plugins: List[schemas.Plugin],
                         base_version_plugins: List[schemas.Plugin]) -> List[schemas.Plugin]:
    """
    处理插件列表：合并、去重、排序、保留最高版本
    :param higher_version_plugins: 高版本插件列表
    :param base_version_plugins: 基础版本插件列表
    :return: 处理后的插件列表
    """
    # 优先处理高版本插件
    all_plugins = []
    all_plugins.extend(higher_version_plugins)
    # 将未出现在高版本插件列表中的 v1 插件加入 all_plugins
    higher_plugin_ids = {f"{p.id}{p.plugin_version}" for p in higher_version_plugins}
    all_plugins.extend([p for p in base_version_plugins if f"{p.id}{p.plugin_version}" not in higher_plugin_ids])
    markets = [item for item in settings.PLUGIN_MARKET.split(",") if item]

    def repo_order(plugin: schemas.Plugin) -> int:
        if is_local_repo_url(plugin.repo_url):
            return len(markets) + 1
        if plugin.repo_url in markets:
            return markets.index(plugin.repo_url)
        return len(markets)

    # 去重：同 ID + 版本优先保留市场来源，其次按来源顺序稳定保留。
    dedup_plugins = {}
    for plugin in sorted(all_plugins, key=repo_order):
        key = f"{plugin.id}{plugin.plugin_version}"
        exists = dedup_plugins.get(key)
        if not exists:
            dedup_plugins[key] = plugin
            continue
        if is_local_repo_url(exists.repo_url) and not is_local_repo_url(plugin.repo_url):
            dedup_plugins[key] = plugin

    # 相同 ID 的插件保留版本号最大的版本；同版本市场来源优先。
    result_by_id = {}
    for plugin in sorted(dedup_plugins.values(), key=repo_order):
        exists = result_by_id.get(plugin.id)
        if not exists:
            result_by_id[plugin.id] = plugin
            continue
        if StringUtils.compare_version(plugin.plugin_version, ">", exists.plugin_version):
            result_by_id[plugin.id] = plugin
        elif plugin.plugin_version == exists.plugin_version \
                and is_local_repo_url(exists.repo_url) \
                and not is_local_repo_url(plugin.repo_url):
            result_by_id[plugin.id] = plugin

    return list(result_by_id.values())
