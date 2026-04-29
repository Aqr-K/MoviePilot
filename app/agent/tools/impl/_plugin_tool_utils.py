"""插件 Agent 工具共享辅助方法"""

import json
from typing import Any, Optional

from app.core.plugin import PluginManager

# 默认只向智能体返回一个可读预览，避免超大插件数据挤爆上下文窗口。
DEFAULT_PLUGIN_DATA_PREVIEW_CHARS = 12_000
MAX_PLUGIN_DATA_PREVIEW_CHARS = 50_000
PLUGIN_DATA_KEY_PREVIEW_LIMIT = 50
PLUGIN_DATA_TRUNCATION_SUFFIX = "\n...(插件数据内容过长，已截断)"


def get_plugin_snapshot(plugin_id: str) -> Optional[dict[str, Any]]:
    """
    获取已安装插件的基础信息快照。
    """
    plugin_manager = PluginManager()
    for plugin in plugin_manager.get_local_plugins():
        if plugin.id == plugin_id:
            return {
                "plugin_id": plugin.id,
                "plugin_name": plugin.plugin_name,
                "plugin_version": plugin.plugin_version,
                "state": plugin.state,
            }
    return None


def clamp_preview_chars(max_chars: Optional[int]) -> int:
    """
    约束插件数据预览长度，避免工具结果无限膨胀。
    """
    if max_chars is None:
        return DEFAULT_PLUGIN_DATA_PREVIEW_CHARS
    return max(512, min(int(max_chars), MAX_PLUGIN_DATA_PREVIEW_CHARS))


def serialize_for_agent(value: Any) -> str:
    """
    将结果稳定序列化为 JSON 字符串，无法原生序列化的对象退化为字符串。
    """
    return json.dumps(value, ensure_ascii=False, indent=2, default=str)


def build_preview_payload(value: Any, max_chars: Optional[int]) -> tuple[bool, int, int, str]:
    """
    为可能很大的插件数据生成预览结果。
    """
    serialized = serialize_for_agent(value)
    if len(serialized) <= clamp_preview_chars(max_chars):
        return False, len(serialized), len(serialized), serialized

    preview_limit = clamp_preview_chars(max_chars)
    preview = serialized[:preview_limit] + PLUGIN_DATA_TRUNCATION_SUFFIX
    return True, len(serialized), len(preview), preview


def reload_plugin_runtime(plugin_id: str) -> None:
    """
    重载插件并重新注册其命令、定时任务和 API。
    """
    # 这些依赖只在真正执行重载时才导入，避免普通查询工具引入不必要的初始化开销。
    from app.api.endpoints.plugin import register_plugin_api
    from app.command import Command
    from app.scheduler import Scheduler

    plugin_manager = PluginManager()
    plugin_manager.reload_plugin(plugin_id)
    Scheduler().update_plugin_job(plugin_id)
    Command().init_commands(plugin_id)
    register_plugin_api(plugin_id)
