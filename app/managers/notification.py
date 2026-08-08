from typing import Any, Dict, Optional

from app.managers.base import PluginDispatchManager


class NotificationManager(PluginDispatchManager):
    """
    消息通知（Notification 域）统一入口（单例）。

    对外提供一组通知操作方法（契约见 app.modules.INotification），按方法名分两步分发：先经各已启用插件
    注册的同名方法，再到系统通知后端模块（内建 Telegram/WeChat/Slack/Discord/VoceChat/... 及插件经
    provides_notifications() 注册的渠道）。每次分发实时查询当前运行的后端，自动纳入运行期注册/卸载的渠道。

    分发内核（两步 dispatch / 插件钩子面 + 系统后端面 / 合并 / 错误处理）见基类 PluginDispatchManager。

    通知为广播域：post_* 类方法返回 None、不短路，对所有启用渠道广播（各渠道内部自行按渠道/来源/类型过滤
    是否处理）；delete_message/edit_message 等返回非空值，按取首个非空短路。后端按需实现子集，按方法名分发
    自然只命中实现者。

    对外方法的参数原样转发到后端（各方法的参数见下方说明及 app.modules.INotification）。
    """

    # ------------------------------------------------------------------ #
    # INotification 对外面：按方法名转发到 dispatch。
    # ------------------------------------------------------------------ #

    def post_message(self, *args, **kwargs) -> None:
        """
        发送通知消息，广播到所有启用的通知渠道（各渠道内部自行过滤是否处理）。

        :param message: 通知内容（Notification）
        """
        return self.dispatch("post_message", *args, **kwargs)

    def post_medias_message(self, *args, **kwargs) -> None:
        """
        发送媒体信息选择列表，广播到所有启用渠道。

        :param message: 通知内容（Notification）
        :param medias: 媒体信息列表（List[MediaInfo]）
        """
        return self.dispatch("post_medias_message", *args, **kwargs)

    def post_torrents_message(self, *args, **kwargs) -> None:
        """
        发送种子信息选择列表，广播到所有启用渠道。

        :param message: 通知内容（Notification）
        :param torrents: 种子上下文列表（List[Context]）
        """
        return self.dispatch("post_torrents_message", *args, **kwargs)

    def delete_message(self, *args, **kwargs) -> Optional[bool]:
        """
        删除已发送的消息（取首个非空结果）。

        :param channel: 消息渠道
        :param source: 渠道来源标识
        :param message_id: 消息 ID
        :param chat_id: 会话 ID
        :return: 是否删除成功
        """
        return self.dispatch("delete_message", *args, **kwargs)

    def edit_message(self, *args, **kwargs) -> Any:
        """
        编辑已发送的消息（取首个非空结果）。

        :param channel: 消息渠道
        :param source: 渠道来源标识
        :param message_id: 消息 ID
        :param chat_id: 会话 ID
        :param text: 新正文
        :param title: 新标题
        :param buttons: 按钮列表
        :param metadata: 附加元数据
        :return: 是否编辑成功
        """
        return self.dispatch("edit_message", *args, **kwargs)

    def send_direct_message(self, *args, **kwargs) -> Any:
        """
        直接发送消息并返回渠道响应（取首个非空，不入消息队列/历史）。

        :param message: 通知内容（Notification）
        :return: 渠道响应（MessageResponse）
        """
        return self.dispatch("send_direct_message", *args, **kwargs)

    def finalize_message(self, *args, **kwargs) -> Optional[bool]:
        """
        对已发送消息执行渠道收尾动作（取首个非空）。

        :param response: 发送阶段返回的渠道响应（MessageResponse）
        :return: 是否处理成功
        """
        return self.dispatch("finalize_message", *args, **kwargs)

    def register_commands(self, commands: Dict[str, dict]) -> None:
        """
        向所有启用渠道注册菜单命令（广播）。

        :param commands: 命令定义（命令名 -> 命令配置）
        """
        return self.dispatch("register_commands", commands=commands)
