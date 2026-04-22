import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from threading import Lock
from typing import Dict, List, Optional, Tuple, Union
import uuid

from app.chain import ChainBase
from app.helper.skill import SkillHelper, SkillInfo
from app.schemas import Notification
from app.schemas.message import ChannelCapabilityManager
from app.schemas.types import MessageChannel


@dataclass
class PendingSkillsInteraction:
    """
    记录一次 /skills 会话的上下文，便于按钮和文本回复共用同一状态。
    """

    request_id: str
    user_id: str
    channel: Optional[MessageChannel]
    source: Optional[str]
    username: Optional[str]
    view: str = "root"
    local_page: int = 0
    market_page: int = 0
    created_at: datetime = field(default_factory=datetime.now)


class SkillsInteractionManager:
    """
    管理用户当前的技能交互状态。

    每个用户同一时间只保留一个有效会话，避免旧按钮继续生效。
    """

    _ttl = timedelta(hours=24)

    def __init__(self):
        self._by_id: Dict[str, PendingSkillsInteraction] = {}
        self._by_user: Dict[str, str] = {}
        self._lock = Lock()

    def _cleanup_locked(self):
        """
        清理超时会话，避免按钮回调无限积累。
        """
        expire_before = datetime.now() - self._ttl
        expired = [
            request_id
            for request_id, request in self._by_id.items()
            if request.created_at < expire_before
        ]
        for request_id in expired:
            request = self._by_id.pop(request_id, None)
            if request:
                self._by_user.pop(str(request.user_id), None)

    def create_or_replace(
        self,
        user_id: Union[str, int],
        channel: Optional[MessageChannel],
        source: Optional[str],
        username: Optional[str],
    ) -> PendingSkillsInteraction:
        """
        为用户创建新会话，并替换掉旧的技能交互状态。
        """
        with self._lock:
            self._cleanup_locked()
            user_key = str(user_id)
            old_request_id = self._by_user.get(user_key)
            if old_request_id:
                self._by_id.pop(old_request_id, None)
            request_id = uuid.uuid4().hex[:12]
            request = PendingSkillsInteraction(
                request_id=request_id,
                user_id=user_key,
                channel=channel,
                source=source,
                username=username,
            )
            self._by_id[request_id] = request
            self._by_user[user_key] = request_id
            return request

    def get_by_user(
        self, user_id: Union[str, int]
    ) -> Optional[PendingSkillsInteraction]:
        """
        按用户获取当前有效会话，供纯文本回复路由使用。
        """
        with self._lock:
            self._cleanup_locked()
            request_id = self._by_user.get(str(user_id))
            if not request_id:
                return None
            return self._by_id.get(request_id)

    def get_by_id(
        self, request_id: str, user_id: Union[str, int]
    ) -> Optional[PendingSkillsInteraction]:
        """
        按请求 ID 获取会话，并校验会话归属用户。
        """
        with self._lock:
            self._cleanup_locked()
            request = self._by_id.get(request_id)
            if not request or str(request.user_id) != str(user_id):
                return None
            return request

    def remove(self, request_id: str) -> None:
        """
        主动结束会话，释放用户和请求 ID 的双向索引。
        """
        with self._lock:
            request = self._by_id.pop(request_id, None)
            if request:
                self._by_user.pop(str(request.user_id), None)

    def clear(self):
        """
        清空所有会话，主要用于测试场景。
        """
        with self._lock:
            self._by_id.clear()
            self._by_user.clear()


skills_interaction_manager = SkillsInteractionManager()


class SkillsChain(ChainBase):
    """
    处理 /skills 指令、按钮回调和文本式技能管理交互。
    """

    _button_page_size = 6
    _text_page_size = 8

    def __init__(self):
        super().__init__()
        self.skillhelper = SkillHelper()

    def remote_manage(
        self,
        arg_str: str,
        channel: MessageChannel,
        userid: Union[str, int],
        source: Optional[str] = None,
    ):
        """
        /skills 入口。创建新会话并渲染首屏菜单。
        """
        request = skills_interaction_manager.create_or_replace(
            user_id=userid,
            channel=channel,
            source=source,
            username=None,
        )
        force = (arg_str or "").strip().lower() in {"refresh", "刷新"}
        self._render_interaction(
            request=request,
            channel=channel,
            source=source,
            userid=userid,
            username=None,
            force_market_refresh=force,
        )

    @staticmethod
    def parse_callback(callback_data: str) -> Optional[Tuple[str, str, Optional[int]]]:
        """
        解析 /skills 按钮回调。

        回调格式：skills:{request_id}:{action}[:index]
        """
        if not callback_data.startswith("skills:"):
            return None
        parts = callback_data.split(":")
        if len(parts) < 3:
            return None
        request_id = parts[1]
        action = parts[2]
        index = None
        if len(parts) >= 4 and parts[3].isdigit():
            index = int(parts[3])
        return request_id, action, index

    def handle_callback_interaction(
        self,
        callback_data: str,
        channel: MessageChannel,
        source: str,
        userid: Union[str, int],
        username: str,
        original_message_id: Optional[Union[str, int]] = None,
        original_chat_id: Optional[str] = None,
    ) -> bool:
        """
        处理按钮交互，并在同一条消息上刷新当前视图。
        """
        parsed = self.parse_callback(callback_data)
        if not parsed:
            return False

        request_id, action, index = parsed
        request = skills_interaction_manager.get_by_id(request_id, userid)
        if not request:
            self.post_message(
                Notification(
                    channel=channel,
                    source=source,
                    userid=userid,
                    username=username,
                    title="技能交互已失效，请重新发送 /skills",
                )
            )
            return True

        request.channel = channel
        request.source = source
        request.username = username

        if action == "close":
            skills_interaction_manager.remove(request.request_id)
            self._update_or_post_message(
                channel=channel,
                source=source,
                userid=userid,
                username=username,
                title="技能管理",
                text="技能交互已结束",
                original_message_id=original_message_id,
                original_chat_id=original_chat_id,
            )
            return True

        if action == "root":
            request.view = "root"
        elif action == "installed":
            request.view = "installed"
            request.local_page = 0
        elif action == "market":
            request.view = "market"
            request.market_page = 0
        elif action == "refresh":
            self._render_interaction(
                request=request,
                channel=channel,
                source=source,
                userid=userid,
                username=username,
                original_message_id=original_message_id,
                original_chat_id=original_chat_id,
                force_market_refresh=True,
            )
            return True
        elif action == "page-next":
            if request.view == "installed":
                request.local_page += 1
            elif request.view == "market":
                request.market_page += 1
        elif action == "page-prev":
            if request.view == "installed":
                request.local_page = max(0, request.local_page - 1)
            elif request.view == "market":
                request.market_page = max(0, request.market_page - 1)
        elif action == "install" and index:
            success, message = self._install_market_skill(request, index)
            if success:
                self.post_message(
                    Notification(
                        channel=channel,
                        source=source,
                        userid=userid,
                        username=username,
                        title=message,
                    )
                )
            else:
                self.post_message(
                    Notification(
                        channel=channel,
                        source=source,
                        userid=userid,
                        username=username,
                        title=message,
                    )
                )
        elif action == "remove" and index:
            success, message = self._remove_local_skill(request, index)
            self.post_message(
                Notification(
                    channel=channel,
                    source=source,
                    userid=userid,
                    username=username,
                    title=message,
                )
            )
            if not success:
                # 保持当前页
                pass

        self._render_interaction(
            request=request,
            channel=channel,
            source=source,
            userid=userid,
            username=username,
            original_message_id=original_message_id,
            original_chat_id=original_chat_id,
        )
        return True

    def handle_text_interaction(
        self,
        channel: MessageChannel,
        source: str,
        userid: Union[str, int],
        username: str,
        text: str,
    ) -> bool:
        """
        处理不支持按钮渠道上的文本指令，也兼容用户直接回复文字操作。
        """
        request = skills_interaction_manager.get_by_user(userid)
        if not request:
            return False

        request.channel = channel
        request.source = source
        request.username = username

        normalized = (text or "").strip()
        lowered = normalized.lower()
        if lowered in {"退出", "关闭", "q", "quit", "exit"}:
            skills_interaction_manager.remove(request.request_id)
            self.post_message(
                Notification(
                    channel=channel,
                    source=source,
                    userid=userid,
                    username=username,
                    title="技能交互已结束",
                )
            )
            return True

        if lowered in {"返回", "back"}:
            request.view = "root"
            self._render_interaction(
                request=request,
                channel=channel,
                source=source,
                userid=userid,
                username=username,
            )
            return True

        if lowered in {"刷新", "refresh"}:
            self._render_interaction(
                request=request,
                channel=channel,
                source=source,
                userid=userid,
                username=username,
                force_market_refresh=True,
            )
            return True

        if lowered in {"p", "prev", "上一页"}:
            if request.view == "installed":
                request.local_page = max(0, request.local_page - 1)
            elif request.view == "market":
                request.market_page = max(0, request.market_page - 1)
            self._render_interaction(
                request=request,
                channel=channel,
                source=source,
                userid=userid,
                username=username,
            )
            return True

        if lowered in {"n", "next", "下一页"}:
            if request.view == "installed":
                request.local_page += 1
            elif request.view == "market":
                request.market_page += 1
            self._render_interaction(
                request=request,
                channel=channel,
                source=source,
                userid=userid,
                username=username,
            )
            return True

        if request.view == "root":
            if lowered in {"1", "已安装", "本地", "local"}:
                request.view = "installed"
            elif lowered in {"2", "市场", "market"}:
                request.view = "market"
            else:
                self.post_message(
                    Notification(
                        channel=channel,
                        source=source,
                        userid=userid,
                        username=username,
                        title="请输入 1 查看已安装技能，2 查看技能市场，或回复 刷新/退出",
                    )
                )
                return True
            self._render_interaction(
                request=request,
                channel=channel,
                source=source,
                userid=userid,
                username=username,
            )
            return True

        install_match = re.match(r"^(?:安装|装)\s*(\d+)$", normalized)
        remove_match = re.match(r"^(?:删除|删)\s*(\d+)$", normalized)
        if request.view == "market" and install_match:
            success, message = self._install_market_skill(
                request=request,
                page_index=int(install_match.group(1)),
            )
            self.post_message(
                Notification(
                    channel=channel,
                    source=source,
                    userid=userid,
                    username=username,
                    title=message,
                )
            )
            self._render_interaction(
                request=request,
                channel=channel,
                source=source,
                userid=userid,
                username=username,
            )
            return True
        if request.view == "installed" and remove_match:
            success, message = self._remove_local_skill(
                request=request,
                page_index=int(remove_match.group(1)),
            )
            self.post_message(
                Notification(
                    channel=channel,
                    source=source,
                    userid=userid,
                    username=username,
                    title=message,
                )
            )
            self._render_interaction(
                request=request,
                channel=channel,
                source=source,
                userid=userid,
                username=username,
            )
            return True

        self.post_message(
            Notification(
                channel=channel,
                source=source,
                userid=userid,
                username=username,
                title=self._build_usage_hint(request.view),
            )
        )
        return True

    def _install_market_skill(
        self,
        request: PendingSkillsInteraction,
        page_index: int,
    ) -> Tuple[bool, str]:
        """
        按当前市场页的可见序号安装技能，避免跨页序号歧义。
        """
        market_skills = [skill for skill in self.skillhelper.list_market_skills() if not skill.installed]
        page_items, page, _ = self._page_items(
            items=market_skills,
            page=request.market_page,
            page_size=self._page_size(request.channel),
        )
        request.market_page = page
        if page_index < 1 or page_index > len(page_items):
            return False, "安装序号无效"
        return self.skillhelper.install_market_skill(page_items[page_index - 1])

    def _remove_local_skill(
        self,
        request: PendingSkillsInteraction,
        page_index: int,
    ) -> Tuple[bool, str]:
        """
        按当前已安装页的可见序号删除技能，并拦截内置技能。
        """
        local_skills = self.skillhelper.list_local_skills()
        page_items, page, _ = self._page_items(
            items=local_skills,
            page=request.local_page,
            page_size=self._page_size(request.channel),
        )
        request.local_page = page
        if page_index < 1 or page_index > len(page_items):
            return False, "删除序号无效"
        target = page_items[page_index - 1]
        if not target.removable:
            return False, f"技能 {target.id} 是内置技能，不能删除"
        return self.skillhelper.remove_local_skill(target.id)

    def _render_interaction(
        self,
        request: PendingSkillsInteraction,
        channel: MessageChannel,
        source: Optional[str],
        userid: Union[str, int],
        username: Optional[str],
        original_message_id: Optional[Union[str, int]] = None,
        original_chat_id: Optional[str] = None,
        force_market_refresh: bool = False,
    ) -> None:
        """
        根据当前视图生成内容，并选择编辑原消息或发送新消息。
        """
        if request.view == "installed":
            title, text, buttons = self._build_installed_view(
                request=request,
                force_market_refresh=force_market_refresh,
            )
        elif request.view == "market":
            title, text, buttons = self._build_market_view(
                request=request,
                force_market_refresh=force_market_refresh,
            )
        else:
            title, text, buttons = self._build_root_view(
                request=request,
                force_market_refresh=force_market_refresh,
            )

        self._update_or_post_message(
            channel=channel,
            source=source,
            userid=userid,
            username=username,
            title=title,
            text=text,
            buttons=buttons,
            original_message_id=original_message_id,
            original_chat_id=original_chat_id,
        )

    def _build_root_view(
        self,
        request: PendingSkillsInteraction,
        force_market_refresh: bool = False,
    ) -> Tuple[str, str, Optional[List[List[dict]]]]:
        """
        构建根菜单视图，汇总本地技能和市场概览。
        """
        local_skills = self.skillhelper.list_local_skills()
        market_skills = [
            skill
            for skill in self.skillhelper.list_market_skills(force=force_market_refresh)
            if not skill.installed
        ]
        sources = self.skillhelper.get_market_sources()
        source_lines = []
        for index, source in enumerate(sources, start=1):
            source_lines.append(f"{index}. {self.skillhelper.describe_market_source(source)}")

        text_lines = [
            f"已安装技能：{len(local_skills)}",
            f"市场可安装技能：{len(market_skills)}",
        ]
        if source_lines:
            text_lines.extend(["", "公开技能源：", *source_lines])
        text_lines.extend(
            [
                "",
                "1. 查看已安装技能",
                "2. 浏览技能市场",
                "回复 刷新 重新获取市场数据，回复 退出 结束交互",
            ]
        )

        buttons = None
        if self._supports_interactive_buttons(request.channel):
            buttons = [
                [{"text": "已安装技能", "callback_data": f"skills:{request.request_id}:installed"}],
                [{"text": "技能市场", "callback_data": f"skills:{request.request_id}:market"}],
                [
                    {"text": "刷新市场", "callback_data": f"skills:{request.request_id}:refresh"},
                    {"text": "关闭", "callback_data": f"skills:{request.request_id}:close"},
                ],
            ]
        return "技能管理", "\n".join(text_lines), buttons

    def _build_installed_view(
        self,
        request: PendingSkillsInteraction,
        force_market_refresh: bool = False,  # noqa: ARG002
    ) -> Tuple[str, str, Optional[List[List[dict]]]]:
        """
        构建已安装技能视图，列出来源和可删除状态。
        """
        local_skills = self.skillhelper.list_local_skills()
        page_items, page, total_pages = self._page_items(
            items=local_skills,
            page=request.local_page,
            page_size=self._page_size(request.channel),
        )
        request.local_page = page

        text_lines = [f"第 {page + 1}/{total_pages} 页，共 {len(local_skills)} 个技能"]
        if not page_items:
            text_lines.append("")
            text_lines.append("当前没有已安装技能")
        else:
            for index, skill in enumerate(page_items, start=1):
                action = "可删除" if skill.removable else "内置不可删"
                text_lines.extend(
                    [
                        "",
                        f"{index}. {skill.id} ({skill.source_label}，{action})",
                        self._truncate(skill.description),
                    ]
                )

        text_lines.extend(
            [
                "",
                "回复 删除 <序号> 删除技能，回复 n/p 翻页，回复 返回 回到菜单，回复 退出 结束交互",
            ]
        )

        buttons = None
        if self._supports_interactive_buttons(request.channel):
            buttons = []
            for index, skill in enumerate(page_items, start=1):
                if not skill.removable:
                    continue
                buttons.append(
                    [
                        {
                            "text": f"删除 {index}",
                            "callback_data": f"skills:{request.request_id}:remove:{index}",
                        }
                    ]
                )
            buttons.extend(self._navigation_buttons(request, page, total_pages))
            buttons.append(
                [
                    {"text": "返回", "callback_data": f"skills:{request.request_id}:root"},
                    {"text": "关闭", "callback_data": f"skills:{request.request_id}:close"},
                ]
            )
        return "已安装技能", "\n".join(text_lines), buttons

    def _build_market_view(
        self,
        request: PendingSkillsInteraction,
        force_market_refresh: bool = False,
    ) -> Tuple[str, str, Optional[List[List[dict]]]]:
        """
        构建技能市场视图，仅展示尚未安装的技能。
        """
        market_skills = [
            skill
            for skill in self.skillhelper.list_market_skills(force=force_market_refresh)
            if not skill.installed
        ]
        page_items, page, total_pages = self._page_items(
            items=market_skills,
            page=request.market_page,
            page_size=self._page_size(request.channel),
        )
        request.market_page = page

        text_lines = [f"第 {page + 1}/{total_pages} 页，共 {len(market_skills)} 个可安装技能"]
        if not page_items:
            text_lines.append("")
            text_lines.append("当前没有可安装的市场技能")
        else:
            for index, skill in enumerate(page_items, start=1):
                text_lines.extend(
                    [
                        "",
                        f"{index}. {skill.id} ({skill.source_label})",
                        self._truncate(skill.description),
                    ]
                )
                if skill.source_type == "registry":
                    text_lines.append("社区源，安装前请自行甄别安全性")

        if any(skill.source_type == "registry" for skill in page_items):
            text_lines.extend(
                [
                    "",
                    "提示：ClawHub 属于社区注册表，技能质量与安全性需要自行甄别。",
                ]
            )

        text_lines.extend(
            [
                "",
                "回复 安装 <序号> 安装技能，回复 刷新 重新拉取市场，回复 n/p 翻页，回复 返回 回到菜单，回复 退出 结束交互",
            ]
        )

        buttons = None
        if self._supports_interactive_buttons(request.channel):
            buttons = []
            for index, _skill in enumerate(page_items, start=1):
                buttons.append(
                    [
                        {
                            "text": f"安装 {index}",
                            "callback_data": f"skills:{request.request_id}:install:{index}",
                        }
                    ]
                )
            buttons.extend(self._navigation_buttons(request, page, total_pages))
            buttons.append(
                [
                    {"text": "刷新", "callback_data": f"skills:{request.request_id}:refresh"},
                    {"text": "返回", "callback_data": f"skills:{request.request_id}:root"},
                    {"text": "关闭", "callback_data": f"skills:{request.request_id}:close"},
                ]
            )
        return "技能市场", "\n".join(text_lines), buttons

    @staticmethod
    def _truncate(text: str, limit: int = 140) -> str:
        """
        对技能描述做轻量截断，避免消息过长。
        """
        if len(text) <= limit:
            return text
        return text[: limit - 3] + "..."

    @staticmethod
    def _page_items(
        items: List[SkillInfo],
        page: int,
        page_size: int,
    ) -> Tuple[List[SkillInfo], int, int]:
        """
        返回当前页的数据，并把页码钳制到有效范围内。
        """
        total_pages = max(1, math.ceil(len(items) / page_size)) if page_size else 1
        page = min(max(0, page), total_pages - 1)
        start = page * page_size
        end = start + page_size
        return items[start:end], page, total_pages

    def _page_size(self, channel: Optional[MessageChannel]) -> int:
        """
        按渠道能力选择分页大小，按钮渠道单页更短，便于直接操作。
        """
        return (
            self._button_page_size
            if self._supports_interactive_buttons(channel)
            else self._text_page_size
        )

    @staticmethod
    def _supports_interactive_buttons(channel: Optional[MessageChannel]) -> bool:
        """
        判断当前渠道是否同时支持按钮展示和回调。
        """
        return bool(
            channel
            and ChannelCapabilityManager.supports_buttons(channel)
            and ChannelCapabilityManager.supports_callbacks(channel)
        )

    @staticmethod
    def _navigation_buttons(
        request: PendingSkillsInteraction,
        page: int,
        total_pages: int,
    ) -> List[List[dict]]:
        """
        为分页视图生成上一页和下一页按钮。
        """
        buttons = []
        nav_row = []
        if page > 0:
            nav_row.append(
                {
                    "text": "⬅️ 上一页",
                    "callback_data": f"skills:{request.request_id}:page-prev",
                }
            )
        if page < total_pages - 1:
            nav_row.append(
                {
                    "text": "下一页 ➡️",
                    "callback_data": f"skills:{request.request_id}:page-next",
                }
            )
        if nav_row:
            buttons.append(nav_row)
        return buttons

    def _update_or_post_message(
        self,
        channel: MessageChannel,
        source: Optional[str],
        userid: Union[str, int],
        username: Optional[str],
        title: str,
        text: str,
        buttons: Optional[List[List[dict]]] = None,
        original_message_id: Optional[Union[str, int]] = None,
        original_chat_id: Optional[str] = None,
    ) -> None:
        """
        优先编辑原消息，编辑失败时再回退为发送新消息。
        """
        if (
            original_message_id
            and original_chat_id
            and ChannelCapabilityManager.supports_editing(channel)
        ):
            edited = self.edit_message(
                channel=channel,
                source=source,
                message_id=original_message_id,
                chat_id=original_chat_id,
                title=title,
                text=text,
                buttons=buttons,
            )
            if edited:
                return

        self.post_message(
            Notification(
                channel=channel,
                source=source,
                userid=userid,
                username=username,
                title=title,
                text=text,
                buttons=buttons,
            )
        )

    @staticmethod
    def _build_usage_hint(view: str) -> str:
        """
        根据当前视图返回可执行的文本命令提示。
        """
        if view == "market":
            return "请输入 安装 <序号>、刷新、n、p、返回 或 退出"
        if view == "installed":
            return "请输入 删除 <序号>、n、p、返回 或 退出"
        return "请输入 1、2、刷新 或 退出"
