from typing import Any, Dict, List, Optional

from pydantic import Field

from app.workflow.actions import BaseAction
from app.runtime.extensions.plugin_instance import is_default_instance_key
from app.runtime.extensions.plugin_manager import PluginManager
from app.runtime.extensions.plugin_spi import get_plugin_actions
from app.runtime.log import logger
from app.schemas import ActionParams, ActionContext


class InvokePluginParams(ActionParams):
    """
    调用插件动作参数
    """
    plugin_id: str = Field(default=None, description="插件ID或实例键")
    action_id: str = Field(default=None, description="动作ID")
    action_params: dict = Field(default={}, description="动作参数")


class InvokePluginAction(BaseAction):
    """
    调用插件
    """

    contract = {}

    def __init__(self, action_id: str):
        super().__init__(action_id)
        self._success = False

    @classmethod
    @property
    def name(cls) -> str: # noqa
        return "调用插件"

    @classmethod
    @property
    def description(cls) -> str: # noqa
        return "调用插件提供的动作"

    @classmethod
    @property
    def data(cls) -> dict: # noqa
        return InvokePluginParams().model_dump()

    @property
    def success(self) -> bool:
        return self._success

    @staticmethod
    def _select_action_group(groups: List[Dict[str, Any]], target: str) -> Optional[Dict[str, Any]]:
        """
        在动作分组中定位目标插件实例

        分组以声明来源的实例键为键：实例键精确命中该实例，裸插件标识只命中默认实例。

        :param groups: 动作分组列表
        :param target: 插件标识或实例键
        :return: 命中的动作分组，未命中时为 None
        """
        return next((group for group in groups if group.get("plugin_id") == target), None)

    def execute(self, workflow_id: int, params: dict, context: ActionContext) -> ActionContext:
        """
        执行插件定义的动作
        """
        params = InvokePluginParams(**params)
        if not params.plugin_id or not params.action_id:
            return context
        try:
            plugin_actions = get_plugin_actions(PluginManager().running_plugins, params.plugin_id)
            if not plugin_actions:
                logger.error(f"插件不存在: {params.plugin_id}")
                return context
            candidates = [group.get("plugin_id") for group in plugin_actions]
            plugin_action = self._select_action_group(plugin_actions, params.plugin_id)
            if plugin_action is None:
                logger.error(f"插件实例不存在: {params.plugin_id}，当前可用实例: {candidates}")
                return context
            if len(plugin_actions) > 1 and is_default_instance_key(params.plugin_id):
                logger.warning(
                    f"插件 {params.plugin_id} 有多个实例声明动作，按默认实例执行；"
                    f"改用实例键可指定其它实例: {candidates}"
                )
            actions = plugin_action.get("actions", [])
            action = next((action for action in actions if action.get("action_id") == params.action_id), None)
            if not action or not action.get("func"):
                logger.error(f"插件动作不存在: {params.plugin_id} - {params.action_id}")
                return context
            # 执行插件动作
            self._success, context = action["func"](context, **params.action_params)
        except Exception as e:
            self._success = False
            logger.error(f"调用插件动作失败: {e}")
            return context
        self.job_done()
        return context
