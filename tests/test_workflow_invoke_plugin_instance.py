"""工作流「调用插件动作」的实例定位。

动作声明按实例键分组，同一插件的每个实例各占一组。分组顺序来自运行态插件表，实例标识
按字典序排在默认实例之前的分身会排在最前，因此按位置取第一组会让存量工作流（存的是裸
插件标识）静默执行到分身实例上，用分身的配置与数据且照常报成功。
"""
from types import SimpleNamespace
from typing import Any, Dict, List
from unittest.mock import patch

import pytest

from app.schemas import ActionContext
from app.workflow.actions.invoke_plugin import InvokePluginAction

PLUGIN_ID = "InvokeTargetPlugin"
ALPHA_KEY = f"{PLUGIN_ID}@alpha"
ACTION_ID = "do_something"

# 动作执行的落点，记录声明该动作的实例键
EXECUTED: List[str] = []


@pytest.fixture(autouse=True)
def _reset_executed():
    """每个用例独享动作执行落点。"""
    EXECUTED.clear()
    yield
    EXECUTED.clear()


def action_group(owner: str) -> Dict[str, Any]:
    """
    构造一个归属指定实例的动作分组

    :param owner: 声明该动作的实例键
    :return: 动作分组
    """

    def func(context: ActionContext, **_kwargs):
        EXECUTED.append(owner)
        return True, context

    return {
        "plugin_id": owner,
        "plugin_name": "调用目标插件",
        "actions": [{"action_id": ACTION_ID, "name": "示例动作", "func": func}],
    }


def invoke(groups: List[Dict[str, Any]], plugin_id: str):
    """
    以给定的动作分组执行一次调用插件动作

    :param groups: get_plugin_actions 的返回值
    :param plugin_id: 动作参数里填写的插件标识或实例键
    :return: (动作实例, 日志替身)
    """
    action = InvokePluginAction(action_id="invoke_plugin")
    params = {"plugin_id": plugin_id, "action_id": ACTION_ID, "action_params": {}}
    with patch("app.workflow.actions.invoke_plugin.get_plugin_actions", return_value=groups), \
            patch("app.workflow.actions.invoke_plugin.PluginManager",
                  return_value=SimpleNamespace(running_plugins={})), \
            patch("app.workflow.actions.invoke_plugin.logger") as logger:
        action.execute(workflow_id=1, params=params, context=ActionContext())
    return action, logger


def test_single_instance_invocation_is_unchanged():
    """单实例插件按裸插件标识执行，行为保持原样。"""
    action, logger = invoke([action_group(PLUGIN_ID)], PLUGIN_ID)

    assert EXECUTED == [PLUGIN_ID]
    assert action.success is True
    logger.error.assert_not_called()
    logger.warning.assert_not_called()


def test_bare_plugin_id_runs_the_default_instance_not_the_first_group():
    """分身排在默认实例之前时，裸插件标识仍须执行到默认实例。"""
    action, _ = invoke([action_group(ALPHA_KEY), action_group(PLUGIN_ID)], PLUGIN_ID)

    assert EXECUTED == [PLUGIN_ID]
    assert action.success is True


def test_bare_plugin_id_warns_when_more_than_one_instance_declares_the_action():
    """多个实例都声明动作时，按裸标识执行要留下可据以改配置的告警。"""
    _, logger = invoke([action_group(ALPHA_KEY), action_group(PLUGIN_ID)], PLUGIN_ID)

    warning = logger.warning.call_args.args[0]
    assert ALPHA_KEY in warning


def test_instance_key_hits_exactly_that_instance():
    """填写实例键时精确命中该实例。"""
    action, _ = invoke([action_group(PLUGIN_ID), action_group(ALPHA_KEY)], ALPHA_KEY)

    assert EXECUTED == [ALPHA_KEY]
    assert action.success is True


def test_missing_default_instance_reports_an_error_instead_of_running_a_sibling():
    """默认实例不在运行态时报错，不得改用同插件的其它实例。"""
    action, logger = invoke([action_group(ALPHA_KEY)], PLUGIN_ID)

    assert EXECUTED == []
    assert action.success is False
    logger.error.assert_called_once()
    assert ALPHA_KEY in logger.error.call_args.args[0]


def test_unknown_instance_key_reports_an_error():
    """填写的实例键没有对应实例时报错。"""
    action, logger = invoke([action_group(PLUGIN_ID)], f"{PLUGIN_ID}@ghost")

    assert EXECUTED == []
    assert action.success is False
    logger.error.assert_called_once()
