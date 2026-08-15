"""插件命令菜单条目的归属判定。

命令声明按运行态插件表的顺序到达，实例标识按字典序排在默认实例之前的分身会先到，
菜单条目因此显示分身的描述。菜单条目只决定显示，命令事件按事件订阅投递，不受条目归属
限制，冲突提示必须照此措辞并在重复构建时收敛。
"""
from types import SimpleNamespace
from typing import Any, Dict, Iterator, List
from unittest.mock import patch

import pytest

from app.command import Command
from app.schemas.types import EventType

PLUGIN_ID = "MenuPlugin"
ALPHA_KEY = f"{PLUGIN_ID}@alpha"
OTHER_PLUGIN_ID = "OtherMenuPlugin"
CMD = "/menu"


@pytest.fixture
def command() -> Iterator[Command]:
    """构造只保留命令构建能力的命令管理器，与全局单例隔离。"""
    instance = object.__new__(Command)
    instance.pluginmanager = SimpleNamespace(running_plugins={})
    instance._warned_command_overlaps = set()
    yield instance


def declaration(pid: str, desc: str = "示例命令") -> Dict[str, Any]:
    """
    构造一条归属指定实例的命令声明

    :param pid: 声明该命令的实例键
    :param desc: 命令描述
    :return: 命令声明
    """
    return {
        "cmd": CMD,
        "event": EventType.PluginAction,
        "desc": desc,
        "category": "示例",
        "data": {},
        "pid": pid,
    }


def build(command: Command, declarations: List[Dict[str, Any]]):
    """
    以给定的命令声明构建一次插件命令

    :param command: 命令管理器
    :param declarations: 命令声明列表，顺序即声明顺序
    :return: (构建结果, 日志替身)
    """
    with patch("app.command.get_plugin_commands", return_value=declarations), \
            patch("app.command.logger") as logger:
        built = command._Command__build_plugin_commands()
    return built, logger


def test_default_instance_owns_the_menu_entry_over_an_earlier_alias(command):
    """分身排在默认实例之前时，菜单条目仍归默认实例，描述取默认实例的。"""
    built, _ = build(command, [
        declaration(ALPHA_KEY, desc="分身描述"),
        declaration(PLUGIN_ID, desc="默认描述"),
    ])

    assert built[CMD]["pid"] == PLUGIN_ID
    assert built[CMD]["description"] == "默认描述"


def test_menu_owner_is_stable_regardless_of_declaration_order(command):
    """同一组声明换个到达顺序，菜单归属不变。"""
    forward, _ = build(command, [declaration(PLUGIN_ID), declaration(ALPHA_KEY)])
    command._warned_command_overlaps = set()
    backward, _ = build(command, [declaration(ALPHA_KEY), declaration(PLUGIN_ID)])

    assert forward[CMD]["pid"] == backward[CMD]["pid"] == PLUGIN_ID


def test_cross_plugin_overlap_keeps_the_first_declaring_plugin(command):
    """不同插件声明同一条命令时，菜单归属按声明顺序取先到的插件。"""
    built, logger = build(command, [
        declaration(OTHER_PLUGIN_ID),
        declaration(PLUGIN_ID),
    ])

    assert built[CMD]["pid"] == OTHER_PLUGIN_ID
    logger.warning.assert_called_once()


def test_overlap_warning_does_not_claim_the_other_instance_is_rejected(command):
    """提示只说明菜单条目的取舍，不得声称另一个实例的命令被拒绝执行。"""
    _, logger = build(command, [declaration(PLUGIN_ID), declaration(ALPHA_KEY)])

    warning = logger.warning.call_args.args[0]
    assert ALPHA_KEY in warning
    assert "拒绝" not in warning


def test_stable_overlap_warns_once_across_repeated_builds(command):
    """同一组重叠在每次重建命令时只提示一次。"""
    declarations = [declaration(PLUGIN_ID), declaration(ALPHA_KEY)]
    _, first = build(command, declarations)
    _, second = build(command, declarations)

    assert first.warning.call_count == 1
    second.warning.assert_not_called()


def test_a_new_overlap_warns_again(command):
    """重叠对象发生变化时重新提示。"""
    build(command, [declaration(PLUGIN_ID), declaration(ALPHA_KEY)])

    _, logger = build(command, [
        declaration(PLUGIN_ID),
        declaration(ALPHA_KEY),
        declaration(f"{PLUGIN_ID}@beta"),
    ])

    assert logger.warning.call_count == 1
    assert f"{PLUGIN_ID}@beta" in logger.warning.call_args.args[0]
