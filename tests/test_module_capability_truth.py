"""能力归属的事实校验。

ModuleType 一个标签同时承担分发路由、服务配置归类、契约归属声明与健康检查分类四种职责，
不可能对四种目的都正确，于是出现两个方向的错配：声明了某类型却不提供该类型的核心能力，
以及实际提供某族能力却挂着别的类型。

能力由运行期实例推导（见 app/runtime/extensions/capability.py），推导出来的事实无法与
实现不符——继承自兄弟模块的能力也算数，AlistGo 的整套存储契约就继承自 Alist。

本文件不锁死全量成员表（indexer/subtitle 依赖资源包，在部分环境无法导入，全量表会随
环境漂移），而是校验不变量，并把已知偏差显式登记：出现新的偏差必须改表。
"""
import ast
import inspect
import pathlib
from typing import Dict, FrozenSet, List, Set

import pytest

from app.foundation.reflection import ModuleHelper
from app.modules import _ModuleBase
from app.runtime.extensions import contract
from app.runtime.extensions.capability import provided_capabilities
from app.runtime.extensions.module_manager import PRECISE_DISPATCH_TYPES
from app.schemas.types import ModuleType

# 各模块类型的核心能力：声明该类型即应提供它
TYPE_CORE_CAPABILITY: Dict[ModuleType, str] = {
    # download 同时是存储的方法名，改用下载器独有的能力做判据
    ModuleType.Downloader: "list_torrents",
    ModuleType.MediaServer: "mediaserver_librarys",
    ModuleType.Notification: "post_message",
    ModuleType.MediaRecognize: "recognize_media",
    ModuleType.Storage: "list",
    ModuleType.Indexer: "search_torrents",
}

# 声明了类型却不提供其核心能力的模块。它们是能力不全的族成员，不是错分：
# TheTvDbModule 只提供 tvdb_info / tvdb_slug / search_tvdb 三个独占查询。
KNOWN_PARTIAL_MEMBERS: Dict[ModuleType, FrozenSet[str]] = {
    ModuleType.MediaRecognize: frozenset({"TheTvDbModule"}),
}

# 跨类型的能力族：目录与 ModuleType 都表达不了，只能在此锁定。
# FanartModule 声明 ModuleType.Other，但契约上是图片族正式成员，独占能力为 0。
CROSS_TYPE_FAMILIES: Dict[str, FrozenSet[str]] = {
    "metadata_img": frozenset({
        "AniListModule", "BangumiModule", "DoubanModule", "FanartModule", "TheMovieDbModule",
    }),
    "obtain_images": frozenset({"DoubanModule", "FanartModule", "TheMovieDbModule"}),
}


@pytest.fixture(scope="module", autouse=True)
def module_base():
    """把模块基类装配到契约校验层。"""
    previous = contract._module_base  # noqa: SLF001
    contract.configure_module_base(_ModuleBase)
    yield
    contract._module_base = previous  # noqa: SLF001


@pytest.fixture(scope="module")
def module_classes() -> List[type]:
    """
    扫描到的全部模块类

    :return: 模块类列表，当前环境无法导入的模块不在其中
    """
    return ModuleHelper.load(
        "app.modules",
        filter_func=lambda _, obj: hasattr(obj, "init_module") and hasattr(obj, "init_setting")
        and not inspect.isabstract(obj),
    )


def capability_owners(module_classes: List[type], capability: str) -> Set[str]:
    """
    取提供某能力的模块

    :param module_classes: 模块类列表
    :param capability: 能力方法名
    :return: 模块类名集合
    """
    return {cls.__name__ for cls in module_classes
            if capability in provided_capabilities(cls)}


def typed_modules(module_classes: List[type], module_type: ModuleType) -> Set[str]:
    """
    取声明为某类型的模块

    :param module_classes: 模块类列表
    :param module_type: 模块类型
    :return: 模块类名集合
    """
    return {cls.__name__ for cls in module_classes if cls.get_type() == module_type}


@pytest.mark.parametrize("module_type, capability", sorted(
    TYPE_CORE_CAPABILITY.items(), key=lambda item: item[0].value))
def test_a_typed_module_provides_its_core_capability(module_classes, module_type, capability):
    """声明某类型的模块必须提供该类型的核心能力，例外须显式登记。"""
    declared = typed_modules(module_classes, module_type)
    if not declared:
        pytest.skip(f"当前环境没有装载 {module_type.value} 模块")
    allowed = KNOWN_PARTIAL_MEMBERS.get(module_type, frozenset())

    missing = declared - capability_owners(module_classes, capability) - allowed

    assert missing == set()


@pytest.mark.parametrize("module_type, capability", sorted(
    TYPE_CORE_CAPABILITY.items(), key=lambda item: item[0].value))
def test_a_core_capability_is_only_provided_by_its_own_type(module_classes, module_type, capability):
    """提供某类型核心能力的模块必须声明该类型，避免能力落在类型之外无人知晓。"""
    owners = capability_owners(module_classes, capability)
    if not owners:
        pytest.skip(f"当前环境没有模块提供 {capability}")

    assert owners <= typed_modules(module_classes, module_type)


@pytest.mark.parametrize("capability, members", sorted(CROSS_TYPE_FAMILIES.items()))
def test_a_cross_type_family_keeps_its_declared_members(module_classes, capability, members):
    """跨类型的能力族成员固定，模块加入或退出必须显式改表。"""
    loaded = {cls.__name__ for cls in module_classes}
    expected = {name for name in members if name in loaded}
    if not expected:
        pytest.skip(f"当前环境没有装载 {capability} 的任何提供者")

    assert capability_owners(module_classes, capability) == expected


def test_capabilities_include_those_inherited_from_a_sibling_module(module_classes):
    """能力推导覆盖继承：AlistGo 的存储契约全部继承自 Alist，静态扫描看不到。"""
    alistgo = next((cls for cls in module_classes if cls.__name__ == "AlistGo"), None)
    if alistgo is None:
        pytest.skip("当前环境没有装载 AlistGo")

    assert {"list", "delete", "rename", "upload"} <= provided_capabilities(alistgo)


def test_a_module_never_mixes_two_domains(module_classes):
    """豆瓣影视与豆瓣音乐分属不同模块，混合模块不得复现。"""
    by_name = {cls.__name__: cls for cls in module_classes}
    douban = provided_capabilities(by_name["DoubanModule"])
    douban_music = provided_capabilities(by_name["DoubanMusicModule"])

    assert not ({"recognize_music", "search_music", "music_album"} & douban)
    assert {"recognize_music", "search_music", "music_album"} <= douban_music


def broadcast_capabilities() -> Set[str]:
    """
    扫描 run_module 广播调用点上的方法名

    :return: 被广播的方法名集合
    """
    app_root = pathlib.Path(__file__).resolve().parents[1] / "app"
    names: Set[str] = set()
    for path in app_root.rglob("*.py"):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            called = func.attr if isinstance(func, ast.Attribute) else None
            if called not in ("run_module", "async_run_module"):
                continue
            if node.args and isinstance(node.args[0], ast.Constant) \
                    and isinstance(node.args[0].value, str):
                names.add(node.args[0].value)
    return names


# 有意跨类型的广播族：提供者分属不同 ModuleType，但签名一致、广播即其语义。
# 图片族的 FanartModule 声明 Other 却是正式成员；media_exists 由媒体库与整理编排共同回答。
INTENTIONAL_CROSS_TYPE_BROADCASTS: FrozenSet[str] = frozenset({
    "obtain_images", "async_obtain_images", "metadata_img", "media_exists",
})


def test_a_capability_shared_across_types_is_never_broadcast(module_classes):
    """跨类型重名的能力不得走广播，否则一次调用会打到两个族的全部后端。

    download 就是这样一个名字：存储与下载器各有一个签名不同的 download。存储侧走
    run_module_for 精确分发，下载器侧不经 chain 广播，因此当前无害；一旦有人加一个
    run_module("download")，7 个存储和 3 个下载器会被同时命中。
    """
    owners_by_type: Dict[str, Set[ModuleType]] = {}
    for cls in module_classes:
        if cls.get_type() in PRECISE_DISPATCH_TYPES:
            continue
        for capability in provided_capabilities(cls):
            owners_by_type.setdefault(capability, set()).add(cls.get_type())
    shared = {name for name, types in owners_by_type.items() if len(types) > 1}

    unexpected = shared & broadcast_capabilities() - INTENTIONAL_CROSS_TYPE_BROADCASTS

    assert unexpected == set()
