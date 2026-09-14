"""插件多版本并存写法体检的合同测试。"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from app.adapters.system.plugin.package import PluginPackageManager
from app.runtime.extensions.plugin.readiness import (
    plugin_multi_version_blockers,
    scan_plugin_version_readiness,
)
from app.runtime.extensions.plugin.version import (
    plugin_version_dirs,
    read_plugin_versions_manifest,
    register_plugin_version,
)
from app.startup.composition.plugin import (
    _register_plugin_install_version as register_plugin_install_version,
)
from app.startup.composition.plugin import _reject_incompatible_plugin_version_switch
from app.startup.composition.plugin import (
    _resolve_plugin_install_target as resolve_plugin_install_target,
)
from app.startup.composition.plugin import (
    _rollback_plugin_install_version as rollback_plugin_install_version,
)

GUARD_PLUGIN_ID = "GuardPlugin"
REPO_URL = "https://github.com/demo/MoviePilot-Plugins"
LOCAL_REPO_URL = "local://guardplugin"
SELF_REFERENTIAL_IMPORT = "from app.plugins.guardplugin.utils import helper\n"


def _write_plugin(root: Path, plugin_id: str, files: dict[str, str]) -> Path:
    """按给定文件映射写入一个仅用于静态扫描的插件源码目录。"""
    plugin_dir = root / plugin_id
    plugin_dir.mkdir(parents=True)
    for relative_path, content in files.items():
        target = plugin_dir / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return plugin_dir


def _plugin_main_module(version: str, body: str = "") -> str:
    """拼出一个声明了版本号的插件主模块源码。"""
    return f'class DemoPlugin:\n    plugin_version = "{version}"\n\n{body}'


def test_relative_imports_report_all_three_criteria_as_clean(tmp_path: Path) -> None:
    """只用相对 import、不依赖其它插件、不继承共享 Base 的插件三项判据均为否。"""
    plugin_dir = _write_plugin(
        tmp_path,
        "cleanplugin",
        {
            "__init__.py": "from .utils import helper\n\nhelper()\n",
            "utils.py": "def helper():\n    return 1\n",
        },
    )

    readiness = scan_plugin_version_readiness("cleanplugin", plugin_dir)

    assert readiness.is_clean
    assert readiness.has_self_referential_imports is False
    assert readiness.has_cross_plugin_imports is False
    assert readiness.has_shared_base_models is False
    assert readiness.unparsed_files == ()


def test_self_referential_import_from_reports_file_line_and_suggestion(tmp_path: Path) -> None:
    """from app.plugins.<自身ID>.xxx import X 应精确报出文件、行号和相对写法建议。"""
    plugin_dir = _write_plugin(
        tmp_path,
        "myplugin",
        {
            "__init__.py": "\nfrom app.plugins.myplugin.utils import helper\n",
            "utils.py": "def helper():\n    pass\n",
        },
    )

    readiness = scan_plugin_version_readiness("myplugin", plugin_dir)

    assert readiness.has_self_referential_imports
    assert len(readiness.self_referential_imports) == 1
    hit = readiness.self_referential_imports[0]
    assert hit.file == "__init__.py"
    assert hit.line == 2
    assert hit.statement == "from app.plugins.myplugin.utils import helper"
    assert hit.suggestion == "from .utils import helper"


def test_self_referential_plain_import_reports_relative_module_suggestion(tmp_path: Path) -> None:
    """import app.plugins.<自身ID>.xxx 应报出改写为相对 from-import 的建议。"""
    plugin_dir = _write_plugin(
        tmp_path,
        "myplugin",
        {
            "__init__.py": "import app.plugins.myplugin.utils as utils_mod\n",
            "utils.py": "value = 1\n",
        },
    )

    readiness = scan_plugin_version_readiness("myplugin", plugin_dir)

    assert readiness.has_self_referential_imports
    hit = readiness.self_referential_imports[0]
    assert hit.file == "__init__.py"
    assert hit.line == 1
    assert hit.statement == "import app.plugins.myplugin.utils as utils_mod"
    assert hit.suggestion == "from . import utils as utils_mod"


def test_self_referential_dynamic_import_module_reports_suggestion(tmp_path: Path) -> None:
    """importlib.import_module("app.plugins.<自身ID>.xxx") 字符串常量形式应被识别。"""
    plugin_dir = _write_plugin(
        tmp_path,
        "myplugin",
        {
            "__init__.py": (
                "import importlib\n"
                'importlib.import_module("app.plugins.myplugin.utils")\n'
            ),
            "utils.py": "value = 1\n",
        },
    )

    readiness = scan_plugin_version_readiness("myplugin", plugin_dir)

    assert readiness.has_self_referential_imports
    hit = readiness.self_referential_imports[0]
    assert hit.file == "__init__.py"
    assert hit.line == 2
    assert hit.statement == 'importlib.import_module("app.plugins.myplugin.utils")'
    assert "from .utils import" in hit.suggestion


def test_dynamic_import_with_computed_module_name_is_not_reported(tmp_path: Path) -> None:
    """拼接出来的模块名静态阶段无法判定，不得当成自引用命中制造噪声。"""
    plugin_dir = _write_plugin(
        tmp_path,
        "myplugin",
        {
            "__init__.py": (
                "import importlib\n"
                'name = "utils"\n'
                'importlib.import_module("app.plugins.myplugin." + name)\n'
            ),
        },
    )

    readiness = scan_plugin_version_readiness("myplugin", plugin_dir)

    assert readiness.is_clean


def test_self_referential_import_inside_type_checking_block_is_not_reported(tmp_path: Path) -> None:
    """if TYPE_CHECKING: 内的自引用绝对 import 运行期不执行，不应计入阻断。"""
    plugin_dir = _write_plugin(
        tmp_path,
        "myplugin",
        {
            "__init__.py": (
                "from typing import TYPE_CHECKING\n\n"
                "if TYPE_CHECKING:\n"
                "    from app.plugins.myplugin.utils import helper\n"
            ),
            "utils.py": "def helper():\n    pass\n",
        },
    )

    readiness = scan_plugin_version_readiness("myplugin", plugin_dir)

    assert readiness.has_self_referential_imports is False


def test_self_referential_import_inside_typing_module_alias_block_is_not_reported(tmp_path: Path) -> None:
    """if typing.TYPE_CHECKING: 与别名形式同样运行期不执行，不应计入阻断。"""
    plugin_dir = _write_plugin(
        tmp_path,
        "myplugin",
        {
            "__init__.py": (
                "import typing as t\n\n"
                "if t.TYPE_CHECKING:\n"
                "    from app.plugins.myplugin.utils import helper\n"
            ),
            "utils.py": "def helper():\n    pass\n",
        },
    )

    readiness = scan_plugin_version_readiness("myplugin", plugin_dir)

    assert readiness.has_self_referential_imports is False


def test_self_referential_import_inside_type_checking_else_branch_is_still_reported(tmp_path: Path) -> None:
    """if TYPE_CHECKING: 的 else 分支运行期正常执行，其中的自引用导入仍应计入阻断。"""
    plugin_dir = _write_plugin(
        tmp_path,
        "myplugin",
        {
            "__init__.py": (
                "from typing import TYPE_CHECKING\n\n"
                "if TYPE_CHECKING:\n"
                "    pass\n"
                "else:\n"
                "    from app.plugins.myplugin.utils import helper\n"
            ),
            "utils.py": "def helper():\n    pass\n",
        },
    )

    readiness = scan_plugin_version_readiness("myplugin", plugin_dir)

    assert readiness.has_self_referential_imports
    hit = readiness.self_referential_imports[0]
    assert hit.statement == "from app.plugins.myplugin.utils import helper"


def test_cross_plugin_import_is_not_confused_with_self_reference(tmp_path: Path) -> None:
    """引用其它插件应归入跨插件依赖类，不计入自引用绝对 import。"""
    plugin_dir = _write_plugin(
        tmp_path,
        "myplugin",
        {"__init__.py": "from app.plugins.otherplugin import Thing\n"},
    )

    readiness = scan_plugin_version_readiness("myplugin", plugin_dir)

    assert readiness.has_self_referential_imports is False
    assert readiness.has_cross_plugin_imports
    hit = readiness.cross_plugin_imports[0]
    assert hit.file == "__init__.py"
    assert hit.line == 1
    assert hit.target_plugin_id == "otherplugin"
    assert hit.statement == "from app.plugins.otherplugin import Thing"


def test_cross_plugin_absolute_import_and_dynamic_import_are_both_classified(tmp_path: Path) -> None:
    """跨插件依赖的 import 与 importlib.import_module 形式都应归入跨插件类。"""
    plugin_dir = _write_plugin(
        tmp_path,
        "myplugin",
        {
            "__init__.py": (
                "import app.plugins.otherplugin.helpers\n"
                "import importlib\n"
                'importlib.import_module("app.plugins.thirdplugin.tools")\n'
            ),
        },
    )

    readiness = scan_plugin_version_readiness("myplugin", plugin_dir)

    assert readiness.has_self_referential_imports is False
    targets = {hit.target_plugin_id for hit in readiness.cross_plugin_imports}
    assert targets == {"otherplugin", "thirdplugin"}


def test_host_imports_are_not_mistaken_for_plugin_imports(tmp_path: Path) -> None:
    """导入宿主模块与第三方包不属于任何一类插件间依赖，不得误报。"""
    plugin_dir = _write_plugin(
        tmp_path,
        "myplugin",
        {
            "__init__.py": (
                "import requests\n"
                "from app.sdk.plugin import _PluginBase\n"
                "from app.schemas.types import EventType\n"
            ),
        },
    )

    readiness = scan_plugin_version_readiness("myplugin", plugin_dir)

    assert readiness.is_clean


def test_shared_base_model_via_from_app_db_import_is_reported(tmp_path: Path) -> None:
    """from app.db import Base 继承应被识别为共享基类建模。"""
    plugin_dir = _write_plugin(
        tmp_path,
        "myplugin",
        {
            "__init__.py": (
                "from app.db import Base\n"
                "from sqlalchemy.orm import Mapped, mapped_column\n\n"
                "class MyData(Base):\n"
                "    id: Mapped[int] = mapped_column(primary_key=True)\n"
            ),
        },
    )

    readiness = scan_plugin_version_readiness("myplugin", plugin_dir)

    assert readiness.has_shared_base_models
    hit = readiness.shared_base_models[0]
    assert hit.file == "__init__.py"
    assert hit.class_name == "MyData"
    assert hit.line == 4


def test_shared_base_model_via_app_db_base_module_attribute_is_reported(tmp_path: Path) -> None:
    """import app.db.base 后以 app.db.base.Base 继承也应被识别。"""
    plugin_dir = _write_plugin(
        tmp_path,
        "myplugin",
        {"__init__.py": "import app.db.base\n\nclass MyData(app.db.base.Base):\n    pass\n"},
    )

    readiness = scan_plugin_version_readiness("myplugin", plugin_dir)

    assert readiness.has_shared_base_models
    assert readiness.shared_base_models[0].class_name == "MyData"


def test_shared_base_model_via_module_alias_is_reported(tmp_path: Path) -> None:
    """import app.db as db 后以 db.Base 继承也应被识别。"""
    plugin_dir = _write_plugin(
        tmp_path,
        "myplugin",
        {"__init__.py": "import app.db as db\n\nclass MyData(db.Base):\n    pass\n"},
    )

    readiness = scan_plugin_version_readiness("myplugin", plugin_dir)

    assert readiness.has_shared_base_models
    assert readiness.shared_base_models[0].class_name == "MyData"


def test_shared_base_model_via_from_package_import_submodule_with_alias_is_reported(tmp_path: Path) -> None:
    """from app.db import base as db_base 后以 db_base.Base 继承应被识别。"""
    plugin_dir = _write_plugin(
        tmp_path,
        "myplugin",
        {"__init__.py": "from app.db import base as db_base\n\nclass MyData(db_base.Base):\n    pass\n"},
    )

    readiness = scan_plugin_version_readiness("myplugin", plugin_dir)

    assert readiness.has_shared_base_models
    assert readiness.shared_base_models[0].class_name == "MyData"


def test_shared_base_model_via_from_package_import_submodule_without_alias_is_reported(tmp_path: Path) -> None:
    """from app.db import base（无 as）后以 base.Base 继承应被识别。"""
    plugin_dir = _write_plugin(
        tmp_path,
        "myplugin",
        {"__init__.py": "from app.db import base\n\nclass MyData(base.Base):\n    pass\n"},
    )

    readiness = scan_plugin_version_readiness("myplugin", plugin_dir)

    assert readiness.has_shared_base_models
    assert readiness.shared_base_models[0].class_name == "MyData"


def test_plugin_own_base_class_is_not_confused_with_shared_base(tmp_path: Path) -> None:
    """插件自定义同名 Base 或继承非宿主基类不应被误报。"""
    plugin_dir = _write_plugin(
        tmp_path,
        "myplugin",
        {"__init__.py": "class Base:\n    pass\n\nclass MyData(Base):\n    pass\n"},
    )

    readiness = scan_plugin_version_readiness("myplugin", plugin_dir)

    assert readiness.has_shared_base_models is False


def test_plugin_private_declarative_base_is_not_reported(tmp_path: Path) -> None:
    """插件自建声明基类是并存安全的正确写法，不得被判成共享基类建模。"""
    plugin_dir = _write_plugin(
        tmp_path,
        "myplugin",
        {
            "__init__.py": (
                "from sqlalchemy.orm import declarative_base\n\n"
                "Base = declarative_base()\n\n"
                "class MyData(Base):\n"
                "    pass\n"
            ),
        },
    )

    readiness = scan_plugin_version_readiness("myplugin", plugin_dir)

    assert readiness.is_clean


def test_syntax_error_file_does_not_crash_scan_and_is_recorded_as_unparsed(tmp_path: Path) -> None:
    """插件文件语法错误不得让扫描抛异常，应记录为无法解析并继续扫描其余文件。"""
    plugin_dir = _write_plugin(
        tmp_path,
        "myplugin",
        {
            "__init__.py": "from app.plugins.myplugin.utils import helper\n",
            "broken.py": "def broken(:\n    pass\n",
        },
    )

    readiness = scan_plugin_version_readiness("myplugin", plugin_dir)

    assert readiness.unparsed_files == ("broken.py",)
    assert readiness.has_self_referential_imports
    assert readiness.is_clean is False


def test_nested_subpackage_self_import_computes_correct_relative_dots(tmp_path: Path) -> None:
    """深层子包内的自引用绝对 import 应算出正确的多层相对 import。"""
    plugin_dir = _write_plugin(
        tmp_path,
        "myplugin",
        {
            "__init__.py": "",
            "sub/__init__.py": "",
            "sub/foo.py": "from app.plugins.myplugin.utils import helper\n",
            "utils.py": "def helper():\n    pass\n",
        },
    )

    readiness = scan_plugin_version_readiness("myplugin", plugin_dir)

    hits = [hit for hit in readiness.self_referential_imports if hit.file == "sub/foo.py"]
    assert len(hits) == 1
    assert hits[0].suggestion == "from ..utils import helper"


def test_missing_plugin_directory_returns_empty_readiness(tmp_path: Path) -> None:
    """插件目录不存在时应返回空结论而不是抛异常。"""
    readiness = scan_plugin_version_readiness("ghost", tmp_path / "does-not-exist")

    assert readiness.is_clean


def test_multi_version_blockers_aggregates_self_referential_and_shared_base_hits(tmp_path: Path) -> None:
    """跨多个源码目录汇总阻断原因，只统计自引用导入与共享基类两类。"""
    old_dir = _write_plugin(
        tmp_path,
        "old",
        {"__init__.py": "from app.plugins.blockedplugin.utils import helper\n"},
    )
    new_dir = _write_plugin(
        tmp_path,
        "new",
        {"__init__.py": "from app.db import Base\n\nclass MyData(Base):\n    pass\n"},
    )

    blockers = plugin_multi_version_blockers("blockedplugin", [old_dir, new_dir])

    assert len(blockers) == 2
    assert any("自引用" in blocker for blocker in blockers)
    assert any("共享声明基类" in blocker for blocker in blockers)


def test_multi_version_blockers_ignores_cross_plugin_dependency(tmp_path: Path) -> None:
    """跨插件依赖不是本插件自身的写法错误，不计入并存阻断。"""
    plugin_dir = _write_plugin(
        tmp_path,
        "consumer",
        {"__init__.py": "from app.plugins.otherplugin import Thing\n"},
    )

    blockers = plugin_multi_version_blockers("consumer", [plugin_dir])

    assert blockers == []


def test_multi_version_blockers_is_empty_for_clean_source_dirs(tmp_path: Path) -> None:
    """全部源码目录都干净时不阻断多版本并存。"""
    first = _write_plugin(tmp_path, "clean-a", {"__init__.py": "value = 1\n"})
    second = _write_plugin(tmp_path, "clean-b", {"__init__.py": "value = 2\n"})

    assert plugin_multi_version_blockers("clean", [first, second]) == []


def _versioned_plugin(tmp_path: Path, version_bodies: dict[str, str]) -> Path:
    """按版本目录布局写入插件根目录，返回插件根目录。"""
    plugin_dir = tmp_path / "plugins" / GUARD_PLUGIN_ID.lower()
    for version, body in version_bodies.items():
        version_dir = plugin_dir / f"v{version.replace('.', '_')}"
        version_dir.mkdir(parents=True)
        (version_dir / "__init__.py").write_text(_plugin_main_module(version, body), encoding="utf-8")
    return plugin_dir


def _staged_source(tmp_path: Path, version: str, body: str = "") -> Path:
    """写出一份待安装的暂存源码目录。"""
    source_dir = tmp_path / "staging"
    source_dir.mkdir(parents=True)
    (source_dir / "__init__.py").write_text(_plugin_main_module(version, body), encoding="utf-8")
    return source_dir


def test_version_switch_guard_allows_install_when_plugin_is_not_installed(tmp_path: Path) -> None:
    """插件尚未安装任何源码时不存在并存，安装必须放行。"""
    plugin_dir = tmp_path / "plugins" / GUARD_PLUGIN_ID.lower()
    source_dir = _staged_source(tmp_path, "2.0.0", "from app.plugins.guardplugin.utils import helper\n")

    assert _reject_incompatible_plugin_version_switch(GUARD_PLUGIN_ID, plugin_dir, source_dir) is None


def test_version_switch_guard_allows_flat_layout_even_with_blocking_style(tmp_path: Path) -> None:
    """平铺布局下整个插件根目录被本次内容换入，磁盘上不会留下第二份源码，不体检。"""
    plugin_dir = tmp_path / "plugins" / GUARD_PLUGIN_ID.lower()
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "__init__.py").write_text(
        _plugin_main_module("1.0.0", "from app.plugins.guardplugin.utils import helper\n"),
        encoding="utf-8",
    )
    source_dir = _staged_source(tmp_path, "2.0.0", "from app.plugins.guardplugin.utils import helper\n")

    assert _reject_incompatible_plugin_version_switch(GUARD_PLUGIN_ID, plugin_dir, source_dir) is None


def test_version_switch_guard_allows_same_version_reinstall(tmp_path: Path) -> None:
    """同版本重新同步是开发闭环的日常操作，不触发体检也不拒绝。"""
    plugin_dir = _versioned_plugin(
        tmp_path, {"1.0.0": "from app.plugins.guardplugin.utils import helper\n"}
    )
    source_dir = _staged_source(tmp_path, "1.0.0", "from app.plugins.guardplugin.utils import helper\n")

    assert _reject_incompatible_plugin_version_switch(GUARD_PLUGIN_ID, plugin_dir, source_dir) is None


def test_version_switch_guard_rejects_switch_when_style_blocks_coexistence(tmp_path: Path) -> None:
    """版本目录布局下切换到另一版本，写法阻断并存时必须拒绝并说明原因。"""
    plugin_dir = _versioned_plugin(tmp_path, {"1.0.0": ""})
    source_dir = _staged_source(tmp_path, "2.0.0", "from app.plugins.guardplugin.utils import helper\n")

    rejection = _reject_incompatible_plugin_version_switch(GUARD_PLUGIN_ID, plugin_dir, source_dir)

    assert rejection is not None
    assert "1.0.0" in rejection and "2.0.0" in rejection
    assert "自引用绝对导入" in rejection


def test_version_switch_guard_rejects_switch_when_installed_version_blocks_coexistence(tmp_path: Path) -> None:
    """阻断写法在已装版本里时同样拒绝——并存要求全部参与版本都合规。"""
    plugin_dir = _versioned_plugin(
        tmp_path, {"1.0.0": "from app.db import Base\n\nclass MyData(Base):\n    pass\n"}
    )
    source_dir = _staged_source(tmp_path, "2.0.0")

    rejection = _reject_incompatible_plugin_version_switch(GUARD_PLUGIN_ID, plugin_dir, source_dir)

    assert rejection is not None
    assert "共享声明基类" in rejection


def test_version_switch_guard_allows_switch_when_every_version_is_clean(tmp_path: Path) -> None:
    """版本目录布局下写法全部合规时放行版本切换。"""
    plugin_dir = _versioned_plugin(tmp_path, {"1.0.0": "from .utils import helper\n"})
    source_dir = _staged_source(tmp_path, "2.0.0", "from .utils import helper\n")

    assert _reject_incompatible_plugin_version_switch(GUARD_PLUGIN_ID, plugin_dir, source_dir) is None


def _guarded_manager(monkeypatch, tmp_path: Path) -> tuple[PluginPackageManager, Path]:
    """构造隔离目录、且已装配恒拒绝守卫的包 owner，并预置一个已装插件。"""
    plugin_root = tmp_path / "plugins"
    settings = SimpleNamespace(
        ROOT_PATH=tmp_path,
        TEMP_PATH=tmp_path / "temp",
        CONFIG_PATH=tmp_path / "config",
    )
    monkeypatch.setattr(
        "app.adapters.system.plugin.package.get_runtime_setting",
        lambda key: getattr(settings, key),
    )
    monkeypatch.setattr("app.adapters.system.plugin.package.SystemUtils.is_frozen", lambda: False)
    plugin_dir = plugin_root / GUARD_PLUGIN_ID.lower()
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "__init__.py").write_text("installed", encoding="utf-8")
    manager = PluginPackageManager(
        source=Mock(),
        plugin_root=plugin_root,
        version_switch_guard=lambda *_args: "写法不支持多版本并存",
    )
    monkeypatch.setattr(manager, "is_local_repo_url", lambda _repo_url: False)
    monkeypatch.setattr(manager, "get_repo_info", lambda _repo_url: ("demo", "repo"))
    monkeypatch.setattr(manager, "get_plugin_package_version", lambda *_args: "v2")
    monkeypatch.setattr(
        manager,
        "_PluginPackageManager__get_plugin_meta",
        lambda *_args: {"release": False, "version": "2.0.0"},
    )
    return manager, plugin_dir


def test_sync_install_is_rejected_by_version_switch_guard(monkeypatch, tmp_path: Path) -> None:
    """守卫拒绝时同步安装失败，且已装插件原样保留——运行目录尚未被触碰。"""
    manager, plugin_dir = _guarded_manager(monkeypatch, tmp_path)

    def prepare(_pid, _user_repo, _package_version, dest_root: Path) -> tuple[bool, str]:
        """把新版本内容写进本次分配的暂存目录。"""
        dest_root.mkdir(parents=True, exist_ok=True)
        (dest_root / "__init__.py").write_text("upgraded", encoding="utf-8")
        return True, ""

    monkeypatch.setattr(manager, "_PluginPackageManager__prepare_content_via_filelist_sync", prepare)

    success, message = manager.install_raw(
        GUARD_PLUGIN_ID, REPO_URL, package_version="v2", force_install=True
    )

    assert success is False
    assert message == "写法不支持多版本并存"
    assert (plugin_dir / "__init__.py").read_text(encoding="utf-8") == "installed"


@pytest.mark.asyncio
async def test_async_install_is_rejected_by_version_switch_guard(monkeypatch, tmp_path: Path) -> None:
    """异步安装与同步保持一致的拒绝语义，守卫拒绝时不得触碰运行目录。"""
    manager, plugin_dir = _guarded_manager(monkeypatch, tmp_path)

    async def async_package_version(*_args) -> str:
        """异步入口复用同一索引代际。"""
        return "v2"

    async def async_meta(*_args) -> dict:
        """异步入口复用同一插件元数据。"""
        return {"release": False, "version": "2.0.0"}

    async def prepare(_pid, _user_repo, _package_version, dest_root: Path) -> tuple[bool, str]:
        """把新版本内容写进本次分配的暂存目录。"""
        dest_root.mkdir(parents=True, exist_ok=True)
        (dest_root / "__init__.py").write_text("upgraded", encoding="utf-8")
        return True, ""

    monkeypatch.setattr(manager, "async_get_plugin_package_version", async_package_version)
    monkeypatch.setattr(manager, "_PluginPackageManager__async_get_plugin_meta", async_meta)
    monkeypatch.setattr(manager, "_PluginPackageManager__prepare_content_via_filelist_async", prepare)

    success, message = await manager.async_install_raw(
        GUARD_PLUGIN_ID, REPO_URL, package_version="v2", force_install=True
    )

    assert success is False
    assert message == "写法不支持多版本并存"
    assert (plugin_dir / "__init__.py").read_text(encoding="utf-8") == "installed"


# 安装落盘到版本目录之后，守卫的触发面从「永不触发」变成真的会触发


def _fully_wired_manager(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, incoming_body: str
) -> tuple[PluginPackageManager, Path, list[tuple[str, Path, Path]]]:
    """装配全部四个真实端口的包 owner，并备好一份待装的 2.0.0 源码。

    守卫外面包一层只记参数、随即原样转交真实实现的替身：安装落盘到版本目录之后，
    磁盘上才会真的出现第二份源码，因此这里要证明的不是守卫自己的判据，而是它确实
    被接在安装路径上、且拿到的是插件根目录与本次暂存源码目录。

    :param monkeypatch: pytest monkeypatch 夹具
    :param tmp_path: 隔离全部落盘的临时根
    :param incoming_body: 待装 2.0.0 源码主模块的类体外追加内容
    :return: (包 owner, 插件根目录, 守卫每次调用时的插件ID、插件根目录与暂存源码是否齐备)
    """
    source_dir = tmp_path / "repo" / GUARD_PLUGIN_ID.lower()
    source_dir.mkdir(parents=True)
    (source_dir / "__init__.py").write_text(
        _plugin_main_module("2.0.0", incoming_body), encoding="utf-8"
    )

    plugins_root = tmp_path / "app" / "plugins"
    settings = SimpleNamespace(
        ROOT_PATH=tmp_path,
        TEMP_PATH=tmp_path / "temp",
        CONFIG_PATH=tmp_path / "config",
        VERSION_FLAG="v2",
        REPO_GITHUB_HEADERS=lambda _repo: {},
    )
    monkeypatch.setattr(
        "app.adapters.system.plugin.package.get_runtime_setting",
        lambda key: getattr(settings, key),
    )

    guard_calls: list[tuple[str, Path, bool]] = []

    def spying_guard(plugin_id: str, plugin_dir: Path, staged_dir: Path) -> str | None:
        """记下一次调用后把判定原样交还给组合根装配的真实守卫。

        暂存目录在安装结束时会被清掉，因此「调用时暂存源码是否已齐备」必须在这里
        当场取样，事后再看只剩一个不存在的路径。
        """
        guard_calls.append((plugin_id, plugin_dir, (staged_dir / "__init__.py").is_file()))
        return _reject_incompatible_plugin_version_switch(plugin_id, plugin_dir, staged_dir)

    source_port = Mock()
    source_port.is_local_repo_url.return_value = True
    source_port.parse_local_repo_url.return_value = GUARD_PLUGIN_ID
    source_port.parse_local_repo_path.return_value = None
    source_port.parse_local_repo_package_version.return_value = None
    source_port.get_local_plugin_candidate.return_value = {"path": str(source_dir)}
    source_port.check_plugin_system_version.return_value = (True, "")

    manager = PluginPackageManager(
        source=source_port,
        plugin_root=plugins_root,
        install_target_resolver=resolve_plugin_install_target,
        install_version_registrar=register_plugin_install_version,
        install_version_rollback=rollback_plugin_install_version,
        version_switch_guard=spying_guard,
    )
    return manager, plugins_root / GUARD_PLUGIN_ID.lower(), guard_calls


def _install_registered_version(plugin_dir: Path, version: str, body: str) -> Path:
    """在插件根目录下放一个已登记的版本目录，模拟此前装好的版本。"""
    version_dir = plugin_dir / f"v{version.replace('.', '_')}"
    version_dir.mkdir(parents=True)
    (version_dir / "__init__.py").write_text(_plugin_main_module(version, body), encoding="utf-8")
    (version_dir / "marker.txt").write_text(version, encoding="utf-8")
    register_plugin_version(plugin_dir, version, "market")
    return version_dir


def test_installing_a_new_version_runs_the_guard_and_lands_in_a_version_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """装新版本时守卫确实被调用，写法合规则照常落到新的版本目录。"""
    manager, plugin_dir, guard_calls = _fully_wired_manager(
        monkeypatch, tmp_path, incoming_body="from .utils import helper\n"
    )
    _install_registered_version(plugin_dir, "1.0.0", "from .utils import helper\n")

    assert manager.install_local_raw(GUARD_PLUGIN_ID, repo_url=LOCAL_REPO_URL) == (True, "")

    assert guard_calls == [(GUARD_PLUGIN_ID, plugin_dir, True)]
    assert set(plugin_version_dirs(plugin_dir)) == {"1.0.0", "2.0.0"}
    assert read_plugin_versions_manifest(plugin_dir)["current"] == "2.0.0"


def test_blocking_style_rejects_the_install_and_leaves_the_runtime_dir_untouched(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """体检不通过时安装被拒绝，运行目录一件不动：既没有新版本目录也没改元信息。"""
    manager, plugin_dir, guard_calls = _fully_wired_manager(
        monkeypatch, tmp_path, incoming_body=SELF_REFERENTIAL_IMPORT
    )
    _install_registered_version(plugin_dir, "1.0.0", "from .utils import helper\n")
    manifest_before = (plugin_dir / "versions.json").read_bytes()

    success, message = manager.install_local_raw(GUARD_PLUGIN_ID, repo_url=LOCAL_REPO_URL)

    assert success is False
    assert "不支持多版本并存" in message and "自引用绝对导入" in message
    assert len(guard_calls) == 1
    assert set(plugin_version_dirs(plugin_dir)) == {"1.0.0"}
    assert (plugin_dir / "v1_0_0" / "marker.txt").read_text(encoding="utf-8") == "1.0.0"
    assert (plugin_dir / "versions.json").read_bytes() == manifest_before


@pytest.mark.asyncio
async def test_async_install_rejection_leaves_the_runtime_dir_untouched(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """异步安装把体检转交线程池后仍拿到同一个拒绝结论，运行目录同样一件不动。"""
    manager, plugin_dir, guard_calls = _fully_wired_manager(
        monkeypatch, tmp_path, incoming_body=SELF_REFERENTIAL_IMPORT
    )
    _install_registered_version(plugin_dir, "1.0.0", "from .utils import helper\n")
    manifest_before = (plugin_dir / "versions.json").read_bytes()

    success, message = await manager.async_install_local_raw(
        GUARD_PLUGIN_ID, repo_url=LOCAL_REPO_URL
    )

    assert success is False
    assert "不支持多版本并存" in message and "自引用绝对导入" in message
    assert len(guard_calls) == 1
    assert set(plugin_version_dirs(plugin_dir)) == {"1.0.0"}
    assert (plugin_dir / "versions.json").read_bytes() == manifest_before
