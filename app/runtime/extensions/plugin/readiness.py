"""静态扫描插件源码，判定其写法能否让同一插件的多个版本在同一进程内并存。

三类判据：

1. 自引用绝对 import——插件写 ``from app.plugins.<自身ID>.xxx import X`` 引用自己包内的
   模块。版本化后真实模块路径是 ``app.plugins.<插件ID>.<版本目录>.xxx``，该写法直接
   ``ModuleNotFoundError``；即便宿主替它改写，两个版本也会指向同一个绝对路径，后加载的
   版本会拿到先加载版本的代码。宿主不做兼容，插件必须改成相对 import。
2. 跨插件导入——插件引用其它插件的模块。多版本下同样脆弱（被依赖插件切版本会连带改变本
   插件的行为），但这不是本插件自身的写法错误，只报告不阻断。
3. 共享声明基类建模——插件在宿主 ``app.db.Base``／``app.db.base.Base`` 上定义模型类。
   声明基类的 MetaData 是进程级单例，同一插件的两个版本会向它注册同名表，第二个版本
   import 时直接冲突。

写在 ``if TYPE_CHECKING:``（含 ``typing.TYPE_CHECKING`` 及其别名）body 内的自引用或跨插件
绝对 import 运行期永不执行，不计入第 1、2 类判据；同一 if 的 else 分支运行期正常执行，仍
计入判据。

本模块只做只读静态分析，不导入插件代码、不改变插件加载行为，因此只依赖标准库。
"""

from __future__ import annotations

import ast
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

# 插件可能用来引用宿主共享声明基类 Base 的模块路径
_SHARED_BASE_MODULES = frozenset({"app.db", "app.db.base"})
# 归一化后的导入点形态，决定改写建议的措辞
_FROM_IMPORT = "from"
_PLAIN_IMPORT = "module"
_DYNAMIC_IMPORT = "dynamic"


@dataclass(frozen=True, slots=True)
class SelfReferentialImportHit:
    """一次自引用绝对 import 命中。"""

    file: str  # 相对插件目录的文件路径
    line: int  # 源码行号
    statement: str  # 原始导入语句原文
    suggestion: str  # 建议改写成的相对 import 写法


@dataclass(frozen=True, slots=True)
class CrossPluginImportHit:
    """一次跨插件 import 命中。"""

    file: str
    line: int
    statement: str
    target_plugin_id: str  # 被依赖插件的目录名


@dataclass(frozen=True, slots=True)
class SharedBaseModelHit:
    """一次继承宿主共享声明基类的模型类定义命中。"""

    file: str
    line: int
    class_name: str


@dataclass(frozen=True, slots=True)
class PluginVersionReadiness:
    """单个插件的多版本目录布局静态扫描结论。"""

    plugin_id: str
    self_referential_imports: tuple[SelfReferentialImportHit, ...] = field(default_factory=tuple)
    cross_plugin_imports: tuple[CrossPluginImportHit, ...] = field(default_factory=tuple)
    shared_base_models: tuple[SharedBaseModelHit, ...] = field(default_factory=tuple)
    unparsed_files: tuple[str, ...] = field(default_factory=tuple)

    @property
    def has_self_referential_imports(self) -> bool:
        """是否命中自引用绝对 import。"""
        return bool(self.self_referential_imports)

    @property
    def has_cross_plugin_imports(self) -> bool:
        """是否命中跨插件依赖。"""
        return bool(self.cross_plugin_imports)

    @property
    def has_shared_base_models(self) -> bool:
        """是否命中宿主共享声明基类建模。"""
        return bool(self.shared_base_models)

    @property
    def is_clean(self) -> bool:
        """三类判据均未命中且全部文件可解析。"""
        return not (
            self.self_referential_imports
            or self.cross_plugin_imports
            or self.shared_base_models
            or self.unparsed_files
        )


@dataclass(frozen=True, slots=True)
class _ImportSite:
    """把不同语法形态的一次绝对导入归一成同一结构，供分类与建议共用。"""

    module: str  # 被导入模块的全名
    line: int
    statement: str  # 导入语句原文
    shape: str  # _FROM_IMPORT / _PLAIN_IMPORT / _DYNAMIC_IMPORT
    names: tuple[ast.alias, ...] = ()  # from-import 引入的符号表
    asname: str | None = None  # ``import x as y`` 的本地绑定名


@dataclass(frozen=True, slots=True)
class _FileHits:
    """单个源码文件的三类命中。"""

    self_referential: tuple[SelfReferentialImportHit, ...]
    cross_plugin: tuple[CrossPluginImportHit, ...]
    shared_base: tuple[SharedBaseModelHit, ...]


def _classify_plugin_module(module_name: str, own_plugin_id: str) -> tuple[str, str] | None:
    """判断 module_name 是否指向某个插件包，返回 (分类, 目标插件目录名)。

    :param module_name: 待判定的模块名
    :param own_plugin_id: 发起 import 的插件目录名
    :return: 分类为 ``self`` 表示指向 own_plugin_id 自身，``cross`` 表示指向其它插件；
        module_name 不属于 ``app.plugins.<插件ID>`` 形态时返回 None
    """
    parts = module_name.split(".")
    if len(parts) < 3 or parts[0] != "app" or parts[1] != "plugins" or not parts[2]:
        return None
    target_plugin_id = parts[2]
    category = "self" if target_plugin_id.lower() == own_plugin_id.lower() else "cross"
    return category, target_plugin_id


def _relative_module_reference(from_package_parts: list[str], target_parts: list[str]) -> str:
    """计算从 from_package_parts 所在包引用 target_parts 对应模块的相对写法。

    :param from_package_parts: 发起 import 的文件所在包，相对插件根目录的目录分段
    :param target_parts: 目标模块相对插件根目录的路径分段（已剥离 app.plugins.<插件ID> 前缀）
    :return: 形如 ``.``、``..utils``、``.sub.utils`` 的相对模块引用（不含 from/import 关键字）
    """
    common = 0
    limit = min(len(from_package_parts), len(target_parts))
    while common < limit and from_package_parts[common] == target_parts[common]:
        common += 1
    dots = "." * (len(from_package_parts) - common + 1)
    suffix = ".".join(target_parts[common:])
    return f"{dots}{suffix}" if suffix else dots


def _import_from_suggestion(names: Iterable[ast.alias], relative_ref: str) -> str:
    """拼装 from-import 形态的改写建议文本。"""
    rendered = ", ".join(
        f"{alias.name} as {alias.asname}" if alias.asname else alias.name
        for alias in names
    )
    return f"from {relative_ref} import {rendered}"


def _plain_import_suggestion(site: _ImportSite, from_package_parts: list[str], target_after_pid: list[str]) -> str:
    """为 ``import app.plugins.<插件ID>.xxx`` 形态生成改写建议文本。"""
    if not target_after_pid:
        return (
            "避免用 import 以绝对路径导入自身插件包；"
            "如需引用包内符号，改写为 from . import <符号名>。"
        )
    relative_ref = _relative_module_reference(from_package_parts, target_after_pid[:-1])
    leaf_name = target_after_pid[-1]
    if site.asname:
        return f"from {relative_ref} import {leaf_name} as {site.asname}"
    return (
        f"from {relative_ref} import {leaf_name}；"
        f"并将文件内 {site.module} 的属性访问改写为 {leaf_name}"
    )


def _dynamic_import_suggestion(from_package_parts: list[str], target_after_pid: list[str]) -> str:
    """为 ``importlib.import_module("app.plugins.<插件ID>.xxx")`` 形态生成改写建议文本。"""
    if not target_after_pid:
        return (
            "避免用 importlib.import_module 以绝对路径导入自身插件包；"
            "改为静态相对 import（如 from . import <符号名>）。"
        )
    relative_ref = _relative_module_reference(from_package_parts, target_after_pid)
    return (
        f"改为静态相对 import：from {relative_ref} import <所需符号>"
        "（importlib.import_module 的绝对字符串路径在版本化目录下会失效）"
    )


def _self_reference_suggestion(site: _ImportSite, from_package_parts: list[str]) -> str:
    """按导入点形态给出对应的相对 import 改写建议。"""
    target_after_pid = site.module.split(".")[3:]
    if site.shape == _FROM_IMPORT:
        return _import_from_suggestion(site.names, _relative_module_reference(from_package_parts, target_after_pid))
    if site.shape == _PLAIN_IMPORT:
        return _plain_import_suggestion(site, from_package_parts, target_after_pid)
    return _dynamic_import_suggestion(from_package_parts, target_after_pid)


def _dotted_attribute_name(expr: ast.expr) -> str | None:
    """把 Name/Attribute 链还原成点分字符串，其余表达式返回 None。"""
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        base = _dotted_attribute_name(expr.value)
        return f"{base}.{expr.attr}" if base else None
    return None


def _collect_base_bindings(tree: ast.AST) -> tuple[set[str], set[str]]:
    """收集文件内可能指向宿主共享 Base 的符号别名与模块别名。

    ``from <父包> import <子名>`` 既可能引入符号 ``Base`` 本身，也可能引入
    ``_SHARED_BASE_MODULES`` 中某一模块的子模块（如 ``from app.db import base``）；后者绑定
    的是模块，需要按 ``<父包>.<子名>`` 拼出完整路径再与 ``_SHARED_BASE_MODULES`` 比对，才能
    覆盖 ``db_base.Base`` 这类属性访问写法。``import app.db`` 这类无 as 的形态绑定的是顶层
    包名，引用时必然写出完整点分路径，由 :func:`_is_shared_base_reference` 的全路径比对覆盖，
    这里不登记，否则 ``app.Base`` 会被误判成宿主基类。

    :param tree: 已解析的文件语法树
    :return: (符号别名集合, 模块别名集合)
    """
    symbol_aliases: set[str] = set()
    module_aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for alias in node.names:
                if node.module in _SHARED_BASE_MODULES and alias.name == "Base":
                    symbol_aliases.add(alias.asname or alias.name)
                elif f"{node.module}.{alias.name}" in _SHARED_BASE_MODULES:
                    module_aliases.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in _SHARED_BASE_MODULES and alias.asname:
                    module_aliases.add(alias.asname)
    return symbol_aliases, module_aliases


def _is_shared_base_reference(expr: ast.expr, symbol_aliases: set[str], module_aliases: set[str]) -> bool:
    """判断一个基类表达式是否指向宿主共享声明基类 Base。"""
    if isinstance(expr, ast.Name):
        return expr.id in symbol_aliases
    if isinstance(expr, ast.Attribute) and expr.attr == "Base":
        dotted = _dotted_attribute_name(expr.value)
        if dotted is None:
            return False
        return dotted in module_aliases or dotted in _SHARED_BASE_MODULES
    return False


def _typing_check_aliases(tree: ast.AST) -> tuple[set[str], set[str]]:
    """收集文件内 ``typing.TYPE_CHECKING`` 的符号别名与 typing 模块别名。

    仅类型检查分支的判定依赖这两类绑定：符号别名来自 ``from typing import TYPE_CHECKING``，
    用于匹配 ``if X:``；模块别名来自 ``import typing``，用于匹配 ``if X.TYPE_CHECKING:``。

    :param tree: 已解析的文件语法树
    :return: (TYPE_CHECKING 符号别名集合, typing 模块别名集合)
    """
    symbol_aliases: set[str] = set()
    module_aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "typing" and node.level == 0:
            for alias in node.names:
                if alias.name == "TYPE_CHECKING":
                    symbol_aliases.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "typing":
                    module_aliases.add(alias.asname or alias.name)
    return symbol_aliases, module_aliases


def _is_type_checking_test(test: ast.expr, symbol_aliases: set[str], module_aliases: set[str]) -> bool:
    """判断 if 条件表达式是否为仅类型检查判据（TYPE_CHECKING 或其别名）。"""
    if isinstance(test, ast.Name):
        return test.id in symbol_aliases
    if isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING":
        base = test.value
        return isinstance(base, ast.Name) and base.id in module_aliases
    return False


def _type_checking_only_node_ids(tree: ast.AST) -> frozenset[int]:
    """收集仅类型检查分支内全部节点的 id，供导入类判据跳过。

    ``if TYPE_CHECKING:``（或其别名形式）的 body 运行期永不执行，其中的导入在版本化目录下
    不会触发 ``ModuleNotFoundError``，不应计入阻断；同一 if 的 ``else`` 分支运行期正常执行，
    不在排除范围内。

    :param tree: 已解析的文件语法树
    :return: 需要从自引用/跨插件导入判据中排除的节点 id 集合
    """
    symbol_aliases, module_aliases = _typing_check_aliases(tree)
    excluded: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and _is_type_checking_test(node.test, symbol_aliases, module_aliases):
            for statement in node.body:
                excluded.update(id(sub) for sub in ast.walk(statement))
    return frozenset(excluded)


def _dynamic_import_aliases(tree: ast.AST) -> tuple[set[str], set[str]]:
    """收集 importlib 模块别名与 import_module 函数别名。

    与 ``app/runtime/compat/resources.py`` 的同名私有实现刻意重复：canonical 实现层不得反向
    依赖兼容层，两份实现各自服务于不同判据，共用一份会把兼容边界拉进插件运行时。

    :param tree: 已解析的文件语法树
    :return: (importlib 模块别名集合, import_module 函数别名集合)
    """
    module_aliases = {"importlib"}
    function_aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "importlib":
                    module_aliases.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module == "importlib":
            for alias in node.names:
                if alias.name == "import_module":
                    function_aliases.add(alias.asname or alias.name)
    return module_aliases, function_aliases


def _constant_dynamic_import(node: ast.Call, importlib_aliases: set[str], import_module_aliases: set[str]) -> str | None:
    """提取 ``importlib.import_module``／``__import__`` 调用里的常量模块名。

    只认字符串常量实参：拼接出来的模块名要执行才知道结果，静态阶段无法判定，报出来只会制造
    噪声。

    :param node: 待判定的调用节点
    :param importlib_aliases: importlib 模块别名集合
    :param import_module_aliases: import_module 函数别名集合
    :return: 常量模块名；不是可判定的动态导入时为 None
    """
    if not node.args:
        return None
    is_import_call = isinstance(node.func, ast.Name) and (
        node.func.id == "__import__" or node.func.id in import_module_aliases
    )
    if (
        isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in importlib_aliases
        and node.func.attr == "import_module"
    ):
        is_import_call = True
    if not is_import_call:
        return None
    argument = node.args[0]
    if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
        return argument.value
    return None


def _import_sites(
    node: ast.AST,
    source: str,
    importlib_aliases: set[str],
    import_module_aliases: set[str],
) -> list[_ImportSite]:
    """把一个语法节点归一成零到多个绝对导入点。

    :param node: 待归一的语法节点
    :param source: 文件源码原文，用于取回语句原文
    :param importlib_aliases: importlib 模块别名集合
    :param import_module_aliases: import_module 函数别名集合
    :return: 该节点对应的绝对导入点；相对 import 与非导入节点返回空列表
    """
    if isinstance(node, ast.ImportFrom):
        if not node.module or node.level != 0:
            return []
        statement = ast.get_source_segment(source, node) or node.module
        return [
            _ImportSite(
                module=node.module,
                line=node.lineno,
                statement=statement,
                shape=_FROM_IMPORT,
                names=tuple(node.names),
            )
        ]
    if isinstance(node, ast.Import):
        statement = ast.get_source_segment(source, node) or ""
        return [
            _ImportSite(
                module=alias.name,
                line=node.lineno,
                statement=statement or alias.name,
                shape=_PLAIN_IMPORT,
                asname=alias.asname,
            )
            for alias in node.names
        ]
    if isinstance(node, ast.Call):
        module_name = _constant_dynamic_import(node, importlib_aliases, import_module_aliases)
        if not module_name:
            return []
        statement = ast.get_source_segment(source, node) or module_name
        return [
            _ImportSite(
                module=module_name,
                line=node.lineno,
                statement=statement,
                shape=_DYNAMIC_IMPORT,
            )
        ]
    return []


def _scan_source_file(plugin_id: str, relative_path: Path, source: str, tree: ast.AST) -> _FileHits:
    """扫描单个已解析的源码文件，返回其三类命中。

    :param plugin_id: 插件目录名
    :param relative_path: 文件相对插件根目录的路径
    :param source: 文件源码原文
    :param tree: 已解析的文件语法树
    :return: 该文件的三类命中
    """
    file_name = str(relative_path)
    package_parts = list(relative_path.parts[:-1])
    importlib_aliases, import_module_aliases = _dynamic_import_aliases(tree)
    symbol_aliases, module_aliases = _collect_base_bindings(tree)
    type_checking_only_ids = _type_checking_only_node_ids(tree)

    self_hits: list[SelfReferentialImportHit] = []
    cross_hits: list[CrossPluginImportHit] = []
    base_hits: list[SharedBaseModelHit] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            if any(_is_shared_base_reference(base, symbol_aliases, module_aliases) for base in node.bases):
                base_hits.append(SharedBaseModelHit(file=file_name, line=node.lineno, class_name=node.name))
            continue
        if id(node) in type_checking_only_ids:
            continue
        for site in _import_sites(node, source, importlib_aliases, import_module_aliases):
            classification = _classify_plugin_module(site.module, plugin_id)
            if not classification:
                continue
            category, target_plugin_id = classification
            if category == "self":
                self_hits.append(
                    SelfReferentialImportHit(
                        file=file_name,
                        line=site.line,
                        statement=site.statement,
                        suggestion=_self_reference_suggestion(site, package_parts),
                    )
                )
            else:
                cross_hits.append(
                    CrossPluginImportHit(
                        file=file_name,
                        line=site.line,
                        statement=site.statement,
                        target_plugin_id=target_plugin_id,
                    )
                )
    return _FileHits(tuple(self_hits), tuple(cross_hits), tuple(base_hits))


def scan_plugin_version_readiness(plugin_id: str, plugin_dir: Path) -> PluginVersionReadiness:
    """扫描单个插件源码目录，返回其多版本目录布局适配结论。

    :param plugin_id: 插件目录名（即版本化后 app/plugins/<插件ID>/<版本目录>/ 的 <插件ID>）
    :param plugin_dir: 插件源码目录
    :return: 结构化的静态扫描结论；语法错误等无法解析的文件记录在 unparsed_files 中，不中断扫描
    """
    if not plugin_dir.is_dir():
        return PluginVersionReadiness(plugin_id=plugin_id)

    self_hits: list[SelfReferentialImportHit] = []
    cross_hits: list[CrossPluginImportHit] = []
    base_hits: list[SharedBaseModelHit] = []
    unparsed: list[str] = []
    for path in sorted(plugin_dir.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        relative_path = path.relative_to(plugin_dir)
        try:
            source = path.read_text(encoding="utf-8-sig")
            tree = ast.parse(source, filename=str(path))
        except (OSError, SyntaxError, UnicodeError, ValueError):
            unparsed.append(str(relative_path))
            continue
        hits = _scan_source_file(plugin_id, relative_path, source, tree)
        self_hits.extend(hits.self_referential)
        cross_hits.extend(hits.cross_plugin)
        base_hits.extend(hits.shared_base)

    return PluginVersionReadiness(
        plugin_id=plugin_id,
        self_referential_imports=tuple(self_hits),
        cross_plugin_imports=tuple(cross_hits),
        shared_base_models=tuple(base_hits),
        unparsed_files=tuple(unparsed),
    )


def plugin_multi_version_blockers(plugin_id: str, source_dirs: Iterable[Path]) -> list[str]:
    """汇总插件多个版本源码目录中不支持多版本并存的写法。

    自引用绝对 import 在版本化目录下必然 ``ModuleNotFoundError``；在宿主共享声明基类上定义的
    模型会让两个版本向同一个进程级 MetaData 注册同名表，第二个版本 import 时直接冲突。这两类
    都是本插件自身的写法错误，真正双版本并存时必然失败，因此纳入阻断；跨插件依赖不是本插件
    自身的写法错误，不纳入阻断。

    :param plugin_id: 插件目录名
    :param source_dirs: 待检查的插件源码目录，不存在的目录按无命中处理
    :return: 阻断原因列表；为空表示允许多版本并存
    """
    blockers: list[str] = []
    for source_dir in source_dirs:
        readiness = scan_plugin_version_readiness(plugin_id, Path(source_dir))
        blockers.extend(
            f"存在自引用绝对导入：{hit.file}:{hit.line} {hit.statement}；{hit.suggestion}"
            for hit in readiness.self_referential_imports
        )
        blockers.extend(
            f"在宿主共享声明基类上定义模型 {hit.class_name}：{hit.file}:{hit.line}"
            for hit in readiness.shared_base_models
        )
    return blockers
