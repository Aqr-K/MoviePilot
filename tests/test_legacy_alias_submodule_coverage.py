"""兼容别名的子模块覆盖度。

``LegacyImportFinder.find_spec`` 只按精确 ``fullname`` 查 ``MODULE_ALIASES``。旧包路径命中后
``LegacyAliasLoader`` 会把 canonical 包的 ``__path__`` 恢复到旧名下，此时未单独登记的子模块
会退回 ``PathFinder`` 沿这个 ``__path__`` 二次执行源码，生成一个 id 不同的模块对象——插件与
主程序各持一份同名却不同一的类，``isinstance``/``issubclass`` 会静默失败。

因此每个 ``is_package=True`` 的旧路径，其 canonical 目标下的每个子模块都必须单独登记。
"""
import importlib
import pkgutil
from typing import List, Tuple

import pytest

from app.runtime.compat.imports import install_legacy_import_hook
from app.runtime.compat.manifest import MODULE_ALIASES


def package_aliases() -> List[Tuple[str, str]]:
    """
    列出登记为包的别名

    :return: [(旧包路径, canonical 包路径), ...]
    """
    return [(legacy, alias.target) for legacy, alias in sorted(MODULE_ALIASES.items())
            if alias.is_package]


def submodules(legacy: str, target: str) -> List[Tuple[str, str]]:
    """
    列出 canonical 包下的全部子模块及其对应的旧路径

    :param legacy: 旧包路径
    :param target: canonical 包路径
    :return: [(旧子模块路径, canonical 子模块路径), ...]
    """
    package = importlib.import_module(target)
    search_path = getattr(package, "__path__", None)
    if not search_path:
        return []
    return [(legacy + name[len(target):], name)
            for _, name, _ in pkgutil.walk_packages(search_path, prefix=f"{target}.")]


def test_every_submodule_of_an_aliased_package_is_registered():
    """登记为包的别名，其下每个子模块都要单独登记。"""
    missing = []
    for legacy, target in package_aliases():
        try:
            children = submodules(legacy, target)
        except Exception as err:
            pytest.skip(f"canonical 包 {target} 在当前环境不可导入：{err}")
        missing.extend(child for child, _ in children if child not in MODULE_ALIASES)

    assert missing == []


@pytest.mark.parametrize("legacy, target", package_aliases())
def test_an_aliased_package_resolves_to_the_canonical_module_object(legacy, target):
    """旧包路径解析到 canonical 模块对象本身，而不是重新执行出的副本。"""
    install_legacy_import_hook()

    try:
        canonical = importlib.import_module(target)
    except Exception as err:
        pytest.skip(f"canonical 包 {target} 在当前环境不可导入：{err}")

    assert importlib.import_module(legacy) is canonical
