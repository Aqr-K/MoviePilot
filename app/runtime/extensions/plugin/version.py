"""插件源码按版本分目录布局的目录名映射、已装版本元信息读写与加载路径解析。"""

from __future__ import annotations

import ast
import json
import os
import re
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.foundation.version import compare_version
from app.runtime.log import logger
from app.schemas.plugin import PluginInstance

# 插件源码版本目录名的前缀，用于把版本目录与插件目录下的其它条目区分开
PLUGIN_VERSION_DIR_PREFIX = "v"
# 插件已装版本元信息文件名，位于 app/plugins/<插件ID>/ 下，不是 Python 模块
PLUGIN_VERSIONS_MANIFEST_NAME = "versions.json"
# 版本元信息文件的结构版本号
PLUGIN_VERSIONS_MANIFEST_SCHEMA = 1
# 存量平铺布局迁移到版本目录时使用的中转目录名前缀。中转目录落在插件目录内部，
# 与版本目录同父：两次改名都发生在同一个目录下，不可能跨文件系统，也不会像
# 落在 app/plugins 下那样被插件扫描误当成另一个插件
PLUGIN_LAYOUT_STAGING_PREFIX = ".migrating-"
# 元信息原子改名用的临时文件名前缀，与正式文件同目录
_PLUGIN_MANIFEST_STAGING_PREFIX = f".{PLUGIN_VERSIONS_MANIFEST_NAME}."
# 存量插件没有声明版本号时迁移使用的兜底版本号
PLUGIN_FALLBACK_VERSION = "0.0.0"
# 合法版本号字符集：数字、字母、点、连字符、加号。语义化版本的先行版与构建
# 元数据字符集不含下划线，据此保证点与下划线的互换是单射、可逆
_PLUGIN_VERSION_PATTERN = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+-]*$")


class PluginLayoutMigrationError(RuntimeError):
    """存量平铺布局迁移到版本目录未能完成。

    抛出本异常时插件源码可能已经部分搬进中转目录，插件在下一次迁移续做成功前
    不保证可加载；调用方必须据此放弃本次安装，而不是继续往版本目录写新内容。
    """


def plugin_version_dir_name(version: str) -> str:
    """把插件版本号映射为版本目录名。

    映射规则为前缀 ``v`` 加上版本号中的 ``.`` 全部换成 ``_``，例如 ``1.2.0``
    映射为 ``v1_2_0``。版本号含下划线时直接拒绝，不做静默转换，否则两个不同
    版本号会映射到同一个目录。

    :param version: 插件版本号
    :return: 版本目录名
    :raise ValueError: 版本号为空、含下划线，或含版本号字符集以外的字符
    """
    text = (version or "").strip()
    if not text:
        raise ValueError("插件版本号为空")
    if "_" in text:
        raise ValueError(f"插件版本号含下划线，无法映射为版本目录：{version}")
    if not _PLUGIN_VERSION_PATTERN.match(text) or ".." in text or text.endswith("."):
        raise ValueError(f"插件版本号不是语义化版本：{version}")
    return f"{PLUGIN_VERSION_DIR_PREFIX}{text.replace('.', '_')}"


def plugin_version_from_dir_name(dir_name: str) -> str | None:
    """把版本目录名反解为插件版本号。

    反解规则是去掉前导 ``v`` 后把 ``_`` 换回 ``.``。反解结果需能原样映射回原
    目录名，否则视为不是版本目录，据此排除 dist、wheels、__pycache__ 等目录。

    :param dir_name: 目录名
    :return: 版本号；不是版本目录时为 None
    """
    if not dir_name or not dir_name.startswith(PLUGIN_VERSION_DIR_PREFIX):
        return None
    core = dir_name[len(PLUGIN_VERSION_DIR_PREFIX):]
    if not core or "." in core:
        return None
    version = core.replace("_", ".")
    try:
        if plugin_version_dir_name(version) != dir_name:
            return None
    except ValueError:
        return None
    return version


def plugin_version_dirs(plugin_root: Path) -> dict[str, Path]:
    """列出插件源码目录下所有版本目录。

    :param plugin_root: 插件源码根目录（app/plugins/<插件ID>）
    :return: 版本号到版本目录的映射，目录不存在时为空字典
    """
    result: dict[str, Path] = {}
    try:
        entries = sorted(plugin_root.iterdir())
    except (FileNotFoundError, NotADirectoryError, OSError):
        return result
    for entry in entries:
        if not entry.is_dir():
            continue
        version = plugin_version_from_dir_name(entry.name)
        if version:
            result[version] = entry
    return result


def read_plugin_versions_manifest(plugin_root: Path) -> dict[str, Any]:
    """读取插件已装版本元信息。

    :param plugin_root: 插件源码根目录
    :return: 元信息字典，文件缺失、损坏或格式不是字典时为空字典
    """
    manifest_file = plugin_root / PLUGIN_VERSIONS_MANIFEST_NAME
    try:
        payload = json.loads(manifest_file.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as err:
        logger.warning(f"插件版本元信息不可读，按未登记处理：{manifest_file} - {err}")
        return {}
    return payload if isinstance(payload, dict) else {}


def write_plugin_versions_manifest(
    plugin_root: Path,
    versions: list[dict[str, Any]],
    current: str | None,
) -> None:
    """写入插件已装版本元信息。

    先写同目录临时文件再原子改名，而不是直接覆写正式文件：元信息是「本次该加载
    哪个版本」的唯一权威，直接覆写一旦写到一半被中断就只剩截断的 JSON，读取方
    只能按「清单不可读」退化，插件的当前版本事实就此丢失。改名在同一目录内完成，
    因此任何中断点上读到的要么是完整的旧清单，要么是完整的新清单。

    :param plugin_root: 插件源码根目录
    :param versions: 版本条目列表，每条含 version、directory、installed_at、source
    :param current: 当前生效版本号
    """
    payload = {
        "schema_version": PLUGIN_VERSIONS_MANIFEST_SCHEMA,
        "plugin_id": plugin_root.name,
        "current": current,
        "versions": versions,
    }
    plugin_root.mkdir(parents=True, exist_ok=True)
    staging = plugin_root / f"{_PLUGIN_MANIFEST_STAGING_PREFIX}{uuid.uuid4().hex}"
    try:
        staging.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(staging, plugin_root / PLUGIN_VERSIONS_MANIFEST_NAME)
    finally:
        staging.unlink(missing_ok=True)


def plugin_manifest_versions(plugin_root: Path) -> dict[str, str]:
    """读取元信息登记的版本号到目录名映射，并校验目录名可由版本号推出。

    目录名不是权威真值，权威在元信息的版本号。两者不一致时告警并以元信息为准。

    :param plugin_root: 插件源码根目录
    :return: 版本号到目录名的映射
    """
    result: dict[str, str] = {}
    for entry in read_plugin_versions_manifest(plugin_root).get("versions") or []:
        if not isinstance(entry, dict):
            continue
        version = entry.get("version")
        directory = entry.get("directory")
        if not isinstance(version, str) or not version:
            continue
        try:
            expected = plugin_version_dir_name(version)
        except ValueError as err:
            logger.warning(f"插件 {plugin_root.name} 元信息版本号非法，已忽略：{err}")
            continue
        if isinstance(directory, str) and directory and directory != expected:
            logger.warning(
                f"插件 {plugin_root.name} 版本 {version} 的目录名 {directory} "
                f"与元信息不一致，以元信息为准使用 {expected}"
            )
        result[version] = expected
    return result


def ensure_plugin_version_dir_available(plugin_root: Path, version: str) -> str:
    """校验版本号可安装并返回其版本目录名。

    除版本号字符集校验外，还对同插件已装版本做大小写不敏感比对，避免在大小写
    不敏感的文件系统上两个版本落到同一个目录。

    :param plugin_root: 插件源码根目录
    :param version: 待安装版本号
    :return: 版本目录名
    :raise ValueError: 版本号非法，或与已装版本大小写撞名
    """
    dir_name = plugin_version_dir_name(version)
    known: dict[str, str] = dict(plugin_manifest_versions(plugin_root))
    known.update(
        {installed: path.name for installed, path in plugin_version_dirs(plugin_root).items()}
    )
    for installed_version, installed_dir in known.items():
        if installed_version == version:
            continue
        if installed_dir.lower() == dir_name.lower():
            raise ValueError(
                f"插件版本 {version} 与已装版本 {installed_version} 的目录名仅大小写不同，拒绝安装"
            )
    return dir_name


def _discovered_version_entry(version: str, directory: Path) -> dict[str, Any]:
    """为磁盘上存在、元信息却没登记的版本目录补一条登记。

    安装时间取目录自身的修改时间：它是这份源码落盘时刻的唯一可得近似，凭空写
    当前时间会把一个旧版本伪造成刚装上。

    :param version: 版本号
    :param directory: 该版本的版本目录
    :return: 版本条目
    """
    try:
        installed_at = datetime.fromtimestamp(
            directory.stat().st_mtime, tz=timezone.utc
        ).isoformat()
    except OSError:
        installed_at = None
    return {
        "version": version,
        "directory": directory.name,
        "installed_at": installed_at,
        "source": "discovered",
    }


def register_plugin_version(
    plugin_root: Path, version: str, source: str
) -> tuple[str, str | None]:
    """把一个已就位的版本目录登记进版本元信息，并置为当前版本。

    调用方需确保 ``plugin_root / <版本目录>`` 已经就位了该版本的源码；本函数只
    更新元信息、不做任何文件搬迁，因此存量布局迁移与真正的多版本安装可以共用。

    登记时顺带把磁盘上已存在、元信息却没登记的版本目录一并收编：元信息写入既不是
    迁移的最后一步也不是安装的最后一步，中途中断会留下「目录已落盘、清单没登记」
    的失步，收编让清单向磁盘收敛，而不是让一个确实装着的版本永远查不到来源。反向
    的失步（清单登记了磁盘上没有的版本）不在这里处理，那是加载解析的回落职责。

    同时返回登记前的当前版本号，供安装失败清理据此精确复原当前版本，不必靠猜。

    :param plugin_root: 插件源码根目录
    :param version: 已落盘的版本号
    :param source: 版本来源标签，如 market、local、migrated
    :return: 版本目录名，以及登记前元信息里的当前版本号（登记前没有任何已装
        版本时为 None）
    :raise ValueError: 版本号非法
    """
    dir_name = plugin_version_dir_name(version)
    manifest = read_plugin_versions_manifest(plugin_root)
    raw_current = manifest.get("current")
    previous_current = raw_current if isinstance(raw_current, str) and raw_current else None
    entries = [
        entry
        for entry in (manifest.get("versions") or [])
        if isinstance(entry, dict) and entry.get("version") != version
    ]
    listed = {entry.get("version") for entry in entries}
    for discovered, directory in sorted(plugin_version_dirs(plugin_root).items()):
        if discovered == version or discovered in listed:
            continue
        entries.append(_discovered_version_entry(discovered, directory))
    entries.append(
        {
            "version": version,
            "directory": dir_name,
            "installed_at": datetime.now(timezone.utc).isoformat(),
            "source": source,
        }
    )
    write_plugin_versions_manifest(plugin_root, entries, version)
    return dir_name, previous_current


def _is_reserved_layout_entry(entry: Path) -> bool:
    """判断插件目录下的条目是否属于版本化布局自身，不参与存量迁移。

    :param entry: 插件源码根目录下的直接子条目
    :return: 是版本目录、版本元信息或迁移中转材料时为 True
    """
    name = entry.name
    if name == PLUGIN_VERSIONS_MANIFEST_NAME:
        return True
    if name.startswith(_PLUGIN_MANIFEST_STAGING_PREFIX):
        return True
    if not entry.is_dir():
        return False
    return name.startswith(PLUGIN_LAYOUT_STAGING_PREFIX) or bool(
        plugin_version_from_dir_name(name)
    )


def _find_leftover_layout_staging(plugin_root: Path) -> Path | None:
    """查找上次迁移中断遗留的改名中转目录。

    :param plugin_root: 插件源码根目录
    :return: 遗留的中转目录；没有时为 None
    """
    try:
        candidates = sorted(
            entry
            for entry in plugin_root.iterdir()
            if entry.is_dir() and entry.name.startswith(PLUGIN_LAYOUT_STAGING_PREFIX)
        )
    except OSError:
        return None
    return candidates[0] if candidates else None


def _pending_layout_entries(plugin_root: Path) -> list[Path]:
    """列出仍需搬进版本目录的存量条目，并把主模块排到最前。

    「这里还有没有一个平铺插件」的判据是主模块本身。把主模块留到最后搬会让中断
    后的插件根目录看上去仍是一个可导入的平铺插件，实则源码已经残缺；把它排到
    最前，则任何中断点上的插件根目录要么是完整的平铺布局，要么干脆不像插件、被
    加载侧整个跳过，不会出现半份可导入的源码。

    :param plugin_root: 插件源码根目录
    :return: 待搬迁条目，主模块在最前
    """
    entries = [
        entry for entry in sorted(plugin_root.iterdir())
        if not _is_reserved_layout_entry(entry)
    ]
    return sorted(entries, key=lambda item: item.name != "__init__.py")


def migrate_legacy_plugin_layout(plugin_root: Path) -> Path | None:
    """把平铺布局的存量插件源码原地迁移为按版本分目录的布局。

    先把平铺源码逐条改名搬进插件目录内的中转目录，再一次改名把中转目录落成版本
    目录，最后登记版本元信息。两次改名都在插件目录内部完成，同一目录下的改名不
    可能跨文件系统，因此 overlayfs 把插件目录留在镜像层、或插件根目录本身是
    bind-mount 时，需要 copy-up 的只有被搬动的条目，不会整体退化为复制。

    中断语义：中转目录本身就是续做哨兵。搬到一半被中断时，插件根目录已没有主
    模块、加载侧按「不是插件」跳过，不会导入半份源码；下次迁移会发现遗留的中转
    目录并把剩余条目续做完。中转目录已改名成版本目录、元信息尚未写入时中转目录
    已消失，版本目录就是完整源码，加载解析按「清单缺失回落到磁盘上版本号最高者」
    仍能取到它，元信息的缺口由下一次版本登记收编。

    :param plugin_root: 插件源码根目录
    :return: 迁移后的版本目录；插件目录下没有任何待迁移源码时为 None
    :raise PluginLayoutMigrationError: 迁移未能完成，插件源码可能仍分散在中转目录
    """
    staging = _find_leftover_layout_staging(plugin_root)
    flat_init = plugin_root / "__init__.py"
    has_flat_source = flat_init.is_file()
    # 版本号要从实际持有主模块的一侧读：中断续做时主模块可能已经搬进中转目录，
    # 仍按插件根目录读会读空，把一个声明了版本号的插件迁成兜底版本目录
    if has_flat_source:
        init_file = flat_init
    elif staging is not None:
        init_file = staging / "__init__.py"
    else:
        return None
    version = read_declared_plugin_version(init_file)
    if not version:
        version = PLUGIN_FALLBACK_VERSION
        logger.warning(
            f"插件 {plugin_root.name} 未声明版本号，存量源码按兜底版本 "
            f"{PLUGIN_FALLBACK_VERSION} 迁移"
        )
    try:
        dir_name = plugin_version_dir_name(version)
    except ValueError as err:
        raise PluginLayoutMigrationError(
            f"插件 {plugin_root.name} 的版本号无法映射为版本目录：{err}"
        ) from err

    target = plugin_root / dir_name
    if target.exists():
        raise PluginLayoutMigrationError(
            f"插件 {plugin_root.name} 的版本目录 {dir_name} 已存在，拒绝与存量源码合并"
        )
    if staging is None:
        staging = plugin_root / f"{PLUGIN_LAYOUT_STAGING_PREFIX}{uuid.uuid4().hex}"
    try:
        staging.mkdir(parents=True, exist_ok=True)
        for entry in _pending_layout_entries(plugin_root):
            os.rename(entry, staging / entry.name)
        os.rename(staging, target)
    except OSError as error:
        raise PluginLayoutMigrationError(
            f"插件 {plugin_root.name} 存量源码迁移到版本目录失败：{error}"
        ) from error

    try:
        register_plugin_version(plugin_root, version, source="migrated")
    except OSError as error:
        # 版本目录已经落位，源码不会丢；元信息缺口由下一次版本登记收编
        logger.warning(f"插件版本元信息写入失败，下次登记将收编：{plugin_root} - {error}")
    return target


def _delete_plugin_version_dir(plugin_root: Path, version: str, directory: Path) -> bool:
    """删除单个插件版本目录，删除前三重校验，任一不通过即拒绝且不删除。

    校验顺序：目录 ``resolve()`` 后确认位于插件目录之内；确认不等于插件目录本身；
    确认目录名能反解回待删除的版本号本身，据此排除 dist、wheels、__pycache__ 等
    保留条目，也排除元信息与磁盘目录名不一致的条目。删除失败（占用、权限等）只
    记错误日志、不向上抛出，不牵连插件的其它版本。

    :param plugin_root: 插件源码根目录
    :param version: 待删除的版本号
    :param directory: 待删除的版本目录
    :return: 是否已删除
    """
    resolved_root = plugin_root.resolve()
    resolved_dir = directory.resolve()
    if not (
        resolved_dir.is_relative_to(resolved_root)
        and resolved_dir != resolved_root
        and plugin_version_from_dir_name(resolved_dir.name) == version
    ):
        logger.error(f"插件版本目录校验未通过，跳过删除：{resolved_dir}")
        return False
    try:
        shutil.rmtree(resolved_dir)
        return True
    except OSError as error:
        logger.error(f"插件版本目录删除失败：{resolved_dir} - {error}")
        return False


def _write_manifest_without_version(
    plugin_root: Path, version: str, previous_current: str | None
) -> None:
    """从版本元信息中摘除一个版本，并把当前版本精确复原为登记它之前的值。

    :param plugin_root: 插件源码根目录
    :param version: 待摘除的版本号
    :param previous_current: 登记该版本之前元信息里的当前版本号
    """
    manifest = read_plugin_versions_manifest(plugin_root)
    remaining = [
        entry
        for entry in (manifest.get("versions") or [])
        if isinstance(entry, dict) and entry.get("version") != version
    ]
    current = manifest.get("current")
    if not isinstance(current, str) or not current or current == version:
        remaining_numbers = {entry.get("version") for entry in remaining}
        current = previous_current if previous_current in remaining_numbers else None
    write_plugin_versions_manifest(plugin_root, remaining, current)


def remove_plugin_installed_version(
    plugin_root: Path,
    version: str,
    previous_current: str | None,
) -> None:
    """回滚一次失败的版本化安装：把该版本从元信息摘除并删除其版本目录。

    只清理调用方指定的这一个版本，不牵连插件目录下的其它已装版本——多版本并存
    下失败清理的范围必须收敛到本次安装尝试本身，否则会连带删掉正被其它实例使用
    的版本。当前版本不按「剩余版本里版本号最高者」去猜，而是精确复原为
    ``previous_current``，即登记本次失败版本之前元信息里的当前版本；它为 None 或
    已不在剩余版本里时同样置空，不去猜一个可能已与磁盘脱节的版本号。

    先改元信息、后删目录：反过来一旦在两步之间被中断，元信息会把一个已经删掉的
    版本声称为当前版本，加载只能靠磁盘回落去猜；先落元信息则任何中断点上元信息
    描述的都是本次安装之前那份真实存在的版本，最坏也只是磁盘上多一个没人引用的
    版本目录。仅当本次是插件唯一的版本、删完就是空壳时才反过来先删——那种情况下
    留一份只记录着空版本列表的元信息毫无意义，整根删掉才是干净的失败清理。

    :param plugin_root: 插件源码根目录
    :param version: 安装失败需要回滚的版本号
    :param previous_current: 登记本次失败版本之前元信息里的当前版本号，由
        ``register_plugin_version`` 返回并逐层穿透而来
    """
    directory = plugin_version_dirs(plugin_root).get(version)
    survivors = {
        installed for installed in plugin_version_dirs(plugin_root) if installed != version
    }
    if survivors or (plugin_root / "__init__.py").is_file():
        _write_manifest_without_version(plugin_root, version, previous_current)
        if directory is not None:
            _delete_plugin_version_dir(plugin_root, version, directory)
        return

    if directory is None or _delete_plugin_version_dir(plugin_root, version, directory):
        shutil.rmtree(plugin_root, ignore_errors=True)
        return
    # 版本目录删不掉，插件目录还留着半份失败载荷；至少让元信息不再声称它是当前版本
    _write_manifest_without_version(plugin_root, version, previous_current)


def read_declared_plugin_version(init_file: Path) -> str | None:
    """静态解析插件主模块声明的版本号，不导入插件代码。

    存量插件的版本号只写在类体的 ``plugin_version`` 属性上，而判断源码属于哪个
    版本必须早于导入——导入会执行插件代码，对一个还没确定能否加载的版本来说是
    不可接受的副作用，因此这里走 AST 而不是反射。

    :param init_file: 插件主模块 __init__.py 路径
    :return: 版本号；解析不到时为 None
    """
    try:
        tree = ast.parse(init_file.read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError, ValueError):
        return None
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        for statement in node.body:
            targets: list[ast.expr]
            if isinstance(statement, ast.Assign):
                targets = statement.targets
            elif isinstance(statement, ast.AnnAssign):
                targets = [statement.target]
            else:
                continue
            if not any(
                isinstance(target, ast.Name) and target.id == "plugin_version"
                for target in targets
            ):
                continue
            value = statement.value
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                return value.value.strip() or None
    return None


def resolve_plugin_version_dir(plugin_root: Path, version: str | None = None) -> Path:
    """定位插件本次要加载的源码目录。

    指定版本时返回该版本的版本目录；未指定时返回版本元信息登记的当前版本目录，
    元信息缺失或指向磁盘上不存在的目录时回落到版本号最高的已装版本。插件根目录
    下没有任何版本目录时，视为存量平铺布局，回落到插件根目录本身，使今天没有
    安装任何版本目录的插件加载路径与本函数引入前逐字一致。

    :param plugin_root: 插件源码根目录
    :param version: 指定加载的版本号，为空时取元信息里的当前版本
    :return: 源码目录；没有版本目录时为插件根目录本身
    :raise ValueError: 指定的版本号没有对应的已装版本目录
    """
    on_disk = plugin_version_dirs(plugin_root)
    if not on_disk:
        return plugin_root

    if version:
        target = on_disk.get(version)
        if target is None:
            raise ValueError(f"插件 {plugin_root.name} 未安装版本 {version}")
        return target

    manifest = read_plugin_versions_manifest(plugin_root)
    current = manifest.get("current")
    if isinstance(current, str) and current:
        if current in on_disk:
            return on_disk[current]
        logger.warning(
            f"插件 {plugin_root.name} 元信息登记的当前版本 {current} 在磁盘上不存在，"
            f"回落到版本号最高的已装版本"
        )

    newest = next(iter(sorted(on_disk)))
    for candidate in on_disk:
        if compare_version(candidate, ">", newest):
            newest = candidate
    return on_disk[newest]


def resolve_instance_version_dir(
    plugin_root: Path,
    instance: PluginInstance | None,
) -> Path:
    """按实例的版本绑定解析它应当读取的源码目录。

    未传入实例、或实例跟随当前版本时按插件当前版本解析；钉住某个版本时按该版本解析。
    钉住的版本目录已不在磁盘上时回落到当前版本，与加载器对同一失效场景的处置口径
    一致：绑定是一条可以被版本回收或手工删目录改写的旁路事实，它失效不该让实例的
    静态资源整个取不到，更不该让资源停在一个版本而代码已经落在另一个版本。

    :param plugin_root: 源插件源码根目录
    :param instance: 实例描述；为空表示直接按插件当前版本解析
    :return: 源码目录；没有任何版本目录的存量平铺布局时为插件根目录本身
    """
    desired_version = None if instance is None else instance.pinned_version
    try:
        return resolve_plugin_version_dir(plugin_root, desired_version)
    except ValueError:
        return resolve_plugin_version_dir(plugin_root)
