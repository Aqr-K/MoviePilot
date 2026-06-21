"""插件分身的纯文件/AST 改写工具。

无状态的文件改写逻辑——改写 __init__.py 的类名/插件元信息、改写联邦插件前端 JS/CSS、重命名联邦资源——
为纯文件 + 正则操作，均为模块级函数。由 PluginManager.clone_plugin 解析原类名后，把
original_class_name/clone_class_name 作为参数传入。
"""
import re
from pathlib import Path
from typing import Optional, Tuple

from app.log import logger


def modify_plugin_files(plugin_dir: Path, original_class_name: str, clone_class_name: str,
                        name: str, description: str, version: Optional[str] = None,
                        icon: Optional[str] = None) -> Tuple[bool, str]:
    """
    修改插件文件中的类名和相关信息
    :param plugin_dir: 插件目录
    :param original_class_name: 原插件类名（由 clone_plugin 从 _plugins 解析后传入）
    :param clone_class_name: 分身插件类名
    :param name: 分身名称
    :param description: 分身描述
    :param version: 自定义版本号
    :param icon: 自定义图标URL
    :return: (是否成功, 错误信息)
    """
    try:
        # 修改 __init__.py 文件
        init_file = plugin_dir / "__init__.py"
        if init_file.exists():
            success, msg = modify_python_file(
                file_path=init_file,
                original_class_name=original_class_name,
                clone_class_name=clone_class_name,
                name=name,
                description=description,
                version=version,
                icon=icon
            )
            if not success:
                return False, msg

        # 检查是否为联邦插件（存在dist目录）
        dist_dir = plugin_dir / "dist"
        if dist_dir.exists():
            success, msg = modify_federation_files(
                dist_dir=dist_dir,
                original_class_name=original_class_name,
                clone_class_name=clone_class_name
            )
            if not success:
                return False, msg

        return True, "文件修改成功"

    except Exception as e:
        logger.error(f"修改插件文件失败：{str(e)}")
        return False, f"修改插件文件失败：{str(e)}"


def modify_python_file(file_path: Path, original_class_name: str, clone_class_name: str,
                       name: str, description: str, version: Optional[str] = None,
                       icon: Optional[str] = None) -> Tuple[bool, str]:
    """
    修改Python文件中的类名和插件信息
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()

        # 替换类名
        content = content.replace(f"class {original_class_name}", f"class {clone_class_name}")

        # 替换插件名称和描述

        # 替换 plugin_name
        if name:
            content = re.sub(
                r'plugin_name\s*=\s*["\'][^"\']*["\']',
                f'plugin_name = "{name}"',
                content
            )

        # 替换 plugin_desc
        if description:
            content = re.sub(
                r'plugin_desc\s*=\s*["\'][^"\']*["\']',
                f'plugin_desc = "{description}"',
                content
            )

        # 替换 plugin_config_prefix（如果存在）
        content = re.sub(
            r'plugin_config_prefix\s*=\s*["\'][^"\']*["\']',
            f'plugin_config_prefix = "{clone_class_name.lower()}_"',
            content
        )

        # 替换 plugin_version（如果提供了自定义版本）
        if version:
            content = re.sub(
                r'plugin_version\s*=\s*["\'][^"\']*["\']',
                f'plugin_version = "{version}"',
                content
            )

        # 替换 plugin_icon（如果提供了自定义图标）
        if icon and icon.strip():
            old_content = content
            content = re.sub(
                r'plugin_icon\s*=\s*["\'][^"\']*["\']',
                f'plugin_icon = "{icon}"',
                content
            )
            if old_content != content:
                logger.info(f"已替换插件图标为: {icon}")
            else:
                logger.warning(f"插件图标替换失败，未找到匹配的图标设置")
        else:
            logger.info("未提供自定义图标，保持原插件图标")

        # 添加分身标志
        if "def init_plugin(self" in content:
            init_index = content.index("def init_plugin(self")
            # 在 def init_plugin(self 前添加 is_clone = True
            content = content[:init_index] + "is_clone = True\n\n    " + content[init_index:]

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)

        logger.debug(f"已修改Python文件：{file_path}")
        return True, "Python文件修改成功"

    except Exception as e:
        logger.error(f"修改Python文件失败：{str(e)}")
        return False, f"修改Python文件失败：{str(e)}"


def modify_federation_files(dist_dir: Path, original_class_name: str,
                            clone_class_name: str) -> Tuple[bool, str]:
    """
    修改联邦插件的前端文件
    """
    try:
        # 获取原始插件名（从类名推导）
        original_plugin_name = original_class_name
        clone_plugin_name = clone_class_name

        # 遍历dist目录下的所有文件
        for file_path in dist_dir.rglob("*"):
            if not file_path.is_file():
                continue

            # 处理JS文件
            if file_path.suffix == '.js':
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                        content = f.read()

                    # 替换类名引用（精确匹配）
                    content = content.replace(original_class_name, clone_class_name)
                    # 替换插件名引用（如果存在）
                    content = content.replace(f'"{original_plugin_name}"', f'"{clone_plugin_name}"')
                    content = content.replace(f"'{original_plugin_name}'", f"'{clone_plugin_name}'")
                    # 替换CSS key中的类名（联邦插件特有）
                    content = content.replace(f'css__{original_class_name}__', f'css__{clone_class_name}__')
                    # 替换可能的小写类名引用
                    content = content.replace(original_class_name.lower(), clone_class_name.lower())

                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(content)

                    logger.debug(f"已修改联邦插件JS文件：{file_path}")

                except Exception as e:
                    logger.warning(f"修改联邦插件文件 {file_path} 失败：{str(e)}")
                    continue

            # 处理CSS文件
            elif file_path.suffix == '.css':
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                        content = f.read()

                    # 替换CSS中可能的类名引用
                    content = content.replace(original_class_name.lower(),
                                              clone_class_name.lower()).replace(original_class_name,
                                                                                clone_class_name)

                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(content)

                    logger.debug(f"已修改联邦插件CSS文件：{file_path}")

                except Exception as e:
                    logger.warning(f"修改联邦插件CSS文件 {file_path} 失败：{str(e)}")
                    continue

        # 重命名构建文件（如果需要）
        rename_federation_assets(dist_dir, original_class_name, clone_class_name)

        return True, "联邦插件文件修改完成"

    except Exception as e:
        logger.error(f"修改联邦插件文件失败：{str(e)}")
        return False, f"修改联邦插件文件失败：{str(e)}"


def rename_federation_assets(dist_dir: Path, original_class_name: str, clone_class_name: str) -> None:
    """
    重命名联邦插件的资源文件，避免文件名冲突
    """
    try:
        # 查找包含原类名的文件并重命名
        for file_path in dist_dir.glob("*"):
            if not file_path.is_file():
                continue

            file_name = file_path.name
            # 如果文件名包含原类名，则重命名
            if original_class_name.lower() in file_name.lower():
                new_name = file_name.replace(
                    original_class_name.lower(),
                    clone_class_name.lower()
                )
                new_path = file_path.parent / new_name

                # 避免重命名冲突
                if not new_path.exists():
                    file_path.rename(new_path)
                    logger.debug(f"重命名联邦插件文件：{file_name} -> {new_name}")

    except Exception as e:
        # 重命名失败不影响整体流程
        logger.warning(f"重命名联邦插件资源文件失败：{str(e)}")
