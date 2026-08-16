"""插件分身：按新标识复制并改写插件文件。"""
from pathlib import Path
from typing import Callable, Tuple


from app.runtime.log import logger
from app.schemas.types import SystemConfigKey

LegacyDiagnosticsConfigurator = Callable[..., None]
LegacyImportScanner = Callable[..., None]
LegacyPluginImportPreparer = Callable[..., None]
PluginInstallReporter = Callable[..., None]

from app.runtime.extensions import plugin_shared as _shared


class _PluginCloneMixin:
    """插件分身：按新标识复制并改写插件文件。"""

    def clone_plugin(self, plugin_id: str, suffix: str, name: str, description: str,
                     version: str = None, icon: str = None) -> Tuple[bool, str]:
        """
        创建插件分身
        :param plugin_id: 原插件ID
        :param suffix: 分身后缀
        :param name: 分身名称
        :param description: 分身描述
        :param version: 自定义版本号
        :param icon: 自定义图标URL
        :return: (是否成功, 错误信息)
        """
        try:
            # 验证参数
            if not plugin_id or not suffix:
                return False, "插件ID和分身后缀不能为空"

            # 检查原插件是否存在
            if plugin_id not in self._plugins:
                return False, f"原插件 {plugin_id} 不存在"

            # 生成分身插件ID
            clone_id = f"{plugin_id}{suffix.lower()}"

            # 检查分身插件是否已存在
            if self.is_plugin_exists(clone_id):
                return False, f"分身插件 {clone_id} 已存在"

            # 获取原插件目录
            original_plugin_dir = Path(_shared.settings.ROOT_PATH) / "app" / "plugins" / plugin_id.lower()
            if not original_plugin_dir.exists():
                return False, f"原插件目录 {original_plugin_dir} 不存在"

            # 创建分身插件目录
            clone_plugin_dir = Path(_shared.settings.ROOT_PATH) / "app" / "plugins" / clone_id.lower()

            # 复制插件目录
            import shutil
            shutil.copytree(original_plugin_dir, clone_plugin_dir)
            logger.info(f"已复制插件目录：{original_plugin_dir} -> {clone_plugin_dir}")

            # 修改插件文件内容
            success, msg = self._modify_plugin_files(
                plugin_dir=clone_plugin_dir,
                original_id=plugin_id,
                suffix=suffix.lower(),
                name=name,
                description=description,
                version=version,
                icon=icon
            )

            if not success:
                # 如果修改失败，清理已创建的目录
                if clone_plugin_dir.exists():
                    shutil.rmtree(clone_plugin_dir)
                return False, msg

            # 将分身插件添加到已安装列表
            systemconfig = _shared.SystemConfigOper()
            installed_plugins = systemconfig.get(SystemConfigKey.UserInstalledPlugins) or []
            if clone_id not in installed_plugins:
                installed_plugins.append(clone_id)
                systemconfig.set(SystemConfigKey.UserInstalledPlugins, installed_plugins)

            # 为分身插件创建初始配置（从原插件复制配置）
            logger.info(f"正在为分身插件 {clone_id} 创建初始配置...")
            original_config = self.get_plugin_config(plugin_id)
            if original_config:
                # 复制原插件配置作为分身插件的初始配置
                clone_config = original_config.copy()
                # 可以在这里修改一些默认值，比如禁用分身插件
                # 默认禁用分身插件，让用户手动配置
                clone_config['enable'] = False
                clone_config['enabled'] = False
                self.save_plugin_config(clone_id, clone_config, force=True)
                logger.info(f"已为分身插件 {clone_id} 设置初始配置")
            else:
                logger.info(f"原插件 {plugin_id} 没有配置，分身插件 {clone_id} 将使用默认配置")

            # 注册分身插件的API和服务
            logger.info(f"正在注册分身插件 {clone_id} ...")
            self.reload_plugin(clone_id)
            # 确保分身插件正确初始化配置
            if clone_id in self._running_plugins:
                clone_instance = self._running_plugins[clone_id]
                clone_config = self.get_plugin_config(clone_id)
                if clone_config:
                    logger.info(f"正在为分身插件 {clone_id} 重新初始化配置...")
                    clone_instance.init_plugin(clone_config)
                    logger.info(f"分身插件 {clone_id} 配置重新初始化完成")

            logger.info(f"插件分身 {clone_id} 创建成功")
            return True, clone_id

        except Exception as e:
            logger.error(f"创建插件分身失败：{str(e)}")
            return False, f"创建插件分身失败：{str(e)}"

    def _modify_plugin_files(self, plugin_dir: Path, original_id: str, suffix: str,
                             name: str, description: str, version: str = None,
                             icon: str = None) -> Tuple[bool, str]:
        """
        修改插件文件中的类名和相关信息
        :param plugin_dir: 插件目录
        :param original_id: 原插件ID
        :param suffix: 分身后缀
        :param name: 分身名称
        :param description: 分身描述
        :param version: 自定义版本号
        :param icon: 自定义图标URL
        :return: (是否成功, 错误信息)
        """
        try:
            # 获取原插件类
            original_plugin_class = self._plugins.get(original_id)
            if not original_plugin_class:
                return False, f"无法获取原插件类 {original_id}"

            # 获取原类名
            original_class_name = original_plugin_class.__name__
            clone_class_name = f"{original_class_name}{suffix}"

            # 修改 __init__.py 文件
            init_file = plugin_dir / "__init__.py"
            if init_file.exists():
                success, msg = self._modify_python_file(
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
                success, msg = self._modify_federation_files(
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

    @staticmethod
    def _modify_python_file(file_path: Path, original_class_name: str,
                            clone_class_name: str, name: str, description: str,
                            version: str = None, icon: str = None) -> Tuple[bool, str]:
        """
        修改Python文件中的类名和插件信息
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()

            # 替换类名
            content = content.replace(f"class {original_class_name}", f"class {clone_class_name}")

            # 替换插件名称和描述
            import re

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

    def _modify_federation_files(self, dist_dir: Path, original_class_name: str,
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
            self._rename_federation_assets(dist_dir, original_class_name, clone_class_name)

            return True, "联邦插件文件修改完成"

        except Exception as e:
            logger.error(f"修改联邦插件文件失败：{str(e)}")
            return False, f"修改联邦插件文件失败：{str(e)}"

    @staticmethod
    def _rename_federation_assets(dist_dir: Path, original_class_name: str, clone_class_name: str):
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
