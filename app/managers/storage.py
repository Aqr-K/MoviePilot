from typing import Any, Optional

from app.managers.base import PluginDispatchManager


class StorageManager(PluginDispatchManager):
    """
    存储（Storage 域）统一入口（单例）。

    对外提供一组存储操作方法，按方法名分两步分发：先经各已启用插件注册的同名方法，再到系统存储后端
    （FileManagerModule，内部按存储类型 schema 路由到本地/115/U115/阿里云盘/Rclone 等具体存储后端，
    后端契约见 app.modules.filemanager.storages.StorageBase）。插件可经同名方法接入自定义存储。

    分发内核（两步 dispatch / 插件钩子面 + 系统后端面 / 合并 / 错误处理）见基类 PluginDispatchManager。

    分发结果取首个非空 / 列表合并 / 非空标量短路。存储方法按 storage 名称或 fileitem 所属存储路由到对应
    后端，故各方法天然作用于单个存储。

    对外方法的参数原样转发到后端（各方法的参数见下方说明）。
    """

    # ------------------------------------------------------------------ #
    # 存储对外面：按方法名转发到 dispatch。
    # ------------------------------------------------------------------ #

    def save_config(self, *args, **kwargs) -> Any:
        """
        保存指定存储的配置。

        :param storage: 存储类型标识（schema）
        :param conf: 配置内容
        """
        return self.dispatch("save_config", *args, **kwargs)

    def reset_config(self, *args, **kwargs) -> Any:
        """
        重置指定存储的配置。

        :param storage: 存储类型标识（schema）
        """
        return self.dispatch("reset_config", *args, **kwargs)

    def generate_qrcode(self, *args, **kwargs) -> Optional[dict]:
        """
        生成存储登录二维码（仅支持扫码登录的存储）。

        :param storage: 存储类型标识（schema）
        :return: (二维码数据, 提示信息)
        """
        return self.dispatch("generate_qrcode", *args, **kwargs)

    def generate_auth_url(self, *args, **kwargs) -> Optional[str]:
        """
        生成 OAuth2 授权链接（仅支持 OAuth2 的存储）。

        :param storage: 存储类型标识（schema）
        :return: (授权参数, 授权链接)
        """
        return self.dispatch("generate_auth_url", *args, **kwargs)

    def check_login(self, *args, **kwargs) -> Optional[dict]:
        """
        查询存储登录状态（如扫码/授权是否完成）。

        :param storage: 存储类型标识（schema）
        :return: 登录状态信息
        """
        return self.dispatch("check_login", *args, **kwargs)

    def list_files(self, *args, **kwargs) -> Any:
        """
        浏览目录下的文件与子目录。

        :param fileitem: 目录项
        :param recursion: 是否递归列出子目录
        :return: 文件/目录项列表
        """
        return self.dispatch("list_files", *args, **kwargs)

    def any_files(self, *args, **kwargs) -> Optional[bool]:
        """
        判断目录下是否存在指定扩展名的文件。

        :param fileitem: 目录项
        :param extensions: 扩展名列表，None 表示任意文件
        :return: 是否存在
        """
        return self.dispatch("any_files", *args, **kwargs)

    def create_folder(self, *args, **kwargs) -> Any:
        """
        在指定父目录下创建子目录。

        :param fileitem: 父目录项
        :param name: 新目录名
        :return: 新建的目录项
        """
        return self.dispatch("create_folder", *args, **kwargs)

    def get_folder(self, *args, **kwargs) -> Any:
        """
        获取目录项，不存在则创建。

        :param storage: 存储类型标识（schema）
        :param path: 目录路径
        :return: 目录项
        """
        return self.dispatch("get_folder", *args, **kwargs)

    def download_file(self, *args, **kwargs) -> Any:
        """
        下载文件到本地。

        :param fileitem: 文件项
        :param path: 本地保存路径，None 表示临时目录
        :return: 本地文件路径
        """
        return self.dispatch("download_file", *args, **kwargs)

    def upload_file(self, *args, **kwargs) -> Any:
        """
        上传本地文件到指定目录。

        :param fileitem: 上传目标目录项
        :param path: 本地文件路径
        :param new_name: 上传后的文件名，None 表示沿用原名
        :return: 上传后的文件项
        """
        return self.dispatch("upload_file", *args, **kwargs)

    def delete_file(self, *args, **kwargs) -> Optional[bool]:
        """
        删除文件或目录。

        :param fileitem: 文件/目录项
        :return: 是否删除成功
        """
        return self.dispatch("delete_file", *args, **kwargs)

    def rename_file(self, *args, **kwargs) -> Optional[bool]:
        """
        重命名文件或目录。

        :param fileitem: 文件/目录项
        :param name: 新名称
        :return: 是否重命名成功
        """
        return self.dispatch("rename_file", *args, **kwargs)

    def get_file_item(self, *args, **kwargs) -> Any:
        """
        按路径获取文件或目录项。

        :param storage: 存储类型标识（schema）
        :param path: 文件/目录路径
        :return: 文件/目录项
        """
        return self.dispatch("get_file_item", *args, **kwargs)

    def get_parent_item(self, *args, **kwargs) -> Any:
        """
        获取文件/目录的父目录项。

        :param fileitem: 文件/目录项
        :return: 父目录项
        """
        return self.dispatch("get_parent_item", *args, **kwargs)

    def snapshot_storage(self, *args, **kwargs) -> Any:
        """
        对存储目录做快照（输出各层级文件信息，用于变更比对）。

        :param storage: 存储类型标识（schema）
        :param path: 快照根路径
        :param last_snapshot_time: 上次快照时间，用于增量快照
        :param max_depth: 最大递归深度
        :return: 路径 -> 文件信息 的快照字典
        """
        return self.dispatch("snapshot_storage", *args, **kwargs)

    def storage_usage(self, *args, **kwargs) -> Any:
        """
        获取存储空间使用情况。

        :param storage: 存储类型标识（schema）
        :return: 存储使用信息
        """
        return self.dispatch("storage_usage", *args, **kwargs)

    def support_transtype(self, *args, **kwargs) -> Any:
        """
        获取存储支持的整理方式（移动/复制/硬链接等）。

        :param storage: 存储类型标识（schema）
        :return: 支持的整理方式
        """
        return self.dispatch("support_transtype", *args, **kwargs)
