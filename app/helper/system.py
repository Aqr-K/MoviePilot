import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional, Tuple

import docker
import psutil

from app.core.config import settings
from app.log import logger
from app.utils.mixins import ConfigReloadMixin
from app.utils.system import SystemUtils


class SystemHelper(ConfigReloadMixin):
    """
    系统工具类，提供系统相关的操作和判断
    """
    CONFIG_WATCH = {
        "DEBUG",
        "LOG_LEVEL",
        "LOG_MAX_FILE_SIZE",
        "LOG_BACKUP_COUNT",
        "LOG_FILE_FORMAT",
        "LOG_CONSOLE_FORMAT",
    }

    __system_flag_file = "/var/log/nginx/__moviepilot__"
    __local_backend_runtime_file = settings.TEMP_PATH / "moviepilot.runtime.json"
    __local_restart_log_file = settings.LOG_PATH / "moviepilot.restart.stdout.log"

    def on_config_changed(self):
        logger.update_loggers()

    def get_reload_name(self):
        return "日志设置"

    @staticmethod
    def can_restart() -> bool:
        """
        判断是否可以内部重启
        """
        return SystemUtils.is_docker() or SystemHelper._is_local_cli_managed()

    @staticmethod
    def _load_runtime_file(path: Path) -> Optional[dict]:
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return payload if isinstance(payload, dict) else None

    @staticmethod
    def _is_local_cli_managed() -> bool:
        runtime = SystemHelper._load_runtime_file(SystemHelper.__local_backend_runtime_file)
        if not runtime:
            return False

        pid = runtime.get("pid")
        create_time = runtime.get("create_time")
        if not pid:
            return False

        try:
            pid = int(pid)
        except (TypeError, ValueError):
            return False

        if pid != os.getpid():
            return False

        if create_time is None:
            return True

        try:
            current_process = psutil.Process(os.getpid())
            return abs(current_process.create_time() - float(create_time)) <= 2
        except (psutil.Error, TypeError, ValueError):
            return False

    @staticmethod
    def _spawn_local_restart_helper() -> None:
        helper_code = (
            "import os, subprocess, sys, time;"
            "time.sleep(1.0);"
            "cmd=[sys.executable, '-m', 'app.cli', 'restart', '--force', '--stop-timeout', '30', '--start-timeout', '60'];"
            "subprocess.run(cmd, cwd=os.environ.get('MOVIEPILOT_ROOT'), env=os.environ.copy(), check=False)"
        )
        env = os.environ.copy()
        env["MOVIEPILOT_ROOT"] = str(settings.ROOT_PATH)
        env["PYTHONUNBUFFERED"] = "1"

        SystemHelper.__local_restart_log_file.parent.mkdir(parents=True, exist_ok=True)
        with SystemHelper.__local_restart_log_file.open("a", encoding="utf-8") as log_handle:
            kwargs = {
                "cwd": str(settings.ROOT_PATH),
                "stdout": log_handle,
                "stderr": subprocess.STDOUT,
                "stdin": subprocess.DEVNULL,
                "close_fds": True,
                "env": env,
            }
            if os.name == "nt":
                kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
            else:
                kwargs["start_new_session"] = True
            process = subprocess.Popen([sys.executable, "-c", helper_code], **kwargs)
        logger.info(f"已创建本地 CLI 重启任务，辅助进程 PID: {process.pid}")

    @staticmethod
    def _get_container_id() -> str:
        """
        获取当前容器ID
        """
        container_id = None
        try:
            with open("/proc/self/mountinfo", "r") as f:
                data = f.read()
                index_resolv_conf = data.find("resolv.conf")
                if index_resolv_conf != -1:
                    index_second_slash = data.rfind("/", 0, index_resolv_conf)
                    index_first_slash = data.rfind("/", 0, index_second_slash) + 1
                    container_id = data[index_first_slash:index_second_slash]
                    if len(container_id) < 20:
                        index_resolv_conf = data.find("/sys/fs/cgroup/devices")
                        if index_resolv_conf != -1:
                            index_second_slash = data.rfind(" ", 0, index_resolv_conf)
                            index_first_slash = (
                                    data.rfind("/", 0, index_second_slash) + 1
                            )
                            container_id = data[index_first_slash:index_second_slash]
        except Exception as e:
            logger.debug(f"获取容器ID失败: {str(e)}")
        return container_id.strip() if container_id else None

    @staticmethod
    def _check_restart_policy() -> bool:
        """
        检查当前容器是否配置了自动重启策略
        """
        try:
            # 获取当前容器ID
            container_id = SystemHelper._get_container_id()
            if not container_id:
                return False

            # 创建 Docker 客户端
            client = docker.DockerClient(base_url=settings.DOCKER_CLIENT_API)
            # 获取容器信息
            container = client.containers.get(container_id)
            restart_policy = container.attrs.get('HostConfig', {}).get('RestartPolicy', {})
            policy_name = restart_policy.get('Name', 'no')
            # 检查是否有有效的重启策略
            auto_restart_policies = ['always', 'unless-stopped', 'on-failure']
            has_restart_policy = policy_name in auto_restart_policies

            logger.info(f"容器重启策略: {policy_name}, 支持自动重启: {has_restart_policy}")
            return has_restart_policy

        except Exception as e:
            logger.warning(f"检查重启策略失败: {str(e)}")
            return False

    @staticmethod
    def restart() -> Tuple[bool, str]:
        """
        执行Docker重启操作
        """
        if not SystemUtils.is_docker():
            if not SystemHelper._is_local_cli_managed():
                return False, "当前实例不是由 moviepilot CLI 启动，无法执行内建重启！"
            try:
                SystemHelper._spawn_local_restart_helper()
                return True, ""
            except Exception as err:
                logger.error(f"本地 CLI 重启失败: {str(err)}")
                return False, f"本地 CLI 重启失败：{str(err)}"

        try:
            # 检查容器是否配置了自动重启策略
            has_restart_policy = SystemHelper._check_restart_policy()
            if has_restart_policy:
                # 有重启策略，使用优雅退出方式
                logger.info("检测到容器配置了自动重启策略，使用优雅重启方式...")
                # 启动优雅退出超时监控
                SystemHelper._start_graceful_shutdown_monitor()
                # 发送SIGTERM信号给当前进程，触发优雅停止
                os.kill(os.getpid(), signal.SIGTERM)
                return True, ""
            else:
                # 没有重启策略，使用Docker API强制重启
                logger.info("容器未配置自动重启策略，使用Docker API重启...")
                return SystemHelper._docker_api_restart()
        except Exception as err:
            logger.error(f"重启失败: {str(err)}")
            # 降级为Docker API重启
            logger.warning("降级为Docker API重启...")
            return SystemHelper._docker_api_restart()

    @staticmethod
    def _start_graceful_shutdown_monitor():
        """
        启动优雅退出超时监控
        如果30秒内进程没有退出，则使用Docker API强制重启
        """

        def monitor_thread():
            time.sleep(30)  # 等待30秒
            logger.warning("优雅退出超时30秒，使用Docker API强制重启...")
            try:
                SystemHelper._docker_api_restart()
            except Exception as e:
                logger.error(f"强制重启失败: {str(e)}")

        # 在后台线程中启动监控
        thread = threading.Thread(target=monitor_thread, daemon=True)
        thread.start()

    @staticmethod
    def _docker_api_restart() -> Tuple[bool, str]:
        """
        使用Docker API重启容器，并尝试优雅停止
        """
        try:
            # 创建 Docker 客户端
            client = docker.DockerClient(base_url=settings.DOCKER_CLIENT_API)
            container_id = SystemHelper._get_container_id()
            if not container_id:
                return False, "获取容器ID失败！"
            # 重启容器
            client.containers.get(container_id).restart()
            return True, ""
        except Exception as docker_err:
            return False, f"重启时发生错误：{str(docker_err)}"

    def set_system_modified(self):
        """
        设置系统已修改标志
        """
        try:
            if SystemUtils.is_docker():
                Path(self.__system_flag_file).touch(exist_ok=True)
        except Exception as e:
            print(f"设置系统修改标志失败: {str(e)}")

    def is_system_reset(self) -> bool:
        """
        检查系统是否已被重置
        :return: 如果系统已重置，返回 True；否则返回 False
        """
        if SystemUtils.is_docker():
            return not Path(self.__system_flag_file).exists()
        return False
