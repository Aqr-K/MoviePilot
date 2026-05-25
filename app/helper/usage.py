import platform
from pathlib import Path
from typing import Any, Dict

from app.core.config import settings
from app.log import logger
from app.utils.http import AsyncRequestUtils, RequestUtils
from app.utils.singleton import WeakSingleton
from app.utils.system import SystemUtils
from version import APP_VERSION, FRONTEND_VERSION


class UsageHelper(metaclass=WeakSingleton):
    """
    安装版本统计上报
    """

    _usage_report = f"{settings.MP_SERVER_HOST}/usage/report"
    _usage_statistic = f"{settings.MP_SERVER_HOST}/usage/statistic"

    @staticmethod
    def get_frontend_version() -> str:
        """
        获取当前前端版本。
        """
        if SystemUtils.is_frozen() and SystemUtils.is_windows():
            version_file = settings.CONFIG_PATH.parent / "nginx" / "html" / "version.txt"
        else:
            version_file = Path(settings.FRONTEND_PATH) / "version.txt"
        if version_file.exists():
            try:
                with open(version_file, "r") as file:
                    version = str(file.read()).strip()
                return version or FRONTEND_VERSION
            except Exception as err:
                logger.debug(f"加载版本文件 {version_file} 出错：{str(err)}")
        return FRONTEND_VERSION

    @staticmethod
    def build_payload() -> Dict[str, Any]:
        """
        构建安装版本统计上报载荷。
        """
        return {
            "user_uid": SystemUtils.generate_user_unique_id(),
            "backend_version": APP_VERSION,
            "frontend_version": UsageHelper.get_frontend_version(),
            "version_flag": settings.VERSION_FLAG,
            "platform": f"{platform.system()} {platform.release()}".strip(),
            "arch": SystemUtils.cpu_arch(),
        }

    def report(self) -> bool:
        """
        上报当前安装实例的版本统计。
        """
        if not settings.USAGE_STATISTIC_SHARE:
            return False
        payload = self.build_payload()
        if not payload.get("user_uid"):
            return False
        try:
            res = RequestUtils(
                proxies=settings.PROXY,
                content_type="application/json",
                timeout=5,
            ).post(self._usage_report, json=payload)
            return bool(res is not None and res.status_code == 200)
        except Exception as err:
            logger.debug(f"上报安装版本统计失败：{str(err)}")
            return False

    async def async_report(self) -> bool:
        """
        异步上报当前安装实例的版本统计。
        """
        if not settings.USAGE_STATISTIC_SHARE:
            return False
        payload = self.build_payload()
        if not payload.get("user_uid"):
            return False
        try:
            res = await AsyncRequestUtils(
                proxies=settings.PROXY,
                content_type="application/json",
                timeout=5,
            ).post(self._usage_report, json=payload)
            return bool(res is not None and res.status_code == 200)
        except Exception as err:
            logger.debug(f"异步上报安装版本统计失败：{str(err)}")
            return False

    def get_statistic(self) -> Dict[str, Any]:
        """
        获取安装版本统计报表。
        """
        if not settings.USAGE_STATISTIC_SHARE:
            return {}
        try:
            res = RequestUtils(proxies=settings.PROXY, timeout=10).get_res(self._usage_statistic)
            if res is not None and res.status_code == 200:
                return res.json()
        except Exception as err:
            logger.debug(f"获取安装版本统计报表失败：{str(err)}")
        return {}

    async def async_get_statistic(self) -> Dict[str, Any]:
        """
        异步获取安装版本统计报表。
        """
        if not settings.USAGE_STATISTIC_SHARE:
            return {}
        try:
            res = await AsyncRequestUtils(proxies=settings.PROXY, timeout=10).get_res(self._usage_statistic)
            if res is not None and res.status_code == 200:
                return res.json()
        except Exception as err:
            logger.debug(f"异步获取安装版本统计报表失败：{str(err)}")
        return {}
