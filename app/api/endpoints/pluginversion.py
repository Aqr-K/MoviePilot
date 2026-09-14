"""插件已装版本查询与实例版本绑定切换接口。"""

from typing import Any

from fastapi import Depends

from app.api.dependencies.auth import get_current_active_superuser
from app.api.principal import ApiPrincipal
from app.api.response import ResponseAPIRouter
from app.application.plugin.runtime import get_plugin_manager
from app.schemas.plugin import PluginInstanceVersionUpdateRequest as _SchemaPluginInstanceVersionUpdateRequest
from app.schemas.plugin import PluginVersionOverview as _SchemaPluginVersionOverview
from app.schemas.response import Response as _SchemaResponse

router = ResponseAPIRouter()


@router.get(  # type: ignore[misc]
    "/versions/{plugin_id}",
    summary="查询插件已装版本与实例版本绑定",
    response_model=_SchemaResponse[_SchemaPluginVersionOverview],
)
def plugin_version_overview(
    plugin_id: str,
    _: ApiPrincipal = Depends(get_current_active_superuser),
) -> Any:
    """
    查询插件已装版本列表与各实例（含本体）的版本绑定

    权限与其它插件管理接口同档（仅超级管理员）：已装版本与各实例的绑定暴露的是这台
    实例装了什么、跑的是哪一版，属于部署事实而非普通用户可见的内容。
    """
    try:
        overview = get_plugin_manager().get_plugin_version_overview(plugin_id)
    except LookupError as error:
        return _SchemaResponse(success=False, message=str(error))
    return _SchemaResponse(success=True, data=overview)


@router.put(  # type: ignore[misc]
    "/versions/{plugin_id}/{instance_id}",
    summary="设置插件实例的版本绑定",
    response_model=_SchemaResponse[None],
)
def set_plugin_instance_version(
    plugin_id: str,
    instance_id: str,
    update: _SchemaPluginInstanceVersionUpdateRequest,
    _: ApiPrincipal = Depends(get_current_active_superuser),
) -> Any:
    """
    设置指定插件实例的版本绑定，并完成一次停止再启动

    路径上带 ``plugin_id`` 不只是为了好看：切换只认实例 ID，先用它核对目标实例确实
    归属这个插件，才不会让一次 URL 拼错把另一个插件的实例停掉重启。核对走版本总览
    这一个入口，判据因而与界面看到的列表逐字相同。

    切换是停旧起新的完整生命周期，可能耗时且可能失败；失败时已生效版本会被原样恢复，
    可读原因随响应返回。
    """
    plugin_manager = get_plugin_manager()
    try:
        overview = plugin_manager.get_plugin_version_overview(plugin_id)
    except LookupError as error:
        return _SchemaResponse(success=False, message=str(error))
    known_instance_ids = {item["instance_id"] for item in overview["instances"]}
    if instance_id not in known_instance_ids:
        return _SchemaResponse(success=False, message=f"插件实例 {instance_id} 不存在")
    success, message = plugin_manager.set_plugin_instance_version(
        instance_id,
        pinned_version=update.pinned_version,
    )
    return _SchemaResponse(
        success=success,
        message="版本切换成功" if success else message,
    )
