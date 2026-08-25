"""应用数据端口的启动组合根。

api / application / agent / workflow 各层只声明持久化端口，具体 Oper 由本模块选定并登记。
装配只保存工厂或服务实例，不触发数据库访问；端口未登记时取用方一律抛出运行时错误，
因此本模块必须在数据库引擎就绪后、路由开始接收请求前执行。
"""

from __future__ import annotations

from contextlib import asynccontextmanager, contextmanager

from app.api.data import configure_api_data_ports
from app.application.agentdata import configure_agent_data_ports
from app.application.configuration import (
    SystemConfigService,
    TransferRetryConfig,
    configure_system_config,
    configure_transfer_retry_config,
    get_configured_system_config,
)
from app.application.history import configure_transfer_history_provider
from app.application.messaging.chat import (
    AgentChatService,
    configure_agent_chat_service,
)
from app.application.messaging.gateway import CommandChain
from app.application.orchestration.data import configure_chain_data_ports
from app.application.orchestration.durable_events import (
    restore_download_added,
    restore_transfer_result,
)
from app.application.outbox import (
    OutboxDispatcher,
    SqlAlchemyAsyncOutboxStager,
    SqlAlchemyOutboxRepository,
    configure_outbox_dispatcher,
)
from app.application.security.auth import (
    AuthService,
    configure_auth_identity_ports,
    configure_auth_service,
)
from app.application.security.user import configure_user_lookups
from app.application.security.userconfig import (
    UserConfigurationService,
    configure_user_configuration,
)
from app.application.site.query import SiteQueryService, configure_site_query_service
from app.application.subscription.complete import (
    CompleteSubscriptionCommand,
    configure_subscription_completion_scope,
)
from app.application.subscription.delete import (
    DeleteSubscribeCommand,
    SyncDeleteSubscribeCommand,
    configure_delete_subscribe_scope,
    configure_sync_delete_subscribe_scope,
)
from app.application.subscription.mutation import (
    SubscriptionMutationService,
    configure_subscription_mutation_scope,
)
from app.application.subscription.transactional import TransactionalSubscribeWriter
from app.application.subscription.write import configure_subscribe_writer
from app.application.transaction import TransactionalWriteRunner
from app.application.workflow_transactional import TransactionalWorkflowExecutionService
from app.adapters.external.server import MoviePilotServerHelper
from app.db.oper.agentchat import AgentChatOper
from app.db.oper.agenttask import AgentTaskOper
from app.db.oper.downloadfailure import DownloadFailureOper
from app.db.oper.downloadhistory import DownloadHistoryOper
from app.db.oper.mediaserver import MediaServerOper
from app.db.oper.message import MessageOper
from app.db.oper.passkey import PassKeyOper
from app.db.oper.plugindata import PluginDataOper
from app.db.oper.site import SiteOper
from app.db.oper.subscribe import SubscribeOper
from app.db.oper.subscribehistory import SubscribeHistoryOper
from app.db.oper.systemconfig import SystemConfigOper
from app.db.oper.transferhistory import TransferHistoryOper
from app.db.oper.transferpending import TransferPendingOper
from app.db.oper.user import UserOper
from app.db.oper.user_identity import UserIdentityOper
from app.db.oper.userconfig import UserConfigOper
from app.db.oper.workflow import WorkflowOper, configure_workflow_legacy_writer
from app.db.session import SessionFactory, async_session_scope, get_async_db, get_db
from app.db.uow import (
    SqlAlchemyAsyncUnitOfWork,
    SqlAlchemyUnitOfWork,
    configure_transaction_runners,
)
from app.runtime.config import settings
from app.runtime.events import EventManager
from app.runtime.observability import record_metric
from app.schemas.message import Message
from app.schemas.types import EventType


def configure_request_data_ports() -> None:
    """登记 API 请求级会话、仓储与事务端口，供 ``app.api.deps`` 按能力名取用。"""
    configure_api_data_ports(
        sync_session=get_db,
        async_session=get_async_db,
        repositories={
            "agent_chat": AgentChatOper,
            "download_history": DownloadHistoryOper,
            "media_server": MediaServerOper,
            "message": MessageOper,
            "passkey": PassKeyOper,
            "site": SiteOper,
            "subscribe": SubscribeOper,
            "subscribe_history": SubscribeHistoryOper,
            "transfer_history": TransferHistoryOper,
            "user": UserOper,
            "user_identity": UserIdentityOper,
            "workflow": WorkflowOper,
        },
        standalone={
            "passkey": PassKeyOper,
            "system_config": SystemConfigOper,
            "user": UserOper,
            "user_identity": UserIdentityOper,
        },
        unit_of_work={
            "async": SqlAlchemyAsyncUnitOfWork,
            "sync": SqlAlchemyUnitOfWork,
        },
        outbox={
            "subscribe": SqlAlchemyAsyncOutboxStager,
        },
    )


def configure_orchestration_data_ports() -> None:
    """登记编排、工作流、监控与 Agent 工具共用的持久化端口。"""
    configure_chain_data_ports(
        site=SiteOper,
        subscribe=SubscribeOper,
        workflow=WorkflowOper,
        download_history=DownloadHistoryOper,
        transfer_history=TransferHistoryOper,
        transfer_pending=TransferPendingOper,
        media_server=MediaServerOper,
        download_failure=DownloadFailureOper,
        user=UserOper,
    )
    configure_agent_data_ports(
        agent_chat=AgentChatOper,
        agent_task=AgentTaskOper,
        user=UserOper,
        site=SiteOper,
        subscribe=SubscribeOper,
        subscribe_history=SubscribeHistoryOper,
        transfer_history=TransferHistoryOper,
        download_history=DownloadHistoryOper,
        workflow=WorkflowOper,
        plugin_data=PluginDataOper,
    )
    configure_subscribe_writer(
        lambda: TransactionalSubscribeWriter(
            sync_session=SessionFactory,
            async_session=async_session_scope,
        )
    )
    configure_transfer_history_provider(TransferHistoryOper)
    configure_transactional_subscription_scopes()
    configure_workflow_legacy_writer(
        TransactionalWorkflowExecutionService(SessionFactory)
    )


async def _publish_subscribe_modified(payload: dict) -> None:
    """通过宿主事件总线发布已提交的订阅修改事件。"""
    await EventManager().async_send_event(EventType.SubscribeModified, payload)


async def _publish_subscribe_deleted(payload: dict) -> None:
    """通过宿主事件总线发布已提交的订阅删除事件。"""
    await EventManager().async_send_event(EventType.SubscribeDeleted, payload)


def _publish_subscribe_deleted_sync(payload: dict) -> None:
    """为同步消息入口发布事务已提交的订阅删除事件。"""
    EventManager().send_event(EventType.SubscribeDeleted, payload)


def _publish_subscribe_completed(payload: dict) -> None:
    """通过宿主事件总线发布已提交的订阅完成事件。"""
    EventManager().send_event(EventType.SubscribeComplete, payload)


@asynccontextmanager
async def _subscription_mutation_scope():
    """为 Agent 等非 HTTP 入口创建独占订阅修改会话、事务与 outbox。"""
    async with async_session_scope() as session:
        yield SubscriptionMutationService(
            repository=SubscribeOper(session),
            history_repository=SubscribeHistoryOper(session),
            unit_of_work=SqlAlchemyAsyncUnitOfWork(session),
            outbox=SqlAlchemyAsyncOutboxStager(session),
            publish_modified=_publish_subscribe_modified,
        )


@asynccontextmanager
async def _delete_subscribe_scope():
    """为 Agent 等非 HTTP 入口创建独占订阅删除会话、事务与 outbox。"""
    async with async_session_scope() as session:
        yield DeleteSubscribeCommand(
            repository=SubscribeOper(session),
            unit_of_work=SqlAlchemyAsyncUnitOfWork(session),
            publish_deleted=_publish_subscribe_deleted,
            report_deleted=MoviePilotServerHelper.async_sub_done_durable,
            outbox=SqlAlchemyAsyncOutboxStager(session),
        )


@contextmanager
def _sync_delete_subscribe_scope():
    """为同步消息入口创建独占 Session、UoW 与 durable outbox。"""
    session = SessionFactory()
    try:
        yield SyncDeleteSubscribeCommand(
            repository=SubscribeOper(session),
            unit_of_work=SqlAlchemyUnitOfWork(session),
            publish_deleted=_publish_subscribe_deleted_sync,
            report_deleted=MoviePilotServerHelper.sub_done_durable,
            outbox=SqlAlchemyOutboxRepository(session),
        )
    finally:
        session.close()


@contextmanager
def _subscription_completion_scope():
    """为同步完成链创建独占 Session、UoW 与 durable outbox。"""
    session = SessionFactory()
    try:
        yield CompleteSubscriptionCommand(
            repository=SubscribeOper(session),
            unit_of_work=SqlAlchemyUnitOfWork(session),
            outbox=SqlAlchemyOutboxRepository(session),
            publish=_publish_subscribe_completed,
        )
    finally:
        session.close()


def configure_transactional_subscription_scopes() -> None:
    """登记 Agent 等非 HTTP 入口复用的订阅修改与删除事务作用域。"""
    configure_subscription_mutation_scope(_subscription_mutation_scope)
    configure_delete_subscribe_scope(_delete_subscribe_scope)
    configure_sync_delete_subscribe_scope(_sync_delete_subscribe_scope)
    configure_subscription_completion_scope(_subscription_completion_scope)


def _dispatch_subscribe_deleted_report(message) -> None:
    """重放订阅删除统计；未确认时抛错以进入有限重试。"""
    if not MoviePilotServerHelper.sub_done_durable(
        message.payload.get("subscribe_info") or {}
    ):
        raise RuntimeError("订阅删除统计上报未确认")


def _dispatch_subscribe_complete_report(message) -> None:
    """重放订阅完成统计；未确认时抛错以进入有限重试。"""
    if not MoviePilotServerHelper.sub_done_durable(
        message.payload.get("subscribe_info") or {}
    ):
        raise RuntimeError("订阅完成统计上报未确认")


def _dispatch_subscribe_added_report(message) -> None:
    """重放订阅新增统计；未确认时抛错以进入有限重试。"""
    if not MoviePilotServerHelper.sub_reg_durable(
        message.payload.get("subscribe_info") or {}
    ):
        raise RuntimeError("订阅新增统计上报未确认")


def _dispatch_subscribe_added_notification(message) -> None:
    """恢复订阅新增通知；恢复使用提交前冻结的渲染消息快照。"""
    snapshot = message.payload.get("message") or {}
    if not isinstance(snapshot, dict):
        raise RuntimeError("订阅新增通知快照格式无效")
    CommandChain().post_message(Message.model_validate(snapshot))


def _dispatch_subscribe_complete_notification(message) -> None:
    """恢复订阅完成通知；消息快照无需重建领域对象。"""
    snapshot = message.payload.get("message") or {}
    if not isinstance(snapshot, dict):
        raise RuntimeError("订阅完成通知快照格式无效")
    CommandChain().post_message(Message.model_validate(snapshot))


def _build_outbox_dispatcher() -> OutboxDispatcher:
    """创建一次恢复批次独占的 Session、Repository 和事件 handler。"""
    session = SessionFactory()
    return OutboxDispatcher(
        repository=SqlAlchemyOutboxRepository(session),
        handlers={
            "subscribe.added": lambda message: EventManager().send_event(
                EventType.SubscribeAdded,
                message.payload,
            ),
            "subscribe.added.report": _dispatch_subscribe_added_report,
            "subscribe.added.notification": _dispatch_subscribe_added_notification,
            "subscribe.modified": lambda message: EventManager().send_event(
                EventType.SubscribeModified,
                message.payload,
            ),
            "subscribe.deleted": lambda message: EventManager().send_event(
                EventType.SubscribeDeleted,
                message.payload,
            ),
            "subscribe.deleted.report": _dispatch_subscribe_deleted_report,
            "subscribe.complete": lambda message: EventManager().send_event(
                EventType.SubscribeComplete,
                message.payload,
            ),
            "subscribe.complete.report": _dispatch_subscribe_complete_report,
            "subscribe.complete.notification": _dispatch_subscribe_complete_notification,
            "download.added": lambda message: EventManager().send_event(
                EventType.DownloadAdded,
                restore_download_added(message.payload),
            ),
            "transfer.completed": lambda message: EventManager().send_event(
                EventType.TransferComplete,
                restore_transfer_result(message.payload),
            ),
            "transfer.failed": lambda message: EventManager().send_event(
                EventType.TransferFailed,
                restore_transfer_result(message.payload),
            ),
        },
        close=session.close,
        failure_observer=lambda dead: record_metric(
            "scheduler.job.dead_letter" if dead else "scheduler.job.retry",
            owner="outbox",
        ),
    )


def configure_application_service_ports() -> None:
    """登记跨请求复用的单例应用服务，供无请求会话的调用方取用。"""
    users = UserOper()
    configure_system_config(SystemConfigService(repository=SystemConfigOper()))
    configure_outbox_dispatcher(_build_outbox_dispatcher)
    configure_transfer_retry_config(
        lambda: TransferRetryConfig(
            max_failed_retries=settings.TRANSFER_MAX_FAILED_RETRIES,
        )
    )
    configure_site_query_service(SiteQueryService(repository=SiteOper()))
    configure_agent_chat_service(AgentChatService(repository=AgentChatOper()))
    configure_user_configuration(
        UserConfigurationService(repository=UserConfigOper())
    )
    configure_user_lookups(
        by_id=users.get_by_id,
        by_name=users.get_by_name,
        by_channel=users.get_name,
    )
    configure_auth_service(
        AuthService(
            users=UserOper(),
            config=get_configured_system_config(),
            passkeys=PassKeyOper(),
        )
    )
    configure_auth_identity_ports(
        identities=UserIdentityOper(),
        provisioning=UserOper(),
    )


def configure_data_ports() -> None:
    """登记全部应用数据端口，使各层在启动完成后按端口而非按 Oper 取用持久化能力。"""
    # 兼容 Oper 的无 Session 写入口仍由组合根持有事务，避免模型恢复自动提交；
    # 必须先于其余端口装配，任何写入口在装配期间就可能被触发。
    transaction_runner = TransactionalWriteRunner(
        sync_session=SessionFactory,
        async_session=async_session_scope,
    )
    configure_transaction_runners(
        sync=transaction_runner.sync,
        async_=transaction_runner.async_,
    )
    configure_request_data_ports()
    configure_orchestration_data_ports()
    configure_application_service_ports()
