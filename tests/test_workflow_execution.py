import base64
import pickle
import threading
from types import SimpleNamespace

from app.chain import workflow as workflow_module
from app.schemas import ActionContext
from app.schemas.types import EventType
from app import workflow as workflow_package


def _build_workflow(current_action=None, context=None):
    """构造最小工作流对象。"""
    return SimpleNamespace(
        id=1,
        name="测试工作流",
        actions=[
            {"id": "A", "type": "FakeAction", "name": "动作A", "data": {}},
            {"id": "B", "type": "FakeAction", "name": "动作B", "data": {}},
        ],
        flows=[
            {"id": "flow-1", "source": "A", "target": "B", "animated": True},
        ],
        current_action=current_action,
        context=context,
    )


def _encoded_context(context: ActionContext) -> dict:
    """编码工作流恢复上下文。"""
    return {
        "content": base64.b64encode(pickle.dumps(context)).decode("utf-8"),
    }


class _FakeWorkflowManager:
    """记录执行动作的工作流管理器。"""

    def __init__(self, calls):
        self.calls = calls

    def excute(self, workflow_id, action, context=None):
        self.calls.append(action.id)
        return True, f"{action.name}完成", context or ActionContext()


def test_workflow_executor_resumes_downstream_nodes(monkeypatch):
    """恢复执行时应释放已完成节点的后继节点。"""
    calls = []
    fake_manager = _FakeWorkflowManager(calls)
    workflow = _build_workflow(
        current_action="A",
        context=_encoded_context(ActionContext()),
    )

    monkeypatch.setattr(workflow_module, "WorkFlowManager", lambda: fake_manager)
    monkeypatch.setattr(workflow_module.global_vars, "workflow_resume", lambda workflow_id: None)
    monkeypatch.setattr(workflow_module.global_vars, "is_workflow_stopped", lambda workflow_id: False)

    executor = workflow_module.WorkflowExecutor(workflow)
    executor.execute()

    assert calls == ["B"]
    assert executor.success is True
    assert executor.context.progress == 100


def test_workflow_executor_reports_incremental_progress(monkeypatch):
    """顺序工作流的中间进度应按已完成比例计算。"""
    calls = []
    progresses = []
    fake_manager = _FakeWorkflowManager(calls)

    monkeypatch.setattr(workflow_module, "WorkFlowManager", lambda: fake_manager)
    monkeypatch.setattr(workflow_module.global_vars, "workflow_resume", lambda workflow_id: None)
    monkeypatch.setattr(workflow_module.global_vars, "is_workflow_stopped", lambda workflow_id: False)

    executor = workflow_module.WorkflowExecutor(
        _build_workflow(),
        step_callback=lambda action, context: progresses.append(context.progress),
    )
    executor.execute()

    assert calls == ["A", "B"]
    assert progresses == [50, 100]


def test_workflow_executor_stop_is_not_success(monkeypatch):
    """停止信号不应被执行器汇报为成功完成。"""
    calls = []
    fake_manager = _FakeWorkflowManager(calls)

    monkeypatch.setattr(workflow_module, "WorkFlowManager", lambda: fake_manager)
    monkeypatch.setattr(workflow_module.global_vars, "workflow_resume", lambda workflow_id: None)
    monkeypatch.setattr(workflow_module.global_vars, "is_workflow_stopped", lambda workflow_id: True)

    executor = workflow_module.WorkflowExecutor(_build_workflow())
    executor.execute()

    assert calls == []
    assert executor.stopped is True
    assert executor.success is False
    assert executor.errmsg == "工作流已停止"


def test_workflow_context_merge_preserves_runtime_objects():
    """合并上下文时应保留运行时对象，而不是转成字典。"""
    executor = object.__new__(workflow_module.WorkflowExecutor)
    executor.context = ActionContext()
    runtime_torrent = SimpleNamespace(title="runtime torrent")
    result_context = ActionContext()
    result_context.torrents.append(runtime_torrent)

    executor.merge_context(result_context)

    assert executor.context.torrents[0] is runtime_torrent


class _FakeEventManager:
    """记录事件监听器注册和移除次数。"""

    def __init__(self):
        self.added = []
        self.removed = []

    def add_event_listener(self, event_type, handler):
        self.added.append(event_type)

    def remove_event_listener(self, event_type, handler):
        self.removed.append(event_type)


def test_workflow_event_listener_keeps_shared_handler_until_last_workflow(monkeypatch):
    """同一事件下移除单个工作流时不应断开其他工作流监听。"""
    fake_eventmanager = _FakeEventManager()
    manager = object.__new__(workflow_package.WorkFlowManager)
    manager._lock = threading.Lock()
    manager._event_workflows = {}

    monkeypatch.setattr(workflow_package, "eventmanager", fake_eventmanager)

    manager.register_workflow_event(1, EventType.DownloadAdded.value)
    manager.register_workflow_event(2, EventType.DownloadAdded.value)
    manager.remove_workflow_event(1, EventType.DownloadAdded.value)

    assert fake_eventmanager.added == [EventType.DownloadAdded]
    assert fake_eventmanager.removed == []
    assert manager.get_event_workflows() == {EventType.DownloadAdded.value: [2]}

    manager.remove_workflow_event(2, EventType.DownloadAdded.value)

    assert fake_eventmanager.removed == [EventType.DownloadAdded]
    assert manager.get_event_workflows() == {}
