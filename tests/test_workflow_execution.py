import base64
import pickle
import threading
from types import SimpleNamespace

from app.chain import workflow as workflow_module
from app.schemas import ActionContext, ActionResult
from app.schemas.types import EventType
from app import workflow as workflow_package


def _build_workflow(current_action=None, context=None, actions=None, flows=None):
    """构造最小工作流对象。"""
    return SimpleNamespace(
        id=1,
        name="测试工作流",
        actions=actions or [
            {"id": "A", "type": "FakeAction", "name": "动作A", "data": {}},
            {"id": "B", "type": "FakeAction", "name": "动作B", "data": {}},
        ],
        flows=flows or [
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

    def __init__(self, calls, results=None):
        self.calls = calls
        self.results = results or {}

    def execute(self, workflow_id, action, context=None):
        self.calls.append(action.id)
        result = self.results.get(action.id)
        if callable(result):
            return result(action, context or ActionContext())
        if result:
            return result
        return ActionResult(success=True, message=f"{action.name}完成", context=context or ActionContext())

    def excute(self, workflow_id, action, context=None):
        """兼容历史执行方法。"""
        result = self.execute(workflow_id, action, context)
        return result.success, result.message, result.context


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


def test_workflow_executor_skips_false_condition_branch(monkeypatch):
    """条件边不满足时应跳过对应分支，并继续执行满足条件的分支。"""
    calls = []
    fake_manager = _FakeWorkflowManager(
        calls,
        results={
            "A": lambda action, context: ActionResult(
                success=True,
                message=f"{action.name}完成",
                context=context,
                outputs={"items": ["movie"]}
            )
        }
    )
    workflow = _build_workflow(
        actions=[
            {"id": "A", "type": "FakeAction", "name": "动作A", "data": {}},
            {"id": "B", "type": "FakeAction", "name": "动作B", "data": {}},
            {"id": "C", "type": "FakeAction", "name": "动作C", "data": {}},
        ],
        flows=[
            {"id": "flow-ab", "source": "A", "target": "B", "condition": "outputs.A.items.count == 0"},
            {"id": "flow-ac", "source": "A", "target": "C", "data": {"condition": "outputs.A.items.count > 0"}},
        ],
    )

    monkeypatch.setattr(workflow_module, "WorkFlowManager", lambda: fake_manager)
    monkeypatch.setattr(workflow_module.global_vars, "workflow_resume", lambda workflow_id: None)
    monkeypatch.setattr(workflow_module.global_vars, "is_workflow_stopped", lambda workflow_id: False)

    executor = workflow_module.WorkflowExecutor(workflow)
    executor.execute()

    assert calls == ["A", "C"]
    assert executor.success is True
    assert executor.context.progress == 100
    assert executor.context.node_outputs["A"]["items"] == ["movie"]


def test_workflow_executor_all_success_join_waits_parallel_branches(monkeypatch):
    """默认汇合策略应等待所有上游分支成功后再执行目标节点。"""
    calls = []
    joined_outputs = {}

    def run_join(action, context):
        """记录汇合节点读取到的上游输出。"""
        joined_outputs.update(context.node_outputs)
        return ActionResult(success=True, message=f"{action.name}完成", context=context)

    fake_manager = _FakeWorkflowManager(
        calls,
        results={
            "A": lambda action, context: ActionResult(
                success=True,
                message=f"{action.name}完成",
                context=context,
                outputs={"value": "A"}
            ),
            "B": lambda action, context: ActionResult(
                success=True,
                message=f"{action.name}完成",
                context=context,
                outputs={"value": "B"}
            ),
            "C": run_join,
        }
    )
    workflow = _build_workflow(
        actions=[
            {"id": "A", "type": "FakeAction", "name": "动作A", "data": {}},
            {"id": "B", "type": "FakeAction", "name": "动作B", "data": {}},
            {"id": "C", "type": "FakeAction", "name": "动作C", "data": {}},
        ],
        flows=[
            {"id": "flow-ac", "source": "A", "target": "C"},
            {"id": "flow-bc", "source": "B", "target": "C"},
        ],
    )

    monkeypatch.setattr(workflow_module, "WorkFlowManager", lambda: fake_manager)
    monkeypatch.setattr(workflow_module.global_vars, "workflow_resume", lambda workflow_id: None)
    monkeypatch.setattr(workflow_module.global_vars, "is_workflow_stopped", lambda workflow_id: False)

    executor = workflow_module.WorkflowExecutor(workflow)
    executor.execute()

    assert set(calls) == {"A", "B", "C"}
    assert calls[-1] == "C"
    assert joined_outputs["A"] == {"value": "A"}
    assert joined_outputs["B"] == {"value": "B"}


def test_workflow_executor_any_success_join_runs_after_available_branch(monkeypatch):
    """any_success 汇合策略应允许任一满足条件的上游分支触发目标节点。"""
    calls = []
    fake_manager = _FakeWorkflowManager(
        calls,
        results={
            "A": lambda action, context: ActionResult(
                success=True,
                message=f"{action.name}完成",
                context=context,
                outputs={"items": ["movie"]}
            )
        }
    )
    workflow = _build_workflow(
        actions=[
            {"id": "A", "type": "FakeAction", "name": "动作A", "data": {}},
            {"id": "B", "type": "FakeAction", "name": "动作B", "data": {}},
            {"id": "C", "type": "FakeAction", "name": "动作C", "data": {}},
            {"id": "D", "type": "FakeAction", "name": "动作D", "data": {"join_policy": "any_success"}},
        ],
        flows=[
            {"id": "flow-ab", "source": "A", "target": "B", "condition": "outputs.A.items.count == 0"},
            {"id": "flow-ac", "source": "A", "target": "C", "condition": "outputs.A.items.count > 0"},
            {"id": "flow-bd", "source": "B", "target": "D"},
            {"id": "flow-cd", "source": "C", "target": "D"},
        ],
    )

    monkeypatch.setattr(workflow_module, "WorkFlowManager", lambda: fake_manager)
    monkeypatch.setattr(workflow_module.global_vars, "workflow_resume", lambda workflow_id: None)
    monkeypatch.setattr(workflow_module.global_vars, "is_workflow_stopped", lambda workflow_id: False)

    executor = workflow_module.WorkflowExecutor(workflow)
    executor.execute()

    assert calls == ["A", "C", "D"]
    assert executor.context.progress == 100


def test_workflow_executor_all_done_join_can_continue_after_failure(monkeypatch):
    """continue 失败策略配合 all_done 汇合时应继续执行收尾节点。"""
    calls = []
    fake_manager = _FakeWorkflowManager(
        calls,
        results={
            "A": lambda action, context: ActionResult(success=False, message=f"{action.name}失败", context=context)
        }
    )
    workflow = _build_workflow(
        actions=[
            {"id": "A", "type": "FakeAction", "name": "动作A", "data": {"fail_policy": "continue"}},
            {"id": "B", "type": "FakeAction", "name": "动作B", "data": {}},
            {"id": "C", "type": "FakeAction", "name": "动作C", "data": {"join_policy": "all_done"}},
        ],
        flows=[
            {"id": "flow-ac", "source": "A", "target": "C"},
            {"id": "flow-bc", "source": "B", "target": "C"},
        ],
    )

    monkeypatch.setattr(workflow_module, "WorkFlowManager", lambda: fake_manager)
    monkeypatch.setattr(workflow_module.global_vars, "workflow_resume", lambda workflow_id: None)
    monkeypatch.setattr(workflow_module.global_vars, "is_workflow_stopped", lambda workflow_id: False)

    executor = workflow_module.WorkflowExecutor(workflow)
    executor.execute()

    assert set(calls) == {"A", "B", "C"}
    assert calls[-1] == "C"
    assert executor.has_failure is True
    assert executor.success is True


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
