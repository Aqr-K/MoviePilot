import ast
import base64
import copy
import pickle
import threading
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from time import sleep
from typing import Any, Callable, List, Optional, Tuple

from app.chain import ChainBase
from app.core.config import global_vars
from app.core.event import Event, eventmanager
from app.db.models import Workflow
from app.db.workflow_oper import WorkflowOper
from app.log import logger
from app.schemas import ActionContext, ActionFlow, Action, ActionExecution, ActionResult
from app.schemas.types import EventType
from app.workflow import WorkFlowManager


class WorkflowExecutor:
    """
    工作流执行器
    """

    def __init__(self, workflow: Workflow, step_callback: Callable = None):
        """
        初始化工作流执行器
        :param workflow: 工作流对象
        :param step_callback: 步骤回调函数
        """
        # 工作流数据
        self.workflow = workflow
        self.step_callback = step_callback
        self.actions = {action['id']: Action(**action) for action in workflow.actions}
        self.flows = [ActionFlow(**flow) for flow in workflow.flows]
        self.total_actions = len(self.actions)
        self.completed_actions = {
            action_id for action_id in (workflow.current_action or "").split(",")
            if action_id in self.actions
        }
        self.finished_actions = len(self.completed_actions)

        self.success = True
        self.has_failure = False
        self.stopped = False
        self.errmsg = ""
        self.node_states = {action_id: "pending" for action_id in self.actions}
        for action_id in self.completed_actions:
            self.node_states[action_id] = "completed"
        self.flow_finished = set()
        self.flow_satisfied = set()

        # 工作流管理器
        self.workflowmanager = WorkFlowManager()
        # 线程安全队列
        self.queue = deque()
        self.queued_actions = set()
        # 锁用于保证线程安全
        self.lock = threading.Lock()
        # 线程池
        self.executor = ThreadPoolExecutor()
        # 跟踪运行中的任务数
        self.running_tasks = 0

        # 构建出边与入边表，用于条件流转和多上游汇合。
        self.outgoing_flows = defaultdict(list)
        self.incoming_flows = defaultdict(list)
        for flow in self.flows:
            if not flow.source or not flow.target:
                continue
            self.outgoing_flows[flow.source].append(flow)
            self.incoming_flows[flow.target].append(flow)

        # 初始上下文
        if workflow.current_action and workflow.context:
            logger.info(f"工作流已执行动作：{workflow.current_action}")
            # Base64解码
            decoded_data = base64.b64decode(workflow.context["content"])
            # 反序列化数据
            self.context = pickle.loads(decoded_data)
        else:
            self.context = ActionContext()
        self.context.node_outputs = self.context.node_outputs or {}

        # 恢复工作流
        global_vars.workflow_resume(self.workflow.id)
        # 恢复时重新释放已完成节点的出边，使后继节点能继续执行。
        for action_id in self.completed_actions:
            self.release_successors(action_id, source_success=True)
        # 初始化队列，添加没有入边的起始节点。
        for action_id in self.actions:
            if action_id not in self.completed_actions and not self.incoming_flows.get(action_id):
                self.enqueue_node(action_id)

    def execute(self) -> None:
        """
        执行工作流
        """
        try:
            while True:
                should_sleep = False
                node_id = None
                with self.lock:
                    if global_vars.is_workflow_stopped(self.workflow.id):
                        self.success = False
                        self.stopped = True
                        self.errmsg = "工作流已停止"
                        if self.running_tasks == 0:
                            break
                        should_sleep = True
                    # 退出条件：队列为空且无运行任务
                    elif not self.queue and self.running_tasks == 0:
                        break
                    # 出错后不再调度新节点，但等待已提交节点完成，避免后台线程继续写状态。
                    if not self.success:
                        if self.running_tasks == 0:
                            break
                        should_sleep = True
                    elif not self.queue:
                        should_sleep = True
                    else:
                        # 取出队首节点
                        node_id = self.queue.popleft()
                        self.queued_actions.discard(node_id)
                        if self.node_states.get(node_id) != "queued":
                            continue
                        self.node_states[node_id] = "running"
                        # 标记任务开始
                        self.running_tasks += 1

                if should_sleep:
                    sleep(0.1)
                    continue

                if not node_id:
                    continue

                # 提交任务到线程池，每个节点使用上下文快照，避免并行节点互相修改同一个对象。
                future = self.executor.submit(
                    self.execute_node,
                    self.workflow.id,
                    node_id,
                    copy.deepcopy(self.context)
                )
                future.add_done_callback(self.on_node_complete)
        finally:
            self.executor.shutdown(wait=True, cancel_futures=True)

    def execute_node(self, workflow_id: int, node_id: str,
                     context: ActionContext) -> Tuple[Action, ActionResult]:
        """
        执行单个节点操作，返回修改后的上下文和节点ID
        """
        action = self.actions[node_id]
        action_result = self.workflowmanager.execute(workflow_id, action, context=context)
        return action, action_result

    def on_node_complete(self, future):
        """
        节点完成回调：更新上下文、处理后继节点
        """
        try:
            action, action_result = future.result()
            with self.lock:
                if global_vars.is_workflow_stopped(self.workflow.id):
                    self.success = False
                    self.stopped = True
                    self.errmsg = "工作流已停止"
                    return
                state = bool(action_result.success)
                message = action_result.message or ""
                result_ctx = action_result.context or ActionContext()

                self.finished_actions += 1
                self.update_progress()
                # 更新当前进度
                self.context.execute_history.append(
                    ActionExecution(
                        action=action.name,
                        result=state,
                        message=message
                    )
                )

                # 节点执行失败时默认停止；显式配置 continue/ignore 时继续释放后续 all_done 汇合。
                if not state:
                    self.node_states[action.id] = "failed"
                    fail_policy = self.get_action_fail_policy(action)
                    if fail_policy != "ignore":
                        self.has_failure = True
                        self.errmsg = f"{action.name} 失败"
                    if fail_policy == "stop":
                        self.success = False
                        return
                    if fail_policy not in ("continue", "ignore"):
                        self.success = False
                        self.errmsg = f"{action.name} 失败：无效失败策略 {fail_policy}"
                        return
                    self.release_successors(action.id, source_success=False)
                    return

                # 更新主上下文
                self.merge_context(result_ctx)
                self.record_node_outputs(action.id, action_result, result_ctx)
                self.completed_actions.add(action.id)
                self.node_states[action.id] = "completed"
                # 处理后继节点
                self.release_successors(action.id, source_success=True)
                # 回调
                if self.step_callback:
                    self.step_callback(action, self.context)
        except Exception as err:
            logger.error(f"工作流节点执行回调失败: {str(err)}")
            with self.lock:
                self.success = False
                self.errmsg = str(err)
        finally:
            # 标记任务完成
            with self.lock:
                self.running_tasks -= 1

    def enqueue_node(self, node_id: str) -> None:
        """
        将满足条件的节点加入待执行队列。
        """
        if node_id not in self.actions:
            return
        if self.node_states.get(node_id) != "pending" or node_id in self.queued_actions:
            return
        self.queue.append(node_id)
        self.queued_actions.add(node_id)
        self.node_states[node_id] = "queued"

    def skip_node(self, node_id: str, message: str) -> None:
        """
        将不可达节点标记为跳过，并把跳过状态继续传递给后继节点。
        """
        if node_id not in self.actions:
            return
        if self.node_states.get(node_id) not in ("pending", "queued"):
            return
        self.queued_actions.discard(node_id)
        self.node_states[node_id] = "skipped"
        self.finished_actions += 1
        self.update_progress()
        self.context.execute_history.append(
            ActionExecution(
                action=self.actions[node_id].name,
                result=True,
                message=message
            )
        )
        self.release_successors(node_id, source_success=False)

    def release_successors(self, source_id: str, source_success: bool) -> None:
        """
        根据源节点状态释放出边，并重新判断目标节点是否可运行。
        """
        for flow in self.outgoing_flows.get(source_id, []):
            flow_key = self.get_flow_key(flow)
            if flow_key in self.flow_finished:
                continue
            condition_matched = False
            if source_success:
                try:
                    condition_matched = self.evaluate_condition(self.get_flow_condition(flow))
                except ValueError as err:
                    self.success = False
                    self.errmsg = f"流程条件判断失败：{err}"
                    return
            self.flow_finished.add(flow_key)
            if source_success and condition_matched:
                self.flow_satisfied.add(flow_key)
            self.evaluate_target_state(flow.target)

    def evaluate_target_state(self, target_id: str) -> None:
        """
        按目标节点汇合策略判断节点是否入队或跳过。
        """
        if not target_id or target_id not in self.actions:
            return
        if self.node_states.get(target_id) != "pending":
            return
        incoming_flows = self.incoming_flows.get(target_id, [])
        if not incoming_flows:
            self.enqueue_node(target_id)
            return

        total_count = len(incoming_flows)
        finished_count = sum(1 for flow in incoming_flows if self.get_flow_key(flow) in self.flow_finished)
        satisfied_count = sum(1 for flow in incoming_flows if self.get_flow_key(flow) in self.flow_satisfied)
        join_policy = self.get_action_join_policy(self.actions[target_id], incoming_flows)

        if join_policy == "any_success":
            if satisfied_count > 0:
                self.enqueue_node(target_id)
            elif finished_count == total_count:
                self.skip_node(target_id, "所有上游条件均未满足，已跳过")
            return

        if join_policy == "all_done":
            if finished_count == total_count:
                self.enqueue_node(target_id)
            return

        if join_policy != "all_success":
            self.success = False
            self.errmsg = f"{self.actions[target_id].name} 汇合策略无效：{join_policy}"
            return

        if finished_count != total_count:
            return
        if satisfied_count == total_count:
            self.enqueue_node(target_id)
        else:
            self.skip_node(target_id, "上游条件未全部满足，已跳过")

    def update_progress(self) -> None:
        """
        根据已完成和已跳过节点数量更新整体进度。
        """
        self.context.progress = round(self.finished_actions / self.total_actions * 100) if self.total_actions else 100

    def record_node_outputs(self, action_id: str, action_result: ActionResult, result_context: ActionContext) -> None:
        """
        记录当前节点输出，供后续条件表达式读取。
        """
        outputs = action_result.outputs or self.extract_context_outputs(result_context)
        if outputs:
            self.context.node_outputs[action_id] = outputs

    @staticmethod
    def extract_context_outputs(context: ActionContext) -> dict:
        """
        从动作上下文中提取非空业务字段作为节点默认输出。
        """
        if not context:
            return {}
        outputs = {}
        for key in context.__class__.model_fields:
            if key in ("execute_history", "progress", "node_outputs"):
                continue
            value = getattr(context, key, None)
            if value in (None, "", [], {}):
                continue
            outputs[key] = value
        return outputs

    @staticmethod
    def get_flow_key(flow: ActionFlow) -> str:
        """
        生成流程边的运行期唯一标识。
        """
        return flow.id or f"{flow.source}->{flow.target}:{id(flow)}"

    def get_action_join_policy(self, action: Action, incoming_flows: List[ActionFlow]) -> str:
        """
        获取动作汇合策略，优先使用动作配置，其次兼容流程边配置。
        """
        join_policy = action.join_policy or self.get_action_data_value(action, "join_policy")
        if join_policy:
            return join_policy
        for flow in incoming_flows:
            join_policy = flow.join_policy or self.get_flow_data_value(flow, "join_policy")
            if join_policy:
                return join_policy
        return "all_success"

    def get_action_fail_policy(self, action: Action) -> str:
        """
        获取动作失败策略。
        """
        return action.fail_policy or self.get_action_data_value(action, "fail_policy") or "stop"

    def get_flow_condition(self, flow: ActionFlow) -> Optional[str]:
        """
        获取流程边条件表达式。
        """
        return flow.condition or self.get_flow_data_value(flow, "condition")

    @staticmethod
    def get_action_data_value(action: Action, key: str) -> Any:
        """
        从动作 data 中读取扩展配置。
        """
        data = action.data or {}
        return data.get(key) if isinstance(data, dict) else None

    @staticmethod
    def get_flow_data_value(flow: ActionFlow, key: str) -> Any:
        """
        从流程边 data 中读取扩展配置。
        """
        data = flow.data or {}
        return data.get(key) if isinstance(data, dict) else None

    def evaluate_condition(self, condition: Optional[str]) -> bool:
        """
        安全计算流程边条件表达式。
        """
        if not condition:
            return True
        expression = condition.strip()
        if not expression:
            return True
        expression = expression.replace("&&", " and ").replace("||", " or ")
        try:
            tree = ast.parse(expression, mode="eval")
        except SyntaxError as err:
            raise ValueError(f"{condition} 语法错误") from err
        return bool(self.evaluate_condition_node(tree.body))

    def evaluate_condition_node(self, node: ast.AST) -> Any:
        """
        递归计算受限 AST 节点，避免执行任意代码。
        """
        if isinstance(node, ast.BoolOp):
            values = [bool(self.evaluate_condition_node(value)) for value in node.values]
            if isinstance(node.op, ast.And):
                return all(values)
            if isinstance(node.op, ast.Or):
                return any(values)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return not bool(self.evaluate_condition_node(node.operand))
        if isinstance(node, ast.Compare):
            return self.evaluate_compare_node(node)
        if isinstance(node, ast.Name):
            return self.resolve_condition_name(node.id)
        if isinstance(node, ast.Attribute):
            return self.read_value(self.evaluate_condition_node(node.value), node.attr)
        if isinstance(node, ast.Subscript):
            return self.read_subscript_node(node)
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.List):
            return [self.evaluate_condition_node(item) for item in node.elts]
        if isinstance(node, ast.Tuple):
            return tuple(self.evaluate_condition_node(item) for item in node.elts)
        if isinstance(node, ast.Set):
            return {self.evaluate_condition_node(item) for item in node.elts}
        if isinstance(node, ast.Dict):
            return {
                self.evaluate_condition_node(key): self.evaluate_condition_node(value)
                for key, value in zip(node.keys, node.values)
            }
        raise ValueError(f"不支持的条件表达式：{ast.dump(node)}")

    def evaluate_compare_node(self, node: ast.Compare) -> bool:
        """
        计算比较表达式，支持链式比较和成员判断。
        """
        left = self.evaluate_condition_node(node.left)
        for operator, comparator in zip(node.ops, node.comparators):
            right = self.evaluate_condition_node(comparator)
            if not self.compare_values(left, operator, right):
                return False
            left = right
        return True

    def read_subscript_node(self, node: ast.Subscript) -> Any:
        """
        读取下标访问表达式。
        """
        if isinstance(node.slice, ast.Slice):
            raise ValueError("条件表达式不支持切片访问")
        container = self.evaluate_condition_node(node.value)
        key = self.evaluate_condition_node(node.slice)
        return self.read_value(container, key)

    def resolve_condition_name(self, name: str) -> Any:
        """
        将条件表达式中的根名称映射到当前工作流上下文。
        """
        if name in ("true", "True"):
            return True
        if name in ("false", "False"):
            return False
        if name in ("none", "None", "null"):
            return None
        if name == "context":
            return self.context
        if name in ("outputs", "node_outputs"):
            return self.context.node_outputs or {}
        if name in ActionContext.model_fields:
            return getattr(self.context, name, None)
        raise ValueError(f"未知上下文变量 {name}")

    def resolve_context_path(self, path: str) -> Any:
        """
        按点分路径读取工作流上下文数据。
        """
        if not path:
            return None
        value = None
        for index, part in enumerate(path.split(".")):
            if index == 0:
                value = self.resolve_condition_name(part)
                continue
            key = int(part) if part.isdigit() else part
            value = self.read_value(value, key)
        return value

    @staticmethod
    def read_value(value: Any, key: Any) -> Any:
        """
        从 dict、对象或序列中读取属性值。
        """
        if value is None:
            return None
        if isinstance(key, str) and key in ("count", "length") and hasattr(value, "__len__"):
            return len(value)
        if isinstance(value, dict):
            return value.get(key)
        if isinstance(value, (list, tuple)):
            if isinstance(key, int) and 0 <= key < len(value):
                return value[key]
            return None
        if isinstance(key, str) and hasattr(value, key):
            return getattr(value, key)
        return None

    @staticmethod
    def compare_values(left: Any, operator: ast.cmpop, right: Any) -> bool:
        """
        比较两个条件表达式值。
        """
        try:
            if isinstance(operator, ast.Eq):
                return left == right
            if isinstance(operator, ast.NotEq):
                return left != right
            if isinstance(operator, ast.Gt):
                return left > right
            if isinstance(operator, ast.GtE):
                return left >= right
            if isinstance(operator, ast.Lt):
                return left < right
            if isinstance(operator, ast.LtE):
                return left <= right
            if isinstance(operator, ast.In):
                return left in right
            if isinstance(operator, ast.NotIn):
                return left not in right
        except TypeError:
            return False
        raise ValueError(f"不支持的比较操作符：{operator.__class__.__name__}")

    def merge_context(self, context: ActionContext) -> None:
        """
        合并上下文
        """
        if not context:
            return
        for key in context.__class__.model_fields:
            value = getattr(context, key, None)
            if key in ("execute_history", "progress") or value in (None, "", [], {}):
                continue
            current_value = getattr(self.context, key, None)
            if isinstance(value, list):
                if current_value is None:
                    setattr(self.context, key, value)
                    continue
                for item in value:
                    if item not in current_value:
                        current_value.append(item)
            elif isinstance(value, dict):
                if not current_value:
                    setattr(self.context, key, value)
                else:
                    current_value.update(value)
            elif not current_value:
                setattr(self.context, key, value)


class WorkflowChain(ChainBase):
    """
    工作流链
    """

    @eventmanager.register(EventType.WorkflowExecute)
    def event_process(self, event: Event):
        """
        事件触发工作流执行
        """
        workflow_id = event.event_data.get('workflow_id')
        if not workflow_id:
            return
        self.process(workflow_id, from_begin=False)

    @staticmethod
    def process(workflow_id: int, from_begin: Optional[bool] = True) -> Tuple[bool, str]:
        """
        处理工作流
        :param workflow_id: 工作流ID
        :param from_begin: 是否从头开始，默认为True
        """
        workflowoper = WorkflowOper()

        def save_step(action: Action, context: ActionContext):
            """
            保存上下文到数据库
            """
            # 序列化数据
            serialized_data = pickle.dumps(context)
            # 使用Base64编码字节流
            encoded_data = base64.b64encode(serialized_data).decode('utf-8')
            WorkflowOper().step(workflow_id, action_id=action.id, context={
                "content": encoded_data
            })

        # 重置工作流
        if from_begin:
            workflowoper.reset(workflow_id)

        # 查询工作流数据
        workflow = workflowoper.get(workflow_id)
        if not workflow:
            logger.warn(f"工作流 {workflow_id} 不存在")
            return False, "工作流不存在"
        if not workflow.actions:
            logger.warn(f"工作流 {workflow.name} 无动作")
            return False, "工作流无动作"
        if not workflow.flows:
            logger.warn(f"工作流 {workflow.name} 无流程")
            return False, "工作流无流程"

        logger.info(f"开始执行工作流 {workflow.name}，共 {len(workflow.actions)} 个动作 ...")
        workflowoper.start(workflow_id)

        # 执行工作流
        executor = WorkflowExecutor(workflow, step_callback=save_step)
        executor.execute()

        if executor.stopped:
            logger.info(f"工作流 {workflow.name} 已停止")
            return False, executor.errmsg

        if not executor.success or executor.has_failure:
            logger.info(f"工作流 {workflow.name} 执行失败：{executor.errmsg}")
            workflowoper.fail(workflow_id, result=executor.errmsg)
            return False, executor.errmsg
        logger.info(f"工作流 {workflow.name} 执行完成")
        workflowoper.success(workflow_id)
        return True, ""

    @staticmethod
    def get_workflows() -> List[Workflow]:
        """
        获取工作流列表
        """
        return WorkflowOper().list_enabled()

    @staticmethod
    def get_timer_workflows() -> List[Workflow]:
        """
        获取定时触发的工作流列表
        """
        return WorkflowOper().get_timer_triggered_workflows()

    @staticmethod
    def get_event_workflows() -> List[Workflow]:
        """
        获取事件触发的工作流列表
        """
        return WorkflowOper().get_event_triggered_workflows()
