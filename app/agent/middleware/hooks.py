"""结构化 Agent hooks 中间件。"""

from collections.abc import Awaitable, Callable
from typing import Annotated, NotRequired, TypedDict

from langchain.agents.middleware.types import (
    AgentMiddleware,
    AgentState,
    ContextT,
    ModelRequest,
    ModelResponse,
    PrivateStateAttr,  # noqa
    ResponseT,
)
from langchain_core.runnables import RunnableConfig
from langgraph.runtime import Runtime

from app.agent.middleware.utils import append_to_system_message
from app.agent.runtime import agent_runtime_manager


class HooksState(AgentState):
    """hooks 中间件状态。"""

    hooks_prompt: NotRequired[Annotated[str, PrivateStateAttr]]


class HooksStateUpdate(TypedDict):
    """hooks 状态更新。"""

    hooks_prompt: str


class AgentHooksMiddleware(AgentMiddleware[HooksState, ContextT, ResponseT]):  # noqa
    """在固定生命周期点注入结构化 pre/in/post hooks。"""

    state_schema = HooksState

    async def abefore_agent(  # noqa
        self, state: HooksState, runtime: Runtime, config: RunnableConfig
    ) -> HooksStateUpdate | None:
        if "hooks_prompt" in state:
            return None

        runtime_config = agent_runtime_manager.load_runtime_config()
        return HooksStateUpdate(hooks_prompt=runtime_config.render_hooks_prompt())

    def modify_request(self, request: ModelRequest[ContextT]) -> ModelRequest[ContextT]:   # noqa
        hooks_prompt = request.state.get("hooks_prompt", "")  # noqa
        if not hooks_prompt:
            return request

        new_system_message = append_to_system_message(
            request.system_message, hooks_prompt
        )
        return request.override(system_message=new_system_message)

    async def awrap_model_call(
        self,
        request: ModelRequest[ContextT],
        handler: Callable[
            [ModelRequest[ContextT]], Awaitable[ModelResponse[ResponseT]]
        ],
    ) -> ModelResponse[ResponseT]:
        return await handler(self.modify_request(request))


__all__ = ["AgentHooksMiddleware"]
