from collections.abc import Awaitable, Callable
from typing import Any

from langchain.agents.middleware.types import (
    AgentMiddleware,
    ContextT,
    ModelRequest,
    ModelResponse,
    ResponseT,
)
from langchain_core.messages import AIMessage

from app.log import logger


class UsageMiddleware(AgentMiddleware):
    """记录模型调用 usage 信息并回传给外部会话。"""

    def __init__(
        self,
        *,
        on_usage: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.on_usage = on_usage

    @staticmethod
    def _coerce_int(value: Any) -> int | None:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @classmethod
    def _lookup_int(cls, container: Any, *keys: str) -> int | None:
        if not container:
            return None

        getter = getattr(container, "get", None)
        if callable(getter):
            for key in keys:
                value = getter(key)
                if value is not None:
                    return cls._coerce_int(value)

        for key in keys:
            value = getattr(container, key, None)
            if value is not None:
                return cls._coerce_int(value)

        return None

    @classmethod
    def _extract_model_name(cls, model: Any) -> str | None:
        return (
            getattr(model, "model", None)
            or getattr(model, "model_name", None)
            or getattr(model, "model_id", None)
        )

    @classmethod
    def _extract_context_window_tokens(cls, model: Any) -> int | None:
        profile = getattr(model, "profile", None)
        if not profile:
            return None
        return cls._lookup_int(profile, "max_input_tokens", "input_token_limit")

    @classmethod
    def _extract_usage(cls, ai_message: AIMessage) -> dict[str, Any]:
        usage_metadata = getattr(ai_message, "usage_metadata", None)

        input_tokens = cls._lookup_int(usage_metadata, "input_tokens")
        output_tokens = cls._lookup_int(usage_metadata, "output_tokens")
        total_tokens = cls._lookup_int(usage_metadata, "total_tokens")

        response_metadata = getattr(ai_message, "response_metadata", None) or {}
        token_usage = (
            response_metadata.get("token_usage")
            or response_metadata.get("usage")
            or response_metadata.get("usage_metadata")
            or {}
        )

        if input_tokens is None:
            input_tokens = cls._lookup_int(
                token_usage,
                "prompt_tokens",
                "input_tokens",
            )
        if input_tokens is None:
            input_tokens = cls._lookup_int(
                response_metadata,
                "prompt_token_count",
                "input_tokens",
            )

        if output_tokens is None:
            output_tokens = cls._lookup_int(
                token_usage,
                "completion_tokens",
                "output_tokens",
            )
        if output_tokens is None:
            output_tokens = cls._lookup_int(
                response_metadata,
                "candidates_token_count",
                "output_tokens",
            )

        if total_tokens is None:
            total_tokens = cls._lookup_int(token_usage, "total_tokens")
        if total_tokens is None:
            total_tokens = cls._lookup_int(response_metadata, "total_token_count")

        has_usage = any(
            value is not None for value in (input_tokens, output_tokens, total_tokens)
        )
        resolved_input = input_tokens or 0
        resolved_output = output_tokens or 0
        resolved_total = (
            total_tokens
            if total_tokens is not None
            else resolved_input + resolved_output
        )

        return {
            "has_usage": has_usage,
            "input_tokens": resolved_input,
            "output_tokens": resolved_output,
            "total_tokens": resolved_total,
        }

    async def awrap_model_call(
        self,
        request: ModelRequest[ContextT],
        handler: Callable[
            [ModelRequest[ContextT]], Awaitable[ModelResponse[ResponseT]]
        ],
    ) -> ModelResponse[ResponseT]:
        response = await handler(request)

        if not callable(self.on_usage):
            return response

        try:
            ai_message = next(
                (
                    message
                    for message in reversed(response.result)
                    if isinstance(message, AIMessage)
                ),
                None,
            )
            usage = (
                self._extract_usage(ai_message)
                if ai_message
                else {
                    "has_usage": False,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "total_tokens": 0,
                }
            )
            context_window_tokens = self._extract_context_window_tokens(request.model)
            context_usage_ratio = None
            if context_window_tokens and usage["has_usage"]:
                context_usage_ratio = usage["input_tokens"] / context_window_tokens

            self.on_usage(
                {
                    "model": self._extract_model_name(request.model),
                    "context_window_tokens": context_window_tokens,
                    "context_usage_ratio": context_usage_ratio,
                    **usage,
                }
            )
        except Exception as e:
            logger.debug("记录模型 usage 失败: %s", e)

        return response


__all__ = ["UsageMiddleware"]
