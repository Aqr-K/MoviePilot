import asyncio

from app.agent import agent_manager
from app.core.config import settings, global_vars
from app.log import logger


class AgentInitializer:
    """
    AI智能体初始化器
    """

    def __init__(self):
        self._initialized = False

    async def initialize(self) -> bool:
        """
        初始化AI智能体管理器
        """
        try:
            if not settings.AI_AGENT_ENABLE:
                logger.info("AI智能体功能未启用")
                return True

            await agent_manager.initialize()
            self._initialized = True
            logger.info("AI智能体管理器初始化成功")
            return True

        except Exception as e:
            logger.error(f"AI智能体管理器初始化失败: {e}")
            return False

    async def cleanup(self) -> None:
        """
        清理AI智能体管理器
        """
        try:
            if not self._initialized:
                return
            await agent_manager.close()
            self._initialized = False
            logger.info("AI智能体管理器已关闭")

        except Exception as e:
            logger.debug(f"关闭AI智能体管理器时发生错误: {e}")


# 全局AI智能体初始化器实例
agent_initializer = AgentInitializer()


def init_agent():
    """
    初始化AI智能体（同步入口，将初始化协程调度到主事件循环中执行）

    早前实现为每次启动新建守护线程 + 临时事件循环来 run_until_complete，
    导致 Agent 的后台任务（会话 worker / 空闲清理）绑定在随线程结束即关闭的
    临时循环上，与关停时 stop_agent 所在的主循环不是同一个，关停无法取消这些任务。
    改为复用项目既有约定 asyncio.run_coroutine_threadsafe(coro, global_vars.loop)，
    使 Agent 后台任务与关停同处主循环。
    """
    try:
        if not settings.AI_AGENT_ENABLE:
            logger.info("AI智能体功能未启用")
            return True

        # 调度到主事件循环初始化（fire-and-forget；initialize 内部已记录成功/失败并吞掉异常）
        asyncio.run_coroutine_threadsafe(agent_initializer.initialize(), global_vars.loop)
        return True

    except Exception as e:
        logger.error(f"初始化AI智能体时发生错误: {e}")
        return False


async def stop_agent():
    """
    停止AI智能体（异步版本，用于在应用关闭时调用）
    """
    try:
        await agent_initializer.cleanup()
    except Exception as e:
        logger.error(f"停止AI智能体时发生错误: {e}")
