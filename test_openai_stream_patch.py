import asyncio
from app.agent.llm.helper import LLMHelper
from app.core.config import settings
import json

async def run():
    llm = await LLMHelper.get_llm(
        streaming=False,
        provider="chatgpt",
        model="gpt-5.1-codex",
    )
    print("streaming:", llm.streaming)
    
asyncio.run(run())
