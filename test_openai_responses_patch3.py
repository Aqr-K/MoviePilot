from app.agent.llm.helper import _patch_openai_responses_instructions_support
from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage
import json

_patch_openai_responses_instructions_support()
model = ChatOpenAI(model="gpt-4o", openai_api_key="sk-123", use_responses_api=True, temperature=0.7)
payload = model._get_request_payload([SystemMessage(content="Hello system"), HumanMessage(content="Hello user")])
print(json.dumps(payload, indent=2))
