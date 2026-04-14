"""浏览器操作工具 - 让Agent能够通过Playwright控制浏览器进行网页交互"""

import asyncio
import base64
import json
from enum import Enum
from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.core.config import settings
from app.log import logger

# 页面内容最大长度
MAX_CONTENT_LENGTH = 8000
# 默认超时时间（秒）
DEFAULT_TIMEOUT = 30
# 截图最大宽度
SCREENSHOT_MAX_WIDTH = 1280
# 截图最大高度
SCREENSHOT_MAX_HEIGHT = 720


class BrowserAction(str, Enum):
    """浏览器操作类型"""

    GOTO = "goto"
    GET_CONTENT = "get_content"
    SCREENSHOT = "screenshot"
    CLICK = "click"
    FILL = "fill"
    SELECT = "select"
    EVALUATE = "evaluate"
    WAIT = "wait"


class BrowseWebpageInput(BaseModel):
    """浏览器操作工具的输入参数模型"""

    explanation: str = Field(
        ...,
        description="Clear explanation of why this browser action is being performed",
    )
    action: str = Field(
        ...,
        description=(
            "The browser action to perform. Available actions:\n"
            "- 'goto': Navigate to a URL, returns page title and text summary\n"
            "- 'get_content': Get current page content (text or HTML)\n"
            "- 'screenshot': Take a screenshot of the current page, returns base64 image\n"
            "- 'click': Click on an element specified by selector\n"
            "- 'fill': Fill text into an input element specified by selector\n"
            "- 'select': Select an option from a dropdown element\n"
            "- 'evaluate': Execute JavaScript code on the page and return the result\n"
            "- 'wait': Wait for an element to appear on the page"
        ),
    )
    url: Optional[str] = Field(
        None, description="URL to navigate to (required for 'goto' action)"
    )
    selector: Optional[str] = Field(
        None,
        description="CSS selector or text selector for the target element (for 'click', 'fill', 'select', 'wait' actions). "
        "Supports CSS selectors like '#id', '.class', 'tag', and Playwright text selectors like 'text=Click me'",
    )
    value: Optional[str] = Field(
        None,
        description="Value to fill into input or option value to select (for 'fill' and 'select' actions)",
    )
    script: Optional[str] = Field(
        None,
        description="JavaScript code to execute on the page (for 'evaluate' action). "
        "The script should return a value that can be serialized to JSON.",
    )
    content_type: Optional[str] = Field(
        "text",
        description="Content type for 'get_content' action: 'text' for readable text, 'html' for raw HTML",
    )
    timeout: Optional[int] = Field(
        DEFAULT_TIMEOUT, description="Timeout in seconds for the action (default: 30)"
    )
    cookies: Optional[str] = Field(
        None,
        description="Cookies to set for the browser context, format: 'name1=value1; name2=value2'",
    )
    user_agent: Optional[str] = Field(
        None, description="Custom User-Agent string for the browser context"
    )


class BrowseWebpageTool(MoviePilotTool):
    name: str = "browse_webpage"
    description: str = (
        "Control a real browser (Playwright) to interact with web pages. "
        "Supports navigating to URLs, reading page content, taking screenshots, "
        "clicking elements, filling forms, selecting dropdown options, executing JavaScript, and waiting for elements. "
        "Use this tool when you need to interact with dynamic web pages, "
        "fill in forms, click buttons, or extract content from JavaScript-rendered pages. "
        "The browser session persists across multiple calls within the same conversation - "
        "first call 'goto' to open a page, then use other actions to interact with it."
    )
    args_schema: Type[BaseModel] = BrowseWebpageInput

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """根据操作类型生成友好的提示消息"""
        action = kwargs.get("action", "")
        url = kwargs.get("url", "")
        selector = kwargs.get("selector", "")
        action_messages = {
            "goto": f"正在打开网页: {url}",
            "get_content": "正在获取页面内容",
            "screenshot": "正在截取页面截图",
            "click": f"正在点击元素: {selector}",
            "fill": f"正在填写表单: {selector}",
            "select": f"正在选择选项: {selector}",
            "evaluate": "正在执行 JavaScript",
            "wait": f"正在等待元素: {selector}",
        }
        return action_messages.get(action, f"正在执行浏览器操作: {action}")

    async def run(
        self,
        action: str,
        url: Optional[str] = None,
        selector: Optional[str] = None,
        value: Optional[str] = None,
        script: Optional[str] = None,
        content_type: Optional[str] = "text",
        timeout: Optional[int] = DEFAULT_TIMEOUT,
        cookies: Optional[str] = None,
        user_agent: Optional[str] = None,
        **kwargs,
    ) -> str:
        """执行浏览器操作"""
        logger.info(
            f"执行工具: {self.name}, 动作: {action}, URL: {url}, 选择器: {selector}"
        )

        try:
            # 验证操作类型
            try:
                browser_action = BrowserAction(action)
            except ValueError:
                valid_actions = ", ".join([a.value for a in BrowserAction])
                return f"错误: 不支持的操作类型 '{action}'，支持的操作: {valid_actions}"

            # 参数校验
            if browser_action == BrowserAction.GOTO and not url:
                return "错误: 'goto' 操作需要提供 url 参数"
            if (
                browser_action
                in (
                    BrowserAction.CLICK,
                    BrowserAction.FILL,
                    BrowserAction.SELECT,
                    BrowserAction.WAIT,
                )
                and not selector
            ):
                return f"错误: '{action}' 操作需要提供 selector 参数"
            if browser_action == BrowserAction.FILL and value is None:
                return "错误: 'fill' 操作需要提供 value 参数"
            if browser_action == BrowserAction.EVALUATE and not script:
                return "错误: 'evaluate' 操作需要提供 script 参数"

            # 在线程池中运行同步的 Playwright 操作
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                None,
                lambda: self._execute_browser_action(
                    browser_action=browser_action,
                    url=url,
                    selector=selector,
                    value=value,
                    script=script,
                    content_type=content_type,
                    timeout=timeout,
                    cookies=cookies,
                    user_agent=user_agent,
                ),
            )
            return result

        except Exception as e:
            logger.error(f"浏览器操作失败: {e}", exc_info=True)
            return f"浏览器操作失败: {str(e)}"

    def _execute_browser_action(
        self,
        browser_action: BrowserAction,
        url: Optional[str],
        selector: Optional[str],
        value: Optional[str],
        script: Optional[str],
        content_type: Optional[str],
        timeout: int,
        cookies: Optional[str],
        user_agent: Optional[str],
    ) -> str:
        """在同步上下文中执行 Playwright 浏览器操作"""
        from playwright.sync_api import sync_playwright

        try:
            with sync_playwright() as playwright:
                browser = None
                context = None
                page = None
                try:
                    # 启动浏览器
                    browser_type = settings.PLAYWRIGHT_BROWSER_TYPE or "chromium"
                    browser = playwright[browser_type].launch(headless=True)

                    # 创建上下文
                    context_kwargs = {}
                    if user_agent:
                        context_kwargs["user_agent"] = user_agent
                    # 设置视口大小
                    context_kwargs["viewport"] = {
                        "width": SCREENSHOT_MAX_WIDTH,
                        "height": SCREENSHOT_MAX_HEIGHT,
                    }

                    context = browser.new_context(**context_kwargs)
                    page = context.new_page()
                    page.set_default_timeout(timeout * 1000)

                    # 设置 cookies
                    if cookies:
                        page.set_extra_http_headers({"cookie": cookies})

                    # 对于非 goto 操作，如果提供了 url 先导航
                    if url and browser_action != BrowserAction.GOTO:
                        page.goto(
                            url, wait_until="domcontentloaded", timeout=timeout * 1000
                        )
                        page.wait_for_load_state("networkidle", timeout=timeout * 1000)

                    # 执行具体操作
                    result = self._do_action(
                        page,
                        browser_action,
                        url,
                        selector,
                        value,
                        script,
                        content_type,
                        timeout,
                    )
                    return result

                finally:
                    if page:
                        page.close()
                    if context:
                        context.close()
                    if browser:
                        browser.close()

        except Exception as e:
            logger.error(f"Playwright 执行失败: {e}", exc_info=True)
            return f"Playwright 执行失败: {str(e)}"

    def _do_action(
        self,
        page,
        browser_action: BrowserAction,
        url: Optional[str],
        selector: Optional[str],
        value: Optional[str],
        script: Optional[str],
        content_type: Optional[str],
        timeout: int,
    ) -> str:
        """执行具体的浏览器操作"""

        if browser_action == BrowserAction.GOTO:
            return self._action_goto(page, url, timeout)

        elif browser_action == BrowserAction.GET_CONTENT:
            return self._action_get_content(page, content_type)

        elif browser_action == BrowserAction.SCREENSHOT:
            return self._action_screenshot(page)

        elif browser_action == BrowserAction.CLICK:
            return self._action_click(page, selector, timeout)

        elif browser_action == BrowserAction.FILL:
            return self._action_fill(page, selector, value, timeout)

        elif browser_action == BrowserAction.SELECT:
            return self._action_select(page, selector, value, timeout)

        elif browser_action == BrowserAction.EVALUATE:
            return self._action_evaluate(page, script)

        elif browser_action == BrowserAction.WAIT:
            return self._action_wait(page, selector, timeout)

        return f"未知操作: {browser_action}"

    @staticmethod
    def _action_goto(page, url: str, timeout: int) -> str:
        """导航到URL"""
        response = page.goto(url, wait_until="domcontentloaded", timeout=timeout * 1000)
        try:
            page.wait_for_load_state("networkidle", timeout=min(timeout, 15) * 1000)
        except Exception:
            # networkidle 超时不是致命错误，页面可能已经可用
            pass

        status = response.status if response else "unknown"
        title = page.title()
        page_url = page.url

        # 提取页面可读文本摘要
        text_content = page.inner_text("body")
        if text_content and len(text_content) > MAX_CONTENT_LENGTH:
            text_content = text_content[:MAX_CONTENT_LENGTH] + "\n\n...(内容已截断)"

        # 提取页面链接
        links = page.evaluate("""
            () => {
                const links = [];
                document.querySelectorAll('a[href]').forEach(a => {
                    const text = a.innerText.trim();
                    const href = a.href;
                    if (text && href && !href.startsWith('javascript:')) {
                        links.push({text: text.substring(0, 80), href: href});
                    }
                });
                return links.slice(0, 30);
            }
        """)

        # 提取表单信息
        forms = page.evaluate("""
            () => {
                const forms = [];
                document.querySelectorAll('input, textarea, select, button').forEach(el => {
                    const info = {
                        tag: el.tagName.toLowerCase(),
                        type: el.type || '',
                        name: el.name || '',
                        id: el.id || '',
                        placeholder: el.placeholder || '',
                        value: el.tagName.toLowerCase() === 'select' ? '' : (el.value || '').substring(0, 50),
                        text: el.innerText ? el.innerText.trim().substring(0, 50) : ''
                    };
                    // 只保留有标识信息的元素
                    if (info.name || info.id || info.placeholder || info.text) {
                        forms.push(info);
                    }
                });
                return forms.slice(0, 30);
            }
        """)

        result = {
            "status": status,
            "url": page_url,
            "title": title,
            "text_content": text_content,
        }
        if links:
            result["links"] = links
        if forms:
            result["form_elements"] = forms

        return json.dumps(result, ensure_ascii=False, indent=2)

    @staticmethod
    def _action_get_content(page, content_type: Optional[str]) -> str:
        """获取页面内容"""
        title = page.title()
        page_url = page.url

        if content_type == "html":
            content = page.content()
        else:
            content = page.inner_text("body")

        if content and len(content) > MAX_CONTENT_LENGTH:
            content = content[:MAX_CONTENT_LENGTH] + "\n\n...(内容已截断)"

        result = {
            "url": page_url,
            "title": title,
            "content_type": content_type,
            "content": content,
        }
        return json.dumps(result, ensure_ascii=False, indent=2)

    @staticmethod
    def _action_screenshot(page) -> str:
        """截取页面截图"""
        screenshot_bytes = page.screenshot(
            full_page=False,
            type="jpeg",
            quality=60,
        )
        screenshot_b64 = base64.b64encode(screenshot_bytes).decode("utf-8")

        # 限制截图大小（base64编码后大约增大33%）
        max_b64_size = 200 * 1024  # ~150KB 原始图片
        if len(screenshot_b64) > max_b64_size:
            # 降低质量重新截图
            screenshot_bytes = page.screenshot(
                full_page=False,
                type="jpeg",
                quality=30,
            )
            screenshot_b64 = base64.b64encode(screenshot_bytes).decode("utf-8")

        title = page.title()
        page_url = page.url

        result = {
            "url": page_url,
            "title": title,
            "screenshot_base64": screenshot_b64,
            "format": "jpeg",
            "note": "截图已以 base64 编码返回",
        }
        return json.dumps(result, ensure_ascii=False, indent=2)

    @staticmethod
    def _action_click(page, selector: str, timeout: int) -> str:
        """点击元素"""
        page.click(selector, timeout=timeout * 1000)

        # 等待可能的页面变化
        try:
            page.wait_for_load_state("networkidle", timeout=5000)
        except Exception:
            pass

        title = page.title()
        page_url = page.url

        return json.dumps(
            {
                "success": True,
                "message": f"成功点击元素: {selector}",
                "current_url": page_url,
                "current_title": title,
            },
            ensure_ascii=False,
            indent=2,
        )

    @staticmethod
    def _action_fill(page, selector: str, value: str, timeout: int) -> str:
        """填写表单"""
        page.fill(selector, value, timeout=timeout * 1000)

        return json.dumps(
            {
                "success": True,
                "message": f"成功填写元素 '{selector}' 的值为 '{value}'",
            },
            ensure_ascii=False,
            indent=2,
        )

    @staticmethod
    def _action_select(page, selector: str, value: Optional[str], timeout: int) -> str:
        """选择下拉选项"""
        if value:
            page.select_option(selector, value=value, timeout=timeout * 1000)
        else:
            return "错误: 'select' 操作需要提供 value 参数"

        return json.dumps(
            {
                "success": True,
                "message": f"成功选择元素 '{selector}' 的选项 '{value}'",
            },
            ensure_ascii=False,
            indent=2,
        )

    @staticmethod
    def _action_evaluate(page, script: str) -> str:
        """执行 JavaScript"""
        result = page.evaluate(script)

        # 格式化结果
        if result is None:
            formatted = "null"
        elif isinstance(result, (dict, list)):
            formatted = json.dumps(result, ensure_ascii=False, indent=2)
        else:
            formatted = str(result)

        # 限制结果长度
        if len(formatted) > MAX_CONTENT_LENGTH:
            formatted = formatted[:MAX_CONTENT_LENGTH] + "\n\n...(结果已截断)"

        return json.dumps(
            {
                "success": True,
                "result": formatted,
            },
            ensure_ascii=False,
            indent=2,
        )

    @staticmethod
    def _action_wait(page, selector: str, timeout: int) -> str:
        """等待元素出现"""
        element = page.wait_for_selector(selector, timeout=timeout * 1000)

        if element:
            visible = element.is_visible()
            text = element.inner_text()
            if text and len(text) > 200:
                text = text[:200] + "..."

            return json.dumps(
                {
                    "success": True,
                    "message": f"元素 '{selector}' 已出现",
                    "visible": visible,
                    "text": text,
                },
                ensure_ascii=False,
                indent=2,
            )
        else:
            return json.dumps(
                {
                    "success": False,
                    "message": f"等待元素 '{selector}' 超时",
                },
                ensure_ascii=False,
                indent=2,
            )
