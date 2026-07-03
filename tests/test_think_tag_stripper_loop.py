"""
_ThinkTagStripper.process 死循环回归测试（单进程事件循环 DoS）。

not-in-think 分支处理 <think> 不完整前缀后缺 while-break：当 buffer 恰为裸前缀
（'<' / '<t' / ... / '<think'）时既不输出也不改 buffer，while self.buffer 无限自旋。
用 threading + 超时保护，未修时测试会因超时失败/挂死。
"""
import threading

from app.agent import _ThinkTagStripper


def _run_with_timeout(fn, timeout=2.0):
    """在子线程跑 fn，超时视为死循环。返回 True 表示按时完成。"""
    done = threading.Event()

    def _target():
        fn()
        done.set()

    t = threading.Thread(target=_target, daemon=True)
    t.start()
    return done.wait(timeout)


class TestThinkTagStripperNoInfiniteLoop:
    def test_bare_partial_prefix_terminates(self):
        """token 恰以裸 '<' 结尾时 process 必须终止（此前死循环）。"""
        out = []
        stripper = _ThinkTagStripper()
        completed = _run_with_timeout(lambda: stripper.process("Hello <", out.append))
        assert completed, "process('Hello <') 未在超时内返回——死循环未修复"

    def test_all_partial_prefixes_terminate(self):
        for tail in ("<", "<t", "<th", "<thi", "<thin", "<think"):
            out = []
            stripper = _ThinkTagStripper()
            completed = _run_with_timeout(lambda: stripper.process(f"text {tail}", out.append))
            assert completed, f"process 以 {tail!r} 结尾时死循环"

    def test_emits_content_before_partial_prefix(self):
        """部分前缀前的正文应先被输出，前缀留待后续 token。"""
        out = []
        stripper = _ThinkTagStripper()
        assert _run_with_timeout(lambda: stripper.process("Hello <", out.append))
        assert "".join(out) == "Hello "

    def test_partial_prefix_completes_into_think_across_tokens(self):
        """裸前缀跨 token 补全为完整 <think> 后，思考内容被剥离、正文正常输出。"""
        out = []
        stripper = _ThinkTagStripper()
        assert _run_with_timeout(lambda: stripper.process("答案 <", out.append))
        assert _run_with_timeout(lambda: stripper.process("think>秘密</think>结果", out.append))
        assert "".join(out) == "答案 结果"

    def test_plain_less_than_not_prefix_is_emitted(self):
        """普通 '<'（后面还有非前缀字符）正常输出，不被吞。"""
        out = []
        stripper = _ThinkTagStripper()
        assert _run_with_timeout(lambda: stripper.process("x < 5", out.append))
        assert "".join(out) == "x < 5"
