"""
关停竞态死锁回归测试（H2）。

PR-B(#3) 给协程定时任务加的 `run_coroutine_threadsafe(coro, loop).result()`
会阻塞 APScheduler worker 线程等主循环执行协程；关停时 lifespan 在**主循环上同步**
调 stop_scheduler()→scheduler.shutdown(wait=True) join 该 worker →
worker 等主循环、主循环等 worker，互等死锁。

修复：lifecycle 关停改 `await asyncio.to_thread(stop_scheduler)`，令主循环在等待
scheduler 关停期间仍能推进挂起协程，使 .result() 返回从而解开互等。

死锁会冻结事件循环（连 asyncio 超时都无法触发），无法在进程内安全复现，故用
子进程 + 硬超时隔离：on-loop 同步 join 复现死锁（子进程超时），off-loop（fix 技法）正常完成。
"""
import subprocess
import sys
import textwrap

# 复现同一死锁条件：worker 在主循环上 run_coroutine_threadsafe(...).result() 阻塞，
# 关停在主循环上 join 该 worker。SHUTDOWN 占位替换为 on-loop / off-loop 两种写法。
_REPRO = textwrap.dedent(
    """
    import asyncio, threading

    async def main():
        loop = asyncio.get_running_loop()
        started = threading.Event()

        async def inflight_coro():
            started.set()
            await asyncio.sleep(0.3)   # 需要主循环推进才能完成
            return "ok"

        box = {{}}
        def worker():
            box["r"] = asyncio.run_coroutine_threadsafe(inflight_coro(), loop).result()

        wt = threading.Thread(target=worker)
        wt.start()
        started.wait(2)                # 确保 worker 已在 .result() 阻塞

        {shutdown}                     # 关停：join 阻塞中的 worker

        assert box["r"] == "ok"
        print("COMPLETED")

    asyncio.run(main())
    """
)


def _run_repro(shutdown_stmt: str, timeout: float):
    script = _REPRO.format(shutdown=shutdown_stmt)
    return subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True, text=True, timeout=timeout,
    )


def test_onloop_sync_shutdown_deadlocks():
    """主循环上同步 join 在途 worker → 死锁（子进程超时）。"""
    try:
        _run_repro("wt.join()", timeout=4)
    except subprocess.TimeoutExpired:
        return  # 预期：死锁导致超时
    raise AssertionError("on-loop 同步关停未死锁——复现条件已失效，测试无意义")


def test_offloop_to_thread_shutdown_completes():
    """off-loop（await asyncio.to_thread(join)）关停不死锁，协程正常完成。"""
    result = _run_repro("await asyncio.to_thread(wt.join)", timeout=10)
    assert result.returncode == 0, f"off-loop 关停应正常完成，stderr={result.stderr}"
    assert "COMPLETED" in result.stdout
