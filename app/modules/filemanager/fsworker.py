"""
文件系统操作代理 worker。

**本文件不能被 import，只能作为独立脚本执行**（fsproxy 用
`subprocess.Popen([sys.executable, <本文件绝对路径>])` 启动）。直接执行文件
路径不会触发 `app/__init__.py` 的导入链，因此这个进程只依赖标准库、启动是
毫秒级的；一旦走 import 就会把整个应用的依赖拉进来，代理被强杀后的重启成本
会高到无法接受。

存在的理由：FUSE/网络挂载进入 block 型故障时，`stat`/`listdir`/`rename` 这类
系统调用既不返回错误也不返回结果，而 Python 没有中断线程的手段——阻塞其上的
线程永远无法回收。放进独立进程后，父进程可以在超时后 SIGKILL 掉它，把
「不可处理的 block」转换成「可处理的 crash」。

协议：stdin/stdout 逐行 JSON。
  请求  {"op": "stat", "path": "/mnt/cd2/x.mkv"}
  成功  {"ok": true, "result": {...}}
  失败  {"ok": false, "errno": 2, "error": "No such file or directory"}
"""
import json
import os
import shutil
import sys


def _stat(payload):
    """
    读取路径的基本属性。
    """
    path = payload["path"]
    info = os.stat(path)
    return {
        "size": info.st_size,
        "mtime": info.st_mtime,
        "is_dir": os.path.isdir(path),
        "is_file": os.path.isfile(path),
    }


def _exists(payload):
    """
    判断路径是否存在。

    用 os.stat 而不是 os.path.exists：后者会把任意 OSError 都归为「不存在」，
    挂载抖动会被误判成文件消失。这里让异常原样抛出，由父进程按 errno 区分。
    """
    os.stat(payload["path"])
    return True


def _listdir(payload):
    """
    列出目录下的条目名。
    """
    return sorted(os.listdir(payload["path"]))


def _rename(payload):
    """
    同一存储内重命名/移动。

    这是第一版唯一放行的写操作：同文件系统内的 rename 由内核保证原子性，
    进程被强杀后要么完全成功要么完全没发生，不存在需要清理的中间状态。
    跨存储的复制+删除不走这里，它需要单独的可恢复语义。
    """
    src, dst = payload["src"], payload["dst"]
    if os.stat(src).st_dev != os.stat(os.path.dirname(dst) or ".").st_dev:
        raise OSError(18, "Cross-device rename is not handled by the proxy")
    os.rename(src, dst)
    return True


def _unlink(payload):
    """
    删除单个文件。unlink 是原子操作，强杀后要么删掉了要么没删，没有中间状态。
    """
    os.unlink(payload["path"])
    return True


def _rmtree(payload):
    """
    递归删除目录。

    这一项不是原子的，强杀可能只删掉一部分。放行的理由是：删除被中断的后果
    （残留若干文件）远轻于写入被中断（留下叫最终文件名的半成品），而且调用方
    本来就以 ignore_errors 容忍部分失败、可以重复执行直到成功。
    """
    shutil.rmtree(payload["path"], ignore_errors=True)
    return True


_HANDLERS = {
    "stat": _stat,
    "exists": _exists,
    "listdir": _listdir,
    "rename": _rename,
    "unlink": _unlink,
    "rmtree": _rmtree,
    "ping": lambda _payload: True,
}


def main():
    """
    请求循环：每读一行处理一个请求，直到 stdin 关闭。
    """
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
            handler = _HANDLERS.get(payload.get("op"))
            if handler is None:
                response = {"ok": False, "errno": 0,
                            "error": f"unknown op: {payload.get('op')}"}
            else:
                response = {"ok": True, "result": handler(payload)}
        except OSError as err:
            response = {"ok": False, "errno": err.errno or 0,
                        "error": err.strerror or str(err)}
        except Exception as err:  # noqa: BLE001 - worker 不能因任何异常退出
            response = {"ok": False, "errno": 0, "error": str(err)}
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
