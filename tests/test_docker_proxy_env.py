from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _read_shell_prefix(path: Path, stop_marker: str) -> str:
    """
    读取 Docker 脚本中可独立执行的函数定义前缀。
    """
    lines = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith(stop_marker):
            break
        lines.append(line)
    return "\n".join(lines)


@pytest.mark.parametrize(
    ("script_path", "stop_marker"),
    [
        (ROOT / "docker" / "entrypoint.sh", "# 环境变量补全"),
        (ROOT / "docker" / "update.sh", "# 下载及解压"),
    ],
)
def test_docker_proxy_env_adds_default_no_proxy_ranges(
    tmp_path: Path, script_path: Path, stop_marker: str
) -> None:
    """
    Docker 代理环境应默认绕过本机、局域网和常见容器内部地址。
    """
    shell_prefix = _read_shell_prefix(script_path, stop_marker)
    config_dir = tmp_path / "config"
    script = f"""
set -euo pipefail
CONFIG_DIR="{config_dir}"
PROXY_HOST="http://proxy.example:7890"
NO_PROXY="custom.internal,127.0.0.1"
no_proxy="extra.lan,127.0.0.1"
{shell_prefix}
apply_package_proxy_env
printf 'HTTP_PROXY=%s\\n' "${{HTTP_PROXY:-}}"
printf 'HTTPS_PROXY=%s\\n' "${{HTTPS_PROXY:-}}"
printf 'NO_PROXY=%s\\n' "${{NO_PROXY:-}}"
printf 'no_proxy=%s\\n' "${{no_proxy:-}}"
"""

    result = subprocess.run(
        ["bash"],
        input=script,
        text=True,
        capture_output=True,
        check=True,
        env={"PATH": os.environ.get("PATH", "")},
    )
    output = dict(line.split("=", 1) for line in result.stdout.splitlines())

    assert output["HTTP_PROXY"] == "http://proxy.example:7890"
    assert output["HTTPS_PROXY"] == "http://proxy.example:7890"
    assert output["NO_PROXY"] == output["no_proxy"]
    assert output["NO_PROXY"].count("127.0.0.1") == 1
    for item in (
        "localhost",
        "::1",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "host.docker.internal",
        "host.containers.internal",
        "gateway.docker.internal",
        "custom.internal",
        "extra.lan",
    ):
        assert item in output["NO_PROXY"]
