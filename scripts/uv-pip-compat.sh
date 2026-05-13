#!/bin/sh

set -eu

SCRIPT_PATH="$0"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$SCRIPT_PATH")" && pwd)
COMMAND_NAME=$(basename -- "$SCRIPT_PATH")

if [ "${COMMAND_NAME}" = "uv-pip-compat" ] || [ "${COMMAND_NAME}" = "uv-pip-compat.sh" ]; then
    if [ "$#" -eq 0 ]; then
        echo "用法: uv-pip-compat <pip|pip-compile|pip-sync> [args...]" >&2
        exit 2
    fi
    COMMAND_NAME="$1"
    shift
fi

if [ -x "${SCRIPT_DIR}/uv" ]; then
    UV_BIN="${SCRIPT_DIR}/uv"
elif command -v uv >/dev/null 2>&1; then
    UV_BIN=$(command -v uv)
else
    echo "未找到 uv，可执行 pip 兼容层无法继续运行。" >&2
    exit 127
fi

has_environment_option() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            -p|--python|--python=*|-p*|--system)
                return 0
                ;;
            --)
                return 1
                ;;
        esac
        shift
    done
    return 1
}

case "${COMMAND_NAME}" in
    pip|pip3|pip3.*)
        if [ "$#" -eq 0 ]; then
            exec "${UV_BIN}" pip --help
        fi

        case "$1" in
            -V|--version|version)
                exec "${UV_BIN}" --version
                ;;
            help)
                shift
                exec "${UV_BIN}" help pip "$@"
                ;;
            check)
                if [ -x "${SCRIPT_DIR}/python" ] && ! has_environment_option "$@"; then
                    # uv 不会仅凭 pip 软链接位置锁定 venv，显式绑定当前运行态解释器。
                    shift
                    exec "${UV_BIN}" pip check --python "${SCRIPT_DIR}/python" "$@"
                fi
                exec "${UV_BIN}" pip "$@"
                ;;
            *)
                exec "${UV_BIN}" pip "$@"
                ;;
        esac
        ;;
    pip-compile)
        exec "${UV_BIN}" pip compile "$@"
        ;;
    pip-sync)
        exec "${UV_BIN}" pip sync "$@"
        ;;
    *)
        echo "不支持的 pip 兼容命令入口：${COMMAND_NAME}" >&2
        exit 2
        ;;
esac
