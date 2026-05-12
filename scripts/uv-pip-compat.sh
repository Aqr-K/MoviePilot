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
