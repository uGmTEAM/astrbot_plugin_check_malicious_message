#!/usr/bin/env bash
# 恶意消息检测插件 - 云同步服务端 停止脚本
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$SCRIPT_DIR/cloud_server.pid"

if [ ! -f "$PID_FILE" ]; then
    echo "[INFO] 未发现 PID 文件，服务可能未在后台运行。"
    # 尝试根据进程名查找
    PIDS=$(pgrep -f "server.py" 2>/dev/null || true)
    if [ -n "$PIDS" ]; then
        echo "[INFO] 找到匹配进程: $PIDS"
        read -p "是否结束这些进程？[y/N] " ans
        case "$ans" in
            y|Y) echo "$PIDS" | xargs -r kill; echo "[OK] 已发送 SIGTERM" ;;
            *) echo "[INFO] 已取消。" ;;
        esac
    fi
    exit 0
fi

PID=$(cat "$PID_FILE")
if kill -0 "$PID" 2>/dev/null; then
    kill "$PID"
    echo "[OK] 已向 PID $PID 发送 SIGTERM，等待退出…"
    for i in $(seq 1 10); do
        if ! kill -0 "$PID" 2>/dev/null; then
            break
        fi
        sleep 0.5
    done
    if kill -0 "$PID" 2>/dev/null; then
        echo "[WARN] 进程未响应，发送 SIGKILL…"
        kill -9 "$PID" 2>/dev/null || true
    fi
    echo "[OK] 服务已停止。"
else
    echo "[INFO] 进程 $PID 已不存在。"
fi
rm -f "$PID_FILE"
