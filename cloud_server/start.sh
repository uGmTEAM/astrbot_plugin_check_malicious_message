#!/usr/bin/env bash
# 恶意消息检测插件 - 云同步服务端 启动脚本
# 用法:
#   ./start.sh                 # 前台运行（默认 config.json）
#   ./start.sh --daemon        # 后台运行（守护进程模式）
#   ./start.sh --port 9000     # 指定端口
#   ./start.sh --config my.json # 指定配置
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PY=python3
if ! command -v "$PY" >/dev/null 2>&1; then
    PY=python
fi
if ! command -v "$PY" >/dev/null 2>&1; then
    echo "[ERROR] 未找到 python3 / python，请先安装: sudo apt install -y python3"
    exit 1
fi

# 版本检查
PY_VER=$($PY -c 'import sys; print("%d.%d" % sys.version_info[:2])')
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 8 ]; }; then
    echo "[ERROR] Python 版本过低 ($PY_VER)，需要 3.8+。"
    exit 1
fi
echo "[INFO] Python 版本: $PY_VER"

# 配置文件检查
if [ ! -f "config.json" ]; then
    echo "[ERROR] 未找到 config.json，请先创建。可参考 README.md。"
    exit 1
fi

# Token 检查
if grep -q 'CHANGE_ME' config.json; then
    echo "[WARN] config.json 中的 token 仍是默认值 (CHANGE_ME_*)，请务必修改后再部署到公网！"
    echo "       未修改将允许任何人上传/删除数据。"
    read -p "是否仍然继续？[y/N] " ans
    case "$ans" in
        y|Y) echo "[INFO] 用户确认继续。" ;;
        *) echo "[INFO] 已取消启动。"; exit 0 ;;
    esac
fi

# 解析参数
DAEMON=0
EXTRA_ARGS=()
for arg in "$@"; do
    case "$arg" in
        --daemon) DAEMON=1 ;;
        *) EXTRA_ARGS+=("$arg") ;;
    esac
done

if [ "$DAEMON" -eq 1 ]; then
    # 守护进程模式
    PID_FILE="$SCRIPT_DIR/cloud_server.pid"
    LOG_FILE="$SCRIPT_DIR/logs/stdout.log"
    mkdir -p "$SCRIPT_DIR/logs"
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        echo "[ERROR] 服务已在运行 (PID $(cat "$PID_FILE"))。如需重启请先执行 ./stop.sh"
        exit 1
    fi
    nohup "$PY" server.py "${EXTRA_ARGS[@]}" > "$LOG_FILE" 2>&1 &
    echo $! > "$PID_FILE"
    sleep 1
    if kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        echo "[OK] 服务已后台启动 (PID $(cat "$PID_FILE"))"
        echo "     日志: $LOG_FILE"
        echo "     停止: ./stop.sh"
    else
        echo "[ERROR] 启动失败，请查看日志: $LOG_FILE"
        rm -f "$PID_FILE"
        exit 1
    fi
else
    echo "[INFO] 前台运行中，按 Ctrl+C 停止。后台运行请使用: ./start.sh --daemon"
    exec "$PY" server.py "${EXTRA_ARGS[@]}"
fi
