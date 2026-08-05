#!/usr/bin/env python3
"""
恶意消息检测插件 - 云同步服务端
================================

零外部依赖（仅使用 Python 标准库），适配 Ubuntu / Debian / 任何装有 Python 3.8+ 的系统。

功能：
  - 上传警告记录      POST /api/upload_record     (X-Client-Token)
  - 上传特殊记录      POST /api/upload_special    (X-Client-Token)
  - 拉取增量更新      GET  /api/sync              (X-Client-Token)
  - 推送增量变更      POST /api/sync              (X-Client-Token)
  - 删除警告记录      POST /api/delete_record     (X-Admin-Token)
  - 列出全部记录      GET  /api/records           (X-Client-Token)
  - 列出特殊记录      GET  /api/special           (X-Client-Token)
  - 服务端统计        GET  /api/stats            (X-Client-Token)
  - 健康检查          GET  /api/health           (无 Token)

启动：python3 server.py [--config config.json] [--port 8765] [--host 0.0.0.0]
"""

import argparse
import json
import os
import sys
import threading
import time
import uuid
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

__VERSION__ = "1.4.0"
CONFIG_PATH_DEFAULT = "config.json"
RECORDS_FILE = "records.json"
SPECIAL_FILE = "special_records.json"
LOGS_FILE = "logs.json"
AUDIT_LOG = "audit.log.jsonl"
REQUEST_LOG = "request.log.jsonl"
WEB_DIR = "web"
MAX_LOGS = 50000  # 备案日志容量上限（FIFO 截断）

# ---------------------------------------------------------------------------
# 全局状态（受 LOCK 保护）
# ---------------------------------------------------------------------------

LOCK = threading.RLock()
CONFIG: dict = {}
RECORDS: dict[str, dict] = {}
SPECIAL_RECORDS: list[dict] = []
LOGS: list[dict] = []            # 备案日志（个体警告事件，由客户端上传）
LOGS_INDEX: set[str] = set()     # log_id 去重索引，启动时重建
META: dict = {"created_at": 0, "last_seq": 0}
DATA_DIR = "data"
LOG_DIR = "logs"
BLACKLIST: list[str] = []  # IP 黑名单（支持精确匹配和 CIDR 前缀，如 192.168.1.）


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

def now_ts() -> float:
    return time.time()


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def record_key(platform_id: str, user_id: str) -> str:
    return f"{platform_id or ''}:{user_id or ''}"


def _special_fingerprint(item: dict, default_bot_id: str = "") -> str:
    """为特殊记录生成去重指纹。基于 (cloud_bot_id, user_id, platform_id, time, message)。

    返回空字符串表示无法生成有效指纹（跳过该记录的去重检查）。
    """
    if not isinstance(item, dict):
        return ""
    bot_id = str(item.get("cloud_bot_id", "") or default_bot_id or "")
    uid = str(item.get("user_id", "") or "")
    pid = str(item.get("platform_id", "") or "")
    msg = str(item.get("message", "") or "")[:200]
    t = float(item.get("time", 0) or 0)
    if not uid or t <= 0:
        return ""
    return f"{bot_id}|{pid}|{uid}|{t}|{msg}"


def atomic_write(path: str, data) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def append_jsonl(path: str, obj: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def log_request(method: str, path: str, status: int, client: str, body_summary: str = "") -> None:
    if not CONFIG.get("enable_request_logging", True):
        return
    try:
        log_path = os.path.join(LOG_DIR, REQUEST_LOG)
        append_jsonl(log_path, {
            "time": now_ts(),
            "time_str": now_str(),
            "method": method,
            "path": path,
            "status": status,
            "client": client,
            "summary": body_summary[:200],
        })
        # 限制请求日志大小（保留最近 5000 条）
        _trim_jsonl(log_path, CONFIG.get("max_audit_log_entries", 5000))
    except Exception:
        pass


def _trim_jsonl(path: str, max_lines: int) -> None:
    try:
        if not os.path.exists(path):
            return
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        if len(lines) <= max_lines:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(lines[-max_lines:])
    except Exception:
        pass


def audit_log(action: str, actor: str, detail: dict) -> None:
    try:
        log_path = os.path.join(LOG_DIR, AUDIT_LOG)
        append_jsonl(log_path, {
            "time": now_ts(),
            "time_str": now_str(),
            "action": action,
            "actor": actor,
            "detail": detail,
        })
    except Exception:
        pass


def next_seq() -> int:
    global META
    META["last_seq"] = int(META.get("last_seq", 0)) + 1
    return META["last_seq"]


def read_jsonl(path: str, limit: int = 500) -> list:
    """读取 JSONL 日志文件的最近 limit 条记录。"""
    try:
        if not os.path.exists(path):
            return []
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        result = []
        for line in reversed(lines[-limit * 2:]):  # 多读一些以应对过滤
            line = line.strip()
            if not line:
                continue
            try:
                result.append(json.loads(line))
            except Exception:
                continue
            if len(result) >= limit:
                break
        return result
    except Exception:
        return []


# Web 管理器静态文件目录（脚本所在目录下的 web/）
WEB_BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), WEB_DIR)

# 静态文件 MIME 类型映射
MIME_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
}


# ---------------------------------------------------------------------------
# 持久化
# ---------------------------------------------------------------------------

def records_path() -> str:
    return os.path.join(DATA_DIR, RECORDS_FILE)


def special_path() -> str:
    return os.path.join(DATA_DIR, SPECIAL_FILE)


def logs_path() -> str:
    return os.path.join(DATA_DIR, LOGS_FILE)


def load_data() -> None:
    global RECORDS, SPECIAL_RECORDS, LOGS, LOGS_INDEX, META
    try:
        if os.path.exists(records_path()):
            with open(records_path(), "r", encoding="utf-8") as f:
                d = json.load(f)
            RECORDS = d.get("records", {}) or {}
            META = d.get("meta", {}) or {}
            if "created_at" not in META:
                META["created_at"] = now_ts()
            if "last_seq" not in META:
                META["last_seq"] = 0
        else:
            META = {"created_at": now_ts(), "last_seq": 0}
    except Exception as e:
        sys.stderr.write(f"[load records] 失败: {e}\n")
        META = {"created_at": now_ts(), "last_seq": 0}

    try:
        if os.path.exists(special_path()):
            with open(special_path(), "r", encoding="utf-8") as f:
                d = json.load(f)
            SPECIAL_RECORDS = d.get("special_records", []) or []
        else:
            SPECIAL_RECORDS = []
    except Exception as e:
        sys.stderr.write(f"[load special] 失败: {e}\n")
        SPECIAL_RECORDS = []

    try:
        if os.path.exists(logs_path()):
            with open(logs_path(), "r", encoding="utf-8") as f:
                d = json.load(f)
            LOGS = d.get("logs", []) or []
        else:
            LOGS = []
        # 重建 log_id 去重索引
        LOGS_INDEX = {str(l.get("log_id", "")) for l in LOGS if l.get("log_id")}
    except Exception as e:
        sys.stderr.write(f"[load logs] 失败: {e}\n")
        LOGS = []
        LOGS_INDEX = set()


def save_records() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    data = {"records": RECORDS, "meta": META, "version": __VERSION__}
    atomic_write(records_path(), data)


def save_special() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    data = {"special_records": SPECIAL_RECORDS, "meta": {"updated_at": now_ts()}}
    atomic_write(special_path(), data)


def save_logs() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    data = {"logs": LOGS, "meta": {"updated_at": now_ts()}}
    atomic_write(logs_path(), data)


def trim_logs() -> None:
    """FIFO 截断备案日志到 MAX_LOGS，同步更新索引。"""
    global LOGS_INDEX
    if len(LOGS) <= MAX_LOGS:
        return
    LOGS[:] = LOGS[-MAX_LOGS:]
    LOGS_INDEX = {str(l.get("log_id", "")) for l in LOGS if l.get("log_id")}


# ---- IP 黑名单 ----

BLACKLIST_FILE = "blacklist.json"
BLACKLISTED_RESPONSE_TEXT = "你的IP已被拉黑，无法访问此服务。"


def blacklist_path() -> str:
    return os.path.join(DATA_DIR, BLACKLIST_FILE)


def load_blacklist() -> None:
    global BLACKLIST
    try:
        if os.path.exists(blacklist_path()):
            with open(blacklist_path(), "r", encoding="utf-8") as f:
                data = json.load(f)
            BLACKLIST = data.get("blacklist", []) or []
        else:
            BLACKLIST = []
    except Exception as e:
        sys.stderr.write(f"[load blacklist] 失败: {e}\n")
        BLACKLIST = []


def save_blacklist() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    data = {"blacklist": BLACKLIST, "updated_at": now_ts()}
    atomic_write(blacklist_path(), data)


def is_ip_blacklisted(ip: str) -> bool:
    """检查 IP 是否被拉黑。支持精确匹配和前缀匹配（如 192.168.1.）。"""
    if not ip:
        return False
    for pattern in BLACKLIST:
        if not pattern:
            continue
        if ip == pattern:
            return True
        if pattern.endswith(".") and ip.startswith(pattern):
            return True
        if "/" in pattern:
            # 简单 CIDR 前缀匹配
            try:
                prefix = pattern.rsplit(".", 1)[0]  # e.g., "192.168.1"
                if ip.startswith(prefix + "."):
                    return True
            except Exception:
                pass
    return False


# ---------------------------------------------------------------------------
# 同步核心逻辑
# ---------------------------------------------------------------------------

def merge_record(key: str, incoming: dict, bot_id: str) -> dict:
    """合并上传的记录到云端。

    规则：
      - count 取 max(云端, 上传)（取较大值，避免丢失警告进度）
      - total 取 max(云端, 上传)
      - last_warned 取较新者
      - last_muted_until 取较新者
      - is_muted 由 last_muted_until > now 决定
      - last_reason / sender_name / platform 取较新者
      - sources 记录所有贡献过的 bot_id
    """
    cur = RECORDS.get(key)
    ts = now_ts()
    if cur is None:
        cur = {
            "user_id": incoming.get("user_id", ""),
            "sender_name": incoming.get("sender_name", ""),
            "platform": incoming.get("platform", ""),
            "platform_id": incoming.get("platform_id", ""),
            "count": 0,
            "total": 0,
            "last_warned": 0,
            "last_reason": "",
            "last_muted_until": 0,
            "is_muted": False,
            "updated_by": bot_id,
            "updated_at": ts,
            "created_at": ts,
            "sources": [],
            "admin_rev": 0,   # 管理员修订版本号：admin 改动 +1，强制下发覆盖客户端
        }
        RECORDS[key] = cur

    cur["count"] = max(int(cur.get("count", 0)), int(incoming.get("count", 0) or 0))
    cur["total"] = max(int(cur.get("total", 0)), int(incoming.get("total", 0) or 0))

    if float(incoming.get("last_warned", 0) or 0) > float(cur.get("last_warned", 0) or 0):
        cur["last_warned"] = float(incoming.get("last_warned", 0) or 0)
        cur["last_reason"] = incoming.get("last_reason", "") or cur.get("last_reason", "")
        cur["sender_name"] = incoming.get("sender_name", "") or cur.get("sender_name", "")

    if float(incoming.get("last_muted_until", 0) or 0) > float(cur.get("last_muted_until", 0) or 0):
        cur["last_muted_until"] = float(incoming.get("last_muted_until", 0) or 0)

    cur["is_muted"] = float(cur.get("last_muted_until", 0) or 0) > ts

    # 更新平台字段（保留最完整的信息）
    if incoming.get("platform") and not cur.get("platform"):
        cur["platform"] = incoming.get("platform")
    if incoming.get("platform_id") and not cur.get("platform_id"):
        cur["platform_id"] = incoming.get("platform_id")

    # 记录贡献者
    srcs = cur.get("sources") or []
    if bot_id and bot_id not in srcs:
        srcs.append(bot_id)
    cur["sources"] = srcs

    cur["updated_by"] = bot_id
    cur["updated_at"] = ts
    cur["seq"] = next_seq()
    return cur


def apply_incremental(updates: dict, bot_id: str) -> dict:
    """应用增量更新。

    updates 格式:
      {
        "count_delta": {"<key>": +1, "<key2>": -1, ...},
        "mute_status": {"<key>": {"muted": true/false, "until": ts}, ...},
        "reset_keys": ["<key>", ...]
      }
    返回 {"applied": N, "skipped": M, "details": [...]}
    """
    applied = 0
    skipped = 0
    details = []
    ts = now_ts()

    count_delta = updates.get("count_delta", {}) or {}
    for k, delta in count_delta.items():
        try:
            delta = int(delta)
        except (TypeError, ValueError):
            skipped += 1
            continue
        rec = RECORDS.get(k)
        if rec is None:
            # 云端无此记录，跳过（不能凭空创造负数）
            if delta > 0:
                # 但 +N 可以创建占位记录
                rec = {
                    "user_id": "",
                    "platform_id": "",
                    "count": delta,
                    "total": delta,
                    "last_warned": ts,
                    "last_reason": "由其他 bot 同步",
                    "last_muted_until": 0,
                    "is_muted": False,
                    "updated_by": bot_id,
                    "updated_at": ts,
                    "created_at": ts,
                    "sources": [bot_id] if bot_id else [],
                    "seq": next_seq(),
                }
                RECORDS[k] = rec
                applied += 1
                details.append({"key": k, "action": "created", "delta": delta})
            else:
                skipped += 1
            continue
        new_count = max(0, int(rec.get("count", 0)) + delta)
        rec["count"] = new_count
        rec["updated_by"] = bot_id
        rec["updated_at"] = ts
        rec["seq"] = next_seq()
        applied += 1
        details.append({"key": k, "action": "delta", "delta": delta, "new_count": new_count})

    mute_status = updates.get("mute_status", {}) or {}
    for k, info in mute_status.items():
        if not isinstance(info, dict):
            skipped += 1
            continue
        muted = bool(info.get("muted", False))
        until = float(info.get("until", 0) or 0)
        rec = RECORDS.get(k)
        if rec is None:
            skipped += 1
            continue
        # 只接受比当前更新的禁言状态
        if muted:
            if until > float(rec.get("last_muted_until", 0) or 0):
                rec["last_muted_until"] = until
                rec["is_muted"] = True
                rec["updated_by"] = bot_id
                rec["updated_at"] = ts
                rec["seq"] = next_seq()
                applied += 1
                details.append({"key": k, "action": "mute", "until": until})
            else:
                skipped += 1
        else:
            # 解禁：仅在当前禁言已过期或主动解禁时
            if rec.get("is_muted"):
                rec["is_muted"] = False
                # 不清空 last_muted_until（保留历史）
                rec["updated_by"] = bot_id
                rec["updated_at"] = ts
                rec["seq"] = next_seq()
                applied += 1
                details.append({"key": k, "action": "unmute"})
            else:
                skipped += 1

    reset_keys = updates.get("reset_keys", []) or []
    for k in reset_keys:
        rec = RECORDS.get(k)
        if rec is None:
            skipped += 1
            continue
        rec["count"] = 0
        rec["updated_by"] = bot_id
        rec["updated_at"] = ts
        rec["seq"] = next_seq()
        applied += 1
        details.append({"key": k, "action": "reset"})

    return {"applied": applied, "skipped": skipped, "details": details}


def collect_since(since: float, bot_id: str = "") -> dict:
    """返回 since 之后有更新的记录及特殊记录。"""
    items = []
    for k, rec in RECORDS.items():
        if float(rec.get("updated_at", 0) or 0) > since:
            items.append({"key": k, **rec})
    special_items = [s for s in SPECIAL_RECORDS if float(s.get("time", 0) or 0) > since]
    return {
        "records": items,
        "special_records": special_items,
        "server_time": now_ts(),
        "total_records": len(RECORDS),
        "total_special": len(SPECIAL_RECORDS),
        "bot_id": bot_id,
    }


# ---------------------------------------------------------------------------
# HTTP Handler
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = f"MaliciousCloud/{__VERSION__}"
    protocol_version = "HTTP/1.1"

    # ---- 静默访问日志（自己写日志） ----
    def log_message(self, format, *args):
        pass

    # ---- 通用响应 ----
    def _send_json(self, status: int, obj: dict, extra_headers: dict | None = None) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", ",".join(CONFIG.get("cors_origins", ["*"])))
        self.send_header("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type,X-Client-Token,X-Admin-Token,Authorization")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _send_error_json(self, status: int, message: str) -> None:
        self._send_json(status, {"ok": False, "error": message})

    def _read_body(self) -> tuple[dict | None, str]:
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            length = 0
        if length == 0:
            return {}, "empty body"
        if length > 5 * 1024 * 1024:
            return None, "body too large (max 5MB)"
        try:
            raw = self.rfile.read(length)
            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, dict):
                return None, "body must be a JSON object"
            return data, ""
        except Exception as e:
            return None, f"invalid JSON: {e}"

    # ---- Token 校验 ----
    def _check_client_token(self) -> bool:
        tok = self.headers.get("X-Client-Token", "")
        return bool(tok) and tok == CONFIG.get("client_token")

    def _check_admin_token(self) -> bool:
        # 支持 X-Admin-Token 头 或 Authorization: Bearer <token>
        tok = self.headers.get("X-Admin-Token", "")
        if not tok:
            auth = self.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                tok = auth[7:]
        return bool(tok) and tok == CONFIG.get("admin_token")

    def _check_any_token(self) -> bool:
        """读端点：接受 client_token 或 admin_token。"""
        return self._check_client_token() or self._check_admin_token()

    # ---- 静态文件服务（Web 管理器） ----
    def _serve_static(self, rel_path: str) -> bool:
        """从 web/ 目录提供静态文件。返回 True 表示已处理。"""
        if not rel_path or rel_path == "/":
            rel_path = "/index.html"
        # 防止路径穿越
        safe = rel_path.lstrip("/")
        full = os.path.normpath(os.path.join(WEB_BASE, safe))
        if not full.startswith(WEB_BASE):
            self._send_simple(403, "forbidden")
            return True
        if not os.path.isfile(full):
            return False
        ext = os.path.splitext(full)[1].lower()
        ctype = MIME_TYPES.get(ext, "application/octet-stream")
        try:
            with open(full, "rb") as f:
                body = f.read()
        except Exception as e:
            self._send_simple(500, f"read error: {e}")
            return True
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)
        return True

    def _send_simple(self, status: int, text: str) -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _check_blacklist(self) -> bool:
        """检查客户端 IP 是否在黑名单中。若被拉黑则返回 True 并发送响应。

        注意：健康检查端点（/api/health）不拉黑，避免影响负载均衡。
        """
        ip = self.client_address[0] if self.client_address else ""
        path = self.path or ""
        # 健康检查不拉黑
        if path.startswith("/api/health"):
            return False
        if ip and is_ip_blacklisted(ip):
            log_request("*", path, 403, ip, "blocked by blacklist")
            self._send_simple(403, BLACKLISTED_RESPONSE_TEXT)
            return True
        return False

    # ---- 路由分发 ----
    def do_OPTIONS(self):  # noqa: N802
        self._send_json(HTTPStatus.OK, {"ok": True, "method": "OPTIONS"})

    def do_GET(self):  # noqa: N802
        try:
            # ---- IP 黑名单检查 ----
            if self._check_blacklist():
                return

            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"
            qs = parse_qs(parsed.query)

            # ---- Web 管理器静态文件（无 Token 即可访问，前端自行登录） ----
            if path == "/" or path.startswith("/static/"):
                rel = path.replace("/static/", "/", 1) if path.startswith("/static/") else path
                if self._serve_static(rel):
                    return
                # 静态文件不存在 → 回退到 index.html（SPA）
                if self._serve_static("/index.html"):
                    return
                return self._send_simple(404, "web manager not found")
            if path in ("/app.js", "/style.css", "/favicon.ico"):
                if self._serve_static(path):
                    return
                return self._send_simple(404, "not found")

            if path == "/api/health":
                return self._handle_health()
            if path == "/api/auth_check":
                # 供前端校验 token 是否有效，自动识别类型
                if self._check_admin_token():
                    return self._send_json(HTTPStatus.OK, {"ok": True, "token_type": "admin"})
                if self._check_client_token():
                    return self._send_json(HTTPStatus.OK, {"ok": True, "token_type": "client"})
                return self._send_error_json(HTTPStatus.UNAUTHORIZED, "invalid token")
            if path == "/api/stats":
                if not self._check_any_token():
                    log_request("GET", path, 401, self.client_address[0])
                    return self._send_error_json(HTTPStatus.UNAUTHORIZED, "invalid token")
                return self._handle_stats()
            if path == "/api/records":
                if not self._check_any_token():
                    log_request("GET", path, 401, self.client_address[0])
                    return self._send_error_json(HTTPStatus.UNAUTHORIZED, "invalid token")
                return self._handle_list_records(qs)
            if path == "/api/special":
                if not self._check_any_token():
                    log_request("GET", path, 401, self.client_address[0])
                    return self._send_error_json(HTTPStatus.UNAUTHORIZED, "invalid token")
                return self._handle_list_special(qs)
            if path == "/api/logs":
                # 备案日志：admin 和 client 都可读（详情弹窗数据源）
                if not self._check_any_token():
                    log_request("GET", path, 401, self.client_address[0])
                    return self._send_error_json(HTTPStatus.UNAUTHORIZED, "invalid token")
                return self._handle_list_logs(qs)
            if path == "/api/sync":
                if not self._check_client_token():
                    log_request("GET", path, 401, self.client_address[0])
                    return self._send_error_json(HTTPStatus.UNAUTHORIZED, "invalid client token")
                return self._handle_get_sync(qs)
            if path == "/api/audit_log":
                if not self._check_admin_token():
                    log_request("GET", path, 401, self.client_address[0])
                    return self._send_error_json(HTTPStatus.UNAUTHORIZED, "invalid admin token")
                return self._handle_audit_log(qs)
            if path == "/api/request_log":
                if not self._check_admin_token():
                    log_request("GET", path, 401, self.client_address[0])
                    return self._send_error_json(HTTPStatus.UNAUTHORIZED, "invalid admin token")
                return self._handle_request_log(qs)
            if path == "/api/blacklist":
                # 获取黑名单（admin_token）
                if not self._check_admin_token():
                    log_request("GET", path, 401, self.client_address[0])
                    return self._send_error_json(HTTPStatus.UNAUTHORIZED, "invalid admin token")
                return self._handle_blacklist_list()
            log_request("GET", path, 404, self.client_address[0])
            return self._send_error_json(HTTPStatus.NOT_FOUND, "not found")
        except Exception as e:
            sys.stderr.write(f"[GET error] {e}\n")
            return self._send_error_json(HTTPStatus.INTERNAL_SERVER_ERROR, str(e))

    def do_POST(self):  # noqa: N802
        try:
            # ---- IP 黑名单检查 ----
            if self._check_blacklist():
                return

            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"

            if path == "/api/auth":
                # Web 管理器登录：校验 admin_token
                return self._handle_auth()
            if path == "/api/upload_record":
                if not self._check_client_token():
                    log_request("POST", path, 401, self.client_address[0])
                    return self._send_error_json(HTTPStatus.UNAUTHORIZED, "invalid client token")
                return self._handle_upload_record()
            if path == "/api/upload_special":
                if not self._check_client_token():
                    log_request("POST", path, 401, self.client_address[0])
                    return self._send_error_json(HTTPStatus.UNAUTHORIZED, "invalid client token")
                return self._handle_upload_special()
            if path == "/api/upload_logs":
                # 客户端推送备案日志
                if not self._check_client_token():
                    log_request("POST", path, 401, self.client_address[0])
                    return self._send_error_json(HTTPStatus.UNAUTHORIZED, "invalid client token")
                return self._handle_upload_logs()
            if path == "/api/sync":
                if not self._check_client_token():
                    log_request("POST", path, 401, self.client_address[0])
                    return self._send_error_json(HTTPStatus.UNAUTHORIZED, "invalid client token")
                return self._handle_post_sync()
            if path == "/api/delete_record":
                if not self._check_admin_token():
                    log_request("POST", path, 401, self.client_address[0])
                    return self._send_error_json(HTTPStatus.UNAUTHORIZED, "invalid admin token")
                return self._handle_delete_record()
            if path == "/api/zero_count":
                # 管理员清零（强制下发）
                if not self._check_admin_token():
                    log_request("POST", path, 401, self.client_address[0])
                    return self._send_error_json(HTTPStatus.UNAUTHORIZED, "invalid admin token")
                return self._handle_zero_count()
            if path == "/api/revoke_record":
                # 误判撤回：client_token 鉴权 + bot_id 一致性校验
                if not self._check_client_token():
                    log_request("POST", path, 401, self.client_address[0])
                    return self._send_error_json(HTTPStatus.UNAUTHORIZED, "invalid client token")
                return self._handle_revoke_record()
            if path == "/api/decay":
                # 合法衰减：admin_token 或 client_token 均可（鉴权在 handler 内细分）
                if not (self._check_admin_token() or self._check_client_token()):
                    log_request("POST", path, 401, self.client_address[0])
                    return self._send_error_json(HTTPStatus.UNAUTHORIZED, "invalid token")
                return self._handle_decay()
            if path == "/api/dedup":
                # 手动去重：仅 admin_token
                if not self._check_admin_token():
                    log_request("POST", path, 401, self.client_address[0])
                    return self._send_error_json(HTTPStatus.UNAUTHORIZED, "invalid admin token")
                return self._handle_dedup()
            if path == "/api/blacklist/add":
                # 添加黑名单（admin_token）
                if not self._check_admin_token():
                    log_request("POST", path, 401, self.client_address[0])
                    return self._send_error_json(HTTPStatus.UNAUTHORIZED, "invalid admin token")
                return self._handle_blacklist_add()
            if path == "/api/blacklist/remove":
                # 移除黑名单（admin_token）
                if not self._check_admin_token():
                    log_request("POST", path, 401, self.client_address[0])
                    return self._send_error_json(HTTPStatus.UNAUTHORIZED, "invalid admin token")
                return self._handle_blacklist_remove()
            if path == "/api/delete_old_logs":
                # 管理员删除存放超过 N 天的备案日志
                if not self._check_admin_token():
                    log_request("POST", path, 401, self.client_address[0])
                    return self._send_error_json(HTTPStatus.UNAUTHORIZED, "invalid admin token")
                return self._handle_delete_old_logs()
            log_request("POST", path, 404, self.client_address[0])
            return self._send_error_json(HTTPStatus.NOT_FOUND, "not found")
        except Exception as e:
            sys.stderr.write(f"[POST error] {e}\n")
            return self._send_error_json(HTTPStatus.INTERNAL_SERVER_ERROR, str(e))

    # ---- 各端点实现 ----
    def _handle_health(self):
        with LOCK:
            stats = {
                "ok": True,
                "version": __VERSION__,
                "server_time": now_ts(),
                "records": len(RECORDS),
                "special_records": len(SPECIAL_RECORDS),
                "uptime": now_ts() - float(META.get("created_at", now_ts())),
            }
        log_request("GET", "/api/health", 200, self.client_address[0])
        return self._send_json(HTTPStatus.OK, stats)

    def _handle_stats(self):
        with LOCK:
            muted = sum(1 for r in RECORDS.values() if r.get("is_muted"))
            high = sum(1 for r in RECORDS.values() if int(r.get("count", 0)) > 5)
            bots = set()
            for r in RECORDS.values():
                for s in (r.get("sources") or []):
                    bots.add(s)
            stats = {
                "ok": True,
                "records": len(RECORDS),
                "special_records": len(SPECIAL_RECORDS),
                "logs": len(LOGS),
                "muted_users": muted,
                "high_risk_users": high,
                "bots_contributed": len(bots),
                "bot_ids": sorted(bots),
                "server_time": now_ts(),
                "last_seq": META.get("last_seq", 0),
                "created_at": META.get("created_at", 0),
            }
        log_request("GET", "/api/stats", 200, self.client_address[0])
        return self._send_json(HTTPStatus.OK, stats)

    def _handle_list_records(self, qs):
        try:
            limit = int((qs.get("limit", ["500"])[0]))
        except ValueError:
            limit = 500
        with LOCK:
            items = []
            for k, rec in RECORDS.items():
                items.append({"key": k, **rec})
            items.sort(key=lambda r: (int(r.get("count", 0)), int(r.get("total", 0))), reverse=True)
            data = {"total": len(items), "items": items[:limit]}
        log_request("GET", "/api/records", 200, self.client_address[0])
        return self._send_json(HTTPStatus.OK, data)

    def _handle_list_special(self, qs):
        try:
            limit = int((qs.get("limit", ["500"])[0]))
        except ValueError:
            limit = 500
        with LOCK:
            items = list(reversed(SPECIAL_RECORDS))[:limit]
            by_user = {}
            for it in items:
                uid = str(it.get("user_id", ""))
                by_user.setdefault(uid, []).append(it)
            data = {"total": len(SPECIAL_RECORDS), "items": items, "by_user": by_user}
        log_request("GET", "/api/special", 200, self.client_address[0])
        return self._send_json(HTTPStatus.OK, data)

    def _handle_upload_record(self):
        body, err = self._read_body()
        if err:
            log_request("POST", "/api/upload_record", 400, self.client_address[0], err)
            return self._send_error_json(HTTPStatus.BAD_REQUEST, f"invalid body: {err}")
        bot_id = str(body.get("bot_id", "anonymous")) or "anonymous"
        records = body.get("records") or []
        if not isinstance(records, list):
            return self._send_error_json(HTTPStatus.BAD_REQUEST, "records must be a list")

        max_size = int(CONFIG.get("max_record_size", 100000))
        with LOCK:
            uploaded = 0
            skipped = 0
            for item in records:
                if not isinstance(item, dict):
                    skipped += 1
                    continue
                uid = str(item.get("user_id", ""))
                pid = str(item.get("platform_id", ""))
                if not uid:
                    skipped += 1
                    continue
                k = record_key(pid, uid)
                # ★ 去重：若服务端已存在相同 key 且 last_warned 一致，跳过（以服务器为准）
                existing = RECORDS.get(k)
                if existing is not None:
                    incoming_lw = float(item.get("last_warned", 0) or 0)
                    existing_lw = float(existing.get("last_warned", 0) or 0)
                    if incoming_lw > 0 and incoming_lw == existing_lw:
                        skipped += 1
                        continue
                merge_record(k, item, bot_id)
                uploaded += 1
                if len(RECORDS) > max_size:
                    _evict_old_records(max_size)
            save_records()
        result = {"ok": True, "uploaded": uploaded, "skipped": skipped, "total_cloud": len(RECORDS)}
        audit_log("upload_record", bot_id, {"uploaded": uploaded, "skipped": skipped})
        log_request("POST", "/api/upload_record", 200, self.client_address[0], f"uploaded={uploaded}")
        return self._send_json(HTTPStatus.OK, result)

    def _handle_upload_special(self):
        body, err = self._read_body()
        if err:
            log_request("POST", "/api/upload_special", 400, self.client_address[0], err)
            return self._send_error_json(HTTPStatus.BAD_REQUEST, f"invalid body: {err}")
        bot_id = str(body.get("bot_id", "anonymous")) or "anonymous"
        records = body.get("records") or []
        if not isinstance(records, list):
            return self._send_error_json(HTTPStatus.BAD_REQUEST, "records must be a list")

        max_special = int(CONFIG.get("max_special_records", 10000))
        with LOCK:
            uploaded = 0
            skipped = 0
            # ★ 预建索引：基于 (cloud_bot_id, user_id, platform_id, time, message) 去重
            existing_fingerprints = set()
            for s in SPECIAL_RECORDS:
                fp = _special_fingerprint(s)
                if fp:
                    existing_fingerprints.add(fp)
            for item in records:
                if not isinstance(item, dict):
                    skipped += 1
                    continue
                # ★ 去重：若指纹已存在则跳过
                incoming_fp = _special_fingerprint(item, bot_id)
                if incoming_fp and incoming_fp in existing_fingerprints:
                    skipped += 1
                    continue
                item.setdefault("time", now_ts())
                item.setdefault("time_str", now_str())
                item["cloud_bot_id"] = bot_id
                item["cloud_seq"] = next_seq()
                SPECIAL_RECORDS.append(item)
                if incoming_fp:
                    existing_fingerprints.add(incoming_fp)
                uploaded += 1
            if len(SPECIAL_RECORDS) > max_special:
                SPECIAL_RECORDS[:] = SPECIAL_RECORDS[-max_special:]
            save_special()
        result = {"ok": True, "uploaded": uploaded, "skipped": skipped, "total_cloud": len(SPECIAL_RECORDS)}
        audit_log("upload_special", bot_id, {"uploaded": uploaded, "skipped": skipped})
        log_request("POST", "/api/upload_special", 200, self.client_address[0], f"uploaded={uploaded}, skipped={skipped}")
        return self._send_json(HTTPStatus.OK, result)

    def _handle_get_sync(self, qs):
        try:
            since = float(qs.get("since", ["0"])[0] or 0)
        except ValueError:
            since = 0.0
        bot_id = (qs.get("bot_id", [""])[0] or "")
        with LOCK:
            data = collect_since(since, bot_id)
        log_request("GET", "/api/sync", 200, self.client_address[0], f"since={since}")
        return self._send_json(HTTPStatus.OK, data)

    def _handle_post_sync(self):
        body, err = self._read_body()
        if err:
            log_request("POST", "/api/sync", 400, self.client_address[0], err)
            return self._send_error_json(HTTPStatus.BAD_REQUEST, f"invalid body: {err}")
        bot_id = str(body.get("bot_id", "anonymous")) or "anonymous"
        updates = body.get("updates") or {}
        if not isinstance(updates, dict):
            return self._send_error_json(HTTPStatus.BAD_REQUEST, "updates must be an object")

        # 可选：附带全量上传（同 upload_record）
        records = body.get("records")
        with LOCK:
            uploaded = 0
            skipped = 0
            if isinstance(records, list):
                for item in records:
                    if not isinstance(item, dict):
                        skipped += 1
                        continue
                    uid = str(item.get("user_id", ""))
                    pid = str(item.get("platform_id", ""))
                    if not uid:
                        skipped += 1
                        continue
                    k = record_key(pid, uid)
                    # ★ 去重：若服务端已存在相同 key 且 last_warned 一致，跳过
                    existing = RECORDS.get(k)
                    if existing is not None:
                        incoming_lw = float(item.get("last_warned", 0) or 0)
                        existing_lw = float(existing.get("last_warned", 0) or 0)
                        if incoming_lw > 0 and incoming_lw == existing_lw:
                            skipped += 1
                            continue
                    merge_record(k, item, bot_id)
                    uploaded += 1
            result = apply_incremental(updates, bot_id)
            save_records()
        resp = {
            "ok": True,
            "uploaded": uploaded,
            "records_skipped": skipped,
            "applied": result["applied"],
            "skipped": result["skipped"],
            "details": result["details"][:200],
            "total_cloud": len(RECORDS),
            "server_time": now_ts(),
        }
        audit_log("post_sync", bot_id, {"uploaded": uploaded, "records_skipped": skipped, "applied": result["applied"]})
        log_request("POST", "/api/sync", 200, self.client_address[0],
                    f"uploaded={uploaded}, records_skipped={skipped}, applied={result['applied']}")
        return self._send_json(HTTPStatus.OK, resp)

    def _handle_delete_record(self):
        body, err = self._read_body()
        if err:
            log_request("POST", "/api/delete_record", 400, self.client_address[0], err)
            return self._send_error_json(HTTPStatus.BAD_REQUEST, f"invalid body: {err}")
        bot_id = str(body.get("bot_id", "admin")) or "admin"
        keys = body.get("keys") or []
        if isinstance(keys, str):
            keys = [keys]
        if not isinstance(keys, list) or not keys:
            # 支持按 user_id 删除
            uid = str(body.get("user_id", ""))
            pid = str(body.get("platform_id", ""))
            if uid:
                keys = [record_key(pid, uid)]
            else:
                return self._send_error_json(HTTPStatus.BAD_REQUEST, "missing keys/user_id")
        deleted = []
        not_found = []
        with LOCK:
            for k in keys:
                if k in RECORDS:
                    rec = RECORDS.pop(k)
                    deleted.append({"key": k, "user_id": rec.get("user_id")})
                else:
                    not_found.append(k)
            save_records()
        audit_log("delete_record", bot_id, {"deleted": deleted, "not_found": not_found})
        log_request("POST", "/api/delete_record", 200, self.client_address[0],
                    f"deleted={len(deleted)}")
        return self._send_json(HTTPStatus.OK, {
            "ok": True,
            "deleted": deleted,
            "not_found": not_found,
            "deleted_count": len(deleted),
        })

    def _handle_auth(self):
        """Web 管理器登录：接受 admin_token 或 client_token，自动识别类型。"""
        body, err = self._read_body()
        if err:
            return self._send_error_json(HTTPStatus.BAD_REQUEST, f"invalid body: {err}")
        token = str(body.get("token", "") or "")
        if not token:
            return self._send_error_json(HTTPStatus.BAD_REQUEST, "missing token")
        admin_tok = CONFIG.get("admin_token")
        client_tok = CONFIG.get("client_token")
        if token == admin_tok:
            log_request("POST", "/api/auth", 200, self.client_address[0], "login_admin")
            audit_log("login", "web_admin", {"client": self.client_address[0]})
            return self._send_json(HTTPStatus.OK, {"ok": True, "token_type": "admin"})
        if token == client_tok:
            log_request("POST", "/api/auth", 200, self.client_address[0], "login_client")
            audit_log("login", "web_client", {"client": self.client_address[0]})
            return self._send_json(HTTPStatus.OK, {"ok": True, "token_type": "client"})
        log_request("POST", "/api/auth", 401, self.client_address[0], "login_fail")
        return self._send_error_json(HTTPStatus.UNAUTHORIZED, "invalid token")

    def _handle_revoke_record(self):
        """误判撤回：校验 bot_id 在记录 sources 中，递减 count。

        body: {bot_id, record_key, log_id, message, reason}
        """
        body, err = self._read_body()
        if err:
            log_request("POST", "/api/revoke_record", 400, self.client_address[0], err)
            return self._send_error_json(HTTPStatus.BAD_REQUEST, f"invalid body: {err}")
        bot_id = str(body.get("bot_id", "")) or ""
        record_key = str(body.get("record_key", "")) or ""
        log_id = str(body.get("log_id", "")) or ""
        message = str(body.get("message", "")) or ""
        reason = str(body.get("reason", "")) or ""
        if not record_key or not bot_id:
            return self._send_error_json(HTTPStatus.BAD_REQUEST, "missing bot_id/record_key")

        with LOCK:
            rec = RECORDS.get(record_key)
            if rec is None:
                log_request("POST", "/api/revoke_record", 404, self.client_address[0],
                            f"key={record_key}")
                return self._send_error_json(HTTPStatus.NOT_FOUND, "record not found")
            # 校验：bot_id 必须在该记录的 sources 中（即上传该警告的 bot 才能撤回）
            sources = rec.get("sources") or []
            if bot_id not in sources:
                log_request("POST", "/api/revoke_record", 403, self.client_address[0],
                            f"bot_id={bot_id} not in sources")
                audit_log("revoke_denied", bot_id, {
                    "record_key": record_key,
                    "reason": "bot_id not in sources",
                    "sources": sources,
                })
                return self._send_error_json(
                    HTTPStatus.FORBIDDEN,
                    f"bot_id '{bot_id}' not in record sources {sources}",
                )
            old_count = int(rec.get("count", 0) or 0)
            new_count = max(0, old_count - 1)
            rec["count"] = new_count
            rec["updated_by"] = bot_id
            rec["updated_at"] = now_ts()
            rec["seq"] = next_seq()
            # 记录撤回标记
            revokes = rec.setdefault("revokes", [])
            revokes.append({
                "bot_id": bot_id,
                "log_id": log_id,
                "message": message[:500],
                "reason": reason,
                "time": now_ts(),
                "old_count": old_count,
                "new_count": new_count,
            })
            save_records()

        audit_log("revoke_record", bot_id, {
            "record_key": record_key,
            "log_id": log_id,
            "old_count": old_count,
            "new_count": new_count,
            "reason": reason,
        })
        log_request("POST", "/api/revoke_record", 200, self.client_address[0],
                    f"key={record_key} {old_count}->{new_count}")
        return self._send_json(HTTPStatus.OK, {
            "ok": True,
            "revoked": True,
            "record_key": record_key,
            "old_count": old_count,
            "new_count": new_count,
        })

    def _handle_decay(self):
        """合法衰减：批量将指定 key 的 count -1。

        鉴权：admin_token → 全局衰减权（跳过 sources 校验）；
              client_token → 强制校验 bot_id 在 record.sources 中（仅能衰减本 bot 上传的数据）。
        body: {"bot_id": "...", "keys": ["k1", "k2", ...]}
        """
        body, err = self._read_body()
        if err:
            log_request("POST", "/api/decay", 400, self.client_address[0], err)
            return self._send_error_json(HTTPStatus.BAD_REQUEST, f"invalid body: {err}")
        bot_id = str(body.get("bot_id", "")) or ""
        keys = body.get("keys") or []
        if isinstance(keys, str):
            keys = [keys]
        if not isinstance(keys, list) or not keys:
            return self._send_error_json(HTTPStatus.BAD_REQUEST, "missing keys")
        is_admin = self._check_admin_token()
        decayed = []
        denied = []
        not_found = []
        ts = now_ts()
        with LOCK:
            for k in keys:
                rec = RECORDS.get(k)
                if rec is None:
                    not_found.append(k)
                    continue
                # 鉴权：非 admin 时校验 bot_id 在 sources 中
                if not is_admin:
                    sources = rec.get("sources") or []
                    if bot_id not in sources:
                        denied.append(k)
                        audit_log("decay_denied", bot_id, {
                            "record_key": k, "reason": "bot_id not in sources", "sources": sources,
                        })
                        continue
                old_count = int(rec.get("count", 0) or 0)
                new_count = max(0, old_count - 1)
                rec["count"] = new_count
                rec["updated_by"] = bot_id if not is_admin else "admin"
                rec["updated_at"] = ts
                rec["seq"] = next_seq()
                decayed.append({"key": k, "old_count": old_count, "new_count": new_count})
            if decayed:
                save_records()
        audit_log("decay", bot_id if not is_admin else "admin", {
            "decayed": len(decayed), "denied": len(denied), "not_found": len(not_found),
        })
        log_request("POST", "/api/decay", 200, self.client_address[0],
                    f"decayed={len(decayed)}, denied={len(denied)}, not_found={len(not_found)}")
        return self._send_json(HTTPStatus.OK, {
            "ok": True, "decayed": decayed, "denied": denied, "not_found": not_found,
        })

    def _handle_upload_logs(self):
        """客户端推送备案日志（个体警告事件）。按 log_id 去重。
        body: {"bot_id": "...", "logs": [{...}, ...]}
        """
        body, err = self._read_body()
        if err:
            log_request("POST", "/api/upload_logs", 400, self.client_address[0], err)
            return self._send_error_json(HTTPStatus.BAD_REQUEST, f"invalid body: {err}")
        bot_id = str(body.get("bot_id", "anonymous")) or "anonymous"
        logs = body.get("logs") or []
        if not isinstance(logs, list):
            return self._send_error_json(HTTPStatus.BAD_REQUEST, "logs must be a list")
        uploaded = 0
        skipped = 0
        ts = now_ts()
        with LOCK:
            for item in logs:
                if not isinstance(item, dict):
                    skipped += 1
                    continue
                lid = str(item.get("log_id", ""))
                if not lid:
                    skipped += 1
                    continue
                if lid in LOGS_INDEX:
                    skipped += 1
                    continue
                item["cloud_bot_id"] = bot_id
                item["cloud_seq"] = next_seq()
                item["cloud_uploaded_at"] = ts
                LOGS.append(item)
                LOGS_INDEX.add(lid)
                uploaded += 1
            trim_logs()
            if uploaded > 0:
                save_logs()
        audit_log("upload_logs", bot_id, {"uploaded": uploaded, "skipped": skipped})
        log_request("POST", "/api/upload_logs", 200, self.client_address[0],
                    f"uploaded={uploaded}, skipped={skipped}")
        return self._send_json(HTTPStatus.OK, {
            "ok": True, "uploaded": uploaded, "skipped": skipped, "total_cloud": len(LOGS),
        })

    def _handle_list_logs(self, qs):
        """列出备案日志，支持按 user_id/platform_id 过滤。"""
        try:
            limit = int(qs.get("limit", ["200"])[0] or 200)
        except ValueError:
            limit = 200
        try:
            offset = int(qs.get("offset", ["0"])[0] or 0)
        except ValueError:
            offset = 0
        limit = max(1, min(limit, 1000))
        offset = max(0, offset)
        uid = (qs.get("user_id", [""])[0] or "").strip()
        pid = (qs.get("platform_id", [""])[0] or "").strip()
        with LOCK:
            items = list(LOGS)
        # 倒序（最新在前）
        items.reverse()
        if uid:
            items = [l for l in items if str(l.get("user_id", "")) == uid]
        if pid:
            items = [l for l in items if str(l.get("platform_id", "")) == pid]
        total = len(items)
        items = items[offset: offset + limit]
        log_request("GET", "/api/logs", 200, self.client_address[0],
                    f"uid={uid}, pid={pid}, total={total}")
        return self._send_json(HTTPStatus.OK, {"total": total, "items": items})

    def _handle_zero_count(self):
        """管理员清零：将指定 key 的 count 设为 0 并 bump admin_rev（强制下发）。
        body: {"keys": ["k1", ...]} 或 {"key": "k1"}
        """
        body, err = self._read_body()
        if err:
            log_request("POST", "/api/zero_count", 400, self.client_address[0], err)
            return self._send_error_json(HTTPStatus.BAD_REQUEST, f"invalid body: {err}")
        keys = body.get("keys") or []
        if isinstance(keys, str):
            keys = [keys]
        if not isinstance(keys, list) or not keys:
            single = body.get("key")
            if single:
                keys = [single]
            else:
                return self._send_error_json(HTTPStatus.BAD_REQUEST, "missing keys/key")
        zeroed = []
        skipped = 0
        ts = now_ts()
        with LOCK:
            for k in keys:
                rec = RECORDS.get(k)
                if rec is None:
                    skipped += 1
                    continue
                old_count = int(rec.get("count", 0) or 0)
                rec["count"] = 0
                rec["admin_rev"] = int(rec.get("admin_rev", 0) or 0) + 1
                rec["updated_by"] = "admin"
                rec["updated_at"] = ts
                rec["seq"] = next_seq()
                zeroed.append({"key": k, "old_count": old_count})
            if zeroed:
                save_records()
        audit_log("zero_count", "admin", {"zeroed": zeroed, "skipped": skipped})
        log_request("POST", "/api/zero_count", 200, self.client_address[0],
                    f"zeroed={len(zeroed)}, skipped={skipped}")
        return self._send_json(HTTPStatus.OK, {
            "ok": True, "zeroed": zeroed, "skipped": skipped,
        })

    def _handle_delete_old_logs(self):
        """管理员删除存放超过指定天数的备案日志。
        body 可选: {"days": 7}（默认 7）
        """
        global LOGS_INDEX
        body, err = self._read_body()
        if err:
            # 允许空 body
            body = {}
        try:
            days = int((body or {}).get("days", 7) or 7)
        except (TypeError, ValueError):
            days = 7
        days = max(1, days)
        cutoff = now_ts() - days * 86400
        with LOCK:
            old_len = len(LOGS)
            kept = [l for l in LOGS if float(l.get("time", 0) or 0) >= cutoff]
            removed = old_len - len(kept)
            LOGS[:] = kept
            # 重建索引
            LOGS_INDEX = {str(l.get("log_id", "")) for l in LOGS if l.get("log_id")}
            if removed > 0:
                save_logs()
        audit_log("delete_old_logs", "admin", {"removed": removed, "days": days, "remaining": len(LOGS)})
        log_request("POST", "/api/delete_old_logs", 200, self.client_address[0],
                    f"removed={removed}, remaining={len(LOGS)}")
        return self._send_json(HTTPStatus.OK, {
            "ok": True, "removed": removed, "remaining": len(LOGS),
        })

    def _handle_dedup(self):
        """手动去重：支持 records 和 special 两种类型。

        - records: 清理 count=0、未禁言、last_warned 超过 30 天的僵尸记录
        - special: 按指纹去重，保留首次出现，移除后续重复项（不删除非重复记录）
        """
        body, err = self._read_body()
        if err:
            return self._send_error_json(HTTPStatus.BAD_REQUEST, f"invalid body: {err}")
        bot_id = str(body.get("bot_id", "admin")) or "admin"
        dedup_type = str(body.get("type", "") or "")

        result = {"ok": True, "records": {}, "special": {}}

        with LOCK:
            # ---- 普通记录去重 ----
            if dedup_type in ("", "records"):
                now = time.time()
                stale_threshold = 30 * 86400  # 30 天
                removed_records = []
                for k, rec in list(RECORDS.items()):
                    count = int(rec.get("count", 0) or 0)
                    is_muted = bool(rec.get("is_muted", False))
                    last_warned = float(rec.get("last_warned", 0) or 0)
                    # 僵尸记录判定：count=0 且未禁言 且 last_warned 已过期
                    if count <= 0 and not is_muted and (now - last_warned) > stale_threshold:
                        removed_records.append({
                            "key": k,
                            "user_id": rec.get("user_id", ""),
                            "count": count,
                            "is_muted": is_muted,
                            "last_warned": last_warned,
                        })
                        del RECORDS[k]
                if removed_records:
                    save_records()
                result["records"] = {
                    "removed": len(removed_records),
                    "total_before": len(RECORDS) + len(removed_records),
                    "total_after": len(RECORDS),
                }

            # ---- 特殊记录去重 ----
            if dedup_type in ("", "special"):
                seen_fps = set()
                kept = []
                removed_special = 0
                for item in SPECIAL_RECORDS:
                    fp = _special_fingerprint(item)
                    if fp and fp in seen_fps:
                        removed_special += 1
                        continue
                    if fp:
                        seen_fps.add(fp)
                    kept.append(item)
                if removed_special > 0:
                    SPECIAL_RECORDS[:] = kept
                    save_special()
                result["special"] = {
                    "removed": removed_special,
                    "total_before": len(SPECIAL_RECORDS) + removed_special,
                    "total_after": len(SPECIAL_RECORDS),
                }

        # 清理空的 result 字段
        if dedup_type == "records":
            del result["special"]
        elif dedup_type == "special":
            del result["records"]

        audit_log("dedup", bot_id, result)
        log_request("POST", "/api/dedup", 200, self.client_address[0],
                    f"type={dedup_type} records_removed={result.get('records', {}).get('removed', 0)} special_removed={result.get('special', {}).get('removed', 0)}")
        return self._send_json(HTTPStatus.OK, result)

    # ---- IP 黑名单管理 ----

    def _handle_blacklist_list(self):
        """获取当前黑名单列表。"""
        with LOCK:
            items = list(BLACKLIST)
        log_request("GET", "/api/blacklist", 200, self.client_address[0])
        return self._send_json(HTTPStatus.OK, {"ok": True, "items": items, "total": len(items)})

    def _handle_blacklist_add(self):
        """添加 IP 到黑名单。body: {"ip": "192.168.1.1"}"""
        body, err = self._read_body()
        if err:
            return self._send_error_json(HTTPStatus.BAD_REQUEST, f"invalid body: {err}")
        ip = str(body.get("ip", "") or "").strip()
        if not ip:
            return self._send_error_json(HTTPStatus.BAD_REQUEST, "缺少 ip 参数")
        with LOCK:
            if ip not in BLACKLIST:
                BLACKLIST.append(ip)
                save_blacklist()
                audit_log("blacklist_add", self.client_address[0], {"ip": ip})
        log_request("POST", "/api/blacklist/add", 200, self.client_address[0], f"ip={ip}")
        return self._send_json(HTTPStatus.OK, {"ok": True, "ip": ip, "added": True})

    def _handle_blacklist_remove(self):
        """从黑名单移除 IP。body: {"ip": "192.168.1.1"}"""
        body, err = self._read_body()
        if err:
            return self._send_error_json(HTTPStatus.BAD_REQUEST, f"invalid body: {err}")
        ip = str(body.get("ip", "") or "").strip()
        if not ip:
            return self._send_error_json(HTTPStatus.BAD_REQUEST, "缺少 ip 参数")
        removed = False
        with LOCK:
            if ip in BLACKLIST:
                BLACKLIST.remove(ip)
                save_blacklist()
                removed = True
                audit_log("blacklist_remove", self.client_address[0], {"ip": ip})
        log_request("POST", "/api/blacklist/remove", 200, self.client_address[0], f"ip={ip}")
        return self._send_json(HTTPStatus.OK, {"ok": True, "ip": ip, "removed": removed})

    def _handle_audit_log(self, qs):
        try:
            limit = int(qs.get("limit", ["500"])[0])
        except ValueError:
            limit = 500
        limit = max(1, min(limit, 5000))
        path = os.path.join(LOG_DIR, AUDIT_LOG)
        items = read_jsonl(path, limit)
        log_request("GET", "/api/audit_log", 200, self.client_address[0])
        return self._send_json(HTTPStatus.OK, {"total": len(items), "items": items})

    def _handle_request_log(self, qs):
        try:
            limit = int(qs.get("limit", ["500"])[0])
        except ValueError:
            limit = 500
        limit = max(1, min(limit, 5000))
        path = os.path.join(LOG_DIR, REQUEST_LOG)
        items = read_jsonl(path, limit)
        log_request("GET", "/api/request_log", 200, self.client_address[0])
        return self._send_json(HTTPStatus.OK, {"total": len(items), "items": items})


def _evict_old_records(max_size: int) -> None:
    """当记录数超过上限时，淘汰 count=0 且未禁言的最旧记录。"""
    candidates = [
        (k, r) for k, r in RECORDS.items()
        if int(r.get("count", 0)) == 0 and not r.get("is_muted", False)
    ]
    candidates.sort(key=lambda kv: float(kv[1].get("updated_at", 0) or 0))
    need_remove = len(RECORDS) - max_size
    for k, _ in candidates[:need_remove]:
        RECORDS.pop(k, None)


# ---------------------------------------------------------------------------
# 启动
# ---------------------------------------------------------------------------

def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def main():
    global CONFIG, DATA_DIR, LOG_DIR
    parser = argparse.ArgumentParser(description="恶意消息检测插件 - 云同步服务端")
    parser.add_argument("--config", default=CONFIG_PATH_DEFAULT, help="配置文件路径")
    parser.add_argument("--host", default=None, help="监听地址（覆盖配置）")
    parser.add_argument("--port", type=int, default=None, help="监听端口（覆盖配置）")
    args = parser.parse_args()

    cfg_path = args.config
    if not os.path.isabs(cfg_path):
        # 相对路径以脚本所在目录为基准
        cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), cfg_path)

    if not os.path.exists(cfg_path):
        sys.stderr.write(f"[FATAL] 配置文件不存在: {cfg_path}\n")
        sys.stderr.write("请复制 config.json 并修改 token 后再启动。\n")
        sys.exit(2)

    CONFIG = load_config(cfg_path)
    base_dir = os.path.dirname(os.path.abspath(__file__))
    DATA_DIR = CONFIG.get("data_dir", "data")
    if not os.path.isabs(DATA_DIR):
        DATA_DIR = os.path.join(base_dir, DATA_DIR)
    LOG_DIR = CONFIG.get("log_dir", "logs")
    if not os.path.isabs(LOG_DIR):
        LOG_DIR = os.path.join(base_dir, LOG_DIR)
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)

    # 校验 token 是否已修改
    if CONFIG.get("client_token", "").startswith("CHANGE_ME"):
        sys.stderr.write(
            "[WARN] client_token 仍是默认值，请修改 config.json！\n"
            "      未修改将允许任何人上传数据。\n"
        )
    if CONFIG.get("admin_token", "").startswith("CHANGE_ME"):
        sys.stderr.write(
            "[WARN] admin_token 仍是默认值，请修改 config.json！\n"
            "      未修改将允许任何人删除记录。\n"
        )

    load_data()
    load_blacklist()
    if not META.get("created_at"):
        META["created_at"] = now_ts()
        save_records()

    host = args.host or CONFIG.get("host", "0.0.0.0")
    port = args.port or int(CONFIG.get("port", 8765))

    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    print(f"[MaliciousCloud v{__VERSION__}] 监听 http://{host}:{port}")
    print(f"  数据目录: {DATA_DIR}")
    print(f"  日志目录: {LOG_DIR}")
    print(f"  记录数:   {len(RECORDS)}")
    print(f"  特殊记录: {len(SPECIAL_RECORDS)}")
    print(f"  健康检查: curl http://{host}:{port}/api/health")
    print("按 Ctrl+C 停止。")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[MaliciousCloud] 正在停止…")
    finally:
        with LOCK:
            save_records()
            save_special()
        server.server_close()
        print("[MaliciousCloud] 已停止。")


if __name__ == "__main__":
    main()
