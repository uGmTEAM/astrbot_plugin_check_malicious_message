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

__VERSION__ = "1.1.0"
CONFIG_PATH_DEFAULT = "config.json"
RECORDS_FILE = "records.json"
SPECIAL_FILE = "special_records.json"
AUDIT_LOG = "audit.log.jsonl"
REQUEST_LOG = "request.log.jsonl"

# ---------------------------------------------------------------------------
# 全局状态（受 LOCK 保护）
# ---------------------------------------------------------------------------

LOCK = threading.RLock()
CONFIG: dict = {}
RECORDS: dict[str, dict] = {}
SPECIAL_RECORDS: list[dict] = []
META: dict = {"created_at": 0, "last_seq": 0}
DATA_DIR = "data"
LOG_DIR = "logs"


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

def now_ts() -> float:
    return time.time()


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def record_key(platform_id: str, user_id: str) -> str:
    return f"{platform_id or ''}:{user_id or ''}"


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


# ---------------------------------------------------------------------------
# 持久化
# ---------------------------------------------------------------------------

def records_path() -> str:
    return os.path.join(DATA_DIR, RECORDS_FILE)


def special_path() -> str:
    return os.path.join(DATA_DIR, SPECIAL_FILE)


def load_data() -> None:
    global RECORDS, SPECIAL_RECORDS, META
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


def save_records() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    data = {"records": RECORDS, "meta": META, "version": __VERSION__}
    atomic_write(records_path(), data)


def save_special() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    data = {"special_records": SPECIAL_RECORDS, "meta": {"updated_at": now_ts()}}
    atomic_write(special_path(), data)


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
        self.send_header("Access-Control-Allow-Headers", "Content-Type,X-Client-Token,X-Admin-Token")
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
        tok = self.headers.get("X-Admin-Token", "")
        return bool(tok) and tok == CONFIG.get("admin_token")

    # ---- 路由分发 ----
    def do_OPTIONS(self):  # noqa: N802
        self._send_json(HTTPStatus.OK, {"ok": True, "method": "OPTIONS"})

    def do_GET(self):  # noqa: N802
        try:
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"
            qs = parse_qs(parsed.query)

            if path == "/api/health":
                return self._handle_health()
            if path == "/api/stats":
                if not self._check_client_token():
                    log_request("GET", path, 401, self.client_address[0])
                    return self._send_error_json(HTTPStatus.UNAUTHORIZED, "invalid client token")
                return self._handle_stats()
            if path == "/api/records":
                if not self._check_client_token():
                    log_request("GET", path, 401, self.client_address[0])
                    return self._send_error_json(HTTPStatus.UNAUTHORIZED, "invalid client token")
                return self._handle_list_records(qs)
            if path == "/api/special":
                if not self._check_client_token():
                    log_request("GET", path, 401, self.client_address[0])
                    return self._send_error_json(HTTPStatus.UNAUTHORIZED, "invalid client token")
                return self._handle_list_special(qs)
            if path == "/api/sync":
                if not self._check_client_token():
                    log_request("GET", path, 401, self.client_address[0])
                    return self._send_error_json(HTTPStatus.UNAUTHORIZED, "invalid client token")
                return self._handle_get_sync(qs)
            log_request("GET", path, 404, self.client_address[0])
            return self._send_error_json(HTTPStatus.NOT_FOUND, "not found")
        except Exception as e:
            sys.stderr.write(f"[GET error] {e}\n")
            return self._send_error_json(HTTPStatus.INTERNAL_SERVER_ERROR, str(e))

    def do_POST(self):  # noqa: N802
        try:
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"

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
                merge_record(k, item, bot_id)
                uploaded += 1
                if len(RECORDS) > max_size:
                    # 超出上限：淘汰 count=0 且未禁言的最旧记录
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
            for item in records:
                if not isinstance(item, dict):
                    continue
                item.setdefault("time", now_ts())
                item.setdefault("time_str", now_str())
                item["cloud_bot_id"] = bot_id
                item["cloud_seq"] = next_seq()
                SPECIAL_RECORDS.append(item)
                uploaded += 1
            if len(SPECIAL_RECORDS) > max_special:
                SPECIAL_RECORDS[:] = SPECIAL_RECORDS[-max_special:]
            save_special()
        result = {"ok": True, "uploaded": uploaded, "total_cloud": len(SPECIAL_RECORDS)}
        audit_log("upload_special", bot_id, {"uploaded": uploaded})
        log_request("POST", "/api/upload_special", 200, self.client_address[0], f"uploaded={uploaded}")
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
            if isinstance(records, list):
                for item in records:
                    if not isinstance(item, dict):
                        continue
                    uid = str(item.get("user_id", ""))
                    pid = str(item.get("platform_id", ""))
                    if not uid:
                        continue
                    k = record_key(pid, uid)
                    merge_record(k, item, bot_id)
                    uploaded += 1
            result = apply_incremental(updates, bot_id)
            save_records()
        resp = {
            "ok": True,
            "uploaded": uploaded,
            "applied": result["applied"],
            "skipped": result["skipped"],
            "details": result["details"][:200],
            "total_cloud": len(RECORDS),
            "server_time": now_ts(),
        }
        audit_log("post_sync", bot_id, {"uploaded": uploaded, "applied": result["applied"]})
        log_request("POST", "/api/sync", 200, self.client_address[0],
                    f"applied={result['applied']}")
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
