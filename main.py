"""
astrbot_plugin_check_malicious_message
通过调用大模型判断用户消息是否含有严重恶意内容（辱骂/人身攻击/骚扰/威胁/诈骗等），
检测到时自动发出警告（以 LLM 当前人格的语气生成），并记录每人的被警告次数 x：
  - 当 x 超过阈值（默认 5）且机器人为群管理员时，自动禁言 10*x 分钟；
  - 私聊或机器人非管理员的群仅累计 x，不尝试禁言；
  - 每 2 小时所有人的 x 自动 -1；
  - 通过插件页面实时展示每个人的 x 次数。

v1.0.1 新增功能：
  - 刷屏检测：单群单人连续发送多条消息时判断是否为无意义内容并决定是否警告；
  - 防误判：首次判定为恶意时结合最近本群消息进行二次判定；
  - 群管理员/群主豁免警告（但仍记录并增加 x）；
  - 跨群禁言：用户在一个群被禁言后自动在其他群也禁言；
  - 特殊记录页面：政治敏感/违法内容单独归档，按人分类以便举报；
  - 超时记录页面：标准记录超过 7 天后归档至超时记录，可一键清理；
  - 每日总结：自动归档超时记录并生成每日统计。

依赖 AstrBot >= 4.5.7 的 LLM 调用接口（context.llm_generate / get_current_chat_provider_id）。
"""

import asyncio
import json
import os
import re
import time
import urllib.error
import urllib.request
import uuid
from typing import Any, Optional

from astrbot.api import AstrBotConfig, logger
from astrbot.api.event import AstrMessageEvent, MessageEventResult, filter
from astrbot.api.star import Context, Star
from astrbot.api.web import error_response, json_response, request

PLUGIN_NAME = "astrbot_plugin_check_malicious_message"

# 默认判定提示词（与 _conf_schema.json 中保持一致，作为兜底）
DEFAULT_JUDGE_PROMPT = (
    "你是一个内容安全审核助手。请判断用户发送的消息是否含有【严重】恶意内容。\n\n"
    "判定为严重恶意的标准（满足任一即可）：\n"
    "1. 严重辱骂、人身攻击、侮辱性、贬损性言语\n"
    "2. 骚扰、恐吓、威胁他人人身或财产安全\n"
    "3. 诈骗、诱导转账汇款、钓鱼链接、虚假中奖\n"
    "4. 煽动仇恨、歧视、暴力、自残自杀\n"
    "5. 散布违法信息（黄赌毒、暴恐、违禁品交易等）\n\n"
    "以下情况【不】判定为严重恶意：\n"
    "- 普通调侃、玩笑、轻微吐槽、阴阳怪气\n"
    "- 正常讨论、争论、表达不满或不同意见\n"
    "- 单独的表情符号、语气词\n"
    "- 不带恶意的网络用语\n\n"
    "请严格只输出如下 JSON，不要输出任何其他文字或解释：\n"
    '{"malicious": true, "reason": "简要原因，不超过30字"}\n'
    "或\n"
    '{"malicious": false, "reason": "无"}'
)

DEFAULT_WARN_MESSAGE = (
    "⚠️ {sender}，你发送的消息被判定为含有严重恶意内容"
    "（辱骂/人身攻击/骚扰/威胁/诈骗等），请遵守群规，文明发言。"
    "多次违规可能被禁言或移出。当前累计警告次数：{x}。"
)

DECAY_INTERVAL = 2 * 3600  # 每 2 小时衰减一次
ROLE_CACHE_TTL = 600  # 机器人群角色缓存 10 分钟
TARGET_ROLE_CACHE_TTL = 300  # 目标用户群角色缓存 5 分钟
SPAM_TRACKER_MAX = 20  # 每用户每群保留的最近消息条数
RECENT_MSG_MAX = 20  # 每用户每群保留的最近文本消息条数（防误判用）
ARCHIVE_CHECK_INTERVAL = 6 * 3600  # 超时归档检查间隔（6 小时）
DATA_FILENAME = "warning_data.json"

# ---- 云同步相关 ----
CLOUD_DEFAULT_INTERVAL = 300  # 默认同步间隔（5 分钟）
CLOUD_HTTP_TIMEOUT = 15  # HTTP 请求超时（秒）
CLOUD_MAX_PUSH_RECORDS = 500  # 单次推送上限
CLOUD_USER_AGENT = "MaliciousCloudClient/1.1.0"


class CheckMaliciousMessagePlugin(Star):
    """调用大模型检测严重恶意消息，累计警告次数并按人格语气警告 / 按需禁言。"""

    def __init__(self, context: Context, config: AstrBotConfig):
        super().__init__(context)
        self.config = config
        # 警告记录: {key: {user_id, sender_name, platform, platform_id, count, total,
        #                  last_warned, last_reason, last_muted_until}}
        self._records: dict[str, dict] = {}
        # 备案日志: 每条记录被警告的消息内容与上下文
        self._logs: list[dict] = []
        # 特殊记录: 政治敏感/违法内容，按人分类归档
        self._special_records: list[dict] = []
        # 超时记录: 标准备案记录超过 archive_timeout_days 后转移至此
        self._timeout_archive: list[dict] = []
        # 每日总结历史
        self._daily_summaries: list[dict] = []
        # 误判撤回记录：被标记为误判的消息，检测前跳过以免再次误判
        self._false_positives: list[dict] = []
        self._meta: dict = {
            "last_decrement": time.time(),
            "last_archive_check": 0.0,
            "last_daily_summary": 0.0,
        }
        # 用户级警告冷却记录: {key: 上次警告时间戳}
        self._cooldowns: dict[str, float] = {}
        # 机器人群角色缓存: {(platform_id, group_id): (role, expire_ts)}
        self._bot_role_cache: dict[tuple[str, str], tuple[str, float]] = {}
        # 目标用户群角色缓存: {(platform_id, group_id, user_id): (role, expire_ts)}
        self._target_role_cache: dict[tuple[str, str, str], tuple[str, float]] = {}
        # 刷屏追踪: {(platform_id, group_id, user_id): [timestamps]}
        self._spam_tracker: dict[tuple[str, str, str], list[float]] = {}
        # 最近文本消息（防误判用）: {(platform_id, group_id, user_id): [str]}
        self._recent_group_msgs: dict[tuple[str, str, str], list[str]] = {}
        self._data_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), DATA_FILENAME)
        self._decrement_task: Optional[asyncio.Task] = None
        self._archive_task: Optional[asyncio.Task] = None
        self._cloud_task: Optional[asyncio.Task] = None
        # 云同步状态（持久化到 warning_data.json 的 "cloud" 字段）
        self._cloud: dict = {
            "bot_id": "",
            "last_sync_ts": 0.0,        # 上次成功同步的时间戳
            "last_attempt_ts": 0.0,      # 上次尝试同步的时间戳（用于倒计时和循环触发）
            "last_pull_ts": 0.0,        # 上次拉取基准（since 参数）
            "last_push_ts": 0.0,        # 上次推送时间戳
            "last_error": "",
            "last_error_ts": 0.0,
            "sync_count": 0,            # 累计同步次数
            "push_count": 0,            # 累计推送次数
            "pull_count": 0,            # 累计拉取次数
            "error_count": 0,           # 累计错误次数
            "last_uploaded_records": 0, # 上次上传的记录数
            "last_pulled_records": 0,    # 上次拉取的记录数
            "last_pulled_special": 0,   # 上次拉取的特殊记录数
            "last_log_upload_ts": 0.0,  # 备案日志上传水位（仅上传 time > 此值的日志）
        }
        # 云同步进行中标志（避免重入与回环同步）
        self._cloud_syncing = False
        # 待推送队列：在警告发生时累积，由后台任务统一推送
        self._cloud_pending_push: set[str] = set()  # 待推送记录的 key 集合
        self._cloud_pending_special: int = 0  # 待推送的特殊记录条数
        # 待重试的全局合法衰减标志（_cloud_push_decay 失败时置 True，full_sync 重试）
        self._cloud_pending_global_decay: bool = False

        # 后台任务健康监控（验证计数器 + 心跳时间戳）
        # 用于检测并自愈「循环卡死 / 任务静默退出」问题
        self._decay_heartbeat: float = time.time()   # 衰减循环最近一次心跳
        self._decay_iter_count: int = 0                # 衰减循环累计迭代次数
        self._cloud_heartbeat: float = time.time()     # 云同步循环最近一次心跳
        self._cloud_iter_count: int = 0                # 云同步循环累计迭代次数
        self._last_health_check_ts: float = 0.0        # 上次健康检查时间（节流用）

        self._load()
        self._apply_pending_decrements()
        self._cloud_ensure_bot_id()

        # 注册插件页后端 API
        self.context.register_web_api(
            f"/{PLUGIN_NAME}/stats",
            self._api_stats,
            ["GET"],
            "获取恶意消息警告统计",
        )
        self.context.register_web_api(
            f"/{PLUGIN_NAME}/logs",
            self._api_logs,
            ["GET"],
            "获取被警告消息备案",
        )
        self.context.register_web_api(
            f"/{PLUGIN_NAME}/reset",
            self._api_reset,
            ["POST"],
            "重置某用户的警告次数",
        )
        self.context.register_web_api(
            f"/{PLUGIN_NAME}/special",
            self._api_special,
            ["GET"],
            "获取特殊记录（政治敏感/违法内容）",
        )
        self.context.register_web_api(
            f"/{PLUGIN_NAME}/timeout",
            self._api_timeout,
            ["GET"],
            "获取超时记录",
        )
        self.context.register_web_api(
            f"/{PLUGIN_NAME}/timeout/clear",
            self._api_timeout_clear,
            ["POST"],
            "清理超时记录",
        )
        self.context.register_web_api(
            f"/{PLUGIN_NAME}/revoke",
            self._api_revoke,
            ["POST"],
            "撤回误判警告（递减 count 并标记以免再次误判）",
        )
        self.context.register_web_api(
            f"/{PLUGIN_NAME}/false_positives",
            self._api_false_positives,
            ["GET"],
            "获取误判撤回记录列表",
        )
        # ---- 云同步 API（供 LLM 自助调用）----
        self.context.register_web_api(
            f"/{PLUGIN_NAME}/cloud/status",
            self._api_cloud_status,
            ["GET"],
            "获取云同步状态",
        )
        self.context.register_web_api(
            f"/{PLUGIN_NAME}/cloud/upload_record",
            self._api_cloud_upload_record,
            ["POST"],
            "上传警告记录到云端（LLM 可调用）",
        )
        self.context.register_web_api(
            f"/{PLUGIN_NAME}/cloud/upload_special",
            self._api_cloud_upload_special,
            ["POST"],
            "上传特殊记录到云端（LLM 可调用）",
        )
        self.context.register_web_api(
            f"/{PLUGIN_NAME}/cloud/sync",
            self._api_cloud_sync,
            ["POST"],
            "执行一次云同步（拉取+推送）（LLM 可调用）",
        )
        self.context.register_web_api(
            f"/{PLUGIN_NAME}/cloud/delete_record",
            self._api_cloud_delete_record,
            ["POST"],
            "删除云端记录（需 admin_token）",
        )
        self.context.register_web_api(
            f"/{PLUGIN_NAME}/cloud/records",
            self._api_cloud_records,
            ["GET"],
            "查询云端记录列表",
        )
        self.context.register_web_api(
            f"/{PLUGIN_NAME}/cloud/revoke_record",
            self._api_cloud_revoke_record,
            ["POST"],
            "向云端发送误判撤回请求（需 bot_id 一致）",
        )
        self.context.register_web_api(
            f"/{PLUGIN_NAME}/cloud/dedup",
            self._api_cloud_dedup,
            ["POST"],
            "手动去重：清理僵尸记录 + 特殊记录指纹去重（需 admin_token）",
        )
        self.context.register_web_api(
            f"/{PLUGIN_NAME}/cloud/blacklist",
            self._api_cloud_blacklist,
            ["GET"],
            "获取云端 IP 黑名单列表（需 admin_token）",
        )
        self.context.register_web_api(
            f"/{PLUGIN_NAME}/cloud/blacklist_add",
            self._api_cloud_blacklist_add,
            ["POST"],
            "添加 IP 到云端黑名单（需 admin_token）",
        )
        self.context.register_web_api(
            f"/{PLUGIN_NAME}/cloud/blacklist_remove",
            self._api_cloud_blacklist_remove,
            ["POST"],
            "从云端黑名单移除 IP（需 admin_token）",
        )

    # ------------------------------------------------------------------ 生命周期

    @filter.on_astrbot_loaded()
    async def _on_loaded(self):
        """AstrBot 初始化完成后启动后台任务。"""
        if self._decrement_task is not None and not self._decrement_task.done():
            self._decrement_task.cancel()
            try:
                await self._decrement_task
            except asyncio.CancelledError:
                pass
        self._decrement_task = asyncio.create_task(self._decrement_loop())
        if self._archive_task is None or self._archive_task.done():
            self._archive_task = asyncio.create_task(self._archive_loop())
        # 云同步后台任务（仅在启用时实际工作）
        if self._cloud_task is None or self._cloud_task.done():
            self._cloud_task = asyncio.create_task(self._cloud_sync_loop())
            logger.info("[恶意消息检测] 云同步后台任务已启动")

    async def terminate(self):
        """插件卸载 / 停用时调用。"""
        if self._decrement_task and not self._decrement_task.done():
            self._decrement_task.cancel()
            try:
                await self._decrement_task
            except asyncio.CancelledError:
                pass
        if self._archive_task and not self._archive_task.done():
            self._archive_task.cancel()
            try:
                await self._archive_task
            except asyncio.CancelledError:
                pass
        if self._cloud_task and not self._cloud_task.done():
            self._cloud_task.cancel()
            try:
                await self._cloud_task
            except asyncio.CancelledError:
                pass
        self._save()

    # ------------------------------------------------------------------ 后台任务健康检查（自愈看门狗）
    #
    # 设计目的：用户反馈「自动同步 / 自动衰减跑一会就崩了，只会循环一次」。
    # 根因可能是任务异常退出、被事件循环回收、或状态时间戳未持久化。
    # 本看门狗在每条消息 & 每次同步时被调用（内部节流），做三件事：
    #   1. 检测后台任务是否存活 → 死亡则重建；
    #   2. 检测心跳是否停滞（任务活着但卡住）→ 取消并重建；
    #   3. 检测状态时间戳是否过期 → 触发补偿（补衰减 / 补同步）。

    def _restart_decrement_task(self, reason: str = "") -> None:
        """（重新）启动衰减后台任务。"""
        if self._decrement_task is not None and not self._decrement_task.done():
            self._decrement_task.cancel()
        self._decay_heartbeat = time.time()
        self._decrement_task = asyncio.create_task(self._decrement_loop())
        logger.warning(f"[恶意消息检测] 衰减任务已重建（{reason}）")

    def _restart_cloud_task(self, reason: str = "") -> None:
        """（重新）启动云同步后台任务。"""
        if self._cloud_task is not None and not self._cloud_task.done():
            self._cloud_task.cancel()
        self._cloud_heartbeat = time.time()
        self._cloud_task = asyncio.create_task(self._cloud_sync_loop())
        logger.warning(f"[恶意消息检测] 云同步任务已重建（{reason}）")

    def _health_check(self, force: bool = False) -> None:
        """看门狗：检查并修复后台任务状态。节流到每 60 秒最多一次（force 可跳过）。

        - 任务为 None / 已结束 → 重建；
        - 任务心跳停滞超过 3 倍间隔 → 视为卡死，取消并重建；
        - last_decrement 落后超过 2 倍衰减间隔 → 立即补做一次衰减；
        - last_attempt_ts 落后超过 2 倍同步间隔 → 立即补做一次同步（异步触发）。
        """
        now = time.time()
        # 节流：默认每 60 秒最多检查一次，避免每条消息都跑全量检查
        if not force and (now - self._last_health_check_ts) < 60:
            return
        self._last_health_check_ts = now

        # ---- 1. 衰减任务存活 & 心跳 ----
        decay_alive = self._decrement_task is not None and not self._decrement_task.done()
        if not decay_alive:
            self._restart_decrement_task("任务未存活")
        else:
            # 心跳停滞检测：超过 3 倍衰减间隔没心跳 = 卡死
            hb_age = now - float(self._decay_heartbeat or 0)
            if hb_age > 3 * DECAY_INTERVAL:
                logger.warning(
                    f"[恶意消息检测] 衰减任务心跳停滞 {int(hb_age)}s，iter={self._decay_iter_count}，重建任务"
                )
                self._restart_decrement_task(f"心跳停滞 {int(hb_age)}s")

        # ---- 2. 云同步任务存活 & 心跳 ----
        cloud_alive = self._cloud_task is not None and not self._cloud_task.done()
        if not cloud_alive:
            self._restart_cloud_task("任务未存活")
        else:
            try:
                sync_interval = max(30, int(self.config.get("cloud_sync_interval", CLOUD_DEFAULT_INTERVAL) or CLOUD_DEFAULT_INTERVAL))
            except (TypeError, ValueError):
                sync_interval = CLOUD_DEFAULT_INTERVAL
            hb_age = now - float(self._cloud_heartbeat or 0)
            if hb_age > 3 * sync_interval:
                logger.warning(
                    f"[恶意消息检测] 云同步任务心跳停滞 {int(hb_age)}s，iter={self._cloud_iter_count}，重建任务"
                )
                self._restart_cloud_task(f"心跳停滞 {int(hb_age)}s")

        # ---- 3. 状态时间戳补偿（catch-up）----
        # 衰减：若 last_decrement 落后超过 2 倍间隔，立即补衰减
        last_dec = float(self._meta.get("last_decrement", now) or now)
        if now - last_dec > 2 * DECAY_INTERVAL:
            logger.warning(
                f"[恶意消息检测] 检测到衰减落后 {int(now - last_dec)}s > 2×{DECAY_INTERVAL}s，补做一次衰减"
            )
            try:
                asyncio.create_task(self._do_decrement())
            except RuntimeError:
                # 事件循环未就绪时降级
                pass

        # 云同步：若 last_attempt_ts 落后超过 2 倍间隔，异步触发一次同步
        if self._cloud_enabled() and not self._cloud_syncing:
            try:
                sync_interval = max(30, int(self.config.get("cloud_sync_interval", CLOUD_DEFAULT_INTERVAL) or CLOUD_DEFAULT_INTERVAL))
            except (TypeError, ValueError):
                sync_interval = CLOUD_DEFAULT_INTERVAL
            last_att = float(self._cloud.get("last_attempt_ts", 0) or 0)
            if last_att > 0 and (now - last_att) > 2 * sync_interval:
                logger.warning(
                    f"[恶意消息检测] 检测到同步落后 {int(now - last_att)}s > 2×{sync_interval}s，补做一次同步"
                )
                try:
                    asyncio.create_task(self._cloud_full_sync())
                except RuntimeError:
                    pass

    # ------------------------------------------------------------------ 主流程

    @filter.event_message_type(filter.EventMessageType.ALL, priority=30)
    async def on_message(self, event: AstrMessageEvent):
        """监听所有消息，检测是否含有严重恶意内容。"""
        # 看门狗：每条消息都尝试健康检查（内部节流），自愈卡死/退出的后台任务
        try:
            self._health_check()
        except Exception as e:
            logger.warning(f"[恶意消息检测] 健康检查异常: {e}")
        try:
            result = await self._check(event)
        except Exception as e:  # 任何异常都不应阻断正常聊天
            logger.warning(f"[恶意消息检测] 处理异常，已放行: {e}")
            return
        if result is not None:
            yield result

    async def _check(self, event: AstrMessageEvent) -> Optional[MessageEventResult]:
        """核心检测逻辑。返回需要 yield 的警告结果；返回 None 表示放行。"""
        cfg = self.config
        if not cfg.get("enable", True):
            return None

        message_str = (event.message_str or "").strip()
        if not message_str:
            return None

        sender_id = event.get_sender_id()
        self_id = event.get_self_id()
        if sender_id and self_id and sender_id == self_id:
            return None

        is_private = event.is_private_chat()
        if is_private and not cfg.get("scan_private", True):
            return None
        if not is_private and not cfg.get("scan_group", True):
            return None

        try:
            min_len = int(cfg.get("min_length", 2) or 0)
        except (TypeError, ValueError):
            min_len = 2
        if len(message_str) < min_len:
            return None
        try:
            max_len = int(cfg.get("max_length", 500) or 0)
        except (TypeError, ValueError):
            max_len = 500
        checked_str = message_str[:max_len] if max_len > 0 else message_str

        if not cfg.get("scan_command", False):
            prefixes = cfg.get("command_prefixes", ["/"]) or ["/"]
            if any(p and message_str.startswith(p) for p in prefixes):
                return None

        group_id = event.get_group_id()
        umo = event.unified_msg_origin
        platform_id = event.get_platform_id()
        whitelist_users = cfg.get("whitelist_users", []) or []
        whitelist_groups = cfg.get("whitelist_groups", []) or []
        if sender_id and sender_id in whitelist_users:
            return None
        if group_id and group_id in whitelist_groups:
            return None

        # 冷却（仅控制警告节奏，不影响计数衰减）
        try:
            cooldown = int(cfg.get("cooldown", 0) or 0)
        except (TypeError, ValueError):
            cooldown = 0
        key = self._record_key(platform_id, sender_id)
        now = time.time()
        if cooldown > 0:
            self._prune_cooldowns(now, cooldown)
            last = self._cooldowns.get(key)
            if last is not None and now - last < cooldown:
                # 即使冷却中也要追踪消息用于刷屏/防误判
                self._track_message(platform_id, group_id, sender_id, message_str, now)
                return None

        # 追踪消息（用于刷屏检测和防误判上下文）
        self._track_message(platform_id, group_id, sender_id, message_str, now)

        # ---- 误判撤回标记：跳过已知误判消息，避免再次误判 ----
        if bool(cfg.get("enable_false_positive_skip", True)) and self._is_false_positive(message_str):
            logger.info(f"[恶意消息检测] 命中误判撤回标记，跳过检测: sender={sender_id}")
            return None

        # ---- 刷屏检测 ----
        if bool(cfg.get("enable_spam_detect", True)) and not is_private and group_id:
            spam_result = await self._check_spam(
                event, platform_id, group_id, sender_id, umo, now
            )
            if spam_result is not None:
                return spam_result

        # 调用 LLM 判定恶意
        malicious, reason = await self._detect(event, checked_str, umo)
        if not malicious:
            return None

        # ---- 防误判：二次判定 ----
        if bool(cfg.get("enable_anti_false_positive", True)) and not is_private and group_id:
            confirmed, reason = await self._rejudge_with_context(
                event, checked_str, reason, umo, platform_id, group_id, sender_id
            )
            if not confirmed:
                logger.info(f"[恶意消息检测] 防误判：二次判定未通过，放行 sender={sender_id}")
                return None

        # ---- 检查目标用户是否为群管理员/群主 ----
        target_is_admin = False
        if bool(cfg.get("exempt_admin_from_warn", True)) and not is_private and group_id:
            if event.get_platform_name() == "aiocqhttp":
                target_is_admin = await self._target_is_admin(
                    event, platform_id, group_id, sender_id
                )

        # 命中恶意：累计 x（无论是否管理员都记录）
        rec = self._increment_count(event, reason, now)
        x = rec["count"]

        if cooldown > 0:
            self._cooldowns[key] = now

        # 触发云同步推送（如启用，仅标记待推送，由后台任务统一上传）
        self._cloud_schedule_push(key)

        # ---- 特殊记录检测（政治敏感/违法内容） ----
        if bool(cfg.get("enable_special_record", True)):
            asyncio.create_task(
                self._detect_and_record_special(event, message_str, reason, umo, now)
            )

        # 管理员豁免：记录+x 但不警告不禁言
        if target_is_admin:
            logger.info(
                f"[恶意消息检测] 目标为群管理员/群主，仅记录 x={x} sender={sender_id}"
            )
            self._record_log(event, message_str, reason, x, False, 0, now, is_admin=True)
            self._save()
            return None

        # 判断是否为"可禁言场景"：群聊 + aiocqhttp + enable_mute + 机器人为群管理员
        mute_capable = False
        muted = False
        mute_minutes = 0
        if not is_private and group_id and bool(cfg.get("enable_mute", True)):
            if event.get_platform_name() == "aiocqhttp":
                mute_capable = await self._bot_is_admin(event, platform_id, group_id, self_id)
            # 私聊或机器人非管理员的群：mute_capable 保持 False，仅累计 x

        # 可禁言场景下 x 超过阈值则禁言
        if mute_capable:
            muted, mute_minutes = await self._maybe_mute(
                event, sender_id, group_id, platform_id, x
            )
            if muted and mute_minutes > 0:
                rec["last_muted_until"] = now + mute_minutes * 60
                # 禁言状态变更后标记云同步推送
                self._cloud_schedule_push(key)
                # ---- 跨群禁言 ----
                if bool(cfg.get("enable_cross_group_mute", True)):
                    asyncio.create_task(
                        self._cross_group_mute(event, sender_id, group_id, platform_id, mute_minutes)
                    )

        # 生成警告文案（以当前人格语气；可禁言场景会包含 x/禁言提示）
        warn_text = await self._generate_warning(
            umo, rec, reason, x, mute_capable, muted, mute_minutes, message_str
        )
        logger.info(
            f"[恶意消息检测] 命中恶意 sender={sender_id} x={x} umo={umo} "
            f"mute_capable={mute_capable} muted={muted}({mute_minutes}min) "
            f"target_admin={target_is_admin} reason={reason} text={message_str[:60]!r}"
        )

        # 备案：保存被警告的消息内容与上下文
        self._record_log(event, message_str, reason, x, muted, mute_minutes, now)

        self._save()
        return self._build_warn_result(event, sender_id, warn_text)

    # ------------------------------------------------------------------ 检测

    async def _detect(
        self, event: AstrMessageEvent, message_str: str, umo: str
    ) -> tuple[bool, str]:
        """调用大模型判定消息是否恶意。失败时 fail-open（返回非恶意）。"""
        cfg = self.config
        provider_id = (cfg.get("provider_id") or "").strip()
        if not provider_id:
            try:
                provider_id = await self.context.get_current_chat_provider_id(umo=umo)
            except Exception as e:
                logger.warning(f"[恶意消息检测] 获取当前会话 Provider 失败，跳过: {e}")
                return False, ""

        system_prompt = cfg.get("judge_prompt") or DEFAULT_JUDGE_PROMPT
        user_prompt = (
            "请判断以下用户发送的消息是否含有严重恶意内容。"
            "只输出 JSON。\n\n"
            f"用户消息：\n{message_str}"
        )
        try:
            resp = await self.context.llm_generate(
                chat_provider_id=provider_id,
                prompt=user_prompt,
                system_prompt=system_prompt,
            )
        except Exception as e:
            logger.warning(f"[恶意消息检测] LLM 检测调用失败，已放行: {e}")
            return False, ""

        text = getattr(resp, "completion_text", "") or ""
        return self._parse_detect(text)

    @staticmethod
    def _parse_detect(text: str) -> tuple[bool, str]:
        """解析检测模型的判定结果，兼容多种输出格式。"""
        raw = (text or "").strip()
        if not raw:
            return False, ""
        candidate = raw
        fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", candidate, re.DOTALL)
        if fence:
            candidate = fence.group(1)
        else:
            obj = re.search(r"\{[^{}]*\}", candidate, re.DOTALL)
            if obj:
                candidate = obj.group(0)
        try:
            data = json.loads(candidate)
        except Exception:
            low = raw.lower()
            if '"malicious"' in low and (
                '"malicious": true' in low or '"malicious":true' in low
            ):
                return True, "模型判定为恶意"
            return False, ""
        if isinstance(data, dict):
            mal = data.get("malicious")
            reason = data.get("reason", "")
            if isinstance(mal, str):
                mal = mal.strip().lower() in ("true", "1", "yes", "y", "是")
            if bool(mal):
                return True, str(reason) if reason else "模型判定为恶意"
        return False, ""

    # ------------------------------------------------------------------ 消息追踪 / 刷屏检测

    def _track_message(
        self,
        platform_id: str,
        group_id: str,
        sender_id: str,
        message_str: str,
        now: float,
    ) -> None:
        """追踪每条消息的时间戳和内容，用于刷屏检测和防误判。"""
        if not group_id:
            return
        tk = (platform_id, group_id, sender_id)
        # 追踪时间戳
        ts_list = self._spam_tracker.setdefault(tk, [])
        ts_list.append(now)
        if len(ts_list) > SPAM_TRACKER_MAX:
            self._spam_tracker[tk] = ts_list[-SPAM_TRACKER_MAX:]
        # 追踪文本内容（防误判用）
        msg_list = self._recent_group_msgs.setdefault(tk, [])
        msg_list.append(message_str[:500])
        if len(msg_list) > RECENT_MSG_MAX:
            self._recent_group_msgs[tk] = msg_list[-RECENT_MSG_MAX:]

    def _get_spam_count(
        self, platform_id: str, group_id: str, sender_id: str, now: float, window: int
    ) -> int:
        """返回用户在指定时间窗口内发送的消息条数。"""
        tk = (platform_id, group_id, sender_id)
        ts_list = self._spam_tracker.get(tk, [])
        cutoff = now - window
        count = sum(1 for ts in ts_list if ts >= cutoff)
        return count

    def _get_recent_messages(
        self, platform_id: str, group_id: str, sender_id: str, count: int
    ) -> list[str]:
        """返回用户最近在本群发送的若干条文本消息（用于防误判）。"""
        tk = (platform_id, group_id, sender_id)
        msg_list = self._recent_group_msgs.get(tk, [])
        return msg_list[-count:] if count > 0 else []

    async def _check_spam(
        self,
        event: AstrMessageEvent,
        platform_id: str,
        group_id: str,
        sender_id: str,
        umo: str,
        now: float,
    ) -> Optional[MessageEventResult]:
        """刷屏检测：当用户在时间窗口内连续发送超过阈值条消息时，判断是否为无意义内容。"""
        cfg = self.config
        try:
            threshold = int(cfg.get("spam_threshold", 3) or 3)
        except (TypeError, ValueError):
            threshold = 3
        try:
            window = int(cfg.get("spam_window", 10) or 10)
        except (TypeError, ValueError):
            window = 10

        msg_count = self._get_spam_count(platform_id, group_id, sender_id, now, window)
        if msg_count <= threshold:
            return None

        # 超过阈值，调用 LLM 判断是否为无意义刷屏
        recent_msgs = self._get_recent_messages(platform_id, group_id, sender_id, msg_count)
        is_spam, spam_reason = await self._detect_spam(event, recent_msgs, umo)
        if not is_spam:
            return None

        logger.info(
            f"[恶意消息检测] 刷屏检测命中 sender={sender_id} group={group_id} "
            f"count={msg_count} reason={spam_reason}"
        )

        # 刷屏作为恶意处理：累计 x
        reason = f"刷屏：{spam_reason}" if spam_reason else "刷屏"
        rec = self._increment_count(event, reason, now)
        x = rec["count"]
        # 标记云同步推送
        spam_key = self._record_key(platform_id, sender_id)
        self._cloud_schedule_push(spam_key)

        # 检查目标是否为管理员
        target_is_admin = False
        if bool(cfg.get("exempt_admin_from_warn", True)):
            if event.get_platform_name() == "aiocqhttp":
                target_is_admin = await self._target_is_admin(
                    event, platform_id, group_id, sender_id
                )

        if target_is_admin:
            self._record_log(event, "\n".join(recent_msgs[-5:]), reason, x, False, 0, now, is_admin=True)
            self._save()
            return None

        # 尝试禁言
        mute_capable = False
        muted = False
        mute_minutes = 0
        self_id = event.get_self_id()
        if bool(cfg.get("enable_mute", True)) and event.get_platform_name() == "aiocqhttp":
            mute_capable = await self._bot_is_admin(event, platform_id, group_id, self_id)
        if mute_capable:
            muted, mute_minutes = await self._maybe_mute(
                event, sender_id, group_id, platform_id, x
            )
            if muted and mute_minutes > 0:
                rec["last_muted_until"] = now + mute_minutes * 60
                # 禁言状态变更后标记云同步推送
                self._cloud_schedule_push(spam_key)
                if bool(cfg.get("enable_cross_group_mute", True)):
                    asyncio.create_task(
                        self._cross_group_mute(event, sender_id, group_id, platform_id, mute_minutes)
                    )

        warn_text = await self._generate_warning(
            umo, rec, reason, x, mute_capable, muted, mute_minutes,
            "\n".join(recent_msgs[-3:])
        )
        self._record_log(event, "\n".join(recent_msgs[-5:]), reason, x, muted, mute_minutes, now)
        self._save()
        return self._build_warn_result(event, sender_id, warn_text)

    async def _detect_spam(
        self, event: AstrMessageEvent, recent_msgs: list[str], umo: str
    ) -> tuple[bool, str]:
        """调用 LLM 判断连续消息是否为无意义刷屏。失败时 fail-open。"""
        cfg = self.config
        provider_id = (cfg.get("provider_id") or "").strip()
        if not provider_id:
            try:
                provider_id = await self.context.get_current_chat_provider_id(umo=umo)
            except Exception:
                return False, ""

        system_prompt = cfg.get("spam_prompt") or ""
        if not system_prompt:
            return False, ""

        msgs_text = "\n".join(f"{i+1}. {m}" for i, m in enumerate(recent_msgs[-10:]))
        user_prompt = f"以下是用户连续发送的消息，请判断是否属于无意义刷屏：\n\n{msgs_text}"
        try:
            resp = await self.context.llm_generate(
                chat_provider_id=provider_id,
                prompt=user_prompt,
                system_prompt=system_prompt,
            )
        except Exception as e:
            logger.warning(f"[恶意消息检测] 刷屏检测 LLM 调用失败，已放行: {e}")
            return False, ""

        text = getattr(resp, "completion_text", "") or ""
        return self._parse_spam_detect(text)

    @staticmethod
    def _parse_spam_detect(text: str) -> tuple[bool, str]:
        """解析刷屏检测结果。"""
        raw = (text or "").strip()
        if not raw:
            return False, ""
        candidate = raw
        fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", candidate, re.DOTALL)
        if fence:
            candidate = fence.group(1)
        else:
            obj = re.search(r"\{[^{}]*\}", candidate, re.DOTALL)
            if obj:
                candidate = obj.group(0)
        try:
            data = json.loads(candidate)
        except Exception:
            low = raw.lower()
            if '"spam"' in low and ('"spam": true' in low or '"spam":true' in low):
                return True, "刷屏"
            return False, ""
        if isinstance(data, dict):
            spam = data.get("spam")
            reason = data.get("reason", "")
            if isinstance(spam, str):
                spam = spam.strip().lower() in ("true", "1", "yes", "y", "是")
            if bool(spam):
                return True, str(reason) if reason else "刷屏"
        return False, ""

    # ------------------------------------------------------------------ 防误判

    async def _rejudge_with_context(
        self,
        event: AstrMessageEvent,
        message_str: str,
        first_reason: str,
        umo: str,
        platform_id: str,
        group_id: str,
        sender_id: str,
    ) -> tuple[bool, str]:
        """结合最近本群消息进行二次判定，降低误判率。

        返回 (是否确认恶意, 原因)。
        """
        cfg = self.config
        try:
            ctx_count = int(cfg.get("anti_fp_context_count", 5) or 5)
        except (TypeError, ValueError):
            ctx_count = 5

        recent_msgs = self._get_recent_messages(platform_id, group_id, sender_id, ctx_count)
        # 移除最后一条（即当前正在判定的消息），避免重复
        context_msgs = recent_msgs[:-1] if len(recent_msgs) > 1 else []

        provider_id = (cfg.get("provider_id") or "").strip()
        if not provider_id:
            try:
                provider_id = await self.context.get_current_chat_provider_id(umo=umo)
            except Exception:
                return True, first_reason  # 无法获取 Provider 时维持原判定

        system_prompt = cfg.get("judge_prompt") or DEFAULT_JUDGE_PROMPT
        context_text = "\n".join(
            f"历史消息{i+1}: {m}" for i, m in enumerate(context_msgs)
        ) if context_msgs else "（无历史消息）"

        user_prompt = (
            "首次判定认为以下消息含有严重恶意内容。请结合该用户在本群的最近消息上下文，"
            "进行二次判定。如果结合上下文后发现并非真正恶意（如是在引用/讨论/反讽等），"
            "请判定为非恶意。\n\n"
            f"当前消息：\n{message_str}\n\n"
            f"该用户最近在本群的消息：\n{context_text}\n\n"
            "请只输出 JSON：\n"
            '{"malicious": true, "reason": "确认恶意，简要原因"}\n'
            "或\n"
            '{"malicious": false, "reason": "非恶意原因"}'
        )
        try:
            resp = await self.context.llm_generate(
                chat_provider_id=provider_id,
                prompt=user_prompt,
                system_prompt=system_prompt,
            )
        except Exception as e:
            logger.warning(f"[恶意消息检测] 防误判 LLM 调用失败，维持原判定: {e}")
            return True, first_reason

        text = getattr(resp, "completion_text", "") or ""
        confirmed, reason = self._parse_detect(text)
        if confirmed:
            return True, reason or first_reason
        return False, reason

    # ------------------------------------------------------------------ 警告生成（人格）

    async def _generate_warning(
        self,
        umo: str,
        rec: dict,
        reason: str,
        x: int,
        mute_capable: bool,
        muted: bool,
        mute_minutes: int,
        message_str: str = "",
    ) -> str:
        """以 LLM 当前人格的语气生成警告文案。

        - 可禁言场景（mute_capable=True）：必须告知当前累计次数 x，并按 x 与阈值的关系
          给出禁言提示（见 _build_mute_hint）。
        - 不可禁言场景（私聊/机器人非管理员群）：只告知累计 x，不提禁言。
        - 警告中会引用被警告的消息原文与判定原因，让被警告者清楚知道原因。
        失败时回退到模板。
        """
        cfg = self.config
        try:
            persona_prompt = await self._get_persona_prompt(umo)
        except Exception as e:
            logger.warning(f"[恶意消息检测] 获取人格失败，回退模板: {e}")
            persona_prompt = ""

        provider_id = (cfg.get("provider_id") or "").strip()
        if not provider_id:
            try:
                provider_id = await self.context.get_current_chat_provider_id(umo=umo)
            except Exception:
                provider_id = ""

        mute_hint = self._build_mute_hint(x, mute_capable, muted, mute_minutes)

        if not provider_id or not persona_prompt:
            return self._template_warning(rec, reason, mute_hint, message_str)

        system_prompt = (
            persona_prompt.rstrip()
            + "\n\n[附加任务] 你现在需要以你的人格设定和语气，对一名刚刚发送了恶意消息的用户"
            "发出简短、有威慑力但符合你人设的警告。要求：不超过 150 字，只输出警告正文，"
            "不要输出引号、JSON 或任何解释。必须自然地包含："
            "1) 被警告的消息原文摘要（不超过 50 字，用「」或引号引用）；"
            "2) 清晰的判定原因；"
            "3) 给定的累计次数与禁言提示信息。"
        )
        quoted_msg = ""
        if message_str:
            snippet = message_str[:50] + ("…" if len(message_str) > 50 else "")
            quoted_msg = f"\n被警告的消息原文：「{snippet}」"
        user_prompt = (
            f"用户 {rec.get('sender_name') or '该用户'} 发送了恶意消息。"
            f"判定原因：{reason or '含有严重恶意内容'}。\n"
            f"这是该用户第 {x} 次被警告，历史累计 {rec.get('total', x)} 次。"
            f"{quoted_msg}\n"
            f"请在警告中包含以下信息（用你自己的语气表达，数字必须准确）：\n{mute_hint}"
        )
        try:
            resp = await self.context.llm_generate(
                chat_provider_id=provider_id,
                prompt=user_prompt,
                system_prompt=system_prompt,
            )
            text = (getattr(resp, "completion_text", "") or "").strip().strip('"').strip()
            if text:
                return text
        except Exception as e:
            logger.warning(f"[恶意消息检测] 警告文案生成失败，回退模板: {e}")
        return self._template_warning(rec, reason, mute_hint, message_str)

    def _build_mute_hint(
        self, x: int, mute_capable: bool, muted: bool, mute_minutes: int
    ) -> str:
        """构造要告知用户的“累计次数 + 禁言提示”文本片段。

        - mute_capable=False（私聊或机器人非管理员群）：只告知累计 x，不提禁言。
        - mute_capable=True 且 muted=True（x>=阈值，本次已禁言）：
          告知本次禁言 10*x 分钟，再犯下次禁言 10*(x+1) 分钟。
        - mute_capable=True 且 x==阈值-1（下次将触发）：告知再被警告 1 次将禁言 10*(x+1) 分钟。
        - mute_capable=True 且 x<阈值-1：仅告知累计 x，提示接近禁言。
        """
        cfg = self.config
        try:
            threshold = int(cfg.get("mute_threshold", 5) or 5)
        except (TypeError, ValueError):
            threshold = 5
        try:
            multiplier = int(cfg.get("mute_multiplier", 10) or 10)
        except (TypeError, ValueError):
            multiplier = 10

        if not mute_capable:
            return f"当前累计警告次数 {x} 次。"

        if muted:
            # x >= threshold，本次已禁言
            this_min = multiplier * x
            next_min = multiplier * (x + 1)
            return (
                f"当前累计警告次数 {x} 次。本次已被禁言 {this_min} 分钟。"
                f"若再犯，下次将禁言 {next_min} 分钟。"
            )
        if x == threshold - 1:
            # 下次将触发禁言
            next_min = multiplier * (x + 1)
            return (
                f"当前累计警告次数 {x} 次。再次被警告将触发禁言 {next_min} 分钟。"
            )
        if x < threshold - 1:
            return (
                f"当前累计警告次数 {x} 次。累计达到 {threshold} 次将被禁言。"
            )
        # x >= threshold 但未禁言（如禁言调用失败）：按已超阈值处理
        this_min = multiplier * x
        next_min = multiplier * (x + 1)
        return (
            f"当前累计警告次数 {x} 次。本次应被禁言 {this_min} 分钟，"
            f"若再犯下次将禁言 {next_min} 分钟。"
        )


    async def _get_persona_prompt(self, umo: str) -> str:
        """获取当前首选人格的 system prompt（astrbot 配置文件的首选人格）。

        AstrBot 的 get_default_persona_v3 返回值可能是 dict（来自 personas_v3）
        也可能是 Personality 对象（DEFAULT_PERSONALITY 兜底），这里统一兼容。
        """
        pm = getattr(self.context, "persona_manager", None)
        if pm is None:
            return ""
        try:
            persona = await pm.get_default_persona_v3(umo=umo)
        except Exception as e:
            logger.warning(f"[恶意消息检测] get_default_persona_v3 失败: {e}")
            persona = None
        if persona is None:
            # 兜底：直接读已解析的全局默认人格
            persona = getattr(pm, "selected_default_persona_v3", None)
        if persona is None:
            return ""
        if isinstance(persona, dict):
            return persona.get("prompt", "") or ""
        return getattr(persona, "prompt", "") or ""

    def _template_warning(self, rec: dict, reason: str, mute_hint: str = "", message_str: str = "") -> str:
        """LLM 不可用时的模板警告。包含消息原文引用与清晰原因。"""
        cfg = self.config
        tpl = cfg.get("warn_message") or DEFAULT_WARN_MESSAGE
        text = tpl.replace("{sender}", rec.get("sender_name") or "该用户")
        text = text.replace("{x}", str(rec.get("count", 0)))
        if reason and "{reason}" in text:
            text = text.replace("{reason}", reason)
        # 追加引用消息与清晰原因
        parts = []
        if message_str:
            snippet = message_str[:80] + ("…" if len(message_str) > 80 else "")
            parts.append(f"📎 你发送的消息：「{snippet}」")
        if reason:
            parts.append(f"🔍 判定原因：{reason}")
        if parts:
            text = text + "\n" + "\n".join(parts)
        if mute_hint:
            text = text + "\n" + mute_hint
        return text

    # ------------------------------------------------------------------ 禁言

    async def _maybe_mute(
        self,
        event: AstrMessageEvent,
        sender_id: str,
        group_id: str,
        platform_id: str,
        x: int,
    ) -> tuple[bool, int]:
        """x 超过阈值时禁言 10*x 分钟。

        调用前应已确认 mute_capable=True（群聊 + aiocqhttp + 机器人管理员）。
        返回 (是否成功禁言, 禁言分钟数)。
        """
        cfg = self.config
        try:
            threshold = int(cfg.get("mute_threshold", 5) or 0)
        except (TypeError, ValueError):
            threshold = 5
        if x <= threshold:
            return False, 0

        try:
            multiplier = int(cfg.get("mute_multiplier", 10) or 10)
        except (TypeError, ValueError):
            multiplier = 10
        try:
            max_minutes = int(cfg.get("mute_max_minutes", 43200) or 43200)
        except (TypeError, ValueError):
            max_minutes = 43200
        mute_minutes = max(1, min(multiplier * x, max_minutes))
        # OneBot set_group_ban duration 单位为秒，上限 30 天
        duration = min(mute_minutes * 60, 2592000)

        try:
            uid = int(sender_id)
            gid = int(group_id)
        except (TypeError, ValueError):
            logger.warning(f"[恶意消息检测] 无法将 uid/gid 转为整数，跳过禁言: {sender_id}/{group_id}")
            return False, 0

        try:
            client = event.bot
            await client.api.call_action(
                "set_group_ban",
                group_id=gid,
                user_id=uid,
                duration=duration,
            )
            logger.info(
                f"[恶意消息检测] 已禁言 uid={uid} gid={gid} {mute_minutes} 分钟(x={x})"
            )
            return True, mute_minutes
        except Exception as e:
            logger.warning(f"[恶意消息检测] 禁言调用失败（可能权限不足）: {e}")
            return False, mute_minutes

    async def _bot_is_admin(
        self,
        event: AstrMessageEvent,
        platform_id: str,
        group_id: str,
        self_id: str,
    ) -> bool:
        """查询机器人在指定群的角色。结果缓存 10 分钟。"""
        cache_key = (platform_id, group_id)
        now = time.time()
        cached = self._bot_role_cache.get(cache_key)
        if cached and cached[1] > now:
            return cached[0] in ("admin", "owner")
        try:
            client = event.bot
            gid = int(group_id)
            sid = int(self_id) if self_id else 0
            if not sid:
                return False
            info = await client.api.call_action(
                "get_group_member_info", group_id=gid, user_id=sid
            )
            role = ""
            if isinstance(info, dict):
                role = str(info.get("role", "")).lower()
            self._bot_role_cache[cache_key] = (role, now + ROLE_CACHE_TTL)
            return role in ("admin", "owner")
        except Exception as e:
            logger.warning(f"[恶意消息检测] 查询机器人群角色失败，按非管理员处理: {e}")
            return False

    async def _target_is_admin(
        self,
        event: AstrMessageEvent,
        platform_id: str,
        group_id: str,
        user_id: str,
    ) -> bool:
        """查询目标用户在指定群是否为管理员/群主。结果缓存 5 分钟。"""
        cache_key = (platform_id, group_id, user_id)
        now = time.time()
        cached = self._target_role_cache.get(cache_key)
        if cached and cached[1] > now:
            return cached[0] in ("admin", "owner")
        try:
            client = event.bot
            gid = int(group_id)
            uid = int(user_id)
            info = await client.api.call_action(
                "get_group_member_info", group_id=gid, user_id=uid
            )
            role = ""
            if isinstance(info, dict):
                role = str(info.get("role", "")).lower()
            self._target_role_cache[cache_key] = (role, now + TARGET_ROLE_CACHE_TTL)
            return role in ("admin", "owner")
        except Exception as e:
            logger.warning(f"[恶意消息检测] 查询目标群角色失败，按非管理员处理: {e}")
            return False

    async def _cross_group_mute(
        self,
        event: AstrMessageEvent,
        sender_id: str,
        source_group_id: str,
        platform_id: str,
        mute_minutes: int,
    ) -> None:
        """当用户在一个群被禁言后，自动在其他群也禁言。

        检查顺序（每个群）：
        1. 机器人是否为该群管理员
        2. 目标用户是否在该群（尝试查询群成员信息）
        3. 目标用户是否非该群管理员（管理员不禁言）
        满足全部条件则执行禁言。
        """
        try:
            duration = min(mute_minutes * 60, 2592000)
            uid = int(sender_id)
        except (TypeError, ValueError):
            logger.warning(f"[恶意消息检测] 跨群禁言：uid 转换失败: {sender_id}")
            return

        client = event.bot
        # 获取机器人加入的所有群
        try:
            group_list = await client.api.call_action("get_group_list")
        except Exception as e:
            logger.warning(f"[恶意消息检测] 跨群禁言：获取群列表失败: {e}")
            return

        if not isinstance(group_list, list):
            return

        self_id = event.get_self_id()
        for g in group_list:
            if not isinstance(g, dict):
                continue
            gid_str = str(g.get("group_id", ""))
            if not gid_str or gid_str == str(source_group_id):
                continue  # 跳过源群

            gid = 0
            try:
                gid = int(gid_str)
            except (TypeError, ValueError):
                continue

            # 1. 机器人是否为该群管理员
            bot_admin = await self._bot_is_admin_in_group(client, platform_id, gid_str, self_id)
            if not bot_admin:
                continue

            # 2. 目标用户是否在该群
            in_group = await self._user_in_group(client, gid, uid)
            if not in_group:
                continue

            # 3. 目标用户是否非该群管理员
            target_admin = await self._target_is_admin_in_group(client, gid, uid)
            if target_admin:
                continue

            try:
                await client.api.call_action(
                    "set_group_ban",
                    group_id=gid,
                    user_id=uid,
                    duration=duration,
                )
                logger.info(
                    f"[恶意消息检测] 跨群禁言成功 uid={uid} gid={gid} {mute_minutes} 分钟"
                )
            except Exception as e:
                logger.debug(f"[恶意消息检测] 跨群禁言失败 gid={gid}: {e}")

    async def _bot_is_admin_in_group(
        self, client: Any, platform_id: str, group_id: str, self_id: str
    ) -> bool:
        """查询机器人在指定群是否为管理员（跨群禁言用）。"""
        cache_key = (platform_id, group_id)
        now = time.time()
        cached = self._bot_role_cache.get(cache_key)
        if cached and cached[1] > now:
            return cached[0] in ("admin", "owner")
        try:
            sid = int(self_id) if self_id else 0
            gid = int(group_id)
            if not sid:
                return False
            info = await client.api.call_action(
                "get_group_member_info", group_id=gid, user_id=sid
            )
            role = ""
            if isinstance(info, dict):
                role = str(info.get("role", "")).lower()
            self._bot_role_cache[cache_key] = (role, now + ROLE_CACHE_TTL)
            return role in ("admin", "owner")
        except Exception:
            return False

    async def _user_in_group(self, client: Any, gid: int, uid: int) -> bool:
        """检查用户是否在指定群中。"""
        try:
            await client.api.call_action(
                "get_group_member_info", group_id=gid, user_id=uid
            )
            return True
        except Exception:
            return False

    async def _target_is_admin_in_group(self, client: Any, gid: int, uid: int) -> bool:
        """查询目标用户在指定群是否为管理员（跨群禁言用，无缓存）。"""
        try:
            info = await client.api.call_action(
                "get_group_member_info", group_id=gid, user_id=uid
            )
            role = ""
            if isinstance(info, dict):
                role = str(info.get("role", "")).lower()
            return role in ("admin", "owner")
        except Exception:
            return False

    # ------------------------------------------------------------------ 特殊记录

    async def _detect_and_record_special(
        self,
        event: AstrMessageEvent,
        message_str: str,
        reason: str,
        umo: str,
        now: float,
    ) -> None:
        """检测消息是否涉及政治敏感/违法内容，若是则记录到特殊记录。"""
        cfg = self.config
        provider_id = (cfg.get("provider_id") or "").strip()
        if not provider_id:
            try:
                provider_id = await self.context.get_current_chat_provider_id(umo=umo)
            except Exception:
                return

        system_prompt = cfg.get("special_record_prompt") or ""
        if not system_prompt:
            return

        user_prompt = f"请判断以下消息是否可能涉及政治敏感或违法内容：\n\n{message_str[:500]}"
        try:
            resp = await self.context.llm_generate(
                chat_provider_id=provider_id,
                prompt=user_prompt,
                system_prompt=system_prompt,
            )
        except Exception as e:
            logger.warning(f"[恶意消息检测] 特殊记录检测 LLM 调用失败: {e}")
            return

        text = getattr(resp, "completion_text", "") or ""
        special, category, sp_reason = self._parse_special_detect(text)
        if not special:
            return

        entry = {
            "time": now,
            "time_str": self._fmt_ts(now),
            "user_id": event.get_sender_id(),
            "sender_name": event.get_sender_name(),
            "platform": event.get_platform_name(),
            "platform_id": event.get_platform_id(),
            "group_id": event.get_group_id(),
            "is_private": event.is_private_chat(),
            "message": message_str[:500],
            "reason": reason,
            "special_category": category,
            "special_reason": sp_reason,
            "archived": False,
        }
        self._special_records.append(entry)
        # 保留最近 1000 条特殊记录
        if len(self._special_records) > 1000:
            self._special_records = self._special_records[-1000:]
        self._save()
        # 标记有新特殊记录待推送
        self._cloud_schedule_special_push()
        logger.info(
            f"[恶意消息检测] 特殊记录 sender={event.get_sender_id()} "
            f"category={category} reason={sp_reason}"
        )

    @staticmethod
    def _parse_special_detect(text: str) -> tuple[bool, str, str]:
        """解析特殊记录检测结果。返回 (是否特殊, 分类, 原因)。"""
        raw = (text or "").strip()
        if not raw:
            return False, "", ""
        candidate = raw
        fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", candidate, re.DOTALL)
        if fence:
            candidate = fence.group(1)
        else:
            obj = re.search(r"\{.*\}", candidate, re.DOTALL)
            if obj:
                candidate = obj.group(0)
        try:
            data = json.loads(candidate)
        except Exception:
            low = raw.lower()
            if '"special"' in low and ('"special": true' in low or '"special":true' in low):
                return True, "其他", "模型判定为特殊内容"
            return False, "", ""
        if isinstance(data, dict):
            special = data.get("special")
            category = data.get("category", "")
            reason = data.get("reason", "")
            if isinstance(special, str):
                special = special.strip().lower() in ("true", "1", "yes", "y", "是")
            if bool(special):
                return True, str(category) or "其他", str(reason)
        return False, "", ""

    def _record_key(self, platform_id: str, sender_id: str) -> str:
        return f"{platform_id}:{sender_id}"

    def _increment_count(
        self, event: AstrMessageEvent, reason: str, now: float
    ) -> dict:
        key = self._record_key(event.get_platform_id(), event.get_sender_id())
        rec = self._records.get(key)
        if rec is None:
            rec = {
                "user_id": event.get_sender_id(),
                "sender_name": event.get_sender_name(),
                "platform": event.get_platform_name(),
                "platform_id": event.get_platform_id(),
                "count": 0,
                "total": 0,
                "last_warned": 0,
                "last_reason": "",
                "last_muted_until": 0,
            }
            self._records[key] = rec
        rec["count"] = int(rec.get("count", 0)) + 1
        rec["total"] = int(rec.get("total", 0)) + 1
        rec["last_warned"] = now
        rec["last_reason"] = reason
        rec["sender_name"] = event.get_sender_name() or rec.get("sender_name", "")
        rec["platform"] = event.get_platform_name()
        rec["platform_id"] = event.get_platform_id()
        rec["user_id"] = event.get_sender_id()
        return rec

    def _record_log(
        self,
        event: AstrMessageEvent,
        message_str: str,
        reason: str,
        x: int,
        muted: bool,
        mute_minutes: int,
        now: float,
        is_admin: bool = False,
    ) -> None:
        """备案：保存被警告的消息内容与上下文（仅保留最近 500 条）。"""
        entry = {
            "log_id": uuid.uuid4().hex[:12],
            "time": now,
            "time_str": self._fmt_ts(now),
            "user_id": event.get_sender_id(),
            "sender_name": event.get_sender_name(),
            "platform": event.get_platform_name(),
            "platform_id": event.get_platform_id(),
            "group_id": event.get_group_id(),
            "is_private": event.is_private_chat(),
            "message": message_str[:500],
            "reason": reason,
            "count": x,
            "muted": muted,
            "mute_minutes": mute_minutes,
            "is_admin": is_admin,
            "revoked": False,
        }
        self._logs.append(entry)
        # 仅保留最近 500 条，防止无限增长
        if len(self._logs) > 500:
            self._logs = self._logs[-500:]

    @staticmethod
    def _normalize_msg(text: str) -> str:
        """归一化消息文本用于误判匹配（去空白、去标点、小写）。"""
        return re.sub(r"[\s\W_]+", "", (text or "")).lower()

    def _is_false_positive(self, message: str) -> bool:
        """检查消息是否在误判撤回列表中（精确 + 归一化匹配）。"""
        if not self._false_positives:
            return False
        norm = self._normalize_msg(message)
        if not norm:
            return False
        for fp in self._false_positives:
            fp_msg = fp.get("message", "")
            if not fp_msg:
                continue
            if fp_msg == message:
                return True
            if self._normalize_msg(fp_msg) == norm:
                return True
        return False

    async def _decrement_loop(self):
        """按 last_decrement 时间戳计算下一次衰减时刻，确保重载后倒计时一致。

        逻辑：
        - 每次衰减后记录 last_decrement = now
        - 下一次衰减时间 = last_decrement + DECAY_INTERVAL
        - 若当前已超过下次衰减时间（如停机期间错过了），立即补做一次
        - 每次迭代 / 每个 sleep 分段都更新 _decay_heartbeat 心跳，供 _health_check 自愈使用
        """
        while True:
            try:
                self._decay_heartbeat = time.time()
                self._decay_iter_count += 1
                now = time.time()
                last = float(self._meta.get("last_decrement", now) or now)
                next_fire = last + DECAY_INTERVAL
                if next_fire <= now:
                    # 已到期（可能是重载前就该衰减了），立即执行
                    await self._do_decrement()
                    continue  # 继续循环，重新计算下一次
                # 等到下次衰减时刻
                wait = next_fire - time.time()
                # 分段等待，避免一次 sleep 过长无法及时响应
                while wait > 0:
                    self._decay_heartbeat = time.time()
                    chunk = min(wait, 60)
                    await asyncio.sleep(chunk)
                    wait -= chunk
                    if time.time() >= next_fire:
                        break
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.warning(f"[恶意消息检测] 衰减任务异常: {e}")
                await asyncio.sleep(60)

    async def _do_decrement(self):
        """执行一次衰减：所有用户 count -1（不低于 0）。

        衰减后同步推送「合法衰减」到云端（仅本 bot 上传的数据可被衰减，服务端鉴权）。
        """
        changed = False
        decayed_keys: list[str] = []
        # ★ 迭代快照，避免与 on_message 并发修改字典触发 RuntimeError
        for key, rec in list(self._records.items()):
            old_count = int(rec.get("count", 0) or 0)
            if old_count > 0:
                rec["count"] = max(0, old_count - 1)
                changed = True
                decayed_keys.append(key)
        self._meta["last_decrement"] = time.time()
        # ★ 始终持久化，即使 changed=False，也要保存 last_decrement 时间戳
        # （否则重载后会用旧时间戳，导致「只衰减一次」/倒计时错乱）
        self._save()
        logger.info(
            f"[恶意消息检测] 每 2 小时衰减完成: changed={changed}, decayed={len(decayed_keys)}, "
            f"last_decrement={self._fmt_ts(self._meta['last_decrement'])}"
        )
        # ★ 合法衰减同步：通知服务端按 bot_id 统一衰减（不传具体 keys）
        # 受 enable_cloud_revoke 控制（默认 True），不依赖 enable_cloud_sync_count
        # 服务端遍历 sources 包含本 bot_id 且 count>0 的记录统一 -1
        if decayed_keys and self._cloud_enabled() and self._cloud_feature_enabled("enable_cloud_revoke", True):
            try:
                asyncio.create_task(self._cloud_push_decay())
            except RuntimeError:
                # 事件循环未就绪时置 pending 标志，由 full_sync 重试
                self._cloud_pending_global_decay = True

    def _apply_pending_decrements(self):
        """加载时补算停机期间应衰减的次数。"""
        now = time.time()
        last = float(self._meta.get("last_decrement", now) or now)
        elapsed = now - last
        if elapsed < DECAY_INTERVAL:
            return
        intervals = int(elapsed // DECAY_INTERVAL)
        if intervals <= 0:
            return
        for rec in self._records.values():
            if rec.get("count", 0) > 0:
                rec["count"] = max(0, rec.get("count", 0) - intervals)
        self._meta["last_decrement"] = last + intervals * DECAY_INTERVAL
        logger.info(f"[恶意消息检测] 补算停机期间衰减 {intervals} 次")
        self._save()

    # ------------------------------------------------------------------ 超时归档 / 每日总结

    async def _archive_loop(self):
        """每 6 小时检查一次是否有标准备案记录超过 archive_timeout_days 天，需要归档。"""
        await asyncio.sleep(10)
        while True:
            try:
                if bool(self.config.get("enable_daily_summary", True)):
                    self._archive_old_records()
                    self._do_daily_summary_if_needed()
                # 每 6 小时检查一次
                await asyncio.sleep(ARCHIVE_CHECK_INTERVAL)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.warning(f"[恶意消息检测] 归档任务异常: {e}")
                await asyncio.sleep(3600)

    def _archive_old_records(self):
        """将超过 archive_timeout_days 天的标准备案记录转移到超时记录。特殊记录不受影响。"""
        try:
            timeout_days = int(self.config.get("archive_timeout_days", 7) or 7)
        except (TypeError, ValueError):
            timeout_days = 7
        cutoff = time.time() - timeout_days * 86400

        new_logs = []
        archived = []
        for entry in self._logs:
            if entry.get("time", 0) < cutoff:
                entry["archived_at"] = time.time()
                archived.append(entry)
            else:
                new_logs.append(entry)

        if archived:
            self._logs = new_logs
            self._timeout_archive.extend(archived)
            # 保留最近 2000 条超时记录
            if len(self._timeout_archive) > 2000:
                self._timeout_archive = self._timeout_archive[-2000:]
            self._meta["last_archive_check"] = time.time()
            self._save()
            logger.info(f"[恶意消息检测] 已归档 {len(archived)} 条超时备案记录")

    def _do_daily_summary_if_needed(self):
        """如果距上次每日总结超过 24 小时，执行一次。"""
        now = time.time()
        last = float(self._meta.get("last_daily_summary", 0) or 0)
        if now - last < 86400:  # 24 小时
            return

        # 统计当日数据
        day_start = now - 86400
        today_logs = [l for l in self._logs if l.get("time", 0) >= day_start]
        today_special = [s for s in self._special_records if s.get("time", 0) >= day_start]

        total_warned = len(set(l.get("user_id") for l in today_logs if l.get("user_id")))
        total_muted = sum(1 for l in today_logs if l.get("muted"))
        total_special = len(today_special)

        summary = {
            "time": now,
            "time_str": self._fmt_ts(now),
            "date": self._fmt_date(now),
            "total_warnings": len(today_logs),
            "total_warned_users": total_warned,
            "total_muted": total_muted,
            "total_special": total_special,
            "top_users": sorted(
                [
                    {
                        "user_id": l.get("user_id"),
                        "sender_name": l.get("sender_name"),
                        "count": sum(
                            1 for x in today_logs if x.get("user_id") == l.get("user_id")
                        ),
                    }
                    for l in today_logs
                ],
                key=lambda x: x["count"],
                reverse=True,
            )[:10],
        }
        self._daily_summaries.append(summary)
        if len(self._daily_summaries) > 365:
            self._daily_summaries = self._daily_summaries[-365:]
        self._meta["last_daily_summary"] = now
        self._save()
        logger.info(
            f"[恶意消息检测] 每日总结: 警告 {summary['total_warnings']} 次, "
            f"涉及 {total_warned} 人, 禁言 {total_muted} 次, 特殊记录 {total_special} 条"
        )

    # ------------------------------------------------------------------ 持久化

    def _load(self):
        try:
            if os.path.exists(self._data_path):
                with open(self._data_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._records = data.get("records", {}) or {}
                self._logs = data.get("logs", []) or []
                self._special_records = data.get("special_records", []) or []
                self._timeout_archive = data.get("timeout_archive", []) or []
                self._daily_summaries = data.get("daily_summaries", []) or []
                self._false_positives = data.get("false_positives", []) or []
                self._meta = data.get("meta", {}) or {}
                # 为旧日志条目补填 log_id（升级兼容）
                for log_entry in self._logs:
                    if not log_entry.get("log_id"):
                        log_entry["log_id"] = uuid.uuid4().hex[:12]
                    if "revoked" not in log_entry:
                        log_entry["revoked"] = False
                cloud = data.get("cloud", {}) or {}
                # 合并到默认 cloud 字典（保证新增字段有默认值）
                for k, v in cloud.items():
                    self._cloud[k] = v
                if "last_decrement" not in self._meta:
                    self._meta["last_decrement"] = time.time()
                if "last_archive_check" not in self._meta:
                    self._meta["last_archive_check"] = 0.0
                if "last_daily_summary" not in self._meta:
                    self._meta["last_daily_summary"] = 0.0
        except Exception as e:
            logger.warning(f"[恶意消息检测] 加载持久化数据失败，使用空数据: {e}")
            self._records = {}
            self._logs = []
            self._special_records = []
            self._timeout_archive = []
            self._daily_summaries = []
            self._false_positives = []
            self._meta = {"last_decrement": time.time(), "last_archive_check": 0.0, "last_daily_summary": 0.0}

    def _save(self):
        try:
            data = {
                "records": self._records,
                "logs": self._logs,
                "special_records": self._special_records,
                "timeout_archive": self._timeout_archive,
                "daily_summaries": self._daily_summaries,
                "false_positives": self._false_positives,
                "meta": self._meta,
                "cloud": self._cloud,
            }
            tmp = self._data_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self._data_path)
        except Exception as e:
            logger.warning(f"[恶意消息检测] 保存持久化数据失败: {e}")

    def _prune_cooldowns(self, now: float, cooldown: int) -> None:
        if len(self._cooldowns) > 512:
            threshold = now - cooldown * 3
            self._cooldowns = {
                k: v for k, v in self._cooldowns.items() if v >= threshold
            }

    # ------------------------------------------------------------------ 警告消息构造

    def _build_warn_result(
        self,
        event: AstrMessageEvent,
        sender_id: str,
        warn_text: str,
    ) -> MessageEventResult:
        """构造警告消息结果（x/禁言提示已包含在 warn_text 中）。

        使用 reply() 引用被警告的原消息，让用户清楚知道是哪条消息触发的警告。
        """
        cfg = self.config
        result = event.make_result()
        # 优先使用 reply 引用原消息，让被警告者清楚知道是哪条消息触发的
        if bool(cfg.get("warn_at_sender", True)) and sender_id:
            try:
                result.reply(event.message_id, " ")
            except Exception:
                pass
            result.at(event.get_sender_name() or sender_id, sender_id)
            result.message(" " + warn_text)
        else:
            try:
                result.reply(event.message_id, " ")
            except Exception:
                pass
            result.message(warn_text)

        if bool(cfg.get("stop_event", True)):
            result.stop_event()
        else:
            result.continue_event()
        return result

    # ------------------------------------------------------------------ 云同步

    def _cloud_ensure_bot_id(self) -> None:
        """确保有 bot_id（配置为空则自动生成并持久化）。"""
        bid = (self.config.get("cloud_bot_id") or "").strip()
        if not bid:
            bid = self._cloud.get("bot_id") or ""
        if not bid:
            bid = "bot-" + uuid.uuid4().hex[:12]
        self._cloud["bot_id"] = bid

    def _cloud_enabled(self) -> bool:
        """云同步总开关。"""
        return bool(self.config.get("enable_cloud_sync", False)) and bool(
            (self.config.get("cloud_server_url") or "").strip()
        )

    def _cloud_server_url(self) -> str:
        return (self.config.get("cloud_server_url") or "").strip().rstrip("/")

    def _cloud_client_token(self) -> str:
        return (self.config.get("cloud_client_token") or "").strip()

    def _cloud_admin_token(self) -> str:
        return (self.config.get("cloud_admin_token") or "").strip()

    def _cloud_bot_id(self) -> str:
        return self._cloud.get("bot_id") or "anonymous"

    def _cloud_feature_enabled(self, key: str, default: bool = True) -> bool:
        """检查某个子功能开关。"""
        return bool(self.config.get(key, default))

    def _cloud_schedule_push(self, key: str) -> None:
        """标记某 key 为待推送（仅累计到集合，由后台任务下次同步时上传）。"""
        if not self._cloud_enabled():
            return
        if not self._cloud_feature_enabled("enable_cloud_upload_record", True):
            return
        self._cloud_pending_push.add(key)

    def _cloud_schedule_special_push(self) -> None:
        """标记有新特殊记录待推送。"""
        if not self._cloud_enabled():
            return
        if not self._cloud_feature_enabled("enable_cloud_upload_special", True):
            return
        self._cloud_pending_special += 1

    def _cloud_record_error(self, msg: str) -> None:
        """记录云同步错误。"""
        self._cloud["last_error"] = msg[:500]
        self._cloud["last_error_ts"] = time.time()
        self._cloud["error_count"] = int(self._cloud.get("error_count", 0)) + 1

    def _cloud_record_success(self, kind: str = "sync", **extra) -> None:
        """记录云同步成功。kind: sync/push/pull/delete"""
        ts = time.time()
        if kind == "sync":
            self._cloud["last_sync_ts"] = ts
            self._cloud["sync_count"] = int(self._cloud.get("sync_count", 0)) + 1
        elif kind == "push":
            self._cloud["last_push_ts"] = ts
            self._cloud["push_count"] = int(self._cloud.get("push_count", 0)) + 1
        elif kind == "pull":
            self._cloud["last_pull_ts"] = ts
            self._cloud["pull_count"] = int(self._cloud.get("pull_count", 0)) + 1
        for k, v in extra.items():
            self._cloud[k] = v
        # 清错误
        self._cloud["last_error"] = ""
        self._cloud["last_error_ts"] = 0.0

    async def _cloud_http_request(
        self,
        method: str,
        path: str,
        body: Optional[dict] = None,
        use_admin_token: bool = False,
        timeout: Optional[int] = None,
    ) -> tuple[int, dict]:
        """发起 HTTP 请求到云服务端。返回 (status_code, response_dict)。

        使用 urllib + asyncio.to_thread 避免依赖 aiohttp。
        """
        url = self._cloud_server_url() + path
        token = self._cloud_admin_token() if use_admin_token else self._cloud_client_token()
        headers = {
            "User-Agent": CLOUD_USER_AGENT,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if token:
            header_name = "X-Admin-Token" if use_admin_token else "X-Client-Token"
            headers[header_name] = token
        data_bytes = b""
        if body is not None:
            data_bytes = json.dumps(body, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(url, data=data_bytes, method=method, headers=headers)
        t = timeout or CLOUD_HTTP_TIMEOUT

        def _do() -> tuple[int, dict]:
            try:
                with urllib.request.urlopen(req, timeout=t) as resp:
                    raw = resp.read()
                    status = resp.status
            except urllib.error.HTTPError as e:
                raw = e.read() or b"{}"
                status = e.code
            except urllib.error.URLError as e:
                msg = str(e)
                # 识别 SSL 协议不匹配（通常是 cloud_server_url 协议与服务端不一致）
                if "SSL" in msg or "WRONG_VERSION_NUMBER" in msg or "CERTIFICATE" in msg:
                    srv = self._cloud_server_url()
                    scheme = srv.split("://")[0].lower() if "://" in srv else ""
                    hint = (
                        f"SSL 错误：请检查 cloud_server_url 协议是否与服务端一致"
                        f"（当前配置: {scheme}://）。服务端为 HTTP 时应使用 http://，"
                        f"为 HTTPS 时应使用 https://。原始错误: {msg}"
                    )
                    raise RuntimeError(hint)
                # 连接被拒绝（端口/防火墙）
                if "Connection refused" in msg or "Connection refused" in str(getattr(e, "reason", "")):
                    raise RuntimeError(
                        f"连接被拒绝，请检查服务端是否启动、端口是否正确、防火墙是否放行。原始错误: {msg}"
                    )
                raise RuntimeError(f"网络错误: {e}")
            except Exception as e:
                raise RuntimeError(f"请求失败: {e}")
            try:
                obj = json.loads(raw.decode("utf-8")) if raw else {}
            except Exception:
                obj = {"raw": raw.decode("utf-8", errors="replace")}
            if not isinstance(obj, dict):
                obj = {"data": obj}
            return status, obj

        return await asyncio.to_thread(_do)

    async def _cloud_upload_records(self, keys: Optional[set[str]] = None) -> dict:
        """上传本地警告记录到云端。

        keys 为 None 时上传全部；否则只上传指定 key。
        返回 {"uploaded": N, "skipped": M, "status": int, "ok": bool, "error": str}。
        """
        if not self._cloud_enabled():
            return {"ok": False, "error": "云同步未启用", "uploaded": 0, "skipped": 0, "status": 0}
        if not self._cloud_feature_enabled("enable_cloud_upload_record", True):
            return {"ok": False, "error": "上传警告记录子功能未开启", "uploaded": 0, "skipped": 0, "status": 0}

        items = []
        skipped = 0
        for k, rec in self._records.items():
            if keys is not None and k not in keys:
                continue
            items.append({
                "user_id": str(rec.get("user_id", "")),
                "sender_name": str(rec.get("sender_name", "")),
                "platform": str(rec.get("platform", "")),
                "platform_id": str(rec.get("platform_id", "")),
                "count": int(rec.get("count", 0) or 0),
                "total": int(rec.get("total", 0) or 0),
                "last_warned": float(rec.get("last_warned", 0) or 0),
                "last_reason": str(rec.get("last_reason", "")),
                "last_muted_until": float(rec.get("last_muted_until", 0) or 0),
            })
            if len(items) >= CLOUD_MAX_PUSH_RECORDS:
                break
        # 即使没有待上传项，也允许发送空请求以同步状态
        body = {"bot_id": self._cloud_bot_id(), "records": items}
        try:
            status, resp = await self._cloud_http_request(
                "POST", "/api/upload_record", body=body
            )
        except Exception as e:
            self._cloud_record_error(f"upload_record: {e}")
            logger.warning(f"[恶意消息检测] 云同步上传记录失败: {e}")
            return {"ok": False, "error": str(e), "uploaded": 0, "skipped": skipped, "status": 0}
        if status == 200 and resp.get("ok"):
            uploaded = int(resp.get("uploaded", 0))
            server_skipped = int(resp.get("skipped", 0))
            self._cloud_record_success("push", last_uploaded_records=uploaded)
            self._cloud["last_pulled_records"] = int(resp.get("total_cloud", 0))
            logger.info(f"[恶意消息检测] 云同步上传 {uploaded} 条记录成功（跳过 {server_skipped} 条重复）")
            return {"ok": True, "uploaded": uploaded, "skipped": server_skipped, "status": status,
                    "total_cloud": resp.get("total_cloud", 0)}
        msg = resp.get("error") or f"HTTP {status}"
        self._cloud_record_error(f"upload_record: {msg}")
        logger.warning(f"[恶意消息检测] 云同步上传记录返回错误: {msg}")
        return {"ok": False, "error": msg, "uploaded": 0, "skipped": skipped, "status": status}

    async def _cloud_upload_special_records(self, limit: int = 100) -> dict:
        """上传本地特殊记录到云端（只上传最近的若干条，避免重复上传历史数据）。"""
        if not self._cloud_enabled():
            return {"ok": False, "error": "云同步未启用", "uploaded": 0, "status": 0}
        if not self._cloud_feature_enabled("enable_cloud_upload_special", True):
            return {"ok": False, "error": "上传特殊记录子功能未开启", "uploaded": 0, "status": 0}

        # 只上传本地最近 limit 条（避免每次全量上传）
        recent = self._special_records[-limit:] if limit > 0 else self._special_records
        items = []
        for s in recent:
            items.append({
                "user_id": str(s.get("user_id", "")),
                "sender_name": str(s.get("sender_name", "")),
                "platform": str(s.get("platform", "")),
                "platform_id": str(s.get("platform_id", "")),
                "group_id": str(s.get("group_id", "")),
                "is_private": bool(s.get("is_private", False)),
                "message": str(s.get("message", ""))[:500],
                "reason": str(s.get("reason", "")),
                "special_category": str(s.get("special_category", "")),
                "special_reason": str(s.get("special_reason", "")),
                "time": float(s.get("time", 0) or 0),
                "time_str": str(s.get("time_str", "")),
            })
        body = {"bot_id": self._cloud_bot_id(), "records": items}
        try:
            status, resp = await self._cloud_http_request(
                "POST", "/api/upload_special", body=body
            )
        except Exception as e:
            self._cloud_record_error(f"upload_special: {e}")
            return {"ok": False, "error": str(e), "uploaded": 0, "status": 0}
        if status == 200 and resp.get("ok"):
            uploaded = int(resp.get("uploaded", 0))
            server_skipped = int(resp.get("skipped", 0))
            self._cloud_record_success("push", last_uploaded_records=uploaded)
            logger.info(f"[恶意消息检测] 云同步上传特殊记录 {uploaded} 条（跳过 {server_skipped} 条重复）")
            return {"ok": True, "uploaded": uploaded, "skipped": server_skipped, "status": status,
                    "total_cloud": resp.get("total_cloud", 0)}
        msg = resp.get("error") or f"HTTP {status}"
        self._cloud_record_error(f"upload_special: {msg}")
        return {"ok": False, "error": msg, "uploaded": 0, "status": status}

    async def _cloud_pull(self) -> dict:
        """从云端拉取增量更新并合并到本地。返回 {"pulled": N, "special": M, "ok": bool}。"""
        if not self._cloud_enabled():
            return {"ok": False, "error": "云同步未启用", "pulled": 0, "special": 0}
        since = float(self._cloud.get("last_pull_ts", 0) or 0)
        url_path = f"/api/sync?since={since}&bot_id={self._cloud_bot_id()}"
        try:
            status, resp = await self._cloud_http_request("GET", url_path)
        except Exception as e:
            self._cloud_record_error(f"pull: {e}")
            return {"ok": False, "error": str(e), "pulled": 0, "special": 0}
        if status != 200:
            msg = resp.get("error") or f"HTTP {status}"
            self._cloud_record_error(f"pull: {msg}")
            return {"ok": False, "error": msg, "pulled": 0, "special": 0}

        remote_records = resp.get("records", []) or []
        remote_special = resp.get("special_records", []) or []
        pulled = self._cloud_apply_remote_records(remote_records)
        special_merged = self._cloud_apply_remote_special(remote_special)
        server_time = float(resp.get("server_time", time.time()) or time.time())
        self._cloud["last_pull_ts"] = server_time
        self._cloud_record_success("pull",
                                    last_pulled_records=pulled,
                                    last_pulled_special=special_merged)
        if pulled > 0 or special_merged > 0:
            self._save()
        logger.info(
            f"[恶意消息检测] 云同步拉取完成: 记录 {pulled} 条, 特殊 {special_merged} 条"
        )
        return {"ok": True, "pulled": pulled, "special": special_merged}

    def _cloud_apply_remote_records(self, remote_records: list[dict]) -> int:
        """将远端记录合并到本地。

        规则（与本地备份互补，本地始终保留）:
          - count: max(本地, 远端)（仅当 enable_cloud_sync_count 开启时）
          - total: max(本地, 远端)
          - last_muted_until: max(本地, 远端)（仅当 enable_cloud_sync_mute 开启时）
          - 其他字段：取较新者的信息
        """
        if not remote_records:
            return 0
        sync_count = self._cloud_feature_enabled("enable_cloud_sync_count", False)
        sync_mute = self._cloud_feature_enabled("enable_cloud_sync_mute", False)
        applied = 0
        now = time.time()
        for r in remote_records:
            if not isinstance(r, dict):
                continue
            uid = str(r.get("user_id", ""))
            pid = str(r.get("platform_id", ""))
            if not uid:
                continue
            k = self._record_key(pid, uid)
            local = self._records.get(k)
            if local is None:
                # 远端有而本地没有：仅当同步开关开启时才创建（避免误植入禁言风险）
                # 管理员强制覆盖（admin_rev > 0）也允许创建
                remote_admin_rev = int(r.get("admin_rev", 0) or 0)
                if not (sync_count or sync_mute or remote_admin_rev > 0):
                    continue
                local = {
                    "user_id": uid,
                    "sender_name": str(r.get("sender_name", "")),
                    "platform": str(r.get("platform", "")),
                    "platform_id": pid,
                    "count": 0,
                    "total": 0,
                    "last_warned": 0,
                    "last_reason": "",
                    "last_muted_until": 0,
                    "cloud_source": True,
                    "admin_rev": remote_admin_rev,
                }
                self._records[k] = local
            # ★ 管理员强制覆盖：admin_rev 升高时，无条件采用远端 count，绕过 max() 与 sync_count 开关
            # 这使管理员清零等操作能强制下发到客户端（即使本地 count 更高）
            remote_admin_rev = int(r.get("admin_rev", 0) or 0)
            local_admin_rev = int(local.get("admin_rev", 0) or 0)
            if remote_admin_rev > local_admin_rev:
                local["count"] = int(r.get("count", 0) or 0)
                local["admin_rev"] = remote_admin_rev
                applied += 1
                logger.info(
                    f"[恶意消息检测] 管理员强制覆盖: key={k}, count→{local['count']}, admin_rev={remote_admin_rev}"
                )
            # count 同步（普通 max 合并，仅在 sync_count 开启时）
            if sync_count:
                remote_count = int(r.get("count", 0) or 0)
                if remote_count > int(local.get("count", 0) or 0):
                    local["count"] = remote_count
                    applied += 1
                remote_total = int(r.get("total", 0) or 0)
                if remote_total > int(local.get("total", 0) or 0):
                    local["total"] = remote_total
            # 禁言状态同步
            if sync_mute:
                remote_mute_until = float(r.get("last_muted_until", 0) or 0)
                if remote_mute_until > float(local.get("last_muted_until", 0) or 0):
                    local["last_muted_until"] = remote_mute_until
                    applied += 1
            # 更新展示信息（取较新者）
            remote_warned = float(r.get("last_warned", 0) or 0)
            if remote_warned > float(local.get("last_warned", 0) or 0):
                local["last_warned"] = remote_warned
                local["last_reason"] = str(r.get("last_reason", "")) or local.get("last_reason", "")
                if r.get("sender_name"):
                    local["sender_name"] = str(r.get("sender_name"))
            # 平台字段补全
            if r.get("platform") and not local.get("platform"):
                local["platform"] = str(r.get("platform"))
            if r.get("platform_id") and not local.get("platform_id"):
                local["platform_id"] = str(r.get("platform_id"))
        return applied

    def _cloud_apply_remote_special(self, remote_special: list[dict]) -> int:
        """合并远端特殊记录到本地（去重，避免回环）。"""
        if not remote_special:
            return 0
        # 用 (user_id, message, time) 作为去重键
        existing_keys = set()
        for s in self._special_records:
            existing_keys.add((
                str(s.get("user_id", "")),
                str(s.get("message", ""))[:200],
                float(s.get("time", 0) or 0),
            ))
        added = 0
        for r in remote_special:
            if not isinstance(r, dict):
                continue
            dedup_key = (
                str(r.get("user_id", "")),
                str(r.get("message", ""))[:200],
                float(r.get("time", 0) or 0),
            )
            if dedup_key in existing_keys:
                continue
            entry = {
                "time": float(r.get("time", 0) or 0),
                "time_str": str(r.get("time_str", "")) or self._fmt_ts(float(r.get("time", 0) or 0)),
                "user_id": str(r.get("user_id", "")),
                "sender_name": str(r.get("sender_name", "")),
                "platform": str(r.get("platform", "")),
                "platform_id": str(r.get("platform_id", "")),
                "group_id": str(r.get("group_id", "")),
                "is_private": bool(r.get("is_private", False)),
                "message": str(r.get("message", ""))[:500],
                "reason": str(r.get("reason", "")),
                "special_category": str(r.get("special_category", "")),
                "special_reason": str(r.get("special_reason", "")),
                "archived": False,
                "cloud_source": True,
            }
            self._special_records.append(entry)
            existing_keys.add(dedup_key)
            added += 1
        # 限制总数
        if len(self._special_records) > 1000:
            self._special_records = self._special_records[-1000:]
        return added

    async def _cloud_push_incremental(self) -> dict:
        """推送增量更新（仅 pending 队列中的记录的增量）。

        updates 格式:
          count_delta: 仅在 enable_cloud_sync_count 开启时发送（避免无谓推送）
          mute_status: 仅在 enable_cloud_sync_mute 开启时发送
        """
        if not self._cloud_enabled():
            return {"ok": False, "error": "云同步未启用", "applied": 0}
        sync_count = self._cloud_feature_enabled("enable_cloud_sync_count", False)
        sync_mute = self._cloud_feature_enabled("enable_cloud_sync_mute", False)
        if not (sync_count or sync_mute):
            # 没有可推送的增量项（仅 upload_record 走 upload 路径）
            return {"ok": True, "applied": 0, "skipped": "no_incremental_features"}

        pending = self._cloud_pending_push
        if not pending:
            return {"ok": True, "applied": 0, "skipped": "no_pending"}

        count_delta: dict[str, int] = {}
        mute_status: dict[str, dict] = {}
        now = time.time()
        for k in list(pending):
            rec = self._records.get(k)
            if rec is None:
                continue
            if sync_count:
                # 推送当前 count 作为绝对值（服务端按 max 合并）— 走 upload_record 更合适
                # 这里走 incremental 仅推 mute_status
                pass
            if sync_mute:
                mute_until = float(rec.get("last_muted_until", 0) or 0)
                muted = mute_until > now
                mute_status[k] = {"muted": muted, "until": mute_until}

        if not mute_status and not count_delta:
            return {"ok": True, "applied": 0, "skipped": "nothing_to_send"}

        body = {
            "bot_id": self._cloud_bot_id(),
            "updates": {
                "count_delta": count_delta,
                "mute_status": mute_status,
            },
        }
        try:
            status, resp = await self._cloud_http_request("POST", "/api/sync", body=body)
        except Exception as e:
            self._cloud_record_error(f"push_incremental: {e}")
            return {"ok": False, "error": str(e), "applied": 0}
        if status == 200 and resp.get("ok"):
            applied = int(resp.get("applied", 0))
            self._cloud_record_success("push")
            return {"ok": True, "applied": applied, "skipped": int(resp.get("skipped", 0))}
        msg = resp.get("error") or f"HTTP {status}"
        self._cloud_record_error(f"push_incremental: {msg}")
        return {"ok": False, "error": msg, "applied": 0}

    async def _cloud_push_decay(self) -> dict:
        """推送全局合法衰减到云端（POST /api/decay，不传 keys）。

        服务端按 bot_id 统一衰减所有该 bot 上传的记录（sources 包含 bot_id 且 count>0）；
        使用 admin_token 时衰减全部记录。
        失败时设置 _cloud_pending_global_decay 标志，由 full_sync 重试。
        """
        if not self._cloud_enabled():
            return {"ok": False, "error": "未启用"}
        # 不传 keys，触发服务端「按 bot_id 统一衰减」模式
        body = {"bot_id": self._cloud_bot_id()}
        try:
            status, resp = await self._cloud_http_request("POST", "/api/decay", body=body)
        except Exception as e:
            self._cloud_record_error(f"decay: {e}")
            self._cloud_pending_global_decay = True
            return {"ok": False, "error": str(e)}
        if status == 200 and resp.get("ok"):
            decayed = resp.get("decayed", []) or []
            self._cloud_pending_global_decay = False
            mode = resp.get("mode", "global")
            logger.info(
                f"[恶意消息检测] 合法衰减已同步云端（按 bot_id 统一衰减）: "
                f"mode={mode}, decayed={len(decayed)}"
            )
            return {"ok": True, "decayed": len(decayed), "mode": mode}
        msg = resp.get("error") or f"HTTP {status}"
        self._cloud_record_error(f"decay: {msg}")
        self._cloud_pending_global_decay = True
        return {"ok": False, "error": msg}

    async def _cloud_upload_logs(self) -> dict:
        """上传备案日志（个体警告事件）到云端。仅上传 time > last_log_upload_ts 的新日志，按 log_id 去重。"""
        if not self._cloud_enabled():
            return {"ok": False, "error": "云同步未启用", "uploaded": 0}
        if not self._cloud_feature_enabled("enable_cloud_upload_record", True):
            return {"ok": False, "error": "上传记录子功能未开启", "uploaded": 0}
        watermark = float(self._cloud.get("last_log_upload_ts", 0) or 0)
        # 取水位之后的新日志，按时间升序
        new_logs = [l for l in self._logs if float(l.get("time", 0) or 0) > watermark]
        if not new_logs:
            return {"ok": True, "uploaded": 0}
        new_logs.sort(key=lambda l: float(l.get("time", 0) or 0))
        total_uploaded = 0
        total_skipped = 0
        # 分批上传（每批 200 条）
        batch_size = 200
        for i in range(0, len(new_logs), batch_size):
            batch = new_logs[i: i + batch_size]
            items = []
            for l in batch:
                items.append({
                    "log_id": str(l.get("log_id", "")),
                    "time": float(l.get("time", 0) or 0),
                    "time_str": str(l.get("time_str", "")),
                    "user_id": str(l.get("user_id", "")),
                    "sender_name": str(l.get("sender_name", "")),
                    "platform": str(l.get("platform", "")),
                    "platform_id": str(l.get("platform_id", "")),
                    "group_id": str(l.get("group_id", "")),
                    "is_private": bool(l.get("is_private", False)),
                    "message": str(l.get("message", ""))[:500],
                    "reason": str(l.get("reason", "")),
                    "count": int(l.get("count", 0) or 0),
                    "muted": bool(l.get("muted", False)),
                    "mute_minutes": int(l.get("mute_minutes", 0) or 0),
                    "is_admin": bool(l.get("is_admin", False)),
                    "revoked": bool(l.get("revoked", False)),
                })
            body = {"bot_id": self._cloud_bot_id(), "logs": items}
            try:
                status, resp = await self._cloud_http_request("POST", "/api/upload_logs", body=body)
            except Exception as e:
                self._cloud_record_error(f"upload_logs: {e}")
                return {"ok": False, "error": str(e), "uploaded": total_uploaded}
            if status == 200 and resp.get("ok"):
                total_uploaded += int(resp.get("uploaded", 0))
                total_skipped += int(resp.get("skipped", 0))
                # 推进水位到本批最大 time（仅成功批次推进，失败下次重试）
                self._cloud["last_log_upload_ts"] = max(float(l.get("time", 0) or 0) for l in batch)
            else:
                msg = resp.get("error") or f"HTTP {status}"
                self._cloud_record_error(f"upload_logs: {msg}")
                return {"ok": False, "error": msg, "uploaded": total_uploaded}
        self._save()
        logger.info(f"[恶意消息检测] 备案日志上传完成: uploaded={total_uploaded}, skipped={total_skipped}")
        return {"ok": True, "uploaded": total_uploaded, "skipped": total_skipped}

    async def _cloud_full_sync(self) -> dict:
        """执行一次完整同步：拉取 → 推送本地记录 → 推送增量禁言状态 → 推送特殊记录。

        本地数据始终保留（云端为补充）。仅在启用对应子功能时执行对应步骤。
        """
        # 看门狗：每次同步前检查并修复后台任务状态（用户建议：每次同步时检查并修复状态）
        try:
            self._health_check(force=True)
        except Exception as e:
            logger.warning(f"[恶意消息检测] 同步前健康检查异常: {e}")
        if not self._cloud_enabled():
            return {"ok": False, "error": "云同步未启用"}
        if self._cloud_syncing:
            return {"ok": False, "error": "同步进行中，跳过本次"}
        self._cloud_syncing = True
        # ★ 更新 attempt 时间戳（所有调用路径都会更新，确保倒计时正确）
        now_ts = time.time()
        self._cloud["last_attempt_ts"] = now_ts
        self._save()
        try:
            # 1. 拉取（拉取本身不需要子开关，是否合并由 _cloud_apply_remote_records 控制）
            pull_result = await self._cloud_pull()

            # 2. 推送本地警告记录（全量上传，服务端按 max 合并）
            push_keys = None
            if self._cloud_pending_push:
                push_keys = set(self._cloud_pending_push)
            upload_result = await self._cloud_upload_records(keys=push_keys)
            if upload_result.get("ok"):
                # 推送成功后清空 pending
                self._cloud_pending_push.clear()

            # 3. 推送增量（禁言状态/计数 delta）
            inc_result = await self._cloud_push_incremental()

            # 4. 推送特殊记录（如有 pending）
            special_result = {"ok": True, "uploaded": 0}
            if self._cloud_pending_special > 0 and self._cloud_feature_enabled(
                "enable_cloud_upload_special", True
            ):
                special_result = await self._cloud_upload_special_records(
                    limit=min(self._cloud_pending_special, 100)
                )
                if special_result.get("ok"):
                    self._cloud_pending_special = 0

            # 5. 重试失败的全局合法衰减推送
            decay_result = {"ok": True, "decayed": 0}
            if self._cloud_pending_global_decay:
                decay_result = await self._cloud_push_decay()

            # 6. 上传备案日志（新警告事件）
            logs_result = await self._cloud_upload_logs()

            self._cloud_record_success("sync")
            self._save()
            return {
                "ok": True,
                "pull": pull_result,
                "upload": upload_result,
                "incremental": inc_result,
                "special": special_result,
                "decay": decay_result,
                "logs": logs_result,
            }
        except Exception as e:
            self._cloud_record_error(f"full_sync: {e}")
            logger.warning(f"[恶意消息检测] 云同步异常: {e}")
            # 持久化错误信息
            self._save()
            return {"ok": False, "error": str(e)}
        finally:
            self._cloud_syncing = False

    async def _cloud_sync_loop(self):
        """云同步后台任务：按 interval 周期性同步（与衰减任务相同的绝对时间点调度模式）。

        逻辑：
        - 每次同步后记录 last_attempt_ts = now
        - 下一次同步时间 = last_attempt_ts + interval
        - 若当前已超过下次同步时间（如停机期间错过了），立即执行
        - 使用分段 sleep 避免一次 sleep 过长无法及时响应
        """
        # 启动后稍等
        await asyncio.sleep(15)
        while True:
            try:
                self._cloud_heartbeat = time.time()
                self._cloud_iter_count += 1
                if not self._cloud_enabled():
                    await asyncio.sleep(30)
                    continue
                interval = int(self.config.get("cloud_sync_interval", CLOUD_DEFAULT_INTERVAL) or CLOUD_DEFAULT_INTERVAL)
                interval = max(30, interval)
                now = time.time()
                last = float(self._cloud.get("last_attempt_ts", 0) or 0)
                next_fire = last + interval
                if next_fire <= now:
                    # 已到期，执行同步
                    logger.info(f"[恶意消息检测] 云同步循环触发: now={self._fmt_ts(now)}, next_fire={next_fire}")
                    result = await self._cloud_full_sync()
                    # 如果同步因 _cloud_syncing 被跳过，稍等后重试（避免 tight loop）
                    if result.get("error") == "同步进行中，跳过本次":
                        await asyncio.sleep(10)
                    continue  # 继续循环，重新计算下一次
                # 等到下次同步时刻
                wait = next_fire - time.time()
                # 分段等待，避免一次 sleep 过长无法及时响应
                while wait > 0:
                    self._cloud_heartbeat = time.time()
                    chunk = min(wait, 60)
                    await asyncio.sleep(chunk)
                    wait -= chunk
                    if time.time() >= next_fire:
                        break
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.warning(f"[恶意消息检测] 云同步后台任务异常: {e}")
                self._cloud_record_error(f"loop: {e}")
                await asyncio.sleep(60)

    async def _cloud_delete_remote_records(self, keys: list[str]) -> dict:
        """删除云端记录（需 admin_token）。"""
        if not self._cloud_enabled():
            return {"ok": False, "error": "云同步未启用", "deleted": 0}
        if not self._cloud_feature_enabled("enable_cloud_delete_record", False):
            return {"ok": False, "error": "删除云端记录子功能未开启", "deleted": 0}
        if not self._cloud_admin_token():
            return {"ok": False, "error": "未配置 admin_token", "deleted": 0}
        body = {"bot_id": self._cloud_bot_id(), "keys": keys}
        try:
            status, resp = await self._cloud_http_request(
                "POST", "/api/delete_record", body=body, use_admin_token=True
            )
        except Exception as e:
            self._cloud_record_error(f"delete: {e}")
            return {"ok": False, "error": str(e), "deleted": 0}
        if status == 200 and resp.get("ok"):
            deleted = int(resp.get("deleted_count", 0))
            logger.info(f"[恶意消息检测] 云同步删除 {deleted} 条记录")
            return {"ok": True, "deleted": deleted, "details": resp.get("deleted", [])}
        msg = resp.get("error") or f"HTTP {status}"
        self._cloud_record_error(f"delete: {msg}")
        return {"ok": False, "error": msg, "deleted": 0}

    async def _cloud_revoke_record(
        self, key: str, log_id: str, message: str, reason: str
    ) -> dict:
        """向云端发送误判撤回请求。

        服务端校验：bot_id 必须在该记录的 sources 中（即上传该警告的 bot 才能撤回）。
        """
        if not self._cloud_enabled():
            return {"ok": False, "error": "云同步未启用"}
        if not bool(self.config.get("enable_cloud_revoke", True)):
            return {"ok": False, "error": "云端误判撤回子功能未开启"}
        body = {
            "bot_id": self._cloud_bot_id(),
            "record_key": key,
            "log_id": log_id,
            "message": message,
            "reason": reason,
        }
        try:
            status, resp = await self._cloud_http_request(
                "POST", "/api/revoke_record", body=body
            )
        except Exception as e:
            self._cloud_record_error(f"revoke: {e}")
            return {"ok": False, "error": str(e)}
        if status == 200 and resp.get("ok"):
            logger.info(f"[恶意消息检测] 云端误判撤回成功: key={key} log_id={log_id}")
            return {"ok": True, "revoked": resp.get("revoked", False)}
        msg = resp.get("error") or f"HTTP {status}"
        self._cloud_record_error(f"revoke: {msg}")
        return {"ok": False, "error": msg}

    # ------------------------------------------------------------------ 插件页 Web API

    async def _api_stats(self):
        """返回所有用户的警告统计，按 count 降序。"""
        limit = request.query.get("limit", 500, type=int) or 500
        now = time.time()
        items = []
        for rec in self._records.values():
            items.append(
                {
                    "user_id": rec.get("user_id", ""),
                    "sender_name": rec.get("sender_name", ""),
                    "platform": rec.get("platform", ""),
                    "platform_id": rec.get("platform_id", ""),
                    "count": rec.get("count", 0),
                    "total": rec.get("total", rec.get("count", 0)),
                    "last_warned": rec.get("last_warned", 0),
                    "last_reason": rec.get("last_reason", ""),
                    "last_muted_until": rec.get("last_muted_until", 0),
                    "last_warned_str": self._fmt_ts(rec.get("last_warned", 0)),
                    "is_muted": rec.get("last_muted_until", 0) > now,
                }
            )
        items.sort(key=lambda r: (r["count"], r["total"]), reverse=True)
        return json_response(
            {
                "total_users": len(items),
                "next_decay_in": self._next_decay_seconds(),
                "items": items[:limit],
            }
        )

    async def _api_logs(self):
        """返回被警告消息备案（倒序）。支持按 user_id/platform_id 过滤（供详情弹窗使用）。"""
        limit = request.query.get("limit", 200, type=int) or 200
        uid = (request.query.get("user_id", "") or "").strip()
        pid = (request.query.get("platform_id", "") or "").strip()
        items = list(reversed(self._logs))
        if uid:
            items = [l for l in items if str(l.get("user_id", "")) == uid]
        if pid:
            items = [l for l in items if str(l.get("platform_id", "")) == pid]
        total = len(items)
        items = items[:limit]
        return json_response(
            {"total": total, "items": items}
        )

    async def _api_reset(self):
        """重置某用户的警告次数。body: {"key": "..."} 或 {"user_id":"...","platform_id":"..."}"""
        body = {}
        try:
            body = await request.json(default={}) or {}
        except Exception as e:
            logger.warning(f"[恶意消息检测] reset 读取请求体失败: {e}")
            body = {}
        if not isinstance(body, dict):
            body = {}
        key = body.get("key")
        if not key:
            pid = body.get("platform_id") or ""
            uid = body.get("user_id") or ""
            if uid:
                key = self._record_key(str(pid), str(uid))
        if not key:
            return error_response("缺少 key/user_id", status_code=400)
        rec = self._records.get(key)
        if rec is None:
            # 尝试模糊匹配（处理 None platform_id 的情况）
            matched = None
            for k, r in self._records.items():
                if str(r.get("user_id", "")) == str(body.get("user_id", "")) and body.get("user_id"):
                    matched = k
                    break
            if matched:
                key = matched
                rec = self._records[key]
            else:
                return error_response("记录不存在", status_code=404)
        rec["count"] = 0
        self._save()
        logger.info(f"[恶意消息检测] 已重置用户 {key} 的警告次数为 0")
        return json_response({"ok": True, "key": key})

    async def _api_special(self):
        """返回特殊记录（政治敏感/违法内容），按人分类。"""
        limit = request.query.get("limit", 500, type=int) or 500
        items = list(reversed(self._special_records))[:limit]
        # 按用户分组
        by_user: dict[str, list] = {}
        for item in items:
            uid = str(item.get("user_id", ""))
            by_user.setdefault(uid, []).append(item)
        return json_response({
            "total": len(self._special_records),
            "items": items,
            "by_user": by_user,
        })

    async def _api_timeout(self):
        """返回超时记录与每日总结。"""
        limit = request.query.get("limit", 500, type=int) or 500
        items = list(reversed(self._timeout_archive))[:limit]
        summaries = list(reversed(self._daily_summaries))[:30]
        return json_response({
            "total": len(self._timeout_archive),
            "items": items,
            "summaries": summaries,
        })

    async def _api_timeout_clear(self):
        """清空超时记录。"""
        count = len(self._timeout_archive)
        self._timeout_archive = []
        self._save()
        logger.info(f"[恶意消息检测] 已清理 {count} 条超时记录")
        return json_response({"ok": True, "cleared": count})

    async def _api_revoke(self):
        """撤回误判警告。

        body: {"log_id": "...", "reason": "误判理由"}
        - 根据 log_id 找到备案记录
        - 将该用户 count -1（不低于 0），total 不变（保留审计）
        - 标记日志为 revoked
        - 将消息+理由加入误判列表，避免再次误判
        - 如启用云同步误判撤回，向云端发送撤回请求（需 bot_id 一致）
        """
        body = {}
        try:
            body = await request.json(default={}) or {}
        except Exception as e:
            logger.warning(f"[恶意消息检测] revoke 读取请求体失败: {e}")
            body = {}
        if not isinstance(body, dict):
            body = {}
        log_id = str(body.get("log_id", "") or "")
        reason = str(body.get("reason", "") or "").strip()
        if not log_id:
            return error_response("缺少 log_id", status_code=400)
        if not reason:
            return error_response("缺少误判理由", status_code=400)

        # 查找日志条目
        target_log = None
        for log_entry in self._logs:
            if log_entry.get("log_id") == log_id:
                target_log = log_entry
                break
        if target_log is None:
            return error_response("未找到该日志记录", status_code=404)
        if target_log.get("revoked"):
            return error_response("该警告已被撤回", status_code=409)

        uid = str(target_log.get("user_id", ""))
        pid = str(target_log.get("platform_id", ""))
        message = str(target_log.get("message", ""))
        old_count = 0
        new_count = 0

        # 递减该用户 count
        if uid:
            key = self._record_key(pid, uid)
            rec = self._records.get(key)
            if rec:
                old_count = int(rec.get("count", 0) or 0)
                new_count = max(0, old_count - 1)
                rec["count"] = new_count
                # 触发云同步推送（如启用）
                self._cloud_schedule_push(key)

        # 标记日志为已撤回
        target_log["revoked"] = True
        target_log["revoke_reason"] = reason
        target_log["revoked_at"] = time.time()

        # 加入误判列表（去重：同消息已存在则跳过）
        if message and not self._is_false_positive(message):
            self._false_positives.append({
                "message": message,
                "reason": reason,
                "original_reason": target_log.get("reason", ""),
                "user_id": uid,
                "platform_id": pid,
                "log_id": log_id,
                "revoked_at": target_log["revoked_at"],
            })
            # 限制误判列表上限
            if len(self._false_positives) > 2000:
                self._false_positives = self._false_positives[-2000:]

        self._save()
        logger.info(
            f"[恶意消息检测] 撤回误判警告 log_id={log_id} user={uid} "
            f"count {old_count} -> {new_count}"
        )

        # 云端撤回（如启用）
        cloud_revoked = False
        cloud_error = ""
        if (
            self._cloud_enabled()
            and bool(self.config.get("enable_cloud_revoke", True))
            and uid
        ):
            key = self._record_key(pid, uid)
            cloud_result = await self._cloud_revoke_record(key, log_id, message, reason)
            cloud_revoked = bool(cloud_result.get("ok"))
            cloud_error = cloud_result.get("error", "")

        return json_response({
            "ok": True,
            "log_id": log_id,
            "old_count": old_count,
            "new_count": new_count,
            "cloud_revoked": cloud_revoked,
            "cloud_error": cloud_error,
        })

    async def _api_false_positives(self):
        """返回误判撤回记录列表。"""
        limit = request.query.get("limit", 500, type=int) or 500
        items = list(reversed(self._false_positives))[:limit]
        return json_response({
            "total": len(self._false_positives),
            "items": items,
        })

    # ------------------------------------------------------------------ 云同步 API

    async def _api_cloud_status(self):
        """返回云同步状态。"""
        cfg = self.config
        enabled = self._cloud_enabled()
        status = {
            "enabled": enabled,
            "cloud_server_url": self._cloud_server_url() if enabled else "",
            "bot_id": self._cloud_bot_id(),
            "features": {
                "upload_record": self._cloud_feature_enabled("enable_cloud_upload_record", True),
                "sync_count": self._cloud_feature_enabled("enable_cloud_sync_count", False),
                "sync_mute": self._cloud_feature_enabled("enable_cloud_sync_mute", False),
                "delete_record": self._cloud_feature_enabled("enable_cloud_delete_record", False),
                "upload_special": self._cloud_feature_enabled("enable_cloud_upload_special", True),
                "revoke": bool(cfg.get("enable_cloud_revoke", True)),
            },
            "stats": {
                "sync_count": int(self._cloud.get("sync_count", 0)),
                "push_count": int(self._cloud.get("push_count", 0)),
                "pull_count": int(self._cloud.get("pull_count", 0)),
                "error_count": int(self._cloud.get("error_count", 0)),
                "last_uploaded_records": int(self._cloud.get("last_uploaded_records", 0)),
                "last_pulled_records": int(self._cloud.get("last_pulled_records", 0)),
                "last_pulled_special": int(self._cloud.get("last_pulled_special", 0)),
            },
            "timing": {
                "last_sync_ts": float(self._cloud.get("last_sync_ts", 0) or 0),
                "last_sync_str": self._fmt_ts(float(self._cloud.get("last_sync_ts", 0) or 0)),
                "last_attempt_ts": float(self._cloud.get("last_attempt_ts", 0) or 0),
                "last_attempt_str": self._fmt_ts(float(self._cloud.get("last_attempt_ts", 0) or 0)),
                "last_pull_ts": float(self._cloud.get("last_pull_ts", 0) or 0),
                "last_pull_str": self._fmt_ts(float(self._cloud.get("last_pull_ts", 0) or 0)),
                "last_push_ts": float(self._cloud.get("last_push_ts", 0) or 0),
                "last_push_str": self._fmt_ts(float(self._cloud.get("last_push_ts", 0) or 0)),
                "next_sync_in": self._cloud_next_sync_seconds(cfg),
            },
            "errors": {
                "last_error": self._cloud.get("last_error", ""),
                "last_error_ts": float(self._cloud.get("last_error_ts", 0) or 0),
                "last_error_str": self._fmt_ts(float(self._cloud.get("last_error_ts", 0) or 0)),
            },
            "pending": {
                "push_keys": len(self._cloud_pending_push),
                "special": int(self._cloud_pending_special),
                "syncing": self._cloud_syncing,
            },
            "syncing": self._cloud_syncing,
            "server_time": time.time(),
            "watchdog": {
                "decay_task_alive": self._decrement_task is not None and not self._decrement_task.done(),
                "decay_iter_count": int(self._decay_iter_count),
                "decay_heartbeat_ts": float(self._decay_heartbeat or 0),
                "decay_heartbeat_str": self._fmt_ts(float(self._decay_heartbeat or 0)),
                "cloud_task_alive": self._cloud_task is not None and not self._cloud_task.done(),
                "cloud_iter_count": int(self._cloud_iter_count),
                "cloud_heartbeat_ts": float(self._cloud_heartbeat or 0),
                "cloud_heartbeat_str": self._fmt_ts(float(self._cloud_heartbeat or 0)),
                "last_health_check_ts": float(self._last_health_check_ts or 0),
                "last_health_check_str": self._fmt_ts(float(self._last_health_check_ts or 0)),
            },
        }
        return json_response(status)

    def _cloud_next_sync_seconds(self, cfg) -> int:
        if not self._cloud_enabled():
            return -1
        if self._cloud_syncing:
            return 0  # 正在同步中，下次同步在当前完成后立即触发
        try:
            interval = int(cfg.get("cloud_sync_interval", CLOUD_DEFAULT_INTERVAL) or CLOUD_DEFAULT_INTERVAL)
            interval = max(30, interval)
        except (TypeError, ValueError):
            interval = CLOUD_DEFAULT_INTERVAL
        last = float(self._cloud.get("last_attempt_ts", 0) or 0)
        if last <= 0:
            return 0
        elapsed = time.time() - last
        return max(0, int(interval - elapsed))

    async def _api_cloud_upload_record(self):
        """上传警告记录到云端。可指定 keys 或全量上传。

        body: {"keys": ["platform_id:user_id", ...]} 或 {} 全量
        """
        try:
            body = await request.json(default={}) or {}
        except Exception:
            body = {}
        if not isinstance(body, dict):
            body = {}
        keys_in = body.get("keys")
        keys = None
        if isinstance(keys_in, list) and keys_in:
            keys = set(str(k) for k in keys_in if k)
        result = await self._cloud_upload_records(keys=keys)
        return json_response(result)

    async def _api_cloud_upload_special(self):
        """上传特殊记录到云端。body: {"limit": 100}"""
        try:
            body = await request.json(default={}) or {}
        except Exception:
            body = {}
        if not isinstance(body, dict):
            body = {}
        try:
            limit = int(body.get("limit", 100) or 100)
        except (TypeError, ValueError):
            limit = 100
        result = await self._cloud_upload_special_records(limit=limit)
        return json_response(result)

    async def _api_cloud_sync(self):
        """执行一次完整云同步（拉取 + 推送）。

        body 可空。返回详细同步结果。
        """
        result = await self._cloud_full_sync()
        return json_response(result)

    async def _api_cloud_delete_record(self):
        """删除云端记录（需 admin_token 与子开关）。

        body: {"keys": ["platform_id:user_id", ...]}
        或:   {"user_id": "123", "platform_id": "qq"}
        """
        try:
            body = await request.json(default={}) or {}
        except Exception:
            body = {}
        if not isinstance(body, dict):
            body = {}
        keys = body.get("keys")
        if isinstance(keys, str):
            keys = [keys]
        if not isinstance(keys, list) or not keys:
            uid = str(body.get("user_id", ""))
            pid = str(body.get("platform_id", ""))
            if uid:
                keys = [self._record_key(pid, uid)]
            else:
                return error_response("缺少 keys 或 user_id", status_code=400)
        keys = [str(k) for k in keys if k]
        if not keys:
            return error_response("keys 为空", status_code=400)
        result = await self._cloud_delete_remote_records(keys)
        return json_response(result)

    async def _api_cloud_records(self):
        """查询云端记录列表（代理调用云服务端 /api/records）。"""
        if not self._cloud_enabled():
            return json_response({"ok": False, "error": "云同步未启用", "items": []})
        try:
            limit = request.query.get("limit", 500, type=int) or 500
        except Exception:
            limit = 500
        url_path = f"/api/records?limit={limit}"
        try:
            status, resp = await self._cloud_http_request("GET", url_path)
        except Exception as e:
            return json_response({"ok": False, "error": str(e), "items": []})
        if status == 200:
            return json_response(resp)
        return json_response({"ok": False, "error": resp.get("error", f"HTTP {status}"), "items": []})

    async def _api_cloud_revoke_record(self):
        """向云端发送误判撤回请求（LLM 可调用）。

        body: {"record_key": "...", "log_id": "...", "message": "...", "reason": "..."}
        """
        body = {}
        try:
            body = await request.json(default={}) or {}
        except Exception as e:
            logger.warning(f"[恶意消息检测] cloud_revoke 读取请求体失败: {e}")
            body = {}
        if not isinstance(body, dict):
            body = {}
        key = str(body.get("record_key", "") or "")
        log_id = str(body.get("log_id", "") or "")
        message = str(body.get("message", "") or "")
        reason = str(body.get("reason", "") or "").strip()
        if not key:
            return error_response("缺少 record_key", status_code=400)
        if not reason:
            return error_response("缺少误判理由", status_code=400)
        result = await self._cloud_revoke_record(key, log_id, message, reason)
        return json_response(result)

    async def _api_cloud_dedup(self):
        """手动去重：清理本地僵尸记录 + 调用云端去重。

        body: {"type": "records"|"special"|""} 空=全部
        """
        body = {}
        try:
            body = await request.json(default={}) or {}
        except Exception:
            body = {}
        if not isinstance(body, dict):
            body = {}
        dedup_type = str(body.get("type", "") or "")
        result = await self._do_cloud_dedup(dedup_type)
        return json_response(result)

    async def _do_cloud_dedup(self, dedup_type: str = "") -> dict:
        """执行去重逻辑（可被 API 和命令共同调用）。"""
        result = {"ok": True, "local": {}, "cloud": {}}

        # ---- 本地去重 ----
        if dedup_type in ("", "records"):
            now = time.time()
            stale_threshold = 30 * 86400
            removed_local = 0
            for k, rec in list(self._records.items()):
                count = int(rec.get("count", 0) or 0)
                is_muted = bool(rec.get("is_muted", False))
                last_warned = float(rec.get("last_warned", 0) or 0)
                if count <= 0 and not is_muted and (now - last_warned) > stale_threshold:
                    del self._records[k]
                    removed_local += 1
            if removed_local > 0:
                self._save()
            result["local"] = {
                "removed": removed_local,
                "total_after": len(self._records),
            }

        # ---- 云端去重 ----
        if dedup_type in ("", "records", "special"):
            cloud_result = await self._cloud_dedup(dedup_type)
            result["cloud"] = cloud_result
            if not cloud_result.get("ok"):
                result["ok"] = False

        # 清理空字段
        if dedup_type == "records":
            if "special" in result.get("cloud", {}):
                del result["cloud"]["special"]
        elif dedup_type == "special":
            if "records" in result.get("cloud", {}):
                del result["cloud"]["records"]

        return result

    async def _cloud_dedup(self, dedup_type: str = "") -> dict:
        """调用云端 /api/dedup 端点执行去重。"""
        if not self._cloud_enabled():
            return {"ok": False, "error": "云同步未启用"}
        if not self._cloud_admin_token():
            return {"ok": False, "error": "未配置 admin_token"}
        body = {"bot_id": self._cloud_bot_id(), "type": dedup_type}
        try:
            status, resp = await self._cloud_http_request(
                "POST", "/api/dedup", body=body, use_admin_token=True
            )
        except Exception as e:
            self._cloud_record_error(f"dedup: {e}")
            return {"ok": False, "error": str(e)}
        if status == 200 and resp.get("ok"):
            logger.info(f"[恶意消息检测] 云同步去重完成: {resp}")
            return resp
        msg = resp.get("error") or f"HTTP {status}"
        self._cloud_record_error(f"dedup: {msg}")
        return {"ok": False, "error": msg}

    # ------------------------------------------------------------------ 云黑名单

    async def _api_cloud_blacklist(self):
        """获取云端 IP 黑名单列表。"""
        result = await self._cloud_blacklist_list()
        return json_response(result)

    async def _api_cloud_blacklist_add(self):
        """添加 IP 到云端黑名单。body: {"ip": "192.168.1."}"""
        body = {}
        try:
            body = await request.json(default={}) or {}
        except Exception:
            body = {}
        if not isinstance(body, dict):
            body = {}
        ip = str(body.get("ip", "") or "").strip()
        if not ip:
            return json_response({"ok": False, "error": "缺少 ip 参数"}, 400)
        result = await self._cloud_blacklist_add(ip)
        return json_response(result)

    async def _api_cloud_blacklist_remove(self):
        """从云端黑名单移除 IP。body: {"ip": "192.168.1."}"""
        body = {}
        try:
            body = await request.json(default={}) or {}
        except Exception:
            body = {}
        if not isinstance(body, dict):
            body = {}
        ip = str(body.get("ip", "") or "").strip()
        if not ip:
            return json_response({"ok": False, "error": "缺少 ip 参数"}, 400)
        result = await self._cloud_blacklist_remove(ip)
        return json_response(result)

    async def _cloud_blacklist_list(self) -> dict:
        """获取云端黑名单列表。"""
        if not self._cloud_enabled():
            return {"ok": False, "error": "云同步未启用"}
        if not self._cloud_admin_token():
            return {"ok": False, "error": "未配置 admin_token"}
        try:
            status, resp = await self._cloud_http_request(
                "GET", "/api/blacklist", use_admin_token=True
            )
        except Exception as e:
            self._cloud_record_error(f"blacklist_list: {e}")
            return {"ok": False, "error": str(e)}
        if status == 200:
            return resp
        msg = resp.get("error") or f"HTTP {status}"
        self._cloud_record_error(f"blacklist_list: {msg}")
        return {"ok": False, "error": msg}

    async def _cloud_blacklist_add(self, ip: str) -> dict:
        """添加 IP 到云端黑名单。"""
        if not self._cloud_enabled():
            return {"ok": False, "error": "云同步未启用"}
        if not self._cloud_admin_token():
            return {"ok": False, "error": "未配置 admin_token"}
        try:
            status, resp = await self._cloud_http_request(
                "POST", "/api/blacklist/add", body={"ip": ip}, use_admin_token=True
            )
        except Exception as e:
            self._cloud_record_error(f"blacklist_add: {e}")
            return {"ok": False, "error": str(e)}
        if status == 200 and resp.get("ok"):
            logger.info(f"[恶意消息检测] IP 已加入黑名单: {ip}")
            return resp
        msg = resp.get("error") or f"HTTP {status}"
        self._cloud_record_error(f"blacklist_add: {msg}")
        return {"ok": False, "error": msg}

    async def _cloud_blacklist_remove(self, ip: str) -> dict:
        """从云端黑名单移除 IP。"""
        if not self._cloud_enabled():
            return {"ok": False, "error": "云同步未启用"}
        if not self._cloud_admin_token():
            return {"ok": False, "error": "未配置 admin_token"}
        try:
            status, resp = await self._cloud_http_request(
                "POST", "/api/blacklist/remove", body={"ip": ip}, use_admin_token=True
            )
        except Exception as e:
            self._cloud_record_error(f"blacklist_remove: {e}")
            return {"ok": False, "error": str(e)}
        if status == 200 and resp.get("ok"):
            logger.info(f"[恶意消息检测] IP 已从黑名单移除: {ip}")
            return resp
        msg = resp.get("error") or f"HTTP {status}"
        self._cloud_record_error(f"blacklist_remove: {msg}")
        return {"ok": False, "error": msg}

    def _next_decay_seconds(self) -> int:
        last = float(self._meta.get("last_decrement", 0) or 0)
        if last <= 0:
            return DECAY_INTERVAL
        elapsed = time.time() - last
        return max(0, int(DECAY_INTERVAL - elapsed))

    @staticmethod
    def _fmt_ts(ts: float) -> str:
        if not ts:
            return "-"
        try:
            import datetime as _dt

            return _dt.datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return str(ts)

    @staticmethod
    def _fmt_date(ts: float) -> str:
        if not ts:
            return "-"
        try:
            import datetime as _dt

            return _dt.datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d")
        except Exception:
            return str(ts)

    # ------------------------------------------------------------------ 管理指令

    @filter.command("malicious_stats", alias={"恶意统计"})
    @filter.permission_type(filter.PermissionType.ADMIN)
    async def malicious_stats(self, event: AstrMessageEvent):
        """查看恶意消息警告统计（管理员）。"""
        now = time.time()
        items = sorted(
            self._records.values(),
            key=lambda r: (r.get("count", 0), r.get("total", 0)),
            reverse=True,
        )[:20]
        if not items:
            yield event.plain_result("暂无警告记录。")
            return
        lines = [f"共 {len(self._records)} 人，Top 20："]
        for i, r in enumerate(items, 1):
            lines.append(
                f"{i}. {r.get('sender_name') or r.get('user_id')} "
                f"[{r.get('platform', '')}] x={r.get('count', 0)} "
                f"累计={r.get('total', 0)}"
            )
        lines.append(f"距下次衰减：{self._next_decay_seconds() // 60} 分钟")
        yield event.plain_result("\n".join(lines))

    @filter.command("malicious_reset", alias={"恶意重置"})
    @filter.permission_type(filter.PermissionType.ADMIN)
    async def malicious_reset(self, event: AstrMessageEvent, user_id: str):
        """重置某用户的警告次数（管理员）。/malicious_reset <user_id>"""
        pid = event.get_platform_id()
        key = self._record_key(pid, user_id)
        rec = self._records.get(key)
        if rec is None:
            yield event.plain_result(f"未找到用户 {user_id} 的记录。")
            return
        rec["count"] = 0
        self._save()
        yield event.plain_result(f"已重置 {rec.get('sender_name') or user_id} 的警告次数为 0。")

    # ------------------------------------------------------------------ 群白名单动态管理

    def _get_whitelist_groups(self) -> list:
        wl = self.config.get("whitelist_groups", None)
        if wl is None:
            wl = []
        if not isinstance(wl, list):
            wl = [str(wl)]
        return [str(g) for g in wl]

    async def _save_whitelist_groups(self, new_list: list) -> None:
        """更新白名单并持久化到插件配置文件。"""
        try:
            await self.config.save_config_async(
                replace_config={"whitelist_groups": new_list}
            )
        except Exception as e:
            logger.warning(f"[恶意消息检测] 保存群白名单失败: {e}")
            # 兜底：至少更新内存
            self.config["whitelist_groups"] = new_list

    @filter.command("malicious_wl_add", alias={"恶意白名单添加"})
    @filter.permission_type(filter.PermissionType.ADMIN)
    async def malicious_wl_add(self, event: AstrMessageEvent, group_id: str):
        """将群加入白名单（管理员）。/malicious_wl_add <group_id>"""
        gid = (group_id or "").strip()
        if not gid:
            yield event.plain_result("用法：/malicious_wl_add <群号>")
            return
        wl = self._get_whitelist_groups()
        if gid in wl:
            yield event.plain_result(f"群 {gid} 已在白名单中。")
            return
        wl.append(gid)
        await self._save_whitelist_groups(wl)
        yield event.plain_result(
            f"已将群 {gid} 加入白名单（共 {len(wl)} 个）。该群的消息将不再检测。"
        )

    @filter.command("malicious_wl_del", alias={"恶意白名单删除"})
    @filter.permission_type(filter.PermissionType.ADMIN)
    async def malicious_wl_del(self, event: AstrMessageEvent, group_id: str):
        """将群移出白名单（管理员）。/malicious_wl_del <group_id>"""
        gid = (group_id or "").strip()
        if not gid:
            yield event.plain_result("用法：/malicious_wl_del <群号>")
            return
        wl = self._get_whitelist_groups()
        if gid not in wl:
            yield event.plain_result(f"群 {gid} 不在白名单中。")
            return
        wl = [g for g in wl if g != gid]
        await self._save_whitelist_groups(wl)
        yield event.plain_result(
            f"已将群 {gid} 移出白名单（剩余 {len(wl)} 个）。该群的消息将恢复检测。"
        )

    @filter.command("malicious_wl_list", alias={"恶意白名单列表"})
    @filter.permission_type(filter.PermissionType.ADMIN)
    async def malicious_wl_list(self, event: AstrMessageEvent):
        """查看群白名单（管理员）。"""
        wl = self._get_whitelist_groups()
        if not wl:
            yield event.plain_result("群白名单为空。")
            return
        lines = [f"群白名单（共 {len(wl)} 个）："]
        for i, g in enumerate(wl, 1):
            lines.append(f"{i}. {g}")
        yield event.plain_result("\n".join(lines))

    # ------------------------------------------------------------------ 云同步管理指令

    @filter.command("malicious_cloud_status", alias={"云状态"})
    @filter.permission_type(filter.PermissionType.ADMIN)
    async def malicious_cloud_status(self, event: AstrMessageEvent):
        """查看云同步状态（管理员）。"""
        if not self._cloud_enabled():
            yield event.plain_result(
                "云同步未启用。请在配置中开启 enable_cloud_sync 并填写 cloud_server_url / cloud_client_token。"
            )
            return
        feat = {
            "upload_record": self._cloud_feature_enabled("enable_cloud_upload_record", True),
            "sync_count": self._cloud_feature_enabled("enable_cloud_sync_count", False),
            "sync_mute": self._cloud_feature_enabled("enable_cloud_sync_mute", False),
            "delete_record": self._cloud_feature_enabled("enable_cloud_delete_record", False),
            "upload_special": self._cloud_feature_enabled("enable_cloud_upload_special", True),
            "revoke": bool(self.config.get("enable_cloud_revoke", True)),
        }
        lines = [
            f"云同步状态：",
            f"  服务端：{self._cloud_server_url()}",
            f"  Bot ID：{self._cloud_bot_id()}",
            f"  子功能：",
            f"    上传警告记录：{'✅' if feat['upload_record'] else '❌'}",
            f"    同步警告次数：{'✅' if feat['sync_count'] else '❌'}（⚠️ 有误禁言风险）",
            f"    同步禁言状态：{'✅' if feat['sync_mute'] else '❌'}（⚠️ 有误禁言风险）",
            f"    删除云端记录：{'✅' if feat['delete_record'] else '❌'}（需 admin_token）",
            f"    上传特殊记录：{'✅' if feat['upload_special'] else '❌'}",
            f"    误判撤回：{'✅' if feat['revoke'] else '❌'}（需 bot_id 一致）",
            f"  统计：",
            f"    累计同步 {self._cloud.get('sync_count', 0)} 次，推送 {self._cloud.get('push_count', 0)} 次，拉取 {self._cloud.get('pull_count', 0)} 次",
            f"    累计错误 {self._cloud.get('error_count', 0)} 次",
            f"    上次成功同步：{self._fmt_ts(float(self._cloud.get('last_sync_ts', 0) or 0))}",
            f"    上次尝试同步：{self._fmt_ts(float(self._cloud.get('last_attempt_ts', 0) or 0))}",
            f"    上次上传：{self._cloud.get('last_uploaded_records', 0)} 条",
            f"    上次拉取：记录 {self._cloud.get('last_pulled_records', 0)} 条，特殊 {self._cloud.get('last_pulled_special', 0)} 条",
            f"    距下次同步：{self._cloud_next_sync_seconds(self.config)} 秒",
            f"    待推送：{len(self._cloud_pending_push)} 条记录，{self._cloud_pending_special} 条特殊记录",
        ]
        err = self._cloud.get("last_error", "")
        if err:
            lines.append(f"  ⚠️ 上次错误：{err}（{self._fmt_ts(float(self._cloud.get('last_error_ts', 0) or 0))}）")
        yield event.plain_result("\n".join(lines))

    @filter.command("malicious_cloud_sync", alias={"云同步"})
    @filter.permission_type(filter.PermissionType.ADMIN)
    async def malicious_cloud_sync(self, event: AstrMessageEvent):
        """手动触发一次云同步（管理员）。"""
        if not self._cloud_enabled():
            yield event.plain_result("云同步未启用。")
            return
        if self._cloud_syncing:
            yield event.plain_result("同步进行中，请稍后。")
            return
        yield event.plain_result("⏳ 正在执行云同步…")
        result = await self._cloud_full_sync()
        if not result.get("ok"):
            yield event.plain_result(f"❌ 同步失败：{result.get('error', '未知错误')}")
            return
        pull = result.get("pull", {}) or {}
        upload = result.get("upload", {}) or {}
        inc = result.get("incremental", {}) or {}
        special = result.get("special", {}) or {}
        lines = [
            "✅ 云同步完成：",
            f"  拉取：记录 {pull.get('pulled', 0)} 条，特殊 {pull.get('special', 0)} 条",
            f"  上传：警告记录 {upload.get('uploaded', 0)} 条" + (
                f"（跳过 {upload.get('skipped', 0)} 条重复" if upload.get('skipped', 0) > 0 else ""
            ) + (
                f"，云端共 {upload.get('total_cloud', 0)} 条）" if upload.get('total_cloud') else "）"
            ),
            f"  增量：应用 {inc.get('applied', 0)} 条" + (
                f"（跳过 {inc.get('skipped', 0)} 条）" if inc.get('skipped', 0) else ""
            ),
            f"  特殊：上传 {special.get('uploaded', 0)} 条" + (
                f"（跳过 {special.get('skipped', 0)} 条重复" if special.get('skipped', 0) > 0 else ""
            ) + (
                f"，云端共 {special.get('total_cloud', 0)} 条）" if special.get('total_cloud') else "）"
            ),
        ]
        if self._cloud.get("last_error"):
            lines.append(f"  ⚠️ 错误信息：{self._cloud.get('last_error')}")
        yield event.plain_result("\n".join(lines))

    @filter.command("malicious_cloud_dedup", alias={"云去重"})
    @filter.permission_type(filter.PermissionType.ADMIN)
    async def malicious_cloud_dedup(self, event: AstrMessageEvent):
        """手动去重：清理本地僵尸记录 + 云端去重（管理员）。

        用法：
          云去重           → 全部去重（记录+特殊）
          云去重 records   → 仅记录去重
          云去重 special   → 仅特殊去重
        """
        if not self._cloud_enabled():
            yield event.plain_result("云同步未启用。")
            return
        # 解析参数
        args = str(event.message.message).strip().split()
        dedup_type = ""
        if len(args) >= 2:
            t = args[-1].lower()
            if t in ("records", "special"):
                dedup_type = t
        type_label = {"": "全部", "records": "仅记录", "special": "仅特殊"}.get(dedup_type, "全部")
        yield event.plain_result(f"⏳ 正在执行{type_label}去重…")
        result = await self._do_cloud_dedup(dedup_type)
        if not result.get("ok"):
            yield event.plain_result(f"❌ 去重失败：{result.get('error', '未知错误')}")
            return
        local = result.get("local", {}) or {}
        cloud = result.get("cloud", {}) or {}
        cloud_records = cloud.get("records", {}) or {}
        cloud_special = cloud.get("special", {}) or {}
        lines = [
            f"✅ 去重完成（{type_label}）：",
            f"  本地：清理 {local.get('removed', 0)} 条僵尸记录，剩余 {local.get('total_after', 0)} 条",
        ]
        if dedup_type in ("", "records"):
            lines.append(
                f"  云端记录：清理 {cloud_records.get('removed', 0)} 条僵尸记录"
                + (f"（{cloud_records.get('total_before', 0)}→{cloud_records.get('total_after', 0)}）" if cloud_records else "")
            )
        if dedup_type in ("", "special"):
            lines.append(
                f"  云端特殊：去重 {cloud_special.get('removed', 0)} 条重复"
                + (f"（{cloud_special.get('total_before', 0)}→{cloud_special.get('total_after', 0)}）" if cloud_special else "")
            )
        if cloud.get("error"):
            lines.append(f"  ⚠️ 云端错误：{cloud.get('error')}")
        yield event.plain_result("\n".join(lines))

    @filter.command("malicious_cloud_blacklist", alias={"云黑名单"})
    @filter.permission_type(filter.PermissionType.ADMIN)
    async def malicious_cloud_blacklist(self, event: AstrMessageEvent):
        """管理云端 IP 黑名单（管理员）。

        用法：
          云黑名单              → 查看黑名单列表
          云黑名单 add <ip>     → 添加 IP 到黑名单
          云黑名单 rm <ip>      → 从黑名单移除
          云黑名单 list         → 查看黑名单列表
        """
        if not self._cloud_enabled():
            yield event.plain_result("云同步未启用。")
            return
        args = str(event.message.message).strip().split()
        if len(args) < 2:
            yield event.plain_result("⚠️ 用法：\n  云黑名单 list          → 查看列表\n  云黑名单 add <ip>      → 添加\n  云黑名单 rm <ip>       → 移除")
            return
        action = args[1].lower()
        if action == "list":
            yield event.plain_result("⏳ 正在获取黑名单列表…")
            result = await self._cloud_blacklist_list()
            if not result.get("ok"):
                yield event.plain_result(f"❌ 获取失败：{result.get('error', '未知错误')}")
                return
            items = result.get("items", []) or []
            total = result.get("total", len(items))
            if not items:
                yield event.plain_result("📋 黑名单为空。")
                return
            lines = [f"📋 黑名单（共 {total} 条）："]
            for i, ip in enumerate(items, 1):
                lines.append(f"  {i}. {ip}")
            yield event.plain_result("\n".join(lines))
        elif action in ("add", "rm", "remove", "del"):
            if len(args) < 3:
                yield event.plain_result(f"⚠️ 请指定 IP：云黑名单 {action} <ip>")
                return
            ip = args[2]
            op = "添加" if action == "add" else "移除"
            yield event.plain_result(f"⏳ 正在{op} {ip}…")
            if action == "add":
                result = await self._cloud_blacklist_add(ip)
            else:
                result = await self._cloud_blacklist_remove(ip)
            if not result.get("ok"):
                yield event.plain_result(f"❌ {op}失败：{result.get('error', '未知错误')}")
                return
            yield event.plain_result(f"✅ {op}成功：{ip}")
        else:
            yield event.plain_result(f"⚠️ 未知操作：{action}\n用法：list / add <ip> / rm <ip>")
