"""
astrbot_plugin_check_malicious_message
通过调用大模型判断用户消息是否含有严重恶意内容（辱骂/人身攻击/骚扰/威胁/诈骗等），
检测到时自动发出警告（以 LLM 当前人格的语气生成），并记录每人的被警告次数 x：
  - 当 x 超过阈值（默认 5）且机器人为群管理员时，自动禁言 10*x 分钟；
  - 私聊或机器人非管理员的群仅累计 x，不尝试禁言；
  - 每 2 小时所有人的 x 自动 -1；
  - 通过插件页面实时展示每个人的 x 次数。

依赖 AstrBot >= 4.5.7 的 LLM 调用接口（context.llm_generate / get_current_chat_provider_id）。
"""

import asyncio
import json
import os
import re
import time
from typing import Optional

from astrbot.api import AstrBotConfig, logger
from astrbot.api.event import AstrMessageEvent, MessageEventResult, filter
from astrbot.api.star import Context, Star
from astrbot.api.web import json_response, request

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
DATA_FILENAME = "warning_data.json"


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
        self._meta: dict = {"last_decrement": time.time()}
        # 用户级警告冷却记录: {key: 上次警告时间戳}
        self._cooldowns: dict[str, float] = {}
        # 机器人群角色缓存: {(platform_id, group_id): (role, expire_ts)}
        self._bot_role_cache: dict[tuple[str, str], tuple[str, float]] = {}
        self._data_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), DATA_FILENAME)
        self._decrement_task: Optional[asyncio.Task] = None

        self._load()
        self._apply_pending_decrements()

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

    # ------------------------------------------------------------------ 生命周期

    @filter.on_astrbot_loaded()
    async def _on_loaded(self):
        """AstrBot 初始化完成后启动后台衰减任务。"""
        if self._decrement_task is None or self._decrement_task.done():
            self._decrement_task = asyncio.create_task(self._decrement_loop())

    async def terminate(self):
        """插件卸载 / 停用时调用。"""
        if self._decrement_task and not self._decrement_task.done():
            self._decrement_task.cancel()
            try:
                await self._decrement_task
            except asyncio.CancelledError:
                pass
        self._save()

    # ------------------------------------------------------------------ 主流程

    @filter.event_message_type(filter.EventMessageType.ALL, priority=30)
    async def on_message(self, event: AstrMessageEvent):
        """监听所有消息，检测是否含有严重恶意内容。"""
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
                return None

        # 调用 LLM 判定
        malicious, reason = await self._detect(event, checked_str, umo)
        if not malicious:
            return None

        # 命中恶意：累计 x
        rec = self._increment_count(event, reason, now)
        x = rec["count"]

        if cooldown > 0:
            self._cooldowns[key] = now

        # 判断是否为“可禁言场景”：群聊 + aiocqhttp + enable_mute + 机器人为群管理员
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

        # 生成警告文案（以当前人格语气；可禁言场景会包含 x/禁言提示）
        warn_text = await self._generate_warning(
            umo, rec, reason, x, mute_capable, muted, mute_minutes
        )
        logger.info(
            f"[恶意消息检测] 命中恶意 sender={sender_id} x={x} umo={umo} "
            f"mute_capable={mute_capable} muted={muted}({mute_minutes}min) "
            f"reason={reason} text={message_str[:60]!r}"
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
    ) -> str:
        """以 LLM 当前人格的语气生成警告文案。

        - 可禁言场景（mute_capable=True）：必须告知当前累计次数 x，并按 x 与阈值的关系
          给出禁言提示（见 _build_mute_hint）。
        - 不可禁言场景（私聊/机器人非管理员群）：只告知累计 x，不提禁言。
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
            return self._template_warning(rec, reason, mute_hint)

        system_prompt = (
            persona_prompt.rstrip()
            + "\n\n[附加任务] 你现在需要以你的人格设定和语气，对一名刚刚发送了恶意消息的用户"
            "发出简短、有威慑力但符合你人设的警告。要求：不超过 100 字，只输出警告正文，"
            "不要输出引号、JSON 或任何解释。必须自然地包含给定的累计次数与禁言提示信息。"
        )
        user_prompt = (
            f"用户 {rec.get('sender_name') or '该用户'} 发送了恶意消息。"
            f"判定原因：{reason or '含有严重恶意内容'}。\n"
            f"这是该用户第 {x} 次被警告，历史累计 {rec.get('total', x)} 次。\n"
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
        return self._template_warning(rec, reason, mute_hint)

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

    def _template_warning(self, rec: dict, reason: str, mute_hint: str = "") -> str:
        """LLM 不可用时的模板警告。"""
        cfg = self.config
        tpl = cfg.get("warn_message") or DEFAULT_WARN_MESSAGE
        text = tpl.replace("{sender}", rec.get("sender_name") or "该用户")
        text = text.replace("{x}", str(rec.get("count", 0)))
        if reason and "{reason}" in text:
            text = text.replace("{reason}", reason)
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

    # ------------------------------------------------------------------ 计数与衰减

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
    ) -> None:
        """备案：保存被警告的消息内容与上下文（仅保留最近 500 条）。"""
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
            "count": x,
            "muted": muted,
            "mute_minutes": mute_minutes,
        }
        self._logs.append(entry)
        # 仅保留最近 500 条，防止无限增长
        if len(self._logs) > 500:
            self._logs = self._logs[-500:]

    async def _decrement_loop(self):
        """每 2 小时将所有人的 count - 1（不低于 0）。"""
        while True:
            try:
                await asyncio.sleep(DECAY_INTERVAL)
                changed = False
                for rec in self._records.values():
                    if rec.get("count", 0) > 0:
                        rec["count"] = max(0, rec.get("count", 0) - 1)
                        changed = True
                self._meta["last_decrement"] = time.time()
                if changed:
                    self._save()
                    logger.info("[恶意消息检测] 每 2 小时衰减：所有用户警告次数 -1")
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.warning(f"[恶意消息检测] 衰减任务异常: {e}")
                await asyncio.sleep(60)

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

    # ------------------------------------------------------------------ 持久化

    def _load(self):
        try:
            if os.path.exists(self._data_path):
                with open(self._data_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._records = data.get("records", {}) or {}
                self._logs = data.get("logs", []) or []
                self._meta = data.get("meta", {}) or {}
                if "last_decrement" not in self._meta:
                    self._meta["last_decrement"] = time.time()
        except Exception as e:
            logger.warning(f"[恶意消息检测] 加载持久化数据失败，使用空数据: {e}")
            self._records = {}
            self._logs = []
            self._meta = {"last_decrement": time.time()}

    def _save(self):
        try:
            data = {"records": self._records, "logs": self._logs, "meta": self._meta}
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
        """构造警告消息结果（x/禁言提示已包含在 warn_text 中）。"""
        cfg = self.config
        result = event.make_result()
        if bool(cfg.get("warn_at_sender", True)) and sender_id:
            result.at(event.get_sender_name() or sender_id, sender_id)
            result.message(" " + warn_text)
        else:
            result.message(warn_text)

        if bool(cfg.get("stop_event", True)):
            result.stop_event()
        else:
            result.continue_event()
        return result

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
        """返回被警告消息备案（最近 500 条，倒序）。"""
        limit = request.query.get("limit", 200, type=int) or 200
        items = list(reversed(self._logs))[:limit]
        return json_response(
            {"total": len(self._logs), "items": items}
        )

    async def _api_reset(self):
        """重置某用户的警告次数。body: {"key": "..."} 或 {"user_id":"...","platform_id":"..."}"""
        body = {}
        try:
            body = await request.json(default={}) or {}
        except Exception:
            body = {}
        key = body.get("key")
        if not key:
            pid = body.get("platform_id", "")
            uid = body.get("user_id", "")
            if uid:
                key = self._record_key(pid, uid)
        if not key:
            return json_response({"ok": False, "msg": "缺少 key/user_id"}, status_code=400)
        rec = self._records.get(key)
        if rec is None:
            return json_response({"ok": False, "msg": "记录不存在"}, status_code=404)
        rec["count"] = 0
        self._save()
        return json_response({"ok": True, "key": key})

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
