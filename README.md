# astrbot_plugin_check_malicious_message 恶意消息检测

> 本插件由AI辅助完成，如有问题请前往 `https://qm.qq.com/q/2HuArULfbq` 反馈

一个 [AstrBot](https://github.com/AstrBotDevs/AstrBot) 插件：调用大模型实时判断用户消息是否含有**严重恶意**（辱骂 / 人身攻击 / 骚扰 / 威胁 / 诈骗等），检测到时：

- 以 **LLM 当前人格的语气**生成警告并发出，**引用被警告的原消息**并指出清晰原因；
- 记录每人的被警告次数 **x**；
- 当 x 超过阈值（默认 5）且机器人为群管理员时，自动**禁言 10×x 分钟**，并**跨群同步禁言**；
- 私聊或机器人非管理员的群**只累计 x，不尝试禁言**；
- 群管理员/群主被判定为恶意时**仍记录并增加 x，但不警告不禁言**；
- 每 **2 小时**所有人的 x 自动 **-1**；
- **刷屏检测**：连续发送多条无意义消息时自动判定并警告；
- **防误判**：首次判定为恶意时结合最近本群消息二次判定；
- **特殊记录**：政治敏感/违法内容单独归档，按人分类以便举报；
- **超时记录**：标准备案记录超 7 天自动归档，可一键清理；
- **☁️ 多 bot 云同步**：自建云服务端后，多个 bot 可共享警告记录、禁言状态与特殊记录；
- **↩️ 误判撤回**：被警告消息备案页可一键撤回误判警告，自动递减 count 并标记消息以免再次误判，同时向云端发送撤回请求（需 bot_id 一致）；
- **🖥️ 云端可视化管理器**：浏览器访问服务端地址即可进入管理后台，查看记录、特殊记录、审计日志、请求日志；
- **🚫 IP 黑名单**：管理员可通过 WebUI 或 AstrBot 指令拉黑 IP，被拉黑 IP 无法访问服务端；
- 通过 **插件页面**实时展示每个人的 x 次数。

## 功能特性

- 🤖 **大模型判定**：复用 AstrBot 已配置的聊天模型提供商，或单独指定一个轻量模型用于检测。
- 🎭 **人格化警告**：警告文案由 LLM 以 astrbot 配置文件的首选人格语气生成（非固定模板），失败时回退模板。
- 📎 **引用原消息**：警告通过 `reply()` 引用被警告的原消息，并包含消息原文摘要与清晰判定原因。
- 📈 **累计计数**：每个用户的警告次数 x 持久化保存，重启不丢失。
- 🛡️ **自动禁言**：x 超过阈值时禁言 `倍数 × x` 分钟（仅 aiocqhttp 群 + 机器人管理员生效）。
- 🌐 **跨群禁言**：用户在一个群被禁言后，自动在其他群（机器人同样为管理员、用户存在且非管理员）也执行禁言。
- 👑 **管理员豁免**：群管理员/群主被判定为恶意时仍记录并增加 x，但不警告不禁言。
- 🔄 **防误判**：首次判定为恶意时结合最近本群 5 条消息进行二次判定，降低误判率。
- 💬 **刷屏检测**：单群单人连续发送多条消息时判断是否为无意义内容并决定是否警告。
- 🔔 **分级警告提示**：可禁言场景下警告文案随 x 变化（接近阈值预告 / 触发禁言告知时长与再犯后果）。
- ⏳ **自动衰减**：每 2 小时所有用户 x - 1，停机期间也会补算。
- 📊 **实时看板**：插件页实时展示各用户 x、累计、禁言状态，支持重置。
- 🗂️ **消息备案**：保存每条被警告消息的内容、原因、上下文，插件页可审计追溯。
- 🔴 **特殊记录**：政治敏感/违法内容单独归档，按人分类，支持一键复制以便举报。
- 📦 **超时归档**：标准备案记录超过 7 天自动转移至超时记录页面，可一键清理。
- 📋 **每日总结**：每日自动生成统计总结（警告次数、涉及人数、禁言次数、Top 10 用户）。
- ↩️ **误判撤回**：被警告消息备案页可一键撤回误判，自动递减 count、标记消息以免再次误判、向云端发送撤回请求。
- ⚙️ **白名单指令**：通过指令动态增删群白名单，持久化到配置文件。
- ⚠️ **事件拦截**：可选拦截事件传播，阻止机器人对恶意消息做 LLM 回复。
- 🎛️ **精细控制**：私聊/群聊开关、指令跳过、长度过滤、用户与群聊白名单。

## 环境要求

- AstrBot **>= 4.5.7**（使用了新版 `context.llm_generate` / `get_current_chat_provider_id` 接口）
- 至少配置一个可用的聊天模型提供商，并配置了首选人格（WebUI「人格与情景」）
- 禁言功能需 aiocqhttp（OneBot 协议端）且机器人具备群管理员权限

## 安装

将本插件目录放入 AstrBot 的插件目录：

```
AstrBot/data/plugins/astrbot_plugin_check_malicious_message/
├── metadata.yaml
├── _conf_schema.json
├── main.py
├── pages/stats/          # 插件页（实时统计看板）
│   ├── index.html
│   ├── app.js
│   └── style.css
└── README.md
```

> 建议目录名使用 `astrbot_plugin_check_malicious_message`。重启 AstrBot 或在 WebUI「插件」页面重新加载即可。

## 配置

在 WebUI「插件」页面点击本插件的配置按钮即可可视化编辑。主要配置项：

### 基础检测

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `enable` | `true` | 总开关 |
| `provider_id` | 空（自动） | 检测/生成警告所用模型，建议选 flash / mini 等快速廉价模型 |
| `scan_private` / `scan_group` | `true` / `true` | 是否检测私聊 / 群聊（私聊只累计 x，不禁言） |
| `scan_command` | `false` | 是否检测指令消息（默认跳过 `/help` 等） |
| `command_prefixes` | `["/"]` | 指令前缀列表（与唤醒前缀保持一致） |
| `min_length` / `max_length` | `2` / `500` | 过短不检测、过长截断 |
| `stop_event` | `true` | 检测到恶意时是否拦截事件传播 |
| `warn_at_sender` | `true` | 警告是否 @ 发送者 |
| `warn_message` | （内置） | LLM 不可用时的回退模板，支持 `{sender}` `{x}` `{reason}` |
| `cooldown` | `0` | 同一用户警告冷却秒数，`0` 为不限制（每次恶意都计入 x） |

### 禁言（累计 x 触发）

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `enable_mute` | `true` | 是否启用自动禁言（仅 aiocqhttp 群 + 机器人管理员） |
| `mute_threshold` | `5` | x 超过此值触发禁言（5 表示第 6 次警告开始禁言） |
| `mute_multiplier` | `10` | 禁言分钟数 = 倍数 × x（x=6 → 60 分钟） |
| `mute_max_minutes` | `43200` | 单次禁言上限（30 天，OneBot 协议上限） |

### 白名单与判定标准

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `whitelist_users` | `[]` | 用户白名单，豁免检测与计数 |
| `whitelist_groups` | `[]` | 群聊白名单，豁免检测 |
| `judge_prompt` | （内置） | 判定恶意消息的系统提示词，可自定义标准 |

### 刷屏检测

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `enable_spam_detect` | `true` | 是否启用刷屏检测 |
| `spam_threshold` | `3` | 时间窗口内连续发送超过此条数触发刷屏检测 |
| `spam_window` | `10` | 刷屏检测时间窗口（秒） |
| `spam_prompt` | （内置） | 刷屏判定系统提示词 |

### 防误判与管理员豁免

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `enable_anti_false_positive` | `true` | 首次判定恶意时结合上下文二次判定 |
| `anti_fp_context_count` | `5` | 二次判定时取最近多少条本群消息作为上下文 |
| `exempt_admin_from_warn` | `true` | 群管理员/群主豁免警告（仍记录+x） |

### 跨群禁言

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `enable_cross_group_mute` | `true` | 用户在一个群被禁言后自动在其他群禁言 |

### 特殊记录与超时归档

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `enable_special_record` | `true` | 检测政治敏感/违法内容并单独归档 |
| `special_record_prompt` | （内置） | 特殊记录检测系统提示词 |
| `archive_timeout_days` | `7` | 标准备案记录多少天后转移至超时记录 |
| `enable_daily_summary` | `true` | 每日自动总结并执行超时归档 |

### 云同步（多 bot 数据共享）

> ⚠️ **重要提示**：所有使用本插件并开启云功能的 AI 数据共享，本地保留备份。请在可信网络环境下使用，并确保服务端 token 已配置。

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `enable_cloud_sync` | `false` | 云同步总开关。开启前需先部署服务端并填写 token |
| `cloud_server_url` | `""` | 云服务端 URL，如 `http://your-server:8765` |
| `cloud_client_token` | `""` | 客户端 Token（上传/同步用），与服务端一致 |
| `cloud_admin_token` | `""` | 管理员 Token（删除记录用），与服务端一致 |
| `cloud_bot_id` | `""` | 本 bot 唯一标识，留空自动生成并持久化 |
| `cloud_sync_interval` | `300` | 后台同步间隔（秒），最小 30 秒 |

子功能开关（可独立启用/禁用）：

| 子功能 | 默认 | 风险说明 |
| --- | --- | --- |
| `enable_cloud_upload_record` | `true` | 相对安全：本地记录按 max 合并到云端，不覆盖较大值 |
| `enable_cloud_sync_count` | `false` | ⚠️ **误禁言风险**：其他 bot 警告该用户的次数会同步到本地，可能导致本地 count 暴涨并提前触发禁言 |
| `enable_cloud_sync_mute` | `false` | ⚠️ **误禁言风险**：其他 bot 对该用户的禁言状态会同步到本地，可能导致本地 bot 误禁言用户 |
| `enable_cloud_delete_record` | `false` | ⚠️ 谨慎：可通过 API/指令删除云端记录，需 admin_token，操作不可恢复（记入审计日志） |
| `enable_cloud_upload_special` | `true` | 相对安全：本地特殊记录上传到云端，便于多 bot 共享举报证据 |
| `enable_cloud_revoke` | `true` | 相对安全：本地撤回误判警告时自动向云端发送撤回请求，服务端校验 bot_id 一致才撤回 |

### 误判撤回

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `enable_false_positive_skip` | `true` | 被标记为误判的消息（精确+归一化匹配）在检测前会被跳过，避免再次误判 |

## 工作流程

1. 插件以较高优先级（`priority=30`）监听所有消息事件。
2. 经开关、长度、指令、白名单、冷却过滤后，**追踪消息**（用于刷屏检测和防误判上下文）。
3. **刷屏检测**：若用户在时间窗口内连续发送超过阈值条消息，调用 LLM 判断是否为无意义刷屏，命中则按恶意处理。
4. 将消息文本送入大模型判定恶意。
5. **防误判**：若首次判定为恶意，结合该用户最近在本群的 5 条消息进行二次判定，不通过则放行。
6. **管理员豁免检查**：若目标为群管理员/群主，仍记录+x 但跳过警告和禁言。
7. **特殊记录检测**：异步检测消息是否涉及政治敏感/违法内容，若是则归档到特殊记录。
8. 若判定为恶意：
   1. 该用户的 **x +1**（持久化），累计总次数 +1；
   2. 取 LLM 当前首选人格的 system prompt，**以人格语气生成警告文案**（包含引用原消息与清晰原因，失败回退模板）；
   3. 若 `x > mute_threshold` 且为群聊且机器人为群管理员（aiocqhttp）：调用 `set_group_ban` 禁言 `mute_multiplier × x` 分钟；
   4. **跨群禁言**：自动在机器人同样为管理员的其他群也执行禁言；
   5. 发送警告（引用原消息，可 @ 发送者），按 `stop_event` 决定是否拦截事件。
9. 若非恶意：不产生任何输出，事件正常继续传播。
10. **后台任务**：
    - 每 2 小时将所有人的 x - 1（不低于 0），停机期间会补算；
    - 每 6 小时检查是否有超时备案记录需要归档；
    - 每日生成一次统计总结。

### x 的含义与衰减

- **x（count）**：当前累计警告次数，每 2 小时 -1，触发禁言时按此计算时长。
- **total**：历史总警告次数，永不衰减，用于审计。
- 例：用户第 6 次被警告（x=6），`mute_multiplier=10` → 禁言 60 分钟；2 小时后 x 衰减为 5，不再处于禁言阈值之上。

### 关于禁言的平台限制

- 仅 **aiocqhttp（OneBot 协议端）** 支持禁言（`set_group_ban`）。
- 插件会先查询机器人在该群的角色（缓存 10 分钟），仅当为 `admin` / `owner` 时才尝试禁言；非管理员或查询失败时**只累计 x，不尝试禁言**。
- 其他平台（微信、Telegram 等）触发警告时仅累计 x。

### 关于人格化警告

警告文案通过额外一次 LLM 调用生成，system prompt = 首选人格的 prompt + 附加任务说明（要求以人设语气输出不超过 80 字的警告）。仅当检测到恶意时才发起此调用，开销可控。若该调用失败，回退到 `warn_message` 模板。

### 关于失败策略（fail-open）

大模型调用失败、未配置提供商、获取人格失败等异常发生时，插件**放行**消息（不阻断正常聊天），仅记录警告日志。

## 警告文案与禁言提示规则

当机器人**具有群管理权限**（aiocqhttp + 群管理员）时，警告文案会以 LLM 当前人格的语气生成，并包含累计次数 x 与对应的禁言提示：

| 当前 x | 提示内容 |
| --- | --- |
| `x < 阈值-1` | 告知累计 x 次，累计达到阈值将被禁言 |
| `x == 阈值-1` | 告知“再次被警告将禁言 10×(x+1) 分钟”（即下次触发时的禁言时长） |
| `x >= 阈值`（本次已禁言） | 告知“本次已被禁言 10×x 分钟，若再犯下次将禁言 10×(x+1) 分钟” |

> 私聊或机器人**非管理员**的群：警告文案只告知累计 x 次，**不提禁言**（仅累计 x，不尝试禁言）。

禁言时长 = `mute_multiplier × x`（默认 10×x 分钟）。例如阈值=5、倍数=10，用户第 6 次违规（x=6）→ 禁言 60 分钟。

## 插件页（实时统计看板）

在 WebUI「插件」页面进入本插件详情，可看到 **stats** 页面，提供四个标签页：

**警告次数统计**

- 总人数、x>5（高风险）人数、当前禁言中人数、距下次全局衰减倒计时；
- 每位用户的当前 x、累计、最近警告原因与时间、禁言状态；
- 默认每 5 秒自动刷新，可手动刷新或重置某用户的 x。

**被警告消息备案**

- 每条被警告消息的完整内容、判定原因、时间、用户、平台/群、x 值、是否禁言及禁言时长；
- 管理员被记录的消息会标注"管理员"标签；
- 倒序展示最近 500 条，用于审计追溯。

**特殊记录**

- 政治敏感/违法内容单独归档，按人分类；
- 显示分类（政治敏感/违法犯罪/暴恐/未成年人保护/其他）、特殊原因、消息内容；
- 支持一键复制消息内容，便于向有关部门举报。

**超时记录**

- 标准备案记录放置超过 7 天后自动转移至此页面（特殊记录不受影响）；
- 显示原时间、归档时间、用户、消息内容、判定原因；
- 提供"清理全部超时记录"按钮，一键清空；
- 显示每日总结历史（警告次数、涉及人数、禁言次数、Top 10 用户）。

数据通过后端 Web API（`/{插件名}/stats`、`/logs`、`/reset`、`/special`、`/timeout`、`/timeout/clear`）提供，记录在插件本地数据文件 `warning_data.json` 中。

**☁️ 云同步**

新增的「云同步」标签页展示：

- 当前云同步开关状态、服务端 URL、Bot ID；
- 五个子功能的开关状态（含 ⚠️ 误禁言风险标记）；
- 累计同步/推送/拉取/错误次数、上次同步时间、距下次同步倒计时；
- 上次上传/拉取的记录数；
- 当前待推送队列长度与同步进行中状态；
- 上次错误信息（如有）；
- 云端记录列表（用户、平台、云端 x、累计、禁言状态、来源 bot）；
- 操作按钮：🔄 立即同步、📤 上传本地记录、📤 上传特殊记录、🔁 刷新状态。

数据通过后端 Web API（`/{插件名}/cloud/status`、`/cloud/upload_record`、`/cloud/upload_special`、`/cloud/sync`、`/cloud/delete_record`、`/cloud/records`）提供。

## ☁️ 云同步功能

### 概述

云同步允许同一用户使用多个 AstrBot 实例时，在各 bot 之间共享警告记录、禁言状态与特殊记录。**所有数据本地始终保留备份**，云端为补充。

### 架构

```
┌─────────────────────┐         ┌──────────────────────┐
│   AstrBot 客户端 A  │ ──┬──▶ │  cloud_server/       │
│  (本插件 + Token)   │   │    │  (Ubuntu, stdlib)    │
└─────────────────────┘   │    │                      │
                          │    │  • POST /api/upload_*│
┌─────────────────────┐   │    │  • GET  /api/sync    │
│   AstrBot 客户端 B  │ ──┼──▶ │  • POST /api/sync    │
│  (本插件 + Token)   │   │    │  • POST /api/delete  │
└─────────────────────┘   │    │  (需 admin_token)    │                          │    └──────────────────────┘
┌─────────────────────┐   │
│   AstrBot 客户端 C  │ ──┘
└─────────────────────┘
```

### 部署服务端

服务端代码位于插件目录下 `cloud_server/`，**零外部依赖**（仅 Python 标准库）。详细部署步骤见 [`cloud_server/README.md`](cloud_server/README.md)，简要步骤：

```bash
# 1. 上传到 Ubuntu 服务器
rsync -avz cloud_server/ user@server:/opt/malicious-cloud/

# 2. 修改 token（必须！）
cd /opt/malicious-cloud
nano config.json   # 修改 client_token 与 admin_token
# 生成随机 token: python3 -c "import secrets; print(secrets.token_urlsafe(32))"

# 3. 启动（三选一）
./start.sh                           # 前台
./start.sh --daemon                  # 后台
# 或 systemd 服务：
sudo cp malicious-cloud.service /etc/systemd/system/
sudo systemctl enable --now malicious-cloud

# 4. 验证
curl http://localhost:8765/api/health
```

### 客户端配置

在 WebUI「插件」→「恶意消息检测」→「配置」中：

1. 开启 `enable_cloud_sync`（总开关）；
2. 填写 `cloud_server_url`（如 `http://your-server:8765`）；
3. 填写 `cloud_client_token`（与服务端 `client_token` 一致）；
4. 如需删除云端记录：填写 `cloud_admin_token`（与服务端 `admin_token` 一致）并开启 `enable_cloud_delete_record`；
5. （可选）填写 `cloud_bot_id`，留空将自动生成；
6. 按需开启子功能开关（注意 ⚠️ 风险提示）；
7. 保存后插件自动启动后台同步任务。

### 同步规则

| 字段 | 规则 |
| --- | --- |
| `count` / `total` | `max(本地, 云端)` —— 取较大值，避免丢失警告进度 |
| `last_warned` / `last_muted_until` | 取较新者 |
| `sender_name` / `last_reason` | 取较新者的信息 |
| `sources` | 累积所有贡献过的 bot_id |
| 特殊记录 | 按 (user_id, message, time) 去重，避免回环 |

### 后台任务

- 周期同步：默认每 300 秒执行一次完整同步（拉取 → 推送 → 上传特殊）；
- 警告时触发：本地警告发生时，标记对应 key 为待推送，下次同步时上传；
- 持久化：同步状态保存在 `warning_data.json` 的 `cloud` 字段，重启不丢；
- 防回环：拉取后合并到本地，不会立即触发反向推送；
- 失败重试：每次失败计入 `error_count`，下次周期继续尝试。

### LLM 自助 API

LLM 可通过以下 Web API 自助调用云同步功能（AstrBot 自动转发到插件 handler）：

| 方法 | 路径 | 鉴权 | 说明 |
| --- | --- | --- | --- |
| GET | `cloud/status` | Dashboard | 查询云同步状态 |
| POST | `cloud/upload_record` | Dashboard | 上传警告记录（body: `{"keys": [...]}` 或空全量） |
| POST | `cloud/upload_special` | Dashboard | 上传特殊记录（body: `{"limit": 100}`） |
| POST | `cloud/sync` | Dashboard | 执行一次完整同步（拉取+推送） |
| POST | `cloud/delete_record` | Dashboard | 删除云端记录（body: `{"keys": [...]}`，需 admin_token + 子开关） |
| POST | `cloud/revoke_record` | Dashboard | 向云端发送误判撤回请求（body: `{"record_key","log_id","message","reason"}`，需 bot_id 一致） |
| GET | `cloud/records` | Dashboard | 查询云端记录列表 |
| POST | `cloud/dedup` | Dashboard | 手动去重（body: `{"type": "records"|"special"|""}`，需 admin_token） |
| GET | `cloud/blacklist` | Dashboard | 获取云端 IP 黑名单列表（需 admin_token） |
| POST | `cloud/blacklist_add` | Dashboard | 添加 IP 到云端黑名单（body: `{"ip": "..."}`，需 admin_token） |
| POST | `cloud/blacklist_remove` | Dashboard | 从云端黑名单移除 IP（body: `{"ip": "..."}`，需 admin_token） |
| POST | `revoke` | Dashboard | 本地撤回误判警告（body: `{"log_id","reason"}`，递减 count 并标记以免再次误判） |
| GET | `false_positives` | Dashboard | 查询误判撤回记录列表 |

> 调用路径：`POST /api/v1/plugins/extensions/astrbot_plugin_check_malicious_message/cloud/sync`。

### ☁️ Web 可视化管理器

浏览器访问服务端地址（如 `http://your-server:8765/`）即可进入管理后台：

1. **输入 Token 登录**，系统自动识别 Token 类型（管理员/客户端）；
2. **📊 概览**：记录总数、特殊记录数、禁言中用户、高风险用户、贡献 Bot 列表、运行时长；
3. **📋 警告记录**：搜索（UID/用户名/平台）、批量删除（复选框）、单条删除；
4. **🔴 特殊记录**：按人分类查看政治敏感/违法内容；
5. **📝 审计日志**：查看最近 500 条审计记录（撤回/删除/登录/上传/同步等操作）；
6. **🌐 请求日志**：查看最近 500 条 HTTP 请求记录（方法/路径/状态/客户端）；
7. **🚫 IP 黑名单**（仅管理员）：添加/移除 IP 黑名单，被拉黑 IP 无法访问服务。

管理器前端文件位于 `cloud_server/web/`（`index.html` / `app.js` / `style.css`），由服务端自动提供，无需额外配置。

### ⚠️ 风险提示

1. **误禁言风险**：开启 `enable_cloud_sync_count` 或 `enable_cloud_sync_mute` 后，其他 bot 的判定会影响本地，可能导致本地 bot 误禁言用户。**仅在多个 bot 服务于同一用户群体、希望统一警告/禁言策略时才开启**。
2. **数据共享**：所有开启云功能的 bot 数据互通。请仅与可信的 bot 共享同一服务端。
3. **删除不可恢复**：`enable_cloud_delete_record` 开启后，删除操作会记录到服务端审计日志但数据本身不可恢复，请谨慎操作。
4. **Token 安全**：`client_token` 与 `admin_token` 必须是足够长的随机字符串，且二者不同。生产环境建议用 Nginx 反向代理 + HTTPS。
5. **本地备份**：即使开启云同步，本地 `warning_data.json` 始终保留，云端服务不可用时插件仍正常工作。

## 管理指令

> 以下指令仅管理员可用。

| 指令 | 别名 | 说明 |
| --- | --- | --- |
| `/malicious_stats` | `恶意统计` | 查看警告统计 Top 20 及距下次衰减时间 |
| `/malicious_reset <user_id>` | `恶意重置` | 重置某用户当前 x 为 0 |
| `/malicious_wl_add <群号>` | `恶意白名单添加` | 将群加入白名单（持久化到配置，重启不丢） |
| `/malicious_wl_del <群号>` | `恶意白名单删除` | 将群移出白名单 |
| `/malicious_wl_list` | `恶意白名单列表` | 查看当前群白名单 |
| `/malicious_cloud_status` | `云状态` | 查看云同步状态（子功能开关、统计、上次同步时间等） |
| `/malicious_cloud_sync` | `云同步` | 手动触发一次云同步（拉取+推送） |
| `/malicious_cloud_dedup` | `云去重` | 手动去重：清理本地僵尸记录 + 云端去重（支持 records/special 参数） |
| `/malicious_cloud_blacklist` | `云黑名单` | 管理云端 IP 黑名单（list 查看 / add <ip> 添加 / rm <ip> 移除） |

群白名单指令会通过 `save_config_async` 直接写回插件配置文件，WebUI 配置页与运行时保持一致。

## 效果示例

```
用户A（第 6 次违规）: 你这种人就是垃圾，赶紧去死吧
机器人: [人格语气警告]（并自动禁言 60 分钟，拦截后续 LLM 回复）

用户B（第 2 次违规，私聊）: 算了不跟你废话
机器人: [人格语气警告]（仅累计 x=2，不尝试禁言）

用户C: 这个功能我觉得还有点问题啊
（非恶意，机器人正常回复，不被打断）
```

## 文件结构

```
astrbot_plugin_check_malicious_message/
├── metadata.yaml          # 插件元数据
├── _conf_schema.json       # 配置项 Schema（WebUI 可视化配置）
├── main.py                 # 插件主逻辑（含云同步客户端）
├── pages/stats/            # 实时统计插件页
│   ├── index.html          # 含「☁️ 云同步」标签页
│   ├── app.js              # 含云同步状态加载与操作
│   └── style.css           # 含云同步面板样式
├── cloud_server/           # ☁️ 云同步服务端（独立部署到 Ubuntu）
│   ├── server.py           # 主服务端程序（stdlib，零依赖）
│   ├── config.json         # 服务端配置（端口/Token）
│   ├── start.sh / stop.sh  # 启停脚本
│   ├── malicious-cloud.service  # systemd 服务文件
│   ├── requirements.txt    # 依赖说明（无第三方依赖）
│   ├── README.md           # 服务端部署文档
│   └── web/                # 🖥️ Web 可视化管理器前端
│       ├── index.html      # 登录页 + 仪表盘
│       ├── app.js          # 管理器逻辑
│       └── style.css       # 管理器样式
├── CHANGELOG.md            # 更新日志
├── README.md
└── warning_data.json       # 运行时自动生成，保存警告记录与云同步状态
```

## 更新日志

详见 [CHANGELOG.md](CHANGELOG.md)。

## 许可证

MIT
