# 更新日志

## v1.2.0 — 2026-08-05

### 新增功能

- **误判撤回（本地 + 云端）**：被警告消息备案页面新增「撤回」按钮，可将误判警告撤回：
  - **本地撤回**：根据 `log_id` 找到备案记录，将该用户 `count` -1（不低于 0，`total` 不变保留审计），标记日志为 `revoked`；
  - **误判标记**：将被撤回的消息 + 误判理由加入 `_false_positives` 列表，检测前自动跳过匹配消息（精确 + 归一化匹配），避免再次误判；
  - **云端撤回**：如启用云同步误判撤回（`enable_cloud_revoke`），本地撤回时自动向云端发送撤回请求，服务端校验 `bot_id` 必须在该记录的 `sources` 中才会撤回（仅上传该警告的 bot 才能撤回）；
  - 新增 API：`POST /revoke`（本地撤回）、`GET /false_positives`（误判列表）、`POST /cloud/revoke_record`（云端撤回）；
  - 新增配置项：`enable_false_positive_skip`（默认开启）、`enable_cloud_revoke`（默认开启）；
  - 每条备案记录新增 `log_id` 字段（UUID），旧数据加载时自动补填。

- **☁️ 云同步 Web 可视化管理器**：在 `cloud_server/web/` 新增管理器前端，浏览器访问服务端地址即可进入：
  - **无 Token 自动进入登录页**，需输入 `admin_token` 登录；
  - **📊 概览**：记录总数、特殊记录数、禁言中用户、高风险用户、贡献 Bot 列表、运行时长；
  - **📋 警告记录**：搜索（UID/用户名/平台）、批量删除（复选框）、单条删除；
  - **🔴 特殊记录**：按人分类查看政治敏感/违法内容；
  - **📝 审计日志**：查看最近 500 条审计记录（撤回/删除/登录/上传/同步等操作）；
  - **🌐 请求日志**：查看最近 500 条 HTTP 请求记录（方法/路径/状态/客户端）；
  - 服务端新增端点：`POST /api/auth`（登录）、`GET /api/auth_check`（校验）、`GET /api/audit_log`、`GET /api/request_log`、`POST /api/revoke_record`；
  - 读端点（records/special/stats）现接受 `client_token` 或 `admin_token`，便于管理器访问。

### 修复

- **按键失效**：修复插件页所有操作按钮（重置/撤回/清理/云同步等）在 AstrBot 沙箱 iframe 中无响应的问题。
  - 根因：iframe 沙箱阻止 `alert()` / `confirm()` / `prompt()`，导致所有以确认对话框开头的按钮事件立即中止；
  - 修复：用自定义 **toast 提示**（屏幕中间正上方，持续 3 秒，支持 info/ok/error 三种类型）替代 `alert()`；用自定义 **asyncConfirm 模态框** + **asyncPrompt 输入框** 替代 `confirm()` / `prompt()`；
  - 「立即刷新」按钮因不使用确认对话框而一直正常，进一步验证了根因。

## v1.1.0 — 2026-08-04

### 新增功能

- **☁️ 多 bot 云同步**：新增独立 Ubuntu 服务端（`cloud_server/`），零外部依赖（仅 Python 标准库），支持多 bot 共享警告记录、禁言状态与特殊记录。**本地始终保留备份**，云端为补充。
  - **服务端**（`cloud_server/`，独立文件夹）：
    - 基于 `http.server` + `threading` 实现，零依赖；
    - 双 Token 鉴权（`client_token` 上传/同步，`admin_token` 删除）；
    - API：`/api/upload_record`、`/api/upload_special`、`/api/sync`（GET 拉取 / POST 推送）、`/api/delete_record`、`/api/records`、`/api/special`、`/api/stats`、`/api/health`；
    - 同步规则：`count`/`total` 取 max，`last_muted_until`/`last_warned` 取较新者，记录贡献过的 `bot_id` 列表；
    - 提供审计日志（`logs/audit.log.jsonl`）记录删除/同步操作；
    - 提供 `start.sh`/`stop.sh`/`malicious-cloud.service`（systemd）部署方案；
  - **客户端**（`main.py` 内）：
    - 总开关 `enable_cloud_sync` + 五个独立子功能开关（`enable_cloud_upload_record`、`enable_cloud_sync_count`、`enable_cloud_sync_mute`、`enable_cloud_delete_record`、`enable_cloud_upload_special`）；
    - 后台周期同步任务（默认 300 秒，可配置最小 30 秒）；
    - 警告/禁言发生时自动标记待推送，下次周期统一上传；
    - 防回环：拉取合并到本地后不立即触发反向推送；
    - HTTP 请求使用 `urllib + asyncio.to_thread`，不引入新依赖；
    - 同步状态持久化到 `warning_data.json` 的 `cloud` 字段，重启不丢；
  - **LLM 自助 API**：插件注册 6 个 Web API（`cloud/status`、`cloud/upload_record`、`cloud/upload_special`、`cloud/sync`、`cloud/delete_record`、`cloud/records`），LLM 可直接调用；
  - **管理指令**：`/malicious_cloud_status`（云状态）、`/malicious_cloud_sync`（云同步）；
  - **Web UI**：插件页新增「☁️ 云同步」标签页，展示同步状态、子功能开关、统计信息、错误日志、云端记录列表，提供「立即同步」「上传本地记录」「上传特殊记录」按钮；
  - **风险提示**：`enable_cloud_sync_count` / `enable_cloud_sync_mute` 默认关闭，配置 hint 明确标注「⚠️ 误禁言风险」；`enable_cloud_delete_record` 默认关闭并要求 `admin_token`；
  - 配置项共 12 项：`enable_cloud_sync`、`cloud_server_url`、`cloud_client_token`、`cloud_admin_token`、`cloud_bot_id`、`cloud_sync_interval` + 5 个子功能开关。

### 修复

- **重置键无效**：修复插件页「重置」按钮无响应的问题。
  - 后端 `_api_reset` 方法增加错误处理与模糊匹配逻辑，支持通过 `user_id` 在 `platform_id` 为空时查找记录；
  - 前端 `app.js` 重置按钮增加 `data-uid` 属性并传递正确的 `key` 参数（`platform_id:user_id` 格式）。

## v1.0.1 — 2026-08-04

### 新增功能

- **刷屏检测**：单群单人在短时间窗口内连续发送超过阈值（默认 3 条）消息时，调用 LLM 判断是否为无意义刷屏内容（重复字符、纯表情刷屏、乱码等），命中则按恶意处理（累计 x / 警告 / 禁言）。
  - 配置项：`enable_spam_detect`、`spam_threshold`、`spam_window`、`spam_prompt`

- **防误判（二次判定）**：首次判定为严重恶意时，结合该用户最近在本群发送的 5 条文字消息进行二次判定，降低因上下文缺失导致的误判率。
  - 配置项：`enable_anti_false_positive`、`anti_fp_context_count`

- **群管理员/群主豁免警告**：群管理员和群主被判定为恶意时仍然会被记录并增加 x，但不会收到警告消息也不会被禁言。
  - 配置项：`exempt_admin_from_warn`

- **跨群禁言**：当用户在一个群被禁言后，自动在其他群也执行禁言。
  - 检查顺序：机器人是否为该群管理员 → 目标是否在该群 → 目标是否非该群管理员
  - 配置项：`enable_cross_group_mute`

- **特殊记录页面**：当消息可能涉及政治敏感或包含违反法律的行为时，单独记录到特殊记录页面，按人分类归档以便举报。支持一键复制消息内容。
  - 配置项：`enable_special_record`、`special_record_prompt`

- **超时记录页面**：标准备案记录放置超过 7 天后自动转移至超时记录页面（特殊记录不受影响），页面提供一键清理按钮。
  - 配置项：`archive_timeout_days`、`enable_daily_summary`

- **每日总结**：每日自动生成一次统计总结（警告次数、涉及人数、禁言次数、特殊记录数、Top 10 用户），保存至每日总结历史。

- **警告引用原消息**：警告消息现在通过 `reply()` 引用被警告的原消息，并包含消息原文摘要与清晰判定原因。

### 修复

- **全局衰减倒计时不准**：修复了插件重载后衰减倒计时显示与实际触发时间不一致的问题。衰减循环现在基于 `last_decrement` 时间戳计算下次触发时刻，而非固定 sleep。


## v1.0.0 — 初始版本

- 调用大模型判断消息是否含有严重恶意并警告
- 记录每人被警告次数 x，超过阈值（默认 5）则警告 + 禁言 10×x 分钟
- 每 2 小时所有人的 x 次数 -1
- 所有回复以 LLM 当前人格生成
- 插件页面实时显示每个人的 x 次数
- 私聊或机器人非管理员群仅累计 x，不尝试禁言
- 群白名单动态管理
- 被警告消息备案
