# 恶意消息检测 - 云同步服务端

本服务端配合 AstrBot 插件 `astrbot_plugin_check_malicious_message` 使用，提供多 bot 间的警告记录与禁言状态云同步能力。

**零外部依赖**：仅使用 Python 标准库（`http.server` + `threading`），Ubuntu 20.04+ 自带 Python 3.8 即可运行，无需 `pip install` 任何包。

## 目录结构

```
cloud_server/
├── server.py                    # 主服务端程序
├── config.json                  # 配置文件（端口/Token/路径）
├── requirements.txt             # 依赖说明（无第三方依赖）
├── start.sh                     # 启动脚本（前台/后台）
├── stop.sh                      # 停止脚本
├── malicious-cloud.service      # systemd 服务文件
├── README.md                    # 本文档
├── web/                         # 🖥️ Web 可视化管理器前端
│   ├── index.html               # 登录页 + 仪表盘
│   ├── app.js                   # 管理器逻辑
│   └── style.css                # 管理器样式
├── data/                        # 数据目录（自动创建）
│   ├── records.json             # 警告记录存储
│   └── special_records.json     # 特殊记录存储
└── logs/                        # 日志目录（自动创建）
    ├── audit.log.jsonl          # 审计日志（删除/同步/撤回/登录操作）
    └── request.log.jsonl        # 请求日志
```

## Web 可视化管理器

启动服务端后，浏览器访问 `http://your-server:8765/` 即可进入管理后台：

1. **无 Token 自动进入登录页**，输入 `admin_token` 登录（Token 存储在浏览器 localStorage）；
2. **📊 概览**：记录总数、特殊记录数、禁言中用户、高风险用户、贡献 Bot 列表、运行时长；
3. **📋 警告记录**：搜索（UID/用户名/平台）、批量删除（复选框）、单条删除；
4. **🔴 特殊记录**：按人分类查看政治敏感/违法内容；
5. **📝 审计日志**：查看最近 500 条审计记录（撤回/删除/登录/上传/同步等操作）；
6. **🌐 请求日志**：查看最近 500 条 HTTP 请求记录。

> 管理器前端文件位于 `web/` 目录，由服务端自动提供，无需额外配置。

## 部署步骤

### 1. 上传到服务器

将整个 `cloud_server` 目录上传到 Ubuntu 服务器，例如 `/opt/malicious-cloud/`：

```bash
# 在服务器上
sudo mkdir -p /opt/malicious-cloud
sudo chown $USER:$USER /opt/malicious-cloud
# 用 scp / rsync 上传
rsync -avz cloud_server/ user@server:/opt/malicious-cloud/
```

### 2. 修改配置文件（关键）

```bash
cd /opt/malicious-cloud
nano config.json
```

**务必修改以下字段**：

```json
{
  "host": "0.0.0.0",
  "port": 8765,
  "client_token": "请修改为一个足够长的随机字符串",
  "admin_token": "请修改为另一个不同的随机字符串",
  "enable_request_logging": true
}
```

生成随机 Token 的方法：

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

> ⚠️ `client_token` 用于上传/同步数据，`admin_token` 用于删除记录。两者必须不同，且足够长（建议 32 字节以上）。

### 3. 安装 Python（如未安装）

```bash
sudo apt update
sudo apt install -y python3
python3 --version  # 需要 >= 3.8
```

### 4. 启动服务

#### 方式 A：手动启动（测试用）

```bash
cd /opt/malicious-cloud
./start.sh                    # 前台运行
./start.sh --daemon           # 后台运行
./start.sh --port 9000        # 指定端口
./stop.sh                     # 停止后台进程
```

#### 方式 B：systemd 服务（生产环境推荐）

```bash
# 1. 复制服务文件
sudo cp /opt/malicious-cloud/malicious-cloud.service /etc/systemd/system/

# 2. 如需修改路径，编辑服务文件
sudo nano /etc/systemd/system/malicious-cloud.service

# 3. 启动并设为开机自启
sudo systemctl daemon-reload
sudo systemctl enable malicious-cloud
sudo systemctl start malicious-cloud

# 4. 检查状态
sudo systemctl status malicious-cloud

# 5. 查看实时日志
sudo journalctl -u malicious-cloud -f
```

#### 方式 C：Docker（可选）

```bash
# 简单的 Dockerfile（自建）
cat > Dockerfile <<'EOF'
FROM python:3.12-slim
WORKDIR /app
COPY . .
EXPOSE 8765
CMD ["python3", "server.py"]
EOF
docker build -t malicious-cloud .
docker run -d --name malicious-cloud -p 8765:8765 -v $(pwd)/data:/app/data -v $(pwd)/logs:/app/logs malicious-cloud
```

### 5. 测试服务

```bash
# 健康检查（无需 Token）
curl http://localhost:8765/api/health

# 期望返回:
# {"ok": true, "version": "1.1.0", "records": 0, "special_records": 0, ...}

# 带鉴权的统计查询
curl -H "X-Client-Token: 你的client_token" http://localhost:8765/api/stats
```

## API 接口文档

所有接口均使用 JSON。除 `/api/health` 外均需在请求头携带 Token。

### 1. 健康检查
```
GET /api/health
```
无需 Token。返回服务状态、版本、记录数。

### 2. 服务端统计
```
GET /api/stats
Header: X-Client-Token: <client_token>
```
返回总记录数、特殊记录数、禁言用户数、高风险用户数、贡献过的 bot 列表。

### 3. 上传警告记录
```
POST /api/upload_record
Header: X-Client-Token: <client_token>
Body:
{
  "bot_id": "bot_001",
  "records": [
    {
      "user_id": "12345",
      "sender_name": "张三",
      "platform": "aiocqhttp",
      "platform_id": "qq",
      "count": 3,
      "total": 5,
      "last_warned": 1735689600,
      "last_reason": "辱骂",
      "last_muted_until": 0
    }
  ]
}
```
合并规则：`count` / `total` 取较大值；`last_warned` / `last_muted_until` 取较新者；记录贡献过的 `bot_id`。

### 4. 上传特殊记录
```
POST /api/upload_special
Header: X-Client-Token: <client_token>
Body:
{
  "bot_id": "bot_001",
  "records": [
    {
      "user_id": "12345",
      "sender_name": "张三",
      "message": "...",
      "special_category": "政治敏感",
      "special_reason": "...",
      "time": 1735689600
    }
  ]
}
```

### 5. 拉取增量更新
```
GET /api/sync?since=<timestamp>&bot_id=<id>
Header: X-Client-Token: <client_token>
```
返回 `since` 之后有更新的记录与特殊记录。客户端首次同步传 `since=0` 拉取全量。

### 6. 推送增量变更
```
POST /api/sync
Header: X-Client-Token: <client_token>
Body:
{
  "bot_id": "bot_001",
  "updates": {
    "count_delta": {
      "qq:12345": 1,
      "qq:67890": -1
    },
    "mute_status": {
      "qq:12345": {"muted": true, "until": 1735776000},
      "qq:67890": {"muted": false, "until": 0}
    },
    "reset_keys": ["qq:11111"]
  },
  "records": []  // 可选，同时上传全量记录
}
```

### 7. 删除记录（管理员）
```
POST /api/delete_record
Header: X-Admin-Token: <admin_token>
Body:
{
  "bot_id": "admin",
  "keys": ["qq:12345", "qq:67890"]
}
```
或：
```json
{"user_id": "12345", "platform_id": "qq"}
```
删除操作会写入审计日志 `logs/audit.log.jsonl`。

### 8. 列出全部记录
```
GET /api/records?limit=500
Header: X-Client-Token: <client_token>
```

### 9. 列出特殊记录
```
GET /api/special?limit=500
Header: X-Client-Token: <client_token>
```

## 安全建议

1. **修改默认 Token**：`config.json` 中的 `CHANGE_ME_*` 必须替换为强随机字符串。
2. **使用反向代理**：生产环境建议用 Nginx 反向代理并启用 HTTPS：

   ```nginx
   server {
       listen 443 ssl http2;
       server_name cloud.example.com;

       ssl_certificate     /etc/letsencrypt/live/cloud.example.com/fullchain.pem;
       ssl_certificate_key /etc/letsencrypt/live/cloud.example.com/privkey.pem;

       location / {
           proxy_pass http://127.0.0.1:8765;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   }
   ```

   然后让客户端连接 `https://cloud.example.com`。

3. **防火墙**：仅放行必要端口（如 443），不要直接暴露 8765 到公网。

4. **定期备份**：`data/` 目录需定期备份，可加入 crontab：

   ```bash
   # 每日凌晨备份
   0 3 * * * tar czf /backup/malicious-cloud-$(date +\%Y\%m\%d).tar.gz /opt/malicious-cloud/data
   ```

5. **审计日志**：`logs/audit.log.jsonl` 记录所有删除/同步操作，请保留以便追溯。

## 故障排查

| 现象 | 排查方法 |
|------|----------|
| 启动失败提示 `Address already in use` | 端口被占用，修改 `config.json` 的 `port` 或 `./stop.sh` 后重试 |
| 客户端连接被拒 | 检查防火墙、安全组、`host` 是否为 `0.0.0.0` |
| 401 Unauthorized | Token 不匹配，检查 `client_token` / `admin_token` 配置 |
| 数据丢失 | 检查 `data/` 目录权限，systemd 服务用户需有写权限 |
| 想重置数据 | 停止服务后删除 `data/records.json` 与 `data/special_records.json`，重启即可 |

## 升级

直接覆盖 `server.py` 后重启服务即可，数据格式向后兼容：

```bash
sudo systemctl restart malicious-cloud
```

## 版本

- 服务端版本：1.1.0
- 配套插件版本：>= 1.1.0

## 反馈

如有问题请前往 `https://qm.qq.com/q/2HuArULfbq` 反馈。

作者：uGmTEAM
