const bridge = window.AstrBotPluginPage;
const tbody = document.getElementById("tbody");
const logTbody = document.getElementById("logTbody");
const specialTbody = document.getElementById("specialTbody");
const timeoutTbody = document.getElementById("timeoutTbody");
const cloudTbody = document.getElementById("cloudTbody");
const summaryEl = document.getElementById("summary");
const emptyEl = document.getElementById("empty");
const logEmptyEl = document.getElementById("logEmpty");
const specialEmptyEl = document.getElementById("specialEmpty");
const specialSummaryEl = document.getElementById("specialSummary");
const timeoutEmptyEl = document.getElementById("timeoutEmpty");
const timeoutSummaryEl = document.getElementById("timeoutSummary");
const cloudSummaryEl = document.getElementById("cloudSummary");
const cloudEmptyEl = document.getElementById("cloudEmpty");
const refreshBtn = document.getElementById("refresh");
const autoChk = document.getElementById("autoRefresh");
const tabs = document.querySelectorAll(".tab");
const paneStats = document.getElementById("pane-stats");
const paneLogs = document.getElementById("pane-logs");
const paneSpecial = document.getElementById("pane-special");
const paneTimeout = document.getElementById("pane-timeout");
const paneCloud = document.getElementById("pane-cloud");

let timer = null;
let activeTab = "stats";

// ---------------------------------------------------------------------------
// 按键反馈：toast（屏幕中间正上方，持续 3 秒）
// ---------------------------------------------------------------------------

const toastBox = document.getElementById("toastBox");

function toast(msg, type = "info", duration = 3000) {
  if (!toastBox) return;
  const el = document.createElement("div");
  el.className = `toast toast-${type}`;
  el.textContent = msg;
  toastBox.appendChild(el);
  // 触发进入动画
  requestAnimationFrame(() => el.classList.add("show"));
  setTimeout(() => {
    el.classList.remove("show");
    setTimeout(() => el.remove(), 300);
  }, duration);
}

// ---------------------------------------------------------------------------
// 自定义确认对话框（替代被 iframe 沙箱阻止的 confirm()）
// ---------------------------------------------------------------------------

const confirmModal = document.getElementById("confirmModal");
const confirmText = document.getElementById("confirmText");
const confirmOkBtn = document.getElementById("confirmOk");
const confirmCancelBtn = document.getElementById("confirmCancel");

function asyncConfirm(message, { okText = "确认", cancelText = "取消", danger = false } = {}) {
  return new Promise((resolve) => {
    if (!confirmModal || !confirmText) {
      // 兜底：若无 modal 元素，直接放行
      resolve(true);
      return;
    }
    confirmText.textContent = message;
    confirmOkBtn.textContent = okText;
    confirmCancelBtn.textContent = cancelText;
    confirmOkBtn.className = danger ? "btn danger" : "btn";
    confirmModal.classList.add("show");

    const cleanup = (val) => {
      confirmModal.classList.remove("show");
      confirmOkBtn.removeEventListener("click", onOk);
      confirmCancelBtn.removeEventListener("click", onCancel);
      confirmModal.removeEventListener("click", onBackdrop);
      document.removeEventListener("keydown", onKey);
      resolve(val);
    };
    const onOk = () => cleanup(true);
    const onCancel = () => cleanup(false);
    const onBackdrop = (e) => {
      if (e.target === confirmModal) cleanup(false);
    };
    const onKey = (e) => {
      if (e.key === "Escape") cleanup(false);
      if (e.key === "Enter") cleanup(true);
    };
    confirmOkBtn.addEventListener("click", onOk);
    confirmCancelBtn.addEventListener("click", onCancel);
    confirmModal.addEventListener("click", onBackdrop);
    document.addEventListener("keydown", onKey);
  });
}

function escapeHtml(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function fmtCountdown(sec, justText = "即将") {
  if (sec <= 0) return justText;
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  return `${h}时${m}分${s}秒`;
}

function badgeClass(x, muted) {
  if (muted) return "badge muted";
  if (x > 5) return "badge high";
  if (x > 0) return "badge low";
  return "badge zero";
}

async function loadStats() {
  try {
    const res = await bridge.apiGet("stats");
    const data = res && res.data !== undefined ? res.data : res;
    const items = data.items || [];
    const total = data.total_users || 0;
    const decay = data.next_decay_in ?? null;

    const highCount = items.filter((r) => r.count > 5).length;
    const mutedCount = items.filter((r) => r.is_muted).length;
    summaryEl.innerHTML =
      `共 <b>${total}</b> 人有警告记录 · ` +
      `x&gt;5（已触发禁言阈值）<b>${highCount}</b> 人 · ` +
      `当前禁言中 <b>${mutedCount}</b> 人` +
      (decay !== null ? ` · 距下次全局衰减：${fmtCountdown(decay, "即将衰减")}` : "");

    if (items.length === 0) {
      tbody.innerHTML = "";
      emptyEl.hidden = false;
      return;
    }
    emptyEl.hidden = true;

    tbody.innerHTML = items
      .map((r, i) => {
        const badge = badgeClass(r.count, r.is_muted);
        const statusText = r.is_muted ? "禁言中" : r.count > 5 ? "高风险" : "正常";
        const resetKey = (r.platform_id || "") + ":" + (r.user_id || "");
        return `<tr>
          <td>${i + 1}</td>
          <td>
            <div class="user">${escapeHtml(r.sender_name || r.user_id || "未知")}</div>
            <div class="uid">UID: ${escapeHtml(r.user_id || "-")}</div>
          </td>
          <td>${escapeHtml(r.platform || "-")}</td>
          <td class="num"><span class="${badge}">${r.count}</span></td>
          <td class="num">${r.total}</td>
          <td class="reason" title="${escapeHtml(r.last_reason)}">${escapeHtml(r.last_reason || "-")}</td>
          <td>${escapeHtml(r.last_warned_str || "-")}</td>
          <td><span class="${badge}">${statusText}</span></td>
          <td>
            <button class="btn small" data-key="${escapeHtml(resetKey)}" data-uid="${escapeHtml(r.user_id || "")}" data-action="reset">重置</button>
          </td>
        </tr>`;
      })
      .join("");

    tbody.querySelectorAll('button[data-action="reset"]').forEach((btn) => {
      btn.addEventListener("click", () => resetUser(btn.dataset.key, btn.dataset.uid, btn));
    });
  } catch (e) {
    if (activeTab === "stats") {
      summaryEl.textContent = "加载失败：" + (e && e.message ? e.message : e);
    }
  }
}

async function loadLogs() {
  try {
    const res = await bridge.apiGet("logs", { limit: 200 });
    const data = res && res.data !== undefined ? res.data : res;
    const items = data.items || [];
    if (items.length === 0) {
      logTbody.innerHTML = "";
      logEmptyEl.hidden = false;
      return;
    }
    logEmptyEl.hidden = true;

    logTbody.innerHTML = items
      .map((r, i) => {
        const isRevoked = !!r.revoked;
        const mutedTag = r.muted
          ? `<span class="badge muted">禁言 ${escapeHtml(r.mute_minutes || 0)} 分钟</span>`
          : '<span class="badge zero">未禁言</span>';
        const scope = r.is_private
          ? `${escapeHtml(r.platform || "-")} · 私聊`
          : `${escapeHtml(r.platform || "-")} · 群 ${escapeHtml(r.group_id || "-")}`;
        const adminTag = r.is_admin ? ' <span class="badge admin">管理员</span>' : "";
        const logId = escapeHtml(r.log_id || "");
        // 已撤回标记 + 撤回理由（鼠标悬停查看）
        const revokedTag = isRevoked
          ? ` <span class="badge revoked" title="${escapeHtml(r.revoke_reason || "")}">已撤回</span>`
          : "";
        const revokeReasonCell = isRevoked
          ? `<div class="revoke-reason" title="${escapeHtml(r.revoke_reason || "")}">撤回理由：${escapeHtml(r.revoke_reason || "-")}</div>`
          : "";
        // 已撤回的记录显示撤回时间，撤回按钮禁用
        const revokeBtn = isRevoked
          ? `<button class="btn small" disabled>已撤回</button>`
          : `<button class="btn small danger" data-log-id="${logId}" data-action="revoke">撤回</button>`;
        const rowClass = isRevoked ? ' class="revoked-row"' : "";
        return `<tr${rowClass}>
          <td>${i + 1}</td>
          <td>${escapeHtml(r.time_str || "-")}${revokedTag}</td>
          <td>
            <div class="user">${escapeHtml(r.sender_name || r.user_id || "未知")}${adminTag}</div>
            <div class="uid">UID: ${escapeHtml(r.user_id || "-")}</div>
          </td>
          <td>${scope}</td>
          <td class="msg" title="${escapeHtml(r.message)}">${escapeHtml(r.message || "-")}</td>
          <td class="reason" title="${escapeHtml(r.reason)}">${escapeHtml(r.reason || "-")}${revokeReasonCell}</td>
          <td class="num"><span class="badge low">${r.count}</span></td>
          <td>${mutedTag}</td>
          <td>${revokeBtn}</td>
        </tr>`;
      })
      .join("");

    logTbody.querySelectorAll('button[data-action="revoke"]').forEach((btn) => {
      btn.addEventListener("click", () => revokeWarning(btn.dataset.logId, btn));
    });
  } catch (e) {
    if (activeTab === "logs") {
      logEmptyEl.hidden = false;
      logEmptyEl.textContent = "加载失败：" + (e && e.message ? e.message : e);
    }
  }
}

async function loadSpecial() {
  try {
    const res = await bridge.apiGet("special", { limit: 500 });
    const data = res && res.data !== undefined ? res.data : res;
    const items = data.items || [];
    const byUser = data.by_user || {};

    specialSummaryEl.innerHTML =
      `共 <b>${data.total || 0}</b> 条特殊记录 · ` +
      `涉及 <b>${Object.keys(byUser).length}</b> 人 · ` +
      `（政治敏感/违法内容，按人分类归档以便举报）`;

    if (items.length === 0) {
      specialTbody.innerHTML = "";
      specialEmptyEl.hidden = false;
      return;
    }
    specialEmptyEl.hidden = true;

    specialTbody.innerHTML = items
      .map((r, i) => {
        const scope = r.is_private
          ? `${escapeHtml(r.platform || "-")} · 私聊`
          : `${escapeHtml(r.platform || "-")} · 群 ${escapeHtml(r.group_id || "-")}`;
        return `<tr>
          <td>${i + 1}</td>
          <td>${escapeHtml(r.time_str || "-")}</td>
          <td>
            <div class="user">${escapeHtml(r.sender_name || r.user_id || "未知")}</div>
            <div class="uid">UID: ${escapeHtml(r.user_id || "-")}</div>
          </td>
          <td><span class="badge special">${escapeHtml(r.special_category || "未分类")}</span></td>
          <td>${scope}</td>
          <td class="msg" title="${escapeHtml(r.message)}">${escapeHtml(r.message || "-")}</td>
          <td class="reason" title="${escapeHtml(r.special_reason)}">${escapeHtml(r.special_reason || "-")}</td>
          <td>
            <button class="btn small" data-msg="${escapeHtml(r.message || "")}">复制</button>
          </td>
        </tr>`;
      })
      .join("");

    specialTbody.querySelectorAll("button").forEach((btn) => {
      btn.addEventListener("click", async () => {
        try {
          if (navigator.clipboard?.writeText) {
            await navigator.clipboard.writeText(btn.dataset.msg);
          } else {
            // iframe 中 clipboard 可能不可用，用临时 textarea 兜底
            const ta = document.createElement("textarea");
            ta.value = btn.dataset.msg;
            ta.style.position = "fixed";
            ta.style.opacity = "0";
            document.body.appendChild(ta);
            ta.select();
            document.execCommand("copy");
            ta.remove();
          }
          toast("已复制消息内容到剪贴板", "ok");
        } catch (e) {
          toast("复制失败：" + (e && e.message ? e.message : e), "error");
        }
      });
    });
  } catch (e) {
    if (activeTab === "special") {
      specialSummaryEl.textContent = "加载失败：" + (e && e.message ? e.message : e);
    }
  }
}

async function loadTimeout() {
  try {
    const res = await bridge.apiGet("timeout", { limit: 500 });
    const data = res && res.data !== undefined ? res.data : res;
    const items = data.items || [];
    const summaries = data.summaries || [];

    timeoutSummaryEl.innerHTML =
      `共 <b>${data.total || 0}</b> 条超时记录 · ` +
      `<button id="clearTimeoutBtn" class="btn small danger">清理全部超时记录</button>`;

    const clearBtn = document.getElementById("clearTimeoutBtn");
    if (clearBtn) {
      clearBtn.addEventListener("click", clearTimeoutArchive);
    }

    if (items.length === 0) {
      timeoutTbody.innerHTML = "";
      timeoutEmptyEl.hidden = false;
      return;
    }
    timeoutEmptyEl.hidden = true;

    timeoutTbody.innerHTML = items
      .map((r, i) => {
        const scope = r.is_private
          ? `${escapeHtml(r.platform || "-")} · 私聊`
          : `${escapeHtml(r.platform || "-")} · 群 ${escapeHtml(r.group_id || "-")}`;
        const archivedStr = r.archived_at
          ? escapeHtml(new Date(r.archived_at * 1000).toLocaleString())
          : "-";
        return `<tr>
          <td>${i + 1}</td>
          <td>${escapeHtml(r.time_str || "-")}</td>
          <td>${archivedStr}</td>
          <td>
            <div class="user">${escapeHtml(r.sender_name || r.user_id || "未知")}</div>
            <div class="uid">UID: ${escapeHtml(r.user_id || "-")}</div>
          </td>
          <td>${scope}</td>
          <td class="msg" title="${escapeHtml(r.message)}">${escapeHtml(r.message || "-")}</td>
          <td class="reason" title="${escapeHtml(r.reason)}">${escapeHtml(r.reason || "-")}</td>
        </tr>`;
      })
      .join("");
  } catch (e) {
    if (activeTab === "timeout") {
      timeoutSummaryEl.textContent = "加载失败：" + (e && e.message ? e.message : e);
    }
  }
}

async function clearTimeoutArchive() {
  if (!(await asyncConfirm("确认清空全部超时记录？此操作不可撤销。", { danger: true }))) return;
  try {
    await bridge.apiPost("timeout/clear", {});
    toast("已清理全部超时记录", "ok");
    await loadTimeout();
  } catch (e) {
    toast("清理失败：" + (e && e.message ? e.message : e), "error");
  }
}

async function load() {
  if (activeTab === "stats") {
    await loadStats();
  } else if (activeTab === "logs") {
    await loadLogs();
  } else if (activeTab === "special") {
    await loadSpecial();
  } else if (activeTab === "timeout") {
    await loadTimeout();
  } else if (activeTab === "cloud") {
    await loadCloud();
  }
}

async function resetUser(key, uid, btn) {
  if (!(await asyncConfirm("确认将该用户的当前 x 重置为 0？", { danger: true }))) return;
  btn.disabled = true;
  try {
    await bridge.apiPost("reset", { key });
    toast("已重置该用户的警告次数为 0", "ok");
    await load();
  } catch (e) {
    toast("重置失败：" + (e && e.message ? e.message : e), "error");
  } finally {
    btn.disabled = false;
  }
}

// ---------------------------------------------------------------------------
// 误判撤回
// ---------------------------------------------------------------------------

async function revokeWarning(logId, btn) {
  if (!logId) {
    toast("该记录缺少 log_id，无法撤回", "error");
    return;
  }
  const reason = await asyncPrompt("请输入误判理由（将标记此消息以免再次误判）：");
  if (reason === null) return; // 取消
  if (!reason.trim()) {
    toast("误判理由不能为空", "error");
    return;
  }
  btn.disabled = true;
  try {
    const res = await bridge.apiPost("revoke", { log_id: logId, reason: reason.trim() });
    const data = res && res.data !== undefined ? res.data : res;
    if (data && data.ok) {
      toast(`✅ 已撤回：count ${data.old_count || 0} → ${data.new_count || 0}`, "ok");
      if (data.cloud_revoked) {
        toast("云端记录已同步撤回", "ok");
      } else if (data.cloud_error) {
        toast("云端撤回失败：" + data.cloud_error, "error", 5000);
      }
      await load();
    } else {
      toast("撤回失败：" + (data && data.error ? data.error : "未知错误"), "error");
    }
  } catch (e) {
    toast("撤回失败：" + (e && e.message ? e.message : e), "error");
  } finally {
    btn.disabled = false;
  }
}

// 自定义输入对话框（替代 prompt()，同样可能被 iframe 沙箱阻止）
const promptModal = document.getElementById("promptModal");
const promptText = document.getElementById("promptText");
const promptInput = document.getElementById("promptInput");
const promptOkBtn = document.getElementById("promptOk");
const promptCancelBtn = document.getElementById("promptCancel");

function asyncPrompt(message, { placeholder = "", defaultVal = "" } = {}) {
  return new Promise((resolve) => {
    if (!promptModal || !promptInput) {
      resolve(defaultVal);
      return;
    }
    promptText.textContent = message;
    promptInput.value = defaultVal;
    promptInput.placeholder = placeholder;
    promptModal.classList.add("show");
    setTimeout(() => promptInput.focus(), 50);

    const cleanup = (val) => {
      promptModal.classList.remove("show");
      promptOkBtn.removeEventListener("click", onOk);
      promptCancelBtn.removeEventListener("click", onCancel);
      promptModal.removeEventListener("click", onBackdrop);
      document.removeEventListener("keydown", onKey);
      resolve(val);
    };
    const onOk = () => cleanup(promptInput.value);
    const onCancel = () => cleanup(null);
    const onBackdrop = (e) => {
      if (e.target === promptModal) cleanup(null);
    };
    const onKey = (e) => {
      if (e.key === "Escape") cleanup(null);
      if (e.key === "Enter") cleanup(promptInput.value);
    };
    promptOkBtn.addEventListener("click", onOk);
    promptCancelBtn.addEventListener("click", onCancel);
    promptModal.addEventListener("click", onBackdrop);
    document.addEventListener("keydown", onKey);
  });
}

refreshBtn.addEventListener("click", load);

const paneMap = {
  stats: paneStats,
  logs: paneLogs,
  special: paneSpecial,
  timeout: paneTimeout,
  cloud: paneCloud,
};

tabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    tabs.forEach((t) => t.classList.remove("active"));
    tab.classList.add("active");
    activeTab = tab.dataset.tab;
    Object.entries(paneMap).forEach(([name, pane]) => {
      pane.hidden = name !== activeTab;
    });
    load();
  });
});

function schedule() {
  if (timer) clearInterval(timer);
  if (autoChk.checked) timer = setInterval(load, 5000);
}
autoChk.addEventListener("change", schedule);

// ---- 云同步 ----

function featureBadge(on, riskLabel = "") {
  const cls = on ? "badge low" : "badge zero";
  const txt = on ? "✅ 开" : "❌ 关";
  return `<span class="${cls}">${txt}</span>${riskLabel ? ` <span class="badge special">${riskLabel}</span>` : ""}`;
}

async function loadCloud() {
  try {
    const statusRes = await bridge.apiGet("cloud/status");
    const status = statusRes && statusRes.data !== undefined ? statusRes.data : statusRes;
    if (!status) {
      cloudSummaryEl.textContent = "加载失败。";
      return;
    }
    const enabled = status.enabled;
    const feat = status.features || {};
    const stats = status.stats || {};
    const timing = status.timing || {};
    const errs = status.errors || {};
    const pending = status.pending || {};

    let html = "";
    if (!enabled) {
      html = '<b>云同步未启用</b>。请在插件配置中开启 <code>enable_cloud_sync</code>，'
        + '并填写 <code>cloud_server_url</code> 与 <code>cloud_client_token</code>。'
        + '<br>⚠️ 重要：所有使用本插件并开启云功能的 AI 数据共享，本地保留备份。';
      cloudSummaryEl.innerHTML = html;
      cloudTbody.innerHTML = "";
      cloudEmptyEl.hidden = false;
      cloudEmptyEl.textContent = "云同步未启用。";
      return;
    }

    html = `<b>☁️ 云同步已启用</b> · 服务端: <code>${escapeHtml(status.cloud_server_url || "")}</code> · Bot ID: <code>${escapeHtml(status.bot_id || "")}</code><br>`;
    html += "<b>子功能状态：</b><br>";
    html += `&nbsp;&nbsp;• 上传警告记录: ${featureBadge(feat.upload_record)}<br>`;
    html += `&nbsp;&nbsp;• 同步警告次数 (+/-): ${featureBadge(feat.sync_count, feat.sync_count ? "⚠️ 误禁言风险" : "")}<br>`;
    html += `&nbsp;&nbsp;• 同步禁言状态 (T/F): ${featureBadge(feat.sync_mute, feat.sync_mute ? "⚠️ 误禁言风险" : "")}<br>`;
    html += `&nbsp;&nbsp;• 删除云端记录: ${featureBadge(feat.delete_record, feat.delete_record ? "需 admin_token" : "")}<br>`;
    html += `&nbsp;&nbsp;• 上传特殊记录: ${featureBadge(feat.upload_special)}<br>`;
    html += `&nbsp;&nbsp;• 误判撤回: ${featureBadge(feat.revoke)}<br>`;
    html += "<b>统计：</b><br>";
    html += `&nbsp;&nbsp;• 累计同步 ${stats.sync_count || 0} 次，推送 ${stats.push_count || 0} 次，拉取 ${stats.pull_count || 0} 次，错误 ${stats.error_count || 0} 次<br>`;
    html += `&nbsp;&nbsp;• 上次同步: ${escapeHtml(timing.last_sync_str || "-")} · 距下次同步: ${fmtCountdown(timing.next_sync_in || 0)}<br>`;
    html += `&nbsp;&nbsp;• 上次上传: ${stats.last_uploaded_records || 0} 条 · 上次拉取: 记录 ${stats.last_pulled_records || 0} 条，特殊 ${stats.last_pulled_special || 0} 条<br>`;
    html += `&nbsp;&nbsp;• 待推送: ${pending.push_keys || 0} 条记录，${pending.special || 0} 条特殊记录${pending.syncing ? ' · <span class="badge low">同步中</span>' : ""}<br>`;
    if (errs.last_error) {
      html += `&nbsp;&nbsp;• <span class="badge muted">⚠️ 上次错误: ${escapeHtml(errs.last_error)} (${escapeHtml(errs.last_error_str || "-")})</span><br>`;
    }
    cloudSummaryEl.innerHTML = html;

    // 加载云端记录列表
    let cloudItems = [];
    try {
      const recRes = await bridge.apiGet("cloud/records", { limit: 500 });
      const recData = recRes && recRes.data !== undefined ? recRes.data : recRes;
      cloudItems = (recData && recData.items) || [];
    } catch (e) {
      cloudEmptyEl.hidden = false;
      cloudEmptyEl.textContent = "云端记录查询失败: " + (e && e.message ? e.message : e);
      return;
    }

    if (!cloudItems.length) {
      cloudTbody.innerHTML = "";
      cloudEmptyEl.hidden = false;
      cloudEmptyEl.textContent = "云端暂无记录。";
      return;
    }
    cloudEmptyEl.hidden = true;

    cloudTbody.innerHTML = cloudItems
      .map((r, i) => {
        const muted = r.is_muted;
        const mutedTag = muted
          ? `<span class="badge muted">禁言中</span>`
          : '<span class="badge zero">未禁言</span>';
        const sources = (r.sources || []).join(", ") || "-";
        return `<tr>
          <td>${i + 1}</td>
          <td>
            <div class="user">${escapeHtml(r.sender_name || r.user_id || "未知")}</div>
            <div class="uid">UID: ${escapeHtml(r.user_id || "-")}</div>
          </td>
          <td>${escapeHtml(r.platform || "-")}</td>
          <td class="num"><span class="badge low">${r.count || 0}</span></td>
          <td class="num">${r.total || 0}</td>
          <td>${mutedTag}</td>
          <td>${escapeHtml(r.last_reason || "-")}</td>
          <td><small>${escapeHtml(sources)}</small></td>
        </tr>`;
      })
      .join("");
  } catch (e) {
    if (activeTab === "cloud") {
      cloudSummaryEl.textContent = "加载失败：" + (e && e.message ? e.message : e);
    }
  }
}

async function cloudSyncNow() {
  if (!(await asyncConfirm("确认立即执行一次云同步（拉取 + 推送）？"))) return;
  try {
    cloudSummaryEl.textContent = "⏳ 正在同步…";
    const res = await bridge.apiPost("cloud/sync", {});
    const data = res && res.data !== undefined ? res.data : res;
    if (!data || !data.ok) {
      toast("同步失败：" + (data && data.error ? data.error : "未知错误"), "error", 5000);
    } else {
      const pull = data.pull || {};
      const upload = data.upload || {};
      const inc = data.incremental || {};
      const special = data.special || {};
      toast(
        `✅ 同步完成：拉取 ${pull.pulled || 0}/${pull.special || 0}，上传 ${upload.uploaded || 0}，增量 ${inc.applied || 0}，特殊 ${special.uploaded || 0}`,
        "ok",
        4000
      );
    }
    await loadCloud();
  } catch (e) {
    toast("同步失败：" + (e && e.message ? e.message : e), "error", 5000);
    await loadCloud();
  }
}

async function cloudUploadRecords() {
  if (!(await asyncConfirm("确认上传全部本地警告记录到云端？"))) return;
  try {
    const res = await bridge.apiPost("cloud/upload_record", {});
    const data = res && res.data !== undefined ? res.data : res;
    if (data && data.ok) {
      toast(`✅ 上传成功: ${data.uploaded || 0} 条（云端共 ${data.total_cloud || 0} 条）`, "ok");
    } else {
      toast("上传失败：" + (data && data.error ? data.error : "未知错误"), "error");
    }
    await loadCloud();
  } catch (e) {
    toast("上传失败：" + (e && e.message ? e.message : e), "error");
  }
}

async function cloudUploadSpecial() {
  if (!(await asyncConfirm("确认上传本地特殊记录到云端？"))) return;
  try {
    const res = await bridge.apiPost("cloud/upload_special", { limit: 100 });
    const data = res && res.data !== undefined ? res.data : res;
    if (data && data.ok) {
      toast(`✅ 上传成功: ${data.uploaded || 0} 条（云端共 ${data.total_cloud || 0} 条）`, "ok");
    } else {
      toast("上传失败：" + (data && data.error ? data.error : "未知错误"), "error");
    }
    await loadCloud();
  } catch (e) {
    toast("上传失败：" + (e && e.message ? e.message : e), "error");
  }
}

// 云同步按钮事件
const cloudSyncBtn = document.getElementById("cloudSyncBtn");
const cloudUploadBtn = document.getElementById("cloudUploadBtn");
const cloudUploadSpecialBtn = document.getElementById("cloudUploadSpecialBtn");
const cloudRefreshBtn = document.getElementById("cloudRefreshBtn");
if (cloudSyncBtn) cloudSyncBtn.addEventListener("click", cloudSyncNow);
if (cloudUploadBtn) cloudUploadBtn.addEventListener("click", cloudUploadRecords);
if (cloudUploadSpecialBtn) cloudUploadSpecialBtn.addEventListener("click", cloudUploadSpecial);
if (cloudRefreshBtn) cloudRefreshBtn.addEventListener("click", loadCloud);

(async () => {
  await bridge.ready();
  await load();
  schedule();
})();
