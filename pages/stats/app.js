const bridge = window.AstrBotPluginPage;
const tbody = document.getElementById("tbody");
const logTbody = document.getElementById("logTbody");
const summaryEl = document.getElementById("summary");
const emptyEl = document.getElementById("empty");
const logEmptyEl = document.getElementById("logEmpty");
const refreshBtn = document.getElementById("refresh");
const autoChk = document.getElementById("autoRefresh");
const tabs = document.querySelectorAll(".tab");
const paneStats = document.getElementById("pane-stats");
const paneLogs = document.getElementById("pane-logs");

let timer = null;
let activeTab = "stats";

function escapeHtml(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function fmtCountdown(sec) {
  if (sec <= 0) return "即将衰减";
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
      (decay !== null ? ` · 距下次全局衰减：${fmtCountdown(decay)}` : "");

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
            <button class="btn small" data-key="${escapeHtml(r.platform_id + ":" + r.user_id)}" data-action="reset">重置</button>
          </td>
        </tr>`;
      })
      .join("");

    tbody.querySelectorAll('button[data-action="reset"]').forEach((btn) => {
      btn.addEventListener("click", () => resetUser(btn.dataset.key, btn));
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
        const mutedTag = r.muted
          ? `<span class="badge muted">禁言 ${escapeHtml(r.mute_minutes || 0)} 分钟</span>`
          : '<span class="badge zero">未禁言</span>';
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
          <td>${scope}</td>
          <td class="msg" title="${escapeHtml(r.message)}">${escapeHtml(r.message || "-")}</td>
          <td class="reason" title="${escapeHtml(r.reason)}">${escapeHtml(r.reason || "-")}</td>
          <td class="num"><span class="badge low">${r.count}</span></td>
          <td>${mutedTag}</td>
        </tr>`;
      })
      .join("");
  } catch (e) {
    if (activeTab === "logs") {
      logEmptyEl.hidden = false;
      logEmptyEl.textContent = "加载失败：" + (e && e.message ? e.message : e);
    }
  }
}

async function load() {
  if (activeTab === "stats") {
    await loadStats();
  } else {
    await loadLogs();
  }
}

async function resetUser(key, btn) {
  if (!confirm("确认将该用户的当前 x 重置为 0？")) return;
  btn.disabled = true;
  try {
    await bridge.apiPost("reset", { key });
    await load();
  } catch (e) {
    alert("重置失败：" + (e && e.message ? e.message : e));
  } finally {
    btn.disabled = false;
  }
}

refreshBtn.addEventListener("click", load);

tabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    tabs.forEach((t) => t.classList.remove("active"));
    tab.classList.add("active");
    activeTab = tab.dataset.tab;
    const showLogs = activeTab === "logs";
    paneStats.hidden = showLogs;
    paneLogs.hidden = !showLogs;
    load();
  });
});

function schedule() {
  if (timer) clearInterval(timer);
  if (autoChk.checked) timer = setInterval(load, 5000);
}
autoChk.addEventListener("change", schedule);

(async () => {
  await bridge.ready();
  await load();
  schedule();
})();
