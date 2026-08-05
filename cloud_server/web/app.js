// ☁️ 恶意消息云同步管理器
(() => {
  "use strict";

  const TOKEN_KEY = "malicious_cloud_admin_token";
  let token = localStorage.getItem(TOKEN_KEY) || "";
  let activeTab = "overview";

  // ---- DOM ----
  const loginPage = document.getElementById("loginPage");
  const dashboard = document.getElementById("dashboard");
  const tokenInput = document.getElementById("tokenInput");
  const loginBtn = document.getElementById("loginBtn");
  const loginError = document.getElementById("loginError");
  const logoutBtn = document.getElementById("logoutBtn");
  const refreshBtn = document.getElementById("refreshBtn");
  const tabs = document.querySelectorAll(".tab");
  const toastBox = document.getElementById("toastBox");
  const confirmModal = document.getElementById("confirmModal");
  const confirmText = document.getElementById("confirmText");
  const confirmOk = document.getElementById("confirmOk");
  const confirmCancel = document.getElementById("confirmCancel");

  // ---- Toast ----
  function toast(msg, type = "info", duration = 3000) {
    const el = document.createElement("div");
    el.className = `toast toast-${type}`;
    el.textContent = msg;
    toastBox.appendChild(el);
    requestAnimationFrame(() => el.classList.add("show"));
    setTimeout(() => {
      el.classList.remove("show");
      setTimeout(() => el.remove(), 300);
    }, duration);
  }

  // ---- 自定义确认 ----
  function asyncConfirm(message) {
    return new Promise((resolve) => {
      confirmText.textContent = message;
      confirmOk.className = "btn danger";
      confirmModal.classList.add("show");
      const cleanup = (val) => {
        confirmModal.classList.remove("show");
        confirmOk.removeEventListener("click", onOk);
        confirmCancel.removeEventListener("click", onCancel);
        confirmModal.removeEventListener("click", onBackdrop);
        document.removeEventListener("keydown", onKey);
        resolve(val);
      };
      const onOk = () => cleanup(true);
      const onCancel = () => cleanup(false);
      const onBackdrop = (e) => { if (e.target === confirmModal) cleanup(false); };
      const onKey = (e) => {
        if (e.key === "Escape") cleanup(false);
        if (e.key === "Enter") cleanup(true);
      };
      confirmOk.addEventListener("click", onOk);
      confirmCancel.addEventListener("click", onCancel);
      confirmModal.addEventListener("click", onBackdrop);
      document.addEventListener("keydown", onKey);
    });
  }

  // ---- API 调用 ----
  async function apiGet(path, params) {
    const url = new URL(path, window.location.origin);
    if (params) {
      Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, v));
    }
    const resp = await fetch(url.toString(), {
      headers: { "X-Admin-Token": token },
    });
    if (resp.status === 401) {
      logout();
      throw new Error("未授权，请重新登录");
    }
    return resp.json();
  }

  async function apiPost(path, body) {
    const resp = await fetch(path, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Admin-Token": token,
      },
      body: JSON.stringify(body || {}),
    });
    if (resp.status === 401) {
      logout();
      throw new Error("未授权，请重新登录");
    }
    return resp.json();
  }

  // ---- 登录 / 登出 ----
  function showLogin() {
    loginPage.style.display = "flex";
    dashboard.hidden = true;
    tokenInput.value = "";
    tokenInput.focus();
  }

  function showDashboard() {
    loginPage.style.display = "none";
    dashboard.hidden = false;
    loadAll();
  }

  function logout() {
    token = "";
    localStorage.removeItem(TOKEN_KEY);
    showLogin();
  }

  async function login() {
    const t = tokenInput.value.trim();
    if (!t) {
      loginError.hidden = false;
      loginError.textContent = "请输入 admin_token";
      return;
    }
    loginBtn.disabled = true;
    try {
      const resp = await fetch("/api/auth", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: t }),
      });
      const data = await resp.json();
      if (resp.ok && data.ok) {
        token = t;
        localStorage.setItem(TOKEN_KEY, t);
        loginError.hidden = true;
        toast("登录成功", "ok");
        showDashboard();
      } else {
        loginError.hidden = false;
        loginError.textContent = data.error || "登录失败";
      }
    } catch (e) {
      loginError.hidden = false;
      loginError.textContent = "网络错误: " + e.message;
    } finally {
      loginBtn.disabled = false;
    }
  }

  loginBtn.addEventListener("click", login);
  tokenInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") login();
  });
  logoutBtn.addEventListener("click", () => {
    if (confirm("确认退出登录？")) logout();
  });
  refreshBtn.addEventListener("click", loadAll);

  // ---- Tab 切换 ----
  const paneMap = {
    overview: "pane-overview",
    records: "pane-records",
    special: "pane-special",
    audit: "pane-audit",
    requests: "pane-requests",
  };

  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      tabs.forEach((t) => t.classList.remove("active"));
      tab.classList.add("active");
      activeTab = tab.dataset.tab;
      Object.entries(paneMap).forEach(([name, id]) => {
        document.getElementById(id).hidden = name !== activeTab;
      });
      loadTab(activeTab);
    });
  });

  async function loadTab(tab) {
    if (tab === "overview") await loadOverview();
    else if (tab === "records") await loadRecords();
    else if (tab === "special") await loadSpecial();
    else if (tab === "audit") await loadAudit();
    else if (tab === "requests") await loadRequests();
  }

  function loadAll() {
    loadTab(activeTab);
  }

  // ---- 工具函数 ----
  function escapeHtml(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function fmtTime(ts) {
    if (!ts) return "-";
    try {
      return new Date(ts * 1000).toLocaleString();
    } catch {
      return String(ts);
    }
  }

  // ---- 概览 ----
  async function loadOverview() {
    const el = document.getElementById("overviewStats");
    try {
      const data = await apiGet("/api/stats");
      if (!data.ok && data.error) throw new Error(data.error);
      el.innerHTML = [
        statCard("警告记录总数", data.records || 0),
        statCard("特殊记录总数", data.special_records || 0),
        statCard("禁言中用户", data.muted_users || 0, "red"),
        statCard("高风险用户", data.high_risk_users || 0, "orange"),
        statCard("贡献 Bot 数", data.bots_contributed || 0),
        statCard("服务运行时长", fmtDuration(data.uptime)),
      ].join("");
      // Bot 列表
      const bots = data.bot_ids || [];
      if (bots.length) {
        el.innerHTML += `<div class="stat-card" style="grid-column:1/-1"><div class="label">贡献 Bot 列表</div><div>${bots.map((b) => `<span class="badge low">${escapeHtml(b)}</span>`).join(" ")}</div></div>`;
      }
    } catch (e) {
      el.innerHTML = `<p class="err">加载失败: ${escapeHtml(e.message)}</p>`;
    }
  }

  function statCard(label, value, colorClass = "") {
    return `<div class="stat-card"><div class="label">${escapeHtml(label)}</div><div class="value ${colorClass}">${escapeHtml(value)}</div></div>`;
  }

  function fmtDuration(sec) {
    if (!sec || sec < 0) return "-";
    const d = Math.floor(sec / 86400);
    const h = Math.floor((sec % 86400) / 3600);
    const m = Math.floor((sec % 3600) / 60);
    if (d > 0) return `${d}天${h}时`;
    if (h > 0) return `${h}时${m}分`;
    return `${m}分`;
  }

  // ---- 警告记录 ----
  let allRecords = [];
  const recordSearch = document.getElementById("recordSearch");
  const deleteSelectedBtn = document.getElementById("deleteSelectedBtn");

  recordSearch.addEventListener("input", () => renderRecords());

  async function loadRecords() {
    try {
      const data = await apiGet("/api/records", { limit: 2000 });
      allRecords = data.items || [];
      renderRecords();
    } catch (e) {
      toast("加载记录失败: " + e.message, "error");
    }
  }

  function renderRecords() {
    const tbody = document.getElementById("recordTbody");
    const empty = document.getElementById("recordEmpty");
    const q = (recordSearch.value || "").trim().toLowerCase();
    let items = allRecords;
    if (q) {
      items = items.filter((r) =>
        String(r.user_id || "").toLowerCase().includes(q) ||
        String(r.sender_name || "").toLowerCase().includes(q) ||
        String(r.platform || "").toLowerCase().includes(q)
      );
    }
    if (!items.length) {
      tbody.innerHTML = "";
      empty.hidden = false;
      return;
    }
    empty.hidden = true;
    tbody.innerHTML = items.map((r) => {
      const key = escapeHtml(r.key || "");
      const muted = r.is_muted;
      const mutedTag = muted
        ? `<span class="badge muted">禁言中</span>`
        : `<span class="badge zero">未禁言</span>`;
      const sources = (r.sources || []).join(", ") || "-";
      const countBadge = r.count > 5 ? "high" : r.count > 0 ? "low" : "zero";
      return `<tr>
        <td><input type="checkbox" class="rec-check" data-key="${key}" /></td>
        <td>
          <div class="user">${escapeHtml(r.sender_name || r.user_id || "未知")}</div>
          <div class="uid">UID: ${escapeHtml(r.user_id || "-")}</div>
        </td>
        <td>${escapeHtml(r.platform || "-")}</td>
        <td class="num"><span class="badge ${countBadge}">${r.count || 0}</span></td>
        <td class="num">${r.total || 0}</td>
        <td>${mutedTag}</td>
        <td class="reason" title="${escapeHtml(r.last_reason)}">${escapeHtml(r.last_reason || "-")}</td>
        <td><small>${escapeHtml(sources)}</small></td>
        <td>${escapeHtml(fmtTime(r.updated_at))}</td>
        <td>
          <button class="btn small danger" data-action="delete" data-key="${key}">删除</button>
        </td>
      </tr>`;
    }).join("");

    // 绑定删除按钮
    tbody.querySelectorAll('button[data-action="delete"]').forEach((btn) => {
      btn.addEventListener("click", () => deleteRecord(btn.dataset.key));
    });
    // 绑定复选框
    tbody.querySelectorAll(".rec-check").forEach((chk) => {
      chk.addEventListener("change", updateDeleteBtn);
    });
  }

  function updateDeleteBtn() {
    const checked = document.querySelectorAll(".rec-check:checked").length;
    deleteSelectedBtn.disabled = checked === 0;
    deleteSelectedBtn.textContent = checked > 0 ? `删除选中(${checked})` : "删除选中";
  }

  deleteSelectedBtn.addEventListener("click", async () => {
    const checked = Array.from(document.querySelectorAll(".rec-check:checked")).map((c) => c.dataset.key);
    if (!checked.length) return;
    if (!(await asyncConfirm(`确认删除选中的 ${checked.length} 条记录？此操作不可恢复。`))) return;
    try {
      const data = await apiPost("/api/delete_record", { keys: checked });
      if (data.ok) {
        toast(`已删除 ${data.deleted_count || 0} 条记录`, "ok");
        await loadRecords();
      } else {
        toast("删除失败: " + (data.error || "未知错误"), "error");
      }
    } catch (e) {
      toast("删除失败: " + e.message, "error");
    }
  });

  async function deleteRecord(key) {
    if (!(await asyncConfirm(`确认删除该记录？\nkey: ${key}\n此操作不可恢复。`))) return;
    try {
      const data = await apiPost("/api/delete_record", { keys: [key] });
      if (data.ok) {
        toast("已删除该记录", "ok");
        await loadRecords();
        await loadOverview();
      } else {
        toast("删除失败: " + (data.error || "未知错误"), "error");
      }
    } catch (e) {
      toast("删除失败: " + e.message, "error");
    }
  }

  // ---- 特殊记录 ----
  async function loadSpecial() {
    const tbody = document.getElementById("specialTbody");
    const empty = document.getElementById("specialEmpty");
    try {
      const data = await apiGet("/api/special", { limit: 500 });
      const items = data.items || [];
      if (!items.length) {
        tbody.innerHTML = "";
        empty.hidden = false;
        return;
      }
      empty.hidden = true;
      tbody.innerHTML = items.map((r) => {
        const sources = r.cloud_bot_id || "-";
        return `<tr>
          <td>${escapeHtml(fmtTime(r.time))}</td>
          <td>
            <div class="user">${escapeHtml(r.sender_name || r.user_id || "未知")}</div>
            <div class="uid">UID: ${escapeHtml(r.user_id || "-")}</div>
          </td>
          <td><span class="badge special">${escapeHtml(r.special_category || "未分类")}</span></td>
          <td>${escapeHtml(r.platform || "-")}</td>
          <td class="msg" title="${escapeHtml(r.message)}">${escapeHtml(r.message || "-")}</td>
          <td class="reason" title="${escapeHtml(r.special_reason)}">${escapeHtml(r.special_reason || "-")}</td>
          <td><small>${escapeHtml(sources)}</small></td>
        </tr>`;
      }).join("");
    } catch (e) {
      toast("加载特殊记录失败: " + e.message, "error");
    }
  }

  // ---- 审计日志 ----
  async function loadAudit() {
    const tbody = document.getElementById("auditTbody");
    const empty = document.getElementById("auditEmpty");
    try {
      const data = await apiGet("/api/audit_log", { limit: 500 });
      const items = data.items || [];
      if (!items.length) {
        tbody.innerHTML = "";
        empty.hidden = false;
        return;
      }
      empty.hidden = true;
      tbody.innerHTML = items.map((r) => {
        const detail = JSON.stringify(r.detail || {}, null, 0);
        const actionClass = r.action?.includes("delete") || r.action?.includes("revoke") ? "high" :
                            r.action?.includes("login") || r.action?.includes("denied") ? "low" : "zero";
        return `<tr>
          <td>${escapeHtml(fmtTime(r.time))}</td>
          <td><span class="badge ${actionClass}">${escapeHtml(r.action || "-")}</span></td>
          <td>${escapeHtml(r.actor || "-")}</td>
          <td class="msg">${escapeHtml(detail)}</td>
        </tr>`;
      }).join("");
    } catch (e) {
      toast("加载审计日志失败: " + e.message, "error");
    }
  }

  // ---- 请求日志 ----
  async function loadRequests() {
    const tbody = document.getElementById("requestTbody");
    const empty = document.getElementById("requestEmpty");
    try {
      const data = await apiGet("/api/request_log", { limit: 500 });
      const items = data.items || [];
      if (!items.length) {
        tbody.innerHTML = "";
        empty.hidden = false;
        return;
      }
      empty.hidden = true;
      tbody.innerHTML = items.map((r) => {
        const statusClass = r.status >= 400 ? "high" : r.status >= 300 ? "low" : "ok";
        return `<tr>
          <td>${escapeHtml(fmtTime(r.time))}</td>
          <td><span class="badge ${statusClass}">${escapeHtml(r.method || "-")}</span></td>
          <td class="msg">${escapeHtml(r.path || "-")}</td>
          <td class="num"><span class="badge ${statusClass}">${r.status || "-"}</span></td>
          <td>${escapeHtml(r.client || "-")}</td>
          <td class="reason">${escapeHtml(r.summary || "-")}</td>
        </tr>`;
      }).join("");
    } catch (e) {
      toast("加载请求日志失败: " + e.message, "error");
    }
  }

  // ---- 启动 ----
  async function init() {
    if (token) {
      // 校验已存的 token
      try {
        const resp = await fetch("/api/auth_check", {
          headers: { "X-Admin-Token": token },
        });
        if (resp.ok) {
          showDashboard();
          return;
        }
      } catch {}
      token = "";
      localStorage.removeItem(TOKEN_KEY);
    }
    showLogin();
  }

  init();
})();
