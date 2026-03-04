// PhishGuard background service worker
let API_BASE = "https://phishguard-0nal.onrender.com"; // update after deploy

const tabResults  = {};  // tabId → latest result
const tabPending  = {};  // tabId → bool (AI in flight)
const tabPayloads = {};  // tabId → last email payload (for reporting)

// Allow overriding API base from storage (for dev/testing)
chrome.storage.local.get("api_base", ({ api_base }) => {
  if (api_base) API_BASE = api_base;
});

function getApiBase() {
  return API_BASE;
}

// ── Receive email payload from content script ─────────────────────────────

chrome.runtime.onMessage.addListener((message, sender) => {
  const tabId = sender.tab?.id;
  if (!tabId) return;

  if (message.type === "CLEAR_EMAIL") {
    tabResults[tabId]  = null;
    tabPending[tabId]  = false;
    tabPayloads[tabId] = null;
    chrome.action.setBadgeText({ tabId, text: "" });
    return;
  }

  if (message.type !== "ANALYZE_EMAIL") return;

  const payload = message.payload;
  tabPayloads[tabId] = payload;
  tabResults[tabId]  = null;
  tabPending[tabId]  = true;

  updateBadge(tabId, "analyzing");

  const body    = JSON.stringify(payload);
  const headers = { "Content-Type": "application/json" };
  const base    = getApiBase();

  // Stage 1: instant rule-based scan
  fetch(`${base}/api/quick-analyze`, { method: "POST", headers, body })
    .then((r) => r.json())
    .then((result) => {
      if (tabPending[tabId]) {
        tabResults[tabId] = { ...result, _refining: true };
        updateBadge(tabId, result.risk_level);
      }
    })
    .catch(() => {});

  // Stage 2: AI analysis — overwrites when done
  fetch(`${base}/api/analyze`, { method: "POST", headers, body })
    .then((r) => r.json())
    .then((result) => {
      tabResults[tabId] = { ...result, _refining: false };
      tabPending[tabId] = false;
      updateBadge(tabId, result.risk_level);
    })
    .catch((err) => {
      console.error("PhishGuard AI failed:", err);
      tabPending[tabId] = false;
      if (tabResults[tabId]) {
        tabResults[tabId]._refining = false;
      }
    });
});

// ── Popup: get current result ─────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "GET_RESULT") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tabId = tabs[0]?.id;
      sendResponse({
        result:  tabResults[tabId]  || null,
        pending: tabPending[tabId]  || false,
        payload: tabPayloads[tabId] || null,
      });
    });
    return true;
  }

  if (message.type === "REPORT_PHISHING") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tabId  = tabs[0]?.id;
      const payload = tabPayloads[tabId] || {};
      const result  = tabResults[tabId]  || {};

      fetch(`${getApiBase()}/api/report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ...payload,
          analysis:       result,
          reporter_email: message.reporter_email || null,
        }),
      })
        .then((r) => r.json())
        .then((data) => sendResponse({ ok: true, report_id: data.report_id }))
        .catch(() => sendResponse({ ok: false }));
    });
    return true;
  }
});

// ── Keep Render server warm (ping every 14 min to prevent cold start) ────────

function pingServer() {
  fetch(`${API_BASE}/health`).catch(() => {});
}
pingServer();
setInterval(pingServer, 14 * 60 * 1000);

// ── Clean up on tab close ─────────────────────────────────────────────────

chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabResults[tabId];
  delete tabPending[tabId];
  delete tabPayloads[tabId];
});

// ── Badge helpers ─────────────────────────────────────────────────────────

function updateBadge(tabId, state) {
  const config = {
    analyzing: { text: "...",  color: "#64748b" },
    low:       { text: "OK",   color: "#22c55e" },
    medium:    { text: "!",    color: "#f59e0b" },
    high:      { text: "!!",   color: "#ef4444" },
    critical:  { text: "!!!",  color: "#7f1d1d" },
  };
  const { text, color } = config[state] || { text: "?", color: "#64748b" };
  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
}
