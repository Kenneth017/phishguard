const main = document.getElementById("main");

// ── Checks derived from raw email payload ─────────────────────────────────

function buildChecks(payload) {
  const checks = [];
  if (!payload) return checks;

  const links = payload.links || [];

  // 1. Sender domain
  if (payload.sender) {
    const match = payload.sender.match(/@([\w.-]+)/);
    if (match) {
      const domain = match[1].toLowerCase();
      const suspiciousTlds = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".click"];
      if (suspiciousTlds.some((t) => domain.endsWith(t))) {
        checks.push({ type: "fail", text: `Sender uses suspicious domain: ${domain}` });
      } else {
        checks.push({ type: "pass", text: `Sender domain: ${domain}` });
      }
    }
  }

  // 2. HTTP (unencrypted) links
  const httpLinks = links.filter((l) => {
    const href = l.includes("→") ? l.split("→")[1].trim() : l;
    return href.startsWith("http://");
  });
  if (httpLinks.length > 0) {
    checks.push({ type: "fail", text: `${httpLinks.length} unencrypted HTTP link(s) found` });
  } else if (links.length > 0) {
    checks.push({ type: "pass", text: "All links use HTTPS" });
  }

  // 3. Display text vs actual URL mismatch
  const mismatched = links.filter((l) => {
    if (!l.includes("→")) return false;
    const [display, href] = l.split("→").map((s) => s.trim());
    if (!/https?:\/\//.test(display)) return false;
    const dDomain = display.match(/https?:\/\/([^/?#]+)/)?.[1];
    const hDomain = href.match(/https?:\/\/([^/?#]+)/)?.[1];
    return dDomain && hDomain && dDomain !== hDomain;
  });
  if (mismatched.length > 0) {
    checks.push({ type: "fail", text: `${mismatched.length} link(s) hide different destination URLs` });
  }

  // 4. External link count
  if (links.length > 10) {
    checks.push({ type: "warn", text: `${links.length} external links — unusually high` });
  } else if (links.length > 0) {
    checks.push({ type: "pass", text: `${links.length} external link(s) found` });
  } else {
    checks.push({ type: "pass", text: "No external links" });
  }

  // 5. Urgency keywords in subject
  const urgencyWords = ["urgent", "immediately", "verify", "suspended", "confirm", "action required", "expire"];
  const subjectLower = (payload.subject || "").toLowerCase();
  const hitWord = urgencyWords.find((w) => subjectLower.includes(w));
  if (hitWord) {
    checks.push({ type: "warn", text: `Subject contains urgency keyword: "${hitWord}"` });
  } else {
    checks.push({ type: "pass", text: "No urgency keywords in subject" });
  }

  return checks;
}

// ── Link list ──────────────────────────────────────────────────────────────

function buildLinksHtml(links) {
  if (!links || links.length === 0) return "";
  const items = links.slice(0, 8).map((l) => {
    if (l.includes("→")) {
      const [display, href] = l.split("→").map((s) => s.trim());
      const isMismatch = /https?:\/\//.test(display) &&
        display.match(/https?:\/\/([^/?#]+)/)?.[1] !== href.match(/https?:\/\/([^/?#]+)/)?.[1];
      return `<div class="link-item">
        <div class="link-display">${escHtml(display)}</div>
        <div class="link-href">${escHtml(href)}</div>
        ${isMismatch ? '<div class="link-mismatch">⚠ Display URL differs from actual destination</div>' : ""}
      </div>`;
    }
    return `<div class="link-item"><div class="link-href">${escHtml(l)}</div></div>`;
  }).join("");
  return `<details>
    <summary>Links found (${links.length})</summary>
    ${items}
    ${links.length > 8 ? `<div style="color:#475569;font-size:11px;margin-top:6px;">+${links.length - 8} more</div>` : ""}
  </details>`;
}

// ── Render ─────────────────────────────────────────────────────────────────

function render(result, pending, payload) {
  if (!result && !pending) {
    main.innerHTML = `<div class="status-msg">Open an email to analyze it.</div>`;
    return;
  }
  if (!result && pending) {
    main.innerHTML = `<div class="status-msg">Analyzing email...</div>`;
    setTimeout(poll, 1000);
    return;
  }

  const confidence = Math.round(result.confidence * 100);
  const modelLabel = result.model_used === "rules" ? "Quick scan" : `AI · ${result.model_used}`;
  const checks     = buildChecks(payload);

  const checksHtml = checks.map((c) => `
    <div class="check check-${c.type}">
      <span class="check-icon">${c.type === "pass" ? "✓" : c.type === "fail" ? "✗" : "⚠"}</span>
      <span class="check-text">${escHtml(c.text)}</span>
    </div>`).join("");

  const reasonsHtml = (result.reasons || [])
    .map((r) => `<div class="reason">${escHtml(r)}</div>`).join("");

  const senderDisplay = payload?.sender
    ? `<div class="info-row"><span class="info-label">From</span><span class="info-value">${escHtml(payload.sender)}</span></div>`
    : "";
  const subjectDisplay = payload?.subject
    ? `<div class="info-row"><span class="info-label">Subject</span><span class="info-value">${escHtml(payload.subject)}</span></div>`
    : "";

  main.innerHTML = `
    ${result._refining ? `<div class="refining">⟳ AI analysis running...</div>` : ""}

    <div class="risk-row">
      <span class="risk-badge risk-${result.risk_level}">${result.risk_level} risk</span>
      <div>
        <div class="confidence">${confidence}% confidence</div>
        <div class="model-tag">${modelLabel}</div>
      </div>
    </div>

    ${senderDisplay || subjectDisplay ? `
    <div class="section">
      <div class="section-title">Email Info</div>
      ${senderDisplay}
      ${subjectDisplay}
    </div>` : ""}

    <div class="section">
      <div class="section-title">Security Checks</div>
      ${checksHtml || "<div style='color:#475569'>No data yet</div>"}
    </div>

    ${reasonsHtml ? `
    <div class="section">
      <div class="section-title">AI Findings</div>
      ${reasonsHtml}
      <p class="recommendation">${escHtml(result.recommendation)}</p>
    </div>` : ""}

    ${buildLinksHtml(payload?.links)}

    <div class="report-section">
      <p class="report-hint">Think this is phishing? Report it for deeper review.</p>
      <input type="email" id="reporterEmail" placeholder="Your email (optional)" />
      <button class="report-btn" id="reportBtn" onclick="reportPhishing()">Report as Phishing</button>
      <div id="reportStatus"></div>
    </div>
  `;

  if (result._refining || pending) setTimeout(poll, 1000);
}

// ── Poll ───────────────────────────────────────────────────────────────────

function poll() {
  chrome.runtime.sendMessage({ type: "GET_RESULT" }, ({ result, pending, payload }) => {
    render(result, pending, payload);
  });
}

// ── Report ─────────────────────────────────────────────────────────────────

function reportPhishing() {
  const btn    = document.getElementById("reportBtn");
  const email  = document.getElementById("reporterEmail")?.value?.trim();
  const status = document.getElementById("reportStatus");

  btn.disabled = true;
  btn.textContent = "Reporting...";

  chrome.runtime.sendMessage(
    { type: "REPORT_PHISHING", reporter_email: email || null },
    ({ ok, report_id }) => {
      if (ok) {
        status.innerHTML = `<p class="report-success">✓ Reported (#${report_id}). Thank you!</p>`;
        btn.textContent = "Reported";
      } else {
        status.innerHTML = `<p style="color:#f87171;font-size:12px;text-align:center;">Failed. Try again.</p>`;
        btn.disabled = false;
        btn.textContent = "Report as Phishing";
      }
    }
  );
}

// ── Util ───────────────────────────────────────────────────────────────────

function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

poll();
