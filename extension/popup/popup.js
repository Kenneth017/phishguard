const main = document.getElementById("main");

function render(result, pending) {
  if (!result) {
    main.innerHTML = pending
      ? `<div class="status-msg">Analyzing email...</div>`
      : `<div class="status-msg">Open an email to analyze it.</div>`;
    if (pending) setTimeout(poll, 1000);
    return;
  }

  const confidence = Math.round(result.confidence * 100);
  const reasonsHtml = (result.reasons || [])
    .map((r) => `<li>${r}</li>`).join("");

  const modelLabel = result.model_used === "rules"
    ? "Quick scan"
    : `AI · ${result.model_used}`;

  main.innerHTML = `
    <div class="section">
      <div class="risk-row">
        <span class="risk-badge risk-${result.risk_level}">${result.risk_level} risk</span>
        <span class="confidence">${confidence}% confidence</span>
      </div>
      ${reasonsHtml ? `<ul class="reasons">${reasonsHtml}</ul>` : ""}
      <p class="recommendation">${result.recommendation}</p>
      <p class="meta">${modelLabel}</p>
      ${result._refining ? `<p class="refining">⟳ AI refining result...</p>` : ""}
    </div>
    <div class="report-section">
      <p>Think this is phishing? Report it for deeper review.</p>
      <input type="email" id="reporterEmail" placeholder="Your email (optional)" />
      <button class="report-btn" id="reportBtn" onclick="reportPhishing()">
        Report as Phishing
      </button>
      <div id="reportStatus"></div>
    </div>
  `;

  if (result._refining || pending) setTimeout(poll, 1000);
}

function poll() {
  chrome.runtime.sendMessage({ type: "GET_RESULT" }, ({ result, pending }) => {
    render(result, pending);
  });
}

async function reportPhishing() {
  const btn   = document.getElementById("reportBtn");
  const email = document.getElementById("reporterEmail")?.value?.trim();
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
        status.innerHTML = `<p style="color:#f87171; font-size:12px; text-align:center;">Failed to report. Try again.</p>`;
        btn.disabled = false;
        btn.textContent = "Report as Phishing";
      }
    }
  );
}

poll();
