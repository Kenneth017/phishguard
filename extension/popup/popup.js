const main = document.getElementById("main");

// ── All security checks ───────────────────────────────────────────────────

function runChecks(payload) {
  const sender  = payload?.sender  || "";
  const subject = payload?.subject || "";
  const body    = (payload?.body_text || "").toLowerCase();
  const links   = payload?.links || [];

  // Parse sender
  const emailMatch  = sender.match(/<([^>]+)>/) || sender.match(/(\S+@\S+)/);
  const senderEmail = (emailMatch?.[1] || "").toLowerCase();
  const senderDomain = senderEmail.split("@")[1] || "";
  const displayName  = sender.replace(/<[^>]+>/, "").replace(/"/g, "").trim();
  const subjectLower = subject.toLowerCase();

  const FREE_PROVIDERS  = ["gmail.com","yahoo.com","hotmail.com","outlook.com","aol.com","ymail.com","icloud.com"];
  const SUSPICIOUS_TLDS = [".xyz",".tk",".ml",".ga",".cf",".gq",".top",".click",".online",".site"];
  const BRANDS          = ["paypal","amazon","google","microsoft","apple","netflix","facebook","instagram","chase","wellsfargo","bdo","bpi","metrobank","dhl","fedex","usps"];
  const SHORTENERS      = ["bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","tiny.cc","cutt.ly","rb.gy"];

  // ── 1. Sender Verification ──────────────────────────────────────────────
  const senderChecks = [];

  if (senderDomain) {
    // Free provider used with business-sounding display name
    const brandInDisplay = BRANDS.find(b => displayName.toLowerCase().includes(b));
    const isFree = FREE_PROVIDERS.includes(senderDomain);
    if (brandInDisplay && isFree) {
      senderChecks.push({ type:"fail", text:`Claims to be "${brandInDisplay}" but sends from free email (${senderDomain})` });
    } else if (isFree) {
      senderChecks.push({ type:"warn", text:`Sender uses free email provider (${senderDomain})` });
    } else {
      senderChecks.push({ type:"pass", text:`Sender uses business domain: ${senderDomain}` });
    }

    // Suspicious TLD
    if (SUSPICIOUS_TLDS.some(t => senderDomain.endsWith(t))) {
      senderChecks.push({ type:"fail", text:`Sender domain has suspicious extension: .${senderDomain.split(".").pop()}` });
    }

    // Brand impersonation — brand in display name but not in domain
    const spoofed = BRANDS.find(b =>
      displayName.toLowerCase().includes(b) && !senderDomain.includes(b)
    );
    if (spoofed && !isFree) {
      senderChecks.push({ type:"fail", text:`Display name says "${spoofed}" but domain is "${senderDomain}"` });
    }

    // Lots of hyphens (randomized domains)
    if ((senderDomain.match(/-/g) || []).length >= 2) {
      senderChecks.push({ type:"warn", text:`Sender domain has many hyphens: ${senderDomain}` });
    }

    if (senderChecks.length === 1 && senderChecks[0].type === "pass") {
      senderChecks.push({ type:"pass", text:`Display name: ${displayName || "—"}` });
    }
  } else {
    senderChecks.push({ type:"warn", text:"Could not extract sender email address" });
  }

  // ── 2. Subject Line ─────────────────────────────────────────────────────
  const subjectChecks = [];

  const URGENCY  = ["urgent","immediately","verify","suspended","confirm","action required","expire","act now","final notice","last chance","response required"];
  const PRIZE    = ["winner","prize","congratulations","you won","reward","free gift","claim now","lottery"];
  const FINANCE  = ["invoice","payment due","refund","money transfer","transaction","billing","overdue","wire transfer"];
  const SECURITY = ["password reset","account locked","unusual sign","suspicious activity","security alert","unauthorized"];

  const hitUrgency  = URGENCY.find(w  => subjectLower.includes(w));
  const hitPrize    = PRIZE.find(w    => subjectLower.includes(w));
  const hitFinance  = FINANCE.find(w  => subjectLower.includes(w));
  const hitSecurity = SECURITY.find(w => subjectLower.includes(w));

  if (hitPrize)    subjectChecks.push({ type:"fail", text:`Prize/reward language in subject: "${hitPrize}"` });
  if (hitUrgency)  subjectChecks.push({ type:"warn", text:`Urgency language in subject: "${hitUrgency}"` });
  if (hitFinance)  subjectChecks.push({ type:"warn", text:`Financial keyword in subject: "${hitFinance}"` });
  if (hitSecurity) subjectChecks.push({ type:"warn", text:`Security alert keyword: "${hitSecurity}"` });

  if (/[A-Z]{5,}/.test(subject)) {
    subjectChecks.push({ type:"warn", text:"Subject uses ALL CAPS words (pressure tactic)" });
  }
  if ((subject.match(/[!?]/g) || []).length >= 3) {
    subjectChecks.push({ type:"warn", text:"Excessive punctuation in subject (!!!, ???)" });
  }
  if (subjectChecks.length === 0) {
    subjectChecks.push({ type:"pass", text:"No suspicious keywords in subject" });
  }

  // ── 3. Link Safety ──────────────────────────────────────────────────────
  const linkChecks = [];

  const getHref = (l) => l.includes("→") ? l.split("→")[1].trim() : l;
  const getDisplay = (l) => l.includes("→") ? l.split("→")[0].trim() : "";

  const httpLinks = links.filter(l => getHref(l).startsWith("http://"));
  const ipLinks   = links.filter(l => /https?:\/\/\d+\.\d+\.\d+\.\d+/.test(getHref(l)));
  const shortLinks = links.filter(l => SHORTENERS.some(s => getHref(l).includes(s)));
  const mismatched = links.filter(l => {
    const display = getDisplay(l);
    const href    = getHref(l);
    if (!/https?:\/\//.test(display)) return false;
    const dDomain = display.match(/https?:\/\/([^/?#]+)/)?.[1];
    const hDomain = href.match(/https?:\/\/([^/?#]+)/)?.[1];
    return dDomain && hDomain && dDomain !== hDomain;
  });
  const suspLinks = links.filter(l =>
    SUSPICIOUS_TLDS.some(t => getHref(l).includes(t))
  );

  if (ipLinks.length > 0)    linkChecks.push({ type:"fail", text:`${ipLinks.length} link(s) use IP address instead of domain name` });
  if (shortLinks.length > 0) linkChecks.push({ type:"fail", text:`${shortLinks.length} shortened URL(s) hiding actual destination` });
  if (httpLinks.length > 0)  linkChecks.push({ type:"fail", text:`${httpLinks.length} unencrypted HTTP link(s) — no privacy protection` });
  if (mismatched.length > 0) linkChecks.push({ type:"fail", text:`${mismatched.length} link(s) show different URL than actual destination` });
  if (suspLinks.length > 0)  linkChecks.push({ type:"warn", text:`${suspLinks.length} link(s) use suspicious domain extension` });

  if (links.length === 0) {
    linkChecks.push({ type:"pass", text:"No external links found in email" });
  } else {
    if (httpLinks.length === 0 && ipLinks.length === 0 && shortLinks.length === 0) {
      linkChecks.push({ type:"pass", text:"All links use HTTPS and appear normal" });
    }
    linkChecks.push({
      type: links.length > 15 ? "warn" : "pass",
      text: `${links.length} external link(s) in email`
    });
  }

  // ── 4. Content Analysis ─────────────────────────────────────────────────
  const contentChecks = [];

  const CREDENTIAL_PHRASES = [
    "enter your password","confirm your password","verify your account",
    "credit card number","card details","social security","bank account number",
    "pin number","enter your ssn","billing information"
  ];
  const THREAT_PHRASES = [
    "will be suspended","will be terminated","will be closed","will be deleted",
    "account will be locked","legal action","law enforcement","report you"
  ];
  const GENERIC_GREETINGS = ["dear customer","dear user","dear account holder","dear valued member","dear subscriber"];
  const INFO_REQUEST = ["click here to verify","click the link below","update your information","confirm your identity","validate your account"];

  const hitCred     = CREDENTIAL_PHRASES.find(w => body.includes(w));
  const hitThreat   = THREAT_PHRASES.find(w => body.includes(w));
  const hitGeneric  = GENERIC_GREETINGS.find(w => body.includes(w));
  const hitRequest  = INFO_REQUEST.find(w => body.includes(w));

  if (hitCred)    contentChecks.push({ type:"fail", text:`Asks for sensitive info: "${hitCred}"` });
  if (hitThreat)  contentChecks.push({ type:"fail", text:`Uses threats: "${hitThreat}"` });
  if (hitRequest) contentChecks.push({ type:"warn", text:`Prompts you to click and verify: "${hitRequest}"` });
  if (hitGeneric) contentChecks.push({ type:"warn", text:`Generic greeting used — not personalized: "${hitGeneric}"` });

  // Very short body
  if ((payload?.body_text || "").trim().length < 30 && links.length > 0) {
    contentChecks.push({ type:"warn", text:"Very short message with links — common in phishing" });
  }
  // Image-only email (short text, many links)
  if ((payload?.body_text || "").trim().length < 100 && links.length > 3) {
    contentChecks.push({ type:"warn", text:"Mostly image-based email — text scanners can't read hidden content" });
  }

  if (contentChecks.length === 0) {
    contentChecks.push({ type:"pass", text:"No credential requests or threats detected" });
    contentChecks.push({ type:"pass", text:"Email content appears normal" });
  }

  return { senderChecks, subjectChecks, linkChecks, contentChecks };
}

// ── Build check HTML ───────────────────────────────────────────────────────

function checkIcon(type) {
  return type === "pass" ? "✓" : type === "fail" ? "✗" : "⚠";
}

function checksHtml(items) {
  return items.map(c => `
    <div class="check check-${c.type}">
      <span class="check-icon">${checkIcon(c.type)}</span>
      <span class="check-text">${escHtml(c.text)}</span>
    </div>`).join("");
}

// ── Links section ──────────────────────────────────────────────────────────

function linksHtml(links) {
  if (!links || links.length === 0) return "";
  const getHref    = (l) => l.includes("→") ? l.split("→")[1].trim() : l;
  const getDisplay = (l) => l.includes("→") ? l.split("→")[0].trim() : "";

  const items = links.slice(0, 10).map(l => {
    const href    = getHref(l);
    const display = getDisplay(l);
    const isMismatch = display && /https?:\/\//.test(display) &&
      display.match(/https?:\/\/([^/?#]+)/)?.[1] !== href.match(/https?:\/\/([^/?#]+)/)?.[1];
    const isHttp  = href.startsWith("http://");
    const isShort = ["bit.ly","tinyurl","t.co","goo.gl"].some(s => href.includes(s));
    const isIp    = /https?:\/\/\d+\.\d+\.\d+\.\d+/.test(href);
    const flags   = [
      isMismatch ? "⚠ URL mismatch" : null,
      isHttp     ? "⚠ Unencrypted" : null,
      isShort    ? "⚠ Shortened URL" : null,
      isIp       ? "⚠ IP address" : null,
    ].filter(Boolean).join(" · ");

    return `<div class="link-item">
      ${display ? `<div class="link-display">${escHtml(display)}</div>` : ""}
      <div class="link-href">${escHtml(href)}</div>
      ${flags ? `<div class="link-flags">${flags}</div>` : ""}
    </div>`;
  }).join("");

  return `<details>
    <summary>Links in Email <span class="link-count">${links.length}</span></summary>
    ${items}
    ${links.length > 10 ? `<div class="link-more">+${links.length - 10} more links</div>` : ""}
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

  const pct      = Math.round(result.confidence * 100);
  const label    = result.model_used === "rules" ? "Quick scan" : `AI · ${result.model_used}`;
  const { senderChecks, subjectChecks, linkChecks, contentChecks } = runChecks(payload);

  const reasonsBlock = (result.reasons || []).length
    ? `<div class="section">
        <div class="section-title">AI Findings</div>
        ${(result.reasons || []).map(r => `<div class="reason">${escHtml(r)}</div>`).join("")}
        <p class="recommendation">${escHtml(result.recommendation)}</p>
       </div>`
    : "";

  main.innerHTML = `
    ${result._refining ? `<div class="refining">⟳ AI analysis running...</div>` : ""}

    <div class="risk-row">
      <span class="risk-badge risk-${result.risk_level}">${result.risk_level} risk</span>
      <div>
        <div class="confidence">${pct}% confidence</div>
        <div class="model-tag">${label}</div>
      </div>
    </div>

    ${payload?.sender || payload?.subject ? `
    <div class="section">
      <div class="section-title">Email Info</div>
      ${payload.sender  ? `<div class="info-row"><span class="info-label">From</span><span class="info-value">${escHtml(payload.sender)}</span></div>` : ""}
      ${payload.subject ? `<div class="info-row"><span class="info-label">Subject</span><span class="info-value">${escHtml(payload.subject)}</span></div>` : ""}
    </div>` : ""}

    <div class="section">
      <div class="section-title">Sender Verification</div>
      ${checksHtml(senderChecks)}
    </div>

    <div class="section">
      <div class="section-title">Subject Analysis</div>
      ${checksHtml(subjectChecks)}
    </div>

    <div class="section">
      <div class="section-title">Link Safety</div>
      ${checksHtml(linkChecks)}
    </div>

    <div class="section">
      <div class="section-title">Content Analysis</div>
      ${checksHtml(contentChecks)}
    </div>

    ${reasonsBlock}

    ${linksHtml(payload?.links)}

    <div class="report-section">
      <p class="report-hint">Think this is phishing? Report it for deeper review.</p>
      <input type="email" id="reporterEmail" placeholder="Your email (optional)" />
      <button class="report-btn" id="reportBtn" onclick="reportPhishing()">Report as Phishing</button>
      <div id="reportStatus"></div>
    </div>
  `;

  if (result._refining || pending) setTimeout(poll, 1000);
}

function poll() {
  chrome.runtime.sendMessage({ type: "GET_RESULT" }, ({ result, pending, payload }) => {
    render(result, pending, payload);
  });
}

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

function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

poll();
