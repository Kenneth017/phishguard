// PhishGuard — email content script
// Only runs on Gmail, Outlook, Yahoo Mail
(function () {
  const MAX_TEXT = 2000;

  const WATCHERS = {
    "mail.google.com":        watchGmail,
    "outlook.live.com":       watchOutlook,
    "outlook.office.com":     watchOutlook,
    "outlook.office365.com":  watchOutlook,
    "mail.yahoo.com":         watchYahoo,
  };

  const watcher = WATCHERS[window.location.hostname];
  if (watcher) watcher();

  // ── Gmail ─────────────────────────────────────────────────────────────────

  function watchGmail() {
    let lastMessageId = null;
    let debounce = null;

    function tryExtract() {
      // Only proceed when URL indicates an open email (long hash ID)
      if (!/[#/][a-zA-Z0-9]{10,}$/.test(window.location.hash)) return;

      const bodyEl =
        document.querySelector("div.ii.gt") ||
        document.querySelector("div.a3s.aiL") ||
        document.querySelector("div[data-message-id] div.ii");

      if (!bodyEl || !bodyEl.innerText.trim()) {
        // Body not rendered yet — retry
        debounce = setTimeout(tryExtract, 1000);
        return;
      }

      const messageEl  = document.querySelector("[data-message-id]");
      const messageId  = messageEl?.dataset?.messageId || window.location.hash;
      if (messageId === lastMessageId) return;
      lastMessageId = messageId;

      const subjectEl  = document.querySelector("h2.hP");
      const senderEl   = document.querySelector(".gD[email]");
      const senderEmail = senderEl?.getAttribute("email") || "";
      const senderName  = senderEl?.innerText?.trim() || "";

      const sender = senderEmail
        ? `${senderName} <${senderEmail}>`
        : senderName || null;

      chrome.runtime.sendMessage({
        type: "ANALYZE_EMAIL",
        payload: {
          url:       window.location.href,
          subject:   subjectEl?.innerText?.trim() || document.title,
          sender,
          body_text: bodyEl.innerText.slice(0, MAX_TEXT),
          links:     getLinks(bodyEl),
        },
      });
    }

    const observer = new MutationObserver(() => {
      clearTimeout(debounce);
      debounce = setTimeout(tryExtract, 1500);
    });
    observer.observe(document.body, { childList: true, subtree: true });

    // Trigger on hash change (user clicks different email)
    window.addEventListener("hashchange", () => {
      clearTimeout(debounce);
      lastMessageId = null;
      debounce = setTimeout(tryExtract, 1500);
    });
  }

  // ── Outlook ───────────────────────────────────────────────────────────────

  function watchOutlook() {
    let lastSubject = null;
    let debounce = null;

    function tryExtract() {
      const bodyEl = document.querySelector(
        '[aria-label="Message body"],' +
        'div[class*="ReadingPane"] div[class*="body"]'
      );
      if (!bodyEl || !bodyEl.innerText.trim()) return;

      const subjectEl = document.querySelector(
        '[data-testid="ConversationHeader"] span,' +
        '[class*="SubjectHeader"]'
      );
      const senderEl = document.querySelector(
        '[data-testid="senderName"],' +
        '[class*="SenderName"]'
      );

      const subject = subjectEl?.innerText?.trim() || "";
      if (subject === lastSubject) return;
      lastSubject = subject;

      chrome.runtime.sendMessage({
        type: "ANALYZE_EMAIL",
        payload: {
          url:       window.location.href,
          subject:   subject || document.title,
          sender:    senderEl?.innerText?.trim() || null,
          body_text: bodyEl.innerText.slice(0, MAX_TEXT),
          links:     getLinks(bodyEl),
        },
      });
    }

    const observer = new MutationObserver(() => {
      clearTimeout(debounce);
      debounce = setTimeout(tryExtract, 1500);
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }

  // ── Yahoo Mail ────────────────────────────────────────────────────────────

  function watchYahoo() {
    let lastUrl = null;
    let debounce = null;

    function tryExtract() {
      const url = window.location.href;
      if (!/\/message\/|#mid=/.test(url)) return;
      if (url === lastUrl) return;

      const bodyEl = document.querySelector(
        '[data-test-id="message-body"],' +
        'article[tabindex]'
      );
      if (!bodyEl || !bodyEl.innerText.trim()) return;
      lastUrl = url;

      const subjectEl = document.querySelector(
        '[data-test-id="message-group-subject"],' +
        'h1[tabindex]'
      );
      const senderEl = document.querySelector('[data-test-id="message-header-from"]');

      chrome.runtime.sendMessage({
        type: "ANALYZE_EMAIL",
        payload: {
          url,
          subject:   subjectEl?.innerText?.trim() || document.title,
          sender:    senderEl?.innerText?.trim() || null,
          body_text: bodyEl.innerText.slice(0, MAX_TEXT),
          links:     getLinks(bodyEl),
        },
      });
    }

    const observer = new MutationObserver(() => {
      clearTimeout(debounce);
      debounce = setTimeout(tryExtract, 1500);
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  function getLinks(root) {
    return Array.from(root.querySelectorAll("a[href]"))
      .map((a) => ({ text: a.innerText.trim().slice(0, 60), href: a.href }))
      .filter((l) => l.href.startsWith("http"))
      .slice(0, 30)
      .map((l) => l.text ? `${l.text} → ${l.href}` : l.href);
  }
})();
