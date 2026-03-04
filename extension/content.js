// PhishGuard — email content script
// Only runs on Gmail, Outlook, Yahoo Mail
(function () {
  const MAX_TEXT = 2000;
  const MAX_RETRIES = 8;
  const RETRY_INTERVAL = 1000; // ms between retries

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
    let retryCount    = 0;
    let retryTimer    = null;

    function gmailEmailOpen() {
      // Gmail email URLs have a hash with a long alphanumeric ID
      return /[#/][a-zA-Z0-9]{10,}/.test(window.location.hash);
    }

    function extractAndSend() {
      if (!gmailEmailOpen()) return;

      // Try multiple selectors — Gmail sometimes uses different class names
      const bodyEl =
        document.querySelector("div.ii.gt") ||
        document.querySelector("div.a3s.aiL") ||
        document.querySelector("div.ii");

      const hasContent = bodyEl && bodyEl.innerText.trim().length > 20;

      if (!hasContent) {
        if (retryCount < MAX_RETRIES) {
          retryCount++;
          retryTimer = setTimeout(extractAndSend, RETRY_INTERVAL);
        }
        return;
      }

      // Get message ID to avoid re-analyzing same email
      const messageEl  = document.querySelector("[data-message-id]");
      const messageId  = messageEl?.dataset?.messageId || window.location.hash;
      if (messageId === lastMessageId) return;
      lastMessageId = messageId;
      retryCount    = 0;

      const subjectEl   = document.querySelector("h2.hP");
      const senderEl    = document.querySelector(".gD[email]");
      const senderEmail = senderEl?.getAttribute("email") || "";
      const senderName  = senderEl?.innerText?.trim() || "";
      const sender      = senderEmail ? `${senderName} <${senderEmail}>` : senderName || null;

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

    function onNavigate() {
      clearTimeout(retryTimer);
      retryCount    = 0;
      lastMessageId = null;

      if (!gmailEmailOpen()) {
        chrome.runtime.sendMessage({ type: "CLEAR_EMAIL" });
        return;
      }
      retryTimer = setTimeout(extractAndSend, 1200);
    }

    // MutationObserver for dynamic DOM updates
    let mutationDebounce = null;
    const observer = new MutationObserver(() => {
      clearTimeout(mutationDebounce);
      mutationDebounce = setTimeout(() => {
        if (gmailEmailOpen() && !lastMessageId) {
          extractAndSend();
        }
      }, 800);
    });
    observer.observe(document.body, { childList: true, subtree: true });

    // Hash change covers most Gmail navigation
    window.addEventListener("hashchange", onNavigate);
    // popstate covers History API navigation (some Gmail layouts)
    window.addEventListener("popstate", onNavigate);
  }

  // ── Outlook ───────────────────────────────────────────────────────────────

  function watchOutlook() {
    let lastSubject  = null;
    let retryCount   = 0;
    let retryTimer   = null;

    function extractAndSend() {
      const bodyEl = document.querySelector(
        '[aria-label="Message body"],' +
        'div[class*="ReadingPane"] div[class*="body"]'
      );

      if (!bodyEl || bodyEl.innerText.trim().length < 10) {
        if (retryCount < MAX_RETRIES) {
          retryCount++;
          retryTimer = setTimeout(extractAndSend, RETRY_INTERVAL);
        }
        return;
      }
      retryCount = 0;

      const subjectEl = document.querySelector(
        '[data-testid="ConversationHeader"] span,' +
        '[class*="SubjectHeader"]'
      );
      const senderEl = document.querySelector(
        '[data-testid="senderName"],' +
        '[class*="SenderName"]'
      );

      const subject = subjectEl?.innerText?.trim() || "";
      if (subject && subject === lastSubject) return;
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

    let debounce = null;
    const observer = new MutationObserver(() => {
      clearTimeout(debounce);
      debounce = setTimeout(extractAndSend, 1200);
    });
    observer.observe(document.body, { childList: true, subtree: true });
    window.addEventListener("popstate", () => {
      clearTimeout(retryTimer);
      retryCount  = 0;
      lastSubject = null;
      chrome.runtime.sendMessage({ type: "CLEAR_EMAIL" });
    });
  }

  // ── Yahoo Mail ────────────────────────────────────────────────────────────

  function watchYahoo() {
    let lastUrl    = null;
    let retryCount = 0;
    let retryTimer = null;

    function extractAndSend() {
      const url = window.location.href;
      if (!/\/message\/|#mid=/.test(url)) return;
      if (url === lastUrl) return;

      const bodyEl = document.querySelector(
        '[data-test-id="message-body"],' +
        'article[tabindex]'
      );

      if (!bodyEl || bodyEl.innerText.trim().length < 10) {
        if (retryCount < MAX_RETRIES) {
          retryCount++;
          retryTimer = setTimeout(extractAndSend, RETRY_INTERVAL);
        }
        return;
      }
      retryCount = 0;
      lastUrl    = url;

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

    let debounce = null;
    const observer = new MutationObserver(() => {
      clearTimeout(debounce);
      debounce = setTimeout(extractAndSend, 1200);
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
