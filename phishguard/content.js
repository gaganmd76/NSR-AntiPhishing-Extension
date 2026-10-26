// Runs inside every web page. Scans the DOM, reports findings to the
// background worker, and shows a warning banner on dangerous pages.
// NOTE: content scripts can't use ES module imports, so this file is self-contained.

(function () {
  const URGENT_PHRASES = [
    "verify your account",
    "account has been suspended",
    "account will be suspended",
    "account will be closed",
    "unusual activity",
    "suspicious activity",
    "confirm your identity",
    "confirm your password",
    "update your payment",
    "update your billing",
    "limited access",
    "security alert",
    "immediately",
    "within 24 hours",
    "action required",
    "click here to restore",
  ];

  const BRAND_KEYWORDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "facebook",
    "instagram", "netflix", "linkedin", "dropbox", "coinbase", "binance",
    "wells fargo", "bank of america", "citibank", "chase", "hdfc", "icici", "sbi",
  ];

  const IPV4_REGEX = /^\d{1,3}(\.\d{1,3}){3}$/;

  // ---------- Helpers ----------

  function getRegistrable(hostname) {
    const labels = hostname.toLowerCase().split(".");
    if (labels.length <= 2) return hostname.toLowerCase();
    const multi = ["co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "co.in",
      "co.jp", "com.br", "com.cn", "co.za", "com.mx", "co.nz", "com.sg"];
    const lastTwo = labels.slice(-2).join(".");
    return multi.includes(lastTwo)
      ? labels.slice(-3).join(".")
      : labels.slice(-2).join(".");
  }

  // True for localhost and private/loopback addresses (local development)
  function isLocalHost(hostname) {
    const h = hostname.toLowerCase().replace(/^\[|\]$/g, "");
    if (h === "localhost" || h === "::1") return true;
    if (h.endsWith(".localhost") || h.endsWith(".local")) return true;

    const m = h.match(/^(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/);
    if (!m) return false;
    const a = Number(m[1]);
    const b = Number(m[2]);
    return (
      a === 10 ||
      a === 127 ||
      (a === 192 && b === 168) ||
      (a === 172 && b >= 16 && b <= 31)
    );
  }

  function isVisible(el) {
    const style = window.getComputedStyle(el);
    const rect = el.getBoundingClientRect();
    return (
      style.display !== "none" &&
      style.visibility !== "hidden" &&
      parseFloat(style.opacity) > 0 &&
      rect.width > 0 &&
      rect.height > 0
    );
  }

  // ---------- Scanners ----------

  function scanForms() {
    const findings = [];
    const pageHost = location.hostname;
    const pageRegistrable = getRegistrable(pageHost);
    const forms = document.querySelectorAll("form");
    let passwordFormCount = 0;

    forms.forEach((form) => {
      const passwordFields = form.querySelectorAll('input[type="password"]');
      if (passwordFields.length === 0) return;
      passwordFormCount++;

      const rawAction = form.getAttribute("action");

      // No action or empty: submits to the same page (or handled by JS)
      if (!rawAction || rawAction.trim() === "" || rawAction.startsWith("javascript:")) {
        findings.push({
          id: "form-js-action",
          message: "Password form has no clear destination (handled by JavaScript)",
          points: 10,
        });
        return;
      }

      let actionUrl;
      try {
        actionUrl = new URL(rawAction, location.href);
      } catch {
        findings.push({
          id: "form-bad-action",
          message: "Password form has an invalid submit address",
          points: 15,
        });
        return;
      }

      const actionHost = actionUrl.hostname;
      const actionRegistrable = getRegistrable(actionHost);

      // Cross-domain submission
      if (actionRegistrable !== pageRegistrable) {
        findings.push({
          id: "form-cross-domain",
          message: `Password form sends data to a different site: ${actionHost}`,
          points: 40,
        });
      }

      // Plain HTTP submission (only when it's a downgrade or goes to another site)
      if (
        actionUrl.protocol === "http:" &&
        !isLocalHost(actionHost) &&
        (location.protocol === "https:" || actionRegistrable !== pageRegistrable)
      ) {
        findings.push({
          id: "form-http",
          message: "Password form submits over unencrypted HTTP",
          points: 25,
        });
      }

      // Submitting to a raw IP
      if (IPV4_REGEX.test(actionHost) && !isLocalHost(actionHost)) {
        findings.push({
          id: "form-ip",
          message: `Password form submits to a raw IP address: ${actionHost}`,
          points: 35,
        });
      }

      // Many hidden fields alongside a password field
      const hiddenCount = form.querySelectorAll('input[type="hidden"]').length;
      if (hiddenCount >= 5) {
        findings.push({
          id: "form-hidden-fields",
          message: `Password form contains ${hiddenCount} hidden fields`,
          points: 10,
        });
      }
    });

    // Password field on an insecure page
    if (
      passwordFormCount > 0 &&
      location.protocol === "http:" &&
      !isLocalHost(location.hostname)
    ) {
      findings.push({
        id: "password-on-http",
        message: "Page asks for a password without HTTPS",
        points: 20,
      });
    }

    // Password inputs that live outside any <form> (JS-driven login)
    const looseInputs = [...document.querySelectorAll('input[type="password"]')]
      .filter((i) => !i.closest("form"));
    if (looseInputs.length > 0) {
      findings.push({
        id: "password-no-form",
        message: "Password field exists outside a form (JavaScript-driven login)",
        points: 10,
      });
    }

    return {
      findings,
      hasPasswordField: document.querySelector('input[type="password"]') !== null,
    };
  }

  function scanIframes() {
    const findings = [];
    const iframes = document.querySelectorAll("iframe");

    iframes.forEach((frame) => {
      const rect = frame.getBoundingClientRect();
      const tiny = rect.width <= 2 || rect.height <= 2;
      const hidden = !isVisible(frame);

      if (tiny || hidden) {
        const src = frame.getAttribute("src") || "";
        // Ignore empty/about:blank frames, they're common and harmless
        if (src && !src.startsWith("about:")) {
          findings.push({
            id: "hidden-iframe",
            message: "Hidden iframe loading external content",
            points: 15,
          });
        }
      }
    });

    // Only report once even if several hidden iframes exist
    return findings.slice(0, 1);
  }

  function scanLanguage() {
    const findings = [];
    const text = (document.body?.innerText || "").toLowerCase().slice(0, 20000);

    const matched = URGENT_PHRASES.filter((p) => text.includes(p));
    if (matched.length >= 2) {
      findings.push({
        id: "urgent-language",
        message: `Pressure language found: "${matched.slice(0, 3).join('", "')}"`,
        points: 15,
      });
    }

    return findings;
  }

  function scanBrandMismatch(hasPasswordField) {
    const findings = [];
    if (!hasPasswordField) return findings;

    const title = (document.title || "").toLowerCase();
    const registrable = getRegistrable(location.hostname);

    for (const brand of BRAND_KEYWORDS) {
      if (title.includes(brand)) {
        const compact = brand.replace(/\s+/g, "");
        if (!registrable.includes(compact)) {
          findings.push({
            id: "title-brand-mismatch",
            message: `Page title mentions "${brand}" and asks for a password, but the domain is ${registrable}`,
            points: 30,
          });
        }
        break;
      }
    }
    return findings;
  }

  function scanObfuscation() {
    const findings = [];
    let suspicious = false;

    document.querySelectorAll("script:not([src])").forEach((s) => {
      const code = s.textContent || "";
      if (
        code.length > 500 &&
        (/eval\s*\(/.test(code) ||
          /unescape\s*\(/.test(code) ||
          /atob\s*\(/.test(code) ||
          /fromCharCode/.test(code))
      ) {
        suspicious = true;
      }
    });

    if (suspicious) {
      findings.push({
        id: "obfuscated-script",
        message: "Page contains obfuscated JavaScript (eval/atob/fromCharCode)",
        points: 10,
      });
    }
    return findings;
  }

    function scanSensors() {
    const findings = [];
    let events = [];
    try {
      events = JSON.parse(
        document.documentElement.getAttribute("data-nsr-sensors") || "[]"
      );
    } catch {}

    // "Automatic" = the page asked without any click or key press
    const auto = (kind) => events.some((e) => e.kind === kind && !e.activated);

    if (auto("camera")) {
      findings.push({
        id: "sensor-camera-auto",
        message: "Page asked for your camera as soon as it loaded, without any click",
        points: 40,
      });
    }
    if (auto("microphone")) {
      findings.push({
        id: "sensor-mic-auto",
        message: "Page asked for your microphone as soon as it loaded, without any click",
        points: 25,
      });
    }
    if (auto("location")) {
      findings.push({
        id: "sensor-location-auto",
        message: "Page asked for your location as soon as it loaded, without any click",
        points: 15,
      });
    }
    return findings;
  }

  // ---------- Run everything ----------

  function runScan() {
    const formResult = scanForms();
    const findings = [
      ...formResult.findings,
      ...scanIframes(),
      ...scanLanguage(),
      ...scanBrandMismatch(formResult.hasPasswordField),
      ...scanObfuscation(),
      ...scanObfuscation(),
      ...scanSensors(),
    ];

    return {
      url: location.href,
      hasPasswordField: formResult.hasPasswordField,
      findings,
    };
  }

  // ---------- Warning banner (Part 5) ----------

  let bannerHost = null;
  let dismissed = false;
  let lastSignature = "";

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text) node.textContent = text;
    return node;
  }

  function removeBanner() {
    if (bannerHost) {
      bannerHost.remove();
      bannerHost = null;
    }
  }

  function showBanner(result) {
    if (dismissed) return;
    removeBanner();

    bannerHost = document.createElement("div");
    bannerHost.id = "nsr-banner-host";
    bannerHost.style.cssText =
      "all: initial !important; position: fixed !important; top: 0 !important;" +
      "left: 0 !important; right: 0 !important; z-index: 2147483647 !important;";

    // Shadow DOM keeps the page's CSS from touching our banner
    const root = bannerHost.attachShadow({ mode: "closed" });

    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = chrome.runtime.getURL("banner.css");

    const bar = el("div", "bar");
    const main = el("div", "main");

    const text = el("div", "text");
    text.append(
      el("strong", "", "NSR: this page looks like phishing"),
      el(
        "span",
        "",
        `Risk score ${result.score}/100. Don't enter passwords or personal information here.`
      )
    );

    const actions = el("div", "actions");
    const leaveBtn = el("button", "btn primary", "Leave this page");
    const detailsBtn = el("button", "btn secondary", "Details");
    const trustBtn = el("button", "btn secondary", "I trust this site");
    const closeBtn = el("button", "close", "×");
    closeBtn.title = "Dismiss";
    actions.append(leaveBtn, detailsBtn, trustBtn, closeBtn);

    const list = el("ul", "details");
    for (const f of result.findings) {
      list.appendChild(el("li", "", f.message));
    }

    leaveBtn.addEventListener("click", () => {
      location.replace("about:blank");
    });

    detailsBtn.addEventListener("click", () => {
      const open = list.classList.toggle("open");
      detailsBtn.textContent = open ? "Hide details" : "Details";
    });

    trustBtn.addEventListener("click", async () => {
      const ok = confirm(
        `Always trust ${location.hostname}?\nNSR will stop warning you about this site.`
      );
      if (!ok) return;
      try {
        await chrome.runtime.sendMessage({ type: "TRUST_SITE" });
      } catch {
        // extension was reloaded; ignore
      }
      dismissed = true;
      removeBanner();
    });

    closeBtn.addEventListener("click", () => {
      dismissed = true;
      removeBanner();
    });

    main.append(el("div", "icon", "🚨"), text, actions);
    bar.append(main, list);
    root.append(link, bar);
    document.documentElement.appendChild(bannerHost);
  }

    function applyVerdict(res) {
    if (res && res.verdict === "dangerous" && res.banner !== false) showBanner(res);
    else removeBanner();
  }

  // ---------- Reporting to the background worker ----------

  async function reportScan() {
    const scan = runScan();

    // Skip if nothing changed since the last report
    const signature =
      JSON.stringify(scan.findings.map((f) => f.id)) + scan.hasPasswordField;
    if (signature === lastSignature) return;
    lastSignature = signature;

    try {
      const res = await chrome.runtime.sendMessage({
        type: "PAGE_SCAN_RESULT",
        scan,
      });
      applyVerdict(res);
    } catch {
      // Extension was reloaded or updated; this old script can't talk anymore
    }
  }

  // Popup asks for scan results (still used by the popup)
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "GET_PAGE_SCAN") {
      sendResponse(runScan());
    }
  });

    // The page just used the camera, microphone or location: rescan quickly
  let sensorTimer = null;
  window.addEventListener("nsr-sensor", () => {
    clearTimeout(sensorTimer);
    sensorTimer = setTimeout(reportScan, 300);
  });
  
  // First scan right away
  reportScan();

  // Pages that add a login form later: rescan on DOM changes for 30 seconds
  let timer = null;
  const observer = new MutationObserver((mutations) => {
    // Ignore changes caused by our own banner
    const onlyOurs = mutations.every((m) =>
      [...m.addedNodes, ...m.removedNodes].every(
        (n) => n.id === "nsr-banner-host"
      )
    );
    if (onlyOurs) return;

    clearTimeout(timer);
    timer = setTimeout(reportScan, 1500);
  });
  observer.observe(document.documentElement, { childList: true, subtree: true });
  setTimeout(() => observer.disconnect(), 30000);
})();