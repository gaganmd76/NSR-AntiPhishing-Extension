import { analyzeRedirectChain } from "./lib/redirectAnalyzer.js";
import { analyzeUrl, splitHostname } from "./lib/urlAnalyzer.js";
import { evaluate } from "./lib/scoring.js";

// The service worker can be shut down at any moment, so state lives in
// chrome.storage.session instead of normal variables.
//
// nav:<tabId>        -> working state while navigations are in progress
// redirects:<tabId>  -> finished redirect result

const queues = new Map();

// Runs tasks for the same tab one after another, so events never overlap
function enqueue(tabId, task) {
  const prev = queues.get(tabId) || Promise.resolve();
  const next = prev.then(task).catch((err) => console.error("NSR:", err));
  queues.set(tabId, next);
  return next;
}

const navKey = (tabId) => `nav:${tabId}`;
const resultKey = (tabId) => `redirects:${tabId}`;

// ---------- Badge + evaluation (Part 5) ----------

const BADGE = {
  safe: { text: "", color: "#22c55e" },
  suspicious: { text: "!", color: "#eab308" },
  dangerous: { text: "!!", color: "#ef4444" },
};

async function getWhitelist() {
  try {
    const data = await chrome.storage.sync.get("whitelist");
    return data.whitelist || [];
  } catch {
    return [];
  }
}

// Combines URL + redirect + (optional) page scan into one scored result
async function evaluateTab(tabId, url, pageScan) {
  const urlResult = analyzeUrl(url || "");
  if (!urlResult.supported) return null;

  const data = await chrome.storage.session.get(resultKey(tabId));
  const redirectInfo = data[resultKey(tabId)] || null;
  const whitelist = await getWhitelist();

  const result = evaluate({
    hostname: urlResult.hostname,
    urlFindings: urlResult.findings,
    pageFindings: pageScan?.findings || [],
    redirectFindings: redirectInfo?.findings || [],
    hasPasswordField: pageScan?.hasPasswordField || false,
    whitelist,
  });

  return { ...result, hostname: urlResult.hostname };
}

async function updateBadge(tabId, result) {
  try {
    if (!result) {
      await chrome.action.setBadgeText({ tabId, text: "" });
      return;
    }
    const b = BADGE[result.verdict];
    await chrome.action.setBadgeText({ tabId, text: b.text });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: b.color });
    await chrome.action.setTitle({
      tabId,
      title: `NSR: ${result.verdict} (${result.score}/100)`,
    });
  } catch {
    // Tab was closed before we could update it
  }
}

// The content script sent its scan: evaluate, update badge, reply with verdict
async function handleScan(tabId, url, scan) {
  const result = await evaluateTab(tabId, url, scan);
  await updateBadge(tabId, result);
  if (!result) return null;

  return {
    verdict: result.verdict,
    score: result.score,
    trusted: result.trusted,
    findings: result.findings
      .slice(0, 8)
      .map((f) => ({ message: f.message, points: f.points })),
  };
}

// User clicked "I trust this site" on the banner
async function trustSite(tabId, url) {
  const { registrable } = splitHostname(new URL(url).hostname);
  const list = await getWhitelist();
  if (!list.includes(registrable)) list.push(registrable);
  await chrome.storage.sync.set({ whitelist: list });

  const result = await evaluateTab(tabId, url, null);
  await updateBadge(tabId, result);
  return { ok: true };
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Only accept messages from the top frame of a real tab
  if (!sender.tab || sender.frameId !== 0) return;
  const tabId = sender.tab.id;
  const url = sender.tab.url;

  if (message.type === "PAGE_SCAN_RESULT") {
    // enqueue so we run after any pending redirect bookkeeping for this tab
    enqueue(tabId, () => handleScan(tabId, url, message.scan)).then(sendResponse);
    return true; // keep the channel open for the async reply
  }

  if (message.type === "TRUST_SITE") {
    enqueue(tabId, () => trustSite(tabId, url)).then(sendResponse);
    return true;
  }
});

// ---------- Redirect tracking (Part 3) ----------

async function loadState(tabId) {
  const data = await chrome.storage.session.get(navKey(tabId));
  return (
    data[navKey(tabId)] || {
      hops: [],           // finished chain of the current page
      pending: [],        // server redirects seen for the navigation in progress
      pendingStart: null, // URL where the navigation in progress began
      finalUrl: null,     // URL the tab is currently on
    }
  );
}

async function saveState(tabId, state) {
  await chrome.storage.session.set({ [navKey(tabId)]: state });
}

// 1. A navigation starts in the top frame
chrome.webNavigation.onBeforeNavigate.addListener((d) => {
  if (d.frameId !== 0) return;
  enqueue(d.tabId, async () => {
    const state = await loadState(d.tabId);
    state.pendingStart = d.url;
    await saveState(d.tabId, state);
  });
});

// 2. Server-side redirect (HTTP 301/302/303/307/308)
chrome.webRequest.onBeforeRedirect.addListener(
  (d) => {
    if (d.tabId < 0) return;
    enqueue(d.tabId, async () => {
      const state = await loadState(d.tabId);
      state.pending.push({
        from: d.url,
        to: d.redirectUrl,
        type: "server",
        status: d.statusCode,
      });
      await saveState(d.tabId, state);
    });
  },
  { urls: ["http://*/*", "https://*/*"], types: ["main_frame"] }
);

// 3. The page has been committed (the browser decided what it is showing)
chrome.webNavigation.onCommitted.addListener((d) => {
  if (d.frameId !== 0) return;
  enqueue(d.tabId, async () => {
    const state = await loadState(d.tabId);
    const isClientRedirect = d.transitionQualifiers.includes("client_redirect");

    let hops;
    if (isClientRedirect && state.finalUrl) {
      hops = [
        ...state.hops,
        { from: state.finalUrl, to: state.pendingStart || d.url, type: "client" },
        ...state.pending,
      ];
    } else {
      hops = [...state.pending];
    }

    await saveState(d.tabId, {
      hops,
      pending: [],
      pendingStart: null,
      finalUrl: d.url,
    });

    const analysis = analyzeRedirectChain(hops, d.url);
    await chrome.storage.session.set({
      [resultKey(d.tabId)]: {
        hops,
        finalUrl: d.url,
        findings: analysis.findings,
        score: analysis.score,
      },
    });

    // Part 5: early badge from URL + redirects (page scan comes later)
    const result = await evaluateTab(d.tabId, d.url, null);
    await updateBadge(d.tabId, result);
  });
});

// Navigation failed or was cancelled: drop half-collected data
chrome.webNavigation.onErrorOccurred.addListener((d) => {
  if (d.frameId !== 0) return;
  enqueue(d.tabId, async () => {
    const state = await loadState(d.tabId);
    state.pending = [];
    state.pendingStart = null;
    await saveState(d.tabId, state);
  });
});

// Tab closed: clean up
chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.session.remove([navKey(tabId), resultKey(tabId)]);
  queues.delete(tabId);
});