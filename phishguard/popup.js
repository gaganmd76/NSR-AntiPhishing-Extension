import { analyzeUrl } from "./lib/urlAnalyzer.js";
import { evaluate, CATEGORY_LABELS } from "./lib/scoring.js";
import { getSettings } from "./lib/settings.js";

const VERDICT_LABELS = {
  safe: "✅ Looks safe",
  suspicious: "⚠️ Suspicious",
  dangerous: "🚨 Likely phishing",
  unsupported: "ℹ️ Not a web page (nothing to check)",
};

// ---------- Rendering ----------

function renderResult(result, { verdictEl, hostEl, barEl, scoreEl, listEl, breakdownEl }) {
  verdictEl.textContent = VERDICT_LABELS[result.verdict];
  verdictEl.className = `verdict ${result.verdict}`;

  hostEl.textContent = result.hostname || "";

  barEl.style.width = `${result.score}%`;
  barEl.className = `score-bar ${result.verdict}`;
  scoreEl.textContent = result.supported === false ? "" : `Risk score: ${result.score} / 100`;

  // Category chips
  if (breakdownEl) {
    breakdownEl.replaceChildren();
    for (const [cat, pts] of Object.entries(result.categories || {})) {
      const chip = document.createElement("span");
      chip.className = "chip";
      chip.append(`${CATEGORY_LABELS[cat] || cat}: `);
      const b = document.createElement("b");
      b.textContent = pts;
      chip.appendChild(b);
      breakdownEl.appendChild(chip);
    }
  }

  // Findings list
  listEl.replaceChildren();
  for (const f of result.findings) {
    const li = document.createElement("li");
    li.textContent = f.message + " ";
    const pts = document.createElement("span");
    pts.className = "pts";
    pts.textContent = `(+${f.points})`;
    li.appendChild(pts);
    listEl.appendChild(li);
  }
}

function renderNotes(notes, anchorEl) {
  anchorEl.parentElement.querySelectorAll(".note").forEach((n) => n.remove());
  for (const text of notes || []) {
    const div = document.createElement("div");
    div.className = "note";
    div.textContent = text;
    anchorEl.after(div);
  }
}

function renderChain(info, el) {
  el.replaceChildren();
  if (!info || !info.hops || info.hops.length === 0) return;

  const hostOf = (u) => {
    try {
      return new URL(u).host;
    } catch {
      return u;
    }
  };

  const title = document.createElement("div");
  title.className = "chain-title";
  title.textContent = `Redirect chain (${info.hops.length} hop${info.hops.length > 1 ? "s" : ""})`;

  const ol = document.createElement("ol");
  const first = document.createElement("li");
  first.textContent = hostOf(info.hops[0].from);
  ol.appendChild(first);

  for (const hop of info.hops) {
    const li = document.createElement("li");
    li.textContent = hostOf(hop.to) + " ";
    const tag = document.createElement("span");
    tag.className = "tag";
    tag.textContent = hop.type === "client" ? "(page redirect)" : `(HTTP ${hop.status || "3xx"})`;
    li.appendChild(tag);
    ol.appendChild(li);
  }

  el.append(title, ol);
}

// ---------- Data sources ----------

async function getPageScan(tabId) {
  try {
    return await chrome.tabs.sendMessage(tabId, { type: "GET_PAGE_SCAN" });
  } catch {
    return null;
  }
}

async function getRedirectInfo(tabId) {
  try {
    const key = `redirects:${tabId}`;
    const data = await chrome.storage.session.get(key);
    return data[key] || null;
  } catch {
    return null;
  }
}

// ---------- Current tab ----------

async function analyzeCurrentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const settings = await getSettings();
  const urlResult = analyzeUrl(tab?.url || "", settings.customBrands);

  const els = {
    verdictEl: document.getElementById("verdict"),
    hostEl: document.getElementById("host"),
    barEl: document.getElementById("score-bar"),
    scoreEl: document.getElementById("score-text"),
    listEl: document.getElementById("findings"),
    breakdownEl: document.getElementById("breakdown"),
  };

  if (!urlResult.supported) {
    renderResult({ ...urlResult, findings: [], categories: {} }, els);
    return;
  }

  const [pageScan, redirectInfo] = await Promise.all([
    getPageScan(tab.id),
    getRedirectInfo(tab.id),
  ]);

  const result = evaluate({
    hostname: urlResult.hostname,
    urlFindings: urlResult.findings,
    pageFindings: pageScan?.findings || [],
    redirectFindings: redirectInfo?.findings || [],
    hasPasswordField: pageScan?.hasPasswordField || false,
    whitelist: settings.whitelist,
    sensitivity: settings.sensitivity,
    extraBrands: settings.customBrands,
  });

  renderResult({ ...result, hostname: urlResult.hostname }, els);
  renderNotes(result.notes, els.scoreEl);
  renderChain(redirectInfo, document.getElementById("chain"));

  const note = document.getElementById("scan-note");
  if (!pageScan) {
    note.textContent = "Page content not scanned. Reload the page and reopen NSR.";
  } else if (pageScan.hasPasswordField) {
    note.textContent = "🔑 This page has a password field.";
  } else {
    note.textContent = "No password field on this page.";
  }
}

// ---------- URL tester ----------

function setupTester() {
  const input = document.getElementById("test-input");
  const button = document.getElementById("test-btn");
  const out = document.getElementById("test-result");

  async function run() {
    const value = input.value.trim();
    if (!value) return;

    const settings = await getSettings();
    const urlResult = analyzeUrl(value, settings.customBrands);
    const result = urlResult.supported
      ? {
          ...evaluate({
            hostname: urlResult.hostname,
            urlFindings: urlResult.findings,
            whitelist: settings.whitelist,
            sensitivity: settings.sensitivity,
            extraBrands: settings.customBrands,
          }),
          hostname: urlResult.hostname,
        }
      : { ...urlResult, categories: {} };

    out.replaceChildren();

    const verdict = document.createElement("div");
    const host = document.createElement("div");
    host.className = "host";
    const wrap = document.createElement("div");
    wrap.className = "score-wrap";
    const bar = document.createElement("div");
    bar.className = "score-bar";
    wrap.appendChild(bar);
    const score = document.createElement("div");
    score.className = "score-text";
    const breakdown = document.createElement("div");
    breakdown.className = "breakdown";
    const list = document.createElement("ul");

    out.append(verdict, host, wrap, score, breakdown, list);
    renderResult(result, {
      verdictEl: verdict, hostEl: host, barEl: bar,
      scoreEl: score, listEl: list, breakdownEl: breakdown,
    });
  }

  button.addEventListener("click", run);
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") run();
  });
}

document.getElementById("settings-btn").addEventListener("click", () => {
  chrome.tabs.create({ url: chrome.runtime.getURL("options.html") });
});

analyzeCurrentTab();
setupTester();