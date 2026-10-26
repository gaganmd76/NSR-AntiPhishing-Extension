import { getSettings } from "./lib/settings.js";
import { splitHostname } from "./lib/urlAnalyzer.js";

const $ = (id) => document.getElementById(id);

// ---------- Helpers ----------

function toast(message, isError = false) {
  const t = $("toast");
  t.textContent = message;
  t.className = isError ? "show error" : "show";
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => (t.className = ""), 2200);
}

// "https://www.App.GitHub.com/login" -> "github.com", or null if invalid
function cleanDomain(raw) {
  let d = String(raw).trim().toLowerCase();
  d = d.replace(/^https?:\/\//, "").replace(/^www\./, "");
  d = d.split("/")[0].split("?")[0].split("#")[0].split(":")[0];
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(d)) return null;
  return splitHostname(d).registrable;
}

function renderList(ul, items, labelFn, onRemove, emptyText) {
  ul.replaceChildren();

  if (items.length === 0) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = emptyText;
    ul.appendChild(li);
    return;
  }

  items.forEach((item, index) => {
    const li = document.createElement("li");
    const label = document.createElement("span");
    label.textContent = labelFn(item);

    const btn = document.createElement("button");
    btn.className = "remove";
    btn.textContent = "Remove";
    btn.addEventListener("click", () => onRemove(index));

    li.append(label, btn);
    ul.appendChild(li);
  });
}

// ---------- Render everything from storage ----------

async function render() {
  const s = await getSettings();

  const radio = document.querySelector(
    `input[name="sensitivity"][value="${s.sensitivity}"]`
  );
  if (radio) radio.checked = true;

  $("show-banner").checked = s.showBanner;

  renderList(
    $("wl-list"),
    s.whitelist,
    (d) => d,
    removeWhitelist,
    "No trusted sites yet."
  );

  renderList(
    $("brand-list"),
    s.customBrands,
    (b) => `${b.name}  →  ${b.domains.join(", ")}`,
    removeBrand,
    "No custom brands yet."
  );
}

// ---------- Whitelist ----------

async function addWhitelist() {
  const domain = cleanDomain($("wl-input").value);
  if (!domain) return toast("Enter a valid domain, like example.com", true);

  const s = await getSettings();
  if (s.whitelist.includes(domain)) return toast("Already in the list", true);

  await chrome.storage.sync.set({ whitelist: [...s.whitelist, domain] });
  $("wl-input").value = "";
  toast(`Added ${domain}`);
  render();
}

async function removeWhitelist(index) {
  const s = await getSettings();
  const next = s.whitelist.filter((_, i) => i !== index);
  await chrome.storage.sync.set({ whitelist: next });
  toast("Removed");
  render();
}

// ---------- Custom brands ----------

async function addBrand() {
  const name = $("brand-name").value.trim().toLowerCase();
  const rawDomains = $("brand-domains").value
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);

  if (!/^[a-z0-9]{5,30}$/.test(name)) {
    return toast("Keyword: 5 to 30 letters or numbers, no spaces", true);
  }
  if (rawDomains.length === 0) {
    return toast("Add at least one official domain", true);
  }

  const domains = rawDomains.map(cleanDomain);
  if (domains.includes(null)) {
    return toast("One of the domains is not valid", true);
  }

  const s = await getSettings();
  if (s.customBrands.some((b) => b.name === name)) {
    return toast("That brand already exists", true);
  }

  const brand = { name, domains: [...new Set(domains)] };
  await chrome.storage.sync.set({ customBrands: [...s.customBrands, brand] });

  $("brand-name").value = "";
  $("brand-domains").value = "";
  toast(`Added ${name}`);
  render();
}

async function removeBrand(index) {
  const s = await getSettings();
  const next = s.customBrands.filter((_, i) => i !== index);
  await chrome.storage.sync.set({ customBrands: next });
  toast("Removed");
  render();
}

// ---------- Wire up the page ----------

document.querySelectorAll('input[name="sensitivity"]').forEach((radio) => {
  radio.addEventListener("change", async () => {
    await chrome.storage.sync.set({ sensitivity: radio.value });
    toast(`Sensitivity: ${radio.value}`);
  });
});

$("show-banner").addEventListener("change", async (e) => {
  await chrome.storage.sync.set({ showBanner: e.target.checked });
  toast(e.target.checked ? "Banner on" : "Banner off");
});

$("wl-add").addEventListener("click", addWhitelist);
$("wl-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter") addWhitelist();
});

$("brand-add").addEventListener("click", addBrand);
$("brand-domains").addEventListener("keydown", (e) => {
  if (e.key === "Enter") addBrand();
});

// If the whitelist changes elsewhere (e.g. "I trust this site"), refresh the lists
chrome.storage.onChanged.addListener(render);

render();