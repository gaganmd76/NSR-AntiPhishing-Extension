import { BRANDS } from "./brands.js";
import { splitHostname } from "./urlAnalyzer.js";

// Score needed to reach each verdict, per sensitivity level
export const THRESHOLDS = {
  low: { suspicious: 35, dangerous: 70 },
  medium: { suspicious: 25, dangerous: 60 },
  high: { suspicious: 18, dangerous: 45 },
};

const CATEGORY_CAP = 70;     // max points any single category can contribute
const TRUSTED_FACTOR = 0.25; // official brand domains keep only 25% of their score

const PAGE_IDS = [
  "hidden-iframe",
  "urgent-language",
  "title-brand-mismatch",
  "obfuscated-script",
];

const IMPERSONATION_IDS = [
  "lookalike-substitution",
  "lookalike-distance",
  "brand-in-domain",
  "brand-in-subdomain",
  "punycode",
];

export const CATEGORY_LABELS = {
  url: "URL",
  form: "Forms",
  page: "Page",
  redirect: "Redirects",
  combo: "Combined",
};

// ---------- Helpers ----------

export function verdictFromScore(score, sensitivity = "medium") {
  const t = THRESHOLDS[sensitivity] || THRESHOLDS.medium;
  if (score >= t.dangerous) return "dangerous";
  if (score >= t.suspicious) return "suspicious";
  return "safe";
}

export function categoryOf(id) {
  if (id.startsWith("combo-")) return "combo";
  if (id.startsWith("form-") || id.startsWith("password-")) return "form";
  if (id.startsWith("redirect-") || id === "open-redirect") return "redirect";
  if (PAGE_IDS.includes(id)) return "page";
  return "url";
}

// If the same finding appears twice, keep the one with the most points
function dedupe(findings) {
  const byId = new Map();
  for (const f of findings) {
    const existing = byId.get(f.id);
    if (!existing || f.points > existing.points) byId.set(f.id, f);
  }
  return [...byId.values()];
}

function isOfficialBrandDomain(registrable, brands) {
  return brands.some((b) => b.domains.includes(registrable));
}

// ---------- Main entry point ----------

export function evaluate({
  hostname = "",
  urlFindings = [],
  pageFindings = [],
  redirectFindings = [],
  hasPasswordField = false,
  whitelist = [],
  sensitivity = "medium",
  extraBrands = [],
}) {
  const registrable = hostname ? splitHostname(hostname).registrable : "";
  const notes = [];

  // 1. User whitelist: skip everything
  if (registrable && whitelist.includes(registrable)) {
    return {
      score: 0,
      verdict: "safe",
      findings: [],
      categories: {},
      notes: [`${registrable} is on your whitelist`],
      trusted: true,
    };
  }

  // 2. Merge and dedupe
  let findings = dedupe([...urlFindings, ...pageFindings, ...redirectFindings]);
  const ids = new Set(findings.map((f) => f.id));

  // 3. Combo bonuses
  const impersonating = IMPERSONATION_IDS.some((id) => ids.has(id));

  if (hasPasswordField && impersonating) {
    findings.push({
      id: "combo-impersonation-login",
      message: "Password page on a domain that imitates a known brand",
      points: 20,
    });
  }

  if (
    ids.has("form-cross-domain") &&
    (ids.has("urgent-language") || ids.has("title-brand-mismatch"))
  ) {
    findings.push({
      id: "combo-pressure-exfil",
      message: "Pressure tactics combined with credentials sent to another site",
      points: 15,
    });
  }

  // 4. Tag each finding with its category and sum per category (with cap)
  findings = findings.map((f) => ({ ...f, category: categoryOf(f.id) }));

  const categories = {};
  for (const f of findings) {
    categories[f.category] = (categories[f.category] || 0) + f.points;
  }
  let total = 0;
  for (const cat of Object.keys(categories)) {
    categories[cat] = Math.min(CATEGORY_CAP, categories[cat]);
    total += categories[cat];
  }

  // 5. Trusted domain adjustment (built-in brands + the user's own brands)
  let trusted = false;
  const allBrands = [...BRANDS, ...extraBrands];
  if (registrable && isOfficialBrandDomain(registrable, allBrands)) {
    trusted = true;
    total = Math.round(total * TRUSTED_FACTOR);
    notes.push(`${registrable} is an official domain, so the score was reduced`);
  }

  const score = Math.min(100, Math.round(total));

  // Biggest contributors first
  findings.sort((a, b) => b.points - a.points);

  return {
    score,
    verdict: verdictFromScore(score, sensitivity),
    findings,
    categories,
    notes,
    trusted,
  };
}