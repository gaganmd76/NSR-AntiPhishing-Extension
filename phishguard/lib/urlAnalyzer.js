import { levenshtein } from "./levenshtein.js";
import { BRANDS } from "./brands.js";

// Two-part TLDs, so "bbc.co.uk" is treated as domain "bbc" + TLD "co.uk"
const MULTI_PART_TLDS = [
  "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "co.in", "co.jp",
  "com.br", "com.cn", "co.za", "com.mx", "co.nz", "com.sg",
];

const SUSPICIOUS_TLDS = [
  "zip", "mov", "tk", "ml", "ga", "cf", "gq", "xyz", "top",
  "click", "work", "support", "country", "kim", "loan", "icu",
];

const KEYWORDS = [
  "login", "signin", "verify", "secure", "account", "update",
  "confirm", "banking", "wallet", "password", "suspend", "unlock",
];

const IPV4_REGEX = /^\d{1,3}(\.\d{1,3}){3}$/;

// Free, anonymous tunnel services often used to host throwaway attack pages
const TUNNEL_HOSTS = [
  "trycloudflare.com", "ngrok.io", "ngrok-free.app", "ngrok-free.dev",
  "ngrok.app", "ngrok.dev", "serveo.net", "loca.lt", "localtunnel.me",
  "lhr.life", "localhost.run", "pinggy.link", "pagekite.me",
];

// ---------- Helpers ----------

function parseUrl(input) {
  try {
    return new URL(input);
  } catch {
    try {
      return new URL("https://" + input);
    } catch {
      return null;
    }
  }
}

export function splitHostname(hostname) {
  const labels = hostname.split(".");
  const lastTwo = labels.slice(-2).join(".");
  const tldLength = MULTI_PART_TLDS.includes(lastTwo) ? 2 : 1;

  const tld = labels.slice(-tldLength).join(".");
  const label = labels[labels.length - tldLength - 1] || "";
  const registrable = label ? `${label}.${tld}` : hostname;
  const subdomain = labels.slice(0, labels.length - tldLength - 1).join(".");

  return { tld, label, registrable, subdomain };
}

// Turn "paypa1" -> ["paypal", "paypai"], "g00gle" -> ["google"], etc.
function normalizeVariants(label) {
  const base = label
    .replace(/0/g, "o")
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/5/g, "s")
    .replace(/7/g, "t")
    .replace(/\$/g, "s")
    .replace(/rn/g, "m")
    .replace(/vv/g, "w");

  return [base.replace(/1/g, "l"), base.replace(/1/g, "i")];
}

function isLegitBrandDomain(registrable, brands) {
  return brands.some((b) => b.domains.includes(registrable));
}

export function isLocalHost(hostname) {
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

// ---------- Main analyzer ----------

export function analyzeUrl(input, extraBrands = []) {
  const brands = [...BRANDS, ...extraBrands];
  const url = parseUrl(input.trim());
  if (!url || !["http:", "https:"].includes(url.protocol)) {
    return { supported: false, findings: [], score: 0, verdict: "unsupported" };
  }

  const findings = [];
  const add = (id, message, points) => findings.push({ id, message, points });

  const hostname = url.hostname.toLowerCase();
  const fullUrl = url.href;
  const isIp = IPV4_REGEX.test(hostname) || hostname.startsWith("[");
  const { tld, label, registrable, subdomain } = splitHostname(hostname);
  const isLocal = isLocalHost(hostname);

  // 1. IP address instead of a domain
  if (isIp && !isLocal) {
    add("ip-address", "Site uses a raw IP address instead of a domain name", 35);
  }

  // 2. Credentials embedded in URL (user@host trick)
  if (url.username || url.password || fullUrl.split("?")[0].includes("@")) {
    add("at-symbol", "URL contains '@', which can hide the real destination", 25);
  }

  // 3. Not using HTTPS
  if (url.protocol === "http:" && !isLocal) {
    add("no-https", "Connection is not encrypted (HTTP)", 10);
  }

  // 4. Too many subdomains
  if (!isIp && subdomain && subdomain.split(".").length >= 3) {
    add("many-subdomains", `Unusually many subdomains (${subdomain})`, 15);
  }

  // 5. Very long URL
  if (fullUrl.length > 100) {
    add("long-url", `Very long URL (${fullUrl.length} characters)`, 10);
  }

  // 6. Suspicious TLD
  if (!isIp && SUSPICIOUS_TLDS.includes(tld)) {
    add("bad-tld", `Domain ends in '.${tld}', often abused for phishing`, 15);
  }

  // 7. Phishing keywords inside the hostname
  const hostKeywords = KEYWORDS.filter((k) => hostname.includes(k));
  if (!isIp && hostKeywords.length > 0) {
    add("keywords", `Hostname contains: ${hostKeywords.join(", ")}`, 10);
  }

  // 8. Lots of hyphens in hostname
  if ((hostname.match(/-/g) || []).length >= 3) {
    add("hyphens", "Hostname has many hyphens", 10);
  }

  // 9. Punycode (possible homograph attack, e.g. Cyrillic letters)
  if (hostname.split(".").some((l) => l.startsWith("xn--"))) {
    add("punycode", "Domain uses punycode (xn--), possible lookalike characters", 30);
  }

  // 10. Brand impersonation checks (skip if this IS the real brand)
  if (!isIp && !isLegitBrandDomain(registrable, brands)) {
    for (const brand of brands) {
      const name = brand.name;

      // a) Character substitution: paypa1, g00gle, rnicrosoft
      const variants = normalizeVariants(label);
      if (label !== name && variants.includes(name)) {
        add("lookalike-substitution",
          `'${label}' imitates '${name}' using look-alike characters`, 45);
        break;
      }

      // b) Small edit distance: paypall, gooogle
      if (name.length >= 6) {
        const maxDistance = name.length >= 9 ? 2 : 1;
        const dist = levenshtein(label, name);
        if (dist > 0 && dist <= maxDistance) {
          add("lookalike-distance",
            `'${label}' is ${dist} edit(s) away from '${name}'`, 40);
          break;
        }
      }

      // c) Brand embedded in a different domain: paypal-secure-login.xyz
      if (name.length >= 5 && label.includes(name) && label !== name) {
        add("brand-in-domain",
          `Domain contains brand '${name}' but isn't the official site`, 35);
        break;
      }

      // d) Brand in subdomain: paypal.com.evil.net
      if (name.length >= 5 && subdomain.includes(name)) {
        add("brand-in-subdomain",
          `Brand '${name}' appears in the subdomain, but real domain is '${registrable}'`, 40);
        break;
      }
    }
  }

    // Temporary tunnel hosting
  const tunnel = TUNNEL_HOSTS.find(
    (t) => hostname === t || hostname.endsWith("." + t)
  );
  if (!isIp && tunnel) {
    add(
      "tunnel-host",
      `Hosted on a temporary tunnel service (${tunnel}), rarely used by real businesses`,
      35
    );
  }

  const score = Math.min(100, findings.reduce((sum, f) => sum + f.points, 0));
  let verdict = "safe";
  if (score >= 60) verdict = "dangerous";
  else if (score >= 25) verdict = "suspicious";

  return {
    supported: true,
    hostname,
    registrable,
    findings,
    score,
    verdict,
  };
}