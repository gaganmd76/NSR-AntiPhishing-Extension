import { splitHostname } from "./urlAnalyzer.js";

const SHORTENERS = [
  "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd",
  "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc",
];

const IPV4_REGEX = /^\d{1,3}(\.\d{1,3}){3}$/;

function hostOf(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function domainOf(url) {
  const host = hostOf(url);
  if (!host) return "";
  if (IPV4_REGEX.test(host)) return host;
  return splitHostname(host).registrable;
}

// hops: [{ from, to, type: "server" | "client", status? }]
export function analyzeRedirectChain(hops, finalUrl) {
  const findings = [];
  const add = (id, message, points) => findings.push({ id, message, points });

  if (!hops || hops.length === 0) {
    return { findings, score: 0 };
  }

  // Full list of URLs visited, in order
  const urls = [hops[0].from, ...hops.map((h) => h.to)];
  const domains = new Set(urls.map(domainOf).filter(Boolean));

  // 1. Number of hops
  if (hops.length >= 5) {
    add("redirect-long", `Very long redirect chain (${hops.length} hops)`, 25);
  } else if (hops.length >= 3) {
    add("redirect-many", `Multiple redirects before landing (${hops.length} hops)`, 15);
  }

  // 2. Passing through many unrelated domains
  if (domains.size >= 3) {
    add("redirect-domains", `Redirected through ${domains.size} different domains`, 20);
  }

  // 3. URL shortener at the start leading somewhere else
  const startDomain = domainOf(urls[0]);
  const endDomain = domainOf(finalUrl || urls[urls.length - 1]);
  if (SHORTENERS.includes(startDomain) && startDomain !== endDomain) {
    add("redirect-shortener", `Link started at a URL shortener (${startDomain})`, 10);
  }

  // 4. HTTPS -> HTTP downgrade
  const downgrade = hops.some(
    (h) => h.from.startsWith("https://") && h.to.startsWith("http://")
  );
  if (downgrade) {
    add("redirect-downgrade", "Redirect moved from HTTPS to unencrypted HTTP", 15);
  }

  // 5. Redirected to a raw IP address
  const ipHop = hops.find((h) => IPV4_REGEX.test(hostOf(h.to)));
  if (ipHop) {
    add("redirect-ip", `Redirected to a raw IP address (${hostOf(ipHop.to)})`, 25);
  }

  // 6. Open-redirect pattern: first URL carries another URL in its query string
  try {
    const first = new URL(urls[0]);
    for (const value of first.searchParams.values()) {
      if (/^https?:\/\//i.test(value) && domainOf(value) !== domainOf(urls[0])) {
        add(
          "open-redirect",
          `URL passes another site in its query string (${hostOf(value)})`,
          10
        );
        break;
      }
    }
  } catch {
    // ignore malformed URLs
  }

  const score = Math.min(100, findings.reduce((sum, f) => sum + f.points, 0));
  return { findings, score };
}