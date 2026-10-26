# NSR

A browser extension that detects phishing attempts in real time. It runs
entirely in your browser: no servers, no accounts, and no URLs are ever sent
anywhere.

## What it detects

| Signal | Examples |
|---|---|
| **Lookalike domains** | `paypa1.com`, `paypall.com`, `paypal-secure-login.xyz`, `paypal.com.evil.net`, punycode homographs |
| **Suspicious URLs** | raw IP addresses, `@` tricks, too many subdomains, risky TLDs, very long URLs |
| **Credential forms** | password forms posting to another domain, raw IPs or plain HTTP; JavaScript-only logins |
| **Page content** | hidden iframes, pressure language ("your account will be suspended"), brand names in the title that don't match the domain, obfuscated scripts |
| **Redirects** | long chains, hops across many domains, URL shorteners, HTTPS to HTTP downgrades, open-redirect patterns |

Each signal adds points to a **risk score (0 to 100)**. The score is capped per
category, boosted by dangerous combinations, and reduced for official brand
domains, to cut false positives.

## Features

- Toolbar badge: none = safe, `!` = suspicious, `!!` = dangerous
- Red warning banner on dangerous pages (rendered in a Shadow DOM so the page
  can't tamper with it)
- Glass-style popup with score, category breakdown, findings and redirect chain
- URL tester: check any URL without visiting it
- Settings: sensitivity (low / medium / high), banner toggle, trusted sites,
  custom brands
- Rescans pages that add a login form after loading

## Install (development)

**Chrome**
1. Go to `chrome://extensions` and enable **Developer mode**.
2. Click **Load unpacked** and select this folder.

**Firefox**
1. Run `python build.py`.
2. Go to `about:debugging#/runtime/this-firefox`.
3. Click **Load Temporary Add-on** and pick `dist/firefox/manifest.json`.
4. In `about:addons`, open NSR's Permissions tab and allow site access.

## Project structure

```
manifest.json            Chrome manifest (MV3, service worker)
manifest.firefox.json    Firefox manifest (MV3, background scripts)
background.js            Redirect tracking, scoring, toolbar badge
content.js               Page scanner and warning banner
popup.*                  Toolbar popup
options.*                Settings page
banner.css               Banner styles (loaded inside a Shadow DOM)
icons/                   Extension icons
lib/
  brands.js              Commonly impersonated brands
  levenshtein.js         Edit distance for typo detection
  urlAnalyzer.js         URL and domain heuristics
  redirectAnalyzer.js    Redirect chain heuristics
  scoring.js             Combines all signals into one score
  settings.js            Reads user settings from storage
build.py                 Packages Chrome and Firefox builds
```

## How it works

1. `background.js` records each tab's redirect chain (`webNavigation` +
   `webRequest`) and keeps its state in `chrome.storage.session`, because MV3
   service workers can shut down at any time.
2. `content.js` scans the page's DOM and sends its findings to the background.
3. The background merges URL, redirect and page findings in `lib/scoring.js`,
   updates the badge, and replies with a verdict.
4. If the verdict is dangerous, the content script shows the banner.

## Testing safely

Never test against real phishing sites. Use local test pages served with
`python redirect_server.py`. They use reserved documentation addresses, so
nothing real is contacted.

## Limitations

- Heuristics only. There is no threat-intelligence feed (Google Safe Browsing,
  PhishTank), so brand-new attacks that avoid these patterns can be missed.
- The brand list is small; add your own in Settings.
- Some legitimate sites (single sign-on, payment providers) post forms to
  other domains and may score as suspicious. Use "I trust this site".
- Homograph detection covers punycode domains, not every Unicode trick.

## Ideas for the future

- Safe Browsing / PhishTank lookups (opt-in, with privacy trade-offs)
- Larger brand list loaded from a bundled JSON file
- Logo and visual similarity checks
- Unit tests for the analyzers

## License

MIT