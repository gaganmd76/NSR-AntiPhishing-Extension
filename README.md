# NSR

**Real-time phishing detection in your browser.**

NSR is a browser extension that analyzes web pages as they load and warns you before you fall for a phishing attempt. It checks the address, the page content and the redirect path, then gives each page a **risk score from 0 to 100**. Everything runs locally in your browser: no accounts, no servers, and no URLs or page data ever leave your device.

![Manifest V3](https://img.shields.io/badge/Manifest-V3-blue)
![Chrome](https://img.shields.io/badge/Chrome-supported-green)
![Brave and Edge](https://img.shields.io/badge/Brave%20%7C%20Edge-supported-green)
![Firefox](https://img.shields.io/badge/Firefox-experimental-orange)
![License](https://img.shields.io/badge/license-All%20Rights%20Reserved-red)


<img width="1897" height="1032" alt="Screenshot 2026-10-26 121942" src="https://github.com/user-attachments/assets/1648e741-0a54-489f-85ee-9d59e96694c2" />
<img width="987" height="933" alt="image" src="https://github.com/user-attachments/assets/cbb62e77-5931-42c2-adf5-e53f38b0c3f0" />
<img width="1911" height="1028" alt="Screenshot 2026-10-26 123240" src="https://github.com/user-attachments/assets/31d0c3a7-5f8d-4fbe-97b9-e20334a53f39" />
<img width="1917" height="771" alt="Screenshot 2026-10-26 123513" src="https://github.com/user-attachments/assets/a59fe451-b116-4fc9-a117-ae0d774f6a49" />

---

## Table of contents

- [Features](#features)
- [What it detects](#what-it-detects)
- [Installation](#installation)
- [How to use](#how-to-use)
- [How it works](#how-it-works)
- [Technology used](#technology-used)
- [Project structure](#project-structure)
- [Permissions and privacy](#permissions-and-privacy)
- [Testing safely](#testing-safely)
- [Advantages](#advantages)
- [Disadvantages and limitations](#disadvantages-and-limitations)
- [License and usage rules](#license-and-usage-rules)
- [Contributing](#contributing)
- [Disclaimer](#disclaimer)
- [Roadmap](#roadmap)

---

## Features

- **Risk score (0 to 100)** for every page, with the exact reasons listed
- **Toolbar badge:** no badge = safe, `!` = suspicious, `!!` = dangerous
- **Warning banner** on dangerous pages, built in a Shadow DOM so the page cannot hide or tamper with it
- **Glass-style popup** with the score, category breakdown, findings and redirect chain
- **URL tester:** check any address without visiting it
- **Settings:** sensitivity (low, medium, high), banner on or off, trusted sites, custom brands
- **Late-loading form detection:** pages that add a login form after loading are rescanned for 30 seconds
- **100% local:** no tracking, no external requests

---

## What it detects

| Category | Examples |
|---|---|
| **Lookalike domains** | `paypa1.com`, `paypall.com`, `paypal-secure-login.xyz`, `paypal.com.evil.net`, punycode (`xn--`) homographs |
| **Suspicious URLs** | raw IP addresses, the `@` trick, too many subdomains, risky TLDs, very long URLs, phishing keywords, missing HTTPS |
| **Credential forms** | password forms posting to another domain, a raw IP or plain HTTP; logins handled only by JavaScript; many hidden fields |
| **Page content** | hidden iframes, pressure language ("your account will be suspended"), a title naming a brand that does not match the domain, obfuscated scripts |
| **Redirects** | long chains, hops across many domains, URL shorteners, HTTPS to HTTP downgrades, redirects to raw IPs, open-redirect patterns |

---

## Installation

NSR is not on a browser store yet, so you load it manually (about one minute).

### Chrome, Brave, Edge and other Chromium browsers

1. Download the code:
   ```bash
   git clone (https://github.com/gaganmd76/NSR-AntiPhishing-Extension.git)
   ```
   Or click **Code, then Download ZIP** on GitHub and unzip it.
2. Open the extensions page:
   - Chrome: `chrome://extensions`
   - Brave: `brave://extensions`
   - Edge: `edge://extensions`
3. Turn on **Developer mode** (top right).
4. Click **Load unpacked** and select the folder that contains `manifest.json`.
5. Click the puzzle-piece icon in the toolbar and **pin NSR**.


---

## How to use

1. **Browse normally.** NSR checks each page automatically.
2. **Read the badge:**
   - no badge: nothing suspicious found
   - yellow `!`: suspicious, be careful
   - red `!!`: likely phishing, do not enter any information
3. **Click the NSR icon** to see the score, the category breakdown, every finding and the redirect chain.
4. **On a dangerous page,** a red banner appears:
   - **Leave this page** takes you to a blank page
   - **Details** shows why the page was flagged
   - **I trust this site** adds it to your trusted list (use only if you are sure)
   - **×** hides the banner for this visit
5. **Test a link safely:** type any address into the "Test any URL" box in the popup. Nothing is visited, it only analyzes the text.
6. **Open Settings** (the ⚙️ button in the popup) to:
   - change **sensitivity** (Low = fewer warnings, High = more warnings and more false alarms)
   - turn the **banner** on or off (the badge always stays)
   - manage **trusted sites**
   - add **your own brands** (for example your company or bank) so lookalikes of them get flagged

---

## How it works

1. The **background service worker** (`background.js`) records each tab's redirect chain and keeps its state in `chrome.storage.session`, because Manifest V3 workers can shut down at any time.
2. The **content script** (`content.js`) scans the page's DOM for forms, iframes, text, titles and scripts, then sends its findings to the background worker.
3. The **scoring engine** (`lib/scoring.js`) merges URL, page and redirect findings. It removes duplicates, caps each category, adds bonuses for dangerous combinations, and lowers the score for official brand domains.
4. The score becomes a **verdict** based on your sensitivity setting, the badge is updated, and the banner is shown if the page is dangerous.

| Sensitivity | Suspicious from | Dangerous from |
|---|---|---|
| Low | 35 | 70 |
| Medium (default) | 25 | 60 |
| High | 18 | 45 |

---

## Technology used

| Area | Technology |
|---|---|
| Languages | JavaScript (ES modules), HTML, CSS, JSON |
| Platform | Chrome Extension **Manifest V3** (service worker), Firefox Manifest V3 build |
| Extension APIs | `tabs`, `webNavigation`, `webRequest`, `storage` (session and sync), `action`, `runtime` messaging, options page |
| Web APIs | DOM, `URL`, `MutationObserver`, Shadow DOM, `getComputedStyle` |
| Algorithms | Levenshtein edit distance, character-substitution normalization, weighted heuristic scoring |
| Tooling | VS Code, Chrome DevTools, GitHub Copilot, Python (local test server and build script), Git |

No frameworks, no npm packages, no build step needed to run it.

---

## Project structure

```
manifest.json            Chrome and Chromium manifest (MV3, service worker)
manifest.firefox.json    Firefox manifest (MV3, background scripts)
background.js            Redirect tracking, scoring, toolbar badge
content.js               Page scanner and warning banner
popup.html / .css / .js  Toolbar popup
options.html / .css / .js  Settings page
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

---

## Permissions and privacy

NSR collects **no data** and makes **no network requests**. All analysis happens on your device. Your settings are stored in your browser's own storage (`chrome.storage`).

| Permission | Why it is needed |
|---|---|
| `tabs`, `activeTab` | Read the current tab's address for analysis and for the popup |
| `webNavigation`, `webRequest` | Observe redirects to build the redirect chain (NSR only observes, it never blocks or changes requests) |
| `storage` | Save your settings and the per-tab redirect results |
| Access to `http://*/*` and `https://*/*` | Scan the forms and content of the pages you visit, which is the core feature |

---

## Testing safely

**Never test against real phishing sites.** Use local test pages served from your own computer (for example a fake login page and a redirect chain served with `python redirect_server.py`). The fake forms point to reserved documentation addresses, so nothing real is contacted. Never type real passwords into any test page.

---

## Advantages

- **Private by design:** everything runs locally, nothing is uploaded
- **Explainable:** every warning lists the exact reasons and points behind it
- **Real-time:** checks happen as pages load, before you type anything
- **Catches new sites:** heuristics do not need a database of known bad URLs
- **Multi-signal:** URL, forms, page content and redirects are combined, which reduces false alarms
- **Customizable:** sensitivity, trusted sites and your own brands
- **Tamper-resistant banner:** Shadow DOM stops page CSS and scripts from hiding it
- **Lightweight:** plain JavaScript, no dependencies, no account needed
- **Works across browsers:** Chrome, Brave and Edge directly, Firefox through a separate build

---

## Disadvantages and limitations

- **Heuristics only:** there is no threat-intelligence feed (such as Google Safe Browsing or PhishTank), so a new attack that avoids these patterns can be missed
- **False positives:** legitimate sign-in or payment flows that post to other domains may score as suspicious (use "I trust this site")
- **Small built-in brand list:** you can add your own brands in Settings, but coverage is limited
- **Limited homograph detection:** covers punycode domains, not every Unicode lookalike trick
- **No visual checks:** it does not compare logos or page appearance
- **Manual installation:** not on a browser store yet
- **Firefox support is experimental** and needs more testing
- **No automated tests yet**
- **Not a replacement for care:** a clean result is not a guarantee that a site is safe

---

## License and usage rules

**Copyright © 2026 [Your Name]. All rights reserved.**

This repository is published so that people can **view and learn from** the code. The following rules apply:

1. **No copying, modification or redistribution.** You may not copy, modify, merge, republish, sell, sublicense or distribute this code, in whole or in part, without written permission from the author.
2. **No derivative works.** You may not build products, extensions or services based on this code without permission.
3. **Personal evaluation is allowed.** You may download and run the extension on your own devices to evaluate it.
4. **Attribution.** Any permitted use must credit the original author and link to this repository.
5. **No warranty.** The software is provided "as is", without warranty of any kind. The author is not liable for any damage or loss arising from its use.

To request permission for any other use, contact: **[your-email@example.com]**

---

## Contributing

This is a personal project and the code is **not open for direct editing**.

- Only the repository owner can change the code.
- Bug reports and suggestions are welcome through **GitHub Issues**.
- Pull requests are reviewed by the owner and may be declined. Submitting one does not grant any rights to the code.

---

## Disclaimer

NSR is an educational project and a heuristic tool. It can miss real phishing sites and can flag legitimate ones. Treat its result as one signal among others, and never rely on it as your only protection. The author is not responsible for any loss resulting from its use.

---

## Roadmap

- [ ] Opt-in Safe Browsing or
