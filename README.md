# 🛡️ PhishGuard — URL Threat Analyser

A beginner-friendly, **client-side phishing URL detector** built with vanilla HTML, CSS, and JavaScript. No frameworks, no back-end, no data ever leaves your browser.

![PhishGuard Screenshot](https://img.shields.io/badge/status-educational%20tool-yellow?style=flat-square) ![HTML](https://img.shields.io/badge/HTML5-E34F26?style=flat-square&logo=html5&logoColor=white) ![CSS](https://img.shields.io/badge/CSS3-1572B6?style=flat-square&logo=css3&logoColor=white) ![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=flat-square&logo=javascript&logoColor=black)

---

## ✨ Features

- 🔍 **Heuristic URL analysis** — checks for IP addresses, URL shorteners, brand impersonation, suspicious subdomains, lookalike domains, and more
- 🎯 **Risk score (0–100)** with animated SVG ring, verdict badge, and gradient meter bar
- 🎭 **Brand impersonation detection** — catches both apex-domain fakes (`paypal-secure.net`) and subdomain spoofing (`paypal.com.evil.net`)
- 📋 **Threat indicator cards** with severity levels (High / Medium / Low) and plain-language explanations
- 🕓 **Scan history** stored in `localStorage` — click any past entry to re-scan it
- 📊 **Summary stats** — total scans, high-risk detections, and clean-pattern results derived from real local data
- ✅ **False-positive reduction** — trusted domains (Instagram, GitHub, Google, etc.) are exempt from keyword-only scoring
- 🔒 **Privacy-first** — URLs are **never visited, fetched, or sent anywhere**
- 📱 **Fully responsive** — works on desktop, tablet, and mobile

---

## 🖥️ Demo

> Open `index.html` directly in any modern browser — no install required.

**Try these example URLs to see the tool in action:**

| URL | Expected result |
|-----|----------------|
| `https://www.instagram.com/accounts/login/?hl=en` | ✅ Low Risk |
| `https://github.com/login` | ✅ Low Risk |
| `https://secure-paypal-login-verify.com/account` | 🔴 High Risk |
| `https://paypal.com.evil-phish.net/login` | 🔴 High Risk |
| `http://192.168.1.1/login` | 🔴 High Risk |
| `https://bit.ly/3xYzAbc` | 🟡 Moderate Risk |

---

## 🚀 Getting Started

### Option A — Double-click (simplest)

1. Clone or download this repository
2. Open `index.html` in your browser

```bash
git clone https://github.com/YOUR_USERNAME/phishguard.git
cd phishguard
# Then open index.html in your browser
```

### Option B — Local dev server (recommended)

**With Node.js:**
```bash
npx serve .
# Open http://localhost:3000
```

**With Python:**
```bash
python -m http.server 8080
# Open http://localhost:8080
```

**With VS Code:**
Install the [Live Server](https://marketplace.visualstudio.com/items?itemName=ritwickdey.LiveServer) extension → right-click `index.html` → **Open with Live Server**

---

## 📁 Project Structure

```
phishguard/
├── index.html   # Markup — header, scanner, result panel, history, footer
├── style.css    # Dark navy theme, cyan accents, animations, responsive layout
└── script.js    # Detection engine, localStorage history, DOM rendering
```

No dependencies. No build step. No `node_modules`.

---

## 🔬 How Detection Works

The analyser runs a series of heuristic checks against the URL structure. **No network requests are made.**

| Check | Weight | Severity |
|-------|--------|----------|
| IP address as host | +35 | 🔴 High |
| Known URL shortener | +30 | 🔴 High |
| `@` symbol redirect trick | +25 | 🔴 High |
| Brand name in apex domain (lookalike) | +28 | 🔴 High |
| Brand name used as subdomain (spoofing) | +28 | 🔴 High |
| Excessive subdomain depth (4+ parts) | +20 | 🟡 Medium |
| Non-standard port | +15 | 🟡 Medium |
| HTTP (no encryption) | +12 | 🟡 Medium |
| URL length > 75 characters | +8 | 🟢 Low |
| 3+ hyphens in hostname | +8 | 🟢 Low |
| High numeric ratio in domain | +7 | 🟢 Low |
| Percent-encoded chars in hostname | +7 | 🟢 Low |
| Sensitive keywords in path | +6 (flat) | 🟢 Low |

**Risk thresholds:**
- 🟢 **Low** — 0–17 pts
- 🟡 **Medium** — 18–39 pts
- 🔴 **High** — 40+ pts

### False-positive reduction

Common path keywords (`login`, `account`, `verify`) are **skipped** for a set of 20 well-known trusted domains (Instagram, GitHub, Google, PayPal, etc.) to prevent false positives on legitimate login pages.

---

## ⚠️ Disclaimer

**PhishGuard is a heuristic-based educational tool.**

- It uses pattern-matching only and **cannot definitively identify** phishing URLs.
- A low score does **not** guarantee a URL is safe.
- URLs are **never visited, fetched, or contacted**.
- This is not a substitute for professional security tooling.

Always verify suspicious links through a trusted service such as [Google Safe Browsing](https://transparencyreport.google.com/safe-browsing/search) or [VirusTotal](https://www.virustotal.com).

---

## 🛠️ Tech Stack

- **HTML5** — semantic markup, SVG icons, `aria-label` accessibility attributes
- **CSS3** — custom properties, CSS Grid, Flexbox, `backdrop-filter`, `stroke-dashoffset` animation, `@keyframes`
- **Vanilla JavaScript (ES6+)** — `URL` API for parsing, `localStorage` for history, `requestAnimationFrame` for smooth animations

---

## 📜 License

[MIT](LICENSE) — free to use, modify, and distribute.

---

> Built as a beginner cybersecurity project to demonstrate client-side URL heuristics. Contributions and feedback welcome!
