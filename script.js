/**
 * PhishGuard — script.js
 *
 * Heuristic URL threat analyser.
 * No network requests are made. URLs are never visited or contacted.
 */

// ─────────────────────────────────────────────────────────────────────────────
// Detection data
// ─────────────────────────────────────────────────────────────────────────────

const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
  'buff.ly', 'adf.ly', 'shorte.st', 'tiny.cc', 'rebrand.ly', 'cutt.ly',
  'shorturl.at', 'qlink.me', 'tr.im', 'su.pr', 'lnkd.in', 'dlvr.it',
  'mcaf.ee', 'soo.gd', 'x.co', 'prettylinkpro.com', 'shorten.ws',
]);

// Keyword check is skipped for these apex domains to avoid false positives
// on well-known services that legitimately use words like "login" in their paths.
// Inclusion here does NOT declare a URL safe — all structural checks still run.
const TRUSTED_DOMAINS = new Set([
  'instagram.com', 'facebook.com', 'twitter.com', 'x.com',
  'google.com', 'youtube.com', 'gmail.com', 'microsoft.com',
  'apple.com', 'icloud.com', 'amazon.com', 'paypal.com',
  'github.com', 'linkedin.com', 'reddit.com', 'wikipedia.org',
  'netflix.com', 'spotify.com', 'dropbox.com', 'zoom.us',
]);

// Checked against the APEX DOMAIN only — never the path.
// Only fires when the apex domain is NOT in TRUSTED_DOMAINS.
const BRAND_NAMES = [
  'paypal', 'apple', 'amazon', 'microsoft', 'google', 'instagram',
  'facebook', 'netflix', 'spotify', 'dropbox', 'linkedin', 'twitter',
  'github', 'youtube', 'gmail', 'icloud', 'reddit', 'wikipedia',
  'chase', 'wellsfargo', 'citibank', 'bankofamerica', 'hsbc', 'barclays',
];

// Weak path-level signals — brand names removed (they belong in domain checks).
const SUSPICIOUS_KEYWORDS = [
  'login', 'log-in', 'signin', 'sign-in', 'verify', 'verification',
  'account', 'update', 'confirm', 'secure', 'security', 'password',
  'support', 'helpdesk', 'suspended', 'validate', 'unlock', 'restore',
  'billing', 'invoice', 'wallet', 'credential',
];

const WEIGHTS = {
  ipAddress:         35,   // strong structural signal
  urlShortener:      30,   // hides true destination
  multipleAtSymbol:  25,   // @ redirect trick
  lookalikeDomain:   28,   // brand in apex domain that isn't the real brand
  manySubdomains:    20,   // structural deception
  portInUrl:         15,   // unusual for real services
  noHttps:           12,   // moderate — TLS alone doesn't make a site safe
  suspiciousKeyword:  6,   // weak alone; capped flat; skipped for trusted domains
  longUrl:            8,
  excessiveHyphens:   8,
  numericDomain:      7,
  encodedChars:       7,
};

// ─────────────────────────────────────────────────────────────────────────────
// Scoring helpers
// ─────────────────────────────────────────────────────────────────────────────

function getApexDomain(hostname) {
  const parts = hostname.split('.');
  return parts.length >= 2 ? parts.slice(-2).join('.') : hostname;
}

function clamp(n, min, max) { return Math.max(min, Math.min(max, n)); }

function scoreToRisk(score) {
  if (score >= 40) return 'high';
  if (score >= 18) return 'medium';
  return 'low';
}

// ─────────────────────────────────────────────────────────────────────────────
// Core analysis engine
// ─────────────────────────────────────────────────────────────────────────────

function analyseURL(raw) {
  const findings = [];
  let score = 0;

  // Parse
  let parsed;
  try {
    const toParse = /^https?:\/\//i.test(raw) ? raw : 'http://' + raw;
    parsed = new URL(toParse);
  } catch {
    return null; // invalid URL
  }

  const hostname    = parsed.hostname.toLowerCase();
  const fullUrl     = parsed.href;
  const path        = parsed.pathname + parsed.search;
  const apexDomain  = getApexDomain(hostname);
  const isTrusted   = TRUSTED_DOMAINS.has(apexDomain);

  // ── Check: IP address ────────────────────────────────────────────────────
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    score += WEIGHTS.ipAddress;
    findings.push({
      severity: 'high', icon: '🔴',
      title: 'IP address used instead of a domain name',
      desc: `The host is <strong>${hostname}</strong>. Legitimate services almost always use a named domain, not a raw IP address.`,
    });
  }

  // ── Check: URL shortener ─────────────────────────────────────────────────
  if (URL_SHORTENERS.has(hostname) || URL_SHORTENERS.has(apexDomain)) {
    score += WEIGHTS.urlShortener;
    findings.push({
      severity: 'high', icon: '🔗',
      title: 'URL shortener service detected',
      desc: `<strong>${hostname}</strong> is a known URL shortener. Short links mask the real destination and are commonly used in phishing campaigns.`,
    });
  }

  // ── Check: @ redirect trick ──────────────────────────────────────────────
  if ((raw.match(/@/g) || []).length > 0) {
    score += WEIGHTS.multipleAtSymbol;
    findings.push({
      severity: 'high', icon: '🚨',
      title: 'At-symbol (@) in URL',
      desc: 'Browsers treat everything before <strong>@</strong> as credentials and redirect to the address after it — a classic phishing technique.',
    });
  }

  // ── Check: lookalike apex domain ─────────────────────────────────────────
  if (!isTrusted) {
    const matchedBrand = BRAND_NAMES.find(b => apexDomain.includes(b));
    if (matchedBrand) {
      score += WEIGHTS.lookalikeDomain;
      findings.push({
        severity: 'high', icon: '🎭',
        title: `Brand impersonation — apex domain: "${matchedBrand}"`,
        desc: `The registered domain <strong>${apexDomain}</strong> contains the brand name <em>${matchedBrand}</em> but is not that brand's real domain. This is a hallmark of phishing sites.`,
      });
    }
  }

  // ── Check: brand spoofed as subdomain ────────────────────────────────────
  const subdomainPart = hostname.endsWith('.' + apexDomain)
    ? hostname.slice(0, -(apexDomain.length + 1))
    : '';
  if (!isTrusted && subdomainPart) {
    const spoofedBrand = BRAND_NAMES.find(b => subdomainPart.includes(b));
    if (spoofedBrand) {
      score += WEIGHTS.lookalikeDomain;
      findings.push({
        severity: 'high', icon: '🎭',
        title: `Trusted brand used as subdomain: "${spoofedBrand}"`,
        desc: `<strong>${spoofedBrand}</strong> appears in the subdomain of <em>${apexDomain}</em>, designed to fool a quick visual scan into thinking this is the real brand.`,
      });
    }
  }

  // ── Check: excessive subdomains ─────────────────────────────────────────
  const parts = hostname.replace(/^www\./, '').split('.');
  if (parts.length >= 4) {
    score += WEIGHTS.manySubdomains;
    findings.push({
      severity: 'medium', icon: '🌐',
      title: 'Excessive subdomain depth',
      desc: `The hostname has <strong>${parts.length}</strong> domain parts. Attackers stack subdomains to hide the real apex domain at the end.`,
    });
  }

  // ── Check: non-HTTPS ────────────────────────────────────────────────────
  if (parsed.protocol !== 'https:') {
    score += WEIGHTS.noHttps;
    findings.push({
      severity: 'medium', icon: '🔓',
      title: 'Connection not encrypted (HTTP)',
      desc: 'The URL uses <strong>HTTP</strong>. Data transmitted to this address is not encrypted. Note: HTTPS alone does not make a site trustworthy.',
    });
  }

  // ── Check: suspicious path keywords (skipped for trusted domains) ────────
  const lowerPath = path.toLowerCase();
  if (!isTrusted) {
    const matched = SUSPICIOUS_KEYWORDS.filter(k => lowerPath.includes(k));
    if (matched.length > 0) {
      score += WEIGHTS.suspiciousKeyword; // flat cap — no stacking
      findings.push({
        severity: 'low', icon: '🔍',
        title: 'Sensitive keywords in URL path',
        desc: `Detected: <strong>${matched.slice(0, 5).join(', ')}</strong>. These words appear frequently in phishing pages but are a weak signal on their own.`,
      });
    }
  }

  // ── Check: non-standard port ─────────────────────────────────────────────
  if (parsed.port && parsed.port !== '80' && parsed.port !== '443') {
    score += WEIGHTS.portInUrl;
    findings.push({
      severity: 'medium', icon: '🔧',
      title: `Non-standard port: ${parsed.port}`,
      desc: 'Legitimate public-facing web services rarely use custom ports. This may indicate a rogue or non-standard server.',
    });
  }

  // ── Check: long URL ─────────────────────────────────────────────────────
  if (fullUrl.length > 75) {
    score += WEIGHTS.longUrl;
    findings.push({
      severity: 'low', icon: '📏',
      title: `URL is unusually long (${fullUrl.length} characters)`,
      desc: 'Very long URLs can bury the real domain in a sea of parameters, making it hard to spot the actual destination.',
    });
  }

  // ── Check: excessive hyphens ────────────────────────────────────────────
  const hyphenCount = (hostname.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    score += WEIGHTS.excessiveHyphens;
    findings.push({
      severity: 'low', icon: '➖',
      title: `Many hyphens in hostname (${hyphenCount})`,
      desc: 'Multiple hyphens are used to mimic real brand names, e.g. <em>secure-login-paypal-verify.com</em>.',
    });
  }

  // ── Check: numeric domain ────────────────────────────────────────────────
  const digits  = (apexDomain.match(/\d/g) || []).length;
  const letters = (apexDomain.match(/[a-z]/g) || []).length;
  if (digits > 0 && letters > 0 && digits / (digits + letters) > 0.4) {
    score += WEIGHTS.numericDomain;
    findings.push({
      severity: 'low', icon: '🔢',
      title: 'Domain contains a high proportion of numbers',
      desc: `<strong>${apexDomain}</strong> — real brand domains rarely rely heavily on digits in their name.`,
    });
  }

  // ── Check: percent-encoded chars in hostname ─────────────────────────────
  if (/%[0-9a-f]{2}/i.test(hostname)) {
    score += WEIGHTS.encodedChars;
    findings.push({
      severity: 'low', icon: '🔤',
      title: 'Percent-encoded characters in hostname',
      desc: 'Encoded characters in a hostname can obscure the real address or bypass naive security filters.',
    });
  }

  return {
    raw,
    score: clamp(score, 0, 100),
    risk:  scoreToRisk(clamp(score, 0, 100)),
    findings,
    ts:    Date.now(),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// localStorage history & stats
// ─────────────────────────────────────────────────────────────────────────────

const HISTORY_KEY = 'phishguard_history';
const MAX_HISTORY = 20;

function loadHistory() {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY)) || []; }
  catch { return []; }
}

function saveToHistory(result) {
  const history = loadHistory();
  // Deduplicate by exact URL — keep only latest
  const filtered = history.filter(h => h.raw !== result.raw);
  filtered.unshift(result);
  localStorage.setItem(HISTORY_KEY, JSON.stringify(filtered.slice(0, MAX_HISTORY)));
}

function clearHistory() {
  localStorage.removeItem(HISTORY_KEY);
  renderHistory();
  renderStats();
}

// ─────────────────────────────────────────────────────────────────────────────
// Render: stats cards
// ─────────────────────────────────────────────────────────────────────────────

function renderStats() {
  const history = loadHistory();
  document.getElementById('statTotal').textContent = history.length;
  document.getElementById('statHigh').textContent  = history.filter(h => h.risk === 'high').length;
  document.getElementById('statClean').textContent = history.filter(h => h.risk === 'low').length;
}

// ─────────────────────────────────────────────────────────────────────────────
// Render: history list
// ─────────────────────────────────────────────────────────────────────────────

function formatTime(ts) {
  const diff = Date.now() - ts;
  const m = Math.floor(diff / 60000);
  if (m < 1)  return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function renderHistory() {
  const history = loadHistory();
  const listEl  = document.getElementById('historyList');
  const emptyEl = document.getElementById('historyEmpty');

  if (history.length === 0) {
    listEl.innerHTML  = '';
    emptyEl.style.display = 'flex';
    return;
  }

  emptyEl.style.display = 'none';
  listEl.innerHTML = `<div class="history-list-items">${
    history.map(h => `
      <div class="history-item" onclick="loadFromHistory(${JSON.stringify(h.raw).replace(/"/g, '&quot;')})">
        <span class="history-risk-dot dot-${h.risk}"></span>
        <span class="history-url">${escHtml(h.raw)}</span>
        <span class="history-meta">
          <span class="history-score score-${h.risk}">${h.score}</span>
          <span class="history-time">${formatTime(h.ts)}</span>
        </span>
      </div>
    `).join('')
  }</div>`;
}

function loadFromHistory(url) {
  document.getElementById('urlInput').value = url;
  showClearBtn(true);
  scanURL();
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// ─────────────────────────────────────────────────────────────────────────────
// Render: result panel
// ─────────────────────────────────────────────────────────────────────────────

function renderResult(result) {
  const { raw, score, risk, findings } = result;
  const panel = document.getElementById('resultPanel');

  // Show panel
  panel.style.display = 'block';

  // ── Score ring (SVG arc) ─────────────────────────────────────────────────
  const circumference = 2 * Math.PI * 42; // r=42 → ≈ 263.9
  const offset = circumference - (score / 100) * circumference;
  const arcEl = document.getElementById('scoreArc');
  // Set colour based on risk
  const arcColor = { low: '#34d399', medium: '#fbbf24', high: '#f87171' }[risk];
  arcEl.style.stroke = arcColor;
  arcEl.style.strokeDashoffset = circumference; // reset then animate
  document.getElementById('scoreNumber').textContent = score;

  // Trigger CSS transition after a tick
  requestAnimationFrame(() => {
    requestAnimationFrame(() => { arcEl.style.strokeDashoffset = offset; });
  });

  // ── Verdict ──────────────────────────────────────────────────────────────
  const verdictData = {
    low:    { badge: 'Low Risk',      title: 'No major threats detected',        desc: 'The URL passed all significant structural checks. No red flags were found. Remain cautious — always verify the source independently.' },
    medium: { badge: 'Moderate Risk', title: 'Some suspicious patterns found',   desc: 'One or more indicators of concern were detected. Treat this link with caution before proceeding.' },
    high:   { badge: 'High Risk',     title: 'Multiple threat indicators found', desc: 'This URL exhibits strong phishing signals. It is strongly advisable to avoid this link.' },
  };

  const vd = verdictData[risk];
  const badgeEl = document.getElementById('verdictBadge');
  badgeEl.textContent  = vd.badge;
  badgeEl.className    = `verdict-badge badge-${risk}`;
  document.getElementById('verdictTitle').textContent = vd.title;
  document.getElementById('verdictDesc').textContent  = vd.desc;

  // ── Risk meter ────────────────────────────────────────────────────────────
  const meterFill = document.getElementById('riskMeterFill');
  meterFill.style.width = '0%';
  meterFill.className = `risk-meter__fill fill-${risk}`;
  requestAnimationFrame(() => {
    requestAnimationFrame(() => { meterFill.style.width = score + '%'; });
  });

  // ── Scanned URL (plain text — never a link) ───────────────────────────────
  document.getElementById('scannedUrl').textContent = raw;

  // ── Indicators / clean state ─────────────────────────────────────────────
  const indicatorsSection = document.getElementById('indicatorsSection');
  const indicatorsList    = document.getElementById('indicatorsList');
  const cleanResult       = document.getElementById('cleanResult');

  if (findings.length === 0) {
    indicatorsSection.style.display = 'none';
    cleanResult.style.display = 'flex';
  } else {
    cleanResult.style.display = 'none';
    indicatorsSection.style.display = 'block';
    indicatorsList.innerHTML = findings.map(f => `
      <div class="indicator-item sev-${f.severity}">
        <span class="indicator-icon">${f.icon}</span>
        <div class="indicator-body">
          <div class="indicator-name">${escHtml(f.title)}</div>
          <div class="indicator-desc">${f.desc}</div>
        </div>
        <span class="indicator-pill pill-${f.severity}">${f.severity}</span>
      </div>
    `).join('');
  }

  // Smooth scroll into view
  panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ─────────────────────────────────────────────────────────────────────────────
// Main scan entry point
// ─────────────────────────────────────────────────────────────────────────────

function scanURL() {
  const raw   = document.getElementById('urlInput').value.trim();
  const errEl = document.getElementById('inputError');
  const input = document.getElementById('urlInput');

  // Clear previous error state
  input.classList.remove('error');
  errEl.style.display = 'none';

  if (!raw) {
    input.classList.add('error');
    showError('Please enter a URL before scanning.');
    input.focus();
    return;
  }

  // Basic format validation — must look URL-like
  if (!/^https?:\/\//i.test(raw) && !/^[\w-]+(\.[\w-]+)+/.test(raw)) {
    input.classList.add('error');
    showError('That doesn\'t look like a valid URL. Try including https://');
    return;
  }

  // Animated scanning state
  setScanningState(true);

  // Small async delay so the UI update is visible before the sync work runs
  setTimeout(() => {
    const result = analyseURL(raw);

    setScanningState(false);

    if (!result) {
      input.classList.add('error');
      showError('Could not parse that URL. Please include the full address, e.g. https://example.com');
      return;
    }

    saveToHistory(result);
    renderResult(result);
    renderHistory();
    renderStats();
  }, 480);
}

function setScanningState(scanning) {
  const btn     = document.getElementById('scanBtn');
  const idleEl  = btn.querySelector('.scan-btn__idle');
  const loadEl  = btn.querySelector('.scan-btn__loading');
  btn.disabled         = scanning;
  idleEl.style.display = scanning ? 'none' : 'flex';
  loadEl.style.display = scanning ? 'flex' : 'none';
}

function showError(msg) {
  const errEl = document.getElementById('inputError');
  errEl.textContent    = '⚠ ' + msg;
  errEl.style.display  = 'flex';
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility
// ─────────────────────────────────────────────────────────────────────────────

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function showClearBtn(show) {
  document.getElementById('clearInputBtn').style.display = show ? 'flex' : 'none';
}

// ─────────────────────────────────────────────────────────────────────────────
// Init
// ─────────────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  const input    = document.getElementById('urlInput');
  const clearBtn = document.getElementById('clearInputBtn');

  // Enter key
  input.addEventListener('keydown', e => { if (e.key === 'Enter') scanURL(); });

  // Clear error on typing
  input.addEventListener('input', () => {
    input.classList.remove('error');
    document.getElementById('inputError').style.display = 'none';
    showClearBtn(input.value.length > 0);
  });

  // Clear button
  clearBtn.addEventListener('click', () => {
    input.value = '';
    input.classList.remove('error');
    document.getElementById('inputError').style.display = 'none';
    showClearBtn(false);
    input.focus();
  });

  // Load persisted data
  renderHistory();
  renderStats();
});
