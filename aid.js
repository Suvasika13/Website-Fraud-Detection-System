// Popular domains for typo detection
const POPULAR_DOMAINS = [
  "google.com", "facebook.com", "youtube.com", "amazon.com",
  "twitter.com", "linkedin.com", "apple.com", "github.com",
  "microsoft.com", "paypal.com", "wikipedia.org", "instagram.com"
];

// Suspicious TLDs commonly used by scammers
const SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".biz"];

// Suspicious keywords in URL
const FRAUD_KEYWORDS = [
  "login", "verify", "update", "secure", "bank", "account",
  "paypal", "confirm", "password", "signin", "click", "free",
  "winner", "claim", "urgent"
];

// Levenshtein distance for typo-squatting check
function levenshtein(a, b) {
  if (!a) return b.length;
  if (!b) return a.length;
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i-1][j]+1, dp[i][j-1]+1, dp[i-1][j-1]+cost);
    }
  }
  return dp[m][n];
}

// Extract hostname safely
function getHostname(url) {
  try {
    let tmp = url;
    if (!/^[a-zA-Z]+:\/\//.test(tmp)) tmp = "http://" + tmp;
    return new URL(tmp).hostname.toLowerCase();
  } catch {
    return null;
  }
}

// Analyze URL and return verdict + reasons
function analyzeURL(url) {
  const reasons = [];
  let score = 0;

  if (!/^(ftp|http|https):\/\/[^ "]+$/.test(url) && !/^[^ "]+\.[^ "]+$/.test(url)) {
    reasons.push("Malformed or missing protocol.");
    score += 1;
  }

  const hostname = getHostname(url);
  if (!hostname) {
    reasons.push("Cannot parse hostname.");
    score += 3;
    return { score, verdict: "Fraudulent", reasons };
  }

  // IP address usage
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    reasons.push("Uses raw IP address.");
    score += 5;
  }

  // Long URLs/hostnames
  if (url.length > 100) { reasons.push("Very long URL."); score += 2; }
  if (hostname.length > 50) { reasons.push("Very long hostname."); score += 2; }

  // Multiple subdomains
  if (hostname.split(".").length >= 4) { reasons.push("Multiple subdomains."); score += 2; }

  // Suspicious TLD
  for (const tld of SUSPICIOUS_TLDS) {
    if (hostname.endsWith(tld)) { reasons.push(`Suspicious TLD: ${tld}`); score += 3; break; }
  }

  // Percent encoding or @ symbol
  if (/%[0-9A-Fa-f]{2}/.test(url)) { reasons.push("Contains percent-encoding."); score += 1; }
  if (/@/.test(url)) { reasons.push("Contains '@' symbol."); score += 4; }

  // Hyphens or digits in hostname
  if ((hostname.match(/-/g) || []).length >= 2) { reasons.push("Many hyphens in domain."); score += 1; }
  if ((hostname.match(/\d/g) || []).length >= 3) { reasons.push("Many digits in domain."); score += 1; }

  // Suspicious keywords
  for (const kw of FRAUD_KEYWORDS) {
    if (url.toLowerCase().includes(kw)) { reasons.push(`Contains keyword "${kw}".`); score += 2; }
  }

  // Homograph detection (typosquatting)
  const normalized = hostname.replace(/0/g,"o").replace(/1/g,"l").replace(/3/g,"e").replace(/[^\w.]/g,"");
  for (const pd of POPULAR_DOMAINS) {
    const dist = levenshtein(normalized, pd);
    if (dist / Math.max(normalized.length, pd.length) <= 0.25 && normalized !== pd) {
      reasons.push(`Looks similar to popular site "${pd}" (possible typosquat).`);
      score += 4; break;
    }
  }

  // Path and query checks
  const path = url.split(hostname)[1] || "";
  if (path.length > 80) { reasons.push("Long path or query."); score += 1; }
  if ((path.match(/[?&]/g) || []).length >= 5) { reasons.push("Many query parameters."); score += 1; }

  // Determine verdict
  let verdict = "Safe";
  if (score >= 8) verdict = "Fraudulent";
  else if (score >= 4) verdict = "Suspicious";

  return { score, verdict, reasons };
}

// UI Integration
document.getElementById('urlForm').addEventListener('submit', function(e) {
  e.preventDefault();
  const url = document.getElementById('urlInput').value.trim();
  const resultDiv = document.getElementById('result');
  const resultTextEl = document.getElementById('resultText');

  if (!url) { alert("Please enter a URL."); return; }

  const analysis = analyzeURL(url);

  // Display verdict
  resultTextEl.textContent = analysis.verdict;

  // Color coding
  if (analysis.verdict === "Safe") {
    resultTextEl.style.color = "green";
    resultDiv.style.border = "2px solid #c7f0d1";
    resultDiv.style.background = "#f0fff4";
  } else if (analysis.verdict === "Suspicious") {
    resultTextEl.style.color = "orange";
    resultDiv.style.border = "2px solid #ffe6b3";
    resultDiv.style.background = "#fffaf0";
  } else {
    resultTextEl.style.color = "red";
    resultDiv.style.border = "2px solid #f5c6cb";
    resultDiv.style.background = "#fff2f2";
  }

  // Show reasons in preformatted text
  let details = document.getElementById('resultDetails');
  if (!details) {
    details = document.createElement('pre');
    details.id = 'resultDetails';
    details.style.textAlign = "left";
    details.style.whiteSpace = "pre-wrap";
    details.style.marginTop = "12px";
    details.style.fontSize = "0.95rem";
    details.style.color = "#333";
    document.querySelector('.container').appendChild(details);
  }
  details.textContent = analysis.reasons.length ? analysis.reasons.join("\n") : "No suspicious patterns detected.";

  resultDiv.classList.remove('hidden');
});
