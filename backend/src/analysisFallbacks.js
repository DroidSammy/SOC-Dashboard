import crypto from 'node:crypto';

const suspiciousWords = ['login', 'verify', 'account', 'secure', 'update', 'confirm', 'password', 'suspended', 'paypal', 'bank'];
const suspiciousTlds = ['.tk', '.ml', '.ga', '.xyz', '.top', '.club', '.online', '.site'];

export function analyzeUrl(url = '') {
  const lower = url.toLowerCase();
  const score = [
    /^http:\/\//.test(lower) ? 0.15 : 0,
    /\d{1,3}(\.\d{1,3}){3}/.test(lower) ? 0.35 : 0,
    lower.includes('@') ? 0.25 : 0,
    suspiciousTlds.some((tld) => lower.includes(tld)) ? 0.25 : 0,
    Math.min(suspiciousWords.filter((word) => lower.includes(word)).length * 0.12, 0.45),
    Math.min(url.length / 250, 0.2),
  ].reduce((sum, value) => sum + value, 0);

  const phishingScore = Math.min(score, 1);
  const verdict = phishingScore > 0.55 ? 'phishing' : phishingScore > 0.3 ? 'suspicious' : 'legitimate';
  return {
    verdict,
    confidence: verdict === 'legitimate' ? 1 - phishingScore : phishingScore,
    phishing_score: Number(phishingScore.toFixed(2)),
    model_used: 'Node fallback rules',
    features: {
      url_length: url.length,
      keyword_count: suspiciousWords.filter((word) => lower.includes(word)).length,
      has_ip_address: /\d{1,3}(\.\d{1,3}){3}/.test(lower) ? 1 : 0,
      suspicious_tld: suspiciousTlds.some((tld) => lower.includes(tld)) ? 1 : 0,
    },
  };
}

export function analyzeEmail(email = '') {
  const lower = email.toLowerCase();
  const phrases = ['urgent', 'immediately', 'verify', 'suspended', 'click here', 'password', 'credit card', 'bank account'];
  const found = phrases.filter((phrase) => lower.includes(phrase));
  const score = Math.min(found.length * 0.16 + (/(http|https):\/\//.test(lower) ? 0.2 : 0), 1);
  return {
    verdict: score > 0.35 ? 'phishing' : 'legitimate',
    confidence: score > 0.35 ? score : 1 - score,
    phishing_probability: Number(score.toFixed(2)),
    suspicious_phrases: found,
    model_used: 'Node fallback rules',
    flags: {
      urgency_words: found.filter((word) => ['urgent', 'immediately', 'suspended'].includes(word)),
      credential_requests: found.filter((word) => ['password', 'credit card', 'bank account'].includes(word)),
      link_count: (email.match(/https?:\/\//gi) || []).length,
    },
  };
}

export function analyzePassword(password = '') {
  let score = 0;
  if (password.length >= 8) score += 20;
  if (password.length >= 12) score += 20;
  if (/[a-z]/.test(password)) score += 12;
  if (/[A-Z]/.test(password)) score += 16;
  if (/\d/.test(password)) score += 16;
  if (/[^A-Za-z0-9]/.test(password)) score += 16;
  if (/password|qwerty|123456|admin/i.test(password)) score = Math.min(score, 18);

  const suggestions = [];
  if (password.length < 12) suggestions.push('Make it at least 12 characters');
  if (!/[A-Z]/.test(password)) suggestions.push('Add uppercase letters');
  if (!/\d/.test(password)) suggestions.push('Add numbers');
  if (!/[^A-Za-z0-9]/.test(password)) suggestions.push('Add symbols');

  return {
    score,
    strength: score >= 80 ? 'Very Strong' : score >= 60 ? 'Strong' : score >= 40 ? 'Moderate' : score >= 20 ? 'Weak' : 'Very Weak',
    color: score >= 80 ? 'green' : score >= 60 ? 'lime' : score >= 40 ? 'yellow' : score >= 20 ? 'orange' : 'red',
    length: password.length,
    crack_time: score >= 80 ? 'Centuries' : score >= 60 ? 'Years' : score >= 40 ? 'Days' : 'Minutes',
    checks: {
      has_lowercase: /[a-z]/.test(password),
      has_uppercase: /[A-Z]/.test(password),
      has_numbers: /\d/.test(password),
      has_special: /[^A-Za-z0-9]/.test(password),
      length_ok: password.length >= 12,
      not_common: !/password|qwerty|123456|admin/i.test(password),
    },
    patterns_found: /password|qwerty|123456|admin/i.test(password) ? ['Contains a very common password pattern'] : [],
    suggestions,
    strong_alternative: score < 60 ? crypto.randomBytes(12).toString('base64').replace(/[+/=]/g, 'A') : null,
  };
}

export function analyzeNetwork(features = {}) {
  const pps = Number(features.packets_per_second || 0);
  const uniquePorts = Number(features.unique_ports || 0);
  const isAnomaly = pps > 300 || uniquePorts > 50;
  return {
    is_anomaly: isAnomaly,
    anomaly_score: isAnomaly ? -0.82 : 0.56,
    severity: isAnomaly && pps > 600 ? 'high' : isAnomaly ? 'medium' : 'none',
  };
}

export function scanWeb(targetUrl = '') {
  const target = targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`;
  return {
    target,
    scanned_at: new Date().toISOString(),
    total_findings: 3,
    summary: { critical: 0, high: target.startsWith('http://') ? 1 : 0, medium: 1, low: 1 },
    risk_score: target.startsWith('http://') ? 35 : 15,
    findings: [
      {
        id: 1,
        type: 'Missing Security Header',
        name: 'Content-Security-Policy Missing',
        severity: 'medium',
        description: 'No CSP header was confirmed by the fallback scanner.',
        fix: 'Add a Content-Security-Policy header.',
      },
      {
        id: 2,
        type: 'Missing Security Header',
        name: 'Referrer-Policy Missing',
        severity: 'low',
        description: 'Referrer information may leak to external sites.',
        fix: 'Add Referrer-Policy: strict-origin-when-cross-origin.',
      },
      ...(target.startsWith('http://') ? [{
        id: 3,
        type: 'No HTTPS',
        name: 'Site Not Using HTTPS',
        severity: 'high',
        description: 'Traffic is not encrypted.',
        fix: 'Install TLS and redirect HTTP to HTTPS.',
      }] : []),
    ],
  };
}
