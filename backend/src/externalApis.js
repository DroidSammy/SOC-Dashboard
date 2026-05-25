import axios from 'axios';
import OpenAI from 'openai';
import { cves, threats } from './demoData.js';

function base64Url(value) {
  return Buffer.from(value).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export async function checkVirusTotalUrl(url) {
  const key = process.env.VIRUSTOTAL_API_KEY;
  if (!key) return { enabled: false, verdict: 'not_configured' };

  const id = base64Url(url);
  try {
    const { data } = await axios.get(`https://www.virustotal.com/api/v3/urls/${id}`, {
      headers: { 'x-apikey': key },
      timeout: 12000,
    });
    const stats = data.data?.attributes?.last_analysis_stats || {};
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;

    return {
      enabled: true,
      verdict: malicious > 0 ? 'dangerous' : suspicious > 0 ? 'suspicious' : 'safe',
      malicious,
      suspicious,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      enginesFlagged: malicious + suspicious,
      permalink: `https://www.virustotal.com/gui/url/${id}`,
    };
  } catch (error) {
    if (error.response?.status === 404) {
      return {
        enabled: true,
        verdict: 'unscanned',
        malicious: 0,
        suspicious: 0,
        harmless: 0,
        undetected: 0,
        enginesFlagged: 0,
        permalink: `https://www.virustotal.com/gui/url/${id}`,
      };
    }
    throw error;
  }
}

export async function checkGoogleSafeBrowsing(url) {
  const key = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  if (!key) return { enabled: false, verdict: 'not_configured' };

  const { data } = await axios.post(
    `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${key}`,
    {
      client: {
        clientId: 'soc-dashboard-minor-project',
        clientVersion: '1.0.0',
      },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url }],
      },
    },
    { timeout: 12000 },
  );

  const matches = data.matches || [];
  return {
    enabled: true,
    verdict: matches.length ? 'dangerous' : 'safe',
    matches: matches.map((match) => ({
      threatType: match.threatType,
      platformType: match.platformType,
      cacheDuration: match.cacheDuration,
    })),
  };
}

export async function getAbuseIpThreats(limit = 25) {
  const key = process.env.ABUSEIPDB_API_KEY;
  if (!key) {
    return demoThreats();
  }

  let data;
  try {
    const response = await axios.get('https://api.abuseipdb.com/api/v2/blacklist', {
      params: {
        confidenceMinimum: 75,
        limit,
      },
      headers: {
        Key: key,
        Accept: 'application/json',
      },
      timeout: 12000,
    });
    data = response.data;
  } catch {
    return demoThreats('abuseipdb-error-fallback');
  }

  return (data.data || []).map((item, index) => ({
    id: `abuse-${item.ipAddress}`,
    ip: item.ipAddress,
    country: item.countryCode || 'Unknown',
    city: item.countryCode || 'Unknown',
    type: 'AbuseIPDB malicious IP',
    severity: item.abuseConfidenceScore >= 95 ? 'critical' : 'high',
    abuseConfidenceScore: item.abuseConfidenceScore,
    lastReportedAt: item.lastReportedAt,
    lat: threats[index % threats.length].lat,
    lng: threats[index % threats.length].lng,
    source: 'abuseipdb',
    seenAt: item.lastReportedAt || new Date().toISOString(),
  }));
}

function demoThreats(source = 'demo') {
  return threats.map((threat, index) => ({
    ...threat,
    id: `demo-threat-${index + 1}`,
    abuseConfidenceScore: threat.severity === 'critical' ? 100 : threat.severity === 'high' ? 85 : 45,
    source,
    seenAt: new Date(Date.now() - index * 1000 * 45).toISOString(),
  }));
}

export async function searchNvd(keyword) {
  const params = { keywordSearch: keyword, cvssV3Severity: 'CRITICAL' };
  const headers = {};
  if (process.env.NVD_API_KEY) headers.apiKey = process.env.NVD_API_KEY;

  const { data } = await axios.get('https://services.nvd.nist.gov/rest/json/cves/2.0', {
    params,
    headers,
    timeout: 12000,
  });

  const parsed = (data.vulnerabilities || []).slice(0, 8).map((item) => {
    const cve = item.cve;
    const metric = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || {};
    return {
      id: cve.id,
      score: metric.cvssData?.baseScore || 0,
      product: keyword,
      published: cve.published?.slice(0, 10),
      summary: cve.descriptions?.[0]?.value || 'No description available.',
      source: 'nvd',
    };
  });

  return parsed.length ? parsed : cves;
}

export function combineUrlVerdicts(localResult, virusTotal, safeBrowsing) {
  const dangerous = [virusTotal.verdict, safeBrowsing.verdict].includes('dangerous');
  const suspicious = [virusTotal.verdict, safeBrowsing.verdict, localResult.verdict].includes('suspicious');

  if (dangerous) return 'phishing';
  if (localResult.verdict === 'phishing') return 'phishing';
  if (suspicious) return 'suspicious';
  return localResult.verdict || 'legitimate';
}

export async function explainEmailWithChatGPT(emailText, verdict) {
  const key = process.env.OPENAI_API_KEY;
  if (!key || key.includes("sk-fake")) {
    return explainEmailFallback(emailText, verdict);
  }

  try {
    const openai = new OpenAI({ apiKey: key });
    const response = await openai.chat.completions.create({
      model: 'gpt-3.5-turbo',
      messages: [
        { role: 'system', content: 'You are an expert cybersecurity analyst.' },
        { role: 'user', content: `Analyze the following email which was classified as "${verdict}". Explain in 2-3 concise sentences why it might be ${verdict}, focusing on security indicators like urgency, suspicious links, tone, or requests for sensitive info. Email content: "${emailText}"` }
      ],
      temperature: 0.7,
      max_tokens: 150,
    });
    return response.choices[0]?.message?.content?.trim() || null;
  } catch (error) {
    console.error("OpenAI API Error:", error.message);
    return explainEmailFallback(emailText, verdict);
  }
}

function explainEmailFallback(emailText, verdict) {
  const lower = emailText.toLowerCase();
  if (verdict === 'phishing' || verdict === 'suspicious') {
    if (lower.includes('urgent') || lower.includes('immediately')) {
      return "This email employs artificial urgency, a classic social engineering tactic designed to panic the recipient into acting without thinking.";
    }
    if (lower.includes('password') || lower.includes('verify') || lower.includes('login')) {
      return "The email explicitly requests credential verification or sensitive information. Legitimate organizations will never ask for your password via email.";
    }
    return "This email exhibits multiple traits of a phishing attempt, including suspicious domain routing, potential impersonation, or unexpected attachments.";
  }
  return "This email appears to be legitimate. It lacks common phishing indicators such as suspicious links, malicious attachments, or high-pressure language.";
}

export async function askCyberAdvisorWithChatGPT(question) {
  const key = process.env.OPENAI_API_KEY;
  if (!key || key.includes("sk-fake")) {
    return getChatbotFallback(question);
  }

  try {
    const openai = new OpenAI({ apiKey: key });
    const response = await openai.chat.completions.create({
      model: 'gpt-3.5-turbo',
      messages: [
        { role: 'system', content: 'You are a helpful, professional cybersecurity advisor for students. Keep your answers concise, practical, and easy to understand.' },
        { role: 'user', content: question }
      ],
      temperature: 0.7,
      max_tokens: 300,
    });
    return response.choices[0]?.message?.content?.trim() || "I'm sorry, I couldn't generate a response.";
  } catch (error) {
    console.error("OpenAI API Error:", error.message);
    return getChatbotFallback(question);
  }
}

function getChatbotFallback(question) {
  const lowerQ = question.toLowerCase();
  if (lowerQ.includes("password")) return "A strong password should be at least 12 characters long, include a mix of uppercase, lowercase, numbers, and symbols. I highly recommend using a trusted Password Manager and enabling 2FA on all accounts.";
  if (lowerQ.includes("phishing") || lowerQ.includes("scam")) return "Always check the exact sender's email address. Phishing emails often contain spelling errors, demand urgent action, or ask for passwords/payments. Verify the request through an official, secondary channel before clicking any links.";
  if (lowerQ.includes("usb") || lowerQ.includes("flash drive")) return "Never plug an unknown USB drive into your computer! Attackers often drop 'rogue USBs' in public places. They can be programmed to automatically install malware, execute scripts (like a Rubber Ducky), or steal your session tokens as soon as they are connected.";
  if (lowerQ.includes("vpn") || lowerQ.includes("public wifi")) return "When using public Wi-Fi (like at a cafe or airport), your data can be intercepted by anyone on the network. Using a Virtual Private Network (VPN) creates an encrypted tunnel for your traffic, keeping your browsing secure.";
  if (lowerQ.includes("ransomware")) return "Ransomware is malware that encrypts your files and demands payment to unlock them. The best defense is regular offline backups (3-2-1 backup rule) and never downloading attachments from unverified sources.";
  if (lowerQ.includes("firewall") || lowerQ.includes("port")) return "A firewall monitors and filters incoming and outgoing network traffic based on security rules. By blocking unnecessary ports (like port 22 for SSH or 3389 for RDP), we prevent attackers from gaining unauthorized access to our campus servers.";
  if (lowerQ.includes("social engineering") || lowerQ.includes("vishing")) return "Social engineering is hacking the human, not the computer. Vishing (voice phishing) is when attackers call you pretending to be IT support to trick you into revealing passwords. Real IT will never ask for your password!";
  if (lowerQ.includes("malware") || lowerQ.includes("virus")) return "Malware (malicious software) includes viruses, worms, and trojans designed to damage or disrupt systems. Keep your OS and antivirus updated, and only install software from trusted sources.";
  
  return "That's a great question! For a college environment, always prioritize the Principle of Least Privilege: only give users the access they absolutely need. If you encounter something suspicious, report it to the IT Helpdesk immediately.";
}
