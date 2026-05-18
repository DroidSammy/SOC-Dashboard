import 'dotenv/config';
import http from 'node:http';
import axios from 'axios';
import bcrypt from 'bcryptjs';
import cors from 'cors';
import express from 'express';
import jwt from 'jsonwebtoken';
import morgan from 'morgan';
import PDFDocument from 'pdfkit';
import { Server } from 'socket.io';
import { cves, hourlyActivity, weeklyThreats } from './demoData.js';
import {
  checkGoogleSafeBrowsing,
  checkVirusTotalUrl,
  combineUrlVerdicts,
  getAbuseIpThreats,
  searchNvd,
  explainEmailWithChatGPT,
} from './externalApis.js';
import {
  analyzeEmail,
  analyzeNetwork,
  analyzePassword,
  analyzeUrl,
  scanWeb,
} from './analysisFallbacks.js';
import {
  addActivity,
  createIncident,
  ensureStore,
  nextIncidentId,
  readDb,
  storageMode,
  updateIncident,
} from './store.js';

const app = express();
const server = http.createServer(app);
const port = Number(process.env.PORT || 4000);
const mlServiceUrl = process.env.ML_SERVICE_URL || 'http://localhost:5001';
const frontendOrigin = process.env.FRONTEND_ORIGIN || 'http://localhost:5173';
const jwtSecret = process.env.JWT_SECRET || 'soc-dashboard-demo-secret';

const io = new Server(server, {
  cors: {
    origin: [frontendOrigin, 'http://127.0.0.1:5173', 'http://localhost:5173'],
    methods: ['GET', 'POST', 'PATCH'],
  },
});

app.use(cors({
  origin: [frontendOrigin, 'http://127.0.0.1:5173', 'http://localhost:5173'],
}));
app.use(express.json({ limit: '1mb' }));
app.use(morgan('dev'));

function publicUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
  };
}

function signToken(user) {
  return jwt.sign(publicUser(user), jwtSecret, { expiresIn: '8h' });
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) {
    res.status(401).json({ error: 'Missing auth token' });
    return;
  }

  try {
    req.user = jwt.verify(token, jwtSecret);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired auth token' });
  }
}

function emitActivity(entry) {
  io.emit('activity:new', entry);
}

async function logActivity(text, severity = 'low') {
  const entry = await addActivity(text, severity);
  emitActivity(entry);
  return entry;
}

async function proxyToMl(path, payload, fallback) {
  try {
    const { data } = await axios.post(`${mlServiceUrl}${path}`, payload, { timeout: 12000 });
    return { data, source: 'ml-service' };
  } catch {
    return { data: fallback(), source: 'node-fallback' };
  }
}

app.get('/health', async (_req, res) => {
  let ml = { status: 'offline' };
  try {
    const { data } = await axios.get(`${mlServiceUrl}/health`, { timeout: 2000 });
    ml = data;
  } catch {
    ml = { status: 'offline', url: mlServiceUrl };
  }

  res.json({
    status: 'ok',
    service: 'soc-dashboard-backend',
    storage: storageMode(),
    apis: {
      virusTotal: Boolean(process.env.VIRUSTOTAL_API_KEY),
      googleSafeBrowsing: Boolean(process.env.GOOGLE_SAFE_BROWSING_API_KEY),
      abuseIpDb: Boolean(process.env.ABUSEIPDB_API_KEY),
      nvdApiKey: Boolean(process.env.NVD_API_KEY),
    },
    ml,
    timestamp: new Date().toISOString(),
  });
});

app.post('/api/auth/login', async (req, res) => {
  const email = String(req.body.email || '').toLowerCase().trim();
  const password = String(req.body.password || '');
  const db = await readDb();
  const user = (db.users || []).find((item) => item.email.toLowerCase() === email);

  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    res.status(401).json({ error: 'Invalid email or password' });
    return;
  }

  await logActivity(`${user.name} logged in`, 'low');

  // Send push notification to phone
  axios.post('https://ntfy.sh/soc-dashboard-demo-sameer', 
    `🚨 Successful login by ${user.name} (${user.email})`, 
    { headers: { 'Title': 'SOC Sentinel Alert', 'Tags': 'warning,desktop_computer' } }
  ).catch(() => {});

  res.json({ token: signToken(user), user: publicUser(user) });
});

app.post('/api/auth/register', async (req, res) => {
  const email = String(req.body.email || '').toLowerCase().trim();
  const password = String(req.body.password || '');
  const name = String(req.body.name || '').trim();

  if (!email || !password || !name) {
    res.status(400).json({ error: 'Name, email, and password are required' });
    return;
  }

  const hash = bcrypt.hashSync(password, 10);
  const id = `user-${Date.now()}`;
  
  try {
    const db = await readDb();
    if ((db.users || []).find((u) => u.email.toLowerCase() === email)) {
      res.status(409).json({ error: 'Email already exists' });
      return;
    }
    await pool.query(
      `INSERT INTO users (id, name, email, role, password_hash) VALUES ($1, $2, $3, $4, $5)`,
      [id, name, email, 'analyst', hash]
    );
    const user = { id, name, email, role: 'analyst' };
    await logActivity(`New user registered: ${name}`, 'low');

    // Send push notification to phone
    axios.post('https://ntfy.sh/soc-dashboard-demo-sameer', 
      `🎉 New Account Created: ${name} (${email})`, 
      { headers: { 'Title': 'SOC Sentinel Alert', 'Tags': 'tada,bust_in_silhouette' } }
    ).catch(() => {});

    res.json({ token: signToken(user), user });
  } catch (err) {
    res.status(500).json({ error: 'Database error creating user' });
  }
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

app.get('/api/dashboard', async (_req, res) => {
  const db = await readDb();
  const openIncidents = db.incidents.filter((incident) => incident.status !== 'Closed').length;
  const highRisk = db.incidents.filter((incident) => ['critical', 'high'].includes(incident.severity)).length;

  res.json({
    stats: {
      threatsToday: 47 + db.incidents.length,
      openIncidents,
      urlsScanned: 203,
      emailsAnalyzed: 89,
      securityScore: Math.max(62, 88 - highRisk * 4),
    },
    charts: {
      weeklyThreats,
      hourlyActivity,
      threatTypes: { phishing: 38, vulnerability: 22, network: 18, password: 22 },
    },
    recentIncidents: db.incidents.slice(0, 6),
    activity: db.activity.slice(0, 12),
  });
});

app.get('/api/incidents', async (_req, res) => {
  const db = await readDb();
  res.json(db.incidents);
});

app.post('/api/incidents', async (req, res) => {
  const db = await readDb();
  const incident = {
    id: nextIncidentId(db.incidents),
    type: req.body.type || 'Security Event',
    severity: req.body.severity || 'medium',
    status: req.body.status || 'Open',
    source: req.body.source || 'Unknown source',
    assignee: req.body.assignee || 'Unassigned',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    notes: req.body.notes?.length ? req.body.notes : ['Created from backend API'],
  };

  db.incidents = [incident, ...db.incidents];
  await createIncident(incident);
  io.emit('incident:new', incident);
  await logActivity(`Ticket ${incident.id} created: ${incident.type}`, incident.severity);
  res.status(201).json(incident);
});

app.patch('/api/incidents/:id', async (req, res) => {
  const updated = await updateIncident(req.params.id, req.body);
  if (!updated) {
    res.status(404).json({ error: 'Incident not found' });
    return;
  }
  io.emit('incident:update', updated);
  await logActivity(`${updated.id} updated`, updated.severity);
  res.json(updated);
});

app.post('/api/reports/vulnerability', async (req, res) => {
  const targetUrl = String(req.body.target_url || '');
  const providedScan = req.body.scan;
  const scan = providedScan?.findings ? providedScan : scanWeb(targetUrl || 'demo.local');
  const doc = new PDFDocument({ margin: 48 });
  const chunks = [];

  doc.on('data', (chunk) => chunks.push(chunk));
  doc.on('end', () => {
    const pdf = Buffer.concat(chunks);
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'attachment; filename="soc-vulnerability-report.pdf"');
    res.send(pdf);
  });

  doc.fontSize(20).text('SOC Vulnerability Report', { underline: true });
  doc.moveDown();
  doc.fontSize(11).text(`Target: ${scan.target || targetUrl}`);
  doc.text(`Scanned at: ${scan.scanned_at || new Date().toISOString()}`);
  doc.text(`Risk score: ${scan.risk_score || 0}/100`);
  doc.text(`Total findings: ${scan.total_findings || scan.findings?.length || 0}`);
  doc.moveDown();

  doc.fontSize(14).text('Severity Summary');
  Object.entries(scan.summary || {}).forEach(([severity, count]) => {
    doc.fontSize(11).text(`${severity.toUpperCase()}: ${count}`);
  });
  doc.moveDown();

  doc.fontSize(14).text('Findings');
  (scan.findings || []).forEach((finding, index) => {
    doc.moveDown(0.5);
    doc.fontSize(12).text(`${index + 1}. ${finding.name || 'Finding'} [${finding.severity || 'low'}]`);
    doc.fontSize(10).text(`Description: ${finding.description || 'No description.'}`);
    doc.text(`Fix: ${finding.fix || 'Review configuration and apply vendor guidance.'}`);
  });

  doc.end();
});

app.get('/api/activity', async (_req, res) => {
  const db = await readDb();
  res.json(db.activity.slice(0, 50));
});

app.get('/api/threats', async (_req, res) => {
  res.json(await getAbuseIpThreats(25));
});

app.get('/api/cves', async (req, res) => {
  const keyword = String(req.query.keyword || '').trim();
  if (!keyword) {
    res.json(cves);
    return;
  }

  try {
    res.json(await searchNvd(keyword));
  } catch {
    res.json(cves);
  }
});

app.post('/predict/url', async (req, res) => {
  const url = String(req.body.url || '');
  const result = await proxyToMl('/predict/url', { url }, () => analyzeUrl(url));
  const [virusTotal, safeBrowsing] = await Promise.all([
    checkVirusTotalUrl(url).catch((error) => ({ enabled: Boolean(process.env.VIRUSTOTAL_API_KEY), verdict: 'error', error: error.message })),
    checkGoogleSafeBrowsing(url).catch((error) => ({ enabled: Boolean(process.env.GOOGLE_SAFE_BROWSING_API_KEY), verdict: 'error', error: error.message })),
  ]);
  const finalVerdict = combineUrlVerdicts(result.data, virusTotal, safeBrowsing);
  const enriched = {
    ...result.data,
    verdict: finalVerdict,
    source: result.source,
    external_checks: {
      virusTotal,
      googleSafeBrowsing: safeBrowsing,
    },
  };
  await logActivity(`URL scan completed via ${result.source}`, enriched.verdict === 'legitimate' ? 'low' : 'high');
  res.json(enriched);
});

app.post('/predict/email', async (req, res) => {
  const emailContent = String(req.body.email_content || '');
  const result = await proxyToMl('/predict/email', { email_content: emailContent }, () => analyzeEmail(emailContent));
  
  let chatgpt_explanation = null;
  if (process.env.OPENAI_API_KEY) {
    chatgpt_explanation = await explainEmailWithChatGPT(emailContent, result.data.verdict);
  }

  await logActivity(`Email scan completed via ${result.source}`, result.data.verdict === 'legitimate' ? 'low' : 'high');
  res.json({ ...result.data, source: result.source, chatgpt_explanation });
});

app.post('/analyze/password', async (req, res) => {
  const password = String(req.body.password || '');
  const result = await proxyToMl('/analyze/password', { password }, () => analyzePassword(password));
  res.json({ ...result.data, source: result.source });
});

app.post('/check/breach', async (req, res) => {
  const password = String(req.body.password || '');
  const result = await proxyToMl('/check/breach', { password }, () => ({
    breached: /password|123456|qwerty|admin/i.test(password),
    count: /password|123456|qwerty|admin/i.test(password) ? 3800000 : 0,
  }));
  res.json({ ...result.data, source: result.source });
});

app.post('/scan/vulnerability', async (req, res) => {
  const targetUrl = String(req.body.target_url || '');
  const result = await proxyToMl('/scan/vulnerability', { target_url: targetUrl }, () => scanWeb(targetUrl));
  await logActivity(`Web vulnerability scan completed via ${result.source}`, result.data.risk_score > 30 ? 'high' : 'medium');
  res.json({ ...result.data, source: result.source });
});

app.post('/predict/network', async (req, res) => {
  const features = req.body.features || {};
  const result = await proxyToMl('/predict/network', { features }, () => analyzeNetwork(features));
  const pps = Number(features.packets_per_second || 0);
  const uniquePorts = Number(features.unique_ports || 0);
  if (!result.data.is_anomaly && (pps > 300 || uniquePorts > 50)) {
    result.data = {
      ...result.data,
      is_anomaly: true,
      anomaly_score: Math.min(Number(result.data.anomaly_score || 0), -0.72),
      severity: pps > 600 || uniquePorts > 150 ? 'high' : 'medium',
      rule_override: 'High packet rate or broad port access detected',
    };
  }
  await logActivity(result.data.is_anomaly ? 'Network anomaly detected' : 'Network traffic normal', result.data.severity || 'low');
  res.json({ ...result.data, source: result.source });
});

io.on('connection', async (socket) => {
  const db = await readDb();
  socket.emit('activity:seed', db.activity.slice(0, 12));
});

await ensureStore();

server.listen(port, () => {
  console.log(`SOC backend running on http://localhost:${port}`);
  console.log(`Proxying ML analysis to ${mlServiceUrl}`);
});
