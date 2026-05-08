import { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  BarChart3,
  CheckCircle2,
  Clock,
  Globe2,
  KeyRound,
  LogIn,
  MailWarning,
  Radar,
  ScanLine,
  Search,
  ShieldAlert,
  ShieldCheck,
  Siren,
  Ticket,
  Wifi,
} from 'lucide-react';
import {
  ArcElement,
  BarElement,
  CategoryScale,
  Chart as ChartJS,
  Filler,
  Legend,
  LinearScale,
  LineElement,
  PointElement,
  RadialLinearScale,
  Tooltip,
} from 'chart.js';
import { Bar, Doughnut, Line, Radar as RadarChart } from 'react-chartjs-2';
import { api, API_BASE } from './api';

ChartJS.register(
  ArcElement,
  BarElement,
  CategoryScale,
  Filler,
  Legend,
  LinearScale,
  LineElement,
  PointElement,
  RadialLinearScale,
  Tooltip
);

const navItems = [
  ['overview', 'Overview', BarChart3],
  ['url', 'URL Scan', ShieldAlert],
  ['email', 'Email Scan', MailWarning],
  ['password', 'Passwords', KeyRound],
  ['vuln', 'Web Scan', ScanLine],
  ['network', 'Network', Wifi],
  ['cve', 'CVE Intel', Search],
  ['tickets', 'Tickets', Ticket],
];

const demoThreats = [
  { city: 'Moscow', x: 58, y: 31, severity: 'high', ip: '185.220.101.42', type: 'Brute force' },
  { city: 'Singapore', x: 76, y: 58, severity: 'medium', ip: '103.21.244.18', type: 'Phishing host' },
  { city: 'Frankfurt', x: 51, y: 36, severity: 'low', ip: '45.83.64.12', type: 'Scanner' },
  { city: 'Sao Paulo', x: 36, y: 70, severity: 'critical', ip: '177.54.148.33', type: 'Malware C2' },
  { city: 'Virginia', x: 25, y: 42, severity: 'medium', ip: '34.201.89.7', type: 'Credential stuffing' },
];

const sampleCves = [
  {
    id: 'CVE-2025-24813',
    score: 9.8,
    product: 'Apache Tomcat',
    published: '2025-03-10',
    summary: 'Remote code execution risk in vulnerable Tomcat deployments.',
  },
  {
    id: 'CVE-2024-6387',
    score: 8.1,
    product: 'OpenSSH',
    published: '2024-07-01',
    summary: 'Signal handler race condition affecting selected OpenSSH server versions.',
  },
  {
    id: 'CVE-2024-3094',
    score: 10,
    product: 'XZ Utils',
    published: '2024-03-29',
    summary: 'Backdoor discovered in compromised XZ Utils release artifacts.',
  },
];

const initialTickets = [
  {
    id: 'SOC-1001',
    type: 'Phishing URL',
    severity: 'high',
    status: 'Open',
    source: 'paypal-verify-account.tk',
    assignee: 'Analyst A',
    createdAt: new Date(Date.now() - 1000 * 60 * 26).toISOString(),
    notes: ['Auto-created from URL detector'],
  },
  {
    id: 'SOC-1002',
    type: 'Web Vulnerability',
    severity: 'medium',
    status: 'Investigating',
    source: 'test.local',
    assignee: 'Analyst B',
    createdAt: new Date(Date.now() - 1000 * 60 * 67).toISOString(),
    notes: ['Missing CSP and HSTS headers'],
  },
];

const chartText = '#94a3b8';
const chartGrid = 'rgba(148, 163, 184, 0.14)';

function LoginScreen({ onLogin }) {
  const [isRegister, setIsRegister] = useState(false);
  const [name, setName] = useState('');
  const [email, setEmail] = useState('analyst@soc.local');
  const [password, setPassword] = useState('admin123');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const submit = async (event) => {
    event.preventDefault();
    setLoading(true);
    setError('');
    try {
      const data = isRegister 
        ? await api.register(name, email, password)
        : await api.login(email, password);
      localStorage.setItem('soc_token', data.token);
      localStorage.setItem('soc_user', JSON.stringify(data.user));
      onLogin(data.user);
    } catch (err) {
      setError(err.message || (isRegister ? 'Registration failed' : 'Login failed'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="grid h-full place-items-center bg-soc-bg px-4 text-slate-100">
      <form onSubmit={submit} className="w-full max-w-md rounded-lg border border-soc-border bg-soc-card p-6 shadow-2xl">
        <div className="mb-6 flex items-center gap-3">
          <div className="grid h-11 w-11 place-items-center rounded-lg border border-soc-accent/40 bg-soc-accent/10">
            <Radar className="h-5 w-5 text-soc-accent" />
          </div>
          <div>
            <h1 className="font-display text-xl font-bold text-white">SOC Sentinel</h1>
            <p className="text-sm text-slate-400">{isRegister ? 'Create your account' : 'Analyst login'}</p>
          </div>
        </div>
        <div className="space-y-3">
          {isRegister && (
            <input className="soc-input" value={name} onChange={(event) => setName(event.target.value)} placeholder="Full Name" required />
          )}
          <input className="soc-input" type="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="Email" required />
          <input className="soc-input" type="password" value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Password" required />
        </div>
        {error && <p className="mt-4 rounded-lg border border-soc-red/40 bg-soc-red/10 p-3 text-sm text-soc-red">{error}</p>}
        <button type="submit" className="soc-btn soc-btn-primary mt-5 w-full justify-center" disabled={loading}>
          <LogIn className="h-4 w-4" />
          {loading ? 'Processing...' : (isRegister ? 'Create Account' : 'Sign In')}
        </button>
        <div className="mt-4 flex flex-wrap items-center justify-between text-xs font-mono">
          <button type="button" onClick={() => setIsRegister(!isRegister)} className="text-soc-accent hover:underline">
            {isRegister ? 'Already have an account? Sign in' : 'Need an account? Sign up'}
          </button>
          {!isRegister && <span className="text-slate-500">Demo: analyst@soc.local</span>}
        </div>
      </form>
    </div>
  );
}

function classNames(...names) {
  return names.filter(Boolean).join(' ');
}

function severityClass(severity) {
  const normalized = String(severity || 'low').toLowerCase();
  if (normalized === 'critical') return 'badge-critical';
  if (normalized === 'high') return 'badge-high';
  if (normalized === 'medium') return 'badge-medium';
  return 'badge-low';
}

function verdictClass(verdict) {
  const normalized = String(verdict || '').toLowerCase();
  if (['dangerous', 'phishing', 'critical', 'high'].includes(normalized)) return 'badge-dangerous';
  if (['suspicious', 'medium', 'weak'].includes(normalized)) return 'badge-suspicious';
  return 'badge-safe';
}

function formatTime(value) {
  return new Intl.DateTimeFormat('en-IN', {
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  }).format(new Date(value));
}

function useActivityLog() {
  const [logs, setLogs] = useState([
    { id: 1, text: 'Dashboard boot sequence completed', severity: 'low', time: new Date().toISOString() },
    { id: 2, text: 'ML service health check queued', severity: 'medium', time: new Date().toISOString() },
  ]);

  const pushLog = (text, severity = 'low') => {
    setLogs((current) => [
      { id: Date.now(), text, severity, time: new Date().toISOString() },
      ...current,
    ].slice(0, 12));
  };

  return [logs, pushLog];
}

function App() {
  const [active, setActive] = useState('overview');
  const [service, setService] = useState({ status: 'checking', models: {} });
  const [user, setUser] = useState(() => {
    const raw = localStorage.getItem('soc_user');
    return raw ? JSON.parse(raw) : null;
  });
  const [tickets, setTickets] = useState(initialTickets);
  const [logs, pushLog] = useActivityLog();
  const [threatIndex, setThreatIndex] = useState(0);

  useEffect(() => {
    if (!user) return;
    api.health()
      .then((data) => {
        setService({ status: 'online', models: data.ml?.models || {}, ml: data.ml });
        pushLog('Backend service connected on port 4000', 'low');
      })
      .catch(() => {
        setService({ status: 'offline', models: {} });
        pushLog('Backend offline - UI is in demo mode', 'medium');
      });

    api.incidents()
      .then((items) => {
        if (Array.isArray(items) && items.length) setTickets(items);
      })
      .catch(() => {});
  }, [user]);

  useEffect(() => {
    const timer = setInterval(() => {
      setThreatIndex((value) => (value + 1) % demoThreats.length);
    }, 2600);
    return () => clearInterval(timer);
  }, []);

  const createTicket = async (ticket) => {
    const next = {
      id: `SOC-${1000 + tickets.length + 1}`,
      status: 'Open',
      assignee: 'Unassigned',
      createdAt: new Date().toISOString(),
      notes: ['Auto-created by detection module'],
      ...ticket,
    };
    setTickets((current) => [next, ...current]);
    pushLog(`Ticket ${next.id} created: ${next.type}`, next.severity);
    try {
      const saved = await api.createIncident(ticket);
      setTickets((current) => [saved, ...current.filter((item) => item.id !== next.id)]);
    } catch {
      pushLog('Ticket saved locally because backend did not respond', 'medium');
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('soc_token');
    localStorage.removeItem('soc_user');
    setUser(null);
  };

  const stats = useMemo(() => {
    const open = tickets.filter((ticket) => ticket.status !== 'Closed').length;
    const high = tickets.filter((ticket) => ['critical', 'high'].includes(ticket.severity)).length;
    return [
      { label: 'Threats Today', value: 47 + tickets.length, icon: Siren, color: 'text-soc-red' },
      { label: 'Open Incidents', value: open, icon: Ticket, color: 'text-soc-orange' },
      { label: 'High Risk', value: high, icon: AlertTriangle, color: 'text-soc-yellow' },
      { label: 'Security Score', value: `${Math.max(62, 88 - high * 4)}%`, icon: ShieldCheck, color: 'text-soc-green' },
    ];
  }, [tickets]);

  if (!user) {
    return <LoginScreen onLogin={setUser} />;
  }

  return (
    <div className="h-full bg-soc-bg text-slate-100">
      <div className="grid h-full grid-cols-[248px_1fr_320px] overflow-hidden max-xl:grid-cols-[80px_1fr] max-lg:grid-cols-1">
        <aside className="border-r border-soc-border bg-soc-surface px-4 py-5 max-lg:hidden">
          <div className="mb-8 flex items-center gap-3">
            <div className="grid h-10 w-10 place-items-center rounded-lg border border-soc-accent/40 bg-soc-accent/10">
              <Radar className="h-5 w-5 text-soc-accent" />
            </div>
            <div className="max-xl:hidden">
              <h1 className="font-display text-lg font-bold tracking-normal text-white">SOC Sentinel</h1>
              <p className="font-mono text-xs text-slate-400">Minor Project MVP</p>
            </div>
          </div>

          <nav className="space-y-2">
            {navItems.map(([id, label, Icon]) => (
              <button
                key={id}
                type="button"
                onClick={() => setActive(id)}
                className={classNames(
                  'flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left text-sm font-semibold transition',
                  active === id
                    ? 'bg-soc-accent text-black'
                    : 'text-slate-400 hover:bg-soc-card hover:text-white'
                )}
              >
                <Icon className="h-4 w-4 shrink-0" />
                <span className="max-xl:hidden">{label}</span>
              </button>
            ))}
            
            <button
              type="button"
              onClick={handleLogout}
              className="mt-4 flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left text-sm font-semibold text-soc-red transition hover:bg-soc-card"
            >
              <svg className="h-4 w-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
              </svg>
              <span className="max-xl:hidden">Logout</span>
            </button>
          </nav>

          <div className="mt-8 rounded-lg border border-soc-border bg-soc-card p-3 max-xl:hidden">
            <div className="mb-2 flex items-center justify-between">
              <span className="text-xs font-semibold uppercase text-slate-400">ML Service</span>
              <span className={classNames('h-2.5 w-2.5 rounded-full', service.status === 'online' ? 'bg-soc-green' : 'bg-soc-orange')} />
            </div>
            <p className="font-mono text-xs text-slate-300">{API_BASE}</p>
            <p className="mt-2 text-xs capitalize text-slate-500">{service.status}</p>
          </div>
        </aside>

        <main className="overflow-y-auto px-6 py-5 max-sm:px-3">
          <header className="mb-5 flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="font-mono text-xs uppercase text-soc-accent">Security Operations Center</p>
              <h2 className="mt-1 text-2xl font-bold text-white">{navItems.find(([id]) => id === active)?.[1]}</h2>
              <p className="mt-1 text-sm text-slate-500">Signed in as {user.name}</p>
            </div>
            <div className="flex rounded-lg border border-soc-border bg-soc-surface p-1 lg:hidden">
              {navItems.slice(0, 5).map(([id, label, Icon]) => (
                <button
                  key={id}
                  type="button"
                  aria-label={label}
                  onClick={() => setActive(id)}
                  className={classNames(
                    'grid h-9 w-9 place-items-center rounded-md',
                    active === id ? 'bg-soc-accent text-black' : 'text-slate-400'
                  )}
                >
                  <Icon className="h-4 w-4" />
                </button>
              ))}
            </div>
          </header>

          {active === 'overview' && <Overview stats={stats} tickets={tickets} threatIndex={threatIndex} />}
          {active === 'url' && <UrlScanner createTicket={createTicket} pushLog={pushLog} />}
          {active === 'email' && <EmailScanner createTicket={createTicket} pushLog={pushLog} />}
          {active === 'password' && <PasswordAnalyzer pushLog={pushLog} />}
          {active === 'vuln' && <VulnerabilityScanner createTicket={createTicket} pushLog={pushLog} />}
          {active === 'network' && <NetworkMonitor createTicket={createTicket} pushLog={pushLog} />}
          {active === 'cve' && <CveIntel createTicket={createTicket} pushLog={pushLog} />}
          {active === 'tickets' && <TicketDesk tickets={tickets} setTickets={setTickets} pushLog={pushLog} />}
        </main>

        <aside className="overflow-y-auto border-l border-soc-border bg-soc-surface px-4 py-5 max-xl:hidden">
          <h3 className="mb-4 flex items-center gap-2 text-sm font-bold uppercase text-slate-300">
            <Activity className="h-4 w-4 text-soc-accent" />
            Live Activity
          </h3>
          <div className="space-y-3">
            {logs.map((log) => (
              <div key={log.id} className="rounded-lg border border-soc-border bg-soc-card p-3">
                <div className="mb-2 flex items-center justify-between">
                  <span className={classNames('soc-badge', severityClass(log.severity))}>{log.severity}</span>
                  <span className="font-mono text-xs text-slate-500">{formatTime(log.time)}</span>
                </div>
                <p className="text-sm text-slate-300">{log.text}</p>
              </div>
            ))}
          </div>
        </aside>
      </div>
    </div>
  );
}

function Overview({ stats, tickets, threatIndex }) {
  const lineData = {
    labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
    datasets: [{
      label: 'Threats',
      data: [21, 34, 28, 45, 39, 52, 47],
      borderColor: '#00d4ff',
      backgroundColor: 'rgba(0, 212, 255, 0.14)',
      fill: true,
      tension: 0.35,
    }],
  };

  const typeData = {
    labels: ['Phishing', 'Vuln', 'Network', 'Password'],
    datasets: [{
      data: [38, 22, 18, 22],
      backgroundColor: ['#ff4444', '#ff8c00', '#00d4ff', '#00ff88'],
      borderWidth: 0,
    }],
  };

  const barData = {
    labels: ['00', '04', '08', '12', '16', '20'],
    datasets: [{
      label: 'Events',
      data: [4, 7, 16, 20, 15, 9],
      backgroundColor: '#00d4ff',
      borderRadius: 4,
    }],
  };

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-4 gap-4 max-lg:grid-cols-2 max-sm:grid-cols-1">
        {stats.map((stat) => (
          <div key={stat.label} className="soc-card">
            <div className="mb-4 flex items-center justify-between">
              <span className="text-sm font-semibold text-slate-400">{stat.label}</span>
              <stat.icon className={classNames('h-5 w-5', stat.color)} />
            </div>
            <div className="font-mono text-3xl font-bold text-white">{stat.value}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-[1.2fr_0.8fr] gap-4 max-lg:grid-cols-1">
        <Panel title="Threats Over 7 Days">
          <div className="relative h-64 w-full">
            <Line data={lineData} options={chartOptions()} />
          </div>
        </Panel>
        <Panel title="Threat Distribution">
          <div className="relative h-64 w-full">
            <Doughnut data={typeData} options={{ ...chartOptions(), scales: undefined, cutout: '64%' }} />
          </div>
        </Panel>
      </div>

      <div className="grid grid-cols-[1fr_1fr] gap-4 max-lg:grid-cols-1">
        <ThreatMap activeIndex={threatIndex} />
        <Panel title="Hourly Activity">
          <div className="relative h-64 w-full">
            <Bar data={barData} options={chartOptions()} />
          </div>
        </Panel>
      </div>

      <Panel title="Recent Incidents">
        <IncidentTable tickets={tickets.slice(0, 5)} />
      </Panel>
    </div>
  );
}

function UrlScanner({ createTicket, pushLog }) {
  const [url, setUrl] = useState('http://paypal-verify-account.tk/login.php');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const scan = async () => {
    setLoading(true);
    try {
      const data = await api.predictUrl(url);
      setResult(data);
      const risky = ['phishing', 'suspicious'].includes(data.verdict);
      pushLog(`URL scan completed: ${data.verdict}`, risky ? 'high' : 'low');
      if (risky) {
        createTicket({ type: 'Phishing URL', severity: data.verdict === 'phishing' ? 'high' : 'medium', source: url });
      }
    } catch (error) {
      setResult({ verdict: 'offline', confidence: 0, error: error.message });
      pushLog('URL scan failed - start Python service', 'medium');
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolLayout
      icon={ShieldAlert}
      title="Phishing URL Detector"
      action={<button type="button" className="soc-btn soc-btn-primary" onClick={scan} disabled={loading}>{loading ? 'Scanning' : 'Scan URL'}</button>}
    >
      <input className="soc-input" value={url} onChange={(event) => setUrl(event.target.value)} />
      {result && <ResultCard result={result} source="URL" />}
    </ToolLayout>
  );
}

function EmailScanner({ createTicket, pushLog }) {
  const [email, setEmail] = useState('URGENT: Your PayPal account has been suspended. Verify your password immediately at http://paypal-verify.tk or your account will be closed.');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const scan = async () => {
    setLoading(true);
    try {
      const data = await api.predictEmail(email);
      setResult(data);
      const risky = data.verdict === 'phishing';
      pushLog(`Email analysis completed: ${data.verdict}`, risky ? 'high' : 'low');
      if (risky) createTicket({ type: 'Email Phishing', severity: 'high', source: 'Pasted email body' });
    } catch (error) {
      setResult({ verdict: 'offline', confidence: 0, error: error.message });
      pushLog('Email analysis failed - start Python service', 'medium');
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolLayout
      icon={MailWarning}
      title="Email Phishing Detector"
      action={<button type="button" className="soc-btn soc-btn-primary" onClick={scan} disabled={loading}>{loading ? 'Analyzing' : 'Analyze Email'}</button>}
    >
      <textarea className="soc-input min-h-44 resize-y" value={email} onChange={(event) => setEmail(event.target.value)} />
      {result && <ResultCard result={result} source="Email" />}
      {result?.suspicious_phrases?.length > 0 && (
        <div className="soc-card">
          <h4 className="mb-3 font-semibold text-white">Suspicious Phrases</h4>
          <div className="flex flex-wrap gap-2">
            {result.suspicious_phrases.map((phrase) => (
              <span key={phrase} className="soc-badge badge-dangerous">{phrase}</span>
            ))}
          </div>
        </div>
      )}
    </ToolLayout>
  );
}

function PasswordAnalyzer({ pushLog }) {
  const [password, setPassword] = useState('password123');
  const [result, setResult] = useState(null);
  const [breach, setBreach] = useState(null);

  useEffect(() => {
    const timer = setTimeout(async () => {
      if (!password) return;
      try {
        const data = await api.analyzePassword(password);
        setResult(data);
      } catch {
        setResult(null);
      }
    }, 250);
    return () => clearTimeout(timer);
  }, [password]);

  const checkBreach = async () => {
    try {
      const data = await api.checkBreach(password);
      setBreach(data);
      pushLog(data.breached ? 'Password found in breach corpus' : 'Password breach check clean', data.breached ? 'high' : 'low');
    } catch (error) {
      setBreach({ error: error.message });
      pushLog('Breach check failed - check internet or ML service', 'medium');
    }
  };

  return (
    <ToolLayout
      icon={KeyRound}
      title="Password Security Analyzer"
      action={<button type="button" className="soc-btn soc-btn-primary" onClick={checkBreach}>Check Breach</button>}
    >
      <input className="soc-input" value={password} onChange={(event) => setPassword(event.target.value)} />
      {result && (
        <div className="grid grid-cols-[0.8fr_1.2fr] gap-4 max-lg:grid-cols-1">
          <div className="soc-card">
            <div className="mb-3 flex items-center justify-between">
              <span className="text-sm text-slate-400">Strength</span>
              <span className={classNames('soc-badge', verdictClass(result.strength))}>{result.strength}</span>
            </div>
            <div className="mb-4 font-mono text-5xl font-bold text-white">{result.score}</div>
            <div className="h-2 rounded-full bg-soc-surface">
              <div className="h-2 rounded-full bg-soc-accent" style={{ width: `${result.score}%` }} />
            </div>
            <p className="mt-4 font-mono text-sm text-slate-300">Crack time: {result.crack_time}</p>
          </div>
          <div className="soc-card">
            <h4 className="mb-3 font-semibold text-white">Findings</h4>
            <Checklist items={[...(result.patterns_found || []), ...(result.suggestions || [])]} />
            {breach && (
              <div className="mt-4 rounded-lg border border-soc-border bg-soc-surface p-3">
                {breach.error ? breach.error : breach.breached ? `Seen ${breach.count.toLocaleString()} times in breaches` : 'No breach match found'}
              </div>
            )}
          </div>
        </div>
      )}
    </ToolLayout>
  );
}

function VulnerabilityScanner({ createTicket, pushLog }) {
  const [target, setTarget] = useState('http://testphp.vulnweb.com');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [exporting, setExporting] = useState(false);

  const scan = async () => {
    setLoading(true);
    try {
      const data = await api.scanVulnerability(target);
      setResult(data);
      const severity = data.summary.critical ? 'critical' : data.summary.high ? 'high' : 'medium';
      pushLog(`Web scan found ${data.total_findings} findings`, severity);
      if (data.total_findings > 0) {
        createTicket({ type: 'Web Vulnerability', severity, source: data.target });
      }
    } catch (error) {
      setResult({ error: error.message, findings: [], summary: {}, total_findings: 0, risk_score: 0 });
      pushLog('Web scan failed - use a reachable test site', 'medium');
    } finally {
      setLoading(false);
    }
  };

  const exportPdf = async () => {
    if (!result) return;
    setExporting(true);
    try {
      const blob = await api.vulnerabilityReport(target, result);
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'soc-vulnerability-report.pdf';
      link.click();
      URL.revokeObjectURL(url);
      pushLog('Vulnerability PDF report generated', 'low');
    } catch (error) {
      pushLog(`PDF export failed: ${error.message}`, 'medium');
    } finally {
      setExporting(false);
    }
  };

  return (
    <ToolLayout
      icon={ScanLine}
      title="Web Vulnerability Scanner"
      action={(
        <div className="flex flex-wrap gap-2">
          {result && <button type="button" className="soc-btn soc-btn-ghost" onClick={exportPdf} disabled={exporting}>{exporting ? 'Exporting' : 'Export PDF'}</button>}
          <button type="button" className="soc-btn soc-btn-primary" onClick={scan} disabled={loading}>{loading ? 'Scanning' : 'Run Scan'}</button>
        </div>
      )}
    >
      <input className="soc-input" value={target} onChange={(event) => setTarget(event.target.value)} />
      {result && (
        <div className="space-y-4">
          <div className="grid grid-cols-4 gap-3 max-md:grid-cols-2">
            {['critical', 'high', 'medium', 'low'].map((severity) => (
              <div key={severity} className="soc-card">
                <span className={classNames('soc-badge', severityClass(severity))}>{severity}</span>
                <div className="mt-3 font-mono text-3xl font-bold">{result.summary?.[severity] || 0}</div>
              </div>
            ))}
          </div>
          <Panel title={`Risk Score: ${result.risk_score || 0}/100`}>
            <FindingList findings={result.findings || []} />
          </Panel>
        </div>
      )}
    </ToolLayout>
  );
}

function NetworkMonitor({ createTicket, pushLog }) {
  const [traffic, setTraffic] = useState([42, 54, 48, 61, 58, 64, 55, 72]);
  const [status, setStatus] = useState(null);
  const [liveMode, setLiveMode] = useState(false);

  useEffect(() => {
    if (!liveMode) return;
    const interval = setInterval(async () => {
      try {
        const data = await api.predictNetwork({ mode: 'live' });
        setStatus(data);
        setTraffic((current) => [...current.slice(1), data.packets_per_second || 0]);
        if (data.is_anomaly) {
          pushLog('Live network anomaly detected', data.severity || 'high');
          createTicket({ type: 'Live Network Anomaly', severity: data.severity, source: 'Real traffic' });
        }
      } catch (err) {
        console.error('Live sniff failed', err);
      }
    }, 2000);
    return () => clearInterval(interval);
  }, [liveMode]);

  const simulate = async (attack = false) => {
    setLiveMode(false);
    const next = attack ? [52, 61, 70, 310, 620, 870, 530, 140] : [45, 55, 49, 62, 60, 66, 59, 64];
    setTraffic(next);
    const features = {
      packets_per_second: attack ? 870 : 64,
      bytes_per_second: attack ? 1600000 : 82000,
      tcp_ratio: attack ? 0.18 : 0.62,
      udp_ratio: attack ? 0.78 : 0.28,
      icmp_ratio: attack ? 0.04 : 0.1,
      unique_ports: attack ? 240 : 3,
      avg_packet_size: attack ? 72 : 1320,
    };
    try {
      const data = await api.predictNetwork(features);
      setStatus(data);
      pushLog(data.is_anomaly ? 'Network anomaly detected' : 'Network traffic normal', data.is_anomaly ? data.severity : 'low');
      if (data.is_anomaly) createTicket({ type: 'Network Anomaly', severity: data.severity, source: 'Simulated traffic replay' });
    } catch {
      setStatus({ is_anomaly: attack, severity: attack ? 'high' : 'none' });
      pushLog(attack ? 'Network anomaly simulated' : 'Network baseline simulated', attack ? 'high' : 'low');
    }
  };

  const data = {
    labels: traffic.map((_, index) => `${index + 1}s`),
    datasets: [{
      label: 'Packets/sec',
      data: traffic,
      borderColor: status?.is_anomaly ? '#ff4444' : '#00ff88',
      backgroundColor: status?.is_anomaly ? 'rgba(255, 68, 68, 0.18)' : 'rgba(0, 255, 136, 0.14)',
      fill: true,
      tension: 0.3,
    }],
  };

  return (
    <ToolLayout
      icon={Wifi}
      title="Network Traffic Anomaly Detector"
      action={(
        <div className="flex gap-2">
          <button type="button" className={classNames("soc-btn", liveMode ? "soc-btn-primary" : "soc-btn-ghost")} onClick={() => setLiveMode(!liveMode)}>
            {liveMode ? 'Stop Live Sniff' : 'Start Live Sniff'}
          </button>
          <button type="button" className="soc-btn soc-btn-ghost" onClick={() => simulate(false)}>Normal</button>
          <button type="button" className="soc-btn soc-btn-primary" onClick={() => simulate(true)}>Simulate Attack</button>
        </div>
      )}
    >
      <Panel title="Traffic Replay">
        <div className="relative h-64 w-full">
          <Line data={data} options={chartOptions()} />
        </div>
      </Panel>
      {status && <ResultCard result={{ verdict: status.is_anomaly ? 'anomaly' : 'normal', confidence: Math.abs(status.anomaly_score || 0.8), severity: status.severity }} source="Network" />}
    </ToolLayout>
  );
}

function CveIntel({ createTicket, pushLog }) {
  const [query, setQuery] = useState('Apache');
  const [items, setItems] = useState(sampleCves);
  const [loading, setLoading] = useState(false);

  const search = async () => {
    setLoading(true);
    try {
      const parsed = await api.cves(query);
      setItems(parsed.length ? parsed : sampleCves);
      pushLog(`CVE search completed for ${query}`, 'low');
    } catch {
      setItems(sampleCves);
      pushLog('CVE API unavailable - showing demo intelligence', 'medium');
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolLayout
      icon={Search}
      title="CVE Vulnerability Intelligence"
      action={<button type="button" className="soc-btn soc-btn-primary" onClick={search} disabled={loading}>{loading ? 'Searching' : 'Search CVEs'}</button>}
    >
      <input className="soc-input" value={query} onChange={(event) => setQuery(event.target.value)} />
      <div className="grid gap-3">
        {items.map((item) => (
          <button
            key={item.id}
            type="button"
            onClick={() => {
              if (item.score >= 9) createTicket({ type: 'Critical CVE', severity: 'critical', source: item.id });
            }}
            className="rounded-lg border border-soc-border bg-soc-card p-4 text-left transition hover:border-soc-accent"
          >
            <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
              <span className="font-mono text-sm font-bold text-soc-accent">{item.id}</span>
              <span className={classNames('soc-badge', item.score >= 9 ? 'badge-critical' : 'badge-high')}>CVSS {item.score}</span>
            </div>
            <p className="text-sm text-slate-300">{item.summary}</p>
            <p className="mt-2 font-mono text-xs text-slate-500">{item.product} - {item.published}</p>
          </button>
        ))}
      </div>
    </ToolLayout>
  );
}

function TicketDesk({ tickets, setTickets, pushLog }) {
  const updateTicket = async (id, status) => {
    setTickets((current) => current.map((ticket) => (
      ticket.id === id
        ? { ...ticket, status, notes: [`Status changed to ${status}`, ...ticket.notes] }
        : ticket
    )));
    pushLog(`${id} moved to ${status}`, status === 'Closed' ? 'low' : 'medium');
    try {
      const saved = await api.updateIncident(id, { status });
      setTickets((current) => current.map((ticket) => ticket.id === id ? saved : ticket));
    } catch {
      pushLog(`${id} status changed locally`, 'medium');
    }
  };

  return (
    <div className="space-y-4">
      {tickets.map((ticket) => (
        <div key={ticket.id} className="rounded-lg border border-soc-border bg-soc-card p-4">
          <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-sm font-bold text-soc-accent">{ticket.id}</span>
                <span className={classNames('soc-badge', severityClass(ticket.severity))}>{ticket.severity}</span>
                <span className={classNames('soc-badge', `badge-${ticket.status.toLowerCase()}`)}>{ticket.status}</span>
              </div>
              <h3 className="mt-2 text-lg font-bold text-white">{ticket.type}</h3>
              <p className="font-mono text-xs text-slate-400">{ticket.source}</p>
            </div>
            <div className="flex flex-wrap gap-2">
              {['Open', 'Investigating', 'Resolved', 'Closed'].map((status) => (
                <button key={status} type="button" className="soc-btn soc-btn-ghost" onClick={() => updateTicket(ticket.id, status)}>
                  {status}
                </button>
              ))}
            </div>
          </div>
          <div className="grid gap-2">
            {ticket.notes.map((note) => (
              <div key={note} className="rounded-md bg-soc-surface px-3 py-2 text-sm text-slate-300">{note}</div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function ThreatMap({ activeIndex }) {
  return (
    <Panel title="Live Threat Map">
      <div className="relative min-h-80 overflow-hidden rounded-lg border border-soc-border bg-[#08111f]">
        <div className="absolute inset-0 opacity-30 [background-image:linear-gradient(rgba(0,212,255,.12)_1px,transparent_1px),linear-gradient(90deg,rgba(0,212,255,.12)_1px,transparent_1px)] [background-size:36px_36px]" />
        <div className="absolute left-[8%] top-[22%] h-[42%] w-[28%] rounded-[45%] border border-soc-accent/25" />
        <div className="absolute left-[43%] top-[24%] h-[35%] w-[18%] rounded-[45%] border border-soc-accent/25" />
        <div className="absolute left-[63%] top-[18%] h-[48%] w-[28%] rounded-[45%] border border-soc-accent/25" />
        <div className="absolute left-[34%] top-[63%] h-[25%] w-[18%] rounded-[45%] border border-soc-accent/25" />
        {demoThreats.map((threat, index) => (
          <div
            key={threat.ip}
            className="absolute"
            style={{ left: `${threat.x}%`, top: `${threat.y}%` }}
          >
            <div className={classNames(
              'h-3 w-3 rounded-full shadow-[0_0_18px_currentColor]',
              index === activeIndex ? 'animate-ping bg-soc-red text-soc-red' : 'bg-soc-accent text-soc-accent'
            )} />
            {index === activeIndex && (
              <div className="absolute left-4 top-2 w-48 rounded-lg border border-soc-border bg-soc-card p-3 shadow-xl">
                <div className="mb-1 flex items-center justify-between">
                  <span className="font-bold text-white">{threat.city}</span>
                  <span className={classNames('soc-badge', severityClass(threat.severity))}>{threat.severity}</span>
                </div>
                <p className="font-mono text-xs text-slate-300">{threat.ip}</p>
                <p className="text-xs text-slate-400">{threat.type}</p>
              </div>
            )}
          </div>
        ))}
      </div>
    </Panel>
  );
}

function ToolLayout({ icon: Icon, title, action, children }) {
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-soc-border bg-soc-card p-4">
        <div className="flex items-center gap-3">
          <div className="grid h-10 w-10 place-items-center rounded-lg bg-soc-accent/10 text-soc-accent">
            <Icon className="h-5 w-5" />
          </div>
          <h3 className="text-lg font-bold text-white">{title}</h3>
        </div>
        {action}
      </div>
      {children}
    </div>
  );
}

function Panel({ title, children }) {
  return (
    <section className="soc-card">
      <h3 className="mb-4 text-sm font-bold uppercase text-slate-300">{title}</h3>
      {children}
    </section>
  );
}

function ResultCard({ result, source }) {
  const verdict = result.verdict || result.strength || result.severity || 'unknown';
  return (
    <div className="soc-card">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
        <h4 className="font-semibold text-white">{source} Result</h4>
        <span className={classNames('soc-badge', verdictClass(verdict))}>{verdict}</span>
      </div>
      <div className="grid grid-cols-3 gap-3 max-md:grid-cols-1">
        <Metric label="Confidence" value={`${Math.round((result.confidence || 0) * 100)}%`} />
        <Metric label="Model" value={result.model_used || 'Rule/Fallback'} />
        <Metric label="Severity" value={result.severity || verdict} />
      </div>
      {result.external_checks && (
        <div className="mt-4 grid grid-cols-2 gap-3 max-md:grid-cols-1">
          <Metric
            label="VirusTotal"
            value={formatExternalCheck(result.external_checks.virusTotal)}
          />
          <Metric
            label="Google Safe Browsing"
            value={formatExternalCheck(result.external_checks.googleSafeBrowsing)}
          />
        </div>
      )}
      {result.error && <p className="mt-4 rounded-lg border border-soc-orange/40 bg-soc-orange/10 p-3 text-sm text-soc-orange">{result.error}</p>}
    </div>
  );
}

function formatExternalCheck(check) {
  if (!check?.enabled) return 'API key not set';
  if (check.error) return 'API error';
  if (typeof check.enginesFlagged === 'number') return `${check.verdict} - ${check.enginesFlagged} engines`;
  if (Array.isArray(check.matches)) return `${check.verdict} - ${check.matches.length} matches`;
  return check.verdict || 'checked';
}

function Metric({ label, value }) {
  return (
    <div className="rounded-lg border border-soc-border bg-soc-surface p-3">
      <p className="text-xs uppercase text-slate-500">{label}</p>
      <p className="mt-1 break-words font-mono text-sm font-bold text-white">{value}</p>
    </div>
  );
}

function Checklist({ items }) {
  if (!items.length) {
    return <p className="text-sm text-slate-400">No major weaknesses detected.</p>;
  }
  return (
    <div className="space-y-2">
      {items.map((item) => (
        <div key={item} className="flex gap-2 rounded-md bg-soc-surface p-2 text-sm text-slate-300">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-soc-yellow" />
          <span>{item}</span>
        </div>
      ))}
    </div>
  );
}

function FindingList({ findings }) {
  if (!findings.length) {
    return <p className="text-sm text-slate-400">No findings returned.</p>;
  }
  return (
    <div className="space-y-3">
      {findings.map((finding) => (
        <div key={`${finding.id}-${finding.name}`} className="rounded-lg border border-soc-border bg-soc-surface p-3">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
            <h4 className="font-semibold text-white">{finding.name}</h4>
            <span className={classNames('soc-badge', severityClass(finding.severity))}>{finding.severity}</span>
          </div>
          <p className="text-sm text-slate-300">{finding.description}</p>
          <p className="mt-2 text-sm text-soc-accent">{finding.fix}</p>
        </div>
      ))}
    </div>
  );
}

function IncidentTable({ tickets }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[680px] text-left text-sm">
        <thead className="text-xs uppercase text-slate-500">
          <tr>
            <th className="pb-3">Ticket</th>
            <th className="pb-3">Type</th>
            <th className="pb-3">Severity</th>
            <th className="pb-3">Status</th>
            <th className="pb-3">Created</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-soc-border">
          {tickets.map((ticket) => (
            <tr key={ticket.id}>
              <td className="py-3 font-mono text-soc-accent">{ticket.id}</td>
              <td className="py-3 text-slate-300">{ticket.type}</td>
              <td className="py-3"><span className={classNames('soc-badge', severityClass(ticket.severity))}>{ticket.severity}</span></td>
              <td className="py-3 text-slate-300">{ticket.status}</td>
              <td className="py-3 font-mono text-xs text-slate-500">{formatTime(ticket.createdAt)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function chartOptions() {
  return {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { labels: { color: chartText, boxWidth: 10 } },
      tooltip: { backgroundColor: '#111827', borderColor: '#1e2d45', borderWidth: 1 },
    },
    scales: {
      x: { ticks: { color: chartText }, grid: { color: chartGrid } },
      y: { ticks: { color: chartText }, grid: { color: chartGrid } },
      r: { ticks: { color: chartText, backdropColor: 'transparent' }, grid: { color: chartGrid }, angleLines: { color: chartGrid } },
    },
  };
}

export default App;
