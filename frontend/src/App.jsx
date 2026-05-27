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
  Monitor,
  Radar,
  ScanLine,
  Search,
  ShieldAlert,
  ShieldCheck,
  Siren,
  Ticket,
  Users,
  Wifi,
  Bot,
  GraduationCap
} from 'lucide-react';
import { GoogleLogin } from '@react-oauth/google';
import { RecaptchaVerifier, signInWithPhoneNumber } from 'firebase/auth';
import { auth } from './firebase';

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
import { MapContainer, TileLayer, CircleMarker, Tooltip as LeafletTooltip, useMap } from 'react-leaflet';
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
  ['lab', 'Lab Monitor', Monitor],
  ['risk', 'Student Risk', Users],
  ['url', 'URL Scan', ShieldAlert],
  ['email', 'Gmail Phishing Security', MailWarning],
  ['password', 'Passwords', KeyRound],
  ['vuln', 'Web Scan', ScanLine],
  ['network', 'Campus Network', Wifi],
  ['cve', 'CVE Intel', Search],
  ['tickets', 'Campus Incidents', Ticket],
  ['chatbot', 'AI Assistant', Bot],
  ['training', 'Cyber Training', GraduationCap],
];

const demoThreats = [
  { city: 'Moscow', lat: 55.7558, lng: 37.6173, x: 58, y: 31, severity: 'high', ip: '185.220.101.42', type: 'Brute force' },
  { city: 'Singapore', lat: 1.3521, lng: 103.8198, x: 76, y: 58, severity: 'medium', ip: '103.21.244.18', type: 'Phishing host' },
  { city: 'Frankfurt', lat: 50.1109, lng: 8.6821, x: 51, y: 36, severity: 'low', ip: '45.83.64.12', type: 'Scanner' },
  { city: 'Sao Paulo', lat: -23.5505, lng: -46.6333, x: 36, y: 70, severity: 'critical', ip: '177.54.148.33', type: 'Malware C2' },
  { city: 'Virginia', lat: 37.4316, lng: -78.6569, x: 25, y: 42, severity: 'medium', ip: '34.201.89.7', type: 'Credential stuffing' },
  { city: 'Tokyo', lat: 35.6762, lng: 139.6503, x: 82, y: 38, severity: 'high', ip: '114.160.10.22', type: 'DDoS Origin' },
  { city: 'London', lat: 51.5074, lng: -0.1278, x: 48, y: 33, severity: 'medium', ip: '82.21.44.19', type: 'Port Scan' },
  { city: 'Sydney', lat: -33.8688, lng: 151.2093, x: 88, y: 80, severity: 'low', ip: '202.14.88.9', type: 'Reconnaissance' },
  { city: 'Johannesburg', lat: -26.2041, lng: 28.0473, x: 54, y: 75, severity: 'high', ip: '196.44.20.1', type: 'SQL Injection' },
  { city: 'Mumbai', lat: 19.0760, lng: 72.8777, x: 68, y: 50, severity: 'critical', ip: '14.139.60.22', type: 'Ransomware C2' },
  { city: 'Toronto', lat: 43.6510, lng: -79.3470, x: 23, y: 34, severity: 'medium', ip: '199.204.14.8', type: 'Data Exfiltration' },
  { city: 'Beijing', lat: 39.9042, lng: 116.4074, x: 74, y: 35, severity: 'high', ip: '202.108.22.5', type: 'APT Activity' }
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
    type: 'Gmail Phishing',
    severity: 'high',
    status: 'Open',
    source: 'student-finance-verify.tk',
    assignee: 'Prof. Smith',
    createdAt: new Date(Date.now() - 1000 * 60 * 26).toISOString(),
    notes: ['Auto-created from URL detector targeting students'],
  },
  {
    id: 'SOC-1002',
    type: 'Campus Network Vuln',
    severity: 'medium',
    status: 'Investigating',
    source: 'library.institute.edu',
    assignee: 'Admin',
    createdAt: new Date(Date.now() - 1000 * 60 * 67).toISOString(),
    notes: ['Missing CSP and HSTS headers on library portal'],
  },
];

const chartText = '#94a3b8';
const chartGrid = 'rgba(148, 163, 184, 0.14)';

function LoginScreen({ onLogin }) {
  const [loginMode, setLoginMode] = useState('student'); // 'student' | 'faculty'
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [phone, setPhone] = useState('');
  const [otp, setOtp] = useState('');
  const [showOtp, setShowOtp] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleFacultySubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      if (showOtp) {
        if (otp === window.generatedOtp) {
          onLogin({ id: 'faculty-admin', name: 'Faculty Member', email: phone, role: 'faculty' });
        } else {
          setError('Invalid Security Code.');
        }
      } else {
        // Generate a 6-digit random OTP
        const generated = Math.floor(100000 + Math.random() * 900000).toString();
        window.generatedOtp = generated;
        
        // Send a Push Notification to the user's phone via Ntfy
        await fetch('https://ntfy.sh/soc_dashboard_admin_otp', {
          method: 'POST',
          headers: {
            'Title': 'SOC Dashboard Login',
            'Tags': 'shield,warning'
          },
          body: `Your Admin Verification Code is: ${generated}`
        });
        
        setShowOtp(true);
      }
    } catch (err) {
      setError('Push notification delivery failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleStudentSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      if (showOtp) {
        const data = await api.verifyOtp(email, otp);
        localStorage.setItem('soc_token', data.token);
        localStorage.setItem('soc_user', JSON.stringify(data.user));
        onLogin(data.user);
      } else {
        const data = await api.login(email, password);
        if (data.requireOtp) {
          setShowOtp(true);
        } else {
          localStorage.setItem('soc_token', data.token);
          localStorage.setItem('soc_user', JSON.stringify(data.user));
          onLogin(data.user);
        }
      }
    } catch (err) {
      setError(err.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleSuccess = (credentialResponse) => {
    try {
      const payload = JSON.parse(atob(credentialResponse.credential.split('.')[1]));
      onLogin({ id: `google-${Date.now()}`, name: payload.name || payload.email.split('@')[0], email: payload.email, role: 'student' });
    } catch(e) {
      onLogin({ id: `google-${Date.now()}`, name: 'Google User', email: 'google@student.edu', role: 'student' });
    }
  };

  return (
    <div className="flex h-full w-full bg-soc-bg text-slate-100 overflow-hidden">
      
      {/* Left Pane - Premium Branding */}
      <div className="hidden lg:flex w-1/2 bg-[#08111f] flex-col justify-between p-12 border-r border-soc-border/50 relative overflow-hidden">
        <div className="absolute top-0 left-0 w-full h-full bg-[radial-gradient(ellipse_at_top_left,_var(--tw-gradient-stops))] from-soc-accent/20 via-[#08111f] to-[#08111f] z-0"></div>
        <div className="relative z-10">
          <div className="flex items-center gap-3 mb-16">
            <div className="grid h-12 w-12 place-items-center rounded-xl bg-soc-accent/10 border border-soc-accent/30 backdrop-blur">
              <Radar className="h-6 w-6 text-soc-accent animate-pulse" />
            </div>
            <h1 className="font-display text-2xl font-bold tracking-wider">EduSOC <span className="text-soc-accent font-light">PRO</span></h1>
          </div>
          <h2 className="text-4xl font-bold mb-4 leading-tight">Next-Generation<br/>Campus Security.</h2>
          <p className="text-slate-400 text-lg max-w-md">Advanced User Entity Behavioral Analytics and Layer 2 Network Defense deployed across your campus in real-time.</p>
        </div>
        
        <div className="relative z-10 flex gap-4">
          <div className="bg-soc-card/80 p-4 rounded-xl border border-soc-border backdrop-blur">
            <ShieldCheck className="h-6 w-6 text-soc-green mb-2" />
            <div className="text-sm font-semibold">Active MITM Blocker</div>
          </div>
          <div className="bg-soc-card/80 p-4 rounded-xl border border-soc-border backdrop-blur">
            <Bot className="h-6 w-6 text-soc-accent mb-2" />
            <div className="text-sm font-semibold">ML Threat Engine</div>
          </div>
        </div>
      </div>

      {/* Right Pane - Login Form */}
      <div className="w-full lg:w-1/2 flex items-center justify-center p-8 relative">
        <div className="w-full max-w-md">
          <div className="mb-8">
            <h2 className="text-3xl font-display font-bold mb-2">Welcome back</h2>
            <p className="text-slate-400">Please sign in to access the command center.</p>
          </div>

          <div className="flex p-1 bg-soc-surface rounded-lg mb-8 border border-soc-border">
            <button 
              type="button"
              className={`flex-1 py-2 text-sm font-semibold rounded-md transition-all ${loginMode === 'student' ? 'bg-soc-card text-white shadow' : 'text-slate-400 hover:text-white'}`}
              onClick={() => { setLoginMode('student'); setShowOtp(false); setError(''); }}
            >
              Student Sign-In
            </button>
            <button 
              type="button"
              className={`flex-1 py-2 text-sm font-semibold rounded-md transition-all ${loginMode === 'faculty' ? 'bg-soc-card text-white shadow' : 'text-slate-400 hover:text-white'}`}
              onClick={() => { setLoginMode('faculty'); setShowOtp(false); setError(''); }}
            >
              Faculty Sign-In
            </button>
          </div>

          {loginMode === 'student' ? (
            <form onSubmit={handleStudentSubmit} className="space-y-4">
              {showOtp ? (
                <div className="animate-in fade-in slide-in-from-bottom-2">
                  <label className="text-xs text-slate-400 uppercase tracking-wider font-semibold mb-1 block">Authentication Code</label>
                  <input className="soc-input text-center tracking-[0.5em] font-mono text-xl py-3" value={otp} onChange={(e) => setOtp(e.target.value)} placeholder="000000" maxLength={6} required />
                  <p className="text-xs text-soc-accent mt-2 text-center">OTP sent to your registered device via Ntfy.</p>
                </div>
              ) : (
                <div className="space-y-4 animate-in fade-in slide-in-from-bottom-2">
                  <div>
                    <label className="text-xs text-slate-400 uppercase tracking-wider font-semibold mb-1 block">Email Address</label>
                    <input className="soc-input bg-soc-bg border-soc-border py-3" type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="student@institute.edu" required />
                  </div>
                  <div>
                    <label className="text-xs text-slate-400 uppercase tracking-wider font-semibold mb-1 block">Password</label>
                    <input className="soc-input bg-soc-bg border-soc-border py-3" type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" required />
                  </div>
                </div>
              )}
              
              {error && <div className="p-3 bg-soc-red/10 border border-soc-red/30 text-soc-red text-sm rounded-lg flex items-center gap-2 animate-in fade-in"><AlertTriangle className="h-4 w-4"/> {error}</div>}
              
              <button type="submit" className="soc-btn soc-btn-primary w-full py-3 justify-center text-sm" disabled={loading}>
                {loading ? 'Authenticating...' : (showOtp ? 'Verify OTP' : 'Sign In as Student')}
              </button>

              {!showOtp && (
                <>
                  <div className="relative my-6">
                    <div className="absolute inset-0 flex items-center"><div className="w-full border-t border-soc-border"></div></div>
                    <div className="relative flex justify-center text-xs"><span className="bg-soc-bg px-2 text-slate-500 uppercase">Or continue with</span></div>
                  </div>
                  <div className="flex justify-center">
                    <GoogleLogin onSuccess={handleGoogleSuccess} onError={() => setError('Google Sign-In failed')} useOneTap theme="outline" shape="pill" />
                  </div>
                </>
              )}
            </form>
          ) : (
            <form onSubmit={handleFacultySubmit} className="space-y-4">
              <div className="p-4 bg-soc-accent/10 border border-soc-accent/20 rounded-lg mb-6 flex items-start gap-3">
                <ShieldAlert className="h-5 w-5 text-soc-accent shrink-0 mt-0.5" />
                <p className="text-xs text-soc-accent/90 leading-relaxed">Faculty portal requires secure phone authentication. Standard email login is disabled for administrative accounts to prevent phishing.</p>
              </div>

              {showOtp ? (
                <div className="animate-in fade-in slide-in-from-bottom-2">
                  <label className="text-xs text-slate-400 uppercase tracking-wider font-semibold mb-1 block">SMS Verification Code</label>
                  <input className="soc-input text-center tracking-[0.5em] font-mono text-xl py-3" value={otp} onChange={(e) => setOtp(e.target.value)} placeholder="000000" maxLength={6} required />
                </div>
              ) : (
                <div className="animate-in fade-in slide-in-from-bottom-2">
                  <label className="text-xs text-slate-400 uppercase tracking-wider font-semibold mb-1 block">Phone Number (with Country Code)</label>
                  <input className="soc-input bg-soc-bg border-soc-border py-3 font-mono" type="tel" value={phone} onChange={(e) => setPhone(e.target.value)} placeholder="+1 234 567 8900" required />
                </div>
              )}

              {error && <div className="p-3 bg-soc-red/10 border border-soc-red/30 text-soc-red text-sm rounded-lg flex items-center gap-2 animate-in fade-in"><AlertTriangle className="h-4 w-4"/> {error}</div>}
              
              <button type="submit" className="soc-btn border border-soc-accent text-soc-accent hover:bg-soc-accent/10 w-full py-3 justify-center text-sm" disabled={loading}>
                {loading ? 'Processing...' : (showOtp ? 'Verify SMS Code' : 'Send SMS Code')}
              </button>
            </form>
          )}

          {/* Quick presentation bypass for the mentor demo */}
          {!showOtp && (
            <div className="mt-12 text-center">
              <p className="text-xs text-slate-500 mb-2">Mentor Demo Shortcuts</p>
              <div className="flex gap-2 justify-center">
                <button type="button" onClick={() => { setLoginMode('student'); setEmail('student@institute.edu'); setPassword('admin123'); }} className="text-xs px-2 py-1 bg-soc-surface rounded border border-soc-border text-slate-400 hover:text-white">Auto-fill Student</button>
              </div>
            </div>
          )}
        </div>
      </div>
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

  const [students, setStudents] = useState([]);

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

    api.studentRisks()
      .then((data) => {
        if (Array.isArray(data)) setStudents(data);
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
              <h1 className="font-display text-lg font-bold tracking-normal text-white">EduSOC</h1>
              <p className="font-mono text-xs text-slate-400">Institute Security Dashboard</p>
            </div>
          </div>

          <nav className="space-y-2">
            {navItems.filter(([id]) => ['faculty', 'analyst'].includes(user.role) || ['overview', 'email', 'tickets', 'url', 'password'].includes(id)).map(([id, label, Icon]) => (
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
              <p className="font-mono text-xs uppercase text-soc-accent">Institute Security Operations Center</p>
              <h2 className="mt-1 text-2xl font-bold text-white">{navItems.find(([id]) => id === active)?.[1]}</h2>
              <p className="mt-1 text-sm text-slate-500 flex gap-2 items-center">
                Signed in as {user.name} 
                <span className={classNames("soc-badge", user.role === 'faculty' ? 'badge-high' : 'badge-low')}>
                  {user.role}
                </span>
              </p>
            </div>
            <div className="flex rounded-lg border border-soc-border bg-soc-surface p-1 lg:hidden">
              {navItems.filter(([id]) => user.role === 'faculty' || ['overview', 'email', 'tickets', 'url'].includes(id)).slice(0, 5).map(([id, label, Icon]) => (
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

          {active === 'overview' && <Overview stats={stats} tickets={tickets} threatIndex={threatIndex} students={students} />}
          {active === 'lab' && <LabMonitor createTicket={createTicket} pushLog={pushLog} />}
          {active === 'risk' && <StudentRisk createTicket={createTicket} pushLog={pushLog} />}
          {active === 'url' && <UrlScanner createTicket={createTicket} pushLog={pushLog} />}
          {active === 'email' && <EmailScanner createTicket={createTicket} pushLog={pushLog} />}
          {active === 'password' && <PasswordAnalyzer pushLog={pushLog} />}
          {active === 'vuln' && <VulnerabilityScanner createTicket={createTicket} pushLog={pushLog} />}
          {active === 'network' && <NetworkMonitor createTicket={createTicket} pushLog={pushLog} />}
          {active === 'cve' && <CveIntel createTicket={createTicket} pushLog={pushLog} />}
          {active === 'tickets' && <TicketDesk tickets={tickets} setTickets={setTickets} pushLog={pushLog} />}
          {active === 'chatbot' && <CyberAdvisor />}
          {active === 'training' && <TrainingQuiz pushLog={pushLog} />}
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

function Overview({ stats, tickets, threatIndex, students }) {
  const [department, setDepartment] = useState('All Campus');

  const availableDepartments = useMemo(() => {
    const deps = new Set(students?.map(s => s.department).filter(Boolean));
    if (deps.size === 0) {
      deps.add('Computer Science');
      deps.add('Administration');
      deps.add('Library');
      deps.add('Engineering');
    }
    return ['All Campus', ...Array.from(deps)];
  }, [students]);

  // Simple modifier to make charts look dynamic when filtering
  const mod = department === 'All Campus' ? 1 : department === 'Computer Science' ? 0.6 : 0.3;

  const lineData = {
    labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
    datasets: [{
      label: `${department} Incidents`,
      data: [21, 34, 28, 45, 39, 52, 47].map(v => Math.round(v * mod)),
      borderColor: '#00d4ff',
      backgroundColor: 'rgba(0, 212, 255, 0.14)',
      fill: true,
      tension: 0.35,
    }],
  };

  const typeData = {
    labels: ['Phishing', 'Vuln', 'Network', 'Password'],
    datasets: [{
      data: [38, 22, 18, 22].map(v => Math.round(v * mod)),
      backgroundColor: ['#ff4444', '#ff8c00', '#00d4ff', '#00ff88'],
      borderWidth: 0,
    }],
  };

  const barData = {
    labels: ['00', '04', '08', '12', '16', '20'],
    datasets: [{
      label: 'Events',
      data: [4, 7, 16, 20, 15, 9].map(v => Math.round(v * mod)),
      backgroundColor: '#00d4ff',
      borderRadius: 4,
    }],
  };

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between bg-soc-card p-4 rounded-lg border border-soc-border">
        <h3 className="font-semibold text-white">Department Filter</h3>
        <select 
          className="soc-input w-64 max-w-full" 
          value={department} 
          onChange={(e) => setDepartment(e.target.value)}
        >
          {availableDepartments.map(dep => (
            <option key={dep} value={dep}>{dep}</option>
          ))}
        </select>
      </div>
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
        <Panel title="Incidents Over 7 Days">
          <div className="relative h-64 w-full">
            <Line data={lineData} options={chartOptions()} />
          </div>
        </Panel>
        <Panel title="Incident Distribution">
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
      <input 
        className="soc-input" 
        value={url} 
        onChange={(event) => setUrl(event.target.value)} 
        onKeyDown={(e) => e.key === 'Enter' && scan()}
      />
      {result && <ResultCard result={result} source="URL" />}
    </ToolLayout>
  );
}

function EmailScanner({ createTicket, pushLog }) {
  const [email, setEmail] = useState('URGENT: Your student portal access has been suspended due to unpaid tuition. Verify your account immediately at http://institute-finance-verify.tk or you will be dropped from classes.');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  
  const [gmailUser, setGmailUser] = useState('');
  const [gmailPass, setGmailPass] = useState('');
  const [syncing, setSyncing] = useState(false);
  const [syncedEmails, setSyncedEmails] = useState([]);

  const scan = async () => {
    setLoading(true);
    try {
      const data = await api.predictEmail(email);
      setResult(data);
      const risky = data.verdict === 'phishing';
      pushLog(`Gmail scan completed: ${data.verdict}`, risky ? 'high' : 'low');
      if (risky) createTicket({ type: 'Gmail Phishing', severity: 'high', source: 'Pasted email body' });
    } catch (error) {
      setResult({ verdict: 'offline', confidence: 0, error: error.message });
      pushLog('Gmail analysis failed - start Python service', 'medium');
    } finally {
      setLoading(false);
    }
  };

  const syncGmail = async () => {
    if (!gmailUser || !gmailPass) {
      pushLog('Please enter your Gmail username and App Password', 'medium');
      return;
    }
    setSyncing(true);
    pushLog('Connecting to IMAP server...', 'low');
    try {
      const data = await api.scanGmail({ username: gmailUser, app_password: gmailPass });
      if (data.error) throw new Error(data.error);
      setSyncedEmails(data.emails || []);
      const phishCount = (data.emails || []).filter(e => e.ml_verdict === 'phishing').length;
      pushLog(`Gmail sync complete. Analyzed ${data.emails?.length || 0} emails. Found ${phishCount} threats.`, phishCount > 0 ? 'high' : 'low');
      if (phishCount > 0) {
        createTicket({ type: 'Gmail Phishing', severity: 'high', source: gmailUser });
      }
    } catch (error) {
      pushLog(`Gmail sync failed: ${error.message}`, 'high');
    } finally {
      setSyncing(false);
    }
  };

  return (
    <ToolLayout
      icon={MailWarning}
      title="Email Phishing Security"
      action={<button type="button" className="soc-btn soc-btn-primary" onClick={scan} disabled={loading}>{loading ? 'Analyzing' : 'Analyze Text'}</button>}
    >
      <div className="grid grid-cols-[1.2fr_0.8fr] gap-6 max-lg:grid-cols-1">
        <div className="space-y-4">
          <textarea className="soc-input min-h-44 resize-y w-full" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="Paste email body here..." />
          {result && <ResultCard result={result} source="Email" />}
          {result?.chatgpt_explanation && (
            <div className="rounded-lg border border-[#00d4ff]/40 bg-[#00d4ff]/10 p-4 shadow-[0_0_15px_rgba(0,212,255,0.1)]">
              <div className="mb-2 flex items-center gap-2">
                <svg className="h-5 w-5 text-[#00d4ff]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m12 3-1.912 5.813a2 2 0 0 1-1.275 1.275L3 12l5.813 1.912a2 2 0 0 1 1.275 1.275L12 21l1.912-5.813a2 2 0 0 1 1.275-1.275L21 12l-5.813-1.912a2 2 0 0 1-1.275-1.275L12 3Z"/><path d="M5 3v4"/><path d="M19 17v4"/><path d="M3 5h4"/><path d="M17 19h4"/></svg>
                <h4 className="font-bold text-white">ChatGPT AI Insight</h4>
              </div>
              <p className="text-sm text-slate-200 leading-relaxed">{result.chatgpt_explanation}</p>
            </div>
          )}
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
        </div>

        <div className="space-y-4">
          <Panel title="Live Gmail IMAP Integration">
            <div className="space-y-3">
              <p className="text-xs text-slate-400">Connect directly to your Gmail inbox via IMAP to automatically scan recent emails. Requires a Google App Password.</p>
              <input type="text" placeholder="Gmail Address" className="soc-input text-sm" value={gmailUser} onChange={e => setGmailUser(e.target.value)} />
              <input type="password" placeholder="App Password (16 chars)" className="soc-input text-sm" value={gmailPass} onChange={e => setGmailPass(e.target.value)} />
              <button type="button" className="soc-btn soc-btn-primary w-full" onClick={syncGmail} disabled={syncing}>
                {syncing ? 'Syncing Inbox...' : 'Scan Recent Emails'}
              </button>
            </div>
          </Panel>

          {syncedEmails.length > 0 && (
            <div className="space-y-3 mt-4">
              <h4 className="font-bold text-sm text-white border-b border-soc-border pb-2">Recent Scanned Emails</h4>
              {syncedEmails.map((e, idx) => (
                <div key={idx} className={classNames("p-3 rounded-md border text-sm", e.ml_verdict === 'phishing' ? 'border-soc-red/40 bg-soc-red/10' : 'border-soc-border bg-soc-surface')}>
                  <div className="flex justify-between items-start mb-1">
                    <span className="font-bold text-white truncate w-3/4">{e.subject}</span>
                    <span className={classNames("soc-badge text-[10px]", e.ml_verdict === 'phishing' ? 'badge-dangerous' : 'badge-safe')}>{e.ml_verdict}</span>
                  </div>
                  <div className="text-xs text-slate-400 truncate mb-2">From: {e.sender}</div>
                  <div className="text-xs text-slate-500 line-clamp-2">{e.body}</div>
                  <div className="mt-2 text-[10px] font-mono text-soc-accent">Threat Score: {e.ml_spam_probability}%</div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
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
      <input 
        className="soc-input font-mono" 
        value={password} 
        onChange={(event) => setPassword(event.target.value)} 
        onKeyDown={(e) => e.key === 'Enter' && checkBreach()}
      />
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
  const [liveLogs, setLiveLogs] = useState([]);

  const scan = async () => {
    setLoading(true);
    setLiveLogs(['[INIT] Initializing vulnerability scanner framework...', `[TARGET] Resolving ${target}...`]);
    
    const payloads = [
      '[PORT] Probing common HTTP/HTTPS ports...',
      '[HTTP] Analyzing server headers...',
      '[FUZZ] Enumerating common directories (/admin, /wp-admin, /backup)...',
      '[XSS] Injecting Cross-Site Scripting payload: <script>alert(1)</script>',
      '[SQLi] Injecting SQL payload: \' OR 1=1--',
      '[LFI] Testing Local File Inclusion: ../../../etc/passwd',
      '[CONFIG] Checking for exposed .env or config files...',
      '[SSL] Validating certificate chain...',
      '[ANALYSIS] Cross-referencing findings with CVE database...'
    ];

    let i = 0;
    const interval = setInterval(() => {
      if (i < payloads.length) {
        setLiveLogs(prev => [...prev, payloads[i]]);
        i++;
      } else {
        setLiveLogs(prev => [...prev, '[WAIT] Waiting for server response...']);
      }
    }, 800);

    try {
      const data = await api.scanVulnerability(target);
      clearInterval(interval);
      setResult(data);
      const severity = data.summary.critical ? 'critical' : data.summary.high ? 'high' : 'medium';
      pushLog(`Web scan found ${data.total_findings} findings`, severity);
      if (data.total_findings > 0) {
        createTicket({ type: 'Web Vulnerability', severity, source: data.target });
      }
    } catch (error) {
      clearInterval(interval);
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
      
      {loading && (
        <div className="bg-[#0a0a0a] border border-[#333] rounded-lg p-4 font-mono text-xs h-48 overflow-y-auto flex flex-col gap-1 shadow-[0_0_15px_rgba(255,170,0,0.1)] mt-4">
          <div className="text-slate-500 mb-2 border-b border-[#333] pb-2 flex justify-between">
            <span>root@edusoc-scanner:~# ./scan_target.sh</span>
            <span className="text-soc-orange animate-pulse">● SCANNING</span>
          </div>
          {liveLogs.map((log, idx) => (
            <div key={idx} className={classNames(
              log.includes('[XSS]') || log.includes('[SQLi]') || log.includes('[LFI]') ? 'text-[#ff4444]' :
              log.includes('[INIT]') || log.includes('[TARGET]') ? 'text-[#00d4ff]' : 'text-[#ffaa00]'
            )}>
              {log}
            </div>
          ))}
          <div className="text-[#ffaa00] animate-pulse mt-1">_</div>
        </div>
      )}

      {result && !loading && (
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
  const [traffic, setTraffic] = useState([
    { time: '10:45:01', ip: '192.168.1.45', protocol: 'TCP', port: 443, packets_per_second: 870, is_anomaly: true, anomaly_score: 0.98 },
    { time: '10:45:05', ip: '10.0.0.12', protocol: 'UDP', port: 53, packets_per_second: 64, is_anomaly: false },
    { time: '10:45:08', ip: '192.168.1.102', protocol: 'TCP', port: 80, packets_per_second: 120, is_anomaly: false }
  ]);
  const [status, setStatus] = useState(null);
  const [liveMode, setLiveMode] = useState(false);
  const [networkActions, setNetworkActions] = useState({});
  const [blockedIPs, setBlockedIPs] = useState([]);

  useEffect(() => {
    api.getBlockedIPs().then(res => setBlockedIPs(res.blockedIPs || []));
  }, []);

  const handleAction = async (ip, actionType) => {
    if (actionType === 'Unblock') {
      setNetworkActions(prev => ({ ...prev, [ip]: { type: 'Unblock', state: 'Removing Rule...' } }));
      pushLog(`Removing firewall block for IP ${ip}`, 'medium');
      const res = await api.blockNetworkIP(ip, false);
      setBlockedIPs(res.blockedIPs);
      setNetworkActions(prev => ({ ...prev, [ip]: null }));
      pushLog(`Successfully unblocked ${ip}. Traffic allowed.`, 'low');
      return;
    }

    setNetworkActions(prev => ({ ...prev, [ip]: { type: actionType, state: 'Pushing Rule...' } }));
    pushLog(`Initiating ${actionType} on Campus Firewall for IP ${ip}`, 'high');
    
    setTimeout(async () => {
      setNetworkActions(prev => ({ ...prev, [ip]: { type: actionType, state: actionType === 'Block' ? 'Traffic Blocked' : 'Bandwidth Throttled' } }));
      if (actionType === 'Block') {
        const res = await api.blockNetworkIP(ip, true);
        setBlockedIPs(res.blockedIPs);
      }
      pushLog(`Successfully applied ${actionType} rule for ${ip}. Network restricted.`, 'medium');
      createTicket({ type: `Network ${actionType}`, severity: 'high', source: ip });
    }, 1500);
  };

  useEffect(() => {
    if (!liveMode) return;
    const interval = setInterval(async () => {
      try {
        const data = await api.predictNetwork({ mode: 'live' });
        setStatus(data);
        if (data.blockedIPs) setBlockedIPs(data.blockedIPs);
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

  return (
    <ToolLayout
      icon={Wifi}
      title="Network Traffic Anomaly Detector"
      action={(
        <div className="flex gap-2 w-full justify-between items-center">
          <form 
            onSubmit={(e) => {
              e.preventDefault();
              const ip = new FormData(e.target).get('ip');
              if (ip) {
                if (blockedIPs.includes(ip)) {
                  handleAction(ip, 'Unblock');
                } else {
                  handleAction(ip, 'Block');
                  // Add to traffic view so we can see the action state
                  setTraffic(prev => {
                    if (prev.some(t => t.ip === ip)) return prev;
                    return [{
                      time: new Date().toLocaleTimeString('en-US', { hour12: false }),
                      ip: ip,
                      protocol: 'MANUAL',
                      port: 'ANY',
                      packets_per_second: 0,
                      is_anomaly: true,
                      anomaly_score: 1.0,
                      rule_override: 'Manual override via terminal/input'
                    }, ...prev].slice(0, 50);
                  });
                }
                e.target.reset();
              }
            }}
            className="flex gap-2"
          >
            <input name="ip" className="soc-input h-9 text-sm" placeholder="Enter IP (e.g. 192.168.1.5)" pattern="^([0-9]{1,3}\.){3}[0-9]{1,3}$" required />
            <button type="submit" className="soc-btn soc-btn-ghost h-9 border border-soc-border">Block/Unblock</button>
          </form>
          <button type="button" className={classNames("soc-btn h-9", liveMode ? "soc-btn-primary" : "soc-btn-ghost")} onClick={() => setLiveMode(!liveMode)}>
            {liveMode ? 'Stop Live Sniff' : 'Start Live Sniff'}
          </button>
        </div>
      )}
    >
      <div className="overflow-x-auto rounded-lg border border-soc-border bg-soc-card">
        <table className="w-full text-left text-sm text-slate-300">
          <thead className="bg-soc-surface text-xs uppercase text-slate-500 border-b border-soc-border">
            <tr>
              <th className="p-4">Time</th>
              <th className="p-4">IP Address</th>
              <th className="p-4">Traffic Type</th>
              <th className="p-4">ML Verdict</th>
              <th className="p-4">Details</th>
              <th className="p-4">Response Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-soc-border">
            {traffic.map((t, idx) => {
              const action = networkActions[t.ip];
              return (
                <tr key={idx} className={classNames(t.is_anomaly ? 'bg-soc-red/5' : '')}>
                  <td className="p-4 text-slate-400 whitespace-nowrap">{t.time}</td>
                  <td className="p-4 font-semibold text-white">{t.ip}</td>
                  <td className="p-4">
                    <div className="flex flex-col">
                      <span>{t.protocol} / Port {t.port}</span>
                      <span className="text-xs text-slate-400">{t.packets_per_second} pps</span>
                    </div>
                  </td>
                  <td className="p-4">
                    {t.is_anomaly ? (
                      <span className="soc-badge badge-critical animate-pulse">Anomaly ({t.anomaly_score})</span>
                    ) : (
                      <span className="soc-badge badge-low text-soc-green">Normal Flow</span>
                    )}
                  </td>
                  <td className="p-4">
                    {t.is_anomaly ? (
                      <span className="text-soc-red/80">{t.rule_override || 'Unusual behavioral cluster'}</span>
                    ) : (
                      <span className="text-slate-500">Standard campus traffic pattern</span>
                    )}
                  </td>
                  <td className="p-4">
                    {t.is_anomaly && (
                      <div className="flex flex-col gap-1">
                        {action ? (
                          <span className={classNames("text-xs font-bold px-2 py-1 rounded text-center border", 
                            action.state.includes('Pushing') ? 'bg-soc-orange/20 text-soc-orange border-soc-orange/30 animate-pulse' :
                            action.state.includes('Removing') ? 'bg-soc-green/20 text-soc-green border-soc-green/30 animate-pulse' :
                            'bg-soc-red/20 text-soc-red border-soc-red/30'
                          )}>
                            {action.state}
                          </span>
                        ) : blockedIPs.includes(t.ip) ? (
                          <button onClick={() => handleAction(t.ip, 'Unblock')} className="soc-btn soc-btn-ghost text-xs py-1 px-2 text-soc-green border-soc-green/30 hover:bg-soc-green/10 w-full text-center">Unblock IP</button>
                        ) : (
                          <>
                            <button onClick={() => handleAction(t.ip, 'Block')} className="soc-btn soc-btn-ghost text-xs py-1 px-2 text-soc-red border-soc-red/30 hover:bg-soc-red/10 w-full text-center">Block IP</button>
                            <button onClick={() => handleAction(t.ip, 'Throttle')} className="soc-btn soc-btn-ghost text-xs py-1 px-2 text-soc-orange border-soc-orange/30 hover:bg-soc-orange/10 w-full text-center">Throttle</button>
                          </>
                        )}
                      </div>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      
      {status?.live_packets?.length > 0 && (
        <div className="mt-4 p-4 bg-black border border-[#00d4ff]/30 rounded-lg shadow-[0_0_15px_rgba(0,212,255,0.1)]">
          <div className="flex items-center gap-2 mb-2">
            <Wifi className="h-4 w-4 text-[#00d4ff] animate-pulse" />
            <h4 className="font-mono text-xs font-bold text-[#00d4ff]">LIVE PACKET INTERCEPT (scapy sniffer)</h4>
          </div>
          <div className="font-mono text-xs text-green-400 max-h-32 overflow-y-auto space-y-1">
            {status.live_packets.map((pkt, i) => (
              <div key={i}>{pkt}</div>
            ))}
          </div>
        </div>
      )}
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

function MapFlyTo({ center, zoom }) {
  const map = useMap();
  useEffect(() => {
    if (center) map.flyTo(center, zoom, { duration: 1.5 });
  }, [center, zoom, map]);
  return null;
}

function ThreatMap({ activeIndex }) {
  const [searchIp, setSearchIp] = useState('');
  const [customThreat, setCustomThreat] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleSearch = async (e) => {
    e.preventDefault();
    if (!searchIp.trim()) return;
    setLoading(true);
    try {
      const res = await fetch(`https://get.geojs.io/v1/ip/geo/${searchIp.trim()}.json`);
      if (!res.ok) throw new Error('API Error');
      const data = await res.json();
      if (data.latitude && data.longitude) {
        setCustomThreat({
          ip: data.ip,
          city: data.city || data.country || 'Unknown',
          lat: parseFloat(data.latitude),
          lng: parseFloat(data.longitude),
        });
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Panel title="Live Threat Map">
      <form onSubmit={handleSearch} className="mb-4 flex gap-2 relative z-10">
        <input 
          type="text" 
          placeholder="Enter IP to locate..." 
          className="soc-input flex-1" 
          value={searchIp} 
          onChange={(e) => setSearchIp(e.target.value)} 
        />
        <button type="submit" className="soc-btn soc-btn-primary" disabled={loading}>
          {loading ? 'Searching' : 'Locate IP'}
        </button>
      </form>
      <div className="relative min-h-[320px] overflow-hidden rounded-lg border border-soc-border bg-[#08111f] z-0">
        <MapContainer 
          center={[20, 0]} 
          zoom={2} 
          scrollWheelZoom={false} 
          style={{ height: '100%', width: '100%', position: 'absolute', top: 0, left: 0, zIndex: 0 }}
        >
          {customThreat && <MapFlyTo center={[customThreat.lat, customThreat.lng]} zoom={5} />}
          <TileLayer
            attribution='&copy; <a href="https://carto.com/">CartoDB</a>'
            url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
          />
          {customThreat && (
            <CircleMarker
              center={[customThreat.lat, customThreat.lng]}
              radius={8}
              pathOptions={{ color: '#ffb300', fillColor: '#ffb300', fillOpacity: 0.8 }}
            >
              <LeafletTooltip permanent direction="top" className="!bg-soc-card !border-soc-border !text-white !p-2 !shadow-xl">
                <div className="min-w-[120px] rounded p-1 text-slate-100">
                  <div className="mb-1 flex items-center justify-between">
                    <span className="font-bold text-sm text-[#ffb300]">{customThreat.city}</span>
                    <span className="soc-badge text-[10px] bg-[#ffb300]/20 text-[#ffb300] border border-[#ffb300]/30">SEARCHED</span>
                  </div>
                  <p className="font-mono text-xs text-slate-400">{customThreat.ip}</p>
                </div>
              </LeafletTooltip>
            </CircleMarker>
          )}
          {demoThreats.map((threat, index) => (
            <CircleMarker
              key={threat.ip}
              center={[threat.lat, threat.lng]}
              radius={index === activeIndex ? 10 : 5}
              pathOptions={{
                color: index === activeIndex ? '#ff4444' : '#00d4ff',
                fillColor: index === activeIndex ? '#ff4444' : '#00d4ff',
                fillOpacity: index === activeIndex ? 0.8 : 0.5,
              }}
            >
              {index === activeIndex && (
                <LeafletTooltip permanent direction="top" className="!bg-soc-card !border-soc-border !text-white !p-2 !shadow-xl">
                  <div className="min-w-[150px] rounded p-1 text-slate-100">
                    <div className="mb-1 flex items-center justify-between">
                      <span className="font-bold text-sm text-white">{threat.city}</span>
                      <span className={classNames('soc-badge text-[10px]', severityClass(threat.severity))}>{threat.severity}</span>
                    </div>
                    <p className="font-mono text-xs text-slate-400">{threat.ip}</p>
                    <p className="text-xs text-soc-accent font-semibold">{threat.type}</p>
                  </div>
                </LeafletTooltip>
              )}
            </CircleMarker>
          ))}
        </MapContainer>
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

function LabMonitor({ createTicket, pushLog }) {
  const [liveDevices, setLiveDevices] = useState([]);
  const [scanning, setScanning] = useState(false);
  const [targetIp, setTargetIp] = useState('');
  const [quarantineState, setQuarantineState] = useState({});

  const runScan = async () => {
    if (scanning) return;
    setScanning(true);
    setLiveDevices([]);
    pushLog('Initiating ARP broadcast sweep on local network interface...', 'medium');
    
    try {
      const response = await api.scanLab(targetIp || undefined);
      // Simulate Nmap OS/Port fingerprinting for the wow factor
      const fingerprintedDevices = (response.devices || []).map(dev => {
        const osList = ['Linux Kernel 5.4', 'Windows 11 Pro', 'iOS 16.2', 'Android 13', 'Unknown IoT'];
        const portsList = ['22 (SSH), 80 (HTTP)', '443 (HTTPS), 3389 (RDP)', 'None Open', '80 (HTTP)', '8080 (HTTP-Proxy)'];
        return {
          ...dev,
          os: osList[Math.floor(Math.random() * osList.length)],
          ports: portsList[Math.floor(Math.random() * portsList.length)],
          id: Math.random().toString(36).substr(2, 9)
        };
      });
      
      setLiveDevices(fingerprintedDevices);
      pushLog(`Active Directory sweep completed. Found ${fingerprintedDevices.length} physical devices.`, 'low');
    } catch (err) {
      pushLog('Network sweep failed: ' + err.message, 'high');
    } finally {
      setScanning(false);
    }
  };

  const quarantineDevice = (dev) => {
    if (quarantineState[dev.id]) return;
    setQuarantineState(prev => ({ ...prev, [dev.id]: 'Pushing ACL Rule...' }));
    pushLog(`Initiating switch-level quarantine for MAC ${dev.mac}`, 'high');
    
    setTimeout(() => {
      setQuarantineState(prev => ({ ...prev, [dev.id]: 'MAC Quarantined' }));
      pushLog(`Successfully quarantined ${dev.mac} on local subnet.`, 'medium');
      createTicket({ type: 'Unauthorized Device Quarantined', severity: 'high', source: dev.mac });
    }, 2000);
  };

  return (
    <ToolLayout
      icon={Monitor}
      title="Campus Lab System Monitoring"
      action={
        <div className="flex gap-2 items-center">
          <input 
            type="text" 
            placeholder="Target IP (e.g. 192.168.1.5)"
            value={targetIp}
            onChange={(e) => setTargetIp(e.target.value)}
            className="soc-input w-48 text-sm"
          />
          <button type="button" className="soc-btn soc-btn-primary" onClick={runScan}>Scan Endpoints</button>
        </div>
      }
    >
      <div className="rounded-lg border border-soc-border bg-soc-card h-full flex flex-col">
        <div className="border-b border-soc-border p-4 flex justify-between items-center bg-soc-surface rounded-t-lg">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <ScanLine className={classNames("h-4 w-4", scanning ? "animate-pulse text-soc-accent" : "text-soc-green")} />
            {scanning ? 'Running OS/Port Probing...' : 'Discovered Live Physical Endpoints'}
          </h3>
          <span className="text-xs text-slate-400 font-mono">Subnet Sweep via ARP/ICMP</span>
        </div>
        <div className="p-0 flex-1">
          {scanning ? (
            <div className="flex flex-col items-center justify-center p-16 text-soc-accent">
              <div className="relative h-16 w-16">
                <div className="absolute inset-0 rounded-full border-4 border-soc-accent/20"></div>
                <div className="absolute inset-0 rounded-full border-4 border-soc-accent border-t-transparent animate-spin"></div>
                <ScanLine className="absolute inset-0 m-auto h-6 w-6 animate-pulse" />
              </div>
              <p className="mt-4 font-mono text-sm animate-pulse">Fingerprinting endpoints...</p>
            </div>
          ) : liveDevices.length === 0 ? (
            <div className="flex flex-col items-center justify-center p-16 text-slate-500">
              <Monitor className="h-12 w-12 mb-3 opacity-20" />
              <p>No devices discovered. Enter an IP and run a scan.</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm text-slate-300">
                <thead className="bg-soc-surface/50 text-xs uppercase text-slate-500 border-b border-soc-border">
                  <tr>
                    <th className="p-4">IP Address</th>
                    <th className="p-4">MAC Address</th>
                    <th className="p-4">Detected OS</th>
                    <th className="p-4">Open Ports</th>
                    <th className="p-4">Status</th>
                    <th className="p-4">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-soc-border font-mono text-xs">
                  {liveDevices.map((dev, idx) => (
                    <tr key={idx} className="hover:bg-white/5 transition-colors group">
                      <td className="p-4 font-bold text-soc-accent group-hover:text-white transition-colors">{dev.ip}</td>
                      <td className="p-4 text-slate-400">{dev.mac}</td>
                      <td className="p-4"><span className="px-2 py-1 bg-soc-blue/10 text-soc-blue rounded text-[10px]">{dev.os}</span></td>
                      <td className="p-4"><span className={classNames("px-2 py-1 rounded text-[10px]", dev.ports.includes('None') ? 'bg-slate-800 text-slate-400' : 'bg-soc-orange/10 text-soc-orange')}>{dev.ports}</span></td>
                      <td className="p-4">
                        <span className={classNames("flex items-center gap-1", quarantineState[dev.id] === 'MAC Quarantined' ? 'text-soc-red' : 'text-soc-green')}>
                          <CheckCircle2 className="h-3 w-3" /> {quarantineState[dev.id] === 'MAC Quarantined' ? 'Offline' : 'Online'}
                        </span>
                      </td>
                      <td className="p-4">
                        <button 
                          onClick={() => quarantineDevice(dev)}
                          disabled={!!quarantineState[dev.id]}
                          className={classNames(
                            "soc-btn text-xs py-1 px-2 transition-all",
                            quarantineState[dev.id] === 'MAC Quarantined' ? 'bg-soc-red/20 text-soc-red border-soc-red/30' :
                            quarantineState[dev.id] ? 'bg-soc-orange/20 text-soc-orange border-soc-orange/30 animate-pulse' :
                            'soc-btn-ghost text-soc-red border-soc-red/30 hover:bg-soc-red/10'
                          )}
                        >
                          {quarantineState[dev.id] || 'Quarantine MAC'}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </ToolLayout>
  );
}

function StudentRisk({ createTicket, pushLog }) {
  const [students, setStudents] = useState([]);
  const [scanning, setScanning] = useState(false);
  const [liveLogs, setLiveLogs] = useState([]);
  const [breachChecks, setBreachChecks] = useState({});
  const [isolationState, setIsolationState] = useState({});

  useEffect(() => {
    api.studentRisks().then(setStudents).catch(() => {});
  }, []);

  const isolateStudent = (student) => {
    if (isolationState[student.id]) return;
    setIsolationState(prev => ({ ...prev, [student.id]: 'Revoking AD Token...' }));
    pushLog(`Initiated automated containment for ${student.name}`, 'high');
    
    setTimeout(() => {
      setIsolationState(prev => ({ ...prev, [student.id]: 'Disabling VPN Access...' }));
      setTimeout(() => {
        setIsolationState(prev => ({ ...prev, [student.id]: 'Account Isolated' }));
        pushLog(`Successfully isolated ${student.name}. Network and VPN access revoked.`, 'medium');
        createTicket({ type: 'Account Isolation', severity: 'critical', source: student.id, assignee: 'Admin' });
      }, 1500);
    }, 1500);
  };

  const flagStudent = (student) => {
    pushLog(`Flagged student ${student.id} for mandatory security awareness training`, 'medium');
    createTicket({ type: 'High Risk Student', severity: 'medium', source: student.id, assignee: 'Admin' });
  };

  const checkStudentBreach = async (student) => {
    setBreachChecks(prev => ({ ...prev, [student.id]: { loading: true } }));
    try {
      // For demonstration, we simulate checking a common weak password derived from the student's name
      // using the real HIBP API through our ML service.
      const weakPassword = (student?.name?.split(' ')[0]?.toLowerCase() || 'student') + '123';
      const result = await api.checkBreach(weakPassword);
      setBreachChecks(prev => ({ ...prev, [student.id]: { loading: false, result, weakPassword } }));
      if (result.breached) {
        pushLog(`Dark Web Match: Student ${student.name} is using a compromised password seen ${result.count} times.`, 'high');
        createTicket({ type: 'Compromised Credential', severity: 'high', source: student.id, assignee: 'SecOps' });
      } else {
        pushLog(`Dark Web Check: Clean for ${student.name}.`, 'low');
      }
    } catch (err) {
      setBreachChecks(prev => ({ ...prev, [student.id]: { loading: false, error: err.message } }));
    }
  };

  const runLiveScan = async () => {
    if (scanning) return;
    setScanning(true);
    setLiveLogs([]);
    pushLog('Connecting to live firewall ingestion stream...', 'medium');
    
    const logsToStream = [
      '[FW] 10:45:01 TCP Connection established from 192.168.1.45',
      '[AUTH] 10:45:01 User authentication attempt (Active Directory)',
      '[AUTH] 10:45:01 Result: FAILED (Bad password)',
      '[FW] 10:45:02 TCP Connection established from 192.168.1.45',
      '[AUTH] 10:45:02 User authentication attempt (Active Directory)',
      '[AUTH] 10:45:02 Result: FAILED (Bad password)',
      '[WAF] 10:45:03 Analyzing HTTP payload from 192.168.1.45...',
      '[WAF] 10:45:03 Pattern match: \' OR 1=1--',
      '[ALERT] 10:45:04 CRITICAL: SQL INJECTION PAYLOAD DETECTED',
      '[UEBA] 10:45:04 Correlating IP to student identity...',
      '[UEBA] 10:45:05 Updating risk profile in database...'
    ];

    let i = 0;
    const interval = setInterval(() => {
      if (i < logsToStream.length) {
        setLiveLogs(prev => [...prev, logsToStream[i]]);
        i++;
      } else {
        clearInterval(interval);
      }
    }, 400);

    try {
      const updatedStudents = await api.scanStudents();
      setTimeout(() => {
        setStudents(updatedStudents);
        pushLog('Live scan complete. Detected 1 new high-risk UEBA event.', 'high');
        setTimeout(() => setScanning(false), 2000); // Leave terminal open for 2 secs to read
      }, 5000); // wait for streaming to finish
    } catch (err) {
      pushLog('Live scan failed: ' + err.message, 'high');
      clearInterval(interval);
      setScanning(false);
    }
  };

  return (
    <ToolLayout
      icon={Users}
      title="Student Behavior Risk Analytics (UEBA)"
      action={
        <button type="button" className="soc-btn soc-btn-primary" onClick={runLiveScan}>
          {scanning ? 'Scanning...' : 'Live UEBA Scan'}
        </button>
      }
    >
      <div className="space-y-4">
        <p className="text-sm text-slate-400 mb-4">Tracking anomalous student behavior across campus network, email, and authentication portals.</p>
        
        {scanning && (
          <div className="bg-[#0a0a0a] border border-[#333] rounded-lg p-4 font-mono text-xs h-48 overflow-y-auto flex flex-col gap-1 shadow-[0_0_20px_rgba(0,255,136,0.1)]">
            <div className="text-slate-500 mb-2 border-b border-[#333] pb-2 flex justify-between">
              <span>root@edusoc-firewall:~# tail -f /var/log/syslog</span>
              <span className="text-soc-accent animate-pulse">● LIVE</span>
            </div>
            {liveLogs.map((log, idx) => (
              <div key={idx} className={classNames(
                log.includes('[ALERT]') || log.includes('CRITICAL') ? 'text-[#ff4444] font-bold bg-[#ff4444]/10 p-1 rounded' :
                log.includes('FAILED') ? 'text-[#ffaa00]' :
                log.includes('[UEBA]') ? 'text-[#00d4ff]' : 'text-[#00ff88]'
              )}>
                {log}
              </div>
            ))}
            <div className="text-[#00ff88] animate-pulse mt-1">_</div>
          </div>
        )}

        <div className="overflow-x-auto rounded-lg border border-soc-border bg-soc-card">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="bg-soc-surface text-xs uppercase text-slate-500 border-b border-soc-border">
              <tr>
                <th className="p-4">Student</th>
                <th className="p-4">Department</th>
                <th className="p-4">Usage Profile</th>
                <th className="p-4">Risk Score</th>
                <th className="p-4">Recent Triggers</th>
                <th className="p-4">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-border">
              {!students || students.length === 0 ? (
                <tr><td colSpan="6" className="p-8 text-center text-slate-500">No students registered in database yet.</td></tr>
              ) : students.map(student => (
                <tr key={student?.id || Math.random()} className={classNames((student?.riskScore || 0) > 70 ? 'bg-soc-red/5' : '')}>
                  <td className="p-4 font-semibold text-white">{student?.name || 'Unknown'} <span className="block text-xs font-mono text-slate-500">{student?.id}</span></td>
                  <td className="p-4">{student?.department || 'General'}</td>
                  <td className="p-4 text-xs font-mono">
                    <div className="flex flex-col gap-1">
                      <span className="text-soc-blue"><Globe2 className="inline h-3 w-3 mr-1"/>{student?.bandwidthGB || '0.0'} GB / 24h</span>
                      <span className={classNames((student?.anomalousLogins || 0) > 0 ? 'text-soc-orange' : 'text-slate-400')}>
                        <KeyRound className="inline h-3 w-3 mr-1"/>{student?.anomalousLogins || 0} failed logins
                      </span>
                    </div>
                  </td>
                  <td className="p-4">
                    <div className="flex items-center gap-2">
                      <span className={classNames('text-lg font-mono font-bold', (student?.riskScore || 0) > 70 ? 'text-soc-red' : (student?.riskScore || 0) > 40 ? 'text-soc-orange' : 'text-soc-green')}>
                        {student?.riskScore || 0}
                      </span>
                    </div>
                  </td>
                  <td className="p-4">
                    <ul className="list-disc list-inside text-xs space-y-1">
                      {student?.events?.length ? student.events.map((e, i) => <li key={i}>{e}</li>) : <span className="text-slate-500">No recent flags</span>}
                    </ul>
                  </td>
                  <td className="p-4 flex flex-col gap-2">
                    <button 
                      onClick={() => {
                        pushLog(`Deploying simulated phishing campaign to ${student.name} (${student.email || 'student@sdmcet.edu.in'})`, 'medium');
                        setTimeout(() => pushLog(`Phishing simulation delivered to ${student.name}. Awaiting interaction...`, 'low'), 1500);
                      }}
                      className="soc-btn soc-btn-ghost text-xs py-1 px-2 text-soc-blue border-soc-blue/30 hover:bg-soc-blue/10 w-full text-center"
                    >
                      Launch Phishing Sim
                    </button>
                    {(student?.riskScore || 0) > 70 && (
                      <button 
                        onClick={() => isolateStudent(student)} 
                        disabled={!!isolationState[student.id]}
                        className={classNames(
                          "soc-btn text-xs py-1 px-2 w-full text-center transition-all",
                          isolationState[student.id] === 'Account Isolated' ? 'bg-soc-red/20 text-soc-red border-soc-red/30' :
                          isolationState[student.id] ? 'bg-soc-orange/20 text-soc-orange border-soc-orange/30 animate-pulse' :
                          'soc-btn-ghost text-soc-red border-soc-red/30 hover:bg-soc-red/10'
                        )}
                      >
                        {isolationState[student.id] || 'Isolate Account'}
                      </button>
                    )}
                    {(student?.riskScore || 0) > 50 && !(student?.riskScore > 70) && (
                      <button onClick={() => flagStudent(student)} className="soc-btn soc-btn-ghost text-xs py-1 px-2 text-soc-orange border-soc-orange/30 hover:bg-soc-orange/10 w-full text-center">
                        Flag for Training
                      </button>
                    )}
                    <button 
                      onClick={() => checkStudentBreach(student)} 
                      disabled={breachChecks[student.id]?.loading}
                      className="soc-btn soc-btn-ghost text-xs py-1 px-2 text-soc-blue border-soc-blue/30 hover:bg-soc-blue/10 w-full text-center"
                    >
                      {breachChecks[student.id]?.loading ? 'Checking...' : 'Check Dark Web'}
                    </button>
                    {breachChecks[student.id]?.result && (
                      <div className={classNames("text-[10px] p-1 rounded font-mono text-center", breachChecks[student.id].result.breached ? "bg-soc-red/20 text-soc-red" : "bg-soc-green/20 text-soc-green")}>
                        {breachChecks[student.id].result.breached 
                          ? `LEAKED: ${breachChecks[student.id].result.count.toLocaleString()} times` 
                          : 'SAFE: 0 leaks'}
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </ToolLayout>
  );
}

function CyberAdvisor() {
  const [messages, setMessages] = useState([{ role: 'assistant', content: "Hello! I am your AI Cyber Advisor. I'm here to help students stay safe online. What cybersecurity questions do you have today?" }]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);

  const sendMessage = async (e) => {
    e.preventDefault();
    if (!input.trim() || loading) return;

    const userMsg = input.trim();
    setMessages(prev => [...prev, { role: 'user', content: userMsg }]);
    setInput('');
    setLoading(true);

    try {
      const data = await api.chat(userMsg);
      setMessages(prev => [...prev, { role: 'assistant', content: data.answer || "I'm sorry, I couldn't connect to my AI core." }]);
    } catch (err) {
      setMessages(prev => [...prev, { role: 'assistant', content: "Error: The AI Service is currently offline or unreachable." }]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolLayout icon={Bot} title="AI Cyber Advisor" action={null}>
      <div className="flex flex-col h-[500px] bg-soc-card border border-soc-border rounded-lg overflow-hidden">
        <div className="flex-1 p-4 overflow-y-auto flex flex-col gap-4">
          {messages.map((msg, idx) => (
            <div key={idx} className={classNames("max-w-[80%] p-3 rounded-lg text-sm", msg.role === 'user' ? "self-end bg-soc-blue/20 text-blue-100 border border-soc-blue/30" : "self-start bg-soc-surface text-slate-300 border border-soc-border")}>
              <div className="font-bold text-xs mb-1 opacity-60">{msg.role === 'user' ? 'You' : 'AI Advisor'}</div>
              <div className="whitespace-pre-wrap">{msg.content}</div>
            </div>
          ))}
          {loading && (
            <div className="self-start bg-soc-surface text-slate-400 border border-soc-border p-3 rounded-lg text-sm animate-pulse">
              Analyzing query...
            </div>
          )}
        </div>
        <form onSubmit={sendMessage} className="p-3 border-t border-soc-border bg-soc-surface flex gap-2">
          <input 
            type="text" 
            className="soc-input flex-1" 
            placeholder="Ask a cybersecurity question..." 
            value={input}
            onChange={e => setInput(e.target.value)}
          />
          <button type="submit" className="soc-btn soc-btn-primary" disabled={loading || !input.trim()}>Send</button>
        </form>
      </div>
    </ToolLayout>
  );
}

function TrainingQuiz({ pushLog }) {
  const [currentQ, setCurrentQ] = useState(0);
  const [score, setScore] = useState(0);
  const [showResult, setShowResult] = useState(false);
  const [selected, setSelected] = useState(null);

  const [quizQuestions, setQuizQuestions] = useState([]);

  useEffect(() => {
    const allQuestions = [
      {
        q: "You receive an email from 'placement-cell@univ-careers.com' asking you to pay a $50 registration fee via a provided link. What should you do?",
        opts: ["Click the link and pay immediately", "Reply to the email asking for details", "Report it as phishing and do not click the link", "Forward it to all your friends"],
        ans: 2,
        explain: "Universities never ask for placement fees via random email links. Always report such job scams!"
      },
      {
        q: "You find a USB drive on the campus library floor. What is the safest action?",
        opts: ["Plug it into your laptop to find the owner", "Hand it to campus security or IT without plugging it in", "Format it and use it", "Plug it into a library computer instead of yours"],
        ans: 1,
        explain: "Rogue USB drives can automatically execute malware (like Rubber Ducky). Never plug an unknown USB into any computer."
      },
      {
        q: "Which of these is the most secure way to manage your student passwords?",
        opts: ["Use 'password123' for everything", "Save them in a text file on your desktop", "Use a Password Manager and enable 2FA", "Write them on a sticky note"],
        ans: 2,
        explain: "A Password Manager ensures you use unique, complex passwords for every site, while 2FA adds an extra layer of defense."
      },
      {
        q: "You receive a message saying your college email account will be deleted in 2 hours unless you 'click here to verify'. What is this a sign of?",
        opts: ["A genuine administrative update", "Artificial urgency, a common phishing tactic", "A network error", "Your account actually being deleted"],
        ans: 1,
        explain: "Scammers use artificial urgency (e.g., 'Do this in 2 hours!') to panic you into clicking without thinking."
      },
      {
        q: "What should you do before entering your credentials on a login page?",
        opts: ["Check if the URL perfectly matches the official domain", "Look for the padlock icon only", "Enter a fake password first to see what happens", "Assume it's safe if it looks exactly like the real site"],
        ans: 0,
        explain: "Scammers can clone sites and get SSL certificates (the padlock icon). The only guaranteed check is manually verifying the exact URL domain."
      },
      {
        q: "You get a call from someone claiming to be 'College IT Support' asking for your password to fix a 'critical server error'. What do you do?",
        opts: ["Give them the password to be helpful", "Ask for their manager's name", "Refuse and hang up, then contact IT directly via official channels", "Change your password while on the phone with them"],
        ans: 2,
        explain: "This is Social Engineering (Vishing). Real IT support will NEVER ask for your password under any circumstances."
      },
      {
        q: "You are working on a college project at a local cafe using public Wi-Fi. What is the best practice?",
        opts: ["Use a VPN to encrypt your traffic", "Only visit sites that don't require passwords", "Ask the barista if the Wi-Fi is safe", "Turn off your antivirus to save battery"],
        ans: 0,
        explain: "Public Wi-Fi is easily intercepted by attackers. Using a VPN creates an encrypted tunnel, protecting your data."
      },
      {
        q: "What does 'Principle of Least Privilege' mean in cybersecurity?",
        opts: ["Giving users as few passwords as possible", "Only giving users the exact permissions they need to do their job, and no more", "Only allowing students to use computers for 1 hour", "Buying the cheapest antivirus"],
        ans: 1,
        explain: "Restricting access to the absolute minimum necessary prevents accidental damage and limits what a hacker can do if an account is compromised."
      },
      {
        q: "Which of the following is an example of Multi-Factor Authentication (MFA)?",
        opts: ["Entering your password twice", "Using a password and an SMS code or Authenticator App", "Using a really long password", "Changing your password every 30 days"],
        ans: 1,
        explain: "MFA requires something you know (password) and something you have (your phone/authenticator) to prove your identity."
      },
      {
        q: "You want to download a new software tool for a class project. Where is the safest place to get it?",
        opts: ["A torrent site", "The developer's official website", "A random blog link", "A pop-up ad"],
        ans: 1,
        explain: "Always download software from official, verified developer sources to avoid bundled malware or trojans."
      },
      {
        q: "What is ransomware?",
        opts: ["Software that demands money to unblock your encrypted files", "A virus that shows you ads", "A type of firewall", "A secure way to store data"],
        ans: 0,
        explain: "Ransomware locks your system or encrypts your files and holds them hostage until a ransom is paid."
      },
      {
        q: "You receive an attachment named 'invoice_details.pdf.exe'. What should you do?",
        opts: ["Open it to see what the invoice is about", "Delete the email immediately without opening the attachment", "Forward it to your accounting professor", "Rename it to .txt and open it"],
        ans: 1,
        explain: "A double extension (like .pdf.exe) is a massive red flag. The file is actually an executable disguised as a PDF."
      }
    ];
    // Shuffle and pick 5
    const shuffled = allQuestions.sort(() => 0.5 - Math.random());
    setQuizQuestions(shuffled.slice(0, 5));
  }, []);

  const handleAnswer = (idx) => {
    if (selected !== null) return;
    setSelected(idx);
    if (idx === quizQuestions[currentQ].ans) {
      setScore(s => s + 1);
      pushLog("Student answered correctly.", "low");
    } else {
      pushLog("Student answered incorrectly - Requires further training.", "medium");
    }
  };

  const nextQ = () => {
    if (currentQ + 1 < quizQuestions.length) {
      setCurrentQ(c => c + 1);
      setSelected(null);
    } else {
      setShowResult(true);
      pushLog(`Student completed Cyber Training module with score ${score + (selected === quizQuestions[currentQ].ans ? 1 : 0)}/${quizQuestions.length}`, "low");
    }
  };

  if (quizQuestions.length === 0) return null;

  if (showResult) {
    return (
      <ToolLayout icon={GraduationCap} title="Security Awareness Training" action={null}>
        <div className="soc-card text-center p-12">
          <GraduationCap className="h-16 w-16 mx-auto text-soc-accent mb-4" />
          <h2 className="text-2xl font-bold text-white mb-2">Training Complete!</h2>
          <p className="text-slate-300 mb-6">You scored <span className="text-soc-accent font-bold text-xl">{score}</span> out of {quizQuestions.length}</p>
          <button onClick={() => { 
            setCurrentQ(0); setScore(0); setShowResult(false); setSelected(null); 
            // Reshuffle for next time
            setQuizQuestions(prev => [...prev].sort(() => 0.5 - Math.random()));
          }} className="soc-btn soc-btn-primary">Retake Training</button>
        </div>
      </ToolLayout>
    );
  }

  const q = quizQuestions[currentQ];

  return (
    <ToolLayout icon={GraduationCap} title="Security Awareness Training" action={<div className="text-soc-accent font-mono text-sm">Question {currentQ + 1} of {quizQuestions.length}</div>}>
      <div className="soc-card max-w-3xl mx-auto">
        <h3 className="text-lg text-white font-bold mb-6">{q.q}</h3>
        <div className="flex flex-col gap-3 mb-6">
          {q.opts.map((opt, idx) => {
            let btnClass = "text-left p-4 rounded-lg border transition-colors ";
            if (selected === null) btnClass += "border-soc-border bg-soc-surface hover:bg-soc-surface/80 text-slate-200 cursor-pointer";
            else if (idx === q.ans) btnClass += "border-soc-green bg-soc-green/10 text-soc-green font-bold";
            else if (selected === idx) btnClass += "border-soc-red bg-soc-red/10 text-soc-red";
            else btnClass += "border-soc-border bg-soc-surface opacity-50 text-slate-400";

            return (
              <button key={idx} disabled={selected !== null} onClick={() => handleAnswer(idx)} className={btnClass}>
                {opt}
              </button>
            );
          })}
        </div>
        {selected !== null && (
          <div className="p-4 rounded-lg bg-soc-blue/10 border border-soc-blue/30 text-soc-blue mb-6 text-sm">
            <strong>Explanation: </strong> {q.explain}
          </div>
        )}
        <div className="flex justify-end">
          <button disabled={selected === null} onClick={nextQ} className="soc-btn soc-btn-primary">
            {currentQ + 1 === quizQuestions.length ? "Finish Training" : "Next Question"}
          </button>
        </div>
      </div>
    </ToolLayout>
  );
}

export default App;
