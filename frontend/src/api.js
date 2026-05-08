const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:4000';

function authHeaders() {
  const token = localStorage.getItem('soc_token');
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function postJson(path, payload) {
  const response = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(payload),
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || `Request failed: ${response.status}`);
  }
  return data;
}

export const api = {
  login: (email, password) => postJson('/api/auth/login', { email, password }),
  register: (name, email, password) => postJson('/api/auth/register', { name, email, password }),
  me: async () => {
    const response = await fetch(`${API_BASE}/api/auth/me`, { headers: authHeaders() });
    if (!response.ok) throw new Error('Not authenticated');
    return response.json();
  },
  health: async () => {
    const response = await fetch(`${API_BASE}/health`);
    if (!response.ok) throw new Error('Backend service is offline');
    return response.json();
  },
  dashboard: async () => {
    const response = await fetch(`${API_BASE}/api/dashboard`);
    if (!response.ok) throw new Error('Dashboard API failed');
    return response.json();
  },
  incidents: async () => {
    const response = await fetch(`${API_BASE}/api/incidents`);
    if (!response.ok) throw new Error('Incidents API failed');
    return response.json();
  },
  createIncident: (incident) => postJson('/api/incidents', incident),
  updateIncident: async (id, updates) => {
    const response = await fetch(`${API_BASE}/api/incidents/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify(updates),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || 'Incident update failed');
    return data;
  },
  cves: async (keyword) => {
    const response = await fetch(`${API_BASE}/api/cves?keyword=${encodeURIComponent(keyword)}`);
    if (!response.ok) throw new Error('CVE API failed');
    return response.json();
  },
  predictUrl: (url) => postJson('/predict/url', { url }),
  predictEmail: (email_content) => postJson('/predict/email', { email_content }),
  analyzePassword: (password) => postJson('/analyze/password', { password }),
  checkBreach: (password) => postJson('/check/breach', { password }),
  scanVulnerability: (target_url) => postJson('/scan/vulnerability', { target_url }),
  predictNetwork: (features) => postJson('/predict/network', { features }),
  vulnerabilityReport: async (target_url, scan) => {
    const response = await fetch(`${API_BASE}/api/reports/vulnerability`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ target_url, scan }),
    });
    if (!response.ok) throw new Error('Report generation failed');
    return response.blob();
  },
};

export { API_BASE };
