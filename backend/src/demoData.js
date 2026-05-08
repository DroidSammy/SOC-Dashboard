export const threats = [
  { city: 'Moscow', country: 'RU', lat: 55.75, lng: 37.62, severity: 'high', ip: '185.220.101.42', type: 'Brute force' },
  { city: 'Singapore', country: 'SG', lat: 1.35, lng: 103.82, severity: 'medium', ip: '103.21.244.18', type: 'Phishing host' },
  { city: 'Frankfurt', country: 'DE', lat: 50.11, lng: 8.68, severity: 'low', ip: '45.83.64.12', type: 'Scanner' },
  { city: 'Sao Paulo', country: 'BR', lat: -23.55, lng: -46.63, severity: 'critical', ip: '177.54.148.33', type: 'Malware C2' },
  { city: 'Virginia', country: 'US', lat: 37.43, lng: -78.65, severity: 'medium', ip: '34.201.89.7', type: 'Credential stuffing' },
];

export const cves = [
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

export const weeklyThreats = [21, 34, 28, 45, 39, 52, 47];
export const hourlyActivity = [4, 7, 16, 20, 15, 9];
