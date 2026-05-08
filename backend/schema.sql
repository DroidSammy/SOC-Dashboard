CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  role TEXT NOT NULL DEFAULT 'analyst',
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS incidents (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  severity TEXT NOT NULL,
  status TEXT NOT NULL,
  source TEXT NOT NULL,
  assignee TEXT NOT NULL,
  notes JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS activity (
  id BIGINT PRIMARY KEY,
  text TEXT NOT NULL,
  severity TEXT NOT NULL,
  time TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO users (id, name, email, role, password_hash)
VALUES (
  'user-1',
  'SOC Analyst',
  'analyst@soc.local',
  'analyst',
  '$2a$10$i7I9ELhmjnTugp8dGiO.9.ovKj60T8fEbTCBTPb.kUbpUdGGzpL/O'
)
ON CONFLICT (email) DO NOTHING;

INSERT INTO incidents (id, type, severity, status, source, assignee, notes, created_at, updated_at)
VALUES
  ('SOC-1001', 'Phishing URL', 'high', 'Open', 'paypal-verify-account.tk', 'Analyst A', '["Auto-created from URL detector"]'::jsonb, NOW() - INTERVAL '26 minutes', NOW() - INTERVAL '26 minutes'),
  ('SOC-1002', 'Web Vulnerability', 'medium', 'Investigating', 'test.local', 'Analyst B', '["Missing CSP and HSTS headers"]'::jsonb, NOW() - INTERVAL '67 minutes', NOW() - INTERVAL '18 minutes')
ON CONFLICT (id) DO NOTHING;

INSERT INTO activity (id, text, severity, time)
VALUES
  (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 - 2, 'PostgreSQL store initialized', 'low', NOW() - INTERVAL '8 minutes'),
  (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 - 1, 'Demo analyst account ready', 'low', NOW() - INTERVAL '7 minutes')
ON CONFLICT (id) DO NOTHING;
