import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dataDir = path.resolve(__dirname, '..', 'data');
const dbPath = path.join(dataDir, 'db.json');
const usePostgres = Boolean(process.env.DATABASE_URL);
const pool = usePostgres ? new pg.Pool({ connectionString: process.env.DATABASE_URL }) : null;

const seed = {
  users: [
    {
      id: 'user-1',
      name: 'SOC Analyst',
      email: 'analyst@soc.local',
      role: 'analyst',
      // Password: admin123
      passwordHash: '$2a$10$i7I9ELhmjnTugp8dGiO.9.ovKj60T8fEbTCBTPb.kUbpUdGGzpL/O',
    },
  ],
  incidents: [
    {
      id: 'SOC-1001',
      type: 'Phishing URL',
      severity: 'high',
      status: 'Open',
      source: 'paypal-verify-account.tk',
      assignee: 'Analyst A',
      createdAt: new Date(Date.now() - 1000 * 60 * 26).toISOString(),
      updatedAt: new Date(Date.now() - 1000 * 60 * 26).toISOString(),
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
      updatedAt: new Date(Date.now() - 1000 * 60 * 18).toISOString(),
      notes: ['Missing CSP and HSTS headers'],
    },
  ],
  activity: [
    {
      id: Date.now() - 2,
      text: 'Backend API bootstrapped',
      severity: 'low',
      time: new Date(Date.now() - 1000 * 60 * 8).toISOString(),
    },
    {
      id: Date.now() - 1,
      text: 'Demo incident storage loaded',
      severity: 'low',
      time: new Date(Date.now() - 1000 * 60 * 7).toISOString(),
    },
  ],
};

export async function ensureStore() {
  if (usePostgres) {
    const schema = await readFile(path.resolve(__dirname, '..', 'schema.sql'), 'utf8');
    await pool.query(schema);
    return;
  }

  await mkdir(dataDir, { recursive: true });
  try {
    const raw = await readFile(dbPath, 'utf8');
    const existing = JSON.parse(raw);
    const merged = {
      ...seed,
      ...existing,
      users: existing.users?.length ? existing.users : seed.users,
      incidents: existing.incidents?.length ? existing.incidents : seed.incidents,
      activity: existing.activity?.length ? existing.activity : seed.activity,
    };
    await writeFile(dbPath, JSON.stringify(merged, null, 2));
  } catch {
    await writeFile(dbPath, JSON.stringify(seed, null, 2));
  }
}

export async function readDb() {
  if (usePostgres) {
    await ensureStore();
    const [users, incidents, activity] = await Promise.all([
      pool.query('SELECT id, name, email, role, password_hash AS "passwordHash" FROM users ORDER BY created_at ASC'),
      pool.query(`
        SELECT id, type, severity, status, source, assignee, notes,
               created_at AS "createdAt", updated_at AS "updatedAt"
        FROM incidents
        ORDER BY created_at DESC
      `),
      pool.query('SELECT id, text, severity, time FROM activity ORDER BY time DESC LIMIT 50'),
    ]);
    return {
      users: users.rows,
      incidents: incidents.rows.map(normalizeIncident),
      activity: activity.rows.map((entry) => ({
        ...entry,
        id: Number(entry.id),
        time: new Date(entry.time).toISOString(),
      })),
    };
  }

  await ensureStore();
  const raw = await readFile(dbPath, 'utf8');
  return JSON.parse(raw);
}

export async function writeDb(db) {
  if (usePostgres) {
    await ensureStore();
    await pool.query('DELETE FROM incidents');
    for (const incident of db.incidents || []) {
      await upsertIncident(incident);
    }
    return;
  }

  await mkdir(dataDir, { recursive: true });
  await writeFile(dbPath, JSON.stringify(db, null, 2));
}

export async function addActivity(text, severity = 'low') {
  if (usePostgres) {
    await ensureStore();
    const entry = {
      id: Date.now(),
      text,
      severity,
      time: new Date().toISOString(),
    };
    await pool.query(
      'INSERT INTO activity (id, text, severity, time) VALUES ($1, $2, $3, $4)',
      [entry.id, entry.text, entry.severity, entry.time],
    );
    return entry;
  }

  const db = await readDb();
  const entry = {
    id: Date.now(),
    text,
    severity,
    time: new Date().toISOString(),
  };
  db.activity = [entry, ...(db.activity || [])].slice(0, 50);
  await writeDb(db);
  return entry;
}

export async function createIncident(incident) {
  if (!usePostgres) {
    const db = await readDb();
    db.incidents = [incident, ...db.incidents];
    await writeDb(db);
    return incident;
  }

  await ensureStore();
  await upsertIncident(incident);
  return incident;
}

export async function updateIncident(id, updates) {
  const db = await readDb();
  const index = db.incidents.findIndex((incident) => incident.id === id);
  if (index === -1) return null;

  const existing = db.incidents[index];
  const note = updates.note || (updates.status ? `Status changed to ${updates.status}` : null);
  const updated = {
    ...existing,
    ...updates,
    id: existing.id,
    updatedAt: new Date().toISOString(),
    notes: note ? [note, ...(existing.notes || [])] : existing.notes,
  };
  delete updated.note;

  if (!usePostgres) {
    db.incidents[index] = updated;
    await writeDb(db);
    return updated;
  }

  await upsertIncident(updated);
  return updated;
}

export function nextIncidentId(incidents) {
  const max = incidents.reduce((highest, incident) => {
    const number = Number(String(incident.id).replace('SOC-', ''));
    return Number.isFinite(number) ? Math.max(highest, number) : highest;
  }, 1000);
  return `SOC-${max + 1}`;
}

export function storageMode() {
  return usePostgres ? 'postgresql' : 'json';
}

function normalizeIncident(incident) {
  return {
    ...incident,
    notes: Array.isArray(incident.notes) ? incident.notes : [],
    createdAt: new Date(incident.createdAt).toISOString(),
    updatedAt: new Date(incident.updatedAt).toISOString(),
  };
}

async function upsertIncident(incident) {
  await pool.query(
    `
      INSERT INTO incidents (id, type, severity, status, source, assignee, notes, created_at, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9)
      ON CONFLICT (id) DO UPDATE SET
        type = EXCLUDED.type,
        severity = EXCLUDED.severity,
        status = EXCLUDED.status,
        source = EXCLUDED.source,
        assignee = EXCLUDED.assignee,
        notes = EXCLUDED.notes,
        updated_at = EXCLUDED.updated_at
    `,
    [
      incident.id,
      incident.type,
      incident.severity,
      incident.status,
      incident.source,
      incident.assignee,
      JSON.stringify(incident.notes || []),
      incident.createdAt || new Date().toISOString(),
      incident.updatedAt || new Date().toISOString(),
    ],
  );
}
