import admin from 'firebase-admin';
import { createRequire } from 'module';
import path from 'path';
import { fileURLToPath } from 'url';

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

let db = null;
try {
  const serviceAccount = require('../../firebaseServiceAccount.json');
  if (serviceAccount.project_id !== 'YOUR_PROJECT_ID') {
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
    db = admin.firestore();
    console.log('✅ Connected to Firebase Firestore Database');
  } else {
    console.warn('⚠️ Firebase Service Account not configured. Using placeholder.');
  }
} catch (e) {
  console.warn('⚠️ Firebase Service Account file missing or invalid.');
}

export function storageMode() {
  return db ? 'firestore' : 'offline';
}

export async function addActivity(text, severity = 'low') {
  if (!db) return null;
  const entry = { id: Date.now(), text, severity, time: new Date().toISOString() };
  await db.collection('activity').doc(String(entry.id)).set(entry);
  return entry;
}

export async function createIncident(incident) {
  if (!db) return incident;
  await db.collection('incidents').doc(incident.id).set(incident);
  return incident;
}

export async function updateIncident(id, updates) {
  if (!db) return null;
  const docRef = db.collection('incidents').doc(id);
  const doc = await docRef.get();
  if (!doc.exists) return null;
  
  const existing = doc.data();
  const note = updates.note || (updates.status ? `Status changed to ${updates.status}` : null);
  const updated = {
    ...existing,
    ...updates,
    updatedAt: new Date().toISOString(),
    notes: note ? [note, ...(existing.notes || [])] : existing.notes,
  };
  delete updated.note;
  
  await docRef.set(updated);
  return updated;
}

export function nextIncidentId(incidents) {
  const max = incidents.reduce((highest, incident) => {
    const number = Number(String(incident.id).replace('SOC-', ''));
    return Number.isFinite(number) ? Math.max(highest, number) : highest;
  }, 1000);
  return `SOC-${max + 1}`;
}

export async function createUser(id, name, email, role, hash) {
  if (!db) return;
  await db.collection('users').doc(id).set({ id, name, email, role, passwordHash: hash });
}

export async function getStudents() {
  if (!db) return [];
  const snapshot = await db.collection('users').where('role', '==', 'student').get();
  return snapshot.docs.map(doc => {
    const data = doc.data();
    return { id: data.id, name: data.name, email: data.email };
  });
}

export async function getStudentRisks() {
  if (!db) return [];
  const snapshot = await db.collection('studentRisks').get();
  return snapshot.docs.map(doc => doc.data());
}

export async function saveStudentRisks(risks) {
  if (!db) return;
  const batch = db.batch();
  risks.forEach(risk => {
    const ref = db.collection('studentRisks').doc(risk.id);
    batch.set(ref, risk);
  });
  await batch.commit();
}

export async function getBlockedIPs() {
  if (!db) return [];
  const doc = await db.collection('network').doc('blockedIPs').get();
  return doc.exists ? doc.data().ips || [] : [];
}

export async function toggleBlockIP(ip, block) {
  if (!db) return [];
  const docRef = db.collection('network').doc('blockedIPs');
  const doc = await docRef.get();
  let ips = doc.exists ? doc.data().ips || [] : [];
  
  if (block && !ips.includes(ip)) ips.push(ip);
  else if (!block) ips = ips.filter(i => i !== ip);
  
  await docRef.set({ ips });
  return ips;
}
