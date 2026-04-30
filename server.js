import express from 'express';
import multer from 'multer';
import { randomUUID } from 'crypto';
import { google } from 'googleapis';
import { getStorage } from 'firebase-admin/storage';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { createServer } from 'http';
import { WebSocketServer } from 'ws';
import speech from '@google-cloud/speech';
import { initializeApp, getApps } from 'firebase-admin/app';
import { getFirestore, FieldValue } from 'firebase-admin/firestore';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

// ── Firebase init ──
if (!getApps().length) initializeApp();
const db = getFirestore();

// ── API usage instrumentation ──
function incrApiStat(service) {
  const key = new Date().toISOString().slice(0, 10);
  db.collection('api_usage').doc(key)
    .set({ [service]: FieldValue.increment(1) }, { merge: true })
    .catch(() => {});
}

// ── Google OAuth config ──
const GOOGLE_CLIENT_ID     = process.env.OAUTH_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET;
const GOOGLE_REDIRECT_URI  = process.env.OAUTH_REDIRECT_URI || `http://localhost:${PORT}/auth/google/callback`;
const ALLOWED_DOMAIN       = 'realworklabs.com';

if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
  console.warn('\n  ⚠️  OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET must be set.\n');
}

function generateToken() {
  return Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2) + Date.now().toString(36);
}

// ── OAuth state (CSRF) ──
const oauthStates = new Map();
function createState() {
  const state = crypto.randomUUID();
  oauthStates.set(state, Date.now());
  for (const [k, t] of oauthStates) if (Date.now() - t > 600_000) oauthStates.delete(k);
  return state;
}
function consumeState(state) {
  const t = oauthStates.get(state);
  if (!t || Date.now() - t > 600_000) return false;
  oauthStates.delete(state);
  return true;
}

function getCookies(req) {
  const cookies = {};
  (req.headers.cookie || '').split(';').forEach(part => {
    const [k, ...v] = part.trim().split('=');
    if (k) cookies[k.trim()] = decodeURIComponent(v.join('='));
  });
  return cookies;
}

// ── Session cache (in-memory, 5 min TTL) to reduce Firestore reads ──
// Stores { expiry, email } per token
const sessionCache = new Map();

async function requireAuth(req, res, next) {
  // Support Bearer token auth (for Meet add-on iframe) in addition to cookies
  const bearerMatch = req.headers.authorization?.match(/^Bearer (.+)$/);
  // Also support token as query param (for SSE which can't set headers)
  const queryToken = req.query?.token;
  const { auth_token: cookie_token } = getCookies(req);
  const auth_token = bearerMatch?.[1] || queryToken || cookie_token;
  const fail = () => {
    if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Unauthorized' });
    res.setHeader('Set-Cookie', `auth_return_to=${encodeURIComponent(req.originalUrl)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600`);
    res.redirect('/login');
  };
  if (!auth_token) return fail();
  const cached = sessionCache.get(auth_token);
  if (cached && cached.expiry > Date.now()) {
    req.userEmail = cached.email;
    return next();
  }
  try {
    const session = await db.collection('sessions').doc(auth_token).get();
    if (!session.exists) { sessionCache.delete(auth_token); return fail(); }
    const email = session.data().email || '';
    sessionCache.set(auth_token, { expiry: Date.now() + 300_000, email });
    req.userEmail = email;
    next();
  } catch { fail(); }
}

// Like requireAuth but never blocks — attaches req.userEmail if session is valid
async function optionalAuth(req, res, next) {
  const { auth_token } = getCookies(req);
  if (!auth_token) return next();
  const cached = sessionCache.get(auth_token);
  if (cached && cached.expiry > Date.now()) {
    req.userEmail = cached.email;
    return next();
  }
  try {
    const session = await db.collection('sessions').doc(auth_token).get();
    if (session.exists) {
      const email = session.data().email || '';
      sessionCache.set(auth_token, { expiry: Date.now() + 300_000, email });
      req.userEmail = email;
    }
  } catch { /* silent */ }
  next();
}


// ── Slack notifications ──
async function sendSlack(blocks) {
  const url = process.env.SLACK_WEBHOOK_URL;
  if (!url) return;
  try {
    await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ blocks }),
    });
  } catch (err) {
    console.error('Slack notify error:', err.message);
    logApiError('slack', err.message || 'Slack notification failed');
  }
}

// ── Audit log ──
async function logAudit(event) {
  try {
    await db.collection('audit_log').add({
      ...event,
      at: FieldValue.serverTimestamp(),
    });
  } catch (err) {
    console.error('audit log error:', err.message);
  }
}

// ── API error log ──
async function logApiError(integration, message, context = {}) {
  try {
    await db.collection('api_error_log').add({
      integration,
      message: String(message).slice(0, 500),
      context,
      at: FieldValue.serverTimestamp(),
    });
  } catch { /* silent — never throw from a logger */ }
}

// ── Firestore helpers ──
function fmtTs(timestamp) {
  if (!timestamp) return null;
  const d = timestamp.toDate ? timestamp.toDate() : new Date(timestamp);
  return d.toISOString().replace('T', ' ').slice(0, 19);
}

function formatLaunch(doc) {
  const d = doc.data();
  return {
    id:               doc.id,
    department:       d.department       || '',
    account_name:     d.account_name     || '',
    domain_name:      d.domain_name      || '',
    contact_name:     d.contact_name     || '',
    email:            d.email            || '',
    phone:            d.phone            || '',
    status:           d.status           || 'new',
    notes:            d.notes            || '',
    industry:         d.industry         || '',
    owner:            d.owner            || '',
    is_renewal:       d.is_renewal       || false,
    archived:         d.archived         || false,
    submitted_by:     d.submitted_by     || '',
    created_at:       fmtTs(d.created_at),
    updated_at:       fmtTs(d.updated_at),
    status_changed_at: fmtTs(d.status_changed_at),
    analytics_start_date: d.analytics_start_date || null,
    duda_site_name:       d.duda_site_name       || null,
    analytics_note:       d.analytics_note       || '',
    google_place_id:      d.google_place_id      || null,
    place_city:           d.place_city           || null,
    custom_favicon:       d.custom_favicon        || null,
    tags:                 d.tags                  || [],
    last_contact_date:    d.last_contact_date     || null,
    outreach_log:         d.outreach_log          || [],
    onboarding_profile:   d.onboarding_profile    || null,
    onboarding_completed_at: fmtTs(d.onboarding_completed_at),
    drive_folder_id:      d.drive_folder_id       || null,
    drive_folder_url:     d.drive_folder_url      || null,
    has_research:         !!d.research_md,
    projects:             d.projects || [],
  };
}

app.use(express.json());
app.use((req, _res, next) => { if (req.method !== 'GET') console.log(`[req] ${req.method} ${req.path}`); next(); });
// ── Auth (public) ──
app.get('/api/pexels-test', async (req, res) => {
  const q = req.query.q || 'HVAC air conditioning';
  const img = await fetchPexelsImage(q);
  res.json({ query: q, keySet: !!process.env.PEXELS_API_KEY, result: img });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ email: req.userEmail || '' });
});

app.get('/login', (_req, res) => res.sendFile(join(__dirname, 'public', 'login.html')));
app.get('/', requireAuth, (_req, res) => res.sendFile(join(__dirname, 'public', 'index.html')));
app.get('/map', requireAuth, (_req, res) => res.sendFile(join(__dirname, 'public', 'map.html')));

// Return Maps API key to authenticated clients
app.get('/api/config/maps-key', requireAuth, async (req, res) => {
  const key = await getPlacesApiKey();
  res.json({ key: key || null });
});

// ── Team Members (active users available for owner assignment) ──
app.get('/api/team-members', requireAuth, async (req, res) => {
  try {
    const doc = await db.collection('config').doc('team_members').get();
    const members = doc.exists ? (doc.data().members || []) : [
      { name: 'Daniel', active: true, addedAt: new Date().toISOString() },
      { name: 'Thierry', active: true, addedAt: new Date().toISOString() },
    ];
    // Seed if missing
    if (!doc.exists) await db.collection('config').doc('team_members').set({ members });
    res.json({ members });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/team-members', requireAuth, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name || typeof name !== 'string' || !name.trim()) return res.status(400).json({ error: 'name is required' });
    const trimmed = name.trim();
    const doc = await db.collection('config').doc('team_members').get();
    const members = doc.exists ? (doc.data().members || []) : [];
    // Check for duplicate (case-insensitive)
    if (members.some(m => m.name.toLowerCase() === trimmed.toLowerCase())) {
      // If they exist but are inactive, reactivate them
      const existing = members.find(m => m.name.toLowerCase() === trimmed.toLowerCase());
      if (!existing.active) {
        existing.active = true;
        await db.collection('config').doc('team_members').set({ members });
        return res.json({ ok: true, reactivated: true, members });
      }
      return res.status(409).json({ error: 'Member already exists' });
    }
    members.push({ name: trimmed, active: true, addedAt: new Date().toISOString() });
    await db.collection('config').doc('team_members').set({ members });
    res.json({ ok: true, members });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/team-members/:name', requireAuth, async (req, res) => {
  try {
    const targetName = decodeURIComponent(req.params.name);
    const { active } = req.body;
    if (typeof active !== 'boolean') return res.status(400).json({ error: 'active (boolean) is required' });
    const doc = await db.collection('config').doc('team_members').get();
    const members = doc.exists ? (doc.data().members || []) : [];
    const member = members.find(m => m.name === targetName);
    if (!member) return res.status(404).json({ error: 'Member not found' });
    member.active = active;
    if (!active) member.deactivatedAt = new Date().toISOString();
    await db.collection('config').doc('team_members').set({ members });
    res.json({ ok: true, members });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Return all launched sites with lat/lng for the map view
app.get('/api/launches/map-data', requireAuth, async (req, res) => {
  try {
    const snap = await db.collection('launches')
      .where('status', '==', 'launched')
      .get();
    const key = await getPlacesApiKey();
    const results = [];
    const updates = [];

    await Promise.all(snap.docs.map(async doc => {
      const d = doc.data();
      let lat = d.lat || null;
      let lng = d.lng || null;

      if ((!lat || !lng) && key) {
        if (d.google_place_id) {
          try {
            const r = await fetch(
              `https://maps.googleapis.com/maps/api/place/details/json?place_id=${encodeURIComponent(d.google_place_id)}&fields=geometry&key=${key}`
            );
            const j = await r.json();
            if (j.result?.geometry?.location) {
              lat = j.result.geometry.location.lat;
              lng = j.result.geometry.location.lng;
              updates.push(doc.ref.update({ lat, lng }));
            }
          } catch {}
        }
        if ((!lat || !lng) && d.place_city) {
          try {
            const r = await fetch(
              `https://maps.googleapis.com/maps/api/geocode/json?address=${encodeURIComponent(d.place_city + ', USA')}&key=${key}`
            );
            const j = await r.json();
            if (j.results?.[0]?.geometry?.location) {
              lat = j.results[0].geometry.location.lat;
              lng = j.results[0].geometry.location.lng;
              updates.push(doc.ref.update({ lat, lng }));
            }
          } catch {}
        }
      }

      // Nominatim fallback (free, no key) — covers SABs with place_city when Google geocoding is unavailable
      if (!lat || !lng) {
        const query = d.place_city || '';
        if (query) {
          try {
            const r = await fetch(
              `https://nominatim.openstreetmap.org/search?format=json&limit=1&countrycodes=us&q=${encodeURIComponent(query)}`,
              { headers: { 'User-Agent': 'RealWorkLabs-SiteLauncher/1.0 (websites@realworklabs.com)' } }
            );
            const hits = await r.json();
            if (hits?.[0]) {
              lat = parseFloat(hits[0].lat);
              lng = parseFloat(hits[0].lon);
              updates.push(doc.ref.update({ lat, lng }));
            }
          } catch {}
        }
      }

      results.push({
        id: doc.id,
        account_name: d.account_name || '',
        domain_name: d.domain_name || '',
        industry: d.industry || 'Other',
        place_city: d.place_city || '',
        lat: lat || null,
        lng: lng || null,
      });
    }));

    await Promise.all(updates);
    res.json({ sites: results });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.use(express.static(join(__dirname, 'public')));

app.get('/auth/google', (_req, res) => {
  const params = new URLSearchParams({
    client_id:     GOOGLE_CLIENT_ID,
    redirect_uri:  GOOGLE_REDIRECT_URI,
    response_type: 'code',
    scope:         'openid email profile https://www.googleapis.com/auth/gmail.readonly',
    access_type:   'offline',
    prompt:        'consent',
    state:         createState(),
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

app.get('/auth/google/callback', async (req, res) => {
  const { code, state, error } = req.query;
  if (error || !code || !consumeState(state)) return res.redirect('/login?error=cancelled');
  try {
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id:     GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri:  GOOGLE_REDIRECT_URI,
        grant_type:    'authorization_code',
      }),
    });
    const tokens = await tokenRes.json();
    if (!tokenRes.ok) throw new Error(tokens.error || 'token exchange failed');

    const userRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    const user = await userRes.json();
    if (!userRes.ok) throw new Error('userinfo fetch failed');
    if (!user.email?.endsWith(`@${ALLOWED_DOMAIN}`)) return res.redirect('/login?error=domain');

    // Persist OAuth tokens for Gmail API use (refresh_token only present on first auth)
    const tokenData = {
      access_token: tokens.access_token,
      expiry:       Date.now() + (tokens.expires_in || 3600) * 1000,
    };
    if (tokens.refresh_token) tokenData.refresh_token = tokens.refresh_token;
    await db.collection('tokens').doc(user.email).set(tokenData, { merge: true });

    const token = generateToken();
    await db.collection('sessions').doc(token).set({
      email: user.email,
      created_at: FieldValue.serverTimestamp(),
    });
    await logAudit({ type: 'login', email: user.email });
    const returnToCookie = decodeURIComponent(getCookies(req).auth_return_to || '') || '/dashboard';
    res.setHeader('Set-Cookie', [
      `auth_token=${token}; Path=/; HttpOnly; SameSite=None; Secure`,
      `auth_return_to=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`,
    ]);
    res.redirect(returnToCookie);
  } catch (err) {
    console.error('OAuth callback error:', err.message);
    res.redirect('/login?error=failed');
  }
});


app.post('/api/auth/logout', async (req, res) => {
  const { auth_token } = getCookies(req);
  if (auth_token) {
    sessionCache.delete(auth_token);
    await db.collection('sessions').doc(auth_token).delete().catch(() => {});
  }
  res.setHeader('Set-Cookie', 'auth_token=; Path=/; Max-Age=0');
  res.json({ ok: true });
});

// ── Launches API ──
const VALID_STATUSES = ['new', 'in_progress', 'awaiting_dns', 'awaiting_approval', 'launched', 'in_progress_frozen', 'awaiting_dns_frozen', 'awaiting_approval_frozen', 'decommissioned'];

app.get('/api/launches', requireAuth, async (req, res) => {
  try {
    const { status, search, department, industry, owner } = req.query;
    const snapshot = await db.collection('launches').orderBy('created_at', 'desc').get();
    let launches = snapshot.docs.map(formatLaunch);

    // Archived filter: default shows active (non-archived, non-decommissioned) only
    // archived=true shows explicitly archived records AND decommissioned sites
    if (req.query.archived === 'true') launches = launches.filter(r => r.archived || r.status === 'decommissioned');
    else launches = launches.filter(r => !r.archived && r.status !== 'decommissioned');

    if (status     && status     !== 'all') launches = launches.filter(r => r.status     === status);
    if (department && department !== 'all') launches = launches.filter(r => r.department === department);
    if (industry   && industry   !== 'all') launches = launches.filter(r => r.industry   === industry);
    if (owner      && owner      !== 'all') launches = launches.filter(r => r.owner      === owner);
    if (search) {
      const term = search.toLowerCase();
      launches = launches.filter(r =>
        r.account_name.toLowerCase().includes(term) ||
        r.domain_name.toLowerCase().includes(term)  ||
        r.contact_name.toLowerCase().includes(term)
      );
    }
    // Decommissioned always last, launched second-to-last
    const sortWeight = s => s === 'decommissioned' ? 2 : s === 'launched' ? 1 : 0;
    launches.sort((a, b) => sortWeight(a.status) - sortWeight(b.status));
    res.json(launches);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch launches.' });
  }
});

app.get('/api/launches/:id', requireAuth, async (req, res) => {
  try {
    const doc = await db.collection('launches').doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    res.json(formatLaunch(doc));
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch launch.' });
  }
});

app.post('/api/launches', requireAuth, async (req, res) => {
  const { department, account_name, domain_name, contact_name, email, phone, industry, notes, is_renewal } = req.body;
  if (!department || !account_name || !domain_name || !contact_name || !email || !phone || !industry) {
    return res.status(400).json({ error: 'All fields are required.' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email address.' });
  }
  try {
    const now = FieldValue.serverTimestamp();
    const ref = await db.collection('launches').add({
      department,
      account_name:      account_name.trim(),
      domain_name:       domain_name.trim().toLowerCase(),
      contact_name:      contact_name.trim(),
      email:             email.trim().toLowerCase(),
      phone:             phone.trim(),
      industry,
      notes:             (notes || '').trim(),
      is_renewal:        is_renewal === true || is_renewal === 'true',
      submitted_by:      req.userEmail || '',
      status:            'new',
      owner:             '',
      created_at:        now,
      updated_at:        now,
      status_changed_at: now,
    });
    await ref.collection('history').add({ status: 'new', entered_at: now });
    const doc = await ref.get();
    sendSlack([
      { type: 'header', text: { type: 'plain_text', text: '🌐 New Site Intake Submitted' } },
      { type: 'section', fields: [
        { type: 'mrkdwn', text: `*Account*\n${account_name.trim()}` },
        { type: 'mrkdwn', text: `*Domain*\n${domain_name.trim().toLowerCase()}` },
        { type: 'mrkdwn', text: `*Department*\n${department}` },
        { type: 'mrkdwn', text: `*Industry*\n${industry}` },
        { type: 'mrkdwn', text: `*Contact*\n${contact_name.trim()}` },
        { type: 'mrkdwn', text: `*Submitted by*\n${req.userEmail || '—'}` },
      ]},
    ]); // fire-and-forget
    // Auto pre-launch Lighthouse scan (fire-and-forget)
    runPageSpeedAudit(ref.id, domain_name.trim().toLowerCase(), false).catch(e => console.warn('Pre-launch PSI skipped:', e.message));
    // Auto-create Google Drive folder for the client (fire-and-forget)
    (async () => {
      try {
        const token = await getAnalyticsAccessToken();
        const folderId = await driveGetOrCreateClientFolder(account_name.trim(), token);
        await driveGetOrCreateSubfolder('Onboarding', folderId, token);
        await driveGetOrCreateSubfolder('Research', folderId, token);
        await driveGetOrCreateSubfolder('Blog Posts', folderId, token);
        await ref.update({ drive_folder_id: folderId, drive_folder_url: `https://drive.google.com/drive/folders/${folderId}` });
        console.log(`[drive] Auto-created folder for ${account_name.trim()} → ${folderId}`);
      } catch (e) { console.warn('[drive] Auto-create folder skipped:', e.message); }
    })();
    res.status(201).json(formatLaunch(doc));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create launch.' });
  }
});

app.patch('/api/launches/:id', requireAuth, async (req, res) => {
  try {
    const { status, notes, analytics_note, department, industry, account_name, domain_name, contact_name, email, phone, owner, is_renewal, archived, analytics_start_date, launch_date, duda_site_name, hideFormSubmits, last_contact_date } = req.body;
    const ref = db.collection('launches').doc(req.params.id);
    const doc = await ref.get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    const row = doc.data();
    if (status && !VALID_STATUSES.includes(status)) return res.status(400).json({ error: 'Invalid status.' });

    const newStatus     = status || row.status;
    const statusChanged = newStatus !== row.status;
    const newOwner      = owner !== undefined ? owner : (row.owner || '');
    const ownerChanged  = owner !== undefined && owner !== (row.owner || '') && !!owner;

    const updates = {
      status:       newStatus,
      notes:        notes        !== undefined ? notes               : (row.notes || ''),
      department:   department   || row.department,
      industry:     industry     !== undefined ? industry            : (row.industry || ''),
      account_name: account_name ? account_name.trim()              : row.account_name,
      domain_name:  domain_name  ? domain_name.trim().toLowerCase() : row.domain_name,
      contact_name: contact_name ? contact_name.trim()              : row.contact_name,
      email:        email        ? email.trim().toLowerCase()        : row.email,
      phone:        phone        ? phone.trim()                      : row.phone,
      owner:        owner        !== undefined ? owner               : (row.owner || ''),
      is_renewal:   is_renewal   !== undefined ? Boolean(is_renewal) : (row.is_renewal || false),
      updated_at:   FieldValue.serverTimestamp(),
    };
    if (archived  !== undefined) updates.archived = Boolean(archived);
    if (analytics_start_date !== undefined) updates.analytics_start_date = analytics_start_date || null;
    if (duda_site_name       !== undefined) updates.duda_site_name       = duda_site_name       || null;
    if (analytics_note       !== undefined) updates.analytics_note       = String(analytics_note).slice(0, 500);
    if (hideFormSubmits    !== undefined) updates.hideFormSubmits    = Boolean(hideFormSubmits);
    if (last_contact_date  !== undefined) updates.last_contact_date  = last_contact_date || null;
    if (statusChanged) {
      updates.status_changed_at = FieldValue.serverTimestamp();
    } else if (launch_date) {
      // Manual override of the launch date (e.g. site was live before it was added here)
      updates.status_changed_at = new Date(launch_date);
    }

    await ref.update(updates);
    if (statusChanged) {
      await ref.collection('history').add({ status: newStatus, entered_at: FieldValue.serverTimestamp() });
    }

    // Build diff of changed fields for audit
    const changedFields = {};
    const watched = ['status','notes','department','industry','account_name','domain_name','contact_name','email','phone','owner'];
    for (const f of watched) {
      const oldVal = row[f] ?? '';
      const newVal = updates[f] ?? '';
      if (String(oldVal) !== String(newVal)) changedFields[f] = { from: oldVal, to: newVal };
    }
    await logAudit({ type: 'edit', email: req.userEmail || '', launch_id: req.params.id, changes: changedFields });


    if (statusChanged && newStatus === 'launched') {
      const name   = updates.account_name || row.account_name || '';
      const domain = updates.domain_name  || row.domain_name  || '';
      sendSlack([
        { type: 'header', text: { type: 'plain_text', text: '🚀 Site Launched!' } },
        { type: 'section', fields: [
          { type: 'mrkdwn', text: `*Account*\n${name}` },
          { type: 'mrkdwn', text: `*Domain*\n<https://${domain}|${domain}>` },
          { type: 'mrkdwn', text: `*Owner*\n${newOwner || '—'}` },
          { type: 'mrkdwn', text: `*Marked by*\n${req.userEmail || '—'}` },
        ]},
      ]); // fire-and-forget
      // Auto post-launch Lighthouse scan (fire-and-forget)
      runPageSpeedAudit(req.params.id, domain, true).catch(e => console.warn('Post-launch PSI skipped:', e.message));
    }

    const updated = await ref.get();
    res.json(formatLaunch(updated));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update launch.' });
  }
});

// ── Outreach log ──
app.post('/api/launches/:id/outreach', requireAuth, async (req, res) => {
  try {
    const { note, type } = req.body;
    const ref = db.collection('launches').doc(req.params.id);
    const doc = await ref.get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    const d = doc.data();
    const today = new Date().toISOString().slice(0, 10);
    const entry = { date: today, note: (note || '').trim(), type: type || 'manual', logged_by: req.userEmail || '' };
    const log = [entry, ...(d.outreach_log || [])];
    await ref.update({ last_contact_date: today, outreach_log: log, updated_at: FieldValue.serverTimestamp() });
    res.json(formatLaunch(await ref.get()));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to log outreach.' });
  }
});

app.delete('/api/launches/:id/outreach/latest', requireAuth, async (req, res) => {
  try {
    const ref = db.collection('launches').doc(req.params.id);
    const doc = await ref.get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    const d = doc.data();
    const log = [...(d.outreach_log || [])];
    if (!log.length) return res.status(400).json({ error: 'Nothing to undo.' });
    log.shift();
    const prevDate = log[0]?.date || null;
    await ref.update({ last_contact_date: prevDate, outreach_log: log, updated_at: FieldValue.serverTimestamp() });
    res.json(formatLaunch(await ref.get()));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to undo.' });
  }
});

app.get('/api/launches/:id/history', requireAuth, async (req, res) => {
  try {
    const snapshot = await db.collection('launches').doc(req.params.id)
      .collection('history').orderBy('entered_at', 'asc').get();
    res.json(snapshot.docs.map(doc => ({
      id:         doc.id,
      launch_id:  req.params.id,
      status:     doc.data().status,
      entered_at: fmtTs(doc.data().entered_at),
    })));
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch history.' });
  }
});

app.delete('/api/launches/:id', requireAuth, async (req, res) => {
  try {
    const ref = db.collection('launches').doc(req.params.id);
    const doc = await ref.get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    const data = doc.data();
    const history = await ref.collection('history').get();
    const batch = db.batch();
    history.docs.forEach(d => batch.delete(d.ref));
    batch.delete(ref);
    await batch.commit();
    await logAudit({ type: 'delete', email: req.userEmail || '', launch_id: req.params.id, account_name: data.account_name || '' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete launch.' });
  }
});

app.delete('/api/edit-requests/:id', requireAuth, async (req, res) => {
  try {
    const ref = db.collection('edit_requests').doc(req.params.id);
    const doc = await ref.get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    await ref.delete();
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete edit request.' });
  }
});

// ── Admin audit log ──
app.get('/api/admin/logs', requireAuth, async (req, res) => {
  try {
    const snapshot = await db.collection('audit_log')
      .orderBy('at', 'desc')
      .limit(200)
      .get();
    const logs = snapshot.docs.map(doc => {
      const d = doc.data();
      return { id: doc.id, ...d, at: fmtTs(d.at) };
    });
    res.json(logs);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch logs.' });
  }
});


// ── Lighthouse Bulk Scan (SSE streaming) ──
app.post('/api/admin/lighthouse/bulk', requireAuth, async (req, res) => {
  const { statuses, stale_only } = req.body; // statuses: 'all' | string[]; stale_only: bool

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const emit = (data) => {
    if (!res.writableEnded) res.write(`data: ${JSON.stringify(data)}\n\n`);
  };

  try {
    const snapshot = await db.collection('launches').get();
    let sites = snapshot.docs
      .map(doc => ({ id: doc.id, ...doc.data() }))
      .filter(s => !s.archived && s.domain_name);

    if (statuses !== 'all' && Array.isArray(statuses) && statuses.length > 0) {
      sites = sites.filter(s => statuses.includes(s.status));
    }

    // If stale_only, check each site's latest audit timestamp and filter out recent ones
    let skipped = 0;
    if (stale_only) {
      emit({ type: 'checking', count: sites.length });
      const thirtyDaysAgo = Date.now() - 30 * 86_400_000;
      const staleness = await Promise.all(sites.map(async (site) => {
        const snap = await db.collection('launches').doc(site.id)
          .collection('lighthouse_audits').orderBy('created_at', 'desc').limit(1).get();
        if (snap.empty) return { site, include: true, last_scanned: null };
        const ts = snap.docs[0].data().created_at?.toMillis?.() ?? 0;
        return { site, include: ts < thirtyDaysAgo, last_scanned: ts };
      }));
      const recent = staleness.filter(s => !s.include);
      skipped = recent.length;
      sites = staleness.filter(s => s.include).map(s => s.site);
    }

    emit({ type: 'start', total: sites.length, skipped });

    let success = 0, failed = 0;
    for (const site of sites) {
      if (res.writableEnded) break; // client disconnected
      emit({ type: 'scanning', id: site.id, domain: site.domain_name, account_name: site.account_name });
      try {
        const result = await runPageSpeedAudit(site.id, site.domain_name, site.status === 'launched');
        success++;
        emit({
          type: 'result', id: site.id, domain: site.domain_name,
          account_name: site.account_name, ok: true,
          performance: result.performance,
          mobile_lcp: result.mobile?.lcp || null,
          desktop_lcp: result.desktop?.lcp || null,
        });
      } catch (err) {
        failed++;
        emit({ type: 'result', id: site.id, domain: site.domain_name, account_name: site.account_name, ok: false, error: err.message });
      }
    }

    emit({ type: 'done', total: sites.length, success, failed, skipped });
  } catch (err) {
    emit({ type: 'error', message: err.message });
  }

  res.end();
});

// ── RDAP / Domain Info ──
let rdapBootstrap = null;
let rdapBootstrapExpiry = 0;

async function getRdapBaseUrl(tld) {
  if (!rdapBootstrap || Date.now() > rdapBootstrapExpiry) {
    const res = await fetch('https://data.iana.org/rdap/dns.json', {
      signal: AbortSignal.timeout(6000),
    });
    if (!res.ok) throw new Error('Failed to fetch RDAP bootstrap');
    rdapBootstrap = await res.json();
    rdapBootstrapExpiry = Date.now() + 86400000;
  }
  for (const [tlds, urls] of rdapBootstrap.services) {
    if (tlds.map(t => t.toLowerCase()).includes(tld)) {
      return urls.find(u => u.startsWith('https://')) || urls[0];
    }
  }
  return null;
}

// ── Site Screener ──────────────────────────────────────────────────────────────
function screenerDetectCms(html) {
  if (/wixstatic\.com|wix\.com\/|generator[^>]*wix/i.test(html))           return { name: 'Wix',        flag: 'green'  };
  if (/static\.squarespace\.com|generator[^>]*squarespace/i.test(html))    return { name: 'Squarespace', flag: 'green'  };
  if (/godaddy|secureserver\.net|generator[^>]*godaddy/i.test(html))       return { name: 'GoDaddy',    flag: 'green'  };
  if (/irp\.cdn-website\.com|lirp\.cdn-website\.com|static\.cdn-website\.com|dudaone\.com|dudaplatform\.com/i.test(html)) return { name: 'Duda', flag: 'green' };
  if (/cdn\.shopify\.com|shopify\.com\/s\//i.test(html))                   return { name: 'Shopify',    flag: 'green'  };
  if (/webflow\.io|webflow\.com\/css|generator[^>]*webflow/i.test(html))   return { name: 'Webflow',    flag: 'orange'   };
  if (/wp-content\/|wp-includes\/|generator[^>]*wordpress/i.test(html))   return { name: 'WordPress',  flag: 'neutral'  };
  if (/\/_next\/static\/|__NEXT_DATA__|"__next"|next\/dist\//i.test(html)) return { name: 'Next.js',    flag: 'orange'   };
  return { name: 'Unknown', flag: 'neutral' };
}

// Detect multi-trade, booking systems, chatbots, e-commerce, and payment processors from homepage HTML
function screenerAnalyzeHtml(html) {
  const signals = [];

  // Multi-trade: flag if 2+ distinct trade categories are present
  // Patterns intentionally require the trade name itself to reduce false positives.
  // Avoid terms like "water heater", "heat pump", "furnace", "drain" — these appear
  // in electrical/HVAC wiring contexts and cause false multi-trade detection.
  const tradePatterns = {
    'HVAC':        /\bhvac\b|air[\s-]?condition(?:ing|er)|heating\s+(?:and|&amp;|&)\s+cooling|ac\s+(?:repair|service|install)/i,
    'Plumbing':    /\bplumb(?:ing|er)\b|sewer\s+(?:line|repair|service)|burst\s+pipe|pipe\s+(?:repair|leak|burst)/i,
    'Electrical':  /\belectric(?:al|ian)\b|wiring|circuit\s+breaker|electrical\s+panel|panel\s+upgrade/i,
    'Roofing':     /\bro(?:of(?:ing|er)|ofer)\b|shingles|roof\s+(?:repair|replac|install)|new\s+roof/i,
    'Landscaping': /\blandscap(?:ing|er)\b|lawn\s+(?:care|mowing|service)|irrigation\s+(?:system|install)|sod\s+install/i,
    'Painting':    /\bpaint(?:ing|er)\b(?!\s+contractor.*hvac)/i,
    'Flooring':    /\bflooring\b|hardwood\s+floor|tile\s+(?:install|flooring)|carpet\s+install/i,
    'Cleaning':    /\bcleaning\s+service\b|janitorial\b|maid\s+service/i,
    'Siding':      /\bsiding\b|fiber[\s-]?cement|hardie[\s-]?board|exterior\s+cladding/i,
  };
  // Require ≥3 matches per trade to avoid false positives from incidental mentions
  // (e.g. a roofer mentioning "plumbing vent boots" should not count as a plumbing company)
  const detected = Object.keys(tradePatterns).filter(t => {
    const re = new RegExp(tradePatterns[t].source, 'gi');
    return (html.match(re) || []).length >= 3;
  });
  if (detected.length >= 2) signals.push({ type: 'multi_trade', trades: detected });

  // Booking / scheduling systems
  // Jobber and HouseCallPro are standard work-request forms — acceptable for any service site
  if (/calendly|acuityscheduling|setmore\.com|simplybook|booksy|servicetitan|scheduling\s+widget/i.test(html)) {
    signals.push({ type: 'booking' });
  }

  // Chatbot / live-chat widgets
  if (/tidio|tawk\.to|crisp\.chat|intercom\.io|freshchat|zendesk.*chat|hubspot.*chat|livechat\.com|drift\.com/i.test(html)) {
    signals.push({ type: 'chatbot' });
  }

  // E-commerce — specific platform embeds only; avoid broad patterns like
  // checkout.*cart which match Squarespace/GoDaddy template boilerplate
  if (/woocommerce|bigcommerce|ecwid\.com|shopify-buy|cdn\.snipcart|add[\s-]to[\s-]cart/i.test(html)) {
    signals.push({ type: 'ecommerce' });
  }

  // Payment processors
  if (/square\.com|squareup\.com|js\.stripe\.com|stripe\.com|paypal\.com|paypalobjects\.com|pay\.google/i.test(html)) {
    signals.push({ type: 'payment' });
  }

  return signals;
}

// Detect the most recent year mentioned near a copyright notice
function screenerDetectCopyrightYear(html) {
  // Matches patterns like: © 2018, Copyright 2019, © 2015-2023, &copy; 2020
  const re = /(?:©|&copy;|\bcopyright\b)[^<\n]{0,80}/gi;
  const yearRe = /((?:19|20)\d{2})/g;
  let maxYear = 0;
  let block;
  while ((block = re.exec(html)) !== null) {
    let m;
    while ((m = yearRe.exec(block[0])) !== null) {
      const y = parseInt(m[1]);
      if (y > maxYear) maxYear = y;
    }
  }
  return maxYear || null;
}

// Count FAQ entries across combined HTML (homepage + optional FAQ page)
function screenerCountFaqEntries(html) {
  const byDetails  = (html.match(/<details[\s>]/gi) || []).length;
  const byClass    = (html.match(/class="[^"]*\b(?:faq[-_]item|faq[-_]question|accordion[-_]item|accordion[-_]question|accordion[-_]trigger|faq[-_]entry)\b[^"]*"/gi) || []).length;
  const byQColon   = (html.match(/(?:^|[\n>])\s*Q\s*[:.]/gm) || []).length;
  return Math.max(byDetails, byClass, byQColon);
}

function screenerParseSitemap(xml) {
  const isSitemapIndex = /<sitemapindex/i.test(xml);
  const urls = [...xml.matchAll(/<loc>\s*(.*?)\s*<\/loc>/gi)].map(m => m[1].trim());
  const pageUrls = urls.filter(u => !u.endsWith('.xml'));

  // Location/area pages: standalone location strategy (city, area, county pages)
  const locationRe    = /\/(service[-_]?areas?|areas?|cities|city|locations?|coverage|towns?|counti?e?s?)\b/i;
  // Service+location combo pages: slugs like /ac-repair-austin or /austin-electrician
  const svcLocRe      = /\/[\w]+-(?:repair|install|service|replacement|cleaning|mainten\w+)-[\w]|\/[\w]+-(?:electrician|plumber|roofer|hvac|painter)\b/i;
  // Deeply nested service sub-pages: /services/category/item
  const servicePageRe = /\/services?\/[\w-]+/i;
  // Blog / news posts
  const blogRe        = /\/(blog|news|articles?|posts?)\//i;

  // Most recent lastmod year across all sitemap entries
  const lastmodYears = [...xml.matchAll(/<lastmod>\s*((?:19|20)\d{2})/gi)].map(m => parseInt(m[1]));
  const mostRecentYear = lastmodYears.length ? Math.max(...lastmodYears) : null;

  return {
    totalPages:      pageUrls.length,
    locationPages:   pageUrls.filter(u => locationRe.test(u)).length,
    svcLocPages:     pageUrls.filter(u => svcLocRe.test(u)).length,
    servicePages:    pageUrls.filter(u => servicePageRe.test(u)).length,
    blogPosts:       pageUrls.filter(u => blogRe.test(u)).length,
    faqPageUrl:      pageUrls.find(u => /\/faq\b/i.test(u)) || null,
    mostRecentYear,
    isSitemapIndex,
  };
}

async function screenerDiscoverSitemapUrls(baseUrl) {
  // Parse robots.txt first — it's the authoritative source for sitemap location
  try {
    const ctrl = new AbortController();
    setTimeout(() => ctrl.abort(), 5000);
    const r = await fetch(`${baseUrl}/robots.txt`, { signal: ctrl.signal, headers: { 'User-Agent': 'Mozilla/5.0 (compatible; RealWorkScreener/1.0)' } });
    if (r.ok) {
      const text = await r.text();
      const declared = [...text.matchAll(/^Sitemap:\s*(.+)$/gim)].map(m => m[1].trim()).filter(Boolean);
      if (declared.length > 0) return declared; // return all declared sitemaps
    }
  } catch {}
  // Fall back to common paths
  return [`${baseUrl}/sitemap.xml`, `${baseUrl}/sitemap_index.xml`, `${baseUrl}/sitemap-index.xml`, `${baseUrl}/sitemap/sitemap.xml`];
}

async function screenerFetchSitemap(baseUrl) {
  const sitemapUrls = await screenerDiscoverSitemapUrls(baseUrl);
  for (const sitemapUrl of sitemapUrls) {
    try {
      const ctrl = new AbortController();
      setTimeout(() => ctrl.abort(), 7000);
      const r = await fetch(sitemapUrl, { signal: ctrl.signal, headers: { 'User-Agent': 'Mozilla/5.0 (compatible; RealWorkScreener/1.0)' } });
      if (!r.ok) continue;
      const xml = await r.text();
      if (!xml.includes('<urlset') && !xml.includes('<sitemapindex')) continue;

      const parsed = screenerParseSitemap(xml);

      // If this is a sitemap index, follow child sitemaps to get real page counts
      // rather than blindly warning about "multiple sitemaps"
      if (parsed.isSitemapIndex) {
        const childUrls = [...xml.matchAll(/<loc>\s*(.*?)\s*<\/loc>/gi)]
          .map(m => m[1].trim())
          .filter(u => u.endsWith('.xml'))
          .slice(0, 5); // cap at 5 child sitemaps

        const childResults = await Promise.all(childUrls.map(async (childUrl) => {
          try {
            const ctrl2 = new AbortController();
            setTimeout(() => ctrl2.abort(), 5000);
            const r2 = await fetch(childUrl, { signal: ctrl2.signal, headers: { 'User-Agent': 'Mozilla/5.0 (compatible; RealWorkScreener/1.0)' } });
            if (!r2.ok) return null;
            const xml2 = await r2.text();
            if (!xml2.includes('<urlset')) return null;
            return screenerParseSitemap(xml2);
          } catch { return null; }
        }));

        const valid = childResults.filter(Boolean);
        if (valid.length > 0) {
          // Aggregate all child sitemap data — we now have real page counts
          return {
            totalPages:     valid.reduce((s, c) => s + c.totalPages, 0),
            locationPages:  valid.reduce((s, c) => s + c.locationPages, 0),
            svcLocPages:    valid.reduce((s, c) => s + c.svcLocPages, 0),
            servicePages:   valid.reduce((s, c) => s + c.servicePages, 0),
            blogPosts:      valid.reduce((s, c) => s + c.blogPosts, 0),
            faqPageUrl:     valid.find(c => c.faqPageUrl)?.faqPageUrl || null,
            mostRecentYear: Math.max(...valid.map(c => c.mostRecentYear || 0)) || null,
            isSitemapIndex: false, // resolved — treat like a normal sitemap now
          };
        }
        // Couldn't follow any child sitemaps — keep isSitemapIndex:true as a soft signal
      }

      return parsed;
    } catch {}
  }
  return null;
}

app.post('/api/screen-site', requireAuth, async (req, res) => {
  let { url } = req.body;
  if (!url?.trim()) return res.status(400).json({ error: 'URL required' });
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url.trim();
  let baseUrl;
  try { baseUrl = new URL(url).origin; } catch { return res.status(400).json({ error: 'Invalid URL' }); }

  try {
    const ctrl = new AbortController();
    setTimeout(() => ctrl.abort(), 10000);
    const htmlRes = await fetch(url, { signal: ctrl.signal, redirect: 'follow', headers: { 'User-Agent': 'Mozilla/5.0 (compatible; RealWorkScreener/1.0)' } });
    const html = await htmlRes.text();

    const cms      = screenerDetectCms(html);

    // ── RealWork platform fingerprint ──
    // The /contact-us4726b987 slug is baked into every RealWork Duda template.
    // If it appears, this site is already live on the RealWork platform.
    if (/contact-us4726b987/i.test(html)) {
      return res.json({ cms, sitemap: null, verdict: 'pass', score: 0, flags: [], warnings: [], isRealWorkSite: true });
    }

    const htmlSigs = screenerAnalyzeHtml(html);
    const sitemap  = await screenerFetchSitemap(new URL(htmlRes.url).origin);

    // Fetch FAQ page for more accurate FAQ entry counting
    let faqHtml = '';
    if (sitemap?.faqPageUrl) {
      try {
        const ctrl2 = new AbortController();
        setTimeout(() => ctrl2.abort(), 5000);
        const faqRes = await fetch(sitemap.faqPageUrl, { signal: ctrl2.signal, redirect: 'follow', headers: { 'User-Agent': 'Mozilla/5.0 (compatible; RealWorkScreener/1.0)' } });
        if (faqRes.ok) faqHtml = await faqRes.text();
      } catch {}
    }
    const faqCount = screenerCountFaqEntries(html + faqHtml);

    const flags = [], warnings = [];

    // ── HTML signals ──
    if (cms.name === 'Next.js') flags.push('Built on Next.js — custom-built site, not a website builder');
    else if (cms.flag === 'orange') warnings.push(`Built on ${cms.name} — complex platform`);
    for (const sig of htmlSigs) {
      if (sig.type === 'multi_trade')
        flags.push(`Multi-trade site (${sig.trades.slice(0, 3).join(' + ')})`);
      else if (sig.type === 'booking')
        flags.push('Online booking or scheduling system detected');
      else if (sig.type === 'ecommerce' && !['Squarespace','Wix','GoDaddy','Duda'].includes(cms.name))
        flags.push('E-commerce functionality detected');
      else if (sig.type === 'payment')
        flags.push('Payment processor detected (Square/Stripe/PayPal)');
      else if (sig.type === 'chatbot')
        warnings.push('Chatbot or live-chat widget detected');
    }

    // ── Sitemap signals ──
    if (!sitemap) {
      flags.push('No sitemap found — site structure unknown');
    } else if (sitemap) {
      if (sitemap.totalPages > 20)       flags.push(`${sitemap.totalPages} pages — large site`);
      else if (sitemap.totalPages > 12)  warnings.push(`${sitemap.totalPages} pages detected`);

      if (sitemap.svcLocPages > 2)       flags.push(`${sitemap.svcLocPages} service+location pages (e.g. "AC Repair Austin")`);
      else if (sitemap.svcLocPages > 0)  warnings.push(`${sitemap.svcLocPages} service+location page(s) detected`);

      if (sitemap.locationPages > 3)      flags.push(`${sitemap.locationPages} location/area pages — RealWork sites have 1 service area page`);
      else if (sitemap.locationPages > 1) warnings.push(`${sitemap.locationPages} location/area pages detected`);

      if (sitemap.servicePages > 5)      flags.push(`${sitemap.servicePages} nested service sub-pages`);
      else if (sitemap.servicePages > 2) warnings.push(`${sitemap.servicePages} service sub-page(s)`);

      if (sitemap.blogPosts >= 5)        warnings.push(`${sitemap.blogPosts} blog/news posts`);

      if (sitemap.isSitemapIndex)        warnings.push('Multiple sitemaps — site may be larger than reported');
    }

    if (faqCount >= 20) warnings.push(`${faqCount}+ FAQ entries detected`);

    // ── Site age ──
    const currentYear     = new Date().getFullYear();
    const ageThreshold    = currentYear - 5;
    const copyrightYear   = screenerDetectCopyrightYear(html);
    const sitemapYear     = sitemap?.mostRecentYear || null;
    // Use whichever indicator is most recent; both must clear the threshold to warn
    const mostRecentSignal = Math.max(copyrightYear || 0, sitemapYear || 0);
    if (mostRecentSignal > 0 && mostRecentSignal <= ageThreshold) {
      warnings.push(`Site content appears to be from ${mostRecentSignal} or earlier — may have outdated info`);
    }

    // ── Compound signals ──
    if (cms.name === 'WordPress' && sitemap && sitemap.totalPages > 20) {
      warnings.push(`Large WordPress site (${sitemap.totalPages} pages) — content migration adds complexity`);
    }

    // ── Weighted scoring ──
    const score   = flags.length * 10 + warnings.length * 4;
    const verdict = score >= 25 ? 'warn' : score >= 10 ? 'review' : score > 0 ? 'caution' : 'pass';

    res.json({ cms, sitemap, verdict, score, flags, warnings });
  } catch (err) {
    if (err.name === 'AbortError') return res.status(504).json({ error: 'Site did not respond in time' });
    res.status(502).json({ error: 'Could not reach site — check the URL and try again' });
  }
});

const domainCache = new Map();

app.get('/api/domain-info/:domain', requireAuth, async (req, res) => {
  const domain = req.params.domain.toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
  const cached = domainCache.get(domain);
  if (cached && Date.now() < cached.expiry) return res.json(cached.data);
  try {
    const tld = domain.split('.').pop();
    const baseUrl = await getRdapBaseUrl(tld);
    if (!baseUrl) return res.status(404).json({ error: `No RDAP server found for .${tld}` });
    const rdapRes = await fetch(`${baseUrl}domain/${domain}`, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(10000),
    });
    if (!rdapRes.ok) return res.status(404).json({ error: 'Domain not found.' });
    const data = await rdapRes.json();
    let registrar = null;
    const regEntity = data.entities?.find(e => e.roles?.includes('registrar'));
    if (regEntity?.vcardArray?.[1]) {
      const fn = regEntity.vcardArray[1].find(p => p[0] === 'fn');
      if (fn) registrar = fn[3];
    }
    const dates = {};
    for (const ev of data.events || []) {
      if (ev.eventAction === 'registration') dates.created = ev.eventDate;
      if (ev.eventAction === 'expiration')   dates.expires = ev.eventDate;
      if (ev.eventAction === 'last changed') dates.updated = ev.eventDate;
    }
    const nameservers = (data.nameservers || []).map(ns => ns.ldhName?.toLowerCase()).filter(Boolean);
    const result = { registrar, nameservers, ...dates };
    domainCache.set(domain, { data: result, expiry: Date.now() + 3600000 });
    res.json(result);
  } catch (err) {
    if (err.name === 'TimeoutError') return res.status(504).json({ error: 'Lookup timed out.' });
    console.error('RDAP error:', err.message);
    res.status(500).json({ error: 'Lookup failed.' });
  }
});

// ── Edit Requests ──
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024, files: 3 } });

const EDIT_REQUEST_STATUSES = ['new', 'in_progress', 'completed', 'need_info', 'rejected'];

async function uploadToStorage(buffer, filename, mimetype) {
  // STORAGE_BUCKET can be set explicitly; if not, derive from the project ID
  // that Cloud Run / Firebase App Hosting injects automatically.
  const projectId  = process.env.GOOGLE_CLOUD_PROJECT || process.env.GCLOUD_PROJECT;
  const bucketName = process.env.STORAGE_BUCKET || (projectId ? `${projectId}.firebasestorage.app` : null);
  if (!bucketName) { console.warn('uploadToStorage: no bucket name available'); return null; }
  try {
    const token       = crypto.randomUUID();
    const safeName    = filename.replace(/[^a-zA-Z0-9._-]/g, '_');
    const path        = `edit-requests/${Date.now()}-${safeName}`;
    const bucket      = getStorage().bucket(bucketName);
    const file        = bucket.file(path);
    await file.save(buffer, {
      metadata: { contentType: mimetype, metadata: { firebaseStorageDownloadTokens: token } },
    });
    return `https://firebasestorage.googleapis.com/v0/b/${bucketName}/o/${encodeURIComponent(path)}?alt=media&token=${token}`;
  } catch (err) {
    console.error('Storage upload error:', err.message);
    return null;
  }
}

function formatEditRequest(doc) {
  const d = doc.data();
  return {
    id:           doc.id,
    company_name: d.company_name || '',
    first_name:   d.first_name   || '',
    last_name:    d.last_name    || '',
    email:        d.email        || '',
    phone:        d.phone        || '',
    requests:     d.requests     || [],
    status:       d.status       || 'new',
    owner:        d.owner        || '',
    archived:     d.archived     || false,
    notes:        d.notes        || '',
    created_at:   fmtTs(d.created_at),
    updated_at:   fmtTs(d.updated_at),
  };
}

app.post('/api/edit-requests', upload.any(), async (req, res) => {
  const { company_name, first_name, last_name, email, phone } = req.body || {};
  if (!company_name || !first_name || !last_name || !email || !phone) {
    return res.status(400).json({ error: 'All contact fields are required.' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email address.' });
  }
  const requests = [];
  for (let i = 0; i < 3; i++) {
    const description = (req.body[`request_${i}_description`] || '').trim();
    if (!description) continue;
    const fileField = `request_${i}_image`;
    const file = (req.files || []).find(f => f.fieldname === fileField);
    let image_url = null, image_name = null;
    if (file) {
      image_url  = await uploadToStorage(file.buffer, file.originalname, file.mimetype);
      image_name = file.originalname;
    }
    requests.push({ description, image_url, image_name });
  }
  if (!requests.length) return res.status(400).json({ error: 'At least one edit request is required.' });
  try {
    const now = FieldValue.serverTimestamp();
    const ref = await db.collection('edit_requests').add({
      company_name: company_name.trim(),
      first_name:   first_name.trim(),
      last_name:    last_name.trim(),
      email:        email.trim().toLowerCase(),
      phone:        phone.trim(),
      requests,
      status:    'new',
      owner:     '',
      notes:     '',
      created_at: now,
      updated_at: now,
    });
    const doc = await ref.get();
    res.status(201).json(formatEditRequest(doc));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to submit request.' });
  }
});

app.get('/api/edit-requests', requireAuth, async (req, res) => {
  try {
    const snapshot = await db.collection('edit_requests').orderBy('created_at', 'desc').get();
    let requests = snapshot.docs.map(formatEditRequest);
    if (req.query.archived === 'true') requests = requests.filter(r => r.archived);
    else requests = requests.filter(r => !r.archived);
    res.json(requests);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch edit requests.' });
  }
});

app.get('/api/edit-requests/:id', requireAuth, async (req, res) => {
  try {
    const doc = await db.collection('edit_requests').doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    res.json(formatEditRequest(doc));
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch edit request.' });
  }
});

app.patch('/api/edit-requests/:id', requireAuth, async (req, res) => {
  try {
    const { status, notes, owner, archived } = req.body;
    const ref = db.collection('edit_requests').doc(req.params.id);
    const doc = await ref.get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    if (status && !EDIT_REQUEST_STATUSES.includes(status)) return res.status(400).json({ error: 'Invalid status.' });
    const updates = { updated_at: FieldValue.serverTimestamp() };
    if (status   !== undefined) updates.status   = status;
    if (notes    !== undefined) updates.notes    = notes;
    if (owner    !== undefined) updates.owner    = owner;
    if (archived !== undefined) updates.archived = Boolean(archived);
    await ref.update(updates);
    const updated = await ref.get();
    res.json(formatEditRequest(updated));
  } catch (err) {
    res.status(500).json({ error: 'Failed to update edit request.' });
  }
});

// ── Gmail API ──
async function getGmailAccessToken(email) {
  const doc = await db.collection('tokens').doc(email).get();
  if (!doc.exists) return null;
  const { access_token, refresh_token, expiry } = doc.data();
  if (!refresh_token) return null;
  if (Date.now() < expiry - 60_000) return access_token;
  // Refresh expired token
  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type:    'refresh_token',
      refresh_token,
      client_id:     GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
    }),
  });
  const data = await res.json();
  if (!res.ok || !data.access_token) return null;
  await db.collection('tokens').doc(email).update({
    access_token: data.access_token,
    expiry:       Date.now() + (data.expires_in || 3600) * 1000,
  });
  return data.access_token;
}

function decodeBase64Url(encoded) {
  if (!encoded) return '';
  return Buffer.from(encoded.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf-8');
}

function extractMessageBody(payload) {
  if (!payload) return { text: '', html: '' };
  if (payload.body?.data) {
    const content = decodeBase64Url(payload.body.data);
    return payload.mimeType === 'text/html' ? { text: '', html: content } : { text: content, html: '' };
  }
  if (payload.parts) {
    let text = '', html = '';
    for (const part of payload.parts) {
      const result = extractMessageBody(part);
      if (result.html) html = result.html;
      if (result.text) text = result.text;
    }
    return { text, html };
  }
  return { text: '', html: '' };
}

// Batch unread-thread check for dashboard badges
app.get('/api/gmail/unread', requireAuth, async (req, res) => {
  const emails = (req.query.emails || '').split(',').map(e => e.trim()).filter(Boolean).slice(0, 50);
  if (!emails.length) return res.json({});
  const accessToken = await getGmailAccessToken(req.userEmail);
  if (!accessToken) return res.json({}); // silently skip if not connected
  try {
    const results = await Promise.all(emails.map(async (email) => {
      const q = `(from:${email} OR to:${email}) is:unread`;
      const r = await fetch(
        `https://gmail.googleapis.com/gmail/v1/users/me/threads?q=${encodeURIComponent(q)}&maxResults=10`,
        { headers: { Authorization: `Bearer ${accessToken}` } }
      );
      if (!r.ok) return [email, 0];
      const data = await r.json();
      return [email, data.threads?.length || 0];
    }));
    res.json(Object.fromEntries(results.filter(([, n]) => n > 0)));
  } catch (err) {
    console.error('Gmail unread error:', err);
    res.json({});
  }
});

// List threads for a contact email
app.get('/api/gmail/threads', requireAuth, async (req, res) => {
  const { email: contactEmail } = req.query;
  if (!contactEmail) return res.status(400).json({ error: 'email param required' });
  const accessToken = await getGmailAccessToken(req.userEmail);
  if (!accessToken) return res.status(403).json({ error: 'gmail_not_connected' });
  try {
    const q = `from:${contactEmail} OR to:${contactEmail}`;
    const listRes = await fetch(
      `https://gmail.googleapis.com/gmail/v1/users/me/threads?q=${encodeURIComponent(q)}&maxResults=10`,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );
    if (listRes.status === 401) return res.status(403).json({ error: 'gmail_not_connected' });
    if (!listRes.ok) return res.status(listRes.status).json({ error: 'Gmail API error' });
    const listData = await listRes.json();
    const threads = listData.threads || [];
    const getHeader = (msg, name) => msg?.payload?.headers?.find(h => h.name.toLowerCase() === name.toLowerCase())?.value || '';
    const detailed = await Promise.all(threads.map(async (t) => {
      const tRes = await fetch(
        `https://gmail.googleapis.com/gmail/v1/users/me/threads/${t.id}?format=metadata&metadataHeaders=Subject&metadataHeaders=From&metadataHeaders=To&metadataHeaders=Date`,
        { headers: { Authorization: `Bearer ${accessToken}` } }
      );
      if (!tRes.ok) return { id: t.id, snippet: t.snippet, subject: '(error)', from: '', date: '', messageCount: 1 };
      const tData = await tRes.json();
      const msgs = tData.messages || [];
      return {
        id:           t.id,
        snippet:      t.snippet,
        subject:      getHeader(msgs[0], 'Subject') || '(no subject)',
        from:         getHeader(msgs[msgs.length - 1], 'From'),
        date:         getHeader(msgs[msgs.length - 1], 'Date'),
        messageCount: msgs.length,
      };
    }));
    res.json(detailed);
  } catch (err) {
    console.error('Gmail threads error:', err);
    logApiError('gmail', err.message || 'Gmail threads fetch failed');
    res.status(500).json({ error: 'Failed to fetch Gmail threads.' });
  }
});

// Get full thread messages
app.get('/api/gmail/threads/:threadId', requireAuth, async (req, res) => {
  const accessToken = await getGmailAccessToken(req.userEmail);
  if (!accessToken) return res.status(403).json({ error: 'gmail_not_connected' });
  try {
    const tRes = await fetch(
      `https://gmail.googleapis.com/gmail/v1/users/me/threads/${req.params.threadId}?format=full`,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );
    if (tRes.status === 401) return res.status(403).json({ error: 'gmail_not_connected' });
    if (!tRes.ok) return res.status(tRes.status).json({ error: 'Gmail API error' });
    const thread = await tRes.json();
    const getHeader = (msg, name) => msg?.payload?.headers?.find(h => h.name.toLowerCase() === name.toLowerCase())?.value || '';
    const messages = (thread.messages || []).map(msg => {
      const { text, html } = extractMessageBody(msg.payload);
      return {
        id:      msg.id,
        from:    getHeader(msg, 'From'),
        to:      getHeader(msg, 'To'),
        date:    getHeader(msg, 'Date'),
        subject: getHeader(msg, 'Subject'),
        bodyHtml: html,
        bodyText: text,
      };
    });
    res.json(messages);
  } catch (err) {
    console.error('Gmail thread detail error:', err);
    res.status(500).json({ error: 'Failed to fetch thread.' });
  }
});

// ── Lighthouse / PageSpeed Insights ──

async function runPageSpeedAudit(launchId, domain, isPostLaunch) {
  const apiKey = process.env.PAGESPEED_API_KEY;
  if (!apiKey) throw new Error('PAGESPEED_API_KEY is not configured.');
  const url = `https://${domain.replace(/^https?:\/\//, '').replace(/\/$/, '')}`;
  const catParams = ['performance','accessibility','best-practices','seo'].map(c => `&category=${c}`).join('');
  const keyParam  = `&key=${encodeURIComponent(apiKey)}`;
  const base      = `https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=${encodeURIComponent(url)}${keyParam}${catParams}`;

  incrApiStat('pagespeed'); // mobile
  incrApiStat('pagespeed'); // desktop
  const [mobileRes, desktopRes] = await Promise.all([
    fetch(`${base}&strategy=mobile`,  { signal: AbortSignal.timeout(110_000) }),
    fetch(`${base}&strategy=desktop`, { signal: AbortSignal.timeout(110_000) }),
  ]);

  const parsePsi = async (r) => {
    if (!r.ok) return null;
    const d = await r.json();
    const c = d.lighthouseResult?.categories || {};
    const a = d.lighthouseResult?.audits     || {};
    return {
      performance:    Math.round((c.performance?.score          ?? 0) * 100),
      accessibility:  Math.round((c.accessibility?.score        ?? 0) * 100),
      best_practices: Math.round((c['best-practices']?.score    ?? 0) * 100),
      seo:            Math.round((c.seo?.score                  ?? 0) * 100),
      lcp: a['largest-contentful-paint']?.displayValue  || null,
      cls: a['cumulative-layout-shift']?.displayValue   || null,
      fcp: a['first-contentful-paint']?.displayValue    || null,
      fid: a['interaction-to-next-paint']?.displayValue || a['max-potential-fid']?.displayValue || null,
    };
  };

  const [mobile, desktop] = await Promise.all([parsePsi(mobileRes), parsePsi(desktopRes)]);
  if (!mobile && !desktop) throw new Error('PageSpeed returned no results for either strategy.');

  const audit = {
    // Top-level scores from mobile (primary) for quick access
    performance:    mobile?.performance    ?? desktop?.performance    ?? 0,
    accessibility:  mobile?.accessibility  ?? desktop?.accessibility  ?? 0,
    best_practices: mobile?.best_practices ?? desktop?.best_practices ?? 0,
    seo:            mobile?.seo            ?? desktop?.seo            ?? 0,
    mobile,
    desktop,
    url,
    is_post_launch: isPostLaunch,
    created_at: FieldValue.serverTimestamp(),
  };

  const ref = await db.collection('launches').doc(launchId).collection('lighthouse_audits').add(audit);
  const saved = await ref.get();
  return { id: saved.id, ...audit, created_at: new Date().toISOString() };
}

app.post('/api/launches/:id/lighthouse', requireAuth, async (req, res) => {
  try {
    const doc = await db.collection('launches').doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    const domain = doc.data().domain_name;
    if (!domain) return res.status(400).json({ error: 'No domain on this launch.' });
    if (!process.env.PAGESPEED_API_KEY) return res.status(400).json({ error: 'PAGESPEED_API_KEY is not configured. Add it in Firebase App Hosting environment settings.' });

    const result = await runPageSpeedAudit(req.params.id, domain, doc.data().status === 'launched');
    res.json(result);
  } catch (err) {
    if (err.name === 'TimeoutError') return res.status(504).json({ error: 'PageSpeed timed out.' });
    console.error('Lighthouse error:', err);
    logApiError('lighthouse', err.message || 'PageSpeed audit failed');
    res.status(500).json({ error: err.message || 'Lighthouse audit failed.' });
  }
});

app.get('/api/launches/:id/lighthouse', requireAuth, async (req, res) => {
  try {
    const snapshot = await db.collection('launches').doc(req.params.id)
      .collection('lighthouse_audits').orderBy('created_at', 'desc').limit(10).get();
    res.json(snapshot.docs.map(d => {
      const data = d.data();
      return { id: d.id, ...data, created_at: fmtTs(data.created_at) };
    }));
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch Lighthouse history.' });
  }
});

// ── Google Analytics & Search Console (OAuth) ──
// User connects by clicking "Connect Analytics Account" in the Analytics tab.
// Refresh token is stored in Firestore at config/analytics_oauth.

const ANALYTICS_REDIRECT_URI = (() => {
  const base = (process.env.OAUTH_REDIRECT_URI || `http://localhost:${PORT}/auth/google/callback`)
    .replace(/\/auth\/google\/callback$/, '');
  return `${base}/auth/analytics/callback`;
})();

const ANALYTICS_SCOPES = [
  'email',
  'https://www.googleapis.com/auth/webmasters.readonly',
  'https://www.googleapis.com/auth/analytics.readonly',
  'https://www.googleapis.com/auth/drive.file',
  'https://www.googleapis.com/auth/drive.readonly',
];

// In-memory token cache (avoids Firestore read on every request)
let _analyticsToken = null; // { access_token, expires_at }

async function getAnalyticsAccessToken() {
  if (_analyticsToken && Date.now() < _analyticsToken.expires_at - 60_000) {
    return _analyticsToken.access_token;
  }
  const snap = await db.collection('config').doc('analytics_oauth').get();
  if (!snap.exists) throw Object.assign(new Error('not_connected'), { code: 'not_connected' });
  const { refresh_token } = snap.data();
  const r = await fetchWithRetry('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      refresh_token,
      grant_type: 'refresh_token',
    }),
  });
  const data = await r.json();
  if (!data.access_token) throw new Error(data.error_description || data.error || 'Failed to refresh analytics token');
  _analyticsToken = { access_token: data.access_token, expires_at: Date.now() + (data.expires_in || 3600) * 1000 };
  return _analyticsToken.access_token;
}

// OAuth connect flow
app.get('/auth/analytics', requireAuth, (req, res) => {
  const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  url.searchParams.set('client_id', GOOGLE_CLIENT_ID);
  url.searchParams.set('redirect_uri', ANALYTICS_REDIRECT_URI);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', ANALYTICS_SCOPES.join(' '));
  url.searchParams.set('access_type', 'offline');
  url.searchParams.set('prompt', 'consent');
  res.redirect(url.toString());
});

app.get('/auth/analytics/callback', requireAuth, async (req, res) => {
  const { code, error } = req.query;
  if (error) return res.redirect('/dashboard?analytics_error=' + encodeURIComponent(error));
  try {
    const r = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: ANALYTICS_REDIRECT_URI,
        grant_type: 'authorization_code',
      }),
    });
    const tokens = await r.json();
    if (!tokens.refresh_token) throw new Error('No refresh token returned — ensure prompt=consent');
    // Get connected email
    const userInfo = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    }).then(r => r.json());
    await db.collection('config').doc('analytics_oauth').set({
      refresh_token: tokens.refresh_token,
      email: userInfo.email || '',
      connected_at: new Date().toISOString(),
    });
    _analyticsToken = null; // bust cache
    ga4Cache = null;
    res.redirect('/dashboard?tab=analytics&analytics_connected=1');
  } catch (err) {
    console.error('Analytics OAuth callback error:', err.message);
    res.redirect('/dashboard?analytics_error=' + encodeURIComponent(err.message));
  }
});

app.get('/api/analytics/debug-domains', requireAuth, async (req, res) => {
  try {
    const token = await getAnalyticsAccessToken();
    ga4Cache = null; // force fresh fetch
    const map = await refreshGa4Cache(token);
    res.json({ domains: Object.keys(map).sort(), map });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/analytics/connection', requireAuth, async (req, res) => {
  const snap = await db.collection('config').doc('analytics_oauth').get();
  if (!snap.exists) return res.json({ connected: false });
  const { email, connected_at } = snap.data();
  res.json({ connected: true, email, connected_at });
});

app.delete('/api/analytics/connection', requireAuth, async (req, res) => {
  await db.collection('config').doc('analytics_oauth').delete();
  _analyticsToken = null;
  ga4Cache = null;
  res.json({ ok: true });
});

// GA4 property discovery cache: normalised domain → propertyId
let ga4Cache = null; // { map: {domain: propertyId}, at: timestamp }

async function refreshGa4Cache(token) {
  const map = {};
  const allProps = [];
  let pageToken;
  do {
    const r = await fetch(
      `https://analyticsadmin.googleapis.com/v1alpha/accountSummaries?pageSize=200${pageToken ? '&pageToken=' + pageToken : ''}`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    const data = await r.json();
    for (const acc of data.accountSummaries || [])
      for (const p of acc.propertySummaries || []) allProps.push(p.property);
    pageToken = data.nextPageToken;
  } while (pageToken);

  for (let i = 0; i < allProps.length; i += 10) {
    await Promise.all(allProps.slice(i, i + 10).map(async propResource => {
      try {
        const [streamsData, propData] = await Promise.all([
          fetch(
            `https://analyticsadmin.googleapis.com/v1alpha/${propResource}/dataStreams?pageSize=50`,
            { headers: { Authorization: `Bearer ${token}` } }
          ).then(r => r.json()),
          fetch(
            `https://analyticsadmin.googleapis.com/v1beta/${propResource}`,
            { headers: { Authorization: `Bearer ${token}` } }
          ).then(r => r.json()).catch(() => ({})),
        ]);
        const propId = propResource.replace('properties/', '');
        const tz = propData.timeZone || null;
        for (const s of streamsData.dataStreams || []) {
          if (s.type === 'WEB_DATA_STREAM' && s.webStreamData?.defaultUri) {
            const d = s.webStreamData.defaultUri
              .replace(/^https?:\/\//, '').replace(/\/$/, '').replace(/^www\./, '');
            map[d] = { id: propId, tz };
          }
        }
      } catch { /* skip inaccessible */ }
    }));
  }
  return map;
}

async function getGa4PropertyId(domain, token) {
  if (!ga4Cache || Date.now() - ga4Cache.at > 600_000) {
    ga4Cache = { map: await refreshGa4Cache(token), at: Date.now() };
  }
  const clean = domain.replace(/^https?:\/\//, '').replace(/\/$/, '').replace(/^www\./, '');
  return ga4Cache.map[clean]?.id || null;
}

async function getGa4PropertyInfo(domain, token) {
  if (!ga4Cache || Date.now() - ga4Cache.at > 600_000) {
    ga4Cache = { map: await refreshGa4Cache(token), at: Date.now() };
  }
  const clean = domain.replace(/^https?:\/\//, '').replace(/\/$/, '').replace(/^www\./, '');
  return ga4Cache.map[clean] || null; // { id, tz }
}

function isoDate(d) { return d.toISOString().slice(0, 10); }

// Retry wrapper for external API calls — retries once on transient errors (429, 500-503, network)
async function fetchWithRetry(url, opts = {}, { retries = 1, delay = 2000 } = {}) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const r = await fetch(url, { signal: AbortSignal.timeout(15_000), ...opts });
      if (r.ok || attempt === retries) return r;
      if ([429, 500, 502, 503].includes(r.status)) {
        await new Promise(resolve => setTimeout(resolve, delay));
        continue;
      }
      return r; // non-retryable HTTP error (401, 403, 404, etc.)
    } catch (err) {
      if (attempt === retries) throw err;
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}

function computePctChange(weeks, key) {
  if (weeks.length < 4) return null;
  const n = Math.min(4, Math.floor(weeks.length / 2));
  const prev = weeks.slice(-n * 2, -n).reduce((s, w) => s + (w[key] || 0), 0);
  const last = weeks.slice(-n).reduce((s, w) => s + (w[key] || 0), 0);
  if (prev === 0) return null;
  return Math.round((last - prev) / prev * 1000) / 10;
}

async function fetchGSC(domain, launchDate, token) {
  const startDate = isoDate(new Date(launchDate));
  const endDate = isoDate(new Date());
  const cleanDomain = domain.replace(/^www\./, '');

  async function querySC(siteUrl, body) {
    incrApiStat('gsc');
    const r = await fetchWithRetry(
      `https://www.googleapis.com/webmasters/v3/sites/${encodeURIComponent(siteUrl)}/searchAnalytics/query`,
      {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      }
    );
    if (!r.ok) throw new Error(`GSC ${r.status}`);
    return r.json();
  }

  // Try all common GSC siteUrl formats in order
  const siteUrlCandidates = [
    `sc-domain:${cleanDomain}`,
    `https://www.${cleanDomain}/`,
    `https://${cleanDomain}/`,
    `http://www.${cleanDomain}/`,
    `http://${cleanDomain}/`,
  ];
  let siteUrl = null;
  let rows = [];
  for (const candidate of siteUrlCandidates) {
    try {
      const data = await querySC(candidate, { startDate, endDate, dimensions: ['date'], rowLimit: 500 });
      rows = data.rows || [];
      siteUrl = candidate;
      break;
    } catch { /* try next candidate */ }
  }
  if (!siteUrl) return { available: false };

  const topData = await querySC(siteUrl, { startDate, endDate, dimensions: ['query'], rowLimit: 25 })
    .catch(() => ({ rows: [] }));

  // Helper: bucket a date string into its Sun-start week key using UTC to avoid timezone shift
  function utcWeekStart(dateStr) {
    const d = new Date(dateStr + 'T00:00:00Z');
    d.setUTCDate(d.getUTCDate() - d.getUTCDay()); // roll back to Sunday in UTC
    return d.toISOString().slice(0, 10);
  }

  const weekMap = {};
  let clicks = 0, impressions = 0, posWSum = 0, posWImps = 0;
  for (const row of rows) {
    const wk = utcWeekStart(row.keys[0]);
    if (!weekMap[wk]) weekMap[wk] = { clicks: 0, impressions: 0, posWSum: 0, posWImps: 0 };
    weekMap[wk].clicks += row.clicks || 0;
    weekMap[wk].impressions += row.impressions || 0;
    clicks += row.clicks || 0;
    impressions += row.impressions || 0;
    // Impressions-weighted position (same methodology GSC uses internally)
    const imp = row.impressions || 0;
    const pos = row.position || 0;
    if (pos && imp) { weekMap[wk].posWSum += pos * imp; weekMap[wk].posWImps += imp; posWSum += pos * imp; posWImps += imp; }
  }
  const weeks = Object.entries(weekMap)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([week, d]) => ({
      week,
      clicks: d.clicks,
      impressions: d.impressions,
      position: d.posWImps > 0 ? Math.round(d.posWSum / d.posWImps * 10) / 10 : null,
    }));

  return {
    available: true,
    total: {
      clicks,
      impressions,
      ctr: impressions > 0 ? Math.round(clicks / impressions * 10000) / 100 : 0,
      position: posWImps > 0 ? Math.round(posWSum / posWImps * 10) / 10 : null,
    },
    comparison: {
      clicksPct: computePctChange(weeks, 'clicks'),
      impressionsPct: computePctChange(weeks, 'impressions'),
    },
    weeks,
    topQueries: (topData.rows || []).map(r => ({
      query: r.keys[0],
      clicks: r.clicks || 0,
      impressions: r.impressions || 0,
      ctr: r.ctr != null ? Math.round(r.ctr * 10000) / 100 : 0,
      position: r.position ? Math.round(r.position * 10) / 10 : null,
    })),
  };
}

// forceSiteUrl: skip discovery and query a specific known property (for pre/post consistency)
async function fetchGSCWindow(domain, startDate, endDate, token, forceSiteUrl = null) {
  const cleanDomain = domain.replace(/^www\./, '');

  async function querySC(siteUrl, body) {
    incrApiStat('gsc');
    const r = await fetchWithRetry(
      `https://www.googleapis.com/webmasters/v3/sites/${encodeURIComponent(siteUrl)}/searchAnalytics/query`,
      {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      }
    );
    if (!r.ok) throw new Error(`GSC ${r.status} for ${siteUrl}`);
    return r.json();
  }

  let siteUrl = null;
  let rows = [];

  if (forceSiteUrl) {
    // Try the preferred property first (same as post-launch for apples-to-apples).
    // If it returns no data for this window (e.g. site was non-www pre-launch but
    // www post-launch), fall through and search all candidates so we don't miss data.
    siteUrl = forceSiteUrl;
    try {
      const data = await querySC(siteUrl, { startDate, endDate, dimensions: ['date'], rowLimit: 500 });
      rows = data.rows || [];
    } catch (e) {
      console.warn(`[fetchGSCWindow] forced siteUrl ${siteUrl} failed: ${e.message}`);
      rows = [];
    }
    // Fall back to full candidate search if forced property had no data
    if (rows.length === 0) {
      console.log(`[fetchGSCWindow] forced ${siteUrl} empty for ${startDate}→${endDate}, trying all candidates`);
      forceSiteUrl = null; // allow fall-through to candidate loop below
    }
  }
  if (!forceSiteUrl) {
    const siteUrlCandidates = [
      `sc-domain:${cleanDomain}`,
      `https://www.${cleanDomain}/`,
      `https://${cleanDomain}/`,
      `http://www.${cleanDomain}/`,
      `http://${cleanDomain}/`,
    ];
    for (const candidate of siteUrlCandidates) {
      try {
        const data = await querySC(candidate, { startDate, endDate, dimensions: ['date'], rowLimit: 500 });
        const candidateRows = data.rows || [];
        if (candidateRows.length > 0) {
          rows = candidateRows;
          siteUrl = candidate;
          break;
        }
        if (!siteUrl) siteUrl = candidate; // first valid 200-OK even if empty, as fallback
      } catch { /* try next */ }
    }
  }

  if (!siteUrl) return { weeks: [], totals: { clicks: 0, impressions: 0, ctr: 0, position: null }, siteUrl: null };

  function utcWeekStartW(dateStr) {
    const d = new Date(dateStr + 'T00:00:00Z');
    d.setUTCDate(d.getUTCDate() - d.getUTCDay());
    return d.toISOString().slice(0, 10);
  }
  const weekMap = {};
  let clicks = 0, impressions = 0, posWSum = 0, posWImps = 0;
  for (const row of rows) {
    const wk = utcWeekStartW(row.keys[0]);
    if (!weekMap[wk]) weekMap[wk] = { clicks: 0, impressions: 0, posWSum: 0, posWImps: 0 };
    weekMap[wk].clicks += row.clicks || 0;
    weekMap[wk].impressions += row.impressions || 0;
    clicks += row.clicks || 0;
    impressions += row.impressions || 0;
    const imp = row.impressions || 0;
    const pos = row.position || 0;
    if (pos && imp) { weekMap[wk].posWSum += pos * imp; weekMap[wk].posWImps += imp; posWSum += pos * imp; posWImps += imp; }
  }
  const weeks = Object.entries(weekMap)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([week, d]) => ({
      week,
      clicks: d.clicks,
      impressions: d.impressions,
      position: d.posWImps > 0 ? Math.round(d.posWSum / d.posWImps * 10) / 10 : null,
    }));

  return {
    weeks,
    totals: {
      clicks,
      impressions,
      ctr: impressions > 0 ? Math.round(clicks / impressions * 10000) / 100 : 0,
      position: posWImps > 0 ? Math.round(posWSum / posWImps * 10) / 10 : null,
    },
    siteUrl,
  };
}

async function fetchGA4(propertyId, launchDate, token) {
  const property = `properties/${propertyId}`;
  const startDate = isoDate(new Date(launchDate));

  async function runReport(body) {
    incrApiStat('ga4');
    const r = await fetchWithRetry(
      `https://analyticsdata.googleapis.com/v1beta/${property}:runReport`,
      {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      }
    );
    if (!r.ok) throw new Error(`GA4 ${r.status}`);
    return r.json();
  }

  const periodMetrics = [
    { name: 'sessions' },
    { name: 'activeUsers' },
    { name: 'newUsers' },
    { name: 'engagementRate' },
  ];
  function parsePeriodRow(rows) {
    if (!rows || !rows.length) return { sessions: 0, users: 0, newUsers: 0, engagementRate: null };
    const [s, u, n, e] = rows[0].metricValues.map(m => parseFloat(m.value) || 0);
    return {
      sessions: Math.round(s),
      users: Math.round(u),
      newUsers: Math.round(n),
      engagementRate: s > 0 ? Math.round(e * 1000) / 10 : null,
    };
  }

  const [dailyData, channelData, last7Data, last30Data, last60Data] = await Promise.all([
    runReport({
      dateRanges: [{ startDate, endDate: 'today' }],
      dimensions: [{ name: 'date' }],
      metrics: periodMetrics,
      orderBys: [{ dimension: { dimensionName: 'date' } }],
      limit: 500,
    }),
    runReport({
      dateRanges: [{ startDate, endDate: 'today' }],
      dimensions: [{ name: 'sessionDefaultChannelGrouping' }],
      metrics: [{ name: 'sessions' }],
      orderBys: [{ metric: { metricName: 'sessions' }, desc: true }],
      limit: 6,
    }),
    runReport({
      dateRanges: [{ startDate: '7daysAgo', endDate: 'today' }],
      metrics: periodMetrics,
    }),
    runReport({
      dateRanges: [{ startDate: '30daysAgo', endDate: 'today' }],
      metrics: periodMetrics,
    }),
    runReport({
      dateRanges: [{ startDate: '60daysAgo', endDate: 'today' }],
      metrics: periodMetrics,
    }),
  ]);

  function utcWeekStartGA4(yyyymmdd) {
    const ds = `${yyyymmdd.slice(0,4)}-${yyyymmdd.slice(4,6)}-${yyyymmdd.slice(6,8)}`;
    const d = new Date(ds + 'T00:00:00Z');
    d.setUTCDate(d.getUTCDate() - d.getUTCDay());
    return d.toISOString().slice(0, 10);
  }
  const weekMap = {};
  let sessions = 0, users = 0, newUsers = 0, engSum = 0, engCount = 0;
  for (const row of dailyData.rows || []) {
    const raw = row.dimensionValues[0].value;
    const wk = utcWeekStartGA4(raw);
    const [s, u, n, e] = row.metricValues.map(m => parseFloat(m.value) || 0);
    if (!weekMap[wk]) weekMap[wk] = { sessions: 0, users: 0, newUsers: 0, engSum: 0, engCount: 0 };
    weekMap[wk].sessions += s;
    weekMap[wk].users += u;
    weekMap[wk].newUsers += n;
    // Sessions-weighted engagement rate: weight each day's rate by its session count
    if (e > 0 && s > 0) { weekMap[wk].engSum += e * s; weekMap[wk].engCount += s; }
    sessions += s; users += u; newUsers += n;
    if (e > 0 && s > 0) { engSum += e * s; engCount += s; }
  }
  const weeks = Object.entries(weekMap)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([week, d]) => ({
      week,
      sessions: Math.round(d.sessions),
      users: Math.round(d.users),
      newUsers: Math.round(d.newUsers),
      engagementRate: d.engCount > 0 ? Math.round(d.engSum / d.engCount * 1000) / 10 : null,
    }));

  return {
    available: true,
    total: {
      sessions: Math.round(sessions),
      users: Math.round(users),
      newUsers: Math.round(newUsers),
      engagementRate: engCount > 0 ? Math.round(engSum / engCount * 1000) / 10 : null,
    },
    periods: {
      last7:  parsePeriodRow(last7Data.rows),
      last30: parsePeriodRow(last30Data.rows),
      last60: parsePeriodRow(last60Data.rows),
    },
    comparison: {
      sessionsPct: computePctChange(weeks, 'sessions'),
      usersPct: computePctChange(weeks, 'users'),
    },
    weeks,
    channels: (channelData.rows || []).map(r => ({
      channel: r.dimensionValues[0].value,
      sessions: parseInt(r.metricValues[0].value) || 0,
    })),
  };
}

// ── Gemini API key ──
let geminiKeyCache = null;
async function getGeminiKey() {
  if (geminiKeyCache) return geminiKeyCache;
  // Try env var first (local dev), fall back to Firestore
  if (process.env.GEMINI_API_KEY) { geminiKeyCache = process.env.GEMINI_API_KEY; return geminiKeyCache; }
  const snap = await db.collection('config').doc('gemini_credentials').get();
  if (!snap.exists || !snap.data().api_key) throw new Error('Gemini API key not configured');
  geminiKeyCache = snap.data().api_key;
  return geminiKeyCache;
}

let placesKeyCache = null;
async function getPlacesApiKey() {
  if (placesKeyCache) return placesKeyCache;
  if (process.env.GOOGLE_PLACES_API_KEY) { placesKeyCache = process.env.GOOGLE_PLACES_API_KEY; return placesKeyCache; }
  const snap = await db.collection('config').doc('google_credentials').get();
  if (!snap.exists || !snap.data().places_api_key) return null; // optional — graceful fallback
  placesKeyCache = snap.data().places_api_key;
  return placesKeyCache;
}

let pexelsKeyCache = null;
async function getPexelsKey() {
  if (pexelsKeyCache) return pexelsKeyCache;
  if (process.env.PEXELS_API_KEY) { pexelsKeyCache = process.env.PEXELS_API_KEY; return pexelsKeyCache; }
  const snap = await db.collection('config').doc('pexels_credentials').get();
  if (!snap.exists || !snap.data().api_key) return null;
  pexelsKeyCache = snap.data().api_key;
  return pexelsKeyCache;
}

async function fetchPexelsImage(query) {
  const debug = { query, step: 'start' };
  try {
    const key = await getPexelsKey();
    if (!key) { debug.step = 'no_key'; return { url: null, debug }; }
    debug.step = 'fetching';
    const url = `https://api.pexels.com/v1/search?query=${encodeURIComponent(query)}&per_page=5&orientation=landscape`;
    const r = await fetch(url, { headers: { Authorization: key } });
    debug.httpStatus = r.status;
    if (!r.ok) { debug.step = 'http_error'; return { url: null, debug }; }
    const { photos } = await r.json();
    debug.photoCount = photos?.length || 0;
    if (!photos?.length) { debug.step = 'no_photos'; return { url: null, debug }; }
    const p = photos[0];
    debug.step = 'success';
    return {
      url:             p.src.large,
      alt:             p.alt || query,
      photographer:    p.photographer,
      photographerUrl: p.photographer_url,
      debug,
    };
  } catch (e) { debug.step = 'exception'; debug.error = e.message; return { url: null, debug }; }
}

async function fetchPlaceRating(placeId) {
  try {
    const key = await getPlacesApiKey();
    if (!key) return null;
    const r = await fetch(`https://maps.googleapis.com/maps/api/place/details/json?place_id=${encodeURIComponent(placeId)}&fields=rating,user_ratings_total,address_components,vicinity,formatted_address,reviews&key=${key}`);
    const d = await r.json();
    if (d.status !== 'OK' || !d.result) return null;

    // Extract city — SABs hide their address so address_components may be empty;
    // fall back to vicinity then formatted_address which Google still returns
    const comps = d.result.address_components || [];
    const cityComp  = comps.find(c => c.types.includes('locality'));
    const stateComp = comps.find(c => c.types.includes('administrative_area_level_1'));
    let city = cityComp && stateComp
      ? `${cityComp.long_name}, ${stateComp.short_name}`
      : (cityComp?.long_name || null);

    if (!city && d.result.vicinity) {
      // vicinity is typically "City, State" or just "City" for SABs
      city = d.result.vicinity;
    }
    if (!city && d.result.formatted_address) {
      // formatted_address is "Street, City, State ZIP, Country" — extract City, ST
      const m = d.result.formatted_address.match(/([^,]+),\s*([A-Z]{2})\s+\d/);
      if (m) city = `${m[1].trim()}, ${m[2]}`;
    }

    // Extract reviews — 4+ star only, meaningful length, truncate last name to initial
    const reviews = (d.result.reviews || [])
      .filter(rv => rv.text && rv.text.trim().length > 40 && rv.rating >= 4)
      .slice(0, 5)
      .map(rv => {
        const parts = (rv.author_name || '').trim().split(/\s+/);
        const name = parts.length > 1
          ? `${parts[0]} ${parts[parts.length - 1][0]}.`
          : (parts[0] || 'Anonymous');
        return { name, rating: rv.rating, text: rv.text.trim().slice(0, 300) };
      });

    return { rating: d.result.rating || null, reviewCount: d.result.user_ratings_total || null, city, reviews };
  } catch { return null; }
}

async function fetchPlaceCity(placeId) {
  const data = await fetchPlaceRating(placeId);
  return data?.city || null;
}

// ── Duda Analytics ──
let dudaCredsCache = null;
async function getDudaCredentials() {
  if (dudaCredsCache) return dudaCredsCache;
  const snap = await db.collection('config').doc('duda_credentials').get();
  if (!snap.exists) throw new Error('Duda credentials not configured');
  dudaCredsCache = snap.data();
  return dudaCredsCache;
}

const dudaCache = {};
const DUDA_TTL  = 10 * 60 * 1000; // 10 minutes

app.post('/api/analytics/duda/clear-cache', requireAuth, (_req, res) => {
  Object.keys(dudaCache).forEach(k => delete dudaCache[k]);
  res.json({ ok: true });
});

async function fetchDuda(siteName, launchDate) {
  const cacheKey = `${siteName}`;
  const cached   = dudaCache[cacheKey];
  if (cached && Date.now() - cached.ts < DUDA_TTL) return cached.data;

  const creds  = await getDudaCredentials();
  const token  = Buffer.from(`${creds.api_user}:${creds.api_pass}`).toString('base64');
  const base   = 'https://api.duda.co/api';
  const headers = { Authorization: `Basic ${token}`, 'Content-Type': 'application/json' };

  const from = launchDate ? launchDate.slice(0, 10) : undefined;
  const to   = new Date().toISOString().slice(0, 10);
  const dateParams = from ? `?from=${from}&to=${to}&dateGranularity=DAYS` : `?to=${to}&dateGranularity=DAYS`;

  incrApiStat('duda'); // traffic
  incrApiStat('duda'); // activities
  const [trafficRes, activityRes] = await Promise.all([
    fetchWithRetry(`${base}/analytics/site/${siteName}${dateParams}&result=traffic`,     { headers }),
    fetchWithRetry(`${base}/analytics/site/${siteName}${dateParams}&result=activities`,  { headers }),
  ]);

  if (!trafficRes.ok) {
    const err = await trafficRes.text();
    throw new Error(`Duda API error ${trafficRes.status}: ${err}`);
  }

  const trafficDaily  = await trafficRes.json();
  const activityDaily = activityRes.ok ? await activityRes.json() : {};

  // Parse {"2026-03-18": [{VISITORS:4,...}]} into sorted day arrays
  function parseDaily(obj, keyMap) {
    return Object.entries(obj).map(([day, rows]) => {
      const row = rows[0] || {};
      const entry = { day };
      for (const [src, dst] of Object.entries(keyMap)) entry[dst] = row[src] ?? 0;
      return entry;
    }).sort((a, b) => a.day.localeCompare(b.day));
  }

  const tDays = parseDaily(trafficDaily,  { VISITORS: 'visitors', VISITS: 'visits', PAGE_VIEWS: 'pageViews' });
  const aDays = parseDaily(activityDaily, { FORM_SUBMITS: 'formSubmits', CLICK_TO_CALLS: 'callClicks', CLICK_TO_EMAILS: 'emailClicks', CLICK_TO_MAPS: 'mapClicks' });

  // Merge traffic + activity by day key
  const dayMap = {};
  const zeroActivity = { formSubmits: 0, callClicks: 0, emailClicks: 0, mapClicks: 0 };
  for (const d of tDays) dayMap[d.day] = { ...zeroActivity, ...d };
  for (const d of aDays) {
    if (dayMap[d.day]) Object.assign(dayMap[d.day], d);
    else dayMap[d.day] = { day: d.day, visitors: 0, visits: 0, pageViews: 0, ...d };
  }
  const days = Object.values(dayMap).sort((a, b) => a.day.localeCompare(b.day));

  // Group daily data into ISO weeks (Mon start) for charting
  function isoWeekStart(dateStr) {
    const d = new Date(dateStr + 'T00:00:00Z');
    d.setUTCDate(d.getUTCDate() - d.getUTCDay()); // back to Sunday, matching GSC/GA4
    return d.toISOString().slice(0, 10);
  }
  const weekMap = {};
  for (const d of days) {
    const wk = isoWeekStart(d.day);
    if (!weekMap[wk]) weekMap[wk] = { week: wk, visitors: 0, visits: 0, pageViews: 0, formSubmits: 0, callClicks: 0, emailClicks: 0, mapClicks: 0 };
    weekMap[wk].visitors    += d.visitors    || 0;
    weekMap[wk].visits      += d.visits      || 0;
    weekMap[wk].pageViews   += d.pageViews   || 0;
    weekMap[wk].formSubmits += d.formSubmits || 0;
    weekMap[wk].callClicks  += d.callClicks  || 0;
    weekMap[wk].emailClicks += d.emailClicks || 0;
    weekMap[wk].mapClicks   += d.mapClicks   || 0;
  }
  const weeks = Object.values(weekMap).sort((a, b) => a.week.localeCompare(b.week));

  // Full-range totals from daily data
  const total = days.reduce((acc, d) => {
    acc.visitors    += d.visitors    || 0;
    acc.visits      += d.visits      || 0;
    acc.pageViews   += d.pageViews   || 0;
    acc.formSubmits += d.formSubmits || 0;
    acc.callClicks  += d.callClicks  || 0;
    acc.emailClicks += d.emailClicks || 0;
    acc.mapClicks   += d.mapClicks   || 0;
    return acc;
  }, { visitors: 0, visits: 0, pageViews: 0, formSubmits: 0, callClicks: 0, emailClicks: 0, mapClicks: 0 });

  const data = { available: true, days, weeks, total };

  dudaCache[cacheKey] = { ts: Date.now(), data };
  return data;
}

app.get('/api/launches/:id/widget-events', requireAuth, async (req, res) => {
  const days = Math.min(parseInt(req.query.days) || 30, 90);
  try {
    const token = await getAnalyticsAccessToken();
    const doc = await db.collection('launches').doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    const { domain_name: domain, duda_site_name: dudaSiteName, analytics_start_date, launch_date } = doc.data();
    const chatbotSince = analytics_start_date || launch_date || null;
    const info = await getGa4PropertyInfo(domain, token);
    if (!info) return res.json({ available: false, reason: 'No GA4 property found for this domain' });
    const { id: propertyId, tz: timezone } = info;

    const property = `properties/${propertyId}`;
    const widgetFilter = {
      orGroup: { expressions: [
        { filter: { fieldName: 'eventName', stringFilter: { matchType: 'BEGINS_WITH', value: 'widget_' } } },
        { filter: { fieldName: 'eventName', stringFilter: { matchType: 'BEGINS_WITH', value: 'bcs_' } } },
      ]}
    };

    const ga4Post = body => fetch(`https://analyticsdata.googleapis.com/v1beta/${property}:runReport`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }).then(r => r.json());

    const formSubmitFilter = { filter: { fieldName: 'eventName', stringFilter: { matchType: 'EXACT', value: 'widget_form_submit' } } };

    // Fetch Duda form submissions in parallel with GA4 queries
    const dudaFormsPromise = (async () => {
      if (!dudaSiteName) return null;
      try {
        const creds = await getDudaCredentials();
        const auth  = Buffer.from(`${creds.api_user}:${creds.api_pass}`).toString('base64');
        const r = await fetch(`https://api.duda.co/api/sites/multiscreen/get-forms/${dudaSiteName}`, {
          headers: { Authorization: `Basic ${auth}`, 'Content-Type': 'application/json' },
        });
        if (!r.ok) return null;
        const raw  = await r.json();
        const subs = Array.isArray(raw) ? raw : (raw.results || []);
        if (subs.length) console.log('[widget-events] Duda form sample:', JSON.stringify(subs[0]).slice(0, 800));
        return subs
          .map(s => {
            // Duda stores form values in s.message as either:
            //   a flat object { "Name": "John", "Phone": "555..." } (most common)
            //   or an array of { name, value } pairs
            const msg = s.message || {};
            let fieldMap = {};
            if (Array.isArray(msg)) {
              msg.forEach(f => { if (f.name) fieldMap[f.name.toLowerCase()] = f.value; });
            } else if (Array.isArray(msg.fields)) {
              msg.fields.forEach(f => { if (f.name) fieldMap[f.name.toLowerCase()] = f.value; });
            } else if (typeof msg === 'object') {
              Object.entries(msg).forEach(([k, v]) => { fieldMap[k.toLowerCase()] = v; });
            }
            const field = (...keys) => {
              const k = Object.keys(fieldMap).find(fk => keys.some(k => fk.includes(k)));
              return (k && typeof fieldMap[k] === 'string') ? fieldMap[k] || null : null;
            };
            return {
              id:           s.id || null,
              name:         field('name', 'full name', 'contact name', 'your name') || s.name || [s.first_name, s.last_name].filter(Boolean).join(' ') || null,
              email:        field('email') || s.email || null,
              phone:        field('phone', 'mobile', 'cell', 'telephone', 'number') || s.phone || s.phone_number || null,
              form_name:    s.form_title || s.form_name || null,
              message:      field('message', 'note', 'comment', 'how can', 'service', 'help', 'describe', 'question') || null,
              submitted_at: s.date || s.created_at || null,
            };
          })
          // Only include submissions on/after the AI chatbot launch date
          .filter(s => !chatbotSince || !s.submitted_at || s.submitted_at >= chatbotSince);
      } catch (e) {
        console.error('[widget-events] Duda forms error:', e.message);
        return null;
      }
    })();

    const [eventsRes, trendRes, formDatesRes, formHourlyRes, widgetOpenHourlyRes, interactionRes] = await Promise.all([
      ga4Post({
        dateRanges: [{ startDate: `${days}daysAgo`, endDate: 'today' }],
        dimensions: [{ name: 'eventName' }],
        metrics: [{ name: 'eventCount' }],
        dimensionFilter: widgetFilter,
        orderBys: [{ metric: { metricName: 'eventCount' }, desc: true }],
      }),
      ga4Post({
        dateRanges: [{ startDate: `${days}daysAgo`, endDate: 'today' }],
        dimensions: [{ name: 'date' }],
        metrics: [{ name: 'eventCount' }],
        dimensionFilter: { filter: { fieldName: 'eventName', stringFilter: { matchType: 'EXACT', value: 'widget_open' } } },
        orderBys: [{ dimension: { dimensionName: 'date' } }],
      }),
      ga4Post({
        dateRanges: [{ startDate: `${days}daysAgo`, endDate: 'today' }],
        dimensions: [{ name: 'date' }],
        metrics: [{ name: 'eventCount' }],
        dimensionFilter: formSubmitFilter,
        orderBys: [{ dimension: { dimensionName: 'date' }, desc: true }],
      }),
      // Hourly breakdown for closed-loop correlation — always fetch 90 days
      ga4Post({
        dateRanges: [{ startDate: '90daysAgo', endDate: 'today' }],
        dimensions: [{ name: 'date' }, { name: 'hour' }],
        metrics: [{ name: 'eventCount' }],
        dimensionFilter: formSubmitFilter,
        orderBys: [{ dimension: { dimensionName: 'date' }, desc: true }],
      }),
      // Hourly widget_open breakdown — for Duda form closed-loop correlation
      ga4Post({
        dateRanges: [{ startDate: '90daysAgo', endDate: 'today' }],
        dimensions: [{ name: 'date' }, { name: 'hour' }],
        metrics: [{ name: 'eventCount' }],
        dimensionFilter: { filter: { fieldName: 'eventName', stringFilter: { matchType: 'EXACT', value: 'widget_open' } } },
        orderBys: [{ dimension: { dimensionName: 'date' }, desc: true }],
      }),
      // Chip / button click breakdown by label
      ga4Post({
        dateRanges: [{ startDate: `${days}daysAgo`, endDate: 'today' }],
        dimensions: [{ name: 'eventName' }, { name: 'customEvent:button_label' }],
        metrics: [{ name: 'eventCount' }],
        dimensionFilter: { orGroup: { expressions: [
          { filter: { fieldName: 'eventName', stringFilter: { matchType: 'EXACT', value: 'bcs_chip_click' } } },
          { filter: { fieldName: 'eventName', stringFilter: { matchType: 'EXACT', value: 'bcs_sub_chip_click' } } },
          { filter: { fieldName: 'eventName', stringFilter: { matchType: 'EXACT', value: 'bcs_quick_reply_click' } } },
          { filter: { fieldName: 'eventName', stringFilter: { matchType: 'EXACT', value: 'widget_button_click' } } },
        ]}},
        orderBys: [{ metric: { metricName: 'eventCount' }, desc: true }],
      }),
    ]);

    res.json({
      available: true,
      days,
      timezone: timezone || null,
      chatbotSince: chatbotSince || null,
      events: (eventsRes.rows || []).map(r => ({
        name: r.dimensionValues[0].value,
        count: parseInt(r.metricValues[0].value),
      })),
      dailyOpens: (trendRes.rows || []).map(r => ({
        date: r.dimensionValues[0].value,
        count: parseInt(r.metricValues[0].value),
      })),
      formSubmitDates: (formDatesRes.rows || []).map(r => ({
        date: r.dimensionValues[0].value,
        count: parseInt(r.metricValues[0].value),
      })),
      // Each entry = one "contact form shown" event slot, with its local date+hour
      formSubmitHourly: (formHourlyRes.rows || []).map(r => ({
        date: r.dimensionValues[0].value,
        hour: r.dimensionValues[1].value,
        count: parseInt(r.metricValues[0].value),
      })),
      // Hourly widget_open breakdown for Duda closed-loop correlation
      widgetOpenHourly: (widgetOpenHourlyRes.rows || []).map(r => ({
        date:  r.dimensionValues[0].value,
        hour:  r.dimensionValues[1].value,
        count: parseInt(r.metricValues[0].value),
      })),
      // Chip/button clicks broken down by which label was clicked
      interactionDetail: (interactionRes.rows || [])
        .filter(r => r.dimensionValues[1].value !== '(not set)')
        .map(r => ({
          event: r.dimensionValues[0].value,
          label: r.dimensionValues[1].value,
          count: parseInt(r.metricValues[0].value),
        })),
      // Duda native site form submissions (resolved in parallel above)
      dudaForms: await dudaFormsPromise,
    });
  } catch (err) {
    if (err.code === 'not_connected') return res.json({ available: false, reason: 'Analytics not connected' });
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/launches/:id/hcp-api-key', requireAuth, async (req, res) => {
  try {
    const { api_key } = req.body;
    if (!api_key || typeof api_key !== 'string') return res.status(400).json({ error: 'api_key required' });
    const ref = db.collection('launches').doc(req.params.id);
    const doc = await ref.get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    await ref.update({ hcp_api_key: api_key.trim() });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/launches/:id/analytics-start-date', requireAuth, async (req, res) => {
  try {
    const { date } = req.body;
    if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({ error: 'date required (YYYY-MM-DD)' });
    const ref = db.collection('launches').doc(req.params.id);
    const doc = await ref.get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    await ref.update({ analytics_start_date: date });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/launches/:id/hcp-leads', requireAuth, async (req, res) => {
  try {
    const doc = await db.collection('launches').doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    const { hcp_api_key, analytics_start_date, launch_date } = doc.data();
    if (!hcp_api_key) return res.json({ available: false, reason: 'No HCP API key configured' });
    const sinceDate = analytics_start_date || launch_date || null;
    const hcpHeaders = { Authorization: `Token ${hcp_api_key}`, 'Content-Type': 'application/json' };

    // Fetch leads and invoices in parallel
    const [leadsRes, invoicesRes] = await Promise.all([
      fetch('https://api.housecallpro.com/leads?page_size=100', { headers: hcpHeaders }),
      fetch('https://api.housecallpro.com/v1/invoices?page_size=200&sort_by=created_at&sort_direction=desc', { headers: hcpHeaders })
        .catch(() => null),
    ]);

    if (!leadsRes.ok) return res.status(leadsRes.status).json({ error: `HCP API error: ${leadsRes.status}` });
    const leadsData = await leadsRes.json();

    // Build customer_id → invoices map (best effort — ignore if v1 auth fails)
    let invoicesByCustomer = {};
    let invoicesAvailable = false;
    if (invoicesRes?.ok) {
      try {
        const invData = await invoicesRes.json();
        const invList = invData.invoices || invData.results || invData || [];
        if (Array.isArray(invList)) {
          invoicesAvailable = true;
          for (const inv of invList) {
            const cid = inv.customer_id || inv.customer?.id;
            if (!cid) continue;
            if (!invoicesByCustomer[cid]) invoicesByCustomer[cid] = [];
            invoicesByCustomer[cid].push({
              id:          inv.id,
              number:      inv.invoice_number || inv.number || null,
              status:      inv.status || null,
              total:       parseFloat(inv.total ?? inv.amount ?? 0),
              paid:        parseFloat(inv.paid_amount ?? 0),
              balance_due: parseFloat(inv.balance_due ?? inv.due ?? 0),
              created_at:  inv.created_at || null,
            });
          }
          console.log(`[hcp-leads] invoices loaded: ${invList.length} total, ${Object.keys(invoicesByCustomer).length} customers with invoices`);
        }
      } catch (e) { console.warn('[hcp-leads] invoice parse error:', e.message); }
    } else {
      console.log('[hcp-leads] v1/invoices status:', invoicesRes?.status, '— invoices not available');
    }

    const leads = (leadsData.leads || [])
      .filter(l => {
        if (!sinceDate || !l.customer?.created_at) return true;
        return l.customer.created_at >= sinceDate;
      })
      .map(l => {
        const customerId = l.customer?.id || null;
        const invoices = customerId ? (invoicesByCustomer[customerId] || []) : [];
        return {
          id:           l.id,
          customer_id:  customerId,
          number:       l.number,
          name:         `${l.customer?.first_name || ''} ${l.customer?.last_name || ''}`.trim(),
          phone:        l.customer?.mobile_number || l.customer?.home_number || null,
          email:        l.customer?.email || null,
          lead_source:  l.lead_source,
          status:       l.pipeline_status || l.status,
          submitted_at: l.customer?.created_at || null,
          description:  l.description || l.notes || null,
          address:      [l.customer?.street, l.customer?.city, l.customer?.state].filter(Boolean).join(', ') || null,
          invoices,
        };
      });

    res.json({ available: true, total: leads.length, since: sinceDate, invoicesAvailable, leads });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/launches/:id/forms', requireAuth, async (req, res) => {
  try {
    const doc = await db.collection('launches').doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    const siteName = doc.data().duda_site_name;
    if (!siteName) return res.json({ available: false, reason: 'No Duda site ID set' });
    const creds = await getDudaCredentials();
    const token = Buffer.from(`${creds.api_user}:${creds.api_pass}`).toString('base64');
    const r = await fetch(`https://api.duda.co/api/sites/multiscreen/get-forms/${siteName}`, {
      headers: { Authorization: `Basic ${token}`, 'Content-Type': 'application/json' },
    });
    const rawText = await r.text();
    console.log('[forms] Duda status:', r.status, 'body:', rawText.slice(0, 1500));
    if (!r.ok) return res.json({ available: false, reason: `Duda error ${r.status}: ${rawText.slice(0, 200)}` });
    const data = JSON.parse(rawText);
    // data may be an array or { results: [...] }
    const submissions = Array.isArray(data) ? data : (data.results || []);
    console.log('[forms] parsed submissions count:', submissions.length, 'first:', JSON.stringify(submissions[0]).slice(0, 300));
    res.json({ available: true, submissions });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Daily analytics cache ──────────────────────────────────────────────────
// Data is cached in Firestore under launches/{id}/analytics_cache/daily for
// 23 hours. On a cache miss the live APIs are called and the result is stored.
// Trigger POST /api/analytics/warm-all each morning via Cloud Scheduler so
// data is pre-warmed before users open the dashboard.
const ANALYTICS_CACHE_TTL_MS = 23 * 60 * 60 * 1000;

async function fetchAndCacheAnalytics(id, { force = false } = {}) {
  // 1. Return cached response if still fresh
  if (!force) {
    const cacheDoc = await db.collection('launches').doc(id)
      .collection('analytics_cache').doc('daily').get();
    if (cacheDoc.exists) {
      const { data, cachedAt } = cacheDoc.data();
      if (cachedAt && Date.now() - new Date(cachedAt).getTime() < ANALYTICS_CACHE_TTL_MS) {
        return { ...data, _cached: true, _cachedAt: cachedAt };
      }
    }
  }

  // 2. Fetch live from GSC / GA4 / Duda
  const token = await getAnalyticsAccessToken();
  const doc = await db.collection('launches').doc(id).get();
  if (!doc.exists) { const e = new Error('Not found'); e.statusCode = 404; throw e; }
  const launch = formatLaunch(doc);
  if (launch.status !== 'launched') { const e = new Error('Not a launched site'); e.statusCode = 400; throw e; }

  const domain = launch.domain_name.replace(/^https?:\/\//, '').replace(/\/$/, '');
  const rawLaunchDate = launch.status_changed_at || launch.created_at;
  const analyticsStartDate = launch.analytics_start_date || null;
  const startDate = analyticsStartDate || rawLaunchDate;
  const daysSince = Math.floor((Date.now() - new Date(startDate.replace(' ', 'T') + 'Z')) / 86_400_000);

  const [gsc, ga4PropertyId, duda] = await Promise.all([
    fetchGSC(domain, startDate, token).catch(() => ({ available: false })),
    getGa4PropertyId(domain, token).catch(() => null),
    launch.duda_site_name
      ? fetchDuda(launch.duda_site_name, startDate).catch(e => ({ available: false, reason: e.message }))
      : Promise.resolve({ available: false, reason: 'No Duda site ID set' }),
  ]);
  const ga4 = ga4PropertyId
    ? await fetchGA4(ga4PropertyId, startDate, token).catch(() => ({ available: false }))
    : { available: false, reason: 'GA4 property not found for this domain' };

  // Supplement Duda analytics with actual form submissions from the Forms API.
  // The analytics FORM_SUBMITS event can be unreliable (blocked trackers, form types
  // that don't fire the event), so we use the Forms API as the authoritative count.
  if (duda?.available && launch.duda_site_name) {
    try {
      const dudaCreds = await getDudaCredentials();
      const dudaAuth  = Buffer.from(`${dudaCreds.api_user}:${dudaCreds.api_pass}`).toString('base64');
      const fRes = await fetchWithRetry(`https://api.duda.co/api/sites/multiscreen/get-forms/${launch.duda_site_name}`, {
        headers: { Authorization: `Basic ${dudaAuth}`, 'Content-Type': 'application/json' },
      });
      if (fRes.ok) {
        const fRaw = await fRes.json();
        const subs  = Array.isArray(fRaw) ? fRaw : (fRaw.results || []);
        duda.formsApiCount = subs.length;
        // Store submission timestamps for period-filtered counts on the client
        duda.formDates = subs.map(s => s.date || s.created_at || null).filter(Boolean);
      }
    } catch (e) { console.error('[forms-cache]', e.message); }
  }

  const responseData = {
    id: launch.id, account_name: launch.account_name, domain,
    industry: launch.industry || '', launchDate: rawLaunchDate,
    analyticsStartDate, daysSince, gsc, ga4, duda,
    analytics_note:  launch.analytics_note  || '',
    duda_site_name:  launch.duda_site_name  || '',
    google_place_id: launch.google_place_id || null,
  };
  const cachedAt = new Date().toISOString();

  // 3. Persist cache + weekly snapshot (fire-and-forget)
  (async () => {
    try {
      await db.collection('launches').doc(id)
        .collection('analytics_cache').doc('daily')
        .set({ data: responseData, cachedAt });
    } catch (e) { console.error('[cache] Write error:', e.message); }

    try {
      const weekStart = new Date();
      const dow = weekStart.getDay(); // 0=Sun … 6=Sat
      weekStart.setDate(weekStart.getDate() - (dow === 0 ? 6 : dow - 1)); // back to Monday
      const weekKey = weekStart.toISOString().slice(0, 10);
      const snapRef = db.collection('launches').doc(id).collection('snapshots').doc(weekKey);
      const existing = await snapRef.get();
      if (!existing.exists) {
        const isBaseline = daysSince <= 7;
        const milestone = daysSince >= 88 ? '90day' : daysSince >= 58 ? '60day' : daysSince >= 28 ? '30day' : null;
        await snapRef.set({
          weekKey, daysSince, capturedAt: cachedAt, isBaseline, milestone,
          gsc: gsc.available ? {
            clicks: gsc.total?.clicks || 0, impressions: gsc.total?.impressions || 0,
            ctr: gsc.total?.ctr || 0, position: gsc.total?.position || null,
            topQueries: (gsc.topQueries || []).slice(0, 25),
          } : null,
          ga4: ga4.available ? { sessions: ga4.total?.sessions || 0, users: ga4.total?.users || 0 } : null,
          duda: duda?.available ? { visitors: duda.total?.visitors || 0, pageViews: duda.total?.pageViews || 0 } : null,
        });
      }
    } catch (e) { console.error('[snapshot] Error:', e.message); }
  })();

  return { ...responseData, _cached: false, _cachedAt: cachedAt };
}

// POST /api/analytics/warm-all
// Pre-warms the daily cache for every launched site in background batches.
// Set up a Cloud Scheduler job to hit this endpoint at 06:00 America/Chicago
// so data is ready before the workday: POST https://<app>/api/analytics/warm-all
// Accepts either a valid session cookie OR the X-Warm-Key header matching WARM_ALL_SECRET.
// ── Tags ──
app.get('/api/tags', requireAuth, async (req, res) => {
  try {
    const snap = await db.collection('tags').orderBy('created_at', 'asc').get();
    res.json(snap.docs.map(d => ({ id: d.id, name: d.data().name, color: d.data().color })));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/tags', requireAuth, async (req, res) => {
  const { name, color } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Tag name required' });
  try {
    const ref = await db.collection('tags').add({
      name:       name.trim(),
      color:      color || '#6366f1',
      created_at: FieldValue.serverTimestamp(),
    });
    const doc = await ref.get();
    res.status(201).json({ id: doc.id, name: doc.data().name, color: doc.data().color });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/tags/:id', requireAuth, async (req, res) => {
  const { name, color } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Tag name required' });
  try {
    const ref = db.collection('tags').doc(req.params.id);
    const updates = { name: name.trim() };
    if (color) updates.color = color;
    await ref.update(updates);
    const doc = await ref.get();
    res.json({ id: doc.id, name: doc.data().name, color: doc.data().color });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/tags/:id', requireAuth, async (req, res) => {
  try {
    await db.collection('tags').doc(req.params.id).delete();
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/launches/:id/tags', requireAuth, async (req, res) => {
  const { tags } = req.body;
  if (!Array.isArray(tags)) return res.status(400).json({ error: 'tags must be an array' });
  try {
    await db.collection('launches').doc(req.params.id).update({
      tags,
      updated_at: FieldValue.serverTimestamp(),
    });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

async function requireAuthOrWarmKey(req, res, next) {
  const key = req.headers['x-warm-key'];
  if (key && process.env.WARM_ALL_SECRET && key === process.env.WARM_ALL_SECRET) return next();
  return requireAuth(req, res, next);
}

app.post('/api/analytics/warm-all', requireAuthOrWarmKey, async (req, res) => {
  const force = req.query.force === 'true';
  try {
    const snap = await db.collection('launches').where('status', '==', 'launched').get();
    const ids = snap.docs.map(d => d.id);
    res.json({ queued: ids.length, message: `Warming cache for ${ids.length} sites in background` });
    (async () => {
      let warmed = 0, skipped = 0, failed = 0;
      for (let i = 0; i < ids.length; i += 3) {
        await Promise.all(ids.slice(i, i + 3).map(async id => {
          try {
            const result = await fetchAndCacheAnalytics(id, { force });
            if (result._cached) skipped++; else warmed++;
          } catch (e) {
            failed++;
            console.error(`[warm-all] ${id}:`, e.message);
          }
        }));
      }
      console.log(`[warm-all] Done — warmed: ${warmed}, skipped (fresh): ${skipped}, failed: ${failed}`);
    })();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Recent blog posts across all sites (for overview card)
app.get('/api/analytics/recent-blog-posts', requireAuth, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 40, 100);
    // No orderBy — avoids requiring a Firestore collection group index.
    // Fetch a larger batch and sort in JS.
    const snap = await db.collectionGroup('blog_drafts')
      .limit(limit * 4)
      .get();

    // Collect unique site IDs
    const siteIds = [...new Set(snap.docs.map(d => d.ref.parent.parent.id))];
    const siteSnaps = await Promise.all(siteIds.map(id => db.collection('launches').doc(id).get()));
    const siteMap = {};
    siteSnaps.forEach(s => {
      if (s.exists) {
        const d = s.data();
        siteMap[s.id] = { account_name: d.account_name || '', domain: d.domain_name || '', industry: d.industry || null };
      }
    });

    const sorted = snap.docs
      .sort((a, b) => {
        const aAt = a.data().pushedAt?.toDate?.() || new Date(0);
        const bAt = b.data().pushedAt?.toDate?.() || new Date(0);
        return bAt - aAt;
      })
      .slice(0, limit);

    const posts = sorted.map(doc => {
      const siteId = doc.ref.parent.parent.id;
      const data = doc.data();
      return {
        id: doc.id,
        siteId,
        title: data.title || '',
        status: data.status || 'draft',
        postId: data.postId || null,
        pushedAt: data.pushedAt?.toDate?.()?.toISOString() || null,
        industry: data.industry || siteMap[siteId]?.industry || null,
        city: data.city || null,
        keyword: data.keyword || null,
        account_name: siteMap[siteId]?.account_name || '',
        domain: siteMap[siteId]?.domain || '',
      };
    });

    res.json({ posts });
  } catch (err) {
    console.error('recent-blog-posts error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/analytics/:id', requireAuth, async (req, res) => {
  try {
    const data = await fetchAndCacheAnalytics(req.params.id, { force: req.query.force === 'true' });
    // Always serve a fresh analytics_note and tags (not frozen in cache)
    const noteDoc = await db.collection('launches').doc(req.params.id).get();
    const freshNote          = noteDoc.exists ? (noteDoc.data().analytics_note   || '') : '';
    const freshTags          = noteDoc.exists ? (noteDoc.data().tags             || []) : [];
    const freshDudaName      = noteDoc.exists ? (noteDoc.data().duda_site_name   || '') : '';
    const freshFavicon       = noteDoc.exists ? (noteDoc.data().custom_favicon   || null) : null;
    const freshHideFormSubs  = noteDoc.exists ? (noteDoc.data().hideFormSubmits  || false) : false;
    const freshPlaceId       = noteDoc.exists ? (noteDoc.data().google_place_id  || null) : null;
    const freshPlaceCity     = noteDoc.exists ? (noteDoc.data().place_city       || null) : null;
    res.json({ ...data, analytics_note: freshNote, tags: freshTags, duda_site_name: freshDudaName, custom_favicon: freshFavicon, hideFormSubmits: freshHideFormSubs, google_place_id: freshPlaceId, place_city: freshPlaceCity });
  } catch (err) {
    console.error('Analytics error:', err.message);
    if (err.code === 'not_connected') return res.status(503).json({ error: 'not_connected' });
    logApiError('analytics', err.message || 'Failed to fetch analytics', { id: req.params.id });
    res.status(err.statusCode || 500).json({ error: err.message || 'Failed to fetch analytics' });
  }
});

// ── Launch Impact — before vs after GSC comparison ──
app.get('/api/analytics/:id/gsc-impact', requireAuth, async (req, res) => {
  try {
    const id = req.params.id;

    // Check Firestore cache (skip with ?force=true)
    const cacheRef = db.collection('launches').doc(id).collection('gsc_impact_cache').doc('latest');
    if (!req.query.force) {
      const cacheSnap = await cacheRef.get();
      if (cacheSnap.exists) {
        const cached = cacheSnap.data();
        const cachedAt = cached.cachedAt ? new Date(cached.cachedAt) : null;
        if (cachedAt && (Date.now() - cachedAt.getTime()) < 24 * 60 * 60 * 1000 && cached.available) {
          return res.json(cached);
        }
      }
    }

    // Load launch doc
    const docSnap = await db.collection('launches').doc(id).get();
    if (!docSnap.exists) return res.status(404).json({ error: 'not_found' });
    const d = docSnap.data();

    const domain = (d.domain_name || '').replace(/^https?:\/\//, '').replace(/\/$/, '');
    if (!domain) return res.json({ available: false, reason: 'no_domain' });

    const rawLaunchDate = d.analytics_start_date || d.status_changed_at || d.created_at;
    if (!rawLaunchDate) return res.json({ available: false, reason: 'no_launch_date' });

    const launchDate = new Date(rawLaunchDate.toDate ? rawLaunchDate.toDate() : rawLaunchDate);
    const daysSince = Math.floor((Date.now() - launchDate.getTime()) / (1000 * 60 * 60 * 24));
    const windowWeeks = Math.min(12, Math.floor(daysSince / 7));

    if (windowWeeks < 4) {
      return res.json({ available: false, reason: 'too_early', daysSince });
    }

    const token = await getAnalyticsAccessToken();

    const preStartDate = new Date(launchDate); preStartDate.setDate(preStartDate.getDate() - windowWeeks * 7);
    const preEndDate   = new Date(launchDate); preEndDate.setDate(preEndDate.getDate() - 1);
    const postStartDate = new Date(launchDate);
    const postEndDate   = new Date(launchDate); postEndDate.setDate(postEndDate.getDate() + windowWeeks * 7);

    const preStart  = isoDate(preStartDate);
    const preEnd    = isoDate(preEndDate);
    const postStart = isoDate(postStartDate);
    const postEnd   = isoDate(postEndDate);

    // Step 1: discover the correct GSC property using the POST-launch window (guaranteed to have data)
    const postData = await fetchGSCWindow(domain, postStart, postEnd, token);
    if (!postData.siteUrl) return res.json({ available: false, reason: 'no_gsc' });

    // Step 2: query PRE-launch preferring the same property, but falling back to any candidate
    // if the post-launch property has no pre-launch data (e.g. site switched www↔non-www at launch)
    const preData = await fetchGSCWindow(domain, preStart, preEnd, token, postData.siteUrl);

    const preProp  = preData.siteUrl  || '—';
    const postProp = postData.siteUrl || '—';
    console.log(`[gsc-impact] ${domain} pre_prop=${preProp} post_prop=${postProp} pre=${preStart}→${preEnd} clicks=${preData.totals.clicks} imps=${preData.totals.impressions} | post=${postStart}→${postEnd} clicks=${postData.totals.clicks} imps=${postData.totals.impressions}`);

    // If pre window has no impressions or no weekly data at all, we can't compare meaningfully
    if (preData.totals.impressions === 0 || preData.weeks.length === 0) {
      return res.json({ available: false, reason: 'no_pre_data' });
    }

    const result = {
      available: true,
      launchDate: isoDate(launchDate),
      windowWeeks,
      gscProperty:    postData.siteUrl,
      gscPropertyPre: preData.siteUrl !== postData.siteUrl ? preData.siteUrl : null, // only set when different
      pre:  { startDate: preStart,  endDate: preEnd,  ...preData  },
      post: { startDate: postStart, endDate: postEnd, ...postData },
      cachedAt: new Date().toISOString(),
    };

    // Cache fire-and-forget
    cacheRef.set(result).catch(err => console.error('gsc-impact cache write error:', err.message));

    res.json(result);
  } catch (err) {
    console.error('gsc-impact error:', err.message);
    if (err.code === 'not_connected') return res.status(503).json({ error: 'not_connected' });
    res.status(500).json({ error: err.message || 'Failed to fetch GSC impact' });
  }
});

// Clear all gsc_impact_cache subcollection docs so impact data is re-fetched fresh
app.post('/api/analytics/clear-impact-cache', requireAuth, async (req, res) => {
  try {
    const launches = await db.collection('launches').where('status', '==', 'launched').get();
    const deletes = [];
    for (const doc of launches.docs) {
      const cacheDoc = db.collection('launches').doc(doc.id).collection('gsc_impact_cache').doc('latest');
      deletes.push(cacheDoc.delete());
    }
    await Promise.all(deletes);
    res.json({ cleared: deletes.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Core Web Vitals — reads from stored Lighthouse audits ──
app.get('/api/analytics/:id/cwv', requireAuth, async (req, res) => {
  try {
    const snapshot = await db.collection('launches').doc(req.params.id)
      .collection('lighthouse_audits').orderBy('created_at', 'desc').limit(1).get();
    if (snapshot.empty) return res.json({ url: null, mobile: null, desktop: null, created_at: null });
    const data = snapshot.docs[0].data();
    res.json({
      url:            data.url            || null,
      mobile:         data.mobile         || null,
      desktop:        data.desktop        || null,
      is_post_launch: data.is_post_launch ?? false,
      created_at:     fmtTs(data.created_at),
    });
  } catch (err) {
    console.error('CWV error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── Perf cache — latest Lighthouse score for all sites ──
app.get('/api/perf-cache', requireAuth, async (req, res) => {
  try {
    const launches = await db.collection('launches').where('status', '!=', 'decommissioned').get();
    const results = {};
    await Promise.all(launches.docs.map(async (doc) => {
      const snap = await db.collection('launches').doc(doc.id)
        .collection('lighthouse_audits').orderBy('created_at', 'desc').limit(1).get();
      if (!snap.empty) {
        const d = snap.docs[0].data();
        results[doc.id] = {
          performance:    d.performance    ?? null,
          accessibility:  d.accessibility  ?? null,
          best_practices: d.best_practices ?? null,
          seo:            d.seo            ?? null,
          mobile:         d.mobile         ?? null,
          desktop:        d.desktop        ?? null,
          is_post_launch: d.is_post_launch ?? false,
          created_at:     fmtTs(d.created_at),
        };
      }
    }));
    res.json(results);
  } catch (err) {
    console.error('Perf cache error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/analytics/:id/snapshots', requireAuth, async (req, res) => {
  try {
    const snaps = await db.collection('launches').doc(req.params.id)
      .collection('snapshots').orderBy('weekKey', 'desc').limit(16).get();
    res.json(snaps.docs.map(d => ({ id: d.id, ...d.data() })));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Google Drive Integration ──
const DRIVE_ROOT_FOLDER_ID = '1WaqG1DGZ1KHnlbUc6nTWaRAXT8ZV8O7W'; // RW Website Clients

async function driveCreateFolder(name, parentId, token) {
  const r = await fetchWithRetry('https://www.googleapis.com/drive/v3/files', {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, mimeType: 'application/vnd.google-apps.folder', parents: [parentId] }),
  });
  if (!r.ok) {
    const errBody = await r.text().catch(() => '');
    throw new Error(`Drive folder create failed (${r.status}): ${errBody.slice(0, 200)}`);
  }
  return (await r.json()).id;
}

async function driveFindFolder(name, parentId, token) {
  const q = encodeURIComponent(`name='${name.replace(/'/g, "\\'")}' and '${parentId}' in parents and mimeType='application/vnd.google-apps.folder' and trashed=false`);
  const r = await fetchWithRetry(`https://www.googleapis.com/drive/v3/files?q=${q}&fields=files(id,name)&pageSize=1`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!r.ok) {
    const errBody = await r.text().catch(() => '');
    console.warn(`[drive] findFolder failed (${r.status}):`, errBody.slice(0, 200));
    return null;
  }
  const data = await r.json();
  return data.files?.[0]?.id || null;
}

async function driveGetOrCreateClientFolder(clientName, token) {
  // Find or create: RW Website Clients / {clientName}
  let clientFolderId = await driveFindFolder(clientName, DRIVE_ROOT_FOLDER_ID, token);
  if (!clientFolderId) clientFolderId = await driveCreateFolder(clientName, DRIVE_ROOT_FOLDER_ID, token);
  return clientFolderId;
}

async function driveGetOrCreateSubfolder(subfolderName, parentId, token) {
  let folderId = await driveFindFolder(subfolderName, parentId, token);
  if (!folderId) folderId = await driveCreateFolder(subfolderName, parentId, token);
  return folderId;
}

async function driveUploadFile(name, content, mimeType, parentId, token) {
  const metadata = { name, parents: [parentId] };
  const boundary = '-----DriveUploadBoundary';
  const body = `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify(metadata)}\r\n--${boundary}\r\nContent-Type: ${mimeType}\r\n\r\n${content}\r\n--${boundary}--`;
  const r = await fetchWithRetry('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,webViewLink', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': `multipart/related; boundary=${boundary}`,
    },
    body,
  });
  if (!r.ok) throw new Error(`Drive upload failed: ${r.status}`);
  return r.json();
}

// Push onboarding profile + transcript to Google Drive
async function pushOnboardingToDrive(launchId, clientName, profile, transcript) {
  try {
    const token = await getAnalyticsAccessToken();
    const clientFolderId = await driveGetOrCreateClientFolder(clientName, token);
    const obFolderId = await driveGetOrCreateSubfolder('Onboarding', clientFolderId, token);

    const date = new Date().toISOString().slice(0, 10);
    // Upload profile JSON
    const profileFile = await driveUploadFile(
      `Onboarding Profile — ${date}.json`,
      JSON.stringify(profile, null, 2),
      'application/json',
      obFolderId, token
    );

    // Upload transcript if available
    let transcriptFile = null;
    if (transcript) {
      transcriptFile = await driveUploadFile(
        `Interview Transcript — ${date}.txt`,
        typeof transcript === 'string' ? transcript : JSON.stringify(transcript, null, 2),
        'text/plain',
        obFolderId, token
      );
    }

    // Save Drive folder ID on the launch doc for quick access
    await db.collection('launches').doc(launchId).update({
      drive_folder_id: clientFolderId,
      drive_folder_url: `https://drive.google.com/drive/folders/${clientFolderId}`,
    }).catch(() => {});

    console.log(`[drive] Pushed onboarding for ${clientName} → folder ${clientFolderId}`);
    return { clientFolderId, profileFileId: profileFile?.id, transcriptFileId: transcriptFile?.id };
  } catch (err) {
    console.warn('[drive] Failed to push onboarding to Drive:', err.message);
    return null; // Don't fail the main operation
  }
}

// Push a blog post to Google Drive
async function pushBlogToDrive(launchId, clientName, title, html) {
  try {
    const token = await getAnalyticsAccessToken();
    const clientFolderId = await driveGetOrCreateClientFolder(clientName, token);
    const blogFolderId = await driveGetOrCreateSubfolder('Blog Posts', clientFolderId, token);

    const date = new Date().toISOString().slice(0, 10);
    const safeName = title.replace(/[<>:"/\\|?*]/g, '').slice(0, 80);
    const file = await driveUploadFile(
      `${date} — ${safeName}.html`,
      html,
      'text/html',
      blogFolderId, token
    );

    // Save Drive folder ID on the launch doc if not already set
    await db.collection('launches').doc(launchId).update({
      drive_folder_id: clientFolderId,
      drive_folder_url: `https://drive.google.com/drive/folders/${clientFolderId}`,
    }).catch(() => {});

    return file;
  } catch (err) {
    console.warn('[drive] Failed to push blog to Drive:', err.message);
    return null;
  }
}

// ── Blog Draft Generator (Gemini + Duda Blog API) ──
app.post('/api/analytics/:id/generate-blog', requireAuth, async (req, res) => {
  const { keyword } = req.body;
  if (!keyword) return res.status(400).json({ error: 'keyword is required' });

  const geminiKey = await getGeminiKey().catch(() => null);
  if (!geminiKey) return res.status(500).json({ error: 'Gemini API key not configured — add it in Firestore config/gemini_credentials.api_key' });

  try {
    const doc = await db.collection('launches').doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ error: 'Site not found' });
    const launch = formatLaunch(doc);
    const siteName = doc.data().duda_site_name;
    if (!siteName) return res.status(400).json({ error: 'No Duda site name configured for this site' });

    const domain   = launch.domain_name.replace(/^https?:\/\//, '').replace(/\/$/, '');
    const industry = launch.industry || 'home services';
    const bizName  = launch.account_name;

    // Generate post with Gemini
    const prompt = `You are a local SEO content writer. Write a blog post for a ${industry} company called "${bizName}" (${domain}).

Target keyword: "${keyword}"

Requirements:
- Title: Naturally include the keyword, make it useful and click-worthy
- Length: 600–800 words
- Format: Return valid HTML. Use <h1> for the title, <h2> for 2–3 section headings, <p> for paragraphs
- Tone: Helpful, friendly, professional — written for local homeowners or property owners
- Include practical tips relevant to the service
- Mention the local area naturally where it fits
- End with a short call-to-action paragraph encouraging readers to contact ${bizName}
- Do NOT include <html>, <head>, or <body> tags — start directly with the <h1>

Return only the HTML content, no markdown fencing, no explanation.`;

    const gRes = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${geminiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: { temperature: 0.7, maxOutputTokens: 2048 },
        }),
      }
    );
    const gData = await gRes.json();
    console.log('Gemini response status:', gRes.status, JSON.stringify(gData).slice(0, 300));
    let content = gData.candidates?.[0]?.content?.parts?.[0]?.text || '';
    if (!content) return res.status(500).json({ error: gData.error?.message || gData.promptFeedback?.blockReason || 'Gemini returned no content' });
    // Strip accidental markdown code fences
    content = content.replace(/^```html?\s*/i, '').replace(/```\s*$/, '').trim();

    // Extract title from <h1>
    const titleMatch = content.match(/<h1[^>]*>([\s\S]*?)<\/h1>/i);
    const title = titleMatch ? titleMatch[1].replace(/<[^>]+>/g, '').trim() : `${keyword} — ${bizName}`;

    // Post to Duda as draft (INACTIVE = unpublished)
    const creds  = await getDudaCredentials();
    const token  = Buffer.from(`${creds.api_user}:${creds.api_pass}`).toString('base64');
    const dRes   = await fetch(
      `https://api.duda.co/api/sites/multiscreen/${siteName}/blog/posts/import`,
      {
        method: 'POST',
        headers: { Authorization: `Basic ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title,
          description: `Blog post targeting: ${keyword}`,
          content: Buffer.from(content).toString('base64'),
          author: bizName,
        }),
      }
    );

    if (!dRes.ok) {
      const txt = await dRes.text();
      console.error('Duda blog API error:', dRes.status, txt);
      return res.status(502).json({ error: `Duda API error (${dRes.status}): ${txt || 'empty response'}` });
    }

    const post = await dRes.json();
    res.json({ success: true, title, postId: post.id || null });
  } catch (err) {
    console.error('generate-blog error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/launches/:id/place-city', requireAuth, async (req, res) => {
  try {
    const { city } = req.body;
    if (typeof city !== 'string') return res.status(400).json({ error: 'city required' });
    const ref = db.collection('launches').doc(req.params.id);
    if (!(await ref.get()).exists) return res.status(404).json({ error: 'Not found' });
    await ref.update({ place_city: city.trim() || null });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Push a pre-generated HTML blog post to a specific site's Duda blog
app.post('/api/launches/:id/place-id', requireAuth, async (req, res) => {
  try {
    const { place_id } = req.body;
    if (typeof place_id !== 'string') return res.status(400).json({ error: 'place_id required' });
    const ref = db.collection('launches').doc(req.params.id);
    if (!(await ref.get()).exists) return res.status(404).json({ error: 'Not found' });
    const trimmedId = place_id.trim() || null;
    const city = trimmedId ? await fetchPlaceCity(trimmedId) : null;
    await ref.update({ google_place_id: trimmedId, ...(city !== undefined ? { place_city: city } : {}) });
    res.json({ ok: true, place_city: city });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/analytics/:id/push-blog', requireAuth, async (req, res) => {
  const { title, html, publish = false, heroImageUrl } = req.body;
  if (!title || !html) return res.status(400).json({ error: 'title and html are required' });
  try {
    const doc = await db.collection('launches').doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ error: 'Site not found' });
    const launch = formatLaunch(doc);
    const siteName = doc.data().duda_site_name;
    if (!siteName) return res.status(400).json({ error: 'No Duda site name configured for this site' });
    const creds = await getDudaCredentials();
    const token = Buffer.from(`${creds.api_user}:${creds.api_pass}`).toString('base64');
    const authHeader = { Authorization: `Basic ${token}`, 'Content-Type': 'application/json' };

    // Step 1: Import (always creates a draft)
    console.log('[push-blog] heroImageUrl:', heroImageUrl || '(none)');
    const dRes = await fetch(
      `https://api.duda.co/api/sites/multiscreen/${siteName}/blog/posts/import`,
      {
        method: 'POST',
        headers: authHeader,
        body: JSON.stringify({
          title,
          description: '',
          content: Buffer.from(heroImageUrl
            ? `<div style="width:100%;margin:0 0 2rem;border-radius:6px;overflow:hidden"><img src="${heroImageUrl}" alt="" style="width:100%;height:auto;display:block"></div>\n${html}`
            : html
          ).toString('base64'),
          author: launch.account_name || 'Team',
        }),
      }
    );
    if (!dRes.ok) {
      const txt = await dRes.text();
      return res.status(502).json({ error: `Duda API error (${dRes.status}): ${txt || 'empty response'}` });
    }
    const post = await dRes.json();
    const postId = post.id || null;

    // Step 1.5: Set thumbnail via PATCH if we have a hero image
    if (postId && heroImageUrl) {
      try {
        await fetch(
          `https://api.duda.co/api/sites/multiscreen/${siteName}/blog/posts/${postId}`,
          {
            method: 'PATCH',
            headers: authHeader,
            body: JSON.stringify({ thumbnail: heroImageUrl }),
          }
        );
      } catch (e) {
        console.warn('[push-blog] thumbnail PATCH failed:', e.message);
      }
    }

    // Step 2: Publish if requested
    if (publish && postId) {
      const pRes = await fetch(
        `https://api.duda.co/api/sites/multiscreen/${siteName}/blog/posts/${postId}/publish`,
        { method: 'POST', headers: authHeader }
      );
      if (!pRes.ok) {
        const txt = await pRes.text();
        console.error('Duda publish error:', pRes.status, txt);
        // Still saved the draft — surface the publish failure to the client
        return res.status(502).json({ error: `Post saved but publish failed (${pRes.status}): ${txt || 'empty response'}` });
      }
    }

    const status = publish ? 'published' : 'draft';
    const launchRef = db.collection('launches').doc(req.params.id);
    const draftWrite = launchRef.collection('blog_drafts').add({
      title,
      postId,
      status,
      pushedAt: new Date(),
      industry: req.body.industry || null,
      city: req.body.city || null,
      keyword: req.body.keyword || null,
      questionId: req.body.questionId || null,
      heroImageUrl: req.body.heroImageUrl || null,
    });
    const excludeWrite = req.body.questionId
      ? launchRef.update({ blog_excluded_ids: FieldValue.arrayUnion(req.body.questionId) })
      : Promise.resolve();
    await Promise.all([draftWrite, excludeWrite]);
    res.json({ success: true, title, postId, status });

    // Push to Google Drive in the background (fire-and-forget)
    pushBlogToDrive(req.params.id, launch.account_name, title, html).catch(() => {});
  } catch (err) {
    console.error('push-blog error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/analytics/:id/blog-history', requireAuth, async (req, res) => {
  try {
    const snap = await db.collection('launches').doc(req.params.id)
      .collection('blog_drafts')
      .orderBy('pushedAt', 'desc')
      .limit(50)
      .get();
    const posts = snap.docs.map(d => ({
      id: d.id,
      ...d.data(),
      pushedAt: d.data().pushedAt?.toDate?.()?.toISOString() || null,
    }));
    res.json({ posts });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Save a generated post to Firestore without pushing to Duda (queued status)
app.post('/api/analytics/:id/save-blog-draft', requireAuth, async (req, res) => {
  const { title, html, industry, city, keyword, questionId, heroImageUrl } = req.body;
  if (!title || !html) return res.status(400).json({ error: 'title and html required' });
  try {
    const ref = db.collection('launches').doc(req.params.id);
    if (!(await ref.get()).exists) return res.status(404).json({ error: 'Site not found' });
    const doc = await ref.collection('blog_drafts').add({
      title,
      html,
      status: 'queued',
      pushedAt: new Date(),
      industry: industry || null,
      city: city || null,
      keyword: keyword || null,
      questionId: questionId || null,
      heroImageUrl: heroImageUrl || null,
    });
    res.json({ success: true, id: doc.id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete a blog draft record from Firestore (does NOT touch Duda)
app.delete('/api/analytics/:siteId/blog-drafts/:draftId', requireAuth, async (req, res) => {
  try {
    await db.collection('launches').doc(req.params.siteId)
      .collection('blog_drafts').doc(req.params.draftId).delete();
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Fetch a specific blog draft (including html content for preview)
app.get('/api/analytics/:siteId/blog-drafts/:draftId', requireAuth, async (req, res) => {
  try {
    const doc = await db.collection('launches').doc(req.params.siteId)
      .collection('blog_drafts').doc(req.params.draftId).get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    const data = doc.data();
    res.json({
      id: doc.id,
      title: data.title || '',
      html: data.html || null,
      status: data.status || 'queued',
      industry: data.industry || null,
      city: data.city || null,
      keyword: data.keyword || null,
      questionId: data.questionId || null,
      pushedAt: data.pushedAt?.toDate?.()?.toISOString() || null,
      heroImageUrl: data.heroImageUrl || null,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Reddit OAuth ──
// Reads credentials from Firestore config/reddit_credentials.
// Returns null gracefully if not configured — callers fall back to anonymous.
let _redditToken = null;
let _redditTokenExpiry = 0;
let _redditUsername = null;

async function getRedditToken() {
  if (_redditToken && Date.now() < _redditTokenExpiry) return { token: _redditToken, username: _redditUsername };
  try {
    const snap = await db.collection('config').doc('reddit_credentials').get();
    if (!snap.exists) return null;
    const { client_id, client_secret, username, password } = snap.data();
    if (!client_id || !client_secret || !username || !password) return null;
    const basic = Buffer.from(`${client_id}:${client_secret}`).toString('base64');
    const res = await fetch('https://www.reddit.com/api/v1/access_token', {
      method: 'POST',
      headers: {
        Authorization: `Basic ${basic}`,
        'User-Agent': `SiteLaunchTracker/1.0 (by /u/${username})`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ grant_type: 'password', username, password }),
    });
    if (!res.ok) { console.warn('Reddit OAuth failed:', res.status, await res.text()); return null; }
    const data = await res.json();
    if (!data.access_token) return null;
    _redditToken = data.access_token;
    _redditUsername = username;
    _redditTokenExpiry = Date.now() + ((data.expires_in || 86400) - 300) * 1000;
    return { token: _redditToken, username };
  } catch (e) {
    console.warn('getRedditToken error:', e.message);
    return null;
  }
}

// ── Blog Generator ──
// Returns true for Reddit titles too vague to generate a useful blog post from
function isVagueTitle(title) {
  if (!title) return true;
  const t = title.trim();
  if (t.length < 20) return true;
  // Purely demonstrative — no concrete subject
  if (/^(what|which|who)\s+(is|are|was|were)?\s*(this|these|that|those|it)\b/i.test(t)) return true;
  if (/^which\s+one\b/i.test(t)) return true;
  if (/^(what would you do|wwyd)\b/i.test(t)) return true;
  // Short sentences whose only noun is a demonstrative
  if (t.split(/\s+/).length <= 6 && /\b(this|these|that|those)\b/i.test(t)) return true;
  return false;
}

const INDUSTRY_SUBREDDITS = {
  'plumbing':           ['Plumbing', 'DIY', 'HomeImprovement'],
  'roofing':            ['Roofing', 'HomeImprovement', 'DIY'],
  'hvac':               ['hvacadvice', 'HVAC', 'HomeImprovement'],
  'home improvement':   ['HomeImprovement', 'DIY', 'fixit'],
  'diy':                ['DIY', 'HomeImprovement', 'fixit'],
  'landscaping':        ['landscaping', 'gardening', 'HomeImprovement'],
  'electrical':         ['electrical', 'DIY', 'HomeImprovement'],
  'painting':           ['paint', 'DIY', 'HomeImprovement'],
  'flooring':           ['flooring', 'DIY', 'HomeImprovement'],
  'general contractor': ['HomeImprovement', 'DIY', 'fixit'],
};

app.post('/api/launches/:id/blog-dismiss', requireAuth, async (req, res) => {
  try {
    const { question_ids } = req.body;
    if (!Array.isArray(question_ids) || !question_ids.length) return res.status(400).json({ error: 'question_ids array required' });
    const ref = db.collection('launches').doc(req.params.id);
    if (!(await ref.get()).exists) return res.status(404).json({ error: 'Not found' });
    await ref.update({ blog_excluded_ids: FieldValue.arrayUnion(...question_ids) });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/blog/questions', requireAuth, async (req, res) => {
  try {
    const { industry, city, launchId } = req.body;
    if (!industry) return res.status(400).json({ error: 'industry is required' });

    // Load excluded IDs (dismissed + already used) for this launch
    let excludedIds = new Set();
    if (launchId) {
      const snap = await db.collection('launches').doc(launchId).get();
      if (snap.exists) {
        const ids = snap.data().blog_excluded_ids || [];
        ids.forEach(id => excludedIds.add(id));
      }
    }

    const key = industry.toLowerCase();
    const subreddits = INDUSTRY_SUBREDDITS[key] || ['HomeImprovement', 'DIY'];
    let questions = [];

    // Layer 1: Reddit API — OAuth if credentials are in Firestore, anonymous otherwise
    try {
      const auth = await getRedditToken();
      const baseUrl = auth ? 'https://oauth.reddit.com' : 'https://www.reddit.com';
      const headers = auth
        ? { Authorization: `Bearer ${auth.token}`, 'User-Agent': `SiteLaunchTracker/1.0 (by /u/${auth.username})` }
        : { 'User-Agent': 'SiteLaunchTracker/1.0 (internal marketing tool)' };

      for (const sub of subreddits) {
        if (questions.length >= 5) break;
        // Only throttle for anonymous requests — OAuth has much higher rate limits
        if (!auth && questions.length > 0) await new Promise(r => setTimeout(r, 600));
        const rRes = await fetch(`${baseUrl}/r/${sub}/top.json?t=week&limit=50`, { headers });
        if (!rRes.ok) continue;
        const rData = await rRes.json();
        const posts = (rData.data?.children || [])
          .filter(p =>
            !p.data.stickied && p.data.score > 5 && p.data.title &&
            !isVagueTitle(p.data.title) &&
            !excludedIds.has(p.data.id) &&
            (p.data.title.includes('?') || (p.data.selftext && p.data.selftext.length > 20))
          )
          .map(p => ({
            id: p.data.id,
            title: p.data.title,
            detail: (p.data.selftext || '').slice(0, 200).replace(/\n+/g, ' ').trim() || null,
            upvotes: p.data.score,
            subreddit: p.data.subreddit,
            url: 'https://reddit.com' + p.data.permalink,
          }));
        questions.push(...posts);
      }
      questions = questions.slice(0, 10);
    } catch (e) {
      console.warn('Reddit API failed:', e.message);
    }

    // Layer 2: Reddit RSS fallback
    if (questions.length < 5) {
      try {
        for (const sub of subreddits) {
          if (questions.length >= 5) break;
          const rRes = await fetch(`https://www.reddit.com/r/${sub}/top.rss?t=week&limit=25`, {
            headers: { 'User-Agent': 'SiteLaunchTracker/1.0 (internal marketing tool)' },
          });
          if (!rRes.ok) continue;
          const xml = await rRes.text();
          const titles = [...xml.matchAll(/<entry>[\s\S]*?<title[^>]*>([^<]+)<\/title>/g)]
            .map(m => m[1].trim().replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>'))
            .filter(t => t.includes('?') && !isVagueTitle(t));
          const newPosts = titles.map((title, i) => ({
            id: 'q' + (questions.length + i + 1),
            title,
            detail: null,
            upvotes: null,
            subreddit: sub,
            url: null,
          }));
          questions.push(...newPosts);
        }
        questions = questions.slice(0, 10);
      } catch (e) {
        console.warn('Reddit RSS failed:', e.message);
      }
    }

    // Layer 3: Gemini text generation (last resort) — with seasonal awareness
    if (questions.length < 5) {
      const location = city ? ` in ${city}` : '';
      const geminiKey = await getGeminiKey();
      const monthNames = ['January','February','March','April','May','June','July','August','September','October','November','December'];
      const currentMonth = monthNames[new Date().getMonth()];
      const SEASONAL_HINTS = {
        hvac:        { 'January':'furnace emergency tips, heating costs','February':'indoor air quality, humidifiers','March':'spring AC prep','April':'AC tune-up, filter replacement','May':'pre-summer AC check','June':'emergency AC, energy efficiency','July':'AC troubleshooting, thermostats','August':'air quality','September':'fall HVAC prep, furnace','October':'furnace tune-up, heat pumps','November':'heating emergency, thermostats','December':'holiday heating tips' },
        roofing:     { 'January':'ice dam prevention','February':'winter inspection, attic insulation','March':'spring inspection, gutters','April':'storm damage prep','May':'storm damage, hail season','June':'summer heat, flat roof','July':'emergency leak repair','August':'end of hail season','September':'fall inspection, pre-winter','October':'winter prep, moss treatment','November':'pre-winter gutter cleaning','December':'ice dam prevention, warranty' },
        plumbing:    { 'January':'frozen pipe emergency','February':'water heater maintenance','March':'spring inspection','April':'outdoor faucets','May':'sump pump check','June':'summer plumbing tips','July':'water conservation','August':'back-to-school plumbing','September':'fall prep','October':'winterize pipes','November':'outdoor faucet shutoff','December':'holiday plumbing tips' },
        electrical:  { 'January':'winter electrical safety','February':'electrical panel check','March':'spring electrical inspection','April':'outdoor lighting','May':'pre-summer AC electrical load','June':'summer energy efficiency','July':'surge protection','August':'back-to-school wiring','September':'generator prep, storm prep','October':'fall electrical safety','November':'holiday lighting safety','December':'holiday lighting, generator' },
        restoration: { 'January':'winter pipe burst damage','February':'ice dam water damage','March':'spring flood prep','April':'flood prep, water damage','May':'hurricane season prep','June':'storm damage restoration','July':'mold after flooding','August':'humidity and mold','September':'fall storm prep','October':'winter pipe burst prevention','November':'pre-winter prep','December':'holiday fire safety' },
      };
      const seasonalHint = SEASONAL_HINTS[industry.toLowerCase()]?.[currentMonth] || '';
      const seasonalLine = seasonalHint ? `\nIt is currently ${currentMonth}. Weight 3-4 of the questions toward seasonal topics relevant right now: ${seasonalHint}.` : `\nIt is currently ${currentMonth}. Include 2-3 seasonally relevant questions for this time of year.`;
      const prompt = `You are simulating Reddit posts from homeowners${location} asking questions about ${industry}.
Generate exactly 10 realistic questions a homeowner might post on r/HomeImprovement or r/DIY.${seasonalLine}
Mix question types: 2-3 problem/symptom questions, 1-2 cost questions, 1-2 seasonal/maintenance questions, 1 emergency question, and 1-2 general "how do I choose" or trust questions.
Return ONLY a valid JSON array with no markdown, no code fences, no explanation. Each item must have:
{"id": "q1", "title": "short question headline under 80 chars", "detail": "1-2 sentence context from homeowner perspective", "upvotes": 42, "suggestedType": "symptom|cost|seasonal|emergency|trust"}
ids must be q1 through q10. upvotes should be realistic numbers between 12 and 847.`;
      const gRes = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${geminiKey}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] }),
      });
      const gData = await gRes.json();
      if (gRes.ok) {
        const raw = gData.candidates?.[0]?.content?.parts?.[0]?.text || '';
        const jsonMatch = raw.match(/\[[\s\S]*\]/);
        if (jsonMatch) questions = JSON.parse(jsonMatch[0]);
      }
    }

    const source = !questions[0]?.subreddit ? 'ai' : questions[0]?.upvotes != null ? 'reddit' : 'rss';
    res.json({ questions, subreddits, source });
  } catch (err) {
    console.error('blog/questions error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── Blog context endpoint — returns available data sources for a launch ──
app.get('/api/blog/context/:id', requireAuth, async (req, res) => {
  try {
    const doc = await db.collection('launches').doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ error: 'Launch not found' });
    const d = doc.data();

    // Parse research keywords
    let researchKeywords = [];
    if (d.research_md) {
      const kwSection = d.research_md.match(/### (?:Primary|Location|Service|Problem|Long-Tail)[\s\S]*?(?=###|$)/gi);
      researchKeywords = [...d.research_md.matchAll(/^- (.+)$/gm)].map(m => m[1].trim()).slice(0, 30);
    }

    // Fetch Google rating if place ID exists
    let placeRating = null;
    if (d.google_place_id) {
      try {
        const pd = await fetchPlaceRating(d.google_place_id);
        if (pd) placeRating = { rating: pd.rating, reviewCount: pd.reviewCount };
      } catch (e) { /* ignore */ }
    }

    // Count GSC keywords if analytics data exists
    let gscKeywordCount = 0;
    try {
      const analyticsDoc = await db.collection('launches').doc(req.params.id).collection('analytics').doc('latest').get();
      if (analyticsDoc.exists) {
        const ad = analyticsDoc.data();
        gscKeywordCount = (ad.gsc_queries || []).length;
      }
    } catch (e) { /* ignore */ }

    res.json({
      onboarding: { available: !!d.onboarding_profile, profile: d.onboarding_profile || null },
      research: { available: !!d.research_md, keywords: researchKeywords },
      projects: { available: !!(d.projects?.length), count: d.projects?.length || 0, items: d.projects || [] },
      placeId: d.google_place_id || null,
      placeRating,
      gscKeywordCount,
      industry: d.industry,
      city: d.place_city,
      domain: d.domain_name,
      accountName: d.account_name,
    });
  } catch (err) {
    console.error('blog/context error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── Blog topic suggestions — AI-generated topics based on client data ──
app.post('/api/blog/suggest-topics', requireAuth, async (req, res) => {
  try {
    const { launchId, contentType } = req.body;
    if (!launchId) return res.status(400).json({ error: 'launchId is required' });

    const doc = await db.collection('launches').doc(launchId).get();
    if (!doc.exists) return res.status(404).json({ error: 'Launch not found' });
    const d = doc.data();

    const industry = d.industry || 'home services';
    const city = d.place_city || '';
    const bizName = d.account_name || '';

    // Build context from available data
    const contextParts = [];

    if (d.onboarding_profile) {
      const ob = d.onboarding_profile;
      if (ob.services?.core?.length) contextParts.push(`Core services: ${ob.services.core.join(', ')}`);
      if (ob.differentiation?.unique_selling_points?.length) contextParts.push(`USPs: ${ob.differentiation.unique_selling_points.join('; ')}`);
      if (ob.service_area?.cities?.length) contextParts.push(`Service area: ${ob.service_area.cities.join(', ')}`);
    }

    if (d.research_md) {
      const kwLines = [...d.research_md.matchAll(/^- (.+)$/gm)].map(m => m[1].trim()).slice(0, 15);
      if (kwLines.length) contextParts.push(`SEO keywords from research: ${kwLines.join(', ')}`);
    }

    if (d.projects?.length) {
      const projSummary = d.projects.slice(0, 3).map(p => p.job_title || 'Untitled project').join('; ');
      contextParts.push(`Recent projects: ${projSummary}`);
    }

    const CONTENT_TYPE_LABELS = {
      symptom: 'Problem / Symptom',
      cost: 'Cost / Buying Guide',
      seasonal: 'Seasonal / Maintenance',
      emergency: 'Emergency / Urgent',
      trust: 'Trust / Authority',
    };
    const ctLabel = CONTENT_TYPE_LABELS[contentType] || CONTENT_TYPE_LABELS.symptom;
    const monthNames = ['January','February','March','April','May','June','July','August','September','October','November','December'];
    const currentMonth = monthNames[new Date().getMonth()];

    const contextBlock = contextParts.length ? `\n\nClient context:\n${contextParts.join('\n')}` : '';

    const prompt = `You are a local SEO content strategist for home service contractors.

Suggest exactly 6 blog post topics for a ${ctLabel} post for a ${industry} company${city ? ` in ${city}` : ''}${bizName ? ` called "${bizName}"` : ''}.
It is currently ${currentMonth} — weight 2-3 suggestions toward seasonally relevant topics.
${contextBlock}

Each topic should be a specific, actionable blog post idea that targets real homeowner search intent.
Return ONLY a valid JSON array with no markdown, no code fences. Each item must have:
{"title": "Blog post title under 70 chars", "description": "One sentence describing the angle and target audience"}`;

    const geminiKey = await getGeminiKey();
    const gRes = await fetchWithRetry(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${geminiKey}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { temperature: 0.8, maxOutputTokens: 2048, thinkingConfig: { thinkingBudget: 0 } } }),
    });
    const gData = await gRes.json();
    if (!gRes.ok) throw new Error(gData.error?.message || 'Gemini error');
    // Grab the last text part (skip thinking part if present)
    const parts = gData.candidates?.[0]?.content?.parts || [];
    const raw = (parts.filter(p => p.text).pop()?.text || '').trim();
    const cleaned = raw.replace(/^```json?\s*/i, '').replace(/```\s*$/, '').trim();
    const jsonMatch = cleaned.match(/\[[\s\S]*\]/);
    if (!jsonMatch) throw new Error('Failed to parse AI response');
    const topics = JSON.parse(jsonMatch[0]);
    res.json({ topics });
  } catch (err) {
    console.error('blog/suggest-topics error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/blog/post', requireAuth, async (req, res) => {
  try {
    const { industry, city: cityParam, question, detail, keywords, bizName, domain, wordCount, placeId, contentType: rawContentType } = req.body;
    const kwArray = Array.isArray(keywords) ? keywords.filter(Boolean) : (keywords ? [keywords] : []);
    if (!industry || !question) return res.status(400).json({ error: 'industry and question are required' });
    const cleanDomain = domain ? domain.replace(/^https?:\/\//, '').replace(/\/$/, '') : null;
    const geminiKey = await getGeminiKey();

    // ── Content type definitions ──
    const CONTENT_TYPES = {
      symptom: {
        label: 'Problem / Symptom',
        wordRange: [800, 1200], defaultWords: 800,
        structure: `- Open with a 1-2 sentence direct answer to the symptom/problem question
- 3-4 <h2> sections phrased as questions (e.g. "What Causes [Symptom]?", "Is [Symptom] Dangerous?", "How Much Does It Cost to Fix [Symptom]?")
- Immediately after each question-format <h2>, write a single direct-answer sentence BEFORE any elaboration — this is critical for AI Overview citations
- Include a mid-post CTA after the first major section (e.g. "Not sure what's causing this? Call [bizName] for a free diagnosis")`,
        ctaStyle: 'Not sure what is wrong? Our technicians diagnose for free — call [bizName] today',
      },
      cost: {
        label: 'Cost / Buying Guide',
        wordRange: [1000, 1500], defaultWords: 1000,
        structure: `- Open with a clear average cost range in the FIRST paragraph (e.g. "Most homeowners pay between $X and $Y"). NEVER write "costs vary" without a specific dollar range
- 3-4 <h2> sections phrased as questions (e.g. "How Much Does [Service] Cost?", "What Factors Affect [Service] Cost?", "Is It Worth Repairing or Replacing?")
- Immediately after each question-format <h2>, write a single direct-answer sentence BEFORE any elaboration
- Include a cost breakdown: what drives cost up or down (size, material, labor, location)
- If relevant, include a repair vs replace comparison
- Include a mid-post CTA after the cost breakdown (e.g. "Want an exact quote? [bizName] offers free estimates — no obligation")`,
        ctaStyle: 'Get a free estimate from [bizName] — no obligation',
      },
      seasonal: {
        label: 'Seasonal Prep / Maintenance',
        wordRange: [800, 1200], defaultWords: 800,
        structure: `- Open with a timely hook referencing the current season and why this maintenance matters NOW
- 3-4 <h2> sections phrased as questions (e.g. "When Should You Schedule [Service]?", "What Does a [Season] [Service] Include?", "How Much Does [Service] Cost?")
- Immediately after each question-format <h2>, write a single direct-answer sentence BEFORE any elaboration
- Use numbered lists for step-by-step checklists
- Reference the local climate when discussing seasonal patterns
- Include a mid-post CTA (e.g. "Schedule your [season] tune-up with [bizName] before spots fill up")`,
        ctaStyle: 'Schedule your tune-up with [bizName] before spots fill up',
      },
      emergency: {
        label: 'Emergency / Urgent Action',
        wordRange: [500, 800], defaultWords: 600,
        structure: `- Open with a 2-3 step "do this right now" summary at the VERY TOP — formatted as a numbered list
- Keep paragraphs extremely short (2-3 sentences max) — the reader is in crisis
- 2-3 <h2> sections phrased as questions (e.g. "What Should You Do Right Now?", "How Dangerous Is [Problem]?", "What Will a Professional Do When They Arrive?")
- Immediately after each question-format <h2>, write a single direct-answer sentence BEFORE any elaboration — voice search pulls this verbatim
- Briefly explain the risk if they delay
- Describe what the professional will do when they arrive
- Include a PROMINENT mid-post CTA with phone mention (e.g. "Call [bizName] now — we answer 24/7")`,
        ctaStyle: 'Call [bizName] now — we answer 24/7',
      },
      trust: {
        label: 'Trust / Authority',
        wordRange: [1000, 2000], defaultWords: 1200,
        structure: `- Frame as a process walkthrough, scam awareness guide, or industry explainer
- 3-4 <h2> sections phrased as questions (e.g. "What Should You Expect During [Service]?", "How Do You Spot a Dishonest [Trade] Contractor?", "What Questions Should You Ask Before Hiring?")
- Immediately after each question-format <h2>, write a single direct-answer sentence BEFORE any elaboration
- Position the business as transparent and trustworthy — show expertise through specifics, not claims
- Include a mid-post CTA (e.g. "Want to see how [bizName] handles this? Check out our customer reviews")`,
        ctaStyle: 'See why homeowners trust [bizName] — read our customer reviews',
      },
    };

    const contentType = CONTENT_TYPES[rawContentType] ? rawContentType : 'symptom';
    const ct = CONTENT_TYPES[contentType];
    const words = Math.min(Math.max(parseInt(wordCount) || ct.defaultWords, ct.wordRange[0]), ct.wordRange[1]);

    // Fetch Google place data (rating + city) if a Place ID is provided
    const placeData = placeId ? await fetchPlaceRating(placeId) : null;
    const city = cityParam || placeData?.city || '';
    const location = city ? ` in ${city}` : '';

    // ── Fetch onboarding profile for this site (if available) ──
    let onboardingContext = '';
    if (cleanDomain) {
      try {
        const snap = await db.collection('launches')
          .where('domain_name', '==', cleanDomain).limit(1).get();
        if (!snap.empty) {
          const profile = snap.docs[0].data().onboarding_profile;
          if (profile) {
            const ob = profile;
            // Build context based on content type — each type needs different data
            const parts = [];
            // Always include brand voice if available
            if (ob.brand_voice) {
              const bv = ob.brand_voice;
              parts.push(`BRAND VOICE — Write in this contractor's actual voice:
- Personality: ${bv.personality || 'professional'}
- Tone: ${bv.tone || 'friendly'}
${bv.preferred_phrases?.length ? `- Phrases they use: ${bv.preferred_phrases.join(', ')}` : ''}
${bv.avoid_phrases?.length ? `- Phrases to AVOID: ${bv.avoid_phrases.join(', ')}` : ''}
${bv.voice_description ? `- Voice description: ${bv.voice_description}` : ''}`);
            }
            // Origin story for trust/authority posts
            if (['trust', 'symptom', 'seasonal'].includes(contentType) && ob.origin_story) {
              parts.push(`CONTRACTOR BACKGROUND: ${ob.origin_story}${ob.years_in_business ? ` (${ob.years_in_business} years in business)` : ''}${ob.family_connection ? ` Family connection: ${ob.family_connection}` : ''}`);
            }
            // Services detail for symptom and cost posts
            if (['symptom', 'cost', 'emergency'].includes(contentType) && ob.services) {
              const sv = ob.services;
              parts.push(`SERVICES DETAIL:
${sv.core?.length ? `- Core services: ${sv.core.join(', ')}` : ''}
${sv.top_revenue ? `- Top revenue service: ${sv.top_revenue}` : ''}
${sv.emergency_available != null ? `- Emergency/after-hours: ${sv.emergency_available ? 'Yes' : 'No'}` : ''}`);
            }
            // Differentiation for all types
            if (ob.differentiation) {
              const df = ob.differentiation;
              parts.push(`WHAT MAKES THEM DIFFERENT:
${df.unique_selling_points?.length ? `- USPs: ${df.unique_selling_points.join('; ')}` : ''}
${df.guarantees?.length ? `- Guarantees: ${df.guarantees.join('; ')}` : ''}
${df.customer_compliments?.length ? `- Customers say: ${df.customer_compliments.join('; ')}` : ''}`);
            }
            // Credentials for trust, emergency
            if (['trust', 'emergency'].includes(contentType) && ob.credentials) {
              const cr = ob.credentials;
              parts.push(`CREDENTIALS:
${cr.licenses?.length ? `- Licenses: ${cr.licenses.join(', ')}` : ''}
${cr.insured ? '- Fully insured' : ''}${cr.bonded ? ', bonded' : ''}
${cr.associations?.length ? `- Associations: ${cr.associations.join(', ')}` : ''}
${cr.awards?.length ? `- Awards: ${cr.awards.join(', ')}` : ''}`);
            }
            // Service area for local posts
            if (ob.service_area) {
              const sa = ob.service_area;
              if (sa.cities?.length) parts.push(`SERVICE AREA: ${sa.cities.join(', ')}${sa.primary_markets?.length ? `. Primary markets: ${sa.primary_markets.join(', ')}` : ''}`);
            }
            if (parts.length) {
              onboardingContext = `\n\n--- CONTRACTOR PROFILE (from onboarding interview — use this to make the post authentic) ---\n${parts.join('\n\n')}\n--- END CONTRACTOR PROFILE ---\n\nIMPORTANT: Use the contractor's actual brand voice, reference their real credentials, and weave in their specific differentiators. This post should sound like THEM, not a generic contractor.\n`;
            }
          }
        }
      } catch (e) { console.warn('Failed to fetch onboarding profile for blog:', e.message); }
    }

    // ── Fetch research data for this site (if available) ──
    let researchContext = '';
    if (cleanDomain) {
      try {
        const snap = await db.collection('launches')
          .where('domain_name', '==', cleanDomain).limit(1).get();
        if (!snap.empty) {
          const researchMd = snap.docs[0].data().research_md;
          if (researchMd) {
            const parts = [];
            // Extract SEO keywords section
            const kwMatch = researchMd.match(/#+\s*(?:SEO|Keywords?|Target Keywords?)[\s\S]*?(?=\n#+\s|\n---|\$)/i);
            if (kwMatch) {
              const kwText = kwMatch[0].replace(/^#+\s*.+\n/, '').trim().slice(0, 400);
              if (kwText) parts.push(`SEO KEYWORDS TO TARGET:\n${kwText}`);
            }
            // Extract content guidance
            const cgMatch = researchMd.match(/#+\s*(?:Content Guidance|Content Strategy|Content Recommendations?)[\s\S]*?(?=\n#+\s|\n---|\$)/i);
            if (cgMatch) {
              const cgText = cgMatch[0].replace(/^#+\s*.+\n/, '').trim().slice(0, 400);
              if (cgText) parts.push(`CONTENT GUIDANCE:\n${cgText}`);
            }
            // Extract competitive landscape
            const compMatch = researchMd.match(/#+\s*(?:Competi|Landscape|Market Analysis)[\s\S]*?(?=\n#+\s|\n---|\$)/i);
            if (compMatch) {
              const compText = compMatch[0].replace(/^#+\s*.+\n/, '').trim().slice(0, 300);
              if (compText) parts.push(`COMPETITIVE CONTEXT:\n${compText}`);
            }
            // Extract customer reviews/quotes
            const revMatch = researchMd.match(/#+\s*(?:Customer Review|Review|Testimonial|Quote)[\s\S]*?(?=\n#+\s|\n---|\$)/i);
            if (revMatch) {
              const revText = revMatch[0].replace(/^#+\s*.+\n/, '').trim().slice(0, 300);
              if (revText) parts.push(`CUSTOMER QUOTES (use as social proof):\n${revText}`);
            }
            // Extract do-not-use / warnings
            const warnMatch = researchMd.match(/#+\s*(?:Do Not|Warning|Unconfirmed|Avoid|Caution)[\s\S]*?(?=\n#+\s|\n---|\$)/i);
            if (warnMatch) {
              const warnText = warnMatch[0].replace(/^#+\s*.+\n/, '').trim().slice(0, 200);
              if (warnText) parts.push(`DO NOT CLAIM (unconfirmed):\n${warnText}`);
            }
            if (parts.length) {
              researchContext = `\n\n--- CLIENT RESEARCH DATA ---\n${parts.join('\n\n').slice(0, 2000)}\n--- END RESEARCH DATA ---\n`;
            }
          }
        }
      } catch (e) { console.warn('Failed to fetch research for blog:', e.message); }
    }

    // ── Fetch project examples + images for this site (if available) ──
    let projectsContext = '';
    let projectImageUrls = [];
    if (cleanDomain) {
      try {
        const snap = await db.collection('launches')
          .where('domain_name', '==', cleanDomain).limit(1).get();
        if (!snap.empty) {
          const launchData = snap.docs[0].data();
          const projectsArr = launchData.projects;
          if (projectsArr?.length) {
            const top3 = projectsArr.slice(0, 3);
            const lines = top3.map((p, i) => {
              let entry = `Project ${i + 1}: ${p.job_title || 'Untitled'} in ${p.customer_city || 'unknown location'}`;
              if (p.job_description) entry += `\nDescription: ${p.job_description}`;
              if (p.customer_name) entry += `\nCustomer: ${p.customer_name}`;
              if (p.review_rating) entry += ` — ${p.review_rating} stars`;
              if (p.review_text) entry += `\nReview: "${p.review_text}"`;
              return entry;
            }).join('\n\n');
            projectsContext = `\n\n--- REAL PROJECT EXAMPLES (from completed jobs) ---\n${lines}\n--- END PROJECT EXAMPLES ---\n\nUse these real project examples to ground the blog post in actual work. Reference specific jobs, quote real customer reviews, and mention real locations. This is what makes the content unique and trustworthy.\n`;
          }

          // Fetch project images from Drive for use as blog images
          if (launchData.drive_folder_id) {
            try {
              const driveToken = await getAnalyticsAccessToken();
              const projFolderId = await driveFindFolder('Projects', launchData.drive_folder_id, driveToken);
              if (projFolderId) {
                const imgQ = encodeURIComponent(`'${projFolderId}' in parents and trashed=false`);
                const imgR = await fetchWithRetry(`https://www.googleapis.com/drive/v3/files?q=${imgQ}&fields=files(id,name,mimeType,webContentLink,thumbnailLink)&pageSize=10`, {
                  headers: { Authorization: `Bearer ${driveToken}` },
                });
                if (imgR.ok) {
                  const imgData = await imgR.json();
                  const imgs = (imgData.files || []).filter(f => f.mimeType?.startsWith('image/') || f.name?.match(/\.(jpg|jpeg|png|webp)$/i));
                  // Make images accessible via a proxy URL
                  projectImageUrls = imgs.slice(0, 5).map(f => ({
                    id: f.id,
                    name: f.name,
                    url: `https://drive.google.com/thumbnail?id=${f.id}&sz=w800`,
                  }));
                }
              }
            } catch (e) { console.warn('Failed to fetch project images:', e.message); }
          }
        }
      } catch (e) { console.warn('Failed to fetch projects for blog:', e.message); }
    }

    // Add project image instructions to the prompt if available
    if (projectImageUrls.length && projectsContext) {
      projectsContext += `\nPROJECT PHOTOS AVAILABLE — Include these images in the blog post using <img> tags:
${projectImageUrls.map((img, i) => `- Image ${i + 1}: <img src="${img.url}" alt="${img.name}" style="width:100%;border-radius:12px;margin:1rem 0">`).join('\n')}
Place the first image as the hero image after the H1. Place additional images near the project examples they relate to.\n`;
    }

    const keywordLine = kwArray.length
      ? `\nTarget SEO keywords: ${kwArray.map(k => `"${k}"`).join(', ')} — weave these naturally throughout the post (max 3 mentions of the primary keyword). Include "${kwArray[0]}" in the <h1> and at least one <h2>.\n`
      : '';
    const bizLine = bizName
      ? `\nBusiness: "${bizName}"${cleanDomain ? ` (${cleanDomain})` : ''} — use this exact name in CTA paragraphs, never write "[Your Company Name]".\n`
      : '';
    const cityLine = city
      ? `\nService area: "${city}" — mention this city/region naturally in the <h1>, the intro paragraph, and the CTA to improve local SEO.\n`
      : '';
    const reviewsLine = (placeData?.rating && placeData?.reviewCount)
      ? `\nGoogle reviews: This business has ${placeData.rating} stars from ${placeData.reviewCount} Google reviews. Mention this naturally in the CTA (e.g. "Trusted by homeowners across ${city || 'the area'} — ${placeData.reviewCount} 5-star Google reviews"). Link the review count to: https://search.google.com/local/reviews?placeid=${placeId}\n`
      : '';
    const customerReviewsLine = (placeData?.reviews?.length)
      ? `\nCustomer reviews to feature — Add a "Don't just take our word for it" section near the end of the post (before the CTA). Use 2–3 of the reviews below. Quote them exactly — do not alter the wording. Wrap each in a <blockquote> tag. Format as: reviewer name + star rating (e.g. ★★★★★) on one line, then the quoted text.
${placeData.reviews.map(rv => `- [${rv.rating} stars] ${rv.name}: "${rv.text}"`).join('\n')}\n`
      : '';
    const internalLinksLine = cleanDomain
      ? `\nInternal links — embed these three hyperlinks naturally in the post body:
- <a href="https://${cleanDomain}/services">our services</a>
- <a href="https://${cleanDomain}/service-areas">our service areas</a>
- <a href="https://${cleanDomain}/customer-reviews">customer reviews</a>\n`
      : '';
    const tldrLine = words >= 1000
      ? `\n- After the intro paragraph, include a <div class="key-takeaway" style="background:#f0f9ff;border-left:4px solid #0284c7;padding:1rem 1.25rem;border-radius:0 8px 8px 0;margin:1.25rem 0"><strong>Key Takeaway:</strong> [1-2 sentence summary answering the main question]</div>\n`
      : '';

    const prompt = `You are a local SEO and AEO (Answer Engine Optimization) content writer for home service contractors. Write a ${ct.label} blog post about ${industry}${location}.

Content type: ${ct.label}

Question: "${question}"
Context: ${detail || '(no additional context)'}
${onboardingContext}${researchContext}${projectsContext}${keywordLine}${bizLine}${cityLine}${reviewsLine}${customerReviewsLine}${internalLinksLine}
Write an SEO-optimized blog post in clean HTML. Structure:
- A compelling <h1> title under 60 characters — rewrite the source question into an SEO-friendly blog title (e.g. not "Which one of yall did this?" but "5 Signs Your Roof Was Damaged in a Storm")${kwArray.length ? ` Include the target keyword.` : ''}${city ? ` Include "${city}".` : ''}
- A brief intro paragraph (2-3 sentences) that directly addresses the question within the first 150 words
${tldrLine}${ct.structure}
${placeData?.reviews?.length ? `- A "Don't just take our word for it" <h2> section using the provided customer reviews (blockquote each one)\n` : ''}- A closing CTA section that mentions the business by name${placeData?.rating ? `, their Google rating, and links to their reviews page` : ''}
- A <h2>Frequently Asked Questions</h2> section near the end (before the closing CTA) with 3-5 Q&As. Each Q&A should use: <h3>[Question]</h3> followed by <p>[2-3 sentence answer]</p>. Use questions homeowners actually search — not questions you wish they'd ask.
- Total length: approximately ${words} words

ALSO generate a meta description on its own line at the very end, wrapped in <!-- META: [your 140-155 character meta description with keyword and a soft CTA like "Learn what to expect" or "Get a free estimate today"] -->

OUTPUT FORMAT:
Return the blog post wrapped in a styled container div. Include:
1. A <style> block at the top with clean, modern CSS for the post
2. The full post HTML inside a <div class="rw-blog-post"> wrapper

The CSS should include:
- Clean typography (system fonts, 1.6 line-height, max-width: 720px, centered)
- Styled headings — CRITICAL: h1 must use "color: #1a1a1a !important" (Duda themes often set white h1 which makes it invisible). h1: 2rem bold, h2: 1.4rem with bottom border, h3: 1.1rem. All headings must have "color: #1a1a1a !important"
- Blockquote styling (left border, italic, grey background)
- CTA button styling (primary color, rounded, centered)
- FAQ section styling (each Q&A as a card with subtle border)
- Image styling (width: 100%, border-radius: 12px, margin-bottom: 1.5rem)
- List styling (custom bullets, spacing)
- Responsive (works on mobile)

Make the CSS inline-friendly — use a <style> block, not external stylesheets.
Use !important on all heading colors to override CMS theme defaults.

RULES — DO NOT VIOLATE:
- Every <h2> MUST be phrased as a question (e.g. "What Causes...?" not "Common Causes of...")
- Immediately after each <h2> question, the FIRST sentence must directly answer it — do not bury the answer
- No paragraph longer than 4 sentences
- Do NOT open with "When it comes to..." or "As a homeowner..." or any generic filler
- Do NOT write "costs vary depending on many factors" without giving a specific dollar range
- Do NOT repeat the target keyword more than 3 times in the body
- Do NOT use "click here" or "learn more" as anchor text — use descriptive service names
- Use <strong> to bold key terms where a skimmer would want to land — not randomly
- Use numbered lists for step-by-step processes, bulleted lists for tips and warning signs

Return the HTML with the <style> block and <div class="rw-blog-post"> wrapper. Do not include <html>, <head>, or <body> tags. Use only <h1>, <h2>, <h3>, <p>, <a>, <ul>, <ol>, <li>, <strong>, <blockquote>, <div> tags inside the wrapper.`;

    // Build Pexels search query from topic title (more relevant than location-based keyword)
    // Strip question words and city names; keep nouns related to the subject
    const STOP = /\b(what|when|how|why|do|does|did|is|are|can|should|will|the|a|an|in|on|at|to|for|of|and|or|but|my|your|our|you|we|i|it|ok|ohio|texas|florida|california|georgia|michigan|arizona|colorado|nevada|city|town|county|near|local)\b/gi;
    const topicWords = question.replace(/[?!.,]/g, '').replace(STOP, ' ').trim().split(/\s+/).filter(w => w.length > 2).slice(0, 3);
    const pexelsQuery = [...topicWords, industry].join(' ').trim();

    const [gRes, heroImage] = await Promise.all([
      fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${geminiKey}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { temperature: 0.7, maxOutputTokens: 8192 } }),
      }),
      fetchPexelsImage(pexelsQuery),
    ]);
    const gData = await gRes.json();
    if (!gRes.ok) throw new Error(gData.error?.message || 'Gemini error');
    const candidate = gData.candidates?.[0];
    const raw = candidate?.content?.parts?.[0]?.text || '';
    let post = raw.replace(/^```html?\n?/i, '').replace(/\n?```$/m, '').trim();
    if (!post) throw new Error(gData.error?.message || gData.promptFeedback?.blockReason || 'Gemini returned no content');

    // Detect truncation — Gemini sets finishReason to MAX_TOKENS when it runs out
    const finishReason = candidate?.finishReason || '';
    const wasTruncated = finishReason === 'MAX_TOKENS';

    // Detect empty headings (H2/H3 followed by another heading or end-of-string, with no paragraph between)
    const emptyHeadings = (post.match(/<h[23][^>]*>[^<]*<\/h[23]>\s*(?=<h[23]|<\/div>|$)/gi) || []).length;

    // Extract meta description from <!-- META: ... --> comment before stripping it
    const metaMatch = post.match(/<!--\s*META:\s*([\s\S]*?)\s*-->/i);
    const craftedMetaDesc = metaMatch ? metaMatch[1].trim().slice(0, 155) : null;
    post = post.replace(/<!--\s*META:[\s\S]*?-->/gi, '').trim();

    // Clean up internal links — remove standalone link paragraphs Gemini sometimes generates
    if (cleanDomain) {
      post = post.replace(/<p>\s*<a\s+href="https?:\/\/[^"]*"[^>]*>[^<]+<\/a>\s*<\/p>/gi, (match) => {
        const textContent = match.replace(/<[^>]+>/g, '').trim();
        const linkText = (match.match(/>([^<]+)<\/a>/) || [])[1] || '';
        return textContent === linkText ? '' : match;
      });

      // Guarantee all three internal links are present somewhere in the post
      const internalLinks = [
        { url: `https://${cleanDomain}/services`,         anchor: 'our services' },
        { url: `https://${cleanDomain}/service-areas`,    anchor: 'our service areas' },
        { url: `https://${cleanDomain}/customer-reviews`, anchor: 'customer reviews' },
      ];
      const missing = internalLinks.filter(l => !post.includes(l.url));
      if (missing.length > 0) {
        const linkStr = missing.map(l => `<a href="${l.url}">${l.anchor}</a>`).join(', ');
        const inject = `<p>For more information about what we offer, visit ${linkStr}.</p>`;
        const lastP = post.lastIndexOf('</p>');
        post = lastP !== -1
          ? post.slice(0, lastP + 4) + '\n' + inject
          : post + '\n' + inject;
      }
    }

    // ── Extract data for schema and quality checks ──
    const h1Match     = post.match(/<h1[^>]*>([\s\S]*?)<\/h1>/i);
    const pMatch      = post.match(/<p[^>]*>([\s\S]*?)<\/p>/i);
    const jsonLdTitle = h1Match ? h1Match[1].replace(/<[^>]+>/g, '').trim() : question;
    const fallbackDesc = pMatch ? pMatch[1].replace(/<[^>]+>/g, '').trim().slice(0, 160) : '';
    const metaDesc = craftedMetaDesc || fallbackDesc;

    // ── Build BlogPosting JSON-LD ──
    const jsonLd = {
      '@context': 'https://schema.org',
      '@type': 'BlogPosting',
      headline: jsonLdTitle,
      ...(metaDesc ? { description: metaDesc } : {}),
      datePublished: new Date().toISOString().slice(0, 10),
      author:    { '@type': 'Organization', name: bizName || industry },
      publisher: { '@type': 'Organization', name: bizName || industry },
      ...(cleanDomain ? { url: `https://${cleanDomain}` } : {}),
      ...(placeData?.rating && placeData?.reviewCount ? {
        aggregateRating: {
          '@type': 'AggregateRating',
          ratingValue: placeData.rating,
          reviewCount: placeData.reviewCount,
          bestRating: 5,
        },
      } : {}),
    };

    // ── Build FAQPage JSON-LD from FAQ section ──
    const faqItems = [];
    const faqRegex = /<h3[^>]*>([\s\S]*?)<\/h3>\s*<p[^>]*>([\s\S]*?)<\/p>/gi;
    let faqMatch;
    while ((faqMatch = faqRegex.exec(post)) !== null) {
      const qText = faqMatch[1].replace(/<[^>]+>/g, '').trim();
      const aText = faqMatch[2].replace(/<[^>]+>/g, '').trim();
      if (qText && aText) faqItems.push({ question: qText, answer: aText });
    }
    const faqJsonLd = faqItems.length >= 2 ? {
      '@context': 'https://schema.org',
      '@type': 'FAQPage',
      mainEntity: faqItems.map(f => ({
        '@type': 'Question',
        name: f.question,
        acceptedAnswer: { '@type': 'Answer', text: f.answer },
      })),
    } : null;

    // ── Quality score — check post against strategy checklist ──
    const qualityFlags = [];
    const h1Text = jsonLdTitle;
    if (h1Text.length > 60) qualityFlags.push({ rule: 'title_length', msg: `Title is ${h1Text.length} chars (target: under 60)` });
    const questionH2s = (post.match(/<h2[^>]*>[^<]*\?[^<]*<\/h2>/gi) || []).length;
    if (questionH2s < 2) qualityFlags.push({ rule: 'question_h2s', msg: `Only ${questionH2s} question-format H2s (target: 2+)` });
    if (faqItems.length < 3) qualityFlags.push({ rule: 'faq_count', msg: `Only ${faqItems.length} FAQ items (target: 3-5)` });
    const hasInternalLink = cleanDomain ? post.includes(cleanDomain) : true;
    if (!hasInternalLink) qualityFlags.push({ rule: 'internal_links', msg: 'No internal links to service pages' });
    if (metaDesc.length < 130 || metaDesc.length > 160) qualityFlags.push({ rule: 'meta_length', msg: `Meta description is ${metaDesc.length} chars (target: 140-155)` });
    // Check for long paragraphs (>4 sentences)
    const paragraphs = post.match(/<p[^>]*>([\s\S]*?)<\/p>/gi) || [];
    const longParas = paragraphs.filter(p => {
      const text = p.replace(/<[^>]+>/g, '').trim();
      const sentences = text.split(/[.!?]+\s/).filter(s => s.trim().length > 5);
      return sentences.length > 4;
    }).length;
    if (longParas > 0) qualityFlags.push({ rule: 'para_length', msg: `${longParas} paragraph(s) exceed 4 sentences` });
    // Count CTAs (look for CTA-like patterns)
    const ctaCount = (post.match(/call\s+(us|[\w]+)\s+(now|today)|free\s+estimate|schedule\s+(a|your)|contact\s+(us|[\w]+)|get\s+a\s+free|book\s+(a|your)/gi) || []).length;
    if (ctaCount < 2) qualityFlags.push({ rule: 'cta_count', msg: `Only ${ctaCount} CTA(s) detected (target: 2+)` });
    // Truncation detection
    if (wasTruncated) qualityFlags.push({ rule: 'truncated', msg: 'Post was truncated by Gemini token limit — content is incomplete' });
    if (emptyHeadings >= 2) qualityFlags.push({ rule: 'empty_headings', msg: `${emptyHeadings} heading(s) have no content beneath them — likely truncated` });

    const qualityScore = Math.max(0, 100 - (qualityFlags.length * 15));
    const isTruncated = wasTruncated || emptyHeadings >= 2;

    res.json({
      post,
      jsonLd,
      faqJsonLd,
      metaDesc,
      heroImageUrl: heroImage?.url || null,
      contentType,
      qualityScore,
      qualityFlags,
      isTruncated,
      _pexelsDebug: heroImage?.debug || null,
    });
  } catch (err) {
    console.error('blog/post error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── Milestone Thresholds Config ──
const DEFAULT_MILESTONES = {
  '30day': { gscImpressions: 500,  gscClicks: 20,  ga4Sessions: 100 },
  '60day': { gscImpressions: 1500, gscClicks: 60,  ga4Sessions: 300 },
  '90day': { gscImpressions: 3000, gscClicks: 120, ga4Sessions: 600 }
};

app.get('/api/milestones/thresholds', requireAuth, async (req, res) => {
  try {
    const doc = await db.collection('config').doc('milestones').get();
    res.json(doc.exists ? doc.data() : DEFAULT_MILESTONES);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/milestones/thresholds', requireAuth, async (req, res) => {
  try {
    await db.collection('config').doc('milestones').set(req.body, { merge: true });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── SEO Audit ──
const SAFE_BROWSING_API_KEY = process.env.SAFE_BROWSING_API_KEY || '';

// Required and recommended fields per schema @type
const SCHEMA_RULES = {
  LocalBusiness:  { required: ['name','address'], recommended: ['telephone','url','description','openingHours'] },
  Organization:   { required: ['name'],           recommended: ['url','logo','contactPoint','description'] },
  Service:        { required: ['name'],            recommended: ['description','provider','areaServed','url'] },
  FAQPage:        { required: ['mainEntity'],      recommended: [] },
  WebSite:        { required: ['name','url'],      recommended: [] },
  Product:        { required: ['name'],            recommended: ['description','image','offers','brand'] },
  Article:        { required: ['headline','author','datePublished'], recommended: ['image','description'] },
  BreadcrumbList: { required: ['itemListElement'], recommended: [] },
};

async function scanStructuredData(baseUrl) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10_000);
  try {
    const resp = await fetch(baseUrl, {
      headers: { 'User-Agent': 'RealWork-SEO-Scanner/1.0' },
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!resp.ok) return { status: 'unknown', schemas: [], errors: [], warnings: [] };
    const html = await resp.text();

    // Extract all JSON-LD blocks
    const re = /<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
    const schemas = [];
    const errors = [];
    const warnings = [];
    let m;
    while ((m = re.exec(html)) !== null) {
      let parsed;
      try { parsed = JSON.parse(m[1].trim()); } catch { errors.push('Invalid JSON-LD block'); continue; }
      // Handle @graph arrays
      const items = parsed['@graph'] ? parsed['@graph'] : [parsed];
      for (const item of items) {
        const rawType = item['@type'] || '';
        const types = Array.isArray(rawType) ? rawType : [rawType];
        for (const type of types) {
          const rules = SCHEMA_RULES[type];
          schemas.push(type);
          if (rules) {
            for (const f of rules.required) {
              if (item[f] == null || item[f] === '') errors.push(`${type}: missing required field "${f}"`);
            }
            for (const f of rules.recommended) {
              if (item[f] == null || item[f] === '') warnings.push(`${type}: missing recommended field "${f}"`);
            }
          }
        }
      }
    }

    if (schemas.length === 0) return { status: 'missing', schemas: [], errors: [], warnings: [] };
    if (errors.length > 0)   return { status: 'errors', schemas, errors, warnings };
    if (warnings.length > 0) return { status: 'warnings', schemas, errors, warnings };
    return { status: 'ok', schemas, errors, warnings };
  } catch {
    clearTimeout(timer);
    return { status: 'unknown', schemas: [], errors: [], warnings: [] };
  }
}

async function checkSafeBrowsing(url, apiKey) {
  if (!apiKey) return { status: 'unknown', threats: [] };
  try {
    incrApiStat('safebrowsing');
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8_000);
    const resp = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      signal: controller.signal,
      body: JSON.stringify({
        client: { clientId: 'realwork-seo-scanner', clientVersion: '1.0' },
        threatInfo: {
          threatTypes: ['MALWARE','SOCIAL_ENGINEERING','UNWANTED_SOFTWARE','POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }],
        },
      }),
    });
    clearTimeout(timer);
    if (!resp.ok) return { status: 'unknown', threats: [] };
    const data = await resp.json();
    const matches = data.matches || [];
    if (matches.length === 0) return { status: 'safe', threats: [] };
    const threats = [...new Set(matches.map(t => t.threatType))];
    return { status: 'flagged', threats };
  } catch {
    return { status: 'unknown', threats: [] };
  }
}

async function scanBrokenLinks(baseUrl) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10_000);
  try {
    const resp = await fetch(baseUrl, {
      headers: { 'User-Agent': 'RealWork-SEO-Scanner/1.0' },
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!resp.ok) return [];
    const html = await resp.text();
    const domain = new URL(baseUrl).hostname;
    const seen = new Set();
    const toCheck = [];
    const re = /href=["']([^"'#?][^"']*?)["']/gi;
    let m;
    while ((m = re.exec(html)) !== null && toCheck.length < 40) {
      const href = m[1];
      if (/^(mailto:|tel:|javascript:)/i.test(href)) continue;
      let url;
      try { url = new URL(href, baseUrl).href; } catch { continue; }
      if (new URL(url).hostname !== domain) continue;
      if (seen.has(url)) continue;
      seen.add(url);
      toCheck.push(url);
    }
    const broken = [];
    await Promise.all(toCheck.map(async url => {
      try {
        const c = new AbortController();
        const t = setTimeout(() => c.abort(), 5_000);
        const r = await fetch(url, { method: 'HEAD', redirect: 'follow', signal: c.signal, headers: { 'User-Agent': 'RealWork-SEO-Scanner/1.0' } });
        clearTimeout(t);
        if (r.status === 404) broken.push({ url, status: 404 });
      } catch { /* timeout / network — skip */ }
    }));
    return broken;
  } catch {
    clearTimeout(timer);
    return [];
  }
}

// Returns all cached SEO audits from Firestore without triggering any scans
app.get('/api/page-index-cache', requireAuth, async (req, res) => {
  try {
    const launchSnap = await db.collection('launches').where('status', '!=', 'decommissioned').get();
    const results = {};
    await Promise.all(launchSnap.docs.map(async doc => {
      const cache = await db.collection('launches').doc(doc.id).collection('page_index_cache').doc('latest').get();
      if (cache.exists) results[doc.id] = cache.data();
    }));
    res.json(results);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/seo-cache', requireAuth, async (req, res) => {
  try {
    const launchSnap = await db.collection('launches').where('status', '!=', 'decommissioned').get();
    const ids = launchSnap.docs.map(d => d.id);
    const results = {};
    await Promise.all(ids.map(async id => {
      const doc = await db.collection('launches').doc(id).collection('seo_audits').doc('latest').get();
      if (doc.exists) results[id] = doc.data();
    }));
    res.json(results);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/analytics/:id/seo', requireAuth, async (req, res) => {
  try {
    const doc = await db.collection('launches').doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ error: 'not_found' });
    const launch = formatLaunch(doc);
    const domain = launch.domain_name.replace(/^https?:\/\//, '').replace(/\/$/, '');
    const cleanDomain = domain.replace(/^www\./, '');

    // Serve Firestore cache if < 24h and not forced
    const cacheRef = db.collection('launches').doc(req.params.id).collection('seo_audits').doc('latest');
    if (!req.query.force) {
      const cached = await cacheRef.get();
      if (cached.exists) {
        const data = cached.data();
        if (Date.now() - new Date(data.scannedAt).getTime() < 7 * 86_400_000) return res.json(data);
      }
    }

    const token = await getAnalyticsAccessToken();

    // Find working GSC siteUrl using a 90-day window so we always get data
    // even with GSC's 2-3 day reporting delay. Also use the row count to
    // determine indexing — if the site has ANY impressions it is indexed.
    const today = new Date().toISOString().slice(0, 10);
    const ninetyDaysAgo = new Date(Date.now() - 90 * 86_400_000).toISOString().slice(0, 10);
    const scCandidates = [
      `sc-domain:${cleanDomain}`,
      `https://www.${cleanDomain}/`,
      `https://${cleanDomain}/`,
      `http://www.${cleanDomain}/`,
      `http://${cleanDomain}/`,
    ];
    let siteUrl = null;
    let gscHasImpressions = false;
    for (const c of scCandidates) {
      incrApiStat('gsc');
      const r = await fetch(
        `https://www.googleapis.com/webmasters/v3/sites/${encodeURIComponent(c)}/searchAnalytics/query`,
        {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ startDate: ninetyDaysAgo, endDate: today, dimensions: ['date'], rowLimit: 1 }),
        }
      ).catch(() => null);
      if (r?.ok) {
        const data = await r.json().catch(() => ({}));
        siteUrl = c;
        gscHasImpressions = (data.rows || []).length > 0;
        break;
      }
    }
    console.log(`[seo] ${cleanDomain} siteUrl=${siteUrl} gscHasImpressions=${gscHasImpressions}`);

    // 1. Sitemaps
    let sitemaps = [], sitemapStatus = 'unknown';
    if (siteUrl) {
      incrApiStat('gsc');
      const r = await fetch(`https://www.googleapis.com/webmasters/v3/sites/${encodeURIComponent(siteUrl)}/sitemaps`, {
        headers: { Authorization: `Bearer ${token}` },
      }).catch(() => null);
      if (r?.ok) {
        const data = await r.json();
        sitemaps = (data.sitemap || []).map(s => ({
          path: s.path, lastSubmitted: s.lastSubmitted, lastDownloaded: s.lastDownloaded,
          errors: s.errors || 0, warnings: s.warnings || 0, isSitemapsIndex: !!s.isSitemapsIndex,
        }));
        sitemapStatus = sitemaps.length === 0 ? 'none' : sitemaps.some(s => s.errors > 0) ? 'error' : 'ok';
      }
    }

    // 2. Index check
    // Primary: if Google is returning search analytics data the site is indexed.
    // Fallback: URL Inspection API for sites with no impressions yet (new sites).
    let indexStatus = 'unknown', indexCoverageState = null;
    if (gscHasImpressions) {
      // Site has appeared in Google search results — definitively indexed
      indexStatus = 'indexed';
    } else if (siteUrl) {
      // No impressions yet — try URL Inspection API for a definitive answer
      const inspectUrls = [`https://${cleanDomain}/`, `https://www.${cleanDomain}/`];
      for (const inspectUrl of inspectUrls) {
        incrApiStat('gsc');
        const r = await fetch('https://searchconsole.googleapis.com/v1/urlInspection/index:inspect', {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ inspectionUrl: inspectUrl, siteUrl }),
        }).catch(() => null);
        if (r?.ok) {
          const data = await r.json();
          const result = data.inspectionResult?.indexStatusResult || {};
          indexCoverageState = result.coverageState || null;
          console.log(`[seo] ${cleanDomain} urlInspection verdict=${result.verdict} coverage="${indexCoverageState}"`);
          if (result.verdict === 'PASS' || /indexed/i.test(indexCoverageState || '')) {
            indexStatus = 'indexed'; break;
          } else if (result.verdict === 'FAIL' || result.verdict === 'NEUTRAL') {
            indexStatus = 'not_indexed'; break;
          }
        } else {
          const body = r ? await r.text().catch(() => '') : 'no response';
          console.log(`[seo] urlInspection ${r?.status} for ${cleanDomain}: ${body.slice(0, 300)}`);
          break;
        }
      }
    }

    // 3. Broken links, structured data, safe browsing — run in parallel
    const homeUrl = `https://${cleanDomain}/`;
    const [brokenLinks, structuredData, safeBrowsing] = await Promise.all([
      scanBrokenLinks(homeUrl),
      scanStructuredData(homeUrl),
      checkSafeBrowsing(homeUrl, SAFE_BROWSING_API_KEY),
    ]);

    const result = { scannedAt: new Date().toISOString(), siteUrl, sitemaps, sitemapStatus, indexStatus, indexCoverageState, brokenLinks, structuredData, safeBrowsing };
    await cacheRef.set(result).catch(() => {});
    res.json(result);
  } catch (e) {
    if (e.code === 'not_connected') return res.status(402).json({ error: 'not_connected' });
    res.status(500).json({ error: e.message });
  }
});

// ── API Usage stats ──
app.get('/api/admin/api-usage', requireAuth, async (_req, res) => {
  try {
    const today = new Date().toISOString().slice(0, 10);
    const yesterday = new Date(Date.now() - 86_400_000).toISOString().slice(0, 10);
    const [todaySnap, ySnap] = await Promise.all([
      db.collection('api_usage').doc(today).get(),
      db.collection('api_usage').doc(yesterday).get(),
    ]);
    res.json({
      today:     { date: today,     ...(todaySnap.data() || {}) },
      yesterday: { date: yesterday, ...(ySnap.data()     || {}) },
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Page-level index check ──
async function fetchSitemapUrls(domain) {
  const candidates = [
    `https://${domain}/sitemap.xml`,
    `https://www.${domain}/sitemap.xml`,
    `https://${domain}/sitemap_index.xml`,
    `https://${domain}/page-sitemap.xml`,
  ];
  for (const sUrl of candidates) {
    try {
      const r = await fetch(sUrl, { signal: AbortSignal.timeout(8_000), headers: { 'User-Agent': 'RealWork-SEO-Scanner/1.0' } });
      if (!r.ok) continue;
      const xml = await r.text();
      const urls = [];
      // Expand sitemap index → fetch first child sitemap
      const indexLoc = /<sitemap>[\s\S]*?<loc>\s*(https?:\/\/[^\s<]+)\s*<\/loc>/i.exec(xml)?.[1];
      if (indexLoc && !urls.length) {
        try {
          const r2 = await fetch(indexLoc, { signal: AbortSignal.timeout(8_000), headers: { 'User-Agent': 'RealWork-SEO-Scanner/1.0' } });
          if (r2.ok) {
            const xml2 = await r2.text();
            const re2 = /<loc>\s*(https?:\/\/[^\s<]+)\s*<\/loc>/gi;
            let m2;
            while ((m2 = re2.exec(xml2)) !== null && urls.length < 25) {
              if (!m2[1].endsWith('.xml')) urls.push(m2[1]);
            }
          }
        } catch { /* ignore */ }
      }
      if (!urls.length) {
        const re = /<loc>\s*(https?:\/\/[^\s<]+)\s*<\/loc>/gi;
        let m;
        while ((m = re.exec(xml)) !== null && urls.length < 25) {
          if (!m[1].endsWith('.xml')) urls.push(m[1]);
        }
      }
      if (urls.length) return { urls, source: sUrl };
    } catch { /* try next */ }
  }
  return { urls: [], source: null };
}

app.get('/api/seo/page-index/:id', requireAuth, async (req, res) => {
  try {
    const doc = await db.collection('launches').doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ error: 'not_found' });
    const launch = formatLaunch(doc);
    const domain = launch.domain_name.replace(/^https?:\/\//, '').replace(/\/$/, '');
    const cleanDomain = domain.replace(/^www\./, '');

    const token = await getAnalyticsAccessToken();

    // Find working GSC siteUrl
    const scCandidates = [
      `sc-domain:${cleanDomain}`,
      `https://www.${cleanDomain}/`,
      `https://${cleanDomain}/`,
    ];
    let siteUrl = null;
    for (const c of scCandidates) {
      incrApiStat('gsc');
      const r = await fetch(
        `https://www.googleapis.com/webmasters/v3/sites/${encodeURIComponent(c)}/searchAnalytics/query`,
        { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ startDate: new Date(Date.now()-30*86400000).toISOString().slice(0,10), endDate: new Date().toISOString().slice(0,10), dimensions:['date'], rowLimit:1 }) }
      ).catch(() => null);
      if (r?.ok) { siteUrl = c; break; }
    }
    if (!siteUrl) return res.json({ error: 'gsc_not_connected', pages: [] });

    // Get page URLs from sitemap
    const { urls: sitemapUrls, source } = await fetchSitemapUrls(cleanDomain);

    // Fallback: just check homepage if no sitemap
    const urlsToCheck = sitemapUrls.length ? sitemapUrls.slice(0, 20) : [`https://${cleanDomain}/`];

    // URL Inspection for each page (sequential to avoid rate limits)
    const pages = [];
    for (const pageUrl of urlsToCheck) {
      incrApiStat('gsc');
      const r = await fetch('https://searchconsole.googleapis.com/v1/urlInspection/index:inspect', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ inspectionUrl: pageUrl, siteUrl }),
      }).catch(() => null);

      if (!r?.ok) {
        pages.push({ url: pageUrl, verdict: 'ERROR', coverageState: null });
        continue;
      }
      const data = await r.json().catch(() => ({}));
      const result = data.inspectionResult?.indexStatusResult || {};
      pages.push({
        url: pageUrl,
        verdict: result.verdict || 'UNKNOWN',
        coverageState: result.coverageState || null,
        robotsTxtState: result.robotsTxtState || null,
        crawledAs: result.crawledAs || null,
        lastCrawlTime: result.lastCrawlTime || null,
      });
    }

    const payload = { siteUrl, sitemapSource: source, pages, checkedAt: new Date().toISOString() };
    db.collection('launches').doc(req.params.id).collection('page_index_cache').doc('latest')
      .set(payload).catch(() => {});
    res.json(payload);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── API Error Logs ──
app.get('/api/admin/error-logs', requireAuth, async (req, res) => {
  try {
    const snapshot = await db.collection('api_error_log')
      .orderBy('at', 'desc')
      .limit(200)
      .get();
    const logs = snapshot.docs.map(doc => {
      const d = doc.data();
      return { id: doc.id, ...d, at: fmtTs(d.at) };
    });
    res.json(logs);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ── Custom Favicon ──
const faviconUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 512 * 1024, files: 1 } });
app.post('/api/launches/:id/favicon', requireAuth, faviconUpload.single('favicon'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file provided' });
    if (!req.file.mimetype.startsWith('image/')) return res.status(400).json({ error: 'File must be an image' });
    const dataUrl = `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`;
    await db.collection('launches').doc(req.params.id).update({ custom_favicon: dataUrl });
    res.json({ custom_favicon: dataUrl });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.delete('/api/launches/:id/favicon', requireAuth, async (req, res) => {
  try {
    await db.collection('launches').doc(req.params.id).update({ custom_favicon: null });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Share Token Generation ──
app.post('/api/launches/:id/share-token', requireAuth, async (req, res) => {
  try {
    const token = randomUUID();
    await db.collection('launches').doc(req.params.id).update({
      shareToken: token,
      shareTokenCreatedAt: new Date().toISOString(),
    });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Public Share Report (token-based, 48h expiry) ──
app.get('/api/share/:id/:token', async (req, res) => {
  try {
    const [cacheDoc, launchDoc] = await Promise.all([
      db.collection('launches').doc(req.params.id).collection('analytics_cache').doc('daily').get(),
      db.collection('launches').doc(req.params.id).get(),
    ]);
    if (!cacheDoc.exists) return res.status(404).json({ error: 'Report not available yet' });
    if (!launchDoc.exists) return res.status(404).json({ error: 'Not found' });
    const launch = launchDoc.data();
    if (!launch.shareToken || launch.shareToken !== req.params.token) {
      return res.status(403).json({ error: 'Invalid link' });
    }
    if (Date.now() - new Date(launch.shareTokenCreatedAt).getTime() > 48 * 60 * 60 * 1000) {
      return res.status(410).json({ error: 'Link expired' });
    }
    const { data, cachedAt } = cacheDoc.data();
    const { account_name, domain, launchDate, analyticsStartDate, daysSince, gsc, ga4, duda } = data;
    res.json({ account_name, domain, launchDate, analyticsStartDate, daysSince, gsc, ga4, duda, cachedAt, custom_favicon: launch.custom_favicon || null, hideFormSubmits: launch.hideFormSubmits || false });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load report' });
  }
});
app.get('/share/:id/:token', (_req, res) => res.sendFile(join(__dirname, 'public', 'share.html')));
app.get('/share/:id', (_req, res) => res.sendFile(join(__dirname, 'public', 'share.html')));

// ── Bulk Blog Generator ──────────────────────────────────────────────────────

app.get('/api/bulk-blog/industries', requireAuth, async (req, res) => {
  try {
    const snap = await db.collection('launches').get();
    const counts = {};
    snap.forEach(doc => {
      const d = doc.data();
      if (d.archived === true) return;
      if (d.status !== 'launched') return;
      if (!d.duda_site_name) return;
      const ind = (d.industry || '').trim();
      if (!ind) return;
      counts[ind] = (counts[ind] || 0) + 1;
    });
    const industries = Object.entries(counts)
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count);
    res.json({ industries });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/bulk-blog/sites', requireAuth, async (req, res) => {
  try {
    const { industry } = req.query;
    if (!industry) return res.status(400).json({ error: 'industry required' });
    const snap = await db.collection('launches')
      .where('industry', '==', industry).get();
    const sites = [];
    snap.forEach(doc => {
      const d = doc.data();
      if (d.archived || d.status !== 'launched' || !d.duda_site_name) return;
      sites.push({
        id:              doc.id,
        account_name:    d.account_name    || '',
        domain_name:     d.domain_name     || '',
        duda_site_name:  d.duda_site_name  || null,
        place_city:      d.place_city      || null,
        google_place_id: d.google_place_id || null,
        status:          d.status          || '',
        has_duda:        !!d.duda_site_name,
      });
    });
    sites.sort((a, b) => a.account_name.localeCompare(b.account_name));
    res.json({ sites });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/bulk-blog/recent', requireAuth, async (req, res) => {
  try {
    const snap = await db.collectionGroup('blog_drafts')
      .orderBy('pushedAt', 'desc').limit(150).get();
    const counts = {};
    const first  = {};
    snap.forEach(doc => {
      const d = doc.data();
      const key = d.questionId || d.title;
      if (!key) return;
      counts[key] = (counts[key] || 0) + 1;
      if (!first[key]) first[key] = d;
    });
    const recent = Object.entries(first)
      .map(([key, d]) => ({
        title: d.title,
        industry: d.industry || null,
        questionId: d.questionId || null,
        pushedAt: d.pushedAt?.toDate?.()?.toISOString() || null,
        count: counts[key],
      }))
      .sort((a, b) => (b.pushedAt || '') > (a.pushedAt || '') ? 1 : -1)
      .slice(0, 5);
    res.json({ recent });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/bulk-blog/gsc-keyword/:id', requireAuth, async (req, res) => {
  try {
    // 1. Read from analytics cache (warm-all job populates this nightly)
    const cacheDoc = await db.collection('launches').doc(req.params.id)
      .collection('analytics_cache').doc('daily').get();
    if (cacheDoc.exists) {
      const { data } = cacheDoc.data();
      const queries = data?.gsc?.topQueries || [];
      const top3 = queries
        .filter(q => q.position >= 3 && q.position <= 30)
        .sort((a, b) => b.impressions - a.impressions)
        .slice(0, 3)
        .map(q => ({ query: q.query, impressions: q.impressions, position: Math.round(q.position * 10) / 10 }));
      if (top3.length) return res.json({ keywords: top3, keyword: top3[0].query });
      if (queries.length > 0) return res.json({ keywords: [], keyword: null, reason: 'no_opportunity' });
    }
    return res.json({ keywords: [], keyword: null, reason: 'no_data' });
  } catch (err) {
    res.status(500).json({ keyword: null, reason: 'error', error: err.message });
  }
});

app.post('/api/bulk-blog/push-batch', requireAuth, async (req, res) => {
  const { posts } = req.body;
  if (!Array.isArray(posts) || !posts.length) return res.status(400).json({ error: 'posts array required' });
  const creds = await getDudaCredentials();
  const token = Buffer.from(`${creds.api_user}:${creds.api_pass}`).toString('base64');
  const authHeader = { Authorization: `Basic ${token}`, 'Content-Type': 'application/json' };
  const results = [];
  for (const p of posts) {
    await new Promise(r => setTimeout(r, 200)); // small gap between Duda calls
    try {
      const doc = await db.collection('launches').doc(p.launchId).get();
      if (!doc.exists) throw new Error('Site not found');
      const siteName = doc.data().duda_site_name;
      if (!siteName) throw new Error('No Duda site name configured');
      const bizName = doc.data().account_name || '';
      const dRes = await fetch(
        `https://api.duda.co/api/sites/multiscreen/${siteName}/blog/posts/import`,
        { method: 'POST', headers: authHeader,
          body: JSON.stringify({ title: p.title, description: '', content: Buffer.from(p.html).toString('base64'), author: bizName || 'Team' }) }
      );
      if (!dRes.ok) { const txt = await dRes.text(); throw new Error(`Duda error (${dRes.status}): ${txt}`); }
      const post = await dRes.json();
      const postId = post.id || null;
      const publish = p.publish === true;
      if (publish && postId) {
        await fetch(`https://api.duda.co/api/sites/multiscreen/${siteName}/blog/posts/${postId}/publish`,
          { method: 'POST', headers: authHeader });
      }
      const status = publish ? 'published' : 'draft';
      const launchRef = db.collection('launches').doc(p.launchId);
      await Promise.all([
        launchRef.collection('blog_drafts').add({
          title: p.title, postId, status, pushedAt: new Date(),
          industry: p.industry || null, city: p.city || null,
          keyword: p.keyword || null, questionId: p.questionId || null,
        }),
        p.questionId ? launchRef.update({ blog_excluded_ids: FieldValue.arrayUnion(p.questionId) }) : Promise.resolve(),
      ]);
      results.push({ launchId: p.launchId, success: true, postId, status });
    } catch (err) {
      results.push({ launchId: p.launchId, success: false, error: err.message });
    }
  }
  res.json({ results });
});

// ── Onboarding Interview ──

// ── SSE infrastructure for live interview updates ──
const sseClients = new Map(); // Map<sessionId, Set<res>>

function addSseClient(sessionId, res) {
  if (!sseClients.has(sessionId)) sseClients.set(sessionId, new Set());
  sseClients.get(sessionId).add(res);
}

function removeSseClient(sessionId, res) {
  const set = sseClients.get(sessionId);
  if (set) { set.delete(res); if (set.size === 0) sseClients.delete(sessionId); }
}

function emitSseEvent(sessionId, eventType, data) {
  const set = sseClients.get(sessionId);
  if (!set || set.size === 0) return;
  const payload = `event: ${eventType}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of set) {
    try { res.write(payload); } catch { /* client gone */ }
  }
}
app.get('/api/onboarding/sessions', requireAuth, async (req, res) => {
  try {
    // Fetch all and filter/sort in JS to avoid requiring a Firestore composite index
    const snap = await db.collection('onboarding_interviews').get();
    const sessions = snap.docs
      .map(d => {
        const data = d.data();
        return { id: d.id, ...data, created_at: data.created_at?.toDate?.()?.toISOString() || null, updated_at: data.updated_at?.toDate?.()?.toISOString() || null };
      })
      .filter(s => s.created_by === req.userEmail)
      .sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''))
      .slice(0, 20);
    // Strip large fields to keep the list response lightweight
    res.json(sessions.map(s => ({ id: s.id, client_name: s.client_name, client_id: s.client_id, status: s.status, current_question: s.current_question, created_at: s.created_at, join_token: s.join_token })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Update onboarding profile on a launch doc (for manual edits)
app.patch('/api/launches/:id/onboarding-profile', requireAuth, async (req, res) => {
  try {
    const { profile } = req.body;
    if (!profile || typeof profile !== 'object') return res.status(400).json({ error: 'profile object required' });
    const ref = db.collection('launches').doc(req.params.id);
    const doc = await ref.get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    await ref.update({ onboarding_profile: profile, updated_at: FieldValue.serverTimestamp() });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Manually push onboarding profile to Google Drive
app.post('/api/launches/:id/push-to-drive', requireAuth, async (req, res) => {
  try {
    const doc = await db.collection('launches').doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    const d = doc.data();
    if (!d.onboarding_profile) return res.status(400).json({ error: 'No onboarding profile to push' });

    // Attempt Drive push with full error surfacing
    const token = await getAnalyticsAccessToken();
    const clientFolderId = await driveGetOrCreateClientFolder(d.account_name || 'Unknown', token);
    const obFolderId = await driveGetOrCreateSubfolder('Onboarding', clientFolderId, token);
    const date = new Date().toISOString().slice(0, 10);
    await driveUploadFile(`Onboarding Profile — ${date}.json`, JSON.stringify(d.onboarding_profile, null, 2), 'application/json', obFolderId, token);

    await db.collection('launches').doc(req.params.id).update({
      drive_folder_id: clientFolderId,
      drive_folder_url: `https://drive.google.com/drive/folders/${clientFolderId}`,
    });

    res.json({ ok: true, folderId: clientFolderId });
  } catch (err) {
    console.error('[drive] push-to-drive error:', err);
    res.status(502).json({ error: err.message || 'Drive push failed' });
  }
});

// Scan Projects folder via Gemini Vision
app.post('/api/launches/:id/scan-projects', requireAuth, async (req, res) => {
  try {
    const doc = await db.collection('launches').doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    const d = doc.data();
    if (!d.drive_folder_id) return res.status(400).json({ error: 'No Google Drive folder linked to this launch' });

    const token = await getAnalyticsAccessToken();
    const geminiKey = await getGeminiKey();

    // Helper: list all files in a folder
    async function listFiles(folderId) {
      const q = encodeURIComponent(`'${folderId}' in parents and trashed=false`);
      const r = await fetchWithRetry(`https://www.googleapis.com/drive/v3/files?q=${q}&fields=files(id,name,mimeType)&pageSize=50`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!r.ok) return [];
      return (await r.json()).files || [];
    }

    function isImage(f) {
      return f.mimeType?.startsWith('image/') || f.name?.match(/\.(jpg|jpeg|png|gif|webp|avif|bmp|heic)$/i);
    }
    function isScreenshot(f) {
      return f.name?.toLowerCase().includes('screenshot') || f.name?.toLowerCase().includes('screen shot');
    }
    function isFolder(f) { return f.mimeType === 'application/vnd.google-apps.folder'; }

    // Find the Projects folder
    const projFolderId = await driveFindFolder('Projects', d.drive_folder_id, token);
    if (!projFolderId) {
      await driveCreateFolder('Projects', d.drive_folder_id, token);
      return res.json({ projects: [], message: 'Projects folder was empty. Created it — add project subfolders and try again.' });
    }

    // List everything in the Projects folder
    const topLevelFiles = await listFiles(projFolderId);
    const subfolders = topLevelFiles.filter(isFolder);
    const looseImages = topLevelFiles.filter(isImage);

    console.log(`[scan-projects] Projects folder has ${subfolders.length} subfolders, ${looseImages.length} loose images`);

    // Structure: each subfolder = one project
    // Inside each subfolder: screenshots = job info, other images = project photos
    const projectEntries = [];

    // Process subfolders (one project per subfolder)
    for (const sf of subfolders.slice(0, 20)) {
      const files = await listFiles(sf.id);
      const images = files.filter(isImage);
      const screenshots = images.filter(isScreenshot);
      const photos = images.filter(f => !isScreenshot(f));

      projectEntries.push({
        folderName: sf.name,
        folderId: sf.id,
        screenshots,
        photos,
      });
      console.log(`[scan-projects] Subfolder "${sf.name}": ${screenshots.length} screenshots, ${photos.length} photos`);
    }

    // Also handle loose images in the root Projects folder (legacy structure)
    if (looseImages.length && !subfolders.length) {
      const screenshots = looseImages.filter(isScreenshot);
      const photos = looseImages.filter(f => !isScreenshot(f));
      projectEntries.push({
        folderName: 'Projects (root)',
        folderId: projFolderId,
        screenshots: screenshots.length ? screenshots : looseImages.slice(0, 5), // treat all as screenshots if none named
        photos,
      });
    }

    if (!projectEntries.length) {
      return res.json({ projects: [], message: 'No project subfolders or images found. Create subfolders like "2026-04 Gutter Install - Ridge NJ" inside Projects/' });
    }

    const extractionPrompt = `You are extracting project/job data from a screenshot of a home services contractor's project management software.

Extract ALL visible information and return ONLY valid JSON:
{
  "customer_name": "first name and last initial only (e.g. Dave D.)",
  "customer_city": "city and state",
  "job_date": "date of the job",
  "job_title": "brief title for the job",
  "job_description": "the full description text visible",
  "customer_type": "residential or commercial",
  "service_tags": ["list of service types visible"],
  "review_text": "the full Google review text if visible, or null",
  "review_rating": 5 or null,
  "reviewer_name": "reviewer name if visible, or null"
}

If the image is a photo of actual work (not a screenshot of software), return:
{"type": "photo", "description": "brief description of what the photo shows"}

If the image is not relevant, return {"error": "not_relevant"}.`;

    const projects = [];
    for (const entry of projectEntries) {
      const project = {
        folder_name: entry.folderName,
        folder_id: entry.folderId,
        photos: entry.photos.map(p => ({
          id: p.id,
          name: p.name,
          url: `https://drive.google.com/thumbnail?id=${p.id}&sz=w800`,
        })),
      };

      // Process screenshots through Gemini Vision to extract job data
      for (const screenshot of entry.screenshots.slice(0, 3)) {
        try {
          const imgRes = await fetchWithRetry(`https://www.googleapis.com/drive/v3/files/${screenshot.id}?alt=media`, {
            headers: { Authorization: `Bearer ${token}` },
          });
          if (!imgRes.ok) continue;
          const imgBuffer = Buffer.from(await imgRes.arrayBuffer());
          const base64 = imgBuffer.toString('base64');
          const mimeType = screenshot.mimeType || 'image/jpeg';

          const geminiRes = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${geminiKey}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              contents: [{ parts: [
                { text: extractionPrompt },
                { inlineData: { mimeType, data: base64 } }
              ]}],
              generationConfig: { temperature: 0.1, maxOutputTokens: 1024, thinkingConfig: { thinkingBudget: 0 } }
            }),
            signal: AbortSignal.timeout(30000),
          });
          incrApiStat('gemini');

          const geminiData = await geminiRes.json();
          if (!geminiRes.ok) continue;

          const parts = geminiData.candidates?.[0]?.content?.parts || [];
          const rawText = (parts.filter(p => p.text).pop()?.text || '').trim();
          const jsonStr = rawText.replace(/^```json?\n?/i, '').replace(/\n?```$/m, '').trim();
          const parsed = JSON.parse(jsonStr);

          if (!parsed.error && parsed.type !== 'photo') {
            // Merge extracted data into the project
            Object.assign(project, parsed);
            project._source_file = screenshot.name;
            break; // One screenshot is enough for job data
          }
        } catch (err) {
          console.warn(`[scan-projects] Error processing ${screenshot.name}:`, err.message);
        }
        await new Promise(r => setTimeout(r, 1000));
      }

      // Use folder name as fallback title if no data extracted
      if (!project.job_title && entry.folderName !== 'Projects (root)') {
        project.job_title = entry.folderName;
      }

      projects.push(project);
    }

    // Save to launch doc
    await db.collection('launches').doc(req.params.id).update({
      projects,
      updated_at: FieldValue.serverTimestamp(),
    });

    console.log(`[scan-projects] Extracted ${projects.length} projects (${projectEntries.reduce((s, e) => s + e.photos.length, 0)} photos) for ${d.account_name}`);
    res.json({ projects, foldersScanned: projectEntries.length });
  } catch (err) {
    console.error('[scan-projects] error:', err);
    res.status(500).json({ error: err.message || 'Scan failed' });
  }
});

// ── Research file endpoints ──
app.put('/api/launches/:id/research', requireAuth, async (req, res) => {
  try {
    const { content } = req.body;
    if (!content || typeof content !== 'string') return res.status(400).json({ error: 'content string required' });
    if (Buffer.byteLength(content, 'utf8') > 500 * 1024) return res.status(400).json({ error: 'Research file exceeds 500KB limit' });
    const ref = db.collection('launches').doc(req.params.id);
    const doc = await ref.get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    await ref.update({ research_md: content, updated_at: FieldValue.serverTimestamp() });

    // Push to Google Drive (fire-and-forget)
    const d = doc.data();
    const clientName = d.account_name || 'Unknown';
    (async () => {
      try {
        const token = await getAnalyticsAccessToken();
        const clientFolderId = await driveGetOrCreateClientFolder(clientName, token);
        const resFolderId = await driveGetOrCreateSubfolder('Research', clientFolderId, token);
        const date = new Date().toISOString().slice(0, 10);
        await driveUploadFile(`Research — ${date}.md`, content, 'text/markdown', resFolderId, token);
        await ref.update({
          drive_folder_id: clientFolderId,
          drive_folder_url: `https://drive.google.com/drive/folders/${clientFolderId}`,
        }).catch(() => {});
        console.log(`[drive] Pushed research for ${clientName} → folder ${clientFolderId}`);
      } catch (err) {
        console.warn('[drive] Failed to push research to Drive:', err.message);
      }
    })();

    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/launches/:id/research', requireAuth, async (req, res) => {
  try {
    const doc = await db.collection('launches').doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    const content = doc.data().research_md || '';
    res.json({ content });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/launches/:id/research', requireAuth, async (req, res) => {
  try {
    const ref = db.collection('launches').doc(req.params.id);
    const doc = await ref.get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    await ref.update({ research_md: FieldValue.delete(), updated_at: FieldValue.serverTimestamp() });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Backfill Google Drive folders for all existing accounts that don't have one
app.post('/api/admin/backfill-drive-folders', requireAuth, async (req, res) => {
  try {
    const snap = await db.collection('launches').get();
    const missing = snap.docs.filter(d => !d.data().drive_folder_id && !d.data().archived);
    res.json({ queued: missing.length, message: `Creating Drive folders for ${missing.length} accounts in background` });
    (async () => {
      const token = await getAnalyticsAccessToken();
      let created = 0, failed = 0;
      for (const doc of missing) {
        try {
          const name = doc.data().account_name || 'Unknown';
          const folderId = await driveGetOrCreateClientFolder(name, token);
          await driveGetOrCreateSubfolder('Onboarding', folderId, token);
          await driveGetOrCreateSubfolder('Research', folderId, token);
          await driveGetOrCreateSubfolder('Blog Posts', folderId, token);
          await doc.ref.update({ drive_folder_id: folderId, drive_folder_url: `https://drive.google.com/drive/folders/${folderId}` });
          created++;
          // Longer delay to avoid Google Drive rate limiting (each account = ~7 API calls)
          await new Promise(r => setTimeout(r, 2000));
        } catch (e) { failed++; console.warn(`[drive-backfill] ${doc.data().account_name}:`, e.message); }
      }
      console.log(`[drive-backfill] Done — created: ${created}, failed: ${failed}`);
    })();
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Lightweight client search for onboarding picker (returns minimal fields)
app.get('/api/onboarding/clients', requireAuth, async (req, res) => {
  try {
    const { search } = req.query;
    const snapshot = await db.collection('launches').orderBy('created_at', 'desc').get();
    let clients = snapshot.docs
      .map(d => { const data = d.data(); return { id: d.id, account_name: data.account_name || '', contact_name: data.contact_name || '', email: data.email || '', domain_name: data.domain_name || '', industry: data.industry || '', status: data.status || '', phone: data.phone || '' }; })
      .filter(c => !['decommissioned'].includes(c.status));
    if (search) {
      const term = search.toLowerCase();
      clients = clients.filter(c =>
        c.account_name.toLowerCase().includes(term) ||
        c.contact_name.toLowerCase().includes(term) ||
        c.email.toLowerCase().includes(term) ||
        c.domain_name.toLowerCase().includes(term)
      );
    }
    res.json(clients.slice(0, 30));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/onboarding/sessions', requireAuth, async (req, res) => {
  try {
    const { clientName, clientId } = req.body;
    const joinToken = randomUUID();
    const doc = await db.collection('onboarding_interviews').add({
      created_by: req.userEmail,
      created_at: FieldValue.serverTimestamp(),
      updated_at: FieldValue.serverTimestamp(),
      client_name: clientName || 'Untitled',
      client_id: clientId || null,
      mode: 'ai_led',
      status: 'in_progress',
      current_question: -1,
      answers: {},
      skipped: [],
      extracted_profile: null,
      join_token: joinToken,
      join_token_active: true,
      transcript_chunks: [],
    });
    res.json({ id: doc.id, status: 'in_progress', current_question: -1, join_token: joinToken });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/onboarding/sessions/:id', requireAuth, async (req, res) => {
  try {
    const doc = await db.collection('onboarding_interviews').doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    const d = doc.data();
    res.json({ id: doc.id, ...d, created_at: d.created_at?.toDate?.()?.toISOString() || null, updated_at: d.updated_at?.toDate?.()?.toISOString() || null });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Download raw session data (answers + transcript chunks) — always accessible
app.delete('/api/onboarding/sessions/:id', requireAuth, async (req, res) => {
  try {
    const ref = db.collection('onboarding_interviews').doc(req.params.id);
    const doc = await ref.get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    await ref.delete();
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Extract structured profile from an uploaded Zoom transcript file
app.post('/api/onboarding/extract-transcript', requireAuth, async (req, res) => {
  try {
    const { clientId, clientName, transcript } = req.body;
    if (!clientId || !transcript) return res.status(400).json({ error: 'clientId and transcript required' });
    if (transcript.length > 200000) return res.status(400).json({ error: 'Transcript too large (max 200K chars)' });

    const geminiKey = await getGeminiKey();
    const prompt = `You are a structured data extractor for a home services contractor onboarding interview.
Below is a raw transcript from a Zoom call between a RealWork Labs team member and a contractor named "${clientName || 'the contractor'}". The conversation covers their business story, services, what makes them different, service area, brand voice, credentials, and goals for their new website.

Extract a structured JSON profile from this conversation. Pull out every relevant detail — names, years, cities, services, certifications, etc.

TRANSCRIPT:
${transcript.slice(0, 150000)}

Return ONLY valid JSON with no markdown fencing, no commentary. Use this schema:
{
  "business_name": "string or null",
  "owner_name": "string or null",
  "origin_story": "2-3 sentence narrative summarizing their founding story",
  "years_in_business": number or null,
  "pride_points": ["what they're most proud of"],
  "family_connection": "string or null",
  "services": {
    "core": ["list of core services"],
    "top_revenue": "highest revenue service",
    "promote_more": ["services they want to push"],
    "emergency_available": true/false or null
  },
  "differentiation": {
    "unique_selling_points": ["what sets them apart"],
    "customer_compliments": ["what customers say"],
    "guarantees": ["any guarantees or unique processes"],
    "ideal_customer": "description of ideal customer"
  },
  "service_area": {
    "cities": ["cities/areas served"],
    "primary_markets": ["where most jobs come from"],
    "growth_targets": ["areas they want to expand into"],
    "max_travel_radius": "how far they'll travel"
  },
  "brand_voice": {
    "personality": "company personality description",
    "tone": "formal/casual/friendly etc",
    "preferred_phrases": ["phrases they use"],
    "avoid_phrases": ["phrases to avoid"],
    "voice_description": "how the brand would talk as a person"
  },
  "credentials": {
    "licenses": ["licenses held"],
    "insured": true/false,
    "bonded": true/false,
    "associations": ["trade associations"],
    "awards": ["awards or recognitions"]
  },
  "goals": {
    "website_goals": ["goals for the new website"],
    "six_month_success": "what success looks like",
    "additional_notes": "anything else mentioned"
  }
}

Extract as much detail as possible. For fields not discussed in the transcript, use null or empty arrays.`;

    // Use longer timeout and retries for transcript extraction
    async function callGeminiTranscript(promptText, attempt = 0) {
      const r = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${geminiKey}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ contents: [{ parts: [{ text: promptText }] }], generationConfig: { temperature: 0.2, maxOutputTokens: 4096, thinkingConfig: { thinkingBudget: 0 } } }),
          signal: AbortSignal.timeout(90_000), // 90s for transcripts (can be very large)
        }
      );
      if (!r.ok) {
        if (attempt < 2 && [429, 500, 502, 503].includes(r.status)) {
          await new Promise(resolve => setTimeout(resolve, 3000));
          return callGeminiTranscript(promptText, attempt + 1);
        }
        throw new Error(`Gemini API error ${r.status}`);
      }
      const gData = await r.json();
      const parts = gData.candidates?.[0]?.content?.parts || [];
      return (parts.filter(p => p.text).pop()?.text || '').trim();
    }

    let raw = await callGeminiTranscript(prompt);
    let cleaned = raw.replace(/^```json?\s*/i, '').replace(/```\s*$/, '').trim();

    let profile;
    try {
      profile = JSON.parse(cleaned);
    } catch {
      // Retry with stricter prompt
      const retryPrompt = prompt + '\n\nCRITICAL: Return ONLY valid JSON. Start with { and end with }. No markdown, no backticks, no commentary.';
      raw = await callGeminiTranscript(retryPrompt);
      cleaned = raw.replace(/^```json?\s*/i, '').replace(/```\s*$/, '').trim();
      const jsonMatch = cleaned.match(/\{[\s\S]*\}/);
      if (jsonMatch) { try { profile = JSON.parse(jsonMatch[0]); } catch {} }
      if (!profile) return res.status(502).json({ error: 'Extraction failed — please retry', raw: cleaned.slice(0, 300) });
    }

    // Save to the launch doc
    await db.collection('launches').doc(clientId).update({
      onboarding_profile: profile,
      onboarding_completed_at: FieldValue.serverTimestamp(),
    }).catch(e => console.error('Failed to save transcript profile to launch:', e.message));

    // Also create an onboarding_interviews record for history
    await db.collection('onboarding_interviews').add({
      created_by: req.userEmail,
      created_at: FieldValue.serverTimestamp(),
      updated_at: FieldValue.serverTimestamp(),
      client_name: clientName || 'Untitled',
      client_id: clientId,
      mode: 'transcript_upload',
      status: 'extracted',
      current_question: 0,
      answers: {},
      skipped: [],
      extracted_profile: profile,
      completed_at: FieldValue.serverTimestamp(),
      transcript_text: transcript.slice(0, 100000),
      join_token: null,
      join_token_active: false,
    });

    res.json({ profile });

    // Push to Google Drive in the background
    pushOnboardingToDrive(clientId, clientName || 'Unknown', profile, transcript).catch(() => {});
  } catch (err) {
    console.error('extract-transcript error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/onboarding/sessions/:id/raw', requireAuth, async (req, res) => {
  try {
    const doc = await db.collection('onboarding_interviews').doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    const d = doc.data();
    res.json({
      id: doc.id,
      client_name: d.client_name,
      client_id: d.client_id,
      status: d.status,
      created_at: d.created_at?.toDate?.()?.toISOString() || null,
      current_question: d.current_question,
      answers: d.answers || {},
      skipped: d.skipped || [],
      transcript_chunks: d.transcript_chunks || [],
      extracted_profile: d.extracted_profile || null,
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/onboarding/sessions/:id/answer', requireAuth, async (req, res) => {
  try {
    const { questionId, answer, currentQuestion, skipped, aiMessage } = req.body;
    const ref = db.collection('onboarding_interviews').doc(req.params.id);
    const updates = { updated_at: FieldValue.serverTimestamp(), current_question: currentQuestion };
    if (questionId && answer !== undefined) updates[`answers.${questionId}`] = answer;
    if (skipped) updates.skipped = skipped;
    if (aiMessage !== undefined) updates.current_ai_message = aiMessage;
    if (req.body.clearSummary) updates.section_summary = null;
    await ref.update(updates);
    res.json({ ok: true });

    // Emit SSE question_change event for join/present pages
    const q = ONBOARDING_QUESTIONS[currentQuestion] || null;
    emitSseEvent(req.params.id, 'question_change', {
      status: 'in_progress',
      active: true,
      current_question: currentQuestion,
      current_question_label: q?.label || null,
      current_section: q?.section || null,
      current_ai_message: aiMessage !== undefined ? aiMessage : null,
      section_summary: req.body.clearSummary ? null : undefined,
      total_questions: ONBOARDING_QUESTIONS.length,
      progress: Math.round((currentQuestion / ONBOARDING_QUESTIONS.length) * 100),
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// AI conversation turn — evaluates the contractor's answer and decides next action
app.post('/api/onboarding/chat', requireAuth, async (req, res) => {
  try {
    const { question, answer, followups, sectionName, clientName, conversationContext, alreadyFollowedUp } = req.body;
    if (!question || !answer) return res.status(400).json({ error: 'question and answer required' });

    const geminiKey = await getGeminiKey();
    const followupList = (followups || []).map((f, i) => `${i + 1}. "${f}"`).join('\n');
    const contextLine = conversationContext ? `\nRecent conversation context:\n${conversationContext}\n` : '';
    const alreadyFollowedUpLine = alreadyFollowedUp ? `\nIMPORTANT: You already asked a follow-up for this question. Do NOT ask another one. Return "next" and move on.\n` : '';

    const prompt = `You are a friendly, professional interviewer onboarding a home services contractor named "${clientName || 'the contractor'}" for their new website. You are in the "${sectionName || ''}" section.

You asked: "${question}"
They answered: "${answer}"
${contextLine}${alreadyFollowedUpLine}
Your primary goal is to MOVE THE INTERVIEW FORWARD. Follow-ups should be rare and purposeful.

Return ONLY valid JSON with no markdown. Choose ONE action:

{"action":"next","message":"Brief warm 1-sentence acknowledgment referencing what they said. Do NOT include the next question."}
— Use this for ANY answer that is reasonable and on-topic, even if brief. This is the DEFAULT.

{"action":"followup","message":"Natural 1-2 sentence follow-up. Be encouraging, not interrogating."}
— Use this ONLY if ALL of these are true:
  1. The answer is under 15 words AND clearly lacks substance
  2. The question is critical for website copy (not a yes/no question)
  3. You have NOT already asked a follow-up for this question
  Available follow-ups: ${followupList || '(none)'}

Rules:
- DEFAULT TO "next". When in doubt, move on.
- If they said "skip", "I don't know", "not sure", "pass", or similar → ALWAYS return "next"
- If the answer is a simple factual response (a number, a yes/no, a list) → return "next" even if short
- NEVER ask more than ONE follow-up per question
- Keep messages to 1-2 sentences max
- Reference something specific they said
- Return ONLY the JSON object`;

    const gRes = await fetchWithRetry(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${geminiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { temperature: 0.7, maxOutputTokens: 1024, thinkingConfig: { thinkingBudget: 0 } } }),
      }
    );
    const gData = await gRes.json();
    // Grab the last text part (skips thinking part if present)
    const parts = gData.candidates?.[0]?.content?.parts || [];
    const raw = (parts.filter(p => p.text).pop()?.text || '').trim();
    const cleaned = raw.replace(/^```json?\s*/i, '').replace(/```\s*$/, '').trim();

    let result;
    try { result = JSON.parse(cleaned); } catch {
      result = { action: 'next', message: 'Got it, thanks! Let me move on to the next question.' };
    }
    res.json(result);
  } catch (err) {
    console.error('onboarding chat error:', err);
    res.json({ action: 'next', message: 'Thanks for that. Let\'s keep going.' });
  }
});

// AI generates a natural way to ask the next question
app.post('/api/onboarding/ask', requireAuth, async (req, res) => {
  try {
    const { question, sectionName, clientName, isFirstQuestion, previousContext } = req.body;
    if (!question) return res.status(400).json({ error: 'question required' });

    const geminiKey = await getGeminiKey();
    const contextLine = previousContext ? `\nWhat we've covered so far:\n${previousContext}\n` : '';

    const prompt = `You are a friendly, professional interviewer onboarding a home services contractor named "${clientName || 'the contractor'}" for their new website.
${isFirstQuestion ? `This is the very first question of the interview. Start with a warm, brief welcome (1 sentence) before asking.` : `You are in the "${sectionName}" section.`}
${contextLine}
Ask this interview question in a natural, conversational way:
"${question}"

Rules:
- Be warm and human — not robotic or formal
- Keep it to 1-3 sentences
- Ask the question naturally, don't just repeat it verbatim
- If transitioning to a new section, briefly introduce what this section covers (1 sentence)
- Return ONLY the conversational question text, no JSON, no quotes, no markdown`;

    const gRes = await fetchWithRetry(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${geminiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { temperature: 0.8, maxOutputTokens: 1024, thinkingConfig: { thinkingBudget: 0 } } }),
      }
    );
    const gData = await gRes.json();
    // Grab the last text part (skips thinking part if present)
    const parts = gData.candidates?.[0]?.content?.parts || [];
    const raw = (parts.filter(p => p.text).pop()?.text || '').trim();
    const text = raw.replace(/^["']|["']$/g, '').trim();
    res.json({ message: text || question });
  } catch (err) {
    console.error('onboarding ask error:', err);
    res.json({ message: req.body.question }); // fallback to raw question
  }
});

app.post('/api/onboarding/sessions/:id/extract', requireAuth, async (req, res) => {
  try {
    const doc = await db.collection('onboarding_interviews').doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    const sessionData2 = doc.data();
    const firestoreAnswers = sessionData2.answers || {};
    const client_name = sessionData2.client_name;
    const { questions } = req.body; // array of { id, label, answer }
    if (!questions || !questions.length) return res.status(400).json({ error: 'questions array required' });

    // Merge: prefer client-sent answers, fall back to Firestore answers
    const mergedQuestions = questions.map(q => {
      let answer = q.answer;
      if (!answer || answer === '(not discussed)' || answer === '(skipped)') {
        const fsAnswer = firestoreAnswers[q.id];
        if (fsAnswer && fsAnswer.trim()) answer = fsAnswer;
      }
      return { ...q, answer };
    });

    const geminiKey = await getGeminiKey();
    const qaPairs = mergedQuestions.map(q => `Q: ${q.label}\nA: ${q.answer || '(skipped)'}`).join('\n\n');

    const prompt = `You are a structured data extractor for a home services contractor onboarding interview.
Below are questions and the contractor's answers. Extract a structured JSON profile.
Business/client name: "${client_name || 'Unknown'}"

${qaPairs}

Return ONLY valid JSON with no markdown fencing, no commentary. Use this schema:
{
  "business_name": "string or null",
  "owner_name": "string or null",
  "origin_story": "2-3 sentence narrative summarizing their founding story",
  "years_in_business": number or null,
  "pride_points": ["what they're most proud of"],
  "family_connection": "string or null",
  "services": {
    "core": ["list of core services"],
    "top_revenue": "highest revenue service",
    "promote_more": ["services they want to push"],
    "emergency_available": true/false or null
  },
  "differentiation": {
    "unique_selling_points": ["what sets them apart"],
    "customer_compliments": ["what customers say"],
    "guarantees": ["any guarantees or unique processes"],
    "ideal_customer": "description of ideal customer"
  },
  "service_area": {
    "cities": ["cities/areas served"],
    "primary_markets": ["where most jobs come from"],
    "growth_targets": ["areas they want to expand into"],
    "max_travel_radius": "how far they'll travel"
  },
  "brand_voice": {
    "personality": "company personality description",
    "tone": "formal/casual/friendly etc",
    "preferred_phrases": ["phrases they use"],
    "avoid_phrases": ["phrases to avoid"],
    "voice_description": "how the brand would talk as a person"
  },
  "credentials": {
    "licenses": ["licenses held"],
    "insured": true/false,
    "bonded": true/false,
    "associations": ["trade associations"],
    "awards": ["awards or recognitions"]
  },
  "goals": {
    "website_goals": ["goals for the new website"],
    "six_month_success": "what success looks like",
    "additional_notes": "anything else mentioned"
  }
}`;

    // Extraction is critical — use longer timeout (60s), more retries, and disable thinking
    async function callGeminiExtract(promptText, attempt = 0) {
      const r = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${geminiKey}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ contents: [{ parts: [{ text: promptText }] }], generationConfig: { temperature: 0.2, maxOutputTokens: 4096, thinkingConfig: { thinkingBudget: 0 } } }),
          signal: AbortSignal.timeout(60_000), // 60s timeout for extraction
        }
      );
      if (!r.ok) {
        if (attempt < 2 && [429, 500, 502, 503].includes(r.status)) {
          await new Promise(resolve => setTimeout(resolve, 3000));
          return callGeminiExtract(promptText, attempt + 1);
        }
        throw new Error(`Gemini API error ${r.status}`);
      }
      const gData = await r.json();
      const parts = gData.candidates?.[0]?.content?.parts || [];
      const raw = (parts.filter(p => p.text).pop()?.text || '').trim();
      return raw;
    }

    let raw = await callGeminiExtract(prompt);
    let cleaned = raw.replace(/^```json?\s*/i, '').replace(/```\s*$/, '').trim();
    let profile;
    try {
      profile = JSON.parse(cleaned);
    } catch {
      // Retry once with stricter prompt
      console.warn('Extraction JSON parse failed, retrying with stricter prompt...');
      const retryPrompt = prompt + '\n\nCRITICAL: Your previous response was not valid JSON. Return ONLY the JSON object. No markdown fences, no backticks, no text before or after the JSON. Start with { and end with }.';
      raw = await callGeminiExtract(retryPrompt);
      cleaned = raw.replace(/^```json?\s*/i, '').replace(/```\s*$/, '').trim();
      // Try to extract JSON from the response even if there's surrounding text
      const jsonMatch = cleaned.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        try { profile = JSON.parse(jsonMatch[0]); } catch {}
      }
      if (!profile) return res.status(502).json({ error: 'Extraction failed — AI returned invalid data. Please retry.', raw: cleaned.slice(0, 300) });
    }

    // Batch write: interview doc + launch doc in one atomic operation
    const batch = db.batch();
    const interviewRef = db.collection('onboarding_interviews').doc(req.params.id);
    batch.update(interviewRef, {
      status: 'extracted',
      extracted_profile: profile,
      completed_at: FieldValue.serverTimestamp(),
      updated_at: FieldValue.serverTimestamp(),
      join_token_active: false,
    });

    if (sessionData2.client_id) {
      const launchRef = db.collection('launches').doc(sessionData2.client_id);
      batch.update(launchRef, {
        onboarding_profile: profile,
        onboarding_completed_at: FieldValue.serverTimestamp(),
      });
    }

    try { await batch.commit(); } catch (e) {
      console.error('Batch commit failed, falling back:', e.message);
      await interviewRef.update({ status: 'extracted', extracted_profile: profile, completed_at: FieldValue.serverTimestamp(), updated_at: FieldValue.serverTimestamp(), join_token_active: false });
      if (sessionData2.client_id) {
        await db.collection('launches').doc(sessionData2.client_id).update({ onboarding_profile: profile, onboarding_completed_at: FieldValue.serverTimestamp() }).catch(() => {});
      }
    }

    res.json({ profile });
    emitSseEvent(req.params.id, 'complete', { status: 'extracted' });

    // Push to Google Drive in the background (fire-and-forget)
    if (sessionData2.client_id) {
      const transcriptData = firestoreAnswers ? Object.entries(firestoreAnswers).map(([k, v]) => `${k}: ${v}`).join('\n\n') : null;
      pushOnboardingToDrive(sessionData2.client_id, sessionData2.client_name || 'Unknown', profile, transcriptData).catch(() => {});
    }
  } catch (err) {
    console.error('onboarding extract error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Generate a section summary after all questions in a section are answered
app.post('/api/onboarding/sessions/:id/section-summary', requireAuth, async (req, res) => {
  try {
    const { sectionName, sectionIndex, answers: sectionAnswers, clientName } = req.body;
    if (!sectionName || !sectionAnswers) return res.status(400).json({ error: 'sectionName and answers required' });

    const SECTION_UNLOCKS = {
      'Origin Story': ['About Us copy', 'Homepage hero', 'Brand story'],
      'Services': ['Service pages', 'Process section', 'FAQ content'],
      'Differentiation': ['Why Choose Us', 'Trust signals', 'Review framing'],
      'Service Area': ['City pages', 'Area coverage', 'Local SEO'],
      'Brand Voice': ['Site tone', 'Messaging style', 'CTA copy'],
      'Credentials': ['Trust badges', 'Certifications', 'Schema markup'],
      'Goals': ['SEO strategy', 'Conversion goals', 'Content plan'],
    };

    const geminiKey = await getGeminiKey();
    const qaPairs = sectionAnswers.map(qa => `Q: ${qa.question}\nA: ${qa.answer || '(skipped)'}`).join('\n\n');

    const prompt = `You are an experienced brand strategist reviewing a contractor onboarding interview. You just finished the "${sectionName}" section with ${clientName || 'the contractor'}.

Here's what they shared:

${qaPairs}

Write a warm, confident, celebratory summary FOR the contractor — as if you're telling them what you heard and why it matters for their website. This is shown on screen between sections to make them feel good about the process.

Return ONLY valid JSON with no markdown:
{
  "narrative": "2-3 paragraphs. Reference specific details they shared (names, years, services, etc). Tone: warm and confident, like an experienced strategist who's excited about what they heard. NOT corporate — no 'stakeholder', 'value proposition', 'leverage'. Write like a real person talking to another person.",
  "unlocks": ["3-4 short, high-level labels (2-4 words each) for website areas this section improves. Examples: 'About Us copy', 'Service pages', 'Local SEO', 'Trust signals', 'Brand story'. Keep them vague and brief — NO full sentences, NO specific details from the interview. Focus on website pages only: homepage, service pages, service area pages, review page, blog, FAQ."]
}`;

    const gRes = await fetchWithRetry(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${geminiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { temperature: 0.7, maxOutputTokens: 1024, thinkingConfig: { thinkingBudget: 0 } } }),
      }
    );
    const gData = await gRes.json();
    const parts = gData.candidates?.[0]?.content?.parts || [];
    const raw = (parts.filter(p => p.text).pop()?.text || '').trim();
    const cleaned = raw.replace(/^```json?\s*/i, '').replace(/```\s*$/, '').trim();

    let summary;
    try { summary = JSON.parse(cleaned); } catch {
      summary = { narrative: 'Great progress on this section! Let\'s keep going.', unlocks: SECTION_UNLOCKS[sectionName] || ['Website content tailored to your business'] };
    }

    // Add fallback unlocks if AI didn't return enough
    if (!summary.unlocks || summary.unlocks.length < 2) {
      summary.unlocks = SECTION_UNLOCKS[sectionName] || ['Website content tailored to your business'];
    }

    // Save to session doc so the presentation view can pick it up
    const sectionSummary = {
      section_name: sectionName,
      section_index: sectionIndex,
      narrative: summary.narrative,
      unlocks: summary.unlocks,
      client_name: clientName,
    };
    await db.collection('onboarding_interviews').doc(req.params.id).update({
      section_summary: sectionSummary,
      completed_summaries: FieldValue.arrayUnion({
        section_name: sectionName,
        section_index: sectionIndex,
        narrative: summary.narrative,
        unlocks: summary.unlocks,
      }),
      updated_at: FieldValue.serverTimestamp(),
    });

    res.json(sectionSummary);
    emitSseEvent(req.params.id, 'summary', sectionSummary);
  } catch (err) {
    console.error('section-summary error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Clear section summary when advancing to next section
app.post('/api/onboarding/sessions/:id/clear-summary', requireAuth, async (req, res) => {
  try {
    await db.collection('onboarding_interviews').doc(req.params.id).update({
      section_summary: null,
      updated_at: FieldValue.serverTimestamp(),
    });
    res.json({ ok: true });
    emitSseEvent(req.params.id, 'summary_cleared', {});
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Onboarding Join (contractor-facing, no auth) ──
const ONBOARDING_QUESTIONS = [
  { id:'origin_1', section:'Origin Story', label:'Tell us your story — how did you get into this trade and start your business?' },
  { id:'origin_2', section:'Origin Story', label:'What makes you most proud about your company?' },
  { id:'origin_3', section:'Origin Story', label:'Is there a family or personal story connected to the business?' },
  { id:'services_1', section:'Services', label:'Walk me through your core services — what do you do?' },
  { id:'services_2', section:'Services', label:'Which service is your bread and butter, and which do you want to grow?' },
  { id:'services_3', section:'Services', label:'Describe your process from the first call to job completion.' },
  { id:'diff_1', section:'Differentiation', label:'What makes you different from competitors — and what do customers say about you?' },
  { id:'diff_2', section:'Differentiation', label:'Who is your ideal customer?' },
  { id:'area_1', section:'Service Area', label:'What areas do you serve, and where do you get the most work?' },
  { id:'area_2', section:'Service Area', label:'Are there specific neighborhoods or cities you want to target for growth?' },
  { id:'voice_1', section:'Brand Voice', label:'How would you describe your company\'s personality and tone?' },
  { id:'voice_2', section:'Brand Voice', label:'Any words, phrases, or taglines you love — or want to avoid on the website?' },
  { id:'cred_1', section:'Credentials', label:'What licenses, certifications, and insurance do you carry?' },
  { id:'cred_2', section:'Credentials', label:'Any awards, recognitions, or things you want to highlight?' },
  { id:'goals_1', section:'Goals', label:'What are your top goals for the new website?' },
  { id:'goals_2', section:'Goals', label:'What does success look like 6 months from now?' },
  { id:'goals_3', section:'Goals', label:'Anything else we should know about your business?' },
];

// ── Rate limiter for unauthenticated join endpoints ──
const joinRateMap = new Map();
function joinRateLimit(req, res, next) {
  const key = req.params.sessionId;
  const now = Date.now();
  let entry = joinRateMap.get(key);
  if (!entry) { entry = []; joinRateMap.set(key, entry); }
  // Purge timestamps older than 60s
  while (entry.length && entry[0] < now - 60000) entry.shift();
  if (entry.length >= 30) return res.status(429).json({ error: 'Too many requests. Please slow down.' });
  entry.push(now);
  next();
}
// Clean up stale entries every 5 minutes
setInterval(() => {
  const cutoff = Date.now() - 120000;
  for (const [key, timestamps] of joinRateMap) {
    if (!timestamps.length || timestamps[timestamps.length - 1] < cutoff) joinRateMap.delete(key);
  }
}, 300000);

async function validateJoinToken(sessionId, token) {
  const doc = await db.collection('onboarding_interviews').doc(sessionId).get();
  if (!doc.exists) return null;
  const d = doc.data();
  if (d.join_token !== token) return null;
  return { doc, data: d };
}

// ── SSE stream for contractor join page (token-validated, no auth) ──
app.get('/api/join/:sessionId/:token/stream', async (req, res) => {
  try {
    const result = await validateJoinToken(req.params.sessionId, req.params.token);
    if (!result) return res.status(403).json({ error: 'Invalid' });

    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
    });

    const d = result.data;
    const q = ONBOARDING_QUESTIONS[d.current_question] || null;
    const initialState = {
      status: d.status,
      active: d.join_token_active !== false,
      current_question: d.current_question || 0,
      current_question_label: q?.label || null,
      current_section: q?.section || null,
      current_ai_message: d.current_ai_message || null,
      section_summary: d.section_summary || null,
      total_questions: ONBOARDING_QUESTIONS.length,
      progress: Math.round(((d.current_question || 0) / ONBOARDING_QUESTIONS.length) * 100),
    };
    res.write(`event: state\ndata: ${JSON.stringify(initialState)}\n\n`);

    const sid = req.params.sessionId;
    addSseClient(sid, res);

    const heartbeat = setInterval(() => {
      try { res.write(': heartbeat\n\n'); } catch { clearInterval(heartbeat); removeSseClient(sid, res); }
    }, 30000);

    req.on('close', () => { clearInterval(heartbeat); removeSseClient(sid, res); });
  } catch (err) { if (!res.headersSent) res.status(500).json({ error: err.message }); }
});

// ── SSE stream for rep onboarding page (authenticated) ──
app.get('/api/onboarding/sessions/:id/stream', requireAuth, async (req, res) => {
  try {
    const doc = await db.collection('onboarding_interviews').doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });

    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
    });

    const d = doc.data();
    res.write(`event: state\ndata: ${JSON.stringify({
      transcript_chunks: d.transcript_chunks || [],
      contractor_interim: d.contractor_interim || '',
      current_question: d.current_question || 0,
    })}\n\n`);

    const sid = req.params.id;
    addSseClient(sid, res);

    const heartbeat = setInterval(() => {
      try { res.write(': heartbeat\n\n'); } catch { clearInterval(heartbeat); removeSseClient(sid, res); }
    }, 30000);

    req.on('close', () => { clearInterval(heartbeat); removeSseClient(sid, res); });
  } catch (err) { if (!res.headersSent) res.status(500).json({ error: err.message }); }
});

app.get('/api/join/:sessionId/:token', async (req, res) => {
  try {
    const result = await validateJoinToken(req.params.sessionId, req.params.token);
    if (!result) return res.status(403).json({ error: 'Invalid or expired link' });
    const d = result.data;
    const q = ONBOARDING_QUESTIONS[d.current_question] || null;
    res.json({
      client_name: d.client_name,
      status: d.status,
      active: d.join_token_active !== false,
      current_question: d.current_question || 0,
      current_question_label: q?.label || null,
      current_section: q?.section || null,
      current_ai_message: d.current_ai_message || null,
      total_questions: ONBOARDING_QUESTIONS.length,
      progress: Math.round(((d.current_question || 0) / ONBOARDING_QUESTIONS.length) * 100),
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/join/:sessionId/:token/state', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  try {
    const result = await validateJoinToken(req.params.sessionId, req.params.token);
    if (!result) return res.status(403).json({ error: 'Invalid' });
    const d = result.data;
    const q = ONBOARDING_QUESTIONS[d.current_question] || null;
    res.json({
      status: d.status,
      active: d.join_token_active !== false,
      current_question: d.current_question ?? 0,
      current_question_label: q?.label || null,
      current_section: q?.section || null,
      current_ai_message: d.current_ai_message || null,
      section_summary: d.section_summary || null,
      completed_summaries: d.completed_summaries || [],
      client_name: d.client_name || '',
      total_questions: ONBOARDING_QUESTIONS.length,
      progress: Math.round((Math.max(0, d.current_question ?? 0) / ONBOARDING_QUESTIONS.length) * 100),
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/join/:sessionId/:token/transcript', joinRateLimit, async (req, res) => {
  try {
    const result = await validateJoinToken(req.params.sessionId, req.params.token);
    if (!result) return res.status(403).json({ error: 'Invalid' });
    if (!result.data.join_token_active) return res.status(410).json({ error: 'Interview completed' });
    const { text, interim } = req.body;
    if (!text) return res.status(400).json({ error: 'text required' });
    if (typeof text !== 'string' || text.length > 5000) return res.status(400).json({ error: 'text exceeds maximum length of 5000 characters' });

    const ref = db.collection('onboarding_interviews').doc(req.params.sessionId);
    const chunk = { text, ts: new Date().toISOString(), source: 'contractor', questionIndex: result.data.current_question || 0 };
    if (interim) {
      await ref.update({ contractor_interim: text });
    } else {
      await ref.update({
        transcript_chunks: FieldValue.arrayUnion(chunk),
        contractor_interim: '',
      });
      // Emit transcript event for rep's onboarding page
      emitSseEvent(req.params.sessionId, 'transcript', chunk);
    }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/join/:sessionId/:token/skip', joinRateLimit, async (req, res) => {
  try {
    const result = await validateJoinToken(req.params.sessionId, req.params.token);
    if (!result) return res.status(403).json({ error: 'Invalid' });
    if (!result.data.join_token_active) return res.status(410).json({ error: 'Interview completed' });
    const ref = db.collection('onboarding_interviews').doc(req.params.sessionId);
    const skipChunk = { text: '(skipped by contractor)', ts: new Date().toISOString(), source: 'contractor', questionIndex: result.data.current_question || 0, skipped: true };
    await ref.update({
      transcript_chunks: FieldValue.arrayUnion(skipChunk),
    });
    res.json({ ok: true });
    emitSseEvent(req.params.sessionId, 'transcript', skipChunk);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/join/:sessionId/:token', (req, res) => res.sendFile(join(__dirname, 'public', 'join.html')));
app.get('/onboarding/present/:sessionId/:token', (req, res) => res.sendFile(join(__dirname, 'public', 'present.html')));

// ── Meet Add-on ──
app.get('/meet-addon-auth', requireAuth, (_req, res) => res.sendFile(join(__dirname, 'public', 'meet-addon-auth.html')));

app.get('/meet-stage', (req, res) => {
  res.setHeader('Content-Security-Policy', "frame-ancestors 'self' https://meet.google.com https://*.google.com");
  res.removeHeader('X-Frame-Options');
  res.sendFile(join(__dirname, 'public', 'meet-stage.html'));
});

app.get('/meet-addon-test', (req, res) => {
  res.setHeader('Content-Security-Policy', "frame-ancestors 'self' https://meet.google.com https://*.google.com");
  res.removeHeader('X-Frame-Options');
  res.sendFile(join(__dirname, 'public', 'meet-addon-test.html'));
});

app.get('/meet-addon', (req, res) => {
  res.setHeader('Content-Security-Policy', "frame-ancestors 'self' https://meet.google.com https://*.google.com");
  res.removeHeader('X-Frame-Options');
  res.sendFile(join(__dirname, 'public', 'meet-addon.html'));
});

// Generate auth token for Meet add-on (returns the user's existing session token)
app.get('/api/auth/meet-token', requireAuth, (req, res) => {
  const bearerMatch = req.headers.authorization?.match(/^Bearer (.+)$/);
  const { auth_token } = getCookies(req);
  const token = bearerMatch?.[1] || auth_token || null;
  res.json({ token, email: req.userEmail });
});

// Google One Tap sign-in for Meet add-on — verifies the Google ID token and returns a session token
app.post('/api/auth/google-one-tap', async (req, res) => {
  try {
    const { credential } = req.body;
    if (!credential) return res.status(400).json({ error: 'credential required' });
    // Decode the JWT to get the email (Google-signed, trusted for internal apps)
    const parts = credential.split('.');
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
    const email = payload.email;
    if (!email || !email.endsWith('@realworklabs.com')) {
      return res.status(403).json({ error: 'Only @realworklabs.com accounts are allowed' });
    }
    // Create a session token (same as the login flow)
    const token = randomUUID();
    await db.collection('sessions').doc(token).set({ email, expiry: Date.now() + 7 * 24 * 60 * 60 * 1000 });
    res.json({ token, email });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Return the OAuth client ID for Google One Tap (no auth needed)
app.get('/api/auth/client-id', (req, res) => {
  res.json({ clientId: GOOGLE_CLIENT_ID });
});

// Import Meet transcript from Google Drive
app.post('/api/onboarding/sessions/:id/import-meet-transcript', requireAuth, async (req, res) => {
  try {
    const doc = await db.collection('onboarding_interviews').doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ error: 'Session not found' });
    const session = doc.data();

    const token = await getAnalyticsAccessToken();
    const geminiKey = await getGeminiKey();

    // Search Drive for recent transcript documents created after the session started
    const sessionCreated = session.created_at?.toDate?.() || new Date(Date.now() - 24 * 60 * 60 * 1000);
    const createdISO = sessionCreated.toISOString();
    const q = encodeURIComponent(`mimeType='application/vnd.google-apps.document' and name contains 'transcript' and modifiedTime > '${createdISO}' and trashed=false`);
    const searchRes = await fetchWithRetry(`https://www.googleapis.com/drive/v3/files?q=${q}&orderBy=modifiedTime desc&pageSize=5&fields=files(id,name,modifiedTime)`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!searchRes.ok) {
      const errText = await searchRes.text();
      return res.status(502).json({ error: `Drive search failed: ${errText}` });
    }
    const searchData = await searchRes.json();
    const files = searchData.files || [];
    if (!files.length) return res.json({ profile: null, message: 'No transcript documents found in Drive' });

    // Download the most recent transcript as plain text
    const fileId = files[0].id;
    const exportRes = await fetchWithRetry(`https://www.googleapis.com/drive/v3/files/${fileId}/export?mimeType=text/plain`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!exportRes.ok) return res.status(502).json({ error: 'Failed to download transcript from Drive' });
    const transcript = await exportRes.text();

    if (!transcript || transcript.trim().length < 50) {
      return res.json({ profile: null, message: 'Transcript too short for extraction' });
    }

    // Use the same extraction pipeline as extract-transcript
    const clientName = session.client_name || 'the contractor';
    const prompt = `You are a structured data extractor for a home services contractor onboarding interview.
Below is a raw transcript from a Google Meet call between a RealWork Labs team member and a contractor named "${clientName}". The conversation covers their business story, services, what makes them different, service area, brand voice, credentials, and goals for their new website.

Extract a structured JSON profile from this conversation. Pull out every relevant detail — names, years, cities, services, certifications, etc.

TRANSCRIPT:
${transcript.slice(0, 150000)}

Return ONLY valid JSON with no markdown fencing, no commentary. Use this schema:
{
  "business_name": "string or null",
  "owner_name": "string or null",
  "origin_story": "2-3 sentence narrative summarizing their founding story",
  "years_in_business": "number or null",
  "pride_points": ["what they're most proud of"],
  "family_connection": "string or null",
  "services": { "core": [], "top_revenue": "string", "promote_more": [], "emergency_available": "boolean or null" },
  "differentiation": { "unique_selling_points": [], "customer_compliments": [], "guarantees": [], "ideal_customer": "string" },
  "service_area": { "cities": [], "primary_markets": [], "growth_targets": [], "max_travel_radius": "string" },
  "brand_voice": { "personality": "string", "tone": "string", "preferred_phrases": [], "avoid_phrases": [], "voice_description": "string" },
  "credentials": { "licenses": [], "insured": "boolean", "bonded": "boolean", "associations": [], "awards": [] },
  "goals": { "website_goals": [], "six_month_success": "string", "additional_notes": "string" }
}`;

    const geminiRes = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${geminiKey}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { temperature: 0.2, maxOutputTokens: 4096, thinkingConfig: { thinkingBudget: 0 } } }),
      signal: AbortSignal.timeout(90_000),
    });
    incrApiStat('gemini');

    const geminiData = await geminiRes.json();
    if (!geminiRes.ok) return res.status(502).json({ error: `Gemini error: ${geminiData.error?.message}` });

    const rawText = geminiData.candidates?.[0]?.content?.parts?.filter(p => p.text).pop()?.text || '';
    const cleaned = rawText.replace(/^```json?\s*/i, '').replace(/```\s*$/, '').trim();
    let profile;
    try { profile = JSON.parse(cleaned); } catch {
      const jsonMatch = cleaned.match(/\{[\s\S]*\}/);
      if (jsonMatch) try { profile = JSON.parse(jsonMatch[0]); } catch {}
    }
    if (!profile) return res.status(502).json({ error: 'Failed to parse extracted profile' });

    // Save to session and launch doc
    await db.collection('onboarding_interviews').doc(req.params.id).update({
      extracted_profile: profile,
      status: 'extracted',
      completed_at: FieldValue.serverTimestamp(),
      meet_transcript_file: files[0].name,
    });

    if (session.client_id) {
      await db.collection('launches').doc(session.client_id).update({
        onboarding_profile: profile,
        onboarding_completed_at: FieldValue.serverTimestamp(),
      }).catch(e => console.error('Failed to save Meet transcript profile to launch:', e.message));

      pushOnboardingToDrive(session.client_id, clientName, profile, transcript).catch(() => {});
    }

    res.json({ profile, source: files[0].name });
  } catch (err) {
    console.error('[meet-transcript] import error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── Pages ──
app.get('/edit-request', (_req, res) => res.sendFile(join(__dirname, 'public', 'edit-request.html')));
app.get('/bulk-blog', requireAuth, (_req, res) => res.sendFile(join(__dirname, 'public', 'bulk-blog.html')));
app.get('/onboarding', requireAuth, (_req, res) => res.sendFile(join(__dirname, 'public', 'onboarding.html')));
app.get('/dashboard', requireAuth, (_req, res) => res.sendFile(join(__dirname, 'public', 'dashboard.html')));

// ── HTTP server + WebSocket for live transcription ──
const server = createServer(app);

let speechClient = null;
try {
  speechClient = new speech.SpeechClient();
  console.log('[speech] Speech-to-Text client initialized');
} catch (e) {
  console.error('[speech] Failed to initialize Speech-to-Text client:', e.message);
}

const wss = new WebSocketServer({ server, path: '/ws/transcribe' });

async function validateToken(token) {
  if (!token) return null;
  const cached = sessionCache.get(token);
  if (cached && cached.expiry > Date.now()) return cached.email;
  try {
    const session = await db.collection('sessions').doc(token).get();
    if (!session.exists) { sessionCache.delete(token); return null; }
    const email = session.data().email || '';
    sessionCache.set(token, { expiry: Date.now() + 300_000, email });
    return email;
  } catch { return null; }
}

function createRecognizeStream(ws) {
  if (!speechClient) throw new Error('Speech-to-Text client not available');
  const recognizeStream = speechClient.streamingRecognize({
    config: {
      encoding: 'LINEAR16',
      sampleRateHertz: 16000,
      languageCode: 'en-US',
      enableAutomaticPunctuation: true,
      model: 'latest_long',
    },
    interimResults: true,
  });

  recognizeStream.on('data', (data) => {
    const result = data.results[0];
    if (result && ws.readyState === 1) {
      ws.send(JSON.stringify({
        type: 'transcript',
        text: result.alternatives[0].transcript,
        isFinal: result.isFinal,
      }));
    }
  });

  recognizeStream.on('error', (err) => {
    console.error('Speech-to-Text stream error:', err.message);
    if (ws.readyState === 1) {
      ws.send(JSON.stringify({ type: 'error', message: 'Transcription stream error' }));
    }
  });

  return recognizeStream;
}

wss.on('connection', (ws) => {
  let authenticated = false;
  let recognizeStream = null;
  let restartTimer = null;

  function scheduleRestart() {
    clearTimeout(restartTimer);
    restartTimer = setTimeout(() => {
      if (ws.readyState === 1) {
        try { recognizeStream.end(); } catch {}
        recognizeStream = createRecognizeStream(ws);
        if (ws.readyState === 1) {
          ws.send(JSON.stringify({ type: 'info', message: 'Stream restarted (time limit)' }));
        }
        scheduleRestart();
      }
    }, 270_000); // 4.5 minutes
  }

  function startStream() {
    if (recognizeStream) {
      try { recognizeStream.end(); } catch {}
    }
    try {
      recognizeStream = createRecognizeStream(ws);
      scheduleRestart();
      console.log('[ws] Speech-to-Text stream started');
    } catch (e) {
      console.error('[ws] Failed to create Speech-to-Text stream:', e.message);
      if (ws.readyState === 1) ws.send(JSON.stringify({ type: 'error', message: 'Speech-to-Text failed: ' + e.message }));
    }
  }

  const authTimeout = setTimeout(() => {
    if (!authenticated && ws.readyState === 1) {
      ws.send(JSON.stringify({ type: 'error', message: 'Auth timeout' }));
      ws.close();
    }
  }, 10_000);

  ws.on('message', async (data) => {
    // Binary audio data
    if (data instanceof Buffer && authenticated) {
      if (recognizeStream) {
        try { recognizeStream.write(data); } catch (e) {
          console.error('[ws] Write to Speech-to-Text failed:', e.message);
        }
      }
      return;
    }

    // JSON control messages
    try {
      const msg = JSON.parse(data.toString());
      if (msg.type === 'auth' && !authenticated) {
        const email = await validateToken(msg.token);
        if (!email) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid token' }));
          ws.close();
          return;
        }
        authenticated = true;
        clearTimeout(authTimeout);
        ws.send(JSON.stringify({ type: 'auth_ok' }));
        startStream();
      }
    } catch {}
  });

  ws.on('close', (code, reason) => {
    console.log(`[ws] Connection closed (code: ${code}, reason: ${reason || 'none'})`);
    clearTimeout(restartTimer);
    clearTimeout(authTimeout);
    if (recognizeStream) {
      try { recognizeStream.end(); } catch {}
    }
  });

  ws.on('error', (err) => {
    console.error('[ws] WebSocket error:', err.message);
  });

  ws.on('error', () => {
    clearTimeout(restartTimer);
    clearTimeout(authTimeout);
    if (recognizeStream) {
      try { recognizeStream.end(); } catch {}
    }
  });
});

// ── Meet audio capture popup route ──
app.get('/meet-addon-capture', (req, res) => {
  res.setHeader('Content-Security-Policy', "frame-ancestors 'self'");
  res.sendFile(join(__dirname, 'public', 'meet-addon-capture.html'));
});

server.listen(PORT, () => {
  console.log(`\n  Site Launch Tracker running at http://localhost:${PORT}`);
  console.log(`  Dashboard:              http://localhost:${PORT}/dashboard\n`);
});
