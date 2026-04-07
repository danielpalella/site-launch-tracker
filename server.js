import express from 'express';
import multer from 'multer';
import { randomUUID } from 'crypto';
import { google } from 'googleapis';
import { getStorage } from 'firebase-admin/storage';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
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
  const { auth_token } = getCookies(req);
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
    custom_favicon:       d.custom_favicon        || null,
    tags:                 d.tags                  || [],
    last_contact_date:    d.last_contact_date     || null,
    outreach_log:         d.outreach_log          || [],
  };
}

app.use(express.json());
// ── Auth (public) ──
app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ email: req.userEmail || '' });
});

app.get('/login', (_req, res) => res.sendFile(join(__dirname, 'public', 'login.html')));
app.get('/', requireAuth, (_req, res) => res.sendFile(join(__dirname, 'public', 'index.html')));

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
      `auth_token=${token}; Path=/; HttpOnly; SameSite=Lax`,
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
    if (cms.flag === 'orange') warnings.push(`Built on ${cms.name} — complex platform`);
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
    if (sitemap) {
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
  const r = await fetch('https://oauth2.googleapis.com/token', {
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
  if (!data.access_token) throw new Error('Failed to refresh analytics token');
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
    const r = await fetch(
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
    } catch { /* try next */ }
  }
  if (!siteUrl) return { available: false };

  const topData = await querySC(siteUrl, { startDate, endDate, dimensions: ['query'], rowLimit: 25 })
    .catch(() => ({ rows: [] }));

  const weekMap = {};
  let clicks = 0, impressions = 0, posWSum = 0, posWImps = 0;
  for (const row of rows) {
    const d = new Date(row.keys[0]);
    d.setDate(d.getDate() - d.getDay());
    const wk = isoDate(d);
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

async function fetchGA4(propertyId, launchDate, token) {
  const property = `properties/${propertyId}`;
  const startDate = isoDate(new Date(launchDate));

  async function runReport(body) {
    incrApiStat('ga4');
    const r = await fetch(
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

  const weekMap = {};
  let sessions = 0, users = 0, newUsers = 0, engSum = 0, engCount = 0;
  for (const row of dailyData.rows || []) {
    const raw = row.dimensionValues[0].value;
    const d = new Date(`${raw.slice(0,4)}-${raw.slice(4,6)}-${raw.slice(6,8)}`);
    d.setDate(d.getDate() - d.getDay());
    const wk = isoDate(d);
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
    fetch(`${base}/analytics/site/${siteName}${dateParams}&result=traffic`,     { headers }),
    fetch(`${base}/analytics/site/${siteName}${dateParams}&result=activities`,  { headers }),
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
    const domain = doc.data().domain_name;
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

    const [eventsRes, trendRes, formDatesRes, formHourlyRes, interactionRes] = await Promise.all([
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
      // Chip/button clicks broken down by which label was clicked
      interactionDetail: (interactionRes.rows || [])
        .filter(r => r.dimensionValues[1].value !== '(not set)')
        .map(r => ({
          event: r.dimensionValues[0].value,
          label: r.dimensionValues[1].value,
          count: parseInt(r.metricValues[0].value),
        })),
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

app.get('/api/launches/:id/hcp-leads', requireAuth, async (req, res) => {
  try {
    const doc = await db.collection('launches').doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    const { hcp_api_key, analytics_start_date, launch_date } = doc.data();
    if (!hcp_api_key) return res.json({ available: false, reason: 'No HCP API key configured' });
    // Filter leads to only those on/after the widget launch date
    const sinceDate = analytics_start_date || launch_date || null;
    const r = await fetch('https://api.housecallpro.com/leads?page_size=100', {
      headers: { Authorization: `Token ${hcp_api_key}`, 'Content-Type': 'application/json' },
    });
    if (!r.ok) return res.status(r.status).json({ error: `HCP API error: ${r.status}` });
    const data = await r.json();
    const leads = (data.leads || [])
      .filter(l => {
        if (!sinceDate || !l.customer?.created_at) return true;
        return l.customer.created_at >= sinceDate;
      })
      .map(l => ({
        id: l.id,
        number: l.number,
        name: `${l.customer?.first_name || ''} ${l.customer?.last_name || ''}`.trim(),
        phone: l.customer?.mobile_number || l.customer?.home_number || null,
        email: l.customer?.email || null,
        lead_source: l.lead_source,
        status: l.pipeline_status || l.status,
        submitted_at: l.customer?.created_at || null,
        description: l.description || l.notes || null,
        address: [l.customer?.street, l.customer?.city, l.customer?.state].filter(Boolean).join(', ') || null,
      }));
    res.json({ available: true, total: leads.length, since: sinceDate, leads });
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
      const fRes = await fetch(`https://api.duda.co/api/sites/multiscreen/get-forms/${launch.duda_site_name}`, {
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
    analytics_note: launch.analytics_note || '',
    duda_site_name: launch.duda_site_name || '',
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

app.get('/api/analytics/:id', requireAuth, async (req, res) => {
  try {
    const data = await fetchAndCacheAnalytics(req.params.id, { force: req.query.force === 'true' });
    // Always serve a fresh analytics_note and tags (not frozen in cache)
    const noteDoc = await db.collection('launches').doc(req.params.id).get();
    const freshNote          = noteDoc.exists ? (noteDoc.data().analytics_note   || '') : '';
    const freshTags          = noteDoc.exists ? (noteDoc.data().tags             || []) : [];
    const freshDudaName      = noteDoc.exists ? (noteDoc.data().duda_site_name  || '') : '';
    const freshFavicon       = noteDoc.exists ? (noteDoc.data().custom_favicon  || null) : null;
    const freshHideFormSubs  = noteDoc.exists ? (noteDoc.data().hideFormSubmits || false) : false;
    res.json({ ...data, analytics_note: freshNote, tags: freshTags, duda_site_name: freshDudaName, custom_favicon: freshFavicon, hideFormSubmits: freshHideFormSubs });
  } catch (err) {
    console.error('Analytics error:', err.message);
    if (err.code === 'not_connected') return res.status(503).json({ error: 'not_connected' });
    logApiError('analytics', err.message || 'Failed to fetch analytics', { id: req.params.id });
    res.status(err.statusCode || 500).json({ error: err.message || 'Failed to fetch analytics' });
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

// ── Pages ──
app.get('/edit-request', (_req, res) => res.sendFile(join(__dirname, 'public', 'edit-request.html')));
app.get('/dashboard', requireAuth, (_req, res) => res.sendFile(join(__dirname, 'public', 'dashboard.html')));

app.listen(PORT, () => {
  console.log(`\n  Site Launch Tracker running at http://localhost:${PORT}`);
  console.log(`  Dashboard:              http://localhost:${PORT}/dashboard\n`);
});
