import { Database } from 'bun:sqlite';
import { join, dirname } from 'path';
import { mkdirSync } from 'fs';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const dataDir = join(__dirname, 'data');
mkdirSync(dataDir, { recursive: true });
const db = new Database(join(dataDir, 'launches.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS launches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    department TEXT NOT NULL,
    account_name TEXT NOT NULL,
    domain_name TEXT NOT NULL,
    contact_name TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'new',
    notes TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    status_changed_at TEXT NOT NULL DEFAULT (datetime('now'))
  )
`);

// Migration: add status_changed_at to existing databases that don't have it
try {
  db.exec(`ALTER TABLE launches ADD COLUMN status_changed_at TEXT`);
} catch {
  // Column already exists — nothing to do
}
// Backfill any rows where it's still null
db.exec(`UPDATE launches SET status_changed_at = updated_at WHERE status_changed_at IS NULL`);

// Migrate old 'pending_review' status to 'new'
db.exec(`UPDATE launches SET status = 'new' WHERE status = 'pending_review'`);

// Migration: add industry column
try {
  db.exec(`ALTER TABLE launches ADD COLUMN industry TEXT NOT NULL DEFAULT ''`);
} catch {
  // Column already exists
}

// Sessions table — persists across restarts
db.exec(`
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )
`);

export default db;
