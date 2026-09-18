const { DatabaseSync } = require('node:sqlite');
const bcrypt = require('bcryptjs');
const path = require('path');
require('dotenv').config();

// DB_PATH lets you point the database file at a mounted persistent volume
// instead of the app's own folder (which may be wiped on redeploy).
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'app.db');
const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA journal_mode = WAL;');

// ---------- SCHEMA ----------
// Deliberately minimal: just users, deposits, and withdrawals.
// No referral / sponsor / genealogy / level-income fields at all.
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_code TEXT UNIQUE,                 -- public-facing ID / username, e.g. SFS00001
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  phone TEXT,
  password TEXT NOT NULL,
  role TEXT DEFAULT 'user',              -- 'user' | 'admin'
  wallet_balance REAL DEFAULT 0,
  usdt_bep20_address TEXT,               -- user's own USDT (BEP20) address, used for withdrawals
  status TEXT DEFAULT 'active',          -- active | blocked
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS deposits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  amount REAL NOT NULL,
  method TEXT DEFAULT 'USDT (BEP20)',
  txn_ref TEXT,                          -- transaction hash
  status TEXT DEFAULT 'pending',         -- pending | approved | rejected
  remarks TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  processed_at TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS withdrawals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  amount REAL NOT NULL,
  method TEXT DEFAULT 'USDT (BEP20)',
  to_address TEXT NOT NULL,              -- snapshot of the user's saved USDT BEP20 address at request time
  status TEXT DEFAULT 'pending',         -- submitted | approved | processed | rejected (legacy: pending)
  remarks TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  processed_at TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT
);

-- Records each bulk % Income Wallet credit applied to a given deposit for a
-- given month, so re-running the bulk processor never double-credits the
-- same deposit for the same month.
CREATE TABLE IF NOT EXISTS bonus_credits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  deposit_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  month TEXT NOT NULL,             -- 'YYYY-MM' this credit was applied for
  percentage REAL NOT NULL,        -- base % the admin entered
  rate_applied REAL NOT NULL,      -- actual % applied (full or half, by deposit day rule)
  amount REAL NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (deposit_id) REFERENCES deposits(id),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Notifications sent by admins. user_id NULL = broadcast to all users.
CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Per-user read tracking, so a single broadcast row can be read/unread
-- independently for every recipient.
CREATE TABLE IF NOT EXISTS notification_reads (
  notification_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  read_at TEXT DEFAULT (datetime('now')),
  PRIMARY KEY (notification_id, user_id)
);

-- Support ticket threads between a user and admins.
CREATE TABLE IF NOT EXISTS support_tickets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  subject TEXT NOT NULL,
  status TEXT DEFAULT 'open',      -- open | resolved
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);


-- OTP tokens for 2FA (forgot-password, wallet address change, password change, withdrawals)
CREATE TABLE IF NOT EXISTS otp_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  purpose TEXT NOT NULL,   -- 'forgot_password' | 'wallet_address' | 'password_change' | 'withdrawal'
  code TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS support_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ticket_id INTEGER NOT NULL,
  sender_role TEXT NOT NULL,       -- 'user' | 'admin'
  message TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (ticket_id) REFERENCES support_tickets(id)
);
`);

// ---------- MIGRATIONS (safe to run on every boot) ----------
function columnExists(table, col) {
  return db.prepare(`PRAGMA table_info(${table})`).all().some(c => c.name === col);
}
function addColumnIfMissing(table, colName, colDef) {
  if (!columnExists(table, colName)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${colDef}`);
  }
}

// Split the old single wallet_balance into a Principal Wallet (funded by
// approved deposits) and an Income Wallet (funded by admin balance
// adjustments / future income features).
addColumnIfMissing('users', 'principal_wallet', 'principal_wallet REAL DEFAULT 0');
addColumnIfMissing('users', 'income_wallet', 'income_wallet REAL DEFAULT 0');

// Tracks how much of a given deposit's principal has already been
// withdrawn/reserved, so each deposit's 18th/36th-month maturity window
// can be checked independently.
addColumnIfMissing('deposits', 'principal_withdrawn', 'principal_withdrawn REAL DEFAULT 0');

// Which wallet a withdrawal draws from, plus bookkeeping for the
// Submitted -> Approved -> Processed status flow.
addColumnIfMissing('withdrawals', 'wallet_type', "wallet_type TEXT DEFAULT 'principal'");
addColumnIfMissing('withdrawals', 'approved_at', 'approved_at TEXT');
addColumnIfMissing('withdrawals', 'source_breakdown', 'source_breakdown TEXT'); // JSON: which deposit lots a principal withdrawal drew from

// One-time backfill: move any pre-existing wallet_balance into the
// Principal Wallet (that balance came from approved deposits historically).
db.exec(`
  UPDATE users SET principal_wallet = wallet_balance
  WHERE principal_wallet = 0 AND income_wallet = 0 AND wallet_balance > 0
`);

// Rename the old legacy status naming to the current one.
db.exec(`UPDATE withdrawals SET status = 'submitted' WHERE status = 'pending'`);

// Seed the platform deposit address setting from .env on first boot only;
// after that it's managed from the Admin > Settings page.
(function ensureDepositAddressSetting() {
  const existing = db.prepare("SELECT value FROM settings WHERE key = 'deposit_address'").get();
  if (!existing) {
    const addr = process.env.ADMIN_USDT_BEP20_ADDRESS || '';
    db.prepare("INSERT INTO settings (key, value) VALUES ('deposit_address', ?)").run(addr);
  }
})();


// Password reset token for forgot-password flow
addColumnIfMissing('users', 'reset_token', 'reset_token TEXT');
addColumnIfMissing('users', 'reset_token_expires', 'reset_token_expires TEXT');

// ---------- HELPERS ----------
function nextUserCode() {
  const row = db.prepare("SELECT COUNT(*) AS c FROM users").get();
  const n = (row.c || 0) + 1;
  // Public-facing user ID / username, e.g. SFS00001, SFS00002, ...
  return 'SFS' + String(n).padStart(5, '0');
}

// ---------- SEED FIRST ADMIN ----------
function ensureAdmin() {
  const email = (process.env.ADMIN_EMAIL || 'admin@example.com').toLowerCase();
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) return;
  const password = process.env.ADMIN_PASSWORD || 'Admin@123';
  const hash = bcrypt.hashSync(password, 10);
  const code = nextUserCode();
  db.prepare(
    `INSERT INTO users (user_code, name, email, password, role, status)
     VALUES (?, ?, ?, ?, 'admin', 'active')`
  ).run(code, 'Administrator', email, hash);
  console.log(`Seeded admin account -> email: ${email} / password: ${password}`);
}
ensureAdmin();

module.exports = db;

// ── TOTP migration: add totp_secret column if missing ──
try {
  db.exec("ALTER TABLE users ADD COLUMN totp_secret TEXT DEFAULT NULL");
} catch (_) { /* column already exists */ }

module.exports.nextUserCode = nextUserCode;
