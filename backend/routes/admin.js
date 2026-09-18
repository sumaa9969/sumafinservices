const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('../db');
const { authRequired, adminRequired } = require('../middleware/auth');
const { sanitizeName, sanitizeText } = require('../utils/sanitize');
const { releasePrincipal, bonusRateForDay, monthKey, toDate } = require('../utils/walletRules');

const router = express.Router();
router.use(authRequired, adminRequired);

const BEP20_ADDRESS_REGEX = /^0x[a-fA-F0-9]{40}$/;

// ---------- DASHBOARD SUMMARY ----------
router.get('/summary', (req, res) => {
  const totalUsers = db.prepare("SELECT COUNT(*) AS c FROM users WHERE role = 'user'").get().c;
  const totalDeposited = db.prepare("SELECT COALESCE(SUM(amount),0) AS t FROM deposits WHERE status='approved'").get().t;
  const totalWithdrawn = db.prepare("SELECT COALESCE(SUM(amount),0) AS t FROM withdrawals WHERE status='processed'").get().t;
  const pendingDeposits = db.prepare("SELECT COUNT(*) AS c FROM deposits WHERE status='pending'").get().c;
  const pendingWithdrawals = db.prepare("SELECT COUNT(*) AS c FROM withdrawals WHERE status IN ('submitted','approved')").get().c;

  res.json({ totalUsers, totalDeposited, totalWithdrawn, pendingDeposits, pendingWithdrawals });
});

// ---------- PLATFORM SETTINGS ----------
router.get('/settings', (req, res) => {
  const row = db.prepare("SELECT value FROM settings WHERE key = 'deposit_address'").get();
  const lockRow = db.prepare("SELECT value FROM settings WHERE key = 'withdrawal_lock_bypass'").get();
  const monthsRow = db.prepare("SELECT value FROM settings WHERE key = 'withdrawal_months'").get();
  res.json({
    deposit_address: (row && row.value) || '',
    withdrawal_lock_bypass: !!lockRow && lockRow.value === 'true',
    withdrawal_months: (monthsRow && monthsRow.value) || '18,36'
  });
});

// Update the platform's USDT (BEP20) deposit address shown on the user
// Deposit page.
router.put('/settings/deposit-address', (req, res) => {
  let { address } = req.body;
  address = sanitizeText(address, 100);
  if (!address || !BEP20_ADDRESS_REGEX.test(address)) {
    return res.status(400).json({ error: 'Enter a valid USDT (BEP20) address (starts with 0x, 42 characters)' });
  }
  db.prepare(
    `INSERT INTO settings (key, value) VALUES ('deposit_address', ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value`
  ).run(address);
  res.json({ message: 'Deposit address updated', deposit_address: address });
});

// Update the withdrawal eligibility windows (months after deposit approval at
// which principal becomes withdrawable). Stored as a comma-separated list,
// e.g. "18,36" (original default), "1" (monthly), "3,6" (quarterly + semi).
// Each value must be a positive integer; up to 10 windows are accepted.
router.put('/settings/withdrawal-months', (req, res) => {
  const raw = sanitizeText(String(req.body.months || ''), 100);
  const parsed = raw.split(',')
    .map(s => parseInt(s.trim(), 10))
    .filter(n => Number.isFinite(n) && n > 0)
    .sort((a, b) => a - b);

  if (parsed.length === 0) {
    return res.status(400).json({ error: 'Enter at least one valid month number (e.g. 18 or 18,36)' });
  }
  if (parsed.length > 10) {
    return res.status(400).json({ error: 'Maximum 10 withdrawal windows allowed' });
  }

  const value = parsed.join(',');
  db.prepare(
    `INSERT INTO settings (key, value) VALUES ('withdrawal_months', ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value`
  ).run(value);

  res.json({
    message: `Withdrawal windows set to: ${parsed.map(m => m + ' month' + (m === 1 ? '' : 's')).join(', ')}`,
    withdrawal_months: value
  });
});

// Toggle testing mode: when on, the configured Principal windows and the
// last-day-of-month Income rule are bypassed for every user, so withdrawals
// can be submitted and approved end-to-end at any time. Meant to be turned
// back off once testing is done - it applies platform-wide, not per user.
router.put('/settings/withdrawal-lock-bypass', (req, res) => {
  const enabled = req.body.enabled === true;
  db.prepare(
    `INSERT INTO settings (key, value) VALUES ('withdrawal_lock_bypass', ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value`
  ).run(enabled ? 'true' : 'false');
  res.json({ message: enabled ? 'Withdrawal lock bypass enabled' : 'Withdrawal lock bypass disabled', withdrawal_lock_bypass: enabled });
});

// ---------- USERS ----------
router.get('/users', (req, res) => {
  const rows = db.prepare(
    `SELECT id, user_code, name, email, phone, role, status, principal_wallet, income_wallet, created_at
     FROM users ORDER BY id DESC`
  ).all();
  res.json({ users: rows });
});

router.get('/users/:id', (req, res) => {
  const user = db.prepare(
    `SELECT id, user_code, name, email, phone, role, status, principal_wallet, income_wallet, created_at
     FROM users WHERE id = ?`
  ).get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const deposits = db.prepare('SELECT * FROM deposits WHERE user_id = ? ORDER BY id DESC').all(user.id);
  const withdrawals = db.prepare('SELECT * FROM withdrawals WHERE user_id = ? ORDER BY id DESC').all(user.id);

  res.json({ user, deposits, withdrawals });
});

// Block / unblock a user
router.patch('/users/:id/status', (req, res) => {
  const { status } = req.body;
  if (!['active', 'blocked'].includes(status)) {
    return res.status(400).json({ error: "Status must be 'active' or 'blocked'" });
  }
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.role === 'admin') return res.status(400).json({ error: 'Cannot change status of an admin account' });

  db.prepare('UPDATE users SET status = ? WHERE id = ?').run(status, user.id);
  res.json({ message: `User ${status}` });
});

// Reset a user's login password (admin utility — no current-password check).
router.post('/users/:id/reset-password', (req, res) => {
  let { newPassword } = req.body;
  if (!newPassword || String(newPassword).length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters' });
  }
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.role === 'admin') return res.status(400).json({ error: 'Cannot reset the password of an admin account here' });

  const hash = bcrypt.hashSync(String(newPassword), 10);
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hash, user.id);
  res.json({ message: `Password reset for ${user.name} (${user.user_code})` });
});

// ---------- BULK INCOME % ADJUSTMENT ----------
// Replaces per-user manual balance adjustment. Admin enters one percentage
// and it is applied across ALL users' approved deposits at once:
//   - deposit approved on day 1-15 of the month  -> FULL percentage
//   - deposit approved on day 16-end of the month -> HALF percentage
// Each deposit can only be credited once per calendar month (tracked in
// bonus_credits), so running this again for the same month is a no-op for
// deposits already processed.
function computeBulkPlan(percentage, month) {
  const [y, m] = month.split('-').map(Number);
  const deposits = db.prepare(
    `SELECT d.*, u.name AS user_name, u.user_code
     FROM deposits d JOIN users u ON u.id = d.user_id
     WHERE d.status = 'approved'`
  ).all();

  const already = new Set(
    db.prepare('SELECT deposit_id FROM bonus_credits WHERE month = ?').all(month).map(r => r.deposit_id)
  );

  const plan = [];
  for (const d of deposits) {
    if (already.has(d.id)) continue;
    const approvedAt = toDate(d.processed_at || d.created_at);
    if (approvedAt.getFullYear() !== y || approvedAt.getMonth() + 1 !== m) continue;

    const rate = bonusRateForDay(approvedAt.getDate(), percentage);
    const amount = Math.round((d.amount * rate / 100) * 100) / 100;
    if (amount <= 0) continue;

    plan.push({
      deposit_id: d.id,
      user_id: d.user_id,
      user_name: d.user_name,
      user_code: d.user_code,
      deposit_amount: d.amount,
      deposit_day: approvedAt.getDate(),
      rate_applied: rate,
      credit_amount: amount
    });
  }
  return plan;
}

// Preview only — no writes. ?percentage=5&month=2026-09 (month optional,
// defaults to current month).
router.get('/bulk-adjustment/preview', (req, res) => {
  const percentage = Number(req.query.percentage);
  const month = sanitizeText(req.query.month, 7) || monthKey(new Date());
  if (!percentage || percentage <= 0) {
    return res.status(400).json({ error: 'Enter a percentage greater than 0' });
  }
  if (!/^\d{4}-\d{2}$/.test(month)) {
    return res.status(400).json({ error: 'Month must be in YYYY-MM format' });
  }

  const plan = computeBulkPlan(percentage, month);
  const totalCredit = plan.reduce((sum, p) => sum + p.credit_amount, 0);
  res.json({ month, percentage, deposits_affected: plan.length, total_credit: totalCredit, plan });
});

// Apply the bulk % credit for real.
router.post('/bulk-adjustment/apply', (req, res) => {
  let { percentage, month } = req.body;
  percentage = Number(percentage);
  month = sanitizeText(month, 7) || monthKey(new Date());
  if (!percentage || percentage <= 0) {
    return res.status(400).json({ error: 'Enter a percentage greater than 0' });
  }
  if (!/^\d{4}-\d{2}$/.test(month)) {
    return res.status(400).json({ error: 'Month must be in YYYY-MM format' });
  }

  const plan = computeBulkPlan(percentage, month);
  const creditStmt = db.prepare('UPDATE users SET income_wallet = income_wallet + ? WHERE id = ?');
  const logStmt = db.prepare(
    `INSERT INTO bonus_credits (deposit_id, user_id, month, percentage, rate_applied, amount)
     VALUES (?, ?, ?, ?, ?, ?)`
  );

  let totalCredit = 0;
  for (const p of plan) {
    creditStmt.run(p.credit_amount, p.user_id);
    logStmt.run(p.deposit_id, p.user_id, month, percentage, p.rate_applied, p.credit_amount);
    totalCredit += p.credit_amount;
  }

  res.json({
    message: `Applied ${percentage}% bulk Income Wallet credit for ${month}`,
    month,
    percentage,
    deposits_credited: plan.length,
    total_credit: totalCredit
  });
});

// History of past bulk runs, grouped by month + percentage batch.
router.get('/bulk-adjustment/history', (req, res) => {
  const rows = db.prepare(
    `SELECT month, percentage, COUNT(*) AS deposits_credited, SUM(amount) AS total_credit, MAX(created_at) AS applied_at
     FROM bonus_credits GROUP BY month, percentage, DATE(created_at) ORDER BY applied_at DESC`
  ).all();
  res.json({ history: rows });
});

// Create a new admin account (root-style utility)
router.post('/users/create-admin', (req, res) => {
  let { name, email, password } = req.body;
  name = sanitizeName(name);
  email = sanitizeText(email, 150).toLowerCase();
  if (!name || !email || !password || password.length < 6) {
    return res.status(400).json({ error: 'Name, email and a password of 6+ characters are required' });
  }
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) return res.status(409).json({ error: 'Email already in use' });

  const hash = bcrypt.hashSync(password, 10);
  const code = db.nextUserCode();
  db.prepare(
    `INSERT INTO users (user_code, name, email, password, role, status)
     VALUES (?, ?, ?, ?, 'admin', 'active')`
  ).run(code, name, email, hash);

  res.status(201).json({ message: 'Admin account created' });
});

// ---------- DEPOSITS ----------
router.get('/deposits', (req, res) => {
  const status = req.query.status;
  const rows = status
    ? db.prepare(
        `SELECT d.*, u.name AS user_name, u.email AS user_email, u.user_code
         FROM deposits d JOIN users u ON u.id = d.user_id
         WHERE d.status = ? ORDER BY d.id DESC`
      ).all(status)
    : db.prepare(
        `SELECT d.*, u.name AS user_name, u.email AS user_email, u.user_code
         FROM deposits d JOIN users u ON u.id = d.user_id
         ORDER BY d.id DESC`
      ).all();
  res.json({ deposits: rows });
});

router.patch('/deposits/:id', (req, res) => {
  const { action, remarks } = req.body; // action: 'approve' | 'reject'
  if (!['approve', 'reject'].includes(action)) {
    return res.status(400).json({ error: "Action must be 'approve' or 'reject'" });
  }

  const deposit = db.prepare('SELECT * FROM deposits WHERE id = ?').get(req.params.id);
  if (!deposit) return res.status(404).json({ error: 'Deposit not found' });
  if (deposit.status !== 'pending') return res.status(400).json({ error: 'Deposit already processed' });

  if (action === 'approve') {
    // Approved deposits fund the Principal Wallet; their approval
    // timestamp (processed_at, set below) is the anchor for that deposit's
    // 18th/36th-month principal-withdrawal maturity windows.
    db.prepare('UPDATE users SET principal_wallet = principal_wallet + ? WHERE id = ?').run(deposit.amount, deposit.user_id);
  }

  db.prepare(
    `UPDATE deposits SET status = ?, remarks = ?, processed_at = datetime('now') WHERE id = ?`
  ).run(action === 'approve' ? 'approved' : 'rejected', sanitizeText(remarks, 255) || null, deposit.id);

  res.json({ message: `Deposit ${action === 'approve' ? 'approved' : 'rejected'}` });
});

// ---------- WITHDRAWALS ----------
router.get('/withdrawals', (req, res) => {
  const status = req.query.status;
  const rows = status
    ? db.prepare(
        `SELECT w.*, u.name AS user_name, u.email AS user_email, u.user_code
         FROM withdrawals w JOIN users u ON u.id = w.user_id
         WHERE w.status = ? ORDER BY w.id DESC`
      ).all(status)
    : db.prepare(
        `SELECT w.*, u.name AS user_name, u.email AS user_email, u.user_code
         FROM withdrawals w JOIN users u ON u.id = w.user_id
         ORDER BY w.id DESC`
      ).all();
  res.json({ withdrawals: rows });
});

// action: 'approve' | 'process' | 'reject'.
//   submitted -> approve  -> approved   (admin has verified the request; funds
//                                         stay reserved, nothing sent yet)
//   approved  -> process  -> processed  (admin has actually sent the funds)
//   submitted or approved -> reject -> rejected (refunds the wallet and, for
//                                         principal withdrawals, releases the
//                                         reserved amount back onto its
//                                         source deposit(s))
// Funds were already deducted/reserved from the relevant wallet when the
// request was submitted, so approve/process never touch the wallet balance.
router.patch('/withdrawals/:id', (req, res) => {
  const { action, remarks } = req.body;
  if (!['approve', 'process', 'reject'].includes(action)) {
    return res.status(400).json({ error: "Action must be 'approve', 'process' or 'reject'" });
  }

  const withdrawal = db.prepare('SELECT * FROM withdrawals WHERE id = ?').get(req.params.id);
  if (!withdrawal) return res.status(404).json({ error: 'Withdrawal not found' });

  if (action === 'approve' && withdrawal.status !== 'submitted') {
    return res.status(400).json({ error: 'Only submitted withdrawals can be approved' });
  }
  if (action === 'process' && withdrawal.status !== 'approved') {
    return res.status(400).json({ error: 'Only approved withdrawals can be marked processed' });
  }
  if (action === 'reject' && !['submitted', 'approved'].includes(withdrawal.status)) {
    return res.status(400).json({ error: 'Only submitted or approved withdrawals can be rejected' });
  }

  const nowClause = `datetime('now')`;

  if (action === 'approve') {
    db.prepare(
      `UPDATE withdrawals SET status = 'approved', remarks = ?, approved_at = ${nowClause} WHERE id = ?`
    ).run(sanitizeText(remarks, 255) || null, withdrawal.id);
    return res.json({ message: 'Withdrawal approved' });
  }

  if (action === 'process') {
    db.prepare(
      `UPDATE withdrawals SET status = 'processed', remarks = ?, processed_at = ${nowClause} WHERE id = ?`
    ).run(sanitizeText(remarks, 255) || null, withdrawal.id);
    return res.json({ message: 'Withdrawal marked processed' });
  }

  // action === 'reject'
  const walletCol = withdrawal.wallet_type === 'income' ? 'income_wallet' : 'principal_wallet';
  db.prepare(`UPDATE users SET ${walletCol} = ${walletCol} + ? WHERE id = ?`).run(withdrawal.amount, withdrawal.user_id);

  if (withdrawal.wallet_type === 'principal' && withdrawal.source_breakdown) {
    try {
      releasePrincipal(db, JSON.parse(withdrawal.source_breakdown));
    } catch (e) {
      console.error('Failed to parse/release source_breakdown for withdrawal', withdrawal.id, e);
    }
  }

  db.prepare(
    `UPDATE withdrawals SET status = 'rejected', remarks = ?, processed_at = ${nowClause} WHERE id = ?`
  ).run(sanitizeText(remarks, 255) || null, withdrawal.id);

  res.json({ message: 'Withdrawal rejected' });
});

// ---------- NOTIFICATIONS ----------
// List everything sent so far (broadcasts show once with target = 'All users').
router.get('/notifications', (req, res) => {
  const rows = db.prepare(
    `SELECT n.*, u.name AS user_name, u.user_code
     FROM notifications n LEFT JOIN users u ON u.id = n.user_id
     ORDER BY n.id DESC`
  ).all();
  res.json({ notifications: rows });
});

// Send a notification. Omit user_id (or pass null) to broadcast to every
// user; pass a user_id to target one specific user.
router.post('/notifications', (req, res) => {
  let { title, message, user_id } = req.body;
  title = sanitizeText(title, 150);
  message = sanitizeText(message, 1000);
  if (!title || !message) return res.status(400).json({ error: 'Title and message are required' });

  let targetId = null;
  if (user_id !== undefined && user_id !== null && user_id !== '') {
    const user = db.prepare('SELECT id FROM users WHERE id = ? AND role = ?').get(user_id, 'user');
    if (!user) return res.status(404).json({ error: 'User not found' });
    targetId = user.id;
  }

  const info = db.prepare(
    'INSERT INTO notifications (user_id, title, message) VALUES (?, ?, ?)'
  ).run(targetId, title, message);

  res.status(201).json({ message: 'Notification sent', notification_id: info.lastInsertRowid });
});

// ---------- SUPPORT ----------
router.get('/support', (req, res) => {
  const status = req.query.status;
  const rows = status
    ? db.prepare(
        `SELECT t.*, u.name AS user_name, u.email AS user_email, u.user_code
         FROM support_tickets t JOIN users u ON u.id = t.user_id
         WHERE t.status = ? ORDER BY t.updated_at DESC`
      ).all(status)
    : db.prepare(
        `SELECT t.*, u.name AS user_name, u.email AS user_email, u.user_code
         FROM support_tickets t JOIN users u ON u.id = t.user_id
         ORDER BY t.updated_at DESC`
      ).all();
  res.json({ tickets: rows });
});

router.get('/support/:id', (req, res) => {
  const ticket = db.prepare(
    `SELECT t.*, u.name AS user_name, u.email AS user_email, u.user_code
     FROM support_tickets t JOIN users u ON u.id = t.user_id WHERE t.id = ?`
  ).get(req.params.id);
  if (!ticket) return res.status(404).json({ error: 'Ticket not found' });

  const messages = db.prepare('SELECT * FROM support_messages WHERE ticket_id = ? ORDER BY id ASC').all(ticket.id);
  res.json({ ticket, messages });
});

router.post('/support/:id/reply', (req, res) => {
  const message = sanitizeText(req.body.message, 2000);
  if (!message) return res.status(400).json({ error: 'Message is required' });

  const ticket = db.prepare('SELECT * FROM support_tickets WHERE id = ?').get(req.params.id);
  if (!ticket) return res.status(404).json({ error: 'Ticket not found' });

  db.prepare(
    `INSERT INTO support_messages (ticket_id, sender_role, message) VALUES (?, 'admin', ?)`
  ).run(ticket.id, message);
  db.prepare(`UPDATE support_tickets SET updated_at = datetime('now') WHERE id = ?`).run(ticket.id);

  res.status(201).json({ message: 'Reply sent' });
});

router.patch('/support/:id/status', (req, res) => {
  const { status } = req.body;
  if (!['open', 'resolved'].includes(status)) {
    return res.status(400).json({ error: "Status must be 'open' or 'resolved'" });
  }
  const ticket = db.prepare('SELECT * FROM support_tickets WHERE id = ?').get(req.params.id);
  if (!ticket) return res.status(404).json({ error: 'Ticket not found' });

  db.prepare(`UPDATE support_tickets SET status = ?, updated_at = datetime('now') WHERE id = ?`).run(status, ticket.id);
  res.json({ message: `Ticket marked ${status}` });
});

module.exports = router;
