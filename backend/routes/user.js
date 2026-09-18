const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('../db');
const { authRequired } = require('../middleware/auth');
const { sanitizeText } = require('../utils/sanitize');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const {
  isLastDayOfMonth,
  lastDayOfCurrentMonth,
  getPrincipalEligibility,
  reservePrincipal
} = require('../utils/walletRules');
require('dotenv').config();

const router = express.Router();
router.use(authRequired);

const DEPOSIT_METHOD = 'USDT (BEP20)';

// Deposit sizing rule: a user below $1000 in their Principal Wallet must
// deposit at least $1000 to reach it. Once they're at $1000+, further
// deposits just need to be a multiple of $100 (no fixed minimum beyond that).
const MIN_DEPOSIT = 1000;
const TOPUP_MULTIPLE = 100;
const BEP20_ADDRESS_REGEX = /^0x[a-fA-F0-9]{40}$/;

// ---------- TOTP HELPERS (Google Authenticator) ----------
function verifyTOTP(userId, code) {
  const user = db.prepare('SELECT totp_secret FROM users WHERE id = ?').get(userId);
  if (!user || !user.totp_secret) return false;
  return speakeasy.totp.verify({
    secret: user.totp_secret,
    encoding: 'base32',
    token: String(code).trim(),
    window: 1 // allow ±30s drift
  });
}

// ---------- TOTP ROUTES ----------

// GET /user/totp/status — return whether TOTP is configured; if not, generate a pending secret
router.get('/totp/status', (req, res) => {
  try {
    const user = db.prepare('SELECT totp_secret FROM users WHERE id = ?').get(req.user.id);
    if (user && user.totp_secret) {
      return res.json({ totp_enabled: true });
    }
    // Generate a fresh secret for setup
    const generated = speakeasy.generateSecret({ name: `Suma FIN Services (${req.user.email})`, issuer: 'Suma FIN Services' });
    // Store as pending (will be confirmed on enable)
    // We store it immediately so the QR is stable between refreshes; enable call confirms it
    db.prepare('UPDATE users SET totp_secret = ? WHERE id = ?').run(generated.base32, req.user.id);
    // But mark not-yet-confirmed by returning totp_enabled: false
    // We'll use a separate confirmed flag pattern — simpler: just store the secret after verify
    // Reset for now: don't store yet, return the proposed secret
    db.prepare('UPDATE users SET totp_secret = NULL WHERE id = ?').run(req.user.id);
    res.json({
      totp_enabled: false,
      secret: generated.base32,
      otpauth_url: generated.otpauth_url
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /user/totp/enable — verify the code and save the secret
router.post('/totp/enable', (req, res) => {
  try {
    const { code, secret } = req.body;
    if (!code || !secret) return res.status(400).json({ error: 'Code and secret are required' });

    const valid = speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token: String(code).trim(),
      window: 1
    });
    if (!valid) return res.status(400).json({ error: 'Invalid code — check your authenticator app and try again' });

    db.prepare('UPDATE users SET totp_secret = ? WHERE id = ?').run(secret, req.user.id);
    res.json({ message: 'Google Authenticator enabled successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error enabling 2FA' });
  }
});

// POST /user/totp/disable — verify then remove secret
router.post('/totp/disable', (req, res) => {
  try {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: 'Authenticator code required' });

    if (!verifyTOTP(req.user.id, code)) {
      return res.status(400).json({ error: 'Invalid code — check your authenticator app and try again' });
    }

    db.prepare('UPDATE users SET totp_secret = NULL WHERE id = ?').run(req.user.id);
    res.json({ message: '2FA disabled' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error disabling 2FA' });
  }
});

function currentUser(req) {
  return db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
}

function getDepositAddress() {
  const row = db.prepare("SELECT value FROM settings WHERE key = 'deposit_address'").get();
  return (row && row.value) || process.env.ADMIN_USDT_BEP20_ADDRESS || null;
}

// Admin "testing mode" switch (Admin > Settings) that bypasses the configured
// Principal windows and the last-day-of-month Income rule, so withdrawals can
// be tested end-to-end at any time. Off by default.
function isWithdrawLockBypassed() {
  const row = db.prepare("SELECT value FROM settings WHERE key = 'withdrawal_lock_bypass'").get();
  return !!row && row.value === 'true';
}

// Reads the admin-configured withdrawal windows (months) from settings.
// The setting is stored as a comma-separated string, e.g. "18,36" or "1" or "3,6".
// Falls back to the original [18, 36] if not set or invalid.
function getWithdrawalWindows() {
  const row = db.prepare("SELECT value FROM settings WHERE key = 'withdrawal_months'").get();
  if (!row || !row.value) return [18, 36];
  const parsed = row.value.split(',')
    .map(s => parseInt(s.trim(), 10))
    .filter(n => Number.isFinite(n) && n > 0)
    .sort((a, b) => a - b);
  return parsed.length > 0 ? parsed : [18, 36];
}

// ---------- PROFILE / DASHBOARD SUMMARY ----------
router.get('/me', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const pendingDeposits = db.prepare(
    "SELECT COALESCE(SUM(amount),0) AS total FROM deposits WHERE user_id = ? AND status = 'pending'"
  ).get(user.id).total;

  const pendingPrincipalWithdrawals = db.prepare(
    "SELECT COALESCE(SUM(amount),0) AS total FROM withdrawals WHERE user_id = ? AND status = 'submitted' AND wallet_type = 'principal'"
  ).get(user.id).total;

  const pendingIncomeWithdrawals = db.prepare(
    "SELECT COALESCE(SUM(amount),0) AS total FROM withdrawals WHERE user_id = ? AND status = 'submitted' AND wallet_type = 'income'"
  ).get(user.id).total;

  const now = new Date();
  const bypassLock = isWithdrawLockBypassed();
  const withdrawalWindows = getWithdrawalWindows();
  const principal = getPrincipalEligibility(db, user.id, now, bypassLock, withdrawalWindows);
  const incomeOpenToday = bypassLock || isLastDayOfMonth(now);

  res.json({
    id: user.id,
    userCode: user.user_code,
    name: user.name,
    email: user.email,
    role: user.role,
    status: user.status,
    principal_wallet: user.principal_wallet,
    income_wallet: user.income_wallet,
    usdt_bep20_address: user.usdt_bep20_address,
    pending_deposits: pendingDeposits,
    pending_principal_withdrawals: pendingPrincipalWithdrawals,
    pending_income_withdrawals: pendingIncomeWithdrawals,
    pending_withdrawals: pendingPrincipalWithdrawals + pendingIncomeWithdrawals,
    principal_eligible_now: principal.eligibleNow,
    principal_next_window: principal.nextWindowDate ? principal.nextWindowDate.toISOString() : null,
    income_withdraw_open_today: incomeOpenToday,
    income_next_window: incomeOpenToday ? null : lastDayOfCurrentMonth(now).toISOString(),
    created_at: user.created_at,
    deposit_address: getDepositAddress(),
    deposit_method: DEPOSIT_METHOD,
    withdrawal_lock_bypassed: bypassLock,
    min_deposit: MIN_DEPOSIT,
    deposit_topup_multiple: TOPUP_MULTIPLE
  });
});

// OTP via email removed — replaced by Google Authenticator (TOTP)

// ---------- SAVE / UPDATE WITHDRAWAL ADDRESS (requires 2FA OTP) ----------
router.put('/wallet-address', (req, res) => {
  try {
    let { address, otp } = req.body;
    address = sanitizeText(address, 100);

    if (!address || !BEP20_ADDRESS_REGEX.test(address)) {
      return res.status(400).json({ error: 'Enter a valid USDT (BEP20) address (starts with 0x, 42 characters)' });
    }
    if (!otp) {
      return res.status(400).json({ error: 'Verification code is required' });
    }
    if (!verifyTOTP(req.user.id, otp)) {
      return res.status(400).json({ error: 'Invalid authenticator code' });
    }

    db.prepare('UPDATE users SET usdt_bep20_address = ? WHERE id = ?').run(address, req.user.id);
    res.json({ message: 'Withdrawal address saved', usdt_bep20_address: address });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error saving address' });
  }
});

// ---------- CHANGE PASSWORD (requires 2FA OTP) ----------
router.put('/password', (req, res) => {
  try {
    const { currentPassword, newPassword, confirmNewPassword, otp } = req.body;
    const user = currentUser(req);
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current and new password are required' });
    }
    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'New password must be at least 6 characters' });
    }
    if (confirmNewPassword !== undefined && confirmNewPassword !== newPassword) {
      return res.status(400).json({ error: 'New passwords do not match' });
    }

    const valid = bcrypt.compareSync(currentPassword, user.password);
    if (!valid) return res.status(401).json({ error: 'Current password is incorrect' });

    if (!otp) {
      return res.status(400).json({ error: 'Verification code is required' });
    }
    if (!verifyTOTP(user.id, otp)) {
      return res.status(400).json({ error: 'Invalid authenticator code' });
    }

    const hash = bcrypt.hashSync(newPassword, 10);
    db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hash, user.id);

    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error changing password' });
  }
});

// ---------- CREATE DEPOSIT REQUEST ----------
router.post('/deposits', (req, res) => {
  try {
    const user = currentUser(req);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.status === 'blocked') return res.status(403).json({ error: 'Account blocked' });

    let { amount, txn_ref } = req.body;
    amount = Number(amount);
    txn_ref = sanitizeText(txn_ref, 100);

    if (!amount || amount <= 0) {
      return res.status(400).json({ error: 'Enter a valid deposit amount' });
    }

    if (user.principal_wallet >= MIN_DEPOSIT) {
      const cents = Math.round(amount * 100);
      if (cents % (TOPUP_MULTIPLE * 100) !== 0) {
        return res.status(400).json({
          error: `Your Principal Wallet is already $${MIN_DEPOSIT}+, so deposits must be in multiples of $${TOPUP_MULTIPLE}.`
        });
      }
    } else if (amount < MIN_DEPOSIT) {
      return res.status(400).json({
        error: `Minimum deposit is $${MIN_DEPOSIT}. Once your Principal Wallet reaches $${MIN_DEPOSIT}, you can top up in multiples of $${TOPUP_MULTIPLE}.`
      });
    }

    if (!txn_ref) {
      return res.status(400).json({ error: 'Enter the transaction hash for your USDT (BEP20) transfer' });
    }

    const info = db.prepare(
      `INSERT INTO deposits (user_id, amount, method, txn_ref, status)
       VALUES (?, ?, ?, ?, 'pending')`
    ).run(user.id, amount, DEPOSIT_METHOD, txn_ref);

    const deposit = db.prepare('SELECT * FROM deposits WHERE id = ?').get(info.lastInsertRowid);
    res.status(201).json({ message: 'Deposit request submitted. Awaiting admin approval.', deposit });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error creating deposit' });
  }
});

// ---------- CREATE WITHDRAWAL REQUEST (requires 2FA OTP) ----------
router.post('/withdrawals', (req, res) => {
  try {
    const user = currentUser(req);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.status === 'blocked') return res.status(403).json({ error: 'Account blocked' });

    if (!user.usdt_bep20_address) {
      return res.status(400).json({ error: 'Save your USDT (BEP20) withdrawal address in your profile first' });
    }

    let { amount, wallet_type, otp } = req.body;
    amount = Number(amount);
    wallet_type = wallet_type === 'income' ? 'income' : 'principal';

    if (!amount || amount <= 0) {
      return res.status(400).json({ error: 'Enter a valid withdrawal amount' });
    }
    if (!otp) {
      return res.status(400).json({ error: 'Verification code is required to submit a withdrawal' });
    }
    if (!verifyTOTP(user.id, otp)) {
      return res.status(400).json({ error: 'Invalid authenticator code' });
    }

    const now = new Date();
    const bypassLock = isWithdrawLockBypassed();
    const withdrawalWindows = getWithdrawalWindows();
    let breakdown = null;

    if (wallet_type === 'income') {
      if (!bypassLock && !isLastDayOfMonth(now)) {
        const nextDate = lastDayOfCurrentMonth(now).toISOString().slice(0, 10);
        return res.status(400).json({
          error: `Income Wallet withdrawals can only be submitted on the last day of the month. Next window: ${nextDate}.`
        });
      }
      if (amount > user.income_wallet) {
        return res.status(400).json({ error: 'Insufficient Income Wallet balance' });
      }
      db.prepare('UPDATE users SET income_wallet = income_wallet - ? WHERE id = ?').run(amount, user.id);
    } else {
      const reserved = reservePrincipal(db, user.id, amount, now, bypassLock, withdrawalWindows);
      if (!reserved.ok) {
        const { nextWindowDate } = getPrincipalEligibility(db, user.id, now, bypassLock, withdrawalWindows);
        const eligibleMsg = `Only $${reserved.eligibleNow.toFixed(2)} of principal is currently eligible for withdrawal.`;
        const windowMsg = nextWindowDate
          ? ` Next eligible window opens ${nextWindowDate.toISOString().slice(0, 10)}.`
          : '';
        const windowsLabel = withdrawalWindows.join('th / ') + 'th';
        return res.status(400).json({
          error: `Principal Wallet withdrawals are only allowed at the ${windowsLabel} month after a deposit is approved. ${eligibleMsg}${windowMsg}`
        });
      }
      breakdown = reserved.breakdown;
      db.prepare('UPDATE users SET principal_wallet = principal_wallet - ? WHERE id = ?').run(amount, user.id);
    }

    const info = db.prepare(
      `INSERT INTO withdrawals (user_id, amount, method, to_address, status, wallet_type, source_breakdown)
       VALUES (?, ?, ?, ?, 'submitted', ?, ?)`
    ).run(user.id, amount, DEPOSIT_METHOD, user.usdt_bep20_address, wallet_type, breakdown ? JSON.stringify(breakdown) : null);

    const withdrawal = db.prepare('SELECT * FROM withdrawals WHERE id = ?').get(info.lastInsertRowid);
    res.status(201).json({ message: 'Withdrawal request submitted. Awaiting admin approval.', withdrawal });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error creating withdrawal' });
  }
});

// ---------- HISTORY ----------
router.get('/deposits', (req, res) => {
  const rows = db.prepare('SELECT * FROM deposits WHERE user_id = ? ORDER BY id DESC').all(req.user.id);
  res.json({ deposits: rows });
});

router.get('/withdrawals', (req, res) => {
  const rows = db.prepare('SELECT * FROM withdrawals WHERE user_id = ? ORDER BY id DESC').all(req.user.id);
  res.json({ withdrawals: rows });
});

// ---------- NOTIFICATIONS ----------
// A broadcast (user_id IS NULL) only counts for a user if it was sent on
// or after that user's registration date - a newly-registered user should
// not see broadcasts that went out before they signed up. Notifications
// targeted directly at the user (user_id = req.user.id) always show.
router.get('/notifications', (req, res) => {
  const rows = db.prepare(
    `SELECT n.*, CASE WHEN r.notification_id IS NULL THEN 0 ELSE 1 END AS is_read
     FROM notifications n
     JOIN users u ON u.id = ?
     LEFT JOIN notification_reads r ON r.notification_id = n.id AND r.user_id = ?
     WHERE n.user_id = ? OR (n.user_id IS NULL AND n.created_at >= u.created_at)
     ORDER BY n.id DESC`
  ).all(req.user.id, req.user.id, req.user.id);
  res.json({ notifications: rows });
});

router.get('/notifications/unread-count', (req, res) => {
  const row = db.prepare(
    `SELECT COUNT(*) AS c FROM notifications n
     JOIN users u ON u.id = ?
     LEFT JOIN notification_reads r ON r.notification_id = n.id AND r.user_id = ?
     WHERE (n.user_id = ? OR (n.user_id IS NULL AND n.created_at >= u.created_at))
       AND r.notification_id IS NULL`
  ).get(req.user.id, req.user.id, req.user.id);
  res.json({ unread_count: row.c });
});

router.post('/notifications/:id/read', (req, res) => {
  const notif = db.prepare(
    `SELECT n.* FROM notifications n
     JOIN users u ON u.id = ?
     WHERE n.id = ? AND (n.user_id = ? OR (n.user_id IS NULL AND n.created_at >= u.created_at))`
  ).get(req.user.id, req.params.id, req.user.id);
  if (!notif) return res.status(404).json({ error: 'Notification not found' });

  db.prepare(
    `INSERT INTO notification_reads (notification_id, user_id) VALUES (?, ?)
     ON CONFLICT(notification_id, user_id) DO NOTHING`
  ).run(notif.id, req.user.id);
  res.json({ message: 'Marked as read' });
});

// ---------- SUPPORT ----------
router.get('/support', (req, res) => {
  const rows = db.prepare(
    'SELECT * FROM support_tickets WHERE user_id = ? ORDER BY updated_at DESC'
  ).all(req.user.id);
  res.json({ tickets: rows });
});

router.get('/support/:id', (req, res) => {
  const ticket = db.prepare('SELECT * FROM support_tickets WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!ticket) return res.status(404).json({ error: 'Ticket not found' });

  const messages = db.prepare('SELECT * FROM support_messages WHERE ticket_id = ? ORDER BY id ASC').all(ticket.id);
  res.json({ ticket, messages });
});

router.post('/support', (req, res) => {
  const subject = sanitizeText(req.body.subject, 150);
  const message = sanitizeText(req.body.message, 2000);
  if (!subject || !message) return res.status(400).json({ error: 'Subject and message are required' });

  const info = db.prepare(
    `INSERT INTO support_tickets (user_id, subject) VALUES (?, ?)`
  ).run(req.user.id, subject);
  db.prepare(
    `INSERT INTO support_messages (ticket_id, sender_role, message) VALUES (?, 'user', ?)`
  ).run(info.lastInsertRowid, message);

  res.status(201).json({ message: 'Support ticket submitted', ticket_id: info.lastInsertRowid });
});

router.post('/support/:id/reply', (req, res) => {
  const message = sanitizeText(req.body.message, 2000);
  if (!message) return res.status(400).json({ error: 'Message is required' });

  const ticket = db.prepare('SELECT * FROM support_tickets WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!ticket) return res.status(404).json({ error: 'Ticket not found' });

  db.prepare(
    `INSERT INTO support_messages (ticket_id, sender_role, message) VALUES (?, 'user', ?)`
  ).run(ticket.id, message);
  db.prepare(`UPDATE support_tickets SET updated_at = datetime('now'), status = 'open' WHERE id = ?`).run(ticket.id);

  res.status(201).json({ message: 'Reply sent' });
});

module.exports = router;
