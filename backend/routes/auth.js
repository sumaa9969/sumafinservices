const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../db');
const { sanitizeName, sanitizeText } = require('../utils/sanitize');
require('dotenv').config();

const router = express.Router();

// ---------- HELPERS ----------
function issueLoginToken(user) {
  return jwt.sign(
    { id: user.id, userCode: user.user_code, email: user.email, role: user.role, name: user.name },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
}

function loginPayload(user) {
  return {
    id: user.id,
    userCode: user.user_code,
    name: user.name,
    email: user.email,
    role: user.role,
    principal_wallet: user.principal_wallet,
    income_wallet: user.income_wallet,
    status: user.status
  };
}

// Generate a 6-digit OTP, store it (5 min expiry), return the code.
function createOTP(userId, purpose) {
  const code = String(Math.floor(100000 + Math.random() * 900000));
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
  // Invalidate any existing OTP for same user + purpose
  db.prepare("UPDATE otp_tokens SET used = 1 WHERE user_id = ? AND purpose = ? AND used = 0").run(userId, purpose);
  db.prepare(
    "INSERT INTO otp_tokens (user_id, purpose, code, expires_at) VALUES (?, ?, ?, ?)"
  ).run(userId, purpose, code, expiresAt);
  return code;
}

// Validate OTP; returns true and marks used on success, false otherwise.
function verifyOTP(userId, purpose, code) {
  const row = db.prepare(
    "SELECT * FROM otp_tokens WHERE user_id = ? AND purpose = ? AND used = 0 ORDER BY id DESC LIMIT 1"
  ).get(userId, purpose);
  if (!row) return false;
  if (row.code !== String(code).trim()) return false;
  if (new Date(row.expires_at) < new Date()) return false;
  db.prepare("UPDATE otp_tokens SET used = 1 WHERE id = ?").run(row.id);
  return true;
}

// In production, send an actual email. For now, log to console and return
// the code so the frontend can display it during development.
function sendOTPEmail(email, code, purpose) {
  const labels = {
    forgot_password: 'Password Reset',
    wallet_address: 'Wallet Address Change',
    password_change: 'Password Change',
    withdrawal: 'Withdrawal Verification'
  };
  const label = labels[purpose] || 'Verification';
  console.log(`[2FA] ${label} OTP for ${email}: ${code} (expires in 5 min)`);
  // TODO: integrate your email provider (SendGrid, SES, etc.) here.
  return code; // returned so dev mode can surface it
}

// ---------- REGISTER ----------
// Name, email, password only — phone removed.
router.post('/register', (req, res) => {
  try {
    let { name, email, password, confirmPassword } = req.body;

    name = sanitizeName(name);
    email = sanitizeText(email, 150).toLowerCase();

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email and password are required' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    if (confirmPassword !== undefined && confirmPassword !== password) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Invalid email address' });
    }

    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (existing) {
      return res.status(409).json({ error: 'An account with this email already exists' });
    }

    const hash = bcrypt.hashSync(password, 10);
    const code = db.nextUserCode();

    const info = db.prepare(
      `INSERT INTO users (user_code, name, email, password, role, status)
       VALUES (?, ?, ?, ?, 'user', 'active')`
    ).run(code, name, email, hash);

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
    const token = issueLoginToken(user);

    res.status(201).json({ token, user: loginPayload(user) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// ---------- LOGIN ----------
// Accepts either the account email or the SFS#### username/user code in
// the same "email" field (kept for backward compatibility with existing
// clients), plus an optional dedicated "identifier"/"username" field.
router.post('/login', (req, res) => {
  try {
    let { email, password, identifier, username } = req.body;
    let login = identifier || username || email;
    login = sanitizeText(login, 150).trim();

    if (!login || !password) {
      return res.status(400).json({ error: 'Username/email and password are required' });
    }

    const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(login);
    const user = isEmail
      ? db.prepare('SELECT * FROM users WHERE email = ?').get(login.toLowerCase())
      : db.prepare('SELECT * FROM users WHERE user_code = ?').get(login.toUpperCase());

    // Always return the same generic message for invalid login OR password
    // to avoid user enumeration, but be explicit when account is blocked.
    if (!user) {
      return res.status(401).json({ error: 'Invalid email/username or password' });
    }

    if (user.status === 'blocked') {
      return res.status(403).json({ error: 'Your account has been blocked. Contact support.' });
    }

    const valid = bcrypt.compareSync(password, user.password);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid email/username or password' });
    }

    const token = issueLoginToken(user);
    res.json({ token, user: loginPayload(user) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// ---------- FORGOT PASSWORD — STEP 1: request OTP ----------
router.post('/forgot-password/request', (req, res) => {
  try {
    let { email } = req.body;
    email = sanitizeText(email, 150).toLowerCase();
    if (!email) return res.status(400).json({ error: 'Email is required' });

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

    // Always respond success to prevent email enumeration.
    if (!user || user.status === 'blocked') {
      return res.json({ message: 'If that email is registered, a reset code has been sent.' });
    }

    const code = createOTP(user.id, 'forgot_password');
    const devCode = sendOTPEmail(user.email, code, 'forgot_password');

    res.json({
      message: 'If that email is registered, a reset code has been sent.',
      // Remove `dev_otp` in production — only here to aid testing without a mail server.
      dev_otp: process.env.NODE_ENV === 'production' ? undefined : devCode
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- FORGOT PASSWORD — STEP 2: verify OTP + set new password ----------
router.post('/forgot-password/reset', (req, res) => {
  try {
    let { email, otp, newPassword, confirmPassword } = req.body;
    email = sanitizeText(email, 150).toLowerCase();

    if (!email || !otp || !newPassword) {
      return res.status(400).json({ error: 'Email, OTP code and new password are required' });
    }
    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    if (confirmPassword !== undefined && confirmPassword !== newPassword) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) return res.status(400).json({ error: 'Invalid or expired reset code' });

    if (!verifyOTP(user.id, 'forgot_password', otp)) {
      return res.status(400).json({ error: 'Invalid or expired reset code' });
    }

    const hash = bcrypt.hashSync(newPassword, 10);
    db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hash, user.id);

    res.json({ message: 'Password reset successfully. You can now log in.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Expose verifyOTP for use in user routes
router.createOTP = createOTP;
router.verifyOTP = verifyOTP;
router.sendOTPEmail = sendOTPEmail;

module.exports = router;
