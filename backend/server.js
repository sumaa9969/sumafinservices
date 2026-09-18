const express = require('express');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

require('./db'); // initializes schema + seeds first admin

const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/user');
const adminRoutes = require('./routes/admin');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());

// Serve the frontend HTML/CSS/JS directly from this same server, so you
// can just open e.g. http://localhost:5000/login.html in the browser —
// no separate static server, no CORS, no API_BASE editing needed.
app.use(express.static(path.join(__dirname, '..', 'frontend')));

// ---------- CORS ----------
const allowedOrigins = (process.env.FRONTEND_ORIGIN || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true); // same-origin / curl / server-to-server
    if (allowedOrigins.length === 0) return callback(null, true); // dev fallback
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true
}));

// ---------- RATE LIMITING (auth endpoints only) ----------
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/auth', authLimiter);

// ---------- ROUTES ----------
app.use('/api/auth', authRoutes);
app.use('/api/user', userRoutes);
app.use('/api/admin', adminRoutes);

app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

app.get('/', (req, res) => res.redirect('/index.html'));

app.use((req, res) => res.status(404).json({ error: 'Not found' }));

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
