'use strict';

require('dotenv').config();

const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const { doubleCsrf } = require('csrf-csrf');
const path = require('path');

const authRoutes = require('./routes/auth');
const dashboardRoutes = require('./routes/dashboard');

const app = express();

// ─── View engine ─────────────────────────────────────────────────────────────
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ─── Static assets ───────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

// ─── Cookie & body parsing ────────────────────────────────────────────────────
app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// ─── Sessions ────────────────────────────────────────────────────────────────
const isProduction = process.env.NODE_ENV === 'production';

const sessionOptions = {
  secret: process.env.SESSION_SECRET || 'dev-secret-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,            // Prevent JS access to cookie
    secure: isProduction,      // HTTPS-only in production
    sameSite: 'lax',           // CSRF mitigation
    maxAge: 1000 * 60 * 60,    // 1-hour session lifetime
  },
};

// Use a non-leaking memory-based session store (suitable for development/demo;
// swap for a persistent store like connect-pg-simple in production)
if (process.env.NODE_ENV !== 'test') {
  const MemoryStore = require('memorystore')(session);
  sessionOptions.store = new MemoryStore({
    checkPeriod: 86400000, // prune expired entries every 24h
  });
}

app.use(session(sessionOptions));

// ─── CSRF protection ─────────────────────────────────────────────────────────
const csrfCookieName = (process.env.NODE_ENV === 'test' || !isProduction)
  ? 'x-csrf-token'
  : '__Host-psifi.x-csrf-token';

const { doubleCsrfProtection } = doubleCsrf({
  getSecret: () => process.env.SESSION_SECRET || 'dev-secret-change-in-production',
  getSessionIdentifier: (req) => req.session.id,
  cookieName: csrfCookieName,
  cookieOptions: {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'lax',
  },
  // Read the CSRF token from the hidden form field `_csrf` in addition to the
  // default `x-csrf-token` header so HTML forms work without JavaScript.
  getCsrfTokenFromRequest: (req) =>
    req.body?._csrf || req.headers['x-csrf-token'],
});

app.use(doubleCsrfProtection);

// Ensure the session is initialised and persisted on every request so that
// req.session.id is stable across the GET (token generation) and the following
// POST (token validation).  Without this, saveUninitialized:false means the
// session cookie isn't sent on the first GET, so the session ID changes on
// the POST and the CSRF check fails with 403.
app.use((req, res, next) => {
  if (!req.session.csrfInit) {
    req.session.csrfInit = true;
  }
  res.locals.csrfToken = req.csrfToken();
  next();
});

// ─── Routes ──────────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  if (req.session && req.session.userId) {
    return res.redirect('/dashboard');
  }
  res.redirect('/login');
});

app.use('/', authRoutes);
app.use('/', dashboardRoutes);

// ─── 404 handler ─────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).send('<h1>404 – Page Not Found</h1><p><a href="/">Home</a></p>');
});

// ─── Error handler ───────────────────────────────────────────────────────────
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).send('<h1>403 – Invalid CSRF token</h1>');
  }
  console.error(err);
  res.status(500).send('<h1>500 – Internal Server Error</h1>');
});

// ─── Start ───────────────────────────────────────────────────────────────────
if (require.main === module) {
  const PORT = parseInt(process.env.PORT, 10) || 3000;
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

module.exports = app;
