'use strict';

/**
 * Middleware: require an authenticated session.
 * Redirects to /login if the user is not logged in.
 */
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  }
  res.redirect('/login');
}

/**
 * Middleware: redirect already-authenticated users away from auth pages.
 */
function redirectIfAuthenticated(req, res, next) {
  if (req.session && req.session.userId) {
    return res.redirect('/dashboard');
  }
  next();
}

module.exports = { requireAuth, redirectIfAuthenticated };
