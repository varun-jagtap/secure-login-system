'use strict';

const express = require('express');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const { createUser, findUserByUsername, findUserByEmail } = require('../db/database');
const { redirectIfAuthenticated } = require('../middleware/auth');

const router = express.Router();
const SALT_ROUNDS = 12;

// Dummy hash used to ensure bcrypt.compare always runs even for unknown users,
// preventing timing-based username enumeration attacks.
const DUMMY_HASH = bcrypt.hashSync('dummy-placeholder-password', SALT_ROUNDS);

// ─── Registration ────────────────────────────────────────────────────────────

router.get('/register', redirectIfAuthenticated, (req, res) => {
  res.render('register', { errors: [], formData: {} });
});

router.post(
  '/register',
  redirectIfAuthenticated,
  [
    body('username')
      .trim()
      .isLength({ min: 3, max: 30 })
      .withMessage('Username must be 3–30 characters.')
      .matches(/^[A-Za-z0-9_]+$/)
      .withMessage('Username may only contain letters, numbers, and underscores.'),
    body('email')
      .trim()
      .normalizeEmail()
      .isEmail()
      .withMessage('A valid email address is required.'),
    body('password')
      .isLength({ min: 8 })
      .withMessage('Password must be at least 8 characters.'),
    body('confirmPassword').custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Passwords do not match.');
      }
      return true;
    }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    const formData = { username: req.body.username, email: req.body.email };

    if (!errors.isEmpty()) {
      return res.status(422).render('register', {
        errors: errors.array(),
        formData,
      });
    }

    const { username, email, password } = req.body;

    try {
      // Check for duplicate username or email
      if (findUserByUsername(username)) {
        return res.status(422).render('register', {
          errors: [{ msg: 'Username is already taken.' }],
          formData,
        });
      }
      if (findUserByEmail(email)) {
        return res.status(422).render('register', {
          errors: [{ msg: 'Email address is already registered.' }],
          formData,
        });
      }

      const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
      createUser(username, email, hashedPassword);

      req.session.flash = 'Registration successful! Please log in.';
      res.redirect('/login');
    } catch (err) {
      console.error('Registration error:', err);
      res.status(500).render('register', {
        errors: [{ msg: 'An unexpected error occurred. Please try again.' }],
        formData,
      });
    }
  }
);

// ─── Login ───────────────────────────────────────────────────────────────────

router.get('/login', redirectIfAuthenticated, (req, res) => {
  const flash = req.session.flash;
  delete req.session.flash;
  res.render('login', { errors: [], flash });
});

router.post(
  '/login',
  redirectIfAuthenticated,
  [
    body('username').trim().notEmpty().withMessage('Username is required.'),
    body('password').notEmpty().withMessage('Password is required.'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).render('login', {
        errors: errors.array(),
        flash: null,
      });
    }

    const { username, password } = req.body;

    try {
      const user = findUserByUsername(username);
      // Always run bcrypt.compare (even when user doesn't exist) to prevent
      // timing-based username enumeration attacks.
      const hashToCompare = user ? user.password : DUMMY_HASH;
      const passwordMatch = await bcrypt.compare(password, hashToCompare);

      if (!user || !passwordMatch) {
        return res.status(401).render('login', {
          errors: [{ msg: 'Invalid username or password.' }],
          flash: null,
        });
      }

      // Regenerate session to prevent session fixation
      req.session.regenerate((err) => {
        if (err) {
          console.error('Session regeneration error:', err);
          return res.status(500).render('login', {
            errors: [{ msg: 'An unexpected error occurred. Please try again.' }],
            flash: null,
          });
        }
        req.session.userId = user.id;
        req.session.username = user.username;
        res.redirect('/dashboard');
      });
    } catch (err) {
      console.error('Login error:', err);
      res.status(500).render('login', {
        errors: [{ msg: 'An unexpected error occurred. Please try again.' }],
        flash: null,
      });
    }
  }
);

// ─── Logout ──────────────────────────────────────────────────────────────────

router.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
    }
    res.clearCookie('connect.sid');
    res.redirect('/login');
  });
});

module.exports = router;
