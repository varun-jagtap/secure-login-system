'use strict';

/**
 * Integration tests for the secure login system.
 * Uses an isolated temp-file SQLite database to avoid file side-effects.
 */

const os = require('os');
const path = require('path');

// Point the database to a unique temp file per test run
const dbFile = path.join(os.tmpdir(), `test-${Date.now()}.db`);
process.env.DB_PATH = dbFile;
process.env.NODE_ENV = 'test';
process.env.SESSION_SECRET = 'test-secret-32-chars-long-xxxx!!';

const request = require('supertest');
const app = require('../app');
const { closeDb } = require('../db/database');

afterAll(() => {
  closeDb();
});

/**
 * Extract the CSRF token embedded in the hidden `_csrf` input of an HTML page.
 * The agent is used so the CSRF cookie is preserved across requests.
 */
async function getCsrfToken(agent, url) {
  const res = await agent.get(url);
  const match = res.text.match(/name="_csrf"\s+value="([^"]+)"/);
  if (!match) throw new Error(`No CSRF token found on ${url}`);
  return match[1];
}

// ─── GET /register ──────────────────────────────────────────────────────────

describe('GET /register', () => {
  it('returns 200 with registration form', async () => {
    const res = await request(app).get('/register');
    expect(res.status).toBe(200);
    expect(res.text).toContain('Create Account');
  });
});

// ─── POST /register ─────────────────────────────────────────────────────────

describe('POST /register', () => {
  it('redirects to /login on successful registration', async () => {
    const agent = request.agent(app);
    const csrf = await getCsrfToken(agent, '/register');
    const res = await agent.post('/register').type('form').send({
      _csrf: csrf,
      username: 'testuser',
      email: 'test@example.com',
      password: 'securePass1',
      confirmPassword: 'securePass1',
    });
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/login');
  });

  it('rejects short password', async () => {
    const agent = request.agent(app);
    const csrf = await getCsrfToken(agent, '/register');
    const res = await agent.post('/register').type('form').send({
      _csrf: csrf,
      username: 'user2',
      email: 'user2@example.com',
      password: 'short',
      confirmPassword: 'short',
    });
    expect(res.status).toBe(422);
    expect(res.text).toContain('at least 8 characters');
  });

  it('rejects invalid email', async () => {
    const agent = request.agent(app);
    const csrf = await getCsrfToken(agent, '/register');
    const res = await agent.post('/register').type('form').send({
      _csrf: csrf,
      username: 'user3',
      email: 'not-an-email',
      password: 'securePass1',
      confirmPassword: 'securePass1',
    });
    expect(res.status).toBe(422);
    expect(res.text).toContain('valid email');
  });

  it('rejects mismatched passwords', async () => {
    const agent = request.agent(app);
    const csrf = await getCsrfToken(agent, '/register');
    const res = await agent.post('/register').type('form').send({
      _csrf: csrf,
      username: 'user4',
      email: 'user4@example.com',
      password: 'securePass1',
      confirmPassword: 'differentPass1',
    });
    expect(res.status).toBe(422);
    expect(res.text).toContain('do not match');
  });

  it('rejects duplicate username', async () => {
    // testuser was already registered in the first test of this describe block
    const agent = request.agent(app);
    const csrf = await getCsrfToken(agent, '/register');
    const res = await agent.post('/register').type('form').send({
      _csrf: csrf,
      username: 'testuser',
      email: 'other@example.com',
      password: 'securePass1',
      confirmPassword: 'securePass1',
    });
    expect(res.status).toBe(422);
    expect(res.text).toContain('already taken');
  });

  it('rejects duplicate email', async () => {
    const agent = request.agent(app);
    const csrf = await getCsrfToken(agent, '/register');
    const res = await agent.post('/register').type('form').send({
      _csrf: csrf,
      username: 'uniqueuser',
      email: 'test@example.com',
      password: 'securePass1',
      confirmPassword: 'securePass1',
    });
    expect(res.status).toBe(422);
    expect(res.text).toContain('already registered');
  });

  it('rejects username with special characters', async () => {
    const agent = request.agent(app);
    const csrf = await getCsrfToken(agent, '/register');
    const res = await agent.post('/register').type('form').send({
      _csrf: csrf,
      username: 'bad user!',
      email: 'baduser@example.com',
      password: 'securePass1',
      confirmPassword: 'securePass1',
    });
    expect(res.status).toBe(422);
    expect(res.text).toContain('letters, numbers, and underscores');
  });

  it('rejects POST without CSRF token with 403', async () => {
    const res = await request(app).post('/register').type('form').send({
      username: 'hacker',
      email: 'hacker@example.com',
      password: 'securePass1',
      confirmPassword: 'securePass1',
    });
    expect(res.status).toBe(403);
  });
});

// ─── GET /login ─────────────────────────────────────────────────────────────

describe('GET /login', () => {
  it('returns 200 with login form', async () => {
    const res = await request(app).get('/login');
    expect(res.status).toBe(200);
    expect(res.text).toContain('Log In');
  });
});

// ─── POST /login ─────────────────────────────────────────────────────────────

describe('POST /login', () => {
  it('rejects wrong password', async () => {
    const agent = request.agent(app);
    const csrf = await getCsrfToken(agent, '/login');
    const res = await agent.post('/login').type('form').send({
      _csrf: csrf,
      username: 'testuser',
      password: 'wrongpassword',
    });
    expect(res.status).toBe(401);
    expect(res.text).toContain('Invalid username or password');
  });

  it('rejects unknown username', async () => {
    const agent = request.agent(app);
    const csrf = await getCsrfToken(agent, '/login');
    const res = await agent.post('/login').type('form').send({
      _csrf: csrf,
      username: 'nobody',
      password: 'securePass1',
    });
    expect(res.status).toBe(401);
    expect(res.text).toContain('Invalid username or password');
  });

  it('logs in with correct credentials and redirects to dashboard', async () => {
    const agent = request.agent(app);
    const csrf = await getCsrfToken(agent, '/login');
    const res = await agent.post('/login').type('form').send({
      _csrf: csrf,
      username: 'testuser',
      password: 'securePass1',
    });
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/dashboard');
  });
});

// ─── GET /dashboard ──────────────────────────────────────────────────────────

describe('GET /dashboard', () => {
  it('redirects unauthenticated users to /login', async () => {
    const res = await request(app).get('/dashboard');
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/login');
  });

  it('shows dashboard to authenticated users', async () => {
    const agent = request.agent(app);

    // Register
    const regCsrf = await getCsrfToken(agent, '/register');
    await agent.post('/register').type('form').send({
      _csrf: regCsrf,
      username: 'dashuser',
      email: 'dashuser@example.com',
      password: 'securePass1',
      confirmPassword: 'securePass1',
    });

    // Login
    const loginCsrf = await getCsrfToken(agent, '/login');
    await agent.post('/login').type('form').send({
      _csrf: loginCsrf,
      username: 'dashuser',
      password: 'securePass1',
    });

    const res = await agent.get('/dashboard');
    expect(res.status).toBe(200);
    expect(res.text).toContain('Dashboard');
    expect(res.text).toContain('dashuser');
  });
});

// ─── POST /logout ────────────────────────────────────────────────────────────

describe('POST /logout', () => {
  it('logs out and redirects to /login, then denies dashboard access', async () => {
    const agent = request.agent(app);

    // Register
    const regCsrf = await getCsrfToken(agent, '/register');
    await agent.post('/register').type('form').send({
      _csrf: regCsrf,
      username: 'logoutuser',
      email: 'logoutuser@example.com',
      password: 'securePass1',
      confirmPassword: 'securePass1',
    });

    // Login
    const loginCsrf = await getCsrfToken(agent, '/login');
    await agent.post('/login').type('form').send({
      _csrf: loginCsrf,
      username: 'logoutuser',
      password: 'securePass1',
    });

    // Confirm dashboard is accessible
    const before = await agent.get('/dashboard');
    expect(before.status).toBe(200);

    // Logout (get CSRF token from the dashboard page)
    const dashCsrf = before.text.match(/name="_csrf"\s+value="([^"]+)"/)[1];
    const logoutRes = await agent.post('/logout').type('form').send({ _csrf: dashCsrf });
    expect(logoutRes.status).toBe(302);
    expect(logoutRes.headers.location).toBe('/login');

    // Dashboard should now redirect to /login
    const after = await agent.get('/dashboard');
    expect(after.status).toBe(302);
    expect(after.headers.location).toBe('/login');
  });
});
