# Secure Login System

A minimal, production-conscious web application demonstrating secure user authentication with **registration**, **login**, **session management**, and **logout**. Built with Node.js, Express, SQLite, and bcrypt.

---

## Features

| Feature | Detail |
|---|---|
| **Password hashing** | bcrypt with cost factor 12 |
| **SQL injection prevention** | All queries use parameterized statements (`node:sqlite`) |
| **Input validation** | Server-side validation via `express-validator` |
| **Session security** | `express-session` with `httpOnly`, `sameSite=lax`, `secure` (in production) cookies; session regenerated on login |
| **CSRF protection** | Double-submit cookie pattern via `csrf-csrf`; all state-changing forms include a `_csrf` token |
| **Logout** | Full session destruction + cookie clear |
| **Protected routes** | `/dashboard` is only accessible when authenticated |
| **Session fixation protection** | `req.session.regenerate()` called before writing session data |
| **Timing-safe login** | `bcrypt.compare` always runs (dummy hash used for unknown users) |

---

## Tech Stack

- **Runtime**: Node.js 18+
- **Framework**: Express 4
- **Database**: SQLite via Node.js built-in `node:sqlite` (Node 22+)
- **Session store**: `memorystore` (non-leaking in-process store; swap for a persistent store in production)
- **Password hashing**: `bcryptjs` (pure-JS)
- **CSRF protection**: `csrf-csrf` (double-submit cookie pattern)
- **Validation**: `express-validator`
- **Templating**: EJS
- **Tests**: Jest + supertest

---

## Prerequisites

- Node.js 18 or higher
- npm 9 or higher

---

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/varun-jagtap/secure-login-system.git
cd secure-login-system
```

### 2. Install dependencies

```bash
npm install
```

### 3. Configure environment variables

```bash
cp .env.example .env
```

Edit `.env` and set a strong, random `SESSION_SECRET`:

```bash
# Generate a secure secret (run once)
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

`.env` variables:

| Variable | Default | Description |
|---|---|---|
| `SESSION_SECRET` | *(required)* | Secret key for signing session cookies |
| `PORT` | `3000` | TCP port the server listens on |
| `NODE_ENV` | `development` | Set to `production` for secure cookies |

### 4. Start the server

```bash
npm start
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## Usage

| Route | Method | Description |
|---|---|---|
| `/` | GET | Redirects to `/dashboard` (if logged in) or `/login` |
| `/register` | GET | Registration form |
| `/register` | POST | Create a new account |
| `/login` | GET | Login form |
| `/login` | POST | Authenticate and start session |
| `/dashboard` | GET | Protected page (requires login) |
| `/logout` | POST | Destroy session and redirect to `/login` |

### Manual Verification Steps

1. Visit `http://localhost:3000/register` — fill in username, email, and password.
2. You are redirected to `/login` after successful registration.
3. Log in with your credentials.
4. You are redirected to `/dashboard` showing your username.
5. Click **Log Out** — you are redirected to `/login`.
6. Attempt to visit `/dashboard` directly — you are redirected to `/login`.
7. Try logging in with a wrong password — you receive a generic error (no user enumeration).

---

## Running Tests

```bash
npm test
```

Tests cover:

- Registration (success, validation errors, duplicate username/email)
- Login (success, wrong password, unknown user)
- Protected route (`/dashboard`) redirecting unauthenticated users
- Logout and subsequent session invalidation

---

## Project Structure

```
secure-login-system/
├── app.js               # Express application entry point
├── package.json
├── .env.example         # Environment variable template
├── .gitignore
├── db/
│   └── database.js      # SQLite setup and query helpers
├── middleware/
│   └── auth.js          # requireAuth / redirectIfAuthenticated
├── routes/
│   ├── auth.js          # /register, /login, /logout
│   └── dashboard.js     # /dashboard (protected)
├── views/               # EJS templates
│   ├── register.ejs
│   ├── login.ejs
│   └── dashboard.ejs
├── public/
│   └── style.css        # Shared stylesheet
└── tests/
    └── auth.test.js     # Jest + supertest integration tests
```

---

## Security Notes

- **Passwords are never stored in plaintext.** bcrypt with cost factor 12 is used.
- **Parameterized queries** prevent SQL injection throughout.
- **Session cookie** is `httpOnly` (no JS access) and `sameSite=lax` (CSRF mitigation). Set `NODE_ENV=production` for `secure` (HTTPS-only) cookies.
- **Session regeneration** on login prevents session fixation attacks.
- **Generic error messages** on failed login prevent username enumeration.
- Keep `SESSION_SECRET` long, random, and out of source control.

---

## Future Enhancements

- **Two-Factor Authentication (2FA)**: TOTP-based 2FA (e.g., Google Authenticator) can be added using the [`speakeasy`](https://github.com/speakeasy/speakeasy) library. This was intentionally left out to keep the starter implementation minimal.
- **Rate limiting**: Add `express-rate-limit` on `/login` to defend against brute-force attacks.
- **CSRF tokens**: Add [`csurf`](https://github.com/expressjs/csurf) or a CSRF middleware for form submissions.
- **PostgreSQL / MySQL**: Swap `better-sqlite3` for a hosted database in production.
- **Account lockout**: Lock accounts after N failed login attempts.
- **Password reset**: Implement a secure password reset flow via email tokens.
