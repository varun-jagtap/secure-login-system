'use strict';

const { DatabaseSync } = require('node:sqlite');
const path = require('path');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, '..', 'app.db');

let db;

function getDb() {
  if (!db) {
    db = new DatabaseSync(DB_PATH);
    initSchema();
  }
  return db;
}

function initSchema() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      username   TEXT    NOT NULL UNIQUE COLLATE NOCASE,
      email      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
      password   TEXT    NOT NULL,
      created_at TEXT    NOT NULL DEFAULT (datetime('now'))
    );
  `);
}

/**
 * Create a new user row.
 * @param {string} username
 * @param {string} email
 * @param {string} hashedPassword
 * @returns {object} The result info
 */
function createUser(username, email, hashedPassword) {
  const stmt = getDb().prepare(
    'INSERT INTO users (username, email, password) VALUES (?, ?, ?)'
  );
  return stmt.run(username, email, hashedPassword);
}

/**
 * Find a user by username (case-insensitive via COLLATE NOCASE).
 * @param {string} username
 * @returns {object|undefined}
 */
function findUserByUsername(username) {
  return getDb()
    .prepare('SELECT * FROM users WHERE username = ?')
    .get(username);
}

/**
 * Find a user by email (case-insensitive via COLLATE NOCASE).
 * @param {string} email
 * @returns {object|undefined}
 */
function findUserByEmail(email) {
  return getDb()
    .prepare('SELECT * FROM users WHERE email = ?')
    .get(email);
}

/**
 * Close the database (used in tests to reset state).
 */
function closeDb() {
  if (db) {
    db.close();
    db = null;
  }
}

module.exports = { getDb, createUser, findUserByUsername, findUserByEmail, closeDb };
