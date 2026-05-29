'use strict';

const express = require('express');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

router.get('/dashboard', requireAuth, (req, res) => {
  res.render('dashboard', { username: req.session.username });
});

module.exports = router;
