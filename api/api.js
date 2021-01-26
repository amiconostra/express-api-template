const express = require('express');

const authRoutes = require('./auth/routes');
const userRoutes = require('./user/routes');

const router = express.Router();

router.use('/api', authRoutes);
router.use('/api', userRoutes);

module.exports = router;