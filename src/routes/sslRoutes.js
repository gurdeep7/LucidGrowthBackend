const express = require('express');
const router = express.Router();
const { getSslInfo } = require('../controllers/sslController');

router.post('/ssl-info', getSslInfo);

module.exports = router;
