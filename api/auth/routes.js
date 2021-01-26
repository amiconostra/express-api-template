const express = require('express');
const path = require('path');
const rootdir = require('../../helpers/rootdir');
const inputValidator = require(path.join(rootdir, 'middlewares', 'input-validator'));

const authController = require('./controller');

const router = express.Router();

router.post('/auth/register', inputValidator.validate('register'), authController.registerUser);

router.post('/auth/login', inputValidator.validate('email'), authController.loginUser);

router.post('/auth/verify/email', inputValidator.validate('email'), authController.sendVerifyMail);

router.post('/auth/reset/password', inputValidator.validate('email'), authController.sendResetPasswordMail);

module.exports = router;