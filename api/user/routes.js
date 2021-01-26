const express = require('express');
const path = require('path');
const rootdir = require('../../helpers/rootdir');
const inputValidator = require(path.join(rootdir, 'middlewares', 'input-validator'));
const isAuth = require(path.join(rootdir, 'middlewares', 'authenticated'));

const userController = require('./controller');

const router = express.Router();

router.get('/users', isAuth, userController.getUsers);

router.get('/users/:userId', isAuth, userController.getUser);

router.get('/users/:userId/username', isAuth, userController.getUsername);

router.get('/users/:userId/status', isAuth, userController.getUserStatus);

router.get('/users/:userId/avatar', isAuth, userController.getUserAvatar);

router.post('/users/:userId/verifyemail', inputValidator.validate('email'), userController.verifyEmail);

router.post('/users/:userId/password', inputValidator.validate('password'), userController.resetUserPassword);

module.exports = router;