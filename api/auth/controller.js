const crypto = require('crypto');
const path = require('path');
const rootdir = require('../../helpers/rootdir');
const bcrypt = require('bcryptjs');
const { validationResult } = require('express-validator');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const mailConfig = require(path.join(rootdir, 'config', 'mail'));

// mailer
const mailTransporter = nodemailer.createTransport(mailConfig.smtp);

// Models
const User = require(path.join(rootdir, 'models', 'user'));

exports.registerUser = (req, res, next) => {
    const serverUrl = req.protocol + '://' + req.get('host');
    const email = req.body.email;
    const username = req.body.username.toLowerCase();
    const password = req.body.password;
    const errors = validationResult(req);

    if(!errors.isEmpty()) {
        const error = new Error('Validation Failed');
        error.statusCode = 422;
        error.errors = errors.array();
        throw error;
    }

    crypto.randomBytes(32, async(err, buffer) => {
        if(err) {
            const error = new Error('Failed to Generate Verification Token');
            error.statusCode = 500;
            return next(error);
        }

        const token = buffer.toString('hex');

        try {
            const user = await User.findOne({$or: [{email: email}, {username: username}]});
            if(user) {
                const error = new Error('Username or Email Already Exists');
                error.statusCode = 422;
                throw error;
            }

            const hashedPassword = await bcrypt.hash(password, 12);
            const newUser = new User({email: email, username: username, password: hashedPassword, verifyToken: token, verifyTokenExpiration: Date.now() + 600000});
            await newUser.save();

            res.status(201).json({message: 'User successfully registered! Check your Email for Verification!'});

            mailTransporter.sendMail({
                to: email,
                from: mailConfig.general.noreply_mail,
                subject: 'Registration Successful!',
                html: `
                    <h1>You Successfully Signed Up!</h1>
                    <p>Email Verification</p>
                    <p>User ID: ${newUser._id}</p>
                    <p>Verify Token: ${token}</p>
                    <p>Send a POST Request with body{email, verifyToken} to <a href="${serverUrl}/api/users/${newUser._id}/verifyemail">${serverUrl}/api/users/{USER_ID}/verifyemail</a> to verify your email</p>
                `
            });
        } catch(err) {
            if(!err.statusCode) {
                err.statusCode = 500;
            }
            return next(err);
        }
    });
};

exports.loginUser = async(req, res, next) => {
    const email = req.body.email;
    const password = req.body.password;
    const errors = validationResult(req);

    if(!errors.isEmpty()) {
        const error = new Error('Validation Failed');
        error.statusCode = 422;
        error.errors = errors.array();
        return next(error);
    }

    try { 
        const user = await User.findOne({email: email});
        if(!user) {
            const error = new Error('No such User with this Email');
            error.statusCode = 404;
            throw error;
        }

        const matches = await bcrypt.compare(password, user.password);
        if(!matches) {
            const error = new Error('Invalid Password');
            error.statusCode = 401;
            throw error;
        }

        const token = jwt.sign({userId: user._id.toString(), email: user.email, username: user.username}, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.status(200).json({message: 'Login Successful', token: token});
    } catch(err) {
        if(!err.statusCode) {
            err.statusCode = 500;
        }
        return next(err);
    }
};

exports.sendVerifyMail = (req, res, next) => {
    const serverUrl = req.protocol + '://' + req.get('host');
    const email = req.body.email;
    const errors = validationResult(req);

    if(!errors.isEmpty()) {
        const error = new Error('Validation Failed');
        error.statusCode = 422;
        error.errors = errors.array();
        return next(error);
    }

    crypto.randomBytes(32, async(err, buffer) => {
        if(err) {
            const error = new Error('Failed to Generate Verification Token');
            error.statusCode = 500;
            return next(error);
        }
        
        const token = buffer.toString('hex');
        
        try {
            const user = await User.findOne({email: email});

            if(!user) {
                const error = new Error('No such User with this Email');
                error.statusCode = 404;
                throw error;
            }
            
            if(user.verifiedEmail) {
                const error = new Error('User already Verified');
                error.statusCode = 422;
                throw error;
            }

            user.verifyToken = token;
            user.verifyTokenExpiration = Date.now() + 600000; // 10 Minutes in milliseconds
            await user.save();
            res.status(201).json({message: 'Token has been Generated and Emailed!'});
            
            mailTransporter.sendMail({
                to: email,
                from: mailConfig.general.noreply_mail,
                subject: 'Email Verification!',
                html: `
                    <p>Requested Email Verification</p>
                    <p>User ID: ${user._id}</p>
                    <p>Verify Token: ${token}</p>
                    <p>Send a POST Request with body{email, verifyToken} to <a href="${serverUrl}/api/users/${user._id}/verifyemail">${serverUrl}/api/users/{USER_ID}/verifyemail</a> to verify your email</p>
                `
            });
        } catch(err) {
            if(!err.statusCode) {
                err.statusCode = 500;
            }
            return next(err);
        }
    });
};

exports.sendResetPasswordMail = (req, res, next) => {
    const serverUrl = req.protocol + '://' + req.get('host');
    const email = req.body.email;
    const errors = validationResult(req);
    
    if(!errors.isEmpty()) {
        const error = new Error('Validation Failed');
        error.statusCode = 422;
        error.errors = errors.array();
        return next(error);
    }

    crypto.randomBytes(32, async(err, buffer) => {
        if(err) {
            const error = new Error('Failed to Generate Password Reset Token');
            error.statusCode = 500;
            return next(error);
        }
        
        const token = buffer.toString('hex');

        try {
            const user = await User.findOne({email: email});
            if(!user) {
                const error = new Error('No such User with this Email');
                error.statusCode = 404;
                throw error;
            }
            
            user.resetToken = token;
            user.resetTokenExpiration = Date.now() + 600000; //10 Minutes
            await user.save();
            res.status(201).json({message: 'Token has been Generated and Emailed!'})

            mailTransporter.sendMail({
                to: email,
                from: mailConfig.general.noreply_mail,
                subject: 'Password Reset',
                html: `
                    <p>Requested Password Reset</p>
                    <p>Token: ${token}</p>
                    <p>Send a POST Request with body{email, password, resetToken} to <a href="${serverUrl}/api/users/${user._id}/password">${serverUrl}/api/users/{USER_ID}/password</a> to reset your password</p>
                `
            });
        } catch(err) {
            if(!err.statusCode) {
                err.statusCode = 500;
            }
            return next(err);
        }
    });
};