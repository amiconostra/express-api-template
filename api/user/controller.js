const path = require('path');
const rootdir = require('../../helpers/rootdir');
const bcrypt = require('bcryptjs');
const { validationResult } = require('express-validator');

// Models
const User = require(path.join(rootdir, 'models', 'user'));

exports.getUsers = async(req, res, next) => {
    try {
        const users = await User.find().select('-type -password');
        res.status(200).json({users: users});

    } catch(err) {
        if(!err.statusCode) {
            err.statusCode = 500;
        }
        return next(err);
    }
};

exports.getUser = async(req, res, next) => {
    const userId = req.params.userId;

    try {
        const user = await User.findOne({_id: userId}).select(' -type -password');
        if(!user) {
            const error = new Error('User not Found');
            error.statusCode = 404;
            throw error;
        }

        res.status(200).json({user: user});

    } catch(err) {
        if(!err.statusCode) {
            err.statusCode = 500;
        }
        return next(err);
    }
};

exports.getUsername = async(req, res, next) => {
    const userId = req.params.userId;

    try {
        const user = await User.findOne({_id: userId});
        if(!user) {
            const error = new Error('User not Found');
            error.statusCode = 404;
            throw error;
        }

        res.status(200).json({username: user.username});

    } catch(err) {
        if(!err.statusCode) {
            err.statusCode = 500;
        }
        return next(err);
    }
};

exports.getUserStatus = async(req, res, next) => {
    const userId = req.params.userId;

    try {
        const user = await User.findOne({_id: userId});
        if(!user) {
            const error = new Error('User not Found');
            error.statusCode = 404;
            throw error;
        }

        res.status(200).json({status: user.status});

    } catch(err) {
        if(!err.statusCode) {
            err.statusCode = 500;
        }
        return next(err);
    }
};

exports.getUserAvatar = async(req, res, next) => {
    const userId = req.params.userId;

    try {
        const user = await User.findOne({_id: userId});
        if(!user) {
            const error = new Error('User not Found');
            error.statusCode = 404;
            throw error;
        }

        const protocol = req.connection.encrypted ? 'https' : 'http';
        const avatarUrl = `${protocol}://${req.headers.host}/${user.avatarUrl}`
        res.status(200).json({avatar: avatarUrl});

    } catch(err) {
        if(!err.statusCode) {
            err.statusCode = 500;
        }
        return next(err);
    }
};

exports.verifyEmail = async(req, res, next) => {
    const userId = req.params.userId;
    const email = req.body.email;
    const verifyToken = req.body.verifyToken;
    const errors = validationResult(req);

    if(!errors.isEmpty()) {
        const error = new Error('Validation Failed');
        error.statusCode = 422;
        error.errors = errors.array();
        return next(error);
    }

    if(!verifyToken) {
        const error = new Error('Invalid Verify Token');
        error.statusCode = 422;
        return next(error);
    }

    try {
        const user = await User.findOne({_id: userId, email: email});
        if(!user) {
            const error = new Error('User not Found');
            error.statusCode = 404;
            throw error;
        }

        if(user.verifyToken !== verifyToken) {
            const error = new Error('Invalid Verify Token');
            error.statusCode = 422;
            throw error;
        }

        if(Date.now() > user.verifyTokenExpiration) {
            const error = new Error('Verify Token Expired');
            error.statusCode = 422;
            throw error;
        }

        user.verifiedEmail = true;
        user.verifyToken = undefined;
        user.verifyTokenExpiration = undefined;
        await user.save();

        res.status(200).json({message: 'User has been verified'});

    } catch(err) {
        if(!err.statusCode) {
            err.statusCode = 500;
        }
        return next(err);
    }
};

exports.resetUserPassword = async(req, res, next) => {
    const userId = req.params.userId;
    const password = req.body.password;
    const resetToken = req.body.resetToken;
    const errors = validationResult(req);

    if(!errors.isEmpty()) {
        const error = new Error('Validation Failed');
        error.statusCode = 422;
        error.errors = errors.array();
        return next(error);
    }

    if(!resetToken) {
        const error = new Error('Invalid Reset Token');
        error.statusCode = 422;
        return next(error);
    }

    try {
        const user = await User.findOne({_id: userId});
        if(!user) {
            const error = new Error('User not Found');
            error.statusCode = 404;
            throw error;
        }

        if(user.resetToken !== resetToken) {
            const error = new Error('Invalid Reset Token');
            error.statusCode = 422;
            throw error;
        }

        if(Date.now() > user.resetTokenExpiration) {
            const error = new Error('Reset Token Expired');
            error.statusCode = 422;
            throw error;
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        user.password = hashedPassword;
        user.resetToken = undefined;
        user.resetTokenExpiration = undefined;
        await user.save();

        res.status(200).json({message: 'Password has been reset!'});

    } catch(err) {
        if(!err.statusCode) {
            err.statusCode = 500;
        }
        return next(err);
    }
};
