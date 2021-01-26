const mongoose = require('mongoose');
const path = require('path');

const defaultAvatarUrl = path.join('public', 'assets', 'avatars', 'default-avatar.png');

const userSchema = new mongoose.Schema({
    type: {
        type: String,
        required: true,
        default: 'user'
    },
    email: {
        type: String,
        required: true
    },
    username: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    avatarUrl: {
        type: String,
        required: true,
        default: defaultAvatarUrl
    },
    verifiedEmail: {
        type: Boolean,
        required: true,
        default: false
    },
    status: String,
    verifyToken: String,
    verifyTokenExpiration: Date,
    resetToken: String,
    resetTokenExpiration: Date
});

module.exports = mongoose.model('User', userSchema);