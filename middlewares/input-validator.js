/*eslint indent: [2, 4, {"SwitchCase": 1}]*/

const { body } = require('express-validator');

exports.validate = (method) => {
    switch(method) {
        case 'register': {
            return [
                body('email', 'Invalid Email Address').exists().trim().isLength({max: 64}).isEmail().normalizeEmail(),
                body('username', 'Username must be between 2-32 Characters, and can only contain Letters, and Numbers').exists().trim().isAlphanumeric().isLength({min: 2, max: 32}),
                body('password', 'Password must be at least 8 characters, and must contain at least one Uppercase letter, one Special character, and one Number').exists().trim().isStrongPassword({minLength: 8, minLowercase: 1, minUppercase: 1, minNumbers: 1, minSymbols: 1})
            ];
        }
        case 'email': {
            return body('email', 'Invalid Email Address').exists().trim().isLength({max: 64}).isEmail().normalizeEmail();
        }
        case 'password': {
            return body('password', 'Password must be at least 8 characters, and must contain at least one Uppercase letter, one Special character, and one Number').exists().trim().isStrongPassword({minLength: 8, minLowercase: 1, minUppercase: 1, minNumbers: 1, minSymbols: 1});
        }
    }
};