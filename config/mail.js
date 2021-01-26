module.exports = {
    smtp: {
        host: process.env.SMTP_HOST,
        port: process.env.SMTP_PORT,
        auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS
        }
    },
    api: {
        api_url: process.env.API_URL,
        api_user: process.env.API_USER,
        api_key: process.env.API_KEY
    },
    general: {
        domain: process.env.EMAIL_DOMAIN,
        noreply_mail: process.env.NOREPLY_EMAIL,
        register_mail: process.env.REGISTER_MAIL,
        reset_mail: process.env.RESET_PASSWORD_MAIL,
        verify_mail: process.env.EMAIL_VERIFICATION_MAIL
    }
};