const multer = require('multer');
const { v4: uuidv4 } = require('uuid');

function Uploader(req, res, next) {

    // Multer Settings
    const fileStorage = multer.diskStorage({
        destination: (req, file, cb) => {
            if(file.fieldname == 'avatar') {
                cb(null, 'public/assets/avatars');
            } else {
                cb(null, 'public/assets/images');
            }
        },
        filename: (req, file, cb) => {
            cb(null, uuidv4() + '-' + file.originalname);
        }
    });

    const fileFilter = (req, file, cb) => {
        if(file.mimetype === 'image/png' || file.mimetype === 'image/jpeg' || file.mimetype === 'image/jpg') {
            cb(null, true);
        } else {
            cb(null, false);
        }
    }

    const upload = multer({ storage: fileStorage, fileFilter: fileFilter });
    return upload;
}

module.exports = Uploader();