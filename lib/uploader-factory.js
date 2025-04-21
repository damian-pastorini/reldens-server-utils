/**
 *
 * Reldens - UploaderFactory
 *
 */

const multer = require('multer');
const { FileHandler } = require('./file-handler');

class UploaderFactory
{

    constructor(props)
    {
        this.mimeTypes = props.mimeTypes;
        this.error = {message: ''};
    }

    createUploader(fields, buckets, allowedFileTypes)
    {
        let storage = multer.diskStorage({
            destination: (req, file, cb) => {
                cb(null, buckets[file.fieldname]);
            },
            filename: (req,file,cb) => {
                cb(null, file.originalname);
            }
        })
        return multer({
            storage,
            fileFilter: (req, file, cb) => {
                return this.checkFileType(file, allowedFileTypes[file.fieldname], cb);
            }
        }).fields(fields);
    }

    checkFileType(file, allowedFileTypes, cb)
    {
        if(!allowedFileTypes){
            return cb(null, true);
        }
        let allowedFileTypeCheck = this.convertToRegex(allowedFileTypes);
        if(!allowedFileTypeCheck){
            this.error = {message: 'File type could not be converted to regex.', allowedFileTypes};
            return cb(null, false);
        }
        let extension = allowedFileTypeCheck.test(FileHandler.extension(file.originalname).toLowerCase());
        let mimeType = allowedFileTypeCheck.test(file.mimetype);
        if(mimeType && extension){
            return cb(null, true);
        }
        this.error = {message: 'File type not supported.', extension, mimeType, allowedFileTypes};
        return cb(null, false);
    }

    convertToRegex(key)
    {
        if(!this.mimeTypes[key]){
            return false;
        }
        let types = this.mimeTypes[key].map(type => type.split('/').pop().replace('+', '\\+'));
        return new RegExp(types.join('|'));
    }

}

module.exports.UploaderFactory = UploaderFactory;
