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
        this.mimeTypes = props.mimeTypes || {};
        this.error = {message: ''};
        this.maxFileSize = props.maxFileSize || 20 * 1024 * 1024;
        this.fileLimit = props.fileLimit || 0;
        this.allowedExtensions = props.allowedExtensions;
        this.applySecureFileNames = props.applySecureFileNames;
        this.processErrorResponse = props.processErrorResponse || function(status, message, req, res) {
            return { status, message, handled: false };
        };
    }

    createUploader(fields, buckets, allowedFileTypes)
    {
        if(!this.validateInputs(fields, buckets, allowedFileTypes)){
            throw new Error('Invalid uploader configuration: ' + this.error.message);
        }
        let diskStorageConfiguration = {
            destination: (req, file, cb) => {
                let dest = buckets[file.fieldname];
                if(!FileHandler.isValidPath(dest)){
                    return cb(new Error('Invalid destination path'));
                }
                FileHandler.createFolder(dest);
                cb(null, dest);
            }
        };
        diskStorageConfiguration['filename'] = (req, file, cb) => {
            if(!this.applySecureFileNames) {
                cb(null, file.originalname);
                return;
            }
            let secureFilename = FileHandler.generateSecureFilename(file.originalname);
            if(!req.fileNameMapping){
                req.fileNameMapping = {};
            }
            req.fileNameMapping[secureFilename] = file.originalname;
            cb(null, secureFilename);
        };
        let storage = multer.diskStorage(diskStorageConfiguration);
        let limits = {
            fileSize: this.maxFileSize
        };
        if(0 < this.fileLimit){
            limits['files'] = this.fileLimit;
        }
        let upload = multer({
            storage,
            limits,
            fileFilter: (req, file, cb) => {
                return this.validateFile(file, allowedFileTypes[file.fieldname], cb);
            }
        });
        return (req, res, next) => {
            upload.fields(fields)(req, res, async (err) => {
                if(err){
                    if(err instanceof multer.MulterError){
                        if(err.code === 'LIMIT_FILE_SIZE'){
                            let result = this.processErrorResponse(413, 'File too large.', req, res);
                            if(result.handled){
                                return;
                            }
                            return res.status(result.status).send(result.message);
                        }
                        if(err.code === 'LIMIT_FILE_COUNT'){
                            let result = this.processErrorResponse(413, 'Too many files.', req, res);
                            if(result.handled){
                                return;
                            }
                            return res.status(result.status).send(result.message);
                        }
                        let result = this.processErrorResponse(400, 'File upload error: ' + err.message, req, res);
                        if(result.handled){
                            return;
                        }
                        return res.status(result.status).send(result.message);
                    }
                    let result = this.processErrorResponse(500, 'Server error during file upload.', req, res);
                    if(result.handled){
                        return;
                    }
                    return res.status(result.status).send(result.message);
                }
                if(!req.files){
                    return next();
                }
                try {
                    for(let fieldName in req.files){
                        for(let file of req.files[fieldName]){
                            if(!await this.validateFileContents(file, allowedFileTypes[fieldName])){
                                if(FileHandler.exists(file.path)){
                                    FileHandler.remove(file.path);
                                }
                                let result = this.processErrorResponse(
                                    415,
                                    'File contents do not match declared type.', req, res
                                );
                                if(result.handled){
                                    return;
                                }
                                return res.status(result.status).send(result.message);
                            }
                        }
                    }
                    next();
                } catch(error){
                    this.error = {message: 'File validation error.', error};
                    this.cleanupFiles(req.files);
                    let result = this.processErrorResponse(500, 'Error processing uploaded files.', req, res);
                    if(result.handled){
                        return;
                    }
                    return res.status(result.status).send(result.message);
                }
            });
        };
    }

    validateInputs(fields, buckets, allowedFileTypes)
    {
        if(!Array.isArray(fields)){
            this.error = {message: 'Fields must be an array'};
            return false;
        }
        if(!buckets || typeof buckets !== 'object'){
            this.error = {message: 'Buckets must be an object'};
            return false;
        }
        if(!allowedFileTypes || typeof allowedFileTypes !== 'object'){
            this.error = {message: 'AllowedFileTypes must be an object'};
            return false;
        }
        for(let field of fields){
            if(!field.name || typeof field.name !== 'string'){
                this.error = {message: 'Field name is invalid'};
                return false;
            }
            if(!buckets[field.name]){
                this.error = {message: `Missing bucket for field: ${field.name}`};
                return false;
            }
            if(!allowedFileTypes[field.name]){
                this.error = {message: `Missing allowedFileType for field: ${field.name}`};
                return false;
            }
        }
        return true;
    }

    validateFile(file, allowedFileType, cb)
    {
        if(!allowedFileType){
            return cb(null, true);
        }
        let fileExtension = FileHandler.extension(file.originalname).toLowerCase();
        let allowedExtensions = this.allowedExtensions[allowedFileType];
        if(allowedExtensions && !allowedExtensions.includes(fileExtension)){
            this.error = {message: `Invalid file extension: ${fileExtension}`};
            return cb(null, false);
        }
        let allowedFileTypeRegex = this.convertToRegex(allowedFileType);
        if(!allowedFileTypeRegex){
            this.error = {message: 'File type could not be converted to regex.', allowedFileType};
            return cb(null, false);
        }
        let mimeTypeValid = allowedFileTypeRegex.test(file.mimetype);
        if(!mimeTypeValid){
            this.error = {message: `Invalid MIME type: ${file.mimetype}`};
            return cb(null, false);
        }
        return cb(null, true);
    }

    async validateFileContents(file, allowedFileType)
    {
        try {
            if(!FileHandler.isFile(file.path)){
                this.error = {message: 'File path must be provided.', file};
                return false;
            }
            return FileHandler.validateFileType(file.path, allowedFileType, this.allowedExtensions, this.maxFileSize);
        } catch(error){
            this.error = {message: 'Error validating file contents.', error};
            return false;
        }
    }

    convertToRegex(key)
    {
        if(!this.mimeTypes[key]){
            return false;
        }
        let types = this.mimeTypes[key].map(type =>
            type.split('/').pop().replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
        );
        return new RegExp(types.join('|'));
    }

    cleanupFiles(files)
    {
        if(!files){
            return;
        }
        for(let fieldName in files){
            for(let file of files[fieldName]){
                try {
                    if(FileHandler.exists(file.path)){
                        FileHandler.remove(file.path);
                    }
                } catch(error){
                    this.error = {message: 'Error cleaning up file.', error};
                }
            }
        }
    }
}

module.exports.UploaderFactory = UploaderFactory;
