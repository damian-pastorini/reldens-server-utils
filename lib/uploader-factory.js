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
        this.processErrorResponse = props.processErrorResponse || false;
        this.dangerousExtensions = props.dangerousExtensions !== undefined
            ? props.dangerousExtensions
            : ['.exe', '.bat', '.cmd', '.com', '.scr', '.pif', '.vbs', '.js'];
        this.maxFilenameLength = props.maxFilenameLength || 255;
    }

    createUploader(fields, buckets, allowedFileTypes)
    {
        if(!this.validateInputs(fields, buckets, allowedFileTypes)){
            this.error = {message: 'Invalid uploader configuration: ' + this.error.message};
            return false;
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
        diskStorageConfiguration.filename = (req, file, cb) => {
            if(!this.validateFilenameSecurity(file.originalname)){
                return cb(new Error('Invalid filename'));
            }
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
            limits.files = this.fileLimit;
        }
        let upload = multer({
            storage,
            limits,
            fileFilter: (req, file, cb) => {
                return this.validateFile(file, allowedFileTypes[file.fieldname], cb);
            }
        });
        return (req, res, next) => {
            upload.fields(fields)(req, res, async (multerError) => {
                if(multerError){
                    if(multerError instanceof multer.MulterError){
                        if(multerError.code === 'LIMIT_FILE_SIZE'){
                            let messageFile = 'File too large.';
                            if('function' === typeof this.processErrorResponse){
                                return this.processErrorResponse(413, messageFile, req, res);
                            }
                            return res.status(413).send(messageFile);
                        }
                        if(multerError.code === 'LIMIT_FILE_COUNT'){
                            let messageTooMany = 'Too many files.';
                            if('function' === typeof this.processErrorResponse){
                                return this.processErrorResponse(413, messageTooMany, req, res);
                            }
                            return res.status(413).send(messageTooMany);
                        }
                        let messageUpload = 'File upload error.';
                        if('function' === typeof this.processErrorResponse){
                            return this.processErrorResponse(400, messageUpload, multerError, req, res);
                        }
                        return res.status(400).send(messageUpload);
                    }
                    let messageServer = 'Server error during file upload.';
                    if('function' === typeof this.processErrorResponse){
                        return this.processErrorResponse(500, messageServer, req, res);
                    }
                    return res.status(500).send(messageServer);
                }
                if(!req.files){
                    return next();
                }
                let validationResult = await this.validateAllUploadedFiles(req, allowedFileTypes);
                if(!validationResult){
                    this.cleanupFiles(req.files);
                    let messageContents = 'File validation failed.';
                    if('function' === typeof this.processErrorResponse){
                        return this.processErrorResponse(415, messageContents, req, res);
                    }
                    return res.status(415).send(messageContents);
                }
                next();
            });
        };
    }

    async validateAllUploadedFiles(req, allowedFileTypes)
    {
        try {
            for(let fieldName in req.files){
                for(let file of req.files[fieldName]){
                    if(!await this.validateFileContents(file, allowedFileTypes[fieldName])){
                        FileHandler.remove(file.path);
                        return false;
                    }
                }
            }
            return true;
        } catch(error){
            this.error = {message: 'Error processing uploaded files.', error};
            return false;
        }
    }

    validateFilenameSecurity(filename)
    {
        if(!filename || 'string' !== typeof filename){
            return false;
        }
        if(this.maxFilenameLength < filename.length){
            return false;
        }
        let ext = filename.toLowerCase().substring(filename.lastIndexOf('.'));
        if(-1 !== this.dangerousExtensions.indexOf(ext)){
            return false;
        }
        let dangerous = ['../', '..\\', '/', '\\', '<', '>', ':', '*', '?', '"', '|'];
        for(let char of dangerous){
            if(-1 !== filename.indexOf(char)){
                return false;
            }
        }
        return true;
    }

    validateInputs(fields, buckets, allowedFileTypes)
    {
        if(!Array.isArray(fields)){
            this.error = {message: 'Fields must be an array'};
            return false;
        }
        if(!buckets || 'object' !== typeof buckets){
            this.error = {message: 'Buckets must be an object'};
            return false;
        }
        if(!allowedFileTypes || 'object' !== typeof allowedFileTypes){
            this.error = {message: 'AllowedFileTypes must be an object'};
            return false;
        }
        for(let field of fields){
            if(!field.name || 'string' !== typeof field.name){
                this.error = {message: 'Field name is invalid'};
                return false;
            }
            if(!buckets[field.name]){
                this.error = {message: 'Missing bucket for field: ' + field.name};
                return false;
            }
            if(!allowedFileTypes[field.name]){
                this.error = {message: 'Missing allowedFileType for field: ' + field.name};
                return false;
            }
        }
        return true;
    }

    validateFile(file, allowedFileType, cb)
    {
        if(!allowedFileType){
            return cb();
        }
        if(!this.validateFilenameSecurity(file.originalname)){
            this.error = {message: 'Insecure filename: ' + file.originalname};
            return cb(new Error('Insecure filename: ' + file.originalname));
        }
        let fileExtension = FileHandler.extension(file.originalname).toLowerCase();
        let allowedExtensions = this.allowedExtensions[allowedFileType];
        if(allowedExtensions && !allowedExtensions.includes(fileExtension)){
            this.error = {message: 'Invalid file extension: ' + fileExtension};
            return cb(new Error('Invalid file extension: ' + fileExtension));
        }
        let allowedFileTypeRegex = this.convertToRegex(allowedFileType);
        if(!allowedFileTypeRegex){
            this.error = {message: 'File type could not be converted to regex.', allowedFileType};
            return cb(new Error('File type could not be converted to regex'));
        }
        let mimeTypeValid = allowedFileTypeRegex.test(file.mimetype);
        if(!mimeTypeValid){
            this.error = {message: 'Invalid MIME type: ' + file.mimetype};
            return cb(new Error('Invalid MIME type: ' + file.mimetype));
        }
        return cb();
    }

    async validateFileContents(file, allowedFileType)
    {
        if(!FileHandler.isFile(file.path)){
            this.error = {message: 'File path must be provided.', file};
            return false;
        }
        let detectedType = FileHandler.detectFileType(file.path);
        if(detectedType && 'application/octet-stream' !== detectedType){
            let expectedMimeTypes = this.mimeTypes[allowedFileType] || [];
            if(0 < expectedMimeTypes.length && -1 === expectedMimeTypes.indexOf(detectedType)){
                this.error = {
                    message: 'File content type mismatch.',
                    detected: detectedType, expected: expectedMimeTypes
                };
                return false;
            }
        }
        return FileHandler.validateFileType(file.path, allowedFileType, this.allowedExtensions, this.maxFileSize);
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
                FileHandler.remove(file.path);
            }
        }
    }
}

module.exports.UploaderFactory = UploaderFactory;
