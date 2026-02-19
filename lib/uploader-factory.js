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

    setError(message, additionalData = {})
    {
        if(!this.error.message){
            this.error = {message, ...additionalData};
        }
    }

    createUploader(fields, buckets, allowedFileTypes)
    {
        if(!this.validateInputs(fields, buckets, allowedFileTypes)){
            this.setError('Invalid uploader configuration: ' + this.error.message);
            return false;
        }
        let storage = multer.diskStorage({
            destination: (req, file, cb) => {
                try{
                    let dest = buckets[file.fieldname];
                    if(!FileHandler.isValidPath(dest)){
                        this.setError('Invalid destination path', {dest, fieldname: file.fieldname});
                        return cb(new Error('Invalid destination path'));
                    }
                    let folderCreated = FileHandler.createFolder(dest);
                    if(!folderCreated){
                        this.setError('Cannot create destination folder', {dest, fileHandlerError: FileHandler.error});
                        return cb(new Error('Cannot create destination folder'));
                    }
                    cb(null, dest);
                } catch(error){
                    this.setError('Cannot prepare destination.', {error: error});
                    cb(error);
                }
            },
            filename: (req, file, cb) => {
                if(!this.validateFilenameSecurity(file.originalname)){
                    this.setError('Invalid filename', {originalname: file.originalname});
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
            }
        });
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
                        if('LIMIT_FILE_SIZE' === multerError.code){
                            let messageFile = 'File too large.';
                            this.setError(messageFile, {multerError});
                            if('function' === typeof this.processErrorResponse){
                                return this.processErrorResponse(413, messageFile, req, res);
                            }
                            return res.status(413).send(messageFile);
                        }
                        if('LIMIT_FILE_COUNT' === multerError.code){
                            let messageTooMany = 'Too many files.';
                            this.setError(messageTooMany, {multerError});
                            if('function' === typeof this.processErrorResponse){
                                return this.processErrorResponse(413, messageTooMany, req, res);
                            }
                            return res.status(413).send(messageTooMany);
                        }
                        let messageUpload = 'File upload error.';
                        this.setError(messageUpload, {multerError});
                        if('function' === typeof this.processErrorResponse){
                            return this.processErrorResponse(400, messageUpload, multerError, req, res);
                        }
                        return res.status(400).send(messageUpload);
                    }
                    let messageServer = this.error?.message ? this.error.message : 'Server error during file upload.';
                    this.setError(messageServer, {multerError});
                    if('function' === typeof this.processErrorResponse){
                        return this.processErrorResponse(415, messageServer, req, res);
                    }
                    return res.status(415).send(messageServer);
                }
                if(!req.files){
                    return next();
                }
                let validationResult = await this.validateAllUploadedFiles(req, allowedFileTypes);
                if(!validationResult){
                    let filePaths = Object.values(req.files).flat().map(file => file.path);
                    FileHandler.removeMultiple(filePaths);
                    let messageContents = this.error?.message ? this.error.message : 'File validation failed.';
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
                    let validationResult = await this.validateFileContents(file, allowedFileTypes[fieldName]);
                    if(!validationResult){
                        FileHandler.remove(file.path);
                        return false;
                    }
                }
            }
            return true;
        } catch(error){
            this.setError('Error processing uploaded files.', {error});
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
            this.setError('Fields must be an array');
            return false;
        }
        if(!buckets || 'object' !== typeof buckets){
            this.setError('Buckets must be an object');
            return false;
        }
        if(!allowedFileTypes || 'object' !== typeof allowedFileTypes){
            this.setError('AllowedFileTypes must be an object');
            return false;
        }
        for(let field of fields){
            if(!field.name || 'string' !== typeof field.name){
                this.setError('Field name is invalid');
                return false;
            }
            if(!buckets[field.name]){
                this.setError('Missing bucket for field: ' + field.name);
                return false;
            }
            if(!allowedFileTypes[field.name]){
                this.setError('Missing allowedFileType for field: ' + field.name);
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
        if(!this.validateFilenameSecurity(file.originalname)){
            this.setError('Insecure filename: '+file.originalname, {originalname: file.originalname});
            return cb(new Error('Insecure filename: '+file.originalname));
        }
        let fileExtension = FileHandler.extension(file.originalname).toLowerCase();
        let allowedExtensions = this.allowedExtensions && this.allowedExtensions[allowedFileType];
        if(allowedExtensions && !allowedExtensions.includes(fileExtension)){
            this.setError('Invalid file extension: '+fileExtension, {
                extension: fileExtension,
                allowedExtensions,
                allowedFileType,
                filename: file.originalname
            });
            return cb(new Error('Invalid file extension: '+fileExtension));
        }
        let allowedFileTypeRegex = this.convertToRegex(allowedFileType);
        if(!allowedFileTypeRegex){
            this.setError('File type could not be converted to regex.', {allowedFileType});
            return cb(new Error('File type could not be converted to regex'));
        }
        let mimeTypeValid = allowedFileTypeRegex.test(file.mimetype);
        if(!mimeTypeValid){
            this.setError('Invalid MIME type: '+file.mimetype, {
                mimetype: file.mimetype,
                allowedFileType,
                filename: file.originalname,
                regex: allowedFileTypeRegex
            });
            return cb(new Error('Invalid MIME type: '+file.mimetype));
        }
        return cb(null, true);
    }

    async validateFileContents(file, allowedFileType)
    {
        if(!FileHandler.isFile(file.path)){
            this.setError('File path must be provided.', {file});
            return false;
        }
        let detectedType = FileHandler.detectFileType(file.path);
        if(detectedType && 'application/octet-stream' !== detectedType){
            let expectedMimeTypes = this.mimeTypes[allowedFileType] || [];
            if(0 < expectedMimeTypes.length && -1 === expectedMimeTypes.indexOf(detectedType)){
                this.setError('File content type mismatch.', {
                    detected: detectedType,
                    expected: expectedMimeTypes,
                    filename: file.filename,
                    path: file.path,
                    allowedFileType
                });
                return false;
            }
        }
        let typeValidationResult = FileHandler.validateFileType(
            file.path,
            allowedFileType,
            this.allowedExtensions,
            this.maxFileSize
        );
        if(!typeValidationResult){
            this.setError('File type validation failed.', {
                fileHandlerError: FileHandler.error,
                filename: file.filename,
                path: file.path,
                allowedFileType
            });
            return false;
        }
        return true;
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

}

module.exports.UploaderFactory = UploaderFactory;
