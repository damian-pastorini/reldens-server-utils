/**
 *
 * Reldens - FileHandler
 *
 */

const path = require('path');
const fs = require('fs');

class FileHandler
{

    constructor()
    {
        this.encoding = (process.env.RELDENS_DEFAULT_ENCODING || 'utf8');
        this.sep = path.sep;
        this.error = {message: ''};
        this.maxPathLength = 2048;
        this.dangerousPatterns = [
            '../', '..\\', './', '.\\',
            '/etc/', '/proc/', '/sys/',
            'C:\\Windows\\', 'C:\\System32\\',
            '%2e%2e%2f', '%2e%2e%5c'
        ];
        this.nativeHandler = fs;
        this.nativePaths = path;
    }

    joinPaths(...args)
    {
        return path.join(...args);
    }

    getFileName(filePath)
    {
        if(!this.isValidPath(filePath)){
            this.error = {message: 'Invalid file path.', filePath};
            return false;
        }
        return path.basename(filePath);
    }

    getFolderName(filePath)
    {
        if(!this.isValidPath(filePath)){
            this.error = {message: 'Invalid file path.', filePath};
            return false;
        }
        return path.dirname(filePath);
    }

    exists(fullPath)
    {
        if(!this.isValidPath(fullPath)){
            this.error = {message: 'Invalid path.', fullPath};
            return false;
        }
        return fs.existsSync(fullPath);
    }

    isValidPath(filePath)
    {
        if(!filePath){
            return false;
        }
        let pathStr = String(filePath);
        if(this.maxPathLength < pathStr.length){
            return false;
        }
        let normalized = pathStr.replace(/\\/g, '/');
        for(let pattern of this.dangerousPatterns){
            if(normalized.toLowerCase().includes(pattern.toLowerCase())){
                return false;
            }
        }
        return true;
    }

    sanitizePath(filePath)
    {
        if(!filePath){
            return '';
        }
        return String(filePath)
            .replace(/\.\./g, '')
            .replace(/[:*?"<>|]/g, '')
            .substring(0, this.maxPathLength);
    }

    generateSecureFilename(originalName)
    {
        let ext = path.extname(originalName).toLowerCase();
        let randomStr = '';
        let chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
        let charLength = chars.length;
        for(let i = 0; i < 32; i++){
            randomStr += chars.charAt(Math.floor(Math.random() * charLength));
        }
        return randomStr + ext;
    }

    getFileStats(filePath)
    {
        if(!this.isValidPath(filePath)){
            this.error = {message: 'Invalid file path.', filePath};
            return false;
        }
        if(!this.exists(filePath)){
            this.error = {message: 'File does not exist.', filePath};
            return false;
        }
        try {
            return fs.statSync(filePath);
        } catch (error) {
            this.error = {message: 'Failed to get file stats.', error, filePath};
            return false;
        }
    }

    getFileModificationTime(filePath)
    {
        let stats = this.getFileStats(filePath);
        if(!stats){
            return false;
        }
        return stats.mtime;
    }

    remove(fullPath)
    {
        let deletePath = Array.isArray(fullPath) ? this.joinPaths(...fullPath) : fullPath;
        if(!this.exists(deletePath)){
            return true;
        }
        try {
            fs.rmSync(deletePath, {recursive: true, force: true});
            return true;
        } catch (error) {
            this.error = {message: 'Failed to remove folder.', error, fullPath};
            return false;
        }
    }

    createFolder(folderPath)
    {
        if(!this.isValidPath(folderPath)){
            this.error = {message: 'Invalid folder path.', folderPath};
            return false;
        }
        if(this.exists(folderPath)){
            return true;
        }
        try {
            fs.mkdirSync(folderPath, {recursive: true});
            return true;
        } catch (error) {
            this.error = {message: 'Failed to create folder.', error, folderPath};
            return false;
        }
    }

    copyFolderSync(from, to)
    {
        if(!this.isValidPath(from) || !this.isValidPath(to)){
            this.error = {message: 'Invalid path for folder copy.', from, to};
            return false;
        }
        try {
            fs.mkdirSync(to, {recursive: true});
            let folders = fs.readdirSync(from);
            for(let element of folders){
                let elementPath = path.join(from, element);
                if(!this.exists(elementPath)){
                    continue;
                }
                if(fs.lstatSync(elementPath).isFile()){
                    fs.copyFileSync(elementPath, path.join(to, element));
                    continue;
                }
                this.copyFolderSync(elementPath, path.join(to, element));
            }
            return true;
        } catch (error) {
            this.error = {message: 'Failed to copy folder.', error, from, to};
            return false;
        }
    }

    copyFileSyncIfDoesNotExist(from, to)
    {
        if(!this.isValidPath(from) || !this.isValidPath(to)){
            this.error = {message: 'Invalid path for file copy.', from, to};
            return false;
        }
        if(!this.exists(to)){
            try {
                fs.copyFileSync(from, to);
                return true;
            } catch (error) {
                this.error = {message: 'Failed to copy file.', error, from, to};
                return false;
            }
        }
        return true;
    }

    copyFile(from, to)
    {
        if(!this.isValidPath(from) || !this.isValidPath(to)){
            this.error = {message: 'Invalid path for file copy.', from, to};
            return false;
        }
        let origin = Array.isArray(from) ? this.joinPaths(...from) : from;
        let dest = Array.isArray(to) ? this.joinPaths(...to) : to;
        if(!this.exists(origin)){
            this.error = {message: 'Failed to copy file, origin does not exists.', from, to, origin, dest};
            return false;
        }
        try {
            fs.copyFileSync(origin, dest);
            return true;
        } catch (error) {
            this.error = {message: 'Failed to copy file.', error, from, to, origin, dest};
            return false;
        }
    }

    extension(filePath)
    {
        return path.extname(filePath);
    }

    readFolder(folder, options)
    {
        if(!this.isValidPath(folder)){
            this.error = {message: 'Invalid folder path.', folder};
            return [];
        }
        return fs.readdirSync(folder, options);
    }

    fetchSubFoldersList(folder, options)
    {
        if(!this.isValidPath(folder)){
            this.error = {message: 'Invalid folder path.', folder};
            return [];
        }
        let files = fs.readdirSync(folder, options);
        let subFolders = [];
        for(let file of files){
            let filePath = path.join(folder, file);
            if(fs.lstatSync(filePath).isDirectory()){
                subFolders.push(file);
            }
        }
        return subFolders;
    }

    isFile(filePath)
    {
        if(!this.isValidPath(filePath)){
            this.error = {message: 'Invalid file path.', filePath};
            return false;
        }
        try {
            return fs.lstatSync(filePath).isFile();
        } catch (error) {
            this.error = {message: 'Can not check file.', error, filePath};
            return false;
        }
    }

    isFolder(dirPath)
    {
        if(!this.isValidPath(dirPath)){
            this.error = {message: 'Invalid folder path.', dirPath};
            return false;
        }
        if(!this.exists(dirPath)){
            return false;
        }
        try {
            return fs.lstatSync(dirPath).isDirectory();
        } catch (error) {
            this.error = {message: 'Can not check folder.', error, dirPath};
            return false;
        }
    }

    getFilesInFolder(dirPath, extensions = [])
    {
        if(!this.isValidPath(dirPath)){
            this.error = {message: 'Invalid folder path.', dirPath};
            return [];
        }
        let files = this.readFolder(dirPath);
        if(0 === files.length){
            return [];
        }
        let result = [];
        for(let file of files){
            let filePath = path.join(dirPath, file);
            if(!this.isFile(filePath)){
                continue;
            }
            if(0 === extensions.length){
                result.push(file);
                continue;
            }
            for(let ext of extensions){
                if(file.endsWith(ext)){
                    result.push(file);
                    break;
                }
            }
        }
        return result;
    }

    permissionsCheck(systemPath)
    {
        if(!this.isValidPath(systemPath)){
            this.error = {message: 'Invalid system path.', systemPath};
            return false;
        }
        try {
            let crudTestPath = path.join(systemPath, 'crud-test');
            fs.mkdirSync(crudTestPath, {recursive: true});
            fs.rmSync(crudTestPath);
            return true;
        } catch (error) {
            this.error = {message: 'Failed to check permissions.', error, systemPath};
            return false;
        }
    }

    fetchFileJson(filePath)
    {
        if(!this.isValidPath(filePath)){
            this.error = {message: 'Invalid file path.', filePath};
            return false;
        }
        let fileContents = this.fetchFileContents(filePath);
        if(!fileContents){
            this.error = {message: 'Failed to fetch file contents.', filePath};
            return false;
        }
        try {
            return JSON.parse(fileContents);
        } catch(error){
            this.error = {message: 'Can not parse data file.', filePath, error};
            return false;
        }
    }

    fetchFileContents(filePath)
    {
        if(!this.isValidPath(filePath)){
            this.error = {message: 'Invalid file path.', filePath};
            return false;
        }
        if(!this.isFile(filePath)){
            this.error = {message: 'File check failed to fetch file contents.', filePath};
            return false;
        }
        let fileContent = this.readFile(filePath);
        if(!fileContent){
            this.error = {message: 'Can not read data or empty file.', filePath};
            return false;
        }
        return fileContent;
    }

    readFile(filePath)
    {
        if(!this.isValidPath(filePath)){
            this.error = {message: 'Invalid file path.', filePath};
            return false;
        }
        if(!filePath){
            this.error = {message: 'Missing data file.', filePath};
            return false;
        }
        try {
            return fs.readFileSync(filePath, {encoding: this.encoding, flag: 'r'});
        } catch(error){
            this.error = {message: 'Error reading file.', filePath, error};
            return false;
        }
    }

    async updateFileContents(filePath, contents)
    {
        if(!this.isValidPath(filePath)){
            this.error = {message: 'Invalid file path.', filePath};
            return false;
        }
        try {
            fs.writeFileSync(fs.openSync(filePath, 'w+'), contents);
            return true;
        } catch(error){
            this.error = {message: 'Error updating file.', filePath, error};
            return false;
        }
    }

    writeFile(fileName, content)
    {
        if(!this.isValidPath(fileName)){
            this.error = {message: 'Invalid file name.', fileName};
            return false;
        }
        try {
            fs.writeFileSync(fileName, content, this.encoding);
            return true;
        } catch (error) {
            this.error = {message: 'Error saving the file.', fileName, error};
            return false;
        }
    }

    validateFileType(filePath, allowedType, allowedFileTypes, maxFileSize)
    {
        if(!this.isFile(filePath)){
            return false;
        }
        let extension = path.extname(filePath).toLowerCase();
        let allowedExtensions = allowedFileTypes[allowedType] || allowedFileTypes.any;
        if(0 === allowedExtensions.length){
            return true;
        }
        if(!allowedExtensions.includes(extension)){
            this.error = {message: 'Invalid file extension.', extension, allowedType};
            return false;
        }
        let fileSize = fs.statSync(filePath).size;
        if(fileSize > maxFileSize){
            this.error = {message: 'File too large.', fileSize, maxFileSize};
            return false;
        }
        return true;
    }

    isValidJson(filePath)
    {
        if(!this.isFile(filePath)){
            return false;
        }
        try {
            JSON.parse(this.readFile(filePath));
            return true;
        } catch(error){
            this.error = {message: 'Invalid JSON file.', filePath, error};
            return false;
        }
    }

    getFirstFileBytes(filePath, bytes = 4100)
    {
        if(!this.isFile(filePath)){
            return null;
        }
        let fd;
        try {
            fd = fs.openSync(filePath, 'r');
            let buffer = Buffer.alloc(bytes);
            let bytesRead = fs.readSync(fd, buffer, 0, bytes, 0);
            fs.closeSync(fd);
            return buffer.slice(0, bytesRead);
        } catch(err){
            if(fd !== undefined){
                try {
                    fs.closeSync(fd);
                } catch(e){
                }
            }
            this.error = {message: 'Error reading file head.', filePath, error: err};
            return null;
        }
    }

    detectFileType(filePath)
    {
        let buffer = this.getFirstFileBytes(filePath, 16);
        if(!buffer){
            return false;
        }
        let signatures = {
            'image/jpeg': [0xFF, 0xD8, 0xFF],
            'image/png': [0x89, 0x50, 0x4E, 0x47],
            'image/gif': [0x47, 0x49, 0x46, 0x38],
            'application/pdf': [0x25, 0x50, 0x44, 0x46],
            'application/zip': [0x50, 0x4B, 0x03, 0x04]
        };
        for(let mimeType of Object.keys(signatures)){
            let signature = signatures[mimeType];
            let matches = true;
            for(let i = 0; i < signature.length; i++){
                if(buffer[i] !== signature[i]){
                    matches = false;
                    break;
                }
            }
            if(matches){
                return mimeType;
            }
        }
        return 'application/octet-stream';
    }

    quarantineFile(filePath, reason = 'security')
    {
        let quarantineDir = this.joinPaths(process.cwd(), 'quarantine');
        this.createFolder(quarantineDir);
        let timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        let quarantinePath = this.joinPaths(
            quarantineDir,
            timestamp + '-' + reason + '-' + path.basename(filePath)
        );
        return this.copyFile(filePath, quarantinePath);
    }

    createTempFile(prefix = 'temp', extension = '.tmp')
    {
        let tempDir = require('os').tmpdir();
        let fileName = prefix + '-' + this.generateSecureFilename('file' + extension);
        return this.joinPaths(tempDir, fileName);
    }

    moveFile(from, to)
    {
        if(!this.isValidPath(from) || !this.isValidPath(to)){
            this.error = {message: 'Invalid path for file move.', from, to};
            return false;
        }
        if(!this.exists(from)){
            this.error = {message: 'Source file does not exist.', from};
            return false;
        }
        try {
            fs.renameSync(from, to);
            return true;
        } catch (error) {
            this.error = {message: 'Failed to move file.', error, from, to};
            return false;
        }
    }

    getFileSize(filePath)
    {
        if(!this.isValidPath(filePath)){
            this.error = {message: 'Invalid file path.', filePath};
            return false;
        }
        if(!this.exists(filePath)){
            this.error = {message: 'File does not exist.', filePath};
            return false;
        }
        try {
            return fs.statSync(filePath).size;
        } catch (error) {
            this.error = {message: 'Failed to get file size.', error, filePath};
            return false;
        }
    }

    compareFiles(file1, file2)
    {
        if(!this.isValidPath(file1) || !this.isValidPath(file2)){
            this.error = {message: 'Invalid file paths for comparison.', file1, file2};
            return false;
        }
        if(!this.exists(file1) || !this.exists(file2)){
            this.error = {message: 'One or both files do not exist.', file1, file2};
            return false;
        }
        try {
            let content1 = this.readFile(file1);
            let content2 = this.readFile(file2);
            if(!content1 || !content2){
                return false;
            }
            return content1 === content2;
        } catch (error) {
            this.error = {message: 'Failed to compare files.', error, file1, file2};
            return false;
        }
    }

    getRelativePath(from, to)
    {
        if(!this.isValidPath(from) || !this.isValidPath(to)){
            this.error = {message: 'Invalid paths for relative calculation.', from, to};
            return false;
        }
        try {
            return path.relative(from, to);
        } catch (error) {
            this.error = {message: 'Failed to calculate relative path.', error, from, to};
            return false;
        }
    }

    isAbsolutePath(filePath)
    {
        if(!this.isValidPath(filePath)){
            this.error = {message: 'Invalid file path.', filePath};
            return false;
        }
        return path.isAbsolute(filePath);
    }

    normalizePath(filePath)
    {
        if(!filePath){
            this.error = {message: 'Path cannot be empty.', filePath};
            return false;
        }
        try {
            return path.normalize(filePath);
        } catch (error) {
            this.error = {message: 'Failed to normalize path.', error, filePath};
            return false;
        }
    }

    walkDirectory(dirPath, callback)
    {
        if(!this.isValidPath(dirPath)){
            this.error = {message: 'Invalid directory path.', dirPath};
            return false;
        }
        if(!this.isFolder(dirPath)){
            this.error = {message: 'Path is not a directory.', dirPath};
            return false;
        }
        if('function' !== typeof callback){
            this.error = {message: 'Callback must be a function.', dirPath};
            return false;
        }
        try {
            let items = this.readFolder(dirPath);
            for(let item of items){
                let itemPath = this.joinPaths(dirPath, item);
                callback(itemPath);
                if(this.isFolder(itemPath)){
                    this.walkDirectory(itemPath, callback);
                }
            }
            return true;
        } catch (error) {
            this.error = {message: 'Failed to walk directory.', error, dirPath};
            return false;
        }
    }

    getDirectorySize(dirPath)
    {
        if(!this.isValidPath(dirPath)){
            this.error = {message: 'Invalid directory path.', dirPath};
            return false;
        }
        if(!this.isFolder(dirPath)){
            this.error = {message: 'Path is not a directory.', dirPath};
            return false;
        }
        let totalSize = 0;
        let calculateSize = (itemPath) => {
            if(this.isFile(itemPath)){
                let size = this.getFileSize(itemPath);
                if(false !== size){
                    totalSize += size;
                }
            }
        };
        let walkResult = this.walkDirectory(dirPath, calculateSize);
        if(!walkResult){
            return false;
        }
        return totalSize;
    }

    emptyDirectory(dirPath)
    {
        if(!this.isValidPath(dirPath)){
            this.error = {message: 'Invalid directory path.', dirPath};
            return false;
        }
        if(!this.isFolder(dirPath)){
            this.error = {message: 'Path is not a directory.', dirPath};
            return false;
        }
        try {
            let items = this.readFolder(dirPath);
            for(let item of items){
                let itemPath = this.joinPaths(dirPath, item);
                this.remove(itemPath);
            }
            return true;
        } catch (error) {
            this.error = {message: 'Failed to empty directory.', error, dirPath};
            return false;
        }
    }

    appendToFile(filePath, content)
    {
        if(!this.isValidPath(filePath)){
            this.error = {message: 'Invalid file path.', filePath};
            return false;
        }
        try {
            fs.appendFileSync(filePath, content, this.encoding);
            return true;
        } catch (error) {
            this.error = {message: 'Failed to append to file.', error, filePath};
            return false;
        }
    }

    prependToFile(filePath, content)
    {
        if(!this.isValidPath(filePath)){
            this.error = {message: 'Invalid file path.', filePath};
            return false;
        }
        if(!this.exists(filePath)){
            return this.writeFile(filePath, content);
        }
        let existingContent = this.readFile(filePath);
        if(!existingContent){
            return false;
        }
        return this.writeFile(filePath, content + existingContent);
    }

    replaceInFile(filePath, searchValue, replaceValue)
    {
        if(!this.isValidPath(filePath)){
            this.error = {message: 'Invalid file path.', filePath};
            return false;
        }
        if(!this.exists(filePath)){
            this.error = {message: 'File does not exist.', filePath};
            return false;
        }
        let content = this.readFile(filePath);
        if(!content){
            return false;
        }
        return this.writeFile(filePath, content.replace(searchValue, replaceValue));
    }

}

module.exports.FileHandler = new FileHandler();
