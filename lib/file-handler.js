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
    }

    joinPaths(...args)
    {
        return path.join(...args);
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
        return !(pathStr.includes('../') || pathStr.includes('..\\'));
    }

    sanitizePath(filePath)
    {
        if(!filePath){
            return '';
        }
        return String(filePath)
            .replace(/\.\./g, '')
            .replace(/[:*?"<>|]/g, '')
            .substring(0, 255);
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

    remove(fullPath)
    {
        try {
            if(!this.isValidPath(fullPath)){
                this.error = {message: 'Invalid path for removal.', fullPath};
                return false;
            }
            let deletePath = Array.isArray(fullPath) ? this.joinPaths(...fullPath) : fullPath;
            if(fs.existsSync(deletePath)){
                fs.rmSync(deletePath, {recursive: true, force: true});
                return true;
            }
        } catch (error) {
            this.error = {message: 'Failed to remove folder.', error, fullPath};
        }
        return false;
    }

    createFolder(folderPath)
    {
        try {
            if(!this.isValidPath(folderPath)){
                this.error = {message: 'Invalid folder path.', folderPath};
                return false;
            }
            if(fs.existsSync(folderPath)){
                return true;
            }
            fs.mkdirSync(folderPath, {recursive: true});
            return true;
        } catch (error) {
            this.error = {message: 'Failed to create folder.', error, folderPath};
        }
        return false;
    }

    copyFolderSync(from, to)
    {
        try {
            if(!this.isValidPath(from) || !this.isValidPath(to)){
                this.error = {message: 'Invalid path for folder copy.', from, to};
                return false;
            }
            fs.mkdirSync(to, {recursive: true});
            let folders = fs.readdirSync(from);
            for(let element of folders){
                let elementPath = path.join(from, element);
                if(!fs.existsSync(elementPath)){
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
        }
        return false;
    }

    copyFileSyncIfDoesNotExist(from, to)
    {
        if(!this.isValidPath(from) || !this.isValidPath(to)){
            this.error = {message: 'Invalid path for file copy.', from, to};
            return false;
        }
        if(!fs.existsSync(to)){
            return fs.copyFileSync(from, to);
        }
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
        }
        return false;
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
        }
        return false;
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
        }
        return false;
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
        try {
            let fileContent = this.readFile(filePath);
            if(!fileContent){
                this.error = {message: 'Can not read data or empty file.', filePath};
                return false;
            }
            return fileContent;
        } catch(error){
            this.error = {message: 'Error reading file.', filePath, error};
            return false;
        }
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
            return fs.writeFileSync(fs.openSync(filePath, 'w+'), contents);
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
        }
        return false;
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

}

module.exports.FileHandler = new FileHandler();
