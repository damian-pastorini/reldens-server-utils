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
        return fs.existsSync(fullPath);
    }

    remove(fullPath)
    {
        try {
            let deletePath = Array.isArray(fullPath) ? this.joinPaths(...fullPath) : fullPath
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
        if(!fs.existsSync(to)){
            return fs.copyFileSync(from, to);
        }
    }

    copyFile(from, to)
    {
        let origin = Array.isArray(from) ? this.joinPaths(...from) : from;
        let dest = Array.isArray(to) ? this.joinPaths(...to) : to;
        if(!this.exists(origin)){
            return false;
        }
        if(!this.exists(dest)){
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
        return fs.readdirSync(folder, options);
    }

    fetchSubFoldersList(folder, options)
    {
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
        try {
            return fs.lstatSync(filePath).isFile();
        } catch (error) {
            this.error = {message: 'Can not check file.', error, filePath};
        }
        return false;
    }

    permissionsCheck(systemPath)
    {
        try {
            let crudTestPath = path.join(systemPath, 'crud-test');
            fs.mkdirSync(crudTestPath, {recursive: true});
            fs.rmSync(crudTestPath);
            return true;
        } catch (error) {
            return false;
        }
    }

    fetchFileJson(filePath)
    {
        let fileContents = this.fetchFileContents(filePath);
        if(!fileContents){
            return false;
        }
        let importedJson = JSON.parse(fileContents);
        if(!importedJson){
            this.error = {message: 'Can not parse data file.', filePath};
            return false;
        }
        return importedJson;
    }

    fetchFileContents(filePath)
    {
        if(!this.isFile(filePath)){
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
        if(!filePath){
            this.error = {message: 'Missing data file.', filePath};
            return false;
        }
        return fs.readFileSync(filePath, {encoding: this.encoding, flag: 'r'});
    }

    async updateFileContents(filePath, contents)
    {
        return fs.writeFileSync(fs.openSync(filePath, 'w+'), contents);
    }

    writeFile(fileName, content)
    {
        try {
            fs.writeFileSync(fileName, content, this.encoding);
            return true;
        } catch (error) {
            this.error = {message: 'Error saving the file.', fileName, error};
        }
        return false;
    }

}

module.exports.FileHandler = new FileHandler();
