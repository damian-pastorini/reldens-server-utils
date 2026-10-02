/**
 *
 * Reldens - PackageResolver
 *
 */

class PackageResolver
{

    constructor()
    {
        this.error = {message: ''};
    }

    loadPackage(packageName, projectPath)
    {
        this.error = {message: ''};
        try {
            return require(this.resolvePath(packageName, projectPath));
        } catch(error) {
            this.error = {
                message: 'Package "'+packageName+'" not found, install it in the project: npm install '+packageName,
                packageName,
                projectPath,
                error: error.message
            };
            return false;
        }
    }

    resolvePath(packageName, projectPath)
    {
        if(!projectPath){
            return packageName;
        }
        return require.resolve(packageName, {paths: [projectPath]});
    }

}

module.exports.PackageResolver = new PackageResolver();
