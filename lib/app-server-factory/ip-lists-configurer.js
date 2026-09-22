/**
 *
 * Reldens - IpListsConfigurer
 *
 * Mutable allow and deny address lists consulted at request time, with CIDR matching through the Node BlockList and
 * explicit handling of the IPv4 mapped IPv6 addresses. The entries are pushed from the application, this class has
 * no storage access.
 *
 */

const net = require('net');

class IpListsConfigurer
{

    constructor()
    {
        this.enabled = false;
        this.allowList = new net.BlockList();
        this.denyList = new net.BlockList();
        this.hasAllowEntries = false;
        this.hasDenyEntries = false;
        this.forbiddenMessage = 'Forbidden.';
    }

    setLists(params)
    {
        this.enabled = Boolean(params.enabled);
        this.forbiddenMessage = params.forbiddenMessage || this.forbiddenMessage;
        this.allowList = new net.BlockList();
        this.denyList = new net.BlockList();
        this.hasAllowEntries = this.appendEntries(this.allowList, params.allow || []);
        this.hasDenyEntries = this.appendEntries(this.denyList, params.deny || []);
        return true;
    }

    appendEntries(blockList, entries)
    {
        let appendedEntries = 0;
        for(let entry of entries){
            if(this.appendEntry(blockList, String(entry).trim())){
                appendedEntries++;
            }
        }
        return 0 < appendedEntries;
    }

    appendEntry(blockList, entry)
    {
        if('' === entry){
            return false;
        }
        let entryParts = entry.split('/');
        let entryAddress = this.normalizeAddress(entryParts[0]);
        if(!net.isIP(entryAddress)){
            return false;
        }
        let addressType = net.isIPv6(entryAddress) ? 'ipv6' : 'ipv4';
        if(1 === entryParts.length){
            blockList.addAddress(entryAddress, addressType);
            return true;
        }
        blockList.addSubnet(entryAddress, Number(entryParts[1]), addressType);
        return true;
    }

    normalizeAddress(address)
    {
        let normalizedAddress = String(address || '').trim();
        if(0 === normalizedAddress.indexOf('::ffff:')){
            return normalizedAddress.substring(7);
        }
        return normalizedAddress;
    }

    isAllowed(address)
    {
        if(!this.enabled){
            return true;
        }
        let normalizedAddress = this.normalizeAddress(address);
        if(!net.isIP(normalizedAddress)){
            return true;
        }
        let addressType = net.isIPv6(normalizedAddress) ? 'ipv6' : 'ipv4';
        if(this.hasAllowEntries){
            return this.allowList.check(normalizedAddress, addressType);
        }
        if(!this.hasDenyEntries){
            return true;
        }
        return !this.denyList.check(normalizedAddress, addressType);
    }

    setup(app)
    {
        app.use((req, res, next) => {
            if(this.isAllowed(req.ip)){
                return next();
            }
            return res.status(403).send(this.forbiddenMessage);
        });
        return true;
    }

}

module.exports.IpListsConfigurer = IpListsConfigurer;
