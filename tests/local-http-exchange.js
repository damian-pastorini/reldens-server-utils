/**
 *
 * Reldens - Server Utils - LocalHttpExchange
 *
 */

const http = require('http');
const { once } = require('events');

class LocalHttpExchange
{

    constructor()
    {
        this.host = '127.0.0.1';
        this.timeoutMs = 5000;
        this.jsonContentType = 'application/json';
        this.openSockets = new Map();
    }

    async runWithServer(server, exchangeCallback)
    {
        let port = await this.startServer(server);
        try {
            return await exchangeCallback(port);
        } finally {
            await this.stopServer(server);
        }
    }

    async requestServer(server, requestOptions, body)
    {
        let port = await this.startServer(server);
        try {
            return await this.sendRequest(port, requestOptions, body);
        } finally {
            await this.stopServer(server);
        }
    }

    async startServer(server)
    {
        let serverSockets = new Set();
        this.openSockets.set(server, serverSockets);
        server.on('connection', (socket) => {
            serverSockets.add(socket);
            socket.on('close', () => serverSockets.delete(socket));
        });
        server.listen(0, this.host);
        await once(server, 'listening');
        return server.address().port;
    }

    async stopServer(server)
    {
        let serverClosed = once(server, 'close');
        server.close();
        for(let socket of this.openSockets.get(server) || []){
            socket.destroy();
        }
        this.openSockets.delete(server);
        await serverClosed;
        return true;
    }

    async findUnusedPort()
    {
        let server = http.createServer();
        let port = await this.startServer(server);
        await this.stopServer(server);
        return port;
    }

    async sendRequest(port, requestOptions, body)
    {
        let request = http.request(Object.assign({host: this.host, port, agent: false}, requestOptions));
        request.setTimeout(this.timeoutMs, () => request.destroy(new Error('Request timed out: '+requestOptions.path)));
        request.end(body);
        let response = (await once(request, 'response')).shift();
        let chunks = [];
        for await (let chunk of response){
            chunks.push(chunk);
        }
        let exchangeResponse = {
            statusCode: response.statusCode,
            headers: response.headers,
            body: Buffer.concat(chunks),
            json: false
        };
        if(String(response.headers['content-type']).includes(this.jsonContentType)){
            exchangeResponse.json = JSON.parse(String(exchangeResponse.body));
        }
        return exchangeResponse;
    }

    async sendUpgrade(port, path, headers)
    {
        let request = http.request({
            host: this.host,
            port,
            path,
            agent: false,
            headers: Object.assign({'Connection': 'Upgrade', 'Upgrade': 'websocket'}, headers)
        });
        request.setTimeout(this.timeoutMs, () => request.destroy(new Error('Upgrade timed out: '+path)));
        request.end();
        let upgradeArguments = await once(request, 'upgrade');
        let response = upgradeArguments.shift();
        let socket = upgradeArguments.shift();
        socket.setTimeout(0);
        return {statusCode: response.statusCode, socket};
    }

    async exchangeSocketMessage(socket, message)
    {
        socket.setTimeout(this.timeoutMs, () => socket.destroy(new Error('Socket message timed out: '+message)));
        let replyReceived = once(socket, 'data');
        socket.write(message);
        let reply = String((await replyReceived).shift());
        socket.setTimeout(0);
        return reply;
    }

}

module.exports.LocalHttpExchange = LocalHttpExchange;
