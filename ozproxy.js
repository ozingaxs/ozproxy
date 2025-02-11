const express = require('express');
const httpProxy = require('http-proxy');
const http = require('http');
const { PassThrough } = require('stream');
const querystring = require('querystring');
const path = require('path');

// Create the Express app.
const app = express();
const router = express.Router();

// Configure EJS as the view engine.
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Arrays to collect log messages for HTTP and WebSocket events.
const httpLogs = [];
const wsLogs = [];

// Create a proxy server that supports WebSocket upgrades.
const proxy = httpProxy.createProxyServer({ ws: true, changeOrigin: true });

// ─────────────────────────────────────────────
// PROXY EVENT HANDLERS
// ─────────────────────────────────────────────

// Intercept outgoing HTTP request headers and override the Origin header.
proxy.on('proxyReq', (proxyReq, req, res, options) => {
  const logMsg = `[Proxy] Outgoing Request Headers for ${req.method} ${req.url}: ${JSON.stringify(req.headers)}`;
  console.log(logMsg);
  httpLogs.push(logMsg);

  //If an Origin header exists and we have a target defined in options,
  // override it with the target's origin.
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

// Log responses from the target.
proxy.on('proxyRes', (proxyRes, req, res) => {
  const logMsg = `[Proxy] Received response for ${req.method} ${req.url} with headers: ${JSON.stringify(proxyRes.headers)}`;
  console.log(logMsg);
  httpLogs.push(logMsg);
});

// Log any proxy errors.
proxy.on('error', (err, req, res) => {
  const logMsg = `[Proxy] Error encountered: ${err.message}`;
  console.error(logMsg);
  httpLogs.push(logMsg);
});

// ─────────────────────────────────────────────
// EXPRESS MIDDLEWARE FOR HTTP REQUESTS
// ─────────────────────────────────────────────

// Global logging of HTTP requests.
app.use((req, res, next) => {
  const logMsg = `[HTTP] ${req.method} ${req.url} with headers: ${JSON.stringify(req.headers)}`;
  console.log(logMsg);
  httpLogs.push(logMsg);
  next();
});

// Middleware to intercept and modify POST (or other body‑carrying) requests.
app.use((req, res, next) => {
  const methodsWithBody = ['POST', 'PUT', 'PATCH', 'DELETE'];
  if (methodsWithBody.includes(req.method)) {
    let bodyData = [];
    req.on('data', (chunk) => {
      bodyData.push(chunk);
    });
    req.on('end', () => {
      if (bodyData.length > 0) {
        let bodyBuffer = Buffer.concat(bodyData);
        let bodyStr = bodyBuffer.toString('utf8');
        const originalMsg = `[HTTP] Original Request Body for ${req.method} ${req.url}: ${bodyStr}`;
        console.log(originalMsg);
        httpLogs.push(originalMsg);

        // If the content type is URL-encoded, parse and modify.
        if (
          req.headers['content-type'] &&
          req.headers['content-type'].includes('application/x-www-form-urlencoded')
        ) {
          let parsedBody = querystring.parse(bodyStr);

          // Example modifications:
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

          // Reassemble the modified body.
          bodyStr = querystring.stringify(parsedBody);
          bodyBuffer = Buffer.from(bodyStr, 'utf8');
          httpLogs.push(`[HTTP] Modified Request Body: ${bodyStr}`);
        }

        // Attach the (possibly modified) body as a stream for the proxy.
        req.bodyBuffer = new PassThrough();
        req.bodyBuffer.end(bodyBuffer);
      }
      next();
    });
  } else {
    next();
  }
});

// Middleware to wrap res.write/res.end to capture and log HTTP responses.
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

// ─────────────────────────────────────────────
// HTTP ROUTE HANDLERS
// ─────────────────────────────────────────────

// Handler for all non‑static HTTP requests.
const proxyHttp = (req, res) => {
  console.log('[HTTP Proxy] Forwarding HTTP request...');
  const target = 'http://192.168.1.7:8000/'; // Fixed backend target
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

  // Forward CSRF token header if present.
  const csrfToken = req.headers['x-csrf-token'] || req.headers['csrf-token'];
  if (csrfToken) {
    options.headers['x-csrf-token'] = csrfToken;
  }

  if (req.bodyBuffer) {
    options.buffer = req.bodyBuffer;
  }

  proxy.web(req, res, options);
};

// Handler for static content.
const proxyStatic = (req, res) => {
  console.log('[HTTP Proxy] Forwarding static HTTP request...');
  const target = 'http://192.168.1.7:8000/static/';
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
  if (csrfToken) {
    options.headers['x-csrf-token'] = csrfToken;
  }

  if (req.bodyBuffer) {
    options.buffer = req.bodyBuffer;
  }

  proxy.web(req, res, options);
};

// Mount the HTTP route handlers.
router.use('/static', proxyStatic);
router.use('/', proxyHttp);
app.use(router);

// ─────────────────────────────────────────────
// WEBSOCKET INTERCEPTION AND PROXYING
// ─────────────────────────────────────────────

const fixedTarget = 'http://192.168.1.7:8000'; // Fixed backend target for WebSocket

// Listen for WebSocket upgrade events.
const server = http.createServer(app);

server.on('upgrade', (req, socket, head) => {
  const logMsg = `[WS] Upgrade request for ${req.url} from ${req.socket.remoteAddress}`;
  console.log(logMsg);
  wsLogs.push(logMsg);
  console.log('[WS] Request Headers:', req.headers);
  wsLogs.push(`[WS] Request Headers: ${JSON.stringify(req.headers)}`);

  // Intercept inbound WebSocket data.
  socket.on('data', (chunk) => {
    const dataMsg = `[WS] Client -> Proxy data: ${chunk.toString('utf8')}`;
    console.log(dataMsg);
    wsLogs.push(dataMsg);
  });

  // Intercept outbound WebSocket data by wrapping socket.write.
  const originalWrite = socket.write.bind(socket);
  socket.write = function(chunk, encoding, callback) {
    const dataMsg = `[WS] Proxy -> Client data: ${Buffer.isBuffer(chunk) ? chunk.toString('utf8') : chunk}`;
    console.log(dataMsg);
    wsLogs.push(dataMsg);
    return originalWrite(chunk, encoding, callback);
  };

  // // Override the Origin header for the WebSocket request.
  // if (req.headers.origin) {
  //   try {
  //     // const targetUrl = new URL(fixedTarget);
  //     // req.headers.origin = targetUrl.origin;
  //     // const overrideMsg = `[WS] Overriding Origin header to ${targetUrl.origin}`;
  //     // console.log(overrideMsg);
  //     wsLogs.push(overrideMsg);
  //   } catch (error) {
  //     const errMsg = `[WS] Error overriding Origin header: ${error.message}`;
  //     console.error(errMsg);
  //     wsLogs.push(errMsg);
  //   }
  // }

  // Forward the WebSocket request.
  proxy.ws(req, socket, head, { target: fixedTarget });
});

// ─────────────────────────────────────────────
// DASHBOARD ROUTE (Rendered)
// ─────────────────────────────────────────────

// Render a dashboard view that shows the intercepted HTTP and WS logs.
app.get('/asdasdasd', (req, res) => {
  res.render('asdasdasd', { httpLogs, wsLogs });
});

// ─────────────────────────────────────────────
// START THE SERVER ON PORT 9015
// ─────────────────────────────────────────────

server.listen(9015, () => {
  console.log('🚀 Proxy server running on http://localhost:9015');
});
