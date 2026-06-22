const http = require('http');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');
const logger = require('./logger');

/**
 * Production renderer host.
 *
 * This is a TanStack Start (SSR) app: `vite build` emits a web-standard fetch
 * handler at dist/server/server.js plus client assets in dist/client — there is
 * NO static index.html to loadFile(). This module starts a tiny loopback HTTP
 * server that serves the client assets and delegates every other request to the
 * SSR handler, so Electron can loadURL() a fully hydrated app instead of a blank
 * white screen.
 */

const DIST_DIR = path.join(__dirname, '..', 'dist');
const CLIENT_DIR = path.join(DIST_DIR, 'client');
const SERVER_ENTRY = path.join(DIST_DIR, 'server', 'server.js');

const CONTENT_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.ico': 'image/x-icon',
  '.webp': 'image/webp',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
  '.map': 'application/json; charset=utf-8',
};

let ssrHandlerPromise;

function getSsrHandler() {
  if (!ssrHandlerPromise) {
    ssrHandlerPromise = import(pathToFileURL(SERVER_ENTRY).href).then((m) => {
      const handler = m.default ?? m;
      if (typeof handler?.fetch !== 'function') {
        throw new Error('SSR server entry does not export a fetch handler');
      }
      return handler;
    });
  }
  return ssrHandlerPromise;
}

/** Resolve a URL path to a real file inside dist/client, guarding traversal. */
function resolveClientAsset(urlPath) {
  const decoded = decodeURIComponent(urlPath.split('?')[0]);
  const resolved = path.normalize(path.join(CLIENT_DIR, decoded));
  if (resolved !== CLIENT_DIR && !resolved.startsWith(CLIENT_DIR + path.sep)) {
    return null;
  }
  try {
    const stat = fs.statSync(resolved);
    if (stat.isFile()) return resolved;
  } catch {
    /* not a static file */
  }
  return null;
}

function serveStatic(filePath, res) {
  const ext = path.extname(filePath).toLowerCase();
  res.statusCode = 200;
  res.setHeader('Content-Type', CONTENT_TYPES[ext] || 'application/octet-stream');
  fs.createReadStream(filePath)
    .on('error', () => {
      res.statusCode = 500;
      res.end('Asset read error');
    })
    .pipe(res);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function buildWebRequest(req, origin) {
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (Array.isArray(value)) value.forEach((v) => headers.append(key, v));
    else if (value != null) headers.set(key, value);
  }
  const init = { method: req.method, headers };
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    const body = await readBody(req);
    if (body.length) init.body = body;
  }
  return new Request(new URL(req.url, origin).href, init);
}

async function handleSsr(req, res, origin) {
  try {
    const handler = await getSsrHandler();
    const webRequest = await buildWebRequest(req, origin);
    const response = await handler.fetch(webRequest, {}, {});

    res.statusCode = response.status;
    response.headers.forEach((value, key) => res.setHeader(key, value));
    const body = Buffer.from(await response.arrayBuffer());
    res.end(body);
  } catch (e) {
    logger.error('PROD_SERVER', 'SSR render failed', e.message);
    res.statusCode = 500;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end('<h1>NetFast failed to render</h1>');
  }
}

/**
 * Start the loopback production server. Resolves to { url, close } once the
 * server is listening on an OS-assigned port.
 */
function startProdServer() {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      const origin = `http://127.0.0.1:${server.address().port}`;
      if (req.method === 'GET' || req.method === 'HEAD') {
        const asset = resolveClientAsset(req.url);
        if (asset) {
          serveStatic(asset, res);
          return;
        }
      }
      handleSsr(req, res, origin);
    });

    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const url = `http://127.0.0.1:${server.address().port}`;
      logger.info('PROD_SERVER', 'Production renderer server listening', { url });
      resolve({
        url,
        close: () =>
          new Promise((done) => {
            server.close(() => done());
          }),
      });
    });
  });
}

module.exports = { startProdServer };
