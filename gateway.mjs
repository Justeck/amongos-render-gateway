import { createServer } from 'node:http';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { pathToFileURL } from 'node:url';

// This service has one upstream. Never accept an upstream URL from a request or environment variable.
const UPSTREAM = 'https://amongos-dublin-2026.lush-pike-0632.chatgpt.site';
const MAX_BODY_BYTES = 1024 * 1024;
const HOP_HEADERS = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'proxy-connection', 'te', 'trailer', 'transfer-encoding', 'upgrade',
]);

function blockedHeaders(connection) {
  return new Set([...HOP_HEADERS, ...(connection || '').toLowerCase().split(',').map((name) => name.trim())]);
}

function sendError(res, status, message) {
  res.writeHead(status, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
  res.end(`${message}\n`);
}

function secureResponse(res) {
  res.setHeader('cache-control', 'private, no-store');
  res.setHeader('x-frame-options', 'DENY');
  res.setHeader('content-security-policy', "frame-ancestors 'none'; base-uri 'self'; object-src 'none'");
  res.setHeader('x-content-type-options', 'nosniff');
  res.setHeader('referrer-policy', 'no-referrer');
  res.setHeader('x-robots-tag', 'noindex, nofollow, noarchive');
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    const cleanup = () => {
      req.off('data', onData);
      req.off('end', onEnd);
      req.off('error', onError);
      req.off('aborted', onAborted);
    };
    const onError = (error) => { cleanup(); reject(error); };
    const onAborted = () => onError(new Error('Request aborted'));
    const onEnd = () => { cleanup(); resolve(Buffer.concat(chunks, size)); };
    const onData = (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        cleanup();
        req.resume();
        reject(Object.assign(new Error('Request body exceeds one megabyte'), { status: 413 }));
        return;
      }
      chunks.push(chunk);
    };
    req.on('data', onData);
    req.once('end', onEnd);
    req.once('error', onError);
    req.once('aborted', onAborted);
  });
}

function publicOrigin(req, externalHostname) {
  const hostname = externalHostname || req.headers.host;
  if (!hostname || /[\s/\\?#@]/.test(hostname)) throw new Error('Invalid public hostname');
  const origin = new URL(`https://${hostname}`);
  if (origin.host !== hostname.toLowerCase()) throw new Error('Invalid public hostname');
  return origin.origin;
}

export function createGatewayServer({
  fetchImpl = fetch,
  externalHostname = process.env.RENDER_EXTERNAL_HOSTNAME,
  requestTimeoutMs = 60_000,
} = {}) {
  const server = createServer(async (req, res) => {
    secureResponse(res);
    let controller;
    let timeout;
    let timedOut = false;
    const abortOnDisconnect = () => { if (!res.writableEnded) controller?.abort(); };
    res.once('close', abortOnDisconnect);
    try {
      if (!['GET', 'HEAD', 'POST'].includes(req.method)) {
        res.setHeader('allow', 'GET, HEAD, POST');
        sendError(res, 405, 'Method not allowed');
        req.resume();
        return;
      }
      const target = req.url || '';
      if (!target.startsWith('/') || target.startsWith('//') || target.includes('\\') || target.includes('#')) {
        sendError(res, 400, 'Invalid request path');
        req.resume();
        return;
      }
      const upstreamUrl = new URL(target, UPSTREAM);
      if (upstreamUrl.origin !== UPSTREAM) {
        sendError(res, 400, 'Invalid request path');
        return;
      }
      if (req.method === 'POST' && (!upstreamUrl.pathname.startsWith('/api/') || req.headers['next-action'])) {
        res.setHeader('allow', 'GET, HEAD');
        sendError(res, 405, 'Only application API requests may change data');
        req.resume();
        return;
      }
      let origin;
      try { origin = publicOrigin(req, externalHostname); }
      catch { sendError(res, 400, 'Invalid public hostname'); req.resume(); return; }

      // Validate the browser's origin before replacing it for the backend's own CSRF check.
      if (req.method === 'POST' && req.headers.origin !== origin) {
        sendError(res, 403, 'A same-origin request is required');
        req.resume();
        return;
      }
      if (Number(req.headers['content-length'] || 0) > MAX_BODY_BYTES) {
        sendError(res, 413, 'Request body exceeds one megabyte');
        req.resume();
        return;
      }

      const excluded = blockedHeaders(req.headers.connection);
      const headers = new Headers();
      for (const [name, value] of Object.entries(req.headers)) {
        if (value === undefined || excluded.has(name) || ['host', 'authorization', 'content-length', 'origin', 'referer', 'forwarded', 'x-real-ip'].includes(name)
          || /^(x-forwarded-|x-auth-|x-authenticated-|x-original-|cf-|oai-|x-openai-|x-sites-|x-render-)/.test(name)) continue;
        headers.set(name, Array.isArray(value) ? value.join(', ') : value);
      }
      if (req.method === 'POST') {
        headers.set('origin', UPSTREAM);
        headers.set('referer', `${UPSTREAM}/`);
      }
      const body = req.method === 'POST' ? await readBody(req) : undefined;
      controller = new AbortController();
      timeout = setTimeout(() => { timedOut = true; controller.abort(); }, requestTimeoutMs);
      const upstream = await fetchImpl(upstreamUrl, {
        method: req.method, headers, body, redirect: 'manual', signal: controller.signal,
      });

      const responseExcluded = blockedHeaders(upstream.headers.get('connection'));
      for (const [name, value] of upstream.headers) {
        // Node fetch decompresses responses; these upstream byte headers would describe different bytes.
        if (responseExcluded.has(name) || ['set-cookie', 'content-length', 'content-encoding'].includes(name)) continue;
        if (name === 'location') {
          const location = new URL(value, upstreamUrl);
          res.setHeader(name, location.origin === UPSTREAM ? `${origin}${location.pathname}${location.search}${location.hash}` : value);
        } else res.setHeader(name, value);
      }
      const cookies = upstream.headers.getSetCookie();
      if (cookies.length) res.setHeader('set-cookie', cookies);
      secureResponse(res);
      res.statusCode = upstream.status;
      if (req.method === 'HEAD' || !upstream.body) {
        await upstream.body?.cancel();
        res.end();
      } else {
        await pipeline(Readable.fromWeb(upstream.body), res);
      }
    } catch (error) {
      if (res.headersSent) res.destroy();
      else if (!res.destroyed) {
        const status = error.status === 413 ? 413 : timedOut ? 504 : 502;
        sendError(res, status, status === 413 ? 'Request body exceeds one megabyte'
          : status === 504 ? 'The backend request timed out' : 'The backend is temporarily unavailable');
      }
    } finally {
      clearTimeout(timeout);
      res.off('close', abortOnDisconnect);
    }
  });
  server.requestTimeout = 60_000;
  server.headersTimeout = 30_000;
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.env.PORT || 10_000);
  createGatewayServer().listen(port, '0.0.0.0', () => console.log(`Amongos gateway listening on port ${port}`));
}

