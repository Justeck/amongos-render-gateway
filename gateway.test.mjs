import assert from 'node:assert/strict';
import { request } from 'node:http';
import { test } from 'node:test';

const gatewayModule = await import('./gateway.mjs').catch((error) => {
  if (error.code !== 'ERR_MODULE_NOT_FOUND') throw error;
  return {};
});

async function withGateway(t, fetchImpl, options = {}) {
  assert.equal(typeof gatewayModule.createGatewayServer, 'function', 'The Render gateway server must exist');
  const server = gatewayModule.createGatewayServer({
    fetchImpl,
    externalHostname: 'amongos-test.onrender.com',
    ...options,
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  return (path, { method = 'GET', headers = {}, body } = {}) => new Promise((resolve, reject) => {
    const req = request({
      hostname: '127.0.0.1', port: server.address().port, path, method,
      headers: { host: 'amongos-test.onrender.com', ...headers },
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('error', reject);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on('error', reject);
    if (Array.isArray(body)) {
      for (const chunk of body) req.write(chunk);
      req.end();
    } else req.end(body);
  });
}

test('GET forwards only the pinned site path and streams binary responses and separate secure cookies', async (t) => {
  const get = await withGateway(t, async (url, init) => {
    assert.equal(String(url), 'https://amongos-dublin-2026.lush-pike-0632.chatgpt.site/assets/map.bin?v=2');
    assert.equal(init.method, 'GET');
    assert.equal(init.redirect, 'manual');
    for (const name of ['host', 'authorization', 'forwarded', 'x-forwarded-host', 'x-auth-request-user', 'x-remove']) {
      assert.equal(init.headers.get(name), null, `${name} must not be trusted from the client`);
    }
    const headers = new Headers({ 'content-type': 'application/octet-stream', 'content-encoding': 'gzip', 'content-length': '999' });
    headers.append('set-cookie', '__Host-session=one; Path=/; Secure; HttpOnly; SameSite=Lax');
    headers.append('set-cookie', '__Host-host=two; Path=/; Secure; HttpOnly; SameSite=Strict');
    return new Response(new ReadableStream({ start(controller) {
      controller.enqueue(Uint8Array.from([0, 255]));
      controller.enqueue(Uint8Array.from([128, 1]));
      controller.close();
    } }), { headers });
  });
  const result = await get('/assets/map.bin?v=2', { headers: {
    authorization: 'Bearer forged', forwarded: 'host=evil.example', 'x-forwarded-host': 'evil.example',
    'x-auth-request-user': 'admin', connection: 'x-remove', 'x-remove': 'unsafe',
  } });
  assert.equal(result.status, 200);
  assert.deepEqual([...result.body], [0, 255, 128, 1]);
  assert.equal(result.headers['content-encoding'], undefined);
  assert.equal(result.headers['content-length'], undefined);
  assert.deepEqual(result.headers['set-cookie'], [
    '__Host-session=one; Path=/; Secure; HttpOnly; SameSite=Lax',
    '__Host-host=two; Path=/; Secure; HttpOnly; SameSite=Strict',
  ]);
});

test('same-origin POST preserves the body and cookie while rewriting the backend CSRF headers', async (t) => {
  const send = await withGateway(t, async (url, init) => {
    assert.equal(String(url), 'https://amongos-dublin-2026.lush-pike-0632.chatgpt.site/api/rooms');
    assert.equal(init.method, 'POST');
    assert.equal(init.headers.get('origin'), 'https://amongos-dublin-2026.lush-pike-0632.chatgpt.site');
    assert.equal(init.headers.get('referer'), 'https://amongos-dublin-2026.lush-pike-0632.chatgpt.site/');
    assert.equal(init.headers.get('cookie'), '__Host-session=signed-value');
    assert.equal(init.headers.get('content-type'), 'application/json');
    assert.equal(Buffer.from(init.body).toString(), '{"name":"Dublin"}');
    return new Response('{"ok":true}', { status: 201 });
  });
  const result = await send('/api/rooms', { method: 'POST', body: '{"name":"Dublin"}', headers: {
    origin: 'https://amongos-test.onrender.com', referer: 'https://amongos-test.onrender.com/host',
    cookie: '__Host-session=signed-value', 'content-type': 'application/json',
  } });
  assert.equal(result.status, 201);
  assert.equal(result.body.toString(), '{"ok":true}');
});

test('foreign, missing and forged-host POST origins are rejected before contacting the backend', async (t) => {
  let calls = 0;
  const send = await withGateway(t, async () => { calls++; return new Response('unsafe'); });
  for (const headers of [
    { origin: 'https://evil.example' }, {},
    { host: 'evil.example', origin: 'https://evil.example' },
    { origin: 'https://amongos-test.onrender.com.evil.example' },
  ]) {
    assert.equal((await send('/api/rooms', { method: 'POST', headers, body: '{}' })).status, 403);
  }
  assert.equal(calls, 0);
});

test('absolute, protocol-relative and backslash request targets cannot change the upstream', async (t) => {
  let calls = 0;
  const get = await withGateway(t, async () => { calls++; return new Response('unsafe'); });
  for (const path of ['https://evil.example/a', '//evil.example/a', '/\\evil.example/a']) {
    assert.equal((await get(path)).status, 400);
  }
  assert.equal(calls, 0);
});

test('methods outside GET, HEAD and POST are rejected locally', async (t) => {
  let calls = 0;
  const send = await withGateway(t, async () => { calls++; return new Response('unsafe'); });
  const result = await send('/api/rooms', { method: 'DELETE' });
  assert.equal(result.status, 405);
  assert.equal(result.headers.allow, 'GET, HEAD, POST');
  assert.equal(calls, 0);
});

test('POST accepts a one-megabyte restore body and rejects larger bodies before forwarding', async (t) => {
  let calls = 0;
  const send = await withGateway(t, async (_url, init) => {
    calls++;
    assert.equal(init.body.byteLength, 1024 * 1024);
    return new Response('restored');
  });
  const headers = { origin: 'https://amongos-test.onrender.com' };
  assert.equal((await send('/api/host/restore', { method: 'POST', headers, body: Buffer.alloc(1024 * 1024) })).status, 200);
  assert.equal((await send('/api/host/restore', { method: 'POST', headers, body: Buffer.alloc(1024 * 1024 + 1) })).status, 413);
  assert.equal((await send('/api/host/restore', { method: 'POST', headers, body: [Buffer.alloc(1024 * 1024), Buffer.alloc(1)] })).status, 413);
  assert.equal(calls, 1);
});

test('upstream redirects stay on the gateway and upstream failure statuses remain visible', async (t) => {
  const send = await withGateway(t, async (url) => String(url).endsWith('/redirect')
    ? new Response(null, { status: 302, headers: { location: 'https://amongos-dublin-2026.lush-pike-0632.chatgpt.site/host?next=1' } })
    : new Response('Backend maintenance', { status: 503 }));
  const redirect = await send('/redirect');
  assert.equal(redirect.status, 302);
  assert.equal(redirect.headers.location, 'https://amongos-test.onrender.com/host?next=1');
  const failure = await send('/api/status');
  assert.equal(failure.status, 503);
  assert.equal(failure.body.toString(), 'Backend maintenance');
});

test('HEAD forwards HEAD and never emits a response body', async (t) => {
  const send = await withGateway(t, async (_url, init) => {
    assert.equal(init.method, 'HEAD');
    return new Response(null, { status: 200, headers: { 'content-type': 'text/html' } });
  });
  const result = await send('/', { method: 'HEAD' });
  assert.equal(result.status, 200);
  assert.equal(result.body.length, 0);
});

test('unreachable backend returns an honest gateway failure', async (t) => {
  const send = await withGateway(t, async () => { throw new Error('private infrastructure details'); });
  const result = await send('/api/status');
  assert.equal(result.status, 502);
  assert.match(result.body.toString(), /backend.*unavailable/i);
  assert.doesNotMatch(result.body.toString(), /private infrastructure/);
});

test('backend timeout aborts the fetch and returns a timeout response', async (t) => {
  const send = await withGateway(t, async (_url, { signal }) => new Promise((_resolve, reject) => {
    signal.addEventListener('abort', () => reject(signal.reason), { once: true });
  }), { requestTimeoutMs: 15 });
  const result = await send('/api/status');
  assert.equal(result.status, 504);
});

test('edge identity and Sites dispatch headers cannot be smuggled through the public gateway', async (t) => {
  const send = await withGateway(t, async (_url, init) => {
    for (const name of ['oai-sites-authorization', 'oai-authenticated-user-id', 'x-openai-user-id', 'x-sites-auth', 'x-render-user']) {
      assert.equal(init.headers.get(name), null, name);
    }
    return new Response('safe');
  });
  assert.equal((await send('/api/session', {headers:{
    'oai-sites-authorization':'Bearer forged', 'oai-authenticated-user-id':'organizer',
    'x-openai-user-id':'organizer', 'x-sites-auth':'organizer', 'x-render-user':'organizer',
  }})).status, 200);
});

test('non-API mutation and server-action requests never reach the framework', async (t) => {
  let calls=0;
  const send=await withGateway(t, async()=>{calls++;return new Response('unsafe')});
  for(const path of ['/', '/host', '/preview', '/assets/action', '/api/status']) {
    const result=await send(path,{method:'POST',headers:{origin:'https://amongos-test.onrender.com','next-action':'forged'},body:'{}'});
    assert.equal(result.status,405,path);
  }
  assert.equal(calls,0);
});

test('success and error responses prevent framing, sniffing and referrer leaks', async(t)=>{
  const send=await withGateway(t,async()=>new Response('<html>app</html>',{headers:{'content-type':'text/html'}}));
  for(const result of [await send('/'),await send('/',{method:'DELETE'})]) {
    assert.equal(result.headers['x-frame-options'],'DENY');
    assert.match(result.headers['content-security-policy'],/frame-ancestors 'none'/);
    assert.equal(result.headers['x-content-type-options'],'nosniff');
    assert.equal(result.headers['referrer-policy'],'no-referrer');
    assert.match(result.headers['cache-control'],/no-store/);
  }
});

