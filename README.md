# Amongos Render gateway

A zero-dependency Node service that serves one pinned application backend. Event state stays in the existing durable backend; this repository contains no event answers, host credentials, keys, private chat material or database.

## Run

Use Node 24.22.2 or newer. `node --test gateway.test.mjs` runs the request-boundary checks. `node gateway.mjs` listens on Render's `PORT`.

The Render service uses the free plan. Free instances may sleep and need time to wake. Render restarts do not erase application records because those records are kept in the upstream D1/R2 backend. The direct application address remains a fallback.

`RENDER_EXTERNAL_HOSTNAME` pins same-origin browser writes to Render's assigned hostname. No runtime secret is needed here. The gateway permits GET/HEAD and same-origin API POST, bounds bodies, blocks spoofed identity/forwarding headers, prevents framing and private caching, and never accepts a caller-selected upstream.

Host APK controls retain their existing paired application origin. Render player sessions are scoped to the Render hostname; the organizer never gains authority merely by selecting Justin.
