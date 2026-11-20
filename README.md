# WatermelonKatana Proxy

Node.js/Express implementation of the proxy in `Editor/workers/proxy.js`.

## Run

Requires Node.js 20+.

```sh
npm install
npm start
```

Listens on `0.0.0.0:$PORT` (default `3000`).

## Environment

- `PORT`: listening port (default `3000`)
- `USE_CORSFIX_FALLBACK=false`: disable Corsfix fallback (enabled by default)
- `CORSFIX_API_KEY`: optional Corsfix API key
- `BODY_LIMIT`: maximum incoming request body (default `100mb`)

## API compatibility

The main proxy accepts `?url=<target URL>` or `?base64_url=<URL-safe base64 target>`. It forwards HTTP methods and bodies, preserves upstream status and response headers (replacing upstream CORS headers), supports the editor's mobile user-agent / Client Hints emulation, and retries eligible failures through Corsfix.

WebSocket upgrades use the same target parameters.

Document isolation is supported through `GET /isolate?url=<url>&id=<session-id>` and `/isolation/<session-id>/<path>`. It rewrites HTML, CSS, JavaScript URLs and redirects. Sessions are held in process memory and expire after 24 hours (they are lost on restart; the Worker uses KV).

## Security

This is an outbound proxy. Do not expose it publicly without authentication, rate limiting, and destination/IP restrictions suitable for your deployment. For compatibility, the regular `url` route retains the Worker behavior and does not apply the isolation route's destination validation.
