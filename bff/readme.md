## BFF Development

- [![Open in Bolt](https://bolt.new/static/open-in-bolt.svg)](https://bolt.new/) jclempaypal-agent
- [<img src="https://dl.svgcdn.com/png/simple-icons/googlejules-800.png" alt="Google Jules Icon" width="24" height="24" style="vertical-align:middle">](https://jules.google.com) jclempaypal@gmail.com
- [<img src="https://cdn.jsdelivr.net/npm/simple-icons@latest/icons/openai.svg" alt="ChatGPT Codex Logo" width="24" height="24" style="vertical-align:middle">](https://chatgpt.com/codex/cloud/) jclempaypal@gmail.com

The BFF handles the OIDC interaction with PingFederate, manages the user's session, and serves user data to the client.
It uses `express-session` for session management and `openid-client` for OIDC interactions.

1.  **Navigate to the BFF directory:**
    ```bash
    cd bff
    ```

2.  **Create `.env` file:**
    Copy the example environment file and customize it with your PingFederate and application settings:
    ```bash
    cp .env.example .env
    ```
    Now, edit `.env` and fill in the following variables:
    *   `PING_CLIENT_ID`: Your OIDC Client ID for the BFF application from PingFederate.
    *   `PING_CLIENT_SECRET`: The client secret for your BFF application.
    *   `PING_ISSUER_URL`: The issuer URI of your PingFederate server (e.g., `https://ping.hdc.company` or `https://localhost:9031`). The library will use this to discover OIDC endpoints.
    *   `SESSION_SECRET`: A long, random, and secure string used to sign the session ID cookie. Generate a strong one.
    *   `BFF_PORT`: The port on which the BFF server will listen (default is `3001`). If the hosting platform sets `PORT` (Azure App Service does), `PORT` takes precedence.
    *   `FRONTEND_ORIGIN`: **Crucial for CORS configuration.** This **MUST be the exact *origin*** (or a comma-separated list of origins) of your client application(s), used for the BFF's `Access-Control-Allow-Origin` header.
        *   An origin is defined by its scheme (e.g., `http` or `https`), hostname (e.g., `localhost`, `julesclements.github.io`), and port (if it's not the default for the scheme, e.g., `:1234`).
        *   **DO NOT include paths or trailing slashes.**
        *   **Correct Examples:**
            *   For local client development (e.g., Parcel dev server on port 1234): `http://localhost:1234`
            *   For the production client on GitHub Pages: `https://julesclements.github.io`
            *   For multiple origins: `http://localhost:1234,http://localhost:5173,https://julesclements.github.io`
        *   **Incorrect Examples:** `http://localhost:1234/`, `https://julesclements.github.io/mixed/`
        *   **Why it's important for CORS:** The browser's `Origin` header sent with cross-origin requests must match one of the origins in `FRONTEND_ORIGIN` for the browser to accept responses from the BFF.
    *   `FRONTEND_REDIRECT_URL`: The **full URL** (or a comma-separated list of URLs) where the BFF should redirect the user's browser after operations like login or logout.
        *   **Correct Examples:**
            *   For local client development: `http://localhost:1234/`
            *   For the production client on GitHub Pages: `https://julesclements.github.io/mixed/`
            *   For multiple redirects: `http://localhost:1234/,http://localhost:5173/,https://julesclements.github.io/mixed/`
        *   This URL is used in OIDC `post_logout_redirect_uri` and for redirecting after the token exchange. The BFF will attempt to use a `returnTo` query parameter provided during `/login` or `/logout` (if it matches one of the allowed URLs) or fallback to the first URL in this list.
    *   `BFF_BASE_URL`: The base URL where the BFF itself is running. This is crucial for constructing the `redirect_uri` that PingFederate will use.
        *   For local development: `http://localhost:3001` (or whatever `BFF_PORT` is).
        *   For production: `https://mixed.hdc.company` (this is the public URL of your deployed BFF).
    *   `ALLOW_SELF_SIGNED_CERTS`: Set to `true` **only** during local development if your PingFederate instance uses self-signed SSL certificates. This bypasses certificate validation for OIDC communication.
        *   **SECURITY WARNING:** DO NOT set this to `true` in any production or publicly accessible environment, as it exposes the application to man-in-the-middle attacks.
    *   **IMPORTANT OIDC Redirect URI Configuration:** When deploying your BFF to production at `https://mixed.hdc.company`, its OIDC redirect URI will be `https://mixed.hdc.company/auth/callback`. You **MUST** add this exact URI to the list of allowed redirect URIs in your OIDC client configuration within the PingFederate administration console. Failure to do so will result in PingFederate blocking authentication attempts.

3.  **Install Dependencies:**
    ```bash
    npm install
    ```

4.  **Run the BFF:**
    *   To run in standard mode:
        ```bash
        npm start
        ```
    *   To run in development mode with automatic restarts (requires `nodemon`):
        ```bash
        npm run dev
        ```
        If you don't have `nodemon` installed globally, you can install it as a dev dependency (`npm install -D nodemon`) or run with `npx nodemon server.js`.

5.  **Startup Retry Mechanism:**
    *   The BFF server (`bff/server.js`) includes a startup retry mechanism for OIDC issuer discovery.
    *   If the PingFederate instance (specified by `PING_ISSUER_URL`) is not immediately reachable when the BFF starts, the BFF will automatically retry the connection attempt.
    *   Retries occur every 10 seconds for a default maximum of 10 minutes (60 attempts).
    *   Startup attempt progress, failures, and retries are logged to the console output (or container logs).
    *   This makes the BFF more resilient, especially in orchestrated environments (like Docker Compose or Kubernetes) where services might start in an unpredictable order.

6.  **CORS Configuration:**
    *   The BFF uses the `cors` package to handle Cross-Origin Resource Sharing.
    *   This is essential for local development when the client (e.g., Parcel dev server on `http://localhost:1234`) and the BFF (on `http://localhost:3001`) operate on different ports (and thus different origins).
    *   The CORS policy is configured in `bff/server.js` to allow requests specifically from the `FRONTEND_URL` (defined in your `bff/.env` file) and to allow credentials (e.g., cookies) to be sent and received. This ensures that the client can make authenticated API calls to the BFF.

6.  **Session Cookie Configuration:**
    *   The BFF's session cookie behavior is dynamically configured based on the `NODE_ENV` environment variable:
        *   **Development (e.g., `NODE_ENV=development` or not set):**
            *   `cookie.secure` is `false`.
            *   `cookie.sameSite` is `'Lax'`.
            *   This setup is suitable for local development over HTTP, where the client (e.g., `http://localhost:1234`) and BFF (e.g., `http://localhost:3001`) might be on different ports but the same hostname.
        *   **Production (`NODE_ENV=production`):**
            *   `cookie.secure` is `true` (ensuring the cookie is only sent over HTTPS).
            *   `cookie.sameSite` is `'None'`. This is necessary for cross-domain scenarios, such as when the client is on `https://julesclements.github.io` and the BFF is on `https://mixed.hdc.company`.
            *   **Important:** For `SameSite=None` and `secure=true` to function correctly, the BFF **must be served over HTTPS** in production.
    *   **`trust proxy` Setting:**
        *   In production mode (`NODE_ENV=production`), `app.set('trust proxy', 1);` is enabled.
        *   This setting is crucial if you deploy the BFF behind a reverse proxy (e.g., Nginx, AWS ELB/ALB) that terminates TLS (handles HTTPS) and forwards requests to the BFF over HTTP.
        *   It allows Express to correctly determine that the connection was originally secure, which is essential for the `secure: true` cookie attribute to work as intended. Without it, Express might think the connection is insecure (HTTP) and refuse to set the secure cookie.

## Appendix: Security Remediation History

Newest entries first. Add an entry whenever a vulnerability is assessed or remediated.

### Runtime requirement

Three production images run on Node.js: the BFF (`node:26.13.0-slim`) and the
client and SPA static servers, which run `serve` on `node:26.13.0-alpine`. The
BFF is the only one that runs this project's own server code and makes outbound
requests (to the OIDC issuer), so it has the widest exposure to Node runtime
vulnerabilities. The `serve` images are assessed in
[client/security.md](../client/security.md) and [spa/SECURITY.md](../spa/SECURITY.md).

The BFF pins Node.js to exactly `26.13.0`: the `Dockerfile` uses
`node:26.13.0-slim`, CI uses `node-version: '26.13.0'`, and `package.json`
declares `engines.node >=26.13.0`. `engines` is advisory because the repository
has no `.npmrc` with `engine-strict=true`. Raise all of these together, following
the upgrade checklist in the
[local-pipelines skill](../.github/skills/local-pipelines/SKILL.md).

### 2026-10 - Node.js October 2026 security releases

Reference: <https://nodejs.org/en/blog/vulnerability/october-2026-security-releases>
(published 2026-10-21). The advisory lists ten CVEs. The fixed releases are
22.23.4, 24.22.1 and 26.12.1, so the pinned 26.13.0 includes every fix. The
advisory does not map individual CVEs to fixed versions, and CVE details beyond
the advisory were not independently verified.

The first four are rated High.

| CVE | Summary | Exposure in this project |
| --- | --- | --- |
| CVE-2026-111497 | Brotli decoder out-of-bounds write (RCE) | Not reachable on known paths. `express.json()` (body-parser 1.x) accepts only `gzip`/`deflate`/`identity` request bodies. `openid-client` 5.7.1 sends `Accept-Encoding: identity` and never decompresses. `jose` JWKS fetching was not inspected. |
| CVE-2026-105483 | TLS hostname bypass with fullwidth-digit IPs | Runtime-level; outbound HTTPS to the OIDC issuer. Mitigated by the Node upgrade. |
| CVE-2026-106069 | TLS hostname bypass when host loosely resolves to an IP | Runtime-level; outbound HTTPS to the OIDC issuer. Mitigated by the Node upgrade. |
| CVE-2026-105482 | `dns.resolve` truncates names containing NUL | Low; the app does not call `dns.resolve` or resolve user-supplied hostnames. |
| CVE-2026-106072 (Medium) | DNS SANs accepted for non-canonical IPv4 hostnames | Runtime-level; outbound HTTPS to the OIDC issuer. Only relevant if the issuer is configured as an IP address. Mitigated by the Node upgrade. |
| CVE-2026-105481 (Medium) | Keep-alive socket processes a response written before the request | Runtime-level; outbound HTTP requests to the OIDC issuer can reuse keep-alive sockets. Mitigated by the Node upgrade. |
| CVE-2026-106074 (Medium) | `randomUUID()`/`randomInt()` entropy cached in startup snapshots and SEAs | No; the BFF is not built as a startup snapshot or single executable application. |
| CVE-2026-106070 (Low) | `ZipFile` returns prefix bytes after failed header validation | No; no ZIP handling. |
| CVE-2026-106071 (Low) | Permission Model filesystem over-grant | No; the Permission Model (`--permission`) is not used. |
| CVE-2026-106073 (Low) | Permission Model bypass with `fs.realpathSync` | No; the Permission Model is not used. |

Actions taken:

- Moved the Docker base image, CI and the local runner from Node 24 to Node 26,
  then pinned the exact version `26.13.0`.
- Declared `engines.node >=26.13.0`.
- `ALLOW_SELF_SIGNED_CERTS=true` disables certificate validation and overrides
  any TLS fix. It must never be set in production.

### 2026-10 - Dependency CVE remediation

- Locked express 4.22.2 to 4.22.3 and vitest and coverage packages 4.1.10 to
  4.1.12. `npm audit` reports 0 vulnerabilities.
- Docker builds install from the committed lockfile with `npm ci --omit=dev`.
