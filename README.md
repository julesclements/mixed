 PingFederate OIDC Authentication: Client + BFF Example

This project demonstrates a client-server architecture where a frontend client application (served via GitHub Pages or locally) interacts with a Backend-for-Frontend (BFF) to handle OIDC authentication with PingFederate.

The repository is structured as a monorepo:
-   `/client`: Contains the static frontend Javascript application.
-   `/bff`: Contains the Node.js/Express Backend-for-Frontend (BFF) application.
-   `/spa`: Contains a React/TypeScript Single Page Application (SPA) that demonstrates OIDC authentication using Vite and Tailwind CSS.

For flow overview see [[BFF] Backend-for-Frontend for PingIdentity](https://v8lust.atlassian.net/wiki/x/AgDoIg).

## Prerequisites

*   **Node.js and npm:** [Download Node.js](https://nodejs.org/) (npm is included).
*   **Docker:** (Optional) If you plan to run the BFF as a Docker container. [Download Docker](https://www.docker.com/products/docker-desktop).
*   **PingFederate Access:**
    *   An operational PingFederate instance.
    *   An OIDC client registered in PingFederate specifically for the BFF application. This client should be configured with:
        *   **Client ID & Secret:** For the BFF to authenticate itself.
        *   **Redirect URI:** Pointing to the BFF's callback endpoint (e.g., `http://localhost:3001/auth/callback` for local dev, or your production BFF's callback URL).
        *   **Grant Type:** Authorization Code.
        *   (Optional but Recommended) **PKCE:** While `openid-client` supports it, ensure your PingFederate client settings are compatible if PKCE is enforced.

## Environment Variables

This project uses environment variables for configuration. You should create `.env` files in the respective directories.

### Backend-for-Frontend (`/bff/.env`)

| Variable | Description |
| :--- | :--- |
| `PING_CLIENT_ID` | Your OIDC Client ID for the BFF application from PingFederate. |
| `PING_CLIENT_SECRET` | The client secret for your BFF application. |
| `PING_ISSUER_URL` | The issuer URI of your PingFederate server (e.g., `https://ping.hdc.company`). |
| `PING_BROWSER_FACING_BASE_URL` | (Optional) The base URL for PingFederate as seen by the user's browser. |
| `SESSION_SECRET` | A long, random, and secure string used to sign the session ID cookie. |
| `BFF_PORT` | The port on which the BFF server will listen (default is `3001`). |
| `BFF_BASE_URL` | The base URL where the BFF itself is running (e.g., `http://localhost:3001`). |
| `FRONTEND_ORIGIN` | The exact origin of your client application (e.g., `http://localhost:1234`). Supports comma-separated lists for multiple origins. |
| `FRONTEND_REDIRECT_URL` | The full URL where the BFF should redirect after login/logout. Supports comma-separated lists for multiple origins. |
| `ALLOW_SELF_SIGNED_CERTS` | Set to `true` to bypass certificate validation (development only). |
| `NODE_ENV` | Set to `production` to enable secure cookie attributes. |

### Javascript Client (`/client/.env`)

| Variable | Description |
| :--- | :--- |
| `VITE_STAFF_CLIENT_ID` | OIDC Client ID for staff login. |
| `VITE_PING_BASE_URL` | The authorization endpoint for PingFederate. |

### Single Page Application (`/spa/.env`)

| Variable | Description |
| :--- | :--- |
| `VITE_STAFF_CLIENT_ID` | OIDC Client ID for staff login. |
| `VITE_PING_BASE_URL` | The authorization endpoint for PingFederate. |
| `VITE_BFF_BASE_URL` | The base URL of the BFF server. |
| `VITE_SPA_PORT` | The port on which the SPA development server will listen (default is `5173`). |

## Deployment

### Client Application (`/client`)

The client application can be deployed in two ways:

1.  **GitHub Pages (Static Deployment):**
    *   The client application is configured to be built and deployed to **GitHub Pages** automatically.
    *   This is handled by the GitHub Actions workflow defined in `.github/workflows/client-deploy.yml`.
    *   Deployment happens on pushes to the `main` branch (if changes are detected in the `client/` directory or the workflow file).
    *   The live URL will be something like `https://julesclements.github.io/mixed/`.

2.  **Docker Container (Static Serve):**
    *   The client application can also be built into a Docker container that serves its static files using the `serve` package.
    *   A `client/Dockerfile` is provided for this.
    *   **Local Docker Build & Run:**
        *   To build the image locally:
            ```bash
            docker build -t yourdockerhubusername/ping-client:latest client/
            ```
            (Replace `yourdockerhubusername` with your Docker Hub username or any desired image name).
        *   To run the container locally:
            ```bash
            docker run -d -p 1234:1234 yourdockerhubusername/ping-client:latest
            ```
            The client will then be accessible at `http://localhost:1234`.
    *   **Automated Docker Build (GitHub Actions):**
        *   The `.github/workflows/client-docker-build.yml` workflow automatically builds and pushes the client's Docker image to Docker Hub.
        *   This happens on pushes to `main` if files in the `client/` directory or the `client-docker-build.yml` workflow file itself are changed.
        *   The image is tagged as `yourdockerhubusername/ping-client:latest` (or similar, based on the workflow and secrets).
        *   **Required GitHub Secrets:** For this workflow to push to Docker Hub, you must configure `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` in your GitHub repository secrets.
    *   **Client Configuration (`bffBaseUrl` when containerized):**
        *   When the client is run from its Docker container and accessed (e.g., via `http://localhost:1234` locally), the `bffBaseUrl` in `client/script.js` will be determined by `window.location.hostname`.
        *   If accessed via `localhost`, it will attempt to connect to the BFF at `http://localhost:3001` (as per current `script.js` logic).
        *   If the BFF is also running in a Docker container locally, ensure Docker networking allows communication (e.g., by using a shared Docker network or ensuring the BFF's port is mapped to the host).
        *   For deployed scenarios (e.g., client container hosted, BFF at `https://mixed.hdc.company`), the client's `bffBaseUrl` logic should correctly point to the production BFF URL if the client is accessed via its production hostname (e.g., `julesclements.github.io` or a custom domain).

### BFF Application (`/bff`)
*   The BFF application is designed to be run as a **Docker container**.
*   A `Dockerfile` is provided in the `bff/` directory.
*   The GitHub Actions workflow in `.github/workflows/bff-docker-build.yml` automatically builds the Docker image and pushes it to **Docker Hub**.
    *   This workflow triggers on pushes to `main` (if changes are detected in `bff/` or the workflow file).
    *   **Required GitHub Secrets:** You must configure the following secrets in your GitHub repository settings (under "Secrets and variables" > "Actions") for the Docker Hub push to work:
        *   `DOCKERHUB_USERNAME`: Your Docker Hub username.
        *   `DOCKERHUB_TOKEN`: A Docker Hub access token with write permissions.
    *   The image will be tagged as `yourdockerhubusername/ping-bff:latest` (replace `yourdockerhubusername` with your actual Docker Hub username, or modify the tag in the workflow).
*   **You are responsible for deploying the BFF Docker image** from Docker Hub to your preferred hosting environment (e.g., a cloud provider like AWS, Google Cloud, Azure, or any server that can run Docker containers). You will also need to manage the `.env` variables for your deployed BFF instance.
*   **Reverse Proxy (Recommended for Production BFF):** When deploying the BFF, it's highly recommended to place it behind a reverse proxy (like Nginx or an Application Load Balancer). The reverse proxy can handle:
    *   **HTTPS termination:** Ensuring your BFF is served over HTTPS.
    *   **Custom domain names.**
    *   Potentially routing, rate limiting, etc.
    *   The `BFF_BASE_URL` environment variable for your deployed BFF should be its public HTTPS URL provided by the reverse proxy (e.g., `https://mixed.hdc.company`).

## Production Troubleshooting / Considerations

This section addresses common issues encountered when deploying the client and BFF to production, especially when they reside on different domains.

### Symptom: 401 Unauthorized on `/api/user` after successful login

*   **Description:** You have successfully logged in via PingFederate. The BFF redirects you back to the client application (e.g., on `https://julesclements.github.io/mixed/`). However, when you click "Get User Info" (or if the client automatically tries to fetch user data), the call to the BFF's `/api/user` endpoint (e.g., at `https://mixed.hdc.company/api/user`) fails with a 401 Unauthorized error. The client application might display "Please login to view user information."
*   **Likely Cause (Cross-Site Cookies / Third-Party Cookie Restrictions):** This is often due to how modern browsers handle cookies when the frontend (client) and backend (BFF) are on different top-level domains (e.g., `github.io` vs. `hdc.company`). The BFF's session cookie (e.g., `connect.sid`) might be treated as a "third-party cookie" by the browser when the client makes requests from its domain to the BFF's domain. Browsers are increasingly restricting the sending of third-party cookies by default to enhance user privacy (e.g., Chrome's Privacy Sandbox initiative, Safari's Intelligent Tracking Prevention (ITP), Firefox's Enhanced Tracking Protection (ETP)).

### Diagnosing the Issue

1.  **Verify BFF Configuration for Production:**
        *   **CRITICAL:** Ensure `NODE_ENV` is set to `production` for your deployed BFF instance. If this is not set, the BFF will use `Lax` cookies which are NOT sent in cross-site `fetch` requests.
        *   The session cookie settings in `bff/server.js` will then be active:
        *   `cookie.secure: true` (cookie is only sent over HTTPS).
            *   `cookie.sameSite: 'None'` (necessary for cross-site cookie delivery, requires `secure: true`).
            *   `cookie.partitioned: true` (Enables CHIPS - Cookies Having Independent Partitioned State). This helps modern browsers like Chrome allow the cookie in cross-site contexts when correctly partitioned.
    *   If your BFF is behind a reverse proxy that terminates TLS (handles HTTPS), ensure `app.set('trust proxy', 1);` is active in `bff/server.js` so Express correctly identifies the connection as secure.
    *   The BFF **must be served over HTTPS**.

2.  **Use Browser Developer Tools:**
    *   **After Login (on the client page, e.g., `https://julesclements.github.io/mixed/`):**
        1.  Open your browser's Developer Tools.
        2.  Go to the "Application" (Chrome/Edge) or "Storage" (Firefox) tab.
        3.  Under "Cookies", find the section for your BFF's domain (e.g., `https://mixed.hdc.company`).
        4.  **Verify the Session Cookie:** Look for the session cookie (its name is typically `connect.sid` for `express-session`).
            *   Confirm it exists.
            *   Check its attributes: `Secure` should be checked (true), `SameSite` should be `None`.
            *   Note its `Domain` attribute.
    *   **When "Get User Info" is Clicked (triggering the `/api/user` call):**
        1.  Switch to the "Network" tab in Developer Tools.
        2.  Trigger the `/api/user` request (e.g., by clicking the "Get User Info" button).
        3.  Find the request to `/api/user` (e.g., to `https://mixed.hdc.company/api/user`).
        4.  Select this request and look at the "Request Headers".
        5.  **Check for the `Cookie` Header:** See if the session cookie (e.g., `connect.sid=...`) was actually sent with this request to the BFF.

### Interpreting Findings & Potential Solutions

*   **If the session cookie is set correctly in the browser (Secure, SameSite=None) but is NOT SENT with the `/api/user` request to the different domain:**
    *   This strongly indicates that the browser is blocking the cookie due to its third-party cookie policies. The browser sees the request from `julesclements.github.io` to `mixed.hdc.company` as a cross-site request and may prevent the `mixed.hdc.company` cookie from being sent.

*   **Potential Long-Term Solutions (Addressing Third-Party Cookie Restrictions):**
    *   This is a widespread challenge for web applications. Robust solutions often involve architectural changes:
        1.  **Align Domains (Same-Site Cookies):** The most effective solution is to host the client application and the BFF under the same parent domain (or subdomains of the same registrable domain). This makes the cookies "first-party" or "same-site."
            *   Examples:
                *   Client: `app.yourdomain.com`, BFF: `api.yourdomain.com`
                *   Client: `www.yourdomain.com/app/`, BFF: `www.yourdomain.com/api/` (if paths are used to differentiate, ensure cookie paths are set correctly).
                *   For this project: Client on `app.mixed.hdc.company` and BFF on `bff.mixed.hdc.company` (or similar).
        2.  **Token-Based Authentication for API Calls (Stateless BFF for `/api/user`):**
            *   Instead of relying on session cookies for API calls from the client to the BFF, the client could store the access token (received via the BFF during login, e.g., from the `/api/user` initial response) in memory.
            *   The client would then send this access token in the `Authorization: Bearer <token>` header for requests to `/api/user`.
            *   The BFF's `/api/user` endpoint would need to be modified to validate this Bearer token (e.g., by introspecting it or validating its signature if it's a JWT and the BFF has the keys) instead of relying on its own session.
            *   This approach makes the specific `/api/user` endpoint stateless from the BFF's session perspective, though the initial OIDC login flow with PingFederate would still use sessions at the BFF.
            *   This is a more significant refactor of the current BFF's `/api/user` logic.
    *   **Research Current Best Practices:** Browser policies around third-party cookies are evolving. Keep an eye on:
        *   **CHIPS (Cookies Having Independent Partitioned State):** This project now includes the `partitioned: true` attribute on the session cookie when in production mode. This allows the cookie to be "partitioned" by the top-level site (e.g., `github.io`), which allows it to be sent in cross-site requests to the BFF (e.g., `hdc.company`) in browsers that support CHIPS (like Chrome).
        *   Other proposals and standards in the Privacy Sandbox and similar initiatives.

This troubleshooting guide should help in diagnosing and understanding potential production deployment issues related to cross-site cookie handling.

## SPA Application (`/spa` directory)

This directory contains a separate Single Page Application (SPA), distinct from the `/client` application. It is also designed to be built and deployed as a Docker container.

*(Note: The initial setup for this SPA, including its `package.json` and source files, would need to be provided or developed. The instructions below assume a typical Node.js based SPA setup where `npm run build` produces static assets in a `dist` directory, and these assets are served by the Docker container.)*

### Local Development & Build (Example)

1.  **Navigate to the SPA directory:**
    ```bash
    cd spa
    ```
2.  **Install Dependencies (if it has its own `package.json`):**
    ```bash
    npm install
    ```
3.  **Build the SPA (if applicable):**
    ```bash
    npm run build
    ```
    (This command depends on the SPA's `package.json` scripts. It's assumed to output files to a `dist` directory within `/spa`.)

### Docker Deployment

The SPA can be deployed as a Docker container using the provided `spa/Dockerfile`.

1.  **Local Docker Build & Run:**
    *   To build the image locally:
        ```bash
        docker build -t yourdockerhubusername/ping-spa:latest spa/
        ```
        (Replace `yourdockerhubusername` with your Docker Hub username or any desired image name).
    *   To run the container locally:
        ```bash
        docker run -d -p 1234:1234 yourdockerhubusername/ping-spa:latest
        ```
        The SPA will then be accessible at `http://localhost:1234` (as per the port exposed and used in the `spa/Dockerfile`).

2.  **Automated Docker Build (GitHub Actions):**
    *   The `.github/workflows/spa-docker-build.yml` workflow automatically builds and pushes the SPA's Docker image to Docker Hub.
    *   This happens on pushes to `main` if files in the `spa/` directory or the `spa-docker-build.yml` workflow file itself are changed.
    *   The image is tagged as `yourdockerhubusername/ping-spa:latest` (or similar, based on the workflow and secrets).
    *   **Required GitHub Secrets:** For this workflow to push to Docker Hub, you must configure `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` in your GitHub repository secrets.

3.  **SPA Configuration (e.g., BFF URL):**
    *   Similar to the `/client` application, the SPA will need to know the URL of the BFF (`bffBaseUrl`).
    *   If the SPA is a static build, this URL might be configured at build time (e.g., via environment variables passed to the build process) or the SPA's JavaScript might dynamically determine it based on `window.location.hostname` (similar to `client/script.js`).
    *   When running the SPA Docker container locally (e.g., on `http://localhost:1234`), it would typically try to connect to the BFF at `http://localhost:3001` if the BFF is also running locally and the SPA uses similar dynamic logic as the `/client` app.
    *   For deployed scenarios, ensure the SPA is configured to point to the production BFF URL (e.g., `https://mixed.hdc.company`).

### BFF API Endpoints

The BFF exposes the following API endpoints that the client interacts with (after the OIDC login/callback flow which also uses BFF routes like `/login`, `/initiate-ping-login`, `/auth/callback`, `/exchange-code`):

*   **`GET /api/user`**
    *   **Purpose:** Retrieves information about the currently authenticated user, including ID token, access token, and claims.
    *   **Authentication:** Requires an active BFF session (session cookie).
    *   **Response:**
        ```json
        {
          "message": "User is authenticated. Token details below.",
          "id_token": "raw_id_token_string",
          "access_token": "raw_access_token_string",
          "claims": { /* user claims object */ }
        }
        ```
    *   Returns a 401 error if the user is not authenticated or the session is incomplete.

*   **`POST /api/introspect-token`**
    *   **Purpose:** Allows introspection of a provided token (typically an access token) via the PingFederate introspection endpoint.
    *   **Authentication:** Requires an active BFF session. The BFF uses its OIDC client credentials to communicate with the introspection endpoint.
    *   **Request Body (JSON):**
        ```json
        {
          "token_to_introspect": "your_access_token_string"
        }
        ```
    *   **Response:** Returns the JSON response directly from PingFederate's introspection endpoint. This typically includes an `active: true/false` field and other metadata about the token if it's valid and active.
    *   Returns appropriate error responses (400, 401, 500) if the request is invalid, the user is not authenticated with the BFF, or introspection fails.

*   **Login/Logout:** Initiates OIDC authentication flow via the BFF. This involves:
    1. Redirect to BFF's `/login` (shows confirmation page).
    2. User confirms, browser hits BFF's `/initiate-ping-login` (redirects to PingFederate).
    3. After PingFederate auth, redirect to BFF's `/auth/callback` (shows auth code).
    4. User confirms, browser hits BFF's `/exchange-code` (BFF exchanges code for tokens, sets session, redirects to client).
*   **Fetch User Info:** After login, clicking "Get User Info" (after a confirmation dialog) calls the BFF's `/api/user` endpoint. The displayed information includes:
    *   ID Token Claims (as validated and provided by the BFF).
    *   Client-side decoded payload of the ID Token.
    *   Client-side decoded payload of the Access Token (if it's a JWT and parseable). If the Access Token is opaque or not a JWT, the raw token is shown.
    *   The raw ID Token string.
    *   The raw Access Token string.
*   **Introspect Access Token (Conditional):**
    *   If, after fetching user info, the Access Token is found to be opaque (i.e., not a client-decodable JWT), an "Introspect Access Token" button will appear.
    *   Clicking this button sends the Access Token to the BFF's `/api/introspect-token` endpoint.
    *   The JSON introspection result from the BFF (which it gets from PingFederate) is then displayed in a dedicated section on the client page.
    *   This feature is primarily for demonstration and development purposes to understand the details of opaque access tokens.
*   **X-Correlation-ID Handling (Client-Side):**
    *   The client application (`client/script.js`) generates a UUID v4 as an `X-Correlation-ID` to help trace a user's interaction journey.
    *   This ID is passed as a query parameter to the BFF's `/login` route and subsequently sent as an `X-Correlation-ID` header in API calls to `/api/user` and `/api/introspect-token`.
    *   To maintain consistency across page loads and redirects during a single user journey (e.g., after being redirected back from the BFF), the `X-Correlation-ID` is persisted in the browser's `sessionStorage`.
    *   A new ID is generated when the user explicitly initiates a new login, or if no ID is found in `sessionStorage` when an action requiring an ID (like "Get User Info") is performed.
    *   The ID is cleared from `sessionStorage` when the user logs out.
*   **X-Correlation-ID Handling (BFF-Side & Backchannel):**
    *   The BFF is designed to log the `X-Correlation-ID` at various stages of processing requests (login initiation, callback, token exchange, API calls).
    *   **Backchannel Requests to PingFederate:**
        *   **Token Introspection (`/api/introspect-token`):** When the BFF's `/api/introspect-token` endpoint is called, the BFF includes the `X-Correlation-ID` (received from the client's request) as an HTTP header in its direct backchannel request to PingFederate's introspection endpoint.
        *   **Token Exchange (`/exchange-code`):** During the token exchange step (when the BFF exchanges the authorization code for tokens with PingFederate), the BFF logs the `X-Correlation-ID` (retrieved from the user's session). However, the `openid-client` library's standard `callback()` method for this exchange does not provide a direct, per-call option to inject dynamic custom HTTP headers like `X-Correlation-ID`. Thus, while logged by the BFF, this ID might not be present as a header in the actual HTTP POST to PingFederate's token endpoint. Global HTTP options set for `openid-client` (like a custom agent for SSL) apply, but not dynamic per-request headers for this specific call.
        *   **Authorization Redirect (Browser to PingFederate):** When the BFF redirects the user's browser to PingFederate's authorization endpoint (e.g., `/as/authorization.oauth2`), the `X-Correlation-ID` (even if passed to the BFF's `/login` or `/initiate-ping-login` routes) cannot be injected by the BFF as an HTTP header into this redirect, as it's a standard browser navigation initiated by the user agent. The ID is logged by the BFF during these initiation steps.
    *   This forwarding of the `X-Correlation-ID` in backchannel requests (where possible) can be very useful if PingFederate's audit logs or its detailed request logging is configured to capture and display custom HTTP headers, aiding in end-to-end tracing of a specific user interaction.
*   **Security Note on Client-Side Token Decoding:** The client-side decoding of JWTs (ID Token, Access Token) is **for display and informational purposes only**. The client **must not** use any information decoded from these tokens to make security decisions or to grant access to resources. All token validation (signatures, expiry, claims) and authorization decisions are the responsibility of the Backend-for-Frontend (BFF).
