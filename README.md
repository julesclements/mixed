# PingFederate OIDC Authentication: Client + BFF Example

This project demonstrates a client-server architecture where a frontend client application (served via GitHub Pages or locally) interacts with a Backend-for-Frontend (BFF) to handle OIDC authentication with PingFederate.

The repository is structured as a monorepo:
-   `/client`: Contains the static frontend Javascript application.
-   `/bff`: Contains the Node.js/Express Backend-for-Frontend (BFF) application.

## Architecture Flow (Simplified)

```
1. User clicks "Login" on Client App.
   Client (Browser)  ---- Redirect to /login ----> BFF (Node.js/Express)

2. BFF's /login route serves an HTML confirmation page.
   User sees "Confirm Login" page in browser.

3. User clicks "Proceed to PingFederate" on confirmation page.
   Browser  ---- GET request to /initiate-ping-login ----> BFF

4. BFF's /initiate-ping-login route initiates OIDC flow.
   BFF (Node.js/Express) -- Redirect to PingFederate --> PingFederate Auth Server

3. User authenticates with PingFederate.
   User <---- Authenticates ----> PingFederate Auth Server

4. PingFederate redirects back to BFF with authorization code.
   PingFederate Auth Server -- Redirect with code --> BFF (/auth/callback)

6. BFF's /auth/callback route validates state, then displays an HTML page showing the authorization code.
   User sees "Authorization Code Received" page in browser.

7. User clicks "Exchange Code & Proceed" on this page.
   Browser  ---- GET request to /exchange-code ----> BFF

8. BFF's /exchange-code route exchanges the code (retrieved from session) for tokens, stores tokens and user info in session, sets session cookie.
   BFF <---- OIDC Token Exchange ---- PingFederate Auth Server
   BFF ---- Sets HTTP-Only Session Cookie ----> Client (Browser)

9. BFF redirects user back to Client App.
   BFF ---- Redirect ----> Client (Browser)

10. Client requests user data from BFF.
   Client (Browser) ---- GET /api/user (with session cookie) ----> BFF

9. BFF validates session, returns user data.
   BFF ---- Returns User JSON ----> Client (Browser)

11. User clicks "Logout" on Client App.
     Client (Browser) ---- Redirect to /logout ----> BFF

12. BFF clears local session, initiates OIDC logout.
      BFF ---- Redirect to PingFederate SLO ----> PingFederate Auth Server

13. PingFederate logs out user, redirects back to Client App (via BFF's post_logout_redirect_uri).
      PingFederate Auth Server ---- Redirect ----> Client (Browser)
```

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

## BFF Setup (`/bff` directory)

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
    *   `BFF_PORT`: The port on which the BFF server will listen (default is `3001`).
    *   `FRONTEND_ORIGIN`: **Crucial for CORS configuration.** This **MUST be the exact *origin*** of your client application, used for the BFF's `Access-Control-Allow-Origin` header.
        *   An origin is defined by its scheme (e.g., `http` or `https`), hostname (e.g., `localhost`, `julesclements.github.io`), and port (if it's not the default for the scheme, e.g., `:1234`).
        *   **DO NOT include paths or trailing slashes.**
        *   **Correct Examples:**
            *   For local client development (e.g., Parcel dev server on port 1234): `http://localhost:1234`
            *   For the production client on GitHub Pages: `https://julesclements.github.io`
        *   **Incorrect Examples:** `http://localhost:1234/`, `https://julesclements.github.io/mixed/`
        *   **Why it's important for CORS:** The browser's `Origin` header (e.g., `https://julesclements.github.io`) sent with cross-origin requests from the client must exactly match this `FRONTEND_ORIGIN` value for the browser to accept responses from the BFF.
    *   `FRONTEND_REDIRECT_URL`: The **full URL** (including any necessary path like `/mixed/`) where the BFF should redirect the user's browser after operations like login or logout.
        *   **Correct Examples:**
            *   For local client development (if client is served at the root of its port): `http://localhost:1234/`
            *   For the production client on GitHub Pages (if the site is `julesclements.github.io/mixed/`): `https://julesclements.github.io/mixed/`
        *   This URL is used in OIDC `post_logout_redirect_uri` and for redirecting after the token exchange.
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

5.  **CORS Configuration:**
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

## Client Setup (`/client` directory)

The client is a static Javascript application that makes API calls to the BFF.

1.  **Navigate to the Client directory:**
    ```bash
    cd client
    ```
    (If you were in `bff`, you'd do `cd ../client`)

2.  **Install Dependencies:**
    (This installs Parcel and other development tools)
    ```bash
    npm install
    ```

3.  **Run the Client for Development:**
    You have a couple of options:

    *   **Using Parcel's Dev Server (Recommended for Development):**
        The `package.json` includes a `dev` script. This will start a development server with hot reloading.
        ```bash
        npm run dev
        ```
        This typically runs `parcel index.html --port 1234` (or similar, check `client/package.json`). The client will be available at `http://localhost:1234`.

    *   **Build Static Files and Serve Locally:**
        First, build the application:
        ```bash
        npm run build
        ```
        This creates a `docs` directory inside `/client` with the static files. Then serve this directory:
        ```bash
        npx serve client/docs -p 1234
        ```
        (You might need to install `serve`: `npm install -g serve`)

4.  **`bffBaseUrl` in `client/script.js`:**
    The `client/script.js` file dynamically determines the `bffBaseUrl` (the URL for your BFF):
    *   If the client is accessed via `localhost` or `127.0.0.1` (local development), it automatically sets `bffBaseUrl` to `http://localhost:3001` (assuming your BFF is running locally on port 3001).
    *   If the client is accessed via `julesclements.github.io` (the deployed GitHub Pages site), it sets `bffBaseUrl` to `https://mixed.hdc.company`. This should match the public URL where your BFF is deployed.
    *   For other hostnames, it defaults to an empty string (`''`), implying the BFF is at the same origin as the client (less common for this setup).

## Deployment

### Client Application (`/client`)
*   The client application is configured to be built and deployed to **GitHub Pages** automatically.
*   This is handled by the GitHub Actions workflow defined in `.github/workflows/client-deploy.yml`.
*   Deployment happens on pushes to the `main` branch (if changes are detected in the `client/` directory or the workflow file).

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

### Client Application Features
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
*   **Security Note on Client-Side Token Decoding:** The client-side decoding of JWTs (ID Token, Access Token) is **for display and informational purposes only**. The client **must not** use any information decoded from these tokens to make security decisions or to grant access to resources. All token validation (signatures, expiry, claims) and authorization decisions are the responsibility of the Backend-for-Frontend (BFF).
