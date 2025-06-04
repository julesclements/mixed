# PingFederate OIDC Authentication: Client + BFF Example

This project demonstrates a client-server architecture where a frontend client application (served via GitHub Pages or locally) interacts with a Backend-for-Frontend (BFF) to handle OIDC authentication with PingFederate.

The repository is structured as a monorepo:
-   `/client`: Contains the static frontend Javascript application.
-   `/bff`: Contains the Node.js/Express Backend-for-Frontend (BFF) application.

## Architecture Flow (Simplified)

```
1. User clicks "Login" on Client App.
   Client (Browser)  ---- Redirect to /login ----> BFF (Node.js/Express)

2. BFF initiates OIDC flow.
   BFF (Node.js/Express) -- Redirect to PingFederate --> PingFederate Auth Server

3. User authenticates with PingFederate.
   User <---- Authenticates ----> PingFederate Auth Server

4. PingFederate redirects back to BFF with authorization code.
   PingFederate Auth Server -- Redirect with code --> BFF (/auth/callback)

5. BFF exchanges code for tokens, stores them in session, sets session cookie.
   BFF <---- OIDC Callback ---- PingFederate Auth Server
   BFF ---- Sets HTTP-Only Session Cookie ----> Client (Browser)

6. BFF redirects user back to Client App.
   BFF ---- Redirect ----> Client (Browser)

7. Client requests user data from BFF.
   Client (Browser) ---- GET /api/user (with session cookie) ----> BFF

8. BFF validates session, returns user data.
   BFF ---- Returns User JSON ----> Client (Browser)

9. User clicks "Logout" on Client App.
   Client (Browser) ---- Redirect to /logout ----> BFF

10. BFF clears local session, initiates OIDC logout.
    BFF ---- Redirect to PingFederate SLO ----> PingFederate Auth Server

11. PingFederate logs out user, redirects back to Client App (via BFF's post_logout_redirect_uri).
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

The BFF handles the OIDC interaction with PingFederate and manages the user's session.

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
    *   `FRONTEND_URL`: The URL of your client application.
        *   For local client development (e.g., using Parcel's dev server): `http://localhost:1234` (or your client's port).
        *   For testing against a deployed client: Your GitHub Pages URL (e.g., `https://julesclements.github.io/mixed/`).
    *   `BFF_BASE_URL`: The base URL where the BFF itself is running. This is crucial for constructing the `redirect_uri` that PingFederate will use.
        *   For local development: `http://localhost:3001` (or whatever `BFF_PORT` is).
        *   For production: The public URL of your deployed BFF.

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
    *   If the client is accessed via `julesclements.github.io` (the deployed GitHub Pages site), it sets `bffBaseUrl` to `https://ping.hdc.company`. **Important:** This URL (`https://ping.hdc.company`) is a placeholder and **must be replaced** with the actual public URL where your BFF is deployed and accessible from the internet (e.g., the URL of your reverse proxy or deployed BFF container).
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
    *   The `BFF_BASE_URL` environment variable for your deployed BFF should be its public HTTPS URL provided by the reverse proxy.
