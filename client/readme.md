## Client Development

> For deployment guidance, see parent readme.

The client is a static Javascript application that makes API calls to the BFF.

1.  **Navigate to the Client directory:**

    cd client

(If you were in `bff`, you'd do `cd ../client`)

2.  **Install Dependencies:**

(This installs Parcel and other development tools)

    npm install

3.  **Run the Client for Development:**
    You have a couple of options:

- **Using Parcel's Dev Server (Recommended for Development):**

The `package.json` includes a `dev` script. This will start a development server with hot reloading.

    npm run dev

This typically runs `parcel index.html --port 1234` (or similar, check `client/package.json`). The client will be available at `http://localhost:1234`.

- **Build Static Files and Serve Locally:**

First, build the application:

    npm run build

This creates a `docs` directory inside `/client` with the static files. Then serve this directory:

    npx serve client/docs -p 1234

(You might need to install `serve`: `npm install -g serve`)

4.  **`bffBaseUrl` in `client/script.js`:**

The `client/script.js` file dynamically determines the `bffBaseUrl` (the URL for your BFF):

- If the client is accessed via `localhost` or `127.0.0.1` (local development), it automatically sets `bffBaseUrl` to `http://localhost:3001` (assuming your BFF is running locally on port 3001).
- If the client is accessed via `julesclements.github.io` (the deployed GitHub Pages site), it sets `bffBaseUrl` to `https://mixed.hdc.company`. This should match the public URL where your BFF is deployed.
- For other hostnames, it defaults to an empty string (`''`), implying the BFF is at the same origin as the client (less common for this setup).