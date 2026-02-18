# PingFederate Authentication App

> For deployment guidance, see parent readme.

A minimal Node.js application that demonstrates authentication with PingFederate and displays the authorization code after successful sign-in.

## Features

- OAuth 2.0 authentication flow with PingFederate
- Secure redirect handling and callback processing
- Auth code display after successful authentication
- Simple, secure session management
- Responsive design that works across all devices

## Prerequisites

- Node.js (v14 or higher)
- A PingFederate server
- A registered application in PingFederate with proper redirect URIs

## Setup

1. Clone this repository
2. Install dependencies:
   ```
   npm install
   ```
3. Create a `.env` file (e.g., `.env.production` or `.env.development`) and update with your PingFederate credentials:
   ```
   VITE_STAFF_CLIENT_ID=your_client_id
   VITE_PING_BASE_URL=https://your-pingfederate-server
   ```

## Running the application

Start the development server:

```
npm run dev
```

The application will be available at `http://localhost:5173`.

## PingFederate Setup

1. Access your PingFederate administrative console
2. Create a new OAuth client:
   - Name: Choose a name for your application
   - Grant Types: Authorization Code
   - Redirect URIs: http://localhost:5173 (for development)
3. Configure PKCE (Proof Key for Code Exchange)
4. Enable the necessary scopes (openid, profile, email)
5. Note the Client ID for use in your application

## Security Considerations

This is a minimal example for demonstration purposes. For production use, consider:

- Using a more secure session store
- Implementing proper error handling
- Adding HTTPS support
- Using a more robust authentication flow
- Implementing proper token validation
- Handling refresh tokens