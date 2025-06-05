// client/script.js
document.addEventListener('DOMContentLoaded', () => {
    const loginButton = document.getElementById('loginButton');
    const fetchUserButton = document.getElementById('fetchUserButton');
    const logoutButton = document.getElementById('logoutButton');
    const userInfoDiv = document.getElementById('userInfo');
    const errorMessageDiv = document.getElementById('errorMessage');

    // Dynamically determine BFF base URL
    let bffBaseUrl = ''; // Default to same-origin
    const hostname = window.location.hostname;

    if (hostname === 'localhost' || hostname === '127.0.0.1') {
        bffBaseUrl = 'http://localhost:3001';
        console.log('Client running locally, BFF assumed at:', bffBaseUrl);
    } else if (hostname === 'julesclements.github.io') {
        bffBaseUrl = 'https://mixed.hdc.company'; // New BFF Production URL
        console.log('Client running on GitHub Pages, BFF set to:', bffBaseUrl);
    } else {
        bffBaseUrl = ''; // Default for other cases
        console.log('Client running on other hostname, BFF assumed same-origin or proxied.');
    }

    // Helper function to decode JWT payload (simplistic, no signature verification)
    function decodeJwtPayload(token) {
      if (!token || typeof token !== 'string') {
        return null;
      }
      try {
        const parts = token.split('.');
        if (parts.length !== 3) {
          // Not a standard JWT format (or JWE, which we aren't handling here)
          console.warn("Token does not have 3 parts, cannot decode payload.");
          return null;
        }
        const payloadBase64Url = parts[1];
        const payloadBase64 = payloadBase64Url.replace(/-/g, '+').replace(/_/g, '/');
        // Browsers' atob typically handles padding issues for base64url,
        // but if not, manual padding might be needed:
        // const decodedJson = atob(payloadBase64.padEnd(payloadBase64.length + (4 - payloadBase64.length % 4) % 4, '='));
        const decodedJson = atob(payloadBase64);
        return JSON.parse(decodedJson);
      } catch (e) {
        console.error("Failed to decode JWT payload:", e);
        return null;
      }
    }

    // Helper function to escape HTML for displaying raw tokens (basic)
    function escapeHtml(unsafe) {
        if (typeof unsafe !== 'string') {
            return ''; // Or handle as an error, or return unsafe if it's not a string
        }
        return unsafe
             .replace(/&/g, "&amp;")
             .replace(/</g, "&lt;")
             .replace(/>/g, "&gt;")
             .replace(/"/g, "&quot;")
             .replace(/'/g, "&#039;");
    }

    const fetchUser = async () => {
        try {
            const response = await fetch(`${bffBaseUrl}/api/user`, { credentials: 'include' });

            if (response.ok) { // Status 200-299
                const data = await response.json(); // data = { id_token, access_token, claims, message }

                const decodedIdToken = decodeJwtPayload(data.id_token);
                const decodedAccessToken = decodeJwtPayload(data.access_token);

                let userInfoHtml = `<h3>${escapeHtml(data.message) || 'User Information'}</h3>`;

                userInfoHtml += '<h4>ID Token Claims (from BFF session):</h4>';
                userInfoHtml += `<pre>${JSON.stringify(data.claims, null, 2)}</pre>`;

                userInfoHtml += '<h4>Decoded ID Token Payload (client-side decode):</h4>';
                userInfoHtml += `<pre>${JSON.stringify(decodedIdToken, null, 2)}</pre>`;

                if (decodedAccessToken) {
                  userInfoHtml += '<h4>Decoded Access Token Payload (client-side decode):</h4>';
                  userInfoHtml += `<pre>${JSON.stringify(decodedAccessToken, null, 2)}</pre>`;
                } else {
                  userInfoHtml += '<h4>Access Token (Opaque or unparseable by client):</h4>';
                  // Displaying raw access token can be long, consider if it's always needed.
                  // For JWT access tokens, decoding might be useful. For opaque ones, it's just a string.
                  userInfoHtml += `<pre style="word-wrap: break-word; white-space: pre-wrap;">${escapeHtml(data.access_token)}</pre>`;
                }

                userInfoHtml += '<h4>Raw ID Token:</h4>';
                userInfoHtml += `<pre style="word-wrap: break-word; white-space: pre-wrap;">${escapeHtml(data.id_token)}</pre>`;

                userInfoHtml += '<h4>Raw Access Token:</h4>';
                userInfoHtml += `<pre style="word-wrap: break-word; white-space: pre-wrap;">${escapeHtml(data.access_token)}</pre>`;

                userInfoDiv.innerHTML = userInfoHtml;
                errorMessageDiv.textContent = ''; // Clear any previous errors
                loginButton.style.display = 'none';
                fetchUserButton.style.display = 'none';
                logoutButton.style.display = 'block';
            } else if (response.status === 401) { // Not authenticated
                userInfoDiv.innerHTML = '';
                errorMessageDiv.textContent = 'Please login to view user information.';
                loginButton.style.display = 'block';
                fetchUserButton.style.display = 'block'; // Or hide if login is the only path to get user info
                logoutButton.style.display = 'none';
            } else { // Other errors (e.g., 500 from BFF)
                const errorText = await response.text();
                userInfoDiv.innerHTML = '';
                errorMessageDiv.textContent = `Error fetching user: ${response.status} ${errorText || response.statusText}`;
                loginButton.style.display = 'block';
                fetchUserButton.style.display = 'block';
                logoutButton.style.display = 'none';
            }
        } catch (error) { // Network error or other fetch issues
            console.error('Fetch user error:', error);
            userInfoDiv.innerHTML = '';
            errorMessageDiv.textContent = 'Network error or server is unavailable. Please try again later.';
            loginButton.style.display = 'block';
            fetchUserButton.style.display = 'block';
            logoutButton.style.display = 'none';
        }
    };

    const login = () => {
        // Redirect to the BFF's login endpoint
        // The BFF will handle the OIDC redirect to PingFederate
        window.location.href = `${bffBaseUrl}/login`;
    };

    const logout = () => {
        // Redirect to the BFF's logout endpoint
        // The BFF will handle session termination and PingFederate SLO
        window.location.href = `${bffBaseUrl}/logout`;
    };

    // Attach event listeners
    if (loginButton) {
        loginButton.addEventListener('click', login);
    }
    if (fetchUserButton) {
        fetchUserButton.addEventListener('click', () => {
            if (window.confirm("About to call BFF to get user info. Proceed?")) {
                fetchUser();
            }
        });
    }
    if (logoutButton) {
        logoutButton.addEventListener('click', logout);
    }

    // Initial state: Check authentication status by trying to fetch user info
    // fetchUser(); // Call is now only manual via button. User must click "Get User Info".
});
