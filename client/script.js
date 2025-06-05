// client/script.js

// Select DOM elements globally after the document structure is known,
// but ensure they are only accessed *after* DOMContentLoaded if their state is critical at load.
// For simple element existence, this is fine. Event listeners will be attached in DOMContentLoaded.
let loginButton, fetchUserButton, logoutButton, userInfoDiv, errorMessageDiv, introspectionSection;
let bffBaseUrl = ''; // Default to same-origin, will be set in DOMContentLoaded

// Dynamically determine BFF base URL - this part needs to be inside DOMContentLoaded
// or called from there, as window.location might not be fully reliable before that for complex scenarios,
// though for hostname it's usually fine. For safety and consistency, we'll set bffBaseUrl in DOMContentLoaded.

document.addEventListener('DOMContentLoaded', () => {
    // Assign elements now that DOM is loaded
    loginButton = document.getElementById('loginButton');
    fetchUserButton = document.getElementById('fetchUserButton');
    logoutButton = document.getElementById('logoutButton');
    userInfoDiv = document.getElementById('userInfo');
    errorMessageDiv = document.getElementById('errorMessage');
    introspectionSection = document.getElementById('introspectionSection');


    // Dynamically determine BFF base URL
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

                // Conditionally add/remove Introspect Access Token button
                const introspectionSection = document.getElementById('introspectionSection');
                introspectionSection.innerHTML = ''; // Clear previous button or results from this section

                if (!decodedAccessToken && data.access_token) { // If token is opaque (not decoded) and exists
                    const introspectButton = document.createElement('button');
                    introspectButton.id = 'introspectTokenButton'; // ID for potential direct styling or selection
                    // introspectButton.className = 'button'; // Use if you have a general .button CSS class
                    introspectButton.textContent = 'Introspect Access Token';
                    introspectButton.addEventListener('click', () => handleIntrospectionClick(data.access_token));
                    introspectionSection.appendChild(introspectButton);
                }

                errorMessageDiv.textContent = ''; // Clear any previous global errors
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

    // Initialize UI elements that might be affected by fetchUser status (e.g., clear old messages)
    if (userInfoDiv) userInfoDiv.innerHTML = '';
    if (errorMessageDiv) errorMessageDiv.textContent = '';
    if (introspectionSection) introspectionSection.innerHTML = ''; // Clear any old introspection results/button

    // Show login/fetch buttons by default, hide logout
    // This might be redundant if fetchUser() on load handles it, but good for clarity if no auto-fetch
    if (loginButton) loginButton.style.display = 'block';
    if (fetchUserButton) fetchUserButton.style.display = 'block';
    if (logoutButton) logoutButton.style.display = 'none';
});

// Helper function to decode JWT payload (simplistic, no signature verification)
function decodeJwtPayload(token) {
  if (!token || typeof token !== 'string') {
    return null;
  }
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      console.warn("Token does not have 3 parts, cannot decode payload.");
      return null;
    }
    const payloadBase64Url = parts[1];
    const payloadBase64 = payloadBase64Url.replace(/-/g, '+').replace(/_/g, '/');
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
        return '';
    }
    return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}

const fetchUser = async () => {
    // Ensure elements are available before trying to update them
    if (!userInfoDiv || !errorMessageDiv || !loginButton || !fetchUserButton || !logoutButton || !introspectionSection) {
        console.error('Required DOM elements not found in fetchUser.');
        return;
    }
    try {
        const response = await fetch(`${bffBaseUrl}/api/user`, { credentials: 'include' });

        if (response.ok) { // Status 200-299
            const data = await response.json();

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
              userInfoHtml += `<pre style="word-wrap: break-word; white-space: pre-wrap;">${escapeHtml(data.access_token)}</pre>`;
            }

            userInfoHtml += '<h4>Raw ID Token:</h4>';
            userInfoHtml += `<pre style="word-wrap: break-word; white-space: pre-wrap;">${escapeHtml(data.id_token)}</pre>`;
            userInfoHtml += '<h4>Raw Access Token:</h4>';
            userInfoHtml += `<pre style="word-wrap: break-word; white-space: pre-wrap;">${escapeHtml(data.access_token)}</pre>`;

            userInfoDiv.innerHTML = userInfoHtml;
            introspectionSection.innerHTML = ''; // Clear previous button or results

            if (!decodedAccessToken && data.access_token) {
                const introspectButton = document.createElement('button');
                introspectButton.id = 'introspectTokenButton';
                introspectButton.textContent = 'Introspect Access Token';
                introspectButton.addEventListener('click', () => handleIntrospectionClick(data.access_token));
                introspectionSection.appendChild(introspectButton);
            }

            errorMessageDiv.textContent = '';
            loginButton.style.display = 'none';
            fetchUserButton.style.display = 'none';
            logoutButton.style.display = 'block';
        } else if (response.status === 401) {
            userInfoDiv.innerHTML = '';
            introspectionSection.innerHTML = ''; // Clear introspection section on logout/401
            errorMessageDiv.textContent = 'Please login to view user information.';
            loginButton.style.display = 'block';
            fetchUserButton.style.display = 'block';
            logoutButton.style.display = 'none';
        } else {
            const errorText = await response.text();
            userInfoDiv.innerHTML = '';
            introspectionSection.innerHTML = '';
            errorMessageDiv.textContent = `Error fetching user: ${response.status} ${errorText || response.statusText}`;
            loginButton.style.display = 'block';
            fetchUserButton.style.display = 'block';
            logoutButton.style.display = 'none';
        }
    } catch (error) {
        console.error('Fetch user error:', error);
        userInfoDiv.innerHTML = '';
        introspectionSection.innerHTML = '';
        errorMessageDiv.textContent = 'Network error or server is unavailable. Please try again later.';
        loginButton.style.display = 'block';
        fetchUserButton.style.display = 'block';
        logoutButton.style.display = 'none';
    }
};

const login = () => {
    console.log('Login button clicked, redirecting to BFF login...');
    window.location.href = `${bffBaseUrl}/login`;
};

const logout = () => {
    window.location.href = `${bffBaseUrl}/logout`;
};


// handleIntrospectionClick function (now can access global errorMessageDiv and bffBaseUrl)
async function handleIntrospectionClick(accessTokenString) {
  console.log('Introspection requested for token (first 20 chars):', accessTokenString.substring(0, 20) + "...");

  // Ensure elements are available
  if (!introspectionSection || !errorMessageDiv) {
      console.error('Required DOM elements not found in handleIntrospectionClick.');
      return;
  }

  const displayAreaId = 'introspectionDisplayArea';
  let displayArea = document.getElementById(displayAreaId);

  if (!displayArea || !introspectionSection.contains(displayArea)) {
    if (displayArea) displayArea.remove();
    displayArea = document.createElement('div');
    displayArea.id = displayAreaId;
    introspectionSection.appendChild(displayArea);
  }

  displayArea.innerHTML = '<p>Introspecting token...</p>';
  errorMessageDiv.textContent = '';

  try {
    const response = await fetch(`${bffBaseUrl}/api/introspect-token`, {
      method: 'POST',
      credentials: 'include', // Send session cookies
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ token_to_introspect: accessTokenString }),
    });

    const introspectionData = await response.json(); // Try to parse JSON regardless of response.ok

    if (response.ok) {
      displayArea.innerHTML = '<h4>Introspection Result:</h4><pre>' + JSON.stringify(introspectionData, null, 2) + '</pre>';
    } else {
      console.error('Introspection failed:', introspectionData);
      let errorMsg = `Introspection Error ${response.status}: ${introspectionData.error || response.statusText}`;
      if (introspectionData.message) errorMsg += ` - ${introspectionData.message}`;
      if (introspectionData.details) errorMsg += ` (Details: ${JSON.stringify(introspectionData.details)})`;
      displayArea.innerHTML = `<p style="color:red;">${escapeHtml(errorMsg)}</p>`;
      // Also display in main error message div for more visibility if desired
      errorMessageDiv.textContent = `Introspection failed. See details above or in console.`;
    }
  } catch (error) {
    console.error('Network error during token introspection:', error);
    const networkErrorMsg = 'Network error or BFF unavailable during token introspection.';
    displayArea.innerHTML = `<p style="color:red;">${escapeHtml(networkErrorMsg)}</p>`;
    errorMessageDiv.textContent = networkErrorMsg;
  }
}
