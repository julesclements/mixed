// client/script.js

let loginButton, fetchUserButton, logoutButton, userInfoDiv, errorMessageDiv, introspectionSection;
let bffBaseUrl = '';
let currentCorrelationId = null;

// Attempt to load from sessionStorage on script load/parse
const storedCorrelationId = sessionStorage.getItem('xCorrelationId');
if (storedCorrelationId) {
  currentCorrelationId = storedCorrelationId;
  console.log('Loaded existing X-Correlation-ID from sessionStorage:', currentCorrelationId);
}

// --- Helper Functions ---

function generateUUIDv4() {
  return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
    (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
  );
}

function ensureCorrelationId() {
  if (!currentCorrelationId) {
    currentCorrelationId = generateUUIDv4();
    sessionStorage.setItem('xCorrelationId', currentCorrelationId);
    console.log('Generated new X-Correlation-ID for current journey and stored in sessionStorage:', currentCorrelationId);
  }
  return currentCorrelationId;
}

function decodeJwtPayload(token) {
  if (!token || typeof token !== 'string') { return null; }
  try {
    const parts = token.split('.');
    if (parts.length !== 3) { console.warn("Token does not have 3 parts."); return null; }
    const payloadBase64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const decodedJson = atob(payloadBase64);
    return JSON.parse(decodedJson);
  } catch (e) { console.error("Failed to decode JWT payload:", e); return null; }
}

function escapeHtml(unsafe) {
  if (typeof unsafe !== 'string') { return ''; }
  return unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}


document.addEventListener('DOMContentLoaded', () => {
    loginButton = document.getElementById('loginButton');
    fetchUserButton = document.getElementById('fetchUserButton');
    logoutButton = document.getElementById('logoutButton');
    userInfoDiv = document.getElementById('userInfo');
    errorMessageDiv = document.getElementById('errorMessage');
    introspectionSection = document.getElementById('introspectionSection');

    const hostname = window.location.hostname;
    if (hostname === 'localhost' || hostname === '127.0.0.1') {
        bffBaseUrl = 'http://localhost:3001';
        console.log('Client running locally, BFF assumed at:', bffBaseUrl);
    } else if (hostname === 'julesclements.github.io' || hostname === 'client.hdc.company') {
        bffBaseUrl = 'https://mixed.hdc.company';
        console.log('Client running on known production domain, BFF set to:', bffBaseUrl);
    } else {
        bffBaseUrl = '';
        console.log('Client running on other hostname, BFF assumed same-origin or proxied.');
    }

    if (loginButton) { loginButton.addEventListener('click', login); }
    if (fetchUserButton) {
        fetchUserButton.addEventListener('click', () => {
            if (window.confirm("About to call BFF to get user info. Proceed?")) {
                fetchUser();
            }
        });
    }
    if (logoutButton) { logoutButton.addEventListener('click', logout); }

    if (userInfoDiv) userInfoDiv.innerHTML = '';
    if (errorMessageDiv) errorMessageDiv.textContent = '';
    if (introspectionSection) introspectionSection.innerHTML = '';
    if (loginButton) loginButton.style.display = 'block';
    if (fetchUserButton) fetchUserButton.style.display = 'none';
    if (logoutButton) logoutButton.style.display = 'none';

    // Check for diagnostic errors from BFF
    const urlParams = new URLSearchParams(window.location.search);
    const exchangeError = urlParams.get('exchange_error');
    if (exchangeError) {
        const correlationId = urlParams.get('correlationId');
        let errorMsg = `Token Exchange Failed: ${exchangeError}`;
        if (correlationId) errorMsg += ` (Correlation ID: ${correlationId})`;
        alert(errorMsg); // Diagnostic dialogue
    }

    const loginStatus = urlParams.get('login_status');

    // Perform an automatic auth check on page load to update the UI
    fetchUser(true, loginStatus === 'success').then(() => {
        // Clean up diagnostic parameters from the URL
        if (exchangeError || loginStatus) {
            window.history.replaceState({}, document.title, window.location.pathname);
        }
    });
});


const fetchUser = async (isSilent = false, expectedLogin = false) => {
    if (!userInfoDiv || !errorMessageDiv || !loginButton || !fetchUserButton || !logoutButton || !introspectionSection) {
        console.error('Required DOM elements not found in fetchUser.');
        return;
    }
    const idToUse = ensureCorrelationId();
    try {
        const response = await fetch(`${bffBaseUrl}/api/user`, {
            credentials: 'include',
            headers: { 'X-Correlation-ID': idToUse }
        });

        if (response.ok) {
            const data = await response.json();

            if (!isSilent) {
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

                introspectionSection.innerHTML = '';
                if (!decodedAccessToken && data.access_token) {
                    const introspectButton = document.createElement('button');
                    introspectButton.id = 'introspectTokenButton';
                    introspectButton.textContent = 'Introspect Access Token';
                    introspectButton.addEventListener('click', () => handleIntrospectionClick(data.access_token));
                    introspectionSection.appendChild(introspectButton);
                }
            }

            errorMessageDiv.textContent = '';
            loginButton.style.display = 'none';
            fetchUserButton.style.display = 'block'; // Keep fetch button visible to allow refreshing
            logoutButton.style.display = 'block';
        } else if (response.status === 401) {
            userInfoDiv.innerHTML = '';
            introspectionSection.innerHTML = '';

            if (expectedLogin) {
                const urlParams = new URLSearchParams(window.location.search);
                const correlationId = urlParams.get('correlationId');
                const sessionId = urlParams.get('sessionId');
                
                // Log detailed cross-site debugging information
                console.warn('Cross-site authentication issue detected');
                console.log('Frontend origin:', window.location.origin);
                console.log('BFF origin:', new URL(bffBaseUrl).origin);
                console.log('Expected session ID from BFF:', sessionId);
                
                let diagMsg = `Session Diagnostic: The BFF reported a successful login, but the subsequent request to /api/user failed to provide a valid session.\n\n`;
                diagMsg += `This occurs in cross-site scenarios where the browser blocks third-party cookies.\n`;
                diagMsg += `Frontend: ${window.location.origin}\n`;
                diagMsg += `BFF: ${new URL(bffBaseUrl).origin}\n\n`;
                diagMsg += `SOLUTIONS:\n`;
                diagMsg += `1. Check browser cookie settings: Allow third-party cookies for ${new URL(bffBaseUrl).hostname}\n`;
                diagMsg += `2. Ensure BFF is running with NODE_ENV=production (enables Secure flag)\n`;
                diagMsg += `3. For production: Use a same-origin proxy pattern or hosted on same domain\n`;
                
                if (correlationId) diagMsg += `\nCorrelation ID: ${correlationId}`;
                if (sessionId) diagMsg += `\nSession ID (from BFF): ${sessionId}`;
                
                alert(diagMsg);
            } else if (!isSilent) {
                errorMessageDiv.textContent = 'Please login to view user information.';
            }
            loginButton.style.display = 'block';
            fetchUserButton.style.display = 'none';
            logoutButton.style.display = 'none';
        } else {
            const errorText = await response.text();
            userInfoDiv.innerHTML = '';
            introspectionSection.innerHTML = '';
            if (!isSilent) {
                errorMessageDiv.textContent = `Error fetching user: ${response.status} ${errorText || response.statusText}`;
            }
            loginButton.style.display = 'block';
            fetchUserButton.style.display = 'none';
            logoutButton.style.display = 'none';
        }
    } catch (error) {
        console.error('Fetch user error:', error);
        userInfoDiv.innerHTML = '';
        introspectionSection.innerHTML = '';
        if (!isSilent) {
            errorMessageDiv.textContent = 'Network error or server is unavailable. Please try again later.';
        }
        loginButton.style.display = 'block';
        fetchUserButton.style.display = 'none';
        logoutButton.style.display = 'none';
    }
};

const login = () => {
    // Always generate a new ID for a fresh login journey
    currentCorrelationId = generateUUIDv4();
    sessionStorage.setItem('xCorrelationId', currentCorrelationId);
    console.log('Login initiated. New X-Correlation-ID for this journey:', currentCorrelationId);
    window.location.href = `${bffBaseUrl}/login?correlationId=${currentCorrelationId}`;
};

const logout = () => {
    const idToUseForLogout = ensureCorrelationId(); // Get current or generate if somehow missing
    console.log('Logout initiated. Using X-Correlation-ID:', idToUseForLogout);

    sessionStorage.removeItem('xCorrelationId');
    currentCorrelationId = null;
    console.log('X-Correlation-ID cleared from sessionStorage and current session variable.');

    window.location.href = `${bffBaseUrl}/logout?correlationId=${idToUseForLogout}`;
};

async function handleIntrospectionClick(accessTokenString) {
  if (!introspectionSection || !errorMessageDiv) {
      console.error('Required DOM elements not found in handleIntrospectionClick.');
      return;
  }
  const idToUseInIntrospection = ensureCorrelationId();

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
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-Correlation-ID': idToUseInIntrospection
      },
      body: JSON.stringify({ token_to_introspect: accessTokenString }),
    });

    const introspectionData = await response.json();
    if (response.ok) {
      displayArea.innerHTML = '<h4>Introspection Result:</h4><pre>' + JSON.stringify(introspectionData, null, 2) + '</pre>';
    } else {
      console.error('Introspection failed:', introspectionData);
      let errorMsg = `Introspection Error ${response.status}: ${introspectionData.error || response.statusText}`;
      if (introspectionData.message) errorMsg += ` - ${introspectionData.message}`;
      if (introspectionData.details) errorMsg += ` (Details: ${JSON.stringify(introspectionData.details)})`;
      displayArea.innerHTML = `<p style="color:red;">${escapeHtml(errorMsg)}</p>`;
      errorMessageDiv.textContent = `Introspection failed. See details above or in console.`;
    }
  } catch (error) {
    console.error('Network error during token introspection:', error);
    const networkErrorMsg = 'Network error or BFF unavailable during token introspection.';
    displayArea.innerHTML = `<p style="color:red;">${escapeHtml(networkErrorMsg)}</p>`;
    errorMessageDiv.textContent = networkErrorMsg;
  }
}
