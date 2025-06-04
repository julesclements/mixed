// script.js
document.addEventListener('DOMContentLoaded', async () => {
    const appDiv = document.getElementById('app');
    const userInfoDiv = document.getElementById('userInfo');
    const loginBtn = document.getElementById('loginBtn');
    const logoutBtn = document.getElementById('logoutBtn');

    // Determine the correct global SDK object.
    // Common patterns: PingSDK.Auth, PingIdentity.Auth, forgerock.Auth, or directly Auth.
    let AuthClass = null;
    if (window.PingSDK && window.PingSDK.Auth) {
        AuthClass = window.PingSDK.Auth;
    } else if (window.PingIdentity && window.PingIdentity.Auth) {
        AuthClass = window.PingIdentity.Auth;
    } else if (window.forgerock && window.forgerock.Auth) { // In case it's an older version or different branding
        AuthClass = window.forgerock.Auth;
    } else if (window.Auth) {
        AuthClass = window.Auth;
    }

    if (!AuthClass) {
        const errorMessage = "PingFederate SDK not found. Please ensure it's correctly loaded via CDN.";
        console.error(errorMessage);
        appDiv.innerHTML = `<p style="color: red;">${errorMessage}</p>`;
        // Hide buttons if SDK is not loaded
        if(loginBtn) loginBtn.style.display = 'none';
        if(logoutBtn) logoutBtn.style.display = 'none';
        return;
    }

    // PingFederate SDK configuration
    const auth = new AuthClass({
        client_id: 'jules-oidc-client',
        redirect_uri: window.location.origin + window.location.pathname, // Corrected redirect URI
        discovery_uri: 'https://ping.hdc.company/.well-known/openid-configuration',
        scopes: ['openid', 'profile', 'email'],
        response_type: 'code', // Explicitly set for Authorization Code Flow
        pkce: true // Ensure PKCE is enabled (SDKs usually default to true for 'code' flow)
    });

    // Function to handle the redirect callback
    const handleRedirectCallback = async () => {
        try {
            // SDK's handleRedirectCallback typically clears the URL parameters
            const tokenResponse = await auth.handleRedirectCallback(window.location.href);
            if (tokenResponse && tokenResponse.access_token) {
                console.log('Token obtained:', tokenResponse);
                // The SDK usually stores tokens internally.
                // If manual storage is needed, this is where you'd do it.
                // e.g., localStorage.setItem('access_token', tokenResponse.access_token);
                // After processing, remove query parameters if SDK doesn't do it.
                if (window.history.replaceState) {
                    window.history.replaceState({}, document.title, window.location.pathname);
                }
            } else if (window.location.search.includes('error=')) {
                 const urlParams = new URLSearchParams(window.location.search);
                 const error = urlParams.get('error');
                 const errorDescription = urlParams.get('error_description');
                 console.error('Error from auth server:', error, errorDescription);
                 appDiv.innerHTML = `<p style="color: red;">Login Error: ${error} - ${errorDescription}</p>`;
                 if (window.history.replaceState) {
                    window.history.replaceState({}, document.title, window.location.pathname);
                 }
            }
        } catch (error) {
            console.error('Error handling redirect callback:', error);
            appDiv.innerHTML = `<p style="color: red;">Error processing login: ${error.message}</p>`;
        }
    };

    // Function to update UI based on authentication state
    const updateUI = async () => {
        try {
            // Check if there's an active session or valid token for the 'openid' scope.
            // The exact method might vary (e.g., hasValidSession, isAuthenticated)
            const isAuthenticated = await auth.isAuthenticated({scopes: ['openid']});
            if (isAuthenticated) {
                const userInfo = await auth.userInfo();
                let userInfoContent = '<h3>User Information:</h3>';
                if (userInfo) {
                    userInfoContent += `<p><strong>Name:</strong> ${userInfo.name || 'N/A'}</p>`;
                    userInfoContent += `<p><strong>Email:</strong> ${userInfo.email || 'N/A'}</p>`;
                    userInfoContent += `<p><strong>Sub:</strong> ${userInfo.sub || 'N/A'}</p>`;
                    userInfoContent += '<h4>Raw UserInfo:</h4>';
                    userInfoContent += `<pre>${JSON.stringify(userInfo, null, 2)}</pre>`;
                } else {
                    userInfoContent += '<p>Could not fetch user information.</p>';
                }
                userInfoDiv.innerHTML = userInfoContent;
                appDiv.innerHTML = '<p>User is logged in.</p>';
                if(loginBtn) loginBtn.style.display = 'none';
                if(logoutBtn) logoutBtn.style.display = 'block';
            } else {
                userInfoDiv.innerHTML = '';
                appDiv.innerHTML = '<p>User is logged out. Please login.</p>';
                if(loginBtn) loginBtn.style.display = 'block';
                if(logoutBtn) logoutBtn.style.display = 'none';
            }
        } catch (error) {
            console.error('Error updating UI:', error);
            userInfoDiv.innerHTML = '';
            appDiv.innerHTML = `<p style="color: red;">Error checking authentication status: ${error.message}. Please try logging in.</p>`;
            if(loginBtn) loginBtn.style.display = 'block';
            if(logoutBtn) logoutBtn.style.display = 'none';
        }
    };

    // Event listeners for login and logout buttons
    if(loginBtn) {
        loginBtn.addEventListener('click', async () => {
            try {
                // The authorize method will redirect the user to PingFederate
                await auth.authorize({scopes: ['openid', 'profile', 'email']});
            } catch (error) {
                console.error('Error initiating login:', error);
                appDiv.innerHTML = `<p style="color: red;">Error during login initiation: ${error.message}</p>`;
            }
        });
    }

    if(logoutBtn) {
        logoutBtn.addEventListener('click', async () => {
            try {
                // Attempt to revoke tokens first
                if (await auth.isAuthenticated()) { // Check if authenticated before trying to revoke
                    const accessToken = await auth.getToken('access_token'); // Or however SDK provides it
                    if (accessToken) await auth.revokeToken('access_token');
                    
                    // Refresh token revocation if SDK supports/manages it
                    // const refreshToken = await auth.getToken('refresh_token');
                    // if (refreshToken) await auth.revokeToken('refresh_token');
                }
            } catch (error) {
                console.warn('Error revoking tokens, proceeding with sign out:', error);
            }
            try {
                // End session with PingFederate and redirect back
                await auth.signOut({ post_logout_redirect_uri: window.location.origin + window.location.pathname });
            } catch (error) {
                console.error('Error during sign out:', error);
                // Fallback: Clear local SDK state and update UI
                // SDK might have a method like auth.clearLocalSession() or auth.clearTokens()
                // For now, just update UI as if logged out
                userInfoDiv.innerHTML = '';
                appDiv.innerHTML = '<p>User is logged out (or sign out failed, local state cleared).</p>';
                if(loginBtn) loginBtn.style.display = 'block';
                if(logoutBtn) logoutBtn.style.display = 'none';
            }
            // Note: The page will redirect for signOut, so UI update below might not be hit if successful.
            // If signOut fails and doesn't redirect, this ensures UI consistency.
            if (! (await auth.isAuthenticated())) { // Re-check auth status after potential failed signout
                 userInfoDiv.innerHTML = '';
                 appDiv.innerHTML = '<p>User is logged out.</p>';
                 if(loginBtn) loginBtn.style.display = 'block';
                 if(logoutBtn) logoutBtn.style.display = 'none';
            }
        });
    }
    
    // Check if this is a redirect from PingFederate (Authorization Code Flow)
    // The SDK's handleRedirectCallback should ideally detect this.
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.has('code') || urlParams.has('error') || window.location.hash.includes('access_token=') || window.location.hash.includes('id_token=')) {
        await handleRedirectCallback();
    }

    // Initial UI update
    await updateUI();
});
