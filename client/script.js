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
    } else if (hostname === 'julesclements.github.io') {
        // This should be your deployed BFF URL, which might be different from PingFederate's URL.
        // For this example, assuming the BFF is deployed at 'https://ping.hdc.company'
        // if the client is on 'julesclements.github.io'.
        // IMPORTANT: Replace with your actual deployed BFF URL.
        bffBaseUrl = 'https://ping.hdc.company';
    }
    // For any other hostname, bffBaseUrl remains '', implying same-origin.

    console.log(`Client hostname: ${hostname}, BFF Base URL set to: ${bffBaseUrl}`);

    const fetchUser = async () => {
        try {
            const response = await fetch(`${bffBaseUrl}/api/user`);

            if (response.ok) { // Status 200-299
                const userData = await response.json();
                userInfoDiv.innerHTML = `
                    <h3>User Information:</h3>
                    <p><strong>Name:</strong> ${userData.name || userData.sub || 'N/A'}</p>
                    <p><strong>Email:</strong> ${userData.email || 'N/A'}</p>
                    <pre>${JSON.stringify(userData, null, 2)}</pre>
                `;
                errorMessageDiv.textContent = '';
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
        fetchUserButton.addEventListener('click', fetchUser);
    }
    if (logoutButton) {
        logoutButton.addEventListener('click', logout);
    }

    // Initial state: Check authentication status by trying to fetch user info
    fetchUser();
});
