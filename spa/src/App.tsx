import { useState, useEffect } from 'react';
import { LogIn, Copy, CheckCircle, ArrowLeft, RefreshCw, LogOut } from 'lucide-react';
import { jwtDecode } from 'jwt-decode';

async function generateCodeVerifierAndChallenge() {
  const array = new Uint32Array(56/2);
  window.crypto.getRandomValues(array);
  const codeVerifier = Array.from(array, dec => ('0' + dec.toString(16)).substr(-2)).join('');

  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await window.crypto.subtle.digest('SHA-256', data);

  const base64Digest = btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  const codeChallenge = base64Digest;

  return { codeVerifier, codeChallenge };
}

async function exchangeCodeForToken(code: string, codeVerifier: string, clientId: string) {
  const pingBaseUrl = import.meta.env.VITE_PING_BASE_URL;
  const tokenEndpoint = pingBaseUrl.includes('/as/token.oauth2')
    ? pingBaseUrl
    : pingBaseUrl.includes('/as/authorization.oauth2')
      ? pingBaseUrl.replace('authorization.oauth2', 'token.oauth2')
      : `${pingBaseUrl.replace(/\/$/, '')}/as/token.oauth2`;

  const redirectUri = `${window.location.origin}/callback`;

  const params = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: clientId,
    code_verifier: codeVerifier,
    code: code,
    redirect_uri: redirectUri,
  });

  const response = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params,
  });

  if (!response.ok) {
    throw new Error('Failed to exchange code for token');
  }

  return await response.json();
}

function App() {
  const [authCode, setAuthCode] = useState<string | null>(null);
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [idToken, setIdToken] = useState<string | null>(null);
  const [decodedIdToken, setDecodedIdToken] = useState<any | null>(null);
  const [decodedAccessToken, setDecodedAccessToken] = useState<any | null>(null);
  const [copied, setCopied] = useState<'code' | 'token' | 'idToken' | null>(null);
  const [isExchanging, setIsExchanging] = useState(false);
  const [exchangeError, setExchangeError] = useState<string | null>(null);
  const [oauthError, setOAuthError] = useState<{ error: string; description?: string; clientId?: string; redirectUri?: string } | null>(null);
  const [showBackMenu, setShowBackMenu] = useState(false);
  const [codeRefreshMessage, setCodeRefreshMessage] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const getErrorGuidance = (errorCode: string): string => {
    const guidance: Record<string, string> = {
      server_error: 'PingFederate returned a server error. This often indicates: (1) Redirect URI mismatch - verify the callback URL is registered in your PingFederate client configuration, (2) Client configuration issue - check that the client ID and settings are correct, or (3) PingFederate server issue - check PingFederate server logs.',
      access_denied: 'Authentication was cancelled or denied by the user or PingFederate policies.',
      invalid_request: 'The authorization request was malformed. Check that all required parameters are present.',
      unauthorized_client: 'The client is not authorized for the requested grant type. Verify client configuration.',
      unsupported_response_type: 'The response type is not supported. Ensure "code" response type is configured.',
      invalid_scope: 'One or more requested scopes are invalid. Check that "openid" scope is available.',
      temporarily_unavailable: 'The authorization server is temporarily unavailable. Please try again later.',
      interaction_required: 'The authorization server requires user interaction. Please sign in again.',
      consent_required: 'The authorization server requires user consent. Please sign in again.',
    };
    return guidance[errorCode] || `An OAuth error occurred: ${errorCode}. Contact your administrator for assistance.`;
  };

  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const error = urlParams.get('error');
    const error_description = urlParams.get('error_description');
    const state = urlParams.get('state');

    if (error) {
      const clientId = sessionStorage.getItem('auth_client_id');
      const redirectUri = `${window.location.origin}/callback`;
      setOAuthError({
        error,
        description: error_description || undefined,
        clientId: clientId || undefined,
        redirectUri
      });
      window.history.replaceState({}, document.title, '/');
    } else if (code) {
      setAuthCode(code);

      if (window.location.pathname === '/callback') {
        window.history.replaceState({}, document.title, '/');
      }
    }
  }, []);

  const handleTokenExchange = async () => {
    setIsExchanging(true);
    setExchangeError(null);
    setCodeRefreshMessage(null);

    try {
      const storedCodeVerifier = sessionStorage.getItem('pkce_code_verifier');
      if (!authCode || !storedCodeVerifier) {
        throw new Error('Missing required authentication data');
      }

      const clientId = import.meta.env.VITE_STAFF_CLIENT_ID;

      const data = await exchangeCodeForToken(
        authCode,
        storedCodeVerifier,
        clientId
      );

      setAccessToken(data.access_token);

      try {
        const decodedAccess = jwtDecode(data.access_token);
        setDecodedAccessToken(decodedAccess);
      } catch (error) {
        console.error('Failed to decode access token:', error);
      }

      if (data.id_token) {
        setIdToken(data.id_token);
        try {
          const decoded = jwtDecode(data.id_token);
          setDecodedIdToken(decoded);
        } catch (error) {
          console.error('Failed to decode ID token:', error);
        }
      }
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Failed to exchange token';
      setExchangeError(errorMsg);

      if (errorMsg.includes('Failed to exchange code for token')) {
        setIsExchanging(true);
        setCodeRefreshMessage(null);

        try {
          const clientId = import.meta.env.VITE_STAFF_CLIENT_ID;
          const pingBaseUrl = import.meta.env.VITE_PING_BASE_URL;
          const authEndpoint = pingBaseUrl.includes('/as/authorization.oauth2')
            ? pingBaseUrl
            : `${pingBaseUrl.replace(/\/$/, '')}/as/authorization.oauth2`;

          const redirectUri = `${window.location.origin}/callback`;
          const { codeVerifier, codeChallenge } = await generateCodeVerifierAndChallenge();
          const state = window.crypto.randomUUID();

          sessionStorage.setItem('pkce_code_verifier', codeVerifier);
          sessionStorage.setItem('auth_state', state);
          sessionStorage.setItem('auth_client_id', clientId);

          const authUrl = `${authEndpoint}?` +
            `client_id=${clientId}` +
            `&response_type=code` +
            `&redirect_uri=${encodeURIComponent(redirectUri)}` +
            `&scope=openid` +
            `&response_mode=query` +
            `&code_challenge=${codeChallenge}` +
            `&code_challenge_method=S256` +
            `&state=${state}`;

          setCodeRefreshMessage({
            type: 'success',
            message: 'Authorization code expired or used. Redirecting to PingFederate for a new one...'
          });

          setTimeout(() => {
            window.location.href = authUrl;
          }, 2000);
        } catch (refreshError) {
          setCodeRefreshMessage({
            type: 'error',
            message: 'Failed to refresh authorization code'
          });
          setIsExchanging(false);
        }
      }
    } finally {
      if (!codeRefreshMessage) {
        setIsExchanging(false);
      }
    }
  };

  const handleLogin = async (clientId: string) => {
    const pingBaseUrl = import.meta.env.VITE_PING_BASE_URL;
    const authEndpoint = pingBaseUrl.includes('/as/authorization.oauth2')
      ? pingBaseUrl
      : `${pingBaseUrl.replace(/\/$/, '')}/as/authorization.oauth2`;

    const redirectUri = `${window.location.origin}/callback`;

    const { codeVerifier, codeChallenge } = await generateCodeVerifierAndChallenge();
    const state = window.crypto.randomUUID();

    sessionStorage.setItem('pkce_code_verifier', codeVerifier);
    sessionStorage.setItem('auth_state', state);
    sessionStorage.setItem('auth_client_id', clientId);

    const authUrl = `${authEndpoint}?` +
      `client_id=${clientId}` +
      `&response_type=code` +
      `&redirect_uri=${encodeURIComponent(redirectUri)}` +
      `&scope=openid` +
      `&response_mode=query` +
      `&code_challenge=${codeChallenge}` +
      `&code_challenge_method=S256` +
      `&state=${state}`;

    window.location.href = authUrl;
  };

  const copyToClipboard = async (type: 'code' | 'token' | 'idToken', text: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(type);
    setTimeout(() => setCopied(null), 2000);
  };

  const handleLogout = () => {
    setAuthCode(null);
    setAccessToken(null);
    setIdToken(null);
    setDecodedIdToken(null);
    setDecodedAccessToken(null);
    setExchangeError(null);
    setOAuthError(null);
    sessionStorage.clear();
  };

  const handleLogoffToPing = () => {
    const pingBaseUrl = import.meta.env.VITE_PING_BASE_URL;
    const baseUrl = pingBaseUrl.split('/as/')[0];
    const logoffEndpoint = `${baseUrl}/idp/startSLO.ping`;

    handleLogout();
    window.location.href = logoffEndpoint;
  };

  if (oauthError) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center p-4">
        <div className="bg-white rounded-xl shadow-lg p-8 max-w-md w-full">
          <div className="flex justify-center mb-6">
            <div className="w-16 h-16 bg-red-100 rounded-full flex items-center justify-center">
              <span className="text-3xl">⚠️</span>
            </div>
          </div>
          <h1 className="text-2xl font-bold text-center text-gray-900 mb-2">
            Authentication Error
          </h1>

          <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-6">
            <h2 className="font-semibold text-red-900 mb-2">Error: {oauthError.error}</h2>
            {oauthError.description && (
              <p className="text-sm text-red-800 mb-3">{oauthError.description}</p>
            )}
            {oauthError.clientId && (
              <p className="text-sm text-red-800 mb-2">Client ID: <code className="bg-red-100 px-2 py-1 rounded font-mono text-xs">{oauthError.clientId}</code></p>
            )}
            {oauthError.redirectUri && (
              <p className="text-sm text-red-800 mb-3">Redirect URI: <code className="bg-red-100 px-2 py-1 rounded font-mono text-xs break-all">{oauthError.redirectUri}</code></p>
            )}
            <div className="text-sm bg-white rounded p-3 border border-red-100">
              <p className="text-gray-700 leading-relaxed">
                {getErrorGuidance(oauthError.error)}
              </p>
            </div>
          </div>

          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
            <h3 className="font-semibold text-blue-900 mb-2">Troubleshooting Steps:</h3>
            <ul className="text-sm text-blue-800 space-y-2">
              <li className="flex gap-2">
                <span className="font-bold">1.</span>
                <span>Verify the redirect URI is registered in PingFederate for this client</span>
              </li>
              <li className="flex gap-2">
                <span className="font-bold">2.</span>
                <span>Check PingFederate server logs for detailed error information</span>
              </li>
              <li className="flex gap-2">
                <span className="font-bold">3.</span>
                <span>Confirm the client ID matches your PingFederate configuration</span>
              </li>
              <li className="flex gap-2">
                <span className="font-bold">4.</span>
                <span>Try again - some errors are temporary</span>
              </li>
            </ul>
          </div>

          <button
            onClick={handleLogout}
            className="w-full bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition-colors flex items-center justify-center gap-2"
          >
            <ArrowLeft className="w-4 h-4" />
            Try Again
          </button>
        </div>
      </div>
    );
  }

  if (authCode && showBackMenu) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center p-4">
        <div className="bg-white rounded-xl shadow-lg p-8 max-w-md w-full">
          <h1 className="text-2xl font-bold text-center text-gray-900 mb-2">
            Welcome to Secure Auth
          </h1>
          <p className="text-gray-600 text-center mb-8">
            SPA PKCE Demonstration
          </p>
          <div className="flex flex-col gap-3">
            <button
              onClick={handleLogoffToPing}
              className="w-full px-6 py-3 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors flex items-center justify-center gap-2 font-medium"
            >
              <LogOut className="w-5 h-5" />
              Log Off
            </button>
            <button
              onClick={() => {
                setShowBackMenu(false);
                setExchangeError(null);
                setAccessToken(null);
                setIdToken(null);
                setDecodedAccessToken(null);
                setDecodedIdToken(null);
              }}
              className="w-full px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors flex items-center justify-center gap-2 font-medium"
            >
              <RefreshCw className="w-5 h-5" />
              Get User Info
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (authCode) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center p-4">
        <div className="bg-white rounded-xl shadow-lg p-8 max-w-md w-full">
          <div className="flex justify-center mb-6">
            <CheckCircle className="w-16 h-16 text-green-500" />
          </div>
          <h1 className="text-2xl font-bold text-center text-gray-900 mb-2">
            Authentication Successful
          </h1>
          <p className="text-gray-600 text-center mb-6">
            You have successfully authenticated with PingFederate.
          </p>
          
          <div className="space-y-6">
            <div className="bg-gray-50 rounded-lg p-6">
              <h2 className="text-lg font-semibold text-gray-900 mb-3">
                Authorization Code
              </h2>
              <div className="bg-white border border-gray-200 rounded-lg p-3 flex items-center gap-2">
                <code className="text-sm text-gray-800 flex-1 break-all">
                  {authCode}
                </code>
                <button
                  onClick={() => copyToClipboard('code', authCode)}
                  className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
                  title="Copy to clipboard"
                >
                  {copied === 'code' ? (
                    <CheckCircle className="w-5 h-5 text-green-500" />
                  ) : (
                    <Copy className="w-5 h-5 text-gray-500" />
                  )}
                </button>
              </div>
              {codeRefreshMessage && (
                <div className={`mt-3 p-3 rounded-lg text-sm font-medium flex items-center gap-2 ${
                  codeRefreshMessage.type === 'success'
                    ? 'bg-green-50 text-green-700'
                    : 'bg-red-50 text-red-700'
                }`}>
                  {codeRefreshMessage.type === 'success' && (
                    <CheckCircle className="w-4 h-4" />
                  )}
                  {codeRefreshMessage.message}
                </div>
              )}
            </div>

            {!accessToken && (
              <div className="bg-gray-50 rounded-lg p-6">
                <h2 className="text-lg font-semibold text-gray-900 mb-3">
                  Token Exchange
                </h2>
                <button
                  onClick={handleTokenExchange}
                  disabled={isExchanging}
                  className="w-full bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition-colors flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isExchanging ? (
                    <RefreshCw className="w-5 h-5 animate-spin" />
                  ) : (
                    <RefreshCw className="w-5 h-5" />
                  )}
                  {isExchanging ? 'Exchanging...' : 'Exchange for Access Token'}
                </button>
                {exchangeError && (
                  <p className="mt-2 text-sm text-red-600">{exchangeError}</p>
                )}
              </div>
            )}

            {accessToken && (
              <div className="bg-gray-50 rounded-lg p-6">
                <h2 className="text-lg font-semibold text-gray-900 mb-3">
                  Access Token
                </h2>
                <div className="bg-white border border-gray-200 rounded-lg p-3 flex items-center gap-2">
                  <code className="text-sm text-gray-800 flex-1 break-all">
                    {accessToken}
                  </code>
                  <button
                    onClick={() => copyToClipboard('token', accessToken)}
                    className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
                    title="Copy to clipboard"
                  >
                    {copied === 'token' ? (
                      <CheckCircle className="w-5 h-5 text-green-500" />
                    ) : (
                      <Copy className="w-5 h-5 text-gray-500" />
                    )}
                  </button>
                </div>

                {decodedAccessToken && (
                  <div className="mt-4">
                    <h3 className="text-md font-semibold text-gray-900 mb-2">
                      Decoded Access Token
                    </h3>
                    <div className="bg-white border border-gray-200 rounded-lg p-3">
                      <pre className="text-sm text-gray-800 whitespace-pre-wrap break-all">
                        {JSON.stringify(decodedAccessToken, null, 2)}
                      </pre>
                    </div>
                  </div>
                )}
              </div>
            )}

            {idToken ? (
              <div className="bg-gray-50 rounded-lg p-6">
                <h2 className="text-lg font-semibold text-gray-900 mb-3">
                  ID Token
                </h2>
                <div className="bg-white border border-gray-200 rounded-lg p-3 flex items-center gap-2">
                  <code className="text-sm text-gray-800 flex-1 break-all">
                    {idToken}
                  </code>
                  <button
                    onClick={() => copyToClipboard('idToken', idToken)}
                    className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
                    title="Copy to clipboard"
                  >
                    {copied === 'idToken' ? (
                      <CheckCircle className="w-5 h-5 text-green-500" />
                    ) : (
                      <Copy className="w-5 h-5 text-gray-500" />
                    )}
                  </button>
                </div>

                {decodedIdToken && (
                  <div className="mt-4">
                    <h3 className="text-md font-semibold text-gray-900 mb-2">
                      Decoded ID Token
                    </h3>
                    <div className="bg-white border border-gray-200 rounded-lg p-3">
                      <pre className="text-sm text-gray-800 whitespace-pre-wrap break-all">
                        {JSON.stringify(decodedIdToken, null, 2)}
                      </pre>
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <p className="text-sm text-gray-600 text-center">
                No ID token was returned in the response.
              </p>
            )}
          </div>
          
          <button
            onClick={() => setShowBackMenu(true)}
            className="w-full mt-6 px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50 transition-colors flex items-center justify-center gap-2"
          >
            <ArrowLeft className="w-4 h-4" />
            Back to Home
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center p-4">
      <div className="bg-white rounded-xl shadow-lg p-8 max-w-md w-full text-center">
        <h1 className="text-2xl font-bold text-gray-900 mb-2">
          Welcome to Secure Auth
        </h1>
        <p className="text-gray-600 mb-8">
          SPA PKCE Demonstration
        </p>
        <div className="flex flex-col gap-4">
          <button
            onClick={() => handleLogin(import.meta.env.VITE_STAFF_CLIENT_ID)}
            className="w-full bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition-colors flex items-center justify-center gap-2"
          >
            <LogIn className="w-5 h-5" />
            Staff Sign-in
          </button>
        </div>
      </div>
    </div>
  );
}

export default App;