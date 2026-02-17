import { useState, useEffect } from 'react';
import { LogIn, Copy, CheckCircle, ArrowLeft, RefreshCw } from 'lucide-react';
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
  const tokenEndpoint = pingBaseUrl.replace('authorization.oauth2', 'token.oauth2');
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
  const [isStaffLogin, setIsStaffLogin] = useState(false);
  const [isExchanging, setIsExchanging] = useState(false);
  const [exchangeError, setExchangeError] = useState<string | null>(null);

  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const state = urlParams.get('state');
    
    if (code) {
      setAuthCode(code);
      const storedState = sessionStorage.getItem('auth_state');
      const storedClientType = sessionStorage.getItem('client_type');
      
      setIsStaffLogin(storedClientType === 'staff');
      
      if (window.location.pathname === '/callback') {
        window.history.replaceState({}, document.title, '/');
      }
    }
  }, []);

  const handleTokenExchange = async () => {
    setIsExchanging(true);
    setExchangeError(null);
    
    try {
      const storedCodeVerifier = sessionStorage.getItem('pkce_code_verifier');
      if (!authCode || !storedCodeVerifier) {
        throw new Error('Missing required authentication data');
      }
      
      const clientId = isStaffLogin 
        ? import.meta.env.VITE_STAFF_CLIENT_ID 
        : import.meta.env.VITE_CUSTOMER_CLIENT_ID;

      const data = await exchangeCodeForToken(
        authCode,
        storedCodeVerifier,
        clientId
      );

      setAccessToken(data.access_token);
      
      if (isStaffLogin) {
        try {
          const decodedAccess = jwtDecode(data.access_token);
          setDecodedAccessToken(decodedAccess);
        } catch (error) {
          console.error('Failed to decode access token:', error);
        }
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
      setExchangeError(error instanceof Error ? error.message : 'Failed to exchange token');
    } finally {
      setIsExchanging(false);
    }
  };

  const handleLogin = async (clientId: string, clientType: 'staff' | 'customer') => {
    const pingBaseUrl = import.meta.env.VITE_PING_BASE_URL;
    const redirectUri = `${window.location.origin}/callback`;
    
    const { codeVerifier, codeChallenge } = await generateCodeVerifierAndChallenge();
    const state = window.crypto.randomUUID();

    sessionStorage.setItem('pkce_code_verifier', codeVerifier);
    sessionStorage.setItem('auth_state', state);
    sessionStorage.setItem('client_type', clientType);

    const authUrl = `${pingBaseUrl}?` +
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
    sessionStorage.clear();
  };

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
                  {isExchanging ? 'Exchanging...' : `Exchange for ${isStaffLogin ? 'Access' : 'Reference'} Token`}
                </button>
                {exchangeError && (
                  <p className="mt-2 text-sm text-red-600">{exchangeError}</p>
                )}
              </div>
            )}

            {accessToken && (
              <div className="bg-gray-50 rounded-lg p-6">
                <h2 className="text-lg font-semibold text-gray-900 mb-3">
                  {isStaffLogin ? 'Access Token' : 'Reference Token'}
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

                {isStaffLogin && decodedAccessToken && (
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
          
          <div className="flex flex-col sm:flex-row gap-3 mt-6">
            <button
              onClick={handleLogout}
              className="flex-1 px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50 transition-colors flex items-center justify-center gap-2"
            >
              <ArrowLeft className="w-4 h-4" />
              Back to Home
            </button>
          </div>
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
          Please select your sign-in method below.
        </p>
        <div className="flex flex-col gap-4">
          <button
            onClick={() => handleLogin(import.meta.env.VITE_STAFF_CLIENT_ID, 'staff')}
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