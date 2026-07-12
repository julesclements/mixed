import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import App from '../App';

vi.mock('../lib/pkce', () => ({
  generateCodeVerifierAndChallenge: vi.fn().mockResolvedValue({
    codeVerifier: 'mock-verifier',
    codeChallenge: 'mock-challenge',
  }),
  buildAuthUrl: vi.fn(
    (
      authEndpoint: string,
      redirectUri: string,
      clientId: string,
      codeChallenge: string,
      state: string,
    ) =>
      `${authEndpoint}?client_id=${clientId}&redirect_uri=${redirectUri}&code_challenge=${codeChallenge}&code_challenge_method=S256&state=${state}`,
  ),
}));

vi.mock('../lib/tokenExchange', () => ({
  exchangeCodeForToken: vi.fn(),
  resolveAuthEndpoint: vi.fn().mockReturnValue('https://mock-ping.example.com/as/authorization.oauth2'),
  resolveTokenEndpoint: vi.fn().mockReturnValue('https://mock-ping.example.com/as/token.oauth2'),
  resolveLogoffEndpoint: vi.fn().mockReturnValue('https://mock-ping.example.com/idp/startSLO.ping'),
}));

vi.mock('../lib/errors', () => ({
  getErrorGuidance: vi.fn().mockReturnValue('Guidance text for the error.'),
}));

vi.mock('jwt-decode', () => ({
  jwtDecode: vi.fn().mockReturnValue({ sub: 'user-123', name: 'Test User' }),
}));

const { exchangeCodeForToken } = await import('../lib/tokenExchange');
const { jwtDecode } = await import('jwt-decode');

const mockLocation = {
  href: '',
  origin: 'http://localhost:5173',
  search: '',
  pathname: '/',
};

const writeTextMock = vi.fn().mockResolvedValue(undefined);

beforeEach(() => {
  sessionStorage.clear();
  mockLocation.href = '';
  mockLocation.search = '';
  mockLocation.pathname = '/';

  Object.defineProperty(window, 'location', {
    value: mockLocation,
    writable: true,
    configurable: true,
  });

  window.history.replaceState = vi.fn();

  Object.defineProperty(navigator, 'clipboard', {
    value: { writeText: writeTextMock },
    writable: true,
    configurable: true,
  });

  vi.stubEnv('VITE_STAFF_CLIENT_ID', 'staff-oidc-client');
  vi.stubEnv('VITE_API_BASE_URL', 'https://api.example.com');

  vi.mocked(exchangeCodeForToken).mockReset();
  vi.mocked(jwtDecode).mockReset();
  vi.mocked(jwtDecode).mockReturnValue({ sub: 'user-123', name: 'Test User' });
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  writeTextMock.mockClear();
});

describe('App - Login screen', () => {
  it('renders the welcome screen with Vendor Sign-in button', () => {
    render(<App />);
    expect(screen.getByText('Welcome to Secure Auth')).toBeInTheDocument();
    expect(screen.getByText('Vendor Sign-in')).toBeInTheDocument();
  });

  it('redirects to PingFederate auth URL when Vendor Sign-in is clicked', async () => {
    const user = userEvent.setup();
    const cryptoMock = {
      randomUUID: vi.fn().mockReturnValue('state-uuid-123'),
    };
    Object.defineProperty(window, 'crypto', { value: cryptoMock, writable: true, configurable: true });

    render(<App />);
    await user.click(screen.getByText('Vendor Sign-in'));

    expect(mockLocation.href).toContain('authorization.oauth2');
    expect(mockLocation.href).toContain('client_id=staff-oidc-client');
    expect(mockLocation.href).toContain('code_challenge_method=S256');
    expect(mockLocation.href).toContain('state=state-uuid-123');
    expect(mockLocation.href).toContain('code_challenge=mock-challenge');
  });
});

describe('App - Auth code screen', () => {
  it('renders the authorization code and Exchange button when code is present', () => {
    mockLocation.search = '?code=test-auth-code-123';
    render(<App />);
    expect(screen.getByText('Authentication Successful')).toBeInTheDocument();
    expect(screen.getByText('Authorization Code')).toBeInTheDocument();
    expect(screen.getByText('test-auth-code-123')).toBeInTheDocument();
    expect(screen.getByText('Exchange for Access Token')).toBeInTheDocument();
  });

  it('renders the code with a copy button', () => {
    mockLocation.search = '?code=copyable-code';
    render(<App />);
    expect(screen.getByText('copyable-code')).toBeInTheDocument();
    expect(screen.getByTitle('Copy to clipboard')).toBeInTheDocument();
  });

  it('shows Back to Home button on the auth code screen', () => {
    mockLocation.search = '?code=some-code';
    render(<App />);
    expect(screen.getByText('Back to Home')).toBeInTheDocument();
  });

  it('copies auth code to clipboard when copy button is clicked', async () => {
    mockLocation.search = '?code=clip-me';
    render(<App />);

    const copyBtn = screen.getByTitle('Copy to clipboard');
    await fireEvent.click(copyBtn);

    await waitFor(() => {
      expect(writeTextMock).toHaveBeenCalledWith('clip-me');
    });
  });
});

describe('App - Token exchange', () => {
  it('exchanges code for token and displays access token', async () => {
    vi.mocked(exchangeCodeForToken).mockResolvedValue({
      access_token: 'access-token-xyz',
      id_token: 'id-token-abc',
      token_type: 'Bearer',
      expires_in: 3600,
    });

    const user = userEvent.setup();
    mockLocation.search = '?code=exchange-code';
    sessionStorage.setItem('pkce_code_verifier', 'stored-verifier');

    render(<App />);
    await user.click(screen.getByText('Exchange for Access Token'));

    await waitFor(() => {
      expect(screen.getByText('Access Token')).toBeInTheDocument();
      expect(screen.getByText('access-token-xyz')).toBeInTheDocument();
    });
    expect(screen.getByText('ID Token')).toBeInTheDocument();
    expect(screen.getByText('id-token-abc')).toBeInTheDocument();
  });

  it('shows error message when token exchange fails with generic error', async () => {
    vi.mocked(exchangeCodeForToken).mockRejectedValue(new Error('Network failure'));

    const user = userEvent.setup();
    mockLocation.search = '?code=exchange-code';
    sessionStorage.setItem('pkce_code_verifier', 'stored-verifier');

    render(<App />);
    await user.click(screen.getByText('Exchange for Access Token'));

    await waitFor(() => {
      expect(screen.getByText('Network failure')).toBeInTheDocument();
    });
  });

  it('shows error when auth code or verifier is missing', async () => {
    const user = userEvent.setup();
    mockLocation.search = '?code=exchange-code';

    render(<App />);
    await user.click(screen.getByText('Exchange for Access Token'));

    await waitFor(() => {
      expect(screen.getByText('Missing required authentication data')).toBeInTheDocument();
    });
  });

  it('shows "No ID token" message when response has no id_token', async () => {
    vi.mocked(exchangeCodeForToken).mockResolvedValue({
      access_token: 'access-token-only',
    });

    const user = userEvent.setup();
    mockLocation.search = '?code=no-id-token-code';
    sessionStorage.setItem('pkce_code_verifier', 'stored-verifier');

    render(<App />);
    await user.click(screen.getByText('Exchange for Access Token'));

    await waitFor(() => {
      expect(screen.getByText('No ID token was returned in the response.')).toBeInTheDocument();
    });
  });

  it('shows decoded access token and ID token sections', async () => {
    vi.mocked(jwtDecode).mockImplementation((token: string) => ({
      sub: 'user-123',
      token_preview: token.substring(0, 10),
    }));

    vi.mocked(exchangeCodeForToken).mockResolvedValue({
      access_token: 'access-token-decoded',
      id_token: 'id-token-decoded',
    });

    const user = userEvent.setup();
    mockLocation.search = '?code=decoded-test';
    sessionStorage.setItem('pkce_code_verifier', 'stored-verifier');

    render(<App />);
    await user.click(screen.getByText('Exchange for Access Token'));

    await waitFor(() => {
      expect(screen.getByText('Decoded Access Token')).toBeInTheDocument();
      expect(screen.getByText('Decoded ID Token')).toBeInTheDocument();
    });
  });
});

describe('App - Check token (BFF)', () => {
  it('calls BFF API and displays check result on success', async () => {
    vi.mocked(exchangeCodeForToken).mockResolvedValue({
      access_token: 'access-token-check',
    });

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ valid: true, user: 'test' }),
    });
    vi.spyOn(globalThis, 'fetch').mockImplementation(fetchMock as any);

    const user = userEvent.setup();
    mockLocation.search = '?code=check-code';
    sessionStorage.setItem('pkce_code_verifier', 'stored-verifier');

    render(<App />);
    await user.click(screen.getByText('Exchange for Access Token'));

    await waitFor(() => {
      expect(screen.getByText('Check Token (BFF)')).toBeInTheDocument();
    });

    await user.click(screen.getByText('Check Token (BFF)'));

    await waitFor(() => {
      expect(screen.getByText(/Status:/)).toBeInTheDocument();
    });

    expect(fetchMock).toHaveBeenCalledWith(
      'https://api.example.com/api/check',
      expect.objectContaining({
        method: 'GET',
        headers: { Authorization: 'Bearer access-token-check' },
      }),
    );
  });

  it('displays error result when BFF API returns non-200', async () => {
    vi.mocked(exchangeCodeForToken).mockResolvedValue({
      access_token: 'access-token-bad',
    });

    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      json: async () => ({ error: 'invalid_token' }),
    });
    vi.spyOn(globalThis, 'fetch').mockImplementation(fetchMock as any);

    const user = userEvent.setup();
    mockLocation.search = '?code=check-bad-code';
    sessionStorage.setItem('pkce_code_verifier', 'stored-verifier');

    render(<App />);
    await user.click(screen.getByText('Exchange for Access Token'));

    await waitFor(() => {
      expect(screen.getByText('Check Token (BFF)')).toBeInTheDocument();
    });

    await user.click(screen.getByText('Check Token (BFF)'));

    await waitFor(() => {
      expect(screen.getByText(/Status:/)).toBeInTheDocument();
    });
  });

  it('displays error when BFF fetch throws', async () => {
    vi.mocked(exchangeCodeForToken).mockResolvedValue({
      access_token: 'access-token-fetch-err',
    });

    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new TypeError('Failed to fetch'));

    const user = userEvent.setup();
    mockLocation.search = '?code=fetch-err-code';
    sessionStorage.setItem('pkce_code_verifier', 'stored-verifier');

    render(<App />);
    await user.click(screen.getByText('Exchange for Access Token'));

    await waitFor(() => {
      expect(screen.getByText('Check Token (BFF)')).toBeInTheDocument();
    });

    await user.click(screen.getByText('Check Token (BFF)'));

    await waitFor(() => {
      expect(screen.getByText(/Status:/)).toBeInTheDocument();
      expect(screen.getByText(/Failed to connect to BFF API/)).toBeInTheDocument();
    });
  });
});

describe('App - Back menu', () => {
  it('shows Log Off and Get User Info options when Back to Home is clicked', async () => {
    const user = userEvent.setup();
    mockLocation.search = '?code=some-code';
    render(<App />);

    await user.click(screen.getByText('Back to Home'));

    expect(screen.getByText('Log Off')).toBeInTheDocument();
    expect(screen.getByText('Get User Info')).toBeInTheDocument();
  });

  it('resets to auth code screen when Get User Info is clicked', async () => {
    const user = userEvent.setup();
    mockLocation.search = '?code=abc-123';
    render(<App />);

    await user.click(screen.getByText('Back to Home'));
    await user.click(screen.getByText('Get User Info'));

    expect(screen.getByText('Authentication Successful')).toBeInTheDocument();
    expect(screen.getByText('abc-123')).toBeInTheDocument();
    expect(screen.getByText('Exchange for Access Token')).toBeInTheDocument();
    expect(screen.queryByText('Log Off')).not.toBeInTheDocument();
    expect(screen.queryByText('Get User Info')).not.toBeInTheDocument();
  });

  it('redirects to logoff URL when Log Off is clicked', async () => {
    const user = userEvent.setup();
    mockLocation.search = '?code=logoff-code';
    render(<App />);

    await user.click(screen.getByText('Back to Home'));
    await user.click(screen.getByText('Log Off'));

    expect(mockLocation.href).toBe('https://mock-ping.example.com/idp/startSLO.ping');
  });
});

describe('App - Error screen', () => {
  it('renders error screen when error param is present', () => {
    mockLocation.search = '?error=access_denied&error_description=User%20cancelled';
    render(<App />);
    expect(screen.getByText('Authentication Error')).toBeInTheDocument();
    expect(screen.getByText('Error: access_denied')).toBeInTheDocument();
  });

  it('renders Try Again button that resets state', async () => {
    const user = userEvent.setup();
    mockLocation.search = '?error=invalid_request';
    render(<App />);

    expect(screen.getByText('Try Again')).toBeInTheDocument();
    await user.click(screen.getByText('Try Again'));

    expect(screen.getByText('Welcome to Secure Auth')).toBeInTheDocument();
    expect(screen.getByText('Vendor Sign-in')).toBeInTheDocument();
  });

  it('shows troubleshooting steps on error screen', () => {
    mockLocation.search = '?error=server_error';
    render(<App />);
    expect(screen.getByText('Troubleshooting Steps:')).toBeInTheDocument();
    expect(screen.getByText(/redirect URI is registered/)).toBeInTheDocument();
  });

  it('shows client ID and redirect URI when stored in session', () => {
    sessionStorage.setItem('auth_client_id', 'my-client-123');
    mockLocation.search = '?error=server_error';
    render(<App />);

    expect(screen.getByText('Client ID:')).toBeInTheDocument();
    expect(screen.getByText('my-client-123')).toBeInTheDocument();
    expect(screen.getByText('Redirect URI:')).toBeInTheDocument();
  });

  it('shows error description when provided', () => {
    mockLocation.search = '?error=access_denied&error_description=The%20user%20cancelled';
    render(<App />);

    expect(screen.getByText('The user cancelled')).toBeInTheDocument();
  });
});

describe('App - Callback path', () => {
  it('clears URL when code is present on /callback path', () => {
    mockLocation.search = '?code=callback-code';
    mockLocation.pathname = '/callback';
    render(<App />);

    expect(window.history.replaceState).toHaveBeenCalledWith({}, '', '/');
    expect(screen.getByText('callback-code')).toBeInTheDocument();
  });
});
