export interface TokenResponse {
  access_token: string;
  id_token?: string;
  token_type?: string;
  expires_in?: number;
}

export function resolveTokenEndpoint(pingBaseUrl: string): string {
  if (pingBaseUrl.includes('/as/token.oauth2')) {
    return pingBaseUrl;
  }
  if (pingBaseUrl.includes('/as/authorization.oauth2')) {
    return pingBaseUrl.replace('authorization.oauth2', 'token.oauth2');
  }
  return `${pingBaseUrl.replace(/\/$/, '')}/as/token.oauth2`;
}

export function resolveAuthEndpoint(pingBaseUrl: string): string {
  if (pingBaseUrl.includes('/as/authorization.oauth2')) {
    return pingBaseUrl;
  }
  return `${pingBaseUrl.replace(/\/$/, '')}/as/authorization.oauth2`;
}

export function resolveLogoffEndpoint(pingBaseUrl: string): string {
  const baseUrl = pingBaseUrl.split('/as/')[0];
  return `${baseUrl}/idp/startSLO.ping`;
}

export async function exchangeCodeForToken(
  code: string,
  codeVerifier: string,
  clientId: string,
  redirectUri: string,
  tokenEndpoint: string,
  fetchImpl: typeof fetch = globalThis.fetch,
): Promise<TokenResponse> {
  const params = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: clientId,
    code_verifier: codeVerifier,
    code,
    redirect_uri: redirectUri,
  });

  const response = await fetchImpl(tokenEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params,
  });

  if (!response.ok) {
    throw new Error('Failed to exchange code for token');
  }

  return (await response.json()) as TokenResponse;
}
