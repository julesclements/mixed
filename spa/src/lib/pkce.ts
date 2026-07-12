export interface PkcePair {
  codeVerifier: string;
  codeChallenge: string;
}

function toBase64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

export async function generateCodeVerifierAndChallenge(
  crypto: Crypto = globalThis.crypto,
): Promise<PkcePair> {
  const array = new Uint32Array(56 / 2);
  crypto.getRandomValues(array);
  const codeVerifier = Array.from(array, (dec) =>
    ('0' + dec.toString(16)).substr(-2),
  ).join('');

  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  const codeChallenge = toBase64Url(new Uint8Array(digest));

  return { codeVerifier, codeChallenge };
}

export function buildAuthUrl(
  authEndpoint: string,
  redirectUri: string,
  clientId: string,
  codeChallenge: string,
  state: string,
): string {
  const params = new URLSearchParams({
    client_id: clientId,
    response_type: 'code',
    redirect_uri: redirectUri,
    scope: 'openid',
    response_mode: 'query',
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    state,
  });
  return `${authEndpoint}?${params.toString()}`;
}
