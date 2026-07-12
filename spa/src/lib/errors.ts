const GUIDANCE: Record<string, string> = {
  server_error:
    'PingFederate returned a server error. This often indicates: (1) Redirect URI mismatch - verify the callback URL is registered in your PingFederate client configuration, (2) Client configuration issue - check that the client ID and settings are correct, or (3) PingFederate server issue - check PingFederate server logs.',
  access_denied:
    'Authentication was cancelled or denied by the user or PingFederate policies.',
  invalid_request:
    'The authorization request was malformed. Check that all required parameters are present.',
  unauthorized_client:
    'The client is not authorized for the requested grant type. Verify client configuration.',
  unsupported_response_type:
    'The response type is not supported. Ensure "code" response type is configured.',
  invalid_scope:
    'One or more requested scopes are invalid. Check that "openid" scope is available.',
  temporarily_unavailable:
    'The authorization server is temporarily unavailable. Please try again later.',
  interaction_required:
    'The authorization server requires user interaction. Please sign in again.',
  consent_required:
    'The authorization server requires user consent. Please sign in again.',
};

export function getErrorGuidance(errorCode: string): string {
  return (
    GUIDANCE[errorCode] ||
    `An OAuth error occurred: ${errorCode}. Contact your administrator for assistance.`
  );
}

export const ERROR_CODES = Object.keys(GUIDANCE);
