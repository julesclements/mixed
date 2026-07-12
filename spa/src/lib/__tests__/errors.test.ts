import { describe, it, expect } from 'vitest';
import { getErrorGuidance, ERROR_CODES } from '../errors';

describe('getErrorGuidance', () => {
  it('returns specific guidance for known error codes', () => {
    const guidance = getErrorGuidance('server_error');
    expect(guidance).toContain('Redirect URI mismatch');
    expect(guidance).toContain('Client configuration');
    expect(guidance).toContain('PingFederate server logs');
  });

  it('returns guidance for access_denied', () => {
    expect(getErrorGuidance('access_denied')).toContain('cancelled or denied');
  });

  it('returns guidance for invalid_request', () => {
    expect(getErrorGuidance('invalid_request')).toContain('malformed');
  });

  it('returns guidance for unauthorized_client', () => {
    expect(getErrorGuidance('unauthorized_client')).toContain('not authorized');
  });

  it('returns guidance for unsupported_response_type', () => {
    expect(getErrorGuidance('unsupported_response_type')).toContain('not supported');
  });

  it('returns guidance for invalid_scope', () => {
    expect(getErrorGuidance('invalid_scope')).toContain('invalid');
  });

  it('returns guidance for temporarily_unavailable', () => {
    expect(getErrorGuidance('temporarily_unavailable')).toContain('temporarily unavailable');
  });

  it('returns guidance for interaction_required', () => {
    expect(getErrorGuidance('interaction_required')).toContain('user interaction');
  });

  it('returns guidance for consent_required', () => {
    expect(getErrorGuidance('consent_required')).toContain('consent');
  });

  it('returns generic fallback for unknown error codes', () => {
    const guidance = getErrorGuidance('unknown_error_code');
    expect(guidance).toContain('unknown_error_code');
    expect(guidance).toContain('Contact your administrator');
  });

  it('ERROR_CODES contains all known error codes', () => {
    expect(ERROR_CODES).toContain('server_error');
    expect(ERROR_CODES).toContain('access_denied');
    expect(ERROR_CODES).toContain('invalid_request');
    expect(ERROR_CODES).toContain('unauthorized_client');
    expect(ERROR_CODES).toContain('unsupported_response_type');
    expect(ERROR_CODES).toContain('invalid_scope');
    expect(ERROR_CODES).toContain('temporarily_unavailable');
    expect(ERROR_CODES).toContain('interaction_required');
    expect(ERROR_CODES).toContain('consent_required');
    expect(ERROR_CODES.length).toBe(9);
  });
});
