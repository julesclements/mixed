// client/lib.js
// Pure helper functions extracted from script.js for unit testing.

export function generateUUIDv4() {
  return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
    (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
  );
}

export function decodeJwtPayload(token) {
  if (!token || typeof token !== 'string') { return null; }
  try {
    const parts = token.split('.');
    if (parts.length !== 3) { console.warn("Token does not have 3 parts."); return null; }
    const payloadBase64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const decodedJson = atob(payloadBase64);
    return JSON.parse(decodedJson);
  } catch (e) { console.error("Failed to decode JWT payload:", e); return null; }
}

export function escapeHtml(unsafe) {
  if (typeof unsafe !== 'string') { return ''; }
  return unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

export function resolveBffBaseUrl(hostname) {
  if (hostname === 'localhost' || hostname === '127.0.0.1') {
    return 'http://localhost:3001';
  } else if (hostname === 'julesclements.github.io' || hostname === 'client.hdc.company') {
    return 'https://mixed.hdc.company';
  }
  return '';
}
