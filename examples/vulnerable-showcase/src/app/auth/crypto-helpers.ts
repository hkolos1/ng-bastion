import CryptoJS from 'crypto-js';

// NGB047: one IV for every encryption with the same key (AES-GCM nonce reuse).
const IV = new TextEncoder().encode('0123456789ab');

export function newOAuthState(): string {
  // NGB046: Math.random() is predictable; the OAuth state can be guessed.
  const state = Math.random().toString(36).slice(2);
  sessionStorage.setItem('oauth_state', state);
  return state;
}

export function encryptDraft(key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
  return crypto.subtle.encrypt({ name: 'AES-GCM', iv: IV }, key, data);
}

export function prehashPassword(password: string): string {
  // NGB048: MD5 "protecting" a password before it is sent.
  return CryptoJS.MD5(password).toString();
}

export function joinParentDomain(): void {
  // NGB050: lets every *.example.com page script this app.
  document.domain = 'example.com';
}
