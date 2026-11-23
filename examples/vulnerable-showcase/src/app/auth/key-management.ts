// NGB086–NGB090: client-side "encrypted vault" helpers with weak parameters (synthetic).
const SALT = new TextEncoder().encode('ngbastion-vault');

export async function vaultKey(password: string): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  // NGB086 (constant salt) + NGB087 (1,000 iterations)
  return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: SALT, iterations: 1000 }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

export function signingKeys(): Promise<CryptoKeyPair> {
  // NGB088: 1024-bit RSA
  return crypto.subtle.generateKey({ name: 'RSA-PSS', modulusLength: 1024, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, false, ['sign', 'verify']);
}

export function seal(key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  // NGB089: 32-bit tag
  return crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 32 }, key, data);
}

export async function readSignedConfig(key: CryptoKey, signature: ArrayBuffer, payload: ArrayBuffer): Promise<unknown> {
  // NGB090: the boolean result is ignored
  await crypto.subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, key, signature, payload);
  return JSON.parse(new TextDecoder().decode(payload));
}
