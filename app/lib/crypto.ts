/**
 * PassX Zero-Knowledge Cryptographic Engine
 * 
 * Standards & Specifications:
 * - Key Derivation: PBKDF2-HMAC-SHA256 with 600,000 iterations (OWASP Standard)
 * - Cipher: AES-256-GCM (Authenticated Encryption with Associated Data)
 * - IV: 96-bit (12-byte) cryptographically random IV per encryption
 * - Key Storage: Non-extractable CryptoKey in browser RAM only (never persisted to LocalStorage/cookies)
 * - Zero Metadata Leakage: All credential fields (service, username, password, notes) are encrypted inside the ciphertext payload
 */

export const PBKDF2_ITERATIONS = 600_000;
export const VERIFIER_PLAINTEXT = "PASSX_ZERO_KNOWLEDGE_VERIFIER_V1";

// Helper: Uint8Array to Base64
export function bufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

// Helper: Base64 to Uint8Array
export function base64ToBuffer(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// Helper: Cross-environment Web Crypto API accessor
export function getCrypto(): Crypto {
  if (typeof globalThis !== "undefined" && globalThis.crypto) {
    return globalThis.crypto;
  }
  if (typeof window !== "undefined" && window.crypto) {
    return window.crypto;
  }
  throw new Error("Cryptographic engine unavailable: Web Crypto API is not supported in this runtime environment.");
}

// Generate a cryptographically secure 16-byte random salt
export function generateSalt(): string {
  const cryptoObj = getCrypto();
  const salt = cryptoObj.getRandomValues(new Uint8Array(16));
  return bufferToBase64(salt);
}

/**
 * Derives a 256-bit AES-GCM key from the master password and a unique user salt using PBKDF2.
 * The derived key is non-extractable so malicious extensions or scripts cannot dump it.
 */
export async function deriveMasterKey(
  masterPassword: string,
  saltBase64: string
): Promise<CryptoKey> {
  const cryptoObj = getCrypto();
  const enc = new TextEncoder();
  const salt = base64ToBuffer(saltBase64);

  // 1. Import password as base key material
  const keyMaterial = await cryptoObj.subtle.importKey(
    "raw",
    enc.encode(masterPassword),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  // 2. Derive non-extractable AES-256-GCM key
  return cryptoObj.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt as unknown as BufferSource,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    keyMaterial,
    {
      name: "AES-GCM",
      length: 256,
    },
    false, // extractable: false prevents exfiltration
    ["encrypt", "decrypt"]
  );
}

/**
 * Creates a verification payload used to check if an entered master password is correct.
 */
export async function createVaultVerifier(key: CryptoKey): Promise<{ ciphertext: string; iv: string }> {
  return encryptData({ token: VERIFIER_PLAINTEXT }, key);
}

/**
 * Verifies if the candidate master key successfully decrypts the stored verifier.
 */
export async function verifyMasterKey(
  candidateKey: CryptoKey,
  verifier: { ciphertext: string; iv: string }
): Promise<boolean> {
  try {
    const data = await decryptData<{ token: string }>(verifier.ciphertext, verifier.iv, candidateKey);
    return data.token === VERIFIER_PLAINTEXT;
  } catch {
    return false;
  }
}

/**
 * Encrypts arbitrary JSON-serializable data using AES-256-GCM with a unique 12-byte IV.
 */
export async function encryptData(
  data: unknown,
  key: CryptoKey
): Promise<{ ciphertext: string; iv: string }> {
  const cryptoObj = getCrypto();
  const enc = new TextEncoder();
  const encoded = enc.encode(JSON.stringify(data));
  const iv = cryptoObj.getRandomValues(new Uint8Array(12));

  const cipherBuffer = await cryptoObj.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv as unknown as BufferSource,
    },
    key,
    encoded
  );

  return {
    ciphertext: bufferToBase64(cipherBuffer),
    iv: bufferToBase64(iv),
  };
}

/**
 * Decrypts AES-256-GCM ciphertext using the given key and IV.
 */
export async function decryptData<T = unknown>(
  ciphertextBase64: string,
  ivBase64: string,
  key: CryptoKey
): Promise<T> {
  const cryptoObj = getCrypto();
  const ciphertext = base64ToBuffer(ciphertextBase64);
  const iv = base64ToBuffer(ivBase64);

  const decryptedBuffer = await cryptoObj.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv as unknown as BufferSource,
    },
    key,
    ciphertext as unknown as BufferSource
  );

  const dec = new TextDecoder();
  const jsonStr = dec.decode(decryptedBuffer);
  return JSON.parse(jsonStr) as T;
}

/**
 * High-Entropy Cryptographically Secure Password Generator
 */
export interface PasswordGeneratorOptions {
  length: number;
  useUpper: boolean;
  useLower: boolean;
  useNumbers: boolean;
  useSymbols: boolean;
  avoidAmbiguous: boolean;
}

export function generateSecurePassword(
  options: PasswordGeneratorOptions = {
    length: 20,
    useUpper: true,
    useLower: true,
    useNumbers: true,
    useSymbols: true,
    avoidAmbiguous: true,
  }
): string {
  let upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
  let lower = "abcdefghijkmnopqrstuvwxyz";
  let numbers = "23456789";
  let symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?";

  if (!options.avoidAmbiguous) {
    upper += "I";
    lower += "l";
    numbers += "01";
    symbols += "/\\\"'`~";
  }

  let charset = "";
  const guaranteedChars: string[] = [];

  if (options.useUpper) {
    charset += upper;
    guaranteedChars.push(upper[getRandomInt(upper.length)]);
  }
  if (options.useLower) {
    charset += lower;
    guaranteedChars.push(lower[getRandomInt(lower.length)]);
  }
  if (options.useNumbers) {
    charset += numbers;
    guaranteedChars.push(numbers[getRandomInt(numbers.length)]);
  }
  if (options.useSymbols) {
    charset += symbols;
    guaranteedChars.push(symbols[getRandomInt(symbols.length)]);
  }

  if (charset.length === 0) {
    charset = lower + numbers;
  }

  const passwordChars: string[] = [...guaranteedChars];
  const remaining = Math.max(0, options.length - guaranteedChars.length);

  for (let i = 0; i < remaining; i++) {
    passwordChars.push(charset[getRandomInt(charset.length)]);
  }

  // Cryptographically shuffle array using Fisher-Yates
  for (let i = passwordChars.length - 1; i > 0; i--) {
    const j = getRandomInt(i + 1);
    [passwordChars[i], passwordChars[j]] = [passwordChars[j], passwordChars[i]];
  }

  return passwordChars.join("");
}

function getRandomInt(max: number): number {
  if (max <= 1) return 0;
  const cryptoObj = getCrypto();
  // Cryptographic rejection sampling to eliminate modulo bias
  const limit = Math.floor(0x100000000 / max) * max;
  const randomBuffer = new Uint32Array(1);
  do {
    cryptoObj.getRandomValues(randomBuffer);
  } while (randomBuffer[0] >= limit);
  return randomBuffer[0] % max;
}

/**
 * Calculates password entropy in bits and returns score + qualitative label.
 */
export function evaluatePasswordStrength(password: string): {
  entropy: number;
  label: "Very Weak" | "Weak" | "Moderate" | "Strong" | "Military-Grade";
  percent: number;
  color: string;
} {
  if (!password) {
    return { entropy: 0, label: "Very Weak", percent: 0, color: "bg-red-500" };
  }

  let poolSize = 0;
  if (/[a-z]/.test(password)) poolSize += 26;
  if (/[A-Z]/.test(password)) poolSize += 26;
  if (/[0-9]/.test(password)) poolSize += 10;
  if (/[^a-zA-Z0-9]/.test(password)) poolSize += 33;

  const entropy = Math.round(password.length * Math.log2(Math.max(poolSize, 2)));

  if (entropy < 35) {
    return { entropy, label: "Very Weak", percent: 20, color: "bg-red-500" };
  } else if (entropy < 50) {
    return { entropy, label: "Weak", percent: 40, color: "bg-amber-500" };
  } else if (entropy < 65) {
    return { entropy, label: "Moderate", percent: 65, color: "bg-yellow-400" };
  } else if (entropy < 85) {
    return { entropy, label: "Strong", percent: 85, color: "bg-emerald-500" };
  } else {
    return { entropy, label: "Military-Grade", percent: 100, color: "bg-cyan-400" };
  }
}
