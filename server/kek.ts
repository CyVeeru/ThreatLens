/**
 * Key-encryption key (KEK) for secrets at rest (AI provider keys, MFA seeds).
 *
 * Exactly one loader lives here and every consumer imports it, so the key used
 * to encrypt a value is always the key used to decrypt it. Resolution order:
 *
 *   1. THREATLENS_KEY_ENCRYPTION_KEY / THREATLENS_KEK (base64 or passphrase)
 *   2. data/.threatlens-kek — created with a random 256-bit key on first boot
 *
 * There is intentionally no deterministic fallback: a predictable KEK would
 * make the secret store decryptable by anyone who knows the install path.
 */
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { chmodSync, closeSync, mkdirSync, openSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { env } from "./env";

export const DATA_DIR = resolve(process.cwd(), "data");
export const KEK_PATH = join(DATA_DIR, ".threatlens-kek");

function loadKek(): Buffer {
  const configured = env("KEY_ENCRYPTION_KEY") || env("KEK");
  if (configured) {
    const raw = /^[A-Za-z0-9+/=]{43,}$/.test(configured)
      ? Buffer.from(configured, "base64")
      : Buffer.from(configured, "utf8");
    return createHash("sha256").update(raw).digest();
  }
  try {
    mkdirSync(DATA_DIR, { recursive: true });
    try {
      const v = readFileSync(KEK_PATH, "utf8").trim();
      if (v) return Buffer.from(v, "base64");
    } catch (readErr: any) {
      if (readErr?.code !== "ENOENT") throw readErr;
    }
    const key = randomBytes(32);
    const fd = openSync(KEK_PATH, "wx", 0o600);
    try {
      writeFileSync(fd, key.toString("base64"));
    } finally {
      closeSync(fd);
    }
    try {
      chmodSync(KEK_PATH, 0o600);
    } catch {
      /* best-effort on non-POSIX hosts */
    }
    return key;
  } catch (err) {
    throw new Error(`Unable to initialize ThreatLens key-encryption key: ${(err as Error).message}`);
  }
}

// Loaded on first use, not at import time, so merely importing a module that
// can decrypt (aiLive, storage) never touches the filesystem — tests and
// tooling stay side-effect free until a secret is actually read or written.
let cachedKek: Buffer | null = null;
export function getKek(): Buffer {
  if (!cachedKek) cachedKek = loadKek();
  return cachedKek;
}

/** AES-256-GCM, versioned envelope: `v1:<iv>:<tag>:<ciphertext>` (all base64). */
export function encryptSecret(plaintext: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", getKek(), iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v1:${iv.toString("base64")}:${tag.toString("base64")}:${ciphertext.toString("base64")}`;
}

/**
 * Returns the plaintext, or null when the value is empty, tampered, or was
 * encrypted under a different key. Legacy pre-`v1:` values were plain base64
 * and are still decoded so an old workspace keeps working after upgrade.
 */
export function decryptSecret(value: string | null | undefined): string | null {
  if (!value) return null;
  try {
    if (value.startsWith("v1:")) {
      const [, ivB64, tagB64, bodyB64] = value.split(":");
      const decipher = createDecipheriv("aes-256-gcm", getKek(), Buffer.from(ivB64, "base64"));
      decipher.setAuthTag(Buffer.from(tagB64, "base64"));
      return Buffer.concat([decipher.update(Buffer.from(bodyB64, "base64")), decipher.final()]).toString("utf8");
    }
    return Buffer.from(value, "base64").toString("utf8");
  } catch {
    return null;
  }
}
