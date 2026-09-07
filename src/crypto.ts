/**
 * Crypto foundation: AES-256-GCM(gzip(plaintext)) envelopes.
 *
 * One encrypted blob = nonce(12) || ciphertext || tag(16).
 * The key never touches storage or the network: it lives in the
 * OMP_SYNC_ENCRYPTION_KEY env var on each machine.
 */
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { createGunzip, gunzipSync, gzipSync } from "node:zlib";

/** Raw bytes ready to PUT as a single S3 object body. */
export interface Sealed {
  body: Buffer;
}

/**
 * Encrypt + compress. Order matters: plaintext compresses far better
 * than ciphertext. GCM gives authenticated encryption — tampering is
 * detected on decrypt.
 */
export function seal(plaintext: Buffer, key: Buffer, aad?: Buffer): Sealed {
  if (key.length !== 32) throw new Error(`AES-256 needs a 32-byte key, got ${key.length}`);
  const nonce = randomBytes(12); // 96-bit nonce, fresh per seal
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  if (aad) cipher.setAAD(aad); // binds the ciphertext to its object key: bytes swapped between keys fail to open
  const gz = gzipSync(plaintext);
  const enc = Buffer.concat([cipher.update(gz), cipher.final()]);
  const tag = cipher.getAuthTag(); // 16 bytes
  return { body: Buffer.concat([nonce, enc, tag]) };
}

/** Decrypt + decompress. Throws if the key/AAD is wrong or the blob was tampered with. */
export function open(sealed: Sealed, key: Buffer, aad?: Buffer): Buffer {
  if (key.length !== 32) throw new Error(`AES-256 needs a 32-byte key, got ${key.length}`);
  if (sealed.body.length < 12 + 16) throw new Error("sealed blob too short");
  const nonce = sealed.body.subarray(0, 12);
  const tag = sealed.body.subarray(sealed.body.length - 16);
  const enc = sealed.body.subarray(12, sealed.body.length - 16);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  if (aad) decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  const gz = Buffer.concat([decipher.update(enc), decipher.final()]);
  return gunzipSync(gz);
}
/**
 * Decrypt + decompress with a hard cap on inflated bytes (zip-bomb defense).
 * Streams decrypt->inflate and aborts past maxBytes, so a hostile object can
 * never materialize unbounded plaintext. Rejects on wrong key/AAD/tampering.
 */
export function openBounded(sealed: Sealed, key: Buffer, maxBytes: number, aad?: Buffer): Promise<Buffer> {
  if (key.length !== 32) return Promise.reject(new Error(`AES-256 needs a 32-byte key, got ${key.length}`));
  if (sealed.body.length < 12 + 16) return Promise.reject(new Error("sealed blob too short"));
  if (!Number.isFinite(maxBytes) || maxBytes <= 0) return Promise.reject(new Error("maxBytes must be positive"));
  const { promise, resolve, reject } = Promise.withResolvers<Buffer>();
  const nonce = sealed.body.subarray(0, 12);
  const tag = sealed.body.subarray(sealed.body.length - 16);
  const enc = sealed.body.subarray(12, sealed.body.length - 16);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  if (aad) decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  const gunzip = createGunzip();
  const chunks: Buffer[] = [];
  let total = 0;
  let done = false;
  const fail = (e: Error): void => {
    if (done) return;
    done = true;
    gunzip.destroy();
    reject(e);
  };
  gunzip.on("data", (c: Buffer) => {
    total += c.length;
    if (total > maxBytes) {
      fail(new Error(`inflated size exceeds limit (${maxBytes} bytes)`));
      return;
    }
    chunks.push(c);
  });
  gunzip.on("end", () => {
    if (done) return;
    done = true;
    resolve(Buffer.concat(chunks));
  });
  gunzip.on("error", fail);
  let gz: Buffer;
  try {
    gz = Buffer.concat([decipher.update(enc), decipher.final()]);
  } catch (e) {
    fail(e instanceof Error ? e : new Error(String(e)));
    return promise;
  }
  gunzip.end(gz);
  return promise;
}

/** Parse a 32-byte key from a base64 env string (the OMP_SYNC_ENCRYPTION_KEY value). */
export function keyFromEnv(raw: string): Buffer {
  const buf = Buffer.from(raw.trim(), "base64");
  if (buf.length !== 32) {
    throw new Error(
      `OMP_SYNC_ENCRYPTION_KEY must decode to 32 bytes, got ${buf.length}. ` +
        `Generate with: openssl rand -base64 32`,
    );
  }
  return buf;
}
