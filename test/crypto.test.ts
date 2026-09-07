import { test, expect } from "bun:test";
import { randomBytes } from "node:crypto";
import { keyFromEnv, open, openBounded, seal } from "../src/crypto.js";

test("seal/open roundtrip", () => {
  const key = randomBytes(32);
  const plain = Buffer.from(JSON.stringify({ role: "user", content: "hello" }) + "\n".repeat(100));
  expect(open(seal(plain, key), key).equals(plain)).toBe(true);
});

test("sealed blob hides plaintext and compresses", () => {
  const key = randomBytes(32);
  const plain = Buffer.from("a".repeat(10000));
  const sealed = seal(plain, key);
  expect(sealed.body.length).toBeLessThan(plain.length);
  expect(sealed.body.includes(Buffer.from("aaaa"))).toBe(false);
  // nonce(12) + ciphertext + tag(16)
  expect(sealed.body.length).toBeGreaterThan(28);
});

test("tampered blob is rejected (GCM auth)", () => {
  const key = randomBytes(32);
  const sealed = seal(Buffer.from("secret"), key);
  const tampered = Buffer.from(sealed.body);
  tampered[20] ^= 0xff;
  expect(() => open({ body: tampered }, key)).toThrow();
});

test("wrong key is rejected", () => {
  const sealed = seal(Buffer.from("secret"), randomBytes(32));
  expect(() => open(sealed, randomBytes(32))).toThrow();
});

test("short blob is rejected", () => {
  expect(() => open({ body: Buffer.alloc(10) }, randomBytes(32))).toThrow();
});

test("key must be 32 bytes", () => {
  expect(() => seal(Buffer.from("x"), randomBytes(16))).toThrow(/32-byte/);
  expect(() => open({ body: Buffer.alloc(30) }, randomBytes(16))).toThrow(/32-byte/);
});

test("keyFromEnv parses base64", () => {
  const raw = randomBytes(32);
  const key = keyFromEnv(raw.toString("base64"));
  expect(key.equals(raw)).toBe(true);
  expect(() => keyFromEnv("too-short")).toThrow(/32 bytes/);
});
test("nonces are fresh per seal", () => {
  const key = randomBytes(32);
  const a = seal(Buffer.from("same"), key).body.subarray(0, 12);
  const b = seal(Buffer.from("same"), key).body.subarray(0, 12);
  expect(a.equals(b)).toBe(false);
});

test("AAD binds ciphertext to its object key", () => {
  const key = randomBytes(32);
  const sealed = seal(Buffer.from("data"), key, Buffer.from("key-a"));
  expect(open(sealed, key, Buffer.from("key-a")).toString()).toBe("data");
  expect(() => open(sealed, key, Buffer.from("key-b"))).toThrow();
  expect(() => open(sealed, key)).toThrow();
});

test("openBounded roundtrips and caps inflation", async () => {
  const key = randomBytes(32);
  const plain = Buffer.from(JSON.stringify({ x: 1 }));
  const sealed = seal(plain, key);
  expect((await openBounded(sealed, key, 1024 * 1024)).equals(plain)).toBe(true);
  await expect(openBounded(sealed, key, 4)).rejects.toThrow(/exceeds limit/);
  await expect(openBounded({ body: Buffer.alloc(10) }, key, 100)).rejects.toThrow();
  await expect(openBounded(sealed, randomBytes(32), 1024 * 1024)).rejects.toThrow();
});

test("openBounded rejects a zip bomb before materializing it", async () => {
  const key = randomBytes(32);
  const bomb = seal(Buffer.from("0".repeat(2 * 1024 * 1024)), key); // ~2KB on the wire
  expect(bomb.body.length).toBeLessThan(16 * 1024);
  await expect(openBounded(bomb, key, 64 * 1024)).rejects.toThrow(/exceeds limit/);
});
