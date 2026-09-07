/**
 * S3 client tests with a stubbed global fetch: URL construction for both
 * bucket-addressing styles, SigV4 encoding edge cases, and LIST pagination
 * discipline (partial lists must throw, never silently truncate).
 */
import { test, expect, afterEach } from "bun:test";
import { S3, computeSignature, type S3Config } from "../src/s3.js";

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

function cfg(over: Partial<S3Config> = {}): S3Config {
  return {
    endpoint: "https://bkt.s3.example.com",
    bucket: "bkt",
    region: "auto",
    accessKeyId: "AKID",
    secretAccessKey: "SECRET",
    timeoutMs: 5000,
    ...over,
  };
}

function stubFetch(handler: (url: string, init: RequestInit) => Response): string[] {
  const seen: string[] = [];
  globalThis.fetch = (async (u: unknown, init?: RequestInit) => {
    seen.push(String(u));
    return handler(String(u), init ?? {});
  }) as typeof fetch;
  return seen;
}

const okPut = () => new Response("", { status: 200, headers: { ETag: '"e1"' } });

test("virtual-hosted style keeps the bucket out of the path", async () => {
  const seen = stubFetch(() => okPut());
  const s3 = new S3(cfg());
  await s3.putObject("a/b.jsonl.enc", Buffer.from("x"));
  expect(seen.length).toBe(1);
  const u = new URL(seen[0]);
  expect(u.hostname).toBe("bkt.s3.example.com");
  expect(u.pathname).toBe("/a/b.jsonl.enc");
});

test("path style prefixes the bucket when the endpoint lacks it", async () => {
  const seen = stubFetch(() => okPut());
  const s3 = new S3(cfg({ endpoint: "https://s3.example.com", bucket: "myb" }));
  await s3.putObject("a/b.jsonl.enc", Buffer.from("x"));
  const u = new URL(seen[0]);
  expect(u.hostname).toBe("s3.example.com");
  expect(u.pathname).toBe("/myb/a/b.jsonl.enc");
});

test("special characters in keys are SigV4-encoded", async () => {
  const seen = stubFetch(() => okPut());
  const s3 = new S3(cfg());
  await s3.putObject("sp ace+plus%pctünicode.jsonl.enc", Buffer.from("x"));
  const u = new URL(seen[0]);
  expect(u.pathname).toBe("/sp%20ace%2Bplus%25pct%C3%BCnicode.jsonl.enc");
});

test("signed requests carry SigV4 headers", async () => {
  let auth = "";
  stubFetch((_u, init) => {
    auth = String((init.headers as Record<string, string>)["Authorization"] ?? "");
    return okPut();
  });
  const s3 = new S3(cfg());
  const r = await s3.putObject("k", Buffer.from("x"), "application/octet-stream", { ifMatch: '"e0"' });
  expect(r.etag).toBe('"e1"');
  expect(auth.startsWith("AWS4-HMAC-SHA256 Credential=AKID/")).toBe(true);
  expect(auth).toContain("SignedHeaders=");
  expect(auth).toContain("Signature=");
});

test("412 surfaces as EtagMismatchError", async () => {
  stubFetch(() => new Response("precondition", { status: 412 }));
  const s3 = new S3(cfg());
  await expect(s3.putObject("k", Buffer.from("x"), "application/octet-stream", { ifMatch: '"stale"' })).rejects.toThrow(
    /412/,
  );
});

const page = (keys: [string, number][], truncated: boolean, token?: string): string =>
  `<?xml version="1.0"?><ListBucketResult>` +
  keys.map(([k, s]) => `<Contents><Key>${k}</Key><Size>${s}</Size></Contents>`).join("") +
  `<IsTruncated>${truncated ? "true" : "false"}</IsTruncated>` +
  (token ? `<NextContinuationToken>${token}</NextContinuationToken>` : "") +
  `</ListBucketResult>`;

test("paginated LIST follows tokens and decodes entities", async () => {
  stubFetch((u) => {
    if (u.includes("continuation-token=tok1")) return new Response(page([["p/a&amp;b", 3]], false), { status: 200 });
    return new Response(page([["p/one", 1]], true, "tok1"), { status: 200 });
  });
  const s3 = new S3(cfg());
  const out = await s3.listObjects("p/");
  expect(out).toEqual([
    { key: "p/one", size: 1 },
    { key: "p/a&b", size: 3 },
  ]);
});

test("truncated LIST without a token throws instead of truncating", async () => {
  stubFetch(() => new Response(page([["p/one", 1]], true), { status: 200 }));
  const s3 = new S3(cfg());
  await expect(s3.listObjects("p/")).rejects.toThrow(/truncated/);
});

test("repeated continuation token throws instead of looping", async () => {
  stubFetch(() => new Response(page([["p/one", 1]], true, "same"), { status: 200 }));
  const s3 = new S3(cfg());
  await expect(s3.listObjects("p/")).rejects.toThrow(/repeated/);
});

test("computeSignature matches AWS's published SigV4 test vector", () => {
  // AWS S3 developer guide, "GET Object" example: fixed inputs, fixed
  // signature. Pins the canonical-request assembly AND the key-derivation
  // chain against the reference, independent of our own plumbing.
  const { auth, signature } = computeSignature({
    method: "GET",
    path: "/test.txt",
    canonicalQuery: "",
    headers: {
      host: "examplebucket.s3.amazonaws.com",
      range: "bytes=0-9",
      "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "x-amz-date": "20130524T000000Z",
    },
    bodyHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    amzdate: "20130524T000000Z",
    region: "us-east-1",
    accessKeyId: "AKIAIOSFODNN7EXAMPLE",
    secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  });
  expect(signature).toBe("f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41");
  expect(auth).toBe(
    "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, " +
      "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, " +
      "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
  );
});

test("getObject refuses a declared-oversized body before buffering", async () => {
  stubFetch(() => new Response("x".repeat(4096), { status: 200, headers: { "Content-Length": "4096", ETag: '"e"' } }));
  const s3 = new S3(cfg());
  await expect(s3.getObject("big.bin", { maxBytes: 1024 })).rejects.toThrow(/exceeds limit/);
});
