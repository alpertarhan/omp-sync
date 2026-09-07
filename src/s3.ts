/**
 * Minimal SigV4 S3 client. PUT/GET/HEAD/LIST/DELETE — nothing more.
 * One signed request per object, no AWS SDK, no multipart.
 *
 * Two deliberate extras over a naive client:
 * - every request carries a timeout (a wedged endpoint must never hang
 *   the agent or the 2s session_shutdown budget);
 * - PUT supports If-Match so the manifest can do optimistic concurrency
 *   (412 -> reload, re-merge, retry) instead of blind last-writer-wins.
 */
import { createHash, createHmac } from "node:crypto";

export interface S3Config {
  /** Full endpoint incl. scheme, e.g. https://bucket.s3.eu-central-1.idrivee2.com */
  endpoint: string;
  bucket: string;
  region: string;
  accessKeyId: string;
  secretAccessKey: string;
  /** Per-request timeout in ms. Defaults to 15s. */
  timeoutMs?: number;
}

export const DEFAULT_TIMEOUT_MS = 15_000;

/** Thrown when a conditional PUT loses an optimistic-concurrency race. */
export class EtagMismatchError extends Error {
  readonly status = 412;
  constructor(key: string) {
    super(`PUT ${key}: ETag mismatch (412) — remote changed under us`);
    this.name = "EtagMismatchError";
  }
}
/**
 * Minimal object-store surface the sync engine needs. S3 implements it;
 * tests inject an in-memory fake. Structural typing — no registration.
 */
export interface ObjectStore {
  putObject(key: string, body: Buffer, contentType?: string, opts?: { ifMatch?: string; ifNoneMatch?: boolean }): Promise<{ etag?: string }>;
  getObject(key: string): Promise<{ body: Buffer; etag?: string } | null>;
  headObject(key: string): Promise<{ size: number; etag?: string } | null>;
  listObjects(prefix: string): Promise<{ key: string; size: number }[]>;
  ping(): Promise<boolean>;
}

const sha256 = (s: Buffer | string): string =>
  createHash("sha256").update(typeof s === "string" ? Buffer.from(s) : s).digest("hex");

const hmac = (key: Buffer | string, msg: string): Buffer =>
  createHmac("sha256", key).update(msg).digest();

/** URI-encode per SigV4 (slash not encoded in path). */
function encodePath(p: string): string {
  return p
    .split("/")
    .map((seg) => encodeURIComponent(seg).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`))
    .join("/");
}

function encodeQueryVal(v: string): string {
  return encodeURIComponent(v).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

/** Decode the (few) XML entities S3 may emit inside <Key>. */
function decodeXmlEntities(s: string): string {
  return s.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, "&");
}

export class S3 {
  private host: string;
  private base: string;
  private timeoutMs: number;
  /**
   * Path prefix for bucket addressing. Empty when the bucket rides in the
   * endpoint hostname (virtual-hosted style, e.g.
   * https://mybucket.s3.example.com); otherwise `/<bucket>` (path style,
   * e.g. https://s3.example.com + bucket mybucket).
   */
  private bucketPrefix: string;

  constructor(private cfg: S3Config) {
    const u = new URL(cfg.endpoint);
    this.host = u.host;
    this.base = `${u.protocol}//${u.host}`;
    this.timeoutMs = cfg.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const bare = u.hostname === cfg.bucket || u.hostname.startsWith(`${cfg.bucket}.`);
    this.bucketPrefix = bare ? "" : `/${encodePath(cfg.bucket)}`;
  }

  /** Sign one request and fetch it. Returns the Response (caller inspects). */
  private async signed(
    method: string,
    key: string,
    opts: {
      query?: Record<string, string>;
      body?: Buffer;
      contentType?: string;
      ifNoneMatch?: boolean;
      ifMatch?: string;
    } = {},
  ): Promise<Response> {
    const amzdate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, "");
    const datestamp = amzdate.slice(0, 8);
    const bodyHash = opts.body ? sha256(opts.body) : sha256("");

    const path = this.bucketPrefix === "" && key === "" ? "/" : `${this.bucketPrefix}/${encodePath(key)}`;
    const queryItems = opts.query ? Object.entries(opts.query).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)) : [];
    const canonicalQuery = queryItems.map(([k, v]) => `${encodeQueryVal(k)}=${encodeQueryVal(v)}`).join("&");

    const headers: Record<string, string> = {
      host: this.host,
      "x-amz-content-sha256": bodyHash,
      "x-amz-date": amzdate,
    };
    if (opts.contentType) headers["content-type"] = opts.contentType;
    if (opts.ifNoneMatch) headers["if-none-match"] = "*";
    if (opts.ifMatch) headers["if-match"] = opts.ifMatch;

    const sortedHeaders = Object.entries(headers).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    const canonicalHeaders = sortedHeaders.map(([k, v]) => `${k}:${v.trim()}\n`).join("");
    const signedHeaders = sortedHeaders.map(([k]) => k).join(";");

    const canonicalRequest = [method, path, canonicalQuery, canonicalHeaders, signedHeaders, bodyHash].join("\n");

    const scope = `${datestamp}/${this.cfg.region}/s3/aws4_request`;
    const stringToSign = ["AWS4-HMAC-SHA256", amzdate, scope, sha256(canonicalRequest)].join("\n");

    const kDate = hmac(`AWS4${this.cfg.secretAccessKey}`, datestamp);
    const kRegion = hmac(kDate, this.cfg.region);
    const kService = hmac(kRegion, "s3");
    const kSigning = hmac(kService, "aws4_request");
    const signature = createHmac("sha256", kSigning).update(stringToSign).digest("hex");

    const auth = `AWS4-HMAC-SHA256 Credential=${this.cfg.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
    const url = `${this.base}${path}${canonicalQuery ? `?${canonicalQuery}` : ""}`;

    try {
      // fetch BodyInit vs Buffer typing friction; runtime is fine.
      return await fetch(url, {
        method,
        headers: { ...headers, Authorization: auth },
        body: opts.body as BodyInit | undefined,
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (e) {
      if (e instanceof Error && (e.name === "TimeoutError" || e.name === "AbortError")) {
        throw new Error(`${method} ${key || "/"}: timed out after ${this.timeoutMs}ms`);
      }
      throw e;
    }
  }

  async putObject(
    key: string,
    body: Buffer,
    contentType = "application/octet-stream",
    opts: { ifMatch?: string; ifNoneMatch?: boolean } = {},
  ): Promise<{ etag?: string }> {
    const r = await this.signed("PUT", key, { body, contentType, ifMatch: opts.ifMatch, ifNoneMatch: opts.ifNoneMatch });
    if (r.status === 412) throw new EtagMismatchError(key);
    if (!r.ok) throw new Error(`PUT ${key} failed: ${r.status} ${await r.text()}`);
    return { etag: r.headers.get("etag") ?? undefined };
  }

  /**
   * GET one object with its ETag. The ETag belongs to exactly these bytes
   * (same response), so manifest concurrency never pairs a HEAD generation
   * with a GET generation.
   */
  async getObject(key: string): Promise<{ body: Buffer; etag?: string } | null> {
    const r = await this.signed("GET", key);
    if (r.status === 404) return null;
    if (!r.ok) throw new Error(`GET ${key} failed: ${r.status} ${await r.text()}`);
    return { body: Buffer.from(await r.arrayBuffer()), etag: r.headers.get("etag") ?? undefined };
  }

  async headObject(key: string): Promise<{ size: number; etag?: string } | null> {
    const r = await this.signed("HEAD", key);
    if (r.status === 404) return null;
    if (!r.ok) throw new Error(`HEAD ${key} failed: ${r.status}`);
    return { size: Number(r.headers.get("content-length") ?? 0), etag: r.headers.get("etag") ?? undefined };
  }

  /** List all keys under a prefix, following pagination to the end. */
  async listObjects(prefix: string): Promise<{ key: string; size: number }[]> {
    const out: { key: string; size: number }[] = [];
    const seenTokens = new Set<string>();
    let token: string | undefined;
    for (;;) {
      const query: Record<string, string> = { "list-type": "2", prefix, "max-keys": "1000" };
      if (token) query["continuation-token"] = token;
      const r = await this.signed("GET", "", { query });
      if (!r.ok) throw new Error(`LIST ${prefix} failed: ${r.status} ${await r.text()}`);
      const xml = await r.text();
      const re = /<Contents>\s*<Key>([^<]+)<\/Key>[\s\S]*?<Size>(\d+)<\/Size>/g;
      let m: RegExpExecArray | null;
      while ((m = re.exec(xml))) out.push({ key: decodeXmlEntities(m[1]), size: Number(m[2]) });
      const truncated = /<IsTruncated>(true)<\/IsTruncated>/.test(xml);
      const next = /<NextContinuationToken>([^<]+)<\/NextContinuationToken>/.exec(xml)?.[1];
      if (truncated && !next) {
        throw new Error(`LIST ${prefix}: truncated response without a continuation token — refusing a partial list`);
      }
      if (!truncated || !next) break;
      const decoded = decodeXmlEntities(next);
      if (seenTokens.has(decoded)) throw new Error(`LIST ${prefix}: repeated continuation token — refusing a loop`);
      seenTokens.add(decoded);
      token = decoded;
    }
    return out;
  }

  async deleteObject(key: string): Promise<void> {
    const r = await this.signed("DELETE", key);
    if (!r.ok && r.status !== 204) throw new Error(`DELETE ${key} failed: ${r.status} ${await r.text()}`);
  }

  /** Connectivity + credentials sanity check. */
  async ping(): Promise<boolean> {
    const r = await this.signed("HEAD", "");
    return r.ok;
  }
}
