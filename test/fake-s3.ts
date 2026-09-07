/**
 * In-memory ObjectStore with generation-tracked ETags and failure injection.
 * Mirrors S3 conditional-write semantics (If-Match / If-None-Match -> 412)
 * closely enough to pin the sync engine's concurrency discipline.
 */
import { EtagMismatchError, type ObjectStore } from "../src/s3.js";

export class FakeS3 implements ObjectStore {
  objects = new Map<string, { body: Buffer; etag: string }>();
  failOnPut = new Set<string>();
  failOnGet = new Set<string>();
  failOnHead = new Set<string>();
  puts = 0;
  gets = 0;
  heads = 0;
  private seq = 0;

  async putObject(
    key: string,
    body: Buffer,
    _contentType?: string,
    opts: { ifMatch?: string; ifNoneMatch?: boolean } = {},
  ): Promise<{ etag?: string }> {
    this.puts++;
    if (this.failOnPut.has(key)) throw new Error(`injected PUT failure: ${key}`);
    const cur = this.objects.get(key);
    if (opts.ifNoneMatch && cur) throw new EtagMismatchError(key);
    if (opts.ifMatch !== undefined && (!cur || cur.etag !== opts.ifMatch)) throw new EtagMismatchError(key);
    const etag = `"gen${++this.seq}"`;
    this.objects.set(key, { body: Buffer.from(body), etag });
    return { etag };
  }

  async getObject(
    key: string,
    _opts: { maxBytes?: number } = {},
  ): Promise<{ body: Buffer; etag?: string } | null> {
    this.gets++;
    if (this.failOnGet.has(key)) throw new Error(`injected GET failure: ${key}`);
    const cur = this.objects.get(key);
    return cur ? { body: Buffer.from(cur.body), etag: cur.etag } : null;
  }

  async headObject(key: string): Promise<{ size: number; etag?: string } | null> {
    this.heads++;
    if (this.failOnHead.has(key)) throw new Error(`injected HEAD failure: ${key}`);
    const cur = this.objects.get(key);
    return cur ? { size: cur.body.length, etag: cur.etag } : null;
  }

  async listObjects(prefix: string): Promise<{ key: string; size: number }[]> {
    return [...this.objects.entries()]
      .filter(([k]) => k.startsWith(prefix))
      .map(([key, v]) => ({ key, size: v.body.length }));
  }

  async ping(): Promise<boolean> {
    return true;
  }

  keys(): string[] {
    return [...this.objects.keys()].sort();
  }
}
