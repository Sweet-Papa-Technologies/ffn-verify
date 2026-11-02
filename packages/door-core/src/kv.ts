// The only storage the Door SDK needs. Sites plug in their own database
// (Firestore adapter in ./firestore.ts); tests use the in-memory store.

export interface KvStore {
  get<T>(ns: string, id: string): Promise<T | undefined>;
  put<T>(ns: string, id: string, value: T, ttlSeconds?: number): Promise<void>;
  /** Atomic read-and-delete. Single-use codes, nonces and request states rely on it. */
  take<T>(ns: string, id: string): Promise<T | undefined>;
  /** Atomic read-modify-write. Returns the stored value. */
  update<T>(
    ns: string,
    id: string,
    fn: (current: T | undefined) => T,
    ttlSeconds?: number,
  ): Promise<T>;
  delete(ns: string, id: string): Promise<void>;
}

export class MemoryKvStore implements KvStore {
  private readonly data = new Map<string, { value: unknown; until: number }>();

  private key(ns: string, id: string) {
    return `${ns}\u0000${id}`;
  }

  private live(key: string) {
    const hit = this.data.get(key);
    if (!hit) return undefined;
    if (hit.until < Date.now()) {
      this.data.delete(key);
      return undefined;
    }
    return hit;
  }

  async get<T>(ns: string, id: string) {
    return structuredClone(this.live(this.key(ns, id))?.value) as T | undefined;
  }

  async put<T>(ns: string, id: string, value: T, ttlSeconds?: number) {
    const until =
      ttlSeconds === undefined ? Number.POSITIVE_INFINITY : Date.now() + ttlSeconds * 1000;
    this.data.set(this.key(ns, id), { value: structuredClone(value), until });
  }

  async take<T>(ns: string, id: string) {
    const key = this.key(ns, id);
    const hit = this.live(key);
    this.data.delete(key);
    return hit?.value as T | undefined;
  }

  async update<T>(ns: string, id: string, fn: (current: T | undefined) => T, ttlSeconds?: number) {
    const key = this.key(ns, id);
    const hit = this.live(key);
    const next = fn(structuredClone(hit?.value) as T | undefined);
    const until =
      ttlSeconds !== undefined
        ? Date.now() + ttlSeconds * 1000
        : (hit?.until ?? Number.POSITIVE_INFINITY);
    this.data.set(key, { value: structuredClone(next), until });
    return next;
  }

  async delete(ns: string, id: string) {
    this.data.delete(this.key(ns, id));
  }
}
