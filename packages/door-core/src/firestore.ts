import type { KvStore } from './kv.js';

// KvStore over Firestore. Typed structurally so the SDK has no hard dependency
// on firebase-admin or @google-cloud/firestore; pass either one's Firestore.
//
// Expiry: each doc carries `expiresAt`. Reads ignore expired docs; add a
// Firestore TTL policy on `expiresAt` for the door_* collections to reclaim them.

interface DocSnap {
  exists: boolean;
  data(): Record<string, unknown> | undefined;
}
interface DocRef {
  get(): Promise<DocSnap>;
  set(data: Record<string, unknown>): Promise<unknown>;
  delete(): Promise<unknown>;
}
interface Txn {
  get(ref: DocRef): Promise<DocSnap>;
  set(ref: DocRef, data: Record<string, unknown>): unknown;
  delete(ref: DocRef): unknown;
}
export interface FirestoreLike {
  collection(path: string): { doc(id: string): DocRef };
  runTransaction<T>(fn: (txn: Txn) => Promise<T>): Promise<T>;
}

function docId(id: string): string {
  // Firestore ids can't contain '/', and can't be '.' or '..'.
  return /^[A-Za-z0-9_\-:.@]{1,700}$/.test(id) && id !== '.' && id !== '..'
    ? id
    : `b64_${btoa(unescape(encodeURIComponent(id)))
        .replace(/\//g, '_')
        .replace(/\+/g, '-')
        .replace(/=+$/, '')}`;
}

function expired(snap: DocSnap): boolean {
  const at = snap.data()?.expiresAt as { toMillis?: () => number } | Date | undefined;
  if (!at) return false;
  const ms = at instanceof Date ? at.getTime() : at.toMillis?.();
  return ms !== undefined && ms < Date.now();
}

export class FirestoreKvStore implements KvStore {
  constructor(
    private readonly db: FirestoreLike,
    private readonly prefix = 'door_',
  ) {}

  private ref(ns: string, id: string): DocRef {
    return this.db.collection(`${this.prefix}${ns}`).doc(docId(id));
  }

  private wrap(value: unknown, ttlSeconds?: number) {
    // JSON round-trip keeps the stored shape identical to MemoryKvStore's.
    const doc: Record<string, unknown> = { v: JSON.stringify(value) };
    if (ttlSeconds !== undefined) doc.expiresAt = new Date(Date.now() + ttlSeconds * 1000);
    return doc;
  }

  private unwrap<T>(snap: DocSnap): T | undefined {
    if (!snap.exists || expired(snap)) return undefined;
    return JSON.parse(snap.data()!.v as string) as T;
  }

  async get<T>(ns: string, id: string) {
    return this.unwrap<T>(await this.ref(ns, id).get());
  }

  async put<T>(ns: string, id: string, value: T, ttlSeconds?: number) {
    await this.ref(ns, id).set(this.wrap(value, ttlSeconds));
  }

  async take<T>(ns: string, id: string) {
    const ref = this.ref(ns, id);
    return this.db.runTransaction(async (txn) => {
      const snap = await txn.get(ref);
      const value = this.unwrap<T>(snap);
      if (snap.exists) txn.delete(ref);
      return value;
    });
  }

  async update<T>(ns: string, id: string, fn: (current: T | undefined) => T, ttlSeconds?: number) {
    const ref = this.ref(ns, id);
    return this.db.runTransaction(async (txn) => {
      const snap = await txn.get(ref);
      const next = fn(this.unwrap<T>(snap));
      const keepExpiry =
        ttlSeconds === undefined && snap.exists ? snap.data()?.expiresAt : undefined;
      const doc = this.wrap(next, ttlSeconds);
      if (keepExpiry) doc.expiresAt = keepExpiry;
      txn.set(ref, doc);
      return next;
    });
  }

  async delete(ns: string, id: string) {
    await this.ref(ns, id).delete();
  }
}
