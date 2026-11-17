// Client-side envelope encryption with the browser's Web Crypto API.
//
// Upload:   GenerateDataKey (KMS) -> import DEK as non-extractable CryptoKey -> wipe raw DEK bytes
//           -> AES-256-GCM encrypt locally (AAD = encryption context) -> PUT ciphertext + wrapped DEK (Vault)
// Download: GET ciphertext (Vault) -> Decrypt wrapped DEK (KMS) -> import + wipe -> AES-GCM decrypt locally
//
// The plaintext file never leaves this tab. The KMS sees a 32-byte key, the Vault sees ciphertext.

import { kms, vault, type DataKey, type EncryptionContext, type StoredObject } from './api';

const enc = new TextEncoder();
const dec = new TextDecoder();

export const b64 = {
  encode(bytes: Uint8Array): string {
    let s = '';
    for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    return btoa(s);
  },
  decode(text: string): Uint8Array {
    const bin = atob(text);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  },
};

export function hex(bytes: Uint8Array, max = Infinity): string {
  const n = Math.min(bytes.length, max);
  let s = '';
  for (let i = 0; i < n; i++) s += bytes[i].toString(16).padStart(2, '0') + (i % 2 ? ' ' : '');
  return s.trim() + (bytes.length > n ? ' …' : '');
}

/** Must match the server's json.dumps(ctx, sort_keys=True, separators=(",", ":")). */
export function canonical(ctx: EncryptionContext): string {
  const sorted: EncryptionContext = {};
  for (const k of Object.keys(ctx).sort()) sorted[k] = ctx[k];
  return JSON.stringify(sorted);
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Import raw key bytes as a non-extractable AES-GCM key, then overwrite the raw bytes. */
async function importAndWipe(raw: Uint8Array, usage: KeyUsage): Promise<CryptoKey> {
  try {
    return await crypto.subtle.importKey('raw', raw as BufferSource, { name: 'AES-GCM' }, false, [usage]);
  } finally {
    raw.fill(0);
  }
}

// ----------------------------------------------------------------------------- events (for the Inspector)
export type EnvelopeEvent =
  | { kind: 'request-dek'; ctx: EncryptionContext }
  | { kind: 'fetch-ciphertext'; bytes: number; preview: string; ms: number }
  | {
      kind: 'dek-received';
      keyAlias: string;
      version: number;
      algorithm: string;
      blobPreview: string;
      blobBytes: number;
      dek: Uint8Array;
      ms: number;
    }
  | { kind: 'zeroized'; dek: Uint8Array }
  | { kind: 'encrypted'; iv: string; aad: string; plainPreview: string; cipherPreview: string; bytes: number; ms: number }
  | { kind: 'decrypted'; plainPreview: string; bytes: number; ms: number }
  | { kind: 'uploaded'; object: StoredObject; ms: number }
  | { kind: 'done' };

type Listener = (e: EnvelopeEvent) => void;

function previewText(data: Uint8Array): string {
  const head = dec.decode(data.subarray(0, 96));
  const printable = head.replace(/[^\x20-\x7E\n]/g, '·');
  return printable + (data.length > 96 ? '…' : '');
}

export interface UploadParams {
  token: string;
  tenant: string;
  bucket: string;
  objectKey: string;
  data: Uint8Array;
  contentType: string;
  keyId: string;
}

export async function encryptAndUpload(p: UploadParams, on: Listener = () => {}, pace = 0): Promise<StoredObject> {
  const ctx: EncryptionContext = { tenant: p.tenant, bucket: p.bucket, object: p.objectKey };
  on({ kind: 'request-dek', ctx });
  await sleep(pace);

  const { data: dk, totalMs } = await kms.generateDataKey(p.token, p.keyId, ctx);
  const dek = b64.decode(dk.plaintext);
  (dk as Partial<DataKey>).plaintext = undefined; // drop our reference to the base64 copy
  const blob = b64.decode(dk.ciphertext_blob);
  on({
    kind: 'dek-received',
    keyAlias: dk.key_alias,
    version: dk.key_version,
    algorithm: dk.algorithm,
    blobPreview: hex(blob, 24),
    blobBytes: blob.length,
    dek,
    ms: totalMs,
  });
  await sleep(pace);

  const key = await importAndWipe(dek, 'encrypt');
  on({ kind: 'zeroized', dek });
  await sleep(pace);

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = canonical(ctx);
  const t0 = performance.now();
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: enc.encode(aad), tagLength: 128 },
      key,
      p.data as BufferSource,
    ),
  );
  on({
    kind: 'encrypted',
    iv: hex(iv),
    aad,
    plainPreview: previewText(p.data),
    cipherPreview: hex(ciphertext, 40),
    bytes: ciphertext.length,
    ms: performance.now() - t0,
  });
  await sleep(pace);

  const envelope = {
    v: 1,
    alg: 'AES-256-GCM',
    iv: b64.encode(iv),
    ciphertext_blob: dk.ciphertext_blob,
    kms_key_id: dk.key_id,
    kms_key_version: dk.key_version,
    wrap_algorithm: dk.algorithm,
    encryption_context: ctx,
  };
  const form = new FormData();
  form.set('object_key', p.objectKey);
  form.set('envelope', JSON.stringify(envelope));
  form.set('content_type', p.contentType || 'application/octet-stream');
  form.set('plaintext_size', String(p.data.length));
  form.set('body', new Blob([ciphertext as BlobPart], { type: 'application/octet-stream' }), 'ciphertext.bin');
  const up = await vault.putObject(p.token, p.bucket, form);
  on({ kind: 'uploaded', object: up.data, ms: up.totalMs });
  await sleep(pace);
  on({ kind: 'done' });
  return up.data;
}

export async function fetchAndDecrypt(
  token: string,
  bucket: string,
  obj: StoredObject,
  on: Listener = () => {},
  pace = 0,
): Promise<Uint8Array> {
  const env = obj.envelope;
  const body = await vault.body(token, bucket, obj.id);
  on({ kind: 'fetch-ciphertext', bytes: body.data.length, preview: hex(body.data, 40), ms: body.totalMs });
  await sleep(pace);

  const res = await kms.decrypt(token, env.ciphertext_blob, env.encryption_context);
  const dek = b64.decode(res.data.plaintext);
  on({
    kind: 'dek-received',
    keyAlias: res.data.key_alias,
    version: res.data.key_version,
    algorithm: env.wrap_algorithm,
    blobPreview: hex(b64.decode(env.ciphertext_blob), 24),
    blobBytes: b64.decode(env.ciphertext_blob).length,
    dek,
    ms: res.totalMs,
  });
  await sleep(pace);

  const key = await importAndWipe(dek, 'decrypt');
  on({ kind: 'zeroized', dek });
  await sleep(pace);

  const t0 = performance.now();
  const plain = new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: b64.decode(env.iv) as BufferSource,
        additionalData: enc.encode(canonical(env.encryption_context)),
        tagLength: 128,
      },
      key,
      body.data as BufferSource,
    ),
  );
  on({ kind: 'decrypted', plainPreview: previewText(plain), bytes: plain.length, ms: performance.now() - t0 });
  await sleep(pace);
  on({ kind: 'done' });
  return plain;
}

/** After a key rotation: re-wrap the DEK under the new primary version. The payload is not touched. */
export async function rewrapObject(token: string, bucket: string, obj: StoredObject): Promise<StoredObject> {
  const env = obj.envelope;
  const re = await kms.reEncrypt(token, env.ciphertext_blob, env.encryption_context);
  return vault.rewrap(token, bucket, obj.id, re.data.ciphertext_blob, re.data.key_version);
}

export function isText(contentType: string, name: string): boolean {
  return contentType.startsWith('text/') || /\.(txt|csv|json|md|log|xml|ya?ml)$/i.test(name) || contentType.includes('json');
}

export function downloadBytes(data: Uint8Array, name: string, type: string) {
  const url = URL.createObjectURL(new Blob([data as BlobPart], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name.split('/').pop() || 'download';
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export { enc as utf8Encoder, dec as utf8Decoder };
