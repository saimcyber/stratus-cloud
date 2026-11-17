// Thin REST clients for the two services. Note they are separate origins with separate trust:
// the KMS sees only data keys, the Vault sees only ciphertext.

export const KMS_URL: string = (import.meta.env.VITE_KMS_URL as string | undefined) ?? 'http://localhost:8001';
export const VAULT_URL: string = (import.meta.env.VITE_VAULT_URL as string | undefined) ?? 'http://localhost:8002';

export class ApiError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export interface Timed<T> {
  data: T;
  serverMs: number;
  totalMs: number;
}

interface Options {
  method?: string;
  token?: string | null;
  json?: unknown;
  form?: FormData;
  binary?: boolean;
}

async function call<T>(base: string, path: string, opts: Options = {}): Promise<Timed<T>> {
  const headers: Record<string, string> = {};
  if (opts.token) headers.Authorization = `Bearer ${opts.token}`;
  let body: BodyInit | undefined;
  if (opts.json !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(opts.json);
  } else if (opts.form) {
    body = opts.form;
  }
  const t0 = performance.now();
  let res: Response;
  try {
    res = await fetch(base + path, { method: opts.method ?? (body ? 'POST' : 'GET'), headers, body });
  } catch {
    const service = base === KMS_URL ? 'Stratus KMS' : 'Stratus Vault';
    throw new ApiError(0, 'NetworkError', `Can't reach ${service}. It may be waking up; try again in a few seconds.`);
  }
  const totalMs = performance.now() - t0;
  const serverMs = Number(res.headers.get('X-Server-Time-Ms') ?? 0);
  if (!res.ok) {
    let code = 'Error';
    let message = res.statusText;
    try {
      const err = await res.json();
      code = err.error ?? code;
      message = err.message ?? message;
    } catch {
      /* non-JSON error */
    }
    if (res.status === 401 && opts.token) window.dispatchEvent(new Event('stratus:unauthorized'));
    throw new ApiError(res.status, code, message);
  }
  if (res.status === 204) return { data: undefined as T, serverMs, totalMs };
  const data = (opts.binary ? new Uint8Array(await res.arrayBuffer()) : await res.json()) as T;
  return { data, serverMs, totalMs };
}

const get = async <T,>(base: string, path: string, opts?: Options) => (await call<T>(base, path, opts)).data;

// ----------------------------------------------------------------------------- types
export interface User {
  user_id: number;
  username: string;
  display_name: string;
  tenant_id: string;
  tenant_name: string;
  role: string;
}

export interface Persona {
  username: string;
  display_name: string;
  tenant_id: string;
  tenant_name: string;
  role: string;
}

export type KeyState = 'Enabled' | 'Disabled' | 'PendingDeletion' | 'Deleted';
export type WrapAlgorithm = 'AES_KW' | 'RSA_2048_OAEP';

export interface KeyVersion {
  version: number;
  created_at: string;
  status: 'Primary' | 'Decrypt only' | 'Destroyed';
  public_key_pem: string | null;
}

export interface Cmk {
  key_id: string;
  alias: string;
  description: string;
  algorithm: WrapAlgorithm;
  state: KeyState;
  primary_version: number;
  created_by: string;
  created_at: string;
  deletion_date: string | null;
  root_key_id: string;
  my_role: 'admin' | 'user' | null;
  versions: KeyVersion[];
  access: { username: string; display_name: string; role: 'admin' | 'user' }[];
  rotated_to_version?: number;
}

export interface DataKey {
  key_id: string;
  key_alias: string;
  key_version: number;
  algorithm: WrapAlgorithm;
  plaintext: string;
  ciphertext_blob: string;
}

export type EncryptionContext = Record<string, string>;

export interface Envelope {
  v: 1;
  alg: 'AES-256-GCM';
  iv: string;
  ciphertext_blob: string;
  kms_key_id: string;
  kms_key_version: number;
  wrap_algorithm: WrapAlgorithm;
  encryption_context: EncryptionContext;
}

export interface StoredObject {
  id: number;
  object_key: string;
  content_type: string;
  plaintext_size: number;
  stored_size: number;
  ciphertext_sha256: string;
  envelope: Envelope;
  uploaded_by: string;
  created_at: string;
  rewrapped_at: string | null;
}

export interface Bucket {
  name: string;
  default_key_id: string | null;
  created_at: string;
  created_by: string;
  object_count: number;
  total_bytes: number;
}

export interface AuditEvent {
  id: number;
  at: string;
  service: 'kms' | 'vault';
  actor: string;
  action: string;
  key_id?: string | null;
  resource?: string | null;
  outcome: string;
  detail: string;
}

export interface DumpRow {
  tenant: string;
  bucket: string;
  object_key: string;
  object_id: number;
  stored_size: number;
  ciphertext_hex_preview: string;
  entropy_bits_per_byte: number;
  iv: string;
  ciphertext_blob: string;
  encryption_context: EncryptionContext;
  kms_key_id: string;
}

// ----------------------------------------------------------------------------- KMS
export const kms = {
  health: () => get<{ root_key_id: string; demo_mode: boolean }>(KMS_URL, '/health'),
  personas: () => get<Persona[]>(KMS_URL, '/auth/personas'),
  demoLogin: (username: string) =>
    get<{ token: string; user: User }>(KMS_URL, '/auth/demo-login', { json: { username } }),
  login: (username: string, password: string) =>
    get<{ token: string; user: User }>(KMS_URL, '/auth/login', { json: { username, password } }),
  users: (token: string) =>
    get<{ username: string; display_name: string; role: string }[]>(KMS_URL, '/tenant/users', { token }),
  keys: (token: string) => get<Cmk[]>(KMS_URL, '/keys', { token }),
  key: (token: string, id: string) => get<Cmk>(KMS_URL, `/keys/${id}`, { token }),
  createKey: (token: string, alias: string, description: string, algorithm: WrapAlgorithm) =>
    get<Cmk>(KMS_URL, '/keys', { token, json: { alias, description, algorithm } }),
  rotate: (token: string, id: string) => get<Cmk>(KMS_URL, `/keys/${id}/rotate`, { token, method: 'POST' }),
  disable: (token: string, id: string) => get<Cmk>(KMS_URL, `/keys/${id}/disable`, { token, method: 'POST' }),
  enable: (token: string, id: string) => get<Cmk>(KMS_URL, `/keys/${id}/enable`, { token, method: 'POST' }),
  scheduleDeletion: (token: string, id: string, pendingMinutes: number) =>
    get<Cmk>(KMS_URL, `/keys/${id}/schedule-deletion`, { token, json: { pending_minutes: pendingMinutes } }),
  cancelDeletion: (token: string, id: string) =>
    get<Cmk>(KMS_URL, `/keys/${id}/cancel-deletion`, { token, method: 'POST' }),
  setAccess: (token: string, id: string, username: string, role: 'admin' | 'user' | null) =>
    get<Cmk>(KMS_URL, `/keys/${id}/access`, { token, method: 'PUT', json: { username, role } }),
  generateDataKey: (token: string, id: string, ctx: EncryptionContext) =>
    call<DataKey>(KMS_URL, `/keys/${id}/generate-data-key`, { token, json: { encryption_context: ctx } }),
  decrypt: (token: string, blob: string, ctx: EncryptionContext) =>
    call<{ key_id: string; key_alias: string; key_version: number; plaintext: string }>(KMS_URL, '/decrypt', {
      token,
      json: { ciphertext_blob: blob, encryption_context: ctx },
    }),
  reEncrypt: (token: string, blob: string, ctx: EncryptionContext) =>
    call<{ key_id: string; source_version: number; key_version: number; ciphertext_blob: string }>(
      KMS_URL,
      '/re-encrypt',
      { token, json: { ciphertext_blob: blob, encryption_context: ctx } },
    ),
  audit: (token: string) => get<AuditEvent[]>(KMS_URL, '/audit?limit=200', { token }),
};

// ----------------------------------------------------------------------------- Vault
export const vault = {
  health: () => get<{ status: string }>(VAULT_URL, '/health'),
  buckets: (token: string) => get<Bucket[]>(VAULT_URL, '/buckets', { token }),
  createBucket: (token: string, name: string) => get<{ name: string }>(VAULT_URL, '/buckets', { token, json: { name } }),
  deleteBucket: (token: string, name: string) => get<void>(VAULT_URL, `/buckets/${name}`, { token, method: 'DELETE' }),
  objects: (token: string, bucket: string) => get<StoredObject[]>(VAULT_URL, `/buckets/${bucket}/objects`, { token }),
  object: (token: string, bucket: string, id: number) =>
    get<StoredObject>(VAULT_URL, `/buckets/${bucket}/objects/${id}`, { token }),
  body: (token: string, bucket: string, id: number) =>
    call<Uint8Array>(VAULT_URL, `/buckets/${bucket}/objects/${id}/body`, { token, binary: true }),
  putObject: (token: string, bucket: string, form: FormData) =>
    call<StoredObject>(VAULT_URL, `/buckets/${bucket}/objects`, { token, form }),
  rewrap: (token: string, bucket: string, id: number, blob: string, version: number) =>
    get<StoredObject>(VAULT_URL, `/buckets/${bucket}/objects/${id}/envelope`, {
      token,
      method: 'PATCH',
      json: { ciphertext_blob: blob, kms_key_version: version },
    }),
  deleteObject: (token: string, bucket: string, id: number) =>
    get<void>(VAULT_URL, `/buckets/${bucket}/objects/${id}`, { token, method: 'DELETE' }),
  audit: (token: string) => get<AuditEvent[]>(VAULT_URL, '/audit?limit=200', { token }),
  dump: (token: string) => get<DumpRow[]>(VAULT_URL, '/lab/storage-dump', { token }),
};
