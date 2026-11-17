# Architecture

## Components and trust domains

```mermaid
flowchart LR
  subgraph B["Browser (trusted client)"]
    UI[Stratus Console]
    WC[Web Crypto<br/>AES-256-GCM]
  end
  subgraph K["Stratus KMS (trusted for keys, never sees data)"]
    API1[FastAPI]
    ROOT[(Root KEK<br/>env secret)]
    KDB[(kms DB<br/>sealed CMK versions,<br/>users, ACLs, audit)]
  end
  subgraph V["Stratus Vault (untrusted)"]
    API2[FastAPI]
    VDB[(vault DB<br/>ciphertext + wrapped DEKs)]
  end
  UI -- "GenerateDataKey / Decrypt / ReEncrypt<br/>(32-byte keys + context only)" --> API1
  UI -- "PUT/GET ciphertext + envelope" --> API2
  API1 --- ROOT
  API1 --- KDB
  API2 --- VDB
  API1 -. "Ed25519 public key (config, not a call)" .-> API2
```

* The Vault holds **no KMS credential** and makes **no call** to the KMS. Re-wrap jobs are orchestrated by the client.
* The KMS and the Vault use **separate databases with separate roles**, so compromising one service's credentials does not expose the other's data.
* Token signing keys live only in the KMS. The Vault receives the public half, so it can check sessions but cannot create them.

## Data flow: upload (plaintext → ciphertext)

```mermaid
sequenceDiagram
  autonumber
  participant U as Browser
  participant K as Stratus KMS
  participant V as Stratus Vault
  U->>K: POST /keys/{cmk}/generate-data-key {context: tenant, bucket, object}
  K->>K: authorize (tenant, ACL "use", key Enabled, context.tenant == caller)
  K->>K: unseal CMK primary version under Root KEK (AES-KW unwrap)
  K->>K: DEK = 32 random bytes, wrapped = AES-KW(kw_key, DEK) ‖ HMAC(ctx_key, header‖wrapped‖context)
  K-->>U: {plaintext DEK, ciphertext_blob}, then zeroize DEK + CMK material
  U->>U: importKey(DEK, non-extractable), DEK.fill(0)
  U->>U: c = AES-256-GCM(DEK, iv=random96, aad=canonical(context), file)
  U->>V: POST /buckets/{b}/objects {ciphertext c, envelope: iv, ciphertext_blob, key id/version, context}
  V->>V: check tenant owns bucket, context matches upload, size ≤ 10 MB
  V-->>U: stored (sha256 of ciphertext)
```

## Data flow: download (ciphertext → plaintext)

```mermaid
sequenceDiagram
  autonumber
  participant U as Browser
  participant V as Stratus Vault
  participant K as Stratus KMS
  U->>V: GET object metadata + /body
  V-->>U: ciphertext, iv, ciphertext_blob, context
  U->>K: POST /decrypt {ciphertext_blob, context}
  K->>K: parse blob → cmk id + version; authorize; verify HMAC over context (constant time)
  K->>K: unwrap DEK (AES-KW or RSA-OAEP)
  K-->>U: DEK
  U->>U: import non-extractable, wipe raw bytes, AES-GCM decrypt + verify tag with AAD
```

## Key rotation and re-wrap

```mermaid
sequenceDiagram
  participant A as Key admin (browser)
  participant K as Stratus KMS
  participant V as Stratus Vault
  A->>K: POST /keys/{id}/rotate
  K->>K: lock CMK row (SELECT … FOR UPDATE) + in-process lock
  K->>K: create version n+1 sealed under Root KEK, set primary = n+1
  Note over K: versions 1..n stay "decrypt only"
  loop each object still on an old version
    A->>V: GET envelope
    A->>K: POST /re-encrypt {blob, context}
    K->>K: unwrap with vN, wrap with vN+1 (DEK never leaves the KMS)
    K-->>A: new blob
    A->>V: PATCH envelope {blob, version}
  end
  Note over V: ciphertext bytes and their SHA-256 are unchanged
```

## Revocation

```mermaid
stateDiagram-v2
  [*] --> Enabled
  Enabled --> Disabled: disable
  Disabled --> Enabled: enable
  Enabled --> PendingDeletion: schedule deletion (7–30 days; demo allows 0–2 min)
  Disabled --> PendingDeletion: schedule deletion
  PendingDeletion --> Disabled: cancel
  PendingDeletion --> Deleted: window elapses → material nulled (crypto-shred)
  Deleted --> [*]
```

Finer-grained revocation is per user: removing someone from a key's access list makes their next request fail with `AccessDeniedException`.

## Concurrency model

* FastAPI runs synchronous handlers on a thread pool. Each request uses a single database connection, and audit writes reuse it.
* Rotation is serialised by a per-key lock and a database row lock, and `UNIQUE(cmk_id, version)` is the backstop. Two concurrent rotations can never mint the same version (tested in `test_concurrent_data_keys_and_rotation`).
* GenerateDataKey reads the primary version and its material in one transaction, so every issued blob names a version that exists.
* Rate limiting:
  * A token bucket allows 200 burst and 100/s per user.
  * 8 denied calls within 60 s lock the caller out for 30 s.
  * 5 failed sign-ins lock the account for 60 s.

## Ciphertext blob format

```
offset  size  field
0       4     magic "SKB1"
4       1     algorithm (1 = AES-KW, 2 = RSA-2048-OAEP)
5       16    CMK id (UUID bytes)
21      4     CMK version (big-endian)
25      2     wrapped DEK length L
27      L     wrapped DEK (40 bytes for AES-KW, 256 for RSA)
27+L    32    HMAC-SHA256(ctx_key, len‖header‖wrapped‖canonical_context)
```
