# Threat model

## Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| File contents | Browser memory (plaintext); Vault (ciphertext) | The thing being protected |
| Data keys (DEKs) | Browser for milliseconds; KMS during a request; Vault wrapped only | Decrypt exactly one object |
| CMK material | KMS database, sealed under the Root KEK | Unwraps every DEK of a tenant |
| Root KEK | KMS process memory, from an environment secret | Unseals every CMK |
| Token signing key | KMS only | Minting identities |

## Trust assumptions

| Party | Assumption |
|---|---|
| User's browser and device | **Trusted.** Endpoint compromise is out of scope. |
| Stratus KMS host | **Trusted** to hold keys and enforce policy. KMS-host compromise is out of scope; it is the role an HSM plays in a real KMS. |
| Stratus Vault | **Untrusted.** It may be honest-but-curious (reads everything) or malicious (modifies, swaps, replays). |
| Network | **Untrusted.** TLS is terminated by the hosting provider. |
| Other tenants | **Malicious.** Authenticated, but they will try to reach other tenants' data. |

## Adversaries and what stops them

| # | Adversary | Attack | Mitigation | Evidence |
|---|---|---|---|---|
| A1 | Honest-but-curious storage | Reads every stored object | Client-side AES-256-GCM. The Vault stores only ciphertext and wrapped DEKs and holds no KMS credential. | Lab 1, `test_storage_only_ever_sees_ciphertext` |
| A2 | Malicious storage | Flips bits in ciphertext | GCM 128-bit tag over ciphertext, IV and AAD | Lab 3, `test_tamper_and_swap_detected` |
| A3 | Malicious storage | Swaps ciphertext or wrapped keys between objects | Encryption context is GCM AAD **and** is HMAC-bound inside the wrapped key | Lab 4, `test_context_binding_rejects_swap` |
| A4 | Malicious tenant | Reads another tenant's bucket | Vault tenant check on every bucket access | Lab 2 |
| A5 | Malicious tenant with stolen blobs | Calls KMS Decrypt with another tenant's wrapped key | KMS checks key ownership, the per-key ACL and the context tenant; it logs and counts denials | Lab 2, `test_cross_tenant_denied` |
| A6 | Insider in own tenant | Uses a key they were not granted | Per-key access list (user / admin) | `test_member_cannot_manage`, revoke test |
| A7 | Brute force / flooding | Repeated guesses or calls | Token-bucket rate limit, lockout after repeated denials, login lockout after 5 failures | Lab 2 (429s), `test_password_login_and_lockout` |
| A8 | Holder of old backups | Reads data after it should be destroyed | Scheduled deletion destroys CMK material (crypto-shredding) | Lab 5, `test_revocation_disable_access_and_crypto_shred` |
| A9 | Vault forging identities | Mints a token to impersonate a user | Ed25519 signing key exists only in the KMS | Architecture |
| A10 | Network attacker | Reads or alters traffic | HTTPS on Render and Vercel; CORS restricted to the console origin | Deployment |

## STRIDE summary

| Threat | Main control |
|---|---|
| **S**poofing | Ed25519-signed short-lived tokens, scrypt passwords, login lockout |
| **T**ampering | AES-GCM tags; HMAC on wrapped keys; AES-KW integrity check on sealed CMKs |
| **R**epudiation | Audit logs on both services, including refused requests |
| **I**nformation disclosure | Client-side encryption, tenant scoping, no plaintext or keys in logs |
| **D**enial of service | Rate limits, upload size cap, bounded request bodies (`ciphertext_blob` ≤ 4 KB) |
| **E**levation of privilege | Per-key roles separate *use* from *manage*; tenants cannot grant cross-tenant access |

## Side channels and implementation hazards

* **Constant-time comparisons.** HMAC tags are checked with `HMAC.verify` and password hashes with `hmac.compare_digest`.
* **Randomness.** All keys and IVs come from `os.urandom` or `crypto.getRandomValues`. A fresh DEK per object means a random 96-bit IV is never reused under the same key.
* **Padding.** GCM is a stream mode, so no padding oracle is possible. RSA uses OAEP, never PKCS#1 v1.5.
* **Uniform errors.** Unwrap failures report a generic `InvalidCiphertextException` and do not say which check failed.

## Residual risks (stated honestly)

1. **Zeroization is best-effort.**
   * CPython `bytes` are immutable.
   * `cryptography` and OpenSSL copy key material internally.
   * JavaScript strings, such as the base64 DEK in the JSON response, cannot be wiped.

   We minimise lifetime by holding secrets in `bytearray` and wiping them with memset, and by importing keys into non-extractable `CryptoKey`s and filling the raw buffer with zeros. Real KMSs solve this with HSMs.
2. **The Root KEK is an environment secret, not an HSM.** Anyone with access to the KMS host or its env configuration could unseal CMKs.
3. **The KMS sees DEKs in plaintext during GenerateDataKey and Decrypt.** This is inherent to the envelope model, which is why the KMS is in the trusted base.
4. **Deleted key material lives on in database backups.** Neon point-in-time restore could resurrect a "deleted" CMK row within the provider's retention window. Production systems keep key material in an HSM whose deletion is final.
5. **Single-instance rate limiting.** Limits are held in memory, which is fine for one Render instance. A horizontally scaled deployment would need Redis or something similar.
6. **Demo mode.** One-click persona sign-in, the storage-dump endpoint and zero-minute deletion windows exist for teaching, and are disabled with `DEMO_MODE=false`.
