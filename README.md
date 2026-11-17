# Stratus Cloud: Envelope Encryption for Cloud Storage

A working model of how cloud key-management services protect multi-tenant object storage.
Files are encrypted **in the browser** with a fresh AES-256-GCM data key. That key is wrapped
by a tenant's customer managed key (CMK), which is in turn sealed by a Root KEK that lives only
in the KMS. The storage service only ever sees ciphertext and wrapped keys.

**CS-3002 Information Security term project, FAST NUCES Islamabad.**
Team: Saim Zaib (24I-2023), Abdullah Sajid (24I-2101), Nihammad Amish (24I-2099)

| | |
|---|---|
| Live app | _add Vercel URL after deploy_ |
| KMS API docs | _KMS URL_/docs |
| Vault API docs | _Vault URL_/docs |
| Report | [`docs/Stratus-Technical-Report.pdf`](docs/Stratus-Technical-Report.pdf) |
| Slides | [`docs/Stratus-Presentation.pptx`](docs/Stratus-Presentation.pptx) |

---

## Architecture

```
 Browser (trusted client)            Stratus KMS  (service 1)            Stratus Vault  (service 2, untrusted)
 ─────────────────────────           ─────────────────────────           ─────────────────────────────────────
 Web Crypto AES-256-GCM              Root KEK (env secret)               buckets + objects
 asks KMS for a data key ──────────▶ CMK versions (AES-KW sealed)        stores ciphertext + wrapped DEK only
 imports DEK non-extractable ◀────── DEK + wrapped DEK                   verifies sessions with a PUBLIC key
 wipes raw DEK bytes                 per-key ACLs, tenant isolation      no KMS credentials, no code path to KMS
 encrypts file locally               audit log, rate limits
 uploads ciphertext + wrapped DEK ─────────────────────────────────────▶
                                     DB: kms (Neon role A)               DB: vault (Neon role B)
```

Key hierarchy:

```
Root KEK  (256-bit, KMS process only)
  └─ CMK version material (256-bit, AES Key Wrap RFC 3394 under Root KEK)
       ├─ kw key  = HKDF(material, "stratus/kw/v1")   → wraps DEKs (AES-KW)        ┐ CMK algorithm
       ├─ RSA-2048 key pair (private half AES-KWP sealed) → wraps DEKs (OAEP-SHA256)┘ is one or the other
       └─ ctx key = HKDF(material, "stratus/ctx/v1")  → HMAC-SHA256 binds wrapped DEK to its encryption context
            └─ DEK (256-bit, one per object) → AES-256-GCM, AAD = {tenant, bucket, object}
```

More detail is in [`docs/architecture.md`](docs/architecture.md), which has sequence diagrams for upload, download, rotation and revocation, and in [`docs/threat-model.md`](docs/threat-model.md).

## Requirement traceability

| Requirement | Where it lives | Demo moment |
|---|---|---|
| Root KEK → CMK → DEK hierarchy | `services/kms/stratus_kms/crypto.py`, `keys.py` | Key page → *Key hierarchy* tab; Envelope Inspector |
| Rotation | CMK versions, `POST /keys/{id}/rotate`, `POST /re-encrypt` | Rotate, old objects still open, *Re-wrap all* keeps ciphertext hash identical |
| Revocation | access removal, disable, scheduled deletion (crypto-shred) | Access tab → Revoke; Lab #5 |
| Secure zeroization | `zeroize.py` (bytearray + memset); browser `Uint8Array.fill(0)` after non-extractable import | Inspector zeroize step |
| Strict trust boundaries | two services, two databases, two secret sets; browser-side encryption | Lab #1 storage dump; *Raw view* |
| Concurrency and multi-tenancy | tenant scoping, per-key ACLs, row lock + version uniqueness on rotation, token-bucket rate limit, lockout | `scripts/loadtest.py`; Lab #2 |
| Threat model, DFDs | `docs/threat-model.md`, `docs/architecture.md` | Report and slides |
| Guided walkthrough and tooltips | Cloudscape TutorialPanel + hotspots, Info panels, glossary popovers | *Walkthrough* button in top bar |
| Simulated attacks and mitigations | Security lab (5 live attacks) | `/console/lab` |
| Security vs usability | Trade-offs page (live benchmarks) | `/console/tradeoffs` |
| REST APIs | FastAPI, OpenAPI at `/docs` on both services | |

## Cryptography (all from peer-reviewed libraries)

| Purpose | Primitive | Library |
|---|---|---|
| File encryption | AES-256-GCM, 96-bit random IV, 128-bit tag, AAD = canonical encryption context | Web Crypto API |
| DEK wrapping (default) | AES Key Wrap, RFC 3394 | `cryptography` (OpenSSL) |
| DEK wrapping (optional) | RSA-2048-OAEP, SHA-256 / MGF1-SHA-256 | `cryptography` |
| CMK sealing | AES-KW (material), AES-KWP RFC 5649 (RSA private keys) under the Root KEK | `cryptography` |
| Context binding | HMAC-SHA256 with an HKDF-derived key, constant-time verify | `cryptography` |
| Sessions | Ed25519-signed JWT (KMS signs, Vault verifies with the public key only) | PyJWT |
| Passwords | scrypt (N=2^14, r=8, p=1), constant-time compare | Python `hashlib` |

## Run it locally

Requirements: Python 3.11+, Node 20+.

```bash
python -m venv .venv && .venv/Scripts/activate          # macOS/Linux: source .venv/bin/activate
pip install -r requirements-dev.txt
python scripts/gen_secrets.py                           # writes services/*/.env with fresh keys
python scripts/run_services.py                          # KMS :8001, Vault :8002

cd web && npm install && npm run dev                    # console on http://localhost:5173
python scripts/seed_objects.py                          # optional: sample encrypted files
```

Demo identities (password `stratus-demo`, or one click on the sign-in page):

| User | Tenant | Role |
|---|---|---|
| alice | Acme Health | Tenant admin, admin of both Acme keys |
| bob | Acme Health | Member, *user* on both Acme keys |
| mallory | Globex Finance | Admin of a different tenant: the attacker |

## Tests and load test

```bash
python -m pytest services/kms/tests tests              # 24 tests: RFC 3394 vectors, lifecycle, ACLs, tamper, e2e
python scripts/loadtest.py -n 100                       # concurrent data keys + mid-flight rotation + attacks
```

Sample load-test output (local, SQLite):

```
legitimate round-trips  100/100 ok   in 5.14s (19.5/s)
rotations               versions [2, 3, 4]   key versions used [1, 2, 3, 4]
cross-tenant attempts   25 blocked, 0 succeeded
PASS
```

## Deploy

See [`docs/DEPLOY.md`](docs/DEPLOY.md). In short: Neon Postgres (two databases, two roles) → Render (`render.yaml`, two web services) → Vercel (`web/`).

## REST API summary

**Stratus KMS**

| Method | Path | Purpose |
|---|---|---|
| POST | `/auth/login`, `/auth/demo-login` | Session token (Ed25519 JWT) |
| GET | `/keys` · POST `/keys` | List / create CMKs (tenant-scoped) |
| GET | `/keys/{id}` | Describe key, versions, access list |
| POST | `/keys/{id}/rotate` | New primary version |
| POST | `/keys/{id}/disable`, `/enable` | Reversible revocation |
| POST | `/keys/{id}/schedule-deletion`, `/cancel-deletion` | Crypto-shredding with a waiting period |
| PUT | `/keys/{id}/access` | Grant / revoke a user |
| POST | `/keys/{id}/generate-data-key` | Fresh DEK + wrapped DEK |
| POST | `/decrypt` | Unwrap a DEK (ACL + context checked) |
| POST | `/re-encrypt` | Re-wrap under the primary version without exposing the DEK |
| GET | `/audit` | Tenant audit log |

**Stratus Vault**

| Method | Path | Purpose |
|---|---|---|
| GET/POST | `/buckets` | List / create buckets |
| GET/POST | `/buckets/{b}/objects` | List / upload (ciphertext + envelope metadata) |
| GET | `/buckets/{b}/objects/{id}`, `/body` | Envelope metadata / raw ciphertext |
| PATCH | `/buckets/{b}/objects/{id}/envelope` | Swap in a re-wrapped DEK |
| GET | `/audit` | Tenant access log |
| GET | `/lab/storage-dump` | Demo only: what a compromised storage admin sees |

## Repository layout

```
services/kms/      Stratus KMS (FastAPI): crypto core, key lifecycle, IAM, audit
services/vault/    Stratus Vault (FastAPI): untrusted ciphertext store
web/               Console + landing page (React, Cloudscape, Framer Motion)
sdk/               Python client implementing the same envelope flow
scripts/           secrets, local runner, seed, load test, warm-up
tests/             end-to-end tests across both services
docs/              architecture, threat model, deployment, report, slides
```

*Stratus is a teaching model. It is not affiliated with any cloud provider.*
