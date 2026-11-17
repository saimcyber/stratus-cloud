"""Generate the secrets each service needs and write local .env files.

    python scripts/gen_secrets.py            # writes services/kms/.env and services/vault/.env (if absent)
    python scripts/gen_secrets.py --print    # just print values (paste them into Render)

Secret placement is the trust boundary in practice:
  * ROOT_KEK + JWT_PRIVATE_KEY  -> Stratus KMS only
  * JWT_PUBLIC_KEY              -> Stratus Vault (it can verify sessions but never mint them)
"""
from __future__ import annotations

import base64
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent


def generate() -> dict[str, str]:
    signing = Ed25519PrivateKey.generate()
    private_pem = signing.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption())
    public_pem = signing.public_key().public_bytes(serialization.Encoding.PEM,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo)
    return {
        "ROOT_KEK": base64.b64encode(os.urandom(32)).decode(),
        "JWT_PRIVATE_KEY": base64.b64encode(private_pem).decode(),
        "JWT_PUBLIC_KEY": base64.b64encode(public_pem).decode(),
    }


def main() -> None:
    values = generate()
    if "--print" in sys.argv:
        for k, v in values.items():
            print(f"{k}={v}")
        return

    kms_env = ROOT / "services" / "kms" / ".env"
    vault_env = ROOT / "services" / "vault" / ".env"
    if kms_env.exists() or vault_env.exists():
        print("A .env file already exists; refusing to overwrite (existing data would become undecryptable).")
        return
    kms_env.write_text(
        "KMS_DATABASE_URL=sqlite:///./kms.db\n"
        f"ROOT_KEK={values['ROOT_KEK']}\n"
        f"JWT_PRIVATE_KEY={values['JWT_PRIVATE_KEY']}\n"
        "ALLOWED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173\n"
        "DEMO_MODE=true\n"
    )
    vault_env.write_text(
        "VAULT_DATABASE_URL=sqlite:///./vault.db\n"
        f"JWT_PUBLIC_KEY={values['JWT_PUBLIC_KEY']}\n"
        "ALLOWED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173\n"
        "DEMO_MODE=true\n"
    )
    print(f"wrote {kms_env}\nwrote {vault_env}")


if __name__ == "__main__":
    main()
