"""End-to-end tests: real KMS + real Vault apps in-process, client-side AES-GCM in between."""
import base64
import os
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_signing = Ed25519PrivateKey.generate()
_tmp = tempfile.mkdtemp()
os.environ.update({
    "KMS_DATABASE_URL": f"sqlite:///{_tmp}/kms.db",
    "VAULT_DATABASE_URL": f"sqlite:///{_tmp}/vault.db",
    "ROOT_KEK": base64.b64encode(os.urandom(32)).decode(),
    "JWT_PRIVATE_KEY": base64.b64encode(_signing.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())).decode(),
    "JWT_PUBLIC_KEY": base64.b64encode(_signing.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)).decode(),
    "DEMO_MODE": "true",
})
ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "services" / "kms"), str(ROOT / "services" / "vault"), str(ROOT / "sdk")]
