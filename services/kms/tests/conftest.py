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
    "KMS_DATABASE_URL": f"sqlite:///{_tmp}/kms-test.db",
    "ROOT_KEK": base64.b64encode(os.urandom(32)).decode(),
    "JWT_PRIVATE_KEY": base64.b64encode(_signing.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())).decode(),
    "DEMO_MODE": "true",
})
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
