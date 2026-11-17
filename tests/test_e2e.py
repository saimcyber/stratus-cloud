import base64

import pytest
from cryptography.exceptions import InvalidTag
from fastapi.testclient import TestClient

from stratus_kms.main import app as kms_app
from stratus_sdk import StratusClient, StratusError
from stratus_vault.main import app as vault_app

BUCKET = "acme-patient-records"
SECRET = b"Patient #4471 - diagnosis: confidential"


@pytest.fixture(scope="module")
def apps():
    with TestClient(kms_app) as kms, TestClient(vault_app) as vault:
        yield kms, vault


def client(apps, user):
    c = StratusClient(*apps)
    c.demo_login(user)
    return c


def test_storage_only_ever_sees_ciphertext(apps):
    bob = client(apps, "bob")
    meta = bob.put_object(BUCKET, "scan.txt", SECRET, bob.key_id("alias/patient-records"))
    assert meta["stored_size"] == len(SECRET) + 16  # GCM tag
    raw = apps[1].get(f"/buckets/{BUCKET}/objects/{meta['id']}/body", headers=bob._h).content
    assert SECRET not in raw and b"Patient" not in raw
    assert bob.get_object(BUCKET, meta["id"]) == SECRET


def test_rsa_wrapped_objects(apps):
    alice = client(apps, "alice")
    meta = alice.put_object("acme-billing-exports", "invoice.csv", b"a,b,c", alice.key_id("alias/billing-rsa"))
    assert meta["envelope"]["wrap_algorithm"] == "RSA_2048_OAEP"
    assert alice.get_object("acme-billing-exports", meta["id"]) == b"a,b,c"


def test_cross_tenant_blocked_at_both_services(apps):
    bob, mallory = client(apps, "bob"), client(apps, "mallory")
    meta = bob.put_object(BUCKET, "x.txt", SECRET, bob.key_id("alias/patient-records"))
    with pytest.raises(StratusError) as e:
        mallory.get_object(BUCKET, meta["id"])
    assert e.value.status == 403
    # even with the wrapped key stolen from a storage dump, the KMS refuses
    dump = apps[1].get("/lab/storage-dump", headers=mallory._h).json()
    stolen = next(d for d in dump if d["object_id"] == meta["id"])
    with pytest.raises(StratusError) as e:
        mallory.decrypt_data_key(stolen["ciphertext_blob"], stolen["encryption_context"])
    assert e.value.code == "AccessDeniedException"


def test_tamper_and_swap_detected(apps):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from stratus_sdk import canonical

    bob = client(apps, "bob")
    kid = bob.key_id("alias/patient-records")
    a = bob.put_object(BUCKET, "a.txt", b"AAAA", kid)
    b = bob.put_object(BUCKET, "b.txt", b"BBBB", kid)
    body = bytearray(apps[1].get(f"/buckets/{BUCKET}/objects/{a['id']}/body", headers=bob._h).content)
    body[0] ^= 1
    dek = base64.b64decode(bob.decrypt_data_key(a["envelope"]["ciphertext_blob"], a["envelope"]["encryption_context"])["plaintext"])
    with pytest.raises(InvalidTag):
        AESGCM(dek).decrypt(base64.b64decode(a["envelope"]["iv"]), bytes(body), canonical(a["envelope"]["encryption_context"]))
    # swap: a's wrapped key presented with b's context
    with pytest.raises(StratusError) as e:
        bob.decrypt_data_key(a["envelope"]["ciphertext_blob"], b["envelope"]["encryption_context"])
    assert e.value.code == "InvalidCiphertextException"


def test_rotate_and_rewrap_keeps_payload(apps):
    alice = client(apps, "alice")
    kid = alice.key_id("alias/patient-records")
    meta = alice.put_object(BUCKET, "rotate-me.txt", SECRET, kid)
    old_hash = meta["ciphertext_sha256"]
    new_version = alice.rotate(kid)["rotated_to_version"]
    assert alice.get_object(BUCKET, meta["id"]) == SECRET  # old version still decrypts
    after = alice.rewrap(BUCKET, meta["id"])
    assert after["envelope"]["kms_key_version"] == new_version
    assert after["ciphertext_sha256"] == old_hash  # payload untouched
    assert alice.get_object(BUCKET, meta["id"]) == SECRET
