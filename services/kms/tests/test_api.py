import base64
import os
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi.testclient import TestClient

from stratus_kms import ratelimit
from stratus_kms.main import app

CTX = {"tenant": "acme-health", "bucket": "acme-patient-records", "object": "scan.txt"}


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def reset_limits():
    for tracker in (ratelimit.denied_calls, ratelimit.login_failures):
        tracker._fails.clear()
        tracker._locked_until.clear()


def login(client, username):
    r = client.post("/auth/demo-login", json={"username": username})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def key_by_alias(client, h, alias):
    return next(k for k in client.get("/keys", headers=h).json() if k["alias"] == alias)


def test_password_login_and_lockout(client):
    assert client.post("/auth/login", json={"username": "alice", "password": "stratus-demo"}).status_code == 200
    for _ in range(5):
        assert client.post("/auth/login", json={"username": "bob", "password": "nope"}).status_code == 401
    assert client.post("/auth/login", json={"username": "bob", "password": "stratus-demo"}).status_code == 429


def test_envelope_roundtrip_and_never_sees_payload(client):
    h = login(client, "bob")
    key = key_by_alias(client, h, "alias/patient-records")
    dk = client.post(f"/keys/{key['key_id']}/generate-data-key", headers=h, json={"encryption_context": CTX}).json()
    dek = base64.b64decode(dk["plaintext"])
    aad = b'{"bucket":"acme-patient-records","object":"scan.txt","tenant":"acme-health"}'
    nonce = os.urandom(12)
    ct = AESGCM(dek).encrypt(nonce, b"patient data", aad)  # happens client side — KMS never sees it

    back = client.post("/decrypt", headers=h, json={"ciphertext_blob": dk["ciphertext_blob"], "encryption_context": CTX})
    assert back.status_code == 200
    assert AESGCM(base64.b64decode(back.json()["plaintext"])).decrypt(nonce, ct, aad) == b"patient data"


@pytest.mark.parametrize("alias", ["alias/patient-records", "alias/billing-rsa"])
def test_both_wrapping_algorithms(client, alias):
    h = login(client, "alice")
    key = key_by_alias(client, h, alias)
    dk = client.post(f"/keys/{key['key_id']}/generate-data-key", headers=h, json={"encryption_context": CTX}).json()
    back = client.post("/decrypt", headers=h, json={"ciphertext_blob": dk["ciphertext_blob"], "encryption_context": CTX})
    assert back.json()["plaintext"] == dk["plaintext"]


def test_cross_tenant_denied(client):
    alice, mallory = login(client, "alice"), login(client, "mallory")
    key = key_by_alias(client, alice, "alias/patient-records")
    dk = client.post(f"/keys/{key['key_id']}/generate-data-key", headers=alice, json={"encryption_context": CTX}).json()
    r = client.post("/decrypt", headers=mallory, json={"ciphertext_blob": dk["ciphertext_blob"], "encryption_context": CTX})
    assert r.status_code == 403 and r.json()["error"] == "AccessDeniedException"
    r = client.post(f"/keys/{key['key_id']}/generate-data-key", headers=mallory,
                    json={"encryption_context": {**CTX, "tenant": "globex-finance"}})
    assert r.status_code == 403


def test_context_mismatch_rejected(client):
    h = login(client, "alice")
    key = key_by_alias(client, h, "alias/patient-records")
    dk = client.post(f"/keys/{key['key_id']}/generate-data-key", headers=h, json={"encryption_context": CTX}).json()
    r = client.post("/decrypt", headers=h,
                    json={"ciphertext_blob": dk["ciphertext_blob"], "encryption_context": {**CTX, "object": "other.txt"}})
    assert r.status_code == 400 and r.json()["error"] == "InvalidCiphertextException"


def test_rotation_keeps_old_data_and_reencrypt(client):
    h = login(client, "alice")
    key = client.post("/keys", headers=h, json={"alias": "rotation-test", "algorithm": "AES_KW"}).json()
    old = client.post(f"/keys/{key['key_id']}/generate-data-key", headers=h, json={"encryption_context": CTX}).json()
    rotated = client.post(f"/keys/{key['key_id']}/rotate", headers=h).json()
    assert rotated["primary_version"] == 2
    assert [v["status"] for v in rotated["versions"]] == ["Decrypt only", "Primary"]

    # old wrapped key still decrypts under version 1
    r = client.post("/decrypt", headers=h, json={"ciphertext_blob": old["ciphertext_blob"], "encryption_context": CTX})
    assert r.json()["key_version"] == 1 and r.json()["plaintext"] == old["plaintext"]
    # re-encrypt moves it to version 2 without changing the DEK
    re = client.post("/re-encrypt", headers=h, json={"ciphertext_blob": old["ciphertext_blob"], "encryption_context": CTX}).json()
    assert re["source_version"] == 1 and re["key_version"] == 2
    r = client.post("/decrypt", headers=h, json={"ciphertext_blob": re["ciphertext_blob"], "encryption_context": CTX})
    assert r.json()["plaintext"] == old["plaintext"]


def test_revocation_disable_access_and_crypto_shred(client):
    alice, bob = login(client, "alice"), login(client, "bob")
    key = client.post("/keys", headers=alice, json={"alias": "shred-test"}).json()
    kid = key["key_id"]
    client.put(f"/keys/{kid}/access", headers=alice, json={"username": "bob", "role": "user"})
    dk = client.post(f"/keys/{kid}/generate-data-key", headers=bob, json={"encryption_context": CTX}).json()
    body = {"ciphertext_blob": dk["ciphertext_blob"], "encryption_context": CTX}

    client.put(f"/keys/{kid}/access", headers=alice, json={"username": "bob", "role": None})
    assert client.post("/decrypt", headers=bob, json=body).status_code == 403  # access revoked

    client.post(f"/keys/{kid}/disable", headers=alice)
    assert client.post("/decrypt", headers=alice, json=body).json()["error"] == "DisabledException"
    client.post(f"/keys/{kid}/enable", headers=alice)
    assert client.post("/decrypt", headers=alice, json=body).status_code == 200

    shredded = client.post(f"/keys/{kid}/schedule-deletion", headers=alice, json={"pending_minutes": 0}).json()
    assert shredded["state"] == "Deleted"
    assert all(v["status"] == "Destroyed" for v in shredded["versions"])
    assert client.post("/decrypt", headers=alice, json=body).status_code == 409


def test_member_cannot_manage(client):
    alice, bob = login(client, "alice"), login(client, "bob")
    key = key_by_alias(client, alice, "alias/patient-records")
    assert client.post(f"/keys/{key['key_id']}/rotate", headers=bob).status_code == 403


def test_concurrent_data_keys_and_rotation(client):
    alice = login(client, "alice")
    key = client.post("/keys", headers=alice, json={"alias": "concurrency-test"}).json()
    kid = key["key_id"]

    def gen(_):
        r = client.post(f"/keys/{kid}/generate-data-key", headers=alice, json={"encryption_context": CTX})
        assert r.status_code == 200, r.text
        d = client.post("/decrypt", headers=alice, json={"ciphertext_blob": r.json()["ciphertext_blob"],
                                                         "encryption_context": CTX})
        assert d.json()["plaintext"] == r.json()["plaintext"]
        return r.json()["key_version"]

    def rot(_):
        return client.post(f"/keys/{kid}/rotate", headers=alice).json()["rotated_to_version"]

    with ThreadPoolExecutor(max_workers=16) as pool:
        gens = [pool.submit(gen, i) for i in range(40)]
        rots = [pool.submit(rot, i) for i in range(4)]
        versions = {f.result() for f in gens}
        primaries = sorted(f.result() for f in rots)
    assert primaries == [2, 3, 4, 5]  # no duplicate version numbers under concurrent rotation
    assert versions <= {1, 2, 3, 4, 5}


def test_audit_is_tenant_scoped(client):
    mallory = login(client, "mallory")
    events = client.get("/audit", headers=mallory).json()
    assert events and all(e["actor"] in ("mallory",) for e in events)
