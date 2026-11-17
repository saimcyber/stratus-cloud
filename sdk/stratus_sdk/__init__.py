"""Stratus client SDK: the same envelope-encryption flow the browser runs, in Python.

Used by the load test, the benchmark script and the end-to-end tests.

    kms   = httpx.Client(base_url="http://localhost:8001")
    vault = httpx.Client(base_url="http://localhost:8002")
    c = StratusClient(kms, vault); c.demo_login("alice")
    meta = c.put_object("acme-patient-records", "hello.txt", b"hi", key_id)
    assert c.get_object("acme-patient-records", meta["id"]) == b"hi"
"""
from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass

import httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class StratusError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(f"{status} {code}: {message}")
        self.status, self.code, self.message = status, code, message


def canonical(ctx: dict[str, str]) -> bytes:
    return json.dumps(ctx, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _check(r: httpx.Response) -> httpx.Response:
    if r.status_code >= 400:
        try:
            body = r.json()
        except ValueError:
            body = {}
        raise StratusError(r.status_code, body.get("error", "Error"), body.get("message", r.text))
    return r


@dataclass
class StratusClient:
    kms: httpx.Client
    vault: httpx.Client
    token: str | None = None
    tenant: str | None = None

    @property
    def _h(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

    # identity -------------------------------------------------------------------------
    def demo_login(self, username: str) -> dict:
        body = _check(self.kms.post("/auth/demo-login", json={"username": username})).json()
        self.token, self.tenant = body["token"], body["user"]["tenant_id"]
        return body["user"]

    # KMS ------------------------------------------------------------------------------
    def keys(self) -> list[dict]:
        return _check(self.kms.get("/keys", headers=self._h)).json()

    def key_id(self, alias: str) -> str:
        return next(k["key_id"] for k in self.keys() if k["alias"] == alias)

    def generate_data_key(self, key_id: str, ctx: dict[str, str]) -> dict:
        return _check(self.kms.post(f"/keys/{key_id}/generate-data-key", headers=self._h,
                                    json={"encryption_context": ctx})).json()

    def decrypt_data_key(self, blob: str, ctx: dict[str, str]) -> dict:
        return _check(self.kms.post("/decrypt", headers=self._h,
                                    json={"ciphertext_blob": blob, "encryption_context": ctx})).json()

    def rotate(self, key_id: str) -> dict:
        return _check(self.kms.post(f"/keys/{key_id}/rotate", headers=self._h)).json()

    # Vault ----------------------------------------------------------------------------
    def put_object(self, bucket: str, object_key: str, data: bytes, key_id: str) -> dict:
        ctx = {"tenant": self.tenant, "bucket": bucket, "object": object_key}
        dk = self.generate_data_key(key_id, ctx)
        dek = bytearray(base64.b64decode(dk["plaintext"]))
        iv = os.urandom(12)
        try:
            ciphertext = AESGCM(bytes(dek)).encrypt(iv, data, canonical(ctx))
        finally:
            dek[:] = bytes(len(dek))  # zeroize our copy of the plaintext DEK
        envelope = {"v": 1, "alg": "AES-256-GCM", "iv": base64.b64encode(iv).decode(),
                    "ciphertext_blob": dk["ciphertext_blob"], "kms_key_id": dk["key_id"],
                    "kms_key_version": dk["key_version"], "wrap_algorithm": dk["algorithm"], "encryption_context": ctx}
        return _check(self.vault.post(
            f"/buckets/{bucket}/objects", headers=self._h,
            data={"object_key": object_key, "envelope": json.dumps(envelope), "plaintext_size": str(len(data))},
            files={"body": ("blob", ciphertext, "application/octet-stream")},
        )).json()

    def get_object(self, bucket: str, object_id: int) -> bytes:
        meta = _check(self.vault.get(f"/buckets/{bucket}/objects/{object_id}", headers=self._h)).json()
        body = _check(self.vault.get(f"/buckets/{bucket}/objects/{object_id}/body", headers=self._h)).content
        env = meta["envelope"]
        dk = self.decrypt_data_key(env["ciphertext_blob"], env["encryption_context"])
        dek = bytearray(base64.b64decode(dk["plaintext"]))
        try:
            return AESGCM(bytes(dek)).decrypt(base64.b64decode(env["iv"]), body, canonical(env["encryption_context"]))
        finally:
            dek[:] = bytes(len(dek))

    def rewrap(self, bucket: str, object_id: int) -> dict:
        meta = _check(self.vault.get(f"/buckets/{bucket}/objects/{object_id}", headers=self._h)).json()
        env = meta["envelope"]
        re = _check(self.kms.post("/re-encrypt", headers=self._h, json={
            "ciphertext_blob": env["ciphertext_blob"], "encryption_context": env["encryption_context"]})).json()
        return _check(self.vault.patch(f"/buckets/{bucket}/objects/{object_id}/envelope", headers=self._h, json={
            "ciphertext_blob": re["ciphertext_blob"], "kms_key_version": re["key_version"]})).json()
