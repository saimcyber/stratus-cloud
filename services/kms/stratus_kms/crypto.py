"""Cryptographic core of Stratus KMS.

Key hierarchy
-------------
    Root KEK (256-bit, env secret, never leaves this module)
      └── CMK version material (256-bit, stored AES-KW wrapped under the Root KEK)
            ├── kw key   = HKDF(material, "stratus/kw/v1")    -> wraps DEKs (AES-KW, RFC 3394)
            ├── ctx key  = HKDF(material, "stratus/ctx/v1")   -> HMAC binding of encryption context
            └── RSA-2048 private key (RSA CMKs only, stored AES-KWP wrapped under the Root KEK)
                  └── DEK (256-bit, per object) wrapped with RSA-OAEP-SHA256

Every primitive comes from the peer-reviewed `cryptography` package (OpenSSL).
Nothing here implements a cipher by hand.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import uuid
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import (
    InvalidUnwrap,
    aes_key_unwrap,
    aes_key_unwrap_with_padding,
    aes_key_wrap,
    aes_key_wrap_with_padding,
)

from .zeroize import secret, zeroize

ALG_AES_KW = "AES_KW"
ALG_RSA_OAEP = "RSA_2048_OAEP"
ALGORITHMS = (ALG_AES_KW, ALG_RSA_OAEP)
_ALG_CODE = {ALG_AES_KW: 1, ALG_RSA_OAEP: 2}
_CODE_ALG = {v: k for k, v in _ALG_CODE.items()}

DEK_BYTES = 32
BLOB_MAGIC = b"SKB1"
_BLOB_HEADER = struct.Struct(">4sB16sIH")  # magic, alg, cmk uuid, version, wrapped length
_HMAC_LEN = 32

_OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


class CryptoError(Exception):
    """Raised for any integrity / unwrap failure. Message is deliberately generic."""


def random_key() -> bytearray:
    return bytearray(os.urandom(DEK_BYTES))


def _derive(material: bytes | bytearray, info: bytes) -> bytearray:
    return bytearray(HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(bytes(material)))


def canonical_context(ctx: dict[str, str]) -> bytes:
    """Deterministic serialisation of the encryption context (also used as GCM AAD by clients)."""
    if not isinstance(ctx, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in ctx.items()):
        raise CryptoError("encryption context must be a flat string->string map")
    return json.dumps(ctx, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# --------------------------------------------------------------------------------------------
# Root KEK — the top of the hierarchy. Only wrap/unwrap operations are exposed.
# --------------------------------------------------------------------------------------------
class RootKeyring:
    def __init__(self, root_b64: str) -> None:
        self._kek = bytearray(base64.b64decode(root_b64))
        if len(self._kek) != 32:
            raise ValueError("Root KEK must be 32 bytes")
        # Public, non-secret identifier so operators can tell which root sealed a CMK.
        self.key_id = "rk-" + hashlib.sha256(b"stratus/root-id" + bytes(self._kek)).hexdigest()[:12]

    def wrap_material(self, material: bytes | bytearray) -> bytes:
        return aes_key_wrap(bytes(self._kek), bytes(material))

    def unwrap_material(self, wrapped: bytes) -> bytearray:
        try:
            return bytearray(aes_key_unwrap(bytes(self._kek), wrapped))
        except InvalidUnwrap as exc:  # wrong root or tampered row
            raise CryptoError("CMK material failed integrity check") from exc

    def wrap_private_key(self, der: bytes | bytearray) -> bytes:
        return aes_key_wrap_with_padding(bytes(self._kek), bytes(der))

    def unwrap_private_key(self, wrapped: bytes) -> bytearray:
        try:
            return bytearray(aes_key_unwrap_with_padding(bytes(self._kek), wrapped))
        except InvalidUnwrap as exc:
            raise CryptoError("CMK private key failed integrity check") from exc

    def close(self) -> None:
        zeroize(self._kek)


# --------------------------------------------------------------------------------------------
# CMK version creation
# --------------------------------------------------------------------------------------------
@dataclass
class NewVersion:
    wrapped_material: bytes
    wrapped_private_key: bytes | None
    public_key_pem: str | None


def create_cmk_version(root: RootKeyring, algorithm: str) -> NewVersion:
    if algorithm not in ALGORITHMS:
        raise ValueError(f"unsupported algorithm {algorithm}")
    with secret(random_key()) as material:
        wrapped_material = root.wrap_material(material)
    if algorithm == ALG_AES_KW:
        return NewVersion(wrapped_material, None, None)

    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with secret(
        private.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    ) as der:
        wrapped_private = root.wrap_private_key(der)
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return NewVersion(wrapped_material, wrapped_private, public_pem)


# --------------------------------------------------------------------------------------------
# Ciphertext blob = what the client stores next to its data (the "wrapped DEK")
# --------------------------------------------------------------------------------------------
@dataclass
class ParsedBlob:
    algorithm: str
    cmk_id: str
    version: int
    wrapped_dek: bytes
    signed_part: bytes
    tag: bytes


def parse_blob(blob: bytes) -> ParsedBlob:
    if len(blob) < _BLOB_HEADER.size + _HMAC_LEN:
        raise CryptoError("ciphertext blob is malformed")
    magic, code, raw_id, version, wlen = _BLOB_HEADER.unpack_from(blob)
    if magic != BLOB_MAGIC or code not in _CODE_ALG:
        raise CryptoError("ciphertext blob is malformed")
    end = _BLOB_HEADER.size + wlen
    if len(blob) != end + _HMAC_LEN:
        raise CryptoError("ciphertext blob is malformed")
    return ParsedBlob(
        algorithm=_CODE_ALG[code],
        cmk_id=str(uuid.UUID(bytes=raw_id)),
        version=version,
        wrapped_dek=blob[_BLOB_HEADER.size:end],
        signed_part=blob[:end],
        tag=blob[end:],
    )


def _context_mac(material: bytearray, signed_part: bytes, context: bytes) -> hmac.HMAC:
    with secret(_derive(material, b"stratus/ctx/v1")) as ctx_key:
        mac = hmac.HMAC(bytes(ctx_key), hashes.SHA256())
    mac.update(struct.pack(">I", len(signed_part)) + signed_part + context)
    return mac


@dataclass
class UnsealedVersion:
    """Decrypted CMK version material held only for the duration of one request."""

    algorithm: str
    material: bytearray
    private_der: bytearray | None
    public_pem: str | None

    def wipe(self) -> None:
        zeroize(self.material)
        if self.private_der is not None:
            zeroize(self.private_der)


def unseal_version(root: RootKeyring, algorithm: str, wrapped_material: bytes, wrapped_private: bytes | None,
                   public_pem: str | None) -> UnsealedVersion:
    material = root.unwrap_material(wrapped_material)
    private_der = root.unwrap_private_key(wrapped_private) if wrapped_private else None
    return UnsealedVersion(algorithm, material, private_der, public_pem)


def wrap_dek(version: UnsealedVersion, cmk_id: str, version_no: int, dek: bytearray, context: dict[str, str]) -> bytes:
    ctx = canonical_context(context)
    if version.algorithm == ALG_AES_KW:
        with secret(_derive(version.material, b"stratus/kw/v1")) as kw_key:
            wrapped = aes_key_wrap(bytes(kw_key), bytes(dek))
    else:
        public = serialization.load_pem_public_key(version.public_pem.encode())
        wrapped = public.encrypt(bytes(dek), _OAEP)
    header = _BLOB_HEADER.pack(BLOB_MAGIC, _ALG_CODE[version.algorithm], uuid.UUID(cmk_id).bytes, version_no, len(wrapped))
    signed = header + wrapped
    return signed + _context_mac(version.material, signed, ctx).finalize()


def unwrap_dek(version: UnsealedVersion, parsed: ParsedBlob, context: dict[str, str]) -> bytearray:
    ctx = canonical_context(context)
    try:
        _context_mac(version.material, parsed.signed_part, ctx).verify(parsed.tag)  # constant-time compare
    except InvalidSignature as exc:
        raise CryptoError("ciphertext blob does not match this encryption context") from exc

    if parsed.algorithm == ALG_AES_KW:
        with secret(_derive(version.material, b"stratus/kw/v1")) as kw_key:
            try:
                return bytearray(aes_key_unwrap(bytes(kw_key), parsed.wrapped_dek))
            except InvalidUnwrap as exc:
                raise CryptoError("wrapped data key failed integrity check") from exc

    private = serialization.load_der_private_key(bytes(version.private_der), password=None)
    try:
        return bytearray(private.decrypt(parsed.wrapped_dek, _OAEP))
    except ValueError as exc:
        raise CryptoError("wrapped data key failed integrity check") from exc
