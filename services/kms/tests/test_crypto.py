import base64
import os

import pytest
from cryptography.hazmat.primitives.keywrap import aes_key_wrap

from stratus_kms import crypto
from stratus_kms.zeroize import secret, zeroize


def test_rfc3394_vector_128_kek():
    # RFC 3394 §4.1 — wrap 128 bits of key data with a 128-bit KEK
    kek = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
    data = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    assert aes_key_wrap(kek, data).hex().upper() == "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"


def test_rfc3394_vector_256_kek_256_data():
    # RFC 3394 §4.6 — wrap 256 bits of key data with a 256-bit KEK (our exact configuration)
    kek = bytes.fromhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
    data = bytes.fromhex("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
    assert aes_key_wrap(kek, data).hex().upper() == (
        "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"
    )


def test_zeroize_overwrites_buffer():
    buf = bytearray(os.urandom(32))
    zeroize(buf)
    assert buf == bytearray(32)
    with secret(b"\x01" * 16) as held:
        ref = held
    assert ref == bytearray(16)
    with pytest.raises(TypeError):
        zeroize(b"immutable")  # type: ignore[arg-type]


@pytest.fixture(scope="module")
def root():
    return crypto.RootKeyring(base64.b64encode(os.urandom(32)).decode())


@pytest.mark.parametrize("alg", crypto.ALGORITHMS)
def test_wrap_unwrap_roundtrip(root, alg):
    v = crypto.create_cmk_version(root, alg)
    unsealed = crypto.unseal_version(root, alg, v.wrapped_material, v.wrapped_private_key, v.public_key_pem)
    dek = crypto.random_key()
    ctx = {"tenant": "t1", "bucket": "b", "object": "o.txt"}
    blob = crypto.wrap_dek(unsealed, "6f1c2b8e-3a4d-4e5f-8a9b-0c1d2e3f4a5b", 1, dek, ctx)
    parsed = crypto.parse_blob(blob)
    assert parsed.algorithm == alg and parsed.version == 1
    assert crypto.unwrap_dek(unsealed, parsed, ctx) == dek


def test_context_binding_rejects_swap(root):
    v = crypto.create_cmk_version(root, crypto.ALG_AES_KW)
    unsealed = crypto.unseal_version(root, crypto.ALG_AES_KW, v.wrapped_material, None, None)
    blob = crypto.wrap_dek(unsealed, "6f1c2b8e-3a4d-4e5f-8a9b-0c1d2e3f4a5b", 1, crypto.random_key(),
                           {"tenant": "t1", "object": "a.txt"})
    with pytest.raises(crypto.CryptoError):
        crypto.unwrap_dek(unsealed, crypto.parse_blob(blob), {"tenant": "t1", "object": "b.txt"})


def test_tampered_blob_rejected(root):
    v = crypto.create_cmk_version(root, crypto.ALG_AES_KW)
    unsealed = crypto.unseal_version(root, crypto.ALG_AES_KW, v.wrapped_material, None, None)
    ctx = {"tenant": "t1"}
    blob = bytearray(crypto.wrap_dek(unsealed, "6f1c2b8e-3a4d-4e5f-8a9b-0c1d2e3f4a5b", 1, crypto.random_key(), ctx))
    blob[40] ^= 0x01
    with pytest.raises(crypto.CryptoError):
        crypto.unwrap_dek(unsealed, crypto.parse_blob(bytes(blob)), ctx)


def test_wrong_root_cannot_unseal(root):
    v = crypto.create_cmk_version(root, crypto.ALG_AES_KW)
    other = crypto.RootKeyring(base64.b64encode(os.urandom(32)).decode())
    with pytest.raises(crypto.CryptoError):
        other.unwrap_material(v.wrapped_material)
