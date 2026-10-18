"""Ed25519 verification: RFC 8032 vectors, an independent OpenSSL oracle, and malleability cases.

The verifier handles PUBLIC data only. The engine has no runtime dependencies, so this is a
stdlib implementation; it is only trusted because it is checked here against RFC 8032 and against
OpenSSL signatures made with throwaway keys.
"""

from __future__ import annotations

import os

import pytest

from hermes_code_assurance import ed25519
from tests.auth_helpers import (
    FixtureKey,
    openssl_public_from_raw_secret,
    openssl_sign_with_raw_secret,
    require_openssl,
)

L = 2**252 + 27742317777372353535851937790883648493
P = 2**255 - 19

# RFC 8032 section 7.1 (TEST 1 and TEST 2).
RFC_VECTORS = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        (
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e3"
            "9701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ),
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        (
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3"
            "613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        ),
    ),
]


@pytest.mark.parametrize("secret,public,message,signature", RFC_VECTORS)
def test_rfc8032_vectors_verify(secret, public, message, signature):
    assert ed25519.verify(bytes.fromhex(public), bytes.fromhex(message), bytes.fromhex(signature))


@pytest.mark.parametrize("secret,public,message,signature", RFC_VECTORS)
def test_recalled_rfc_vectors_match_openssl(tmp_path, secret, public, message, signature):
    """Guards against a mis-recalled vector: an independent implementation must reproduce it.

    The OpenSSL CLI refuses to sign a zero-length message with -rawin, so for the empty-message
    vector the independent cross-check is the secret->public derivation; its signature is
    covered by test_rfc8032_vectors_verify (a mis-recalled signature could never verify)."""
    assert openssl_public_from_raw_secret(bytes.fromhex(secret), tmp_path).hex() == public
    if message:
        produced = openssl_sign_with_raw_secret(
            bytes.fromhex(secret), bytes.fromhex(message), tmp_path
        )
        assert produced.hex() == signature


def test_openssl_signatures_verify_across_message_shapes(tmp_path):
    # (The empty message is covered by RFC vector 1: the OpenSSL CLI cannot sign it with -rawin.)
    key = FixtureKey(tmp_path)
    for message in (b"a", b"\x00" * 64, os.urandom(1000), "ünï-ćødé".encode(), b"x" * 65536):
        assert ed25519.verify(key.public, message, key.sign(message))


def test_wrong_key_wrong_message_and_bitflips_are_rejected(tmp_path):
    key = FixtureKey(tmp_path, "k1")
    other = FixtureKey(tmp_path, "k2")
    message = b"approve exactly this"
    signature = key.sign(message)
    assert ed25519.verify(key.public, message, signature)
    assert not ed25519.verify(other.public, message, signature)
    assert not ed25519.verify(key.public, message + b"!", signature)
    for index in (0, 31, 32, 63):
        flipped = bytearray(signature)
        flipped[index] ^= 0x01
        assert not ed25519.verify(key.public, message, bytes(flipped))
    flipped_key = bytearray(key.public)
    flipped_key[5] ^= 0x01
    assert not ed25519.verify(bytes(flipped_key), message, signature)


@pytest.mark.parametrize("size", [0, 1, 31, 33, 63, 65, 128])
def test_wrong_lengths_are_rejected(tmp_path, size):
    key = FixtureKey(tmp_path)
    message = b"m"
    signature = key.sign(message)
    assert not ed25519.verify(key.public, message, (signature + b"\x00" * 128)[:size])
    assert not ed25519.verify((key.public + b"\x00" * 128)[:size], message, signature)


def test_malleable_signature_with_s_plus_l_is_rejected(tmp_path):
    key = FixtureKey(tmp_path)
    message = b"malleability"
    signature = key.sign(message)
    s = int.from_bytes(signature[32:], "little")
    assert s + L < 2**256  # the malleated encoding still fits in 32 bytes
    malleated = signature[:32] + (s + L).to_bytes(32, "little")
    assert not ed25519.verify(key.public, message, malleated)


def test_non_canonical_and_small_order_keys_are_rejected(tmp_path):
    key = FixtureKey(tmp_path)
    message = b"weak keys"
    signature = key.sign(message)
    identity_point = (1).to_bytes(32, "little")  # y = 1: the neutral element (order 1)
    assert not ed25519.verify(identity_point, message, signature)
    non_canonical = (P + 1).to_bytes(32, "little")  # y >= p is not a valid encoding
    assert not ed25519.verify(non_canonical, message, signature)
    assert not ed25519.verify(key.public, message, b"\x00" * 64)
    assert not ed25519.verify(key.public, message, non_canonical + signature[32:])


def test_verify_is_total_on_garbage():
    for _ in range(25):
        assert ed25519.verify(os.urandom(32), os.urandom(40), os.urandom(64)) is False
    require_openssl()
