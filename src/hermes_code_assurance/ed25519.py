"""Ed25519 signature VERIFICATION only (RFC 8032 section 5.1.7), standard library only.

Why this exists: the engine ships with no runtime dependencies, and the owner approves an
execution by signing its exact request outside this process. Only public data (public key,
message, signature) ever enters this module, so there is no secret-dependent timing to protect.
It is trusted only because tests/unit/test_ed25519.py checks it against the RFC 8032 vectors and
against signatures made by an independent implementation (OpenSSL) with throwaway keys.

Strictness beyond the RFC reference code: non-canonical field encodings (y >= p), a scalar
S >= L (signature malleability), and small-order public keys are all rejected.
"""

from __future__ import annotations

import hashlib

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493  # order of the base-point subgroup


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


_D = (-121665 * _inv(121666)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _recover_x(y: int, sign: int):
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_BY = 4 * _inv(5) % _P
_BX = _recover_x(_BY, 0)
assert _BX is not None, "base point must decompress"
_BASE = (_BX, _BY, 1, _BX * _BY % _P)
_NEUTRAL = (0, 1, 1, 0)


def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(scalar: int, point):
    result = _NEUTRAL
    while scalar > 0:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _equal(p, q) -> bool:
    return (p[0] * q[2] - q[0] * p[2]) % _P == 0 and (p[1] * q[2] - q[1] * p[2]) % _P == 0


def _decompress(encoded: bytes):
    if len(encoded) != 32:
        return None
    y = int.from_bytes(encoded, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """True only for a valid, canonical signature by ``public_key`` over exactly ``message``."""
    try:
        public_key, message, signature = bytes(public_key), bytes(message), bytes(signature)
    except (TypeError, ValueError):
        return False
    if len(public_key) != 32 or len(signature) != 64:
        return False
    point_a = _decompress(public_key)
    point_r = _decompress(signature[:32])
    if point_a is None or point_r is None:
        return False
    if _equal(_mul(8, point_a), _NEUTRAL):  # small-order (weak) public key
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:  # malleable encoding
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little")
    h %= _L
    return _equal(_mul(s, _BASE), _add(point_r, _mul(h, point_a)))
