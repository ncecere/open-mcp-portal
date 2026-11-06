"""Small, deliberately slow RFC 8032 Ed25519 verifier (standard library only).

Verification uses canonical point encodings, S < L, and the RFC's cofactored
verification equation. This module is a reference harness, not a signing API.
"""
import hashlib

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
IDENTITY = (0, 1)


def decode(raw):
    if len(raw) != 32:
        raise ValueError('invalid point length')
    n = int.from_bytes(raw, 'little')
    sign, y = n >> 255, n & (2**255 - 1)
    if y >= P:
        raise ValueError('noncanonical point')
    denominator = (D * y * y + 1) % P
    if denominator == 0:
        raise ValueError('invalid point')
    x2 = (y*y - 1) * pow(denominator, P - 2, P) % P
    x = pow(x2, (P + 3) // 8, P)
    if x*x % P != x2:
        x = x * SQRT_M1 % P
    if x*x % P != x2 or (x == 0 and sign):
        raise ValueError('invalid point')
    if x & 1 != sign:
        x = P - x
    return x, y


def add(a, b):
    x, y = a
    u, v = b
    product = D*x*u*y*v % P
    return ((x*v + y*u) * pow(1 + product, P - 2, P) % P,
            (y*v + x*u) * pow(1 - product, P - 2, P) % P)


def multiply(point, scalar):
    result = IDENTITY
    while scalar:
        if scalar & 1:
            result = add(result, point)
        point = add(point, point)
        scalar >>= 1
    return result


BASE = decode(bytes.fromhex('58' + '66'*31))


def verify(public, message, signature):
    """Return False for malformed keys/signatures, never accept S modulo L."""
    if len(public) != 32 or len(signature) != 64:
        return False
    scalar = int.from_bytes(signature[32:], 'little')
    if scalar >= L:
        return False
    try:
        a, r = decode(public), decode(signature[:32])
    except ValueError:
        return False
    # Install keys are generated in the prime-order subgroup. Reject small-order
    # public keys, which cannot represent an enrolled signing identity.
    if multiply(a, 8) == IDENTITY:
        return False
    challenge = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), 'little') % L
    return multiply(BASE, 8*scalar) == add(multiply(r, 8), multiply(a, 8*challenge))
