#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2020 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

"""
One-Time Verifiably Encrypted Signatures
https://github.com/LLFourn/one-time-VES/blob/master/main.pdf
"""

import hashlib
from .ecc_util import (
    ep, G, SECP256K1_ORDER_HALF,
    pointToCPK, CPKToPoint,
    getSecretInt,
    i2b, b2i)
from .contrib.ellipticcurve import inverse_mod


def prove_dleq(B1, B2, x):
    # Non-Interactive Zero Knowledge proof of Discrete Logarithm Equality
    P1 = B1 * x
    P2 = B2 * x

    k = getSecretInt()
    K1 = B1 * k
    K2 = B2 * k

    h = hashlib.sha256()
    h.update(pointToCPK(P1))
    h.update(pointToCPK(P2))
    h.update(pointToCPK(K1))
    h.update(pointToCPK(K2))
    c = b2i(h.digest()) % ep.o
    assert(c > 0)

    r = (k - (c * x) % ep.o) % ep.o

    return pointToCPK(K1) + pointToCPK(K2) + i2b(r)


def verify_dleq(proof, B1, B2, P1, P2):
    assert(len(proof) == 33 + 33 + 32)

    o = 0
    K1 = CPKToPoint(proof[o: o + 33])
    o += 33
    K2 = CPKToPoint(proof[o: o + 33])
    o += 33
    r = b2i(proof[o: o + 32])

    assert(not K1 == B1 and not K1 == B2)
    assert(not K2 == B1 and not K2 == B2)
    assert(r > 0 and r < ep.o)

    h = hashlib.sha256()
    h.update(pointToCPK(P1))
    h.update(pointToCPK(P2))
    h.update(pointToCPK(K1))
    h.update(pointToCPK(K2))
    c = b2i(h.digest()) % ep.o
    assert(c > 0)

    R1 = B1 * r
    R2 = B2 * r

    C1 = P1 * c
    C2 = P2 * c

    return True if K1 == R1 + C1 and K2 == R2 + C2 else False


def EncSign(skS, pkE, m):
    # skS - secret signing key
    # pkE - public encryption key
    # m   - message
    # -> ciphertext

    r = getSecretInt()
    R1 = G * r
    R2 = pkE * r

    dleq = prove_dleq(G, pkE, r)

    R2x = R2.x() % ep.o
    assert(R2x > 0)

    assert(len(m) == 32)
    # e = b2i(hashlib.sha256(bytes(m, 'utf-8')).digest()) % ep.o
    e = b2i(m)
    assert(e > 0)
    s = (inverse_mod(r, ep.o) * ((e + ((R2x * skS) % ep.o)) % ep.o)) % ep.o
    assert(s > 0)

    return pointToCPK(R1) + pointToCPK(R2) + i2b(s) + dleq


def EncVrfy(pkS, pkE, m, ct):
    # pkS - public signing key
    # pkE - public encryption key
    # m   - message
    # ct  - ciphertext
    # -> True / False

    assert(len(ct) == 33 + 33 + 32 + 98)

    o = 0
    R1 = CPKToPoint(ct[o: o + 33])
    o += 33
    R2 = CPKToPoint(ct[o: o + 33])
    o += 33
    s = b2i(ct[o: o + 32])
    o += 32
    dleq = ct[o: o + 98]

    assert(not R1 == G)
    assert(not R2 == G)
    assert(s > 0 and s < ep.o)

    if not verify_dleq(dleq, G, pkE, R1, R2):
        return False

    R2x = R2.x() % ep.o
    assert(R2x > 0)

    # e = b2i(hashlib.sha256(bytes(m, 'utf-8')).digest()) % ep.o
    assert(len(m) == 32)
    e = b2i(m)
    assert(e > 0)
    si = inverse_mod(s, ep.o)

    T = G * e + pkS * R2x

    return True if R1 == T * si else False


def DecSig(skE, ct):
    # skE - decryption key
    # ct  - ciphertext
    # -> DER encoded sig

    assert(len(ct) == 33 + 33 + 32 + 98)
    o = 33
    R2 = CPKToPoint(ct[o: o + 33])
    o += 33
    s = b2i(ct[o: o + 32])

    # R2 == G * (b * r)
    # Removing b

    skEi = inverse_mod(skE, ep.o)
    ssig = (s * skEi) % ep.o

    R2x = R2.x() % ep.o

    # Low s
    if ssig >= SECP256K1_ORDER_HALF:
        ssig = ep.o - ssig
    # Encode in DER format.
    rb = R2x.to_bytes((R2x.bit_length() + 8) // 8, 'big')
    sb = ssig.to_bytes((ssig.bit_length() + 8) // 8, 'big')
    return b'\x30' + bytes([4 + len(rb) + len(sb), 2, len(rb)]) + rb + bytes([2, len(sb)]) + sb


def RecoverEncKey(ct, dersig, pkE):
    # dersig - DER encoded signature
    # ct  - ciphertext
    # pkE - public encryption key
    # -> skE

    if not len(ct) == 33 + 33 + 32 + 98:
        raise ValueError('Bad ciphertext encoding.')
    o = 33 + 33
    sct = b2i(ct[o: o + 32])

    assert(len(dersig) > 1)
    if len(dersig) < 4 or \
       dersig[1] + 2 != len(dersig) or \
       dersig[0] != 0x30 or \
       dersig[2] != 0x02:
        raise ValueError('Bad DER encoding.')
    rlen = dersig[3]

    if len(dersig) < 6 + rlen or \
       rlen < 1 or rlen > 33 or \
       dersig[4] >= 0x80 or \
       (rlen > 1 and (dersig[4] == 0) and not (dersig[5] & 0x80)):
        raise ValueError('Bad DER encoding.')

    # Load r
    if dersig[4 + rlen] != 0x02:
        raise ValueError('Bad DER encoding.')
    slen = dersig[5 + rlen]

    if slen < 1 or slen > 33 or \
       (len(dersig) != 6 + rlen + slen) or \
       dersig[6 + rlen] >= 0x80 or \
       (slen > 1 and (dersig[6 + rlen] == 0) and not (dersig[7 + rlen] & 0x80)):
        raise ValueError('Bad DER encoding.')

    s = int.from_bytes(dersig[6 + rlen: 6 + rlen + slen], 'big')

    si = inverse_mod(s, ep.o)

    y = (si * sct) % ep.o

    if G * y == pkE:
        return y

    y = ep.o - y
    if G * y == pkE:
        return y
    return None


def testOtVES():
    print('testOtVES()')

    print('Passed.')


if __name__ == "__main__":
    testOtVES()
