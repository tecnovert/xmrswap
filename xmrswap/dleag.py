#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2020 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

import struct
import hashlib

import xmrswap.contrib.ed25519_fast as edf
import xmrswap.ed25519_fast_util as edu
from xmrswap.ecc_util import (
    ep, G, INFINITY, SECP256K1_ORDER_HALF,
    pointToCPK, ToDER, CPKToPoint,
    hashToCurve,
    i2b, b2i, i2h)
from xmrswap.contrib.ellipticcurve import inverse_mod
from xmrswap.rfc6979 import (
    secp256k1_rfc6979_hmac_sha256_initialize,
    secp256k1_rfc6979_hmac_sha256_generate)


HG = hashToCurve(ToDER(G))
HB = edu.hashToEd25519(edu.encodepoint(edf.B))


def get_sc_secp256k1(csprng):
    for i in range(1000):
        bi = b2i(secp256k1_rfc6979_hmac_sha256_generate(csprng, 32))
        if bi > 0 and bi < ep.o:
            return bi
    raise ValueError('get_sc_secp256k1 failed')


def get_sc_ed25519(csprng):
    for i in range(1000):
        b = bytearray(secp256k1_rfc6979_hmac_sha256_generate(csprng, 32))
        b[0] &= 0x1f  # Clear top 3 bits
        bi = b2i(b)
        if bi > 8 and bi < edf.l:
            return bi
    raise ValueError('get_sc_ed25519 failed')


def hash_sc_secp256k1(bytes_in):
    for i in range(1000):
        t = int.from_bytes(bytes_in, byteorder='big')
        if t > 0 and t < ep.o:
            return bytes_in
        bytes_in = hashlib.sha256(bytes_in).digest()
    raise ValueError('hash_sc_secp256k1 failed')


def hash_sc_ed25519(bytes_in):
    bytes_in = bytearray(bytes_in)
    for i in range(1000):
        bytes_in[0] &= 0x1f  # Clear top 3 bits
        t = int.from_bytes(bytes_in, byteorder='big')
        if t > 9 and t < edf.l:
            return bytes_in
        bytes_in = bytearray(hashlib.sha256(bytes_in).digest())
    raise ValueError('hash_sc_ed25519 failed')


def nonce_function_rfc6979(key32, msg32, count):
    keydata = key32 + msg32
    csprng = secp256k1_rfc6979_hmac_sha256_initialize(keydata)
    for i in range(count + 1):
        nonce32 = secp256k1_rfc6979_hmac_sha256_generate(csprng, 32)
    return nonce32


def sign_ecdsa_compact(x, m, gen):
    nonce_i = None
    found_nonce = False
    for i in range(1000):
        nonce = nonce_function_rfc6979(x, m, i)
        nonce_i = int.from_bytes(nonce, byteorder='big')
        if nonce_i > 0 and nonce_i < ep.o:
            found_nonce = True
            break
    assert(found_nonce)

    recid = 1
    xi = b2i(x)
    mi = b2i(m) % ep.o

    rp = gen * nonce_i
    overflow = 1 if rp.x() >= ep.o else 0
    y_is_odd = rp.y() & 1
    recid = (overflow << 1) | y_is_odd
    sigr = rp.x() % ep.o

    n = (sigr * xi) % ep.o
    n = (n + mi) % ep.o
    sigs = inverse_mod(nonce_i, ep.o)
    sigs = (sigs * n) % ep.o

    # Low s
    high = 0
    if sigs >= SECP256K1_ORDER_HALF:
        sigs = ep.o - sigs
        high = 1
    recid ^= high

    if sigs < 1 or sigr < 1:
        raise ValueError('Signature element zero.')

    return bytes((27 + recid,)) + i2b(sigr) + i2b(sigs)


def verify_ecdsa_compact(pubkey, sig, m, gen):
    P = CPKToPoint(pubkey)
    sigr = b2i(sig[:32])
    sigs = b2i(sig[32:])
    mi = b2i(m) % ep.o

    # Reject low s
    if sigs >= SECP256K1_ORDER_HALF:
        return False

    sn = inverse_mod(sigs, ep.o)
    u1 = (sn * mi) % ep.o
    u2 = (sn * sigr) % ep.o
    pr = P * u2
    qr = gen * u1
    pr = pr + qr
    if pr == INFINITY:
        return False

    xp = pr.x() % ep.o
    return True if sigr == xp else False


def sign_eddsa(x, m, gen):
    xi = b2i(x)
    if xi < 9 or xi >= edf.l:
        raise ValueError('Invalid secret key')

    P = edf.scalarmult(gen, xi)
    az = hashlib.sha512(x[::-1]).digest()
    h = hashlib.sha512()
    h.update(az[32:])
    h.update(m)
    az = h.digest()
    nonce = int.from_bytes(az, byteorder='little') % edf.l
    R = edf.scalarmult(gen, nonce)
    sigr = edu.encodepoint(R)

    h = hashlib.sha512()
    h.update(sigr)
    h.update(edu.encodepoint(P))
    h.update(m)
    hram = h.digest()

    mi = int.from_bytes(hram, byteorder='little') % edf.l
    s = (((mi * xi) % edf.l) + nonce) % edf.l

    return sigr + s.to_bytes(32, byteorder='little')


def verify_eddsa(p, sig, m, gen):
    s = int.from_bytes(sig[32:], byteorder='little')
    if s < 9 or s >= edf.l:
        raise ValueError('Invalid s value')

    P = edf.decodepoint(p)
    check_point_ed25519(P)
    Pi = edf.edwards_negated(P)

    h = hashlib.sha512()
    h.update(sig[:32])
    h.update(p)
    h.update(m)
    hram = h.digest()
    mi = int.from_bytes(hram, byteorder='little') % edf.l

    R = edf.scalarmult(Pi, mi)
    Q = edf.scalarmult(gen, s)
    R = edf.edwards_add(R, Q)
    return True if edu.encodepoint(R) == sig[:32] else False


def proveDLEAG(x, nonce, n=252):
    P1 = G * x
    P2 = edf.scalarmult(edf.B, x)

    proof = bytearray()
    proof += pointToCPK(P1)
    proof += edu.encodepoint(P2)

    message = 'dleag message'
    message_hash = hashlib.sha256(bytes(message, 'utf-8')).digest()
    proof += sign_ecdsa_compact(i2b(x), message_hash, G)[1:]
    proof += sign_eddsa(i2b(x), message_hash, edf.B)

    csprng = secp256k1_rfc6979_hmac_sha256_initialize(nonce)

    sum_r = 0
    sum_s = 0

    r = [None] * n
    s = [None] * n

    # Set the last r and s so they sum to 0 when weighted by bit position
    for i in range(n - 1):
        r[i] = get_sc_secp256k1(csprng)
        s[i] = get_sc_ed25519(csprng)
        sum_r = (sum_r + ((r[i] * (2 ** i)) % ep.o)) % ep.o
        sum_s = (sum_s + ((s[i] * (2 ** i)) % edf.l)) % edf.l

    r[n - 1] = ((ep.o - sum_r) * inverse_mod(2 ** (n - 1), ep.o)) % ep.o
    assert((sum_r + ((r[n - 1] * (2 ** (n - 1))) % ep.o)) % ep.o == 0)

    s[n - 1] = ((edf.l - sum_s) * inverse_mod(2 ** (n - 1), edf.l)) % edf.l
    assert((sum_s + ((s[n - 1] * (2 ** (n - 1))) % edf.l)) % edf.l == 0)

    # Split x into tuple of bits:
    xb = []
    xr = 0
    bpr = 1  # Bits per ring
    m = (2 ** bpr)  # Ring members
    for i in range(n):
        xb.append((x >> (i * bpr)) & ((1 << bpr) - 1))
        xr += xb[i] * (2 ** n)
    assert(xr > 0), 'If x is 0 commitments will sum to the identity point.'

    # Create the commitment points:
    C_G = [None] * n
    C_B = [None] * n

    h = hashlib.sha256()
    h.update(pointToCPK(P1))
    h.update(edu.encodepoint(P2))

    for i in range(n):
        C_G[i] = G * xb[i] + HG * r[i]
        C_B[i] = edf.edwards_add(edf.scalarmult(edf.B, xb[i]), edf.scalarmult(HB, s[i]))

        h.update(pointToCPK(C_G[i]))
        h.update(edu.encodepoint(C_B[i]))

    preimage_hash = h.digest()

    j = [None] * n
    k = [None] * n

    a = [None] * (n * 2)
    b = [None] * (n * 2)

    # Construct the ring signature stack
    #   Prove that in each commitment point there is either 1H or 0H
    #   The offsets of the secret keys at each level must be the same due to the construction of the hash

    J_h = hashlib.sha256()
    K_h = hashlib.sha256()

    for i in range(n):
        j[i] = get_sc_secp256k1(csprng)
        k[i] = get_sc_ed25519(csprng)
        J = HG * j[i]
        K = edf.scalarmult(HB, k[i])
        for ii in range(xb[i] + 1, m):
            h = hashlib.sha256()
            h.update(preimage_hash)
            h.update(pointToCPK(J))
            h.update(edu.encodepoint(K))
            h.update(struct.pack('>I', i))
            h.update(struct.pack('>I', ii))
            hash_b = h.digest()
            ej = b2i(hash_sc_secp256k1(hash_b))
            ek = b2i(hash_sc_ed25519(hash_b))

            a[i * 2 + ii] = get_sc_secp256k1(csprng)
            b[i * 2 + ii] = get_sc_ed25519(csprng)

            # ii == 1:
            J = HG * a[i * 2 + ii] - (C_G[i] - G) * ej
            K = edf.edwards_sub(
                edf.scalarmult(HB, b[i * 2 + ii]),
                edf.scalarmult(edf.edwards_sub(C_B[i], edf.B), ek))

        J_h.update(pointToCPK(J))
        K_h.update(edu.encodepoint(K))

    J_hb = J_h.digest()
    K_hb = K_h.digest()

    # Sign loop
    for i in range(n):
        h = hashlib.sha256()
        h.update(preimage_hash)
        h.update(J_hb)
        h.update(K_hb)
        h.update(struct.pack('>I', i))
        h.update(struct.pack('>I', 0))
        hash_b = h.digest()
        ej = b2i(hash_sc_secp256k1(hash_b))
        ek = b2i(hash_sc_ed25519(hash_b))

        for ii in range(0, xb[i]):
            a[i * 2 + ii] = get_sc_secp256k1(csprng)
            b[i * 2 + ii] = get_sc_ed25519(csprng)

            # ii == 0:
            J = HG * a[i * 2 + ii] - C_G[i] * ej
            K = edf.edwards_sub(
                edf.scalarmult(HB, b[i * 2 + ii]),
                edf.scalarmult(C_B[i], ek))

            h = hashlib.sha256()
            h.update(preimage_hash)
            h.update(pointToCPK(J))
            h.update(edu.encodepoint(K))
            h.update(struct.pack('>I', i))
            h.update(struct.pack('>I', ii + 1))
            hash_b = h.digest()
            ej = b2i(hash_sc_secp256k1(hash_b))
            ek = b2i(hash_sc_ed25519(hash_b))
        # Close the loop
        a[i * 2 + xb[i]] = (j[i] + ((ej * r[i]) % ep.o)) % ep.o
        b[i * 2 + xb[i]] = (k[i] + ((ek * s[i]) % edf.l)) % edf.l

    for i in range(n):
        proof += pointToCPK(C_G[i])
    for i in range(n):
        proof += edu.encodepoint(C_B[i])
    proof += J_hb
    proof += K_hb
    for i in range(n):
        proof += i2b(a[i * 2 + 0])
    for i in range(n):
        proof += i2b(a[i * 2 + 1])
    for i in range(n):
        proof += i2b(b[i * 2 + 0])
    for i in range(n):
        proof += i2b(b[i * 2 + 1])

    return proof


def check_point_secp256k1(P):
    if P == INFINITY:
        raise ValueError('Invalid secp256k1 point')


def check_point_ed25519(P):
    if edf.is_identity(P) or \
       not edf.is_identity(edf.scalarmult(P, edf.l)):
        raise ValueError('Invalid ed25519 point')


def verifyDLEAG(proof, n=252):
    m = 2  # Ring members

    if not len(proof) == 65 + 64 + 64 + 64 + 193 * n:
        raise ValueError('Bad proof size')

    # Unpack proof elements:
    o = 0
    P1 = CPKToPoint(proof[o:o + 33])
    o += 33
    P2 = edf.decodepoint(proof[o:o + 32])
    o += 32

    # Verify points are unblinded
    message = 'dleag message'
    message_hash = hashlib.sha256(bytes(message, 'utf-8')).digest()
    sig_ecdsa = proof[o:o + 64]
    o += 64
    sig_eddsa = proof[o:o + 64]
    o += 64
    if not verify_ecdsa_compact(proof[0:33], sig_ecdsa, message_hash, G):
        raise ValueError('Bad ECDSA signature')
    if not verify_eddsa(proof[33:65], sig_eddsa, message_hash, edf.B):
        raise ValueError('Bad EdDSA signature')

    C_G = [None] * n
    C_B = [None] * n

    a = [None] * (n * 2)
    b = [None] * (n * 2)

    for i in range(n):
        C_G[i] = CPKToPoint(proof[o:o + 33])
        o += 33
    for i in range(n):
        C_B[i] = edf.decodepoint(proof[o:o + 32])
        o += 32
    J_hb = proof[o:o + 32]
    o += 32
    K_hb = proof[o:o + 32]
    o += 32
    for i in range(n):
        a[i * 2 + 0] = b2i(proof[o:o + 32])
        o += 32
    for i in range(n):
        a[i * 2 + 1] = b2i(proof[o:o + 32])
        o += 32
    for i in range(n):
        b[i * 2 + 0] = b2i(proof[o:o + 32])
        o += 32
    for i in range(n):
        b[i * 2 + 1] = b2i(proof[o:o + 32])
        o += 32

    # Verify the weighted commitments sum to the points:
    CsumG = INFINITY
    CsumB = edf.ident

    h = hashlib.sha256()
    h.update(pointToCPK(P1))
    h.update(edu.encodepoint(P2))

    for i in range(n):
        check_point_secp256k1(C_G[i])
        check_point_ed25519(C_B[i])

        h.update(pointToCPK(C_G[i]))
        h.update(edu.encodepoint(C_B[i]))

        CsumG += C_G[i] * (2 ** i)
        CsumB = edf.edwards_add(CsumB, edf.scalarmult(C_B[i], 2 ** i))

    preimage_hash = h.digest()

    if not pointToCPK(CsumG) == pointToCPK(P1) \
       or not edu.encodepoint(CsumB) == edu.encodepoint(P2):
        raise ValueError('Bad commitment sum')

    # Verify the ring signature stack:
    J_h = hashlib.sha256()
    K_h = hashlib.sha256()
    for i in range(n):
        h = hashlib.sha256()
        h.update(preimage_hash)
        h.update(J_hb)
        h.update(K_hb)
        h.update(struct.pack('>I', i))
        h.update(struct.pack('>I', 0))
        hash_b = h.digest()
        ej = b2i(hash_sc_secp256k1(hash_b))
        ek = b2i(hash_sc_ed25519(hash_b))
        for ii in range(0, m):
            if ii == 0:
                J = HG * a[i * 2 + ii] - C_G[i] * ej
                K = edf.edwards_sub(
                    edf.scalarmult(HB, b[i * 2 + ii]),
                    edf.scalarmult(C_B[i], ek))
            else:
                J = HG * a[i * 2 + ii] - (C_G[i] - G) * ej
                K = edf.edwards_sub(
                    edf.scalarmult(HB, b[i * 2 + ii]),
                    edf.scalarmult(edf.edwards_sub(C_B[i], edf.B), ek))

            if ii < m - 1:  # No next ring member to calculate e for
                h = hashlib.sha256()
                h.update(preimage_hash)
                h.update(pointToCPK(J))
                h.update(edu.encodepoint(K))
                h.update(struct.pack('>I', i))
                h.update(struct.pack('>I', ii + 1))
                hash_b = h.digest()
                ej = b2i(hash_sc_secp256k1(hash_b))
                ek = b2i(hash_sc_ed25519(hash_b))
        J_h.update(pointToCPK(J))
        K_h.update(edu.encodepoint(K))

    J_hbv = J_h.digest()
    K_hbv = K_h.digest()

    if not J_hbv == J_hb:
        return False
    if not K_hbv == K_hb:
        return False
    return True


def testDLEAG():
    print('testDLEAG()')
    import time
    import secrets

    assert(G * ep.o == INFINITY)
    assert(HG * ep.o == INFINITY)

    assert(edf.is_identity(edf.scalarmult(edf.B, edf.l)))
    assert(edf.is_identity(edf.scalarmult(HB, edf.l)))

    nonce = secrets.token_bytes(32)

    x = edu.get_secret()
    print('x', i2h(x))

    start = time.time()
    proof = proveDLEAG(x, nonce)
    print('proof len', len(proof))
    print('Took {} seconds'.format(time.time() - start))

    start = time.time()
    passed = verifyDLEAG(proof)
    print('Proof Valid' if passed else 'Proof Invalid')
    print('Took {} seconds'.format(time.time() - start))
    assert(passed is True)

    a = edu.get_secret()
    A = edf.scalarmult(edf.B, a)
    bad_proof = proof[:33] + edu.encodepoint(A) + proof[33 + 32:]

    try:
        passed = verifyDLEAG(bad_proof)
        assert(False), 'Verified bad_proof!'
    except Exception as e:
        assert(str(e) == 'Bad EdDSA signature')

    # Redo signature
    message = 'dleag message'
    message_hash = hashlib.sha256(bytes(message, 'utf-8')).digest()
    bad_proof = bad_proof[:65 + 64] + sign_eddsa(i2b(a), message_hash, edf.B) + bad_proof[65 + 64 + 64:]

    try:
        passed = verifyDLEAG(bad_proof)
        assert(False), 'Verified bad_proof!'
    except Exception as e:
        assert(str(e) == 'Bad commitment sum')

    print('Passed.')


if __name__ == "__main__":
    testDLEAG()
