#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2020 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

import time
import hashlib
import logging
from io import BytesIO

import xmrswap.otves_ecdsa as otves

from xmrswap.dleag import (
    sign_ecdsa_compact,
    verify_ecdsa_compact,
    check_point_secp256k1,
)

from .util import (
    decodeScriptNum,
    getCompactSizeLen,
    dumpj,
    format_amount,
    make_int
)

from .ecc_util import (
    G, ep,
    pointToCPK, CPKToPoint,
    getSecretInt,
    b2h, i2b, b2i, i2h)

from .contrib.test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    FromHex,
    ToHex,
)

from .contrib.test_framework.script import (
    CScript,
    CScriptOp,
    CScriptNum,
    OP_IF, OP_ELSE, OP_ENDIF,
    OP_0,
    OP_2,
    OP_16,
    OP_EQUALVERIFY,
    OP_CHECKSIG,
    OP_SIZE,
    OP_SHA256,
    OP_CHECKMULTISIG,
    OP_CHECKSEQUENCEVERIFY,
    OP_DROP,
    SIGHASH_ALL,
    SegwitV0SignatureHash,
    hash160
)

from .contrib.test_framework.key import ECKey, ECPubKey

from .interface import CoinInterface, assert_cond


def findOutput(tx, script_pk):
    for i in range(len(tx.vout)):
        if tx.vout[i].scriptPubKey == script_pk:
            return i
    return None


class BTCInterface(CoinInterface):
    @staticmethod
    def exp():
        return 8

    @staticmethod
    def nbk():
        return 32

    @staticmethod
    def nbK():  # No. of bytes requires to encode a public key
        return 33

    @staticmethod
    def witnessScaleFactor():
        return 4

    @staticmethod
    def txVersion():
        return 2

    @staticmethod
    def getTxOutputValue(tx):
        rv = 0
        for output in tx.vout:
            rv += output.nValue
        return rv

    def compareFeeRates(self, a, b):
        return abs(a - b) < 20

    def __init__(self, rpc_callback):
        self.rpc_callback = rpc_callback
        self.txoType = CTxOut

    def getNewSecretKey(self):
        return getSecretInt()

    def pubkey(self, key):
        return G * key

    def encodePubkey(self, pk):
        return pointToCPK(pk)

    def decodePubkey(self, pke):
        return CPKToPoint(pke)

    def verifyPubkey(self, pk):
        check_point_secp256k1(pk)

    def decodeKey(self, k):
        i = b2i(k)
        assert(i < ep.o)
        return i

    def sumKeys(self, ka, kb):
        return (ka + kb) % ep.o

    def sumPubkeys(self, Ka, Kb):
        return Ka + Kb

    def extractLongScriptLockScriptValues(self, script_bytes):
        script_len = len(script_bytes)
        assert_cond(script_len > 112, 'Bad script length')
        assert_cond(script_bytes[0] == OP_IF)
        assert_cond(script_bytes[1] == OP_SIZE)
        assert_cond(script_bytes[2:4] == bytes((1, 32)))  # 0120, CScriptNum length, then data
        assert_cond(script_bytes[4] == OP_EQUALVERIFY)
        assert_cond(script_bytes[5] == OP_SHA256)
        assert_cond(script_bytes[6] == 32)
        secret_hash = script_bytes[7: 7 + 32]
        assert_cond(script_bytes[39] == OP_EQUALVERIFY)
        assert_cond(script_bytes[40] == OP_2)
        assert_cond(script_bytes[41] == 33)
        pk1 = script_bytes[42: 42 + 33]
        assert_cond(script_bytes[75] == 33)
        pk2 = script_bytes[76: 76 + 33]
        assert_cond(script_bytes[109] == OP_2)
        assert_cond(script_bytes[110] == OP_CHECKMULTISIG)
        assert_cond(script_bytes[111] == OP_ELSE)
        o = 112

        #  Decode script num
        csv_val, nb = decodeScriptNum(script_bytes, o)
        o += nb

        assert_cond(script_len == o + 8 + 66, 'Bad script length')  # Fails if script too long
        assert_cond(script_bytes[o] == OP_CHECKSEQUENCEVERIFY)
        o += 1
        assert_cond(script_bytes[o] == OP_DROP)
        o += 1
        assert_cond(script_bytes[o] == OP_2)
        o += 1
        assert_cond(script_bytes[o] == 33)
        o += 1
        pk3 = script_bytes[o: o + 33]
        o += 33
        assert_cond(script_bytes[o] == 33)
        o += 1
        pk4 = script_bytes[o: o + 33]
        o += 33
        assert_cond(script_bytes[o] == OP_2)
        o += 1
        assert_cond(script_bytes[o] == OP_CHECKMULTISIG)
        o += 1
        assert_cond(script_bytes[o] == OP_ENDIF)

        return secret_hash, pk1, pk2, csv_val, pk3, pk4

    def genLongScriptLockTxScript(self, sh, Kal, Kaf, lock_blocks, Karl, Karf):
        return CScript([
            CScriptOp(OP_IF),
            CScriptOp(OP_SIZE), 32, CScriptOp(OP_EQUALVERIFY),
            CScriptOp(OP_SHA256), sh, CScriptOp(OP_EQUALVERIFY),
            2, self.encodePubkey(Kal), self.encodePubkey(Kaf), 2, CScriptOp(OP_CHECKMULTISIG),
            CScriptOp(OP_ELSE),
            lock_blocks, CScriptOp(OP_CHECKSEQUENCEVERIFY), CScriptOp(OP_DROP),
            2, self.encodePubkey(Karl), self.encodePubkey(Karf), 2, CScriptOp(OP_CHECKMULTISIG),
            CScriptOp(OP_ENDIF)])

    def extractScriptLockScriptValues(self, script_bytes):
        script_len = len(script_bytes)
        assert_cond(script_len == 145, 'Bad script length')
        o = 0
        assert_cond(script_bytes[o] == OP_IF)
        assert_cond(script_bytes[o + 1] == OP_2)
        assert_cond(script_bytes[o + 2] == 33)
        o += 3
        pk1 = script_bytes[o: o + 33]
        o += 33
        assert_cond(script_bytes[o] == 33)
        o += 1
        pk2 = script_bytes[o: o + 33]
        o += 33
        assert_cond(script_bytes[o] == OP_2)
        assert_cond(script_bytes[o + 1] == OP_CHECKMULTISIG)
        assert_cond(script_bytes[o + 2] == OP_ELSE)
        assert_cond(script_bytes[o + 3] == OP_2)
        assert_cond(script_bytes[o + 4] == 33)
        o += 5
        pk3 = script_bytes[o: o + 33]
        o += 33
        assert_cond(script_bytes[o] == 33)
        o += 1
        pk4 = script_bytes[o: o + 33]
        o += 33
        assert_cond(script_bytes[o] == OP_2)
        assert_cond(script_bytes[o + 1] == OP_CHECKMULTISIG)
        assert_cond(script_bytes[o + 2] == OP_ENDIF)

        return pk1, pk2, pk3, pk4

    def genScriptLockTxScript(self, Kal, Kaf, Karl, Karf):
        return CScript([
            CScriptOp(OP_IF),
            2, self.encodePubkey(Kal), self.encodePubkey(Kaf), 2, CScriptOp(OP_CHECKMULTISIG),
            CScriptOp(OP_ELSE),
            2, self.encodePubkey(Karl), self.encodePubkey(Karf), 2, CScriptOp(OP_CHECKMULTISIG),
            CScriptOp(OP_ENDIF)])

    def createScriptLockTx(self, value, Kal, Kaf, Karl, Karf):

        script = self.genScriptLockTxScript(Kal, Kaf, Karl, Karf)
        tx = CTransaction()
        tx.nVersion = self.txVersion()
        tx.vout.append(self.txoType(value, CScript([OP_0, hashlib.sha256(script).digest()])))

        return tx, script

    def extractScriptLockRefundScriptValues(self, script_bytes):
        script_len = len(script_bytes)
        assert_cond(script_len > 73, 'Bad script length')
        assert_cond(script_bytes[0] == OP_IF)
        assert_cond(script_bytes[1] == OP_2)
        assert_cond(script_bytes[2] == 33)
        pk1 = script_bytes[3: 3 + 33]
        assert_cond(script_bytes[36] == 33)
        pk2 = script_bytes[37: 37 + 33]
        assert_cond(script_bytes[70] == OP_2)
        assert_cond(script_bytes[71] == OP_CHECKMULTISIG)
        assert_cond(script_bytes[72] == OP_ELSE)
        o = 73
        csv_val, nb = decodeScriptNum(script_bytes, o)
        o += nb

        assert_cond(script_len == o + 5 + 33, 'Bad script length')  # Fails if script too long
        assert_cond(script_bytes[o] == OP_CHECKSEQUENCEVERIFY)
        o += 1
        assert_cond(script_bytes[o] == OP_DROP)
        o += 1
        assert_cond(script_bytes[o] == 33)
        o += 1
        pk3 = script_bytes[o: o + 33]
        o += 33
        assert_cond(script_bytes[o] == OP_CHECKSIG)
        o += 1
        assert_cond(script_bytes[o] == OP_ENDIF)

        return pk1, pk2, csv_val, pk3

    def genScriptLockRefundTxScript(self, Karl, Karf, csv_val, Kaf):
        return CScript([
            CScriptOp(OP_IF),
            2, self.encodePubkey(Karl), self.encodePubkey(Karf), 2, CScriptOp(OP_CHECKMULTISIG),
            CScriptOp(OP_ELSE),
            csv_val, CScriptOp(OP_CHECKSEQUENCEVERIFY), CScriptOp(OP_DROP),
            self.encodePubkey(Kaf), CScriptOp(OP_CHECKSIG),
            CScriptOp(OP_ENDIF)])

    def createScriptLockRefundTx(self, tx_lock, script_lock, Karl, Karf, lock1_value, csv_val, Kaf, tx_fee_rate):

        output_script = CScript([OP_0, hashlib.sha256(script_lock).digest()])
        locked_n = findOutput(tx_lock, output_script)
        assert_cond(locked_n is not None, 'Output not found in tx')
        locked_coin = tx_lock.vout[locked_n].nValue

        tx_lock.rehash()
        tx_lock_hash_int = tx_lock.sha256

        refund_script = self.genScriptLockRefundTxScript(Karl, Karf, csv_val, Kaf)
        tx = CTransaction()
        tx.nVersion = self.txVersion()
        tx.vin.append(CTxIn(COutPoint(tx_lock_hash_int, locked_n), nSequence=lock1_value))
        tx.vout.append(self.txoType(locked_coin, CScript([OP_0, hashlib.sha256(refund_script).digest()])))

        witness_bytes = len(script_lock)
        witness_bytes += 73 * 2  # 2 signatures (72 + 1 byts size)
        witness_bytes += 2  # 2 empty witness stack values
        witness_bytes += getCompactSizeLen(witness_bytes)
        vsize = self.getTxVSize(tx, add_witness_bytes=witness_bytes)
        pay_fee = int(tx_fee_rate * vsize / 1000)
        tx.vout[0].nValue = locked_coin - pay_fee

        tx.rehash()
        logging.info('createScriptLockRefundTx %s:\n    fee_rate, vsize, fee: %ld, %ld, %ld.',
                     i2h(tx.sha256), tx_fee_rate, vsize, pay_fee)

        return tx, refund_script, tx.vout[0].nValue

    def createScriptLockRefundSpendTx(self, tx_lock_refund, script_lock_refund, Kal, tx_fee_rate):
        # Returns the coinA locked coin to the leader
        # The follower will sign the multisig path with a signature encumbered by the leader's coinB spend pubkey
        # When the leader publishes the decrypted signature the leader's coinB spend privatekey will be revealed to the follower

        output_script = CScript([OP_0, hashlib.sha256(script_lock_refund).digest()])
        locked_n = findOutput(tx_lock_refund, output_script)
        assert_cond(locked_n is not None, 'Output not found in tx')
        locked_coin = tx_lock_refund.vout[locked_n].nValue

        tx_lock_refund.rehash()
        tx_lock_refund_hash_int = tx_lock_refund.sha256

        tx = CTransaction()
        tx.nVersion = self.txVersion()
        tx.vin.append(CTxIn(COutPoint(tx_lock_refund_hash_int, locked_n), nSequence=0))

        pubkeyhash = hash160(self.encodePubkey(Kal))
        tx.vout.append(self.txoType(locked_coin, CScript([OP_0, pubkeyhash])))

        witness_bytes = len(script_lock_refund)
        witness_bytes += 73 * 2  # 2 signatures (72 + 1 byte size)
        witness_bytes += 4  # 1 empty, 1 true witness stack values
        witness_bytes += getCompactSizeLen(witness_bytes)
        vsize = self.getTxVSize(tx, add_witness_bytes=witness_bytes)
        pay_fee = int(tx_fee_rate * vsize / 1000)
        tx.vout[0].nValue = locked_coin - pay_fee

        tx.rehash()
        logging.info('createScriptLockRefundSpendTx %s:\n    fee_rate, vsize, fee: %ld, %ld, %ld.',
                     i2h(tx.sha256), tx_fee_rate, vsize, pay_fee)

        return tx

    def createScriptLockRefundSpendToFTx(self, tx_lock_refund, script_lock_refund, pkh_dest, tx_fee_rate):
        # Sends the coinA locked coin to the follower
        output_script = CScript([OP_0, hashlib.sha256(script_lock_refund).digest()])
        locked_n = findOutput(tx_lock_refund, output_script)
        assert_cond(locked_n is not None, 'Output not found in tx')
        locked_coin = tx_lock_refund.vout[locked_n].nValue

        A, B, lock2_value, C = self.extractScriptLockRefundScriptValues(script_lock_refund)

        tx_lock_refund.rehash()
        tx_lock_refund_hash_int = tx_lock_refund.sha256

        tx = CTransaction()
        tx.nVersion = self.txVersion()
        tx.vin.append(CTxIn(COutPoint(tx_lock_refund_hash_int, locked_n), nSequence=lock2_value))

        tx.vout.append(self.txoType(locked_coin, CScript([OP_0, pkh_dest])))

        witness_bytes = len(script_lock_refund)
        witness_bytes += 73  # signature (72 + 1 byte size)
        witness_bytes += 1  # 1 empty stack value
        witness_bytes += getCompactSizeLen(witness_bytes)
        vsize = self.getTxVSize(tx, add_witness_bytes=witness_bytes)
        pay_fee = int(tx_fee_rate * vsize / 1000)
        tx.vout[0].nValue = locked_coin - pay_fee

        tx.rehash()
        logging.info('createScriptLockRefundSpendToFTx %s:\n    fee_rate, vsize, fee: %ld, %ld, %ld.',
                     i2h(tx.sha256), tx_fee_rate, vsize, pay_fee)

        return tx

    def createScriptLockSpendTx(self, tx_lock, script_lock, pkh_dest, tx_fee_rate):

        output_script = CScript([OP_0, hashlib.sha256(script_lock).digest()])
        locked_n = findOutput(tx_lock, output_script)
        assert_cond(locked_n is not None, 'Output not found in tx')
        locked_coin = tx_lock.vout[locked_n].nValue

        tx_lock.rehash()
        tx_lock_hash_int = tx_lock.sha256

        tx = CTransaction()
        tx.nVersion = self.txVersion()
        tx.vin.append(CTxIn(COutPoint(tx_lock_hash_int, locked_n)))

        p2wpkh = CScript([OP_0, pkh_dest])
        tx.vout.append(self.txoType(locked_coin, p2wpkh))

        witness_bytes = len(script_lock)
        witness_bytes += 33  # sv, size
        witness_bytes += 73 * 2  # 2 signatures (72 + 1 byts size)
        witness_bytes += 4  # 1 empty, 1 true witness stack values
        witness_bytes += getCompactSizeLen(witness_bytes)
        vsize = self.getTxVSize(tx, add_witness_bytes=witness_bytes)
        pay_fee = int(tx_fee_rate * vsize / 1000)
        tx.vout[0].nValue = locked_coin - pay_fee

        tx.rehash()
        logging.info('createScriptLockSpendTx %s:\n    fee_rate, vsize, fee: %ld, %ld, %ld.',
                     i2h(tx.sha256), tx_fee_rate, vsize, pay_fee)

        return tx

    def verifyLockTx(self, tx, script_out,
                     swap_value,
                     Kal, Kaf,
                     lock_value, feerate,
                     Karl, Karf,
                     check_lock_tx_inputs):
        # Verify:
        #

        # Not necessary to check the lock txn is mineable, as protocol will wait for it to confirm
        # However by checking early we can avoid wasting time processing unmineable txns
        # Check fee is reasonable

        tx_hash = self.getTxHash(tx)
        logging.info('Verifying lock tx: {}.'.format(b2h(tx_hash)))

        assert_cond(tx.nVersion == self.txVersion(), 'Bad version')
        assert_cond(tx.nLockTime == 0, 'Bad nLockTime')

        script_pk = CScript([OP_0, hashlib.sha256(script_out).digest()])
        locked_n = findOutput(tx, script_pk)
        assert_cond(locked_n is not None, 'Output not found in tx')
        locked_coin = tx.vout[locked_n].nValue

        assert_cond(locked_coin == swap_value, 'Bad locked value')

        # Check script and values
        A, B, C, D = self.extractScriptLockScriptValues(script_out)
        assert_cond(A == self.encodePubkey(Kal), 'Bad script pubkey')
        assert_cond(B == self.encodePubkey(Kaf), 'Bad script pubkey')
        assert_cond(C == self.encodePubkey(Karl), 'Bad script pubkey')
        assert_cond(D == self.encodePubkey(Karf), 'Bad script pubkey')

        if check_lock_tx_inputs:
            # Check that inputs are unspent and verify fee rate
            inputs_value = 0
            add_bytes = 0
            add_witness_bytes = getCompactSizeLen(len(tx.vin))
            for pi in tx.vin:
                ptx = self.rpc_callback('getrawtransaction', [i2h(pi.prevout.hash), True])
                print('ptx', dumpj(ptx))
                prevout = ptx['vout'][pi.prevout.n]
                inputs_value += make_int(prevout['value'])

                prevout_type = prevout['scriptPubKey']['type']
                if prevout_type == 'witness_v0_keyhash':
                    add_witness_bytes += 107  # sig 72, pk 33 and 2 size bytes
                    add_witness_bytes += getCompactSizeLen(107)
                else:
                    # Assume P2PKH, TODO more types
                    add_bytes += 107  # OP_PUSH72 <ecdsa_signature> OP_PUSH33 <public_key>

            outputs_value = 0
            for txo in tx.vout:
                outputs_value += txo.nValue
            fee_paid = inputs_value - outputs_value
            assert(fee_paid > 0)

            vsize = self.getTxVSize(tx, add_bytes, add_witness_bytes)
            fee_rate_paid = fee_paid * 1000 / vsize

            logging.info('tx amount, vsize, feerate: %ld, %ld, %ld', locked_coin, vsize, fee_rate_paid)

            if not self.compareFeeRates(fee_rate_paid, feerate):
                logging.warning('feerate paid doesn\'t match expected: %ld, %ld', fee_rate_paid, feerate)
                # TODO: Display warning to user

        return tx_hash, locked_n

    def verifyLockRefundTx(self, tx, script_out,
                           prevout_id, prevout_n, prevout_seq, prevout_script,
                           Karl, Karf, csv_val_expect, Kaf, swap_value, feerate):
        # Verify:
        #   Must have only one input with correct prevout and sequence
        #   Must have only one output to the p2wsh of the lock refund script
        #   Output value must be locked_coin - lock tx fee

        tx_hash = self.getTxHash(tx)
        logging.info('Verifying lock refund tx: {}.'.format(b2h(tx_hash)))

        assert_cond(tx.nVersion == self.txVersion(), 'Bad version')
        assert_cond(tx.nLockTime == 0, 'nLockTime not 0')
        assert_cond(len(tx.vin) == 1, 'tx doesn\'t have one input')

        assert_cond(tx.vin[0].nSequence == prevout_seq, 'Bad input nSequence')
        assert_cond(len(tx.vin[0].scriptSig) == 0, 'Input scriptsig not empty')
        assert_cond(tx.vin[0].prevout.hash == b2i(prevout_id) and tx.vin[0].prevout.n == prevout_n, 'Input prevout mismatch')

        assert_cond(len(tx.vout) == 1, 'tx doesn\'t have one output')

        script_pk = CScript([OP_0, hashlib.sha256(script_out).digest()])
        locked_n = findOutput(tx, script_pk)
        assert_cond(locked_n is not None, 'Output not found in tx')
        locked_coin = tx.vout[locked_n].nValue

        # Check script and values
        A, B, csv_val, C = self.extractScriptLockRefundScriptValues(script_out)
        assert_cond(A == self.encodePubkey(Karl), 'Bad script pubkey')
        assert_cond(B == self.encodePubkey(Karf), 'Bad script pubkey')
        assert_cond(csv_val == csv_val_expect, 'Bad script csv value')
        assert_cond(C == self.encodePubkey(Kaf), 'Bad script pubkey')

        fee_paid = swap_value - locked_coin
        assert(fee_paid > 0)

        witness_bytes = len(prevout_script)
        witness_bytes += 73 * 2  # 2 signatures (72 + 1 byts size)
        witness_bytes += 2  # 2 empty witness stack values
        witness_bytes += getCompactSizeLen(witness_bytes)
        vsize = self.getTxVSize(tx, add_witness_bytes=witness_bytes)
        fee_rate_paid = fee_paid * 1000 / vsize

        logging.info('tx amount, vsize, feerate: %ld, %ld, %ld', locked_coin, vsize, fee_rate_paid)

        if not self.compareFeeRates(fee_rate_paid, feerate):
            raise ValueError('Bad fee rate')

        return tx_hash, locked_coin

    def verifyLockRefundSpendTx(self, tx,
                                lock_refund_tx_id, prevout_script,
                                Kal,
                                prevout_value, feerate):
        # Verify:
        #   Must have only one input with correct prevout (n is always 0) and sequence
        #   Must have only one output sending lock refund tx value - fee to leader's address, TODO: follower shouldn't need to verify destination addr
        tx_hash = self.getTxHash(tx)
        logging.info('Verifying lock refund spend tx: {}.'.format(b2h(tx_hash)))

        assert_cond(tx.nVersion == self.txVersion(), 'Bad version')
        assert_cond(tx.nLockTime == 0, 'nLockTime not 0')
        assert_cond(len(tx.vin) == 1, 'tx doesn\'t have one input')

        assert_cond(tx.vin[0].nSequence == 0, 'Bad input nSequence')
        assert_cond(len(tx.vin[0].scriptSig) == 0, 'Input scriptsig not empty')
        assert_cond(tx.vin[0].prevout.hash == b2i(lock_refund_tx_id) and tx.vin[0].prevout.n == 0, 'Input prevout mismatch')

        assert_cond(len(tx.vout) == 1, 'tx doesn\'t have one output')

        p2wpkh = CScript([OP_0, hash160(self.encodePubkey(Kal))])
        locked_n = findOutput(tx, p2wpkh)
        assert_cond(locked_n is not None, 'Output not found in lock refund spend tx')
        tx_value = tx.vout[locked_n].nValue

        fee_paid = prevout_value - tx_value
        assert(fee_paid > 0)

        witness_bytes = len(prevout_script)
        witness_bytes += 73 * 2  # 2 signatures (72 + 1 byts size)
        witness_bytes += 4  # 1 empty, 1 true witness stack values
        witness_bytes += getCompactSizeLen(witness_bytes)
        vsize = self.getTxVSize(tx, add_witness_bytes=witness_bytes)
        fee_rate_paid = fee_paid * 1000 / vsize

        logging.info('tx amount, vsize, feerate: %ld, %ld, %ld', tx_value, vsize, fee_rate_paid)

        if not self.compareFeeRates(fee_rate_paid, feerate):
            raise ValueError('Bad fee rate')

        return True

    def verifyLockSpendTx(self, tx,
                          lock_tx, lock_tx_script,
                          a_pkhash_f, feerate):
        # Verify:
        #   Must have only one input with correct prevout (n is always 0) and sequence
        #   Must have only one output with destination and amount

        tx_hash = self.getTxHash(tx)
        logging.info('Verifying lock spend tx: {}.'.format(b2h(tx_hash)))

        assert_cond(tx.nVersion == self.txVersion(), 'Bad version')
        assert_cond(tx.nLockTime == 0, 'nLockTime not 0')
        assert_cond(len(tx.vin) == 1, 'tx doesn\'t have one input')

        lock_tx_id = self.getTxHash(lock_tx)

        output_script = CScript([OP_0, hashlib.sha256(lock_tx_script).digest()])
        locked_n = findOutput(lock_tx, output_script)
        assert_cond(locked_n is not None, 'Output not found in tx')
        locked_coin = lock_tx.vout[locked_n].nValue

        assert_cond(tx.vin[0].nSequence == 0, 'Bad input nSequence')
        assert_cond(len(tx.vin[0].scriptSig) == 0, 'Input scriptsig not empty')
        assert_cond(tx.vin[0].prevout.hash == b2i(lock_tx_id) and tx.vin[0].prevout.n == locked_n, 'Input prevout mismatch')

        assert_cond(len(tx.vout) == 1, 'tx doesn\'t have one output')
        p2wpkh = CScript([OP_0, a_pkhash_f])
        assert_cond(tx.vout[0].scriptPubKey == p2wpkh, 'Bad output destination')

        fee_paid = locked_coin - tx.vout[0].nValue
        assert(fee_paid > 0)

        witness_bytes = len(lock_tx_script)
        witness_bytes += 33  # sv, size
        witness_bytes += 73 * 2  # 2 signatures (72 + 1 byts size)
        witness_bytes += 4  # 1 empty, 1 true witness stack values
        witness_bytes += getCompactSizeLen(witness_bytes)
        vsize = self.getTxVSize(tx, add_witness_bytes=witness_bytes)
        fee_rate_paid = fee_paid * 1000 / vsize

        logging.info('tx amount, vsize, feerate: %ld, %ld, %ld', tx.vout[0].nValue, vsize, fee_rate_paid)

        if not self.compareFeeRates(fee_rate_paid, feerate):
            raise ValueError('Bad fee rate')

        return True

    def signTx(self, key_int, tx, prevout_n, prevout_script, prevout_value):
        sig_hash = SegwitV0SignatureHash(prevout_script, tx, prevout_n, SIGHASH_ALL, prevout_value)

        eck = ECKey()
        eck.set(i2b(key_int), compressed=True)

        return eck.sign_ecdsa(sig_hash) + b'\x01'  # 0x1 is SIGHASH_ALL

    def signTxOtVES(self, key_sign, key_encrypt, tx, prevout_n, prevout_script, prevout_value):
        sig_hash = SegwitV0SignatureHash(prevout_script, tx, prevout_n, SIGHASH_ALL, prevout_value)
        return otves.EncSign(key_sign, key_encrypt, sig_hash)

    def verifyTxOtVES(self, tx, sig, Ks, Ke, prevout_n, prevout_script, prevout_value):
        sig_hash = SegwitV0SignatureHash(prevout_script, tx, prevout_n, SIGHASH_ALL, prevout_value)
        return otves.EncVrfy(Ks, Ke, sig_hash, sig)

    def decryptOtVES(self, k, esig):
        return otves.DecSig(k, esig) + b'\x01'  # 0x1 is SIGHASH_ALL

    def verifyTxSig(self, tx, sig, K, prevout_n, prevout_script, prevout_value):
        sig_hash = SegwitV0SignatureHash(prevout_script, tx, prevout_n, SIGHASH_ALL, prevout_value)

        ecK = ECPubKey()
        ecK.set_int(K.x(), K.y())
        return ecK.verify_ecdsa(sig[: -1], sig_hash)  # Pop the hashtype byte

    def fundTx(self, tx, feerate):
        feerate_str = format_amount(feerate, self.exp())
        rv = self.rpc_callback('fundrawtransaction', [ToHex(tx), {'feeRate': feerate_str}])
        return FromHex(tx, rv['hex'])

    def signTxWithWallet(self, tx):
        rv = self.rpc_callback('signrawtransactionwithwallet', [ToHex(tx)])

        return FromHex(tx, rv['hex'])

    def publishTx(self, tx):
        return self.rpc_callback('sendrawtransaction', [ToHex(tx)])

    def encodeTx(self, tx):
        return tx.serialize()

    def loadTx(self, tx_bytes):
        # Load tx from bytes to internal representation
        tx = CTransaction()
        tx.deserialize(BytesIO(tx_bytes))
        return tx

    def getTxHash(self, tx):
        tx.rehash()
        return i2b(tx.sha256)

    def getPubkeyHash(self, K):
        return hash160(self.encodePubkey(K))

    def getScriptDest(self, script):
        return CScript([OP_0, hashlib.sha256(script).digest()])

    def getPkDest(self, K):
        return CScript([OP_0, self.getPubkeyHash(K)])

    def scanTxOutset(self, dest):
        return self.rpc_callback('scantxoutset', ['start', ['raw({})'.format(dest.hex())]])

    def getTransaction(self, txid):
        try:
            return self.rpc_callback('getrawtransaction', [txid.hex()])
        except Exception as ex:
            # TODO: filter errors
            return None

    def setTxSignature(self, tx, stack):
        tx.wit.vtxinwit.clear()
        tx.wit.vtxinwit.append(CTxInWitness())
        tx.wit.vtxinwit[0].scriptWitness.stack = stack
        return True

    def extractLeaderSig(self, tx):
        return tx.wit.vtxinwit[0].scriptWitness.stack[1]

    def extractFollowerSig(self, tx):
        return tx.wit.vtxinwit[0].scriptWitness.stack[2]

    def createBLockTx(self, Kbs, output_amount):
        tx = CTransaction()
        tx.nVersion = self.txVersion()
        p2wpkh = self.getPkDest(Kbs)
        tx.vout.append(self.txoType(output_amount, p2wpkh))
        return tx

    def publishBLockTx(self, Kbv, Kbs, output_amount, feerate):
        b_lock_tx = self.createBLockTx(Kbs, output_amount)

        b_lock_tx = self.fundTx(b_lock_tx, feerate)
        b_lock_tx_id = self.getTxHash(b_lock_tx)
        b_lock_tx = self.signTxWithWallet(b_lock_tx)

        return self.publishTx(b_lock_tx)

    def recoverEncKey(self, esig, sig, K):
        return otves.RecoverEncKey(esig, sig[:-1], K)  # Strip sighash type

    def getTxVSize(self, tx, add_bytes=0, add_witness_bytes=0):
        wsf = self.witnessScaleFactor()
        len_full = len(tx.serialize_with_witness()) + add_bytes + add_witness_bytes
        len_nwit = len(tx.serialize_without_witness()) + add_bytes
        weight = len_nwit * (wsf - 1) + len_full
        return (weight + wsf - 1) // wsf

    def findTxB(self, kbv, Kbs, cb_swap_value, cb_block_confirmed, restore_height):
        raw_dest = self.getPkDest(Kbs)

        rv = self.scanTxOutset(raw_dest)
        print('scanTxOutset', dumpj(rv))

        for utxo in rv['unspents']:
            if 'height' in utxo and utxo['height'] > 0 and rv['height'] - utxo['height'] > cb_block_confirmed:
                if utxo['amount'] * COIN != cb_swap_value:
                    logging.warning('Found output to lock tx pubkey of incorrect value: %s', str(utxo['amount']))
                else:
                    return True
        return False

    def waitForLockTxB(self, kbv, Kbs, cb_swap_value, cb_block_confirmed):

        raw_dest = self.getPkDest(Kbs)

        for i in range(20):
            time.sleep(1)
            rv = self.scanTxOutset(raw_dest)
            print('scanTxOutset', dumpj(rv))

            for utxo in rv['unspents']:
                if 'height' in utxo and utxo['height'] > 0 and rv['height'] - utxo['height'] > cb_block_confirmed:

                    if utxo['amount'] * COIN != cb_swap_value:
                        logging.warning('Found output to lock tx pubkey of incorrect value: %s', str(utxo['amount']))
                    else:
                        return True
        return False

    def spendBLockTx(self, address_to, kbv, kbs, cb_swap_value, b_fee, restore_height):
        print('TODO: spendBLockTx')

    def signCompact(self, k, message):
        message_hash = hashlib.sha256(bytes(message, 'utf-8')).digest()
        return sign_ecdsa_compact(i2b(k), message_hash, G)[1:]

    def verifyCompact(self, K, message, sig):
        K_enc = self.encodePubkey(K)
        message_hash = hashlib.sha256(bytes(message, 'utf-8')).digest()
        rv = verify_ecdsa_compact(K_enc, sig, message_hash, G)
        assert(rv is True)


def testBTCInterface():
    print('testBTCInterface')
    script_bytes = bytes.fromhex('6382012088a820aaf125ff9a34a74c7a17f5e7ee9d07d17cc5e53a539f345d5f73baa7e79b65e28852210224019219ad43c47288c937ae508f26998dd81ec066827773db128fd5e262c04f21039a0fd752bd1a2234820707852e7a30253620052ecd162948a06532a817710b5952ae670114b2755221038689deba25c5578e5457ddadbaf8aeb8badf438dc22f540503dbd4ae10e14f512103c9c5d5acc996216d10852a72cd67c701bfd4b9137a4076350fd32f08db39575552ae68')
    i = BTCInterface(None)
    sh, a, b, csv_val, c, d = i.extractLongScriptLockScriptValues(script_bytes)
    assert(csv_val == 20)

    script_bytes_t = script_bytes + bytes((0x00,))
    try:
        sh, a, b, csv_val, c, d = i.extractLongScriptLockScriptValues(script_bytes_t)
        assert(False), 'Should fail'
    except Exception as e:
        assert(str(e) == 'Bad script length')

    script_bytes_t = script_bytes[:-1]
    try:
        sh, a, b, csv_val, c, d = i.extractLongScriptLockScriptValues(script_bytes_t)
        assert(False), 'Should fail'
    except Exception as e:
        assert(str(e) == 'Bad script length')

    script_bytes_t = bytes((0x00,)) + script_bytes[1:]
    try:
        sh, a, b, csv_val, c, d = i.extractLongScriptLockScriptValues(script_bytes_t)
        assert(False), 'Should fail'
    except Exception as e:
        assert(str(e) == 'Bad opcode')

    # Remove the csv value
    script_part_a = script_bytes[:112]
    script_part_b = script_bytes[114:]

    script_bytes_t = script_part_a + bytes((0x00,)) + script_part_b
    sh, a, b, csv_val, c, d = i.extractLongScriptLockScriptValues(script_bytes_t)
    assert(csv_val == 0)

    script_bytes_t = script_part_a + bytes((OP_16,)) + script_part_b
    sh, a, b, csv_val, c, d = i.extractLongScriptLockScriptValues(script_bytes_t)
    assert(csv_val == 16)

    script_bytes_t = script_part_a + CScriptNum.encode(CScriptNum(17)) + script_part_b
    sh, a, b, csv_val, c, d = i.extractLongScriptLockScriptValues(script_bytes_t)
    assert(csv_val == 17)

    script_bytes_t = script_part_a + CScriptNum.encode(CScriptNum(-15)) + script_part_b
    sh, a, b, csv_val, c, d = i.extractLongScriptLockScriptValues(script_bytes_t)
    assert(csv_val == -15)

    script_bytes_t = script_part_a + CScriptNum.encode(CScriptNum(4000)) + script_part_b
    sh, a, b, csv_val, c, d = i.extractLongScriptLockScriptValues(script_bytes_t)
    assert(csv_val == 4000)

    max_pos = 0x7FFFFFFF
    script_bytes_t = script_part_a + CScriptNum.encode(CScriptNum(max_pos)) + script_part_b
    sh, a, b, csv_val, c, d = i.extractLongScriptLockScriptValues(script_bytes_t)
    assert(csv_val == max_pos)
    script_bytes_t = script_part_a + CScriptNum.encode(CScriptNum(max_pos - 1)) + script_part_b
    sh, a, b, csv_val, c, d = i.extractLongScriptLockScriptValues(script_bytes_t)
    assert(csv_val == max_pos - 1)

    script_bytes_t = script_part_a + CScriptNum.encode(CScriptNum(max_pos + 1)) + script_part_b
    try:
        sh, a, b, csv_val, c, d = i.extractLongScriptLockScriptValues(script_bytes_t)
        assert(False), 'Should fail'
    except Exception as e:
        assert(str(e) == 'Bad scriptnum length')

    min_neg = -2147483647
    script_bytes_t = script_part_a + CScriptNum.encode(CScriptNum(min_neg)) + script_part_b
    sh, a, b, csv_val, c, d = i.extractLongScriptLockScriptValues(script_bytes_t)
    assert(csv_val == min_neg)

    script_bytes_t = script_part_a + CScriptNum.encode(CScriptNum(min_neg - 1)) + script_part_b
    try:
        sh, a, b, csv_val, c, d = i.extractLongScriptLockScriptValues(script_bytes_t)
        assert(False), 'Should fail'
    except Exception as e:
        assert(str(e) == 'Bad scriptnum length')

    print('Passed.')


if __name__ == "__main__":
    testBTCInterface()
