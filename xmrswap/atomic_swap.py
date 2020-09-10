#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2020 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

import json
import time
import struct
import hashlib
import logging
from enum import IntEnum

import xmrswap.dleag as dleag
from .rpc import callrpc, callrpc_xmr, callrpc_xmr_na
from .ecc_util import i2h, b2h, i2b, h2b
from .interface import CoinIds
from .interface_btc import BTCInterface
from .interface_part import PARTInterface
from .interface_xmr import XMRInterface


class MsgIds(IntEnum):
    MSG1F = 1  # Initial parameters to follower
    MSG1L = 2  # Initial parameters to leader
    MSG2F = 3
    MSG3L = 4
    MSG4F = 5
    MSG5F = 6  # Secret value allowing follower to spend the coinA lock tx


def make_xmr_rpc_func(port):
    port = port

    def rpc_func(method, params=None, wallet=None):
        nonlocal port
        return callrpc_xmr_na(port, method, params)
    return rpc_func


def make_xmr_wallet_rpc_func(port, auth):
    port = port
    auth = auth

    def rpc_func(method, params=None, wallet=None):
        nonlocal port, auth
        return callrpc_xmr(port, auth, method, params)
    return rpc_func


def make_rpc_func(port, username, password):
    port = port
    auth = '{}:{}'.format(username, password)

    def rpc_func(method, params=None, wallet=None):
        nonlocal port, auth
        return callrpc(port, auth, method, params, wallet)
    return rpc_func


def makeInterface(coin_type, connection_data):
    if coin_type == CoinIds.BTC:
        return BTCInterface(make_rpc_func(connection_data['port'], connection_data['username'], connection_data['password']))
    elif coin_type == CoinIds.PART:
        return PARTInterface(make_rpc_func(connection_data['port'], connection_data['username'], connection_data['password']))
    elif coin_type == CoinIds.XMR:
        return XMRInterface(make_xmr_rpc_func(connection_data['port']),
                            make_xmr_wallet_rpc_func(connection_data['wallet_port'], connection_data['wallet_auth']))
    else:
        raise ValueError('Unknown coin type')


class SwapInfo:
    '''
    ca: chain A - Must support transaction output scripts and non-malleable transactions.
    cb: chain B
    '''
    def __init__(self):
        self.status = 'Unknown'
        self.swap_leader = False
        self.swap_follower = False
        self.ai = None
        self.bi = None

    def desc_self(self):
        if self.swap_leader is True:
            return 'Leader'
        elif self.swap_follower is True:
            return 'Follower'
        return 'Unknown'

    def setSwapParameters(self, coin_a, val_a, coin_b, val_b, fee_rate_a, fee_rate_b, a_pkhash_f,
                          lock1=100, lock2=101, conf_a=1, conf_b=1):
        self.status = 'Unknown'
        self.a_type = coin_a
        self.b_type = coin_b

        self.a_swap_value = val_a
        self.b_swap_value = val_b

        self.a_fee_rate = fee_rate_a
        self.b_fee_rate = fee_rate_b

        self.a_pkhash_f = a_pkhash_f  # Destination for a_swap_value when swap succeeds

        self.lock_time_1 = lock1  # Delay before the chain a lock refund tx can be mined
        self.lock_time_2 = lock2  # Delay before the follower can spend from the chain a lock refund tx

        self.a_block_confirmed = conf_a
        self.b_block_confirmed = conf_b

    def initialiseLeader(self, coin_a_interface, coin_b_interface):
        self.swap_leader = True
        self.ai = coin_a_interface
        self.bi = coin_b_interface

        # The view and spend keys for coin b are the sum of the leader's and follower's keys
        # NOTE: Why split the view key?
        # ks key must be valid for both coins.
        self.kbvl = self.bi.getNewSecretKey()
        self.kbsl = self.bi.getNewSecretKey()
        self.Kbvl = self.bi.pubkey(self.kbvl)
        self.Kbsl = self.bi.pubkey(self.kbsl)

        self.sv = self.ai.getNewSecretValue()
        self.sh = hashlib.sha256(self.sv).digest()

        # kal and kaf must sign to spend from the coinA lock tx
        # karl and karf must sign to spend from the coinA lock tx refund tx
        self.kal = self.ai.getNewSecretKey()
        self.karl = self.ai.getNewSecretKey()
        self.Kal = self.ai.pubkey(self.kal)
        self.Karl = self.ai.pubkey(self.karl)

        self.Kasl = self.ai.pubkey(self.kbsl)

        if self.b_type == CoinIds.XMR:
            logging.info('%s: Generating DLEAG for kbsl...', self.desc_self())
            nonce = self.bi.getNewSecretValue()
            self.kbsl_dleag = dleag.proveDLEAG(self.kbsl, nonce)

    def initialiseFollower(self, coin_a_interface, coin_b_interface):
        self.swap_follower = True
        self.ai = coin_a_interface
        self.bi = coin_b_interface

        # ks key must be valid for both coins.
        self.kbvf = self.bi.getNewSecretKey()
        self.kbsf = self.bi.getNewSecretKey()
        self.Kbvf = self.bi.pubkey(self.kbvf)
        self.Kbsf = self.bi.pubkey(self.kbsf)

        self.kaf = self.ai.getNewSecretKey()
        self.karf = self.ai.getNewSecretKey()
        self.Kaf = self.ai.pubkey(self.kaf)
        self.Karf = self.ai.pubkey(self.karf)

        self.Kasf = self.ai.pubkey(self.kbsf)

        if self.b_type == CoinIds.XMR:
            logging.info('%s: Generating DLEAG for kbsf...', self.desc_self())
            nonce = self.bi.getNewSecretValue()
            self.kbsf_dleag = dleag.proveDLEAG(self.kbsf, nonce)

    def packageInitMsgToFollower(self):
        rv = bytes((MsgIds.MSG1F,))
        rv += i2b(self.kbvl)
        rv += self.ai.encodePubkey(self.Kal)
        rv += self.ai.encodePubkey(self.Karl)
        rv += self.sh

        if self.b_type == CoinIds.XMR:
            rv += struct.pack('>H', len(self.kbsl_dleag))
            rv += self.kbsl_dleag
        else:
            rv += self.bi.encodePubkey(self.Kbsl)
            rv += self.ai.encodePubkey(self.Kasl)
        return rv

    def packageInitMsgToLeader(self):
        rv = bytes((MsgIds.MSG1L,))
        rv += i2b(self.kbvf)
        rv += self.ai.encodePubkey(self.Kaf)
        rv += self.ai.encodePubkey(self.Karf)

        if self.b_type == CoinIds.XMR:
            rv += struct.pack('>H', len(self.kbsf_dleag))
            rv += self.kbsf_dleag
        else:
            rv += self.bi.encodePubkey(self.Kbsf)
            rv += self.ai.encodePubkey(self.Kasf)
        return rv

    def packageMSG2F(self):
        logging.info('%s: packageMSG2F', self.desc_self())
        # Craft the coinA lock and refund txns, sign for the lock refund tx
        assert(self.swap_leader)

        self.a_lock_tx, self.a_lock_tx_script = self.ai.createScriptLockTx(
            self.a_swap_value,
            self.sh,
            self.Kal, self.Kaf,
            self.lock_time_1,
            self.Karl, self.Karf,
        )

        self.a_lock_tx = self.ai.fundTx(self.a_lock_tx, self.a_fee_rate)

        # TODO: Lock a_lock_tx inputs

        self.a_lock_tx_id = self.ai.getTxHash(self.a_lock_tx)
        self.a_lock_tx_dest = self.ai.getScriptDest(self.a_lock_tx_script)

        self.a_lock_refund_tx, self.a_lock_refund_tx_script, self.a_swap_refund_value = self.ai.createScriptLockRefundTx(
            self.a_lock_tx, self.a_lock_tx_script,
            self.Karl, self.Karf,
            self.lock_time_2,
            self.Kaf,
            self.a_fee_rate
        )

        self.al_lock_refund_tx_sig = self.ai.signTx(self.karl, self.a_lock_refund_tx, 0, self.a_lock_tx_script, self.a_swap_value)

        v = self.ai.verifyTxSig(self.a_lock_refund_tx, self.al_lock_refund_tx_sig, self.Karl, 0, self.a_lock_tx_script, self.a_swap_value)
        assert(v)

        # The al_lock_refund_spend_tx_script returns the coinA locked coin to the leader
        # TODO: generate a unique change address
        self.a_lock_refund_spend_tx = self.ai.createScriptLockRefundSpendTx(
            self.a_lock_refund_tx, self.a_lock_refund_tx_script,
            self.Kal,
            self.a_fee_rate
        )
        logging.info('%s: Created chain A transactions\n{}\n{}\n{}'.format(
            'Lock tx:              {}'.format(b2h(self.ai.getTxHash(self.a_lock_tx))),
            'Lock refund tx:       {}'.format(b2h(self.ai.getTxHash(self.a_lock_refund_tx))),
            'Lock refund spend tx: {}'.format(b2h(self.ai.getTxHash(self.a_lock_refund_spend_tx)))),
            self.desc_self())

        # TODO: Transmit the scripts in the witness?

        rv = bytes((MsgIds.MSG2F,))
        a_lock_tx_bytes = self.a_lock_tx.serialize()
        rv += struct.pack('>H', len(a_lock_tx_bytes))
        rv += a_lock_tx_bytes
        rv += struct.pack('>H', len(self.a_lock_tx_script))
        rv += self.a_lock_tx_script

        a_lock_refund_tx_bytes = self.a_lock_refund_tx.serialize()
        rv += struct.pack('>H', len(a_lock_refund_tx_bytes))
        rv += a_lock_refund_tx_bytes
        rv += struct.pack('>H', len(self.a_lock_refund_tx_script))
        rv += self.a_lock_refund_tx_script

        a_lock_refund_spend_tx_bytes = self.a_lock_refund_spend_tx.serialize()
        rv += struct.pack('>H', len(a_lock_refund_spend_tx_bytes))
        rv += a_lock_refund_spend_tx_bytes

        rv += struct.pack('>H', len(self.al_lock_refund_tx_sig))
        rv += self.al_lock_refund_tx_sig

        return rv

    def packageMSG3L(self):
        logging.info('%s: packageMSG3L', self.desc_self())
        assert(self.swap_follower)

        self.af_lock_refund_spend_tx_esig = self.ai.signTxOtVES(self.karf, self.Kasl, self.a_lock_refund_spend_tx, 0, self.a_lock_refund_tx_script, self.a_swap_refund_value)

        self.af_lock_refund_tx_sig = self.ai.signTx(self.karf, self.a_lock_refund_tx, 0, self.a_lock_tx_script, self.a_swap_value)

        rv = bytes((MsgIds.MSG3L,))
        rv += struct.pack('>H', len(self.af_lock_refund_spend_tx_esig))
        rv += self.af_lock_refund_spend_tx_esig

        rv += struct.pack('>H', len(self.af_lock_refund_tx_sig))
        rv += self.af_lock_refund_tx_sig
        return rv

    def packageMSG4F(self):
        logging.info('%s: packageMSG4F', self.desc_self())
        assert(self.swap_leader)

        self.a_lock_spend_tx = self.ai.createScriptLockSpendTx(
            self.a_lock_tx, self.a_lock_tx_script,
            self.a_pkhash_f,
            self.a_fee_rate)

        self.al_lock_spend_tx_esig = self.ai.signTxOtVES(self.kal, self.Kasf, self.a_lock_spend_tx, 0, self.a_lock_tx_script, self.a_swap_value)

        rv = bytes((MsgIds.MSG4F,))
        a_lock_spend_tx_bytes = self.a_lock_spend_tx.serialize()
        rv += struct.pack('>H', len(a_lock_spend_tx_bytes))
        rv += a_lock_spend_tx_bytes

        rv += struct.pack('>H', len(self.al_lock_spend_tx_esig))
        rv += self.al_lock_spend_tx_esig
        return rv

    def packageMSG5F(self):
        logging.info('%s: packageMSG5F', self.desc_self())
        assert(self.swap_leader)

        rv = bytes((MsgIds.MSG5F,))
        rv += struct.pack('>H', len(self.sv))
        rv += self.sv
        return rv

    def processMSG1F(self, msg):
        logging.info('%s: processMSG1F', self.desc_self())
        assert(self.swap_follower)

        o = 1
        self.kbvl = self.bi.decodeKey(msg[o: o + self.bi.nbk()])
        o += self.bi.nbk()
        self.Kal = self.ai.decodePubkey(msg[o: o + self.ai.nbK()])
        o += self.ai.nbK()
        self.Karl = self.ai.decodePubkey(msg[o: o + self.ai.nbK()])
        o += self.ai.nbK()
        self.sh = msg[o: o + self.ai.nbk()]
        o += self.ai.nbk()

        if self.b_type == CoinIds.XMR:
            length = struct.unpack('>H', msg[o: o + 2])[0]
            o += 2
            self.kbsl_dleag = msg[o: o + length]
            o += length

            # Extract pubkeys from DLEAG
            self.Kasl = self.ai.decodePubkey(self.kbsl_dleag[0: 33])
            self.Kbsl = self.bi.decodePubkey(self.kbsl_dleag[33: 33 + 32])
        else:
            self.Kbsl = self.bi.decodePubkey(msg[o: o + self.bi.nbK()])
            o += self.bi.nbK()
            self.Kasl = self.ai.decodePubkey(msg[o: o + self.ai.nbK()])
            o += self.ai.nbK()

        # Get chain B shared keys:
        self.kbv = self.bi.sumKeys(self.kbvl, self.kbvf)
        self.Kbv = self.bi.pubkey(self.kbv)
        self.Kbs = self.bi.sumPubkeys(self.Kbsl, self.Kbsf)

        if self.b_type == CoinIds.XMR:
            logging.info('%s: Verifying DLEAG for kbsl...', self.desc_self())
            valid = dleag.verifyDLEAG(self.kbsl_dleag)
            assert(valid)

    def processMSG1L(self, msg):
        logging.info('%s: processMSG1L', self.desc_self())
        assert(self.swap_leader)

        o = 1
        self.kbvf = self.bi.decodeKey(msg[o: o + self.bi.nbk()])
        o += self.bi.nbk()
        self.Kaf = self.ai.decodePubkey(msg[o: o + self.ai.nbK()])
        o += self.ai.nbK()
        self.Karf = self.ai.decodePubkey(msg[o: o + self.ai.nbK()])
        o += self.ai.nbK()

        if self.b_type == CoinIds.XMR:
            length = struct.unpack('>H', msg[o: o + 2])[0]
            o += 2
            self.kbsf_dleag = msg[o: o + length]
            o += length

            # Extract pubkeys from DLEAG
            self.Kasf = self.ai.decodePubkey(self.kbsf_dleag[0: 33])
            self.Kbsf = self.bi.decodePubkey(self.kbsf_dleag[33: 33 + 32])
        else:
            self.Kbsf = self.bi.decodePubkey(msg[o: o + self.bi.nbK()])
            o += self.bi.nbK()
            self.Kasf = self.ai.decodePubkey(msg[o: o + self.ai.nbK()])
            o += self.ai.nbK()

        # Get chain B shared keys:
        self.kbv = self.bi.sumKeys(self.kbvl, self.kbvf)
        self.Kbv = self.bi.pubkey(self.kbv)
        self.Kbs = self.bi.sumPubkeys(self.Kbsl, self.Kbsf)

        if self.b_type == CoinIds.XMR:
            logging.info('%s: Verifying DLEAG for kbsf...', self.desc_self())
            valid = dleag.verifyDLEAG(self.kbsf_dleag)
            assert(valid)

    def processMSG2F(self, msg):
        logging.info('%s: processMSG2F', self.desc_self())
        assert(self.swap_follower)

        # Unpack and verify three transactions, two scripts and one sig from the leader
        #   a_lock_tx
        #   a_lock_tx_script
        #   a_lock_refund_tx
        #   a_lock_refund_tx_script
        #   a_lock_refund_spend_tx
        #   al_lock_refund_tx_sig

        o = 1
        len_tx = struct.unpack('>H', msg[o: o + 2])[0]
        o += 2
        self.a_lock_tx = self.ai.loadTx(msg[o: o + len_tx])
        o += len_tx
        len_script = struct.unpack('>H', msg[o: o + 2])[0]
        o += 2
        self.a_lock_tx_script = msg[o: o + len_script]
        o += len_script
        len_tx = struct.unpack('>H', msg[o: o + 2])[0]
        o += 2
        self.a_lock_refund_tx = self.ai.loadTx(msg[o: o + len_tx])
        o += len_tx
        len_script = struct.unpack('>H', msg[o: o + 2])[0]
        o += 2
        self.a_lock_refund_tx_script = msg[o: o + len_script]
        o += len_script
        len_tx = struct.unpack('>H', msg[o: o + 2])[0]
        o += 2
        self.a_lock_refund_spend_tx = self.ai.loadTx(msg[o: o + len_tx])
        o += len_tx
        len_sig = struct.unpack('>H', msg[o: o + 2])[0]
        o += 2
        self.al_lock_refund_tx_sig = msg[o: o + len_sig]
        o += len_sig

        self.a_lock_tx_id, lock_tx_vout = self.ai.verifyLockTx(
            self.a_lock_tx, self.a_lock_tx_script,
            self.a_swap_value,
            self.sh,
            self.Kal, self.Kaf,
            self.lock_time_1, self.a_fee_rate,
            self.Karl, self.Karf,
        )
        self.a_lock_tx_dest = self.ai.getScriptDest(self.a_lock_tx_script)

        lock_refund_tx_id, self.a_swap_refund_value = self.ai.verifyLockRefundTx(
            self.a_lock_refund_tx, self.a_lock_refund_tx_script,
            self.a_lock_tx_id, lock_tx_vout, self.lock_time_1, self.a_lock_tx_script,
            self.Karl, self.Karf,
            self.lock_time_2,
            self.Kaf,
            self.a_swap_value, self.a_fee_rate
        )

        self.ai.verifyLockRefundSpendTx(
            self.a_lock_refund_spend_tx,
            lock_refund_tx_id, self.a_lock_refund_tx_script,
            self.Kal,
            self.a_swap_refund_value, self.a_fee_rate
        )

        logging.info('Checking leader\'s lock refund tx signature')
        v = self.ai.verifyTxSig(self.a_lock_refund_tx, self.al_lock_refund_tx_sig, self.Karl, 0, self.a_lock_tx_script, self.a_swap_value)
        assert(v)

    def processMSG3L(self, msg):
        logging.info('%s: processMSG3L', self.desc_self())
        assert(self.swap_leader)

        o = 1
        len_esig = struct.unpack('>H', msg[o: o + 2])[0]
        o += 2
        self.af_lock_refund_spend_tx_esig = msg[o: o + len_esig]
        o += len_esig
        len_sig = struct.unpack('>H', msg[o: o + 2])[0]
        o += 2
        self.af_lock_refund_tx_sig = msg[o: o + len_sig]

        v = self.ai.verifyTxOtVES(
            self.a_lock_refund_spend_tx, self.af_lock_refund_spend_tx_esig,
            self.Karf, self.Kasl, 0, self.a_lock_refund_tx_script, self.a_swap_refund_value)
        assert(v)
        logging.info('Verified follower\'s encrypted signature for the lock refund spend tx.')

        v = self.ai.verifyTxSig(
            self.a_lock_refund_tx, self.af_lock_refund_tx_sig,
            self.Karf, 0, self.a_lock_tx_script, self.a_swap_value)
        assert(v)
        logging.info('Verified follower\'s signature for the lock refund tx.')

    def processMSG4F(self, msg):
        logging.info('%s: processMSG4F', self.desc_self())
        assert(self.swap_follower)

        o = 1
        len_tx = struct.unpack('>H', msg[o: o + 2])[0]
        o += 2
        self.a_lock_spend_tx = self.ai.loadTx(msg[o: o + len_tx])
        o += len_tx
        len_esig = struct.unpack('>H', msg[o: o + 2])[0]
        o += 2
        self.al_lock_spend_tx_esig = msg[o: o + len_esig]

        self.ai.verifyLockSpendTx(
            self.a_lock_spend_tx,
            self.a_lock_tx, self.a_lock_tx_script,
            self.a_pkhash_f, self.a_fee_rate)

        v = self.ai.verifyTxOtVES(
            self.a_lock_spend_tx, self.al_lock_spend_tx_esig,
            self.Kal, self.Kasf, 0, self.a_lock_tx_script, self.a_swap_value)
        assert(v)
        logging.info('Verified leader\'s encrypted signature for the lock spend tx.')

    def processMSG5F(self, msg):
        logging.info('%s: processMSG4F', self.desc_self())
        assert(self.swap_follower)

        o = 1
        len_sv = struct.unpack('>H', msg[o: o + 2])[0]
        o += 2
        assert(len_sv == 32)
        self.sv = msg[o: o + len_sv]

    def processMessage(self, msg):
        if len(msg) < 1:
            raise ValueError('Bad message length')
        msg_id = msg[0]
        if msg_id == MsgIds.MSG1F:
            self.processMSG1F(msg)
        elif msg_id == MsgIds.MSG1L:
            self.processMSG1L(msg)
        elif msg_id == MsgIds.MSG2F:
            self.processMSG2F(msg)
        elif msg_id == MsgIds.MSG3L:
            self.processMSG3L(msg)
        elif msg_id == MsgIds.MSG4F:
            self.processMSG4F(msg)
        elif msg_id == MsgIds.MSG5F:
            self.processMSG5F(msg)
        else:
            raise ValueError('Unknown message type')

    def publishALockTx(self):
        assert(self.swap_leader)
        lock_tx_signed = self.ai.signTxWithWallet(self.a_lock_tx)
        return self.ai.publishTx(lock_tx_signed)

    def publishALockRefundTx(self):
        witness_stack = [
            b'',
            self.al_lock_refund_tx_sig,
            self.af_lock_refund_tx_sig,
            b'',
            self.a_lock_tx_script,
        ]

        v = self.ai.setTxSignature(self.a_lock_refund_tx, witness_stack)
        assert(v)

        return self.ai.publishTx(self.a_lock_refund_tx)

    def waitForLockTxA(self):
        # Blocking
        logging.info('%s: Waiting for tx %s to confirm.', self.desc_self(), self.a_lock_tx_id.hex())
        return self.waitForTxA(self.a_lock_tx_id, self.a_lock_tx_dest)

    def hasALockTxConfirmed(self):
        return self.waitForTxA(self.a_lock_tx_id, self.a_lock_tx_dest, retry=0)

    def waitForTxA(self, txid, dest, retry=20):
        txid_hex = txid.hex()
        for i in range(1 + retry):
            rv = self.ai.scanTxOutset(dest)

            for utxo in rv['unspents']:
                # Check the utxo txid matches the expected txid
                if utxo['txid'] == txid_hex:
                    if 'height' in utxo and utxo['height'] > 0 and rv['height'] - utxo['height'] > self.a_block_confirmed:
                        return True
            time.sleep(1)
        return False

    def publishBLockTx(self):
        assert(self.swap_follower)

        self.b_lock_tx_id = self.bi.publishBLockTx(self.Kbv, self.Kbs, self.b_swap_value, self.b_fee_rate)

        return self.b_lock_tx_id

    def waitForLockTxB(self):
        # Blocking
        return self.bi.waitForLockTxB(self.kbv, self.Kbs, self.b_swap_value, self.b_block_confirmed)

    def hasBLockTxConfirmed(self):
        return self.bi.findTxB(self.kbv, self.Kbs, self.b_swap_value, self.b_block_confirmed)

    def publishALockSpendTx(self):
        assert(self.swap_follower)
        logging.info('%s: Signing script lock spend tx.', self.desc_self())

        self.al_lock_spend_sig = self.ai.decryptOtVES(self.kbsf, self.al_lock_spend_tx_esig)

        v = self.ai.verifyTxSig(self.a_lock_spend_tx, self.al_lock_spend_sig, self.Kal, 0, self.a_lock_tx_script, self.a_swap_value)
        assert(v)

        self.af_lock_spend_sig = self.ai.signTx(self.kaf, self.a_lock_spend_tx, 0, self.a_lock_tx_script, self.a_swap_value)

        v = self.ai.verifyTxSig(self.a_lock_spend_tx, self.af_lock_spend_sig, self.Kaf, 0, self.a_lock_tx_script, self.a_swap_value)
        assert(v)

        witness_stack = [
            b'',
            self.al_lock_spend_sig,
            self.af_lock_spend_sig,
            self.sv,
            bytes((1,)),
            self.a_lock_tx_script,
        ]

        v = self.ai.setTxSignature(self.a_lock_spend_tx, witness_stack)
        assert(v)

        return self.ai.publishTx(self.a_lock_spend_tx)

    def waitForLockSpendTx(self):
        assert(self.swap_leader)

        spend_txid = self.ai.getTxHash(self.a_lock_spend_tx)
        for i in range(20):
            time.sleep(1)
            rv = self.ai.getTransaction(spend_txid)
            if rv is not None:
                self.a_lock_spend_tx = self.ai.loadTx(h2b(rv))
                return True
        return False

    def findALockSpendTx(self):
        assert(self.swap_leader)
        spend_txid = self.ai.getTxHash(self.a_lock_spend_tx)
        rv = self.ai.getTransaction(spend_txid)
        if rv is not None:
            self.a_lock_spend_tx = self.ai.loadTx(h2b(rv))
            return True
        return False

    def findALockRefundSpendTx(self):
        assert(self.swap_follower)
        spend_txid = self.ai.getTxHash(self.a_lock_refund_spend_tx)
        rv = self.ai.getTransaction(spend_txid)
        if rv is not None:
            self.a_lock_refund_spend_tx = self.ai.loadTx(h2b(rv))
            return True
        return False

    def redeemBLockTx(self, address_to):

        if self.swap_leader:
            # Extract the leader's decrypted signature and use it to recover the follower's privatekey
            self.al_lock_spend_tx_sig = self.ai.extractLeaderSig(self.a_lock_spend_tx)

            self.kbsf = self.ai.recoverEncKey(self.al_lock_spend_tx_esig, self.al_lock_spend_tx_sig, self.Kasf)
            assert(self.kbsf is not None)
        else:
            # Extract the follower's decrypted signature and use it to recover the leader's privatekey
            self.af_lock_refund_spend_tx_sig = self.ai.extractFollowerSig(self.a_lock_refund_spend_tx)

            self.kbsl = self.ai.recoverEncKey(self.af_lock_refund_spend_tx_esig, self.af_lock_refund_spend_tx_sig, self.Kasl)
            assert(self.kbsl is not None)

        self.kbs = self.bi.sumKeys(self.kbsl, self.kbsf)
        Kbs_test = self.bi.pubkey(self.kbs)
        print('Kbs_test', self.bi.encodePubkey(Kbs_test).hex())
        print('Kbs', self.bi.encodePubkey(self.Kbs).hex())

        return self.bi.spendBLockTx(address_to, self.kbv, self.kbs, self.b_swap_value, self.b_fee_rate)

    def publishALockRefundSpendTx(self):
        assert(self.swap_leader)

        self.af_lock_refund_spend_tx_sig = self.ai.decryptOtVES(self.kbsl, self.af_lock_refund_spend_tx_esig)

        v = self.ai.verifyTxSig(self.a_lock_refund_spend_tx, self.af_lock_refund_spend_tx_sig, self.Karf, 0, self.a_lock_refund_tx_script, self.a_swap_refund_value)
        assert(v)

        self.al_lock_refund_spend_tx_sig = self.ai.signTx(self.karl, self.a_lock_refund_spend_tx, 0, self.a_lock_refund_tx_script, self.a_swap_refund_value)

        witness_stack = [
            b'',
            self.al_lock_refund_spend_tx_sig,
            self.af_lock_refund_spend_tx_sig,
            bytes((1,)),
            self.a_lock_refund_tx_script,
        ]

        v = self.ai.setTxSignature(self.a_lock_refund_spend_tx, witness_stack)
        assert(v)

        return self.ai.publishTx(self.a_lock_refund_spend_tx)

    def publishALockRefundSpendToFTx(self, pkh_dest):
        assert(self.swap_follower)

        spend_tx = self.ai.createScriptLockRefundSpendToFTx(
            self.a_lock_refund_tx, self.a_lock_refund_tx_script,
            pkh_dest,
            self.a_fee_rate
        )

        sig = self.ai.signTx(self.kaf, spend_tx, 0, self.a_lock_refund_tx_script, self.a_swap_refund_value)

        witness_stack = [
            sig,
            b'',
            self.a_lock_refund_tx_script,
        ]

        v = self.ai.setTxSignature(spend_tx, witness_stack)
        assert(v)

        return self.ai.publishTx(spend_tx)

    def putattr(self, jso, name):
        try:
            jso[name] = getattr(self, name)
        except Exception:
            pass

    def putbytes(self, jso, name):
        try:
            jso[name] = b2h(getattr(self, name))
        except Exception:
            pass

    def putk(self, jso, i, name):
        try:
            jso[name] = i2h(getattr(self, name))
        except Exception:
            pass

    def putK(self, jso, i, name):
        try:
            jso[name] = b2h(i.encodePubkey(getattr(self, name)))
        except Exception:
            pass

    def puttx(self, jso, i, name):
        try:
            jso[name] = b2h(i.encodeTx(getattr(self, name)))
        except Exception:
            pass

    def exportToFile(self, file_path):
        logging.info('Exporting to: %s', file_path)
        jso = {
            'status': self.status,
            'swap_leader': self.swap_leader,
            'swap_follower': self.swap_follower,
        }

        self.putattr(jso, 'a_connect')
        self.putattr(jso, 'b_connect')

        self.putattr(jso, 'a_type')
        self.putattr(jso, 'b_type')

        self.putattr(jso, 'a_swap_value')
        self.putattr(jso, 'b_swap_value')

        self.putattr(jso, 'a_fee_rate')
        self.putattr(jso, 'b_fee_rate')

        self.putbytes(jso, 'a_pkhash_f')

        self.putattr(jso, 'lock_time_1')
        self.putattr(jso, 'lock_time_2')

        self.putattr(jso, 'a_block_confirmed')
        self.putattr(jso, 'b_block_confirmed')

        if self.ai is None or self.bi is None:
            return

        self.putk(jso, self.bi, 'kbvl')
        self.putk(jso, self.bi, 'kbsl')
        self.putK(jso, self.bi, 'Kbvl')
        self.putK(jso, self.bi, 'Kbsl')

        self.putbytes(jso, 'sv')
        self.putbytes(jso, 'sh')

        self.putk(jso, self.ai, 'kal')
        self.putk(jso, self.ai, 'karl')
        self.putK(jso, self.ai, 'Kal')
        self.putK(jso, self.ai, 'Karl')
        self.putK(jso, self.ai, 'Kasl')

        self.putk(jso, self.bi, 'kbvf')
        self.putk(jso, self.bi, 'kbsf')
        self.putK(jso, self.bi, 'Kbvf')
        self.putK(jso, self.bi, 'Kbsf')

        self.putk(jso, self.ai, 'kaf')
        self.putk(jso, self.ai, 'karf')
        self.putK(jso, self.ai, 'Kaf')
        self.putK(jso, self.ai, 'Karf')
        self.putK(jso, self.ai, 'Kasf')

        self.putbytes(jso, 'kbsl_dleag')
        self.putbytes(jso, 'kbsf_dleag')

        # msg2f
        self.puttx(jso, self.ai, 'a_lock_tx')
        self.puttx(jso, self.ai, 'a_lock_refund_tx')
        self.puttx(jso, self.ai, 'a_lock_refund_spend_tx')
        self.putbytes(jso, 'a_lock_tx_script')
        self.putbytes(jso, 'a_lock_refund_tx_script')
        self.putbytes(jso, 'al_lock_refund_tx_sig')

        # msg3l
        self.putbytes(jso, 'af_lock_refund_spend_tx_esig')
        self.putbytes(jso, 'af_lock_refund_tx_sig')

        # msg4f
        self.puttx(jso, self.ai, 'a_lock_spend_tx')
        self.putbytes(jso, 'al_lock_spend_tx_esig')

        with open(file_path, 'w') as fp:
            json.dump(jso, fp, indent=4)

    def loadattr(self, jsi, name):
        if name in jsi:
            setattr(self, name, jsi[name])

    def loadbytes(self, jsi, name):
        if name in jsi:
            setattr(self, name, h2b(jsi[name]))

    def loadk(self, jsi, i, name):
        if name in jsi:
            setattr(self, name, i.decodeKey(h2b(jsi[name])))

    def loadK(self, jsi, i, name):
        if name in jsi:
            setattr(self, name, i.decodePubkey(h2b(jsi[name])))

    def loadtx(self, jsi, i, name):
        if name in jsi:
            setattr(self, name, i.loadTx(h2b(jsi[name])))

    def importFromFile(self, file_path):
        logging.info('Importing from: %s', file_path)

        with open(file_path) as fp:
            jsi = json.load(fp)

        self.loadattr(jsi, 'status')
        self.loadattr(jsi, 'swap_leader')
        self.loadattr(jsi, 'swap_follower')

        self.loadattr(jsi, 'a_connect')
        self.loadattr(jsi, 'b_connect')

        if 'a_type' in jsi:
            self.a_type = CoinIds(jsi['a_type'])
        if 'b_type' in jsi:
            self.b_type = CoinIds(jsi['b_type'])

        self.loadattr(jsi, 'a_swap_value')
        self.loadattr(jsi, 'b_swap_value')

        self.loadattr(jsi, 'a_fee_rate')
        self.loadattr(jsi, 'b_fee_rate')

        self.loadbytes(jsi, 'a_pkhash_f')

        self.loadattr(jsi, 'lock_time_1')
        self.loadattr(jsi, 'lock_time_2')

        self.loadattr(jsi, 'a_block_confirmed')
        self.loadattr(jsi, 'b_block_confirmed')

        try:
            self.ai = makeInterface(self.a_type, self.a_connect)
        except Exception as e:
            print(str(e))

        try:
            self.bi = makeInterface(self.b_type, self.b_connect)
        except Exception as e:
            print(str(e))
            pass

        if self.ai is None or self.bi is None:
            return

        self.loadk(jsi, self.bi, 'kbvl')
        self.loadk(jsi, self.bi, 'kbsl')
        self.loadK(jsi, self.bi, 'Kbvl')
        self.loadK(jsi, self.bi, 'Kbsl')

        self.loadbytes(jsi, 'sv')
        self.loadbytes(jsi, 'sh')

        self.loadk(jsi, self.ai, 'kal')
        self.loadk(jsi, self.ai, 'karl')
        self.loadK(jsi, self.ai, 'Kal')
        self.loadK(jsi, self.ai, 'Karl')
        self.loadK(jsi, self.ai, 'Kasl')

        self.loadk(jsi, self.bi, 'kbvf')
        self.loadk(jsi, self.bi, 'kbsf')
        self.loadK(jsi, self.bi, 'Kbvf')
        self.loadK(jsi, self.bi, 'Kbsf')

        self.loadk(jsi, self.ai, 'kaf')
        self.loadk(jsi, self.ai, 'karf')
        self.loadK(jsi, self.ai, 'Kaf')
        self.loadK(jsi, self.ai, 'Karf')
        self.loadK(jsi, self.ai, 'Kasf')

        self.loadbytes(jsi, 'kbsl_dleag')
        self.loadbytes(jsi, 'kbsf_dleag')

        if hasattr(self, 'kbvl') and hasattr(self, 'kbvf'):
            self.kbv = self.bi.sumKeys(self.kbvl, self.kbvf)
            self.Kbv = self.bi.pubkey(self.kbv)

        if hasattr(self, 'Kbsl') and hasattr(self, 'Kbsf'):
            self.Kbs = self.bi.sumPubkeys(self.Kbsl, self.Kbsf)

        # msg2f
        self.loadtx(jsi, self.ai, 'a_lock_tx')
        self.loadtx(jsi, self.ai, 'a_lock_refund_tx')
        self.loadtx(jsi, self.ai, 'a_lock_refund_spend_tx')
        self.loadbytes(jsi, 'a_lock_tx_script')
        self.loadbytes(jsi, 'a_lock_refund_tx_script')
        self.loadbytes(jsi, 'al_lock_refund_tx_sig')

        if hasattr(self, 'a_lock_tx'):
            self.a_lock_tx_id = self.ai.getTxHash(self.a_lock_tx)
        if hasattr(self, 'a_lock_tx_script'):
            self.a_lock_tx_dest = self.ai.getScriptDest(self.a_lock_tx_script)
        if hasattr(self, 'a_lock_refund_tx'):
            self.a_swap_refund_value = self.ai.getTxOutputValue(self.a_lock_refund_tx)

        # msg3l
        self.loadbytes(jsi, 'af_lock_refund_spend_tx_esig')
        self.loadbytes(jsi, 'af_lock_refund_tx_sig')

        # msg4f
        self.loadtx(jsi, self.ai, 'a_lock_spend_tx')
        self.loadbytes(jsi, 'al_lock_spend_tx_esig')
