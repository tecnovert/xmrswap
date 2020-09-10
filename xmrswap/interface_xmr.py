#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2020 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

import time
import logging

import xmrswap.ed25519_fast_util as edu
import xmrswap.contrib.ed25519_fast as edf

import xmrswap.xmr_util as xmr_util

from .util import (
    dumpj
)

from .ecc_util import (
    b2h, b2i, intToBytes32_le)

from .interface import CoinInterface


XMR_COIN = 10 ** 12


class XMRInterface(CoinInterface):
    @staticmethod
    def exp():
        return 12

    @staticmethod
    def nbk():
        return 32

    @staticmethod
    def nbK():  # No. of bytes requires to encode a public key
        return 32

    def __init__(self, rpc_cb, rpc_wallet_cb):
        self.rpc_cb = rpc_cb
        self.rpc_wallet_cb = rpc_wallet_cb

    def getNewSecretKey(self):
        return edu.get_secret()

    def pubkey(self, key):
        return edf.scalarmult_B(key)

    def encodePubkey(self, pk):
        return edu.encodepoint(pk)

    def decodePubkey(self, pke):
        return edf.decodepoint(pke)

    def decodeKey(self, k):
        i = b2i(k)
        assert(i < edf.l and i > 8)
        return i

    def sumKeys(self, ka, kb):
        return (ka + kb) % edf.l

    def sumPubkeys(self, Ka, Kb):
        return edf.edwards_add(Ka, Kb)

    def publishBLockTx(self, Kbv, Kbs, output_amount, feerate):

        shared_addr = xmr_util.encode_address(self.encodePubkey(Kbv), self.encodePubkey(Kbs))

        # TODO: How to set feerate?
        params = {'destinations': [{'amount': output_amount, 'address': shared_addr}]}
        rv = self.rpc_wallet_cb('transfer', params)
        logging.info('publishBLockTx %s to address_b58 %s', rv['tx_hash'], shared_addr)

        return rv['tx_hash']

    def findTxB(self, kbv, Kbs, cb_swap_value, cb_block_confirmed):
        Kbv_enc = self.encodePubkey(self.pubkey(kbv))
        address_b58 = xmr_util.encode_address(Kbv_enc, self.encodePubkey(Kbs))

        rv = self.rpc_wallet_cb('close_wallet')

        params = {
            'filename': address_b58,
            'address': address_b58,
            'viewkey': b2h(intToBytes32_le(kbv)),
        }

        try:
            rv = self.rpc_wallet_cb('open_wallet', {'filename': address_b58})
        except Exception as e:
            rv = self.rpc_wallet_cb('generate_from_keys', params)
            logging.info('generate_from_keys %s', dumpj(rv))
            rv = self.rpc_wallet_cb('open_wallet', {'filename': address_b58})

        # Debug
        current_height = self.rpc_cb('get_block_count')['count']
        logging.info('findTxB XMR current_height %d\nAddress: %s', current_height, address_b58)

        # TODO: Why is rescan necessary?
        self.rpc_wallet_cb('rescan_blockchain')

        params = {'transfer_type': 'available'}
        rv = self.rpc_wallet_cb('incoming_transfers', params)
        if 'transfers' in rv:
            for transfer in rv['transfers']:
                if transfer['amount'] == cb_swap_value and current_height - transfer['block_height'] > cb_block_confirmed:
                    return True

        return False

    def waitForLockTxB(self, kbv, Kbs, cb_swap_value, cb_block_confirmed):

        Kbv_enc = self.encodePubkey(self.pubkey(kbv))
        address_b58 = xmr_util.encode_address(Kbv_enc, self.encodePubkey(Kbs))

        rv = self.rpc_wallet_cb('close_wallet')
        print('close_wallet', rv)

        params = {
            'filename': address_b58,
            'address': address_b58,
            'viewkey': b2h(intToBytes32_le(kbv)),
        }
        self.rpc_wallet_cb('generate_from_keys', params)

        self.rpc_wallet_cb('open_wallet', {'filename': address_b58})

        num_tries = 40
        for i in range(num_tries + 1):
            current_height = self.rpc_cb('get_block_count')['count']
            print('current_height', current_height)
            params = {'transfer_type': 'available'}
            rv = self.rpc_wallet_cb('incoming_transfers', params)
            print('rv', rv)
            if 'transfers' in rv:
                for transfer in rv['transfers']:
                    if transfer['amount'] == cb_swap_value and current_height - transfer['block_height'] > cb_block_confirmed:
                        return True

            # TODO: Why is rescan necessary?
            self.rpc_wallet_cb('rescan_blockchain')

            # TODO: Is it necessary to check the address?

            '''
            rv = self.rpc_wallet_cb('get_balance')
            print('get_balance', rv)

            if 'per_subaddress' in rv:
                for sub_addr in rv['per_subaddress']:
                    if sub_addr['address'] == address_b58:

            '''

            if i >= num_tries:
                raise ValueError('Balance not confirming on node')
            time.sleep(1)

        return False

    def spendBLockTx(self, address_to, kbv, kbs, cb_swap_value, b_fee_rate):

        Kbv_enc = self.encodePubkey(self.pubkey(kbv))
        Kbs_enc = self.encodePubkey(self.pubkey(kbs))
        address_b58 = xmr_util.encode_address(Kbv_enc, Kbs_enc)

        self.rpc_wallet_cb('close_wallet')

        wallet_filename = address_b58 + '_spend'

        params = {
            'filename': wallet_filename,
            'address': address_b58,
            'viewkey': b2h(intToBytes32_le(kbv)),
            'spendkey': b2h(intToBytes32_le(kbs)),
        }
        self.rpc_wallet_cb('generate_from_keys', params)
        self.rpc_wallet_cb('open_wallet', {'filename': wallet_filename})

        self.rpc_wallet_cb('rescan_blockchain')

        # Debug
        rv = self.rpc_wallet_cb('get_balance')
        print('get_balance', rv)

        # TODO: need a subfee from output option
        b_fee = b_fee_rate * 10  # Guess

        num_tries = 20
        for i in range(1 + num_tries):
            try:
                params = {'destinations': [{'amount': cb_swap_value - b_fee, 'address': address_to}]}
                rv = self.rpc_wallet_cb('transfer', params)
                print('transfer', rv)
                break
            except Exception as e:
                print('str(e)', str(e))
                pass
            if i >= num_tries:
                raise ValueError('transfer failed.')
            b_fee += b_fee_rate
            logging.info('Raising fee to %d', b_fee)

        return rv['tx_hash']
