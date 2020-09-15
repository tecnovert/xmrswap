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
        self.rpc_cb = rpc_cb  # Not essential
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

    def findTxB(self, kbv, Kbs, cb_swap_value, cb_block_confirmed, restore_height):
        Kbv_enc = self.encodePubkey(self.pubkey(kbv))
        address_b58 = xmr_util.encode_address(Kbv_enc, self.encodePubkey(Kbs))

        try:
            self.rpc_wallet_cb('close_wallet')
        except Exception as e:
            logging.warning('close_wallet failed %s', str(e))

        params = {
            'restore_height': restore_height,
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
        try:
            current_height = self.rpc_cb('get_block_count')['count']
            logging.info('findTxB XMR current_height %d\nAddress: %s', current_height, address_b58)
        except Exception as e:
            logging.info('rpc_cb failed %s', str(e))
            current_height = None  # If the transfer is available it will be deep enough

        # For a while after opening the wallet rpc cmds return empty data
        for i in range(5):
            params = {'transfer_type': 'available'}
            rv = self.rpc_wallet_cb('incoming_transfers', params)
            if 'transfers' in rv:
                for transfer in rv['transfers']:
                    if transfer['amount'] == cb_swap_value \
                       and (current_height is None or current_height - transfer['block_height'] > cb_block_confirmed):
                        return True
            time.sleep(1 + i)

        return False

    def waitForLockTxB(self, kbv, Kbs, cb_swap_value, cb_block_confirmed, restore_height):

        Kbv_enc = self.encodePubkey(self.pubkey(kbv))
        address_b58 = xmr_util.encode_address(Kbv_enc, self.encodePubkey(Kbs))

        try:
            self.rpc_wallet_cb('close_wallet')
        except Exception as e:
            logging.warning('close_wallet failed %s', str(e))

        params = {
            'filename': address_b58,
            'address': address_b58,
            'viewkey': b2h(intToBytes32_le(kbv)),
            'restore_height': restore_height,
        }
        self.rpc_wallet_cb('generate_from_keys', params)

        self.rpc_wallet_cb('open_wallet', {'filename': address_b58})
        # For a while after opening the wallet rpc cmds return empty data

        num_tries = 40
        for i in range(num_tries + 1):
            try:
                current_height = self.rpc_cb('get_block_count')['count']
                print('current_height', current_height)
            except Exception as e:
                logging.warning('rpc_cb failed %s', str(e))
                current_height = None  # If the transfer is available it will be deep enough

            # TODO: Make accepting current_height == None a user selectable option
            #       Or look for all transfers and check height

            params = {'transfer_type': 'available'}
            rv = self.rpc_wallet_cb('incoming_transfers', params)
            print('rv', rv)

            if 'transfers' in rv:
                for transfer in rv['transfers']:
                    if transfer['amount'] == cb_swap_value \
                       and (current_height is None or current_height - transfer['block_height'] > cb_block_confirmed):
                        return True

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

    def spendBLockTx(self, address_to, kbv, kbs, cb_swap_value, b_fee_rate, restore_height):

        Kbv_enc = self.encodePubkey(self.pubkey(kbv))
        Kbs_enc = self.encodePubkey(self.pubkey(kbs))
        address_b58 = xmr_util.encode_address(Kbv_enc, Kbs_enc)

        try:
            self.rpc_wallet_cb('close_wallet')
        except Exception as e:
            logging.warning('close_wallet failed %s', str(e))

        wallet_filename = address_b58 + '_spend'

        params = {
            'filename': wallet_filename,
            'address': address_b58,
            'viewkey': b2h(intToBytes32_le(kbv)),
            'spendkey': b2h(intToBytes32_le(kbs)),
            'restore_height': restore_height,
        }

        try:
            self.rpc_wallet_cb('open_wallet', {'filename': wallet_filename})
        except Exception as e:
            rv = self.rpc_wallet_cb('generate_from_keys', params)
            logging.info('generate_from_keys %s', dumpj(rv))
            self.rpc_wallet_cb('open_wallet', {'filename': wallet_filename})

        # For a while after opening the wallet rpc cmds return empty data
        for i in range(10):
            rv = self.rpc_wallet_cb('get_balance')
            print('get_balance', rv)
            if rv['balance'] >= cb_swap_value:
                break

            time.sleep(1 + i)

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
            if i >= num_tries:
                raise ValueError('transfer failed.')
            b_fee += b_fee_rate
            logging.info('Raising fee to %d', b_fee)

        return rv['tx_hash']
