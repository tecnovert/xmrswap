#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2020 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

import os
import time
import shutil
import logging
import unittest
import threading

from xmrswap.rpc import waitForRPC, callrpc_xmr, callrpc_xmr_na
from xmrswap.util import dumpj, make_int
from xmrswap.ecc_util import h2b
from xmrswap.interface_xmr import XMR_COIN

from xmrswap.contrib.test_framework import segwit_addr
from xmrswap.contrib.test_framework.wallet_util import bytes_to_wif

from tests.xmrswap.common import (
    TEST_DATADIRS,
    BITCOIN_BINDIR, BITCOIND,
    XMR_BINDIR, XMRD, XMR_WALLET_RPC,
    NUM_NODES,
    BASE_RPC_PORT,
    XMR_NUM_NODES,
    XMR_BASE_RPC_PORT, XMR_BASE_WALLET_RPC_PORT,
    prepareXmrDataDir, prepareDataDir,
    startXmrDaemon, startXmrWalletRPC,
    startDaemon, callnoderpc, make_rpc_func,
    checkSoftForks, stopNodes, callSwapTool
)

TEST_DIR = os.path.join(TEST_DATADIRS, 'btc')
logger = logging.getLogger()

ID_ALICE_XMR = 1
ID_BOB_XMR = 2
ID_ALICE_BTC = 1
ID_BOB_BTC = 2


def run_loop(cls):
    while not cls.stop_nodes:
        if cls.btc_addr is not None:
            callnoderpc(0, 'generatetoaddress', [1, cls.btc_addr])

        if cls.xmr_addr is not None:
            callrpc_xmr_na(XMR_BASE_RPC_PORT + 0, 'generateblocks', {'wallet_address': cls.xmr_addr, 'amount_of_blocks': 1})
        time.sleep(0.5)


class Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stop_nodes = False
        cls.update_thread = None
        cls.daemons = []
        cls.xmr_daemons = []
        cls.xmr_wallet_auth = []

        cls.btc_addr = None
        cls.xmr_addr = None

        super(Test, cls).setUpClass()

        logger.propagate = False
        logger.handlers = []
        logger.setLevel(logging.INFO)  # DEBUG shows many messages from requests.post
        formatter = logging.Formatter('%(asctime)s %(levelname)s : %(message)s')
        stream_stdout = logging.StreamHandler()
        stream_stdout.setFormatter(formatter)
        logger.addHandler(stream_stdout)

        if os.path.isdir(TEST_DIR):
            logging.info('Removing ' + TEST_DIR)
            shutil.rmtree(TEST_DIR)
        if not os.path.exists(TEST_DIR):
            os.makedirs(TEST_DIR)

        cls.stream_fp = logging.FileHandler(os.path.join(TEST_DIR, 'test.log'))
        cls.stream_fp.setFormatter(formatter)
        logger.addHandler(cls.stream_fp)

        for i in range(NUM_NODES):
            prepareDataDir(TEST_DIR, i, 'bitcoin.conf')

            cls.daemons.append(startDaemon(os.path.join(TEST_DIR, str(i)), BITCOIN_BINDIR, BITCOIND))
            logging.info('Started %s %d', BITCOIND, cls.daemons[-1].pid)

            waitForRPC(make_rpc_func(i))

        for i in range(XMR_NUM_NODES):
            prepareXmrDataDir(TEST_DIR, i, 'monerod.conf')

            cls.xmr_daemons.append(startXmrDaemon(os.path.join(TEST_DIR, 'xmr' + str(i)), XMR_BINDIR, XMRD))
            logging.info('Started %s %d', XMRD, cls.xmr_daemons[-1].pid)

            cls.xmr_daemons.append(startXmrWalletRPC(os.path.join(TEST_DIR, 'xmr' + str(i)), XMR_BINDIR, XMR_WALLET_RPC, i))

        time.sleep(1)  # TODO: Wait for xmr nodes to start

        for i in range(XMR_NUM_NODES):
            cls.xmr_wallet_auth.append(('test{0}'.format(i), 'test_pass{0}'.format(i)))
            logging.info('Creating XMR wallet %i', i)

            for r in range(5):
                try:
                    callrpc_xmr(XMR_BASE_WALLET_RPC_PORT + i, cls.xmr_wallet_auth[i], 'get_languages')
                    break
                except Exception as ex:
                    logging.warning('Can\'t connect to XMR wallet RPC: %s.  Trying again in %d second/s.', str(ex), (1 + i))
                    time.sleep(1 + i)

            cls.callxmrnodewallet(cls, i, 'create_wallet', {'filename': 'testwallet', 'language': 'English'})
            cls.callxmrnodewallet(cls, i, 'open_wallet', {'filename': 'testwallet'})

        cls.btc_addr = callnoderpc(0, 'getnewaddress', ['mining_addr', 'bech32'])
        cls.xmr_addr = cls.callxmrnodewallet(cls, 0, 'get_address')['address']

        cls.update_thread = threading.Thread(target=run_loop, args=(cls,))
        cls.update_thread.start()

        cls.initialiseTestState(cls)

    @classmethod
    def tearDownClass(cls):
        logging.info('Finalising')

        stopNodes(cls)

        cls.stream_fp.close()

        super(Test, cls).tearDownClass()

    def callxmrnodewallet(self, node_id, method, params=None):
        return callrpc_xmr(XMR_BASE_WALLET_RPC_PORT + node_id, self.xmr_wallet_auth[node_id], method, params)

    def initialiseTestState(self):
        # Called from a classmethod, seems to poison all method calls
        logging.info('\nInitialising chain states')

        # Why so many blocks?
        num_blocks = 500
        if callrpc_xmr_na(XMR_BASE_RPC_PORT + 0, 'get_block_count')['count'] < num_blocks:
            logging.info('Mining %d Monero blocks.', num_blocks)
            callrpc_xmr_na(XMR_BASE_RPC_PORT + 0, 'generateblocks', {'wallet_address': self.xmr_addr, 'amount_of_blocks': num_blocks})
        rv = callrpc_xmr_na(XMR_BASE_RPC_PORT + 0, 'get_block_count')
        logging.info('XMR blocks: %d', rv['count'])

        if callnoderpc(0, 'getblockchaininfo')['blocks'] < num_blocks:
            logging.info('Mining %d bitcoin blocks to %s', num_blocks, self.btc_addr)
            callnoderpc(0, 'generatetoaddress', [num_blocks, self.btc_addr])
        rv = callnoderpc(0, 'getblockchaininfo')
        logging.info('BTC blocks: %d', rv['blocks'])

        btc_addr_alice1 = callnoderpc(ID_ALICE_BTC, 'getnewaddress', ['alice\'s main addr', 'bech32'])
        callnoderpc(0, 'sendtoaddress', [btc_addr_alice1, 100])

        xmr_addr_bob1 = self.callxmrnodewallet(self, ID_BOB_XMR, 'get_address')['address']
        params = {'destinations': [{'amount': 50 * XMR_COIN, 'address': xmr_addr_bob1}]}
        rv = self.callxmrnodewallet(self, 0, 'transfer', params)
        logging.info('Sent initial XMR to Bob: %s', dumpj(rv))

        logging.info('Testing node sync')
        sync_passed = False
        for i in range(20):
            try:
                above_0 = 0
                for i in range(NUM_NODES):
                    r = callnoderpc(i, 'getblockchaininfo')
                    print('BTC', i, r['blocks'])
                    if r['blocks'] > 0:
                        above_0 += 1

                xmr_above_1 = 0
                for i in range(XMR_NUM_NODES):
                    r = callrpc_xmr_na(XMR_BASE_RPC_PORT + i, 'get_block_count')
                    print('XMR', i, r['count'])
                    if r['count'] > 2:  # xmr counts genesis block as 1
                        xmr_above_1 += 1

                if above_0 >= NUM_NODES and xmr_above_1 >= XMR_NUM_NODES:
                    logging.info('Node syncing passed.')
                    sync_passed = True
                    break
            except Exception as e:
                print('Error', repr(e))
            time.sleep(1)

        assert(sync_passed), 'Nodes did not sync'

        num_tries = 40
        for i in range(num_tries + 1):
            rv = self.callxmrnodewallet(self, ID_BOB_XMR, 'get_balance')
            if rv['balance'] > 0 and rv['blocks_to_unlock'] == 0:
                break

            r = callrpc_xmr_na(XMR_BASE_RPC_PORT + ID_BOB_XMR, 'get_block_count')
            print(r)

            if i >= num_tries:
                raise ValueError('XMR Balance not confirming on node {}'.format(ID_BOB_XMR))
            time.sleep(1)

    def startSwap(self, ID_ALICE_SWAP, ID_BOB_SWAP, amount_a, amount_b):
        logging.info('Set initial parameters.')
        btc_addr_bob1 = callnoderpc(ID_BOB_BTC, 'getnewaddress', ['bob\'s addr', 'bech32'])
        ignr, a_pkhash_f = segwit_addr.decode('bcrt', btc_addr_bob1)
        # After a successful swap the coinA amount will be in an output to a_pkhash_f

        swap_info = {
            'side': 'a',
            'a_coin': 'BTC',
            'b_coin': 'XMR',
            'a_amount': amount_a,
            'b_amount': amount_b,
            'a_feerate': 0.00032595,
            'b_feerate': 0.0012595,
            'a_pkhash_f': bytes(a_pkhash_f).hex(),
        }
        swap_info['a_connect'] = {
            'port': BASE_RPC_PORT + ID_ALICE_BTC,
            'username': 'test{}'.format(ID_ALICE_BTC),
            'password': 'test_pass{0}'.format(ID_ALICE_BTC)}
        swap_info['b_connect'] = {
            'port': XMR_BASE_RPC_PORT + ID_ALICE_XMR,
            'wallet_port': XMR_BASE_WALLET_RPC_PORT + ID_ALICE_XMR,
            'wallet_auth': self.xmr_wallet_auth[ID_ALICE_XMR],
        }
        callSwapTool(ID_ALICE_SWAP, 'init', swap_info)

        swap_info['a_connect'] = {
            'port': BASE_RPC_PORT + ID_BOB_BTC,
            'username': 'test{}'.format(ID_BOB_BTC),
            'password': 'test_pass{0}'.format(ID_BOB_BTC)}
        swap_info['b_connect'] = {
            'port': XMR_BASE_RPC_PORT + ID_BOB_XMR,
            'wallet_port': XMR_BASE_WALLET_RPC_PORT + ID_BOB_XMR,
            'wallet_auth': self.xmr_wallet_auth[ID_BOB_XMR],
        }
        swap_info['side'] = 'b'
        callSwapTool(ID_BOB_SWAP, 'init', swap_info)

        logging.info('Alice and Bob exchange keys.')
        msg1f = callSwapTool(ID_ALICE_SWAP, 'msg1f')
        msg1l = callSwapTool(ID_BOB_SWAP, 'msg1l')

        callSwapTool(ID_ALICE_SWAP, 'processmsg', str_param=msg1l)
        callSwapTool(ID_BOB_SWAP, 'processmsg', str_param=msg1f)

    def test_01_swap_successful(self):
        checkSoftForks(callnoderpc(0, 'getblockchaininfo'))

        ID_ALICE_SWAP = os.path.join(TEST_DIR, 'test_01_alice_swap_state') + '.json'
        ID_BOB_SWAP = os.path.join(TEST_DIR, 'test_01_bob_swap_state') + '.json'

        self.startSwap(ID_ALICE_SWAP, ID_BOB_SWAP, 1, 2)

        logging.info('Alice creates the script-chain lock and refund txns and signs the refund tx, sends to Bob.')
        msg2f = callSwapTool(ID_ALICE_SWAP, 'msg2f')

        logging.info('Bob verifies the txns and signs the refund tx and creates an encrypted signature for the refund spend tx encumbered by Alice\'s coin B key share.')
        callSwapTool(ID_BOB_SWAP, 'processmsg', str_param=msg2f)
        msg3l = callSwapTool(ID_BOB_SWAP, 'msg3l')

        logging.info('Alice verifies the signature and encrypted signature from Bob.')
        callSwapTool(ID_ALICE_SWAP, 'processmsg', str_param=msg3l)

        logging.info('Creates the lock spend tx and signs an encrypted signature encumbered by Bob\'s coin B key share')
        msg4f = callSwapTool(ID_ALICE_SWAP, 'msg4f')

        logging.info('Publishes the script-chain lock tx.')
        a_lock_txid = callSwapTool(ID_ALICE_SWAP, 'publishalocktx')

        # Check that the script-chain lock refund tx isn't mineable yet
        try:
            rv = callSwapTool(ID_ALICE_SWAP, 'publishalockrefundtx')
            assert(False)
        except Exception as e:
            assert('non-BIP68-final' in str(e))

        logging.info('Bob verifies the lock spend tx and encrypted signature from Alice.')
        callSwapTool(ID_BOB_SWAP, 'processmsg', str_param=msg4f)

        logging.info('Bob waits for the script-chain lock tx to confirm.')

        num_tries = 30
        for i in range(1 + num_tries):
            rv = callSwapTool(ID_BOB_SWAP, 'confirmalocktx')
            print('confirmalocktx', rv)
            if rv.strip() == 'True':
                break

            if i >= num_tries:
                raise ValueError('Timed out waiting for script-chain lock tx to confirm.')

        logging.info('Then publishes the second-chain lock tx.')
        b_lock_txid = callSwapTool(ID_BOB_SWAP, 'publishblocktx')

        logging.info('Alice waits for the scriptless-chain lock tx to confirm.')

        num_tries = 50
        for i in range(1 + num_tries):
            rv = callSwapTool(ID_ALICE_SWAP, 'confirmblocktx')
            print('confirmblocktx', rv)
            if rv.strip() == 'True':
                break

            if i >= num_tries:
                raise ValueError('Timed out waiting for scriptless-chain lock tx to confirm.')
            time.sleep(1)

        logging.info('Alice shares the secret value with Bob, allowing the script-chain lock tx to be spent')
        msg5f = callSwapTool(ID_ALICE_SWAP, 'msg5f')
        callSwapTool(ID_BOB_SWAP, 'processmsg', str_param=msg5f)

        logging.info('Bob spends from the script-chain lock tx')
        alockspendtxid = callSwapTool(ID_BOB_SWAP, 'publishalockspendtx')
        logging.info('alockspendtxid %s', alockspendtxid)

        logging.info('Alice looks for Bob\'s script-chain lock spend tx and extracts the sig')

        num_tries = 20
        for i in range(1 + num_tries):
            rv = callSwapTool(ID_ALICE_SWAP, 'findalockspendtx')
            print('findalockspendtx', rv)
            if rv.strip() == 'True':
                break

            if i >= num_tries:
                raise ValueError('Timed out waiting for script-chain lock spend tx to confirm.')
            time.sleep(1)

        self.callxmrnodewallet(ID_ALICE_XMR, 'open_wallet', {'filename': 'testwallet'})
        xmr_addr_alice1 = self.callxmrnodewallet(ID_ALICE_XMR, 'get_address')['address']

        logging.info('Alice redeems the scriptless-chain lock tx to her address: %s', xmr_addr_alice1)
        rv = callSwapTool(ID_ALICE_SWAP, 'redeemblocktx', str_param=xmr_addr_alice1)
        print('redeemblocktx', rv)

        self.callxmrnodewallet(ID_ALICE_XMR, 'close_wallet')
        self.callxmrnodewallet(ID_ALICE_XMR, 'open_wallet', {'filename': 'testwallet'})

        logging.info('Waiting for Alice\'s XMR to confirm...')
        num_tries = 40
        for i in range(num_tries + 1):
            rv = self.callxmrnodewallet(ID_ALICE_XMR, 'get_balance')
            if rv['balance'] > 0 and rv['blocks_to_unlock'] == 0:
                break

            r = callrpc_xmr_na(XMR_BASE_RPC_PORT + ID_ALICE_XMR, 'get_block_count')
            print('XMR blocks', r['count'])

            if i >= num_tries:
                raise ValueError('Balance not confirming on node {}'.format(ID_ALICE_XMR))
            time.sleep(1)

        logging.info('Waiting for Bob\'s BTC to confirm...')
        for i in range(num_tries + 1):
            rv = callnoderpc(ID_BOB_BTC, 'getbalances')
            if rv['mine']['trusted'] > 0:
                break
            print('btc height', i, callnoderpc(ID_BOB_BTC, 'getblockchaininfo')['blocks'])
            if i >= num_tries:
                raise ValueError('Balance not confirming on node {}'.format(ID_ALICE_XMR))
            time.sleep(1)

    def test_02_leader_recover_a_lock_tx(self):
        ID_ALICE_SWAP = os.path.join(TEST_DIR, 'test_02_alice_swap_state') + '.json'
        ID_BOB_SWAP = os.path.join(TEST_DIR, 'test_02_bob_swap_state') + '.json'

        alice_btc_start = make_int(callnoderpc(ID_ALICE_BTC, 'getbalances')['mine']['trusted'])
        bob_btc_start = make_int(callnoderpc(ID_BOB_BTC, 'getbalances')['mine']['trusted'])

        alice_xmr_start = self.callxmrnodewallet(ID_ALICE_XMR, 'get_balance')['balance']
        bob_xmr_start = self.callxmrnodewallet(ID_BOB_XMR, 'get_balance')['balance']

        logging.info('Test start wallet states:\nalice_btc_start: %ld\nbob_btc_start: %ld\nalice_xmr_start: %ld\nbob_xmr_start: %ld',
                     alice_btc_start, bob_btc_start, alice_xmr_start, bob_xmr_start)

        self.startSwap(ID_ALICE_SWAP, ID_BOB_SWAP, 2, 3)

        logging.info('Alice creates the script-chain lock and refund txns and signs the refund tx, sends to Bob.')
        msg2f = callSwapTool(ID_ALICE_SWAP, 'msg2f')

        logging.info('Bob verifies the txns and signs the refund tx and creates an encrypted signature for the refund spend tx encumbered by Alice\'s coin B key share.')
        callSwapTool(ID_BOB_SWAP, 'processmsg', str_param=msg2f)
        msg3l = callSwapTool(ID_BOB_SWAP, 'msg3l')

        logging.info('Alice verifies the signature and encrypted signature from Bob.')
        callSwapTool(ID_ALICE_SWAP, 'processmsg', str_param=msg3l)

        logging.info('Creates the lock spend tx and signs an encrypted signature encumbered by Bob\'s coin B key share')
        msg4f = callSwapTool(ID_ALICE_SWAP, 'msg4f')

        logging.info('Publishes the script-chain lock tx.')
        a_lock_txid = callSwapTool(ID_ALICE_SWAP, 'publishalocktx').strip()

        # Wait for the mining node to receive the tx
        for i in range(10):
            try:
                callnoderpc(0, 'getrawtransaction', [a_lock_txid])
                break
            except Exception as e:
                print('Waiting for node 0 to see tx', str(e))
            time.sleep(1)

        logging.info('Bob stops responding here.')

        alice_btc = make_int(callnoderpc(ID_ALICE_BTC, 'getbalances')['mine']['trusted'])
        logging.info('alice_btc %ld', alice_btc)

        alockrefundtxid = None
        for i in range(10):
            callnoderpc(0, 'generatetoaddress', [30, self.btc_addr])
            time.sleep(1)

            logging.info('BTC blocks: %d', callnoderpc(ID_ALICE_BTC, 'getblockchaininfo')['blocks'])
            try:
                alockrefundtxid = callSwapTool(ID_ALICE_SWAP, 'publishalockrefundtx')
                break
            except Exception as e:
                print(str(e))
                if 'Transaction already in block chain' in str(e):
                    break
                assert('non-BIP68-final' in str(e))

        assert(alockrefundtxid is not None)
        logging.info('alockrefundtxid %s', alockrefundtxid)

        # Import key to receive refund in wallet.  Simple method for testing.
        kal = callSwapTool(ID_ALICE_SWAP, 'getkal')
        kal_wif = bytes_to_wif(h2b(kal))
        callnoderpc(ID_ALICE_BTC, 'importprivkey', [kal_wif, 'swap refund'])

        alockrefundspendtxid = callSwapTool(ID_ALICE_SWAP, 'publishalockrefundspendtx')

        rv = callnoderpc(ID_ALICE_BTC, 'getbalances')
        alice_btc_end = make_int(rv['mine']['trusted']) + make_int(rv['mine']['untrusted_pending'])
        logging.info('alice_btc_end %ld', alice_btc_end)

        assert(alice_btc_end > alice_btc)

    def test_03_follower_recover_a_lock_tx(self):
        ID_ALICE_SWAP = os.path.join(TEST_DIR, 'test_03_alice_swap_state') + '.json'
        ID_BOB_SWAP = os.path.join(TEST_DIR, 'test_03_bob_swap_state') + '.json'

        alice_btc_start = make_int(callnoderpc(ID_ALICE_BTC, 'getbalances')['mine']['trusted'])
        bob_btc_start = make_int(callnoderpc(ID_BOB_BTC, 'getbalances')['mine']['trusted'])
        alice_xmr_start = self.callxmrnodewallet(ID_ALICE_XMR, 'get_balance')['balance']
        bob_xmr_start = self.callxmrnodewallet(ID_BOB_XMR, 'get_balance')['balance']

        logging.info('Test start wallet states:\nalice_btc_start: %ld\nbob_btc_start: %ld\nalice_xmr_start: %ld\nbob_xmr_start: %ld',
                     alice_btc_start, bob_btc_start, alice_xmr_start, bob_xmr_start)

        # Same steps as in test_01_swap_successful
        self.startSwap(ID_ALICE_SWAP, ID_BOB_SWAP, 3, 4)
        msg2f = callSwapTool(ID_ALICE_SWAP, 'msg2f')
        callSwapTool(ID_BOB_SWAP, 'processmsg', str_param=msg2f)
        msg3l = callSwapTool(ID_BOB_SWAP, 'msg3l')
        callSwapTool(ID_ALICE_SWAP, 'processmsg', str_param=msg3l)
        msg4f = callSwapTool(ID_ALICE_SWAP, 'msg4f')
        a_lock_txid = callSwapTool(ID_ALICE_SWAP, 'publishalocktx').strip()

        logging.info('Alice stops responding here.')

        # Wait for the mining node to receive the tx
        for i in range(10):
            try:
                callnoderpc(0, 'getrawtransaction', [a_lock_txid])
                break
            except Exception as e:
                print('Waiting for node 0 to see tx', str(e))
            time.sleep(1)

        logging.info('Mining 200 blocks.')
        callnoderpc(0, 'generatetoaddress', [200, self.btc_addr])
        time.sleep(2)
        logging.info('BTC blocks: %d', callnoderpc(ID_BOB_BTC, 'getblockchaininfo')['blocks'])
        a_lock_refund_txid = callSwapTool(ID_BOB_SWAP, 'publishalockrefundtx').strip()
        logging.info('a_lock_refund_txid %s', a_lock_refund_txid)

        # Wait for the mining node to receive the tx
        for i in range(10):
            try:
                callnoderpc(0, 'getrawtransaction', [a_lock_refund_txid])
                break
            except Exception as e:
                print('Waiting for node 0 to see tx', str(e))
            time.sleep(1)

        logging.info('Mining 200 blocks.')
        callnoderpc(0, 'generatetoaddress', [200, self.btc_addr])
        time.sleep(2)

        btc_addr_bob = callnoderpc(ID_BOB_BTC, 'getnewaddress', ['bob\'s addr', 'bech32'])
        ignr, a_pkhash_f = segwit_addr.decode('bcrt', btc_addr_bob)

        time.sleep(1)
        alockrefundspendtxid = callSwapTool(ID_BOB_SWAP, 'publishalockrefundspendftx', str_param=bytes(a_pkhash_f).hex())

        rv = callnoderpc(ID_BOB_BTC, 'getbalances')
        print('getbalances', dumpj(rv))
        bob_btc_end = make_int(rv['mine']['trusted']) + make_int(rv['mine']['untrusted_pending'])
        logging.info('bob_btc_end %ld', bob_btc_end)

        assert(bob_btc_end > bob_btc_start)

    def test_04_follower_recover_b_lock_tx(self):
        ID_ALICE_SWAP = os.path.join(TEST_DIR, 'test_04_alice_swap_state') + '.json'
        ID_BOB_SWAP = os.path.join(TEST_DIR, 'test_04_bob_swap_state') + '.json'

        alice_btc_start = make_int(callnoderpc(ID_ALICE_BTC, 'getbalances')['mine']['trusted'])
        bob_btc_start = make_int(callnoderpc(ID_BOB_BTC, 'getbalances')['mine']['trusted'])
        alice_xmr_start = self.callxmrnodewallet(ID_ALICE_XMR, 'get_balance')['balance']
        bob_xmr_start = self.callxmrnodewallet(ID_BOB_XMR, 'get_balance')['balance']

        logging.info('Test start wallet states:\nalice_btc_start: %ld\nbob_btc_start: %ld\nalice_xmr_start: %ld\nbob_xmr_start: %ld',
                     alice_btc_start, bob_btc_start, alice_xmr_start, bob_xmr_start)

        # Same steps as in test_01_swap_successful
        self.startSwap(ID_ALICE_SWAP, ID_BOB_SWAP, 3, 4)
        msg2f = callSwapTool(ID_ALICE_SWAP, 'msg2f')
        callSwapTool(ID_BOB_SWAP, 'processmsg', str_param=msg2f)
        msg3l = callSwapTool(ID_BOB_SWAP, 'msg3l')
        callSwapTool(ID_ALICE_SWAP, 'processmsg', str_param=msg3l)
        msg4f = callSwapTool(ID_ALICE_SWAP, 'msg4f')
        a_lock_txid = callSwapTool(ID_ALICE_SWAP, 'publishalocktx').strip()

        logging.info('Bob verifies the lock spend tx and encrypted signature from Alice.')
        callSwapTool(ID_BOB_SWAP, 'processmsg', str_param=msg4f)

        logging.info('Bob waits for the script-chain lock tx to confirm.')

        num_tries = 30
        for i in range(1 + num_tries):
            rv = callSwapTool(ID_BOB_SWAP, 'confirmalocktx')
            print('confirmalocktx', rv)
            if rv.strip() == 'True':
                break

            if i >= num_tries:
                raise ValueError('Timed out waiting for script-chain lock tx to confirm.')

        logging.info('Then publishes the second-chain lock tx.')
        b_lock_txid = callSwapTool(ID_BOB_SWAP, 'publishblocktx')

        logging.info('Alice waits for the scriptless-chain lock tx to confirm.')

        num_tries = 50
        for i in range(1 + num_tries):
            rv = callSwapTool(ID_ALICE_SWAP, 'confirmblocktx')
            print('confirmblocktx', rv)
            if rv.strip() == 'True':
                break

            if i >= num_tries:
                raise ValueError('Timed out waiting for scriptless-chain lock tx to confirm.')
            time.sleep(1)

        logging.info('Alice detects a problem with the scriptless-chain lock tx and decides to cancel the swap')

        callnoderpc(0, 'generatetoaddress', [150, self.btc_addr])
        time.sleep(2)

        logging.info('BTC blocks: %d', callnoderpc(ID_ALICE_BTC, 'getblockchaininfo')['blocks'])
        alockrefundtxid = callSwapTool(ID_ALICE_SWAP, 'publishalockrefundtx')

        # Import key to receive refund in wallet.  Simple method for testing.
        kal = callSwapTool(ID_ALICE_SWAP, 'getkal')
        kal_wif = bytes_to_wif(h2b(kal))
        callnoderpc(ID_ALICE_BTC, 'importprivkey', [kal_wif, 'swap refund'])

        alockrefundspendtxid = callSwapTool(ID_ALICE_SWAP, 'publishalockrefundspendtx')

        rv = callnoderpc(ID_ALICE_BTC, 'getbalances')
        print('getbalances', dumpj(rv))
        alice_btc = make_int(rv['mine']['trusted']) + make_int(rv['mine']['untrusted_pending'])
        logging.info('alice_btc %ld', alice_btc)

        logging.info('Bob waits for Alice to spend the lock refund tx.')

        num_tries = 20
        for i in range(1 + num_tries):
            rv = callSwapTool(ID_BOB_SWAP, 'findalockrefundspendtx')
            print('findalockrefundspendtx', rv)
            if rv.strip() == 'True':
                break
            if i >= num_tries:
                raise ValueError('Timed out waiting for script-chain lock refund spend tx to confirm.')
            time.sleep(1)

        logging.info('Then he can recover his scriptless-chain lock tx coin.')

        self.callxmrnodewallet(ID_BOB_XMR, 'open_wallet', {'filename': 'testwallet'})
        xmr_addr_bob = self.callxmrnodewallet(ID_BOB_XMR, 'get_address')['address']

        rv = callSwapTool(ID_BOB_SWAP, 'redeemblocktx', str_param=xmr_addr_bob)
        print('redeemblocktx', rv)

        self.callxmrnodewallet(ID_BOB_XMR, 'close_wallet')
        self.callxmrnodewallet(ID_BOB_XMR, 'open_wallet', {'filename': 'testwallet'})


if __name__ == '__main__':
    unittest.main()
