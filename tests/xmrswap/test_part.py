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
    PARTICL_BINDIR, PARTICLD,
    XMR_BINDIR, XMRD, XMR_WALLET_RPC,
    NUM_NODES,
    BASE_RPC_PORT,
    XMR_NUM_NODES,
    XMR_BASE_RPC_PORT, XMR_BASE_WALLET_RPC_PORT,
    prepareXmrDataDir, prepareDataDir,
    startXmrDaemon, startXmrWalletRPC,
    startDaemon, callnoderpc, make_rpc_func, stopNodes, callSwapTool,
    waitForXMRNode, waitForXMRWallet
)

TEST_DIR = os.path.join(TEST_DATADIRS, 'part')
logger = logging.getLogger()

ID_ALICE_XMR = 1
ID_BOB_XMR = 2
ID_ALICE_PART = 1
ID_BOB_PART = 2


def run_loop(cls):
    while not cls.stop_nodes:
        try:
            if cls.xmr_addr is not None:
                callrpc_xmr_na(XMR_BASE_RPC_PORT + 0, 'generateblocks', {'wallet_address': cls.xmr_addr, 'amount_of_blocks': 1})

            part_height = callnoderpc(0, 'getblockchaininfo')['blocks']
            if cls.part_stakelimit <= part_height:
                cls.part_stakelimit += 1
                callnoderpc(0, 'walletsettings', ['stakelimit', {'height': cls.part_stakelimit}])
        except Exception as e:
            logging.error('Update thread: %s', str(e))
        time.sleep(0.5)


class Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stop_nodes = False
        cls.update_thread = None
        cls.daemons = []
        cls.xmr_daemons = []
        cls.xmr_wallet_auth = []

        cls.part_stakelimit = 0
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
            prepareDataDir(TEST_DIR, i, 'particl.conf')

            cls.daemons.append(startDaemon(os.path.join(TEST_DIR, str(i)), PARTICL_BINDIR, PARTICLD))
            logging.info('Started %s %d', PARTICLD, cls.daemons[-1].pid)

            waitForRPC(make_rpc_func(i))

        for i in range(XMR_NUM_NODES):
            prepareXmrDataDir(TEST_DIR, i, 'monerod.conf')

            cls.xmr_daemons.append(startXmrDaemon(os.path.join(TEST_DIR, 'xmr' + str(i)), XMR_BINDIR, XMRD))
            logging.info('Started %s %d', XMRD, cls.xmr_daemons[-1].pid)
            waitForXMRNode(i)

            cls.xmr_daemons.append(startXmrWalletRPC(os.path.join(TEST_DIR, 'xmr' + str(i)), XMR_BINDIR, XMR_WALLET_RPC, i))

        for i in range(XMR_NUM_NODES):
            cls.xmr_wallet_auth.append(('test{0}'.format(i), 'test_pass{0}'.format(i)))
            logging.info('Creating XMR wallet %i', i)

            waitForXMRWallet(i, cls.xmr_wallet_auth[i])

            cls.callxmrnodewallet(cls, i, 'create_wallet', {'filename': 'testwallet', 'language': 'English'})
            cls.callxmrnodewallet(cls, i, 'open_wallet', {'filename': 'testwallet'})

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
        logging.info('Initialising chain states')

        for i in range(NUM_NODES):
            # Disable staking
            callnoderpc(i, 'reservebalance', [True, 1000000])

            # Lower output split threshold for more stakeable outputs
            callnoderpc(i, 'walletsettings', ['stakingoptions', {'stakecombinethreshold': 100, 'stakesplitthreshold': 200}])

        # Add regtest coins and allow staking for node 0
        callnoderpc(0, 'extkeyimportmaster', ['abandon baby cabbage dad eager fabric gadget habit ice kangaroo lab absorb'])
        assert(callnoderpc(0, 'getwalletinfo')['total_balance'] == 100000)
        callnoderpc(0, 'reservebalance', [False])
        callnoderpc(0, 'walletsettings', ['stakelimit', {'height': 0}])

        # Import coin for Alice
        callnoderpc(ID_ALICE_PART, 'extkeyimportmaster', ['pact mammal barrel matrix local final lecture chunk wasp survey bid various book strong spread fall ozone daring like topple door fatigue limb olympic', '', 'true'])
        callnoderpc(ID_ALICE_PART, 'getnewextaddress', ['lblExtTest'])
        callnoderpc(ID_ALICE_PART, 'rescanblockchain')
        assert(callnoderpc(ID_ALICE_PART, 'getwalletinfo')['total_balance'] == 25000)

        # Import account for Bob
        callnoderpc(ID_BOB_PART, 'extkeyimportmaster', ['sección grito médula hecho pauta posada nueve ebrio bruto buceo baúl mitad'])

        # Why so many blocks?
        num_blocks = 500
        if callrpc_xmr_na(XMR_BASE_RPC_PORT + 0, 'get_block_count')['count'] < num_blocks:
            logging.info('Mining %d Monero blocks.', num_blocks)
            callrpc_xmr_na(XMR_BASE_RPC_PORT + 0, 'generateblocks', {'wallet_address': self.xmr_addr, 'amount_of_blocks': num_blocks})
        rv = callrpc_xmr_na(XMR_BASE_RPC_PORT + 0, 'get_block_count')
        logging.info('XMR blocks: %d', rv['count'])

        rv = callnoderpc(0, 'getblockchaininfo')
        logging.info('PART blocks: %d', rv['blocks'])

        xmr_addr_bob = self.callxmrnodewallet(self, ID_BOB_XMR, 'get_address')['address']
        logging.info('Sending 50 XMR to Bob\'s address %s\n', xmr_addr_bob)
        params = {'destinations': [{'amount': 50 * XMR_COIN, 'address': xmr_addr_bob}]}
        rv = self.callxmrnodewallet(self, 0, 'transfer', params)
        logging.info('Sent initial XMR to Bob: %s', dumpj(rv))

        logging.info('Testing node sync')
        sync_passed = False
        for i in range(20):
            try:
                above_0 = 0
                for i in range(NUM_NODES):
                    r = callnoderpc(i, 'getblockchaininfo')
                    print('PART', i, r['blocks'])
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
                raise ValueError('XMR balance not confirming on node {}'.format(ID_BOB_XMR))
            time.sleep(1)

    def startSwap(self, ID_ALICE_SWAP, ID_BOB_SWAP, amount_a, amount_b):
        logging.info('Set initial parameters.')
        part_addr_bob = callnoderpc(ID_BOB_PART, 'getnewaddress', ['bob\'s addr', False, False, False, 'bech32'])
        # After a successful swap the coinA amount will be in an output to part_addr_bob

        swap_info = {
            'side': 'a',
            'a_coin': 'PART',
            'b_coin': 'XMR',
            'a_amount': amount_a,
            'b_amount': amount_b,
            'a_feerate': 0.00032595,
            'b_feerate': 0.0012595,
            'a_addr_f': part_addr_bob,
            'lock1': 10,
            'lock2': 11,
        }
        swap_info['a_connect'] = {
            'port': BASE_RPC_PORT + ID_ALICE_PART,
            'username': 'test{}'.format(ID_ALICE_PART),
            'password': 'test_pass{0}'.format(ID_ALICE_PART)}
        swap_info['b_connect'] = {
            'port': XMR_BASE_RPC_PORT + ID_ALICE_XMR,
            'wallet_port': XMR_BASE_WALLET_RPC_PORT + ID_ALICE_XMR,
            'wallet_auth': self.xmr_wallet_auth[ID_ALICE_XMR],
        }
        callSwapTool(ID_ALICE_SWAP, 'init', swap_info)

        swap_info['a_connect'] = {
            'port': BASE_RPC_PORT + ID_BOB_PART,
            'username': 'test{}'.format(ID_BOB_PART),
            'password': 'test_pass{0}'.format(ID_BOB_PART)}
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

    def publishALockRefundTx(self, user_id_part, user_id_swap):
        alockrefundtxid = None
        for i in range(20):
            '''
            self.part_stakelimit += 10
            callnoderpc(0, 'walletsettings', ['stakelimit', {'height': self.part_stakelimit}])
            print('self.part_stakelimit', self.part_stakelimit)
            '''
            time.sleep(1)

            logging.info('PART blocks: %d', callnoderpc(user_id_part, 'getblockchaininfo')['blocks'])
            try:
                alockrefundtxid = callSwapTool(user_id_swap, 'publishalockrefundtx').strip()
                break
            except Exception as e:
                print(str(e))
                if 'Transaction already in block chain' in str(e):
                    break
                assert('non-BIP68-final' in str(e))

        assert(alockrefundtxid is not None)
        logging.info('alockrefundtxid %s', alockrefundtxid)
        return alockrefundtxid

    def publishALockRefundFollowerSpendTx(self, user_id_part, user_id_swap, a_pkhash_f):
        alockrefundspendtxid = None
        for i in range(20):
            time.sleep(1)

            logging.info('PART blocks: %d', callnoderpc(user_id_part, 'getblockchaininfo')['blocks'])
            try:
                alockrefundspendtxid = callSwapTool(user_id_swap, 'publishalockrefundspendftx', str_param=bytes(a_pkhash_f).hex()).strip()
                break
            except Exception as e:
                print(str(e))
                if 'Transaction already in block chain' in str(e):
                    break
                assert('non-BIP68-final' in str(e))

        assert(alockrefundspendtxid is not None)
        logging.info('alockrefundspendtxid %s', alockrefundspendtxid)
        return alockrefundspendtxid

    def test_01_swap_successful(self):
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

        num_tries = 120
        for i in range(1 + num_tries):
            rv = callSwapTool(ID_ALICE_SWAP, 'confirmblocktx')
            print('confirmblocktx', rv)
            if rv.strip() == 'True':
                break

            if i >= num_tries:
                raise ValueError('Timed out waiting for scriptless-chain lock tx to confirm.')
            time.sleep(2)

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
        num_tries = 120
        for i in range(num_tries + 1):
            rv = self.callxmrnodewallet(ID_ALICE_XMR, 'get_balance')
            if rv['balance'] > 0 and rv['blocks_to_unlock'] == 0:
                break

            r = callrpc_xmr_na(XMR_BASE_RPC_PORT + ID_ALICE_XMR, 'get_block_count')
            print('XMR blocks', r['count'])

            if i >= num_tries:
                raise ValueError('Balance not confirming on node {}'.format(ID_ALICE_XMR))
            time.sleep(2)

        logging.info('Waiting for Bob\'s BTC to confirm...')
        for i in range(num_tries + 1):
            rv = callnoderpc(ID_BOB_PART, 'getbalances')
            if rv['mine']['trusted'] > 0:
                break
            print('btc height', i, callnoderpc(ID_BOB_PART, 'getblockchaininfo')['blocks'])
            if i >= num_tries:
                raise ValueError('Balance not confirming on node {}'.format(ID_ALICE_XMR))
            time.sleep(1)

    def test_02_leader_recover_a_lock_tx(self):
        ID_ALICE_SWAP = os.path.join(TEST_DIR, 'test_02_alice_swap_state') + '.json'
        ID_BOB_SWAP = os.path.join(TEST_DIR, 'test_02_bob_swap_state') + '.json'

        alice_btc_start = make_int(callnoderpc(ID_ALICE_PART, 'getbalances')['mine']['trusted'])
        bob_btc_start = make_int(callnoderpc(ID_BOB_PART, 'getbalances')['mine']['trusted'])

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

        alice_btc = make_int(callnoderpc(ID_ALICE_PART, 'getbalances')['mine']['trusted'])
        logging.info('alice_btc %ld', alice_btc)

        a_lock_refund_txid = self.publishALockRefundTx(ID_ALICE_PART, ID_ALICE_SWAP)

        # Import key to receive refund in wallet.  Simple method for testing.
        kal = callSwapTool(ID_ALICE_SWAP, 'getkal')
        kal_wif = bytes_to_wif(h2b(kal), prefix=0x2e)
        callnoderpc(ID_ALICE_PART, 'importprivkey', [kal_wif, 'swap refund'])

        alockrefundspendtxid = callSwapTool(ID_ALICE_SWAP, 'publishalockrefundspendtx')

        rv = callnoderpc(ID_ALICE_PART, 'getbalances')
        alice_btc_end = make_int(rv['mine']['trusted']) + make_int(rv['mine']['untrusted_pending'])
        logging.info('alice_btc_end %ld', alice_btc_end)

        assert(alice_btc_end > alice_btc)

    def test_03_follower_recover_a_lock_tx(self):
        ID_ALICE_SWAP = os.path.join(TEST_DIR, 'test_03_alice_swap_state') + '.json'
        ID_BOB_SWAP = os.path.join(TEST_DIR, 'test_03_bob_swap_state') + '.json'

        alice_btc_start = make_int(callnoderpc(ID_ALICE_PART, 'getbalances')['mine']['trusted'])
        bob_btc_start = make_int(callnoderpc(ID_BOB_PART, 'getbalances')['mine']['trusted'])
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

        a_lock_refund_txid = self.publishALockRefundTx(ID_BOB_PART, ID_BOB_SWAP)

        # Wait for the mining node to receive the tx
        for i in range(10):
            try:
                callnoderpc(0, 'getrawtransaction', [a_lock_refund_txid])
                break
            except Exception as e:
                print('Waiting for node 0 to see tx', str(e))
            time.sleep(1)

        btc_addr_bob = callnoderpc(ID_BOB_PART, 'getnewaddress', ['bob\'s addr', False, False, False, 'bech32'])
        ignr, a_pkhash_f = segwit_addr.decode('rtpw', btc_addr_bob)
        assert(a_pkhash_f is not None)

        a_lock_refund_spend_txid = self.publishALockRefundFollowerSpendTx(ID_BOB_PART, ID_BOB_SWAP, a_pkhash_f)

        rv = callnoderpc(ID_BOB_PART, 'getbalances')
        print('getbalances', dumpj(rv))
        bob_btc_end = make_int(rv['mine']['trusted']) + make_int(rv['mine']['untrusted_pending'])
        logging.info('bob_btc_end %ld', bob_btc_end)

        assert(bob_btc_end > bob_btc_start)

    def test_04_follower_recover_b_lock_tx(self):
        ID_ALICE_SWAP = os.path.join(TEST_DIR, 'test_04_alice_swap_state') + '.json'
        ID_BOB_SWAP = os.path.join(TEST_DIR, 'test_04_bob_swap_state') + '.json'

        alice_btc_start = make_int(callnoderpc(ID_ALICE_PART, 'getbalances')['mine']['trusted'])
        bob_btc_start = make_int(callnoderpc(ID_BOB_PART, 'getbalances')['mine']['trusted'])
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

        num_tries = 120
        for i in range(1 + num_tries):
            rv = callSwapTool(ID_ALICE_SWAP, 'confirmblocktx')
            print('confirmblocktx', rv)
            if rv.strip() == 'True':
                break

            if i >= num_tries:
                raise ValueError('Timed out waiting for scriptless-chain lock tx to confirm.')
            time.sleep(2)

        logging.info('Alice detects a problem with the scriptless-chain lock tx and decides to cancel the swap')

        a_lock_refund_txid = self.publishALockRefundTx(ID_ALICE_PART, ID_ALICE_SWAP)

        # Import key to receive refund in wallet.  Simple method for testing.
        kal = callSwapTool(ID_ALICE_SWAP, 'getkal')
        kal_wif = bytes_to_wif(h2b(kal), prefix=0x2e)
        callnoderpc(ID_ALICE_PART, 'importprivkey', [kal_wif, 'swap refund'])

        alockrefundspendtxid = callSwapTool(ID_ALICE_SWAP, 'publishalockrefundspendtx')

        rv = callnoderpc(ID_ALICE_PART, 'getbalances')
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
