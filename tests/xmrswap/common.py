#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2020 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

import os
import sys
import signal
import logging
import subprocess

from io import StringIO
from unittest.mock import patch

from xmrswap.rpc import callrpc
from xmrswap.util import dumpje
from xmrswap.contrib.rpcauth import generate_salt, password_to_hmac

import bin.xmrswaptool as swapTool

TEST_DATADIRS = os.path.expanduser(os.getenv('TEST_DATADIRS', '/tmp/xmrswap'))

NUM_NODES = 3
BASE_PORT = 14792
BASE_RPC_PORT = 19792

XMR_NUM_NODES = 3
XMR_BASE_P2P_PORT = 17792
XMR_BASE_RPC_PORT = 21792
XMR_BASE_ZMQ_PORT = 22792
XMR_BASE_WALLET_RPC_PORT = 23792

bin_suffix = ('.exe' if os.name == 'nt' else '')
PARTICL_BINDIR = os.path.expanduser(os.getenv('PARTICL_BINDIR', '.'))
PARTICLD = os.getenv('PARTICLD', 'particld' + bin_suffix)
PARTICL_CLI = os.getenv('PARTICL_CLI', 'particl-cli' + bin_suffix)
PARTICL_TX = os.getenv('PARTICL_TX', 'particl-tx' + bin_suffix)

BITCOIN_BINDIR = os.path.expanduser(os.getenv('BITCOIN_BINDIR', ''))
BITCOIND = os.getenv('BITCOIND', 'bitcoind' + bin_suffix)
BITCOIN_CLI = os.getenv('BITCOIN_CLI', 'bitcoin-cli' + bin_suffix)
BITCOIN_TX = os.getenv('BITCOIN_TX', 'bitcoin-tx' + bin_suffix)

XMR_BINDIR = os.path.expanduser(os.getenv('XMR_BINDIR', ''))
XMRD = os.getenv('XMRD', 'monerod' + bin_suffix)
XMR_WALLET_RPC = os.getenv('XMR_WALLET_RPC', 'monero-wallet-rpc' + bin_suffix)


def prepareXmrDataDir(datadir, node_id, conf_file):
    node_dir = os.path.join(datadir, 'xmr' + str(node_id))
    if not os.path.exists(node_dir):
        os.makedirs(node_dir)
    cfg_file_path = os.path.join(node_dir, conf_file)
    if os.path.exists(cfg_file_path):
        return
    with open(cfg_file_path, 'w+') as fp:
        fp.write('regtest=1\n')
        fp.write('keep-fakechain=1\n')
        fp.write('data-dir={}\n'.format(node_dir))
        fp.write('fixed-difficulty=1\n')
        # fp.write('offline=1\n')
        fp.write('p2p-bind-port={}\n'.format(XMR_BASE_P2P_PORT + node_id))
        fp.write('rpc-bind-port={}\n'.format(XMR_BASE_RPC_PORT + node_id))
        fp.write('p2p-bind-ip=127.0.0.1\n')
        fp.write('rpc-bind-ip=127.0.0.1\n')

        fp.write('zmq-rpc-bind-port={}\n'.format(XMR_BASE_ZMQ_PORT + node_id))
        fp.write('zmq-rpc-bind-ip=127.0.0.1\n')

        for i in range(0, XMR_NUM_NODES):
            if node_id == i:
                continue
            fp.write('add-exclusive-node=127.0.0.1:{}\n'.format(XMR_BASE_P2P_PORT + i))


def prepareDataDir(datadir, node_id, conf_file):
    node_dir = os.path.join(datadir, str(node_id))
    if not os.path.exists(node_dir):
        os.makedirs(node_dir)
    cfg_file_path = os.path.join(node_dir, conf_file)
    if os.path.exists(cfg_file_path):
        return
    with open(cfg_file_path, 'w+') as fp:
        fp.write('regtest=1\n')
        fp.write('[regtest]\n')
        fp.write('port=' + str(BASE_PORT + node_id) + '\n')
        fp.write('rpcport=' + str(BASE_RPC_PORT + node_id) + '\n')

        salt = generate_salt(16)
        fp.write('rpcauth={}:{}${}\n'.format('test' + str(node_id), salt, password_to_hmac(salt, 'test_pass' + str(node_id))))

        fp.write('daemon=0\n')
        fp.write('printtoconsole=0\n')
        fp.write('server=1\n')
        fp.write('discover=0\n')
        fp.write('listenonion=0\n')
        fp.write('bind=127.0.0.1\n')
        fp.write('debug=1\n')
        fp.write('debugexclude=libevent\n')

        fp.write('fallbackfee=0.01\n')
        fp.write('acceptnonstdtxn=0\n')
        fp.write('txindex=1\n')

        fp.write('findpeers=0\n')
        # minstakeinterval=5  # Using walletsettings stakelimit instead

        for i in range(0, NUM_NODES):
            if node_id == i:
                continue
            fp.write('addnode=127.0.0.1:{}\n'.format(BASE_PORT + i))


def startXmrDaemon(node_dir, bin_dir, daemon_bin, opts=[]):
    daemon_bin = os.path.expanduser(os.path.join(bin_dir, daemon_bin))

    args = [daemon_bin, '--config-file=' + os.path.join(os.path.expanduser(node_dir), 'monerod.conf')] + opts
    logging.info('Starting node {} --data-dir={}'.format(daemon_bin, node_dir))

    return subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def startXmrWalletRPC(node_dir, bin_dir, wallet_bin, node_id, opts=[]):
    daemon_bin = os.path.expanduser(os.path.join(bin_dir, wallet_bin))

    data_dir = os.path.expanduser(node_dir)
    args = [daemon_bin]
    args += ['--daemon-address=localhost:{}'.format(XMR_BASE_RPC_PORT + node_id)]
    args += ['--no-dns']
    args += ['--rpc-bind-port={}'.format(XMR_BASE_WALLET_RPC_PORT + node_id)]
    args += ['--wallet-dir={}'.format(os.path.join(data_dir, 'wallets'))]
    args += ['--log-file={}'.format(os.path.join(data_dir, 'wallet.log'))]
    args += ['--rpc-login=test{0}:test_pass{0}'.format(node_id)]
    args += ['--shared-ringdb-dir={}'.format(os.path.join(data_dir, 'shared-ringdb'))]

    args += opts
    logging.info('Starting daemon {} --wallet-dir={}'.format(daemon_bin, node_dir))

    wallet_stdout = open(os.path.join(data_dir, 'wallet_stdout.log'), 'w')
    wallet_stderr = open(os.path.join(data_dir, 'wallet_stderr.log'), 'w')
    return subprocess.Popen(args, stdin=subprocess.PIPE, stdout=wallet_stdout, stderr=wallet_stderr, cwd=data_dir)


def startDaemon(node_dir, bin_dir, daemon_bin, opts=[]):
    daemon_bin = os.path.expanduser(os.path.join(bin_dir, daemon_bin))

    args = [daemon_bin, '-datadir=' + os.path.expanduser(node_dir)] + opts
    logging.info('Starting node {} -datadir={}'.format(daemon_bin, node_dir))

    return subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def callnoderpc(node_id, method, params=[], wallet=None):
    auth = 'test{0}:test_pass{0}'.format(node_id)
    return callrpc(BASE_RPC_PORT + node_id, auth, method, params, wallet)


def make_rpc_func(node_id):
    node_id = node_id
    auth = 'test{0}:test_pass{0}'.format(node_id)

    def rpc_func(method, params=None, wallet=None):
        nonlocal node_id, auth
        return callrpc(BASE_RPC_PORT + node_id, auth, method, params, wallet)
    return rpc_func


def checkSoftForks(ro):
    if 'bip9_softforks' in ro:
        assert(ro['bip9_softforks']['csv']['status'] == 'active')
        assert(ro['bip9_softforks']['segwit']['status'] == 'active')
    else:
        assert(ro['softforks']['csv']['active'])
        assert(ro['softforks']['segwit']['active'])


def callSwapTool(swap_file, method=None, json_params=None, str_param=None):
    testargs = ['xmrswaptool.py', swap_file]
    if method:
        testargs.append(method)
    if json_params is not None:
        testargs.append('"' + dumpje(json_params) + '"')

    if str_param is not None:
        testargs.append(str_param)

    print('testargs', ' '.join(testargs))
    with patch.object(sys, 'argv', testargs):
        with patch('sys.stdout', new=StringIO()) as fake_out:
            try:
                swapTool.main()
            except Exception as e:
                logging.info('swapTool failed: stdout: %s', fake_out.getvalue())
                raise e

            return fake_out.getvalue()


def stopNodes(self):
    self.stop_nodes = True
    if self.update_thread is not None:
        try:
            self.update_thread.join()
        except Exception:
            logging.info('Failed to join update_thread')
    self.update_thread = None

    for d in self.xmr_daemons:
        logging.info('Interrupting %d', d.pid)
        try:
            d.send_signal(signal.SIGINT)
        except Exception as e:
            logging.info('Interrupting %d, error %s', d.pid, str(e))
    for d in self.xmr_daemons:
        try:
            d.wait(timeout=20)
            if d.stdout:
                d.stdout.close()
            if d.stderr:
                d.stderr.close()
            if d.stdin:
                d.stdin.close()
        except Exception as e:
            logging.info('Closing %d, error %s', d.pid, str(e))
    self.xmr_daemons = []

    for d in self.daemons:
        logging.info('Interrupting %d', d.pid)
        try:
            d.send_signal(signal.SIGINT)
        except Exception as e:
            logging.info('Interrupting %d, error %s', d.pid, str(e))
    for d in self.daemons:
        try:
            d.wait(timeout=20)
            if d.stdout:
                d.stdout.close()
            if d.stderr:
                d.stderr.close()
            if d.stdin:
                d.stdin.close()
        except Exception as e:
            logging.info('Closing %d, error %s', d.pid, str(e))
    self.daemons = []
