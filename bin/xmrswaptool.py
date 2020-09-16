#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2020 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

"""
Method arguments:
info            - Display swap information.
init json_obj   - Initialise swap to parameters.
{
    'side': a/b, Side of swap user is on.
    'a_coin': coin_acronym, coin chain must support output scripts,
    'b_coin': coin_acronym,
    'a_amount': value of a_coin to swap,
    'b_amount': value of b_coin to swap,
    'a_feerate': fee rate per 1k bytes for a_coin transactions,
    'b_feerate': fee rate per 1k bytes for b_coin transactions,
    'a_connect': connection details for a_coin interface,
    'b_connect': connection details for b_coin interface,
}
processmsg <hex_msg>        - Process message from peer
msg1f                       - Output message to peer
msg1l                       - Output message to peer
msg2f                       - Output message to peer
msg3l                       - Output message to peer
msg4f                       - Output message to peer
msg5f                       - Output message to peer
publishalocktx              - Publish script-chain lock tx
publishalockrefundtx        - Publish script-chain lock refund tx
confirmalocktx              - Check script-chain for lock tx
publishblocktx              - Publish scriptless-chain lock tx
confirmblocktx              - Check scriptless-chain for lock tx
publishalockspendtx         - Publish script-chain lock spend tx
findalockspendtx            - Check script-chain for lock spend tx
redeemblocktx <dest>        - Redeem scriptless-chain lock tx to <dest>
publishalockrefundspendtx   - Spend from refund tx back to leader
getkal                      - Print kal key.
publishalockrefundspendftx  - Spend from refund tx to follower
findalockrefundspendtx      - Check script-chain for lock refund spend tx
"""

import os
import json
import logging
import argparse

from xmrswap import __version__

from xmrswap.atomic_swap import SwapInfo, CoinIds, makeInterface
from xmrswap.util import (
    make_int
)
from xmrswap.ecc_util import (
    b2h, h2b, i2h
)
from xmrswap.contrib.test_framework import segwit_addr


def printSwapInfo(swapinfo):
    print('TODO')


def initialiseSwap(swapinfo, data):
    try:
        a_coin = CoinIds[data['a_coin']]
    except Exception as e:
        raise ValueError('Unknown A coin type')

    # Coin A must have a script
    if a_coin == CoinIds.XMR:
        raise ValueError('Bad A coin type')

    try:
        b_coin = CoinIds[data['b_coin']]
    except Exception as e:
        raise ValueError('Unknown B coin type')

    swapinfo.a_connect = data['a_connect']
    swapinfo.b_connect = data['b_connect']
    ai = makeInterface(a_coin, swapinfo.a_connect)
    bi = makeInterface(b_coin, swapinfo.b_connect)

    a_amount = make_int(data['a_amount'], ai.exp())
    b_amount = make_int(data['b_amount'], bi.exp())

    a_feerate = make_int(data['a_feerate'], ai.exp())
    b_feerate = make_int(data['b_feerate'], bi.exp())

    if 'a_addr_f' in data:
        # Decode p2wpkh address
        addr = data['a_addr_f']
        addr_split = addr.split('1')
        if len(addr_split) != 2:
            raise ValueError('Invalid bech32 address')

        if addr_split[0] not in ['bc', 'pw', 'bcrt', 'rtpw']:
            raise ValueError('Unknown bech32 hrp')

        ignr, pkh = segwit_addr.decode(addr_split[0], addr)
        a_pkhash_f = bytes(pkh)
    else:
        a_pkhash_f = h2b(data['a_pkhash_f'])

    lock1 = data['lock1'] if 'lock1' in data else 100
    lock2 = data['lock2'] if 'lock2' in data else 101

    restore_height_b = data['b_restore_height'] if 'b_restore_height' in data else 0

    check_a_lock_tx_inputs = data['check_a_lock_tx_inputs'] if 'check_a_lock_tx_inputs' in data else True

    swapinfo.setSwapParameters(a_coin, a_amount, b_coin, b_amount, a_feerate, b_feerate, a_pkhash_f, lock1=lock1, lock2=lock2, restore_height_b=restore_height_b, check_a_lock_tx_inputs=check_a_lock_tx_inputs)

    if data['side'].lower() == 'a':
        swapinfo.initialiseLeader(ai, bi)
    elif data['side'].lower() == 'b':
        swapinfo.initialiseFollower(ai, bi)
    else:
        raise ValueError('Unknown swap side')


def toJSON(data):
    rv = json.loads(data)
    if isinstance(rv, str):  # Hack for tests
        rv = json.loads(rv)
    return rv


def main():

    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    parser.add_argument('-v', '--version', action='version',
                        version='%(prog)s {version}'.format(version=__version__))
    parser.add_argument('swap_state_file', help='Path to the swap state file')
    parser.add_argument('opts', nargs=argparse.REMAINDER)
    args = parser.parse_args()

    swapinfo = SwapInfo()

    if os.path.isfile(args.swap_state_file):
        swapinfo.importFromFile(args.swap_state_file)

    if len(args.opts) == 0:
        method = 'info'
    else:
        method = args.opts[0]

    if method == 'info':
        printSwapInfo(swapinfo)
        return 0
    elif method == 'init':
        data = toJSON(args.opts[1])
        initialiseSwap(swapinfo, data)
        print('success')
    elif method == 'processmsg':
        msg = h2b(args.opts[1])
        swapinfo.processMessage(msg)
        print('success')
    elif method == 'msg1f':
        msg = swapinfo.packageInitMsgToFollower()
        print(b2h(msg))
    elif method == 'msg1l':
        msg = swapinfo.packageInitMsgToLeader()
        print(b2h(msg))
    elif method == 'msg2f':
        msg = swapinfo.packageMSG2F()
        print(b2h(msg))
    elif method == 'msg3l':
        msg = swapinfo.packageMSG3L()
        print(b2h(msg))
    elif method == 'msg4f':
        msg = swapinfo.packageMSG4F()
        print(b2h(msg))
    elif method == 'msg5f':
        msg = swapinfo.packageMSG5F()
        print(b2h(msg))
    elif method == 'publishalocktx':
        txid = swapinfo.publishALockTx()
        print(txid)
    elif method == 'publishalockrefundtx':
        txid = swapinfo.publishALockRefundTx()
        print(txid)
    elif method == 'confirmalocktx':
        rv = swapinfo.hasALockTxConfirmed()
        print('True' if rv else 'False')
        return 0
    elif method == 'publishblocktx':
        txid = swapinfo.publishBLockTx()
        print(txid)
    elif method == 'confirmblocktx':
        rv = swapinfo.hasBLockTxConfirmed()
        print('True' if rv else 'False')
        return 0
    elif method == 'publishalockspendtx':
        txid = swapinfo.publishALockSpendTx()
        print(txid)
    elif method == 'findalockspendtx':
        rv = swapinfo.findALockSpendTx()
        print('True' if rv else 'False')
    elif method == 'redeemblocktx':
        dest = args.opts[1]
        txid = swapinfo.redeemBLockTx(dest)
        print(txid)
    elif method == 'publishalockrefundspendtx':
        txid = swapinfo.publishALockRefundSpendTx()
        print(txid)
    elif method == 'getkal':
        print(i2h(swapinfo.kal))
        return 0
    elif method == 'publishalockrefundspendftx':
        dest = h2b(args.opts[1])
        txid = swapinfo.publishALockRefundSpendToFTx(dest)
        print(txid)
    elif method == 'findalockrefundspendtx':
        rv = swapinfo.findALockRefundSpendTx()
        print('True' if rv else 'False')
    else:
        raise ValueError('Invalid method')

    swapinfo.exportToFile(args.swap_state_file)

    return 0


if __name__ == '__main__':
    logger = logging.getLogger()
    logger.propagate = False
    logger.setLevel(logging.INFO)  # DEBUG shows many messages from requests.post
    formatter = logging.Formatter('%(asctime)s %(levelname)s : %(message)s')
    stream_stdout = logging.StreamHandler()
    stream_stdout.setFormatter(formatter)
    logger.addHandler(stream_stdout)
    main()
