#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2020 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

import os
import unittest

from tests.xmrswap.common import (
    TEST_DATADIRS,
    callSwapTool
)


class Test(unittest.TestCase):
    def test_decode_p2wpkh(self):
        swap_file = os.path.join(TEST_DATADIRS, 'test') + '.json'

        swap_info = {
            'side': 'a',
            'a_coin': 'PART',
            'b_coin': 'XMR',
            'a_amount': 1,
            'b_amount': 2,
            'a_feerate': 0.00032595,
            'b_feerate': 0.0012595,
            'a_addr_f': 'bart1qy68z7jn0mz64cpcgq77uvlp8h0yxmsdpsq6a6j',
            'lock1': 10,
            'lock2': 11,
        }
        swap_info['a_connect'] = {
            'port': 1234,
            'username': 'test{}'.format(123),
            'password': 'test_pass{0}'.format(123)}
        swap_info['b_connect'] = {
            'port': 1235,
            'wallet_port': 123,
            'wallet_auth': '123',
        }
        try:
            callSwapTool(swap_file, 'init', swap_info)
            assert(False), 'Should fail'
        except Exception as e:
            assert('Unknown bech32 hrp' in str(e))


if __name__ == '__main__':
    unittest.main()
