#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2020 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

import unittest
from xmrswap.interface_btc import (
    testBTCInterface
)
from xmrswap.util import (
    make_int,
    format_amount,
    validate_amount
)
from xmrswap.ecc_util import b2h, h2b
from xmrswap.ed25519_fast_util import (
    hashToEd25519,
    encodepoint
)
import xmrswap.contrib.ed25519_fast as edf


class Test(unittest.TestCase):
    def test_script_checker(self):
        testBTCInterface()

    def test_make_int(self):
        def test_case(vs, vf, expect_int):
            i = make_int(vs)
            assert(i == expect_int and isinstance(i, int))
            i = make_int(vf)
            assert(i == expect_int and isinstance(i, int))
            vs_out = format_amount(i, 8)
            # Strip
            for i in range(7):
                if vs_out[-1] == '0':
                    vs_out = vs_out[:-1]
            if '.' in vs:
                assert(vs_out == vs)
            else:
                assert(vs_out[:-2] == vs)
        test_case('0', 0, 0)
        test_case('1', 1, 100000000)
        test_case('10', 10, 1000000000)
        test_case('0.00899999', 0.00899999, 899999)
        test_case('899999.0', 899999.0, 89999900000000)
        test_case('899999.00899999', 899999.00899999, 89999900899999)
        test_case('0.0', 0.0, 0)
        test_case('1.0', 1.0, 100000000)
        test_case('1.1', 1.1, 110000000)
        test_case('1.2', 1.2, 120000000)
        test_case('0.00899991', 0.00899991, 899991)
        test_case('0.0089999', 0.0089999, 899990)
        test_case('0.0089991', 0.0089991, 899910)
        test_case('0.123', 0.123, 12300000)
        test_case('123000.000123', 123000.000123, 12300000012300)

        try:
            make_int('0.123456789')
            assert(False)
        except Exception as e:
            assert(str(e) == 'Mantissa too long')
        validate_amount('0.12345678')

        # floor
        assert(make_int('0.123456789', r=-1) == 12345678)
        # Round up
        assert(make_int('0.123456789', r=1) == 12345679)

    def test_makeInt12(self):
        def test_case(vs, vf, expect_int):
            i = make_int(vs, 12)
            assert(i == expect_int and isinstance(i, int))
            i = make_int(vf, 12)
            assert(i == expect_int and isinstance(i, int))
            vs_out = format_amount(i, 12)
            # Strip
            for i in range(7):
                if vs_out[-1] == '0':
                    vs_out = vs_out[:-1]
            if '.' in vs:
                assert(vs_out == vs)
            else:
                assert(vs_out[:-2] == vs)
        test_case('0.123456789', 0.123456789, 123456789000)
        test_case('0.123456789123', 0.123456789123, 123456789123)
        try:
            make_int('0.1234567891234', 12)
            assert(False)
        except Exception as e:
            assert(str(e) == 'Mantissa too long')
        validate_amount('0.123456789123', 12)
        try:
            validate_amount('0.1234567891234', 12)
            assert(False)
        except Exception as e:
            assert('Too many decimal places' in str(e))
        try:
            validate_amount(0.1234567891234, 12)
            assert(False)
        except Exception as e:
            assert('Too many decimal places' in str(e))

    def test_ed25519(self):
        assert(encodepoint(edf.B) == b'Xfffffffffffffffffffffffffffffff')

        assert(b2h(encodepoint(hashToEd25519(encodepoint(edf.B))))
               == '13b663e5e06bf5301c77473bb2fc5beb51e4046e9b7efef2f6d1a324cb8b1094')

        test_point_2 = '97ab9932634c2a71ded409c73e84d64487dcc224f9728fde24ef3327782e68c3'
        assert(b2h(encodepoint(hashToEd25519(h2b(test_point_2))))
               == 'ade1232c101e6e42564b97ac2b38387a509df0a31d38e36bf4bdf4ad2f4f5573')


if __name__ == '__main__':
    unittest.main()
