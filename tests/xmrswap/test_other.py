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


class Test(unittest.TestCase):
    def test_script_checker(self):
        testBTCInterface()

    def test_makeInt(self):
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


if __name__ == '__main__':
    unittest.main()
