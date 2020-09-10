#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2020 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

import json
import decimal


OP_1 = 0x51
OP_16 = 0x60


def make_boolean(s):
    return s.lower() in ['1', 'true']


def dquantize(n):
    return n.quantize(decimal.Decimal(10) ** -8)


def jsonDecimal(obj):
    if isinstance(obj, decimal.Decimal):
        return str(obj)
    raise TypeError


def dumpj(jin):
    return json.dumps(jin, indent=4, default=jsonDecimal)


def dumpje(jin):
    return json.dumps(jin, indent=None, default=jsonDecimal).replace('"', '\\"')


def decodeScriptNum(script_bytes, o):
    v = 0
    num_len = script_bytes[o]
    if num_len >= OP_1 and num_len <= OP_16:
        return((num_len - OP_1) + 1, 1)

    if num_len > 4:
        raise ValueError('Bad scriptnum length')  # Max 4 bytes
    if num_len + o >= len(script_bytes):
        raise ValueError('Bad script length')
    o += 1
    for i in range(num_len):
        b = script_bytes[o + i]
        # Negative flag set in last byte, if num is positive and > 0x80 an extra 0x00 byte will be appended
        if i == num_len - 1 and b & 0x80:
            b &= (~(0x80) & 0xFF)
            v += int(b) << 8 * i
            v *= -1
        else:
            v += int(b) << 8 * i
    return(v, 1 + num_len)


def getCompactSizeLen(v):
    # Compact Size
    if v < 253:
        return 1
    if v < 0xffff:  # USHRT_MAX
        return 3
    if v < 0xffffffff:  # UINT_MAX
        return 5
    if v < 0xffffffffffffffff:  # UINT_MAX
        return 9
    raise ValueError('Value too large')


def make_int(v, precision=8, r=0):  # r = 0, no rounding, fail, r > 0 round up, r < 0 floor
    if type(v) == float:
        v = str(v)
    elif type(v) == int:
        return v * 10 ** precision

    ep = 10 ** precision
    have_dp = False
    rv = 0
    for c in v:
        if c == '.':
            rv *= ep
            have_dp = True
            continue
        if not c.isdigit():
            raise ValueError('Invalid char')
        if have_dp:
            ep //= 10
            if ep <= 0:
                if r == 0:
                    raise ValueError('Mantissa too long')
                if r > 0:
                    # Round up
                    if int(c) > 4:
                        rv += 1
                break

            rv += ep * int(c)
        else:
            rv = rv * 10 + int(c)
    if not have_dp:
        rv *= ep
    return rv


def validate_amount(amount, precision=8):
    str_amount = str(amount)
    has_decimal = False
    for c in str_amount:
        if c == '.' and not has_decimal:
            has_decimal = True
            continue
        if not c.isdigit():
            raise ValueError('Invalid amount')

    ar = str_amount.split('.')
    if len(ar) > 1 and len(ar[1]) > precision:
        raise ValueError('Too many decimal places in amount {}'.format(str_amount))
    return True


def format_amount(i, display_precision, precision=None):
    if precision is None:
        precision = display_precision
    ep = 10 ** precision
    n = abs(i)
    quotient = n // ep
    remainder = n % ep
    if display_precision != precision:
        remainder %= (10 ** display_precision)
    rv = '{}.{:0>{prec}}'.format(quotient, remainder, prec=display_precision)
    if i < 0:
        rv = '-' + rv
    return rv
