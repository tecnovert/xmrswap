#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2020 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

import secrets
from enum import IntEnum


def assert_cond(v, err='Bad opcode'):
    if not v:
        raise ValueError(err)


class CoinIds(IntEnum):
    PART = 1
    BTC = 2
    XMR = 3


class CoinInterface:
    def getNewSecretKey(self):
        raise ValueError('Must override')

    def getNewSecretValue(self):
        return secrets.token_bytes(32)
