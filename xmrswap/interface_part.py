#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2020 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

from .contrib.test_framework.messages import (
    CTxOutPart,
)

from .interface_btc import BTCInterface


class PARTInterface(BTCInterface):
    @staticmethod
    def witnessScaleFactor():
        return 2

    @staticmethod
    def txVersion():
        return 0xa0

    def __init__(self, rpc_callback):
        self.rpc_callback = rpc_callback
        self.txoType = CTxOutPart
