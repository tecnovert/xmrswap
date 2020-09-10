# -*- coding: utf-8 -*-

# Copyright (c) 2020 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

import os
import time
import json
import urllib
import logging
import requests
import traceback
import subprocess
from xmlrpc.client import (
    Transport,
    Fault,
)

from .util import jsonDecimal


def waitForRPC(rpc_func, wallet=None):
    for i in range(5):
        try:
            rpc_func('getwalletinfo')
            return
        except Exception as ex:
            logging.warning('Can\'t connect to daemon RPC: %s.  Trying again in %d second/s.', str(ex), (1 + i))
            time.sleep(1 + i)
    raise ValueError('waitForRPC failed')


class Jsonrpc():
    # __getattr__ complicates extending ServerProxy
    def __init__(self, uri, transport=None, encoding=None, verbose=False,
                 allow_none=False, use_datetime=False, use_builtin_types=False,
                 *, context=None):
        # establish a "logical" server connection

        # get the url
        parsed = urllib.parse.urlparse(uri)
        if parsed.scheme not in ("http", "https"):
            raise OSError("unsupported XML-RPC protocol")
        self.__host = parsed.netloc
        self.__handler = parsed.path
        if not self.__handler:
            self.__handler = "/RPC2"

        if transport is None:
            handler = Transport
            extra_kwargs = {}
            transport = handler(use_datetime=use_datetime,
                                use_builtin_types=use_builtin_types,
                                **extra_kwargs)
        self.__transport = transport

        self.__encoding = encoding or 'utf-8'
        self.__verbose = verbose
        self.__allow_none = allow_none

    def close(self):
        if self.__transport is not None:
            self.__transport.close()

    def json_request(self, method, params):
        try:
            connection = self.__transport.make_connection(self.__host)
            headers = self.__transport._extra_headers[:]

            request_body = {
                'method': method,
                'params': params,
                'id': 2
            }

            connection.putrequest("POST", self.__handler)
            headers.append(("Content-Type", "application/json"))
            headers.append(("User-Agent", 'jsonrpc'))
            self.__transport.send_headers(connection, headers)
            self.__transport.send_content(connection, json.dumps(request_body, default=jsonDecimal).encode('utf-8'))

            resp = connection.getresponse()
            return resp.read()

        except Fault:
            raise
        except Exception:
            # All unexpected errors leave connection in
            # a strange state, so we clear it.
            self.__transport.close()
            raise


def callrpc(rpc_port, auth, method, params=[], wallet=None, path=''):
    try:
        url = 'http://{}@127.0.0.1:{}/{}'.format(auth, rpc_port, path)
        if wallet:
            url += 'wallet/' + wallet
        x = Jsonrpc(url)

        v = x.json_request(method, params)
        x.close()
        r = json.loads(v.decode('utf-8'))
    except Exception as ex:
        traceback.print_exc()
        raise ValueError('RPC Server Error')

    if 'error' in r and r['error'] is not None:
        raise ValueError('RPC error ' + str(r['error']))

    return r['result']


def callrpc_cli(bindir, datadir, chain, cmd, cli_bin='particl-cli'):
    cli_bin = os.path.join(bindir, cli_bin)

    args = cli_bin + ('' if chain == 'mainnet' else ' -' + chain) + ' -datadir=' + datadir + ' ' + cmd
    p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    out = p.communicate()

    if len(out[1]) > 0:
        raise ValueError('RPC error ' + str(out[1]))

    r = out[0].decode('utf-8').strip()
    try:
        r = json.loads(r)
    except Exception:
        pass
    return r


def callrpc_xmr(rpc_port, auth, method, params=[], wallet=None, path='json_rpc'):
    # auth is a tuple: (username, password)
    try:
        url = 'http://127.0.0.1:{}/{}'.format(rpc_port, path)
        request_body = {
            'method': method,
            'params': params,
            'id': 2,
            'jsonrpc': '2.0'
        }
        headers = {
            'content-type': 'application/json'
        }
        p = requests.post(url, data=json.dumps(request_body), auth=requests.auth.HTTPDigestAuth(auth[0], auth[1]), headers=headers)
        r = json.loads(p.text)
    except Exception as ex:
        traceback.print_exc()
        raise ValueError('RPC Server Error')

    if 'error' in r and r['error'] is not None:
        raise ValueError('RPC error ' + str(r['error']))

    return r['result']


def callrpc_xmr_na(rpc_port, method, params=[], path='json_rpc'):
    try:
        url = 'http://127.0.0.1:{}/{}'.format(rpc_port, path)
        request_body = {
            'method': method,
            'params': params,
            'id': 2,
            'jsonrpc': '2.0'
        }
        headers = {
            'content-type': 'application/json'
        }
        p = requests.post(url, data=json.dumps(request_body), headers=headers)
        r = json.loads(p.text)
    except Exception as ex:
        traceback.print_exc()
        raise ValueError('RPC Server Error')

    if 'error' in r and r['error'] is not None:
        raise ValueError('RPC error ' + str(r['error']))

    return r['result']


def callrpc_xmr2(rpc_port, method, params=[]):
    try:
        url = 'http://127.0.0.1:{}/{}'.format(rpc_port, method)
        headers = {
            'content-type': 'application/json'
        }
        p = requests.post(url, data=json.dumps(params), headers=headers)
        r = json.loads(p.text)
    except Exception as ex:
        traceback.print_exc()
        raise ValueError('RPC Server Error')

    return r
