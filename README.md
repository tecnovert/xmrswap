
# XMR Cross-chain Atomic Swap Demo

## Overview

Implementation of the h4sh3d Bitcoin–Monero Cross-chain Atomic Swap protocol.  
https://github.com/h4sh3d/xmr-btc-atomic-swap/blob/master/whitepaper/xmr-btc.pdf

Use at your own risk.


Run tests without installing module:
```
export PYTHONPATH=$(pwd)
export BITCOIN_BINDIR=~/tmp/bitcoin-0.19.0.1/bin;
export PARTICL_BINDIR=~/tmp/particl-0.19.1.1/bin;
export XMR_BINDIR=~/tmp/monero-x86_64-linux-gnu-v0.16.0.3;
python setup.py test
```

Individually:
```
python setup.py test -s tests.xmrswap.test_run.Test.test_01_swap_successful
python setup.py test -s tests.xmrswap.test_part.Test
python tests/xmrswap/test_other.py
python tests/xmrswap/test_run.py
python tests/xmrswap/test_part.py
```

Run lint checks:
```
PYTHONWARNINGS="ignore" flake8 --ignore=E501,F841,W503 --exclude=xmrswap/contrib,.eggs
codespell --check-filenames --disable-colors --quiet-level=7 --ignore-words=tests/lint/spelling.ignore-words.txt -S contrib,.git,.eggs,*.pyc
```
