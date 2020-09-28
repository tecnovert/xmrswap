# XMR PART Atomic Swap Instructions (CLI)

The swap leader is the person exchanging PART for XMR.

## Shared setup

Both participants must start a Monero and a Particl wallet.
The swap tool will interact with both wallets over RPC.

#### XMR
Start Monero RPC wallet and attach to a public node: `node.xmr.to` (Use your own node if you have the XMR chain synced)
```
export XMRW=${HOME}/tmp/monero-x86_64-linux-gnu-v0.16.0.3/monero-wallet-rpc;
${XMRW} --daemon-address=node.xmr.to:18081 --rpc-bind-port=18777 --rpc-login=main1:main_pass1 --wallet-dir="${HOME}/xmr"
```

Test wallet is connected to node by getting the current chain height:
```
curl http://localhost:18777/json_rpc -u main1:main_pass1 --digest \
    -d '{"jsonrpc":"2.0","id":"0","method":"getheight"}' -H 'Content-Type: application/json'
```

Create an XMR wallet:
```
curl http://localhost:18777/json_rpc -u main1:main_pass1 --digest \
    -d '{"jsonrpc":"2.0","id":"0","method":"create_wallet","params":{"filename":"swap_test","language":"English"}}' -H 'Content-Type: application/json'
```

#### PART

Start the Qt Wallet with the RPC server enabled:
```
./particl-qt --server -rpcport=51735 -rpcuser=test1 -rpcpassword=test_pass1
```


#### Swap Tool
```
git clone https://github.com/tecnovert/xmrswap.git
```

```
cd xmrswap
export PYTHONPATH=$(pwd)
```

## Swap Parameters

Swap Participants agree on a few parameters
 - ADDR_FOLLOWER_OUT, the address the follower will receive PART at if the swap is successful.
 - a_amount, the amount of Particl being swapped.
 - b_amount, the amount of XMR being swapped.
 - The fees for both chains
 - The number of blocks the swap scripts lock the refund path for


## Swap steps

#### 1. Leader

```
export ADDR_FOLLOWER_OUT=...
export PARTICL_WALLET="Monero Atomic Swap"
export SWAP_FILE=${HOME}/swap1.json

export SWAP_PARAMS=$(jq -c << EOF
{
    "side": "a",
    "a_coin": "PART",
    "b_coin": "XMR",
    "a_amount": 1.0,
    "b_amount": 0.05,
    "a_feerate": 0.00032595,
    "b_feerate": 0.0005595,
    "a_addr_f": "${ADDR_FOLLOWER_OUT}",
    "lock1": 100,
    "lock2": 110,
    "b_restore_height": 2187260,
    "a_connect": {
    "port": 51735,
    "username": "test1",
    "password": "test_pass1",
    "wallet": "${PARTICL_WALLET}"},
    "b_connect": {
    "host": "node.xmr.to",
    "port": 18081,
    "wallet_port": 18777,
    "wallet_auth": ["main1","main_pass1"]}
}
EOF
)

python3 bin/xmrswaptool.py "${SWAP_FILE}" init "${SWAP_PARAMS}"
python3 bin/xmrswaptool.py "${SWAP_FILE}" msg1f > "${HOME}/msg1f.txt"
```

Send msg1f.txt to follower.

#### 2. Follower

```
export ADDR_FOLLOWER_OUT=...
export PARTICL_WALLET="wallet.dat"
export SWAP_FILE=${HOME}/swap1.json

export SWAP_PARAMS=$(jq -c << EOF
{
    "side": "b",
    "a_coin": "PART",
    "b_coin": "XMR",
    "a_amount": 1.0,
    "b_amount": 0.05,
    "a_feerate": 0.00032595,
    "b_feerate": 0.0005595,
    "a_addr_f": "${ADDR_FOLLOWER_OUT}",
    "lock1": 100,
    "lock2": 110,
    "b_restore_height": 2188071,
    "check_a_lock_tx_inputs": false,
    "a_connect": {
    "port": 51735,
    "username": "test1",
    "password": "test_pass1",
    "wallet": "${PARTICL_WALLET}"},
    "b_connect": {
    "host": "node.xmr.to",
    "port": 18081,
    "wallet_port": 18777,
    "wallet_auth": ["main1","main_pass1"]}
}
EOF
)
python3 bin/xmrswaptool.py "${SWAP_FILE}" init "${SWAP_PARAMS}"
python3 bin/xmrswaptool.py "${SWAP_FILE}" msg1l > "${HOME}/msg1l.txt"
```

Send msg1l.txt to leader.


#### 3. Leader

```
python3 bin/xmrswaptool.py "${SWAP_FILE}" processmsg "$(< ${HOME}/msg1l.txt)"
success
```


#### 4. Follower

```
python3 bin/xmrswaptool.py "${SWAP_FILE}" processmsg "$(< ${HOME}/msg1f.txt)"
success
```


#### 5. Leader

Create the script-chain lock and refund txns and signs the refund tx:
```
python3 bin/xmrswaptool.py "${SWAP_FILE}" msg2f > "${HOME}/msg2f.txt"
```

Send msg2f.txt to follower.


#### 6. Follower

Verify the transactions created by the leader:
```
python3 bin/xmrswaptool.py "${SWAP_FILE}" processmsg "$(< ${HOME}/msg2f.txt)"
success
```

Create an encrypted signature for the refund spend tx encumbered by the leader's XMR key share:
```
python3 bin/xmrswaptool.py "${SWAP_FILE}" msg3l > "${HOME}/msg3l.txt"
```

Send msg3l.txt to leader.


#### 7. Leader

Verify the signature and encrypted signature from the follower:
```
python3 bin/xmrswaptool.py "${SWAP_FILE}" processmsg "$(< ${HOME}/msg3l.txt)"
```

Create the lock spend tx and sign an encrypted signature encumbered by the follower's XMR key share:
```
python3 bin/xmrswaptool.py "${SWAP_FILE}" msg4f > "${HOME}/msg4f.txt"
```

Publish the script-chain lock tx:
```
python3 bin/xmrswaptool.py "${SWAP_FILE}" publishalocktx
```

Send msg4f.txt to follower.


#### 8. Follower

Verify the lock spend tx and encrypted signature from the leader:
```
python3 bin/xmrswaptool.py "${SWAP_FILE}" processmsg "$(< ${HOME}/msg4f.txt)"
success
```

Wait for the lock txn to confirm:
```
python3 bin/xmrswaptool.py "${SWAP_FILE}" confirmalocktx
```
Repeat until `True`

Then publish the scriptless-chain lock tx:
```
python3 bin/xmrswaptool.py "${SWAP_FILE}" publishblocktx
```

#### 9. Leader

Wait for the scriptless-chain lock tx to confirm:
```
python3 bin/xmrswaptool.py "${SWAP_FILE}" confirmblocktx
```
Repeat until `True`

Share the swap secret value with the follower, allowing the script-chain lock tx to be spent:
```
python3 bin/xmrswaptool.py "${SWAP_FILE}" msg5f > "${HOME}/msg5f.txt"
```

Send msg5f.txt to follower.


#### 10. Follower

Receive the swap secret from the leader:
```
python3 bin/xmrswaptool.py "${SWAP_FILE}" processmsg "$(< ${HOME}/msg5f.txt)"
success
```

Spend from the script-chain lock tx:
```
python3 bin/xmrswaptool.py "${SWAP_FILE}" publishalockspendtx
```

Received the swapped PART.


#### 11. Leader

Look for the follower's script-chain lock spend tx and extract the sig:
```
python3 bin/xmrswaptool.py "${SWAP_FILE}" findalockspendtx
```
Repeat until `True`


Get an address to receive the swapped XMR:
```
curl http://localhost:18777/json_rpc -u main1:main_pass1 --digest \
    -d '{"jsonrpc":"2.0","id":"0","method":"open_wallet","params":{"filename":"swap_test"}}' -H 'Content-Type: application/json'
export XMR_OUTPUT_ADDR=$(curl http://localhost:18777/json_rpc -u main1:main_pass1 --digest \
    -d '{"jsonrpc":"2.0","id":"0","method":"getaddress"}' -H 'Content-Type: application/json' | jq -r '.result["address"]')
```

Redeem the scriptless-chain lock tx to XMR_OUTPUT_ADDR
```
python3 bin/xmrswaptool.py "${SWAP_FILE}" redeemblocktx "${XMR_OUTPUT_ADDR}"
```


```
curl http://localhost:18777/json_rpc -u main1:main_pass1 --digest \
    -d '{"jsonrpc":"2.0","id":"0","method":"getbalance"}' -H 'Content-Type: application/json'
```

Received the swapped XMR.
