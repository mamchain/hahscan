from ethereum.utils import sha3
from binascii import hexlify, unhexlify
from ethereum.abi import encode_abi
import ed25519
import requests
import json
import utils
import struct
import hashlib
import time

const_forkid = '00000000ed7baa7cd66a44d0c6f98efa3c3e8972bf30ef7fc3b50f043ebe5b30'

def LenHex(n):
	if n < 0xFD:
		return hexlify(struct.pack("<B", n))
	elif n <= 0xFFFF:
		return b"fd" + hexlify(struct.pack("<H", n))
	elif n <= 0xFFFFFFFF:
		return b"fe" + hexlify(struct.pack("<I", n))
	else:
		return b"ff" + hexlify(struct.pack("<Q", n))

def GetTx(ts,forkid,nTxNonce,addr,to,nAmount,nGasPrice,nGasLimit,data):
    ret = hexlify(struct.pack("<H", 1))
    ret = ret + hexlify(struct.pack("<H", 0))
    ret = ret + hexlify(struct.pack("<I", ts))
    ret = ret + hexlify(unhexlify(forkid))
    ret = ret + hexlify(struct.pack("<Q", nTxNonce))
    ret = ret + utils.Addr2Hex(addr).encode()
    ret = ret + utils.Addr2Hex(to).encode()
    ret = ret + encode_abi(["uint256","uint256","uint256"],[int(nAmount),int(nGasPrice),int(nGasLimit)]).hex().encode()
    ret = ret + data.encode()
    return ret

def call(body):
    #rpcurl = 'http://127.0.0.1:6602'
    rpcurl = 'http://124.221.253.93:6602'
    req = requests.post(rpcurl, json=body)
    resp = json.loads(req.content.decode('utf-8'))
    return resp.get('result'), resp.get('error')


# RPC: callcontract
def callcontract(from_addr, to, amount, contractparam=None):
    result, error = call({
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'callcontract',
        'params': {
            'from': from_addr,
            'to': to,
            'amount': str(amount),
            'contractparam': contractparam
        }
    })

    if result:
        return result
    else:
        print('callcontract error, error: {}'.format(error))
        return ""

def transfer(cmd_addr_key, cmd_addr,account_addr,amount):
    ts = int(time.time())
    ret = getbalance(cmd_addr)
    nTxNonce = ret[0]["nonce"] + 1
    nAmount = amount
    nGasPrice = int(0.000001 * 10**18)
    nGasLimit = 10000
    tx_data = '00'
    data = GetTx(ts,const_forkid,nTxNonce,cmd_addr,account_addr,nAmount,nGasPrice,nGasLimit,tx_data)
    blake2b = hashlib.blake2b(digest_size=32)
    blake2b.update(unhexlify(data))
    sign_hash = blake2b.hexdigest()
    sk = ed25519.SigningKey(unhexlify(cmd_addr_key)[::-1])
    sign_data = sk.sign(unhexlify(sign_hash))
    data = data.decode() + '40' + sign_data.hex()
    return data

def sendtransaction(data):
    result, error = call({
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'sendtransaction',
        'params': {
            'txdata': data
        }
    })
    if result:
        return result
    else:
        print('callcontract error, error: {}'.format(error))
        return ""

def getbalance(addr):
    result, error = call({
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'getbalance',
        'params': {
            'address': addr
        }
    })
    if result:
        return result
    else:
        print('callcontract error, error: {}'.format(error))
        return ""


### 转帐的地址和私钥
pri_key = '9ae89671cc1a74e9e404a16982ae48d21c56d4ad8278bc9755235a68fc841271'
from_ = '1231kgws0rhjtfewv57jegfe5bp4dncax60szxk8f4y546jsfkap3t5ws'

## 代币接受地址
account_addr = "1fm5t8qwjq0dn93rha9exfqc4v1jaajgqkk4wgrjjr5p7jm2qh8aa08bh"


def test_send():
    '''
    普通转账一个MNT
    '''
    amount = 10**18
    data = transfer(pri_key,from_,account_addr,amount)
    print(data)
    sendtransaction(data)

test_send()
