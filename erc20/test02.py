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

def transfer_data(addr,amount):
    fun_sig = sha3("transfer(address,uint256)")[28:].hex()
    account_pub = hexlify(unhexlify(utils.Addr2Hex(addr)[2:])[::-1])
    call_data = fun_sig + encode_abi(["bytes32","uint256"],[unhexlify(account_pub),int(amount)]).hex()
    data = '01030144' + call_data
    return data



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

def balanceOf(cmd_addr,contract_addr,account_addr):
    account_pub = hexlify(unhexlify(utils.Addr2Hex(account_addr)[2:])[::-1])
    call_data = sha3("balanceOf(address)")[28:].hex() + account_pub.decode()
    ret = callcontract(account_addr,contract_addr,0,call_data)
    return int(ret["result"],16)

def totalSupply(account_addr,contract_addr):
    FunSig = sha3("totalSupply()")[28:].hex()
    ret = callcontract(account_addr,contract_addr,0,FunSig)
    return int(ret["result"],16)

def transfer(cmd_addr_key, cmd_addr, contract_addr,account_addr,amount):
    ts = int(time.time())
    ret = getbalance(cmd_addr)
    nTxNonce = ret[0]["nonce"] + 1
    nAmount = 0
    nGasPrice = int(0.000001 * 10**18)
    nGasLimit = 990000
    tx_data = transfer_data(account_addr,amount)
    data = GetTx(ts,const_forkid,nTxNonce,cmd_addr,contract_addr,nAmount,nGasPrice,nGasLimit,tx_data)
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

##  这个地址是合约地址
contract_addr = '3rs23z3qt1peh6vfzgp9q3a30w8kcbpt2r432vfkb8yd90nzxtjcsswxp' 

def test_send():
    '''
    测试给指定的地址转一定量的代币
    '''
    amount = 10**18
    data = transfer(pri_key,from_,contract_addr,account_addr,amount)
    #print(data)
    sendtransaction(data)
#test_send()
ret = balanceOf(from_,contract_addr,account_addr)
print(ret)

ret = totalSupply(from_,contract_addr)
print(ret)

# 钱包实现示例参考
# https://gitee.com/shangqingdong/sugar

# 助记词生成规则示例
# https://github.com/dabankio/wallet-core

# 币的地址生成标准
# https://github.com/satoshilabs/slips/blob/master/slip-0044.md
# 548 	0x80000224 	BBC 	BigBang Core

# 地址生成
# curl -d '{"id":42,"method":"makekeypair","jsonrpc":"2.0","params":{}}' http://124.221.253.93:6602


# 通过公钥得到地址
# curl -d '{"id":44,"method":"getpubkeyaddress","jsonrpc":"2.0","params":{"pubkey":"e8e3770e774d5ad84a8ea65ed08cc7c5c30b42e045623604d5c5c6be95afb4f9"}}' http://124.221.253.93:6602
