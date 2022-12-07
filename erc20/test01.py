from ethereum.utils import sha3
from binascii import hexlify, unhexlify
from ethereum.abi import encode_abi
import ed25519
import requests
import json
import utils
import swaplib
import struct
import hashlib

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
    ts = 1661164315
    nTxNonce = 5
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

transaction = {
        "txid" : "d18263035b1b129caeb7e7ae7fb43cc1974c56ecc769cc02f6ae82718be598c2",
        "sign_hash" : "07746391e0ab101f148a1a67030b5d34e81f67de8ed225c53ec35eb4995a9be0",
        "version" : 1,
        "type" : "token",
        "time" : 1661164315,
        "nonce" : 5,
        "from" : "1231kgws0rhjtfewv57jegfe5bp4dncax60szxk8f4y546jsfkap3t5ws",
        "to" : "3amx5nmantt9q6dp5yf4css5rm01wekzkg4hqp8r8zz83dqaeg3r3rg0n",
        "amount" : "0.0",
        "gaslimit" : 990000,
        "gasprice" : "0.000001",
        "gasused" : 21001,
        "txfee" : "0.021001",
        "data" : "0103014447c9049b7d0ba45f92b81b548f11525dd7dd84d864a54a179cc9c86252c16c7950578a140000000000000000000000000000000000000000000000000de0b6b3a7640000",
        "sig" : "c4e00592b8fc979060bff13edf69b8d346b525a32989b2b0751de9d0cd0e84fc3f1a2a52f0aaa7edf44da7da2be881f20401cee49d729bbfb98268efc2126303",
        "fork" : "00000000ed7baa7cd66a44d0c6f98efa3c3e8972bf30ef7fc3b50f043ebe5b30",
        "height" : 421,
        "blockhash" : "000001a55ce3a58913a3e3c74848b4163613d6e4a78cf821bbb7d8eebbd07a27",
        "confirmations" : 0,
        "serialization" : "010000001b5b036300000000ed7baa7cd66a44d0c6f98efa3c3e8972bf30ef7fc3b50f043ebe5b30050000000000000001ac9a2f4b438a270fcdfe33305db1da885dc53de8e4299bbba765c4207338c31003f0804edd36d0ff08237b2381f34fc703a0b8e4ccc8f3c5367393d655d15a3a550000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e8d4a5100000000000000000000000000000000000000000000000000000000000000f1b300103014447c9049b7d0ba45f92b81b548f11525dd7dd84d864a54a179cc9c86252c16c7950578a140000000000000000000000000000000000000000000000000de0b6b3a764000040c4e00592b8fc979060bff13edf69b8d346b525a32989b2b0751de9d0cd0e84fc3f1a2a52f0aaa7edf44da7da2be881f20401cee49d729bbfb98268efc2126303"
    }



token0_txid = swaplib.createContract(transaction['from'],"erc20.wasm","")
ret = swaplib.run_cmd("gettransactionreceipt " + token0_txid)
token0 = json.loads(ret)["contractaddress"]
print(token0)
exit()


#token0 = '3tkfrcre31xy68t94tdxgf22k8qs5psepk83nv3wpp3z7q5t3nrhkv0r9'
#pri_key = '9ae89671cc1a74e9e404a16982ae48d21c56d4ad8278bc9755235a68fc841271'
#account_addr = "1fm5t8qwjq0dn93rha9exfqc4v1jaajgqkk4wgrjjr5p7jm2qh8aa08bh"


#ret = totalSupply(account_addr,token0)
#print(ret)
#exit()

amount = 10**18
data = transfer(pri_key,transaction['from'],transaction['to'],account_addr,amount)
assert(data == transaction["serialization"])

ret = balanceOf(transaction['from'],transaction['to'],account_addr)
print(ret)

ret = totalSupply(transaction['from'],transaction['to'])
print(ret)

