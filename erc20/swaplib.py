#!/usr/bin/env python
# -*- coding: utf-8 -*-

import subprocess
import json
import time
from typing import Tuple
from ethereum.utils import sha3
from binascii import hexlify, unhexlify
from ethereum.abi import encode_abi
import requests
import utils

gasPrice = 10000

def call(body):
    #rpcurl = 'http://127.0.0.1:6602'
    rpcurl = 'http://124.221.253.93:6603'
    req = requests.post(rpcurl, json=body)
    resp = json.loads(req.content.decode('utf-8'))
    return resp.get('result'), resp.get('error')

def createcontract(from_addr, to_addr, amount, contractcode, contractparam):
    result, error = call({
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'sendfrom',
        'params': {
            'from': from_addr,
            'to': to_addr,
            'amount': str(amount),
            'contractcode': contractcode,
            'contractparam': contractparam
        }
    })

    if result:
        txid = result
        return txid, 0
    else:
        print('createcontract sendfrom error, error: {}'.format(error))
        return "", -1

def createContract(fromaddress, file, cparam):
    f = open(file,'rb')
    wasmcode = f.read().hex()
    f.close()
    txid,err = createcontract(fromaddress, '0', 0, wasmcode, cparam)
    print('createcontract ret: {}, txid: {}'.format(err,txid))
    return txid

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

def run_cmd(cmd):
	cmdline = "metabasenet-cli " + cmd
	info = subprocess.run(cmdline, shell=True,stdout=subprocess.PIPE,universal_newlines=True)
	return info.stdout

def totalSupply(account_addr,contract_addr):
    FunSig = sha3("totalSupply()")[28:].hex()
    ret = callcontract(account_addr,contract_addr,0,FunSig)
    return int(ret["result"],16)

def transfer(cmd_addr, contract_addr,account_addr,amount):
    fun_sig = sha3("transfer(address,uint256)")[28:].hex()
    account_pub = utils.Addr2Hex(account_addr)[2:]
    call_data = fun_sig + encode_abi(["bytes32","uint256"],[unhexlify(account_pub),int(amount)]).hex()
    cmd = "sendfrom %s %s 0 -cp=%s" % (cmd_addr,contract_addr,call_data)
    ret = run_cmd(cmd)
    print("erc20转账:",ret.strip())

def balanceOf(cmd_addr,contract_addr,account_addr):
    cmd = "getaddresskey " + account_addr
    account_pub = run_cmd(cmd).strip()
    account_pub = hexlify(unhexlify(account_pub)[::-1]).decode()
    call_data = sha3("balanceOf(address)")[28:].hex() + account_pub
    ret = callcontract(account_addr,contract_addr,0,call_data)
    return int(ret["result"],16)

def allowance(cmd_addr,contract_addr,owner,spender):
    cmd = "getaddresskey " + owner
    owne_pub = run_cmd(cmd).strip()
    owne_pub = hexlify(unhexlify(owne_pub)[::-1]).decode()

    cmd = "getaddresskey " + spender
    spender_pub = run_cmd(cmd).strip()
    spender_pub = hexlify(unhexlify(spender_pub)[::-1]).decode()

    call_data = sha3("allowance(address,address)")[28:].hex() + owne_pub + spender_pub
    #cmd = "callcontract %s %s 0 -cp=%s" % (cmd_addr,contract_addr,call_data)
    ret = callcontract(cmd_addr,contract_addr,0,call_data)
    return int(ret["result"],16)

def approve(cmd_addr, contract_addr, spender, value):
    #"getpubkeyaddress " + spender
    cmd = "getaddresskey " + spender
    spender_pub = run_cmd(cmd).strip()
    spender_pub = hexlify(unhexlify(spender_pub)[::-1]).decode()

    fun_sig = sha3("approve(address,uint256)")[28:].hex()
    call_data = fun_sig + encode_abi(["bytes32","uint256"],[unhexlify(spender_pub),int(value)]).hex()
    cmd = "sendfrom %s %s 0 -cp=%s" % (cmd_addr,contract_addr,call_data)
    ret = run_cmd(cmd)
    print("approve:",ret.strip())

def wait_for_height():
    cmd = "getforkheight"
    ret = run_cmd(cmd)
    while True:
        time.sleep(1)
        ret1 = run_cmd(cmd)
        if ret != ret1:
            break

def getReserves(cmd_addr,contract_addr):
    call_data = sha3("getReserves()")[28:].hex()
    cmd = "callcontract %s %s 0 -d=%s" % (cmd_addr,contract_addr,call_data)
    ret = callcontract(cmd_addr,contract_addr,0,call_data)
    return ret["result"]

def mint(cmd_addr,contract_addr,account_addr):
    cmd = "getaddresskey " + account_addr
    account_pub = run_cmd(cmd).strip()
    account_pub = hexlify(unhexlify(account_pub)[::-1]).decode()
    call_data = sha3("mint(address)")[28:].hex() + account_pub
    cmd = "sendfrom %s %s 0 -g=99000000 -cp=%s" % (cmd_addr,contract_addr,call_data)
    ret = run_cmd(cmd)
    print("mint:",ret.strip())

def Swap(addr,token0,pair,swapAmount,expectedOutputAmount,addr2):
    transfer(addr,token0,pair,swapAmount)
    fun_sig = sha3("swap(uint256,uint256,address)")[28:].hex()
    cmd = "getaddresskey " + addr2
    account_pub = run_cmd(cmd).strip()
    account_pub = hexlify(unhexlify(account_pub)[::-1]).decode()
    call_data = fun_sig + encode_abi(["uint256","uint256","bytes32"],[0,expectedOutputAmount,unhexlify(account_pub)]).hex()
    cmd = "sendfrom %s %s 0 -g=99000000 -cp=%s" % (addr,pair,call_data)
    ret = run_cmd(cmd)
    print("Swap:",ret.strip())


def GetPair(cmd_addr,contract_addr,token0,token1):
    cmd = "getaddresskey " + token0
    account_pub0 = run_cmd(cmd).strip()
    account_pub0 = hexlify(unhexlify(account_pub0)[::-1]).decode()
    cmd = "getaddresskey " + token1
    account_pub1 = run_cmd(cmd).strip()
    account_pub1 = hexlify(unhexlify(account_pub1)[::-1]).decode()
    call_data = sha3("GetPair(address,address)")[28:].hex() + account_pub0 + account_pub1
    #cmd = "callcontract %s %s 0 -d=%s" % (cmd_addr,contract_addr,call_data)
    ret = callcontract(cmd_addr,contract_addr,0,call_data)
    pair = ret["result"]

    pair = hexlify(unhexlify(pair)[::-1]).decode()
    cmd = "getpubkeyaddress " + pair
    ret = run_cmd(cmd).strip()
    return '3' + ret[1:]

def Burn(addr,pair):
    fun_sig = sha3("burn(address)")[28:].hex()
    cmd = "getaddresskey " + addr
    account_pub = run_cmd(cmd).strip()
    account_pub = hexlify(unhexlify(account_pub)[::-1]).decode()
    call_data = fun_sig + account_pub
    cmd = "sendfrom %s %s 0 -g=99000000 -cp=%s" % (addr,pair,call_data)
    ret = run_cmd(cmd)
    print("Burn:",ret.strip())

def SetPairStd(cmd_addr,contract_addr,pari):
    cmd = "getaddresskey " + pari
    pari_pub = run_cmd(cmd).strip()
    pari_pub = hexlify(unhexlify(pari_pub)[::-1]).decode()
    call_data = sha3("setPairStd(address)")[28:].hex() + pari_pub
    cmd = "sendfrom %s %s 0 -cp=%s" % (cmd_addr,contract_addr,call_data)
    ret = run_cmd(cmd)
    print("setPairStd:",ret.strip())

def addLiquidity(cmd_addr, contract_addr,tokenA,tokenB,amountADesired,amountBDesired,amountAMin,amountBMin,to,deadline):
    fun_sig = sha3("addLiquidity(address,address,uint256,uint256,uint256,uint256,address,uint256)")[28:].hex()
    cmd = "getaddresskey " + tokenA
    tokenA_pub = run_cmd(cmd).strip()
    tokenA_pub = hexlify(unhexlify(tokenA_pub)[::-1]).decode()

    cmd = "getaddresskey " + tokenB
    tokenB_pub = run_cmd(cmd).strip()
    tokenB_pub = hexlify(unhexlify(tokenB_pub)[::-1]).decode()

    cmd = "getaddresskey " + to
    to_pub = run_cmd(cmd).strip()
    to_pub = hexlify(unhexlify(to_pub)[::-1]).decode()

    call_data = fun_sig + encode_abi(["bytes32","bytes32","uint256","uint256","uint256","uint256","bytes32","uint256"],
    [unhexlify(tokenA_pub), unhexlify(tokenB_pub),int(amountADesired),int(amountBDesired),int(amountAMin),int(amountBMin),unhexlify(to_pub),int(deadline)]).hex()
    cmd = "sendfrom %s %s 0 -g=99000000 -cp=%s" % (cmd_addr,contract_addr,call_data)
    ret = run_cmd(cmd)
    print("addLiquidity:",ret.strip())

    wait_for_height()
    wait_for_height()
    ret = run_cmd("gettransactionreceipt " + ret.strip())
    
    ret = json.loads(ret)
    if ret["contractstatus"] == 0:
        print("addLiquidity txgasused:",ret["txgasused"])
        ret = ret["contractresult"]
        print("amountA:",int(ret[:64],16))
        print("amountB:",int(ret[64:64*2],16))
        print("liquidity:",int(ret[64*2:],16))
    else:
        print("addLiquidity err.")

def removeLiquidity(cmd_addr, contract_addr,tokenA,tokenB,liquidity,amountAMin,amountBMin,to,deadline):

    fun_sig = sha3("removeLiquidity(address,address,uint256,uint256,uint256,address,uint256)")[28:].hex()
    cmd = "getaddresskey " + tokenA
    tokenA_pub = run_cmd(cmd).strip()
    tokenA_pub = hexlify(unhexlify(tokenA_pub)[::-1]).decode()

    cmd = "getaddresskey " + tokenB
    tokenB_pub = run_cmd(cmd).strip()
    tokenB_pub = hexlify(unhexlify(tokenB_pub)[::-1]).decode()

    cmd = "getaddresskey " + to
    to_pub = run_cmd(cmd).strip()
    to_pub = hexlify(unhexlify(to_pub)[::-1]).decode()

    call_data = fun_sig + encode_abi(["bytes32","bytes32","uint256","uint256","uint256","bytes32","uint256"],
    [unhexlify(tokenA_pub), unhexlify(tokenB_pub),int(liquidity),int(amountAMin),int(amountBMin),unhexlify(to_pub),int(deadline)]).hex()
    cmd = "sendfrom %s %s 0 -g=99000000 -cp=%s" % (cmd_addr,contract_addr,call_data)
    ret = run_cmd(cmd)
    print("removeLiquidity:",ret.strip())
    wait_for_height()
    wait_for_height()
    ret = run_cmd("gettransactionreceipt " + ret.strip())
    ret = json.loads(ret)
    if ret["contractstatus"] == 0:
        print("removeLiquidity txgasused:",ret["txgasused"])
        ret = ret["contractresult"]
        print("amountA:",int(ret[:64],16))
        print("amountB:",int(ret[64:],16))
    else:
        print("removeLiquidity err.")

def swapA2B(cmd_addr,contract_addr,amountIn,amountOutMin,pathA,pathB,to,deadline):
    '''     
    A 换 B
    需要先对pahtA执行approve()操作
    换到的B不能低于amountOutMin这个值
    '''
    cmd = "getaddresskey " + to
    to_pub = run_cmd(cmd).strip()
    to_pub = hexlify(unhexlify(to_pub)[::-1]).decode()

    cmd = "getaddresskey " + pathA
    pathA_pub = run_cmd(cmd).strip()
    pathA_pub = hexlify(unhexlify(pathA_pub)[::-1]).decode()

    cmd = "getaddresskey " + pathB
    pathB_pub = run_cmd(cmd).strip()
    pathB_pub = hexlify(unhexlify(pathB_pub)[::-1]).decode()

    ret = encode_abi(["uint256","uint256","bytes32","bytes32","bytes32","uint256"],
        [amountIn,amountOutMin,unhexlify(pathA_pub),unhexlify(pathB_pub),unhexlify(to_pub),deadline]).hex()

    call_data = sha3("swapA2B(uint256,uint256,address,address,address,uint256)")[28:].hex() + ret
    cmd = "sendfrom %s %s 0 -g=99000000 -cp=%s" % (cmd_addr,contract_addr,call_data)
    ret = run_cmd(cmd)
    wait_for_height()
    wait_for_height()
    ret = run_cmd("gettransactionreceipt " + ret.strip())
    ret = json.loads(ret)
    print("swapA2B txgasused:",ret["txgasused"])
    if len(ret) > 0:
        return int(ret["contractresult"],16)
    else:
        return None

def swapB2A(cmd_addr,contract_addr,amountIn,amountOutMin,pathA,pathB,to,deadline):
    '''     
    B 换 A
    需要先对pahtA执行approve()操作
    换到的B不能低于amountOutMin这个值
    '''
    cmd = "getaddresskey " + to
    to_pub = run_cmd(cmd).strip()
    to_pub = hexlify(unhexlify(to_pub)[::-1]).decode()

    cmd = "getaddresskey " + pathA
    pathA_pub = run_cmd(cmd).strip()
    pathA_pub = hexlify(unhexlify(pathA_pub)[::-1]).decode()

    cmd = "getaddresskey " + pathB
    pathB_pub = run_cmd(cmd).strip()
    pathB_pub = hexlify(unhexlify(pathB_pub)[::-1]).decode()

    ret = encode_abi(["uint256","uint256","bytes32","bytes32","bytes32","uint256"],
        [amountIn,amountOutMin,unhexlify(pathA_pub),unhexlify(pathB_pub),unhexlify(to_pub),deadline]).hex()

    call_data = sha3("swapB2A(uint256,uint256,address,address,address,uint256)")[28:].hex() + ret
    cmd = "sendfrom %s %s 0 -g=99000000 -cp=%s" % (cmd_addr,contract_addr,call_data)
    ret = run_cmd(cmd)
    wait_for_height()
    wait_for_height()
    ret = run_cmd("gettransactionreceipt " + ret.strip())
    ret = json.loads(ret)["contractresult"]
    if len(ret) > 0:
        return int(ret,16)
    else:
        return None

def deposit(cmd_addr,weth_addr,vaule):
    call_data = sha3("deposit()")[28:].hex()
    cmd = "sendfrom %s %s %d -g=99000000 -cp=%s" % (cmd_addr,weth_addr,vaule,call_data)
    ret = run_cmd(cmd)
    wait_for_height()
    wait_for_height()
    return ret

def withdraw(cmd_addr,weth_addr,wad):
    ret = encode_abi(["uint256"],[wad]).hex()
    call_data = sha3("withdraw(uint256)")[28:].hex() + ret
    cmd = "sendfrom %s %s 0 -g=99000000 -cp=%s" % (cmd_addr,weth_addr,call_data)
    print(cmd)
    txid = run_cmd(cmd).strip()
    wait_for_height()
    wait_for_height()
    ret = run_cmd("gettransactionreceipt " + txid)
    return json.loads(ret)


def test1(cmd_addr,contract_addr):
    #cmd = "getaddresskey " + token0
    #account_pub0 = run_cmd(cmd).strip()
    #account_pub0 = hexlify(unhexlify(account_pub0)[::-1]).decode()
    #cmd = "getaddresskey " + token1
    #account_pub1 = run_cmd(cmd).strip()
    #account_pub1 = hexlify(unhexlify(account_pub1)[::-1]).decode()
    
    call_data = sha3("test1()")[28:].hex() # + account_pub0 + account_pub1
    ret = callcontract(cmd_addr,contract_addr,0,call_data)
    return ret["result"]
