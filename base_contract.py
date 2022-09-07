# -*- coding:utf-8 -*-
import json
import os
import subprocess
import sys
import logging
import time

import requests
import web3.eth

import traceback

import bcutils
from  bcutils import tools


from web3 import Web3


class contract_base(object):

    def __init__(self, account_key,addr=None,abifile=None):
        self.key = account_key
        if account_key:
            acct = tools._web3obj.eth.account.privateKeyToAccount(account_key)
            self.acc_addr = acct.address

        self.baseabi = self.getabi(abifile)

        self.baseobj = tools._web3obj.eth.contract(address=Web3.toChecksumAddress(addr), abi=self.baseabi)


    def getabi(self, abifile):
        return json.load(open(abifile))

    def sendtrans(self, key,mytxn):
        if not key:
            key = self.key

        #logging.info("sendtrans " + json.dumps(mytxn, indent=4))
        signed_txn = tools._web3obj.eth.account.sign_transaction(mytxn, private_key=key)
        t1 = int(time.time())
        txhash = signed_txn.hash.hex()
        try:
            sendres = tools._web3obj.eth.send_raw_transaction(signed_txn.rawTransaction)
            print("trxhash:" + txhash)
        except:
            global _has_execute
            _has_execute = 1
            strexct = "except {}".format(traceback.format_exc())
            print(strexct)
            if strexct.find('already known')==-1:
                return

        t2 = int(time.time())

        try:
            print('wait tranx result....')
            waitres = tools._web3obj.eth.wait_for_transaction_receipt(txhash, timeout=100)
            #logging.info(str(waitres))
            return (True, txhash)
        except:
            strexct = "except {}".format(traceback.format_exc())
            print(strexct)
            return (False, txhash)

    def my_wait_for_transaction_receipt(self,txhash):
        try:
            r = tools._web3obj.eth.wait_for_transaction_receipt(txhash)
            return r
        except:
            strexct = "except {}".format(traceback.format_exc())
            logging.info(strexct)

