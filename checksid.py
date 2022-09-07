
from cgitb import text
import os
import subprocess
import sys
import logging
import time
import hashlib

import requests
import web3.eth

import traceback

import bcutils
from  bcutils import tools
from  bcutils import tools as utils

from web3 import Web3

import base_contract


def checksid(sid):
    sidContract='0xE3b1D32e43Ce8d658368e2CBFF95D57Ef39Be8a6'
    obj = base_contract.contract_base('',
    sidContract,"spaceid.abi")
    tmpid = tools._web3obj.sha3(text=sid).hex()
    intid = tools._web3obj.toInt(hexstr=tmpid)
    avai = obj.baseobj.functions.available(intid).call()
    logging.info("Checking id:{} is available:{}".format(sid,avai))



def check():
    checksid('123')
    checksid('342')
    checksid('shouldnotbefound')

if __name__ == "__main__":
    bcutils.tools.init_log("log{}.log".format(os.path.basename(os.path.abspath(__file__))))
    check()