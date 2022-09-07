# -*- coding:utf-8 -*-
import json
import os
import subprocess
import sys
import sys
import logging
import time
from datetime import datetime
import traceback
import requests

import logging.handlers
from web3 import Web3
import logging.handlers

from web3.auto import w3
import  datetime
from datetime import datetime

import uuid
import json
import os
import subprocess
import sys
import sys
import logging
import time

import peewee
import datetime
from bcutils import bcmycrypt
from bcutils import mnemonic_utils
import base64
import eth_utils
import binascii
import platform


proxies = {}

_curf=os.path.abspath(__file__)
_curf = os.path.dirname(_curf)
_curf = os.path.dirname(_curf)
proxyfile = os.path.join(_curf, 'setproxy.txt')

if os.path.isfile(proxyfile):
    buf = open(proxyfile).read()
    if len(buf)>0:
        logging.warning('set proxy!')
        os.environ["https_proxy"] = buf


_bsc_rpc='https://bsc-dataseed.binance.org/'
#_bsc_rpc='https://polygon-rpc.com'

_web3obj = None
if not _web3obj:
    _web3obj  = Web3(Web3.HTTPProvider(_bsc_rpc))

_chainid=0
def getChainId(obj):
    global _chainid
    if _chainid==0:
        _chainid=obj.eth.chain_id
    if not _chainid:
        raise Exception("chainid fail")

    return _chainid

def encrypt_data(data, pub_key):
    try:
        rsa_util = bcmycrypt.RsaUtil(pub_key, "")
        data = str(data)
        encrypt = rsa_util.public_long_encrypt(data)

        return encrypt
    except Exception as e:
        print(str(e))
        return

def decrypt_data(data, pri_key):
    try:
        rsa_util = bcmycrypt.RsaUtil("", pri_key)
        decrypt_str = rsa_util.private_long_decrypt(data)
        return decrypt_str
    except Exception as e:
        print(str(e))
        return

def encrypt_keylist_file(fname="keylist"):
    if not os.path.isfile(fname):
        return
    buf = open(fname).read()
    data=""
    try:
        data = base64.b64decode(buf, validate=True)
    except :
        pass
    if data:
        print("already encrypted!!")
        time.sleep(2)
        return True
    pubkey = input("enter public key to encrypt:")
    print(pubkey)
    # newpubkey=''
    # while len(pubkey)>=64:
    #     newpubkey=newpubkey+"\n" + pubkey[:64]
    #     pubkey = pubkey[64]
    # if len(pubkey):
    #     newpubkey = newpubkey + pubkey
    #
    # pubkey = newpubkey
    #
    enc = encrypt_data(buf, pubkey)
    if not enc:
        print('fail to encrypt!!')
        return
    open(fname,"wb").write(enc)
    return True

def get_key_list_from_encrypt(fname="keylist"):
    if not os.path.isfile(fname):
        return
    print(os.path.abspath(fname))
    buf = open(fname).read()
    import getpass

    prikey = getpass.getpass("enter private key to decrypt:")

    dec = decrypt_data(buf, prikey)
    if not dec:
        return
    dec = to_utf8(dec)

    sp = dec.split('\n')

    flines =[]
    for l in sp:
        l=l.strip()
        if not l:
            continue
        flines.append(l)
    return flines

def to_utf8(s):
    return s if isinstance(s, str) else s.decode('utf-8', errors='ignore')

def to_bytes(s):
    return s if isinstance(s, bytes) else bytes(s, encoding="utf8")

def init_log(logfile='jiucai-dream.log'):
    logging.getLogger().setLevel(logging.NOTSET)
    logging.getLogger('urllib3.connectionpool').setLevel(logging.WARNING)
    logging.getLogger('web3.providers.HTTPProvider').setLevel(logging.WARNING)
    logging.getLogger('web3.providers.WebsocketProvider').setLevel(logging.WARNING)
    logging.getLogger('websockets.protocol').setLevel(logging.WARNING)
    logging.getLogger('web3.RequestManager').setLevel(logging.WARNING)
    logging.getLogger('peewee').setLevel(logging.WARNING)
    logging.getLogger('root').setLevel(logging.INFO)
    loguniID = uuid.uuid4().hex
    formatter = logging.Formatter(loguniID[:5] + " %(asctime)s - %(name)s - %(levelname)s - %(message)s ")

    if len(logging.getLogger().handlers):
        logging.getLogger().handlers[0].setFormatter(formatter)
    else:
        h1 = logging.StreamHandler(sys.stdout)
        h1.setFormatter(formatter)
        h1.setLevel(logging.DEBUG)
        logging.getLogger().addHandler(h1)
        
    h2 = logging.handlers.RotatingFileHandler(
        filename=logfile, maxBytes=(1048576 * 5), backupCount=7
    )
    h2.setFormatter(formatter)
    h2.setLevel(logging.DEBUG)
    logging.getLogger().addHandler(h2)

def privkey_to_account(key):
    acc = w3.eth.account.privateKeyToAccount(key)
    return acc.address

def words_to_prikey(words,id=0):
    private_key = mnemonic_utils.mnemonic_to_private_key(
        words, str_derivation_path=f'{mnemonic_utils.LEDGER_ETH_DERIVATION_PATH}/{id}')
    return private_key.hex()

def words_to_addr(words):
    r = words_to_prikey(words)
    return privkey_to_account(r)


def time_to_string(timestamp1):
    return datetime.datetime.fromtimestamp(timestamp1).strftime("%Y-%m-%d, %H:%M:%S")

def time_to_string_filename(timestamp1):
    return datetime.datetime.fromtimestamp(timestamp1).strftime("%Y_%m_%d %H_%M_%S")

def get_file_to_lines(fname):
    if not os.path.isfile(fname):
        return []
    filebuf = open(fname).read()
    sp = filebuf.split('\n')
    flines =[]
    for l in sp:
        l=l.strip()
        if not l:
            continue
        flines.append(l)
    return flines

def get_function_name():
    return traceback.extract_stack(None, 2)[0][2]

web3obj_list=[]

def get_trans_data(txhash):
    trycnt = 4
    while trycnt:
        trycnt = trycnt-1
        for obj in web3obj_list:
            try:
                transaction_datas = obj.eth.get_transaction(txhash)
                return transaction_datas
            except:

                print('get fail web using ',str(obj), txhash.hex())
        print('retry')
    print("retry fail")

import requests
import hashlib
ipc_msg_key_msgcontent	="msgcontent"

def sendtext(touser, content, texttitle="bnbh_bot"):
    newtexttitle =  texttitle+"\n"

    data={"cmd":"sendtext",
          "touser":touser,
          ipc_msg_key_msgcontent:newtexttitle + content,
          }
    r = requests.post("http://127.0.0.1:8080/cmd", json=data)
    print("sendtext" + r.text)


def sendtext_remote(touser, content, texttitle="bnbh_bot"):
    newtexttitle =  texttitle+"\n"

    data={"cmd":"sendtext",
          "touser":touser,
          ipc_msg_key_msgcontent:newtexttitle + content,
          }
    r = requests.post("http://43.129.195.117:8081/cmd", json=data)
    print("sendtext" + r.text)


db = peewee.SqliteDatabase('bnbhbot.db')

class mydbModel(peewee.Model):

    createtime = peewee.DateTimeField(default=0)
    updatetime = peewee.IntegerField(default=0)
    insert_date = peewee.TextField(default=0)


    def save(self, *args, **kwargs):
        self.createtime = datetime.datetime.fromtimestamp(time.time()).strftime("%Y-%m-%d %H:%M:%S")
        self.insert_date = datetime.datetime.fromtimestamp(time.time()).strftime("%Y-%m-%d")
        self.updatetime = int(time.time())
        super(mydbModel, self).save(*args, **kwargs)

    @classmethod
    def update(cls, __data=None, **update):
        __data["updatetime"]=int(time.time())
        return super().update(__data, **update)

    @classmethod
    def insert(cls, __data=None, **insert):
        insert["createtime"] = datetime.datetime.fromtimestamp(time.time()).strftime("%Y-%m-%d %H:%M:%S")
        insert["insert_date"] = datetime.datetime.fromtimestamp(time.time()).strftime("%Y-%m-%d")
        insert["updatetime"] = int(time.time())
        return super().insert(__data, **insert)

def getabi(abifile):
    return json.load(open(abifile))


def abi_to_sig(abifile):

    fname = os.path.basename(abifile)
    abi = getabi(abifile)
    for entry in abi:
        if entry['type']!='function':
            continue
        print(fname, entry['name'],"0x"+ to_utf8(binascii.hexlify( eth_utils.function_abi_to_4byte_selector(entry))))
        #print(entry['name'], binascii.unhexlify(eth_utils.function_abi_to_4byte_selector(entry)))
    return abi
def functiontype_to_sig(fprototype:str):

    return "0x"+ to_utf8(binascii.hexlify(eth_utils.function_signature_to_4byte_selector(fprototype)))

def get_18_num(num, decimals=18):
    return int(num*10**decimals)

def get_to_address(addressfile):
    tolist = []
    if not os.path.isfile(addressfile):
        return []

    buf = open(addressfile).read()
    if buf[0]=='[':
        tolist1 = json.loads(buf)
        for k in tolist1:
            tolist.append(k['addr'])

    else:
        tolist= get_file_to_lines(addressfile)

    formataddrss = []
    for a in tolist:
        a2 = w3.toChecksumAddress(a)
        formataddrss.append(a2)

    return  formataddrss
