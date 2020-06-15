import secrets

import requests
from Crypto.Cipher import AES

from rsa import RSAKey
from utils import *
from wup import WUP


def randomWUP():
    IMEI = str(random.randint(0, 99999999999999))
    MAC = ':'.join(format(random.getrandbits(8), '02x') for i in range(6))
    IP = '.'.join(format(random.getrandbits(8), 'd') for i in range(4))
    QQ = str(random.randint(0, 99999999999))
    version = '1.0'
    wup = WUP(IMEI=IMEI, MAC=MAC, IP=IP, QQ=QQ, version=version)
    return wup


wup = randomWUP()

server = 'http://localhost:5000/'

ses = requests.Session()
r = ses.get(server + 'getkey')
rsakey = RSAKey.loads(b64decode(r.json()['pubkey']))
aeskey = secrets.token_bytes(16)
aesenc = rsakey.encrypt(aeskey)
wupenc = AES.new(aeskey, mode=AES.MODE_ECB).encrypt(pad(wup.dumps(), 16))

proxy = {'http': 'http://localhost:8080'}   # mitmproxy

r = ses.post(server + 'upload', {'aes': b64encode(aesenc), 'wup': b64encode(wupenc)}, proxies=proxy)
assert r.json()['success'], r.json()['error']
