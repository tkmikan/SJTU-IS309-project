import os
import secrets

from Crypto.Cipher import AES
from flask import Flask, request, session

from rsa import RSAKey
from utils import *
from wup import WUP

app = Flask(__name__)
app.secret_key = secrets.token_bytes(32)

keydir = 'keys'
if not os.path.exists(keydir):
    os.mkdir(keydir)


def get_or_create_key(keyid):
    filename = os.path.join(keydir, keyid)
    if os.path.isfile(filename):
        with open(filename, 'rb') as f:
            key = RSAKey.loads(f.read())
    else:
        key = RSAKey.new(2048)
        with open(filename, 'wb') as f:
            f.write(key.dumps())
    return key


@app.route('/getkey')
def getkey():
    keyid = session.get('keyid')
    if keyid is None:
        keyid = session['keyid'] = secrets.token_hex(16)
    key = get_or_create_key(keyid)
    return {'pubkey': b64encode(key.public_key.dumps()).decode()}


@app.route('/upload', methods=['POST'])
def upload():
    wupenc = request.form.get('wup')
    aesenc = request.form.get('aes')
    try:
        assert wupenc is not None
        assert aesenc is not None
        wupenc = b64decode(wupenc)
        aesenc = b64decode(aesenc)
    except Exception as e:
        print(e)
        return {'success': False, 'error': 'bad request'}
    keyid = session.get('keyid')
    if keyid is None:
        return {'success': False, 'error': 'no RSA key found'}
    rsakey = get_or_create_key(keyid)
    try:
        aeskey = rsakey.decrypt(aesenc)
        aeskey = aeskey[-16:].rjust(16, b'\x00')
        wup = unpad(AES.new(aeskey, mode=AES.MODE_ECB).decrypt(wupenc))
        wup = WUP.loads(wup)
        print(wup.IP)
    except Exception as e:
        print(e)
        return {'success': False, 'error': 'decryption error'}
    return {'success': True}


if __name__ == '__main__':
    app.run()
