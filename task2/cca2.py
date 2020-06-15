import requests
from Crypto.Cipher import AES
from pwn import log

from rsa import RSAKey
from utils import *
from wup import WUP


def hack(session, b64aesenc, b64wupenc):
    def get_bit(i, low):
        fakewup = WUP(IMEI='a', MAC='b', IP='c', QQ='d', version='e')
        testkey = i2b(low << (16 * 8 - i - 1)).rjust(16, b'\x00')
        fakeenc = AES.new(testkey, mode=AES.MODE_ECB).encrypt(pad(fakewup.dumps(), 16))
        shifted_key = i2b(b2i(aesenc) * rsakey.encrypt(1 << (16 * 8 - i - 1)) % rsakey.n)
        r = ses.post(server + 'upload', {'aes': b64encode(shifted_key), 'wup': b64encode(fakeenc)})
        return 1 - r.json()['success']
    server = 'http://localhost:5000/'
    ses = requests.Session()
    ses.cookies['session'] = session
    log.info(f'Encrypted AES Key: {b64aesenc}')
    log.info(f'Encrypted WUP: {b64wupenc}')
    aesenc = b64decode(b64aesenc)
    wupenc = b64decode(b64wupenc)

    r = ses.get(server + 'getkey')
    rsakey = RSAKey.loads(b64decode(r.json()['pubkey']))

    aeskey = 0
    with log.progress('Reconstructing AES Key') as p:
        for i in range(16 * 8):
            aeskey += get_bit(i, aeskey) << i
            p.status(f'{aeskey:032x} {i:3d}/128')

    aeskey = i2b(aeskey).rjust(16, b'\x00')
    log.success(f'Reconstructed AES Key (hex): {aeskey.hex()}')

    wup = unpad(AES.new(aeskey, mode=AES.MODE_ECB).decrypt(wupenc))
    wup = WUP.loads(wup)
    log.success(f'Decrypted WUP: {wup}')


if __name__ == '__main__':
    session = 'eyJrZXlpZCI6ImI0NWQxNTI4ZTlmOThlMDY3ZGZhYjdkMTllZDM1NzdkIn0.Xt900g.rQN1ilD-dvslLjZbjXmXBJP85tQ'
    b64aesenc = 'bR2XnyPzjn/YLu4BfxI4EcG1YXCOjOT1Jf8PxKo550VpROT1TaQMdJm4pADTPMnxWP8nWlRZDloYlIMCDJlqgtK0kho83T7TdJbdGwTEJySBA+oi6gh7ILxVQh87ua+3Ov5FY/XCr8SmCIcukcEcI5s78VdvgTS3NVRzV7dclFP088/mGvesTdUojhEYCVOmCI93oBZq8C6tCK9FaAI+4TelopoBCeQG0Y9AyaW7s7oyvOHnHAlQ6P2OxEEdJwFG36miIbMgM5qHmvbRWis1FJBp30H/pBLtPt/bIGjgozLaNfR59I3vnLYWC6nVog5cPJGyJ4FctspQVz02pCj/Zw=='
    b64wupenc = 'irueD4zTuHBh3hH8QToHHPO5v11NUpWP2K9z2i1/KvCfSkuksIRd2r5VL8FnPyd9mqsefgoIFP8dCtK2AQe023W4MHvcVkh1tob2Lkv3YjHHhvZNgNy3RqOzr3C0x/yHqLaGAW5RGHH7Wkru8a0tTA=='
    hack(session, b64aesenc, b64wupenc)
