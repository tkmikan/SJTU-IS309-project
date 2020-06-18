from utils import *
from rsa import RSAKey


class RSA_OAEP_Key(RSAKey):
    def __init__(self, key=None, hashalgo=None, **kwargs):
        '''
        Initialize a RSA_OAEP_Key.

        If a RSAKey object is provided, its parameters are used directly.
        Otherwise ``RSAKey.__init__`` is invoked.

        ``hashalgo`` is any function from hashlib, and defaults to ``hashlib.sha1``.
        '''
        if key is None:
            super().__init__(**kwargs)
        else:
            self.__dict__ = key.__dict__.copy()
        self.hashalgo = hashalgo or hashlib.sha1
        self.k0 = self.hashalgo().digest_size

    def __repr__(self):
        s = ', '.join(f'{c}:{hex(getattr(self, c))}' for c in 'nepqd' if getattr(self, c) is not None)
        s += f', hash:{self.hashalgo.__name__}'
        return f'<RSA_OAEP_Key ({"private" if self.is_private else "public"}) {s}>'

    @property
    def public_key(self):
        return RSA_OAEP_Key(key=super().public_key, hashalgo=self.hashalgo)

    @classmethod
    def new(cls, nbits: int, hashalgo=None):
        return cls(key=super().new(nbits), hashalgo=hashalgo)

    def H(self, m: bytes) -> bytes:
        return self.hashalgo(m).digest()

    def G(self, seed: bytes, expandlen: int) -> bytes:
        expanded = b''
        while len(expanded) < expandlen:
            expanded += self.H(seed + expanded)
        return expanded[:expandlen]

    def encrypt(self, plain: 'int or bytes') -> 'int or bytes':
        is_bytes = True
        if isinstance(plain, int):
            if plain < 0:
                raise ValueError('plain cannot be negative')
            is_bytes = False
            plain = i2b(plain)
        elif not isinstance(plain, bytes):
            raise TypeError('plain should be int or bytes')
        padlen = self.nbits // 8 - self.k0 - len(plain) - 1
        if padlen < 1:
            raise ValueError('plain too large')
        padplain = plain + b'\x01' + b'\x00' * (padlen - 1)
        r = i2b(random.getrandbits(self.k0 * 8), self.k0)
        X = bytes_xor(padplain, self.G(r, self.nbits // 8 - self.k0 - 1))
        Y = bytes_xor(r, self.H(X))
        combined = X + Y
        cipher = super().encrypt(combined)
        if not is_bytes:
            cipher = b2i(cipher)
        return cipher

    def decrypt(self, cipher: 'int or bytes') -> 'int or bytes':
        if self.is_public:
            raise TypeError('Public key cannot decrypt')
        is_bytes = True
        if isinstance(cipher, int):
            if cipher < 0:
                raise ValueError('cipher cannot be negative')
            is_bytes = False
            cipher = i2b(cipher)
        elif not isinstance(cipher, bytes):
            raise TypeError('cipher should be int or bytes')
        if b2i(cipher) > self.n:
            raise ValueError('cipher too large')
        combined = super().decrypt(cipher)
        X, Y = combined[:-self.k0], combined[-self.k0:]
        r = bytes_xor(Y, self.H(X))
        plain = bytes_xor(X, self.G(r, self.nbits // 8 - self.k0 - 1))
        plain = plain.rstrip(b'\x00')
        if plain[-1] != 1:
            raise ValueError('bad padding')
        plain = plain[:-1]

        if not is_bytes:
            plain = b2i(plain)
        return plain


if __name__ == '__main__':
    plain = b'RSA OAEP test plaintext'
    privkey = RSA_OAEP_Key.new(1024)
    pubkey = privkey.public_key
    print('private key:', privkey)
    print('public key:', pubkey)
    cipher1 = pubkey.encrypt(plain)
    cipher2 = pubkey.encrypt(plain)
    print('plaintext:', plain)
    print('ciphertext 1 (hex):', cipher1.hex())
    print('ciphertext 2 (hex):', cipher2.hex())
    assert cipher1 != cipher2
    assert plain == privkey.decrypt(cipher1) == privkey.decrypt(cipher2)
    assert privkey.decrypt(pubkey.encrypt(b'\x00\x00\x00\x10')) == b'\x00\x00\x00\x10'
