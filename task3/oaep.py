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
        self.k0 = self.hashalgo().digest_size * 8

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

    def H(self, num: int) -> int:
        return b2i(self.hashalgo(i2b(num)).digest())

    def G(self, r: int, expandlen: int) -> int:
        expanded = 0
        while expanded.bit_length() < expandlen:
            expanded = expanded << self.k0 | self.H(r + expanded)
        return expanded >> expanded.bit_length() - expandlen

    def encrypt(self, plain: 'int or bytes') -> 'int or bytes':
        is_bytes = False
        if isinstance(plain, bytes):
            is_bytes = True
            plain = b2i(plain)
        elif not isinstance(plain, int):
            raise TypeError('plain should be int or bytes')
        if plain < 0:
            raise ValueError('plain cannot be negative')
        padlen = self.nbits - self.k0 - plain.bit_length()
        if padlen < 1:
            raise ValueError('plain too large')
        padplain = (plain << 1 | 1) << padlen - 1
        r = random.getrandbits(self.k0)
        X = padplain ^ self.G(r, self.nbits - self.k0)
        Y = r ^ self.H(X)
        combined = X << self.k0 | Y
        cipher = pow(combined, self.e, self.n)
        if is_bytes:
            cipher = i2b(cipher)
        return cipher

    def decrypt(self, cipher: 'int or bytes') -> 'int or bytes':
        if self.is_public:
            raise TypeError('Public key cannot decrypt')
        is_bytes = False
        if isinstance(cipher, bytes):
            is_bytes = True
            cipher = b2i(cipher)
        elif not isinstance(cipher, int):
            raise TypeError('cipher should be int or bytes')
        if cipher < 0:
            raise ValueError('cipher cannot be negative')
        if cipher > self.n:
            raise ValueError('cipher too large')
        combined = pow(cipher, self.d, self.n)
        X, Y = combined >> self.k0, combined % 2 ** self.k0
        r = Y ^ self.H(X)
        plain = X ^ self.G(r, self.nbits - self.k0)
        while plain & 1 == 0:
            plain >>= 1
        plain >>= 1

        if is_bytes:
            plain = i2b(plain)
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
