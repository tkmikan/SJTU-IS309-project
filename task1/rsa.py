from utils import *


class RSAKey:
    def __init__(self, **kwargs):
        '''
        Initialize a RSAKey.

        ``n`` and ``e`` must be provided.

        For a private key, some of ``p``, ``q`` or ``d`` must be provided.

        Checks ``p * q == n`` and the correctness of ``d`` if possible.
        '''
        if any(c not in kwargs for c in 'ne'):
            raise ValueError('RSA component missing')
        for c in 'nepqd':
            setattr(self, c, kwargs.get(c))
        self.nbits = self.n.bit_length()

        if self.p is not None and self.q is not None:
            if self.p * self.q != self.n:
                raise ValueError('p * q != n')
        elif self.p is not None:
            if self.n % self.p:
                raise ValueError('n % p != 0')
            self.q = self.n // self.p
        elif self.q is not None:
            if self.n % self.q:
                raise ValueError('n % q != 0')
            self.p = self.n // self.p
        else:
            return
        if not isPrime(self.p):
            raise ValueError('p is not prime')
        if not isPrime(self.q):
            raise ValueError('p is not prime')
        phi = (self.p - 1) * (self.q - 1)
        if self.d is not None:
            if self.e * self.d % phi != 1:
                raise ValueError('d is not correct')
        else:
            try:
                self.d = modinv(self.e, phi)
            except ValueError:
                raise ValueError('cannot compute private key')

    def __repr__(self):
        s = ', '.join(f'{c}:{hex(getattr(self, c))}' for c in 'nepqd' if getattr(self, c) is not None)
        return f'<RSAKey ({"private" if self.is_private else "public"}) {s}>'

    @classmethod
    def new(cls, nbits: int):
        e = 65537
        while True:
            p = getRandomPrime(nbits // 2)
            q = getRandomPrime(nbits // 2)
            n = p * q
            if n.bit_length() != nbits:
                continue
            try:
                # d = pow(e, -1, (p - 1) * (q - 1))  # python 3.8
                d = modinv(e, (p - 1) * (q - 1))
            except ValueError:
                continue
            return cls(n=n, p=p, q=q, e=e, d=d)

    def dumps(self):
        return marshal.dumps({k: v for k, v in self.__dict__.items() if v is not None})

    @classmethod
    def loads(cls, data):
        return cls(**marshal.loads(data))

    @property
    def is_private(self):
        return self.d is not None

    @property
    def is_public(self):
        return self.d is None

    @property
    def public_key(self):
        return RSAKey(n=self.n, e=self.e)

    def encrypt(self, plain: 'int or bytes') -> 'int or bytes':
        is_bytes = False
        if isinstance(plain, bytes):
            is_bytes = True
            plain = b2i(plain)
        elif not isinstance(plain, int):
            raise TypeError('plain should be int or bytes')
        if plain < 0:
            raise ValueError('plain cannot be negative')
        if plain > self.n:
            raise ValueError('plain too large')
        cipher = pow(plain, self.e, self.n)
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
        plain = pow(cipher, self.d, self.n)
        if is_bytes:
            plain = i2b(plain)
        return plain


if __name__ == '__main__':
    plain = b'RSA test plaintext'
    privkey = RSAKey.new(1024)
    pubkey = privkey.public_key
    print('private key:', privkey)
    print('public key:', pubkey)
    cipher1 = pubkey.encrypt(b2i(plain))
    cipher2 = pubkey.encrypt(b2i(plain) * 2)
    print('plaintext:', plain)
    print('ciphertext 1 (hex):', hex(cipher1))
    print('ciphertext 2 (hex):', hex(cipher2))
    assert cipher1 * pubkey.encrypt(2) % pubkey.n == cipher2
    assert plain == privkey.decrypt(i2b(cipher1))
