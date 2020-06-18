from small_primes import small_primes   # primes < 100000
from base64 import b64encode, b64decode
import marshal
import random
import math
import hashlib


def getRandomPrime(nbits: int) -> int:
    while True:
        p = random.getrandbits(nbits) | 1 << nbits - 1 | 1
        if isPrime(p):
            return p


def isPrime(num: int) -> bool:
    if num < 3 or num & 1 == 0:
        return num == 2

    for p in small_primes:
        if num == p:
            return True
        if num % p == 0:
            return False

    r, u = 0, num - 1
    while u & 1 == 0:
        r += 1
        u //= 2

    rounds = int(math.ceil(-math.log(1e-6) / math.log(4)))
    for j in range(rounds):
        a = random.randint(2, num - 1)
        x = pow(a, u, num)
        if x == 1 or x == num - 1:
            continue
        comp = True
        for i in range(r):
            if pow(a, u << i + 1, num) == num - 1:
                comp = False
                break
        if comp:
            return False
    return True


def egcd(a: int, b: int) -> (int, int, int):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def modinv(a: int, m: int) -> int:
    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError('base is not invertible for the given modulus')
    else:
        return x % m


def i2b(i: int, length=None) -> bytes:
    if length is None:
        length = (i.bit_length() + 7) // 8
    return i.to_bytes(length, 'big')


def b2i(b: bytes) -> int:
    return int.from_bytes(b, 'big')


def pad(b: bytes, blocksize: int) -> bytes:
    padlen = blocksize - len(b) % blocksize
    return b + bytes([padlen] * padlen)


def unpad(b: bytes) -> bytes:
    padlen = b[-1]
    for i in range(padlen):
        if b[-i - 1] != padlen:
            raise ValueError('bad padding')
    return b[:-padlen]


def bytes_xor(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError('bytes length not match')
    return bytes([x ^ y for x, y in zip(a, b)])
