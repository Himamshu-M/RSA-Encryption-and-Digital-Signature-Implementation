import os
import random
import time

# Miller-Rabin Primality Test
def miller_rabin(n: int, k: int = 40) -> bool:
  #Probabilistic primality test. k=40 gives error probability < 4^-40.
    if n < 2: return False
    if n == 2 or n == 3: return True
    if n % 2 == 0: return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)        
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
#Generate a random prime of exactly specified by user bits.
    while True:
        # Ensure high bit and low bit are set (odd number of correct size)
        candidate = random.getrandbits(bits)
        candidate |= (1 << (bits - 1)) | 1      # set MSB and LSB
        if miller_rabin(candidate):
            return candidate


# Extended Euclidean Algorithm (for modular inverse)

def extended_gcd(a: int, b: int):
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def mod_inverse(e: int, phi: int) -> int:
    g, x, _ = extended_gcd(e % phi, phi)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % phi


# RSA Key Generation
class RSAKeyPair:
    def __init__(self, bits: int = 2048):
        half = bits // 2
        print(f"[*] Generating {bits}-bit RSA key pair...")
        t0 = time.time()

        p = generate_prime(half)
        q = generate_prime(half)
        while q == p:
            q = generate_prime(half)

        self.n = p * q
        phi = (p - 1) * (q - 1)

        self.e = 65537          # Standard public exponent
        self.d = mod_inverse(self.e, phi)

        # Store for CRT optimization (optional speedup)
        self.p, self.q = p, q
        self.dp = self.d % (p - 1)
        self.dq = self.d % (q - 1)
        self.qinv = mod_inverse(q, p)

        elapsed = time.time() - t0
        print(f"[+] Key generation complete in {elapsed:.3f}s")

    @property
    def public_key(self):
        return (self.n, self.e)

    @property
    def private_key(self):
        return (self.n, self.d)

    def key_size_bytes(self):
        return (self.n.bit_length() + 7) // 8


# RSA Primitives

def rsa_encrypt_primitive(m_int: int, public_key: tuple) -> int:
    n, e = public_key
    if m_int >= n:
        raise ValueError("Message integer must be < n")
    return pow(m_int, e, n)     


def rsa_decrypt_primitive(c_int: int, key_pair: RSAKeyPair) -> int:
# CRT-optimized decryption — ~4x faster than naive pow(c, d, n).
    p, q = key_pair.p, key_pair.q
    dp, dq, qinv = key_pair.dp, key_pair.dq, key_pair.qinv

    m1 = pow(c_int, dp, p)
    m2 = pow(c_int, dq, q)
    h = (qinv * (m1 - m2)) % p
    return m2 + h * q
