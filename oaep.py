import os
import hashlib

# OAEP Helper Primitives

def mgf1(seed: bytes, length: int, hash_func=hashlib.sha256) -> bytes:

    h_len = hash_func(b"").digest_size
    if length > (2**32) * h_len:
        raise ValueError("Mask too long")
    T = b""
    for counter in range((length + h_len - 1) // h_len):
        C = counter.to_bytes(4, "big")
        T += hash_func(seed + C).digest()
    return T[:length]


def i2osp(x: int, x_len: int) -> bytes:
# Integer to Octet String Primitive.
    return x.to_bytes(x_len, "big")


def os2ip(x: bytes) -> int:
# Octet String to Integer Primitive.
    return int.from_bytes(x, "big")


# OAEP Encode / Decode
def oaep_encode(message: bytes, k: int, label: bytes = b"") -> bytes:

    h_len = 32                       # SHA-256 digest size
    m_len = len(message)
    max_msg = k - 2 * h_len - 2

    if m_len > max_msg:
        raise ValueError(
            f"Message too long: max {max_msg} bytes for {k*8}-bit key"
        )

    l_hash = hashlib.sha256(label).digest()
    ps = b"\x00" * (k - m_len - 2 * h_len - 2)
    db = l_hash + ps + b"\x01" + message          # Data Block

    seed = os.urandom(h_len)                       # Random 32-byte seed
    db_mask = mgf1(seed, k - h_len - 1)
    masked_db = bytes(x ^ y for x, y in zip(db, db_mask))

    seed_mask = mgf1(masked_db, h_len)
    masked_seed = bytes(x ^ y for x, y in zip(seed, seed_mask))

    return b"\x00" + masked_seed + masked_db


def oaep_decode(em: bytes, k: int, label: bytes = b"") -> bytes:

    h_len = 32
    l_hash = hashlib.sha256(label).digest()

    if len(em) != k or k < 2 * h_len + 2:
        raise ValueError("Decryption error: invalid length")

    _, masked_seed, masked_db = em[0], em[1:h_len + 1], em[h_len + 1:]

    seed_mask = mgf1(masked_db, h_len)
    seed = bytes(x ^ y for x, y in zip(masked_seed, seed_mask))

    db_mask = mgf1(seed, k - h_len - 1)
    db = bytes(x ^ y for x, y in zip(masked_db, db_mask))

    l_hash_check = db[:h_len]
    if l_hash_check != l_hash:
        raise ValueError("Decryption error: label hash mismatch")

    # Find 0x01 separator
    i = h_len
    while i < len(db) and db[i] == 0:
        i += 1
    if db[i] != 1:
        raise ValueError("Decryption error: missing 0x01 separator")

    return db[i + 1:]


# High-Level RSA-OAEP Encrypt / Decrypt

def rsa_oaep_encrypt(message: bytes, public_key, key_pair) -> bytes:
    from rsa_core import rsa_encrypt_primitive, i2osp
    k = key_pair.key_size_bytes()
    em = oaep_encode(message, k)
    m_int = os2ip(em)
    c_int = rsa_encrypt_primitive(m_int, public_key)
    return i2osp(c_int, k)


def rsa_oaep_decrypt(ciphertext: bytes, key_pair) -> bytes:
    from rsa_core import rsa_decrypt_primitive
    k = key_pair.key_size_bytes()
    c_int = os2ip(ciphertext)
    m_int = rsa_decrypt_primitive(c_int, key_pair)
    em = i2osp(m_int, k)
    return oaep_decode(em, k)
