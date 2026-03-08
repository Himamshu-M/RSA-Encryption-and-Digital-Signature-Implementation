import hashlib
from rsa_core import RSAKeyPair, rsa_encrypt_primitive, rsa_decrypt_primitive
from oaep import os2ip, i2osp


def sign(message: bytes, key_pair: RSAKeyPair) -> bytes:

    digest = hashlib.sha256(message).digest()          # 32 bytes
    k = key_pair.key_size_bytes()

    # Pad digest to key size with PKCS#1 v1.5-style framing (educational)
    if len(digest) + 11 > k:
        raise ValueError("Key too small for digest")
    padded = (b"\x00\x01"
              + b"\xff" * (k - len(digest) - 3)
              + b"\x00"
              + digest)

    m_int = os2ip(padded)
    sig_int = rsa_decrypt_primitive(m_int, key_pair)   # Private key operation
    return i2osp(sig_int, k)


def verify(message: bytes, signature: bytes, public_key: tuple,
           key_pair: RSAKeyPair) -> bool:
    #Verifying RSA signature using public key.
    k = key_pair.key_size_bytes()
    sig_int = os2ip(signature)
    m_int = rsa_encrypt_primitive(sig_int, public_key)  # Public key operation
    recovered = i2osp(m_int, k)

    expected_digest = hashlib.sha256(message).digest()
    recovered_digest = recovered[-32:]                  # Last 32 bytes
    return recovered_digest == expected_digest
