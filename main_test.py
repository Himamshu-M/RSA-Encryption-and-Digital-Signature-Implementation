from rsa_core import RSAKeyPair
from oaep import rsa_oaep_encrypt, rsa_oaep_decrypt
from digital_signature import sign, verify

if __name__ == "__main__":
    # Key Generation
    kp = RSAKeyPair(bits=2048)
    pub = kp.public_key

    #Encryption / Decryption
    plaintext = b"Hello, RSA from scratch!"
    ciphertext = rsa_oaep_encrypt(plaintext, pub, kp)
    decrypted  = rsa_oaep_decrypt(ciphertext, kp)

    print(f"\nOriginal  : {plaintext}")
    print(f"Decrypted : {decrypted}")
    print(f"Match     : {plaintext == decrypted}")

    #Digital Signature
    message = b"Himanshu Patel - IIIT Kalyani First test "
    sig = sign(message, kp)
    valid = verify(message, sig, pub, kp)

    print(f"\nSignature valid : {valid}")
    print(f"Tamper test     : {verify(b'tampered', sig, pub, kp)}")
