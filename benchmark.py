import time
from rsa_core import RSAKeyPair
from oaep import rsa_oaep_encrypt, rsa_oaep_decrypt
from digital_signature import sign, verify

def run_benchmark(iterations: int = 10):
    kp = RSAKeyPair(bits=2048)
    pub = kp.public_key
    message = b"Benchmark test message for RSA 2048-bit performance."

    # Encryption benchmark
    t0 = time.perf_counter()
    for _ in range(iterations):
        ct = rsa_oaep_encrypt(message, pub, kp)
    enc_time = (time.perf_counter() - t0) / iterations

    # Decryption benchmark
    t0 = time.perf_counter()
    for _ in range(iterations):
        pt = rsa_oaep_decrypt(ct, kp)
    dec_time = (time.perf_counter() - t0) / iterations

    # Signing benchmark
    t0 = time.perf_counter()
    for _ in range(iterations):
        sig = sign(message, kp)
    sign_time = (time.perf_counter() - t0) / iterations

    # Verification benchmark
    t0 = time.perf_counter()
    for _ in range(iterations):
        verify(message, sig, pub, kp)
    verify_time = (time.perf_counter() - t0) / iterations

    print("\n─── RSA-2048 Benchmark Results ───")
    print(f"  Encryption  : {enc_time*1000:.2f} ms/op")
    print(f"  Decryption  : {dec_time*1000:.2f} ms/op  (CRT optimized)")
    print(f"  Signing     : {sign_time*1000:.2f} ms/op")
    print(f"  Verification: {verify_time*1000:.2f} ms/op")
    print(f"  Correctness : {'PASS' if pt == message else 'FAIL'}")

if __name__ == "__main__":
    run_benchmark()
