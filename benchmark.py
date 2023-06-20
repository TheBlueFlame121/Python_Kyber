from kem import *
from timeit import timeit
from time import sleep

for mode in [2, 3, 4]:
    g.set_mode(mode)
    print(f"Kyber {mode}")

    t = timeit("sleep(0.01)", globals=globals(), number = 1000)
    print(f"Test: {round(t, 3)}s")

    t = timeit("crypto_kem_keypair(pk, sk)", setup="pk, sk= [0]*g.KYBER_PUBLICKEYBYTES, [0]*g.KYBER_SECRETKEYBYTES", globals=globals(), number=1000)
    print(f"key generation: {round(t, 3)}s")

    stp = """pk, sk= [0]*g.KYBER_PUBLICKEYBYTES, [0]*g.KYBER_SECRETKEYBYTES;crypto_kem_keypair(pk, sk);ss = [0]*g.KYBER_SSBYTES;ct = [0]*g.KYBER_CIPHERTEXTBYTES"""
    t = timeit("crypto_kem_enc(ct, ss, pk)", setup = stp, globals=globals(), number=1000)
    print(f"Encapsulation: {round(t, 3)}s")

    stp  = """pk, sk= [0]*g.KYBER_PUBLICKEYBYTES, [0]*g.KYBER_SECRETKEYBYTES;crypto_kem_keypair(pk, sk);ss = [0]*g.KYBER_SSBYTES;ct = [0]*g.KYBER_CIPHERTEXTBYTES;crypto_kem_enc(ct, ss, pk); ssp=[0]*g.KYBER_SSBYTES"""
    t = timeit("crypto_kem_dec(ssp, ct, sk)", setup=stp, globals=globals(), number=1000)
    print(f"Decapsulation: {round(t, 3)}s\n")
