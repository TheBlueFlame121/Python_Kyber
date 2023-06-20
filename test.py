from aes_drbg import AES_DRBG
from kem import *


def test_kyber2():
    print("Testing Kyber 512")
    g.set_mode(2)
    f = open("KATs/PQCkemKAT_1632.rsp", "r")
    f.readline()
    f.readline()
    for i in range(100):
        count = int(f.readline().split()[-1])
        seed = bytes.fromhex(f.readline().split()[-1])
        pk_kat = bytes.fromhex(f.readline().split()[-1])
        sk_kat = bytes.fromhex(f.readline().split()[-1])
        ct_kat = bytes.fromhex(f.readline().split()[-1])
        ss_kat = bytes.fromhex(f.readline().split()[-1])
        a = AES_DRBG(256)
        a.instantiate(seed)
        indcpa_seed = a.generate(g.KYBER_SYMBYTES)
        z = a.generate(g.KYBER_SYMBYTES)
        enc_seed = a.generate(g.KYBER_SYMBYTES)
        
        pk = [0]*g.KYBER_PUBLICKEYBYTES
        sk = [0]*g.KYBER_SECRETKEYBYTES
        crypto_kem_keypair(pk, sk, list(indcpa_seed), list(z))
        assert bytes(pk) == pk_kat
        assert bytes(sk) == sk_kat

        ct = [0]*g.KYBER_CIPHERTEXTBYTES
        ss = [0]*g.KYBER_SSBYTES
        crypto_kem_enc(ct, ss, pk, list(enc_seed))
        assert bytes(ct) == ct_kat
        assert bytes(ss) == ss_kat

        ssp = [0]*g.KYBER_SSBYTES
        crypto_kem_dec(ssp, ct, sk)
        assert ssp == ss

        f.readline()
    print("Kyber 512 passes all KATs")


def test_kyber3():
    print("Testing Kyber 768")
    g.set_mode(3)
    f = open("KATs/PQCkemKAT_2400.rsp", "r")
    f.readline()
    f.readline()
    for i in range(100):
        count = int(f.readline().split()[-1])
        seed = bytes.fromhex(f.readline().split()[-1])
        pk_kat = bytes.fromhex(f.readline().split()[-1])
        sk_kat = bytes.fromhex(f.readline().split()[-1])
        ct_kat = bytes.fromhex(f.readline().split()[-1])
        ss_kat = bytes.fromhex(f.readline().split()[-1])
        a = AES_DRBG(256)
        a.instantiate(seed)
        indcpa_seed = a.generate(g.KYBER_SYMBYTES)
        z = a.generate(g.KYBER_SYMBYTES)
        enc_seed = a.generate(g.KYBER_SYMBYTES)
        
        pk = [0]*g.KYBER_PUBLICKEYBYTES
        sk = [0]*g.KYBER_SECRETKEYBYTES
        crypto_kem_keypair(pk, sk, list(indcpa_seed), list(z))
        assert bytes(pk) == pk_kat
        assert bytes(sk) == sk_kat

        ct = [0]*g.KYBER_CIPHERTEXTBYTES
        ss = [0]*g.KYBER_SSBYTES
        crypto_kem_enc(ct, ss, pk, list(enc_seed))
        assert bytes(ct) == ct_kat
        assert bytes(ss) == ss_kat

        ssp = [0]*g.KYBER_SSBYTES
        crypto_kem_dec(ssp, ct, sk)
        assert ssp == ss

        f.readline()
    print("Kyber 768 passes all KATs")


def test_kyber4():
    print("Testing Kyber 1024")
    g.set_mode(4)
    f = open("KATs/PQCkemKAT_3168.rsp", "r")
    f.readline()
    f.readline()
    for i in range(100):
        count = int(f.readline().split()[-1])
        seed = bytes.fromhex(f.readline().split()[-1])
        pk_kat = bytes.fromhex(f.readline().split()[-1])
        sk_kat = bytes.fromhex(f.readline().split()[-1])
        ct_kat = bytes.fromhex(f.readline().split()[-1])
        ss_kat = bytes.fromhex(f.readline().split()[-1])
        a = AES_DRBG(256)
        a.instantiate(seed)
        indcpa_seed = a.generate(g.KYBER_SYMBYTES)
        z = a.generate(g.KYBER_SYMBYTES)
        enc_seed = a.generate(g.KYBER_SYMBYTES)
        
        pk = [0]*g.KYBER_PUBLICKEYBYTES
        sk = [0]*g.KYBER_SECRETKEYBYTES
        crypto_kem_keypair(pk, sk, list(indcpa_seed), list(z))
        assert bytes(pk) == pk_kat
        assert bytes(sk) == sk_kat

        ct = [0]*g.KYBER_CIPHERTEXTBYTES
        ss = [0]*g.KYBER_SSBYTES
        crypto_kem_enc(ct, ss, pk, list(enc_seed))
        assert bytes(ct) == ct_kat
        assert bytes(ss) == ss_kat

        ssp = [0]*g.KYBER_SSBYTES
        crypto_kem_dec(ssp, ct, sk)
        assert ssp == ss

        f.readline()
    print("Kyber 1024 passes all KATs!")


if __name__ == "__main__":
    test_kyber2()
    test_kyber3()
    test_kyber4()
