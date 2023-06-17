# Contains elements from kem.h and kem.c
from verify import *
from indcpa import *


#################################################
# Name:        crypto_kem_keypair
#
# Description: Generates public and private key
#              for CCA-secure Kyber key encapsulation mechanism
#
# Arguments:   - List[int] pk: output public key
#                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
#              - List[int] sk: output private key
#                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
#
# Returns 0 (success)
##################################################
def crypto_kem_keypair(pk:List[int], sk:List[int]) -> int:
    indcpa_keypair(pk, sk)
    for i in range(KYBER_INDCPA_PUBLICKEYBYTES):
        sk[i+KYBER_INDCPA_SECRETKEYBYTES] = pk[i]
    temp = list(hash_h(bytes(pk)))
    for i in range(KYBER_SYMBYTES):
        sk[-2*KYBER_SYMBYTES+i] = temp[i]
    # Value z for pseudo-random output on reject
    temp = list(urandom(KYBER_SYMBYTES))
    # temp = list(range(KYBER_SYMBYTES))
    for i in range(KYBER_SYMBYTES):
        sk[-KYBER_SYMBYTES+i] = temp[i]
    return 0


#################################################
# Name:        crypto_kem_enc
#
# Description: Generates cipher text and shared
#              secret for given public key
#
# Arguments:   - List[int] ct: output cipher text
#                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
#              - List[int] ss: output shared secret
#                (an already allocated array of KYBER_SSBYTES bytes)
#              - List[int] pk: input public key
#                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
#
# Returns 0 (success)
##################################################
def crypto_kem_enc(ct:List[int], ss:List[int], pk:List[int]) -> int:
    buf = [0]*2*KYBER_SYMBYTES
    # Will contain key, coins
    kr = [0]*2*KYBER_SYMBYTES
    
    buf = list(urandom(KYBER_SYMBYTES))
    # buf = list(range(32))
    # Don't release system RNG output
    buf = list(hash_h(bytes(buf)))

    # Multitarget countermeasure for coins + contributory KEM
    buf = buf[:KYBER_SYMBYTES] + list(hash_h(bytes(pk)))
    kr = list(hash_g(bytes(buf)))

    # coins are in kr[KYBER_SYMBYTES:]
    indcpa_enc(ct, buf, pk, kr[KYBER_SYMBYTES:])

    # overwrite coins in kr with H(c)
    kr = kr[:KYBER_SYMBYTES] + list(hash_h(bytes(ct)))
    # overwrite coins in kr with H(c)
    temp = list(kdf(bytes(kr), 2*KYBER_SYMBYTES))
    for i in range(KYBER_SYMBYTES):
        ss[i] = temp[i]

    return 0


#################################################
# Name:        crypto_kem_dec
#
# Description: Generates shared secret for given
#              cipher text and private key
#
# Arguments:   - List[int] ss: output shared secret
#                (an already allocated array of KYBER_SSBYTES bytes)
#              - List[int] ct: input cipher text
#                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
#              - List[int] sk: input private key
#                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
#
# Returns 0.
#
# On failure, ss will contain a pseudo-random value.
##################################################
def crypto_kem_dec(ss:List[int], ct:List[int], sk:List[int]) -> int:
    buf = [0]*2*KYBER_SYMBYTES
    # Will contain key, coins
    kr = [0]*2*KYBER_SYMBYTES
    cmp = [0]*KYBER_CIPHERTEXTBYTES
    pk = sk[KYBER_INDCPA_SECRETKEYBYTES:]

    indcpa_dec(buf, ct, sk)

    # Multitarget countermeasure for coins + contributory KEM
    for i in range(KYBER_SYMBYTES):
        buf[KYBER_SYMBYTES+i] = sk[KYBER_SECRETKEYBYTES - 2*KYBER_SYMBYTES + i]
    kr = list(hash_g(bytes(buf)))

    # coins are in kr[KYBER_SYMBYTES:]
    indcpa_enc(cmp, buf, pk, kr[KYBER_SYMBYTES:])

    fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES)

    # overwrite coins in kr with H(c)
    kr = kr[:KYBER_SYMBYTES] + list(hash_h(bytes(ct)))

    # Overwrite pre-k with z on re-encryption failure
    cmov(kr, sk[KYBER_SECRETKEYBYTES-KYBER_SYMBYTES:], KYBER_SYMBYTES, fail)

    # hash concatenation of pre-k and H(c) to k
    temp = list(kdf(bytes(kr), 2*KYBER_SYMBYTES))
    for i in range(KYBER_SYMBYTES):
        ss[i] = temp[i]
    return 0
