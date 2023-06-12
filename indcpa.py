# Contains elements from indcpa.h and indcpa.c

from polyvec import *


#################################################
# Name:        pack_pk
#
# Description: Serialize the public key as concatenation of the
#              serialized vector of polynomials pk
#              and the public seed used to generate the matrix A.
#
# Arguments:   - List[int] r:    the output serialized public key
#              - polyvec pk:     the input public-key polyvec
#              - List[int] seed: the input public seed
##################################################
def pack_pk(r:List[int], pk:polyvec, seed:List[int]):
    polyvec_tobytes(r, pk)
    for i in range(KYBER_SYMBYTES):
        r[i+KYBER_POLYVECBYTES] = seed[i]


#################################################
# Name:        unpack_pk
#
# Description: De-serialize public key from a byte array;
#              approximate inverse of pack_pk
#
# Arguments:   - polyvec pk: output public-key polynomial vector
#              - List[int] seed: output seed to generate matrix A
#              - List[int] packedpk: input serialized public key
##################################################
def unpack_pk(pk:polyvec, seed:List[int], packedpk:List[int]):
    polyvec_frombytes(pk, packedpk)
    for i in range(KYBER_SYMBYTES):
        seed[i] = packedpk[i+KYBER_POLYVECBYTES]


#################################################
# Name:        pack_sk
#
# Description: Serialize the secret key
#
# Arguments:   - List[int] r: output serialized secret key
#              - polyvec sk: input vector of polynomials (secret key)
##################################################
def pack_sk(r:List[int], sk:polyvec):
    polyvec_tobytes(r, sk)


#################################################
# Name:        unpack_sk
#
# Description: De-serialize the secret key; inverse of pack_sk
#
# Arguments:   - polyvec sk: output vector of polynomials (secret key)
#              - List[int] packedsk: input serialized secret key
##################################################
def unpack_sk(sk:polyvec, packedsk:List[int]):
    polyvec_frombytes(sk, packedsk)


#################################################
# Name:        pack_ciphertext
#
# Description: Serialize the ciphertext as concatenation of the
#              compressed and serialized vector of polynomials b
#              and the compressed and serialized polynomial v
#
# Arguments:   - List[int] r: the output serialized ciphertext
#              - poly pk: the input vector of polynomials b
#              - poly v: the input polynomial v
##################################################
def pack_ciphertext(r:List[int], b:polyvec, v:poly):
    polyvec_compress(r, b)
    temp = [0]*KYBER_POLYCOMPRESSEDBYTES
    poly_compress(temp, v)
    for i in range(KYBER_POLYCOMPRESSEDBYTES):
        r[KYBER_POLYVECCOMPRESSEDBYTES+i] = temp[i]


#################################################
# Name:        unpack_ciphertext
#
# Description: De-serialize and decompress ciphertext from a byte array;
#              approximate inverse of pack_ciphertext
#
# Arguments:   - polyvec b: the output vector of polynomials b
#              - poly v: the output polynomial v
#              - List[int] c: the input serialized ciphertext
##################################################
def unpack_ciphertext(b:polyvec, v:poly, c:List[int]):
    polyvec_decompress(b, c)
    poly_decompress(v, c[KYBER_POLYVECCOMPRESSEDBYTES:])
