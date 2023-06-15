# Contains elements from indcpa.h and indcpa.c

from polyvec import *
from os import urandom


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


#################################################
# Name:        rej_uniform
#
# Description: Run rejection sampling on uniform random bytes to generate
#              uniform random integers mod q
#
# Arguments:   - List[int] r: output buffer
#              - int l: requested number of 16-bit integers (uniform mod q)
#              - List[int] buf: input buffer (assumed to be uniformly random bytes)
#              - buflen: length of input buffer in bytes
#
# Returns number of sampled 16-bit integers (at most l)
##################################################
def rej_uniform(r:List[int], l:int, buf:List[int], buflen:int) -> int:
    ctr, pos = 0, 0
    while ctr<l and pos+3<=buflen:
        val0 = ((buf[pos+0] >> 0) | (buf[pos+1] << 8)) & 0xFFF
        val1 = ((buf[pos+1] >> 4) | (buf[pos+2] << 4)) & 0xFFF
        pos += 3

        if val0 < KYBER_Q:
            r[ctr] = val0
            ctr += 1
        if ctr<l and val1<KYBER_Q:
            r[ctr] = val1
            ctr += 1
    return ctr


#################################################
# Name:        gen_matrix
#
# Description: Deterministically generate matrix A (or the transpose of A)
#              from a seed. Entries of the matrix are polynomials that look
#              uniformly random. Performs rejection sampling on output of
#              a XOF
#
# Arguments:   - polyvec *a: pointer to ouptput matrix A
#              - const uint8_t *seed: pointer to input seed
#              - int transposed: boolean deciding whether A or A^T is generated
##################################################
GEN_MATRIX_NBLOCKS = ((12*KYBER_N//8*(1 << 12)//KYBER_Q + XOF_BLOCKBYTES)//XOF_BLOCKBYTES)
def gen_matrix(a:List[polyvec], seed:List[int], transposed:int):
    buf = [0]*(GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES+2)
    state = xof_state()

    for i in range(KYBER_K):
        for j in range(KYBER_K):
            state = xof_state()
            if transposed:
                xof_absorb(state, seed, i, j)
            else:
                xof_absorb(state, seed, j, i)

            buf = xof_squeezeblocks(GEN_MATRIX_NBLOCKS, state)
            buflen = GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES
            ctr = rej_uniform(a[i].vec[j].coeffs, KYBER_N, buf, buflen)

            while (ctr < KYBER_N):
                off = buflen % 3
                for k in range(off):
                    buf[k] = buf[buflen - off + k]
                buf = buf[:off] + xof_squeezeblocks(1, state)
                buflen = off + XOF_BLOCKBYTES
                temp = [0]*(KYBER_N - ctr)
                ctr1 = rej_uniform(temp, KYBER_N - ctr, buf, buflen)
                for index in range(KYBER_N-ctr):
                    a[i].vec[j].coeffs[ctr+index] = temp[index]
                ctr += ctr1


def gen_a(A, B):
    gen_matrix(A, B, 0)

def gen_at(A, B):
    gen_matrix(A, B, 1)


#################################################
# Name:        indcpa_keypair
#
# Description: Generates public and private key for the CPA-secure
#              public-key encryption scheme underlying Kyber
#
# Arguments:   - List[int] pk: output public key
#                             (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
#              - List[int] sk: output private key
#                             (of length KYBER_INDCPA_SECRETKEYBYTES bytes)
##################################################
def indcpa_keypair(pk:List[int], sk:List[int]):
    buf = [0]*2*KYBER_SYMBYTES
    nonce = 0
    a = [polyvec() for _ in range(KYBER_K)]
    e, pkpv, skpv = [polyvec() for _ in range(3)]

    buf = urandom(KYBER_SYMBYTES)
    # buf = bytes(range(KYBER_SYMBYTES))
    buf = list(hash_g(buf))

    gen_a(a, buf[:KYBER_SYMBYTES])

    for i in range(KYBER_K):
        poly_getnoise_eta1(skpv.vec[i], buf[KYBER_SYMBYTES:], nonce)
        nonce += 1
    for i in range(KYBER_K):
        poly_getnoise_eta1(e.vec[i], buf[KYBER_SYMBYTES:], nonce)
        nonce += 1

    polyvec_ntt(skpv)
    polyvec_ntt(e)

    for i in range(KYBER_K):
        polyvec_basemul_acc_montgomery(pkpv.vec[i], a[i], skpv)
        poly_tomont(pkpv.vec[i])

    polyvec_add(pkpv, pkpv, e)
    polyvec_reduce(pkpv)

    pack_sk(sk, skpv)
    pack_pk(pk, pkpv, buf[:KYBER_SYMBYTES])


#################################################
# Name:        indcpa_enc
#
# Description: Encryption function of the CPA-secure
#              public-key encryption scheme underlying Kyber.
#
# Arguments:   - List[int] c: output ciphertext
#                            (of length KYBER_INDCPA_BYTES bytes)
#              - List[int] m: input message
#                             (of length KYBER_INDCPA_MSGBYTES bytes)
#              - List[int] pk: input public key
#                              (of length KYBER_INDCPA_PUBLICKEYBYTES)
#              - List[int] coins: input random coins used as seed
#                                 (of length KYBER_SYMBYTES) to deterministically
#                                 generate all randomness
##################################################
def indcpa_enc(c:List[int], m:List[int], pk:List[int], coins:List[int]):
    seed = [0]*KYBER_SYMBYTES
    nonce = 0
    at = [polyvec() for _ in range(KYBER_K)]
    sp, pkpv, ep, b = [polyvec() for _ in range(4)]
    v, k, epp = [poly() for _ in range(3)]

    unpack_pk(pkpv, seed, pk)
    poly_frommsg(k, m)
    gen_at(at, seed)

    for i in range(KYBER_K):
        poly_getnoise_eta1(sp.vec[i], coins, nonce)
        nonce += 1
    for i in range(KYBER_K):
        poly_getnoise_eta2(ep.vec[i], coins, nonce)
        nonce += 1
    poly_getnoise_eta2(epp, coins, nonce)
    nonce += 1

    polyvec_ntt(sp)

    for i in range(KYBER_K):
        polyvec_basemul_acc_montgomery(b.vec[i], at[i], sp)

    polyvec_basemul_acc_montgomery(v, pkpv, sp)

    polyvec_invntt_tomont(b)
    poly_invntt_tomont(v)

    polyvec_add(b, b, ep)
    poly_add(v, v, epp)
    poly_add(v, v, k)
    polyvec_reduce(b)
    poly_reduce(v)

    pack_ciphertext(c, b, v)


#################################################
# Name:        indcpa_dec
#
# Description: Decryption function of the CPA-secure
#              public-key encryption scheme underlying Kyber.
#
# Arguments:   - List[int] m: output decrypted message
#                            (of length KYBER_INDCPA_MSGBYTES)
#              - List[int] c: input ciphertext
#                             (of length KYBER_INDCPA_BYTES)
#              - List[int] sk: input secret key
#                              (of length KYBER_INDCPA_SECRETKEYBYTES)
##################################################
def indcpa_dec(m:List[int], c:List[int], sk:List[int]):
    b, skpv = polyvec(), polyvec()
    v, mp = poly(), poly()

    unpack_ciphertext(b, v, c)
    unpack_sk(skpv, sk)

    polyvec_ntt(b)
    polyvec_basemul_acc_montgomery(mp, skpv, b)
    poly_invntt_tomont(mp)

    poly_sub(mp, v, mp)
    poly_reduce(mp)
    
    poly_tomsg(m, mp)
