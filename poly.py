# Contains elements from cbd.h, cbd.c, poly.h and poly.c

from reduce import *
from symmetric import *
from ntt import *


class poly:
    coeffs: List[int]

    def __init__(self, inp: list[int] = None):
        if inp is None:
            inp = [0 for _ in range(KYBER_N)]
        if len(inp) > KYBER_N:
            raise ValueError("Polynomial can't have more than N coeffs")
        if len(inp) < KYBER_N:
            inp = inp + [0 for _ in range(KYBER_N-len(inp))].copy()
        self.coeffs = inp


#################################################
# Name:        load32_littleendian
#
# Description: load 4 bytes into a 32-bit integer
#              in little-endian order
#
# Arguments:   - x: input byte array
#
# Returns 32-bit integer loaded from x
##################################################
def load32_littleendian(x:List[int]) -> int:
    r = x[0]
    r |= x[1] << 8
    r |= x[2] << 16
    r |= x[3] << 24
    return r


#################################################
# Name:        load24_littleendian
#
# Description: load 3 bytes into a 32-bit integer
#              in little-endian order.
#              This function is only needed for Kyber-512
#
# Arguments:   - x: input byte array
#
# Returns 24-bit integer loaded from x 
##################################################
def load24_littleendian(x:List[int]) -> int:
    r = x[0]
    r |= x[1] << 8
    r |= x[2] << 16
    return r


#################################################
# Name:        cbd2
#
# Description: Given an array of uniformly random bytes, compute
#              polynomial with coefficients distributed according to
#              a centered binomial distribution with parameter eta=2
#
# Arguments:   - poly r: output polynomial
#              - List[int] buf: input byte array
##################################################
def cbd2(r:poly, buf:List[int]):
    for i in range(KYBER_N//8):
        t = load32_littleendian(buf[4*i:4*(i+1)])
        d = t & 0x55555555
        d += (t>>1) & 0x55555555

        for j in range(8):
            a = (d >> (4*j+0)) & 0x3
            b = (d >> (4*j+2)) & 0x3
            r.coeffs[8*i+j] = a - b


#################################################
# Name:        cbd3
#
# Description: Given an array of uniformly random bytes, compute
#              polynomial with coefficients distributed according to
#              a centered binomial distribution with parameter eta=3.
#              This function is only needed for Kyber-512
#
# Arguments:   - poly r: output polynomial
#              - List[int] buf: input byte array
##################################################
def cbd3(r:poly, buf:List[int]):
    for i in range(KYBER_N//4):
        t = load24_littleendian(buf[3*i:3*(i+1)])
        d = t & 0x00249249
        d += (t>>1) & 0x00249249
        d += (t>>2) & 0x00249249

        for j in range(4):
            a = (d >> (6*j+0)) & 0x7
            b = (d >> (6*j+3)) & 0x7
            r.coeffs[4*i+j] = a - b


def poly_cbd_eta1(r:poly, buf:List[int]):
    assert KYBER_ETA1 in [2, 3] and "This implementation requires eta1 in {2,3}"
    if KYBER_ETA1 == 2:
        cbd2(r, buf)
    elif KYBER_ETA1 == 3:
        cbd3(r, buf)


def poly_cbd_eta2(r:poly, buf:List[int]):
    assert KYBER_ETA2 == 2 and "This implementation requires eta2 = 2"
    if KYBER_ETA2 == 2:
        cbd2(r, buf)


#################################################
# Name:        poly_compress
#
# Description: Compression and subsequent serialization of a polynomial
#
# Arguments:   - List[int] r: output byte array
#                            (of length KYBER_POLYCOMPRESSEDBYTES)
#              - poly a: input polynomial
##################################################
def poly_compress(r:List[int], a:poly):
    t = [0]*8
    if KYBER_POLYCOMPRESSEDBYTES == 128:
        start = 0
        for i in range(KYBER_N//8):
            for j in range(8):
                u = a.coeffs[8*i+j]
                u += (u >> 15) & KYBER_Q
                t[j] = (((u << 4) + KYBER_Q//2)//KYBER_Q) & 15

            r[start + 0] = t[0] | (t[1] << 4) & 255
            r[start + 1] = t[2] | (t[3] << 4) & 255
            r[start + 2] = t[4] | (t[5] << 4) & 255
            r[start + 3] = t[6] | (t[7] << 4) & 255
            start += 4;

    elif KYBER_POLYCOMPRESSEDBYTES == 160:
        start = 0
        for i in range(KYBER_N//8):
            for j in range(8):
                u = a.coeffs[8*i+j]
                u += (u >> 15) & KYBER_Q
                t[j] = (((u << 5) + KYBER_Q//2)//KYBER_Q) & 31

            r[start + 0] = (t[0] >> 0) | (t[1] << 5)               & 255
            r[start + 1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7) & 255
            r[start + 2] = (t[3] >> 1) | (t[4] << 4)               & 255
            r[start + 3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6) & 255
            r[start + 4] = (t[6] >> 2) | (t[7] << 3)               & 255
            start += 5;


#################################################
# Name:        poly_decompress
#
# Description: De-serialization and subsequent decompression of a polynomial;
#              approximate inverse of poly_compress
#
# Arguments:   - poly r: output polynomial
#              - List[int] a: input byte array
#                             (of length KYBER_POLYCOMPRESSEDBYTES bytes)
##################################################
def poly_decompress(r:poly, a:List[int]):
    if KYBER_POLYCOMPRESSEDBYTES == 128:
        start = 0
        for i in range(KYBER_N//2):
            r.coeffs[2*i+0] = (((a[start + 0] & 15)*KYBER_Q) + 8) >> 4
            r.coeffs[2*i+1] = (((a[start + 0] >> 4)*KYBER_Q) + 8) >> 4
            start += 1

    elif KYBER_POLYCOMPRESSEDBYTES == 160:
        t = [0]*8
        start = 0
        for i in range(KYBER_N//8):
            t[0] = (a[start + 0] >> 0);
            t[1] = (a[start + 0] >> 5) | (a[start + 1] << 3);
            t[2] = (a[start + 1] >> 2);
            t[3] = (a[start + 1] >> 7) | (a[start + 2] << 1);
            t[4] = (a[start + 2] >> 4) | (a[start + 3] << 4);
            t[5] = (a[start + 3] >> 1);
            t[6] = (a[start + 3] >> 6) | (a[start + 4] << 2);
            t[7] = (a[start + 4] >> 3);
            start += 5;

            for j in range(8):
                r.coeffs[8*i+j] = ((t[j] & 31)*KYBER_Q + 16) >> 5


#################################################
# Name:        poly_tobytes
#
# Description: Serialization of a polynomial
#
# Arguments:   - List[int] r: output byte array
#                            (needs space for KYBER_POLYBYTES bytes)
#              - poly a: input polynomial
##################################################
def poly_tobytes(r:List[int], a:poly):
    for i in range(KYBER_N//2):
        t0 = a.coeffs[2*i]
        t0 += (t0 >> 15) & KYBER_Q
        t1 = a.coeffs[2*i+1]
        t1 += (t1 >> 15) & KYBER_Q
        r[3*i+0] = (t0 >> 0)             & 255
        r[3*i+1] = (t0 >> 8) | (t1 << 4) & 255
        r[3*i+2] = (t1 >> 4)             & 255


#################################################
# Name:        poly_frombytes
#
# Description: De-serialization of a polynomial;
#              inverse of poly_tobytes
#
# Arguments:   - poly r: output polynomial
#              - List[int] a: pointer to input byte array
#                                  (of KYBER_POLYBYTES bytes)
##################################################
def poly_frombytes(r:poly, a:List[int]):
    for i in range(KYBER_N//2):
        r.coeffs[2*i]   = ((a[3*i+0] >> 0) | (a[3*i+1] << 8)) & 0xFFF
        r.coeffs[2*i+1] = ((a[3*i+1] >> 4) | (a[3*i+2] << 4)) & 0xFFF


#################################################
# Name:        poly_frommsg
#
# Description: Convert 32-byte message to polynomial
#
# Arguments:   - poly r: output polynomial
#              - List[int] msg: input message
##################################################
def poly_frommsg(r:poly, msg:List[int]):
    assert KYBER_INDCPA_MSGBYTES == KYBER_N//8
    for i in range(KYBER_N//8):
        for j in range(8):
            mask = -((msg[i] >> j)&1)
            r.coeffs[8*i+j] = mask & ((KYBER_Q+1)//2)


#################################################
# Name:        poly_tomsg
#
# Description: Convert polynomial to 32-byte message
#
# Arguments:   - List[int] msg: output message
#              - poly a: input polynomial
##################################################
def poly_tomsg(msg:List[int], a:poly):
    for i in range(KYBER_N//8):
        msg[i] = 0
        for j in range(8):
            t = a.coeffs[8*i+j]
            t += (t >> 15) & KYBER_Q
            t = (((t << 1) + KYBER_Q//2)//KYBER_Q) & 1
            msg[i] |= t << j


#################################################
# Name:        poly_getnoise_eta1
#
# Description: Sample a polynomial deterministically from a seed and a nonce,
#              with output polynomial close to centered binomial distribution
#              with parameter KYBER_ETA1
#
# Arguments:   - poly r: output polynomial
#              - List[int] seed: input seed
#                                (of length KYBER_SYMBYTES bytes)
#              - int nonce: one-byte input nonce
##################################################
def poly_getnoise_eta1(r:poly, seed:List[int], nonce:int):
    buf = [0]*(KYBER_ETA1*KYBER_N//4)
    prf(buf, len(buf), seed, nonce)
    poly_cbd_eta1(r, buf)


#################################################
# Name:        poly_getnoise_eta2
#
# Description: Sample a polynomial deterministically from a seed and a nonce,
#              with output polynomial close to centered binomial distribution
#              with parameter KYBER_ETA2
#
# Arguments:   - poly r: output polynomial
#              - List[int] seed: input seed
#                                (of length KYBER_SYMBYTES bytes)
#              - int nonce: one-byte input nonce
##################################################
def poly_getnoise_eta2(r:poly, seed:List[int], nonce:int):
    buf = [0]*(KYBER_ETA2*KYBER_N//4)
    prf(buf, len(buf), seed, nonce)
    poly_cbd_eta2(r, buf)


#################################################
# Name:        poly_ntt
#
# Description: Computes negacyclic number-theoretic transform (NTT) of
#              a polynomial in place;
#              inputs assumed to be in normal order, output in bitreversed order
#
# Arguments:   - poly r: in/output polynomial
##################################################
def poly_ntt(r:poly):
    ntt(r.coeffs)
    poly_reduce(r)


#################################################
# Name:        poly_invntt_tomont
#
# Description: Computes inverse of negacyclic number-theoretic transform (NTT)
#              of a polynomial in place;
#              inputs assumed to be in bitreversed order, output in normal order
#
# Arguments:   - poly a: in/output polynomial
##################################################
def poly_invntt_tomont(r:poly):
    invntt(r.coeffs)


#################################################
# Name:        poly_basemul_montgomery
#
# Description: Multiplication of two polynomials in NTT domain
#
# Arguments:   - poly r: output polynomial
#              - poly a: first input polynomial
#              - poly b: second input polynomial
##################################################
def poly_basemul_montgomery(r:poly, a:poly, b:poly):
    temp = [0]*2
    for i in range(KYBER_N//4):
        basemul(temp, a.coeffs[4*i:4*i+2], b.coeffs[4*i:4*i+2], zetas[64+i])
        r.coeffs[4*i+0] = temp[0]
        r.coeffs[4*i+1] = temp[1]
        basemul(temp, a.coeffs[4*i+2:4*i+4], b.coeffs[4*i+2:4*i+4], -zetas[64+i])
        r.coeffs[4*i+2] = temp[0]
        r.coeffs[4*i+3] = temp[1] 


#################################################
# Name:        poly_tomont
#
# Description: Inplace conversion of all coefficients of a polynomial
#              from normal domain to Montgomery domain
#
# Arguments:   - poly r: input/output polynomial
##################################################
def poly_tomont(r:poly):
    f = (1<<32) % KYBER_Q
    for i in range(KYBER_N):
        r.coeffs[i] = montgomery_reduce(r.coeffs[i]*f)


#################################################
# Name:        poly_reduce
#
# Description: Applies Barrett reduction to all coefficients of a polynomial
#              for details of the Barrett reduction see comments in reduce.c
#
# Arguments:   - poly r: input/output polynomial
##################################################
def poly_reduce(r:poly):
    for i in range(KYBER_N):
        r.coeffs[i] = barrett_reduce(r.coeffs[i])


#################################################
# Name:        poly_add
#
# Description: Add two polynomials; no modular reduction is performed
#
# Arguments: - poly r: output polynomial
#            - poly a: first input polynomial
#            - poly b: second input polynomial
##################################################
def poly_add(r:poly, a:poly, b:poly):
    for i in range(KYBER_N):
        r.coeffs[i] = a.coeffs[i] + b.coeffs[i]


#################################################
# Name:        poly_sub
#
# Description: Subtract two polynomials; no modular reduction is performed
#
# Arguments: - poly r: output polynomial
#            - poly a: first input polynomial
#            - poly b: second input polynomial
##################################################
def poly_sub(r:poly, a:poly, b:poly):
    for i in range(KYBER_N):
        r.coeffs[i] = a.coeffs[i] - b.coeffs[i]
