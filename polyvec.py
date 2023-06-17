# Contains elements from polyvec.h and polyvec.c

from poly import *

class polyvec:
    vec: List[poly]

    def __init__(self, inp: list[poly] = None):
        if inp is None:
            inp = [poly() for _ in range(g.KYBER_K)]
        if len(inp) > g.KYBER_K:
            raise ValueError("Polynomial Vector can't have more than N polys")
        if len(inp) < g.KYBER_K:
            inp = inp + [poly() for _ in range(g.KYBER_K-len(inp))].copy()
        self.vec = inp


#################################################
# Name:        polyvec_compress
#
# Description: Compress and serialize vector of polynomials
#
# Arguments:   - List[int] r: output byte array
#                            (needs space for KYBER_POLYVECCOMPRESSEDBYTES)
#              - polyvec a: input vector of polynomials
##################################################
def polyvec_compress(r:List[int], a:polyvec):
    if g.KYBER_POLYVECCOMPRESSEDBYTES == (g.KYBER_K * 352):
        start = 0
        t = [0]*8
        for i in range(g.KYBER_K):
            for j in range(g.KYBER_N//8):
                for k in range(8):
                    t[k] = a.vec[i].coeffs[8*j+k]
                    t[k] += (t[k] >> 15) & g.KYBER_Q
                    t[k] = (((t[k] << 11) + g.KYBER_Q//2)//g.KYBER_Q) & 0x7ff
                r[start + 0] = (t[0] >>  0)               & 255
                r[start + 1] = (t[0] >>  8) | (t[1] << 3) & 255
                r[start + 2] = (t[1] >>  5) | (t[2] << 6) & 255
                r[start + 3] = (t[2] >>  2)               & 255
                r[start + 4] = (t[2] >> 10) | (t[3] << 1) & 255
                r[start + 5] = (t[3] >>  7) | (t[4] << 4) & 255
                r[start + 6] = (t[4] >>  4) | (t[5] << 7) & 255
                r[start + 7] = (t[5] >>  1)               & 255
                r[start + 8] = (t[5] >>  9) | (t[6] << 2) & 255
                r[start + 9] = (t[6] >>  6) | (t[7] << 5) & 255
                r[start +10] = (t[7] >>  3)               & 255
                start += 11

    elif g.KYBER_POLYVECCOMPRESSEDBYTES == (g.KYBER_K * 320):
        start = 0
        t = [0]*4
        for i in range(g.KYBER_K):
            for j in range(g.KYBER_N//4):
                for k in range(4):
                    t[k] = a.vec[i].coeffs[4*j+k]
                    t[k] += (t[k] >> 15) & g.KYBER_Q
                    t[k] = (((t[k] << 10) + g.KYBER_Q//2)//g.KYBER_Q) & 0x3ff
                r[start + 0] = (t[0] >> 0)               & 255
                r[start + 1] = (t[0] >> 8) | (t[1] << 2) & 255
                r[start + 2] = (t[1] >> 6) | (t[2] << 4) & 255
                r[start + 3] = (t[2] >> 4) | (t[3] << 6) & 255
                r[start + 4] = (t[3] >> 2)               & 255
                start += 5


#################################################
# Name:        polyvec_decompress
#
# Description: De-serialize and decompress vector of polynomials;
#              approximate inverse of polyvec_compress
#
# Arguments:   - polyvec r:   output vector of polynomials
#              - List[int] a: input byte array
#                             (of length KYBER_POLYVECCOMPRESSEDBYTES)
##################################################
def polyvec_decompress(r:polyvec, a:List[int]):
    if g.KYBER_POLYVECCOMPRESSEDBYTES == (g.KYBER_K * 352):
        start = 0
        t = [0]*8
        for i in range(g.KYBER_K):
            for j in range(g.KYBER_N//8):
                t[0] = (a[start + 0] >> 0) | (a[start +  1] << 8)
                t[1] = (a[start + 1] >> 3) | (a[start +  2] << 5)
                t[2] = (a[start + 2] >> 6) | (a[start +  3] << 2) | (a[start+4] << 10)
                t[3] = (a[start + 4] >> 1) | (a[start +  5] << 7)
                t[4] = (a[start + 5] >> 4) | (a[start +  6] << 4)
                t[5] = (a[start + 6] >> 7) | (a[start +  7] << 1) | (a[start+8] << 9)
                t[6] = (a[start + 8] >> 2) | (a[start +  9] << 6)
                t[7] = (a[start + 9] >> 5) | (a[start + 10] << 3)
                start += 11
                
                for k in range(8):
                    r.vec[i].coeffs[8*j+k] = ((t[k] & 0x7ff)*g.KYBER_Q + 1024) >> 11

    elif g.KYBER_POLYVECCOMPRESSEDBYTES == (g.KYBER_K * 320):
        start = 0
        t = [0]*4
        for i in range(g.KYBER_K):
            for j in range(g.KYBER_N//4):
                t[0] = (a[start + 0] >> 0) | (a[start + 1] << 8);
                t[1] = (a[start + 1] >> 2) | (a[start + 2] << 6);
                t[2] = (a[start + 2] >> 4) | (a[start + 3] << 4);
                t[3] = (a[start + 3] >> 6) | (a[start + 4] << 2);
                start += 5;

                for k in range(4):
                    r.vec[i].coeffs[4*j+k] = ((t[k] & 0x3ff)*g.KYBER_Q + 512) >> 10


#################################################
# Name:        polyvec_tobytes
#
# Description: Serialize vector of polynomials
#
# Arguments:   - List[int] r: output byte array
#                            (needs space for KYBER_POLYVECBYTES)
#              - polyvec a: input vector of polynomials
##################################################
def polyvec_tobytes(r:List[int], a:polyvec):
    temp = [0]*g.KYBER_POLYBYTES
    for i in range(g.KYBER_K):
        poly_tobytes(temp, a.vec[i])
        for j in range(g.KYBER_POLYBYTES):
            r[i*g.KYBER_POLYBYTES+j] = temp[j]


#################################################
# Name:        polyvec_frombytes
#
# Description: De-serialize vector of polynomials;
#              inverse of polyvec_tobytes
#
# Arguments:   - List[int] r: output byte array
#              - polyvec a:   input vector of polynomials
#                             (of length KYBER_POLYVECBYTES)
##################################################
def polyvec_frombytes(r:polyvec, a:List[int]):
    for i in range(g.KYBER_K):
        poly_frombytes(r.vec[i], a[i*g.KYBER_POLYBYTES:(i+1)*g.KYBER_POLYBYTES])


#################################################
# Name:        polyvec_ntt
#
# Description: Apply forward NTT to all elements of a vector of polynomials
#
# Arguments:   - polyvec *r: pointer to in/output vector of polynomials
##################################################
def polyvec_ntt(r:polyvec):
    for i in range(g.KYBER_K):
        poly_ntt(r.vec[i])


#################################################
# Name:        polyvec_invntt_tomont
#
# Description: Apply inverse NTT to all elements of a vector of polynomials
#              and multiply by Montgomery factor 2^16
#
# Arguments:   - polyvec r: in/output vector of polynomials
##################################################
def polyvec_invntt_tomont(r:polyvec):
    for i in range(g.KYBER_K):
        poly_invntt_tomont(r.vec[i])


#################################################
# Name:        polyvec_basemul_acc_montgomery
#
# Description: Multiply elements of a and b in NTT domain, accumulate into r,
#              and multiply by 2^-16.
#
# Arguments: - poly r: output polynomial
#            - polyvec a: first input vector of polynomials
#            - polyvec b: second input vector of polynomials
##################################################
def polyvec_basemul_acc_montgomery(r:poly, a:polyvec, b:polyvec):
    t = poly()
    poly_basemul_montgomery(r, a.vec[0], b.vec[0])
    for i in range(1, g.KYBER_K):
        poly_basemul_montgomery(t, a.vec[i], b.vec[i])
        poly_add(r, r, t)
    poly_reduce(r)


#################################################
# Name:        polyvec_reduce
#
# Description: Applies Barrett reduction to each coefficient
#              of each element of a vector of polynomials;
#              for details of the Barrett reduction see comments in reduce.c
#
# Arguments:   - polyvec r: input/output polynomial
##################################################
def polyvec_reduce(r:polyvec):
    for i in range(g.KYBER_K):
        poly_reduce(r.vec[i])


#################################################
# Name:        polyvec_add
#
# Description: Add vectors of polynomials
#
# Arguments: - polyvec r: output vector of polynomials
#            - polyvec a: first input vector of polynomials
#            - polyvec b: second input vector of polynomials
##################################################
def polyvec_add(r:polyvec, a:polyvec, b:polyvec):
    for i in range(g.KYBER_K):
        poly_add(r.vec[i], a.vec[i], b.vec[i])
