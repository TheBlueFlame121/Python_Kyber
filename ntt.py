# Contains elements from ntt.h and ntt.c

from reduce import *

zetas = [
  -1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
   -171,   622,  1577,   182,   962, -1202, -1474,  1468,
    573, -1325,   264,   383,  -829,  1458, -1602,  -130,
   -681,  1017,   732,   608, -1542,   411,  -205, -1571,
   1223,   652,  -552,  1015, -1293,  1491,  -282, -1544,
    516,    -8,  -320,  -666, -1618, -1162,   126,  1469,
   -853,   -90,  -271,   830,   107, -1421,  -247,  -951,
   -398,   961, -1508,  -725,   448, -1065,   677, -1275,
  -1103,   430,   555,   843, -1251,   871,  1550,   105,
    422,   587,   177,  -235,  -291,  -460,  1574,  1653,
   -246,   778,  1159,  -147,  -777,  1483,  -602,  1119,
  -1590,   644,  -872,   349,   418,   329,  -156,   -75,
    817,  1097,   603,   610,  1322, -1285, -1465,   384,
  -1215,  -136,  1218, -1335,  -874,   220, -1187, -1659,
  -1185, -1530, -1278,   794, -1510,  -854,  -870,   478,
   -108,  -308,   996,   991,   958, -1460,  1522,  1628
   ]


#################################################
# Name:        fqmul
#
# Description: Multiplication followed by Montgomery reduction
#
# Arguments:   - int a: first factor
#              - int b: second factor
#
# Returns 16-bit integer congruent to a*b*R^{-1} mod q
##################################################
def fqmul(a:int, b:int) -> int:
    return montgomery_reduce(a*b)


#################################################
# Name:        ntt
#
# Description: Inplace number-theoretic transform (NTT) in Rq.
#              input is in standard order, output is in bitreversed order
#
# Arguments:   - int r[256]: pointer to input/output vector of elements of Zq
##################################################
def ntt(r:List[int]):
    k=1
    l = 128
    while l >= 2:
        start = 0
        while start < 256:
            zeta = zetas[k]
            k+=1
            for j in range(start, start+l):
                t = fqmul(zeta, r[j+l])
                r[j+l] = r[j] - t
                r[j] = r[j] + t
            start = j + l + 1
        l >>= 1


#################################################
# Name:        invntt_tomont
#
# Description: Inplace inverse number-theoretic transform in Rq and
#              multiplication by Montgomery factor 2^16.
#              Input is in bitreversed order, output is in standard order
#
# Arguments:   - int r[256]: pointer to input/output vector of elements of Zq
##################################################
def invntt(r:List[int]):
    f = 1441
    k = 127
    l = 2
    while l<=128:
        start = 0
        while start < 256:
            zeta = zetas[k]
            k -= 1
            for j in range(start, start+l):
                t = r[j]
                r[j] = barrett_reduce(t + r[j+l])
                r[j+l] = r[j+l] - t
                r[j+l] = fqmul(zeta, r[j+l])
            start = j + l + 1
        l <<= 1
    for j in range(256):
        r[j] = fqmul(r[j], f)


#################################################
# Name:        basemul
#
# Description: Multiplication of polynomials in Zq[X]/(X^2-zeta)
#              used for multiplication of elements in Rq in NTT domain
#
# Arguments:   - int r[2]: the output polynomial
#              - int a[2]: the first factor
#              - int b[2]: the second factor
#              - int zeta: integer defining the reduction polynomial
##################################################
def basemul(r:List[int], a:List[int], b:List[int], zeta:int):
    r[0]  = fqmul(a[1], b[1])
    r[0]  = fqmul(r[0], zeta)
    r[0] += fqmul(a[0], b[0])
    r[1]  = fqmul(a[0], b[1])
    r[1] += fqmul(a[1], b[0])
