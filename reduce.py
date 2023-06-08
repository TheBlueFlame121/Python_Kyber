# Contains elements from reduce.h and reduce.c

from params import *

MONT = -1044 # 2^16 mod q
QINV = -3327 # q^-1 mod 2^16


#################################################
# Name:        montgomery_reduce
#
# Description: Montgomery reduction; given a 32-bit integer a, computes
#              16-bit integer congruent to a * R^-1 mod q, where R=2^16
#
# Arguments:   - int a: input integer to be reduced;
#                       has to be in {-q2^15,...,q2^15-1}
#
# Returns:     integer in {-q+1,...,q-1} congruent to a * R^-1 modulo q.
##################################################
def montgomery_reduce(a:int) -> int:
    t = (a*QINV)%(2**16)
    t = (a - t*KYBER_Q) >> 16
    t += KYBER_Q
    if t > (KYBER_Q>>1):
        t -= KYBER_Q
    return t


#################################################
# Name:        barrett_reduce
#
# Description: Barrett reduction; given a 16-bit integer a, computes
#              centered representative congruent to a mod q in {-(q-1)/2,...,(q-1)/2}
#
# Arguments:   - int a: input integer to be reduced
#
# Returns:     integer in {-(q-1)/2,...,(q-1)/2} congruent to a modulo q.
##################################################
def barrett_reduce(a:int) -> int:
    v = ((1<<26) + KYBER_Q//2)//KYBER_Q

    t = (v*a + (1<<25)) >> 26
    t *= KYBER_Q
    t %= (2**16)
    return a - t
