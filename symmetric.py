# Contains elements from symmetric.h and symmetric-shake.c

from fips202 import *

#################################################
# Name:        kyber_shake128_absorb
#
# Description: Absorb step of the SHAKE128 specialized for the Kyber context.
#
# Arguments:   - state: Keccak state
#              - int seed: KYBER_SYMBYTES input to be absorbed into state
#              - int i: additional byte of input
#              - int j: additional byte of input
##################################################
def kyber_shake128_absorb(state: SHAKE128.SHAKE128_XOF, seed:List[int], x:int, y:int):
    extseed = seed + [x, y]
    state.update(bytes(extseed))


#################################################
# Name:        kyber_shake256_prf
#
# Description: Usage of SHAKE256 as a PRF, concatenates secret and public input
#              and then generates outlen bytes of SHAKE256 output
#
# Arguments:   - int out: output
#              - int outlen: number of requested output bytes
#              - int key: key (of length KYBER_SYMBYTES)
#              - int nonce: single-byte nonce (public PRF input)
##################################################
def kyber_shake256_prf(out:List[int], outlen:int, key:List[int], nonce:int):
    extkey = key+[nonce]
    temp = shake256(bytes(extkey), outlen)
    for i in range(len(out)):
        out[i] = temp[i]


XOF_BLOCKBYTES = SHAKE128_RATE
hash_h = sha3_256
hash_g = sha3_512
xof_absorb = kyber_shake128_absorb
xof_squeezeblocks = shake128_squeezeblocks
prf = kyber_shake256_prf
kdf = shake256
