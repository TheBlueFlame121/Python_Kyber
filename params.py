# Contains elements from params.h

from typing import List

class Parameters:
    def __init__(self, mode:int):
        self.KYBER_K = mode

        assert self.KYBER_K in [2, 3, 4] and "KYBER_K must be in {2, 3, 4}"

        self.KYBER_N = 256
        self.KYBER_Q = 3329

        self.KYBER_SYMBYTES  = 32   # size in bytes of hashes, and seeds
        self.KYBER_SSBYTES   = 32   # size in bytes of shared key

        self.KYBER_POLYBYTES	    = 384
        self.KYBER_POLYVECBYTES  = (self.KYBER_K * self.KYBER_POLYBYTES)

        if self.KYBER_K == 2:
            self.KYBER_ETA1 = 3
            self.KYBER_POLYCOMPRESSEDBYTES    = 128
            self.KYBER_POLYVECCOMPRESSEDBYTES = (self.KYBER_K * 320)
        elif self.KYBER_K == 3:
            self.KYBER_ETA1 = 2
            self.KYBER_POLYCOMPRESSEDBYTES    = 128
            self.KYBER_POLYVECCOMPRESSEDBYTES = (self.KYBER_K * 320)
        elif self.KYBER_K == 4:
            self.KYBER_ETA1 = 2
            self.KYBER_POLYCOMPRESSEDBYTES    = 160
            self.KYBER_POLYVECCOMPRESSEDBYTES = (self.KYBER_K * 352)

        self.KYBER_ETA2 = 2

        self.KYBER_INDCPA_MSGBYTES       = (self.KYBER_SYMBYTES)
        self.KYBER_INDCPA_PUBLICKEYBYTES = (self.KYBER_POLYVECBYTES + self.KYBER_SYMBYTES)
        self.KYBER_INDCPA_SECRETKEYBYTES = (self.KYBER_POLYVECBYTES)
        self.KYBER_INDCPA_BYTES          = (self.KYBER_POLYVECCOMPRESSEDBYTES + self.KYBER_POLYCOMPRESSEDBYTES)

        self.KYBER_PUBLICKEYBYTES  = (self.KYBER_INDCPA_PUBLICKEYBYTES)
        # 32 bytes of additional space to save H(pk)
        self.KYBER_SECRETKEYBYTES  = (self.KYBER_INDCPA_SECRETKEYBYTES + self.KYBER_INDCPA_PUBLICKEYBYTES + 2*self.KYBER_SYMBYTES)
        self.KYBER_CIPHERTEXTBYTES = (self.KYBER_INDCPA_BYTES)

    def set_mode(self, mode:int):
        self.__init__(mode)

g = Parameters(2)

