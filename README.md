# Python_Kyber

A python translation of the reference Kyber implementation for easy experimentation. The goal of this project was to have an implementation that is as close to the latest reference (at the time of writing, v3.0) implementation of Kyber while offering the flexibility to easily experiment and change stuff around.

Some features of this implementation:
1. Effort has been made to keep code as close to reference as possible.
2. This implementation passes all KATs generated from the reference.
3. Better handling of global parameters to switch modes on the go.
4. Key-generation and encryption accept optional inputs for fixed randomness testing

## Disclaimer

This code is not suitable for real world deployment under any scenario. It is neither performant nor constant time. It should only be used for education and experimentation.

## Code Example

```python
>>> from kem import *
>>>
>>> # Set mode
>>> g.set_mode(2) # Can be 2, 3, or 4
>>>
>>> # Key generation
>>> pk = [0]*g.KYBER_PUBLICKEYBYTES
>>> sk = [0]*g.KYBER_SECRETKEYBYTES
>>> crypto_kem_keypair(pk, sk)
0
>>> # Encapsulation
>>> ct = [0]*g.KYBER_CIPHERTEXTBYTES
>>> ss = [0]*g.KYBER_SSBYTES
>>> crypto_kem_enc(ct, ss, pk)
0
>>> # Decapsulation
>>> ssp = [0]*g.KYBER_SSBYTES
>>> crypto_kem_dec(ssp, ct, sk)
0
>>> ssp == ss
True
>>> # Sanity check
>>> crypto_kem_dec(ssp, list(urandom(len(ct))), sk)
0
>>> ssp == ss
False
>>> pk2, sk2 = [0]*g.KYBER_PUBLICKEYBYTES, [0]*g.KYBER_SECRETKEYBYTES
>>> crypto_kem_dec(ssp, ct, sk2)
0
>>> ssp == ss
False
```

## Additional Details

### KATs

This implementation passes all the test vectors generated from v3.0 of the reference implementation. 

The KAT files themselves can be found in the ['KATs'](KATs) folder while the test functions can be found in ['test.py'](test.py).

### AES DRBG

For using deterministic randomness, the reference implementation uses the AES256 CTR DRBG. I used an implementation I found in [this repo](https://github.com/popcornell/pyAES_DRBG). The implementation of the DRBG uses pyAES.

### Dependencies 

Kyber uses `Shake256`, `Shake128` XOFs and `Sha3_256`, `Sha3_512` hashes internally in many places. It didn't seem worthwhile to reimplement them from scratch so I make use of the `pycryptodome` library for it.

Additionally the AES256 CTR DRBG uses the `pyAES` library instead of implementing AES from scratch as well.

You can install these libraries by running `pip -r install requirements`.

### Global parameters

The reference C implementation puts all the parameters in one file called `params.h` and then imports it everywhere. Functions use the value of these global variables as they were at the time of import. While this is fine for a compiled language as one would only make changes to the code before compiling again, it creates problems for an interpreted language like Python.

Keeping all the parameters in one file would mean that we would not be able to change modes while in an interactive session or in a script. To change modes one would have to exit, modify the file and then run it again. To overcome this, instead of treating these parameters as global variables, I made them members of a class.

The class is still defined in params.py and an object `g` of it has been instantiated. The change we have to make now is that to access a global variable `X`, we have to use `g.X`. The upside is that I was able to write another member function called `set_mode` which allows us to change between the different parameter sets on the go.

So in short, the file params differs from the reference in some non trivial ways and all the other files use global variables with a prefix `g.`.

### Repeating randomness

The key generation and encapsulation functions accept additional arguments to replace randomness with desired values for testing. If nothing is provided, `os.urandom` is used to generate fresh randomness. This is useful for testing and was used for verification against the KATs.

### Benchmarks

Because everyone needs numbers:

| 1000 Iterations | Kyber 512 | Kyber 768 | Kyber 1024 |
|-----------------|-----------|-----------|------------|
| key generation  |  3.437s   |  5.866s   |   8.665s   |
| encapsulation   |  4.932s   |  7.692s   |  10.985s   |
| decapsulation   |  7.272s   |  10.442s  |  14.421s   |

The data was generated using ['benchmark.py'](benchmark.py).  The test was done on an i7-10750H laptop cpu.
