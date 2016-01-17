FALCON was created for academic purposes and should not be used in production code or to encrypt sensitive data.

1. FALCON_ref is a basic implementation of the cipher. It is simple but slow. Compiling test.c by using “make test” will allow one to experiment with different inputs to FALCON.

2. benchmark.c performs a speed test of FALCON against AES. Uncomment the CLOCK_FREQ macro and replace it with the correct value for your machine in order to see information such as cycles/byte. Compile benchmark with “make benchmark”

This code assumes that the machine is little-endian. If it is run on a big-endian machine it will produce incorrect plaintext/ciphertext pairs.
