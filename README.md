# Post-Quantum Vehicle-RSU Authentication Protocol (Simulation)

'On the Development of Quantum-Safe PUF-Based Authentication for Pervasive Vehicular Networks'

C simulation of a Kyber-512 (liboqs) based authentication and key agreement protocol between a vehicle and an RSU, with a simulated PUF and fuzzy extractor.



## Requirements

- liboqs 0.12.0, OpenSSL

- Or use the provided Dockerfile (no local install needed)



## Run with Docker

```

docker build -t oqs-gcc .

docker run --rm -v ${PWD}:/app -w /app oqs-gcc bash -c "gcc -O2 protocol.c -o protocol -loqs -lssl -lcrypto -lm && ./protocol"

```



## Sample output

See sample_output.txt. Hex values differ on every run because keys and nonces are random.





