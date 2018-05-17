# comp30023-2018-project-2
Project 2 for COMP30023 Computer Systems 2018

---
### Project Detail
A TLS certificate validation using openssl library

- Input CSV: file path, certificate URL
    - example: cert_one.cer,www.comp30023test.com
- Output CSV: file path, certificate URL, result (1 for valid, 0 for invalid)
    - example: cert_one.cer,www.comp30023test.com,1

#### Minimum Checking
- Validates Not Before date
- Validates Not After date
- Validates domain name in Common Name
- Validates minimum RSA key length of 2048 bits
- Validates Basic Constraint includes "CA:FALSE"
- Validates Extended Key Usage includes "TLS Web Server Authentication"
- Validates Subject Alternative Name extension

---
### Usage
	make
	./certcheck [path to test file]
	make clean
