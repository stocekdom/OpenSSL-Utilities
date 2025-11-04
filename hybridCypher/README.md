# Hybrid Encryption Utility
## Overview

This project implements hybrid encryption and decryption using OpenSSL.
It provides two main functions, seal and open, which securely encrypt and decrypt data files.
The solution follows the OpenSSL hybrid encryption model using symmetric encryption for data and asymmetric encryption (RSA) for the symmetric key.

## Process:

1. The input file is encrypted with this symmetric key.

2. The symmetric key is then encrypted using a public RSA key.

3. The resulting data (cipher NID, encrypted key, IV, encrypted data) is written to the output file.

**Decryption reverses this process:**

1. The symmetric key is decrypted using a private RSA key.

2. The data is decrypted using the recovered symmetric key and IV.

## File Structure
| Offset |Size |Type | Description |
|--------|-----|------|-------------|
| 0 |4 bytes | int | NID - Numerical identifier of the used symmetric cipher |
| 4 | 4 bytes| int | EKlen - Length of the encrypted symmetric key |
| 8 | EKlen bytes | unsigned char[] | Encrypted symmetric key |
| 8 + EKlen | IVlen bytes | unsigned char[] | Initialization vector |
| 8 + EKlen + IVlen | -	| unsigned char[] | Encrypted data |
