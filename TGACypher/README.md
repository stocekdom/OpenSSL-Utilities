# TGA File Encryption and Decryption

## Overview

This utility implements two functions — encrypt_data and decrypt_data — that can encrypt and decrypt simplified TGA image files using OpenSSL block ciphers.

## TGA Format Simplification

The program assumes the following structure for TGA files:

### Mandatory header (18 bytes):
- Always copied directly, without encryption or modification.

### Optional header:
- Treated as part of image data and therefore encrypted.

### Image data:
- The rest of the file, encrypted or decrypted depending on the operation.


