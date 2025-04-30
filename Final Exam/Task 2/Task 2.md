# Task 2: Secure File Exchange Using RSA + AES

This task simulates a secure file exchange from Alice to Bob using a hybrid encryption scheme (AES for data, RSA for key exchange) and includes an integrity check using SHA-256 hashing.

## Encryption/Decryption Flow

1.  **Key Generation (Bob)**: An RSA key pair (public and private keys, 2048 bits) is generated for Bob. The keys are saved in PEM format (`public.pem`, `private.pem`).
2.  **Message Creation (Alice)**: Alice creates the plaintext message file (`alice_message.txt`).
3.  **Original Hash Calculation (Alice)**: Alice computes the SHA-256 hash of `alice_message.txt` before encryption to establish a baseline for integrity verification.
4.  **Symmetric Encryption (Alice)**:
    * Alice generates a random, single-use AES-256 symmetric key and a random 16-byte Initialization Vector (IV).
    * Alice encrypts `alice_message.txt` using AES-256 in Cipher Block Chaining (CBC) mode with PKCS7 padding, utilizing the generated AES key and IV.
    * The IV is prepended to the resulting ciphertext. The combined IV + ciphertext is saved as `encrypted_file.bin`.
5.  **Symmetric Key Encryption (Alice)**: Alice encrypts the *AES session key* (NOT the IV) using Bob's public key (`public.pem`) with RSA-OAEP padding. The result is saved as `aes_key_encrypted.bin`.
6.  **Transmission**: Alice sends `encrypted_file.bin` and `aes_key_encrypted.bin` to Bob.
7.  **Symmetric Key Decryption (Bob)**: Bob uses his *private key* (`private.pem`) to decrypt `aes_key_encrypted.bin`, recovering the original AES session key.
8.  **Symmetric Decryption (Bob)**:
    * Bob reads the 16-byte IV from the beginning of `encrypted_file.bin`.
    * Using the decrypted AES key and the extracted IV, Bob decrypts the rest of the ciphertext from `encrypted_file.bin` using AES-256-CBC and removes the PKCS7 padding.
    * The resulting plaintext is saved as `decrypted_message.txt`.
9.  **Decrypted Hash Calculation (Bob)**: Bob computes the SHA-256 hash of the recovered `decrypted_message.txt`.
10. **Integrity Verification (Bob)**: Bob compares the newly calculated hash with the original hash provided by Alice (or calculated by himself if Alice just sent the hash value). If the hashes match, it provides high confidence that the file was decrypted correctly and was not tampered with during transmission.

## Comparison: AES vs. RSA

| Feature         | AES (Advanced Encryption Standard)                     | RSA (Rivest–Shamir–Adleman)                                   |
| :-------------- | :----------------------------------------------------- | :------------------------------------------------------------ |
| **Type** | Symmetric-key algorithm                              | Asymmetric-key algorithm                                      |
| **Keys** | Uses the **same** secret key for encryption & decryption | Uses a **public key** for encryption, **private key** for decryption (or vice-versa for signatures) |
| **Speed** | Very **fast**, suitable for large amounts of data.     | Significantly **slower** than AES, especially decryption.     |
| **Use Case** | **Bulk data encryption** (files, network traffic, databases), requires a secure way to share the key. | **Key exchange** (encrypting symmetric keys like AES keys), **digital signatures**, encrypting small amounts of data. |
| **Security** | Considered secure (e.g., AES-128, AES-192, AES-256) assuming a strong, secret key. Security based on substitution-permutation network principles. | Considered secure (e.g., RSA-2048, RSA-3072+) assuming sufficiently large keys. Security based on the difficulty of factoring large integers. |
| **Hybrid Approach** | Combines the efficiency of AES for data encryption with the secure key exchange capability of RSA for the AES key, leveraging the strengths of both. |                                                               |