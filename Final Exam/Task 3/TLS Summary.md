=== TLS Security Mechanisms ===

**Confidentiality**:
TLS provides confidentiality by using symmetric encryption algorithms (like AES-256-GCM, identified in the cipher suite) to encrypt the application data exchanged between the client and server. The unique symmetric keys (session keys) used for this encryption are securely generated and agreed upon by both parties during the TLS handshake process, typically using asymmetric cryptography like Diffie-Hellman (often ECDH, e.g., X25519 as seen in the `openssl` output's Server Temp Key) to protect the key exchange.

**Integrity**:
TLS ensures data integrity using Authenticated Encryption with Associated Data (AEAD) ciphers (like AES-GCM used here). These ciphers combine encryption with a Message Authentication Code (MAC). A cryptographic tag is generated based on the message content and the shared secret key. The receiver performs the same calculation and verifies this tag. If the data was altered in transit, the calculated tag will not match the received tag, allowing the tampering to be detected and the connection potentially terminated.
