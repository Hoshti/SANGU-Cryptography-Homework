Signature Verification Explanation

The process of verifying Alice's signature on the message received by Bob confirms two critical security properties: Authenticity and Integrity.

1.  **Authenticity (Who sent it?)**:
    * When Alice signed the message (`gpg --sign ... --local-user alice@company.com ...`), GPG used *Alice's private key* to create a digital signature, which is a cryptographic hash of the message content transformed by the private key.
    * When Bob verified the message (`gpg --decrypt ...`), GPG located the signature attached to the message. It identified the signature as belonging to Alice's key ID.
    * GPG then used *Alice's public key* (which Bob must have in his keyring) to perform the mathematical verification process on the signature and the message content.
    * Only the holder of Alice's private key could have generated a signature that correctly verifies with Alice's public key.
    * Therefore, the output `Good signature from "Alice Example <alice@company.com>"` confirms that the message originated from someone with access to Alice's private key (presumably Alice).

2.  **Integrity (Was it tampered with?)**:
    * The digital signature is intrinsically linked to the exact content of the message at the time of signing.
    * During verification, GPG recalculates a hash of the received message content. It then uses Alice's public key to check if this calculated hash matches the information embedded within the digital signature.
    * If the message content had been altered *in any way* after Alice signed it, the recalculated hash would not match, and the signature verification would fail (GPG would report a `BAD signature`).
    * The `Good signature` message thus also confirms that the message content Bob decrypted is exactly the same as the content Alice signed.

In summary, the successful verification of the digital signature assures Bob that the message is genuinely from Alice and that it arrived exactly as she wrote it, without modification.
