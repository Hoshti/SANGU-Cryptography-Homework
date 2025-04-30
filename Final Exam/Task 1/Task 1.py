# task1_messaging.py
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- Configuration ---
RSA_KEY_SIZE = 2048
RSA_PUBLIC_EXPONENT = 65537
AES_KEY_SIZE_BYTES = 32 # AES-256
AES_NONCE_SIZE_BYTES = 12 # Standard for GCM

# --- File Names ---
MESSAGE_FILE = "message.txt"
ENCRYPTED_MESSAGE_FILE = "encrypted_message.bin"
ENCRYPTED_AES_KEY_FILE = "aes_key_encrypted.bin"
DECRYPTED_MESSAGE_FILE = "decrypted_message.txt"
# Note: RSA keys are kept in memory for this simulation, not saved to .pem files in Task 1

def generate_rsa_keys():
    """Generates an RSA key pair."""
    print("[User A] Generating RSA key pair...")
    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE
    )
    public_key = private_key.public_key()
    print("[User A] RSA key pair generated.")
    return private_key, public_key

def create_message_file(filename, content):
    """Creates the message file."""
    print(f"[User B] Creating original message file: {filename}")
    with open(filename, "w") as f:
        f.write(content)
    print(f"[User B] Original message: '{content}'")

def encrypt_message_hybrid(message_file, public_key):
    """
    Encrypts the message using AES-GCM with a random key,
    then encrypts the AES key using the provided RSA public key.
    """
    # 1. Generate random AES key
    aes_key = AESGCM.generate_key(bit_length=AES_KEY_SIZE_BYTES * 8)
    print(f"[User B] Generated random AES-{AES_KEY_SIZE_BYTES*8} key.") # For demo, don't usually print keys

    # 2. Read the message
    with open(message_file, "rb") as f:
        plaintext = f.read()

    # 3. Encrypt message with AES-GCM
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(AES_NONCE_SIZE_BYTES) # Generate random nonce
    print("[User B] Encrypting message with AES-GCM...")
    ciphertext = aesgcm.encrypt(nonce, plaintext, None) # No associated data

    # Save nonce + ciphertext
    with open(ENCRYPTED_MESSAGE_FILE, "wb") as f:
        f.write(nonce)
        f.write(ciphertext)
    print(f"[User B] Encrypted message saved to: {ENCRYPTED_MESSAGE_FILE} (Nonce prepended)")

    # 4. Encrypt AES key with RSA public key (OAEP padding recommended)
    print("[User B] Encrypting AES key with User A's RSA public key...")
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Save encrypted AES key
    with open(ENCRYPTED_AES_KEY_FILE, "wb") as f:
        f.write(encrypted_aes_key)
    print(f"[User B] Encrypted AES key saved to: {ENCRYPTED_AES_KEY_FILE}")

    # Return the original AES key only for verification purposes in this demo
    return aes_key


def decrypt_message_hybrid(private_key):
    """
    Decrypts the AES key using the RSA private key, then decrypts the message
    using the recovered AES key.
    """
    # 1. Read and decrypt AES key
    print("[User A] Reading encrypted AES key...")
    with open(ENCRYPTED_AES_KEY_FILE, "rb") as f:
        encrypted_aes_key_from_file = f.read()

    print("[User A] Decrypting AES key with RSA private key...")
    decrypted_aes_key = private_key.decrypt(
        encrypted_aes_key_from_file,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"[User A] AES key decrypted.") # For demo, don't usually print keys

    # 2. Read encrypted message (nonce + ciphertext)
    print("[User A] Reading encrypted message file...")
    with open(ENCRYPTED_MESSAGE_FILE, "rb") as f:
        nonce_from_file = f.read(AES_NONCE_SIZE_BYTES)
        ciphertext_from_file = f.read()

    # 3. Decrypt message with recovered AES key
    print("[User A] Decrypting message with recovered AES key...")
    aesgcm = AESGCM(decrypted_aes_key)
    try:
        decrypted_plaintext = aesgcm.decrypt(nonce_from_file, ciphertext_from_file, None)
        print("[User A] Message decrypted successfully.")

        # 4. Save decrypted message
        with open(DECRYPTED_MESSAGE_FILE, "wb") as f:
            f.write(decrypted_plaintext)
        print(f"[User A] Decrypted message saved to: {DECRYPTED_MESSAGE_FILE}")

        # Return decrypted key and message for verification
        return decrypted_aes_key, decrypted_plaintext.decode()

    except Exception as e: # Catch potential decryption/authentication errors
        print(f"[User A] Decryption FAILED: {e}")
        # Write an empty or error file
        with open(DECRYPTED_MESSAGE_FILE, "w") as f:
            f.write(f"DECRYPTION FAILED: {e}")
        return decrypted_aes_key, None


if __name__ == "__main__":
    print("--- Task 1: Encrypted Messaging Simulation ---")

    # User A generates keys
    user_a_private_key, user_a_public_key = generate_rsa_keys()

    # User B prepares and encrypts the message
    original_message_content = f"This is a secret message from User B to User A. Sent on {os.urandom(4).hex()}."
    create_message_file(MESSAGE_FILE, original_message_content)
    original_aes_key_b = encrypt_message_hybrid(MESSAGE_FILE, user_a_public_key) # User B uses A's public key

    print("\n--- Message sent from B to A ---\n")

    # User A receives and decrypts
    decrypted_aes_key_a, decrypted_message_content = decrypt_message_hybrid(user_a_private_key) # User A uses their private key

    # --- Verification (For Demo Purposes) ---
    print("\n--- Verification ---")
    if original_aes_key_b == decrypted_aes_key_a:
        print("[OK] Decrypted AES key matches original AES key.")
    else:
        print("[FAIL] AES keys DO NOT MATCH!")

    if decrypted_message_content == original_message_content:
         print("[OK] Decrypted message matches original message.")
         print(f"     Original:  '{original_message_content}'")
         print(f"     Decrypted: '{decrypted_message_content}'")
    else:
        print("[FAIL] Decrypted message DOES NOT MATCH original!")
        print(f"     Original:  '{original_message_content}'")
        print(f"     Decrypted: '{decrypted_message_content}'") # Print what was actually decrypted

    print("\n--- Task 1 Complete ---")
    print(f"Generated files: {MESSAGE_FILE}, {ENCRYPTED_MESSAGE_FILE}, {ENCRYPTED_AES_KEY_FILE}, {DECRYPTED_MESSAGE_FILE}")