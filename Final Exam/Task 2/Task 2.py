# task2_secure_exchange.py
import os
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

# --- Configuration ---
RSA_KEY_SIZE = 2048
RSA_PUBLIC_EXPONENT = 65537
AES_KEY_SIZE_BYTES = 32 # AES-256
AES_BLOCK_SIZE_BYTES = 16 # Block size for AES is 128 bits (16 bytes)

# --- File Names ---
ALICE_MESSAGE_FILE = "alice_message.txt"
ENCRYPTED_FILE = "encrypted_file.bin"
ENCRYPTED_AES_KEY_FILE = "aes_key_encrypted.bin"
DECRYPTED_MESSAGE_FILE = "decrypted_message.txt"
BOB_PRIVATE_KEY_FILE = "private.pem"
BOB_PUBLIC_KEY_FILE = "public.pem"

def generate_and_save_rsa_keys(private_pem_file, public_pem_file):
    """Generates Bob's RSA key pair and saves them to PEM files."""
    print("[System] Generating Bob's RSA key pair...")
    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE
    )
    public_key = private_key.public_key()

    # Serialize private key
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption() # No password for simplicity
    )
    with open(private_pem_file, 'wb') as f:
        f.write(pem_private)
    print(f"[System] Bob's private key saved to: {private_pem_file}")

    # Serialize public key
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(public_pem_file, 'wb') as f:
        f.write(pem_public)
    print(f"[System] Bob's public key saved to: {public_pem_file}")
    return private_key, public_key # Return for immediate use if needed

def create_alice_message(filename, content):
    """Creates Alice's message file."""
    print(f"[Alice] Creating message file: {filename}")
    with open(filename, "w") as f:
        f.write(content)
    print(f"[Alice] Original message content ready.")

def calculate_sha256(filename):
    """Calculates the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filename, "rb") as f:
            # Read and update hash string value in blocks
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        print(f"[Error] File not found for hashing: {filename}")
        return None

def encrypt_file_hybrid(plaintext_file, public_key_file, encrypted_file_out, encrypted_key_out):
    """
    Encrypts a file using AES-CBC, encrypts the AES key using RSA public key.
    Handles IV generation and prepending it to the ciphertext.
    """
    # 1. Generate random AES key and IV
    aes_key = os.urandom(AES_KEY_SIZE_BYTES)
    iv = os.urandom(AES_BLOCK_SIZE_BYTES)
    print("[Alice] Generated random AES key and IV.")

    # 2. Encrypt the file using AES-CBC
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    pkcs7_padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()

    print(f"[Alice] Encrypting {plaintext_file} using AES-CBC...")
    try:
        with open(plaintext_file, "rb") as infile, open(encrypted_file_out, "wb") as outfile:
            outfile.write(iv) # Prepend IV to the output file
            while True:
                chunk = infile.read(4096)
                if not chunk:
                    # Process the final padded block
                    padded_data = pkcs7_padder.update(b"") + pkcs7_padder.finalize()
                    outfile.write(encryptor.update(padded_data) + encryptor.finalize())
                    break
                # Pad data chunk by chunk (if not the last one)
                padded_data = pkcs7_padder.update(chunk)
                outfile.write(encryptor.update(padded_data))
        print(f"[Alice] Encrypted file saved to: {encrypted_file_out} (IV prepended)")
    except FileNotFoundError:
         print(f"[Error] Plaintext file not found: {plaintext_file}")
         return None # Indicate failure

    # 3. Encrypt the AES key using Bob's RSA Public Key
    print("[Alice] Encrypting AES key with Bob's public key...")
    try:
        with open(public_key_file, "rb") as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())

        encrypted_aes_key = public_key.encrypt(
            aes_key,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        with open(encrypted_key_out, "wb") as f:
            f.write(encrypted_aes_key)
        print(f"[Alice] Encrypted AES key saved to: {encrypted_key_out}")
        return aes_key # Return original key
    except FileNotFoundError:
        print(f"[Error] Bob's public key file not found: {public_key_file}")
        return None
    except Exception as e:
        print(f"[Error] Failed to encrypt AES key: {e}")
        return None


def decrypt_file_hybrid(encrypted_file_in, encrypted_key_in, private_key_file, decrypted_file_out):
    """
    Decrypts the AES key using RSA private key, then decrypts the file using AES-CBC.
    Handles reading the IV from the start of the encrypted file.
    """
    # 1. Decrypt the AES key using Bob's RSA Private Key
    print("[Bob] Decrypting AES key...")
    try:
        with open(private_key_file, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None # Add password handling if key is encrypted
            )
        with open(encrypted_key_in, "rb") as f:
            encrypted_aes_key = f.read()

        decrypted_aes_key = private_key.decrypt(
            encrypted_aes_key,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("[Bob] AES key decrypted successfully.")
    except FileNotFoundError as e:
        print(f"[Error] Required file not found: {e.filename}")
        return None # Indicate failure
    except Exception as e:
        print(f"[Error] Failed to decrypt AES key: {e}")
        return None

    # 2. Decrypt the file using the recovered AES key and IV
    print(f"[Bob] Decrypting {encrypted_file_in} using recovered AES key...")
    try:
        with open(encrypted_file_in, "rb") as infile, open(decrypted_file_out, "wb") as outfile:
            iv_from_file = infile.read(AES_BLOCK_SIZE_BYTES) # Read the prepended IV
            if len(iv_from_file) != AES_BLOCK_SIZE_BYTES:
                raise ValueError("Encrypted file is too short or IV is missing.")

            cipher = Cipher(algorithms.AES(decrypted_aes_key), modes.CBC(iv_from_file))
            decryptor = cipher.decryptor()
            pkcs7_unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()

            # Process in chunks, handling final block for unpadding
            buffered_chunk = b""
            while True:
                chunk = infile.read(4096)
                if not chunk:
                     # Decrypt and unpad the last buffered chunk
                    decrypted_padded = decryptor.update(buffered_chunk) + decryptor.finalize()
                    unpadded_data = pkcs7_unpadder.update(decrypted_padded) + pkcs7_unpadder.finalize()
                    outfile.write(unpadded_data)
                    break
                # Decrypt previous chunk, buffer current one
                if buffered_chunk:
                    decrypted_data = decryptor.update(buffered_chunk)
                    outfile.write(unpadder.update(decrypted_data)) # Unpad non-final blocks
                buffered_chunk = chunk # Buffer the last read chunk

        print(f"[Bob] Decrypted file saved to: {decrypted_file_out}")
        return decrypted_aes_key # Return key for demo verification
    except FileNotFoundError:
         print(f"[Error] Encrypted file not found: {encrypted_file_in}")
         return None
    except ValueError as e: # Catch padding errors etc.
        print(f"[Error] Decryption failed (likely wrong key, IV, or corrupted data): {e}")
        # Create an empty/error output file
        with open(decrypted_file_out, 'w') as f: f.write("DECRYPTION FAILED")
        return None
    except Exception as e:
        print(f"[Error] An unexpected error occurred during file decryption: {e}")
        return None


if __name__ == "__main__":
    print("--- Task 2: Secure File Exchange Simulation ---")

    # Ensure crypto library is available
    try:
        from cryptography.hazmat.primitives import ciphers
    except ImportError:
        print("Error: 'cryptography' library not found. Please install it: pip install cryptography")
        exit(1)

    # --- Setup ---
    # Generate/Save Bob's Keys
    generate_and_save_rsa_keys(BOB_PRIVATE_KEY_FILE, BOB_PUBLIC_KEY_FILE)

    # Alice creates message
    alice_content = f"This file contains sensitive data for Bob.\nTimestamp: {os.urandom(8).hex()}\nEnd of message."
    create_alice_message(ALICE_MESSAGE_FILE, alice_content)

    # Alice calculates original hash
    print("[Alice] Calculating SHA-256 hash of original message...")
    original_hash = calculate_sha256(ALICE_MESSAGE_FILE)
    if original_hash:
        print(f"[Alice] Original SHA-256: {original_hash}")

    # --- Alice Encrypts ---
    # Alice uses Bob's public key file
    aes_key_used_by_alice = encrypt_file_hybrid(
        ALICE_MESSAGE_FILE,
        BOB_PUBLIC_KEY_FILE,
        ENCRYPTED_FILE,
        ENCRYPTED_AES_KEY_FILE
    )

    print("\n--- Files transmitted from Alice to Bob ---\n")
    # (ENCRYPTED_FILE and ENCRYPTED_AES_KEY_FILE are now available for Bob)

    # --- Bob Decrypts ---
    # Bob uses his private key file
    aes_key_recovered_by_bob = decrypt_file_hybrid(
        ENCRYPTED_FILE,
        ENCRYPTED_AES_KEY_FILE,
        BOB_PRIVATE_KEY_FILE,
        DECRYPTED_MESSAGE_FILE
    )

    # --- Verification ---
    print("\n--- Verification ---")
    if aes_key_used_by_alice and aes_key_recovered_by_bob:
        if aes_key_used_by_alice == aes_key_recovered_by_bob:
             print("[OK] Recovered AES key matches the one Alice used.")
        else:
             print("[FAIL] Recovered AES key DOES NOT MATCH the one Alice used!")
    elif not aes_key_recovered_by_bob:
        print("[FAIL] Bob failed to recover the AES key.")

    # Integrity Check using Hashing
    if os.path.exists(DECRYPTED_MESSAGE_FILE) and aes_key_recovered_by_bob: # Only hash if decryption likely succeeded
        print("[Bob] Calculating SHA-256 hash of decrypted message...")
        decrypted_hash = calculate_sha256(DECRYPTED_MESSAGE_FILE)
        if decrypted_hash:
            print(f"[Bob] Decrypted SHA-256: {decrypted_hash}")
            if original_hash and decrypted_hash == original_hash:
                print("[OK] Integrity Check PASSED: Hashes match.")
                # Verify content as well for demo
                with open(ALICE_MESSAGE_FILE, 'r') as f_orig, open(DECRYPTED_MESSAGE_FILE, 'r') as f_dec:
                    orig_content = f_orig.read()
                    dec_content = f_dec.read()
                    if orig_content == dec_content:
                        print("[OK] Decrypted content matches original content.")
                    else:
                        print("[FAIL] Content MISMATCH despite matching hashes (investigate).")

            elif original_hash:
                print("[FAIL] Integrity Check FAILED: Hashes DO NOT match.")
            else:
                 print("[WARN] Could not compare hashes as original hash was not computed.")
        else:
            print("[FAIL] Could not calculate hash of decrypted file.")
    else:
        print("[INFO] Skipping hash comparison as decryption did not complete successfully.")


    print("\n--- Task 2 Complete ---")
    print(f"Generated/Used files: {ALICE_MESSAGE_FILE}, {ENCRYPTED_FILE}, {ENCRYPTED_AES_KEY_FILE}, {DECRYPTED_MESSAGE_FILE}, {BOB_PUBLIC_KEY_FILE}, {BOB_PRIVATE_KEY_FILE}")