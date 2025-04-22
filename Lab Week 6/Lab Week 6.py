from binascii import unhexlify, hexlify
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE = 16 # AES block size is 16 bytes
KEY = b"this_is_16_bytes" # The key the oracle uses (we don't use it directly in the attack)

# Ciphertext = IV + encrypted blocks (from check_decrypt.py success)
CIPHERTEXT_HEX = (
    "746869735f69735f31365f6279746573"  # IV = b'this_is_16_bytes'
    "9404628dcdf3f003482b3b0648bd920b"  # Block 1
    "3f60e13e89fa6950d3340adbbbb41c12"  # Block 2
    "b3d1d97ef97860e9df7ec0d31d13839a"  # Block 3
    "e17b3be8f69921a07627021af16430e1"  # Block 4 (contains padding info)
)

def padding_oracle(ciphertext: bytes) -> bool:
    """Returns True if the ciphertext decrypts with valid padding, False
    otherwise."""
    if len(ciphertext) % BLOCK_SIZE != 0:
        return False
        
    try:
        iv = ciphertext[:BLOCK_SIZE]
        ct = ciphertext[BLOCK_SIZE:]
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ct) + decryptor.finalize()

        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        unpadder.update(decrypted)
        unpadder.finalize()
        return True
    except (ValueError, TypeError):
        return False

# Task 2: Implement Block Splitting
def split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> list[bytes]:
    """Split data into blocks of the specified size."""
    if len(data) % block_size != 0:
        raise ValueError("Data length must be a multiple of block size")
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]

# Task 3: Implement Single Block Decryption
def decrypt_block(prev_block: bytes, target_block: bytes) -> bytes:
    """
    Decrypt a single block using the padding oracle attack.
    Returns the decrypted plaintext block
    """
    if len(prev_block) != BLOCK_SIZE or len(target_block) != BLOCK_SIZE:
        raise ValueError("Blocks must be of BLOCK_SIZE")

    # Intermediate value I_i = D(K, C_i). We want to find this first.
    intermediate_bytes = bytearray(BLOCK_SIZE)
    # The final decrypted bytes for this block P_i
    decrypted_bytes = bytearray(BLOCK_SIZE)

    # We modify the previous block (or IV) to send to the oracle
    manipulated_prev = bytearray(BLOCK_SIZE) # Start with zeros or any placeholder

    # Attack byte by byte, from last to first
    for byte_index in range(BLOCK_SIZE - 1, -1, -1):
        padding_val = BLOCK_SIZE - byte_index # e.g., 1 for last byte, 2 for second last...

        # Set the suffix of the manipulated block to force correct padding bytes
        # C'_ {i-1}[j] = I_i[j] XOR padding_val
        for k in range(byte_index + 1, BLOCK_SIZE):
            manipulated_prev[k] = intermediate_bytes[k] ^ padding_val

        found_byte = False
        # Guess the value for the current byte index
        for guess in range(256):
            manipulated_prev[byte_index] = guess

            # Construct the ciphertext to send to the oracle:
            # C' = Manipulated_Prev_Block || Target_Block
            # The oracle treats Manipulated_Prev_Block as the IV
            # and Target_Block as the first ciphertext block.
            test_ciphertext = bytes(manipulated_prev) + target_block

            if padding_oracle(test_ciphertext):
                # Oracle returned True! Padding is valid (ends in padding_val).
                # This means: D(K, Target_Block)[byte_index] XOR guess == padding_val
                # So, Intermediate_Byte = D(K, Target_Block)[byte_index] = guess XOR padding_val
                intermediate_byte = guess ^ padding_val
                intermediate_bytes[byte_index] = intermediate_byte

                # Now find the original plaintext byte P_i[byte_index]
                # P_i[byte_index] = I_i[byte_index] XOR C_{i-1}[byte_index]
                decrypted_byte = intermediate_byte ^ prev_block[byte_index]
                decrypted_bytes[byte_index] = decrypted_byte

                # Debug print (optional)
                # print(f"  [+] Byte {byte_index} found: intermediate=0x{intermediate_byte:02x}, plaintext=0x{decrypted_byte:02x}")

                found_byte = True
                break # Move to the next byte index

        if not found_byte:
            # This should not happen with a correct oracle and ciphertext
            raise RuntimeError(f"Could not find valid byte for index {byte_index}")

    return bytes(decrypted_bytes)

# Task 4: Implement Full Attack
def padding_oracle_attack(ciphertext: bytes) -> bytes:
    """Perform the padding oracle attack on the entire ciphertext."""
    if len(ciphertext) % BLOCK_SIZE != 0 or len(ciphertext) < BLOCK_SIZE * 2:
         raise ValueError("Ciphertext length invalid")

    blocks = split_blocks(ciphertext)
    iv = blocks[0]
    ciphertext_blocks = blocks[1:] # C_1, C_2, ..., C_n

    recovered_plaintext = b""
    prev_block = iv # For the first block C_1, the previous block is IV

    print(f"[*] Starting attack on {len(ciphertext_blocks)} blocks...")

    for i, target_block in enumerate(ciphertext_blocks):
        print(f"[*] Decrypting Block {i+1}/{len(ciphertext_blocks)}...")
        # Decrypt P_i using C_{i-1} and C_i
        decrypted_block_p = decrypt_block(prev_block, target_block)
        recovered_plaintext += decrypted_block_p
        # Update previous block for the next iteration
        prev_block = target_block # C_i becomes C_{i-1} for the next round
        print(f"[*] Block {i+1} decrypted: {decrypted_block_p.hex()}")

    return recovered_plaintext

# Task 5: Implement Plaintext Decoding
def unpad_and_decode(plaintext: bytes) -> str:
    """Attempt to unpad and decode the plaintext."""
    try:
        # Use the standard PKCS7 unpadder
        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        unpadded_data = unpadder.update(plaintext) + unpadder.finalize()

        # Try decoding as UTF-8
        decoded_string = unpadded_data.decode('utf-8')
        return decoded_string
    except ValueError as e:
        # This catches errors from finalize() if padding is invalid
        return f"Error during unpadding: {e}. Raw bytes: {plaintext.hex()}"
    except UnicodeDecodeError as e:
        # This catches errors if the unpadded data is not valid UTF-8
        return f"Error during decoding: {e}. Unpadded bytes: {unpadded_data.hex()}"
    except Exception as e:
        # Catch any other unexpected errors
        return f"An unexpected error occurred: {e}"


# Main Execution
if __name__ == "__main__":
    try:
        ciphertext = unhexlify(CIPHERTEXT_HEX)
        print(f"[*] Ciphertext length: {len(ciphertext)} bytes ({len(ciphertext)//BLOCK_SIZE} blocks)")
        print(f"[*] IV: {ciphertext[:BLOCK_SIZE].hex()}")

        recovered = padding_oracle_attack(ciphertext)

        print("\n[+] Decryption complete!")
        print(f" Recovered plaintext (raw bytes): {recovered}")
        print(f" Hex: {recovered.hex()}")

        decoded = unpad_and_decode(recovered)

        print("\n[+] Final plaintext:")
        print(decoded)

    except Exception as e:
        print(f"\n[!] Error occurred: {e}")