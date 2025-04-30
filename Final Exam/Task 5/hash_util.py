# hash_util.py
import hashlib
import json
import os
import sys

# --- Configuration ---
HASH_ALGORITHMS = ['sha256', 'sha1', 'md5'] # Include required algorithms
HASH_FILENAME = 'hashes.json' # File to store the known hashes

def compute_hashes(filepath):
    """
    Computes SHA-256, SHA-1, and MD5 hashes for the specified file.

    Args:
        filepath (str): The path to the file to hash.

    Returns:
        dict: A dictionary mapping algorithm name to its hex digest,
              or None if the file cannot be read.
    """
    hashes = {algo: hashlib.new(algo) for algo in HASH_ALGORITHMS}
    try:
        with open(filepath, 'rb') as f:
            while True:
                # Read file in chunks to handle large files efficiently
                chunk = f.read(4096)
                if not chunk:
                    break
                # Update all hash objects
                for algo in HASH_ALGORITHMS:
                    hashes[algo].update(chunk)
        # Return dictionary of hex digests
        return {algo: hashes[algo].hexdigest() for algo in HASH_ALGORITHMS}
    except FileNotFoundError:
        print(f"[Error] File not found: {filepath}", file=sys.stderr)
        return None
    except IOError as e:
        print(f"[Error] Could not read file {filepath}: {e}", file=sys.stderr)
        return None
    except Exception as e:
         print(f"[Error] An unexpected error occurred during hashing: {e}", file=sys.stderr)
         return None

def load_stored_hashes(hash_file=HASH_FILENAME):
    """Loads the hash database from the JSON file."""
    if os.path.exists(hash_file):
        try:
            with open(hash_file, 'r') as f:
                # Handle empty file case
                content = f.read()
                if not content:
                    return {}
                return json.loads(content)
        except json.JSONDecodeError:
            print(f"[Warning] Could not decode JSON from {hash_file}. Starting fresh.", file=sys.stderr)
            return {} # Treat as empty if corrupt
        except Exception as e:
            print(f"[Error] Could not load hash file {hash_file}: {e}", file=sys.stderr)
            return {} # Treat as empty on other errors
    return {} # Return empty dict if file doesn't exist

def save_hashes(hashes_to_store, hash_file=HASH_FILENAME):
    """Saves the hash database to the JSON file."""
    try:
        with open(hash_file, 'w') as f:
            json.dump(hashes_to_store, f, indent=4)
    except IOError as e:
        print(f"[Error] Could not write to hash file {hash_file}: {e}", file=sys.stderr)
    except Exception as e:
         print(f"[Error] An unexpected error occurred during saving hashes: {e}", file=sys.stderr)

def check_integrity(filepath, hash_file=HASH_FILENAME):
    """
    Checks the integrity of the file against stored hashes in the JSON file.
    If no stored hash exists, it computes and stores the current hash.

    Args:
        filepath (str): The path to the file to check.
        hash_file (str): The path to the JSON file storing hashes.

    Returns:
        bool: True if integrity check passes or hash is newly stored,
              False if integrity check fails.
    """
    print(f"\n--- Checking integrity for: {filepath} ---")
    filename_key = os.path.basename(filepath) # Use filename as key in JSON

    # 1. Compute current hashes
    current_hashes = compute_hashes(filepath)
    if current_hashes is None:
        print("[FAIL] Could not compute current hashes. Aborting check.")
        return False

    print("Computed Hashes:")
    for algo, h in current_hashes.items():
        print(f"  {algo.upper()}: {h}")

    # 2. Load stored hashes
    stored_hashes_db = load_stored_hashes(hash_file)
    stored_hashes_for_file = stored_hashes_db.get(filename_key)

    # 3. Compare or Store
    if stored_hashes_for_file is None:
        print(f"[INFO] No previous hashes found for '{filename_key}' in {hash_file}.")
        print("[INFO] Storing current hashes as baseline.")
        stored_hashes_db[filename_key] = current_hashes
        save_hashes(stored_hashes_db, hash_file)
        return True # Consider first run a "pass"
    else:
        print("Comparing against stored hashes...")
        mismatch_found = False
        for algo in HASH_ALGORITHMS:
            current_h = current_hashes.get(algo)
            stored_h = stored_hashes_for_file.get(algo)

            if current_h == stored_h:
                print(f"  [OK] {algo.upper()} hash matches.")
            else:
                print(f"  [FAIL] {algo.upper()} HASH MISMATCH!")
                print(f"      Stored:   {stored_h}")
                print(f"      Computed: {current_h}")
                mismatch_found = True

        if not mismatch_found:
            print("\n[PASS] Integrity check successful. All hashes match the stored baseline.")
            return True
        else:
            print("\n[FAIL] Integrity check FAILED. File content may have changed.")
            return False

if __name__ == "__main__":
    # Check for command-line argument (the file to check)
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <path_to_file>")
        sys.exit(1) # Exit with error code

    file_to_check = sys.argv[1]

    # Run the integrity check
    success = check_integrity(file_to_check, HASH_FILENAME)

    # Exit with appropriate status code
    sys.exit(0 if success else 1)