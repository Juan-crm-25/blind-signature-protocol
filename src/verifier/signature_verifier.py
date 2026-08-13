#!/usr/bin/env python3

import sys
from common.crypto_utils import compute_file_hash, load_public_key

# ----------------------------------------------------------------------
# AUX FUNCTIONS
# ----------------------------------------------------------------------


def parse_signature_file(signature_path) -> int:
    with open(signature_path, "r") as f:
        hex_string = f.read().strip()
    
    # format: '3C:7B:AC:67:...'
    hex_bytes = hex_string.replace(":", "").replace(" ", "")
    
    signature_bytes = bytes.fromhex(hex_bytes)
    return int.from_bytes(signature_bytes, byteorder='big')

# ----------------------------------------------------------------------
# MAIN LOGIC
# ----------------------------------------------------------------------

def main():
    if len(sys.argv) != 4:
        print("Error. Usage: python3 signature_verifier.py <original_file> <signature.txt> <server_key.pub>", file=sys.stderr)
        sys.exit(1)

    file_path = sys.argv[1]
    signature_path = sys.argv[2]
    pub_key_path = sys.argv[3]

    try:
        m = compute_file_hash(file_path)

        n, e = load_public_key(pub_key_path)

        s = parse_signature_file(signature_path)

        if not (0 < s < n):
            print("Error: Signature value out of valid range.", file=sys.stderr)
            print("INVALID SIGNATURE")
            sys.exit(1)

        # RSA Math verification: m_recuperado = s^e mod n
        m_recovered = pow(s, e, n)

        if m == m_recovered:
            print("SIGNATURE VALIDATED SUCCESSFULLY")
            sys.exit(0)
        else:
            print("INVALID SIGNATURE")
            sys.exit(1)

    except FileNotFoundError as e:
        print(f"Error: File not found ({e})", file=sys.stderr)
        print("INVALID SIGNATURE")
        sys.exit(1)
    except ValueError as e:
        print(f"Error parsing signature ({e})", file=sys.stderr)
        print("INVALID SIGNATURE")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error checking signature: {e}", file=sys.stderr)
        print("INVALID SIGNATURE")
        sys.exit(1)

if __name__ == "__main__":
    main()