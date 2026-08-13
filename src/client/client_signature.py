#!/usr/bin/env python3

from pathlib import Path
import sys
import socket
import math
import secrets

# Add the parent directory (src) to sys.path for common folder
sys.path.append(str(Path(__file__).resolve().parent.parent))
from common.crypto_utils import compute_file_hash, load_public_key


HOST = '127.0.0.1'
PORT = 65432


# ----------------------------------------------------------------------
# FILE HASHING & KEY LOADING
# ----------------------------------------------------------------------

def generate_blinding_factor(n) -> int:
    # Generates a random secret blinding factor (k) coprime to n
    while True:
        r = secrets.randbelow(n - 2) + 2    # more reliable than random
        if math.gcd(r, n) == 1:
            return r


# ----------------------------------------------------------------------
# CLIENT MAIN LOGIC
# ----------------------------------------------------------------------

def main():
    if len(sys.argv) != 3:
        print("Error. Usage: python3 client_signature.py <original_file> <server_key.pub>", file=sys.stderr)
        sys.exit(1)

    file_path = sys.argv[1]
    pub_key_path = sys.argv[2]

    try:
        print(f"Hashing file '{file_path}'...", file=sys.stderr)
        m = compute_file_hash(file_path)

        print(f"Loading public key from '{pub_key_path}'...", file=sys.stderr)
        n, e = load_public_key(pub_key_path)

        # Hash integer m must be smaller than RSA modulus n
        if m >= n:
            print("Error: Message hash is larger than RSA modulus n.", file=sys.stderr)
            sys.exit(1)

        print("Generating blinding factor (k)...", file=sys.stderr)
        k = generate_blinding_factor(n)

        # Compute blinded message m' = (m * r^e) mod n
        print("Blinding hash (m')...", file=sys.stderr)
        m_prime = (m * pow(k, e, n)) % n

        print(f"Connecting to server at {HOST}:{PORT}...", file=sys.stderr)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.settimeout(10)
            client_socket.connect((HOST, PORT))

            # Send m' as ASCII text
            client_socket.sendall(str(m_prime).encode('utf-8'))
            
            # Signal EOF to server so it knows we finished sending
            client_socket.shutdown(socket.SHUT_WR)

            # Receive blinded signature s'
            chunks = []
            while True:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            
        raw_response = b"".join(chunks).decode('utf-8').strip()
        if not raw_response:
            print("Error: Server returned empty response.", file=sys.stderr)
            sys.exit(1)

        s_prime = int(raw_response)
        print("Received blinded signature (s') from server.", file=sys.stderr)

        # Unblind the signature using formula: s = (s' * k^-1) mod n
        print("Unblinding signature (s)...", file=sys.stderr)
        k_inv = pow(k, -1, n)
        s = (s_prime * k_inv) % n

        # Format as hex string "3C:7B:AC:67"
        byte_length = (n.bit_length() + 7) // 8     # rounds up for padding
        signature_bytes = s.to_bytes(byte_length, byteorder='big')
        
        formatted_signature = ":".join(f"{b:02X}" for b in signature_bytes)

        # Standard output
        print(formatted_signature, file=sys.stdout)

    except FileNotFoundError as e:
        print(f"Error: File not found: {e}", file=sys.stderr)
        sys.exit(1)
    except ConnectionRefusedError:
        print(f"Error: Could not connect to server at {HOST}:{PORT}. server_signature.py needs to be running first.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected client error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()