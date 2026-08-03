import os
from sys import stderr
import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_PATH = os.path.join(BASE_DIR, "server_key")
PUB_PATH = os.path.join(BASE_DIR, "server_key.pub")

HOST = '127.0.0.1'
PORT = 65432


# ----------------------------------------------------------------------
# RSA STANDAR KEYS MANAGEMENT (PEM FORMAT)
# ----------------------------------------------------------------------


def generate_and_save_keys():

    print("Generating 2048-bit RSA key...", file=stderr)
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # standard exponent
        key_size=2048
    )

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()   # for simplicity
    )

    with open(KEY_PATH, "wb") as f:
        f.write(pem_private)

    public_key = private_key.public_key()
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo  # standard format for public keys
    )

    with open(PUB_PATH, "wb") as f:
        f.write(pem_public)

    print("Keys saved successfully in 'server_key' and 'server_key.pub'.", file=stderr)


def load_private_key():

    with open(KEY_PATH, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None   # we used no password previously
        )

    return private_key



# ----------------------------------------------------------------------
# BLIND SIGNATURE SOCKET SERVER 
# ----------------------------------------------------------------------

def main():

    if not os.path.exists(KEY_PATH) or not os.path.exists(PUB_PATH):
        generate_and_save_keys()

    print("Loading RSA keys", file=stderr)

    private_key = load_private_key()

    private_numbers = private_key.private_numbers()
    n = private_numbers.public_numbers.n
    d = private_numbers.d

    # SOCKET INITIALIZATION

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)   # IPv4 TCP Socket
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)     # allows reuse of local port
    server_socket.bind((HOST, PORT))
    server_socket.listen()

    print(f"Server listening on {HOST}:{PORT}", file=stderr)

    try:
        while True:
            conn, addr = server_socket.accept()
            try:
                print(f"Connection accepted from {addr}", file=stderr)

                # Receive m' (sent as ASCII from the client)

                data = conn.recv(4096).decode('utf-8').strip()

                if data:
                    m_prime = int(data)

                    if not (0 < m_prime < n):
                        print("Invalid blinded message: out of range", file=stderr)
                    else:
                        print(f"Blinded hash received: {str(m_prime)[:30]}", file=stderr)

                        # Signature equation: s' = (m')^d mod n
                        s_prime = pow(m_prime, d, n)

                        conn.sendall(str(s_prime).encode('utf-8'))

            except (ValueError, ConnectionError) as e:
                print(f"Error handling connection: {e}", file=stderr)
            finally:
                conn.close()
                print("Connection closed with client.", file=stderr)

    except KeyboardInterrupt:
        print("Shutting down server...", file=stderr)

    finally:
        server_socket.close()


if __name__ == "__main__":
    main()