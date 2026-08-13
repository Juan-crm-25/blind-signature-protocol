from cryptography.hazmat.primitives import serialization, hashes


def compute_file_hash(filepath) -> int:
    digest = hashes.Hash(hashes.SHA256())
    with open(filepath, "rb") as f:
        while chunk := f.read(4096):
            digest.update(chunk)
    hash_bytes = digest.finalize()
    return int.from_bytes(hash_bytes, byteorder='big')

def load_public_key(pub_key_path) -> tuple[int, int]:
    with open(pub_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    pub_numbers = public_key.public_numbers()
    return pub_numbers.n, pub_numbers.e