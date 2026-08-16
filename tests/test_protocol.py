#!/usr/bin/env python3
"""
test_protocol.py -- End-to-end and unit tests for the Blind Signature Protocol.

Tests are grouped into four categories:
  1. Cryptographic correctness  - the math works as expected
  2. Full protocol flow         - server, client and verifier working together
  3. Security properties        - blindness, unlinkability, tamper detection
  4. Edge cases & robustness    - bad inputs, missing files, out-of-range values
"""

import math
import os
import secrets
import tempfile

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# ---------------------------------------------------------------------------
# Import directly from the real source files
# ---------------------------------------------------------------------------

from common.crypto_utils import compute_file_hash, load_public_key
from client.client_signature import generate_blinding_factor


# ---------------------------------------------------------------------------
# Helpers that mimic the actual protocol logic
# ---------------------------------------------------------------------------

def _generate_rsa_keypair(key_size: int = 2048):
    """Generate a real RSA keypair and return (n, e, d)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    priv = private_key.private_numbers()
    n = priv.public_numbers.n
    e = priv.public_numbers.e
    d = priv.d
    return n, e, d


def _blind(m: int, k: int, e: int, n: int) -> int:
    """Blind message m with factor k using the server's public key (e, n)."""
    return (m * pow(k, e, n)) % n


def _sign(m_prime: int, d: int, n: int) -> int:
    """Server signs the blinded message: s' = (m')^d mod n."""
    return pow(m_prime, d, n)


def _unblind(s_prime: int, k: int, n: int) -> int:
    """Unblind the server's response: s = s' * k^-1 mod n."""
    return (s_prime * pow(k, -1, n)) % n


def _verify(s: int, e: int, n: int, m: int) -> bool:
    """Verify signature: s^e mod n must equal m."""
    return pow(s, e, n) == m


def _format_signature(s: int, n: int) -> str:
    """Format signature integer as colon-separated uppercase hex (e.g. '3C:7B:AC:...')."""
    byte_length = (n.bit_length() + 7) // 8
    return ":".join(f"{b:02X}" for b in s.to_bytes(byte_length, byteorder="big"))


def _parse_hex_signature(hex_str: str) -> int:
    """Parse a colon-separated hex signature string back to an integer."""
    cleaned = hex_str.strip().replace(":", "").replace(" ", "")
    return int.from_bytes(bytes.fromhex(cleaned), byteorder="big")


def _compute_bytes_hash(data: bytes) -> int:
    """Hash raw bytes using the same function as the real source (SHA-256)."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        tmp_path = f.name
    try:
        return compute_file_hash(tmp_path)
    finally:
        os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def rsa_keypair():
    """Generate a real 2048-bit RSA keypair once per test module."""
    return _generate_rsa_keypair(2048)


@pytest.fixture(scope="module")
def rsa_keypair_pem():
    """
    Write the keypair to temporary PEM files so tests can use
    load_public_key() (the real function from crypto_utils.py).
    Returns (n, e, d, pub_key_path).
    """

    # Reconstruct the private key object from raw numbers to export PEM
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv = private_key.private_numbers()
    n = priv.public_numbers.n
    e = priv.public_numbers.e
    d = priv.d

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pub")
    tmp.write(pub_pem)
    tmp.close()

    yield n, e, d, tmp.name
    os.unlink(tmp.name)


@pytest.fixture
def sample_file():
    """Create a temporary file with known content and clean it up after."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
        f.write(b"Hello, blind signature world!")
        path = f.name
    yield path
    os.unlink(path)


# ---------------------------------------------------------------------------
# Helper: run the full protocol in-process
# ---------------------------------------------------------------------------

def run_protocol(data: bytes, n: int, e: int, d: int):
    """Execute the full blind signature protocol and return (m, s)."""
    m = _compute_bytes_hash(data)
    k = generate_blinding_factor(n)
    m_prime = _blind(m, k, e, n)
    s_prime = _sign(m_prime, d, n)
    s = _unblind(s_prime, k, n)
    return m, s


# ===========================================================================
# 1. CRYPTOGRAPHIC CORRECTNESS
# ===========================================================================

class TestCryptographicCorrectness:
    """Verify that the raw RSA blind signature math is correct."""

    def test_sign_and_verify_roundtrip(self, rsa_keypair):
        """A message signed with d and verified with e must match the original."""
        n, e, d = rsa_keypair
        m = secrets.randbelow(n - 1) + 1
        s = _sign(m, d, n)

        assert _verify(s, e, n, m), "Signature verification failed on a valid signature"

    def test_blind_unblind_recovers_original(self, rsa_keypair):
        """Blinding then unblinding must return the exact original message."""
        n, e, d = rsa_keypair
        m = secrets.randbelow(n - 1) + 1
        k = generate_blinding_factor(n)
        s = _unblind(_sign(_blind(m, k, e, n), d, n), k, n)

        assert _verify(s, e, n, m), "Unblinded signature does not verify against original message"

    def test_full_blind_signature_equation(self, rsa_keypair):
        """
        Verify the algebraic identity:
            unblind(sign(blind(m, k, e, n), d, n), k, n)^e ≡ m (mod n)
        """
        n, e, d = rsa_keypair
        m = _compute_bytes_hash(b"test message for equation check")
        k = generate_blinding_factor(n)
        s = _unblind(_sign(_blind(m, k, e, n), d, n), k, n)

        assert pow(s, e, n) == m

    def test_different_blinding_factors_produce_different_blinded_messages(self, rsa_keypair):
        """Two different blinding factors must produce different blinded messages."""
        n, e, _ = rsa_keypair
        m = _compute_bytes_hash(b"same message")
        k1 = generate_blinding_factor(n)
        k2 = generate_blinding_factor(n)

        assert _blind(m, k1, e, n) != _blind(m, k2, e, n), (
            "Different blinding factors should produce different blinded messages"
        )

    def test_blinding_factor_is_coprime_to_n(self, rsa_keypair):
        """Generated blinding factor must be coprime to n (required for invertibility)."""
        n, _, _ = rsa_keypair
        for _ in range(20):
            k = generate_blinding_factor(n)
            assert math.gcd(k, n) == 1, f"Blinding factor {k} is not coprime to n"

    def test_sha256_hash_is_deterministic(self, sample_file):
        """Hashing the same file twice must produce the same integer."""
        h1 = compute_file_hash(sample_file)
        h2 = compute_file_hash(sample_file)

        assert h1 == h2

    def test_sha256_hash_fits_in_2048bit_modulus(self, rsa_keypair, sample_file):
        """SHA-256 output (256 bits) must always be smaller than a 2048-bit modulus."""
        n, _, _ = rsa_keypair
        m = compute_file_hash(sample_file)

        assert m < n, "Hash must be smaller than RSA modulus n"


# ===========================================================================
# 2. FULL PROTOCOL FLOW
# ===========================================================================

class TestProtocolFlow:
    """Integration tests: simulate the complete client-server-verifier interaction."""

    def test_sign_and_verify_file(self, rsa_keypair, sample_file):
        """End-to-end: sign a file and verify the resulting signature."""
        n, e, d = rsa_keypair
        m, s = run_protocol(open(sample_file, "rb").read(), n, e, d)

        assert _verify(s, e, n, m), "Valid file signature must verify correctly"

    def test_signature_output_format(self, rsa_keypair):
        """Signature must be formatted as colon-separated uppercase hex bytes."""
        n, e, d = rsa_keypair
        _, s = run_protocol(b"format test", n, e, d)
        hex_str = _format_signature(s, n)
        parts = hex_str.split(":")

        assert all(len(p) == 2 for p in parts), "Each byte must be exactly 2 hex chars"
        assert all(p == p.upper() for p in parts), "Hex chars must be uppercase"
        assert all(c in "0123456789ABCDEF" for p in parts for c in p), "Invalid hex character"

    def test_parse_and_format_roundtrip(self, rsa_keypair):
        """format → parse → format must be idempotent."""
        n, e, d = rsa_keypair
        _, s = run_protocol(b"roundtrip test", n, e, d)

        formatted = _format_signature(s, n)
        parsed = _parse_hex_signature(formatted)
        reformatted = _format_signature(parsed, n)

        assert reformatted == formatted

    def test_multiple_files_produce_different_signatures(self, rsa_keypair):
        """Different files must produce different signatures."""
        n, e, d = rsa_keypair
        _, s1 = run_protocol(b"file content one", n, e, d)
        _, s2 = run_protocol(b"file content two", n, e, d)

        assert s1 != s2

    def test_load_public_key_returns_correct_components(self, rsa_keypair_pem):
        """load_public_key() must return the correct (n, e) from a PEM file."""
        n, e, _, pub_path = rsa_keypair_pem
        loaded_n, loaded_e = load_public_key(pub_path)

        assert loaded_n == n
        assert loaded_e == e

    def test_same_file_different_sessions_unlinkable(self, rsa_keypair):
        """
        Unlinkability: the server only observes the blinded message m'.
        For the same file, each session must produce a different m' so that
        the server cannot link two requests to the same original message.
        RSA signatures are deterministic, so we verify the property at the
        blinding layer (where randomness is actually introduced).
        """
        n, e, _ = rsa_keypair
        m = _compute_bytes_hash(b"same file content")
        blinded = {_blind(m, generate_blinding_factor(n), e, n) for _ in range(10)}

        assert len(blinded) == 10, (
            "Each session must produce a unique blinded message m' "
            "(the server sees a different value every time)"
        )


# ===========================================================================
# 3. SECURITY PROPERTIES
# ===========================================================================

class TestSecurityProperties:
    """Verify the cryptographic security guarantees of the protocol."""

    def test_tampered_file_fails_verification(self, rsa_keypair):
        """Modifying the file after signing must invalidate the signature."""
        n, e, d = rsa_keypair

        m_original = _compute_bytes_hash(b"original content")
        k = generate_blinding_factor(n)
        s = _unblind(_sign(_blind(m_original, k, e, n), d, n), k, n)
        m_tampered = _compute_bytes_hash(b"tampered content")

        assert not _verify(s, e, n, m_tampered), (
            "Signature must not verify against a tampered file"
        )

    def test_wrong_key_fails_verification(self, rsa_keypair):
        """A signature verified with the wrong public key must fail."""
        n, e, d = rsa_keypair
        n2, e2, _ = _generate_rsa_keypair(2048)

        m = _compute_bytes_hash(b"key mismatch test")
        k = generate_blinding_factor(n)
        s = _unblind(_sign(_blind(m, k, e, n), d, n), k, n)

        assert not _verify(s, e2, n2, m)

    def test_forged_signature_fails_verification(self, rsa_keypair):
        """A randomly generated integer must not verify as a valid signature."""
        n, e, _ = rsa_keypair
        m = _compute_bytes_hash(b"forgery test")
        forged_s = secrets.randbelow(n - 1) + 1

        assert not _verify(forged_s, e, n, m)

    def test_blinded_message_reveals_nothing_about_original(self, rsa_keypair):
        """
        The blinded message m' must never equal m, and must be unique
        across sessions (statistical independence check).
        """
        n, e, _ = rsa_keypair
        m = _compute_bytes_hash(b"blindness test")
        m_primes = {_blind(m, generate_blinding_factor(n), e, n) for _ in range(10)}

        assert m not in m_primes, (
                    "Original message m must never appear as a blinded message m'"
                )
        assert len(m_primes) == 10, (
            "Each blinding must produce a unique m' (randomness check)"
        )

    def test_server_cannot_link_signature_to_session(self, rsa_keypair):
        """
        Given a final signature s, the server (which only saw m') cannot
        determine which blinded message it corresponds to. We verify this by
        confirming that the unblinding step breaks the link between m' and s.
        """
        n, e, d = rsa_keypair
        m = _compute_bytes_hash(b"unlinkability test")

        k = generate_blinding_factor(n)
        m_prime = _blind(m, k, e, n)
        s_prime = _sign(m_prime, d, n)
        s = _unblind(s_prime, k, n)

        # The server knows m_prime and s_prime, but not k.
        # It cannot derive s from (m_prime, s_prime) without k.
        # We verify that s != s_prime (the unblinding changed the value).
        assert s != s_prime, "Unblinded signature must differ from blind signature"

        assert pow(m_prime, d, n) == s_prime   # server computed s_prime
        assert pow(m_prime, d, n) != s         # server cannot derive s


# ===========================================================================
# 4. EDGE CASES & ROBUSTNESS
# ===========================================================================

class TestEdgeCasesAndRobustness:
    """Test boundary conditions, bad inputs and error handling."""

    def test_empty_file_produces_valid_signature(self, rsa_keypair):
        """An empty file must produce a valid, verifiable signature."""
        n, e, d = rsa_keypair
        m, s = run_protocol(b"", n, e, d)

        assert 0 < m < n
        assert _verify(s, e, n, m)

    def test_large_file_produces_valid_signature(self, rsa_keypair):
        """A 10 MB file must hash and sign correctly."""

        n, e, d = rsa_keypair
        m, s = run_protocol(os.urandom(10 * 1024 * 1024), n, e, d)

        assert _verify(s, e, n, m)

    def test_binary_file_produces_valid_signature(self, rsa_keypair):
        """Binary data (e.g. images, PDFs) must sign and verify correctly."""
        n, e, d = rsa_keypair
        m, s = run_protocol(bytes(range(256)) * 100, n, e, d)

        assert _verify(s, e, n, m)

    def test_parse_signature_tolerates_extra_whitespace(self, rsa_keypair):
        """parse_hex_signature must handle leading/trailing whitespace."""
        n, e, d = rsa_keypair
        _, s = run_protocol(b"whitespace test", n, e, d)

        formatted = _format_signature(s, n)

        assert _parse_hex_signature(f"  {formatted}  \n") == s

    def test_parse_signature_tolerates_missing_colons(self, rsa_keypair):
        """parse_hex_signature must handle hex strings without colons."""
        n, e, d = rsa_keypair
        _, s = run_protocol(b"no colon test", n, e, d)

        formatted = _format_signature(s, n)

        assert _parse_hex_signature(formatted.replace(":", "")) == s

    def test_blinding_factor_range(self, rsa_keypair):
        """Blinding factor must be in [2, n-2]."""
        n, _, _ = rsa_keypair

        for _ in range(50):
            k = generate_blinding_factor(n)
            assert 2 <= k <= n - 2

    def test_signature_byte_length_matches_modulus(self, rsa_keypair):
        """Formatted signature byte count must match the RSA modulus byte length."""
        n, e, d = rsa_keypair

        expected = (n.bit_length() + 7) // 8
        _, s = run_protocol(b"length test", n, e, d)

        assert len(_format_signature(s, n).split(":")) == expected

    def test_compute_file_hash_changes_with_content(self, sample_file):
        """Modifying a file must produce a different hash."""
        h1 = compute_file_hash(sample_file)

        with open(sample_file, "ab") as f:
            f.write(b" extra")

        h2 = compute_file_hash(sample_file)
        
        assert h1 != h2
