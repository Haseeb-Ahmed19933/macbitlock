"""BitLocker key derivation, generation, wrapping, and unwrapping."""

import hashlib
import os
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from .constants import EncryptionMethod


def _stretch_key(initial_sha256: bytes, salt: bytes) -> bytes:
    """Run the BitLocker SHA-256 key stretching algorithm (1,048,576 iterations).

    Args:
        initial_sha256: 32-byte SHA-256 hash to stretch.
        salt: 16-byte salt from the VMK's stretch key metadata.

    Returns:
        32-byte stretched key.
    """
    # 88-byte structure: last_sha256 (32) | initial_sha256 (32) | salt (16) | count (8)
    buf = bytearray(88)
    buf[32:64] = initial_sha256
    buf[64:80] = salt

    for i in range(0x100000):
        struct.pack_into("<Q", buf, 80, i)
        digest = hashlib.sha256(buf).digest()
        buf[0:32] = digest

    return bytes(buf[0:32])


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """Derive 256-bit key from user password using SHA-256 stretch.

    Args:
        password: The user's BitLocker password.
        salt: 16-byte salt from the stretch key metadata.

    Returns:
        32-byte stretched key suitable for unwrapping the VMK.
    """
    password_bytes = password.encode("utf-16-le")
    sha1 = hashlib.sha256(password_bytes).digest()
    initial_sha256 = hashlib.sha256(sha1).digest()
    return _stretch_key(initial_sha256, salt)


def derive_key_from_recovery(recovery_password: str, salt: bytes) -> bytes:
    """Derive 256-bit key from recovery password using SHA-256 stretch.

    The recovery password format is:
    "XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX"
    where each group is a decimal number divisible by 11.

    Args:
        recovery_password: The 48-digit recovery password with dashes.
        salt: 16-byte salt from the stretch key metadata.

    Returns:
        32-byte stretched key suitable for unwrapping the VMK.
    """
    groups = recovery_password.strip().split("-")
    if len(groups) != 8:
        raise ValueError(
            f"Recovery password must have 8 groups separated by '-', got {len(groups)}"
        )

    key_parts = []
    for i, group in enumerate(groups):
        value = int(group)
        if value % 11 != 0:
            raise ValueError(f"Group {i} ({value}) is not divisible by 11")
        short_val = value // 11
        if short_val > 0xFFFF:
            raise ValueError(f"Group {i} value {short_val} exceeds 16-bit range")
        key_parts.append(struct.pack("<H", short_val))

    recovery_key = b"".join(key_parts)  # 16 bytes
    initial_sha256 = hashlib.sha256(recovery_key).digest()
    return _stretch_key(initial_sha256, salt)


def unwrap_key(encrypted_data: bytes, key: bytes, nonce: bytes) -> bytes:
    """Decrypt an AES-CCM wrapped key and return the raw key bytes.

    The encrypted data layout:
        - First 16 bytes: MAC/authentication tag
        - Remaining bytes: ciphertext

    The decrypted payload is a key container:
        - Offset 0: Size (4 bytes, uint32 LE)
        - Offset 4: Version (2 bytes)
        - Offset 6: Unknown (2 bytes)
        - Offset 8: Encryption method (4 bytes)
        - Offset 12: Key data (remaining)

    Args:
        encrypted_data: The AES-CCM encrypted blob (tag + ciphertext).
        key: 32-byte decryption key (stretched key for VMK, VMK for FVEK).
        nonce: 12-byte nonce (nonce_time[8] + nonce_counter[4]).

    Returns:
        The raw key bytes extracted from the decrypted container.
    """
    tag = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    aesccm = AESCCM(key, tag_length=16)
    try:
        plaintext = aesccm.decrypt(nonce, ciphertext + tag, None)
    except InvalidTag:
        raise ValueError(
            "Incorrect password or recovery key. The provided credentials do not "
            "match this volume. Please double-check your password (passwords are "
            "case-sensitive) or try using a recovery key instead."
        )

    # Parse the key container and return the key data starting at offset 12
    return plaintext[12:]


# --- Key generation and wrapping (for encryption) ---


def generate_vmk() -> bytes:
    """Generate a random 32-byte (256-bit) Volume Master Key."""
    return os.urandom(32)


def generate_fvek(encryption_method: int) -> bytes:
    """Generate a random Full Volume Encryption Key for the given encryption method.

    Returns the raw key bytes to be stored in the FVEK container.
    """
    if encryption_method == EncryptionMethod.AES_XTS_128:
        return os.urandom(32)  # XTS uses two 128-bit keys
    elif encryption_method == EncryptionMethod.AES_XTS_256:
        return os.urandom(64)  # XTS uses two 256-bit keys
    elif encryption_method == EncryptionMethod.AES_CBC_128:
        return os.urandom(16)
    elif encryption_method == EncryptionMethod.AES_CBC_256:
        return os.urandom(32)
    else:
        raise ValueError(f"Unsupported encryption method for key generation: 0x{encryption_method:04x}")


def recovery_password_to_short_key(recovery_password: str) -> bytes:
    """Convert a 48-digit recovery password to its 16-byte short key representation.

    This is the intermediate key value BEFORE SHA-256 and stretching.
    Windows stores this encrypted inside the recovery VMK's STRETCH_KEY
    for validation purposes.
    """
    groups = recovery_password.strip().split("-")
    if len(groups) != 8:
        raise ValueError(f"Recovery password must have 8 groups, got {len(groups)}")
    key_parts = []
    for group in groups:
        value = int(group)
        short_val = value // 11
        key_parts.append(struct.pack("<H", short_val))
    return b"".join(key_parts)


def generate_recovery_key() -> str:
    """Generate a valid 48-digit BitLocker recovery key.

    Format: 8 groups of 6 digits separated by dashes.
    Each group is a decimal number divisible by 11.
    The value divided by 11 must fit in a uint16 (0-65535).
    """
    groups = []
    for _ in range(8):
        short_val = struct.unpack("<H", os.urandom(2))[0]
        groups.append(f"{short_val * 11:06d}")
    return "-".join(groups)


def wrap_key(
    key_data: bytes,
    wrapping_key: bytes,
    nonce: bytes,
    encryption_method: int,
) -> bytes:
    """Encrypt a key using AES-CCM and return the encrypted blob.

    Builds the key container (12-byte header + key_data), encrypts with AES-CCM,
    and returns the result in BitLocker's on-disk format (tag + ciphertext).

    Args:
        key_data: The raw key bytes to wrap (VMK or FVEK).
        wrapping_key: 32-byte AES-CCM key (stretched key for VMK, VMK for FVEK).
        nonce: 12-byte nonce (nonce_time[8] + nonce_counter[4]).
        encryption_method: The encryption method identifier for the container header.

    Returns:
        Encrypted blob in on-disk format: MAC tag (16 bytes) + ciphertext.
    """
    container_size = 12 + len(key_data)
    container = struct.pack("<IHhI", container_size, 1, 0, encryption_method) + key_data

    aesccm = AESCCM(wrapping_key, tag_length=16)
    ct_and_tag = aesccm.encrypt(nonce, container, None)

    # AES-CCM returns ciphertext + tag; BitLocker stores tag + ciphertext
    ciphertext = ct_and_tag[:-16]
    tag = ct_and_tag[-16:]
    return tag + ciphertext
