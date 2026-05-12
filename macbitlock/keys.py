"""BitLocker key derivation: password/recovery key stretching and VMK/FVEK unwrapping."""

import hashlib
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESCCM


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
    # cryptography library expects ciphertext + tag concatenated
    plaintext = aesccm.decrypt(nonce, ciphertext + tag, None)

    # Parse the key container and return the key data starting at offset 12
    return plaintext[12:]
