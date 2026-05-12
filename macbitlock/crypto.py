"""BitLocker sector-level decryption: AES-XTS, AES-CBC, and Elephant Diffuser."""

import array
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .constants import EncryptionMethod, SECTOR_SIZE


def decrypt_sector_xts(sector_data: bytes, sector_number: int, fvek: bytes) -> bytes:
    """Decrypt a sector using AES-XTS."""
    tweak = struct.pack("<QQ", sector_number, 0)
    cipher = Cipher(algorithms.AES(fvek), modes.XTS(tweak))
    decryptor = cipher.decryptor()
    return decryptor.update(sector_data) + decryptor.finalize()


def decrypt_sector_cbc(sector_data: bytes, sector_offset: int, fvek: bytes) -> bytes:
    """Decrypt a sector using AES-CBC. IV = AES-ECB(fvek, sector_offset as 16-byte LE)."""
    iv_plain = struct.pack("<QQ", sector_offset, 0)
    iv_cipher = Cipher(algorithms.AES(fvek), modes.ECB())
    iv_encryptor = iv_cipher.encryptor()
    iv = iv_encryptor.update(iv_plain) + iv_encryptor.finalize()

    cipher = Cipher(algorithms.AES(fvek), modes.CBC(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(sector_data) + decryptor.finalize()


# --- Elephant Diffuser (legacy, Windows Vista/7) ---

def _rotate_left(num: int, count: int) -> int:
    return ((num << count) | (num >> (32 - count))) & 0xFFFFFFFF


def _diffuser_a_decrypt(buf: array.array, int_size: int) -> None:
    """Elephant Diffuser A (decrypt direction): 5 cycles."""
    r_a = [9, 0, 13, 0]
    for _ in range(5):
        for i in range(int_size):
            buf[i] = (buf[i] + (buf[i - 2] ^ _rotate_left(buf[i - 5], r_a[i % 4]))) & 0xFFFFFFFF


def _diffuser_b_decrypt(buf: array.array, int_size: int) -> None:
    """Elephant Diffuser B (decrypt direction): 3 cycles."""
    r_b = [0, 10, 0, 25]
    for _ in range(3):
        for i in range(int_size):
            buf[i] = (
                buf[i] + (buf[(i + 2) % int_size] ^ _rotate_left(buf[(i + 5) % int_size], r_b[i % 4]))
            ) & 0xFFFFFFFF


def _compute_sector_key(sector_offset: int, tweak_key: bytes) -> bytes:
    """Compute the 32-byte sector key for Elephant Diffuser XOR step.

    Lower 16 bytes: AES-ECB(tweak_key, sector_offset as 16-byte LE)
    Upper 16 bytes: AES-ECB(tweak_key, sector_offset | 0x80 in MSB as 16-byte LE)
    """
    ecb = Cipher(algorithms.AES(tweak_key), modes.ECB()).encryptor()

    lower_plain = struct.pack("<QQ", sector_offset, 0)
    lower = ecb.update(lower_plain)

    ecb2 = Cipher(algorithms.AES(tweak_key), modes.ECB()).encryptor()
    upper_plain = struct.pack("<QQ", sector_offset, 0x80)
    upper = ecb2.update(upper_plain)

    return lower + upper


def decrypt_sector_cbc_elephant(
    sector_data: bytes, sector_offset: int, fvek: bytes, tweak_key: bytes, sector_size: int
) -> bytes:
    """Decrypt a sector using AES-CBC + Elephant Diffuser.

    Decryption order:
    1. AES-CBC decrypt with FVEK
    2. Elephant Diffuser B (decrypt)
    3. Elephant Diffuser A (decrypt)
    4. XOR with sector key (derived from TWEAK key)
    """
    # Step 1: AES-CBC decrypt
    iv_plain = struct.pack("<QQ", sector_offset, 0)
    iv_cipher = Cipher(algorithms.AES(fvek), modes.ECB()).encryptor()
    iv = iv_cipher.update(iv_plain) + iv_cipher.finalize()

    cbc = Cipher(algorithms.AES(fvek), modes.CBC(iv)).decryptor()
    decrypted = bytearray(cbc.update(sector_data) + cbc.finalize())

    # Step 2: Elephant Diffuser B
    int_size = sector_size >> 2
    buf = array.array("I")
    buf.frombytes(decrypted)
    _diffuser_b_decrypt(buf, int_size)

    # Step 3: Elephant Diffuser A
    _diffuser_a_decrypt(buf, int_size)

    # Step 4: XOR with sector key
    sector_key = _compute_sector_key(sector_offset, tweak_key)
    result = bytearray(buf.tobytes())
    for i in range(len(sector_key)):
        result[i] ^= sector_key[i]

    return bytes(result)


def _get_keys(fvek_data: bytes, encryption_method: int):
    """Extract FVEK and optional TWEAK key based on encryption method.

    For Elephant Diffuser modes, fvek_data is 64 bytes:
        first 32 bytes = FVEK (only first 16 used for 128-bit)
        last 32 bytes = TWEAK key (only first 16 used for 128-bit)
    """
    if encryption_method == EncryptionMethod.AES_CBC_128:
        return fvek_data[:16], None
    elif encryption_method == EncryptionMethod.AES_CBC_256:
        return fvek_data[:32], None
    elif encryption_method == EncryptionMethod.AES_CBC_128_DIFFUSER:
        return fvek_data[:16], fvek_data[32:48]
    elif encryption_method == EncryptionMethod.AES_CBC_256_DIFFUSER:
        return fvek_data[:32], fvek_data[32:64]
    elif encryption_method in (EncryptionMethod.AES_XTS_128, EncryptionMethod.AES_XTS_256):
        return fvek_data, None
    return fvek_data, None


def decrypt_sectors(
    data: bytes,
    start_offset: int,
    sector_size: int,
    fvek: bytes,
    encryption_method: int,
) -> bytes:
    """Decrypt multiple contiguous sectors of data."""
    if len(data) % sector_size != 0:
        raise ValueError(
            f"Data length ({len(data)}) is not a multiple of sector size ({sector_size})"
        )

    key, tweak_key = _get_keys(fvek, encryption_method)
    num_sectors = len(data) // sector_size
    result = bytearray()

    for i in range(num_sectors):
        offset = i * sector_size
        sector_data = data[offset : offset + sector_size]
        sector_offset = start_offset + offset

        if encryption_method in (
            EncryptionMethod.AES_XTS_128,
            EncryptionMethod.AES_XTS_256,
        ):
            sector_number = sector_offset // sector_size
            result.extend(decrypt_sector_xts(sector_data, sector_number, key))

        elif encryption_method in (
            EncryptionMethod.AES_CBC_128,
            EncryptionMethod.AES_CBC_256,
        ):
            result.extend(decrypt_sector_cbc(sector_data, sector_offset, key))

        elif encryption_method in (
            EncryptionMethod.AES_CBC_128_DIFFUSER,
            EncryptionMethod.AES_CBC_256_DIFFUSER,
        ):
            result.extend(
                decrypt_sector_cbc_elephant(sector_data, sector_offset, key, tweak_key, sector_size)
            )
        else:
            raise ValueError(f"Unknown encryption method: 0x{encryption_method:04x}")

    return bytes(result)
