"""Construct BitLocker FVE metadata structures for volume encryption."""

import hashlib
import math
import os
import struct
import time
import uuid
import zlib

from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from .constants import (
    FVE_METADATA_SIGNATURE,
    EncryptionMethod,
    KeyProtectionType,
    MetadataEntryType,
    MetadataValueType,
)


def _filetime_now() -> int:
    """Return the current time as a Windows FILETIME (100-ns intervals since 1601-01-01)."""
    EPOCH_DIFF = 116444736000000000
    return int(time.time() * 10_000_000) + EPOCH_DIFF


def _build_entry(entry_type: int, value_type: int, data: bytes, version: int = 1) -> bytes:
    """Build a single FVE metadata entry (8-byte header + data)."""
    size = 8 + len(data)
    return struct.pack("<HHHH", size, entry_type, value_type, version) + data


def _build_aes_ccm_entry(
    nonce_time: int, nonce_counter: int, encrypted_data: bytes, entry_type: int = 0
) -> bytes:
    """Build an AES-CCM encrypted key entry (nested or top-level)."""
    data = struct.pack("<QI", nonce_time, nonce_counter) + encrypted_data
    return _build_entry(entry_type, MetadataValueType.AES_CCM_ENCRYPTED_KEY, data)


def _build_stretch_key_entry(
    enc_method: int, salt: bytes, nested_ccm_entries: list[bytes]
) -> bytes:
    """Build a stretch key entry containing enc_method + salt + nested AES-CCM entries."""
    data = struct.pack("<I", enc_method) + salt + b"".join(nested_ccm_entries)
    return _build_entry(0, MetadataValueType.STRETCH_KEY, data)


def build_vmk_entry(
    protection_type: int,
    salt: bytes,
    nonce_time: int,
    nonce_counter: int,
    encrypted_vmk: bytes,
    encrypted_vmk_standalone: bytes,
    standalone_nonce_counter: int,
    stretch_enc_method: int = 0x1001,
) -> bytes:
    """Build a PASSWORD VMK metadata entry.

    Password VMK structure: STRETCH_KEY(one nested CCM) + standalone CCM.

    Args:
        protection_type: Should be PASSWORD (0x2000).
        salt: 16-byte random salt for key stretching.
        nonce_time: FILETIME for AES-CCM nonce.
        nonce_counter: Counter for the nested CCM in stretch key.
        encrypted_vmk: The nested AES-CCM encrypted blob (tag + ciphertext).
        encrypted_vmk_standalone: The standalone AES-CCM encrypted VMK blob.
        standalone_nonce_counter: Nonce counter for the standalone CCM entry.
        stretch_enc_method: 0x1001 for password.
    """
    key_id = uuid.uuid4().bytes_le
    mod_time = _filetime_now()

    nested_ccm = _build_aes_ccm_entry(nonce_time, nonce_counter, encrypted_vmk)
    stretch_entry = _build_stretch_key_entry(stretch_enc_method, salt, [nested_ccm])

    standalone_ccm = _build_aes_ccm_entry(nonce_time, standalone_nonce_counter, encrypted_vmk_standalone)

    vmk_header = key_id + struct.pack("<QHH", mod_time, 0, protection_type)
    vmk_data = vmk_header + stretch_entry + standalone_ccm

    return _build_entry(MetadataEntryType.VMK, MetadataValueType.VOLUME_MASTER_KEY, vmk_data)


def build_recovery_vmk_entry(
    salt: bytes,
    nonce_time: int,
    encrypted_short_key: bytes,
    short_key_counter: int,
    encrypted_vmk_nested: bytes,
    vmk_nested_counter: int,
    encrypted_vmk_standalone: bytes,
    standalone_counter: int,
) -> bytes:
    """Build a RECOVERY VMK metadata entry matching Windows format.

    Recovery VMK has a more complex structure than password VMK:
    - STRETCH_KEY with TWO nested CCMs:
      - Type 0x12: wraps the 16-byte recovery short key (for validation)
      - Type 0x13: wraps the 32-byte VMK
    - Standalone AES_CCM: wraps the 32-byte VMK
    - Extra sub-entry with vtype=0x15 (timestamps + parameters)

    Args:
        salt: 16-byte random salt for key stretching.
        nonce_time: FILETIME for AES-CCM nonce.
        encrypted_short_key: AES-CCM encrypted 16-byte recovery short key.
        short_key_counter: Nonce counter for the short key CCM.
        encrypted_vmk_nested: AES-CCM encrypted VMK (nested in stretch key).
        vmk_nested_counter: Nonce counter for the nested VMK CCM.
        encrypted_vmk_standalone: AES-CCM encrypted VMK (standalone).
        standalone_counter: Nonce counter for the standalone CCM.
    """
    key_id = uuid.uuid4().bytes_le
    mod_time = _filetime_now()

    # Two nested CCMs inside STRETCH_KEY:
    # Type 0x12 wraps the 16-byte recovery short key
    nested_short = _build_aes_ccm_entry(nonce_time, short_key_counter, encrypted_short_key, entry_type=0x12)
    # Type 0x13 wraps the 32-byte VMK
    nested_vmk = _build_aes_ccm_entry(nonce_time, vmk_nested_counter, encrypted_vmk_nested, entry_type=0x13)

    stretch_entry = _build_stretch_key_entry(0x1000, salt, [nested_short, nested_vmk])

    # Standalone AES-CCM
    standalone_ccm = _build_aes_ccm_entry(nonce_time, standalone_counter, encrypted_vmk_standalone)

    # Validation sub-entry (vtype=0x15): two identical timestamps + parameters
    # Format: FILETIME(8) + FILETIME(8) + uint16(key_bits=16) + uint16(version=2)
    validation_data = struct.pack("<QQHh", mod_time, mod_time, 16, 2)
    validation_entry = _build_entry(0, 0x0015, validation_data)

    vmk_header = key_id + struct.pack("<QHH", mod_time, 0, KeyProtectionType.RECOVERY_PASSWORD)
    vmk_data = vmk_header + stretch_entry + standalone_ccm + validation_entry

    return _build_entry(MetadataEntryType.VMK, MetadataValueType.VOLUME_MASTER_KEY, vmk_data)


def build_fvek_entry(nonce_time: int, nonce_counter: int, encrypted_fvek: bytes) -> bytes:
    """Build the FVEK metadata entry (AES-CCM encrypted)."""
    data = struct.pack("<QI", nonce_time, nonce_counter) + encrypted_fvek
    return _build_entry(
        MetadataEntryType.FVEK, MetadataValueType.AES_CCM_ENCRYPTED_KEY, data
    )


def build_description_entry(computer_name: str, volume_label: str) -> bytes:
    """Build the description entry (type 7, unicode string)."""
    now = time.strftime("%m/%d/%Y")
    desc = f"{computer_name} {volume_label} {now}\x00"
    data = desc.encode("utf-16-le")
    return _build_entry(
        MetadataEntryType.DESCRIPTION, MetadataValueType.UNICODE_STRING, data
    )


def build_volume_header_block_entry(
    offset: int, size: int, original_sector: bytes = None
) -> bytes:
    """Build the volume header block entry with extended filesystem data.

    Windows includes FAT32 BPB parameters after the offset+size fields.
    This extra section is required for Windows compatibility.
    """
    data = struct.pack("<QQ", offset, size)

    if original_sector and len(original_sector) >= 90:
        extra = _build_vhb_extra(original_sector)
        if extra:
            data += extra

    return _build_entry(
        MetadataEntryType.VOLUME_HEADER_BLOCK, MetadataValueType.OFFSET_AND_SIZE, data
    )


def _build_vhb_extra(sector: bytes) -> bytes | None:
    """Build the 76-byte extended VHB section from original FAT32 BPB.

    The format is reverse-engineered from Windows 11 BitLocker:
    - Bytes 0-1: sub-type (5)
    - Bytes 2-3: section size (76 = 0x4C)
    - Bytes 4-7: reserved (0)
    - Bytes 8-11: cluster size in bytes (sectors_per_cluster * bytes_per_sector)
    - Then FAT32-specific layout info padded to 76 bytes total.
    """
    try:
        bytes_per_sector = struct.unpack_from("<H", sector, 11)[0]
        if bytes_per_sector == 0:
            return None
        sectors_per_cluster = sector[13]
        reserved_sectors = struct.unpack_from("<H", sector, 14)[0]
        num_fats = sector[16]
        total_sectors_32 = struct.unpack_from("<I", sector, 32)[0]
        sectors_per_fat_32 = struct.unpack_from("<I", sector, 36)[0]
        root_cluster = struct.unpack_from("<I", sector, 44)[0]
        fsinfo_sector = struct.unpack_from("<H", sector, 48)[0]
        backup_boot = struct.unpack_from("<H", sector, 50)[0]
        fs_version = struct.unpack_from("<H", sector, 42)[0]

        cluster_size = sectors_per_cluster * bytes_per_sector
        fat_start = reserved_sectors * bytes_per_sector
        fat_total = num_fats * sectors_per_fat_32 * bytes_per_sector
        data_start = fat_start + fat_total

        buf = bytearray(76)
        struct.pack_into("<HH", buf, 0, 5, 76)
        struct.pack_into("<I", buf, 8, cluster_size)
        # Zero-padded area for 16 bytes (offsets 12-27)
        struct.pack_into("<I", buf, 28, bytes_per_sector)
        struct.pack_into("<I", buf, 32, bytes_per_sector)
        struct.pack_into("<I", buf, 36, num_fats * sectors_per_cluster)
        struct.pack_into("<I", buf, 44, sectors_per_fat_32)
        struct.pack_into("<I", buf, 48, root_cluster)
        struct.pack_into("<BBBB", buf, 56,
                         sectors_per_cluster, fsinfo_sector, backup_boot, num_fats)
        struct.pack_into("<I", buf, 60, data_start)
        struct.pack_into("<I", buf, 68, total_sectors_32 * bytes_per_sector // cluster_size)

        return bytes(buf)
    except (struct.error, IndexError, ZeroDivisionError):
        return None


def build_metadata_header(
    volume_id: uuid.UUID,
    encryption_method: int,
    entries_data: bytes,
    next_nonce: int = 10,
) -> bytes:
    """Build the 48-byte FVE metadata header.

    The metadata_size field covers this header + all entries.
    """
    creation_time = _filetime_now()
    header_size = 48
    metadata_size = header_size + len(entries_data)

    enc_method_full = (encryption_method << 16) | encryption_method

    return struct.pack(
        "<IIII16sIIQ",
        metadata_size,
        1,               # version
        header_size,
        metadata_size,    # metadata size copy
        volume_id.bytes_le,
        next_nonce,
        enc_method_full,
        creation_time,
    )


def build_block_header(
    encrypted_volume_size: int,
    num_volume_header_sectors: int,
    metadata_offsets: tuple,
    volume_header_offset: int,
    metadata_size: int,
) -> bytes:
    """Build the 64-byte FVE metadata block header.

    Args:
        encrypted_volume_size: Total encrypted data size in bytes.
        num_volume_header_sectors: Number of sectors in the stored volume header (16 for NTFS).
        metadata_offsets: Tuple of 3 metadata block offsets (relative to volume start).
        volume_header_offset: Offset where the encrypted original header is stored.
        metadata_size: The metadata_size from the metadata header (header + entries).
    """
    total_block = 64 + metadata_size
    size_field = math.ceil(total_block / 16)

    return struct.pack(
        "<8sHHHHQIIQQQQ",
        FVE_METADATA_SIGNATURE,
        size_field,
        2,                          # version
        4,                          # status (always 4 in our test images)
        4,                          # status copy
        encrypted_volume_size,
        0,                          # unknown (always 0)
        num_volume_header_sectors,
        metadata_offsets[0],
        metadata_offsets[1],
        metadata_offsets[2],
        volume_header_offset,
    )


def _build_validation_block(fve_block: bytes, vmk: bytes, nonce_time: int) -> bytes:
    """Build the FVE metadata validation block (CRC-32 + encrypted SHA-256).

    Windows validates CRC-32 before prompting for password. The encrypted
    SHA-256 is validated after VMK decryption as a MAC check.

    The validation_size field = remaining space in the 64KB metadata block
    (i.e., METADATA_BLOCK_SIZE - len(fve_block)).

    Args:
        fve_block: The complete FVE metadata block (padded to fve_size*16).
        vmk: The 32-byte Volume Master Key (for encrypting the SHA-256 hash).
        nonce_time: Nonce timestamp for the AES-CCM encryption.

    Returns:
        The validation block bytes (88 bytes of actual data).
    """
    from .encryptor import METADATA_BLOCK_SIZE

    # CRC-32 of the metadata block (standard zlib CRC)
    fve_crc = zlib.crc32(fve_block) & 0xFFFFFFFF

    # SHA-256 of the metadata block
    sha256_hash = hashlib.sha256(fve_block).digest()

    # Build the plaintext validation hash structure (44 bytes)
    # size(2) + role(2) + type(2) + flags(2) + hash_type(2) + unknown(2) + hash(32)
    validation_hash = struct.pack("<HHHHHH", 44, 0, 1, 0, 0x2005, 0) + sha256_hash

    # Encrypt with AES-CCM using VMK
    nonce_counter = 9
    nonce = struct.pack("<QI", nonce_time, nonce_counter)

    aesccm = AESCCM(vmk, tag_length=16)
    ct_and_tag = aesccm.encrypt(nonce, validation_hash, None)
    ciphertext = ct_and_tag[:-16]
    mac_tag = ct_and_tag[-16:]

    # nested_struct_data: nonce(12) + mac_tag(16) + ciphertext(44) = 72 bytes
    nested_data = nonce + mac_tag + ciphertext

    # validation_size = remaining space in 64KB block after FVE metadata
    validation_size = METADATA_BLOCK_SIZE - len(fve_block)
    nested_struct_size = 80  # 8 (header) + 72 (data)

    return struct.pack(
        "<HHIHHHH",
        validation_size,
        2,               # validation_version
        fve_crc,
        nested_struct_size,
        0,               # nested_struct_role
        5,               # nested_struct_type (AES_CCM_ENCRYPTED_KEY)
        1,               # nested_struct_flags (Windows uses 1)
    ) + nested_data


def build_fve_metadata_block(
    volume_id: uuid.UUID,
    encryption_method: int,
    encrypted_volume_size: int,
    num_volume_header_sectors: int,
    metadata_offsets: tuple,
    volume_header_offset: int,
    password_vmk_entry: bytes,
    recovery_vmk_entry: bytes,
    fvek_entry: bytes,
    description_entry: bytes,
    vol_header_block_entry: bytes,
    vmk: bytes = None,
    nonce_time: int = None,
) -> bytes:
    """Assemble a complete FVE metadata block with validation.

    Returns the full block bytes including the CRC-32 validation block.
    Caller writes 3 identical copies at the metadata offsets.
    """
    entries_data = (
        description_entry
        + password_vmk_entry
        + recovery_vmk_entry
        + fvek_entry
        + vol_header_block_entry
    )

    meta_header = build_metadata_header(
        volume_id, encryption_method, entries_data
    )

    metadata_size = 48 + len(entries_data)
    block_header = build_block_header(
        encrypted_volume_size,
        num_volume_header_sectors,
        metadata_offsets,
        volume_header_offset,
        metadata_size,
    )

    fve_block = block_header + meta_header + entries_data

    # Pad to fve_size * 16 boundary (CRC covers exactly this many bytes)
    total_block = 64 + metadata_size
    fve_size_bytes = math.ceil(total_block / 16) * 16
    if len(fve_block) < fve_size_bytes:
        fve_block = fve_block + b"\x00" * (fve_size_bytes - len(fve_block))

    # Append validation block (CRC-32 + encrypted SHA-256)
    if vmk is not None and nonce_time is not None:
        validation = _build_validation_block(fve_block, vmk, nonce_time)
        return fve_block + validation

    return fve_block
