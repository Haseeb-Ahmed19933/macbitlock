"""Orchestrates full volume encryption to create BitLocker-compatible images."""

import os
import struct
import uuid
from pathlib import Path
from typing import BinaryIO, Optional

from .constants import (
    BITLOCKER_GUID, EncryptionMethod, KEY_WRAP_ALGORITHM_AES256,
    ProtectionType, SECTOR_SIZE,
)
from .keys import (
    generate_vmk,
    generate_fvek,
    generate_recovery_key,
    recovery_password_to_short_key,
    derive_key_from_password,
    derive_key_from_recovery,
    wrap_key,
)
from .crypto import encrypt_sectors
from .volume import build_bitlocker_header
from .builder import (
    build_vmk_entry,
    build_recovery_vmk_entry,
    build_fvek_entry,
    build_description_entry,
    build_volume_header_block_entry,
    build_fve_metadata_block,
    _filetime_now,
)


class EncryptionError(Exception):
    pass


# Metadata block size on disk (64 KB, matching Windows default for version 2)
METADATA_BLOCK_SIZE = 65536

# Number of header sectors to store (first 16 sectors = 8192 bytes)
NUM_HEADER_SECTORS = 16


def _detect_source_fs(sector0: bytes) -> str:
    """Detect the filesystem of the source volume from its boot sector."""
    if sector0[3:7] == b"NTFS":
        return "NTFS"
    if sector0[3:11] == b"MSWIN4.1" or sector0[82:90] == b"FAT32   ":
        return "FAT32"
    oem = sector0[3:11]
    if b"FAT" in sector0[54:62] or b"FAT32" in sector0[82:90]:
        return "FAT32"
    raise EncryptionError(
        f"Cannot detect filesystem from boot sector (OEM: {oem!r}). "
        "The source volume must be a valid NTFS or FAT32 filesystem."
    )


def _calculate_layout(volume_size: int, sector_size: int = SECTOR_SIZE):
    """Calculate where to place metadata blocks and the volume header backup.

    Mirrors the Windows BitLocker layout: metadata blocks placed early in
    the volume at 1 GB intervals, starting just after the filesystem
    structures. All offsets stay within 32-bit range for USB compatibility.
    """
    header_size = NUM_HEADER_SECTORS * sector_size

    # Place first metadata block at ~36 MB (aligned to 64 KB boundary)
    # This puts it safely past the FAT tables for any typical FAT32 layout
    METADATA_START = 0x2400000  # 36 MB, same as Windows typically uses
    GB = 0x40000000             # 1 GB spacing between blocks

    meta1_offset = METADATA_START
    meta2_offset = METADATA_START + GB
    meta3_offset = METADATA_START + 2 * GB

    # Ensure metadata fits within the volume
    if meta3_offset + METADATA_BLOCK_SIZE > volume_size:
        # For smaller volumes, space evenly within first half
        usable = min(volume_size // 2, 0xFFFFFFFF)
        spacing = usable // 4
        meta1_offset = _align(spacing, sector_size)
        meta2_offset = _align(spacing * 2, sector_size)
        meta3_offset = _align(spacing * 3, sector_size)

    # Volume header backup goes right after the first metadata block
    vol_header_offset = _align(meta1_offset + METADATA_BLOCK_SIZE, sector_size)

    return {
        "header_size": header_size,
        "metadata_offsets": (meta1_offset, meta2_offset, meta3_offset),
        "volume_header_offset": vol_header_offset,
    }


def _align(offset: int, alignment: int) -> int:
    """Align an offset up to the given boundary."""
    return ((offset + alignment - 1) // alignment) * alignment


def _get_used_regions_fat32(fp, sector0: bytes, volume_size: int, sector_size: int) -> list[tuple[int, int]]:
    """Get list of (start_offset, end_offset) ranges that contain used data on FAT32.

    Returns regions that MUST be encrypted: boot sectors, FAT tables, root dir, and used clusters.
    """
    bytes_per_sector = struct.unpack_from("<H", sector0, 11)[0] or sector_size
    sectors_per_cluster = sector0[13]
    reserved_sectors = struct.unpack_from("<H", sector0, 14)[0]
    num_fats = sector0[16]
    sectors_per_fat = struct.unpack_from("<I", sector0, 36)[0]

    cluster_size = sectors_per_cluster * bytes_per_sector
    fat_start = reserved_sectors * bytes_per_sector
    fat_size = sectors_per_fat * bytes_per_sector
    data_start = fat_start + (num_fats * fat_size)

    # Always include: reserved area + FAT tables + first cluster of root dir
    regions = [(0, data_start + cluster_size)]

    # Read FAT1 to find used clusters
    fp.seek(fat_start)
    fat_data = fp.read(fat_size)

    # FAT32 entries are 4 bytes each, clusters start at 2
    max_cluster = min(len(fat_data) // 4, (volume_size - data_start) // cluster_size + 2)

    for cluster_idx in range(2, max_cluster):
        entry = struct.unpack_from("<I", fat_data, cluster_idx * 4)[0] & 0x0FFFFFFF
        if entry != 0:  # Cluster is used (non-zero = allocated or end-of-chain or bad)
            offset = data_start + (cluster_idx - 2) * cluster_size
            if offset < volume_size:
                regions.append((offset, min(offset + cluster_size, volume_size)))

    # Merge overlapping/adjacent regions and sort
    regions.sort()
    merged = [regions[0]]
    for start, end in regions[1:]:
        if start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))

    return merged


def _get_used_size_fat32(fp, sector0: bytes, volume_size: int, sector_size: int) -> int:
    """Calculate the total bytes of used space on a FAT32 volume."""
    regions = _get_used_regions_fat32(fp, sector0, volume_size, sector_size)
    return sum(end - start for start, end in regions)


def _offset_in_regions(offset: int, size: int, regions: list[tuple[int, int]]) -> bool:
    """Check if a sector at `offset` with `size` overlaps any used region."""
    for start, end in regions:
        if offset < end and (offset + size) > start:
            return True
        if start > offset + size:
            break
    return False


def encrypt_volume(
    source,
    output_path: str,
    password: str,
    encryption_method: int = EncryptionMethod.AES_XTS_128,
    encrypt_full_drive: bool = True,
    progress_callback=None,
) -> dict:
    """Encrypt a plaintext volume into a BitLocker-encrypted image.

    Args:
        source: Path to the unencrypted volume/image or file-like object.
        output_path: Where to write the encrypted image.
        password: The BitLocker password.
        encryption_method: AES_XTS_128 (default) or AES_CBC_128.
        encrypt_full_drive: If True, encrypt all sectors. If False, only encrypt used space.
        progress_callback: Optional callable(bytes_done, total_bytes).

    Returns:
        Dict with 'recovery_key' and 'volume_id'.
    """
    if isinstance(source, (str, Path)):
        fp = open(source, "rb")
        should_close = True
    else:
        fp = source
        should_close = False

    try:
        # Read source volume size and boot sector
        fp.seek(0, 2)
        volume_size = fp.tell()
        fp.seek(0)
        original_header = fp.read(NUM_HEADER_SECTORS * SECTOR_SIZE)

        if len(original_header) < SECTOR_SIZE:
            raise EncryptionError("Source volume is too small")

        sector0 = original_header[:SECTOR_SIZE]
        fs_type = _detect_source_fs(sector0)

        # Generate cryptographic material
        vmk = generate_vmk()
        fvek = generate_fvek(encryption_method)
        recovery_key = generate_recovery_key()
        volume_id = uuid.uuid4()
        bitlocker_guid = uuid.UUID(BITLOCKER_GUID)

        # Calculate layout
        sector_size = struct.unpack_from("<H", sector0, 11)[0] or SECTOR_SIZE
        layout = _calculate_layout(volume_size, sector_size)
        metadata_offsets = layout["metadata_offsets"]
        volume_header_offset = layout["volume_header_offset"]
        header_size = layout["header_size"]

        # Derive stretched keys
        pwd_salt = os.urandom(16)
        rec_salt = os.urandom(16)
        stretched_pwd = derive_key_from_password(password, pwd_salt)
        stretched_rec = derive_key_from_recovery(recovery_key, rec_salt)

        # Build nonces (use same FILETIME for all, increment counter)
        # Windows uses consecutive counters per VMK: pwd(2,3), rec(4,5,6), fvek(8)
        nonce_time = _filetime_now()
        pwd_nested_counter = 2
        pwd_standalone_counter = 3
        rec_short_counter = 4
        rec_vmk_nested_counter = 5
        rec_standalone_counter = 6
        fvek_nonce_counter = 8

        # Wrap VMK with password (nested + standalone)
        encrypted_vmk_pwd_nested = wrap_key(
            vmk, stretched_pwd, struct.pack("<QI", nonce_time, pwd_nested_counter),
            KEY_WRAP_ALGORITHM_AES256,
        )
        encrypted_vmk_pwd_standalone = wrap_key(
            vmk, stretched_pwd, struct.pack("<QI", nonce_time, pwd_standalone_counter),
            KEY_WRAP_ALGORITHM_AES256,
        )

        # Recovery: wrap the 16-byte short key AND the 32-byte VMK
        rec_short_key = recovery_password_to_short_key(recovery_key)
        encrypted_rec_short = wrap_key(
            rec_short_key, stretched_rec, struct.pack("<QI", nonce_time, rec_short_counter),
            KEY_WRAP_ALGORITHM_AES256,
        )
        encrypted_vmk_rec_nested = wrap_key(
            vmk, stretched_rec, struct.pack("<QI", nonce_time, rec_vmk_nested_counter),
            KEY_WRAP_ALGORITHM_AES256,
        )
        encrypted_vmk_rec_standalone = wrap_key(
            vmk, stretched_rec, struct.pack("<QI", nonce_time, rec_standalone_counter),
            KEY_WRAP_ALGORITHM_AES256,
        )

        # Wrap FVEK with VMK
        encrypted_fvek = wrap_key(
            fvek, vmk, struct.pack("<QI", nonce_time, fvek_nonce_counter), encryption_method
        )

        # Build metadata entries
        pwd_vmk_entry = build_vmk_entry(
            ProtectionType.PASSWORD, pwd_salt,
            nonce_time, pwd_nested_counter, encrypted_vmk_pwd_nested,
            encrypted_vmk_pwd_standalone, pwd_standalone_counter,
            stretch_enc_method=0x1001,
        )
        rec_vmk_entry = build_recovery_vmk_entry(
            rec_salt, nonce_time,
            encrypted_rec_short, rec_short_counter,
            encrypted_vmk_rec_nested, rec_vmk_nested_counter,
            encrypted_vmk_rec_standalone, rec_standalone_counter,
        )
        fvek_entry = build_fvek_entry(nonce_time, fvek_nonce_counter, encrypted_fvek)
        desc_entry = build_description_entry("MACBITLOCK", fs_type)
        vol_hdr_entry = build_volume_header_block_entry(
            volume_header_offset, header_size, sector0
        )

        # Build FVE metadata block
        # StateOffset MUST always be the full volume size for Windows compatibility
        fve_block = build_fve_metadata_block(
            volume_id, encryption_method, volume_size,
            NUM_HEADER_SECTORS, metadata_offsets, volume_header_offset,
            pwd_vmk_entry, rec_vmk_entry, fvek_entry,
            desc_entry, vol_hdr_entry,
            vmk=vmk, nonce_time=nonce_time,
        )

        # Pad metadata block to METADATA_BLOCK_SIZE
        if len(fve_block) < METADATA_BLOCK_SIZE:
            fve_block = fve_block + b"\x00" * (METADATA_BLOCK_SIZE - len(fve_block))

        # Build BitLocker volume header (replaces original boot sector)
        bl_header = build_bitlocker_header(sector0, bitlocker_guid, metadata_offsets)

        # Encrypt the original volume header for storage at volume_header_offset
        encrypted_orig_header = encrypt_sectors(
            original_header, volume_header_offset, sector_size, fvek, encryption_method
        )

        # Determine which regions to encrypt for used-space-only mode
        used_regions = None
        if not encrypt_full_drive and fs_type == "FAT32":
            used_regions = _get_used_regions_fat32(fp, sector0, volume_size, sector_size)

        # Write the encrypted output
        chunk_sectors = 256
        chunk_size = chunk_sectors * sector_size

        with open(output_path, "wb") as out:
            # 1. Write the BitLocker volume header + remaining header sectors (zeros)
            out.write(bl_header)
            out.write(b"\x00" * (header_size - SECTOR_SIZE))

            # 2. Encrypt and write the data sectors
            fp.seek(header_size)
            current_offset = header_size

            while current_offset < volume_size:
                remaining = min(chunk_size, volume_size - current_offset)
                fp.seek(current_offset)
                chunk = fp.read(remaining)

                if not chunk:
                    break

                # Pad to sector boundary
                if len(chunk) % sector_size != 0:
                    pad_len = sector_size - (len(chunk) % sector_size)
                    chunk = chunk + b"\x00" * pad_len

                if used_regions is not None:
                    # Used-space-only: encrypt sector-by-sector, skip unused
                    output_chunk = bytearray(len(chunk))
                    for i in range(0, len(chunk), sector_size):
                        sector_offset = current_offset + i
                        sector_data = chunk[i:i + sector_size]
                        if _offset_in_regions(sector_offset, sector_size, used_regions):
                            enc = encrypt_sectors(
                                sector_data, sector_offset, sector_size, fvek, encryption_method
                            )
                            output_chunk[i:i + sector_size] = enc
                        else:
                            output_chunk[i:i + sector_size] = sector_data
                    out.write(bytes(output_chunk))
                else:
                    encrypted_chunk = encrypt_sectors(
                        chunk, current_offset, sector_size, fvek, encryption_method
                    )
                    out.write(encrypted_chunk)

                current_offset += len(chunk)

                if progress_callback:
                    progress_callback(current_offset, volume_size)

            # 3. Overwrite metadata block locations with FVE metadata
            for meta_offset in metadata_offsets:
                if meta_offset < volume_size:
                    out.seek(meta_offset)
                    out.write(fve_block)

            # 4. Write encrypted original header at volume_header_offset
            out.seek(volume_header_offset)
            out.write(encrypted_orig_header)

            # 5. Ensure file is exactly volume_size
            out.seek(0, 2)
            current_file_size = out.tell()
            if current_file_size < volume_size:
                out.write(b"\x00" * (volume_size - current_file_size))
            elif current_file_size > volume_size:
                out.truncate(volume_size)

        return {
            "recovery_key": recovery_key,
            "volume_id": str(volume_id),
            "encryption_method": EncryptionMethod(encryption_method).name,
        }

    finally:
        if should_close:
            fp.close()


def encrypt_device_inplace(
    device_path: str,
    volume_size: int,
    password: str,
    encryption_method: int = EncryptionMethod.AES_XTS_128,
    encrypt_full_drive: bool = False,
    progress_callback=None,
) -> dict:
    """Encrypt a device in-place without needing full-size temp files.

    Reads from the raw device, encrypts used sectors, and writes back directly.
    Only the original header (8 KB) is kept in memory as a backup.

    Args:
        device_path: Path to the raw device (e.g. /dev/rdisk4s1).
        volume_size: Size of the partition in bytes.
        password: BitLocker password.
        encryption_method: AES method (default AES-XTS-128).
        encrypt_full_drive: If True, encrypt all sectors. If False, only used space.
        progress_callback: Optional callable(bytes_done, total_bytes).

    Returns:
        Dict with 'recovery_key', 'volume_id', 'encryption_method'.
    """
    # Read the original header from the device
    with open(device_path, "rb") as fp:
        original_header = fp.read(NUM_HEADER_SECTORS * SECTOR_SIZE)
        if len(original_header) < SECTOR_SIZE:
            raise EncryptionError("Device is too small or unreadable")

        sector0 = original_header[:SECTOR_SIZE]
        fs_type = _detect_source_fs(sector0)
        sector_size = struct.unpack_from("<H", sector0, 11)[0] or SECTOR_SIZE

        # Use the BPB total sectors for volume_size (matches what Windows uses)
        bpb_total_sectors = struct.unpack_from("<I", sector0, 32)[0]
        if bpb_total_sectors > 0:
            volume_size = bpb_total_sectors * sector_size

        # Get used regions if needed
        used_regions = None
        if not encrypt_full_drive and fs_type == "FAT32":
            used_regions = _get_used_regions_fat32(fp, sector0, volume_size, sector_size)

    # Generate cryptographic material
    vmk = generate_vmk()
    fvek = generate_fvek(encryption_method)
    recovery_key = generate_recovery_key()
    volume_id = uuid.uuid4()
    bitlocker_guid = uuid.UUID(BITLOCKER_GUID)

    # Calculate layout
    header_size = NUM_HEADER_SECTORS * sector_size
    layout = _calculate_layout(volume_size, sector_size)
    metadata_offsets = layout["metadata_offsets"]
    volume_header_offset = layout["volume_header_offset"]

    # Derive stretched keys
    pwd_salt = os.urandom(16)
    rec_salt = os.urandom(16)
    stretched_pwd = derive_key_from_password(password, pwd_salt)
    stretched_rec = derive_key_from_recovery(recovery_key, rec_salt)

    # Build nonces: pwd(2,3), rec(4,5,6), fvek(8)
    nonce_time = _filetime_now()
    pwd_nested_counter = 2
    pwd_standalone_counter = 3
    rec_short_counter = 4
    rec_vmk_nested_counter = 5
    rec_standalone_counter = 6
    fvek_nonce_counter = 8

    # Wrap VMK with password (nested + standalone)
    encrypted_vmk_pwd_nested = wrap_key(
        vmk, stretched_pwd, struct.pack("<QI", nonce_time, pwd_nested_counter),
        KEY_WRAP_ALGORITHM_AES256,
    )
    encrypted_vmk_pwd_standalone = wrap_key(
        vmk, stretched_pwd, struct.pack("<QI", nonce_time, pwd_standalone_counter),
        KEY_WRAP_ALGORITHM_AES256,
    )

    # Recovery: wrap the 16-byte short key AND the 32-byte VMK
    rec_short_key = recovery_password_to_short_key(recovery_key)
    encrypted_rec_short = wrap_key(
        rec_short_key, stretched_rec, struct.pack("<QI", nonce_time, rec_short_counter),
        KEY_WRAP_ALGORITHM_AES256,
    )
    encrypted_vmk_rec_nested = wrap_key(
        vmk, stretched_rec, struct.pack("<QI", nonce_time, rec_vmk_nested_counter),
        KEY_WRAP_ALGORITHM_AES256,
    )
    encrypted_vmk_rec_standalone = wrap_key(
        vmk, stretched_rec, struct.pack("<QI", nonce_time, rec_standalone_counter),
        KEY_WRAP_ALGORITHM_AES256,
    )

    # Wrap FVEK with VMK
    encrypted_fvek = wrap_key(
        fvek, vmk, struct.pack("<QI", nonce_time, fvek_nonce_counter), encryption_method
    )

    # Build metadata entries
    pwd_vmk_entry = build_vmk_entry(
        ProtectionType.PASSWORD, pwd_salt,
        nonce_time, pwd_nested_counter, encrypted_vmk_pwd_nested,
        encrypted_vmk_pwd_standalone, pwd_standalone_counter,
        stretch_enc_method=0x1001,
    )
    rec_vmk_entry = build_recovery_vmk_entry(
        rec_salt, nonce_time,
        encrypted_rec_short, rec_short_counter,
        encrypted_vmk_rec_nested, rec_vmk_nested_counter,
        encrypted_vmk_rec_standalone, rec_standalone_counter,
    )
    fvek_entry = build_fvek_entry(nonce_time, fvek_nonce_counter, encrypted_fvek)
    desc_entry = build_description_entry("MACBITLOCK", fs_type)
    vol_hdr_entry = build_volume_header_block_entry(
        volume_header_offset, header_size, sector0
    )

    # Build FVE metadata block
    # StateOffset (encrypted_volume_size) MUST be the full volume size.
    # Windows uses this to know the decryption boundary. Even in "used space only"
    # mode, the final state marks the full volume as encrypted.
    fve_block = build_fve_metadata_block(
        volume_id, encryption_method, volume_size,
        NUM_HEADER_SECTORS, metadata_offsets, volume_header_offset,
        pwd_vmk_entry, rec_vmk_entry, fvek_entry,
        desc_entry, vol_hdr_entry,
        vmk=vmk, nonce_time=nonce_time,
    )
    if len(fve_block) < METADATA_BLOCK_SIZE:
        fve_block = fve_block + b"\x00" * (METADATA_BLOCK_SIZE - len(fve_block))

    # Build BitLocker volume header
    bl_header = build_bitlocker_header(sector0, bitlocker_guid, metadata_offsets)

    # Encrypt the original header for backup storage
    encrypted_orig_header = encrypt_sectors(
        original_header, volume_header_offset, sector_size, fvek, encryption_method
    )

    # Now write directly to the device
    chunk_sectors = 256
    chunk_size = chunk_sectors * sector_size

    with open(device_path, "r+b") as dev:
        if used_regions is not None:
            # USED-SPACE-ONLY: only visit sectors within used regions
            total_used = sum(end - start for start, end in used_regions)
            processed = 0

            for region_start, region_end in used_regions:
                # Skip regions that fall within the header (handled separately)
                if region_end <= header_size:
                    processed += region_end - region_start
                    if progress_callback:
                        progress_callback(processed, total_used)
                    continue

                # Adjust start if region partially overlaps with header
                start = max(region_start, header_size)
                offset = start

                while offset < region_end:
                    read_size = min(chunk_size, region_end - offset)
                    dev.seek(offset)
                    chunk = dev.read(read_size)
                    if not chunk:
                        break

                    # Pad to sector boundary
                    if len(chunk) % sector_size != 0:
                        pad_len = sector_size - (len(chunk) % sector_size)
                        chunk = chunk + b"\x00" * pad_len

                    encrypted_chunk = encrypt_sectors(
                        chunk, offset, sector_size, fvek, encryption_method
                    )
                    dev.seek(offset)
                    dev.write(encrypted_chunk)

                    offset += len(chunk)
                    processed += len(chunk)
                    if progress_callback:
                        progress_callback(processed, total_used)

        else:
            # FULL-DRIVE: encrypt every sector
            current_offset = header_size
            while current_offset < volume_size:
                remaining = min(chunk_size, volume_size - current_offset)

                dev.seek(current_offset)
                chunk = dev.read(remaining)
                if not chunk:
                    break

                if len(chunk) % sector_size != 0:
                    pad_len = sector_size - (len(chunk) % sector_size)
                    chunk = chunk + b"\x00" * pad_len

                encrypted_chunk = encrypt_sectors(
                    chunk, current_offset, sector_size, fvek, encryption_method
                )
                dev.seek(current_offset)
                dev.write(encrypted_chunk)

                current_offset += len(chunk)
                if progress_callback:
                    progress_callback(current_offset, volume_size)

        # Write metadata blocks
        for meta_offset in metadata_offsets:
            if meta_offset < volume_size:
                dev.seek(meta_offset)
                dev.write(fve_block)

        # Write encrypted original header backup
        dev.seek(volume_header_offset)
        dev.write(encrypted_orig_header)

        # Write BitLocker header + zero remaining header sectors (LAST for safety)
        dev.seek(0)
        dev.write(bl_header)
        dev.write(b"\x00" * (header_size - SECTOR_SIZE))

        dev.flush()
        os.fsync(dev.fileno())

    return {
        "recovery_key": recovery_key,
        "volume_id": str(volume_id),
        "encryption_method": EncryptionMethod(encryption_method).name,
    }
