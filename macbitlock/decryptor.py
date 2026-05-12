"""Orchestrates full volume decryption by combining all components."""

import os
import struct
from pathlib import Path
from typing import BinaryIO, Optional

from .constants import EncryptionMethod, ProtectionType, SECTOR_SIZE
from .volume import read_volume_info, VolumeInfo
from .metadata import (
    read_metadata,
    extract_vmk_entries,
    extract_fvek_entry,
    VMKEntry,
    FVEKEntry,
)
from .keys import derive_key_from_password, derive_key_from_recovery, unwrap_key
from .crypto import decrypt_sectors
from .partition import detect_bitlocker_offset, get_volume_size


class DecryptionError(Exception):
    pass


def _open_source(source) -> BinaryIO:
    if isinstance(source, (str, Path)):
        return open(source, "rb")
    return source


def _find_vmk_for_password(vmk_entries: list[VMKEntry]) -> Optional[VMKEntry]:
    for vmk in vmk_entries:
        if vmk.protection_type == ProtectionType.PASSWORD:
            return vmk
    return None


def _find_vmk_for_recovery(vmk_entries: list[VMKEntry]) -> Optional[VMKEntry]:
    for vmk in vmk_entries:
        if vmk.protection_type == ProtectionType.RECOVERY_PASSWORD:
            return vmk
    return None


def _find_vmk_clear_key(vmk_entries: list[VMKEntry]) -> Optional[VMKEntry]:
    for vmk in vmk_entries:
        if vmk.protection_type == ProtectionType.CLEAR_KEY:
            return vmk
    return None


def _build_nonce(vmk: VMKEntry) -> bytes:
    return struct.pack("<Q", vmk.nonce_time) + struct.pack("<I", vmk.nonce_counter)


def decrypt_volume(
    source,
    output_path: str,
    password: Optional[str] = None,
    recovery_key: Optional[str] = None,
    progress_callback=None,
) -> str:
    """
    Decrypt a BitLocker To Go volume.

    Args:
        source: Path to encrypted volume/image or file-like object
        output_path: Where to write the decrypted image
        password: User password (if using password protection)
        recovery_key: Recovery key string (if using recovery key protection)
        progress_callback: Optional callable(bytes_done, total_bytes) for progress

    Returns:
        Path to the decrypted output file
    """
    if not password and not recovery_key:
        raise DecryptionError("Either password or recovery_key must be provided")

    fp = _open_source(source)
    should_close = isinstance(source, (str, Path))

    try:
        # Detect partition offset (handles VHD, MBR, raw volumes)
        partition_offset = detect_bitlocker_offset(fp)
        fp.seek(partition_offset)
        volume_info = read_volume_info(fp)

        metadata_block = None
        for offset in volume_info.metadata_offsets:
            if offset == 0:
                continue
            try:
                block_header, meta_header, entries = read_metadata(
                    fp, partition_offset + offset
                )
                metadata_block = (block_header, meta_header, entries)
                break
            except Exception:
                continue

        if metadata_block is None:
            raise DecryptionError("Could not read any valid FVE metadata block")

        block_header, meta_header, entries = metadata_block

        vmk_entries = extract_vmk_entries(entries)
        if not vmk_entries:
            raise DecryptionError("No VMK entries found in metadata")

        fvek_entry = extract_fvek_entry(entries)
        if fvek_entry is None:
            raise DecryptionError("No FVEK entry found in metadata")

        # Determine which VMK to use and derive the stretched key
        if password:
            vmk = _find_vmk_for_password(vmk_entries)
            if vmk is None:
                raise DecryptionError("No password-protected VMK found")
            stretched_key = derive_key_from_password(password, vmk.salt)
        else:
            vmk = _find_vmk_for_recovery(vmk_entries)
            if vmk is None:
                raise DecryptionError("No recovery-key-protected VMK found")
            stretched_key = derive_key_from_recovery(recovery_key, vmk.salt)

        # Unwrap VMK
        nonce = _build_nonce(vmk)
        vmk_key = unwrap_key(vmk.encrypted_data, stretched_key, nonce)

        # Unwrap FVEK using VMK
        fvek_nonce = struct.pack("<Q", fvek_entry.nonce_time) + struct.pack(
            "<I", fvek_entry.nonce_counter
        )
        fvek = unwrap_key(fvek_entry.encrypted_data, vmk_key, fvek_nonce)

        # Determine the encrypted volume size and data offset
        encrypted_size = block_header.encrypted_volume_size
        volume_header_offset = block_header.volume_header_offset
        num_header_sectors = block_header.num_volume_header_sectors
        header_size = num_header_sectors * volume_info.sector_size

        # Get total volume size
        total_size = get_volume_size(fp) - partition_offset
        if encrypted_size == 0:
            encrypted_size = total_size

        # The encryption method field uses lower 16 bits for the actual method
        encryption_method = meta_header.encryption_method & 0xFFFF

        # Decrypt the volume sector by sector
        sector_size = volume_info.sector_size
        chunk_size = sector_size * 256  # Process 256 sectors at a time

        with open(output_path, "wb") as out:
            # Write decrypted volume header (stored encrypted at volume_header_offset)
            if volume_header_offset and volume_header_offset > 0:
                fp.seek(partition_offset + volume_header_offset)
                encrypted_header = fp.read(header_size)
                # IV is computed from the physical storage offset
                decrypted_header = decrypt_sectors(
                    encrypted_header,
                    volume_header_offset,
                    sector_size,
                    fvek,
                    encryption_method,
                )
                out.write(decrypted_header)
            else:
                out.write(b"\x00" * header_size)

            # Decrypt remaining sectors
            current_offset = header_size
            bytes_written = header_size

            while current_offset < encrypted_size:
                remaining = min(chunk_size, encrypted_size - current_offset)
                fp.seek(partition_offset + current_offset)
                chunk = fp.read(remaining)

                if not chunk:
                    break

                # Pad last chunk to sector boundary if needed
                if len(chunk) % sector_size != 0:
                    padded_len = (len(chunk) // sector_size) * sector_size
                    if padded_len == 0:
                        out.write(chunk)
                        current_offset += len(chunk)
                        continue
                    remainder = chunk[padded_len:]
                    chunk = chunk[:padded_len]
                else:
                    remainder = b""

                decrypted_chunk = decrypt_sectors(
                    chunk, current_offset, sector_size, fvek, encryption_method
                )

                out.write(decrypted_chunk)
                if remainder:
                    out.write(remainder)
                bytes_written += len(decrypted_chunk) + len(remainder)
                current_offset += len(chunk) + len(remainder)

                if progress_callback:
                    progress_callback(current_offset, encrypted_size)

            # If volume is larger than encrypted_size, copy remaining unencrypted data
            if total_size > encrypted_size:
                fp.seek(partition_offset + encrypted_size)
                while True:
                    chunk = fp.read(chunk_size)
                    if not chunk:
                        break
                    out.write(chunk)

    finally:
        if should_close:
            fp.close()

    return output_path


def get_volume_info(source) -> dict:
    """Get information about a BitLocker volume without decrypting."""
    fp = _open_source(source)
    should_close = isinstance(source, (str, Path))

    try:
        partition_offset = detect_bitlocker_offset(fp)
        fp.seek(partition_offset)
        volume_info = read_volume_info(fp)

        info = {
            "volume_type": volume_info.volume_type,
            "sector_size": volume_info.sector_size,
            "cluster_size": volume_info.cluster_size,
            "bitlocker_guid": str(volume_info.bitlocker_guid),
            "metadata_offsets": volume_info.metadata_offsets,
            "partition_offset": partition_offset,
        }

        # Try to read metadata for more details
        for offset in volume_info.metadata_offsets:
            if offset == 0:
                continue
            try:
                block_header, meta_header, entries = read_metadata(
                    fp, partition_offset + offset
                )
                info["encryption_method"] = EncryptionMethod(
                    meta_header.encryption_method & 0xFFFF
                ).name
                info["encrypted_volume_size"] = block_header.encrypted_volume_size
                info["volume_id"] = str(meta_header.volume_id)

                vmk_entries = extract_vmk_entries(entries)
                info["protection_types"] = [
                    ProtectionType(v.protection_type).name for v in vmk_entries
                ]
                break
            except Exception:
                continue

        return info

    finally:
        if should_close:
            fp.close()
