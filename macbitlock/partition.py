"""Detect partitions and container formats (VHD, raw) to find the BitLocker volume."""

import struct
from typing import BinaryIO, Optional

from .constants import FVE_METADATA_SIGNATURE, FAT32_OEM_SIGNATURE


VHD_FOOTER_SIGNATURE = b"conectix"
VHD_FOOTER_SIZE = 512


def detect_bitlocker_offset(fp: BinaryIO) -> int:
    """Detect the byte offset where the BitLocker volume starts.

    Handles:
    - Raw BitLocker volumes (offset 0)
    - MBR-partitioned images (scans partition table)
    - VHD fixed-size images (strips footer, scans partitions)

    Returns:
        Byte offset to the start of the BitLocker volume.
    """
    fp.seek(0)
    first_sector = fp.read(512)

    if len(first_sector) < 512:
        return 0

    # Check if the volume itself starts with BitLocker signature
    sig = first_sector[3:11]
    if sig == FVE_METADATA_SIGNATURE or sig == FAT32_OEM_SIGNATURE:
        # Check if offset 424 or 160 has a valid GUID area
        # (FAT32 BitLocker To Go uses "MSWIN4.1" at offset 3)
        return 0

    # Check for MBR partition table
    if first_sector[510:512] == b"\x55\xAA":
        offset = _find_bitlocker_partition(fp, first_sector)
        if offset is not None:
            return offset

    return 0


def _find_bitlocker_partition(fp: BinaryIO, mbr: bytes) -> Optional[int]:
    """Scan MBR partition table entries for a BitLocker volume."""
    for i in range(4):
        entry_offset = 446 + i * 16
        entry = mbr[entry_offset : entry_offset + 16]

        partition_type = entry[4]
        if partition_type == 0:
            continue

        lba_start = struct.unpack_from("<I", entry, 8)[0]
        byte_offset = lba_start * 512

        # Read the first sector of this partition to check for BitLocker
        fp.seek(byte_offset)
        sector = fp.read(512)
        if len(sector) < 512:
            continue

        sig = sector[3:11]
        if sig == FVE_METADATA_SIGNATURE or sig == FAT32_OEM_SIGNATURE:
            return byte_offset

    return None


def get_volume_size(fp: BinaryIO) -> int:
    """Get the actual data size (excluding VHD footer if present)."""
    fp.seek(0, 2)
    file_size = fp.tell()

    # Check for VHD footer at the end
    if file_size > VHD_FOOTER_SIZE:
        fp.seek(file_size - VHD_FOOTER_SIZE)
        footer = fp.read(8)
        if footer == VHD_FOOTER_SIGNATURE:
            return file_size - VHD_FOOTER_SIZE

    return file_size
