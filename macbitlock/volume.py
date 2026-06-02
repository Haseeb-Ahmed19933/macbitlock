"""BitLocker volume header parsing for NTFS and FAT32-based volumes."""

import struct
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import BinaryIO, Union

from .constants import (
    BOOT_ENTRY_POINT,
    FAT32_FS_SIGNATURE,
    FAT32_OEM_SIGNATURE,
    FVE_METADATA_SIGNATURE,
    SECTOR_SIGNATURE,
    SECTOR_SIZE,
    FAT32Offsets,
    NTFSOffsets,
)


class VolumeType(Enum):
    NTFS = "NTFS"
    FAT32 = "FAT32"


@dataclass
class VolumeHeader:
    volume_type: VolumeType
    boot_entry_point: bytes
    bytes_per_sector: int
    sectors_per_cluster: int
    bitlocker_guid: uuid.UUID
    fve_metadata_offsets: list[int] = field(default_factory=list)
    # FAT32-specific fields
    volume_serial: int | None = None
    volume_label: str | None = None


@dataclass
class VolumeInfo:
    volume_type: VolumeType
    sector_size: int
    cluster_size: int
    metadata_offsets: list[int]
    bitlocker_guid: uuid.UUID


class VolumeHeaderError(Exception):
    """Raised when volume header parsing fails."""


def _read_exact(fp: BinaryIO, size: int) -> bytes:
    data = fp.read(size)
    if len(data) != size:
        raise VolumeHeaderError(
            f"Expected {size} bytes, got {len(data)}"
        )
    return data


def _parse_guid(data: bytes) -> uuid.UUID:
    """Parse a Windows-style mixed-endian GUID from 16 bytes."""
    return uuid.UUID(bytes_le=data)


def _detect_volume_type(sector: bytes) -> VolumeType:
    fs_sig = sector[3:11]
    if fs_sig == FVE_METADATA_SIGNATURE:
        return VolumeType.NTFS
    oem_sig = sector[3:11]
    if oem_sig == FAT32_OEM_SIGNATURE:
        fat_sig = sector[82:90]
        if fat_sig == FAT32_FS_SIGNATURE:
            return VolumeType.FAT32
    raise VolumeHeaderError(
        f"Unrecognized volume signature: {fs_sig!r}"
    )


def _validate_sector_signature(sector: bytes) -> None:
    sig = sector[510:512]
    if sig != SECTOR_SIGNATURE:
        raise VolumeHeaderError(
            f"Invalid sector signature: expected 0x55AA, got {sig.hex()}"
        )


def _parse_ntfs_header(sector: bytes) -> VolumeHeader:
    boot_entry = sector[0:3]
    bytes_per_sector = struct.unpack_from("<H", sector, NTFSOffsets.BYTES_PER_SECTOR)[0]
    sectors_per_cluster = sector[NTFSOffsets.SECTORS_PER_CLUSTER]
    bitlocker_guid = _parse_guid(
        sector[NTFSOffsets.BITLOCKER_GUID : NTFSOffsets.BITLOCKER_GUID + 16]
    )
    fve_offsets = [
        struct.unpack_from("<Q", sector, NTFSOffsets.FVE_METADATA_1)[0],
        struct.unpack_from("<Q", sector, NTFSOffsets.FVE_METADATA_2)[0],
        struct.unpack_from("<Q", sector, NTFSOffsets.FVE_METADATA_3)[0],
    ]
    return VolumeHeader(
        volume_type=VolumeType.NTFS,
        boot_entry_point=boot_entry,
        bytes_per_sector=bytes_per_sector,
        sectors_per_cluster=sectors_per_cluster,
        bitlocker_guid=bitlocker_guid,
        fve_metadata_offsets=fve_offsets,
    )


def _parse_fat32_header(sector: bytes) -> VolumeHeader:
    boot_entry = sector[0:3]
    bytes_per_sector = struct.unpack_from("<H", sector, FAT32Offsets.BYTES_PER_SECTOR)[0]
    sectors_per_cluster = sector[FAT32Offsets.SECTORS_PER_CLUSTER]
    volume_serial = struct.unpack_from("<I", sector, FAT32Offsets.VOLUME_SERIAL)[0]
    volume_label = (
        sector[FAT32Offsets.VOLUME_LABEL : FAT32Offsets.VOLUME_LABEL + 11]
        .decode("ascii", errors="replace")
        .rstrip()
    )
    bitlocker_guid = _parse_guid(
        sector[FAT32Offsets.BITLOCKER_GUID : FAT32Offsets.BITLOCKER_GUID + 16]
    )
    fve_offsets = [
        struct.unpack_from("<Q", sector, FAT32Offsets.FVE_METADATA_1)[0],
        struct.unpack_from("<Q", sector, FAT32Offsets.FVE_METADATA_2)[0],
        struct.unpack_from("<Q", sector, FAT32Offsets.FVE_METADATA_3)[0],
    ]
    return VolumeHeader(
        volume_type=VolumeType.FAT32,
        boot_entry_point=boot_entry,
        bytes_per_sector=bytes_per_sector,
        sectors_per_cluster=sectors_per_cluster,
        bitlocker_guid=bitlocker_guid,
        fve_metadata_offsets=fve_offsets,
        volume_serial=volume_serial,
        volume_label=volume_label,
    )


def read_volume_header(fp: BinaryIO) -> VolumeHeader:
    """Read and parse a BitLocker volume header from a file-like object.

    The file position should be at the start of the volume (sector 0).
    """
    sector = _read_exact(fp, SECTOR_SIZE)
    _validate_sector_signature(sector)

    volume_type = _detect_volume_type(sector)

    if volume_type == VolumeType.NTFS:
        return _parse_ntfs_header(sector)
    else:
        return _parse_fat32_header(sector)


def build_bitlocker_header(
    original_sector: bytes,
    bitlocker_guid: uuid.UUID,
    metadata_offsets: tuple,
) -> bytes:
    """Build a 512-byte BitLocker volume header from an original filesystem boot sector.

    Windows uses -FVE-FS- as OEM and NTFS-style metadata offset positions (160/176/184/192)
    for ALL BitLocker volumes, including FAT32 (BitLocker To Go).

    For FAT32, Windows modifies BPB fields to prevent accidental mounting as regular FAT32:
    - num_fats → 0
    - root_cluster → 0
    - reserved_sectors and sectors_per_fat are recalculated

    Args:
        original_sector: The original 512-byte boot sector (NTFS or FAT32).
        bitlocker_guid: The BitLocker volume GUID.
        metadata_offsets: Tuple of 3 FVE metadata block offsets (relative to volume start).

    Returns:
        512-byte BitLocker volume header.
    """
    header = bytearray(original_sector[:512])

    header[0:3] = BOOT_ENTRY_POINT
    header[3:11] = FVE_METADATA_SIGNATURE

    # Modify BPB fields to match Windows 7+ BitLocker format.
    # The BitLocker format repurposes FAT32 BPB fields with specific values:
    # - reserved_sectors: 0 (per libbde specification for Win7+)
    # - num_fats: 0
    # - sectors_per_fat_32: 0x1FE0 (8160) - fixed constant in all Win7+ BitLocker volumes
    # - root_cluster: 0
    # - MetadataLcn: 0 (Win7+ uses direct offsets at 176/184/192 instead)
    # Windows may update reserved_sectors to a computed value on first access.
    is_fat32 = original_sector[82:90] == FAT32_FS_SIGNATURE
    if is_fat32:
        struct.pack_into("<H", header, 14, 0)              # reserved_sectors = 0
        header[16] = 0                                     # num_fats = 0
        struct.pack_into("<I", header, 36, 0x1FE0)         # sectors_per_fat_32 = 8160 (BitLocker constant)
        struct.pack_into("<I", header, 44, 0)              # root_cluster = 0
        struct.pack_into("<Q", header, 56, 0)              # MetadataLcn = 0

    # Always use NTFS-style positions for GUID and metadata offsets
    struct.pack_into("<16s", header, NTFSOffsets.BITLOCKER_GUID, bitlocker_guid.bytes_le)
    struct.pack_into("<Q", header, NTFSOffsets.FVE_METADATA_1, metadata_offsets[0])
    struct.pack_into("<Q", header, NTFSOffsets.FVE_METADATA_2, metadata_offsets[1])
    struct.pack_into("<Q", header, NTFSOffsets.FVE_METADATA_3, metadata_offsets[2])

    header[510:512] = SECTOR_SIGNATURE

    return bytes(header)


def read_volume_info(source: Union[str, Path, BinaryIO]) -> VolumeInfo:
    """Read volume info from a file path or file-like object.

    Args:
        source: A file path (str/Path) or an open binary file-like object.

    Returns:
        VolumeInfo with parsed volume metadata.
    """
    if isinstance(source, (str, Path)):
        with open(source, "rb") as fp:
            header = read_volume_header(fp)
    else:
        header = read_volume_header(source)

    return VolumeInfo(
        volume_type=header.volume_type,
        sector_size=header.bytes_per_sector,
        cluster_size=header.bytes_per_sector * header.sectors_per_cluster,
        metadata_offsets=header.fve_metadata_offsets,
        bitlocker_guid=header.bitlocker_guid,
    )
