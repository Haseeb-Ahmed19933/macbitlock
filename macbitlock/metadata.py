"""Parse FVE metadata blocks to extract VMK and FVEK entries."""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass
from typing import BinaryIO

from .constants import (
    FVE_METADATA_SIGNATURE,
    EncryptionMethod,
    KeyProtectionType,
    MetadataEntryType,
    MetadataValueType,
)

BLOCK_HEADER_SIZE = 64
METADATA_HEADER_SIZE = 48
ENTRY_HEADER_SIZE = 8


@dataclass
class MetadataBlockHeader:
    signature: bytes
    version: int
    encrypted_volume_size: int
    num_volume_header_sectors: int
    fve_block1_offset: int
    fve_block2_offset: int
    fve_block3_offset: int
    volume_header_offset: int


@dataclass
class MetadataHeader:
    metadata_size: int
    version: int
    header_size: int
    volume_id: uuid.UUID
    next_nonce_counter: int
    encryption_method: int
    creation_time: int


@dataclass
class MetadataEntry:
    entry_size: int
    entry_type: int
    value_type: int
    version: int
    raw_data: bytes


@dataclass
class VMKEntry:
    key_id: uuid.UUID
    protection_type: int
    salt: bytes
    nonce_time: int
    nonce_counter: int
    encrypted_data: bytes


@dataclass
class FVEKEntry:
    nonce_time: int
    nonce_counter: int
    encrypted_data: bytes


def _parse_block_header(data: bytes) -> MetadataBlockHeader:
    if len(data) < BLOCK_HEADER_SIZE:
        raise ValueError(
            f"Block header too short: {len(data)} < {BLOCK_HEADER_SIZE}"
        )

    sig = data[0:8]
    if sig != FVE_METADATA_SIGNATURE:
        raise ValueError(f"Invalid FVE signature: {sig!r}")

    version = struct.unpack_from("<H", data, 10)[0]
    enc_vol_size = struct.unpack_from("<Q", data, 16)[0]
    num_vh_sectors = struct.unpack_from("<I", data, 28)[0]
    blk1_off, blk2_off, blk3_off, vh_off = struct.unpack_from("<QQQQ", data, 32)

    return MetadataBlockHeader(
        signature=sig,
        version=version,
        encrypted_volume_size=enc_vol_size,
        num_volume_header_sectors=num_vh_sectors,
        fve_block1_offset=blk1_off,
        fve_block2_offset=blk2_off,
        fve_block3_offset=blk3_off,
        volume_header_offset=vh_off,
    )


def _parse_metadata_header(data: bytes) -> MetadataHeader:
    if len(data) < METADATA_HEADER_SIZE:
        raise ValueError(
            f"Metadata header too short: {len(data)} < {METADATA_HEADER_SIZE}"
        )

    (
        meta_size,
        version,
        header_size,
        _meta_size_copy,
    ) = struct.unpack_from("<IIII", data, 0)

    volume_id = uuid.UUID(bytes_le=data[16:32])
    next_nonce, enc_method, creation_time = struct.unpack_from("<IIQ", data, 32)

    return MetadataHeader(
        metadata_size=meta_size,
        version=version,
        header_size=header_size,
        volume_id=volume_id,
        next_nonce_counter=next_nonce,
        encryption_method=enc_method,
        creation_time=creation_time,
    )


def _parse_entries(data: bytes) -> list[MetadataEntry]:
    entries: list[MetadataEntry] = []
    offset = 0

    while offset + ENTRY_HEADER_SIZE <= len(data):
        entry_size, entry_type, value_type, version = struct.unpack_from(
            "<HHHH", data, offset
        )
        if entry_size < ENTRY_HEADER_SIZE:
            break
        if offset + entry_size > len(data):
            break

        raw_data = data[offset + ENTRY_HEADER_SIZE : offset + entry_size]
        entries.append(
            MetadataEntry(
                entry_size=entry_size,
                entry_type=entry_type,
                value_type=value_type,
                version=version,
                raw_data=raw_data,
            )
        )
        offset += entry_size

    return entries


def _parse_aes_ccm(data: bytes) -> tuple[int, int, bytes]:
    """Extract (nonce_time, nonce_counter, encrypted_data) from AES-CCM payload."""
    if len(data) < 12:
        raise ValueError("AES-CCM data too short")
    nonce_time = struct.unpack_from("<Q", data, 0)[0]
    nonce_counter = struct.unpack_from("<I", data, 8)[0]
    encrypted_data = data[12:]
    return nonce_time, nonce_counter, encrypted_data


def parse_metadata_block(
    data: bytes,
) -> tuple[MetadataBlockHeader, MetadataHeader, list[MetadataEntry]]:
    """Parse a full FVE metadata block into header, metadata header, and entries."""
    block_header = _parse_block_header(data[:BLOCK_HEADER_SIZE])
    meta_header = _parse_metadata_header(
        data[BLOCK_HEADER_SIZE : BLOCK_HEADER_SIZE + METADATA_HEADER_SIZE]
    )

    entries_offset = BLOCK_HEADER_SIZE + METADATA_HEADER_SIZE
    entries_end = BLOCK_HEADER_SIZE + meta_header.metadata_size
    entries = _parse_entries(data[entries_offset:entries_end])

    return block_header, meta_header, entries


def extract_vmk_entries(entries: list[MetadataEntry]) -> list[VMKEntry]:
    """Find all VMK entries and extract stretch key salt + AES-CCM encrypted data."""
    vmk_entries: list[VMKEntry] = []

    for entry in entries:
        if entry.entry_type != MetadataEntryType.VMK:
            continue
        if entry.value_type != MetadataValueType.VOLUME_MASTER_KEY:
            continue

        vmk_data = entry.raw_data
        if len(vmk_data) < 28:
            continue

        key_id = uuid.UUID(bytes_le=vmk_data[0:16])
        protection_type = struct.unpack_from("<H", vmk_data, 26)[0]

        salt = b""
        nonce_time = 0
        nonce_counter = 0
        encrypted_data = b""

        sub_entries = _parse_entries(vmk_data[28:])
        for sub in sub_entries:
            if sub.value_type == MetadataValueType.STRETCH_KEY:
                if len(sub.raw_data) < 20:
                    continue
                salt = sub.raw_data[4:20]

                nested = _parse_entries(sub.raw_data[20:])
                for n in nested:
                    if n.value_type == MetadataValueType.AES_CCM_ENCRYPTED_KEY:
                        nonce_time, nonce_counter, encrypted_data = _parse_aes_ccm(
                            n.raw_data
                        )
                        break

            elif sub.value_type == MetadataValueType.AES_CCM_ENCRYPTED_KEY:
                nonce_time, nonce_counter, encrypted_data = _parse_aes_ccm(
                    sub.raw_data
                )

        vmk_entries.append(
            VMKEntry(
                key_id=key_id,
                protection_type=protection_type,
                salt=salt,
                nonce_time=nonce_time,
                nonce_counter=nonce_counter,
                encrypted_data=encrypted_data,
            )
        )

    return vmk_entries


def extract_fvek_entry(entries: list[MetadataEntry]) -> FVEKEntry:
    """Find the FVEK entry and extract its AES-CCM encrypted data."""
    for entry in entries:
        if entry.entry_type != MetadataEntryType.FVEK:
            continue

        sub_entries = _parse_entries(entry.raw_data)
        for sub in sub_entries:
            if sub.value_type == MetadataValueType.AES_CCM_ENCRYPTED_KEY:
                nonce_time, nonce_counter, encrypted_data = _parse_aes_ccm(
                    sub.raw_data
                )
                return FVEKEntry(
                    nonce_time=nonce_time,
                    nonce_counter=nonce_counter,
                    encrypted_data=encrypted_data,
                )

        nonce_time, nonce_counter, encrypted_data = _parse_aes_ccm(entry.raw_data)
        return FVEKEntry(
            nonce_time=nonce_time,
            nonce_counter=nonce_counter,
            encrypted_data=encrypted_data,
        )

    raise ValueError("No FVEK entry found in metadata")


def read_metadata(
    fp: BinaryIO, offset: int
) -> tuple[MetadataBlockHeader, MetadataHeader, list[MetadataEntry]]:
    """Seek to *offset* in a file-like object and parse the FVE metadata block."""
    fp.seek(offset)

    header_bytes = fp.read(BLOCK_HEADER_SIZE + METADATA_HEADER_SIZE)
    if len(header_bytes) < BLOCK_HEADER_SIZE + METADATA_HEADER_SIZE:
        raise ValueError("Incomplete metadata block at offset {:#x}".format(offset))

    meta_header = _parse_metadata_header(header_bytes[BLOCK_HEADER_SIZE:])
    remaining = meta_header.metadata_size - METADATA_HEADER_SIZE
    if remaining > 0:
        entry_bytes = fp.read(remaining)
    else:
        entry_bytes = b""

    data = header_bytes + entry_bytes
    return parse_metadata_block(data)
