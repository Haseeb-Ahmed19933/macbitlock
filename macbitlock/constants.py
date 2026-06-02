"""BitLocker constants, magic values, and enumerations."""

from enum import IntEnum


SECTOR_SIZE = 512
SECTOR_SIGNATURE = b"\x55\xAA"
BOOT_ENTRY_POINT = b"\xeb\x58\x90"

FVE_METADATA_SIGNATURE = b"-FVE-FS-"
FAT32_OEM_SIGNATURE = b"MSWIN4.1"
FAT32_FS_SIGNATURE = b"FAT32   "

BITLOCKER_GUID = "4967d63b-2e29-4ad8-8399-f6a339e3d001"


# Volume header field offsets for NTFS-based BitLocker volumes
class NTFSOffsets:
    BOOT_ENTRY = 0
    FS_SIGNATURE = 3
    BYTES_PER_SECTOR = 11
    SECTORS_PER_CLUSTER = 13
    BITLOCKER_GUID = 160
    FVE_METADATA_1 = 176
    FVE_METADATA_2 = 184
    FVE_METADATA_3 = 192
    SECTOR_SIGNATURE = 510


# Volume header field offsets for FAT32-based BitLocker To Go volumes
class FAT32Offsets:
    BOOT_ENTRY = 0
    OEM_SIGNATURE = 3
    BYTES_PER_SECTOR = 11
    SECTORS_PER_CLUSTER = 13
    VOLUME_SERIAL = 67
    VOLUME_LABEL = 71
    FS_SIGNATURE = 82
    BITLOCKER_GUID = 424
    FVE_METADATA_1 = 440
    FVE_METADATA_2 = 448
    FVE_METADATA_3 = 456
    SECTOR_SIGNATURE = 510


class EncryptionMethod(IntEnum):
    AES_CBC_128_DIFFUSER = 0x8000
    AES_CBC_256_DIFFUSER = 0x8001
    AES_CBC_128 = 0x8002
    AES_CBC_256 = 0x8003
    AES_XTS_128 = 0x8004
    AES_XTS_256 = 0x8005


# Algorithm identifier for AES-256 key wrapping (stored inside VMK containers)
KEY_WRAP_ALGORITHM_AES256 = 0x2003


class KeyProtectionType(IntEnum):
    CLEAR_KEY = 0x0000
    TPM = 0x0100
    STARTUP_KEY = 0x0200
    TPM_AND_PIN = 0x0500
    RECOVERY_PASSWORD = 0x0800
    PASSWORD = 0x2000


# Alias used by decryptor module
ProtectionType = KeyProtectionType


class MetadataEntryType(IntEnum):
    VMK = 0x0002
    FVEK = 0x0003
    VALIDATION = 0x0004
    STARTUP_KEY = 0x0006
    DESCRIPTION = 0x0007
    VOLUME_HEADER_BLOCK = 0x000F


class MetadataValueType(IntEnum):
    ERASED = 0x0000
    KEY = 0x0001
    UNICODE_STRING = 0x0002
    STRETCH_KEY = 0x0003
    USE_KEY = 0x0004
    AES_CCM_ENCRYPTED_KEY = 0x0005
    TPM_ENCODED_KEY = 0x0006
    VALIDATION = 0x0007
    VOLUME_MASTER_KEY = 0x0008
    EXTERNAL_KEY = 0x0009
    OFFSET_AND_SIZE = 0x000F
