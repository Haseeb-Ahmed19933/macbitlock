"""
macbitlock - BitLocker Drive Encryption tool for macOS.

An open-source Python tool to decrypt (and eventually encrypt)
BitLocker-encrypted USB drives without requiring Windows.
"""

__version__ = "0.1.0"

from macbitlock.decryptor import decrypt_volume
from macbitlock.volume import VolumeInfo, read_volume_info

__all__ = ["decrypt_volume", "read_volume_info", "VolumeInfo"]
