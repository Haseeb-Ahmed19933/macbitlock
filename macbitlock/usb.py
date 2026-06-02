"""USB drive detection and direct device operations for macOS."""

import os
import plistlib
import subprocess
import sys
import tempfile
from dataclasses import dataclass


@dataclass
class USBDrive:
    device: str          # e.g. /dev/disk4
    partition: str       # e.g. /dev/disk4s1
    raw_partition: str   # e.g. /dev/rdisk4s1 (faster I/O)
    name: str            # e.g. TESTUSB
    size: int            # bytes
    filesystem: str      # e.g. FAT32, NTFS, ExFAT
    mount_point: str     # e.g. /Volumes/TESTUSB


def detect_usb_drives() -> list[USBDrive]:
    """Detect external USB drives with mountable partitions."""
    result = subprocess.run(
        ["diskutil", "list", "-plist", "external", "physical"],
        capture_output=True,
    )
    if result.returncode != 0:
        return []

    plist = plistlib.loads(result.stdout)
    whole_disks = plist.get("WholeDisks", [])

    drives = []
    for disk_id in whole_disks:
        drive = _inspect_disk(disk_id)
        if drive is not None:
            drives.append(drive)

    return drives


def _inspect_disk(disk_id: str) -> USBDrive | None:
    """Get details about a specific disk's data partition."""
    result = subprocess.run(
        ["diskutil", "info", "-plist", disk_id],
        capture_output=True,
    )
    if result.returncode != 0:
        return None

    # Find the data partition (skip EFI, Apple_*, etc.)
    list_result = subprocess.run(
        ["diskutil", "list", "-plist", disk_id],
        capture_output=True,
    )
    if list_result.returncode != 0:
        return None

    disk_plist = plistlib.loads(list_result.stdout)
    partitions = disk_plist.get("AllDisksAndPartitions", [])

    for disk_entry in partitions:
        for part in disk_entry.get("Partitions", []):
            content = part.get("Content", "")
            # Skip EFI, Apple partitions, Linux
            if content in ("EFI", "Apple_APFS", "Apple_HFS", "Linux"):
                continue
            if content in ("DOS_FAT_32", "DOS_FAT_16", "Microsoft Basic Data",
                           "Windows_NTFS", "ExFAT"):
                part_id = part.get("DeviceIdentifier", "")
                return _get_partition_info(part_id)

        # If no recognized partition, check if the whole disk is formatted directly
        content = disk_entry.get("Content", "")
        if content in ("DOS_FAT_32", "DOS_FAT_16"):
            part_id = disk_entry.get("DeviceIdentifier", "")
            return _get_partition_info(part_id)

    return None


def _get_partition_info(part_id: str) -> USBDrive | None:
    """Get detailed info about a specific partition."""
    result = subprocess.run(
        ["diskutil", "info", "-plist", part_id],
        capture_output=True,
    )
    if result.returncode != 0:
        return None

    info = plistlib.loads(result.stdout)
    device = f"/dev/{info.get('ParentWholeDisk', part_id)}"
    partition = f"/dev/{part_id}"
    raw_partition = f"/dev/r{part_id}"
    name = info.get("VolumeName", "") or info.get("MediaName", "Unknown")
    size = info.get("TotalSize", 0) or info.get("Size", 0)
    mount_point = info.get("MountPoint", "")

    fs_type = info.get("FilesystemType", "")
    fs_name = info.get("FilesystemName", "")
    if "FAT" in fs_type or "FAT" in fs_name:
        filesystem = "FAT32"
    elif "NTFS" in fs_type or "NTFS" in fs_name:
        filesystem = "NTFS"
    elif "ExFAT" in fs_type or "ExFAT" in fs_name:
        filesystem = "ExFAT"
    else:
        filesystem = fs_type or "Unknown"

    return USBDrive(
        device=device,
        partition=partition,
        raw_partition=raw_partition,
        name=name,
        size=size,
        filesystem=filesystem,
        mount_point=mount_point,
    )


def unmount_partition(partition: str) -> bool:
    """Unmount a partition (keeps device accessible for raw I/O)."""
    result = subprocess.run(
        ["diskutil", "unmount", partition],
        capture_output=True, text=True,
    )
    return result.returncode == 0


def mount_partition(partition: str) -> bool:
    """Re-mount a partition. Returns False if mount fails (e.g. unrecognized filesystem)."""
    try:
        result = subprocess.run(
            ["diskutil", "mount", partition],
            capture_output=True, text=True,
            timeout=5,
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def check_root() -> bool:
    """Check if running as root (required for raw device access)."""
    return os.geteuid() == 0


def format_size(size_bytes: int) -> str:
    """Format bytes as human-readable size."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} PB"
