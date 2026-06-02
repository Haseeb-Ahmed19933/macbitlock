"""CLI interface for macbitlock."""

import sys
import time
import click

from .decryptor import decrypt_volume, get_volume_info, DecryptionError
from .encryptor import encrypt_volume, encrypt_device_inplace, EncryptionError
from .constants import EncryptionMethod
from .usb import detect_usb_drives, unmount_partition, mount_partition, check_root


def format_size(size_bytes: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} PB"


@click.group()
@click.version_option(version="0.2.0", prog_name="macbitlock")
def main():
    """macbitlock - BitLocker encryption and decryption tool for macOS.

    Encrypt and decrypt BitLocker-encrypted USB drives and disk images without Windows.
    """
    pass


@main.command()
@click.argument("source", type=click.Path(exists=True))
def info(source):
    """Display information about a BitLocker-encrypted volume."""
    try:
        volume_info = get_volume_info(source)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    click.echo(f"Volume Type:        {volume_info.get('volume_type', 'Unknown')}")
    click.echo(f"Sector Size:        {volume_info.get('sector_size', 'Unknown')} bytes")
    click.echo(f"Cluster Size:       {volume_info.get('cluster_size', 'Unknown')} bytes")
    click.echo(f"BitLocker GUID:     {volume_info.get('bitlocker_guid', 'Unknown')}")

    if "encryption_method" in volume_info:
        click.echo(f"Encryption Method:  {volume_info['encryption_method']}")
    if "encrypted_volume_size" in volume_info:
        click.echo(
            f"Encrypted Size:     {format_size(volume_info['encrypted_volume_size'])}"
        )
    if "volume_id" in volume_info:
        click.echo(f"Volume ID:          {volume_info['volume_id']}")
    if "protection_types" in volume_info:
        click.echo(f"Protection Types:   {', '.join(volume_info['protection_types'])}")

    click.echo(f"\nMetadata Offsets:")
    for i, offset in enumerate(volume_info.get("metadata_offsets", []), 1):
        click.echo(f"  Block {i}: 0x{offset:X} ({format_size(offset)})")


@main.command()
@click.argument("source", type=click.Path(exists=True))
@click.option("--password", "-p", help="BitLocker password")
@click.option("--recovery-key", "-r", help="BitLocker recovery key (48 digits with dashes)")
@click.option(
    "--output",
    "-o",
    required=True,
    type=click.Path(),
    help="Output path for decrypted image",
)
def decrypt(source, password, recovery_key, output):
    """Decrypt a BitLocker-encrypted volume or disk image.

    SOURCE is the path to the encrypted volume (/dev/diskXsY) or image file.
    """
    if not password and not recovery_key:
        click.echo("Error: Either --password or --recovery-key must be provided", err=True)
        sys.exit(1)

    start_time = time.time()
    last_update = [0]

    def progress(done, total):
        now = time.time()
        if now - last_update[0] < 0.5:
            return
        last_update[0] = now
        pct = (done / total) * 100 if total > 0 else 0
        bar_len = 40
        filled = int(bar_len * done // total)
        bar = "=" * filled + "-" * (bar_len - filled)
        click.echo(
            f"\r  [{bar}] {pct:.1f}% ({format_size(done)}/{format_size(total)})",
            nl=False,
        )

    click.echo(f"Decrypting: {source}")
    click.echo(f"Output:     {output}")
    click.echo()

    try:
        decrypt_volume(
            source,
            output,
            password=password,
            recovery_key=recovery_key,
            progress_callback=progress,
        )
    except DecryptionError as e:
        click.echo(f"\nError: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"\nUnexpected error: {e}", err=True)
        sys.exit(1)

    elapsed = time.time() - start_time
    click.echo(f"\n\nDecryption complete in {elapsed:.1f}s")
    click.echo(f"Output written to: {output}")
    click.echo(f"\nTo mount on macOS:")
    click.echo(f"  hdiutil attach -imagekey diskimage-class=CRawDiskImage {output}")


ENCRYPTION_METHODS = {
    "aes-xts-128": EncryptionMethod.AES_XTS_128,
    "aes-xts-256": EncryptionMethod.AES_XTS_256,
    "aes-cbc-128": EncryptionMethod.AES_CBC_128,
    "aes-cbc-256": EncryptionMethod.AES_CBC_256,
}


@main.command()
@click.argument("source", type=click.Path(exists=True))
@click.option("--password", "-p", required=True, help="BitLocker password to set")
@click.option(
    "--output",
    "-o",
    required=True,
    type=click.Path(),
    help="Output path for encrypted image",
)
@click.option(
    "--method",
    "-m",
    type=click.Choice(list(ENCRYPTION_METHODS.keys()), case_sensitive=False),
    default="aes-xts-128",
    help="Encryption method (default: aes-xts-128)",
)
def encrypt(source, password, output, method):
    """Encrypt a volume or disk image with BitLocker.

    SOURCE is the path to the unencrypted volume (/dev/diskXsY) or image file.
    A recovery key will be generated and displayed -- save it somewhere safe.
    """
    enc_method = ENCRYPTION_METHODS[method.lower()]

    start_time = time.time()
    last_update = [0]

    def progress(done, total):
        now = time.time()
        if now - last_update[0] < 0.5:
            return
        last_update[0] = now
        pct = (done / total) * 100 if total > 0 else 0
        bar_len = 40
        filled = int(bar_len * done // total)
        bar = "=" * filled + "-" * (bar_len - filled)
        click.echo(
            f"\r  [{bar}] {pct:.1f}% ({format_size(done)}/{format_size(total)})",
            nl=False,
        )

    click.echo(f"Encrypting: {source}")
    click.echo(f"Output:     {output}")
    click.echo(f"Method:     {method}")
    click.echo()

    try:
        result = encrypt_volume(
            source,
            output,
            password=password,
            encryption_method=enc_method,
            progress_callback=progress,
        )
    except EncryptionError as e:
        click.echo(f"\nError: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"\nUnexpected error: {e}", err=True)
        sys.exit(1)

    elapsed = time.time() - start_time
    click.echo(f"\n\nEncryption complete in {elapsed:.1f}s")
    click.echo(f"Output written to: {output}")
    click.echo(f"Encryption method: {result['encryption_method']}")
    click.echo(f"Volume ID: {result['volume_id']}")
    click.echo(f"\n{'=' * 60}")
    click.echo(f"RECOVERY KEY (save this somewhere safe!):")
    click.echo(f"  {result['recovery_key']}")
    click.echo(f"{'=' * 60}")


def _make_progress_fn():
    """Create a progress callback that shows a progress bar."""
    last_update = [0]

    def progress(done, total):
        now = time.time()
        if now - last_update[0] < 0.3:
            return
        last_update[0] = now
        pct = (done / total) * 100 if total > 0 else 0
        bar_len = 40
        filled = int(bar_len * done // total) if total > 0 else 0
        bar = "=" * filled + "-" * (bar_len - filled)
        click.echo(
            f"\r  [{bar}] {pct:.1f}% ({format_size(done)}/{format_size(total)})",
            nl=False,
        )

    return progress



@main.command("encrypt-usb")
def encrypt_usb():
    """Encrypt a USB drive with BitLocker (interactive).

    Detects connected USB drives, encrypts the selected one in-place,
    and produces a BitLocker-encrypted drive that Windows can unlock.

    Requires root access. Run with: sudo python -m macbitlock encrypt-usb
    """
    # Step 0: Check root
    if not check_root():
        click.echo("This command requires root access for raw disk operations.")
        click.echo("Please run with sudo:")
        click.echo()
        click.echo("  sudo python -m macbitlock encrypt-usb")
        sys.exit(1)

    # Step 1: Detect USB drives
    click.echo("Scanning for external USB drives...")
    drives = detect_usb_drives()

    if not drives:
        click.echo("No external USB drives found.", err=True)
        sys.exit(1)

    # Step 2: Select drive (auto-select if only one)
    if len(drives) == 1:
        drive = drives[0]
        click.echo(f"\nFound 1 drive:")
        click.echo(f"  {drive.name} ({format_size(drive.size)}, {drive.filesystem}) - {drive.partition}")
        if not click.confirm("\nEncrypt this drive?", default=True):
            click.echo("Aborted.")
            sys.exit(0)
    else:
        click.echo(f"\nFound {len(drives)} drives:")
        for i, d in enumerate(drives, 1):
            click.echo(f"  {i}. {d.name} ({format_size(d.size)}, {d.filesystem}) - {d.partition}")
        choice = click.prompt(
            "\nSelect drive number",
            type=click.IntRange(1, len(drives)),
        )
        drive = drives[choice - 1]

    # Step 3: Filesystem check
    if drive.filesystem not in ("FAT32", "NTFS"):
        click.echo(f"\nUnsupported filesystem: {drive.filesystem}. Only FAT32 and NTFS are supported.", err=True)
        sys.exit(1)

    # Step 4: Encryption mode -- full drive or used space only
    click.echo(f"\nHow much of the drive do you want to encrypt?")
    click.echo(f"  1. Encrypt used disk space only (faster, recommended for new drives)")
    click.echo(f"  2. Encrypt entire drive (slower, recommended if drive previously had data)")
    mode_choice = click.prompt(
        "\nSelect option",
        type=click.IntRange(1, 2),
        default=1,
    )
    encrypt_full_drive = (mode_choice == 2)

    # Step 5: Confirm -- this is destructive
    mode_label = "entire drive" if encrypt_full_drive else "used space only"
    click.echo(f"\nWARNING: This will encrypt the contents of:")
    click.echo(f"  Drive:      {drive.name}")
    click.echo(f"  Device:     {drive.partition}")
    click.echo(f"  Size:       {format_size(drive.size)}")
    click.echo(f"  Filesystem: {drive.filesystem}")
    click.echo(f"  Mode:       {mode_label}")
    if drive.mount_point:
        click.echo(f"  Mounted at: {drive.mount_point}")
    click.echo()

    if not click.confirm("Are you sure you want to continue?", default=False):
        click.echo("Aborted.")
        sys.exit(0)

    # Step 6: Get password
    password = click.prompt("Enter BitLocker password", hide_input=True)
    password_confirm = click.prompt("Confirm password", hide_input=True)
    if password != password_confirm:
        click.echo("Passwords do not match.", err=True)
        sys.exit(1)

    if len(password) < 8:
        click.echo("Password must be at least 8 characters.", err=True)
        sys.exit(1)

    # Step 7: Unmount
    raw_device = drive.raw_partition

    click.echo(f"\nUnmounting {drive.partition}...")
    if drive.mount_point:
        if not unmount_partition(drive.partition):
            click.echo("Failed to unmount drive.", err=True)
            sys.exit(1)
    click.echo("  Done.")

    # Step 8: Encrypt directly on the device (in-place, no temp files needed)
    # Show how much data will actually be encrypted
    if not encrypt_full_drive:
        from .encryptor import _detect_source_fs, _get_used_regions_fat32, NUM_HEADER_SECTORS, SECTOR_SIZE as _SS
        import struct as _struct
        with open(raw_device, "rb") as _fp:
            _s0 = _fp.read(512)
            _fs = _detect_source_fs(_s0)
            _sec_size = _struct.unpack_from("<H", _s0, 11)[0] or _SS
            if _fs == "FAT32":
                _regions = _get_used_regions_fat32(_fp, _s0, drive.size, _sec_size)
                _used_total = sum(e - s for s, e in _regions)
                click.echo(f"\n  Detected filesystem: {_fs}")
                click.echo(f"  Used regions: {len(_regions)} region(s), {format_size(_used_total)} total")
            else:
                click.echo(f"\n  Detected filesystem: {_fs} (will encrypt full drive)")

    click.echo(f"\nEncrypting ({mode_label})...")
    start_time = time.time()
    result = None

    try:
        result = encrypt_device_inplace(
            raw_device,
            drive.size,
            password=password,
            encryption_method=EncryptionMethod.AES_CBC_128,
            encrypt_full_drive=encrypt_full_drive,
            progress_callback=_make_progress_fn(),
        )
    except OSError as e:
        click.echo(f"\n\nEncryption failed: {e}", err=True)
        click.echo("WARNING: Drive may be in an inconsistent state.", err=True)
        sys.exit(1)
    except EncryptionError as e:
        click.echo(f"\n\nEncryption failed: {e}", err=True)
        sys.exit(1)

    elapsed = time.time() - start_time
    click.echo(f"\n  Encryption complete in {elapsed:.1f}s")

    # Remount the drive (we unmounted it, so we put it back)
    mount_partition(drive.partition)

    # Done
    click.echo(f"\n{'=' * 60}")
    click.echo(f"ENCRYPTION COMPLETE")
    click.echo(f"{'=' * 60}")
    click.echo(f"  Drive:      {drive.name} ({drive.partition})")
    click.echo(f"  Mode:       {mode_label}")
    click.echo(f"  Method:     {result['encryption_method']}")
    click.echo(f"  Volume ID:  {result['volume_id']}")
    click.echo(f"")
    click.echo(f"  RECOVERY KEY (save this somewhere safe!):")
    click.echo(f"  {result['recovery_key']}")
    click.echo(f"{'=' * 60}")
    click.echo(f"\nDone.")
