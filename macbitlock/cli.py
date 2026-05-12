"""CLI interface for BitLocker decryption tool."""

import sys
import time
import click

from .decryptor import decrypt_volume, get_volume_info, DecryptionError


def format_size(size_bytes: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} PB"


@click.group()
@click.version_option(version="0.1.0", prog_name="macbitlock")
def main():
    """macbitlock - BitLocker encryption tool for macOS.

    Decrypt BitLocker-encrypted USB drives and disk images without Windows.
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
