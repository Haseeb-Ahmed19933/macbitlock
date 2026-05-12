# macbitlock

**BitLocker, but for macOS.**

An open-source Python tool to decrypt BitLocker-encrypted USB drives, external hard drives, and disk images on your Mac.

---

## Why macbitlock?

macOS cannot read BitLocker-encrypted drives. macbitlock is a free, open-source command-line tool that handles the decryption for you.

---

## Features

- Decrypt BitLocker To Go encrypted USB drives and external volumes
- Supports password and recovery key (48-digit) authentication
- Works with raw devices (`/dev/diskXsY`), VHD files, and raw disk images
- Handles MBR partition tables and VHD containers automatically
- Full support for all BitLocker encryption modes:
  - AES-XTS 128-bit and 256-bit (Windows 10 and later)
  - AES-CBC 128-bit and 256-bit
  - AES-CBC with Elephant Diffuser (Windows 7 legacy)
- Compatible with both NTFS and FAT32 encrypted volumes
- Tested on Apple Silicon (M1, M2, M3, M4) Macs. Intel Macs are not tested but should work since the implementation is pure Python.
- Progress indicator during decryption
- Volume inspection command to view encryption details before decrypting

---

## Supported BitLocker Versions

| Windows Version | Encryption Mode | Status |
|-----------------|-----------------|--------|
| Windows 7 | AES-CBC + Elephant Diffuser | Supported |
| Windows 8 / 8.1 | AES-CBC 128/256 | Supported |
| Windows 10 | AES-XTS 128/256 | Supported |
| Windows 10 (compatible mode) | AES-CBC 128 | Supported |
| Windows 11 | AES-XTS 128/256 | Supported |

Both "encrypt entire drive" and "encrypt used space only" modes are supported.

---

## Prerequisites

You need the following installed on your Mac before using macbitlock:

### Python 3.9 or later

macOS does not ship with Python 3 by default. Check if you already have it:

```bash
python3 --version
```

If you get "command not found" or a version older than 3.9, install Python 3 using one of these methods:

**Option A: Homebrew (recommended)**

```bash
brew install python@3
```

If you do not have Homebrew installed, get it from [brew.sh](https://brew.sh).

**Option B: Official installer**

Download the macOS installer from [python.org/downloads](https://www.python.org/downloads/).

### Git

Git is needed to clone the repository. macOS includes Git as part of the Xcode Command Line Tools. If you do not have it:

```bash
xcode-select --install
```

### pip

pip comes bundled with Python 3 from the methods above. Verify:

```bash
pip3 --version
```

No other system-level tools are required. Everything else is handled by Python packages.

---

## Installation

```bash
git clone https://github.com/Haseeb-Ahmed19933/macbitlock.git
cd macbitlock
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Usage

### Decrypt a BitLocker USB drive

1. Plug in the BitLocker-encrypted USB drive.
2. Find the device identifier:

```bash
diskutil list
```

Look for the partition labeled `Microsoft Basic Data` or similar. It will be something like `/dev/disk4s1`.

3. Decrypt with a password:

```bash
python -m macbitlock decrypt /dev/disk4s1 -p "your_password" -o decrypted.img
```

Or with a recovery key:

```bash
python -m macbitlock decrypt /dev/disk4s1 -r "123456-789012-345678-901234-567890-123456-789012-345678" -o decrypted.img
```

4. Mount the decrypted image:

```bash
hdiutil attach -imagekey diskimage-class=CRawDiskImage decrypted.img
```

The volume will appear in Finder like any normal drive. You can copy files from it freely.

### Decrypt a VHD or disk image file

```bash
python -m macbitlock decrypt path/to/encrypted.vhd -p "your_password" -o decrypted.img
```

### Inspect volume information

View encryption details without decrypting:

```bash
python -m macbitlock info /dev/disk4s1
```

This displays the volume type, encryption method, sector size, and key protection types.

---

## Command Reference

### `macbitlock decrypt`

Decrypt a BitLocker-encrypted volume or disk image.

| Option | Description |
|--------|-------------|
| `SOURCE` | Path to the encrypted device or image file (required) |
| `-p`, `--password` | BitLocker password |
| `-r`, `--recovery-key` | 48-digit recovery key with dashes |
| `-o`, `--output` | Output path for the decrypted image (required) |

Either `--password` or `--recovery-key` must be provided.

### `macbitlock info`

Display information about a BitLocker-encrypted volume.

| Option | Description |
|--------|-------------|
| `SOURCE` | Path to the encrypted device or image file (required) |

---

## How It Works

BitLocker uses a layered encryption architecture:

1. The volume data is encrypted with a **Full Volume Encryption Key (FVEK)** using AES.
2. The FVEK is encrypted by a **Volume Master Key (VMK)** using AES-CCM.
3. The VMK is protected by a **key protector** -- either a password or recovery key.

When you provide your password, macbitlock:

1. Reads the BitLocker metadata from the volume header.
2. Derives an intermediate key from your password using SHA-256 key stretching (1,048,576 iterations).
3. Unwraps the VMK using AES-CCM authenticated decryption.
4. Unwraps the FVEK using the VMK.
5. Decrypts every sector of the volume using the FVEK and the appropriate AES mode.
6. Restores the original volume header (which BitLocker replaces with its own boot code).

---

## Project Structure

```
macbitlock/
    __init__.py       Package entry point
    __main__.py       Enables python -m macbitlock
    cli.py            Command-line interface (click-based)
    constants.py      BitLocker magic values and enumerations
    volume.py         Volume header parsing (NTFS and FAT32)
    metadata.py       FVE metadata block parsing
    keys.py           Key derivation, stretching, and unwrapping
    crypto.py         AES-XTS, AES-CBC, and Elephant Diffuser decryption
    partition.py      MBR and VHD container detection
    decryptor.py      High-level decryption orchestrator
requirements.txt      Python dependencies
```

---

## Roadmap

- **Phase 1 (current):** BitLocker decryption on macOS -- password and recovery key support
- **Phase 2:** BitLocker encryption -- create BitLocker To Go volumes from macOS
- **Phase 3:** macOS GUI app -- drag-and-drop interface for encrypt and decrypt

---

## Frequently Asked Questions

### Does this work on Apple Silicon Macs?

Yes. macbitlock has been tested on Apple Silicon (M1/M2/M3/M4). It is pure Python, so Intel Macs should also work, but this has not been tested.

### Can I mount the USB directly without creating an image file?

Not yet. Currently macbitlock decrypts to a disk image, which you then mount with `hdiutil`. Direct FUSE-based mounting is on the roadmap.

### Is this safe to use with important data?

macbitlock only reads from the encrypted volume. It never writes to the source device. Your encrypted drive is not modified in any way.

### Does this support TPM-only BitLocker?

Not currently. macbitlock supports password and recovery key protectors, which are the standard methods for BitLocker To Go (removable drives). TPM-based protectors are typically used with internal system drives and require hardware that macOS does not have access to.

### What is the difference between "encrypt entire drive" and "encrypt used space only"?

Both modes are supported. The tool decrypts the full volume regardless of which option was used during encryption.

---

## Dependencies

- [cryptography](https://cryptography.io/) -- AES-XTS, AES-CBC, and AES-CCM operations
- [click](https://click.palletsprojects.com/) -- command-line interface

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Contributing

Contributions are welcome. Please open an issue to discuss significant changes before submitting a pull request.

---

## Related Projects

- [dislocker](https://github.com/Aorimn/dislocker) -- C-based BitLocker decryption for Linux (FUSE-based)
- [libbde](https://github.com/libyal/libbde) -- BitLocker Drive Encryption library by Joachim Metz
- [BitCracker](https://github.com/e-ago/bitcracker) -- BitLocker password cracking tool

---

## Keywords

BitLocker macOS, BitLocker Mac, decrypt BitLocker on Mac, BitLocker USB Mac, BitLocker Apple Silicon, BitLocker M1 M2 M3 M4, open source BitLocker, free BitLocker Mac, BitLocker To Go macOS, BitLocker decryption tool, read BitLocker drive on Mac, BitLocker Python
