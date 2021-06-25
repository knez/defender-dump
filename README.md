# defender-dump

Dump quarantined files from Windows Defender

![](demo.gif)

## Description

Forensically list and extract quarantined files from a mounted disk. Extracted files are put into a tar archive in order to prevent accidental triggering of Defender Real-time protection.

## Usage

### On Windows

List quarantine files located on disk C

```cmd
> python3 defender-dump.py C:\
```

Dump quarantine files from disk C into archive `quarantine.tar`

```cmd
> python3 defender-dump.py C:\ --dump
```

List quarantine files located on disk G, mounted with FTK Imager using the **File System/Read Only** method

```cmd
> python3 defender-dump.py G:\[root]\
```

### On Linux

List quarantine files from a mounted windows partition on `/mnt/win`

```bash
> ./defender-dump.py /mnt/win
```

## Limitation

The script will list and export only entries of the type "FILE". Any other types (like Registry) are not yet supported.

## License
[MIT](https://choosealicense.com/licenses/mit/)
