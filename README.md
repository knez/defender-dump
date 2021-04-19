# defender-dump

Dump quarantined files from Windows Defender

## Usage

### On Windows

List quarantine files located on disk C

```cmd
> python3 defender-dump.py C:\
```

Dump quarantine files from disk C into local folder **malware**

```cmd
> python3 defender-dump.py C:\ --dump malware
```

List quarantine files located on disk G, mounted with FTK Imager using the **File System/Read Only** method

```cmd
> python3 defender-dump.py G:\[root]\
```

### On Linux

List quarantine files from a mounted windows partition on `/mnt/win`

```bash
$ ./defender-dump.py /mnt/win
```

## Contributing
Pull requests are welcome. 

## License
[MIT](https://choosealicense.com/licenses/mit/)
