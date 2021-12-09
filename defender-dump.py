#!/usr/bin/env python3

'''
Dumps quarantined files from Windows Defender
By Nikola Knežević - 2021

Inspired by https://github.com/ernw/quarantine-formats
'''

import io
import struct
import argparse
import datetime
import pathlib
import tarfile

from collections import namedtuple
file_record = namedtuple("file_record", "path hash detection filetime")

def mse_ksa():
    # hardcoded key obtained from mpengine.dll
    key = [
        0x1E, 0x87, 0x78, 0x1B, 0x8D, 0xBA, 0xA8, 0x44, 0xCE, 0x69,
        0x70, 0x2C, 0x0C, 0x78, 0xB7, 0x86, 0xA3, 0xF6, 0x23, 0xB7,
        0x38, 0xF5, 0xED, 0xF9, 0xAF, 0x83, 0x53, 0x0F, 0xB3, 0xFC,
        0x54, 0xFA, 0xA2, 0x1E, 0xB9, 0xCF, 0x13, 0x31, 0xFD, 0x0F,
        0x0D, 0xA9, 0x54, 0xF6, 0x87, 0xCB, 0x9E, 0x18, 0x27, 0x96,
        0x97, 0x90, 0x0E, 0x53, 0xFB, 0x31, 0x7C, 0x9C, 0xBC, 0xE4,
        0x8E, 0x23, 0xD0, 0x53, 0x71, 0xEC, 0xC1, 0x59, 0x51, 0xB8,
        0xF3, 0x64, 0x9D, 0x7C, 0xA3, 0x3E, 0xD6, 0x8D, 0xC9, 0x04,
        0x7E, 0x82, 0xC9, 0xBA, 0xAD, 0x97, 0x99, 0xD0, 0xD4, 0x58,
        0xCB, 0x84, 0x7C, 0xA9, 0xFF, 0xBE, 0x3C, 0x8A, 0x77, 0x52,
        0x33, 0x55, 0x7D, 0xDE, 0x13, 0xA8, 0xB1, 0x40, 0x87, 0xCC,
        0x1B, 0xC8, 0xF1, 0x0F, 0x6E, 0xCD, 0xD0, 0x83, 0xA9, 0x59,
        0xCF, 0xF8, 0x4A, 0x9D, 0x1D, 0x50, 0x75, 0x5E, 0x3E, 0x19,
        0x18, 0x18, 0xAF, 0x23, 0xE2, 0x29, 0x35, 0x58, 0x76, 0x6D,
        0x2C, 0x07, 0xE2, 0x57, 0x12, 0xB2, 0xCA, 0x0B, 0x53, 0x5E,
        0xD8, 0xF6, 0xC5, 0x6C, 0xE7, 0x3D, 0x24, 0xBD, 0xD0, 0x29,
        0x17, 0x71, 0x86, 0x1A, 0x54, 0xB4, 0xC2, 0x85, 0xA9, 0xA3,
        0xDB, 0x7A, 0xCA, 0x6D, 0x22, 0x4A, 0xEA, 0xCD, 0x62, 0x1D,
        0xB9, 0xF2, 0xA2, 0x2E, 0xD1, 0xE9, 0xE1, 0x1D, 0x75, 0xBE,
        0xD7, 0xDC, 0x0E, 0xCB, 0x0A, 0x8E, 0x68, 0xA2, 0xFF, 0x12,
        0x63, 0x40, 0x8D, 0xC8, 0x08, 0xDF, 0xFD, 0x16, 0x4B, 0x11,
        0x67, 0x74, 0xCD, 0x0B, 0x9B, 0x8D, 0x05, 0x41, 0x1E, 0xD6,
        0x26, 0x2E, 0x42, 0x9B, 0xA4, 0x95, 0x67, 0x6B, 0x83, 0x98,
        0xDB, 0x2F, 0x35, 0xD3, 0xC1, 0xB9, 0xCE, 0xD5, 0x26, 0x36,
        0xF2, 0x76, 0x5E, 0x1A, 0x95, 0xCB, 0x7C, 0xA4, 0xC3, 0xDD,
        0xAB, 0xDD, 0xBF, 0xF3, 0x82, 0x53
    ]
    sbox = list(range(256))
    j = 0
    for i in range(256):
        j = (j + sbox[i] + key[i]) % 256
        tmp = sbox[i]
        sbox[i] = sbox[j]
        sbox[j] = tmp
    return sbox

def rc4_decrypt(data):
    sbox = mse_ksa()
    out = bytearray(len(data))
    i = 0
    j = 0
    for k in range(len(data)):
        i = (i + 1) % 256
        j = (j + sbox[i]) % 256
        tmp = sbox[i]
        sbox[i] = sbox[j]
        sbox[j] = tmp
        val = sbox[(sbox[i] + sbox[j]) % 256]
        out[k] = val ^ data[k]

    return out

def unpack_malware(f):

    decrypted = rc4_decrypt(f.read())
    sd_len = struct.unpack_from('<I', decrypted, 0x8)[0]
    header_len = 0x28 + sd_len
    malfile_len = struct.unpack_from('<Q', decrypted, sd_len + 0x1C)[0]
    malfile = decrypted[header_len:header_len + malfile_len]

    return (malfile, malfile_len)

def dump_entries(basedir, entries):

    tar = tarfile.open('quarantine.tar', 'w')

    for file_rec in entries:
        quarfile = basedir / 'ResourceData' / file_rec.hash[:2] / file_rec.hash

        if not quarfile.exists():
            continue

        with open(quarfile, 'rb') as f:

            print(f'Exporting {file_rec.path.name}')
            malfile, malfile_len = unpack_malware(f)

            tarinfo = tarfile.TarInfo(file_rec.path.name)
            tarinfo.size = malfile_len
            tar.addfile(tarinfo, io.BytesIO(malfile))

    tar.close()

    print("File 'quarantine.tar' successfully created")

def get_entry(data):

    # extract path as a null-terminated UTF-16 string
    pos = data.find(b'\x00\x00\x00') + 1
    path_str = data[:pos].decode('utf-16le')

    # normalize the path
    if path_str[2:4] == '?\\':
        path_str = path_str[4:]

    path = pathlib.PureWindowsPath(path_str)

    pos += 4  # skip number of entries field
    type_len = data[pos:].find(b'\x00')
    type = data[pos:pos + type_len].decode()  # get entry Type (UTF-8)
    pos += type_len + 1
    pos += (4 - pos) % 4  # skip padding bytes
    pos += 4  # skip additional metadata
    hash = data[pos:pos + 20].hex().upper()

    return (path, hash, type)

def parse_entries(basedir):

    results = []
    for guid in basedir.glob('Entries/{*}'):
        with open(guid, 'rb') as f:
            header = rc4_decrypt(f.read(0x3c))
            data1_len, data2_len = struct.unpack_from('<II', header, 0x28)

            data1 = rc4_decrypt(f.read(data1_len))
            filetime, = struct.unpack('<Q', data1[0x20:0x28])
            filetime = datetime.datetime(1970, 1, 1) + datetime.timedelta(microseconds=filetime // 10 - 11644473600000000)
            detection = data1[0x34:].decode('utf8')

            data2 = rc4_decrypt(f.read(data2_len))
            cnt = struct.unpack_from('<I', data2)[0]
            offsets = struct.unpack_from('<' + str(cnt) + 'I', data2, 0x4)

            for o in offsets:
                path, hash, type = get_entry(data2[o:])
                if type == 'file':
                    results.append(file_record(path, hash, detection, filetime))

    return results

def main(args):

    basedir = args.rootdir / 'ProgramData/Microsoft/Windows Defender/Quarantine'

    entries = parse_entries(basedir)

    if args.dump:
        # export quarantine files
        dump_entries(basedir, entries)
    else:
        # display quarantine files
        detection_max_len = max([len(x[2]) for x in entries])
        for entry in entries:
            print(entry.filetime, f"{entry.detection:<{detection_max_len}}", entry.path)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
           description='Dump quarantined files from Windows Defender'
    )
    parser.add_argument(
            'rootdir', type=pathlib.Path,
            help='root directory where Defender is installed (example C:\)'
    )
    parser.add_argument(
            '-d', '--dump', action='store_true',
            help='dump all entries into tar archive (quarantine.tar)'
    )

    main(parser.parse_args())
