#!/usr/bin/env python3
"""Validate Android AArch64 ELF shared objects without executing untrusted code."""
import argparse
import pathlib
import struct
import sys


def verify(path: pathlib.Path) -> None:
    data = path.read_bytes()
    if len(data) < 64 or data[:4] != bytes((0x7f, 0x45, 0x4c, 0x46)):
        raise ValueError("not an ELF file")
    if data[4] != 2:
        raise ValueError("not ELF64")
    if data[5] != 1:
        raise ValueError("not little-endian ELF")
    kind, machine = struct.unpack_from("<HH", data, 16)
    if kind != 3:
        raise ValueError("not a shared object (ET_DYN)")
    if machine != 183:
        raise ValueError("not AArch64 (EM_AARCH64)")
    if data[6] != 1:
        raise ValueError("unsupported ELF version")
    if not any(data[64:]):
        raise ValueError("ELF has no content after header")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("library", type=pathlib.Path)
    args = parser.parse_args()
    try:
        verify(args.library)
    except (OSError, ValueError) as error:
        print(f"INVALID: {args.library}: {error}", file=sys.stderr)
        sys.exit(1)
    print(f"VALID Android ARM64 ELF shared object: {args.library}")
