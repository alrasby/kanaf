#!/usr/bin/env python3
"""Validate Android AArch64 ELF shared objects without executing untrusted code."""
import argparse
import pathlib
import struct
import sys


def verify(path: pathlib.Path, require_16kb: bool = False) -> None:
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
    if require_16kb:
        # Android 15+ 16 KiB kernel pages: every PT_LOAD must be mapped with
        # p_align >= 16384 and matching file/virtual address modulo 16384.
        ph_offset = struct.unpack_from("<Q", data, 32)[0]
        ph_size = struct.unpack_from("<H", data, 54)[0]
        ph_count = struct.unpack_from("<H", data, 56)[0]
        if ph_size < 56 or ph_count == 0 or ph_offset < 64 or (
            ph_offset + ph_size * ph_count > len(data)
        ):
            raise ValueError("missing or invalid ELF program headers")
        load_count = 0
        for index in range(ph_count):
            at = ph_offset + index * ph_size
            if struct.unpack_from("<I", data, at)[0] != 1:
                continue
            load_count += 1
            file_offset = struct.unpack_from("<Q", data, at + 8)[0]
            virtual_addr = struct.unpack_from("<Q", data, at + 16)[0]
            alignment = struct.unpack_from("<Q", data, at + 48)[0]
            if alignment < 16384 or alignment & (alignment - 1):
                raise ValueError("PT_LOAD segment not 16 KiB aligned")
            if file_offset % 16384 != virtual_addr % 16384:
                raise ValueError("PT_LOAD offset/virtual address 16 KiB mismatch")
        if not load_count:
            raise ValueError("ELF has no PT_LOAD segment")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("library", type=pathlib.Path)
    parser.add_argument("--require-16kb", action="store_true", help="require Android 16 KiB PT_LOAD alignment")
    args = parser.parse_args()
    try:
        verify(args.library, require_16kb=args.require_16kb)
    except (OSError, ValueError) as error:
        print(f"INVALID: {args.library}: {error}", file=sys.stderr)
        sys.exit(1)
    print(f"VALID Android ARM64 ELF shared object: {args.library}")
