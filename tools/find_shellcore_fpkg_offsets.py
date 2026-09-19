#!/usr/bin/env python3
"""Audit ShellCore import NIDs and GOT slots in unpacked ELF images.

This mirrors the loader's NID-to-JMP_SLOT lookup. PLT stubs and lazy GOT
initializers are checked to catch a changed import ABI before deployment.
"""

import argparse
import hashlib
import struct
from pathlib import Path


IMPORTS = {
    "close": "bY-PO6JhzhQ",
    "open": "wuCroIGjt2g",
    "pread": "ezv-RSBNKqI",
    "mount_game": "FtGP5aXKFQU",
    "umount_game": "UQTSykySQ40",
    "mount_ppr": "MiUxeleLYUc",
    "umount_ppr": "S5+bpaH0TWk",
}
DT_PLTRELSZ = 2
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELAENT = 9
DT_STRSZ = 10
DT_SYMENT = 11
DT_PLTREL = 20
DT_JMPREL = 23
DT_RELA = 7
PT_LOAD = 1
PT_DYNAMIC = 2
R_X86_64_JUMP_SLOT = 7


def derive(path: Path):
    image = path.read_bytes()
    if image[:4] != b"\x7fELF" or image[4:6] != b"\x02\x01":
        raise ValueError("expected an unpacked little-endian ELF64 image")
    phoff = struct.unpack_from("<Q", image, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", image, 54)
    if phentsize != 56 or not 0 < phnum <= 64:
        raise ValueError("unexpected program-header layout")
    segments = [struct.unpack_from("<IIQQQQQQ", image, phoff + i * phentsize)
                for i in range(phnum)]

    def file_offset(vaddr, size):
        for kind, _, offset, start, _, filesz, _, _ in segments:
            if kind == PT_LOAD and start <= vaddr and size <= filesz - (vaddr - start):
                return offset + vaddr - start
        raise ValueError(f"unmapped ELF data at {vaddr:#x}, size {size:#x}")

    dynamics = [segment for segment in segments if segment[0] == PT_DYNAMIC]
    if len(dynamics) != 1:
        raise ValueError("expected one PT_DYNAMIC")
    _, _, dynoff, _, _, dynsize, _, _ = dynamics[0]
    tags = {}
    for off in range(dynoff, dynoff + dynsize, 16):
        tag, value = struct.unpack_from("<QQ", image, off)
        if tag == 0:
            break
        tags[tag] = value
    if (tags.get(DT_PLTREL) != DT_RELA
            or tags.get(DT_RELAENT) != 24
            or tags.get(DT_SYMENT) != 24):
        raise ValueError("unexpected relocation or symbol ABI")
    size = tags[DT_PLTRELSZ]
    if size % 24:
        raise ValueError("JMPREL size is not a multiple of Elf64_Rela")
    reloc_offset = file_offset(tags[DT_JMPREL], size)
    string_offset = file_offset(tags[DT_STRTAB], tags[DT_STRSZ])
    strings = image[string_offset:string_offset + tags[DT_STRSZ]]
    slots = {}
    for off in range(reloc_offset, reloc_offset + size, 24):
        r_offset, r_info, _ = struct.unpack_from("<QQq", image, off)
        if r_info & 0xffffffff != R_X86_64_JUMP_SLOT:
            continue
        symbol = r_info >> 32
        symoff = file_offset(tags[DT_SYMTAB] + 24 * symbol, 24)
        nameoff = struct.unpack_from("<I", image, symoff)[0]
        if nameoff >= len(strings):
            raise ValueError("symbol name outside DT_STRTAB")
        name = strings[nameoff:].split(b"\0", 1)[0].decode("ascii")
        for label, nid in IMPORTS.items():
            if name.startswith(nid + "#"):
                if label in slots:
                    raise ValueError(f"duplicate {label} JMP_SLOT")
                slots[label] = r_offset
    missing = IMPORTS.keys() - slots.keys()
    if missing:
        raise ValueError(f"missing JMP_SLOT imports: {', '.join(sorted(missing))}")

    stubs = {label: [] for label in IMPORTS}
    slots_to_names = {value: name for name, value in slots.items()}
    for kind, flags, offset, start, _, filesz, _, _ in segments:
        if kind != PT_LOAD or not flags & 1:
            continue
        code = image[offset:offset + filesz]
        cursor = 0
        while (cursor := code.find(b"\xff\x25", cursor)) != -1:
            if cursor + 6 > len(code):
                break
            displacement = struct.unpack_from("<i", code, cursor + 2)[0]
            target = start + cursor + 6 + displacement
            if target in slots_to_names:
                stubs[slots_to_names[target]].append(start + cursor)
            cursor += 2
    for label, addresses in stubs.items():
        if len(addresses) != 1:
            raise ValueError(f"{label}: expected one PLT stub, got {addresses}")
    plt = {name: addresses[0] for name, addresses in stubs.items()}
    for label, got in slots.items():
        initial = struct.unpack_from("<Q", image, file_offset(got, 8))[0]
        if initial != plt[label] + 6:
            raise ValueError(f"{label}: unexpected lazy GOT initializer {initial:#x}")
    return plt, slots, hashlib.sha256(image).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("images", type=Path, nargs="+")
    args = parser.parse_args()
    for path in args.images:
        plt, slots, digest = derive(path)
        print(f"{path.name} sha256={digest}")
        for name, value in slots.items():
            print(f"    {name}: GOT={value:#x} lazy_PLT={plt[name]:#x}")


if __name__ == "__main__":
    main()
