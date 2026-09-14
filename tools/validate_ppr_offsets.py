#!/usr/bin/env python3
"""Statically validate retail PPR offsets against local PS5 kernel images.

The checker derives the kdata anchor from existing, independently recognizable
CR0 helper instructions.  It then checks the relationships that make the PPR
trap ABI safe: both get-index calls and return addresses, cleanup call sites,
the clear-key miss instruction, the verifyImage mailbox return address, and the
success continuation.  This is a static audit; console testing is still needed
before calling a firmware fully supported.
"""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path
import re
import struct
import sys
from typing import NamedTuple


PT_LOAD = 1
PF_X = 1
MASK64 = (1 << 64) - 1

PPR_NAMES = (
    "ppr_pfs_get_xts_index",
    "ppr_pfs_get_cmac_index",
    "ppr_pfs_get_xts_return",
    "ppr_pfs_get_cmac_return",
    "ppr_pfs_cleanup_keys",
    "ppr_pfs_clear_key_missing",
    "sceSblServiceMailbox_lr_verifyImage",
    "ppr_pfs_verify_image_no_key_success",
)

ANCHOR_SIGNATURES = {
    "cr0_load": bytes.fromhex("48 8b 47 58"),
    "cr0_clear_store": bytes.fromhex("48 83 e0 f7"),
    "cr0_write_ret": bytes.fromhex("0f 22 c0"),
    "store_rax_rdi": bytes.fromhex("48 89 07"),
}


class Profile(NamedTuple):
    cleanup_cmac_delta: int
    cleanup_xts_delta: int
    clear_prefix: bytes
    success_signature: bytes


VERIFY_SUCCESS_EARLY = bytes.fromhex(
    "49 c1 e7 20 8b 85 1c ff ff ff 45 31 e4 4d 09 f7 "
    "44 8b b5 24 ff ff ff 48 89 85 a8 fe ff ff"
)
VERIFY_SUCCESS_FW5_6 = bytes.fromhex(
    "49 c1 e5 20 4c 03 ad a8 fe ff ff 8b 85 1c ff ff ff "
    "44 8b bd 24 ff ff ff 45 31 e4 48 89 85 a0 fe ff ff"
)
VERIFY_SUCCESS_FW7 = bytes.fromhex(
    "49 c1 e5 20 4c 03 ad b0 fe ff ff 8b 85 e0 fe ff ff "
    "44 8b bd e8 fe ff ff 45 31 e4 48 89 85 a0 fe ff ff"
)
VERIFY_SUCCESS_FW8_9 = bytes.fromhex(
    "49 c1 e5 20 4c 03 ad b0 fe ff ff 8b 85 e0 fe ff ff "
    "8b 9d e8 fe ff ff 45 31 e4 48 89 85 a0 fe ff ff"
)
VERIFY_SUCCESS_FW10_11 = bytes.fromhex(
    "c4 63 fb f0 b5 a8 fe ff ff 20 8b 85 e0 fe ff ff "
    "8b 9d e8 fe ff ff 45 31 e4 48 89 85 a0 fe ff ff"
)
VERIFY_SUCCESS_FW12 = bytes.fromhex(
    "c4 63 fb f0 b5 b0 fe ff ff 20 8b 85 e0 fe ff ff "
    "8b 9d e8 fe ff ff 45 31 e4 48 89 85 98 fe ff ff"
)


PROFILES = {
    1: Profile(0x126, 0x15A, bytes.fromhex("bb fe ff ff ff"),
               VERIFY_SUCCESS_EARLY),
    101: Profile(0x145, 0x179, bytes.fromhex("bb fe ff ff ff"),
                 VERIFY_SUCCESS_EARLY),
    2: Profile(0x144, 0x178, bytes.fromhex("bb fe ff ff ff"),
               VERIFY_SUCCESS_EARLY),
    3: Profile(0x137, 0x166, bytes.fromhex("41 be fe ff ff ff"),
               VERIFY_SUCCESS_EARLY),
    4: Profile(0x13D, 0x16C, bytes.fromhex("41 bc fe ff ff ff"),
               VERIFY_SUCCESS_EARLY),
    5: Profile(0x138, 0x167, bytes.fromhex("41 bc fe ff ff ff"),
               VERIFY_SUCCESS_FW5_6),
    6: Profile(0x138, 0x167, bytes.fromhex("41 bc fe ff ff ff"),
               VERIFY_SUCCESS_FW5_6),
    7: Profile(0x11C, 0x14B, bytes.fromhex("41 bf fe ff ff ff"),
               VERIFY_SUCCESS_FW7),
    8: Profile(0x117, 0x147, bytes.fromhex("bb fe ff ff ff"),
               VERIFY_SUCCESS_FW8_9),
    9: Profile(0x119, 0x149, bytes.fromhex("bb fe ff ff ff"),
               VERIFY_SUCCESS_FW8_9),
    10: Profile(0x119, 0x149, bytes.fromhex("bb fe ff ff ff"),
                VERIFY_SUCCESS_FW10_11),
    11: Profile(0x119, 0x149, bytes.fromhex("bb fe ff ff ff"),
                VERIFY_SUCCESS_FW10_11),
    12: Profile(0x119, 0x149, bytes.fromhex("bb fe ff ff ff"),
                VERIFY_SUCCESS_FW12),
}


class Segment(NamedTuple):
    vaddr: int
    data: bytes
    flags: int


def load_image(path: Path) -> list[Segment]:
    data = path.read_bytes()
    if data[:4] != b"\x7fELF":
        return [Segment(0, data, PF_X)]
    if len(data) < 64 or data[4] != 2 or data[5] != 1:
        raise ValueError("expected a little-endian ELF64 or raw kernel image")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize = struct.unpack_from("<H", data, 54)[0]
    phnum = struct.unpack_from("<H", data, 56)[0]
    if phentsize < 56 or phoff + phentsize * phnum > len(data):
        raise ValueError("invalid program-header table")
    segments = []
    for index in range(phnum):
        pos = phoff + index * phentsize
        p_type, flags, offset, vaddr, _paddr, filesz, _memsz, _align = \
            struct.unpack_from("<IIQQQQQQ", data, pos)
        if p_type != PT_LOAD or not filesz:
            continue
        available = min(filesz, max(0, len(data) - offset))
        segments.append(Segment(vaddr, data[offset:offset + available], flags))
    if not segments:
        raise ValueError("ELF has no readable PT_LOAD segment")
    return segments


def bytes_at(segments: list[Segment], address: int, size: int) -> bytes:
    for segment in segments:
        delta = (address - segment.vaddr) & MASK64
        if delta < len(segment.data):
            return segment.data[delta:delta + size]
    return b""


def find_all(segments: list[Segment], pattern: bytes) -> list[int]:
    found = []
    for segment in segments:
        if not segment.flags & PF_X:
            continue
        start = 0
        while True:
            start = segment.data.find(pattern, start)
            if start < 0:
                break
            found.append((segment.vaddr + start) & MASK64)
            start += 1
    return found


def segment_kdata_anchor(segments: list[Segment]) -> int:
    """Return the first non-executable PT_LOAD following executable text."""
    executable = sorted(
        (segment for segment in segments if segment.flags & PF_X),
        key=lambda segment: segment.vaddr,
    )
    if not executable:
        raise ValueError("image has no executable segment")
    text_end = max(segment.vaddr + len(segment.data)
                   for segment in executable)
    following = sorted(
        segment.vaddr for segment in segments
        if not segment.flags & PF_X and segment.vaddr >= text_end
    )
    if not following:
        raise ValueError("image has no distinct post-text kdata segment")
    return following[0]


def parse_header(path: Path) -> dict[str, int]:
    text = path.read_text(encoding="utf-8")
    return {
        name: int(value, 0)
        for name, value in re.findall(
            r"DEF\((\w+),\s*(-?0x[0-9a-fA-F]+|0)\)", text
        )
    }


def infer_kdata_anchor(segments: list[Segment], offsets: dict[str, int]) \
        -> tuple[int, int]:
    candidates = Counter()
    for name, signature in ANCHOR_SIGNATURES.items():
        delta = offsets.get(name, 0)
        if not delta:
            continue
        for address in find_all(segments, signature):
            anchor = (address - delta) & MASK64
            if anchor & 0xFFFF == 0:
                candidates[anchor] += 1
    if not candidates:
        raise ValueError("could not infer an aligned kdata anchor")
    anchor, score = candidates.most_common(1)[0]
    if score < 2:
        raise ValueError(f"ambiguous kdata anchor (best score {score})")
    return anchor, score


def rel32_call_target(segments: list[Segment], address: int) -> int | None:
    instruction = bytes_at(segments, address, 5)
    if len(instruction) != 5 or instruction[0] != 0xE8:
        return None
    displacement = struct.unpack_from("<i", instruction, 1)[0]
    return (address + 5 + displacement) & MASK64


def version_key(path: Path) -> tuple[str, int, int]:
    match = re.match(r"^(\d+)\.(\d+)", path.stem)
    if not match:
        raise ValueError("filename does not begin with major.minor")
    major, minor = map(int, match.groups())
    return f"{major}_{minor:02d}", major, minor


def validate(path: Path, header_dir: Path) -> list[str]:
    key, major, minor = version_key(path)
    header = header_dir / f"{key}.h"
    if not header.is_file():
        return ["no matching offset header"]
    offsets = parse_header(header)
    if any(not offsets.get(name, 0) for name in PPR_NAMES):
        return ["PPR is not enabled in the matching table"]

    segments = load_image(path)
    anchor, _score = infer_kdata_anchor(segments, offsets)
    address = lambda name: (anchor + offsets[name]) & MASK64
    profile_key = 101 if major == 1 and minor >= 5 else major
    profile = PROFILES[profile_key]
    errors = []

    for name in PPR_NAMES:
        if not bytes_at(segments, address(name), 1):
            errors.append(f"{name}: address is outside the image")

    for kind in ("xts", "cmac"):
        entry = address(f"ppr_pfs_get_{kind}_index")
        return_address = address(f"ppr_pfs_get_{kind}_return")
        if bytes_at(segments, entry, 4) != bytes.fromhex("55 48 89 e5"):
            errors.append(f"get_{kind}_index: not a function prologue")
        target = rel32_call_target(segments, (return_address - 5) & MASK64)
        if target != entry:
            got = "not a call" if target is None else f"target {target:#x}"
            errors.append(f"get_{kind}_return: {got}, expected {entry:#x}")

    cleanup = address("ppr_pfs_cleanup_keys")
    if bytes_at(segments, cleanup, 4) != bytes.fromhex("55 48 89 e5"):
        errors.append("ppr_pfs_cleanup_keys: not a function prologue")
    for kind, delta in (("cmac", profile.cleanup_cmac_delta),
                        ("xts", profile.cleanup_xts_delta)):
        if rel32_call_target(segments, (cleanup + delta) & MASK64) is None:
            errors.append(f"cleanup {kind}: expected an E8 rel32 call")

    clear = address("ppr_pfs_clear_key_missing")
    if bytes_at(segments, clear, len(profile.clear_prefix)) \
            != profile.clear_prefix:
        errors.append("ppr_pfs_clear_key_missing: unexpected result assignment")

    verify_lr = address("sceSblServiceMailbox_lr_verifyImage")
    mailbox = address("sceSblServiceMailbox")
    target = rel32_call_target(segments, (verify_lr - 5) & MASK64)
    if target != mailbox:
        got = "not a call" if target is None else f"target {target:#x}"
        errors.append(f"verifyImage LR: {got}, expected {mailbox:#x}")

    success = address("ppr_pfs_verify_image_no_key_success")
    if bytes_at(segments, success, len(profile.success_signature)) \
            != profile.success_signature:
        errors.append("verifyImage no-key continuation: unexpected ABI sequence")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kernels", type=Path,
                        help="kernel corpus root containing retail/")
    parser.add_argument("--headers", type=Path,
                        default=Path(__file__).resolve().parents[1]
                                / "prosper0gdb" / "offsets")
    args = parser.parse_args()
    retail = args.kernels / "retail"
    if not retail.is_dir():
        parser.error(f"retail directory not found: {retail}")

    failures = 0
    checked = 0
    for path in sorted(retail.iterdir()):
        if path.suffix.lower() not in (".elf", ".bin"):
            continue
        try:
            key, _major, _minor = version_key(path)
        except ValueError:
            continue
        if not (args.headers / f"{key}.h").is_file():
            continue
        try:
            errors = validate(path, args.headers)
        except (OSError, ValueError, struct.error) as exc:
            errors = [str(exc)]
        if errors == ["PPR is not enabled in the matching table"]:
            print(f"SKIP {path.name}: {errors[0]}")
            continue
        checked += 1
        if errors:
            failures += 1
            print(f"FAIL {path.name}")
            for error in errors:
                print(f"  {error}")
        else:
            print(f"PASS {path.name}")

    print(f"Checked {checked} retail image(s): "
          f"{checked - failures} passed, {failures} failed.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
