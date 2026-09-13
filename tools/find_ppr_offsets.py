#!/usr/bin/env python3
r"""Find PPR/fPKG offsets in retail kernels without requiring devkit images.

By default, the scanner chooses the nearest structurally validated reference
from the target's directory.  References must belong to the same PPR ABI
family and have populated offsets in the repository headers.  Pointing the
scanner at a retail directory is therefore sufficient; no devkit corpus is
needed.  An explicit reference can still be supplied for manual investigations.

The reference is used only to build instruction signatures at the eight known
PPR sites.  The target kdata anchor is derived independently from ordinary CR0
helper offsets, and every discovered PPR address is checked as a connected ABI
(get-index calls/returns, cleanup calls and verifyImage mailbox call). Existing
PPR values are therefore never copied to the target.

Typical use when a missing retail kernel is added to the retail corpus:

  python tools/find_ppr_offsets.py C:\kernels\retail\11.60.elf

An explicit retail reference directory may also be used:

  python tools/find_ppr_offsets.py C:\kernels\new\11.60.elf \
      --reference-dir C:\kernels\retail
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct
import sys
from typing import Iterator, NamedTuple

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86 import X86_OP_IMM
except ImportError as exc:  # pragma: no cover - environment diagnostic
    raise SystemExit("capstone is required: python -m pip install capstone") \
        from exc

from validate_ppr_offsets import (
    MASK64,
    PF_X,
    PPR_NAMES,
    PROFILES,
    Segment,
    bytes_at,
    infer_kdata_anchor,
    load_image,
    parse_header,
    rel32_call_target,
    segment_kdata_anchor,
    version_key,
)


MD = Cs(CS_ARCH_X86, CS_MODE_64)
MD.detail = True


class Signature(NamedTuple):
    data: bytes
    mask: bytes


class LocatedSite(NamedTuple):
    address: int
    method: str


class ReferenceChoice(NamedTuple):
    path: Path
    reason: str


def signed_hex(value: int) -> str:
    if value & (1 << 63):
        value -= 1 << 64
    sign = "-" if value < 0 else ""
    return f"{sign}0x{abs(value):x}"


def executable_segments(segments: list[Segment]) -> Iterator[Segment]:
    return (segment for segment in segments if segment.flags & PF_X)


def find_exact(segments: list[Segment], pattern: bytes) -> list[int]:
    found = []
    for segment in executable_segments(segments):
        start = 0
        while True:
            start = segment.data.find(pattern, start)
            if start < 0:
                break
            found.append((segment.vaddr + start) & MASK64)
            start += 1
    return found


def instruction_signature(segments: list[Segment], address: int,
                          instruction_count: int = 12) -> Signature:
    raw = bytes_at(segments, address, 128)
    instructions = list(MD.disasm(raw, address, count=instruction_count))
    if len(instructions) < 6:
        raise ValueError(f"too few instructions at reference site {address:#x}")
    size = sum(instruction.size for instruction in instructions)
    data = bytearray(raw[:size])
    mask = bytearray(b"\x01" * size)
    cursor = 0
    for instruction in instructions:
        for offset, field_size in (
            (instruction.imm_offset, instruction.imm_size),
            (instruction.disp_offset, instruction.disp_size),
        ):
            if field_size:
                mask[cursor + offset:cursor + offset + field_size] = \
                    b"\x00" * field_size
        cursor += instruction.size
    return Signature(bytes(data), bytes(mask))


def longest_fixed_run(mask: bytes) -> tuple[int, int]:
    best_start = best_size = 0
    start = 0
    while start < len(mask):
        while start < len(mask) and not mask[start]:
            start += 1
        end = start
        while end < len(mask) and mask[end]:
            end += 1
        if end - start > best_size:
            best_start, best_size = start, end - start
        start = end + 1
    return best_start, best_size


def masked_matches(data: bytes, start: int, signature: Signature) -> bool:
    if start < 0 or start + len(signature.data) > len(data):
        return False
    view = data[start:start + len(signature.data)]
    return all(not keep or actual == expected
               for actual, expected, keep
               in zip(view, signature.data, signature.mask))


def find_masked(segments: list[Segment], signature: Signature) -> list[int]:
    run_start, run_size = longest_fixed_run(signature.mask)
    if run_size < 3:
        raise ValueError("instruction signature has no useful fixed byte run")
    needle = signature.data[run_start:run_start + run_size]
    found = set()
    for segment in executable_segments(segments):
        position = 0
        while True:
            position = segment.data.find(needle, position)
            if position < 0:
                break
            candidate = position - run_start
            if masked_matches(segment.data, candidate, signature):
                found.add((segment.vaddr + candidate) & MASK64)
            position += 1
    return sorted(found)


def locate_site(reference_segments: list[Segment], reference_address: int,
                target_segments: list[Segment]) -> tuple[LocatedSite | None,
                                                         list[int]]:
    # Exact matching gives the strongest result and is normally sufficient for
    # devkit/retail images built from the same firmware source revision.
    exact = bytes_at(reference_segments, reference_address, 64)
    if len(exact) == 64:
        matches = find_exact(target_segments, exact)
        if len(matches) == 1:
            return LocatedSite(matches[0], "exact-64"), matches

    # Ignore encoded branch targets, RIP-relative displacements and immediates
    # when layout or link-time addresses differ between target types.
    signature = instruction_signature(reference_segments, reference_address)
    matches = find_masked(target_segments, signature)
    if len(matches) == 1:
        return LocatedSite(matches[0], "masked-instructions"), matches
    return None, matches


def direct_call_entry(segments: list[Segment], return_address: int) -> int | None:
    entry = rel32_call_target(segments, (return_address - 5) & MASK64)
    if entry is None or bytes_at(segments, entry, 4) \
            != bytes.fromhex("55 48 89 e5"):
        return None
    return entry


def cleanup_body_delta(segments: list[Segment], address: int) -> int:
    instructions = list(MD.disasm(bytes_at(segments, address, 32), address,
                                  count=8))
    for instruction in instructions:
        if instruction.mnemonic != "jmp" or len(instruction.operands) != 1:
            continue
        operand = instruction.operands[0]
        if operand.type != X86_OP_IMM:
            continue
        target = operand.imm & MASK64
        delta = (target - address) & MASK64
        if delta < 0x100:
            return delta
    return 0


def locate_cleanup(reference_segments: list[Segment], reference_address: int,
                   target_segments: list[Segment]) \
        -> tuple[LocatedSite | None, list[int]]:
    site, candidates = locate_site(
        reference_segments, reference_address, target_segments
    )
    if site is not None:
        return site, candidates

    # Newer kernels expose cleanup_a53io_pkg_keys through a short alignment
    # thunk.  Its rel32 jump changes easily, while the actual body is highly
    # distinctive.  Match the body and translate back to the public entry.
    body_delta = cleanup_body_delta(reference_segments, reference_address)
    if not body_delta:
        return None, candidates
    body, body_candidates = locate_site(
        reference_segments,
        (reference_address + body_delta) & MASK64,
        target_segments,
    )
    if body is None:
        return None, [((candidate - body_delta) & MASK64)
                      for candidate in body_candidates]
    return LocatedSite((body.address - body_delta) & MASK64,
                       f"{body.method}-via-body"), [body.address]


def ppr_profile_key(major: int, minor: int) -> int:
    return 101 if major == 1 and minor >= 5 else major


def reference_is_consistent(path: Path, header_dir: Path) -> tuple[bool, str]:
    try:
        key, major, minor = version_key(path)
        header = header_dir / f"{key}.h"
        if not header.is_file():
            return False, "no offset header"
        offsets = parse_header(header)
        if any(not offsets.get(name, 0) for name in PPR_NAMES):
            return False, "PPR offsets are not populated"
        segments = load_image(path)
        try:
            anchor = segment_kdata_anchor(segments)
        except ValueError:
            anchor, _score = infer_kdata_anchor(segments, offsets)
        errors = connected_abi_errors(
            segments, offsets, anchor, major, minor
        )
        if errors:
            return False, "; ".join(errors)
        return True, "connected PPR ABI validated"
    except (OSError, ValueError, struct.error) as exc:
        return False, str(exc)


def select_reference(reference_dir: Path, major: int, minor: int,
                     header_dir: Path) -> ReferenceChoice:
    if not reference_dir.is_dir():
        raise ValueError(f"reference directory not found: {reference_dir}")
    target_profile = ppr_profile_key(major, minor)
    if target_profile not in PROFILES:
        raise ValueError(
            f"no PPR ABI profile for firmware family {major}.{minor:02d}"
        )

    ranked = []
    rejected = []
    for path in reference_dir.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in (".elf", ".bin"):
            continue
        try:
            _key, reference_major, reference_minor = version_key(path)
        except ValueError:
            continue
        if ppr_profile_key(reference_major, reference_minor) != target_profile:
            continue
        distance = abs((reference_major * 100 + reference_minor)
                       - (major * 100 + minor))
        ranked.append((distance, path.name.lower(), path))

    for distance, _name, path in sorted(ranked):
        usable, reason = reference_is_consistent(path, header_dir)
        if usable:
            relation = "same firmware" if distance == 0 else \
                       f"nearest validated retail ABI ({path.stem})"
            return ReferenceChoice(path, relation)
        rejected.append(f"{path.name}: {reason}")

    stem = f"{major}.{minor:02d}"
    detail = ""
    if rejected:
        detail = "; rejected " + " | ".join(rejected)
    raise ValueError(
        f"no validated reference for {stem} in {reference_dir}{detail}"
    )


def connected_abi_errors(segments: list[Segment], offsets: dict[str, int],
                         anchor: int, major: int, minor: int) -> list[str]:
    address = lambda name: (anchor + offsets[name]) & MASK64
    profile_key = ppr_profile_key(major, minor)
    if profile_key not in PROFILES:
        return [f"no PPR ABI profile for firmware family {major}"]
    profile = PROFILES[profile_key]
    errors = []
    for kind in ("xts", "cmac"):
        entry = address(f"ppr_pfs_get_{kind}_index")
        return_address = address(f"ppr_pfs_get_{kind}_return")
        target = rel32_call_target(segments, (return_address - 5) & MASK64)
        if target != entry:
            got = "not a call" if target is None else f"target {target:#x}"
            errors.append(f"get_{kind}_return: {got}, expected {entry:#x}")

    cleanup = address("ppr_pfs_cleanup_keys")
    for kind, delta in (("cmac", profile.cleanup_cmac_delta),
                        ("xts", profile.cleanup_xts_delta)):
        if rel32_call_target(segments, (cleanup + delta) & MASK64) is None:
            errors.append(f"cleanup {kind}: expected an E8 rel32 call")

    verify_lr = address("sceSblServiceMailbox_lr_verifyImage")
    mailbox = address("sceSblServiceMailbox")
    target = rel32_call_target(segments, (verify_lr - 5) & MASK64)
    if target != mailbox:
        got = "not a call" if target is None else f"target {target:#x}"
        errors.append(f"verifyImage LR: {got}, expected {mailbox:#x}")

    clear = address("ppr_pfs_clear_key_missing")
    if bytes_at(segments, clear, len(profile.clear_prefix)) \
            != profile.clear_prefix:
        errors.append("clear-key miss: unexpected result assignment")
    success = address("ppr_pfs_verify_image_no_key_success")
    if bytes_at(segments, success, len(profile.success_prefix)) \
            != profile.success_prefix:
        errors.append("verifyImage no-key continuation: unexpected instruction")
    return errors


def scan(target: Path, reference: Path, header_dir: Path,
         reference_reason: str = "explicit reference") -> dict[str, object]:
    key, major, minor = version_key(target)
    header = header_dir / f"{key}.h"
    if not header.is_file():
        raise ValueError(f"offset header not found: {header}")
    target_known = parse_header(header)

    reference_key, _reference_major, _reference_minor = version_key(reference)
    reference_header = header_dir / f"{reference_key}.h"
    if not reference_header.is_file():
        raise ValueError(f"reference offset header not found: {reference_header}")
    reference_known = parse_header(reference_header)
    if any(not reference_known.get(name, 0) for name in PPR_NAMES):
        raise ValueError("reference PPR offsets are absent from the header")

    target_segments = load_image(target)
    reference_segments = load_image(reference)
    target_anchor, target_anchor_score = infer_kdata_anchor(
        target_segments, target_known
    )
    try:
        reference_anchor = segment_kdata_anchor(reference_segments)
        reference_anchor_score: int | str = "PT_LOAD"
    except ValueError:
        reference_anchor, reference_anchor_score = infer_kdata_anchor(
            reference_segments, reference_known
        )

    reference_errors = connected_abi_errors(
        reference_segments, reference_known, reference_anchor,
        _reference_major, _reference_minor,
    )
    if reference_errors:
        raise ValueError("reference PPR ABI is inconsistent: "
                         + "; ".join(reference_errors))

    found: dict[str, LocatedSite] = {}
    ambiguous: dict[str, list[str]] = {}

    # Find the two return sites first.  Their preceding E8 instructions reveal
    # the target image's get-index entries even when those functions moved or
    # their prologues are intentionally identical.
    for name in ("ppr_pfs_get_xts_return", "ppr_pfs_get_cmac_return"):
        reference_address = (reference_anchor + reference_known[name]) & MASK64
        site, candidates = locate_site(
            reference_segments, reference_address, target_segments
        )
        if site is None:
            ambiguous[name] = [f"{candidate:#x}" for candidate in candidates]
        else:
            found[name] = site

    for kind in ("xts", "cmac"):
        name = f"ppr_pfs_get_{kind}_index"
        return_name = f"ppr_pfs_get_{kind}_return"
        entry = direct_call_entry(
            target_segments, found[return_name].address
        ) if return_name in found else None
        if entry is not None:
            found[name] = LocatedSite(entry, "derived-call-target")
            continue
        reference_address = (reference_anchor + reference_known[name]) & MASK64
        site, candidates = locate_site(
            reference_segments, reference_address, target_segments
        )
        if site is None:
            ambiguous[name] = [f"{candidate:#x}" for candidate in candidates]
        else:
            found[name] = site

    name = "ppr_pfs_cleanup_keys"
    reference_address = (reference_anchor + reference_known[name]) & MASK64
    site, candidates = locate_cleanup(
        reference_segments, reference_address, target_segments
    )
    if site is None:
        ambiguous[name] = [f"{candidate:#x}" for candidate in candidates]
    else:
        found[name] = site

    for name in (
        "ppr_pfs_clear_key_missing",
        "sceSblServiceMailbox_lr_verifyImage",
        "ppr_pfs_verify_image_no_key_success",
    ):
        reference_address = (reference_anchor + reference_known[name]) & MASK64
        site, candidates = locate_site(
            reference_segments, reference_address, target_segments
        )
        if site is None:
            ambiguous[name] = [f"{candidate:#x}" for candidate in candidates]
        else:
            found[name] = site

    discovered = dict(target_known)
    for name, site in found.items():
        delta = (site.address - target_anchor) & MASK64
        discovered[name] = delta - (1 << 64) if delta & (1 << 63) else delta

    errors = []
    if ambiguous:
        for name, candidates in ambiguous.items():
            state = "no candidates" if not candidates else \
                    f"ambiguous candidates: {', '.join(candidates)}"
            errors.append(f"{name}: {state}")
    else:
        errors.extend(connected_abi_errors(
            target_segments, discovered, target_anchor, major, minor
        ))

    sites = {}
    for name in PPR_NAMES:
        if name not in found:
            sites[name] = {"status": "unresolved",
                           "candidates": ambiguous.get(name, [])}
            continue
        delta = (found[name].address - target_anchor) & MASK64
        sites[name] = {
            "status": "found",
            "address": f"{found[name].address:#x}",
            "offset": signed_hex(delta),
            "method": found[name].method,
        }

    return {
        "target": str(target),
        "reference": str(reference),
        "reference_reason": reference_reason,
        "header": str(header),
        "reference_header": str(reference_header),
        "target_kdata_anchor": f"{target_anchor:#x}",
        "target_anchor_score": target_anchor_score,
        "reference_kdata_anchor": f"{reference_anchor:#x}",
        "reference_anchor_score": reference_anchor_score,
        "status": "complete" if not errors else "needs-review",
        "sites": sites,
        "errors": errors,
    }


def iter_targets(paths: list[Path]) -> Iterator[Path]:
    for path in paths:
        if path.is_dir():
            yield from sorted(
                child for child in path.rglob("*")
                if child.is_file() and child.suffix.lower() in (".elf", ".bin")
            )
        else:
            yield path


def print_human(report: dict[str, object]) -> None:
    print(f"\n{report['target']}")
    print(f"  reference = {report['reference']} "
          f"[{report['reference_reason']}]")
    print(f"  kdata_base = {report['target_kdata_anchor']} "
          f"[anchor score {report['target_anchor_score']}]")
    sites = report["sites"]
    assert isinstance(sites, dict)
    for name, raw_site in sites.items():
        site = raw_site
        assert isinstance(site, dict)
        if site["status"] == "found":
            print(f"  {name}: {site['offset']} "
                  f"({site['address']}, {site['method']})")
        else:
            candidates = site.get("candidates", [])
            print(f"  {name}: unresolved ({len(candidates)} candidate(s))")
    errors = report["errors"]
    assert isinstance(errors, list)
    if errors:
        print("  review:")
        for error in errors:
            print(f"    {error}")
        return
    print("  header definitions:")
    for name, raw_site in sites.items():
        site = raw_site
        print(f"    DEF({name}, {site['offset']})")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("targets", nargs="+", type=Path,
                        help="target retail ELF/BIN or directory")
    parser.add_argument("--reference", type=Path,
                        help="explicit reference image (one target only)")
    parser.add_argument("--reference-dir", type=Path,
                        help="retail reference corpus; defaults to each "
                             "target's directory")
    parser.add_argument("--headers", type=Path,
                        default=Path(__file__).resolve().parents[1]
                                / "prosper0gdb" / "offsets")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args()
    targets = list(iter_targets(args.targets))
    if args.reference and len(targets) != 1:
        parser.error("--reference requires exactly one target")

    reports = []
    failures = 0
    for target in targets:
        try:
            _key, major, minor = version_key(target)
            if args.reference:
                reference = args.reference
                reference_reason = "explicit reference"
            else:
                reference_dir = args.reference_dir or target.parent
                choice = select_reference(
                    reference_dir, major, minor, args.headers
                )
                reference = choice.path
                reference_reason = choice.reason
            reports.append(scan(
                target, reference, args.headers, reference_reason
            ))
            failures += reports[-1]["status"] != "complete"
        except (OSError, ValueError, struct.error) as exc:
            failures += 1
            reports.append({
                "target": str(target),
                "status": "error",
                "error": str(exc),
            })

    if args.json:
        json.dump(reports, sys.stdout, indent=2)
        print()
    else:
        for report in reports:
            if report["status"] == "error":
                print(f"\n{report['target']}\n  error: {report['error']}")
            else:
                print_human(report)
        complete = sum(report["status"] == "complete" for report in reports)
        print(f"\nScanned {len(reports)} target(s): {complete} complete, "
              f"{len(reports) - complete} need review.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
