from __future__ import annotations

import argparse
import hashlib
import sys
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Limits:
    max_archive_bytes: int = 50 * 1024 * 1024
    max_total_uncompressed: int = 1 * 1024**3
    max_single_entry: int = 512 * 1024**2
    max_compression_ratio: float = 150.0
    max_entries: int = 5_000
    max_nesting_depth: int = 3
    max_wall_seconds: int = 60
    chunk_size: int = 64 * 1024


@dataclass
class Verdict:
    safe: bool
    reasons: list[str] = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    def __str__(self) -> str:
        out = [f"[{'SAFE' if self.safe else 'REJECTED'}]"]
        out += [f"  - {r}" for r in self.reasons]
        for k, v in self.stats.items():
            out.append(f"  . {k}: {v}")
        return "\n".join(out)


NESTED_SUFFIXES = (".zip", ".jar", ".war", ".ear", ".whl", ".apk", ".epub")


class BombError(RuntimeError):
    pass


def static_scan(path: Path, lim: Limits) -> tuple[list[str], dict]:
    flags, stats = [], {}
    size = path.stat().st_size
    stats["archive_bytes"] = size
    if size > lim.max_archive_bytes:
        flags.append(f"archive too large: {size} > {lim.max_archive_bytes}")

    try:
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
    except zipfile.BadZipFile as e:
        return [f"not a valid zip: {e}"], stats

    stats["entries"] = len(infos)
    if len(infos) > lim.max_entries:
        flags.append(f"too many entries: {len(infos)} > {lim.max_entries}")

    total, worst = 0, 0.0
    for info in infos:
        total += info.file_size
        if info.file_size > lim.max_single_entry:
            flags.append(f"entry '{info.filename}' declares {info.file_size} bytes")
        cs = max(info.compress_size, 1)
        ratio = info.file_size / cs
        worst = max(worst, ratio)
        if ratio > lim.max_compression_ratio and info.file_size > 1024 * 1024:
            flags.append(
                f"entry '{info.filename}' ratio {ratio:.0f}x "
                f"({info.compress_size} -> {info.file_size})"
            )
        name = info.filename
        if name.startswith("/") or ".." in Path(name).parts:
            flags.append(f"path traversal attempt: {name!r}")

    stats["declared_uncompressed"] = total
    stats["worst_ratio"] = round(worst, 1)
    if total > lim.max_total_uncompressed:
        flags.append(f"declared total {total} > limit {lim.max_total_uncompressed}")
    return flags, stats


def dynamic_scan(path: Path, lim: Limits) -> tuple[list[str], dict]:
    flags, stats = [], {"files_seen": 0}
    start = time.monotonic()
    try:
        with zipfile.ZipFile(path) as zf:
            h = hashlib.sha256()
            total = 0
            for info in zf.infolist():
                if info.is_dir():
                    continue
                stats["files_seen"] += 1
                with zf.open(info, "r") as src:
                    while True:
                        buf = src.read(lim.chunk_size)
                        if not buf:
                            break
                        total += len(buf)
                        h.update(buf)
                        if total > lim.max_total_uncompressed:
                            raise BombError(
                                f"exceeded {lim.max_total_uncompressed} bytes "
                                f"reading '{info.filename}'"
                            )
                        if time.monotonic() - start > lim.max_wall_seconds:
                            raise BombError("wall-clock limit exceeded")
            stats["actual_decompressed"] = total
            stats["sha256"] = h.hexdigest()[:16]
    except BombError as e:
        flags.append(f"BOMB: {e}")
    except MemoryError:
        flags.append("BOMB: memory exhausted")
    return flags, stats


def inspect(path: Path, lim: Limits = Limits()) -> Verdict:
    s_flags, s_stats = static_scan(path, lim)
    if s_flags:
        return Verdict(False, s_flags, s_stats)
    d_flags, d_stats = dynamic_scan(path, lim)
    return Verdict(not d_flags, d_flags, {**s_stats, **d_stats})


def extract_to(path: Path, dest: Path, lim: Limits = Limits()) -> Verdict:
    v = inspect(path, lim)
    if not v.safe:
        return v
    dest.mkdir(parents=True, exist_ok=True)
    written = 0
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            target = (dest / info.filename).resolve()
            if not str(target).startswith(str(dest.resolve())):
                return Verdict(False, [f"zip-slip blocked: {info.filename!r}"])
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as dst:
                while True:
                    buf = src.read(lim.chunk_size)
                    if not buf:
                        break
                    written += len(buf)
                    if written > lim.max_total_uncompressed:
                        target.unlink(missing_ok=True)
                        return Verdict(False, ["aborted: byte budget exceeded"])
                    dst.write(buf)
    return Verdict(True, ["extracted"], {"written": written})


def _parse_size(s: str) -> int:
    s = s.strip().upper()
    for suf, mul in (("GIB", 1024**3), ("MIB", 1024**2), ("KIB", 1024),
                     ("GB", 10**9), ("MB", 10**6), ("KB", 10**3)):
        if s.endswith(suf):
            return int(float(s[: -len(suf)]) * mul)
    return int(s)


def main() -> int:
    p = argparse.ArgumentParser(description="Detect and safely handle zip bombs")
    p.add_argument("archive", type=Path)
    p.add_argument("--extract", type=Path)
    p.add_argument("--max-total", default="1GiB")
    args = p.parse_args()

    lim = Limits(max_total_uncompressed=_parse_size(args.max_total))
    verdict = extract_to(args.archive, args.extract, lim) if args.extract \
        else inspect(args.archive, lim)
    print(verdict)
    return 0 if verdict.safe else 1


if __name__ == "__main__":
    sys.exit(main())
