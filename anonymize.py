#!/usr/bin/env python3
"""
Anonymize terms under a folder and restore from a compact mapping file.

Map format: gzip-compressed UTF-8 JSON: {"v":1,"p":[["old","new"],...]}
Replace order: longest old/new strings first to avoid partial overlaps.
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import secrets
import sys
from pathlib import Path

MAP_VERSION = 1
TOKEN_PREFIX = "__M_ANON_"
TOKEN_SUFFIX = "__"

SKIP_DIR_NAMES = {
    ".git",
    ".svn",
    ".hg",
    "__pycache__",
    ".idea",
    ".vscode",
    "node_modules",
    "target",
    "build",
    "dist",
    ".venv",
    "venv",
}


def _make_token(used: set[str]) -> str:
    while True:
        t = f"{TOKEN_PREFIX}{secrets.token_hex(16)}{TOKEN_SUFFIX}"
        if t not in used:
            used.add(t)
            return t


def _iter_files(root: Path):
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
        for name in filenames:
            yield Path(dirpath) / name


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", newline="")
    except (UnicodeDecodeError, OSError):
        return None


def _write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="")


def _load_map(map_path: Path) -> list[list[str]]:
    """Load an existing map file, returning the pairs list (or empty if missing)."""
    map_path = map_path.resolve()
    if not map_path.exists():
        return []
    raw = map_path.read_bytes()
    if len(raw) >= 2 and raw[0] == 0x1F and raw[1] == 0x8B:
        data = gzip.decompress(raw).decode("utf-8")
    else:
        data = raw.decode("utf-8")
    obj = json.loads(data)
    if obj.get("v") != MAP_VERSION:
        raise SystemExit(f"Unsupported map version: {obj.get('v')}")
    plist = obj.get("p")
    if not isinstance(plist, list):
        raise SystemExit("Invalid map: missing 'p'")
    return [list(item) for item in plist if isinstance(item, (list, tuple)) and len(item) == 2]


def anonymize(terms: list[str], folder: Path, map_path: Path) -> None:
    root = folder.resolve()
    if not root.is_dir():
        raise SystemExit(f"Not a directory: {root}")

    existing_pairs = _load_map(map_path)
    already_mapped: set[str] = {p[0] for p in existing_pairs}
    used: set[str] = {p[1] for p in existing_pairs}

    new_terms = sorted({t for t in terms if t and t not in already_mapped}, key=len, reverse=True)
    if not new_terms and not existing_pairs:
        raise SystemExit("No non-empty terms to anonymize.")
    if not new_terms:
        print("All terms already present in existing map; nothing new to anonymize.", file=sys.stderr)
        return

    new_pairs: list[list[str]] = []
    for old in new_terms:
        new = _make_token(used)
        new_pairs.append([old, new])

    # Apply only new replacements; sort longest-first to avoid partial overlaps
    changed_files = 0
    for path in _iter_files(root):
        text = _read_text(path)
        if text is None:
            continue
        orig = text
        for old, new in new_pairs:
            if old in text:
                text = text.replace(old, new)
        if text != orig:
            _write_text(path, text)
            changed_files += 1

    # Merge: existing pairs + new pairs, re-sorted longest original first
    all_pairs = existing_pairs + new_pairs
    all_pairs.sort(key=lambda x: len(x[0]), reverse=True)

    payload = json.dumps({"v": MAP_VERSION, "p": all_pairs}, ensure_ascii=False, separators=(",", ":"))
    map_path = map_path.resolve()
    map_path.parent.mkdir(parents=True, exist_ok=True)
    map_path.write_bytes(gzip.compress(payload.encode("utf-8"), compresslevel=9))

    total = len(all_pairs)
    print(
        f"Anonymized {len(new_pairs)} new term(s); {total} total in map; "
        f"updated {changed_files} file(s). Map: {map_path}",
        file=sys.stderr,
    )


def restore(map_path: Path, folder: Path) -> None:
    root = folder.resolve()
    if not root.is_dir():
        raise SystemExit(f"Not a directory: {root}")

    raw = map_path.read_bytes()
    if len(raw) >= 2 and raw[0] == 0x1F and raw[1] == 0x8B:
        data = gzip.decompress(raw).decode("utf-8")
    else:
        data = raw.decode("utf-8")

    obj = json.loads(data)
    if obj.get("v") != MAP_VERSION:
        raise SystemExit(f"Unsupported map version: {obj.get('v')}")
    plist = obj.get("p")
    if not isinstance(plist, list):
        raise SystemExit("Invalid map: missing 'p'")

    pairs: list[tuple[str, str]] = []
    for item in plist:
        if isinstance(item, (list, tuple)) and len(item) == 2:
            old, new = str(item[0]), str(item[1])
            pairs.append((old, new))
    # Longest "new" first so one placeholder is never split by another
    pairs.sort(key=lambda x: len(x[1]), reverse=True)

    changed_files = 0
    for path in _iter_files(root):
        text = _read_text(path)
        if text is None:
            continue
        orig = text
        for old, new in pairs:
            if new in text:
                text = text.replace(new, old)
        if text != orig:
            _write_text(path, text)
            changed_files += 1

    print(f"Restored; updated {changed_files} file(s).", file=sys.stderr)


def _load_terms_file(path: Path) -> list[str]:
    return [ln.rstrip("\n\r") for ln in path.read_text(encoding="utf-8").splitlines()]


def _load_gitleaks_secrets(path: Path) -> list[str]:
    """Load Secret values from a Gitleaks JSON report (array of finding objects)."""
    raw = path.read_text(encoding="utf-8")
    data = json.loads(raw)
    if not isinstance(data, list):
        raise SystemExit(f"Gitleaks report must be a JSON array: {path}")
    out: list[str] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        secret = None
        for key in ("Secret", "secret"):
            if key in item:
                secret = item[key]
                break
        if secret is None:
            continue
        if not isinstance(secret, str):
            secret = str(secret)
        if secret:
            out.append(secret)
    if not out:
        raise SystemExit(f"No Secret fields found in Gitleaks report: {path}")
    return out
def main() -> None:
    ap = argparse.ArgumentParser(description="Anonymize or restore text under a folder.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("anonymize", help="Replace terms with unique tokens; write map file.")
    a.add_argument("--terms", nargs="*", default=[], help="Terms to anonymize (repeatable).")
    a.add_argument("--terms-file", type=Path, help="File with one term per line.")
    a.add_argument(
        "--gitleaks-report",
        type=Path,
        help="Gitleaks JSON report: JSON array of objects; each object's Secret becomes a term.",
    )
    a.add_argument("--folder", type=Path, required=True, help="Root folder to scan.")
    a.add_argument(
        "--map",
        type=Path,
        required=True,
        help="Output mapping file (.json.gz recommended).",
    )

    r = sub.add_parser("restore", help="Replace tokens from map with original terms.")
    r.add_argument("--map", type=Path, required=True, help="Mapping file from anonymize.")
    r.add_argument("--folder", type=Path, required=True, help="Same root folder as anonymize.")

    args = ap.parse_args()
    if args.cmd == "anonymize":
        terms = list(args.terms)
        if args.terms_file:
            terms.extend(_load_terms_file(args.terms_file))
        if args.gitleaks_report:
            terms.extend(_load_gitleaks_secrets(args.gitleaks_report))
        if not terms:
            raise SystemExit(
                "Provide --terms, --terms-file, and/or --gitleaks-report with at least one term."
            )
        anonymize(terms, args.folder, args.map)
    else:
        restore(args.map, args.folder)


if __name__ == "__main__":
    main()
