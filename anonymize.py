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
import re
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

# Never rewrite these as text (archives, bytecode, media, etc.).
BINARY_EXTENSIONS = {
    ".7z",
    ".a",
    ".avi",
    ".bin",
    ".bmp",
    ".bz2",
    ".class",
    ".db",
    ".dll",
    ".dylib",
    ".ear",
    ".eot",
    ".exe",
    ".gif",
    ".gz",
    ".ico",
    ".jar",
    ".jpeg",
    ".jpg",
    ".mkv",
    ".mov",
    ".mp3",
    ".mp4",
    ".o",
    ".otf",
    ".pdf",
    ".png",
    ".pyc",
    ".pyo",
    ".rar",
    ".so",
    ".sqlite",
    ".tar",
    ".tgz",
    ".ttf",
    ".war",
    ".wasm",
    ".webp",
    ".woff",
    ".woff2",
    ".xz",
    ".zip",
}


def _whole_word_pattern(term: str, *, ignore_case: bool = False) -> re.Pattern[str]:
    """Compile a whole-word pattern for *term* (optional case-insensitive)."""
    escaped = re.escape(term)
    prefix = r"\b" if term and (term[0].isalnum() or term[0] == "_") else ""
    suffix = r"\b" if term and (term[-1].isalnum() or term[-1] == "_") else ""
    flags = re.IGNORECASE if ignore_case else 0
    return re.compile(prefix + escaped + suffix, flags)


def _whole_word_replace(text: str, old: str, new: str) -> str:
    """Replace *old* with *new* only when *old* appears as a whole word.

    Word boundaries (\\b) are added on each side where the term starts/ends
    with a word character ([a-zA-Z0-9_]).  This avoids matching *old* when
    it is embedded inside a larger identifier (e.g. term "isp" must NOT
    match "provaispprova") while still matching at punctuation boundaries
    (e.g. "isp.com", "//ISP").
    """
    return _whole_word_pattern(old).sub(lambda _: new, text)


def _discover_case_variants(
    terms: list[str],
    *,
    files: list[Path] | None = None,
    root: Path | None = None,
) -> set[str]:
    """Find exact surface forms that match *terms* case-insensitively.

    Each distinct casing (e.g. banca / Banca / BANCA) is returned as-is so
    anonymize can assign a separate token per form.

    Scans *files* when given; otherwise scans text files (and directory names)
    under *root*.
    """
    patterns = [_whole_word_pattern(t, ignore_case=True) for t in terms if t]
    if not patterns:
        return set()
    found: set[str] = set()

    def _scan_text(text: str) -> None:
        for pat in patterns:
            for match in pat.finditer(text):
                found.add(match.group(0))

    if files is not None:
        for path in files:
            text = _read_text(path)
            if text is None:
                continue
            _scan_text(text)
        return found

    if root is None:
        return found
    for path in _iter_files(root):
        text = _read_text(path)
        if text is None:
            continue
        _scan_text(text)
    for path in _collect_dirs(root):
        _scan_text(path.name)
    return found


def _build_anonymize_pairs(
    seed_terms: list[str],
    existing_pairs: list[list[str]],
    *,
    ignore_case: bool,
    files: list[Path] | None = None,
    root: Path | None = None,
) -> list[list[str]]:
    """Return new map pairs for *seed_terms* not already present in the map."""
    already: dict[str, str] = {p[0]: p[1] for p in existing_pairs}
    used: set[str] = set(already.values())
    candidates: set[str] = set(seed_terms)
    if ignore_case:
        candidates |= _discover_case_variants(seed_terms, files=files, root=root)

    new_pairs: list[list[str]] = []
    for old in sorted(candidates, key=len, reverse=True):
        if old in already:
            continue
        new_pairs.append([old, _make_token(used)])
    return new_pairs


def _discover_java_authors(paths) -> set[str]:
    """Collect complete @author entries, excluding whitespace and comment closers."""
    pattern = re.compile(r"@author[ \t]+(?:(?!\*+/)[^\r\n])+")
    found: set[str] = set()
    for path in paths:
        if path.suffix.lower() != ".java":
            continue
        text = _read_text(path)
        if text is None:
            continue
        for match in pattern.finditer(text):
            entry = match.group(0).rstrip()
            if entry != "@author":
                found.add(entry)
    return found


def _save_map(map_path: Path, pairs: list[list[str]]) -> None:
    pairs = sorted(pairs, key=lambda x: len(x[0]), reverse=True)
    payload = json.dumps({"v": MAP_VERSION, "p": pairs}, ensure_ascii=False, separators=(",", ":"))
    map_path = map_path.resolve()
    map_path.parent.mkdir(parents=True, exist_ok=True)
    map_path.write_bytes(gzip.compress(payload.encode("utf-8"), compresslevel=9))


def _require_text_file(path: Path) -> str:
    path = path.resolve()
    if not path.is_file():
        raise SystemExit(f"Not a file: {path}")
    text = _read_text(path)
    if text is None:
        raise SystemExit(f"Not a readable UTF-8 text file: {path}")
    return text


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


def _collect_dirs(root: Path) -> list[Path]:
    """Return directories under *root* (not including root), deepest first.

    Skipped directory names (see SKIP_DIR_NAMES) are not entered and not renamed.
    Deepest-first order keeps child renames valid before parents move.
    """
    root = root.resolve()
    dirs: list[Path] = []
    for dirpath, dirnames, _filenames in os.walk(root, topdown=True, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
        for name in dirnames:
            dirs.append(Path(dirpath) / name)
    dirs.sort(key=lambda p: len(p.parts), reverse=True)
    return dirs


def _rename_dirs(root: Path, pairs: list[tuple[str, str]], *, reverse: bool) -> int:
    """Rename directory basenames under *root* according to *pairs*.

    When *reverse* is False, apply whole-word old→new (anonymize).
    When *reverse* is True, replace new→old tokens (restore).
    Returns the number of directories renamed.
    """
    changed = 0
    for path in _collect_dirs(root):
        name = path.name
        new_name = name
        if reverse:
            for old, new in pairs:
                if new in new_name:
                    new_name = new_name.replace(new, old)
        else:
            for old, new in pairs:
                new_name = _whole_word_replace(new_name, old, new)
        if new_name == name:
            continue
        dest = path.parent / new_name
        if dest.exists():
            print(f"Skip rename (target exists): {path} -> {dest}", file=sys.stderr)
            continue
        try:
            path.rename(dest)
        except OSError as exc:
            print(f"Skip rename ({exc}): {path} -> {dest}", file=sys.stderr)
            continue
        changed += 1
    return changed


def _is_binary_path(path: Path) -> bool:
    return path.suffix.lower() in BINARY_EXTENSIONS


def _read_text(path: Path) -> str | None:
    """Read *path* as UTF-8 text, or None if binary / undecodable / unreadable.

    Binary files (known extensions, or containing NUL bytes) are never treated
    as text — latin-1 and similar fallbacks are intentionally avoided because
    they can decode arbitrary bytes and corrupt archives such as JARs.
    """
    if _is_binary_path(path):
        return None
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
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


def _apply_anonymize(text: str, pairs: list[tuple[str, str]]) -> str:
    for old, new in pairs:
        text = _whole_word_replace(text, old, new)
    return text


def _apply_restore(text: str, pairs: list[tuple[str, str]]) -> str:
    for old, new in pairs:
        if new in text:
            text = text.replace(new, old)
    return text


def _load_restore_pairs(map_path: Path) -> list[tuple[str, str]]:
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
    return pairs


def anonymize(
    terms: list[str],
    map_path: Path,
    *,
    folder: Path | None = None,
    file: Path | None = None,
    ignore_case: bool = False,
) -> None:
    if (folder is None) == (file is None):
        raise SystemExit("Provide exactly one of --folder or --file.")

    seed_terms = [t for t in terms if t]
    existing_pairs = _load_map(map_path)

    if file is not None:
        path = file.resolve()
        text = _require_text_file(path)
        seed_terms.extend(sorted(_discover_java_authors([path])))
        if not seed_terms and not existing_pairs:
            raise SystemExit("No non-empty terms or Java @author entries to anonymize.")
        new_pairs = _build_anonymize_pairs(
            seed_terms,
            existing_pairs,
            ignore_case=ignore_case,
            files=[path],
        )
        all_pairs = sorted(existing_pairs + new_pairs, key=lambda p: len(p[0]), reverse=True)
        out = _apply_anonymize(text, [(o, n) for o, n in all_pairs])
        if out != text:
            _write_text(path, out)
            changed_files = 1
        else:
            changed_files = 0
        _save_map(map_path, existing_pairs + new_pairs)
        print(
            f"Anonymized {len(new_pairs)} new term(s); "
            f"{len(existing_pairs) + len(new_pairs)} total in map; "
            f"updated {changed_files} file(s); renamed 0 dir(s). Map: {map_path.resolve()}",
            file=sys.stderr,
        )
        return

    assert folder is not None
    root = folder.resolve()
    if not root.is_dir():
        raise SystemExit(f"Not a directory: {root}")

    seed_terms.extend(sorted(_discover_java_authors(_iter_files(root))))
    if not seed_terms and not existing_pairs:
        raise SystemExit("No non-empty terms or Java @author entries to anonymize.")
    new_pairs = _build_anonymize_pairs(
        seed_terms,
        existing_pairs,
        ignore_case=ignore_case,
        root=root,
    )
    # Reuse mapped tokens in new files, longest-first to avoid partial overlaps.
    all_pairs = sorted(existing_pairs + new_pairs, key=lambda p: len(p[0]), reverse=True)
    replacements = [(o, n) for o, n in all_pairs]
    changed_files = 0
    for path in _iter_files(root):
        text = _read_text(path)
        if text is None:
            continue
        orig = text
        text = _apply_anonymize(text, replacements)
        if text != orig:
            _write_text(path, text)
            changed_files += 1

    # Rename directories after file edits so walks still see original paths
    renamed_dirs = _rename_dirs(root, replacements, reverse=False)
    _save_map(map_path, all_pairs)

    print(
        f"Anonymized {len(new_pairs)} new term(s); {len(all_pairs)} total in map; "
        f"updated {changed_files} file(s); renamed {renamed_dirs} dir(s). Map: {map_path.resolve()}",
        file=sys.stderr,
    )


def restore(
    map_path: Path,
    *,
    folder: Path | None = None,
    file: Path | None = None,
) -> None:
    if (folder is None) == (file is None):
        raise SystemExit("Provide exactly one of --folder or --file.")

    pairs = _load_restore_pairs(map_path)

    if file is not None:
        path = file.resolve()
        text = _require_text_file(path)
        out = _apply_restore(text, pairs)
        if out != text:
            _write_text(path, out)
            changed_files = 1
        else:
            changed_files = 0
        print(
            f"Restored; updated {changed_files} file(s); renamed 0 dir(s).",
            file=sys.stderr,
        )
        return

    assert folder is not None
    root = folder.resolve()
    if not root.is_dir():
        raise SystemExit(f"Not a directory: {root}")

    changed_files = 0
    for path in _iter_files(root):
        text = _read_text(path)
        if text is None:
            continue
        orig = text
        text = _apply_restore(text, pairs)
        if text != orig:
            _write_text(path, text)
            changed_files += 1

    renamed_dirs = _rename_dirs(root, pairs, reverse=True)

    print(
        f"Restored; updated {changed_files} file(s); renamed {renamed_dirs} dir(s).",
        file=sys.stderr,
    )


def decode_token(token: str, map_path: Path) -> None:
    pairs = _load_map(map_path)
    if not pairs:
        raise SystemExit(f"Map file is empty or missing: {map_path}")
    for original, anon in pairs:
        if anon == token:
            print(original)
            return
    raise SystemExit(f"Token not found in map: {token}")


def encode_token(term: str, map_path: Path) -> None:
    pairs = _load_map(map_path)
    if not pairs:
        raise SystemExit(f"Map file is empty or missing: {map_path}")
    for original, anon in pairs:
        if original == term:
            print(anon)
            return
    raise SystemExit(f"Term not found in map: {term}")


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


def _add_target_args(parser: argparse.ArgumentParser) -> None:
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--folder", type=Path, help="Root folder to scan.")
    target.add_argument("--file", type=Path, help="Single text file to process.")


def main() -> None:
    ap = argparse.ArgumentParser(description="Anonymize or restore text under a folder or file.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("anonymize", help="Replace terms with unique tokens; write map file.")
    a.add_argument("--terms", nargs="*", default=[], help="Terms to anonymize (repeatable).")
    a.add_argument("--terms-file", type=Path, help="File with one term per line.")
    a.add_argument(
        "--gitleaks-report",
        type=Path,
        help="Gitleaks JSON report: JSON array of objects; each object's Secret becomes a term.",
    )
    _add_target_args(a)
    a.add_argument(
        "--map",
        type=Path,
        required=True,
        help="Output mapping file (.json.gz recommended).",
    )
    a.add_argument(
        "--ignore-case",
        action="store_true",
        help=(
            "Match terms case-insensitively, but assign a distinct token to each "
            "exact casing found (e.g. banca and Banca get different tokens)."
        ),
    )

    r = sub.add_parser("restore", help="Replace tokens from map with original terms.")
    r.add_argument("--map", type=Path, required=True, help="Mapping file from anonymize.")
    _add_target_args(r)

    g = sub.add_parser("decode", help="Show the original value of an anonymized token.")
    g.add_argument("token", help="The anonymized token to look up (e.g. __M_ANON_<hex>__).")
    g.add_argument("--map", type=Path, required=True, help="Mapping file from anonymize.")

    e = sub.add_parser("encode", help="Show the anonymized token for a plain-text term.")
    e.add_argument("term", help="The original term to look up.")
    e.add_argument("--map", type=Path, required=True, help="Mapping file from anonymize.")

    args = ap.parse_args()
    if args.cmd == "anonymize":
        terms = list(args.terms)
        if args.terms_file:
            terms.extend(_load_terms_file(args.terms_file))
        if args.gitleaks_report:
            terms.extend(_load_gitleaks_secrets(args.gitleaks_report))
        anonymize(
            terms,
            args.map,
            folder=args.folder,
            file=args.file,
            ignore_case=args.ignore_case,
        )
    elif args.cmd == "decode":
        decode_token(args.token, args.map)
    elif args.cmd == "encode":
        encode_token(args.term, args.map)
    else:
        restore(
            args.map,
            folder=args.folder,
            file=args.file,
        )


if __name__ == "__main__":
    main()
