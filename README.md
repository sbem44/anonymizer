# Anonymizer

Small Python helper to replace sensitive strings under a folder with unique placeholders, then restore the originals using a compact mapping file.

## Requirements

- Python 3.9+ (stdlib only)

## Usage

**Anonymize** — replace terms with tokens and write the map file:

```bash
python3 anonymize.py anonymize \
  --folder /path/to/project \
  --map /path/to/map.anon \
  --terms "Company Name" "user@example.com"
```

You can also pass terms from a file (one per line):

```bash
python3 anonymize.py anonymize \
  --folder /path/to/project \
  --map /path/to/map.anon \
  --terms-file ./terms.txt
```

Or load secrets from a **Gitleaks** JSON report (top-level JSON array of findings; each object’s `Secret` field is used as a term):

```bash
python3 anonymize.py anonymize \
  --folder /path/to/project \
  --map /path/to/map.anon \
  --gitleaks-report ./gitleaks-report.json
```

You can combine `--terms`, `--terms-file`, and `--gitleaks-report`.

**Restore** — swap tokens back to the original strings (use the same folder root as anonymize):

```bash
python3 anonymize.py restore \
  --folder /path/to/project \
  --map /path/to/map.anon
```

**Decode** — look up the original value of an anonymized token:

```bash
python3 anonymize.py decode __M_ANON_e647cc08cc120d60aa5d9010b2eb33e5__ \
  --map /path/to/map.anon
```

**Encode** — look up the anonymized token for a plain-text term:

```bash
python3 anonymize.py encode "myplainkeyword" \
  --map /path/to/map.anon
```

## Map file

The map is gzip-compressed JSON: `{"v":1,"p":[["old","new"],...]}`. If the file is not gzip (no gzip header), plain JSON is accepted.

## Incremental runs

Running `anonymize` multiple times with the **same `--map` file** is fully supported. The script loads the existing map, skips terms already handled, anonymizes only the new terms, and saves a combined map. A single `restore` call undoes everything.

```bash
# First pass: secrets from gitleaks
python3 anonymize.py anonymize --folder ./project --map ./map.anon \
  --gitleaks-report ./gitleaks-report.json

# Second pass: additional terms (map accumulates)
python3 anonymize.py anonymize --folder ./project --map ./map.anon \
  --terms-file ./terms.txt

# Later: realized you forgot some terms — just extend terms.txt and re-run
python3 anonymize.py anonymize --folder ./project --map ./map.anon \
  --terms-file ./terms.txt

# Restore everything in one go
python3 anonymize.py restore --folder ./project --map ./map.anon
```

## Notes

- Only **UTF-8** text files are modified. Binary files (JARs, ZIPs, images, etc.) are never changed — skipped by extension and by NUL-byte detection. See `BINARY_EXTENSIONS` in `anonymize.py`.
- Some directories are skipped (for example `.git`, `node_modules`, `target`, build/virtualenv folders). See `SKIP_DIR_NAMES` in `anonymize.py`.
- Keep the map **outside** the tree you anonymize so it is not edited by mistake.
- Treat the map as **secret**; it contains the original strings.
