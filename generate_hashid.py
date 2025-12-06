#!/usr/bin/env python3
"""
Generate hashid.py directly from `hashcat --example-hashes`.

Steps:
1. Run /usr/bin/hashcat --example-hashes and save output to example_hash_full.txt
2. Parse Hash mode, Name, and Example.Hash lines (ignore Example.Hash.Format)
3. Write a complete hashid.py with detection logic
"""

import subprocess
import re
from pathlib import Path

HASHCAT_BIN = "/usr/bin/hashcat"
RAW_FILE = Path("example_hash_full.txt")
OUTPUT_FILE = Path("app/lib/base/hashid.py")

def run_hashcat_and_save():
    print(f"Running: {HASHCAT_BIN} --example-hashes")
    result = subprocess.run(
        [HASHCAT_BIN, "--example-hashes"],
        capture_output=True, text=True, check=True
    )
    RAW_FILE.write_text(result.stdout)
    print(f"Saved raw output to {RAW_FILE}")
    return result.stdout.splitlines()

def parse_example_hashes(lines):
    entries = []
    current_mode = None
    current_name = None

    for line in lines:
        line = line.strip()

        # Capture "Hash mode #NNNN"
        m = re.match(r"^Hash mode #(\d+)", line)
        if m:
            current_mode = int(m.group(1))
            current_name = None
            continue

        # Capture "Name................: ..."
        if line.startswith("Name"):
            current_name = line.split(":", 1)[1].strip()
            continue

        # Skip Example.Hash.Format lines
        if line.startswith("Example.Hash.Format"):
            continue

        # Capture "Example.Hash........: ..."
        if line.startswith("Example.Hash........"):
            example_hash = line.split(":", 1)[1].strip()

            # Filter out placeholders
            if example_hash.lower() in ("plain", "n/a") or "hex-encoded" in example_hash.lower():
                continue

            if current_mode is not None and current_name and example_hash:
                entries.append({
                    "mode": current_mode,
                    "name": current_name,
                    "example_hash": example_hash
                })
            continue

    return entries

def write_hashid(entries, out_path: Path):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w") as f:
        f.write('"""\n')
        f.write("hashid.py — Auto-generated from hashcat --example-hashes\n")
        f.write('"""\n\n')
        f.write("import re\n")
        f.write("from flask import current_app\n\n")
        f.write("EXAMPLE_HASHES = [\n")
        for e in entries:
            name = e["name"].replace("'", "\\'")
            ex = e["example_hash"].replace("'", "\\'")
            f.write(f"    {{'mode': {e['mode']}, 'name': '{name}', 'example_hash': '{ex}'}},\n")
        f.write("]\n\n")
        f.write("""
class HashIdentifier:
    def __init__(self):
        self.by_prefix = {}
        self.by_regex = []
        for entry in EXAMPLE_HASHES:
            mode = entry['mode']
            name = entry['name']
            example = entry['example_hash']
            if example.startswith("$"):
                prefix = example.split("*")[0]
                self.by_prefix.setdefault(prefix, []).append({"mode": mode, "name": name})
            else:
                try:
                    regex = re.compile(re.escape(example[:16]))
                    self.by_regex.append((regex, {"mode": mode, "name": name}))
                except re.error:
                    continue

    def identify(self, hash_string):
        results = []
        for prefix, data_list in self.by_prefix.items():
            if hash_string.startswith(prefix):
                results.extend(data_list)
        for regex, data in self.by_regex:
            if regex.match(hash_string):
                results.append(data)
        # Deduplicate
        seen = set()
        dedup = []
        for r in results:
            key = (r["mode"], r["name"])
            if key not in seen:
                seen.add(key)
                dedup.append(r)
        if not dedup:
            current_app.logger.debug(f"No match found for hash: {hash_string}")
        return dedup

def guess_hash(hash_string):
    identifier = HashIdentifier()
    return identifier.identify(hash_string)
""")
    print(f"Wrote {len(entries)} entries to {out_path}")

def main():
    lines = run_hashcat_and_save()
    entries = parse_example_hashes(lines)
    write_hashid(entries, OUTPUT_FILE)
    print(f"Parsed {len(entries)} entries")
    print("First 5 entries:", entries[:5])

if __name__ == "__main__":
    main()
