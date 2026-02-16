#!/usr/bin/env python3
"""
Generate function_names.inc.c from Ghidra function export.

Reads tools/function_names_export.txt (format: 0xADDRESS,NAME per line),
produces src/proxy/ddraw_main/function_names.inc.c with a sorted static
lookup table for binary-search resolution of caller addresses.

Usage:
    python3 tools/generate_function_names.py
"""

import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SCRIPT_DIR)
INPUT_FILE = os.path.join(SCRIPT_DIR, "function_names_export.txt")
OUTPUT_FILE = os.path.join(ROOT_DIR, "src", "proxy", "ddraw_main", "function_names.inc.c")


def main():
    if not os.path.exists(INPUT_FILE):
        print(f"ERROR: {INPUT_FILE} not found", file=sys.stderr)
        print("Run the Ghidra export first (see tools/README or CLAUDE.md)", file=sys.stderr)
        sys.exit(1)

    entries = []
    with open(INPUT_FILE, "r") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",", 1)
            if len(parts) != 2:
                print(f"WARNING: skipping malformed line {lineno}: {line!r}", file=sys.stderr)
                continue
            addr_str, name = parts
            try:
                addr = int(addr_str, 16)
            except ValueError:
                print(f"WARNING: bad address on line {lineno}: {addr_str!r}", file=sys.stderr)
                continue
            # Sanitize name for C string (escape backslashes and quotes)
            name = name.replace("\\", "\\\\").replace('"', '\\"')
            entries.append((addr, name))

    # Sort by address
    entries.sort(key=lambda e: e[0])

    # Deduplicate (keep first occurrence at each address)
    deduped = []
    seen_addrs = set()
    for addr, name in entries:
        if addr not in seen_addrs:
            seen_addrs.add(addr)
            deduped.append((addr, name))
    entries = deduped

    print(f"Generating {OUTPUT_FILE} with {len(entries)} entries...")

    with open(OUTPUT_FILE, "w") as f:
        f.write("/* AUTO-GENERATED from Ghidra function export. Do not edit manually.\n")
        f.write(" * Source: tools/function_names_export.txt\n")
        f.write(f" * Entries: {len(entries)}\n")
        f.write(" * Regenerate: python3 tools/generate_function_names.py */\n\n")
        f.write("typedef struct { DWORD addr; const char* name; } FuncName;\n\n")
        f.write("static const FuncName g_funcNames[] = {\n")
        for addr, name in entries:
            f.write(f'    {{ 0x{addr:08X}, "{name}" }},\n')
        f.write("    { 0, NULL }\n")
        f.write("};\n\n")
        f.write("#define FUNC_NAME_COUNT (sizeof(g_funcNames)/sizeof(g_funcNames[0]) - 1)\n")

    print(f"Done. {len(entries)} function entries written.")


if __name__ == "__main__":
    main()
