#!/usr/bin/env python3
"""
Search stbc.exe for Py_InitModule4 by finding CALL instructions
that target known Python C API functions.
"""

import struct
import sys

EXE_PATH = "/mnt/c/GOG Games/Star Trek Bridge Commander/stbc.exe"

# Known VAs
VA_PyImport_AddModule = 0x0075B890
VA_PyModule_GetDict   = 0x00773990
VA_Py_Initialize      = 0x0074A590
VA_SUSPECT            = 0x006F7CE0

def read_pe(path):
    with open(path, "rb") as f:
        data = f.read()
    return data

def parse_pe(data):
    """Parse minimal PE headers to get image base and section table."""
    assert data[0:2] == b'MZ', "Not a valid MZ executable"
    pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
    assert data[pe_offset:pe_offset+4] == b'PE\x00\x00', "Not a valid PE"
    
    coff_offset = pe_offset + 4
    num_sections = struct.unpack_from('<H', data, coff_offset + 2)[0]
    optional_hdr_size = struct.unpack_from('<H', data, coff_offset + 16)[0]
    
    opt_offset = coff_offset + 20
    magic = struct.unpack_from('<H', data, opt_offset)[0]
    assert magic == 0x10B, f"Expected PE32, got magic {magic:#x}"
    
    image_base = struct.unpack_from('<I', data, opt_offset + 28)[0]
    
    section_offset = opt_offset + optional_hdr_size
    
    sections = []
    for i in range(num_sections):
        s_off = section_offset + i * 40
        name = data[s_off:s_off+8].rstrip(b'\x00').decode('ascii', errors='replace')
        virt_size = struct.unpack_from('<I', data, s_off + 8)[0]
        virt_addr = struct.unpack_from('<I', data, s_off + 12)[0]
        raw_size  = struct.unpack_from('<I', data, s_off + 16)[0]
        raw_ptr   = struct.unpack_from('<I', data, s_off + 20)[0]
        sections.append({
            'name': name,
            'virt_size': virt_size,
            'virt_addr': virt_addr,
            'raw_size': raw_size,
            'raw_ptr': raw_ptr,
        })
    
    return image_base, sections

def va_to_file_offset(va, image_base, sections):
    rva = va - image_base
    for s in sections:
        if s['virt_addr'] <= rva < s['virt_addr'] + s['raw_size']:
            return s['raw_ptr'] + (rva - s['virt_addr'])
    return None

def file_offset_to_va(offset, image_base, sections):
    for s in sections:
        if s['raw_ptr'] <= offset < s['raw_ptr'] + s['raw_size']:
            rva = s['virt_addr'] + (offset - s['raw_ptr'])
            return image_base + rva
    return None

def find_call_targets(data, image_base, sections, target_va):
    results = []
    for s in sections:
        start = s['raw_ptr']
        end = start + s['raw_size']
        pos = start
        while pos < end - 5:
            if data[pos] == 0xE8:
                rel32 = struct.unpack_from('<i', data, pos + 1)[0]
                caller_va = file_offset_to_va(pos, image_base, sections)
                if caller_va is not None:
                    call_target_va = caller_va + 5 + rel32
                    if call_target_va == target_va:
                        results.append((pos, caller_va))
            pos += 1
    return results

def main():
    print(f"Reading {EXE_PATH}...")
    data = read_pe(EXE_PATH)
    print(f"File size: {len(data)} bytes ({len(data)/1024/1024:.2f} MB)")
    
    image_base, sections = parse_pe(data)
    print(f"\nImage base: {image_base:#010x}")
    print(f"\nSections:")
    for s in sections:
        va_start = image_base + s['virt_addr']
        va_end = va_start + s['virt_size']
        print(f"  {s['name']:8s}  VA {va_start:#010x}-{va_end:#010x}  "
              f"RawPtr {s['raw_ptr']:#010x}  RawSize {s['raw_size']:#010x}")
    
    # Verify known addresses
    for name, va in [("PyImport_AddModule", VA_PyImport_AddModule),
                     ("PyModule_GetDict", VA_PyModule_GetDict),
                     ("Py_Initialize", VA_Py_Initialize)]:
        fo = va_to_file_offset(va, image_base, sections)
        if fo is not None:
            first_bytes = data[fo:fo+8]
            print(f"\n  {name} @ {va:#010x} -> file offset {fo:#010x}, first bytes: {first_bytes.hex(' ')}")
        else:
            print(f"\n  {name} @ {va:#010x} -> COULD NOT MAP TO FILE OFFSET")
    
    # =========================================================================
    # Step 1: Find all CALLs to PyImport_AddModule
    # =========================================================================
    print(f"\n{'='*70}")
    print(f"Searching for CALL instructions targeting PyImport_AddModule ({VA_PyImport_AddModule:#010x})...")
    calls_addmodule = find_call_targets(data, image_base, sections, VA_PyImport_AddModule)
    print(f"Found {len(calls_addmodule)} CALL(s) to PyImport_AddModule:\n")
    for fo, caller_va in calls_addmodule:
        ctx_after = data[fo:fo+32]
        print(f"  Caller VA: {caller_va:#010x}  (file offset {fo:#010x})")
        print(f"    At+After: {ctx_after.hex(' ')}")
        print()
    
    # =========================================================================
    # Step 2: Find all CALLs to PyModule_GetDict
    # =========================================================================
    print(f"{'='*70}")
    print(f"Searching for CALL instructions targeting PyModule_GetDict ({VA_PyModule_GetDict:#010x})...")
    calls_getdict = find_call_targets(data, image_base, sections, VA_PyModule_GetDict)
    print(f"Found {len(calls_getdict)} CALL(s) to PyModule_GetDict:\n")
    for fo, caller_va in calls_getdict:
        print(f"  Caller VA: {caller_va:#010x}  (file offset {fo:#010x})")
    print()
    
    # =========================================================================
    # Step 3: Find functions that call BOTH within proximity
    # =========================================================================
    print(f"{'='*70}")
    print("Looking for functions calling BOTH PyImport_AddModule AND PyModule_GetDict")
    print("within 150 bytes (strong Py_InitModule4 indicator):\n")
    
    PROXIMITY = 150
    
    matches = []
    for fo_a, va_a in calls_addmodule:
        for fo_g, va_g in calls_getdict:
            dist = va_g - va_a
            if 0 < dist < PROXIMITY:
                matches.append((va_a, va_g, dist))
    
    if matches:
        for va_a, va_g, dist in matches:
            print(f"  *** MATCH: CALL PyImport_AddModule @ {va_a:#010x}, "
                  f"CALL PyModule_GetDict @ {va_g:#010x} (delta: +{dist} bytes)")
    else:
        print("  No close matches found within 150 bytes. Trying wider search (500 bytes)...\n")
        for fo_a, va_a in calls_addmodule:
            for fo_g, va_g in calls_getdict:
                dist = va_g - va_a
                if 0 < dist < 500:
                    matches.append((va_a, va_g, dist))
                    print(f"  Near match: CALL AddModule @ {va_a:#010x}, "
                          f"CALL GetDict @ {va_g:#010x} (delta: +{dist} bytes)")
        if not matches:
            # Try negative direction too
            for fo_g, va_g in calls_getdict:
                for fo_a, va_a in calls_addmodule:
                    dist = va_a - va_g
                    if 0 < dist < 500:
                        print(f"  Reverse match: CALL GetDict @ {va_g:#010x}, "
                              f"CALL AddModule @ {va_a:#010x} (delta: +{dist} bytes)")
    
    # For each match, find function start
    for va_a, va_g, dist in matches:
        fo_a = va_to_file_offset(va_a, image_base, sections)
        search_start = max(0, fo_a - 200)
        func_start_va = None
        for check in range(fo_a - 1, search_start, -1):
            if data[check] == 0x55 and check + 2 < len(data) and data[check+1] == 0x8B and data[check+2] == 0xEC:
                func_start_va = file_offset_to_va(check, image_base, sections)
                break
        
        if func_start_va:
            print(f"\n  Likely Py_InitModule4 start: {func_start_va:#010x}")
            fo_func = va_to_file_offset(func_start_va, image_base, sections)
            print(f"\n  First 256 bytes of function at {func_start_va:#010x}:")
            for line_start in range(0, 256, 16):
                chunk = data[fo_func + line_start : fo_func + line_start + 16]
                hex_str = ' '.join(f'{b:02x}' for b in chunk)
                ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                print(f"    {func_start_va + line_start:#010x}: {hex_str:<48s} {ascii_str}")
        else:
            print(f"\n  Could not find function prologue before {va_a:#010x}")
            show_va = va_a - 80
            fo_show = va_to_file_offset(show_va, image_base, sections)
            if fo_show:
                print(f"  Showing from {show_va:#010x}:")
                for line_start in range(0, 160, 16):
                    chunk = data[fo_show + line_start : fo_show + line_start + 16]
                    hex_str = ' '.join(f'{b:02x}' for b in chunk)
                    print(f"    {show_va + line_start:#010x}: {hex_str}")
    
    # =========================================================================
    # Step 4: Check what's at VA 0x006F7CE0
    # =========================================================================
    print(f"\n{'='*70}")
    print(f"Checking suspected address VA {VA_SUSPECT:#010x}:")
    fo_suspect = va_to_file_offset(VA_SUSPECT, image_base, sections)
    if fo_suspect is not None:
        suspect_bytes = data[fo_suspect:fo_suspect+64]
        print(f"  File offset: {fo_suspect:#010x}")
        print(f"  First 64 bytes (hex):")
        for line_start in range(0, 64, 16):
            chunk = suspect_bytes[line_start:line_start+16]
            hex_str = ' '.join(f'{b:02x}' for b in chunk)
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            print(f"    {VA_SUSPECT + line_start:#010x}: {hex_str:<48s} {ascii_str}")
        
        # Check if this is a function prologue
        if suspect_bytes[0] == 0x55 and suspect_bytes[1] == 0x8B and suspect_bytes[2] == 0xEC:
            print(f"\n  YES - this starts with push ebp; mov ebp, esp (function prologue)")
        elif suspect_bytes[0] == 0xCC:
            print(f"\n  This is INT3 (padding/breakpoint)")
        else:
            print(f"\n  First byte: {suspect_bytes[0]:#04x} - not a standard function prologue")
        
        # Search for calls to known APIs within 500 bytes
        print(f"\n  Searching for calls to known Python APIs within 500 bytes of {VA_SUSPECT:#010x}:")
        region_end = min(len(data), fo_suspect + 500)
        for check in range(fo_suspect, region_end - 5):
            if data[check] == 0xE8:
                rel32 = struct.unpack_from('<i', data, check + 1)[0]
                check_va = file_offset_to_va(check, image_base, sections)
                if check_va is not None:
                    target = check_va + 5 + rel32
                    if target == VA_PyImport_AddModule:
                        print(f"    CALL PyImport_AddModule at {check_va:#010x}")
                    elif target == VA_PyModule_GetDict:
                        print(f"    CALL PyModule_GetDict at {check_va:#010x}")
                    elif target == VA_Py_Initialize:
                        print(f"    CALL Py_Initialize at {check_va:#010x}")
    else:
        print(f"  Could not map VA {VA_SUSPECT:#010x} to file offset!")
    
    # =========================================================================
    # Step 5: Also search for Py_InitModule string references
    # =========================================================================
    print(f"\n{'='*70}")
    print("Searching for 'Py_InitModule4' string in binary...")
    idx = data.find(b'Py_InitModule4')
    while idx != -1:
        va = file_offset_to_va(idx, image_base, sections)
        context = data[idx:idx+30]
        print(f"  Found at file offset {idx:#010x} (VA {va:#010x if va else 'N/A'}): {context}")
        idx = data.find(b'Py_InitModule4', idx + 1)
    
    # Also search for the module_api_version warning string from Python 1.5
    print("\nSearching for 'module_api_version' or 'api version' string...")
    for needle in [b'module_api_version', b'api_version', b'API version']:
        idx = data.find(needle)
        while idx != -1:
            va = file_offset_to_va(idx, image_base, sections)
            context = data[max(0,idx-10):idx+50]
            print(f"  Found '{needle.decode()}' at file offset {idx:#010x} (VA {va:#010x if va else 'N/A'})")
            print(f"    Context: {context}")
            idx = data.find(needle, idx + 1)

if __name__ == "__main__":
    main()
