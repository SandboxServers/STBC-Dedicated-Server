# Ghidra Jython Script: Trace SWIG Wrappers to Name C++ Target Functions
# @category STBC
# @description Walks 3,990 SWIG wrapper functions, identifies the underlying
#   C++ method each wrapper calls (by filtering out Python/SWIG helpers), and
#   names the target function. Uses frequency analysis to auto-detect helpers.
#
# Two-pass approach:
#   Pass 1: Walk all wrappers, collect all CALL targets and their frequency
#   Pass 2: Targets appearing in >50 wrappers are helpers (e.g., PyArg_ParseTuple)
#   Pass 3: For each wrapper, filter helpers, name the last remaining CALL target
#
# Run from Ghidra Script Manager with stbc.exe loaded.
# Prerequisite: Run ghidra_annotate_swig.py first (names wrapper functions).

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit

SWIG_TABLE_START = 0x008e6438
SWIG_TABLE_END   = 0x008f5d98
ENTRY_SIZE       = 16

# Known helper functions (manually verified, always filtered)
KNOWN_HELPERS = set([
    0x0074e310,  # PyArg_ParseTuple
    0x005bae00,  # SWIG_GetPointerObj
    0x005bb0e0,  # SWIG_NewPointerObj
    0x005bb040,  # SWIG_MakePtr
    0x0074d280,  # Py_BuildValue
    0x0074c140,  # PyObject_GetAttrString
    0x00776cf0,  # PyObject_CallObject
    0x0074d140,  # Py_InitModule4
    0x00717840,  # NiAlloc
    0x00718cb0,  # NiAlloc (variant)
    0x00717960,  # NiFree
])

# Minimum frequency to classify a function as a helper
# (helpers appear in many wrappers; targets appear in just one)
HELPER_FREQ_THRESHOLD = 50

def readCString(addr):
    """Read a NULL-terminated C string from memory."""
    result = []
    mem = currentProgram.getMemory()
    for i in range(512):
        b = mem.getByte(addr.add(i))
        if b == 0:
            break
        result.append(chr(b & 0xFF))
    return ''.join(result)

def readInt(addr):
    """Read a 4-byte little-endian int from memory."""
    return currentProgram.getMemory().getInt(addr)

def find_calls(func_addr, fm, listing):
    """Find all CALL target addresses within a function."""
    func = fm.getFunctionAt(toAddr(func_addr))
    if func is None:
        return []
    calls = []
    try:
        instIter = listing.getInstructions(func.getBody(), True)
        while instIter.hasNext():
            inst = instIter.next()
            if inst.getMnemonicString() == "CALL":
                refs = inst.getReferencesFrom()
                for ref in refs:
                    if ref.getReferenceType().isCall():
                        calls.append(ref.getToAddress().getOffset())
    except:
        pass
    return calls

def derive_target_name(swig_name):
    """Derive a C++ target function name from a SWIG wrapper name.
    Examples:
        swig_NiNode_GetName -> NiNode_GetName
        swig_delete_NiNode  -> NiNode_dtor
        swig_new_NiNode     -> NiNode_new
    """
    # Remove swig_ prefix
    if swig_name.startswith("swig_"):
        name = swig_name[5:]
    else:
        name = swig_name

    # Handle delete_ClassName -> ClassName_dtor
    if name.startswith("delete_"):
        return name[7:] + "_dtor"

    # Handle new_ClassName -> ClassName_new
    if name.startswith("new_"):
        return name[4:] + "_new"

    return name

def main():
    fm = currentProgram.getFunctionManager()
    st = currentProgram.getSymbolTable()
    listing = currentProgram.getListing()
    mem = currentProgram.getMemory()

    # ========================================
    # Pass 1: Collect all CALL targets and frequency
    # ========================================
    println("Pass 1: Scanning %d SWIG wrappers for CALL targets..." % (
        (SWIG_TABLE_END - SWIG_TABLE_START) / ENTRY_SIZE))

    # Read all wrapper entries
    entries = []  # (method_name, func_ptr)
    addr_int = SWIG_TABLE_START
    while addr_int < SWIG_TABLE_END:
        entry_addr = toAddr(addr_int)
        try:
            name_ptr = readInt(entry_addr)
            func_ptr = readInt(entry_addr.add(4))
            if name_ptr == 0:
                break
            method_name = readCString(toAddr(name_ptr))
            if method_name and 0x00401000 <= func_ptr <= 0x00860000:
                entries.append((method_name, func_ptr))
        except:
            pass
        addr_int += ENTRY_SIZE

    println("  Found %d valid entries" % len(entries))

    # Collect call frequency across all wrappers
    call_frequency = {}  # target_addr -> count
    wrapper_calls = {}   # func_ptr -> [call_targets]

    for idx, (method_name, func_ptr) in enumerate(entries):
        calls = find_calls(func_ptr, fm, listing)
        wrapper_calls[func_ptr] = calls
        for target in calls:
            if target in call_frequency:
                call_frequency[target] = call_frequency[target] + 1
            else:
                call_frequency[target] = 1

        if (idx + 1) % 500 == 0:
            println("  Scanned %d / %d wrappers..." % (idx + 1, len(entries)))

    println("  Unique CALL targets: %d" % len(call_frequency))

    # ========================================
    # Pass 2: Identify helpers by frequency
    # ========================================
    println("Pass 2: Identifying helpers (frequency > %d)..." % HELPER_FREQ_THRESHOLD)

    auto_helpers = set()
    for target, count in call_frequency.items():
        if count >= HELPER_FREQ_THRESHOLD:
            auto_helpers.add(target)

    all_helpers = KNOWN_HELPERS | auto_helpers
    println("  Known helpers: %d" % len(KNOWN_HELPERS))
    println("  Auto-detected helpers: %d" % len(auto_helpers))
    println("  Total helpers: %d" % len(all_helpers))

    # Print top helpers for debugging
    sorted_helpers = sorted([(c, t) for t, c in call_frequency.items() if t in auto_helpers],
                           reverse=True)
    for count, target in sorted_helpers[:15]:
        fn = fm.getFunctionAt(toAddr(target))
        name = fn.getName() if fn else "???"
        println("    0x%08X (%s) - %d occurrences" % (target, name, count))

    # ========================================
    # Pass 3: Name C++ targets
    # ========================================
    println("Pass 3: Naming C++ target functions...")

    targets_named = 0
    targets_skipped_existing = 0
    targets_skipped_multi = 0
    targets_skipped_none = 0
    targets_skipped_inline = 0

    for method_name, func_ptr in entries:
        calls = wrapper_calls.get(func_ptr, [])

        # Filter out helpers
        non_helper_calls = [c for c in calls if c not in all_helpers]

        if len(non_helper_calls) == 0:
            # No non-helper calls - wrapper is inline (field access, etc.)
            targets_skipped_inline += 1
            continue

        if len(non_helper_calls) > 3:
            # Too many non-helper calls - ambiguous, skip
            targets_skipped_multi += 1
            continue

        # Take the LAST non-helper call as the target
        # (pattern: setup calls first, then actual method call)
        target_addr_int = non_helper_calls[-1]
        target_name = derive_target_name("swig_" + method_name)

        # Don't name if target is another SWIG wrapper
        if target_name.startswith("swig_"):
            targets_skipped_none += 1
            continue

        target_addr = toAddr(target_addr_int)
        fn = fm.getFunctionAt(target_addr)
        if fn is None:
            # Try to create function
            fn = createFunction(target_addr, target_name)
            if fn is not None:
                targets_named += 1
                listing.setComment(target_addr, CodeUnit.PLATE_COMMENT,
                    "C++ implementation called by SWIG wrapper swig_%s" % method_name)
            continue

        old_name = fn.getName()
        if old_name != target_name:
            try:
                fn.setName(target_name, SourceType.USER_DEFINED)
                targets_named += 1
                listing.setComment(target_addr, CodeUnit.PLATE_COMMENT,
                    "C++ implementation called by SWIG wrapper swig_%s" % method_name)
            except:
                targets_skipped_existing += 1
        else:
            targets_skipped_existing += 1

    println("")
    println("=" * 60)
    println("SWIG Target Tracing Complete")
    println("  Total SWIG wrappers:     %d" % len(entries))
    println("  C++ targets named:       %d" % targets_named)
    println("  Skipped (existing name): %d" % targets_skipped_existing)
    println("  Skipped (inline/field):  %d" % targets_skipped_inline)
    println("  Skipped (ambiguous):     %d" % targets_skipped_multi)
    println("  Skipped (other):         %d" % targets_skipped_none)
    println("=" * 60)

main()
