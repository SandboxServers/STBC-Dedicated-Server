# Ghidra Jython Script: Discover Function Names from Debug Strings
# @category STBC
# @description Scans all defined strings in stbc.exe for patterns that reveal
#   function names (e.g., "ClassName::MethodName" in assertions/debug output).
#   For each identifying string, finds the function(s) that reference it and
#   names the function if it's currently unnamed (FUN_*).
#
# Patterns detected:
#   1. "ClassName::MethodName" (C++ debug assertions, error messages)
#   2. "ClassName.MethodName" (some TG framework styles)
#   3. Known error/assert format strings that identify specific functions
#
# Run from Ghidra Script Manager with stbc.exe loaded.
# Should run LAST (after all other annotation scripts) to benefit from
# existing naming when filtering out already-named functions.

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit
import re

# Code range for stbc.exe functions
CODE_START = 0x00401000
CODE_END   = 0x00860000

# Data range for strings
DATA_START = 0x00860000
DATA_END   = 0x009b0000

# Minimum string length to consider
MIN_STRING_LEN = 5

# ============================================================================
# Patterns that identify function names from strings
# ============================================================================

# Pattern 1: "ClassName::MethodName" - C++ assertion/debug strings
# These appear in MSVC assert macros and custom debug output
# Example: "NiNode::AttachChild" in an assertion message
CPP_METHOD_PATTERN = re.compile(r'^([A-Z][A-Za-z0-9_]+)::([A-Z_][A-Za-z0-9_]+)$')

# Pattern 2: Embedded in longer strings like "NiNode::AttachChild: child is NULL"
CPP_METHOD_IN_STRING = re.compile(r'([A-Z][A-Za-z0-9_]{2,})::([A-Z_][A-Za-z0-9_]{2,})')

# Pattern 3: Module-style "ClassName.MethodName" (TG framework)
TG_METHOD_PATTERN = re.compile(r'^([A-Z][A-Za-z0-9_]+)\.([A-Z][A-Za-z0-9_]+)$')

# ============================================================================
# Known function-identifying strings (manually verified patterns)
# These map a distinctive string to the function name it identifies.
# Only the FIRST xref to the string is named.
# ============================================================================
KNOWN_STRING_TO_FUNC = {
    # NiStream operations
    "NiStream::Load": "NiStream_Load",
    "NiStream::Save": "NiStream_Save",
    "NiStream::RegisterObject": "NiStream_RegisterObject",

    # Error/assert messages that identify their containing function
    "pkObject is not NULL": None,  # skip - too generic
    "Error in LinkObject": "NiStream_LinkObject",
}

# ============================================================================
# Exclusion patterns - strings that look like method names but aren't useful
# ============================================================================
EXCLUDED_PREFIXES = [
    "DAT_",    # Ghidra default labels
    "FUN_",    # Ghidra default labels
    "LAB_",    # Ghidra default labels
    "s_",      # Ghidra string labels
]

EXCLUDED_CLASSES = set([
    # Standard library / CRT classes (not interesting for game RE)
    "std", "basic_string", "allocator", "char_traits",
    "ios_base", "locale", "facet", "ctype",
    # Python internal classes
    "Py", "PyObject",
])

# Method names that are too generic to be useful for naming
EXCLUDED_METHODS = set([
    "GetRTTI", "ProcessClone", "LoadBinary", "LinkObject",
    "RegisterStreamables", "SaveBinary", "IsEqual",
    # These are common virtuals, better named by vtable scripts
])


def get_all_strings():
    """Collect all defined strings in the data section."""
    listing = currentProgram.getListing()
    mem = currentProgram.getMemory()
    strings = []

    dataIter = listing.getDefinedData(True)
    while dataIter.hasNext():
        data = dataIter.next()
        addr = data.getMinAddress()
        addr_int = addr.getOffset()

        # Only look at data section
        if addr_int < DATA_START or addr_int > DATA_END:
            continue

        # Check if it's a string type
        dt = data.getDataType()
        type_name = dt.getName() if dt else ""
        if "string" not in type_name.lower() and "char" not in type_name.lower():
            # Also check for TerminatedCString, etc.
            if not type_name.startswith("ds") and "unicode" not in type_name.lower():
                continue

        try:
            val = data.getValue()
            if val is not None and isinstance(val, (str,)):
                if len(val) >= MIN_STRING_LEN:
                    strings.append((addr_int, val))
        except:
            pass

    return strings


def get_all_strings_via_iterator():
    """Fallback: iterate all defined data looking for string-like content."""
    listing = currentProgram.getListing()
    strings = []

    # Use the string data type checker
    from ghidra.program.util import DefinedDataIterator
    try:
        strIter = DefinedDataIterator.definedStrings(currentProgram)
        while strIter.hasNext():
            data = strIter.next()
            addr = data.getMinAddress()
            addr_int = addr.getOffset()
            try:
                val = data.getValue()
                if val is not None and len(str(val)) >= MIN_STRING_LEN:
                    strings.append((addr_int, str(val)))
            except:
                pass
    except:
        # If DefinedDataIterator not available, use manual scan
        return get_all_strings()

    return strings


def find_xrefs_to(addr_int):
    """Find all references to a given address."""
    rm = currentProgram.getReferenceManager()
    addr = toAddr(addr_int)
    refs = rm.getReferencesTo(addr)
    result = []
    for ref in refs:
        from_addr = ref.getFromAddress().getOffset()
        if CODE_START <= from_addr <= CODE_END:
            result.append(from_addr)
    return result


def get_function_at_address(addr_int, fm):
    """Get the function containing the given address."""
    addr = toAddr(addr_int)
    return fm.getFunctionContaining(addr)


def sanitize_name(name):
    """Make a string safe for use as a Ghidra symbol name."""
    # Replace invalid characters
    result = ""
    for ch in name:
        if ch.isalnum() or ch == '_':
            result += ch
        elif ch in (':',):
            result += '_'
        else:
            result += '_'
    # Remove leading digits
    while result and result[0].isdigit():
        result = result[1:]
    # Remove double underscores
    while '__' in result:
        result = result.replace('__', '_')
    # Remove trailing underscore
    result = result.strip('_')
    return result


def get_plate_comment(listing, addr):
    """Get plate comment from a CodeUnit (listing.getComment doesn't exist)."""
    cu = listing.getCodeUnitAt(addr)
    if cu is not None:
        return cu.getComment(CodeUnit.PLATE_COMMENT)
    return None


def main():
    fm = currentProgram.getFunctionManager()
    st = currentProgram.getSymbolTable()
    listing = currentProgram.getListing()

    println("Phase 6: String-Referenced Function Discovery")
    println("=" * 60)

    # Step 1: Collect all strings
    println("Scanning defined strings...")
    strings = get_all_strings_via_iterator()
    println("  Found %d strings (>= %d chars)" % (len(strings), MIN_STRING_LEN))

    # Step 2: Find strings matching our patterns
    println("Matching patterns...")

    candidates = []  # (string_addr, string_val, proposed_name, source_pattern)

    for str_addr, str_val in strings:
        # Pattern 1: Exact "ClassName::MethodName"
        m = CPP_METHOD_PATTERN.match(str_val)
        if m:
            cls_name = m.group(1)
            method_name = m.group(2)
            if cls_name not in EXCLUDED_CLASSES and method_name not in EXCLUDED_METHODS:
                proposed = "%s_%s" % (cls_name, method_name)
                candidates.append((str_addr, str_val, proposed, "exact_cpp"))
                continue

        # Pattern 2: "ClassName::MethodName" embedded in longer string
        m = CPP_METHOD_IN_STRING.search(str_val)
        if m:
            cls_name = m.group(1)
            method_name = m.group(2)
            if cls_name not in EXCLUDED_CLASSES and method_name not in EXCLUDED_METHODS:
                # Only use if string starts with or prominently features the pattern
                # (avoid false matches in long strings)
                if str_val.startswith(cls_name + "::"):
                    proposed = "%s_%s" % (cls_name, method_name)
                    candidates.append((str_addr, str_val, proposed, "prefix_cpp"))
                    continue

        # Pattern 3: Known string -> function name mappings
        if str_val in KNOWN_STRING_TO_FUNC:
            proposed = KNOWN_STRING_TO_FUNC[str_val]
            if proposed is not None:
                candidates.append((str_addr, str_val, proposed, "known"))

    println("  Found %d candidate strings" % len(candidates))

    # Step 3: For each candidate, find xrefs and name the function
    println("Tracing references and naming functions...")

    named_count = 0
    skipped_no_xref = 0
    skipped_multi_func = 0
    skipped_already_named = 0
    skipped_duplicate = 0
    commented_only = 0

    # Track which functions we've already named (avoid conflicts)
    names_used = {}  # proposed_name -> function_addr

    for str_addr, str_val, proposed_name, pattern in candidates:
        # Find code references to this string
        xrefs = find_xrefs_to(str_addr)

        if len(xrefs) == 0:
            skipped_no_xref += 1
            continue

        # Find which functions contain these xrefs
        funcs_seen = {}  # func_entry_addr -> func_obj
        for xref_addr in xrefs:
            fn = get_function_at_address(xref_addr, fm)
            if fn is not None:
                entry = fn.getEntryPoint().getOffset()
                if entry not in funcs_seen:
                    funcs_seen[entry] = fn

        if len(funcs_seen) == 0:
            skipped_no_xref += 1
            continue

        # Sanitize the proposed name
        safe_name = sanitize_name(proposed_name)
        if not safe_name:
            continue

        if len(funcs_seen) == 1:
            # Single function references this string - high confidence
            func_addr, fn = funcs_seen.items()[0]

            old_name = fn.getName()
            if not old_name.startswith("swig_") and not old_name.startswith("py_") and not old_name.startswith("NiFactory_") and not old_name.startswith("NiRegister_"):
                # Check for name collision
                if safe_name in names_used:
                    # Name already used by another function
                    if names_used[safe_name] != func_addr:
                        skipped_duplicate += 1
                        # Add as comment instead
                        entry_addr = fn.getEntryPoint()
                        existing = get_plate_comment(listing, entry_addr) or ""
                        note = "\nString reference: \"%s\" (name conflict with 0x%08X)" % (
                            str_val, names_used[safe_name])
                        if note not in existing:
                            listing.setComment(entry_addr, CodeUnit.PLATE_COMMENT,
                                existing + note)
                    continue

                fn.setName(safe_name, SourceType.USER_DEFINED)
                names_used[safe_name] = func_addr
                named_count += 1

                # Add plate comment
                entry_addr = fn.getEntryPoint()
                listing.setComment(entry_addr, CodeUnit.PLATE_COMMENT,
                    "Named from debug string: \"%s\"\nPattern: %s\nString at: 0x%08X" % (
                        str_val, pattern, str_addr))
            else:
                skipped_already_named += 1
                # Add alias comment if useful
                entry_addr = fn.getEntryPoint()
                existing = get_plate_comment(listing, entry_addr) or ""
                note = "\nDebug string reference: \"%s\"" % str_val
                if note not in existing and str_val not in existing:
                    listing.setComment(entry_addr, CodeUnit.PLATE_COMMENT,
                        existing + note)
                    commented_only += 1
        else:
            # Multiple functions reference this string
            # Still useful: add comment to all, but only name if one is FUN_
            unnamed_funcs = []
            for func_addr, fn in funcs_seen.items():
                old_name = fn.getName()
                if not old_name.startswith("swig_") and not old_name.startswith("py_") and not old_name.startswith("NiFactory_") and not old_name.startswith("NiRegister_"):
                    unnamed_funcs.append((func_addr, fn))

            if len(unnamed_funcs) == 1:
                # Only one unnamed function - name it
                func_addr, fn = unnamed_funcs[0]
                if safe_name not in names_used:
                    fn.setName(safe_name, SourceType.USER_DEFINED)
                    names_used[safe_name] = func_addr
                    named_count += 1

                    entry_addr = fn.getEntryPoint()
                    listing.setComment(entry_addr, CodeUnit.PLATE_COMMENT,
                        "Named from debug string: \"%s\"\nPattern: %s (sole unnamed ref)\nString at: 0x%08X\nAlso referenced by %d other named function(s)" % (
                            str_val, pattern, str_addr, len(funcs_seen) - 1))
                else:
                    skipped_duplicate += 1
            else:
                skipped_multi_func += 1
                # Add comments to all
                for func_addr, fn in funcs_seen.items():
                    entry_addr = fn.getEntryPoint()
                    existing = get_plate_comment(listing, entry_addr) or ""
                    note = "\nDebug string ref: \"%s\" (shared by %d functions)" % (
                        str_val, len(funcs_seen))
                    if note not in existing and str_val not in existing:
                        listing.setComment(entry_addr, CodeUnit.PLATE_COMMENT,
                            existing + note)
                        commented_only += 1

    println("")
    println("=" * 60)
    println("String-Referenced Function Discovery Complete")
    println("  Candidate strings found:    %d" % len(candidates))
    println("  Functions named:            %d" % named_count)
    println("  Skipped (no code xref):     %d" % skipped_no_xref)
    println("  Skipped (already named):    %d" % skipped_already_named)
    println("  Skipped (multi-function):   %d" % skipped_multi_func)
    println("  Skipped (name collision):   %d" % skipped_duplicate)
    println("  Comments added (no rename): %d" % commented_only)
    println("=" * 60)

main()
