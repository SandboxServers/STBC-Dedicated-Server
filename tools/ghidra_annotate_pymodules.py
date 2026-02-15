# Ghidra Jython Script: Annotate Python Built-in Module Method Tables
# @category STBC
# @description Walks all 21 non-SWIG Python module method tables (PyMethodDef
#   format) and names each C function as py_<module>_<method>. Complements
#   ghidra_annotate_swig.py which handles the App/Appc SWIG table.
#
# Data source: PYTHON_MODULES dict from ghidra_annotate_globals.py
# Run from Ghidra Script Manager with stbc.exe loaded.

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit

# PyMethodDef entry: 16 bytes on x86-32
#   +0x00: char* ml_name     (method name string pointer)
#   +0x04: PyCFunction ml_meth  (C function pointer)
#   +0x08: int ml_flags       (METH_VARARGS=1, METH_OLDARGS=0, etc.)
#   +0x0C: char* ml_doc       (docstring pointer, often NULL)
ENTRY_SIZE = 16

# Module method tables: (table_address, module_name, description)
# Addresses from ghidra_annotate_globals.py PYTHON_MODULES dict.
# Excludes SWIG table at 0x008e6438 (handled by ghidra_annotate_swig.py).
MODULE_TABLES = [
    (0x00961490, "builtin",   "__builtin__ module methods"),
    (0x00963a80, "imp",       "imp module methods"),
    (0x009643a0, "marshal",   "marshal module methods"),
    (0x00964658, "locale",    "_locale module methods"),
    (0x00964b60, "cPickle",   "cPickle module methods"),
    (0x009660a8, "cStringIO", "cStringIO module methods"),
    (0x00966ab0, "thread",    "thread module methods"),
    (0x00967410, "time",      "time module methods"),
    (0x009686c0, "struct",    "struct module methods"),
    (0x009697d8, "strop",     "strop module methods"),
    (0x00969d28, "regex",     "regex module methods"),
    (0x0096a078, "operator",  "operator module methods"),
    (0x0096b888, "nt",        "nt (os) module methods"),
    (0x0096bd88, "new",       "new module methods"),
    (0x0096c378, "math",      "math module methods"),
    (0x0099f5c8, "errno",     "errno module methods"),
    (0x0096d178, "cmath",     "cmath module methods"),
    (0x0096d818, "binascii",  "binascii module methods"),
    (0x0096e118, "array",     "array module methods"),
    (0x0096faa8, "sys",       "sys module methods"),
    (0x009743d8, "signal",    "signal module methods"),
]

# Maximum entries per table (safety limit to prevent runaway reads)
MAX_ENTRIES_PER_TABLE = 200

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

def isValidCodeAddress(addr_int):
    """Check if an address is in the code section (plausible function pointer)."""
    # stbc.exe code range: ~0x00401000 - 0x00860000
    return 0x00401000 <= addr_int <= 0x00860000

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

    total_renamed = 0
    total_skipped = 0
    total_errors = 0
    total_entries = 0
    modules_processed = 0

    # Track functions already named (to handle shared function pointers)
    named_functions = {}

    for table_addr_int, module_name, description in MODULE_TABLES:
        table_addr = toAddr(table_addr_int)
        println("Processing module '%s' at 0x%08X..." % (module_name, table_addr_int))

        # Label the table itself (if not already labeled by globals script)
        table_label = "g_PyMethodTable_%s" % module_name
        try:
            existing = st.getPrimarySymbol(table_addr)
            if existing is not None and existing.getSource() != SourceType.DEFAULT:
                existing.setName(table_label, SourceType.USER_DEFINED)
            else:
                st.createLabel(table_addr, table_label, SourceType.USER_DEFINED)
            listing.setComment(table_addr, CodeUnit.PLATE_COMMENT, description)
        except:
            pass

        module_renamed = 0
        module_entries = 0
        addr_int = table_addr_int

        for entry_idx in range(MAX_ENTRIES_PER_TABLE):
            entry_addr = toAddr(addr_int)
            try:
                name_ptr = readInt(entry_addr)
                func_ptr = readInt(entry_addr.add(4))
                flags = readInt(entry_addr.add(8))
                doc_ptr = readInt(entry_addr.add(12))

                # NULL name_ptr = end of table
                if name_ptr == 0:
                    break

                # Read method name string
                method_name = readCString(toAddr(name_ptr))
                if not method_name:
                    addr_int += ENTRY_SIZE
                    continue

                module_entries += 1

                # Validate function pointer
                if not isValidCodeAddress(func_ptr):
                    println("  WARN: entry %d '%s' has invalid func ptr 0x%08X" % (
                        entry_idx, method_name, func_ptr))
                    addr_int += ENTRY_SIZE
                    continue

                func_addr = toAddr(func_ptr)
                target_name = "py_%s_%s" % (module_name, method_name)

                # Check if this function was already named by another module
                if func_ptr in named_functions:
                    prev = named_functions[func_ptr]
                    # Add a comment noting the alias but don't rename
                    fn = fm.getFunctionAt(func_addr)
                    if fn is not None:
                        existing_comment = get_plate_comment(listing, func_addr) or ""
                        alias_note = "\nAlso registered as: %s (module '%s')" % (target_name, module_name)
                        if alias_note not in existing_comment:
                            listing.setComment(func_addr, CodeUnit.PLATE_COMMENT,
                                existing_comment + alias_note)
                    total_skipped += 1
                    addr_int += ENTRY_SIZE
                    continue

                fn = fm.getFunctionAt(func_addr)
                if fn is None:
                    # Try to create function
                    fn = createFunction(func_addr, target_name)
                    if fn is not None:
                        module_renamed += 1
                        named_functions[func_ptr] = target_name
                else:
                    old_name = fn.getName()
                    if old_name != target_name:
                        fn.setName(target_name, SourceType.USER_DEFINED)
                        module_renamed += 1
                        named_functions[func_ptr] = target_name
                    else:
                        total_skipped += 1
                        named_functions[func_ptr] = target_name

                # Add plate comment
                if fn is not None:
                    flags_desc = "METH_VARARGS" if (flags & 1) else "METH_OLDARGS"
                    if flags & 2:
                        flags_desc += "|METH_KEYWORDS"
                    comment = "Python C function: %s.%s\nModule: %s\nTable entry #%d at 0x%08X\nFlags: %d (%s)" % (
                        module_name, method_name, description,
                        entry_idx, addr_int, flags, flags_desc)
                    listing.setComment(func_addr, CodeUnit.PLATE_COMMENT, comment)

                # Label the name string
                name_str_addr = toAddr(name_ptr)
                try:
                    st.createLabel(name_str_addr, "pyname_%s_%s" % (module_name, method_name),
                        SourceType.USER_DEFINED)
                except:
                    pass

            except Exception, e:
                println("  Error at entry %d (0x%08X): %s" % (entry_idx, addr_int, str(e)))
                total_errors += 1

            addr_int += ENTRY_SIZE

        println("  -> %d entries, %d renamed" % (module_entries, module_renamed))
        total_renamed += module_renamed
        total_entries += module_entries
        modules_processed += 1

    println("")
    println("=" * 60)
    println("Python Module Method Table Annotation Complete")
    println("  Modules processed:       %d" % modules_processed)
    println("  Total entries found:     %d" % total_entries)
    println("  Functions renamed:       %d" % total_renamed)
    println("  Skipped (existing name): %d" % total_skipped)
    println("  Errors:                  %d" % total_errors)
    println("=" * 60)

main()
