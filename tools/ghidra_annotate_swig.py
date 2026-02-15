# Ghidra Jython Script: Annotate SWIG Method Table
# @category STBC
# @description Annotates all 3990 SWIG Python binding methods in stbc.exe.
#   Reads the shared App/Appc PyMethodDef table at 0x008e6438, names each
#   wrapper function as swig_<method_name>, and adds plate comments.
#
# Run from Ghidra Script Manager with stbc.exe loaded.

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit

SWIG_TABLE_START = 0x008e6438
SWIG_TABLE_END   = 0x008f5d98  # NULL terminator entry
ENTRY_SIZE       = 16          # sizeof(PyMethodDef) on x86-32

# Key helper function addresses for reference labeling
HELPERS = {
    0x0074e310: "PyArg_ParseTuple",
    0x005bae00: "SWIG_GetPointerObj",
    0x005bb0e0: "SWIG_NewPointerObj",
    0x005bb040: "SWIG_MakePtr",
    0x005bad40: "SWIG_InitAppc_pre",
    0x0074d140: "Py_InitModule4",
    0x0074d280: "Py_BuildValue",
    0x0065a250: "initAppc",
}

def readCString(addr):
    """Read a NULL-terminated C string from memory."""
    result = []
    mem = currentProgram.getMemory()
    for i in range(512):  # safety limit
        b = mem.getByte(addr.add(i))
        if b == 0:
            break
        result.append(chr(b & 0xFF))
    return ''.join(result)

def readInt(addr):
    """Read a 4-byte little-endian int from memory."""
    return currentProgram.getMemory().getInt(addr)

def main():
    fm = currentProgram.getFunctionManager()
    st = currentProgram.getSymbolTable()
    listing = currentProgram.getListing()
    af = currentProgram.getAddressFactory()

    # Label the table itself
    tableAddr = toAddr(SWIG_TABLE_START)
    st.createLabel(tableAddr, "g_SwigMethodTable_AppAppc", SourceType.USER_DEFINED)
    listing.setComment(tableAddr, CodeUnit.PLATE_COMMENT,
        "Shared PyMethodDef table for App/Appc SWIG modules.\n"
        "3990 entries, 16 bytes each. Used by initAppc (0x0065a250).")

    # Label helper functions
    for addr_int, name in HELPERS.items():
        addr = toAddr(addr_int)
        fn = fm.getFunctionAt(addr)
        try:
            if fn is not None:
                fn.setName(name, SourceType.USER_DEFINED)
            else:
                st.createLabel(addr, name, SourceType.USER_DEFINED)
        except Exception, e:
            println("  WARN helper %s: %s" % (name, str(e)))

    # Walk the method table
    renamed = 0
    skipped = 0
    errors = 0
    entry_num = 0

    addr_int = SWIG_TABLE_START
    while addr_int < SWIG_TABLE_END:
        entry_addr = toAddr(addr_int)
        try:
            name_ptr  = readInt(entry_addr)
            func_ptr  = readInt(entry_addr.add(4))
            flags     = readInt(entry_addr.add(8))
            doc_ptr   = readInt(entry_addr.add(12))

            # NULL name_ptr = end of table
            if name_ptr == 0:
                break

            # Read method name string
            method_name = readCString(toAddr(name_ptr))
            if not method_name:
                skipped += 1
                addr_int += ENTRY_SIZE
                continue

            func_addr = toAddr(func_ptr)

            # Create function if it doesn't exist
            fn = fm.getFunctionAt(func_addr)
            if fn is None:
                fn = createFunction(func_addr, "swig_" + method_name)
                if fn is not None:
                    renamed += 1
            else:
                old_name = fn.getName()
                target_name = "swig_" + method_name
                if old_name != target_name:
                    fn.setName(target_name, SourceType.USER_DEFINED)
                    renamed += 1
                else:
                    skipped += 1  # already correct

            # Add plate comment with method info
            if fn is not None:
                comment = "SWIG wrapper: %s\nTable entry #%d at 0x%08X\nFlags: %d (METH_VARARGS)" % (
                    method_name, entry_num, addr_int, flags)
                listing.setComment(func_addr, CodeUnit.PLATE_COMMENT, comment)

            # Label the name string
            name_str_addr = toAddr(name_ptr)
            try:
                st.createLabel(name_str_addr, "swigname_" + method_name, SourceType.USER_DEFINED)
            except:
                pass

        except Exception, e:
            println("  Error at entry %d (0x%08X): %s" % (entry_num, addr_int, str(e)))
            errors += 1

        entry_num += 1
        addr_int += ENTRY_SIZE

        # Progress every 500 entries
        if entry_num % 500 == 0:
            println("  Processed %d / ~3990 entries (%d renamed)..." % (entry_num, renamed))

    println("")
    println("=" * 60)
    println("SWIG Method Table Annotation Complete")
    println("  Total entries processed: %d" % entry_num)
    println("  Functions renamed:       %d" % renamed)
    println("  Skipped (existing name): %d" % skipped)
    println("  Errors:                  %d" % errors)
    println("=" * 60)

main()
