# Ghidra Jython Script: Annotate Game Globals, Key Functions, and Data Labels
# @category STBC
# @description Labels critical game globals, key functions identified through
#   reverse engineering, SWIG type info entries, and Python module tables.
#   Complements the SWIG, NiRTTI, and vtable annotation scripts.
#
# Run from Ghidra Script Manager with stbc.exe loaded.

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit

# ============================================================================
# UtopiaModule globals (game state flags and pointers)
# ============================================================================
UTOPIA_GLOBALS = {
    0x0097FA00: ("g_UtopiaModule", "UtopiaModule base pointer"),
    0x0097FA78: ("g_TGWinsockNetwork", "TGWinsockNetwork* (UtopiaModule+0x78)"),
    0x0097FA7C: ("g_GameSpy", "GameSpy pointer (+0xDC=qr_t for LAN discovery)"),
    0x0097FA80: ("g_NetFile", "NetFile/ChecksumManager pointer"),
    0x0097FA88: ("g_IsClient", "BYTE: 0=host, 1=client"),
    0x0097FA89: ("g_IsHost", "BYTE: 1=host, 0=client"),
    0x0097FA8A: ("g_IsMultiplayer", "BYTE: 1=multiplayer active"),
    0x008e5f59: ("g_SettingsByte1", "Settings packet byte 1 (sent in opcode 0x00)"),
    0x0097faa2: ("g_SettingsByte2", "Settings packet byte 2 (sent in opcode 0x00)"),
    0x0097e238: ("g_TopWindow", "TopWindow/MultiplayerGame pointer"),
    0x009a09d0: ("g_Clock", "Clock object (+0x90=gameTime, +0x54=frameTime)"),
    0x009a2b98: ("g_NiRTTI_FactoryHashTable", "NiRTTI factory hash table (37 buckets)"),
    0x00980798: ("g_ModelRegistry", "Ship model name -> NiNode registry (for +0x140)"),
}

# ============================================================================
# Key functions (reverse-engineered, from MEMORY.md and agent analysis)
# ============================================================================
KEY_FUNCTIONS = {
    # Multiplayer message dispatchers
    0x0069f2a0: ("MultiplayerGame_ReceiveMessage", "Main game opcode dispatcher (0x00-0x2A, jump table at 0x0069F534)"),
    0x006a3cd0: ("NetFile_ReceiveMessage", "Checksum/file opcode dispatcher (0x20-0x27)"),
    0x00504c10: ("MultiplayerWindow_ReceiveMessage", "UI-level dispatcher (0x00, 0x01, 0x16)"),

    # Game opcode handlers
    0x0069f9e0: ("Handler_Settings_0x00", "Settings packet handler (gameTime, map, collision)"),
    0x0069fc00: ("Handler_GameInit_0x01", "Game start trigger"),
    0x0069f620: ("Handler_ObjCreate_0x02_0x03", "Object creation / ObjCreateTeam"),
    0x0069fda0: ("Handler_PythonEvent_0x06", "Python event forwarding (shared by opcodes 0x06-0x12)"),
    0x006a0d90: ("Handler_HostMsg_0x13", "Host message broadcast"),
    0x006a01e0: ("Handler_DestroyObject_0x14", "Object destruction (S->C)"),
    0x006a2470: ("Handler_CollisionEffect_0x15", "Collision damage relay"),
    0x00504c70: ("Handler_UICollisionSetting_0x16", "Collision toggle (MultiplayerWindow)"),
    0x0069fe60: ("Handler_TorpedoFire_0x19", "Torpedo launch"),
    0x006a0340: ("Handler_BeamFire_0x1A", "Beam weapon hit"),
    0x006a0620: ("Handler_ObjNotFound_0x1D", "Object lookup failure"),
    0x006a07d0: ("Handler_RequestObj_0x1E", "Request object data from host"),
    0x006a0a20: ("Handler_EnterSet_0x1F", "Enter game set"),
    0x006a0080: ("Handler_Explosion_0x29", "Explosion damage (S->C)"),
    0x006a1e70: ("Handler_NewPlayerInGame_0x2A", "Player join handshake"),

    # Checksum handlers
    0x006a1b10: ("ChecksumCompleteHandler", "Server: sends Settings + GameInit after checksums pass"),
    0x006f3f30: ("ChecksumMatchDataWriter", "Appends checksum data to stream"),

    # Ship / object management
    0x005b17f0: ("Ship_WriteStateUpdate", "Serializes ship state (pos/orient/subsys/weapons) to stream"),
    0x005b0e80: ("Ship_InitObject", "Ship deserialization from network stream"),
    0x005b3fb0: ("Ship_SetupProperties", "Creates subsystems from NiNode properties"),
    0x006c9520: ("AddToSet", "Links NiProperties to NiNode in game set"),
    0x005a1f50: ("Ship_Deserialize", "Ship deserialization wrapper (called by ObjCreate handler)"),
    0x006a1aa0: ("GetShipFromPlayerID", "__cdecl(int connID) -> ship*, maps connection to ship object"),

    # Damage system
    0x00594020: ("DoDamage", "Central damage dispatcher. Gates: ship+0x18 AND ship+0x140"),
    0x00593e50: ("ProcessDamage", "Distributes damage to subsystems via ship+0x128/+0x130 array"),
    0x005b0060: ("CollisionDamageWrapper", "Collision -> damage conversion"),
    0x00593650: ("DoDamage_FromPosition", "Position-based damage (explosions, area effect)"),
    0x005952d0: ("DoDamage_CollisionContacts", "Collision contact damage"),

    # Network core
    0x006b55b0: ("SendStateUpdates", "Main state replication loop (iterates peer array)"),
    0x006b84d0: ("BufferCopy", "Alloc + memcpy for network buffers"),
    0x006b9f40: ("RemovePeerAddress", "Removes peer from WSN (patched for NULL safety)"),

    # TGL / resource loading
    0x006d1e10: ("TGLFile_FindEntry", "Returns TGL entry ptr (patched: NULL check on ECX)"),
    0x006d03d0: ("TGLManager_LoadFile", "__thiscall on 0x997fd8; fopen + parse"),
    0x006d11d0: ("TGLManager_LoadOrCache", "Allocates + parses TGL; returns NULL on failure"),
    0x006d2eb0: ("ReadCompressedVector3", "Reads 3-component compressed vector (patched: vtable validate)"),
    0x006d2fd0: ("ReadCompressedVector4", "Reads 4-component compressed vector (patched: vtable validate)"),

    # Python bridge
    0x006f8ab0: ("TG_CallPythonFunction", "Calls Python function by module.name path"),
    0x006f7d90: ("TG_ImportModule", "__import__ + sys.modules lookup"),
    0x0074c140: ("PyObject_GetAttrString", "getattr equivalent"),
    0x00776cf0: ("PyObject_CallObject", "Call Python callable with args tuple"),
    0x0074b640: ("Py_CompileAndRun", "Compile + run Python source string"),
    0x0074d140: ("Py_InitModule4", "Register Python module with method table"),
    0x0074e310: ("PyArg_ParseTuple", "Parse Python args using format string"),
    0x0074d280: ("Py_BuildValue", "Build Python return values"),
    0x005bae00: ("SWIG_GetPointerObj", "Unwrap SWIG pointer to raw C++ pointer"),
    0x005bb0e0: ("SWIG_NewPointerObj", "Wrap raw C++ pointer as SWIG pointer"),
    0x005bb040: ("SWIG_MakePtr", "Format SWIG pointer string"),
    0x0065a250: ("initAppc", "Initialize Appc Python module (SWIG bindings)"),

    # Multiplayer game creation
    0x00504F10: ("CreateMultiplayerGame", "Creates MultiplayerGame object"),
    0x00504890: ("MultiplayerWindow_StartGameHandler", "ET_START handler"),

    # Bounding box / model
    0x004360c0: ("GetBoundingBox", "vtable+0xE4, computes AABB from NiBound"),

    # Memory allocator
    0x00717840: ("NiAlloc", "malloc with 4-byte size header, pool for <=0x80"),
    0x00717960: ("NiFree", "Free NiAlloc'd memory"),
    0x007179c0: ("NiRealloc", "Realloc NiAlloc'd memory"),

    # Renderer (headless patches)
    0x007cb2c0: ("NiD3DGeometryGroupManager_ctor", "D3D geometry group manager constructor"),

    # NiStream
    0x008176b0: ("NiStream_LoadObject", "Reads NIF class name, looks up factory, creates object"),
    0x00818150: ("NiStream_LoadObjectAlt", "Alternative NIF load path"),
    0x00817170: ("NiStream_RegisterStreamable", "Registers object in stream hash table"),

    # Ship model pipeline
    0x00591b60: ("Ship_SetModelName", "Sets ship model; vtable[0x128]. Sets +0x140 damage target NiNode"),
}

# ============================================================================
# SWIG type info array
# ============================================================================
SWIG_TYPE_INFO = 0x00900a94  # Pointer array, 348 type descriptors

# ============================================================================
# Jump table for MultiplayerGame dispatcher
# ============================================================================
JUMP_TABLE = 0x0069F534  # 41 entries (opcodes 0x00-0x28)

# ============================================================================
# Python module tables (addresses from swig-method-tables.md)
# ============================================================================
PYTHON_MODULES = {
    0x008e6438: ("g_SwigMethodTable_AppAppc", "SWIG App/Appc shared method table (3990 entries)"),
    0x00961490: ("g_PyMethodTable_builtin", "__builtin__ module methods"),
    0x00963a80: ("g_PyMethodTable_imp", "imp module methods"),
    0x009643a0: ("g_PyMethodTable_marshal", "marshal module methods"),
    0x00964658: ("g_PyMethodTable_locale", "_locale module methods"),
    0x00964b60: ("g_PyMethodTable_cPickle", "cPickle module methods"),
    0x009660a8: ("g_PyMethodTable_cStringIO", "cStringIO module methods"),
    0x00966ab0: ("g_PyMethodTable_thread", "thread module methods"),
    0x00967410: ("g_PyMethodTable_time", "time module methods"),
    0x009686c0: ("g_PyMethodTable_struct", "struct module methods"),
    0x009697d8: ("g_PyMethodTable_strop", "strop module methods"),
    0x00969d28: ("g_PyMethodTable_regex", "regex module methods"),
    0x0096a078: ("g_PyMethodTable_operator", "operator module methods"),
    0x0096b888: ("g_PyMethodTable_nt", "nt (os) module methods"),
    0x0096bd88: ("g_PyMethodTable_new", "new module methods"),
    0x0096c378: ("g_PyMethodTable_math", "math module methods"),
    0x0099f5c8: ("g_PyMethodTable_errno", "errno module methods"),
    0x0096d178: ("g_PyMethodTable_cmath", "cmath module methods"),
    0x0096d818: ("g_PyMethodTable_binascii", "binascii module methods"),
    0x0096e118: ("g_PyMethodTable_array", "array module methods"),
    0x0096faa8: ("g_PyMethodTable_sys", "sys module methods"),
    0x009743d8: ("g_PyMethodTable_signal", "signal module methods"),
}


def label_or_rename(st, addr, name):
    """Create or replace a label at addr. Returns True on success."""
    # Remove any existing user-defined symbol with this name elsewhere
    for sym in st.getSymbols(name):
        if sym.getAddress() != addr and sym.getSource() == SourceType.USER_DEFINED:
            sym.delete()

    # Check if the desired label already exists at this address
    existing = st.getPrimarySymbol(addr)
    if existing is not None and existing.getName() == name:
        return True  # already correct

    # Try to set existing symbol's name, or create new label
    try:
        if existing is not None and existing.getSource() != SourceType.DEFAULT:
            existing.setName(name, SourceType.USER_DEFINED)
        else:
            st.createLabel(addr, name, SourceType.USER_DEFINED)
        return True
    except:
        # Fallback: try creating with explicit global namespace
        try:
            ns = currentProgram.getGlobalNamespace()
            st.createLabel(addr, name, ns, SourceType.USER_DEFINED)
            return True
        except:
            return False


def main():
    fm = currentProgram.getFunctionManager()
    st = currentProgram.getSymbolTable()
    listing = currentProgram.getListing()

    globals_ok = 0
    globals_fail = 0
    funcs_named = 0
    funcs_commented = 0
    funcs_skipped = 0
    funcs_fail = 0
    modules_ok = 0
    modules_skip = 0
    modules_fail = 0

    # ---- Label UtopiaModule globals ----
    println("Labeling game globals...")
    for addr_int, (name, comment) in UTOPIA_GLOBALS.items():
        addr = toAddr(addr_int)
        try:
            if label_or_rename(st, addr, name):
                listing.setComment(addr, CodeUnit.PLATE_COMMENT, comment)
                globals_ok += 1
            else:
                println("  WARN: could not label 0x%08x as %s" % (addr_int, name))
                globals_fail += 1
        except Exception, e:
            println("  ERROR at 0x%08x (%s): %s" % (addr_int, name, str(e)))
            globals_fail += 1

    # ---- Name key functions ----
    println("Naming key functions...")
    for addr_int, (name, comment) in KEY_FUNCTIONS.items():
        addr = toAddr(addr_int)
        try:
            fn = fm.getFunctionAt(addr)
            if fn is not None:
                old = fn.getName()
                # Always rename - our RE names are more meaningful
                if old != name:
                    fn.setName(name, SourceType.USER_DEFINED)
                    funcs_named += 1
                else:
                    funcs_named += 1  # already correct
                listing.setComment(addr, CodeUnit.PLATE_COMMENT, comment)
            else:
                # No function at this address - create one, then name it
                try:
                    fn = createFunction(addr, name)
                    if fn is not None:
                        listing.setComment(addr, CodeUnit.PLATE_COMMENT, comment)
                        funcs_named += 1
                    else:
                        # Can't create function, at least label it
                        if label_or_rename(st, addr, name):
                            listing.setComment(addr, CodeUnit.PLATE_COMMENT, comment)
                            funcs_named += 1
                        else:
                            println("  WARN: no function at 0x%08x, label failed for %s" % (addr_int, name))
                            funcs_fail += 1
                except:
                    # createFunction failed, try label
                    if label_or_rename(st, addr, name):
                        listing.setComment(addr, CodeUnit.PLATE_COMMENT, comment)
                        funcs_named += 1
                    else:
                        println("  WARN: no function at 0x%08x, label failed for %s" % (addr_int, name))
                        funcs_fail += 1
        except Exception, e:
            println("  ERROR at 0x%08x (%s): %s" % (addr_int, name, str(e)))
            funcs_fail += 1

    # ---- Label jump table ----
    try:
        jt_addr = toAddr(JUMP_TABLE)
        label_or_rename(st, jt_addr, "MultiplayerGame_opcodeJumpTable")
        listing.setComment(jt_addr, CodeUnit.PLATE_COMMENT,
            "Jump table for MultiplayerGame::ReceiveMessage dispatcher.\n"
            "41 entries (opcodes 0x00-0x28). Indexed by first byte of message payload.")
    except Exception, e:
        println("  ERROR labeling jump table: %s" % str(e))

    # ---- Label SWIG type info ----
    try:
        label_or_rename(st, toAddr(SWIG_TYPE_INFO), "g_SwigTypeInfo")
        listing.setComment(toAddr(SWIG_TYPE_INFO), CodeUnit.PLATE_COMMENT,
            "SWIG type descriptor pointer array (348 entries).\n"
            "Each entry: {name, converter, str, next}.\n"
            "Used by SWIG_GetPointerObj/SWIG_NewPointerObj for type checking.")
    except Exception, e:
        println("  ERROR labeling SWIG type info: %s" % str(e))

    # ---- Label Python module tables ----
    println("Labeling Python module tables...")
    for addr_int, (name, comment) in PYTHON_MODULES.items():
        addr = toAddr(addr_int)
        try:
            if label_or_rename(st, addr, name):
                listing.setComment(addr, CodeUnit.PLATE_COMMENT, comment)
                modules_ok += 1
            else:
                println("  WARN: could not label 0x%08x as %s" % (addr_int, name))
                modules_fail += 1
        except Exception, e:
            println("  ERROR at 0x%08x (%s): %s" % (addr_int, name, str(e)))
            modules_fail += 1

    # ---- Summary ----
    total_funcs = len(KEY_FUNCTIONS)
    total_modules = len(PYTHON_MODULES)
    println("")
    println("=" * 60)
    println("Game Globals & Functions Annotation Complete")
    println("  Globals labeled:         %d / %d" % (globals_ok, len(UTOPIA_GLOBALS)))
    if globals_fail > 0:
        println("  Globals FAILED:          %d" % globals_fail)
    println("  Functions named:         %d / %d" % (funcs_named, total_funcs))
    if funcs_fail > 0:
        println("  Functions FAILED:        %d" % funcs_fail)
    println("  Module tables labeled:   %d / %d" % (modules_ok, total_modules))
    if modules_fail > 0:
        println("  Module tables FAILED:    %d" % modules_fail)
    println("=" * 60)

main()
