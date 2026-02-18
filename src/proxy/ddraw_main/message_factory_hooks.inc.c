#ifdef OBSERVE_ONLY
/* ================================================================
 * Message Factory Table Hook (OBSERVE_ONLY)
 *
 * The TGNetwork receive processor (FUN_006b5c90) decodes transport
 * framing, then dispatches each message through a factory function
 * table at 0x009962d4. Each entry creates a typed message object
 * from the decoded byte stream.
 *
 * We replace table entries with our hook to log decoded messages:
 * - Message type byte (network opcode)
 * - Message size (from vtable[5] = GetSize method)
 * - Raw hex dump of decoded message body
 *
 * Registered message types (factory table at DAT_009962d4):
 *   0x00: TGDataMessage    (FUN_006bc6a0) - 14-bit length, no fragments
 *   0x01: TGHeaderMessage  (FUN_006bd1f0) - ACK messages
 *   0x02: TGConnectMessage (FUN_006bdd10)
 *   0x03: TGConnectAckMsg  (FUN_006be860)
 *   0x04: TGBootMessage    (FUN_006badb0)
 *   0x05: TGDisconnectMsg  (FUN_006bf410)
 *   0x32: TGMessage base   (FUN_006b83f0) - 13-bit length, fragment support
 *
 * All game-layer opcodes (0x00-0x2A, 0x2C-0x39) are carried
 * as payloads WITHIN type 0x32 messages.
 * ================================================================ */
#define MSG_FACTORY_TABLE_ADDR  0x009962d4
#define MSG_FACTORY_TABLE_COUNT 256

typedef int* (__cdecl *MsgFactoryFn)(unsigned char* data);
typedef int (__attribute__((thiscall)) *MsgGetSizeFn)(void* thisPtr);

static MsgFactoryFn g_origFactories[MSG_FACTORY_TABLE_COUNT];
static volatile LONG g_factoryHooked = 0;
static FILE* g_pMsgLog = NULL;
static volatile LONG g_msgSeq = 0;

static void MsgTraceOpen(void) {
    char path[MAX_PATH];
    SYSTEMTIME st;
    GetLocalTime(&st);
    lstrcpynA(path, g_szBasePath, MAX_PATH);
    lstrcatA(path, "message_trace.log");
    g_pMsgLog = fopen(path, "w");
    if (g_pMsgLog) {
        fprintf(g_pMsgLog,
                "# STBC Message Trace - Decoded Application Layer\n"
                "# Session: %04d-%02d-%02d %02d:%02d:%02d\n"
                "# Format: [time] #seq MSG type=0xNN size=N vtbl=0xNNNNNNNN\n"
                "# Followed by hex dump + structured decode of message body\n"
                "# Types: 0x00=DataMsg, 0x01=ACK, 0x02-0x05=ConnMgmt, 0x32=GameData\n"
                "# Game opcodes are in the transport payload and decoded below when possible\n"
                "# ============================================================\n\n",
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond);
        fflush(g_pMsgLog);
    }
}

static int* __cdecl HookMsgFactory(unsigned char* data) {
    unsigned char msgType = data[0];
    int* msgObj;
    int msgSize = 0;
    SYSTEMTIME st;
    LONG seq;

    /* Call original factory */
    if (!g_origFactories[msgType]) return NULL;
    msgObj = g_origFactories[msgType](data);
    if (!msgObj) return msgObj;

    /* Try to get message size via vtable[5] (offset 0x14 = GetSize) */
    if (!IsBadReadPtr(msgObj, 44) &&
        !IsBadReadPtr(*(void**)msgObj, 24)) {
        void** vt = *(void***)msgObj;
        MsgGetSizeFn getSize = (MsgGetSizeFn)vt[5];
        if (getSize && !IsBadCodePtr((FARPROC)getSize)) {
            msgSize = getSize(msgObj);
        }
    }

    /* Log the decoded message */
    if (g_pMsgLog) {
        int dumpLen;
        GetLocalTime(&st);
        seq = InterlockedIncrement(&g_msgSeq);
        fprintf(g_pMsgLog, "[%02d:%02d:%02d.%03d] #%ld MSG type=0x%02X",
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                seq, msgType);
        if (msgSize > 0)
            fprintf(g_pMsgLog, " size=%d", msgSize);
        fprintf(g_pMsgLog, " vtbl=0x%08X\n",
                (unsigned int)*(unsigned int*)msgObj);

        /* Hex dump + semantic decode of message body (transport type + payload). */
        dumpLen = 0;
        if (msgSize > 0 && msgSize <= 2048 && !IsBadReadPtr(data, msgSize)) {
            dumpLen = msgSize;
        } else if (!IsBadReadPtr(data, 128)) {
            dumpLen = 128;
        } else if (!IsBadReadPtr(data, 64)) {
            dumpLen = 64;
        }

        if (dumpLen > 0) {
            PktHexDump(g_pMsgLog, data, dumpLen);
            PktDecodeMessageBlob(g_pMsgLog, data, dumpLen);
        } else {
            fprintf(g_pMsgLog, "  (message bytes unavailable)\n");
        }
        fprintf(g_pMsgLog, "\n");
        fflush(g_pMsgLog);
    }

    return msgObj;
}

static void TryInstallFactoryHooks(void) {
    MsgFactoryFn* table;
    DWORD oldProt;
    int i, populated;

    if (g_factoryHooked) return;

    table = (MsgFactoryFn*)MSG_FACTORY_TABLE_ADDR;

    /* Check if table is populated (need at least 3 entries) */
    populated = 0;
    for (i = 0; i < MSG_FACTORY_TABLE_COUNT; i++) {
        if (table[i] != NULL) populated++;
    }
    if (populated < 3) return;

    /* Open message trace log if not already open */
    if (!g_pMsgLog) MsgTraceOpen();

    /* Save original factory function pointers */
    for (i = 0; i < MSG_FACTORY_TABLE_COUNT; i++) {
        g_origFactories[i] = table[i];
    }

    /* Make table writable */
    if (!VirtualProtect(table, MSG_FACTORY_TABLE_COUNT * sizeof(void*),
                        PAGE_READWRITE, &oldProt)) {
        ProxyLog("WARN: VirtualProtect on factory table failed (err=%lu)",
                 GetLastError());
        return;
    }

    /* Replace non-NULL entries with our hook */
    for (i = 0; i < MSG_FACTORY_TABLE_COUNT; i++) {
        if (table[i] != NULL) {
            table[i] = HookMsgFactory;
        }
    }

    InterlockedExchange(&g_factoryHooked, 1);
    ProxyLog("Message factory hooks installed (%d active entries)", populated);

    if (g_pMsgLog) {
        fprintf(g_pMsgLog, "# Factory hooks installed: %d active entries\n", populated);
        for (i = 0; i < MSG_FACTORY_TABLE_COUNT; i++) {
            if (g_origFactories[i]) {
                fprintf(g_pMsgLog, "#   type 0x%02X -> factory at 0x%08X\n",
                        i, (unsigned int)(uintptr_t)g_origFactories[i]);
            }
        }
        fprintf(g_pMsgLog, "\n");
        fflush(g_pMsgLog);
    }
}
#endif /* OBSERVE_ONLY */
