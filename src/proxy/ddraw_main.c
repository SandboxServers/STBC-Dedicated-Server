/*
 * ddraw_main.c - DLL entry point, exports, IDirectDraw7 + IDirectDrawClipper
 *
 * Bridge Commander Dedicated Server DDraw Proxy
 *
 * Minimal approach: stub rendering only. Let the game's own code handle
 * networking, events, Python scripting, and multiplayer logic.
 * The Python automation in scripts/Custom/DedicatedServer.py drives the
 * multiplayer UI flow via the game's event system.
 */
#include <winsock2.h>
#include "ddraw_proxy.h"
#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>

/* Forward declarations */
static void ResolveAddr(DWORD addr, char* out, int outLen);
static ProxySurface7* g_pPatchDummy; /* defined in PatchNullSurface */
static BYTE* g_pNullDummy;           /* zeroed 64KB buffer for NULL this fixup */
static void PatchNullGlobals(void);  /* forward decl */
static void PatchSkipRendererSetup(void); /* forward decl */

/* Software breakpoint hooks for function tracing */
static BYTE g_bpOrig[4] = {0};      /* saved original bytes at each BP address */
static volatile int g_bpSS = 0;     /* which BP is in single-step mode (0=none, 1-4) */
#define BP_NEWPLAYER_ADDR  0x006a0a30  /* FUN_006a0a30 - NewPlayerHandler */
#define BP_CHECKSUM_ADDR   0x006a3820  /* FUN_006a3820 - ChecksumRequestSender */
#define BP_SEND_ADDR       0x006b4c10  /* FUN_006b4c10 - TGNetwork::Send */
static int g_bpInstalled = 0;

/* sendto hook for monitoring outbound UDP traffic */
typedef int (WSAAPI *PFN_sendto)(SOCKET, const char*, int, int,
                                  const struct sockaddr*, int);
static PFN_sendto g_pfnOrigSendto = NULL;
static volatile LONG g_sendtoCount = 0;

static int WSAAPI HookedSendto(SOCKET s, const char* buf, int len, int flags,
                                const struct sockaddr* to, int tolen) {
    int rc;
    LONG count;
    rc = g_pfnOrigSendto(s, buf, len, flags, to, tolen);
    count = InterlockedIncrement(&g_sendtoCount);
    if (count <= 200) {
        if (to && tolen >= (int)sizeof(struct sockaddr_in)) {
            const struct sockaddr_in* sin = (const struct sockaddr_in*)to;
            char hexbuf[97] = {0};
            int i, hlen = len < 32 ? len : 32;
            for (i = 0; i < hlen; i++)
                sprintf(hexbuf + i*3, "%02X ", (unsigned char)buf[i]);
            ProxyLog("  SENDTO[%ld]: sock=%d len=%d->rc=%d to=%d.%d.%d.%d:%d",
                     count, (int)s, len, rc,
                     (unsigned char)((char*)&sin->sin_addr)[0],
                     (unsigned char)((char*)&sin->sin_addr)[1],
                     (unsigned char)((char*)&sin->sin_addr)[2],
                     (unsigned char)((char*)&sin->sin_addr)[3],
                     ntohs(sin->sin_port));
            ProxyLog("    DATA: %s", hexbuf);
        } else {
            ProxyLog("  SENDTO[%ld]: sock=%d len=%d->rc=%d (no addr)", count, (int)s, len, rc);
        }
    }
    return rc;
}

/* recvfrom hook for monitoring inbound UDP traffic */
typedef int (WSAAPI *PFN_recvfrom)(SOCKET, char*, int, int,
                                    struct sockaddr*, int*);
static PFN_recvfrom g_pfnOrigRecvfrom = NULL;
static volatile LONG g_recvfromCount = 0;

static int WSAAPI HookedRecvfrom(SOCKET s, char* buf, int len, int flags,
                                  struct sockaddr* from, int* fromlen) {
    int rc = g_pfnOrigRecvfrom(s, buf, len, flags, from, fromlen);
    if (rc > 0 && !(flags & MSG_PEEK)) {
        LONG count = InterlockedIncrement(&g_recvfromCount);
        if (count <= 200) {
            char hexbuf[97] = {0};
            int i, hlen = rc < 32 ? rc : 32;
            for (i = 0; i < hlen; i++)
                sprintf(hexbuf + i*3, "%02X ", (unsigned char)buf[i]);
            if (from && fromlen && *fromlen >= (int)sizeof(struct sockaddr_in)) {
                const struct sockaddr_in* sin = (const struct sockaddr_in*)from;
                ProxyLog("  RECVFROM[%ld]: sock=%d len=%d flags=0x%X from=%d.%d.%d.%d:%d",
                         count, (int)s, rc, flags,
                         (unsigned char)((char*)&sin->sin_addr)[0],
                         (unsigned char)((char*)&sin->sin_addr)[1],
                         (unsigned char)((char*)&sin->sin_addr)[2],
                         (unsigned char)((char*)&sin->sin_addr)[3],
                         ntohs(sin->sin_port));
            } else {
                ProxyLog("  RECVFROM[%ld]: sock=%d len=%d flags=0x%X (no addr)", count, (int)s, rc, flags);
            }
            ProxyLog("    DATA: %s", hexbuf);
        }
    }
    return rc;
}

/* ================================================================
 * Crash handler - logs diagnostics for unhandled access violations
 * ================================================================ */

/* Check if a CALL instruction precedes the address (validates return address) */
static BOOL HasCallBefore(DWORD addr) {
    BYTE* p = (BYTE*)addr;
    if (addr < 0x00401000) return FALSE;
    if (IsBadReadPtr(p - 7, 7)) return FALSE;
    /* CALL rel32 (E8 xx xx xx xx) */
    if (p[-5] == 0xE8) return TRUE;
    /* CALL [reg] (FF /2: FF 10..17) or CALL reg (FF D0..D7) */
    if (p[-2] == 0xFF && ((p[-1] & 0xF8) == 0x10 || (p[-1] & 0xF8) == 0xD0)) return TRUE;
    /* CALL [reg+disp8] (FF 50..57 xx) */
    if (p[-3] == 0xFF && (p[-2] & 0xF8) == 0x50) return TRUE;
    /* CALL [reg+disp32] (FF 90..97 xx xx xx xx) */
    if (p[-6] == 0xFF && (p[-5] & 0xF8) == 0x90) return TRUE;
    /* CALL [disp32] (FF 15 xx xx xx xx) - IAT calls */
    if (p[-6] == 0xFF && p[-5] == 0x15) return TRUE;
    /* CALL [reg*scale+disp32] with SIB: FF 14 xx (3 bytes) */
    if (p[-3] == 0xFF && p[-2] == 0x14) return TRUE;
    return FALSE;
}

/* Phase 2 crash recovery: when FUN_00504f10 causes a PE-header crash loop,
 * the VEH longjmps back to the Phase 2 caller. TopWindow is already created
 * by the time the crash cascade starts, so this is safe. */
static jmp_buf g_phase2JmpBuf;
static volatile int g_phase2Active = 0;

static LONG WINAPI CrashHandler(EXCEPTION_POINTERS* ep) {
    /* ---- Software breakpoint handler ---- */
    if (ep->ExceptionRecord->ExceptionCode == 0x80000003 && g_bpInstalled) {
        CONTEXT* ctx = ep->ContextRecord;
        DWORD eip = (DWORD)ctx->Eip - 1; /* INT3 advances EIP past the 0xCC byte */
        if (eip == BP_NEWPLAYER_ADDR) {
            DWORD* stk = (DWORD*)ctx->Esp;
            ProxyLog("  BP-HIT: NewPlayerHandler ECX(this)=0x%08X event=0x%08X retAddr=0x%08X",
                     (unsigned)ctx->Ecx, stk[1], stk[0]);
            /* Check +0x1F8 on the MultiplayerGame this pointer */
            if (ctx->Ecx && !IsBadReadPtr((void*)(ctx->Ecx + 0x1F8), 1))
                ProxyLog("    this+0x1F8=%d +0x1FC(maxPlayers)=%d",
                         *(BYTE*)(ctx->Ecx + 0x1F8),
                         !IsBadReadPtr((void*)(ctx->Ecx + 0x1FC), 4) ?
                         *(int*)(ctx->Ecx + 0x1FC) : -1);
            *(BYTE*)BP_NEWPLAYER_ADDR = g_bpOrig[0];
            ctx->Eip = BP_NEWPLAYER_ADDR;
            ctx->EFlags |= 0x100; /* TF for single-step */
            g_bpSS = 1;
            return -1; /* EXCEPTION_CONTINUE_EXECUTION */
        }
        if (eip == BP_CHECKSUM_ADDR) {
            DWORD* stk = (DWORD*)ctx->Esp;
            ProxyLog("  BP-HIT: ChecksumSend(0x006a3820) csm=0x%08X connID=%u retAddr=0x%08X",
                     stk[1], stk[2], stk[0]);
            *(BYTE*)BP_CHECKSUM_ADDR = g_bpOrig[1];
            ctx->Eip = BP_CHECKSUM_ADDR;
            ctx->EFlags |= 0x100;
            g_bpSS = 2;
            return -1;
        }
        if (eip == BP_SEND_ADDR) {
            DWORD* stk = (DWORD*)ctx->Esp;
            static int sendHits = 0;
            sendHits++;
            if (sendHits <= 20)
                ProxyLog("  BP-HIT: TGNetwork::Send wsn=0x%08X connID=%u pkt=0x%08X flag=%d",
                         stk[1], stk[2], stk[3], stk[4]);
            *(BYTE*)BP_SEND_ADDR = g_bpOrig[2];
            ctx->Eip = BP_SEND_ADDR;
            ctx->EFlags |= 0x100;
            g_bpSS = 3;
            return -1;
        }
        return 0; /* not our breakpoint */
    }
    if (ep->ExceptionRecord->ExceptionCode == 0x80000004 && g_bpSS) {
        /* Single-step: re-install the breakpoint we just executed past */
        DWORD oldProt;
        if (g_bpSS == 1) {
            VirtualProtect((void*)BP_NEWPLAYER_ADDR, 1, PAGE_EXECUTE_READWRITE, &oldProt);
            *(BYTE*)BP_NEWPLAYER_ADDR = 0xCC;
            VirtualProtect((void*)BP_NEWPLAYER_ADDR, 1, oldProt, &oldProt);
        } else if (g_bpSS == 2) {
            VirtualProtect((void*)BP_CHECKSUM_ADDR, 1, PAGE_EXECUTE_READWRITE, &oldProt);
            *(BYTE*)BP_CHECKSUM_ADDR = 0xCC;
            VirtualProtect((void*)BP_CHECKSUM_ADDR, 1, oldProt, &oldProt);
        } else if (g_bpSS == 3) {
            VirtualProtect((void*)BP_SEND_ADDR, 1, PAGE_EXECUTE_READWRITE, &oldProt);
            *(BYTE*)BP_SEND_ADDR = 0xCC;
            VirtualProtect((void*)BP_SEND_ADDR, 1, oldProt, &oldProt);
        }
        ep->ContextRecord->EFlags &= ~0x100; /* clear TF */
        g_bpSS = 0;
        return -1;
    }

    /* Log any non-AV, non-debug exception for diagnostics */
    if (ep->ExceptionRecord->ExceptionCode != 0xC0000005 &&
        ep->ExceptionRecord->ExceptionCode != 0x80000003 && /* breakpoint */
        ep->ExceptionRecord->ExceptionCode != 0x80000004 && /* single step */
        ep->ExceptionRecord->ExceptionCode != 0x406D1388 && /* thread name */
        ep->ExceptionRecord->ExceptionCode != 0x40010006) { /* OutputDebugString */
        CONTEXT* c = ep->ContextRecord;
        ProxyLog("!!! EXCEPTION 0x%08X at EIP=0x%08X ESP=0x%08X",
                 (unsigned)ep->ExceptionRecord->ExceptionCode,
                 (unsigned)c->Eip, (unsigned)c->Esp);
        if (ep->ExceptionRecord->ExceptionCode == 0xC00000FD) { /* stack overflow */
            ProxyLog("    STACK OVERFLOW detected");
            ProxyLog("    EAX=%08X EBX=%08X ECX=%08X EDX=%08X ESI=%08X EDI=%08X EBP=%08X",
                     (unsigned)c->Eax, (unsigned)c->Ebx, (unsigned)c->Ecx,
                     (unsigned)c->Edx, (unsigned)c->Esi, (unsigned)c->Edi,
                     (unsigned)c->Ebp);
        }
        return 0; /* pass through to default handler */
    }
    if (ep->ExceptionRecord->ExceptionCode == 0xC0000005) {
        CONTEXT* ctx = ep->ContextRecord;
        DWORD eip = (DWORD)ctx->Eip;
        DWORD faultAddr = (DWORD)ep->ExceptionRecord->ExceptionInformation[1];
        int isWrite = ep->ExceptionRecord->ExceptionInformation[0] ? 1 : 0;

        /* ---- NULL/bad EIP: executing non-code memory ----
           Happens when code calls/jumps through a NULL or stale pointer.
           Scan the stack for a return address preceded by a CALL instruction.
           Game code is 0x00401000-0x008FFFFF; anything outside that is "bad EIP". */
        if (eip < 0x00401000 || (eip >= 0x00900000 && eip < 0x10000000)) {
            DWORD* stack = (DWORD*)ctx->Esp;
            static int nullEipCount = 0;
            nullEipCount++;
            if (!IsBadReadPtr(stack, 2048) && nullEipCount <= 500) {
                int i;
                /* First pass: find CLOSE game code return address (within 32 DWORDs = 128 bytes).
                   Recovering to addresses far up the stack corrupts program state. */
                for (i = 0; i < 32; i++) {
                    if (stack[i] >= 0x00401000 && stack[i] < 0x00900000
                        && HasCallBefore(stack[i])) {
                        if (nullEipCount <= 10)
                            ProxyLog("  VEH-FIX: bad EIP=0x%X, return to 0x%08X (ESP+%X, fix #%d)",
                                     (unsigned)eip, (unsigned)stack[i], i * 4, nullEipCount);
                        ctx->Eip = stack[i];
                        ctx->Esp += (i + 1) * 4;
                        ctx->Eax = 0;
                        return -1;
                    }
                }
                /* Log stack for debugging (only first few times) */
                if (nullEipCount <= 3) {
                    ProxyLog("  VEH: bad EIP=0x%X, no close return addr found.", (unsigned)eip);
                    ProxyLog("  Registers: EAX=%08X EBX=%08X ECX=%08X EDX=%08X",
                             (unsigned)ctx->Eax, (unsigned)ctx->Ebx,
                             (unsigned)ctx->Ecx, (unsigned)ctx->Edx);
                    ProxyLog("  Registers: ESI=%08X EDI=%08X EBP=%08X ESP=%08X",
                             (unsigned)ctx->Esi, (unsigned)ctx->Edi,
                             (unsigned)ctx->Ebp, (unsigned)ctx->Esp);
                    /* Raw stack dump - 48 DWORDs = 192 bytes */
                    ProxyLog("  Raw stack (48 DWORDs):");
                    for (i = 0; i < 48; i += 4)
                        ProxyLog("    ESP+%03X: %08X %08X %08X %08X",
                                 i * 4,
                                 (unsigned)stack[i], (unsigned)stack[i+1],
                                 (unsigned)stack[i+2], (unsigned)stack[i+3]);
                    /* Also log any game/DLL code addresses found further on stack */
                    for (i = 48; i < 512; i++) {
                        if ((stack[i] >= 0x00401000 && stack[i] < 0x00900000) ||
                            (stack[i] >= 0x10000000 && stack[i] < 0x20000000)) {
                            ProxyLog("    ESP+%04X: 0x%08X (%s, HasCallBefore=%d)",
                                     i * 4, (unsigned)stack[i],
                                     stack[i] < 0x00900000 ? "game" : "DLL",
                                     HasCallBefore(stack[i]));
                        }
                    }
                }
            }
            /* Phase 2 crash recovery: if we can't find a return address and
               Phase 2 is active, longjmp back. TopWindow is already created. */
            if (g_phase2Active) {
                ProxyLog("  VEH: bad EIP=0x%X during Phase 2 -> longjmp recovery (fix #%d)",
                         (unsigned)eip, nullEipCount);
                g_phase2Active = 0;
                longjmp(g_phase2JmpBuf, 1);
            }
            if (nullEipCount <= 10)
                ProxyLog("  VEH: bad EIP=0x%X, no valid return address found (fix #%d)",
                         (unsigned)eip, nullEipCount);
        }

        /* ---- NULL pointer WRITE handler ----
           Redirect the register containing the fault address to dummy buffer.
           This lets writes to NULL succeed harmlessly in stub mode. */
        if (isWrite && faultAddr < 0x10000 && g_pNullDummy) {
            static int writeFixCount = 0;
            DWORD target = (DWORD)g_pNullDummy + faultAddr;
            const char* regName = NULL;
            writeFixCount++;
            if (writeFixCount > 2000) goto log_crash;
            if      (ctx->Ecx == faultAddr) { ctx->Ecx = target; regName = "ECX"; }
            else if (ctx->Eax == faultAddr) { ctx->Eax = target; regName = "EAX"; }
            else if (ctx->Edx == faultAddr) { ctx->Edx = target; regName = "EDX"; }
            else if (ctx->Esi == faultAddr) { ctx->Esi = target; regName = "ESI"; }
            else if (ctx->Edi == faultAddr) { ctx->Edi = target; regName = "EDI"; }
            else if (ctx->Ebx == faultAddr) { ctx->Ebx = target; regName = "EBX"; }
            if (regName) {
                if (writeFixCount <= 5 || writeFixCount % 100 == 0)
                    ProxyLog("  VEH-FIX: NULL write+0x%X at EIP=0x%08X, set %s -> dummy (wfix #%d)",
                             (unsigned)faultAddr, (unsigned)eip, regName, writeFixCount);
                return -1;
            }
        }

        /* ---- General NULL pointer READ handler ----
           Handles crashes caused by NULL 'this' pointers or NULL object
           pointers. Redirect NULL register to a large zeroed dummy buffer. */
        if (!isWrite && faultAddr < 0x10000 && g_pNullDummy) {
            static DWORD lastFixEip = 0;
            static int sameEipCount = 0;
            static int totalFixCount = 0;

            if (eip == lastFixEip) {
                sameEipCount++;
                if (sameEipCount > 1000) goto log_crash;
            } else {
                lastFixEip = eip;
                sameEipCount = 0;
            }
            totalFixCount++;

            if (totalFixCount == 1)
                PatchNullGlobals();

            /* For mipmap code range: inject dummy surface */
            if (faultAddr <= 4 && eip >= 0x007C0000 && eip <= 0x007D0000
                && g_pPatchDummy) {
                DWORD* stack = (DWORD*)ctx->Esp;
                if (totalFixCount <= 5)
                    ProxyLog("  VEH-FIX: NULL deref at EIP=0x%08X, injecting dummy surface",
                             (unsigned)eip);
                ctx->Eax = (DWORD)g_pPatchDummy;
                if (!IsBadWritePtr(stack, 4) && stack[0] == 0)
                    stack[0] = (DWORD)g_pPatchDummy;
                return -1;
            }

            /* General case: fix the NULL register */
            {
                DWORD dummy = (DWORD)g_pNullDummy;
                const char* regName = NULL;
                if      (ctx->Ecx == 0) { ctx->Ecx = dummy; regName = "ECX"; }
                else if (ctx->Eax == 0) { ctx->Eax = dummy; regName = "EAX"; }
                else if (ctx->Edx == 0) { ctx->Edx = dummy; regName = "EDX"; }
                else if (ctx->Esi == 0) { ctx->Esi = dummy; regName = "ESI"; }
                else if (ctx->Edi == 0) { ctx->Edi = dummy; regName = "EDI"; }
                else if (ctx->Ebx == 0) { ctx->Ebx = dummy; regName = "EBX"; }
                if (regName) {
                    if (totalFixCount <= 5 || totalFixCount % 100 == 0)
                        ProxyLog("  VEH-FIX: NULL+0x%X at EIP=0x%08X, set %s -> dummy (fix #%d)",
                                 (unsigned)faultAddr, (unsigned)eip, regName, totalFixCount);
                    return -1;
                }
            }
        }

        /* Log unhandled crashes (suppress noise from system DLLs like IsBadReadPtr) */
        log_crash:
        if (eip >= 0x70000000) {
            /* System DLL crash - likely IsBadReadPtr or similar. Pass through silently. */
            return 0;
        }
        {
            static int totalCrashCount = 0;
            totalCrashCount++;
            if (totalCrashCount > 50) {
                /* Too many unrecoverable crashes - abort to prevent infinite loop */
                if (totalCrashCount == 51)
                    ProxyLog("!!! TOO MANY CRASHES (%d), passing to OS", totalCrashCount);
                return 0; /* let OS handle it */
            }
        }
        ProxyLog("!!! CRASH: EIP=0x%08X accessing 0x%08X (%s)",
                 (unsigned)eip, (unsigned)faultAddr, isWrite ? "write" : "read");
        ProxyLog("    EAX=0x%08X EBX=0x%08X ECX=0x%08X EDX=0x%08X",
                 (unsigned)ctx->Eax, (unsigned)ctx->Ebx,
                 (unsigned)ctx->Ecx, (unsigned)ctx->Edx);
        ProxyLog("    ESI=0x%08X EDI=0x%08X EBP=0x%08X ESP=0x%08X",
                 (unsigned)ctx->Esi, (unsigned)ctx->Edi,
                 (unsigned)ctx->Ebp, (unsigned)ctx->Esp);
        {
            BYTE* code = (BYTE*)eip;
            if (!IsBadReadPtr(code - 16, 64)) {
                char hexBuf[512];
                char *p = hexBuf;
                int j;
                for (j = -16; j < 32; j++) {
                    if (j == 0) { *p++ = '['; }
                    p += wsprintfA(p, "%02X ", code[j]);
                    if (j == 0) { p[-1] = ']'; *p++ = ' '; }
                }
                ProxyLog("    Code: %s", hexBuf);
            }
        }
    }
    return 0; /* EXCEPTION_CONTINUE_SEARCH */
}

/* ================================================================
 * Hook abort() in game's static CRT
 *
 * abort() at 0x0085A108 starts with "push 0Ah; call raise".
 * We redirect to a code cave that calls HookedAbort then returns,
 * effectively suppressing the abort.
 * ================================================================ */
static BYTE* g_pAbortCave = NULL;
static LONG g_abortCount = 0;

static void __cdecl __attribute__((optimize("O0"))) HookedAbort(void) {
    DWORD* ebp_val;
    char buf[256];

    g_abortCount++;
    __asm__ volatile("movl %%ebp, %0" : "=r" (ebp_val));

    if (g_abortCount <= 5) {
        if (ebp_val && !IsBadReadPtr(ebp_val, 12)) {
            DWORD callerOfAbort = ebp_val[2];
            ResolveAddr(callerOfAbort, buf, sizeof(buf));
            ProxyLog("!!! abort() #%d SUPPRESSED - called from: %s",
                     g_abortCount, buf);
        } else {
            ProxyLog("!!! abort() #%d SUPPRESSED (ebp=%p)", g_abortCount, ebp_val);
        }

        if (g_abortCount == 1) {
            DWORD* stack;
            int i, found = 0;
            __asm__ volatile("movl %%esp, %0" : "=r" (stack));
            ProxyLog("  Raw stack scan:");
            for (i = 0; i < 256 && !IsBadReadPtr(stack + i, 4); i++) {
                DWORD val = stack[i];
                if (val >= 0x00401000 && val < 0x00900000) {
                    ResolveAddr(val, buf, sizeof(buf));
                    ProxyLog("    ESP+%04X: %s", i * 4, buf);
                    found++;
                    if (found >= 20) break;
                }
            }
        }
    } else if (g_abortCount == 6) {
        ProxyLog("!!! abort() called %d times, suppressing further logging", g_abortCount);
    }
}

static void HookAbort(void) {
    BYTE* pAbort = (BYTE*)0x0085A108;
    BYTE* cave;
    DWORD oldProt;
    LONG jmpOffset;
    int c;

    if (IsBadReadPtr(pAbort, 7)) {
        ProxyLog("  HookAbort: address not readable");
        return;
    }
    if (pAbort[0] != 0x6A || pAbort[1] != 0x0A) {
        ProxyLog("  HookAbort: bytes don't match (expected 6A 0A, got %02X %02X)",
                 pAbort[0], pAbort[1]);
        return;
    }

    cave = (BYTE*)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE);
    if (!cave) {
        ProxyLog("  HookAbort: VirtualAlloc failed");
        return;
    }
    g_pAbortCave = cave;

    c = 0;
    cave[c++] = 0xE8; /* call HookedAbort */
    jmpOffset = (LONG)((BYTE*)HookedAbort - (cave + c + 4));
    memcpy(cave + c, &jmpOffset, 4); c += 4;
    cave[c++] = 0xC3; /* ret - return to abort's caller, skip actual abort */
    ProxyLog("  HookAbort: cave written (%d bytes) - abort() SUPPRESSED", c);

    VirtualProtect(pAbort, 7, PAGE_EXECUTE_READWRITE, &oldProt);
    pAbort[0] = 0xE9;
    jmpOffset = (LONG)((DWORD)cave - (DWORD)(pAbort + 5));
    memcpy(pAbort + 1, &jmpOffset, 4);
    pAbort[5] = 0x90; pAbort[6] = 0x90;
    VirtualProtect(pAbort, 7, oldProt, &oldProt);
    ProxyLog("  HookAbort: patched 0x0085A108 -> JMP %p", cave);
}

/* ================================================================
 * PatchNullSurface - fix NULL surface dereference in mipmap code
 *
 * At 0x7CB322, the game stores a surface pointer and calls AddRef
 * without checking for NULL. We redirect to a code cave that
 * substitutes a dummy surface when eax==NULL.
 * ================================================================ */
static BYTE* g_pCodeCave = NULL;

static void PatchNullSurface(void) {
    BYTE* pTarget = (BYTE*)0x007CB322;
    DWORD returnAddr = 0x007CB32A;
    BYTE* cave;
    DWORD oldProt, dummyAddr;
    LONG jmpOffset;
    int c;

    if (IsBadReadPtr(pTarget, 8)) {
        ProxyLog("  PATCH: target 0x7CB322 not readable");
        return;
    }
    if (pTarget[0] != 0x89 || pTarget[1] != 0x06 ||
        pTarget[2] != 0x50 ||
        pTarget[3] != 0x8B || pTarget[4] != 0x08 ||
        pTarget[5] != 0xFF || pTarget[6] != 0x51 || pTarget[7] != 0x04) {
        ProxyLog("  PATCH: bytes at 0x7CB322 don't match expected pattern");
        return;
    }

    g_pPatchDummy = CreateProxySurface7(1, 1, 16, DDSCAPS_TEXTURE | DDSCAPS_SYSTEMMEMORY);
    if (!g_pPatchDummy) {
        ProxyLog("  PATCH: failed to create dummy surface");
        return;
    }
    g_pPatchDummy->refCount = 10000;
    ProxyLog("  PATCH: dummy surface at %p", g_pPatchDummy);

    cave = (BYTE*)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE);
    if (!cave) {
        ProxyLog("  PATCH: VirtualAlloc for code cave failed");
        return;
    }
    g_pCodeCave = cave;
    ProxyLog("  PATCH: code cave at %p", cave);

    dummyAddr = (DWORD)g_pPatchDummy;
    c = 0;
    /* test eax, eax */
    cave[c++] = 0x85; cave[c++] = 0xC0;
    /* jnz +6 (skip to original code path) */
    cave[c++] = 0x75; cave[c++] = 0x06;
    /* mov eax, imm32 (load dummy surface address) */
    cave[c++] = 0xB8;
    memcpy(cave + c, &dummyAddr, 4); c += 4;
    /* Original code: mov [esi], eax */
    cave[c++] = 0x89; cave[c++] = 0x06;
    /* push eax */
    cave[c++] = 0x50;
    /* mov ecx, [eax] */
    cave[c++] = 0x8B; cave[c++] = 0x08;
    /* call [ecx+4] (AddRef) */
    cave[c++] = 0xFF; cave[c++] = 0x51; cave[c++] = 0x04;
    /* jmp returnAddr */
    cave[c++] = 0xE9;
    jmpOffset = (LONG)(returnAddr - (DWORD)(cave + c + 4));
    memcpy(cave + c, &jmpOffset, 4); c += 4;

    ProxyLog("  PATCH: cave code %d bytes", c);

    VirtualProtect(pTarget, 8, PAGE_EXECUTE_READWRITE, &oldProt);
    pTarget[0] = 0xE9;
    jmpOffset = (LONG)((DWORD)cave - (DWORD)(pTarget + 5));
    memcpy(pTarget + 1, &jmpOffset, 4);
    pTarget[5] = 0x90; pTarget[6] = 0x90; pTarget[7] = 0x90;
    VirtualProtect(pTarget, 8, oldProt, &oldProt);
    ProxyLog("  PATCH: patched 0x7CB322 -> JMP %p (NULL surface fix)", cave);
}

/* ================================================================
 * PatchRenderTick - Skip render work in the per-frame function
 *
 * Function at 0x004433E0 checks [0x00995A48] and if zero, does
 * render operations that crash on NULL pointers in stub mode.
 * Patch JNZ to JMP to always skip render work.
 *
 * At 0x004433EA: 75 4A (jnz +0x4A) -> EB 4A (jmp +0x4A)
 *
 * NOTE: This does NOT affect the game's network pump. TGNetwork_Update
 * is called from FUN_00451ac0 (scene traversal), a separate function.
 * ================================================================ */
static void PatchRenderTick(void) {
    BYTE* pTarget = (BYTE*)0x004433EA;
    DWORD oldProt;

    if (IsBadReadPtr(pTarget, 2)) {
        ProxyLog("  PatchRenderTick: address not readable");
        return;
    }
    if (pTarget[0] != 0x75 || pTarget[1] != 0x4A) {
        ProxyLog("  PatchRenderTick: bytes don't match (expected 75 4A, got %02X %02X)",
                 pTarget[0], pTarget[1]);
        return;
    }

    VirtualProtect(pTarget, 2, PAGE_EXECUTE_READWRITE, &oldProt);
    pTarget[0] = 0xEB;  /* JMP rel8 (unconditional) */
    VirtualProtect(pTarget, 2, oldProt, &oldProt);
    ProxyLog("  PatchRenderTick: patched JNZ->JMP at 0x004433EA (skip render work)");
}

/* ================================================================
 * PatchSkipRendererCtor - Skip the NiDX7Renderer constructor in Init
 *
 * In UtopiaApp::Init (FUN_0043ad70), the renderer is constructed at:
 *   0x0043ADB6: JZ 0x0043ADC3  (74 0B) - skip ctor if alloc=NULL
 *   0x0043ADBA: CALL 0x007E7AF0        - renderer constructor
 *   0x0043ADC3: XOR EDI,EDI           - renderer = NULL path
 *
 * The renderer constructor creates D3D devices and initializes HW
 * pipelines that crash without a real GPU. We patch JZ→JMP to always
 * take the "no renderer" path. Init continues with renderer=NULL.
 * ================================================================ */
static void PatchSkipRendererCtor(void) {
    BYTE* pTarget = (BYTE*)0x0043ADB6;
    DWORD oldProt;

    if (IsBadReadPtr(pTarget, 2)) {
        ProxyLog("  PatchSkipRendererCtor: address not readable");
        return;
    }
    if (pTarget[0] != 0x74 || pTarget[1] != 0x0B) {
        ProxyLog("  PatchSkipRendererCtor: bytes don't match (expected 74 0B, got %02X %02X)",
                 pTarget[0], pTarget[1]);
        return;
    }

    VirtualProtect(pTarget, 2, PAGE_EXECUTE_READWRITE, &oldProt);
    pTarget[0] = 0xEB;  /* JMP rel8 (unconditional) */
    VirtualProtect(pTarget, 2, oldProt, &oldProt);
    ProxyLog("  PatchSkipRendererCtor: patched JZ->JMP at 0x0043ADB6 (skip renderer construction)");
}

/* ================================================================
 * PatchRendererCtorEntry - Patch the NiDX7Renderer constructor itself
 *
 * FUN_007e7af0 is the NiDX7Renderer constructor. It's called from
 * 10 different locations. Rather than patching each call site, we
 * patch the entry point to zero the object and set the vtable.
 *
 * The NiDX7Renderer is 0x224 bytes. Many code paths read fields and
 * check for NULL before dereferencing. Zero-initializing ensures all
 * those NULL checks pass cleanly.
 *
 * Original:  6A FF    PUSH -1
 *            68 ...   PUSH SEH handler
 * Patched:   PUSHAD
 *            MOV EDI, ECX       ; dest = this
 *            XOR EAX, EAX       ; fill = 0
 *            MOV ECX, 0x89      ; 0x224/4 = 137 DWORDs
 *            REP STOSD           ; zero 0x224 bytes
 *            POPAD
 *            MOV [ECX], 0x89902C ; set vtable
 *            MOV EAX, ECX       ; return this
 *            RET
 * ================================================================ */
static void PatchRendererCtorEntry(void) {
    BYTE* pTarget = (BYTE*)0x007E7AF0;
    DWORD oldProt;
    int i = 0;

    if (IsBadReadPtr(pTarget, 24)) {
        ProxyLog("  PatchRendererCtorEntry: address not readable");
        return;
    }
    if (pTarget[0] != 0x6A || pTarget[1] != 0xFF) {
        ProxyLog("  PatchRendererCtorEntry: bytes don't match (expected 6A FF, got %02X %02X)",
                 pTarget[0], pTarget[1]);
        return;
    }

    VirtualProtect(pTarget, 22, PAGE_EXECUTE_READWRITE, &oldProt);
    pTarget[i++] = 0x60;                   /* PUSHAD */
    pTarget[i++] = 0x8B; pTarget[i++] = 0xF9; /* MOV EDI, ECX */
    pTarget[i++] = 0x33; pTarget[i++] = 0xC0; /* XOR EAX, EAX */
    pTarget[i++] = 0xB9;                   /* MOV ECX, imm32 */
    pTarget[i++] = 0x89; pTarget[i++] = 0x00;
    pTarget[i++] = 0x00; pTarget[i++] = 0x00; /* = 0x89 DWORDs */
    pTarget[i++] = 0xF3; pTarget[i++] = 0xAB; /* REP STOSD */
    pTarget[i++] = 0x61;                   /* POPAD */
    pTarget[i++] = 0xC7; pTarget[i++] = 0x01; /* MOV [ECX], imm32 */
    pTarget[i++] = 0x2C; pTarget[i++] = 0x90;
    pTarget[i++] = 0x89; pTarget[i++] = 0x00; /* = 0x0089902C (real vtable) */
    pTarget[i++] = 0x8B; pTarget[i++] = 0xC1; /* MOV EAX, ECX */
    pTarget[i++] = 0xC3;                   /* RET */
    VirtualProtect(pTarget, 22, oldProt, &oldProt);
    ProxyLog("  PatchRendererCtorEntry: patched 0x007E7AF0 (zero 0x224 bytes + set vtable 0x89902C + RET)");
}

/* ================================================================
 * PatchInitAbort - Prevent abort() when init check fails
 *
 * At 0x0043B1D2: JMP 0x0085A108 (5 bytes: E9 xx xx xx xx)
 * This abort is called if FUN_006f7d90 returns NULL. Without a
 * renderer, this check may fail. NOP the JMP so execution falls
 * through to the Python script loading at 0x0043B1D7.
 * ================================================================ */
static void PatchInitAbort(void) {
    BYTE* pTarget = (BYTE*)0x0043B1D2;
    DWORD oldProt;

    if (IsBadReadPtr(pTarget, 5)) {
        ProxyLog("  PatchInitAbort: address not readable");
        return;
    }
    if (pTarget[0] != 0xE9) {
        ProxyLog("  PatchInitAbort: bytes don't match (expected E9, got %02X)", pTarget[0]);
        return;
    }

    VirtualProtect(pTarget, 5, PAGE_EXECUTE_READWRITE, &oldProt);
    pTarget[0] = 0x90; pTarget[1] = 0x90; pTarget[2] = 0x90;
    pTarget[3] = 0x90; pTarget[4] = 0x90;
    VirtualProtect(pTarget, 5, oldProt, &oldProt);
    ProxyLog("  PatchInitAbort: NOPed JMP at 0x0043B1D2 (abort suppressed)");
}

/* ================================================================
 * PatchSkipRendererSetup - Skip renderer pipeline construction
 *
 * After the D3D caps check passes at 0x007C39CF in FUN_007c3480
 * (the NiDX7Renderer setup function), skip all the rendering
 * pipeline creation (clone/AddRef calls, texture managers, etc.)
 * and jump directly to the success return at 0x007C3D75.
 *
 * The caps check, format enumeration, and z-buffer setup all run
 * normally. Only the rendering pipeline objects are skipped since
 * the headless server never renders.
 *
 * Patch: 007C39CF  PUSH 0x976b98 (5 bytes) -> JMP 007C3D75
 * ================================================================ */
static void PatchSkipRendererSetup(void) {
    BYTE* target = (BYTE*)0x007C39CF;
    DWORD oldProt;
    LONG jmpOff;

    if (IsBadReadPtr(target, 5) || target[0] != 0x68) {
        ProxyLog("  PatchSkipRendererSetup: unexpected bytes at 0x007C39CF (%02X), skipped",
                 target[0]);
        return;
    }

    /* JMP rel32 to 0x007C3D75 (success return: MOV AL,1; epilogue; RET 0x24) */
    jmpOff = (LONG)(0x007C3D75 - (DWORD)(target + 5));

    VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &oldProt);
    target[0] = 0xE9;
    memcpy(target + 1, &jmpOff, 4);
    VirtualProtect(target, 5, oldProt, &oldProt);

    ProxyLog("  PatchSkipRendererSetup: 007C39CF -> JMP 007C3D75 (skip pipeline, return TRUE)");
}

/* ================================================================
 * PatchSkipDeviceLost - Skip "device lost" recreation path
 *
 * Vtable method at 0x007C1330 (offset +0x98 in renderer wrapper vtable
 * 0x00898984) is called every frame. It calls FUN_007c45b0 to check
 * device status. When the device appears "lost" (always true for stubs),
 * it tries to destroy+recreate pipeline objects at offsets 0xC4, 0xC0,
 * 0xB8, 0xBC - which are NULL because PatchSkipRendererSetup skipped them.
 *
 * Patch: 007C1346 JZ +0x49 (74 49) -> JMP +0x49 (EB 49)
 * This always skips the destruction/recreation sequence.
 * ================================================================ */
static void PatchSkipDeviceLost(void) {
    BYTE* target = (BYTE*)0x007C1346;
    DWORD oldProt;

    if (IsBadReadPtr(target, 2) || target[0] != 0x74 || target[1] != 0x49) {
        ProxyLog("  PatchSkipDeviceLost: unexpected bytes at 0x007C1346 (%02X %02X), skipped",
                 target[0], target[1]);
        return;
    }

    VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, &oldProt);
    target[0] = 0xEB; /* JZ -> JMP short */
    VirtualProtect(target, 1, oldProt, &oldProt);

    ProxyLog("  PatchSkipDeviceLost: 007C1346 JZ->JMP (always skip device-lost recreation)");
}

/* ================================================================
 * PatchRendererMethods - Patch individual renderer methods
 *
 * Some vtable methods blindly dereference pointer fields that are NULL
 * in our zero-initialized renderer or renderer wrapper. Rather than
 * a stub vtable (which breaks thiscall calling conventions), we patch
 * specific methods to return immediately with the correct stack cleanup.
 * ================================================================ */
static void PatchRendererMethods(void) {
    static const BYTE p_ret[]       = { 0xC3 };
    static const BYTE p_ret4_zero[] = { 0x33, 0xC0, 0xC2, 0x04, 0x00 };
    static const struct {
        DWORD addr;
        BYTE expect;
        const BYTE* patch;
        int len;
        const char* desc;
    } fixes[] = {
        /* FUN_007e8780 (vtable+0x94): reads [this+0x190] - frustum planes
         * thiscall, no stack params → RET */
        { 0x007E8780, 0x83, p_ret, 1,
          "FUN_007e8780 (vtable+0x94 frustum calc) -> RET" },
        /* FUN_007c2a10: reads [this+0xC4] - pipeline object
         * thiscall, 1 stack param → XOR EAX,EAX; RET 4 */
        { 0x007C2A10, 0x56, p_ret4_zero, 5,
          "FUN_007c2a10 (pipeline call) -> XOR EAX,EAX; RET 4" },
    };
    int i;
    for (i = 0; i < (int)(sizeof(fixes) / sizeof(fixes[0])); i++) {
        BYTE* target = (BYTE*)fixes[i].addr;
        DWORD oldProt;
        if (IsBadReadPtr(target, 1) || target[0] != fixes[i].expect) {
            ProxyLog("  PatchRendererMethods: %s - unexpected byte %02X (expected %02X), skipped",
                     fixes[i].desc, target[0], fixes[i].expect);
            continue;
        }
        VirtualProtect(target, fixes[i].len, PAGE_EXECUTE_READWRITE, &oldProt);
        memcpy(target, fixes[i].patch, fixes[i].len);
        VirtualProtect(target, fixes[i].len, oldProt, &oldProt);
        ProxyLog("  PatchRendererMethods: %s at 0x%08X", fixes[i].desc, (unsigned)fixes[i].addr);
    }
}

/* ================================================================
 * PatchHeadlessCrashSites - NOP out functions that crash in headless mode
 *
 * These functions try to look up UI panes via FUN_0050e1b0(DAT_009878cc, N).
 * In headless mode DAT_009878cc points to our zeroed dummy, so the lookup
 * returns NULL, and callers crash dereferencing it.
 * Rather than patching FUN_0050e1b0 (which has complex calling conventions),
 * we NOP the problematic callers that are reachable from mission Python code.
 * ================================================================ */
static void PatchHeadlessCrashSites(void) {
    static const struct {
        DWORD addr;
        BYTE expect;   /* expected first byte to verify we're patching the right spot */
        const char* desc;
    } sites[] = {
        /* FUN_0055c810: called during MainTick after checksum-complete event.
         * Looks up UI pane via FUN_0050e1b0(DAT_009878cc, 5) -> NULL in headless.
         * Passes NULL to FUN_00507f80 which dereferences this+0x50 -> CRASH.
         * __fastcall with PUSH ESI, returns via POP ESI; RET.
         * Patching to RET skips render update; caller handles result=0 fine. */
        { 0x0055c810, 0x56, "FUN_0055c810 (UI pane render update)" },
        /* FUN_0055c860: virtual method called from mission UI code.
         * Looks up pane via FUN_0050e1b0, calls FUN_00508120 on result -> NULL crash.
         * __fastcall, no stack params -> safe to RET. */
        { 0x0055c860, 0x56, "FUN_0055c860 (mission UI pane lookup)" },
    };
    int i;
    for (i = 0; i < (int)(sizeof(sites) / sizeof(sites[0])); i++) {
        BYTE* target = (BYTE*)sites[i].addr;
        DWORD oldProt;
        if (IsBadReadPtr(target, 1) || target[0] != sites[i].expect) {
            ProxyLog("  PatchHeadlessCrashSites: %s - unexpected byte %02X (expected %02X), skipped",
                     sites[i].desc, target[0], sites[i].expect);
            continue;
        }
        VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, &oldProt);
        target[0] = 0xC3; /* RET */
        VirtualProtect(target, 1, oldProt, &oldProt);
        ProxyLog("  PatchHeadlessCrashSites: %s -> RET at 0x%08X", sites[i].desc, (unsigned)sites[i].addr);
    }
}

/* PatchDisableDebugConsole - Disable interactive Python debug console
 *
 * FUN_006f9470 is the debug console: prints traceback, then loops on
 * ReadConsoleA waiting for "resume" or "abort".  In headless mode stdin
 * is redirected, so this hangs the server forever.
 *
 * Caller FUN_006f9b80 checks DAT_0099add6:
 *   if 1: calls FUN_006f9470 (debug console), then PyErr_Clear, return 1
 *   if 0: calls PyErr_Print (stderr), then PyErr_Clear, return 1
 *
 * Two-pronged approach:
 *   1. Patch FUN_006f9470 to RET immediately (in case flag gets set to 1
 *      later during game init at 0x00438b10)
 *   2. Set DAT_0099add6 = 0 so the normal path calls PyErr_Print instead
 *      (traceback goes to stderr = our log file) */
static void PatchDisableDebugConsole(void) {
    BYTE* func = (BYTE*)0x006f9470;
    BYTE* flag = (BYTE*)0x0099add6;
    DWORD oldProt;

    /* Patch function entry to RET */
    if (!IsBadReadPtr(func, 1)) {
        VirtualProtect(func, 1, PAGE_EXECUTE_READWRITE, &oldProt);
        ProxyLog("  PatchDisableDebugConsole: FUN_006f9470 first byte was 0x%02X, patching to RET",
                 (int)func[0]);
        func[0] = 0xC3; /* RET */
        VirtualProtect(func, 1, oldProt, &oldProt);
    }

    /* Also clear the flag (belt and suspenders) */
    if (!IsBadReadPtr(flag, 1)) {
        VirtualProtect(flag, 1, PAGE_READWRITE, &oldProt);
        *flag = 0;
        VirtualProtect(flag, 1, oldProt, &oldProt);
    }
}

/* ================================================================
 * PatchChecksumAlwaysPass - Fix first-player-connects-to-empty-server
 *
 * FUN_006a1b10 (ChecksumCompleteHandler) verifies the connecting player's
 * checksums by comparing them against OTHER connected players.  On a fresh
 * dedicated server there are no other players, so the verification loop
 * finds no match and sets the checksum flag to 0 (FAIL).
 *
 * This causes two problems:
 *   1. The opcode 0x00 packet is sent with checksum_flag=0
 *   2. FUN_006f3f30 (which appends critical game state to the packet)
 *      is skipped because of the `if (flag != 0)` guard
 *
 * The client receives an incomplete settings packet and enters a bad
 * state (black screen with music, no ship selection).
 *
 * Fix: Change the flag initialization from 0 to 1 at 0x006a1b75.
 * Assembly: MOV byte ptr [ESP+0x1C], 0x0  ->  MOV byte ptr [ESP+0x1C], 0x1
 * Machine code change: C6 44 24 1C 00  ->  C6 44 24 1C 01
 * ================================================================ */
static void PatchChecksumAlwaysPass(void) {
    BYTE* target = (BYTE*)0x006a1b75;
    DWORD oldProt;

    if (IsBadReadPtr(target, 1)) {
        ProxyLog("  PatchChecksumAlwaysPass: address 0x006a1b75 not readable, skipped");
        return;
    }

    if (*target != 0x00) {
        ProxyLog("  PatchChecksumAlwaysPass: expected 0x00 at 0x006a1b75, got 0x%02X - skipped",
                 (int)*target);
        return;
    }

    /* Verify the instruction prefix bytes (C6 44 24 1C) to be safe */
    BYTE* instr = (BYTE*)0x006a1b71;
    if (instr[0] != 0xC6 || instr[1] != 0x44 || instr[2] != 0x24 || instr[3] != 0x1C) {
        ProxyLog("  PatchChecksumAlwaysPass: instruction prefix mismatch at 0x006a1b71, skipped");
        return;
    }

    VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, &oldProt);
    *target = 0x01;
    VirtualProtect(target, 1, oldProt, &oldProt);
    ProxyLog("  PatchChecksumAlwaysPass: patched 0x006a1b75 (checksum flag init 0->1)");
}

/* ================================================================
 * PatchCreateAppModule - Create "App" SWIG module before init imports it
 *
 * UtopiaApp::Init at 0x0043b1b9 calls TG_ImportModule("App").
 * Normally the game provides App through a mechanism we can't replicate
 * in stub mode (no App.py on disk, not frozen, not built-in as "App").
 *
 * We inject a code cave that calls our C function CreateAppModuleCallback()
 * which creates the App module via Py_InitModule4 and runs post-init
 * diagnostics via PyRun_SimpleString (on the main thread, so thread-safe).
 *
 * Original bytes at 0x0043b1b9:
 *   53                 PUSH EBX         (param2 = 0)
 *   68 80 9c 8d 00     PUSH 0x008d9c80  (param1 = "App")
 *   E8 ...             CALL TG_ImportModule
 * ================================================================ */

/* Python C API helpers */
typedef void* (__cdecl *pfn_Py_InitModule4)(const char*, void*, const char*, void*, int);
typedef int   (__cdecl *pfn_PyRunSimple)(const char*);
typedef int   (__cdecl *pfn_PyErrOccurred)(void);
typedef void  (__cdecl *pfn_PyErrClear)(void);
typedef void  (__cdecl *pfn_PyErrPrint)(void);
typedef void* (__cdecl *pfn_PyImport_GetModuleDict)(void);
typedef void* (__cdecl *pfn_PyDict_GetItemString)(void*, const char*);
typedef void* (__cdecl *pfn_PyImport_ImportModule)(const char*);
typedef void* (__cdecl *pfn_PyObject_GetAttrString)(void*, const char*);
typedef void* (__cdecl *pfn_PyObject_Str)(void*);
typedef const char* (__cdecl *pfn_PyString_AsString)(void*);
typedef void* (__cdecl *pfn_PyImport_AddModule)(const char*);
typedef void* (__cdecl *pfn_PyModule_GetDict)(void*);
typedef void* (__cdecl *pfn_PyRun_String)(const char*, int, void*, void*);
typedef void  (__cdecl *pfn_PyErr_Fetch)(void**, void**, void**);
typedef void* (__cdecl *pfn_PyObject_Repr)(void*);

#define PY_InitModule4         ((pfn_Py_InitModule4)0x0074d140)
#define PY_RunSimpleString     ((pfn_PyRunSimple)0x0074ae80)
#define PY_ErrOccurred         ((pfn_PyErrOccurred)0x00752ec0)
#define PY_ErrClear            ((pfn_PyErrClear)0x00753140)
#define PY_ErrPrint            ((pfn_PyErrPrint)0x0074af10)
#define PY_GetModuleDict       ((pfn_PyImport_GetModuleDict)0x0075b250)
#define PY_DictGetItemString   ((pfn_PyDict_GetItemString)0x00752cd0)
#define PY_ImportModule        ((pfn_PyImport_ImportModule)0x0075bbf0)
#define PY_AddModule           ((pfn_PyImport_AddModule)0x0075b890)
#define PY_ModuleGetDict       ((pfn_PyModule_GetDict)0x00773990)
#define PY_RunString           ((pfn_PyRun_String)0x0074b640)
#define PY_ErrFetch            ((pfn_PyErr_Fetch)0x00753110)

/* Log which modules are in sys.modules (C API, no Python execution needed) */
static void LogPyModules(const char* label) {
    void *modules = PY_GetModuleDict();
    if (!modules) { ProxyLog("  %s: sys.modules = NULL", label); return; }

    const char* check[] = {"App", "Appc", "Autoexec", "Local",
                           "Custom.DedicatedServer", "cPickle", "copy_reg",
                           "TopWindow", "MainMenu", "Multiplayer",
                           "FontsAndIcons", "UITheme", "LoadInterface", NULL};
    int i;
    char buf[1024];
    int pos = 0;
    pos += wsprintfA(buf + pos, "  %s: ", label);
    for (i = 0; check[i]; i++) {
        void *m = PY_DictGetItemString(modules, check[i]);
        if (m) pos += wsprintfA(buf + pos, "%s ", check[i]);
    }
    ProxyLog("%s", buf);
}

/* ================================================================
 * RunPyCode - Execute Python code using PyRun_String directly
 *
 * PyRun_SimpleString fails from TIMERPROC due to re-entrancy: it calls
 * FUN_0074bbf0(1) to adjust the nesting counter, then PyImport_AddModule
 * which can fail during re-entrant execution.
 *
 * This helper bypasses that by:
 * 1. Getting __main__ module from sys.modules dict (C API, always works)
 * 2. Getting its __dict__
 * 3. Calling PyRun_String directly with Py_file_input (0x101)
 * ================================================================ */
static int RunPyCode(const char* code) {
    void *mainMod, *mainDict, *result;

    if (PY_ErrOccurred()) PY_ErrClear();

    /* Try PyImport_AddModule first (standard path) */
    mainMod = PY_AddModule("__main__");
    if (!mainMod) {
        /* Fallback: get __main__ from sys.modules dict manually.
           PY_GetModuleDict + PY_DictGetItemString always work (used by
           LogPyModules successfully). */
        void *modules = PY_GetModuleDict();
        if (PY_ErrOccurred()) PY_ErrClear();
        if (modules)
            mainMod = PY_DictGetItemString(modules, "__main__");
        if (!mainMod) {
            ProxyLog("    RunPyCode: cannot get __main__ module");
            return -1;
        }
        ProxyLog("    RunPyCode: got __main__ via sys.modules fallback");
    }

    mainDict = PY_ModuleGetDict(mainMod);
    if (!mainDict) {
        ProxyLog("    RunPyCode: PyModule_GetDict returned NULL");
        return -1;
    }

    result = PY_RunString(code, 0x101, mainDict, mainDict);
    if (!result) {
        void *errType = NULL, *errValue = NULL, *errTB = NULL;
        PY_ErrFetch(&errType, &errValue, &errTB);
        if (errType) {
            /* Safely read type name: PyTypeObject->tp_name at +12 */
            const char *typeName = "(bad-ptr)";
            if (!IsBadReadPtr(errType, 16)) {
                const char *namePtr = *(const char**)((char*)errType + 12);
                if (namePtr && !IsBadReadPtr(namePtr, 4))
                    typeName = namePtr;
            }
            /* Safely read value: try ob_sval at +20 (PyStringObject) */
            const char *valStr = "(no-value)";
            if (errValue && !IsBadReadPtr(errValue, 24)) {
                const char *candidate = (const char*)errValue + 20;
                if (!IsBadReadPtr(candidate, 4))
                    valStr = candidate;
            }
            ProxyLog("    RunPyCode ERROR: type=0x%08X val=0x%08X [%s]: [%s]",
                     (unsigned)(DWORD)errType, (unsigned)(DWORD)errValue,
                     typeName, valStr);
        } else {
            ProxyLog("    RunPyCode: PyRun_String returned NULL (no error set)");
        }
        /* Note: PY_ErrFetch already cleared the error; we leak the refs (harmless) */
        return -1;
    }

    /* Leak the result ref (Py_None for statements) - harmless */
    return 0;
}

/* ================================================================
 * GameLoopTimerProc - drives the game tick after bootstrap
 *
 * Calls UtopiaApp_MainTick (0x0043b4f0) which processes:
 *   - TGTimerManager_Update on 0x0097F898 and 0x0097F810
 *   - TGEventManager_ProcessEvents on 0x0097F838
 *   - Game subsystem updates (multiplayer, checksum exchange, etc.)
 *   - Rendering via FUN_004433e0 (patched to NOP in stub mode)
 *
 * Also explicitly calls TGNetwork::Update (0x006B4560) to pump
 * network send/recv queues. Without this, the server never reads
 * incoming UDP packets so the checksum exchange can't complete.
 *
 * MainTick has its own SEH frame so exceptions are caught safely.
 * ================================================================ */
typedef void (__fastcall *pfn_UtopiaMainTick)(void* ecx, void* edx);
typedef void (__fastcall *pfn_TGNetworkUpdate)(void* ecx, void* edx);
typedef unsigned int (__fastcall *pfn_GameSpyStartHB)(void* ecx, void* edx, unsigned char lanMode);
typedef void (__fastcall *pfn_GameSpyTick)(void* ecx, void* edx, float gameTime);
typedef void (__cdecl *pfn_qr_handle_query)(void* qr, void* buf, struct sockaddr* addr);

#define UTOPIA_MAIN_TICK     ((pfn_UtopiaMainTick)0x0043b4f0)
#define TGNETWORK_UPDATE     ((pfn_TGNetworkUpdate)0x006B4560)
#define GAMESPY_START_HB     ((pfn_GameSpyStartHB)0x0069c240)
#define GAMESPY_TICK         ((pfn_GameSpyTick)0x0069c440)
#define QR_HANDLE_QUERY      ((pfn_qr_handle_query)0x006ac1e0)
#define UTOPIA_APP_OBJ       ((void*)0x0097FA00)
#define GAMESPY_PTR          (*(DWORD*)0x0097FA7C)  /* UtopiaModule+0x7C */

static VOID CALLBACK GameLoopTimerProc(HWND hwnd, UINT msg,
                                        UINT_PTR id, DWORD time) {
    static int tickCount = 0;
    static int lastPlayerCount = -1;
    static DWORD lastLogTime = 0;
    DWORD wsnPtr = 0;
    (void)msg; (void)hwnd; (void)id;

    tickCount++;

    /* Periodically try to patch mission modules for headless mode.
     * Mission modules may be loaded lazily (not at Phase 3 time).
     * Check every ~1s (30 ticks) until we find and patch something. */
    {
        static int missionPatched = 0;
        if (!missionPatched && (tickCount % 30 == 1)) {
            int rc = RunPyCode(
                "import sys\n"
                "if sys.modules.has_key('Custom.DedicatedServer'):\n"
                "    ds = sys.modules['Custom.DedicatedServer']\n"
                "    n = ds.PatchLoadedMissionModules()\n"
                "    if n > 0:\n"
                "        ds._log('GAMELOOP PATCH: patched ' + str(n) + ' at tick')\n");
            if (rc == 0) {
                /* Check if patching succeeded by reading a flag */
                /* For now, keep trying - PatchLoadedMissionModules is idempotent */
            }
            (void)rc;
        }
    }

    /* Read WSN pointer (used in multiple places below) */
    if (!IsBadReadPtr((void*)0x0097FA78, 4))
        wsnPtr = *(DWORD*)0x0097FA78;

    /* Diagnostic logging for first 5 ticks */
    if (tickCount <= 5) {
        DWORD clockPtr = 0;
        float gameTime = 0.0f;
        int playerCount = 0;
        int connState = -1;

        if (!IsBadReadPtr((void*)0x009a09d0, 4))
            clockPtr = *(DWORD*)0x009a09d0;
        if (clockPtr && !IsBadReadPtr((void*)(clockPtr + 0x90), 4))
            gameTime = *(float*)(clockPtr + 0x90);
        if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x30), 4))
            playerCount = *(int*)(wsnPtr + 0x30);
        if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x14), 4))
            connState = *(int*)(wsnPtr + 0x14);

        {
            /* Check critical WSN flags */
            int sendFlag = 0, isHost = 0, procPkts = 0;
            DWORD pendingQ = 0, incomingQ = 0;
            DWORD socketFD = 0xFFFFFFFF;
            if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x10C), 4)) {
                sendFlag = *(BYTE*)(wsnPtr + 0x10C);
                isHost = *(BYTE*)(wsnPtr + 0x10E);
                procPkts = *(BYTE*)(wsnPtr + 0x10D);
            }
            if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x38), 4))
                pendingQ = *(DWORD*)(wsnPtr + 0x38);
            if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x54), 4))
                incomingQ = *(DWORD*)(wsnPtr + 0x54);
            /* Socket FD at WSN+0x194 */
            if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x194), 4))
                socketFD = *(DWORD*)(wsnPtr + 0x194);

            ProxyLog("  GAMELOOP[%d]: clock=0x%08X time=%.3f WSN=0x%08X players=%d connState=%d",
                     tickCount, clockPtr, gameTime, wsnPtr, playerCount, connState);
            ProxyLog("    sendFlag=0x%02X isHost=%d procPkts=%d pendQ=0x%08X inQ=0x%08X sock=%d",
                     sendFlag, isHost, procPkts, pendingQ, incomingQ, (int)socketFD);
        }
    }

    /* Check emQ BEFORE MainTick to see if events were pending from TGNetwork_Update */
    {
        static DWORD lastPreEmQ = 0;
        DWORD preEmQ = 0;
        if (!IsBadReadPtr((void*)0x0097F840, 4))
            preEmQ = *(DWORD*)0x0097F840;
        if (preEmQ != lastPreEmQ) {
            ProxyLog("  GAMELOOP[%d]: emQ BEFORE MainTick: %u (was %u)", tickCount, preEmQ, lastPreEmQ);
            lastPreEmQ = preEmQ;
        }
    }

    /* Call the game's main tick (processes timers, events, subsystems) */
    UTOPIA_MAIN_TICK(UTOPIA_APP_OBJ, NULL);

    /* After MainTick: check if event processing resulted in queued outbound packets.
     * If NewPlayerHandler was dispatched, it calls ChecksumSend which calls
     * TGNetwork::Send, queuing packets in peer send queues. */
    if (wsnPtr) {
        static int lastUQ = -1, lastRQ = -1, lastPQ = -1;
        static int postMTLogCount = 0;
        int pCount = 0;
        DWORD pArray = 0;
        if (!IsBadReadPtr((void*)(wsnPtr + 0x30), 4))
            pCount = *(int*)(wsnPtr + 0x30);
        if (!IsBadReadPtr((void*)(wsnPtr + 0x2C), 4))
            pArray = *(DWORD*)(wsnPtr + 0x2C);
        if (pCount > 0 && pArray) {
            int pi;
            for (pi = 0; pi < pCount && pi < 4; pi++) {
                DWORD pp = 0;
                if (!IsBadReadPtr((void*)(pArray + pi*4), 4))
                    pp = *(DWORD*)(pArray + pi*4);
                if (pp && !IsBadReadPtr((void*)pp, 0xC0)) {
                    int uq = *(int*)(pp + 0x7C);
                    int rq = *(int*)(pp + 0x98);
                    int pq = *(int*)(pp + 0xB4);
                    /* Only log when queue sizes change */
                    if (uq != lastUQ || rq != lastRQ || pq != lastPQ) {
                        if (postMTLogCount < 50) {
                            postMTLogCount++;
                            ProxyLog("  GAMELOOP[%d]: PEER[%d] id=%u SEND QUEUES after MainTick: unreliable=%d reliable=%d priority=%d",
                                     tickCount, pi, *(DWORD*)(pp + 0x18), uq, rq, pq);
                        }
                        lastUQ = uq; lastRQ = rq; lastPQ = pq;
                    }
                }
            }
        }
    }

    /* Peek-based packet router for shared UDP socket.
     * GameSpy queries and game packets share the same UDP socket (WSN+0x194).
     * GameSpy queries are text-based, always starting with '\' (0x5C), e.g.
     * "\basic\", "\status\". Game packets are binary (first byte != '\').
     *
     * We peek at each pending packet with MSG_PEEK:
     *   - If '\' prefix: consume it and call qr_handle_query directly
     *   - If binary: leave it in the socket for TGNetwork_Update
     *
     * qr_t+0xE4 is kept at 0 so GameSpy_Tick's internal qr_process_incoming
     * returns immediately (no competing recvfrom). GameSpy_Tick is still
     * called for internal state management (counter increments, etc). */
    {
        DWORD gsPtr = 0;
        if (!IsBadReadPtr((void*)0x0097FA7C, 4))
            gsPtr = *(DWORD*)0x0097FA7C;
        if (gsPtr) {
            DWORD qrPtr = 0;
            if (!IsBadReadPtr((void*)(gsPtr + 0xDC), 4))
                qrPtr = *(DWORD*)(gsPtr + 0xDC);
            if (qrPtr) {
                SOCKET sock = *(SOCKET*)qrPtr;
                if (sock != INVALID_SOCKET) {
                    fd_set readSet;
                    struct timeval tv;
                    int routed = 0;
                    tv.tv_sec = 0;
                    tv.tv_usec = 0;
                    /* Drain all GameSpy queries, stop at first game packet */
                    for (;;) {
                        int selRc;
                        char peekByte;
                        struct sockaddr_in srcAddr;
                        int addrLen = sizeof(srcAddr);
                        int peekRc;

                        FD_ZERO(&readSet);
                        FD_SET(sock, &readSet);
                        selRc = select(0, &readSet, NULL, NULL, &tv);
                        if (selRc <= 0) break;

                        /* Peek at first byte without consuming */
                        addrLen = sizeof(srcAddr);
                        peekRc = recvfrom(sock, &peekByte, 1, MSG_PEEK,
                                          (struct sockaddr*)&srcAddr, &addrLen);
                        if (peekRc <= 0) break;

                        if (peekByte == '\\') {
                            /* GameSpy query - consume and handle */
                            char queryBuf[256];
                            int recvRc;
                            addrLen = sizeof(srcAddr);
                            recvRc = recvfrom(sock, queryBuf, sizeof(queryBuf)-1, 0,
                                              (struct sockaddr*)&srcAddr, &addrLen);
                            if (recvRc > 0) {
                                queryBuf[recvRc] = '\0';
                                QR_HANDLE_QUERY((void*)qrPtr, queryBuf,
                                                (struct sockaddr*)&srcAddr);
                                routed++;
                            }
                        } else {
                            /* Binary game packet - leave for TGNetwork_Update */
                            ProxyLog("  GAMELOOP[%d]: Binary packet (0x%02X) from %d.%d.%d.%d:%d - leaving for TGNetwork",
                                     tickCount, (unsigned char)peekByte,
                                     (unsigned char)srcAddr.sin_addr.S_un.S_un_b.s_b1,
                                     (unsigned char)srcAddr.sin_addr.S_un.S_un_b.s_b2,
                                     (unsigned char)srcAddr.sin_addr.S_un.S_un_b.s_b3,
                                     (unsigned char)srcAddr.sin_addr.S_un.S_un_b.s_b4,
                                     ntohs(srcAddr.sin_port));
                            break;
                        }
                    }
                    if (routed) {
                        ProxyLog("  GAMELOOP[%d]: Routed %d GameSpy queries", tickCount, routed);
                    }
                }
            }

            /* Still call GameSpy_Tick for internal state (counters, etc).
             * With qr_t+0xE4=0, its qr_process_incoming returns immediately. */
            {
                float gameTime = 0.0f;
                DWORD clockPtr = 0;
                if (!IsBadReadPtr((void*)0x009a09d0, 4))
                    clockPtr = *(DWORD*)0x009a09d0;
                if (clockPtr && !IsBadReadPtr((void*)(clockPtr + 0x90), 4))
                    gameTime = *(float*)(clockPtr + 0x90);
                GAMESPY_TICK((void*)gsPtr, NULL, gameTime);
            }
        }
    }

    /* Pump network AFTER GameSpy tick. TGNetwork::Update (0x006B4560) reads
     * remaining UDP packets and processes send/recv queues.
     * Host state: WSN+0x14 == 2 (Connect sets 2=host, 3=client). */
    if (wsnPtr) {
        /* Check socket data availability before Update */
        {
            static int selectLogCount = 0;
            SOCKET wsnSock = INVALID_SOCKET;
            if (!IsBadReadPtr((void*)(wsnPtr + 0x194), 4))
                wsnSock = *(SOCKET*)(wsnPtr + 0x194);
            if (wsnSock != INVALID_SOCKET && selectLogCount < 50) {
                fd_set rs;
                struct timeval tv = {0, 0};
                int sr;
                FD_ZERO(&rs);
                FD_SET(wsnSock, &rs);
                sr = select(0, &rs, NULL, NULL, &tv);
                if (sr > 0) {
                    selectLogCount++;
                    ProxyLog("  GAMELOOP[%d]: Data on WSN socket BEFORE Update (#%d)",
                             tickCount, selectLogCount);
                }
            }
        }
        TGNETWORK_UPDATE((void*)wsnPtr, NULL);
    }

    /* Check emQ AFTER TGNetwork_Update to see if events were generated */
    {
        static DWORD lastPostEmQ = 0;
        DWORD postEmQ = 0;
        if (!IsBadReadPtr((void*)0x0097F840, 4))
            postEmQ = *(DWORD*)0x0097F840;
        if (postEmQ != lastPostEmQ) {
            ProxyLog("  GAMELOOP[%d]: emQ AFTER TGNetwork_Update: %u (was %u)", tickCount, postEmQ, lastPostEmQ);
            lastPostEmQ = postEmQ;
        }
    }

    /* Monitor player connections, EM queue, and network queues */
    {
        static DWORD lastPendQ = 0, lastInQ = 0;
        int playerCount = 0;
        DWORD emCount = 0;
        DWORD playerArray = 0;
        DWORD pendingQ = 0, incomingQ = 0;
        if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x30), 4))
            playerCount = *(int*)(wsnPtr + 0x30);
        if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x2C), 4))
            playerArray = *(DWORD*)(wsnPtr + 0x2C);
        if (!IsBadReadPtr((void*)0x0097F840, 4))
            emCount = *(DWORD*)0x0097F840;
        if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x38), 4))
            pendingQ = *(DWORD*)(wsnPtr + 0x38);
        if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x54), 4))
            incomingQ = *(DWORD*)(wsnPtr + 0x54);

        if (playerCount != lastPlayerCount) {
            int connState = -1, numPlayers = 0;
            DWORD hostID = 0, localID = 0;
            if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x14), 4))
                connState = *(int*)(wsnPtr + 0x14);
            if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x18), 4))
                hostID = *(DWORD*)(wsnPtr + 0x18);
            if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x1C), 4))
                localID = *(DWORD*)(wsnPtr + 0x1C);
            ProxyLog("  GAMELOOP: *** PLAYERS CHANGED: %d -> %d (tick %d) ***",
                     lastPlayerCount, playerCount, tickCount);
            ProxyLog("    playerArray=0x%08X emQ=%u connState=%d hostID=%u localID=%u",
                     playerArray, emCount, connState, hostID, localID);
            ProxyLog("    pendQ=0x%08X inQ=0x%08X", pendingQ, incomingQ);
            /* Dump checksum-critical state on player change */
            {
                DWORD csm = 0, mpg = 0;
                BYTE mp1F8 = 0, netActive = 0;
                if (!IsBadReadPtr((void*)0x0097fa80, 4))
                    csm = *(DWORD*)0x0097fa80;
                if (!IsBadReadPtr((void*)0x0097e238, 4))
                    mpg = *(DWORD*)0x0097e238;
                if (mpg && !IsBadReadPtr((void*)(mpg + 0x1F8), 1))
                    mp1F8 = *(BYTE*)(mpg + 0x1F8);
                if (!IsBadReadPtr((void*)0x0097fa8a, 1))
                    netActive = *(BYTE*)0x0097fa8a;
                ProxyLog("    CHECKSUM DIAG: csm=0x%08X mpg=0x%08X +0x1F8=%d netActive=%d",
                         csm, mpg, mp1F8, netActive);
                /* Dump settings bytes that go into opcode 0x00 packet */
                {
                    BYTE settings1 = 0, settings2 = 0;
                    if (!IsBadReadPtr((void*)0x008e5f59, 1))
                        settings1 = *(BYTE*)0x008e5f59;
                    if (!IsBadReadPtr((void*)0x0097faa2, 1))
                        settings2 = *(BYTE*)0x0097faa2;
                    ProxyLog("    SETTINGS: DAT_008e5f59=0x%02X DAT_0097faa2=0x%02X",
                             settings1, settings2);
                    /* Dump map name from MPG->+0x70->+0x3c->+0x14 */
                    if (mpg && !IsBadReadPtr((void*)(mpg + 0x70), 4)) {
                        DWORD p70 = *(DWORD*)(mpg + 0x70);
                        if (p70 && !IsBadReadPtr((void*)(p70 + 0x3c), 4)) {
                            DWORD p3c = *(DWORD*)(p70 + 0x3c);
                            if (p3c && !IsBadReadPtr((void*)(p3c + 0x14), 4)) {
                                char* mapName = *(char**)(p3c + 0x14);
                                if (mapName && !IsBadReadPtr(mapName, 1)) {
                                    ProxyLog("    MAP NAME: '%s'", mapName);
                                } else {
                                    ProxyLog("    MAP NAME: (null or bad ptr 0x%08X)", (unsigned)(DWORD_PTR)mapName);
                                }
                            }
                        }
                    }
                }
            }
            /* Dump first peer entry details */
            if (playerCount > 0 && playerArray) {
                DWORD peerPtr = 0;
                if (!IsBadReadPtr((void*)playerArray, 4))
                    peerPtr = *(DWORD*)playerArray;
                if (peerPtr && !IsBadReadPtr((void*)peerPtr, 0xC0)) {
                    DWORD peerID = *(DWORD*)(peerPtr + 0x18);
                    DWORD peerAddr = *(DWORD*)(peerPtr + 0x1C);
                    BYTE peerBC = *(BYTE*)(peerPtr + 0xBC);
                    DWORD peerQ0 = *(DWORD*)(peerPtr + 0x20);
                    DWORD peerQ4 = *(DWORD*)(peerPtr + 0x24);
                    ProxyLog("    PEER[0]: ptr=0x%08X id=%u addr=0x%08X bc=%d q0=0x%08X q4=0x%08X",
                             peerPtr, peerID, peerAddr, peerBC, peerQ0, peerQ4);
                }
            }
            lastPlayerCount = playerCount;
        }
        if (pendingQ != lastPendQ || incomingQ != lastInQ) {
            ProxyLog("  GAMELOOP: Network queues changed (tick %d): pendQ=0x%08X->0x%08X inQ=0x%08X->0x%08X",
                     tickCount, lastPendQ, pendingQ, lastInQ, incomingQ);
            lastPendQ = pendingQ;
            lastInQ = incomingQ;
        }
    }

    /* Periodic status every ~10s */
    if (time - lastLogTime >= 10000) {
        DWORD clockPtr = 0;
        float gameTime = 0.0f;
        int connState = -1;
        DWORD emCount = 0;
        if (!IsBadReadPtr((void*)0x009a09d0, 4))
            clockPtr = *(DWORD*)0x009a09d0;
        if (clockPtr && !IsBadReadPtr((void*)(clockPtr + 0x90), 4))
            gameTime = *(float*)(clockPtr + 0x90);
        if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x14), 4))
            connState = *(int*)(wsnPtr + 0x14);
        if (!IsBadReadPtr((void*)0x0097F840, 4))
            emCount = *(DWORD*)0x0097F840;
        {
            int pCount = 0;
            DWORD pArray = 0;
            if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x30), 4))
                pCount = *(int*)(wsnPtr + 0x30);
            if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x2C), 4))
                pArray = *(DWORD*)(wsnPtr + 0x2C);
            ProxyLog("  GAMELOOP: tick=%d gameTime=%.3f connState=%d emQ=%u peers=%d sendtos=%ld",
                     tickCount, gameTime, connState, emCount, pCount, g_sendtoCount);
            /* Dump peer details if connected */
            if (pCount > 0 && pArray && !IsBadReadPtr((void*)pArray, 4)) {
                int pi2;
                for (pi2 = 0; pi2 < pCount && pi2 < 4; pi2++) {
                    DWORD pp = 0;
                    if (!IsBadReadPtr((void*)(pArray + pi2*4), 4))
                        pp = *(DWORD*)(pArray + pi2*4);
                    if (pp && !IsBadReadPtr((void*)pp, 0xC0)) {
                        ProxyLog("    PEER[%d]: id=%u bc=%d addr=0x%08X sendQ: unrel=%d rel=%d pri=%d",
                                 pi2, *(DWORD*)(pp + 0x18), *(BYTE*)(pp + 0xBC),
                                 *(DWORD*)(pp + 0x1C),
                                 *(int*)(pp + 0x7C), *(int*)(pp + 0x98), *(int*)(pp + 0xB4));
                    }
                }
            }
        }
        lastLogTime = time;
    }
}

/* ================================================================
 * DedicatedServerTimerProc - TIMERPROC that bootstraps the dedicated server
 *
 * Runs on the MAIN THREAD via SetTimer. Phases:
 *   0: Set multiplayer/host flags (direct memory + SWIG via RunPyCode)
 *   1: Initialize network (create WSN) via direct C++ call to FUN_00445d90
 *   2: Create MultiplayerGame (creates TopWindow) via FUN_00504f10
 *   3: Trigger DedicatedServer.TopWindowInitialized via RunPyCode
 *   4: Start game loop timer (GameLoopTimerProc at 33ms)
 * ================================================================ */
static int g_iDedState = 0;

static VOID CALLBACK DedicatedServerTimerProc(HWND hwnd, UINT msg,
                                               UINT_PTR id, DWORD time) {
    static int polls = 0;
    int nestLvl;
    polls++;
    (void)msg; (void)time;

    /* Log Python nesting level for diagnostics */
    nestLvl = *(int*)0x0099EE38;

    switch (g_iDedState) {
    case 0: {
        /* Phase 0: Set multiplayer/host flags
         * Direct memory writes guarantee flags are set even if Python fails.
         * Then try SWIG methods via RunPyCode for any side effects. */
        DWORD oldProt;
        int rc;

        ProxyLog("  DS_TIMER[0]: Setting flags (poll %d, nest=%d)", polls, nestLvl);

        /* Direct memory writes for critical flags */
        VirtualProtect((void*)0x0097FA88, 4, PAGE_READWRITE, &oldProt);
        *(BYTE*)0x0097FA88 = 1;  /* IsHost */
        *(BYTE*)0x0097FA8A = 1;  /* IsMultiplayer */
        VirtualProtect((void*)0x0097FA88, 4, oldProt, &oldProt);

        ProxyLog("  DS_TIMER[0]: Direct flags: IsHost=%d IsMultiplayer=%d",
                 (int)*(BYTE*)0x0097FA88, (int)*(BYTE*)0x0097FA8A);

        /* Also call SWIG methods for any side effects (non-critical) */
        rc = RunPyCode(
            "import App\n"
            "App.g_kUtopiaModule.SetMultiplayer(1)\n"
            "App.g_kUtopiaModule.SetIsHost(1)\n"
            "App.g_kUtopiaModule.SetIsClient(0)\n");
        ProxyLog("  DS_TIMER[0]: SWIG SetFlags rc=%d", rc);

        /* Set config values (game name, player name, password) */
        rc = RunPyCode(
            "try:\n"
            "    import App\n"
            "    App.g_kConfigMapping.SetStringValue(\n"
            "        'Multiplayer Options', 'Game_Name', 'Dedicated Server')\n"
            "    App.g_kConfigMapping.SetStringValue(\n"
            "        'Multiplayer Options', 'Player_Name', 'Server')\n"
            "    App.g_kConfigMapping.SetStringValue(\n"
            "        'Multiplayer Options', 'Password', '')\n"
            "except:\n"
            "    pass\n");
        ProxyLog("  DS_TIMER[0]: Config rc=%d", rc);

        g_iDedState = 1;
        break;
    }
    case 1: {
        /* Phase 1: Initialize network - create WSN (TGWinsockNetwork)
         *
         * FUN_00445d90 is __thiscall:
         *   this = 0x0097FA00 (UtopiaModule)
         *   param_1 = 0 (address, 0 = host/listen)
         *   param_2 = ptr to TGString-like struct for password (length at +8)
         *   param_3 = 0x5655 (port 22101)
         *
         * Use __fastcall trick: ECX=this, EDX=dummy */
        typedef int (__fastcall *pfn_InitNet)(void* ecx, void* edx,
                                               int addr, void* pw, int port);
        pfn_InitNet pInitNet = (pfn_InitNet)0x00445d90;
        int rc;
        DWORD wsnPtr;
        char fakePw[16];

        ProxyLog("  DS_TIMER[1]: Initializing network (poll %d, nest=%d)", polls, nestLvl);
        memset(fakePw, 0, sizeof(fakePw));

        rc = pInitNet((void*)0x0097FA00, NULL, 0, fakePw, 0x5655);

        wsnPtr = 0;
        if (!IsBadReadPtr((void*)0x0097FA78, 4))
            wsnPtr = *(DWORD*)0x0097FA78;

        ProxyLog("  DS_TIMER[1]: InitNet rc=%d WSN=0x%08X", rc, wsnPtr);

        if (wsnPtr != 0) {
            /* Set SkipChecksum flag - tells the server to skip per-file
             * version mismatch checks during checksum verification.
             * Without this, clients with different .pyc versions get
             * "Disconnected: File version mismatch" errors. */
            {
                DWORD oldProt;
                VirtualProtect((void*)0x0097f94c, 1, PAGE_READWRITE, &oldProt);
                *(BYTE*)0x0097f94c = 1;
                VirtualProtect((void*)0x0097f94c, 1, oldProt, &oldProt);
                ProxyLog("  DS_TIMER[1]: Set SkipChecksum flag at 0x0097f94c = 1");
            }
            g_iDedState = 2;
        } else if (polls > 30) {
            ProxyLog("  DS_TIMER[1]: WSN still NULL after 30 polls, giving up");
            g_iDedState = 99;
        }
        break;
    }
    case 2: {
        /* Phase 2: Create MultiplayerGame
         * FUN_00504f10 allocates a MultiplayerGame object and calls
         * FUN_0069e590 (constructor) which calls FUN_00405c10 (TopWindow
         * constructor), setting DAT_0097e238 = game object pointer.
         * It also runs AI_Setup.GameInit and loads Multiplayer.tgl. */
        typedef void (__cdecl *pfn_CreateMPGame)(void);
        pfn_CreateMPGame pCreate = (pfn_CreateMPGame)0x00504f10;
        DWORD twPtr;

        ProxyLog("  DS_TIMER[2]: Creating MultiplayerGame (poll %d, nest=%d)", polls, nestLvl);
        g_phase2Active = 1;
        if (setjmp(g_phase2JmpBuf) == 0) {
            pCreate();
        } else {
            ProxyLog("  DS_TIMER[2]: Recovered from crash via longjmp");
        }
        g_phase2Active = 0;

        twPtr = 0;
        if (!IsBadReadPtr((void*)0x0097e238, 4))
            twPtr = *(DWORD*)0x0097e238;

        ProxyLog("  DS_TIMER[2]: TopWindow=0x%08X", twPtr);


        if (twPtr != 0) {
            g_iDedState = 3;
        } else {
            ProxyLog("  DS_TIMER[2]: TopWindow creation failed");
            g_iDedState = 99;
        }
        break;
    }
    case 3: {
        /* Phase 3: Trigger DedicatedServer automation via Python.
         * App.TopWindow_GetTopWindow() returns the SWIG-wrapped TopWindow. */
        int rc;

        ProxyLog("  DS_TIMER[3]: Triggering automation (poll %d, nest=%d)", polls, nestLvl);

        rc = RunPyCode(
            "import sys\n"
            "try:\n"
            "    import App\n"
            "    tw = App.TopWindow_GetTopWindow()\n"
            "    if tw is not None:\n"
            "        ds = sys.modules['Custom.DedicatedServer']\n"
            "        ds.TopWindowInitialized(tw)\n"
            "        n = ds.PatchLoadedMissionModules()\n"
            "        f = open('dedicated_init.log', 'a')\n"
            "        f.write('DS_TIMER: TopWindowInitialized called OK\\n')\n"
            "        f.write('DS_TIMER: PatchLoadedMissionModules = ' + str(n) + '\\n')\n"
            "        f.close()\n"
            "    else:\n"
            "        f = open('dedicated_init.log', 'a')\n"
            "        f.write('DS_TIMER: TopWindow_GetTopWindow returned None\\n')\n"
            "        f.close()\n"
            "except:\n"
            "    ei = sys.exc_info()\n"
            "    f = open('dedicated_init.log', 'a')\n"
            "    f.write('DS_TIMER Phase3 ERROR: ' + str(ei[0]) + ': ' + str(ei[1]) + '\\n')\n"
            "    f.close()\n");

        ProxyLog("  DS_TIMER[3]: TopWindowInit rc=%d", rc);

        /* Enable GameSpy LAN query handler.
         * GameSpy_StartHeartbeat (0x0069c240) allocates the qr_t struct,
         * stores it at GameSpy+0xDC, and enables LAN browser responses.
         * The qr_t reuses the UDP socket from WSN+0x194.
         * param_1=1 means LAN mode (process queries + send heartbeats). */
        {
            DWORD gsPtr = 0;
            if (!IsBadReadPtr((void*)0x0097FA7C, 4))
                gsPtr = *(DWORD*)0x0097FA7C;
            if (gsPtr) {
                unsigned int gsRc;
                ProxyLog("  DS_TIMER[3]: GameSpy object at 0x%08X, calling StartHeartbeat", gsPtr);
                gsRc = GAMESPY_START_HB((void*)gsPtr, NULL, 1);
                ProxyLog("  DS_TIMER[3]: GameSpy_StartHeartbeat rc=0x%08X", gsRc);

                /* Log GameSpy state after StartHeartbeat */
                if (!IsBadReadPtr((void*)(gsPtr + 0xDC), 4)) {
                    DWORD qrPtr = *(DWORD*)(gsPtr + 0xDC);
                    BYTE initFlag = *(BYTE*)(gsPtr + 0xED);
                    BYTE hbActive = *(BYTE*)(gsPtr + 0xEE);
                    BYTE lanMode = *(BYTE*)(gsPtr + 0xEF);
                    ProxyLog("  DS_TIMER[3]: GameSpy qr_t=0x%08X init=%d hbActive=%d lan=%d",
                             qrPtr, initFlag, hbActive, lanMode);

                    /* Keep qr_t+0xE4=0 (disable GameSpy's internal recvfrom).
                     * Our peek-based router in the game loop handles query/game
                     * packet demuxing on the shared UDP socket instead. */
                    if (qrPtr && !IsBadReadPtr((void*)(qrPtr + 0xE4), 4)) {
                        *(DWORD*)(qrPtr + 0xE4) = 0;
                        ProxyLog("  DS_TIMER[3]: qr_t+0xE4=0 (peek router handles queries)");
                    }
                }
            } else {
                ProxyLog("  DS_TIMER[3]: GameSpy object is NULL, LAN discovery disabled");
            }
        }

        /* Verify socket consistency: qr_t[0] should equal WSN+0x194 */
        {
            DWORD wsnPtr2 = 0, wsnSock = 0xFFFFFFFF, qrSock = 0xFFFFFFFF;
            DWORD gsPtr2 = 0, qrPtr2 = 0;
            if (!IsBadReadPtr((void*)0x0097FA78, 4))
                wsnPtr2 = *(DWORD*)0x0097FA78;
            if (wsnPtr2 && !IsBadReadPtr((void*)(wsnPtr2 + 0x194), 4))
                wsnSock = *(DWORD*)(wsnPtr2 + 0x194);
            if (!IsBadReadPtr((void*)0x0097FA7C, 4))
                gsPtr2 = *(DWORD*)0x0097FA7C;
            if (gsPtr2 && !IsBadReadPtr((void*)(gsPtr2 + 0xDC), 4))
                qrPtr2 = *(DWORD*)(gsPtr2 + 0xDC);
            if (qrPtr2 && !IsBadReadPtr((void*)qrPtr2, 4))
                qrSock = *(DWORD*)qrPtr2;
            ProxyLog("  DS_TIMER[3]: Socket check: WSN+0x194=%d qr_t[0]=%d %s",
                     (int)wsnSock, (int)qrSock,
                     (wsnSock == qrSock) ? "MATCH" : "*** MISMATCH ***");
        }

        /* Set IsClient=0 (DAT_0097fa89) for dedicated server mode.
         * The MultiplayerGame constructor ALWAYS sets IsClient=1 at the end.
         * In vanilla, the config reader at ~0x00438880 reads "Dedicated Server"
         * from config and restores IsClient=0 post-construction. We bypass that
         * code path, so we must set it directly.
         * IsClient=0 tells the engine this is a dedicated server:
         *   - Skips ship selection UI, hides info pane
         *   - Doesn't add host as a player in score tracking
         *   - Changes object creation, warp, physics behavior */
        {
            DWORD oldProt;
            VirtualProtect((void*)0x0097FA89, 1, PAGE_READWRITE, &oldProt);
            *(BYTE*)0x0097FA89 = 0;  /* IsClient = 0 */
            VirtualProtect((void*)0x0097FA89, 1, oldProt, &oldProt);
            ProxyLog("  DS_TIMER[3]: Set IsClient=0 (0x0097FA89) for dedicated server mode");
        }

        /* Set MultiplayerGame+0x1F8 = 1 to enable immediate new player handling.
         * When 0 (default), NewPlayerHandler defers via timer and checksum exchange stalls.
         * When 1, it processes immediately (assigns slot, sends checksum request). */
        {
            DWORD mpGame = 0;
            if (!IsBadReadPtr((void*)0x0097e238, 4))
                mpGame = *(DWORD*)0x0097e238;
            if (mpGame && !IsBadWritePtr((void*)(mpGame + 0x1F8), 1)) {
                *(BYTE*)(mpGame + 0x1F8) = 1;
                ProxyLog("  DS_TIMER[3]: Set MultiplayerGame+0x1F8=1 (enable immediate new player handling)");
            } else {
                ProxyLog("  DS_TIMER[3]: WARNING - Could not set MultiplayerGame+0x1F8 (mpGame=0x%08X)", mpGame);
            }
        }

        /* Diagnose ChecksumManager at 0x0097fa80 - FUN_006a3820 uses this as 'this'.
         * If NULL, no checksum requests will ever be sent to clients. */
        {
            DWORD csm = 0;
            if (!IsBadReadPtr((void*)0x0097fa80, 4))
                csm = *(DWORD*)0x0097fa80;
            ProxyLog("  DS_TIMER[3]: ChecksumManager(0x0097fa80)=0x%08X", csm);
            if (csm) {
                /* Also check 0x0097fa8a (IsMultiplayer/networking-active flag) */
                BYTE netActive = 0;
                if (!IsBadReadPtr((void*)0x0097fa8a, 1))
                    netActive = *(BYTE*)0x0097fa8a;
                ProxyLog("  DS_TIMER[3]: DAT_0097fa8a(netActive)=%d", netActive);
            } else {
                ProxyLog("  DS_TIMER[3]: WARNING - ChecksumManager is NULL! Checksum exchange will fail.");
            }
        }

        /* Ensure the map/mission name chain is valid.
         * ChecksumCompleteHandler (FUN_006a1b10) reads the map name from:
         *   MultiplayerGame+0x70 -> +0x3c -> +0x14 (char*)
         * Game_LoadEpisode + Episode_LoadMission set +0x70 to a real Episode
         * object, but +0x3c->+0x14 may hold a TGString ptr instead of char*.
         * We patch the inner chain to point to our known-good char* string. */
        {
            static const char g_missionName[] = "Multiplayer.Episode.Mission1.Mission1";
            DWORD mpGame = 0;
            if (!IsBadReadPtr((void*)0x0097e238, 4))
                mpGame = *(DWORD*)0x0097e238;
            if (mpGame) {
                DWORD p70 = 0;
                if (!IsBadReadPtr((void*)(mpGame + 0x70), 4))
                    p70 = *(DWORD*)(mpGame + 0x70);

                if (p70 == 0) {
                    /* Episode not loaded - build full fake chain.
                     * objA[0] must be a valid vtable (main tick dispatches through it).
                     * We create a dummy vtable where all entries point to a RET stub. */
                    BYTE *objA = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x80);
                    BYTE *objB = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x20);
                    DWORD *vtbl = (DWORD*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x80);
                    BYTE *retStub = (BYTE*)VirtualAlloc(NULL, 4, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

                    if (objA && objB && vtbl && retStub) {
                        int i;
                        retStub[0] = 0xC3;
                        for (i = 0; i < 32; i++)
                            vtbl[i] = (DWORD)retStub;
                        *(DWORD**)(objA + 0x00) = vtbl;
                        *(BYTE**)(objA + 0x3c) = objB;
                        *(const char**)(objB + 0x14) = g_missionName;
                        {
                            DWORD oldProt;
                            VirtualProtect((void*)(mpGame + 0x70), 4, PAGE_READWRITE, &oldProt);
                            *(BYTE**)(mpGame + 0x70) = objA;
                            VirtualProtect((void*)(mpGame + 0x70), 4, oldProt, &oldProt);
                        }
                        ProxyLog("  DS_TIMER[3]: Installed full fake mission chain: '%s'", g_missionName);
                    } else {
                        ProxyLog("  DS_TIMER[3]: WARNING - Alloc failed for mission chain");
                    }
                } else {
                    /* Episode object exists (from Game_LoadEpisode).
                     * Patch the inner chain: ensure +0x3c->+0x14 has a valid char*.
                     * The real Mission object may store a TGString* at +0x14 instead. */
                    DWORD p3c = 0;
                    if (!IsBadReadPtr((void*)(p70 + 0x3c), 4))
                        p3c = *(DWORD*)(p70 + 0x3c);
                    if (p3c) {
                        /* Patch Mission+0x14 to point to our raw char* string */
                        DWORD oldProt;
                        VirtualProtect((void*)(p3c + 0x14), 4, PAGE_READWRITE, &oldProt);
                        *(const char**)(p3c + 0x14) = g_missionName;
                        VirtualProtect((void*)(p3c + 0x14), 4, oldProt, &oldProt);
                        ProxyLog("  DS_TIMER[3]: Patched Mission+0x14 -> '%s' (p3c=0x%08X)",
                                 g_missionName, p3c);
                    } else {
                        /* Episode+0x3c is NULL - allocate a Mission stub */
                        BYTE *objB = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x20);
                        if (objB) {
                            DWORD oldProt;
                            *(const char**)(objB + 0x14) = g_missionName;
                            VirtualProtect((void*)(p70 + 0x3c), 4, PAGE_READWRITE, &oldProt);
                            *(BYTE**)(p70 + 0x3c) = objB;
                            VirtualProtect((void*)(p70 + 0x3c), 4, oldProt, &oldProt);
                            ProxyLog("  DS_TIMER[3]: Installed Mission stub at Episode+0x3c -> '%s'",
                                     g_missionName);
                        }
                    }
                }
            }
        }

        ProxyLog("  DS_TIMER[3]: Breakpoints DISABLED (were causing crashes)");

        g_iDedState = 4;
        KillTimer(hwnd, id);

        /* Start the game loop timer - drives UtopiaApp_MainTick at ~30fps.
         * This processes network timers, events, and game subsystems.
         * Timer ID 0xBCBC chosen to avoid conflicts. */
        SetTimer(hwnd, 0xBCBC, 33, GameLoopTimerProc);
        ProxyLog("  DS_TIMER: Bootstrap done, game loop timer started (33ms)");
        break;
    }
    default:
        KillTimer(hwnd, id);
        ProxyLog("  DS_TIMER: Terminated in state %d", g_iDedState);
        break;
    }
}

/* This callback runs from the code cave on the MAIN thread during init.
   It creates the App module before TG_ImportModule("App") runs. */
static void __cdecl CreateAppModuleCallback(void) {
    void* appModule;

    ProxyLog("  CreateAppModuleCallback: ENTERED");

    if (PY_ErrOccurred()) {
        ProxyLog("  CreateAppModuleCallback: clearing pre-existing error");
        PY_ErrClear();
    }

    appModule = PY_InitModule4("App", (void*)0x008e6438, NULL, NULL, 1009);
    ProxyLog("  CreateAppModuleCallback: Py_InitModule4('App') = %p", appModule);

    if (PY_ErrOccurred()) {
        ProxyLog("  CreateAppModuleCallback: ERROR after Py_InitModule4");
        PY_ErrClear();
    }

    LogPyModules("PRE-INIT modules");

    ProxyLog("  CreateAppModuleCallback: DONE");
}

/* This callback runs AFTER TG_ImportModule("Autoexec") completes.
   We hook 0x0043b204 (the PyErr_Print after Autoexec import).
   At this point, Autoexec.py should have loaded Local.py and DedicatedServer.py. */
static void __cdecl PostAutoexecCallback(void) {
    void* localMod;
    int rc;

    ProxyLog("  PostAutoexecCallback: ENTERED");
    LogPyModules("POST-AUTOEXEC");

    /* Autoexec.py fails partway through in stub mode (Tactical.TacticalIcons,
       UITheme, LoadInterface need rendering). The "try: import Local" at line 38
       never executes. We manually import Local here to start DedicatedServer. */

    /* First clear any error left from Autoexec's failed imports */
    if (PY_ErrOccurred()) {
        ProxyLog("  PostAutoexecCallback: clearing Autoexec errors");
        PY_ErrClear();
    }

    /* Import Local.py directly via C API */
    localMod = PY_ImportModule("Local");
    ProxyLog("  PostAutoexecCallback: import Local = %p", localMod);

    if (PY_ErrOccurred()) {
        ProxyLog("  PostAutoexecCallback: Local import had errors");
        PY_ErrPrint();
    }

    LogPyModules("POST-LOCAL");

    /* Also try running the remaining Autoexec setup that was skipped */
    rc = PY_RunSimpleString(
        "try:\n"
        "    import UITheme\n"
        "except:\n"
        "    pass\n"
        "try:\n"
        "    import LoadInterface\n"
        "    LoadInterface.SetupColors()\n"
        "except:\n"
        "    pass\n"
        "try:\n"
        "    import KeyboardBinding\n"
        "except:\n"
        "    pass\n");
    ProxyLog("  PostAutoexecCallback: remaining imports rc=%d", rc);
    if (PY_ErrOccurred()) PY_ErrClear();

    /* Schedule a timer on the main thread to bootstrap the dedicated server.
       TopWindow.Initialize is never called in stub mode because TopWindow/Game
       objects only exist when a multiplayer game starts (FUN_00405c10 sets
       DAT_0097e238). We use a timer to:
       1. Set multiplayer/host flags
       2. Initialize the network (create WSN)
       3. Create the MultiplayerGame (which creates TopWindow)
       4. Trigger DedicatedServer.TopWindowInitialized via Python */
    if (g_hGameWindow) {
        SetTimer(g_hGameWindow, 42 /*DEDICATED_TIMER_ID*/, 500,
                 DedicatedServerTimerProc);
        ProxyLog("  PostAutoexecCallback: Scheduled DedicatedServerTimer (500ms)");
    } else {
        ProxyLog("  PostAutoexecCallback: WARNING - no game window for timer!");
    }

    ProxyLog("  PostAutoexecCallback: DONE");
}

static void PatchCreateAppModule(void) {
    BYTE* pTarget = (BYTE*)0x0043b1b9;
    BYTE* cave;
    DWORD oldProt;
    LONG jmpOffset;
    int c;

    /* Verify original bytes: 53 68 80 9C 8D 00 */
    if (IsBadReadPtr(pTarget, 6)) {
        ProxyLog("  PatchCreateAppModule: address not readable");
        return;
    }
    if (pTarget[0] != 0x53 || pTarget[1] != 0x68) {
        ProxyLog("  PatchCreateAppModule: unexpected bytes %02X %02X (expected 53 68), skipped",
                 pTarget[0], pTarget[1]);
        return;
    }

    cave = (BYTE*)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE);
    if (!cave) {
        ProxyLog("  PatchCreateAppModule: VirtualAlloc failed");
        return;
    }

    c = 0;
    /* PUSHAD - save all registers */
    cave[c++] = 0x60;

    /* CALL CreateAppModuleCallback (our C function, __cdecl, no args) */
    cave[c++] = 0xE8;
    jmpOffset = (LONG)((BYTE*)CreateAppModuleCallback - (cave + c + 4));
    memcpy(cave + c, &jmpOffset, 4); c += 4;

    /* POPAD - restore all registers */
    cave[c++] = 0x61;

    /* Reproduce original instructions */
    cave[c++] = 0x53; /* PUSH EBX (original param2 = 0) */
    cave[c++] = 0x68; /* PUSH 0x008d9c80 (original param1 = "App") */
    *(DWORD*)(cave + c) = 0x008d9c80; c += 4;

    /* JMP back to 0x0043b1bf (the CALL TG_ImportModule instruction) */
    cave[c++] = 0xE9;
    jmpOffset = (LONG)(0x0043b1bf - (DWORD)(cave + c + 4));
    *(LONG*)(cave + c) = jmpOffset; c += 4;

    ProxyLog("  PatchCreateAppModule: cave at %p (%d bytes)", cave, c);

    /* Patch the original code: JMP to cave + NOP */
    VirtualProtect(pTarget, 6, PAGE_EXECUTE_READWRITE, &oldProt);
    pTarget[0] = 0xE9;
    jmpOffset = (LONG)((DWORD)cave - (DWORD)(pTarget + 5));
    memcpy(pTarget + 1, &jmpOffset, 4);
    pTarget[5] = 0x90;
    VirtualProtect(pTarget, 6, oldProt, &oldProt);

    ProxyLog("  PatchCreateAppModule: patched 0x0043B1B9 -> JMP %p (create App module)", cave);

    /* Also hook AFTER TG_ImportModule("Autoexec") to check what loaded.
     * At 0x0043b204: CALL 0x0074af10 (PyErr_Print) - 5 bytes
     * We replace with CALL PostAutoexecCave which calls PostAutoexecCallback
     * then does the original PyErr_Print call and continues. */
    {
        BYTE* pPost = (BYTE*)0x0043b204;
        BYTE* cave2;
        DWORD oldProt2;
        int c2 = 0;

        if (!IsBadReadPtr(pPost, 5) && pPost[0] == 0xE8) {
            cave2 = cave + 256; /* reuse same page, offset 256 */

            /* PUSHAD */
            cave2[c2++] = 0x60;
            /* CALL PostAutoexecCallback */
            cave2[c2++] = 0xE8;
            jmpOffset = (LONG)((BYTE*)PostAutoexecCallback - (cave2 + c2 + 4));
            memcpy(cave2 + c2, &jmpOffset, 4); c2 += 4;
            /* POPAD */
            cave2[c2++] = 0x61;
            /* Original: CALL PyErr_Print (0x0074af10) */
            cave2[c2++] = 0xE8;
            jmpOffset = (LONG)(0x0074af10 - (DWORD)(cave2 + c2 + 4));
            memcpy(cave2 + c2, &jmpOffset, 4); c2 += 4;
            /* JMP back to 0x0043b209 (instruction after the original CALL) */
            cave2[c2++] = 0xE9;
            jmpOffset = (LONG)(0x0043b209 - (DWORD)(cave2 + c2 + 4));
            memcpy(cave2 + c2, &jmpOffset, 4); c2 += 4;

            VirtualProtect(pPost, 5, PAGE_EXECUTE_READWRITE, &oldProt2);
            pPost[0] = 0xE9;
            jmpOffset = (LONG)((DWORD)cave2 - (DWORD)(pPost + 5));
            memcpy(pPost + 1, &jmpOffset, 4);
            VirtualProtect(pPost, 5, oldProt2, &oldProt2);

            ProxyLog("  PatchCreateAppModule: post-Autoexec hook at 0x0043B204 -> cave2 %p (%d bytes)", cave2, c2);
        } else {
            ProxyLog("  PatchCreateAppModule: post-Autoexec hook SKIPPED (unexpected bytes at 0x0043b204)");
        }
    }
}

/* ================================================================
 * PatchPyFatalError - Make Py_FatalError return instead of aborting
 *
 * Py_FatalError (0x0074b9e0) ends with JMP 0x0085a108 (tail call to
 * abort). ALL abort xrefs in the binary are JMP tail calls, so our
 * abort hook's RET pops garbage (saved registers, not return addr).
 *
 * Fix: Replace the JMP at 0x0074ba10 with POP EDI; POP ESI; RET
 * which properly unwinds the function prologue (PUSH ESI; PUSH EDI)
 * and returns to the caller. This lets init continue after errors
 * like missing modules (cPickle's copy_reg, etc).
 * ================================================================ */
static void PatchPyFatalError(void) {
    BYTE* pJmp = (BYTE*)0x0074ba10;
    DWORD oldProt;

    if (IsBadReadPtr(pJmp, 5)) {
        ProxyLog("  PatchPyFatalError: address not readable");
        return;
    }
    /* Verify it's a JMP (E9 xx xx xx xx) */
    if (pJmp[0] != 0xE9) {
        ProxyLog("  PatchPyFatalError: unexpected byte %02X (expected E9), skipped",
                 pJmp[0]);
        return;
    }

    VirtualProtect(pJmp, 5, PAGE_EXECUTE_READWRITE, &oldProt);
    pJmp[0] = 0x5F; /* POP EDI */
    pJmp[1] = 0x5E; /* POP ESI */
    pJmp[2] = 0xC3; /* RET     */
    pJmp[3] = 0x90; /* NOP     */
    pJmp[4] = 0x90; /* NOP     */
    VirtualProtect(pJmp, 5, oldProt, &oldProt);
    ProxyLog("  PatchPyFatalError: patched 0x0074ba10 JMP->abort to POP EDI; POP ESI; RET");
}

/* ================================================================
 * PatchNullGlobals - Write dummy pointer to known NULL globals
 *
 * [0x009878CC] = scene/render manager singleton - NULL in stub mode.
 * Writing the dummy buffer address prevents cascading NULL derefs.
 * ================================================================ */
static volatile LONG g_bNullGlobalsPatched = 0;

static void PatchNullGlobals(void) {
    DWORD* pGlobal;
    DWORD oldProt;

    if (!g_pNullDummy) return;
    if (InterlockedExchange(&g_bNullGlobalsPatched, 1)) return;

    pGlobal = (DWORD*)0x009878CC;
    if (!IsBadReadPtr(pGlobal, 4) && *pGlobal == 0) {
        VirtualProtect(pGlobal, 4, PAGE_READWRITE, &oldProt);
        *pGlobal = (DWORD)g_pNullDummy;
        VirtualProtect(pGlobal, 4, oldProt, &oldProt);
        ProxyLog("  PatchNullGlobals: [0x009878CC] = dummy (0x%08X)",
                 (unsigned)(DWORD)g_pNullDummy);
    }

    /* Pre-fill DAT_009a12a4 (cached DirectDrawCreateEx function pointer).
       FUN_007c7f80 checks: if (DAT_009a12a4 != NULL) skip GetModuleHandle/GetProcAddress.
       By setting this to OUR DirectDrawCreateEx, the game calls us directly
       and bypasses apphelp.dll's shim (which crashes with proxy DDraw objects).
       The adapter enumeration via FUN_007c8eb0 still runs normally through our
       DirectDrawEnumerateExA export, populating DAT_009a1298/129c/12a0. */
    {
        DWORD* pDDCreateExCache = (DWORD*)0x009A12A4;
        if (!IsBadReadPtr(pDDCreateExCache, 4) && *pDDCreateExCache == 0) {
            HMODULE hSelf = GetModuleHandleA("ddraw.dll");
            FARPROC pfn = GetProcAddress(hSelf, "DirectDrawCreateEx");
            if (pfn) {
                VirtualProtect(pDDCreateExCache, 4, PAGE_READWRITE, &oldProt);
                *pDDCreateExCache = (DWORD)pfn;
                VirtualProtect(pDDCreateExCache, 4, oldProt, &oldProt);
                ProxyLog("  PatchNullGlobals: [0x009A12A4] = DirectDrawCreateEx (0x%08X)",
                         (unsigned)(DWORD)pfn);
            }
        }
    }
}

/* ================================================================
 * SIGABRT handler
 * ================================================================ */
static void __cdecl SigAbrtHandler(int sig) {
    DWORD* ebp;
    int i;
    (void)sig;
    ProxyLog("!!! SIGABRT caught - abort() was called!");
    __asm__("movl %%ebp, %0" : "=r" (ebp));
    ProxyLog("  Call stack:");
    for (i = 0; i < 20 && ebp && !IsBadReadPtr(ebp, 8); i++) {
        DWORD retAddr = ebp[1];
        ProxyLog("    [%d] 0x%08X", i, retAddr);
        ebp = (DWORD*)ebp[0];
        if ((DWORD)ebp < 0x10000 || (DWORD)ebp > 0x7FFFFFFF) break;
    }
}

/* ================================================================
 * ExitProcess hook - captures stack trace when game exits
 * ================================================================ */
typedef void (WINAPI *PFN_ExitProcess)(UINT uExitCode);
static PFN_ExitProcess g_pfnOrigExitProcess = NULL;

static void WINAPI HookedExitProcess(UINT uExitCode) {
    DWORD* ebp;
    int i;
    char buf[256];
    ProxyLog("!!! ExitProcess called with code %u (0x%08X)", uExitCode, uExitCode);
    __asm__("movl %%ebp, %0" : "=r" (ebp));
    ProxyLog("  EBP chain walk:");
    for (i = 0; i < 15 && ebp && !IsBadReadPtr(ebp, 8); i++) {
        DWORD retAddr = ebp[1];
        ResolveAddr(retAddr, buf, sizeof(buf));
        ProxyLog("    [%d] %s", i, buf);
        ebp = (DWORD*)ebp[0];
        if ((DWORD)ebp < 0x10000 || (DWORD)ebp > 0x7FFFFFFF) break;
    }
    if (g_pfnOrigExitProcess) g_pfnOrigExitProcess(uExitCode);
    TerminateProcess(GetCurrentProcess(), uExitCode);
}

/* ================================================================
 * MessageBoxA hooks - suppress CRT abort dialogs
 * ================================================================ */
typedef int (WINAPI *PFN_MessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
static PFN_MessageBoxA g_pfnOrigMessageBoxA = NULL;

static int WINAPI HookedMessageBoxA(HWND hwnd, LPCSTR text, LPCSTR caption, UINT type) {
    ProxyLog("!!! MessageBoxA intercepted: caption='%s' text='%s'",
             caption ? caption : "(null)", text ? text : "(null)");
    if (caption && (strstr(caption, "Runtime") || strstr(caption, "Visual C++"))) {
        ProxyLog("  -> Auto-dismissed (returning IDOK)");
        return IDOK;
    }
    if (g_pfnOrigMessageBoxA) return g_pfnOrigMessageBoxA(hwnd, text, caption, type);
    return IDOK;
}

static int WINAPI InlineHookedMBA(HWND hwnd, LPCSTR text, LPCSTR caption, UINT type) {
    ProxyLog("!!! MessageBoxA (INLINE HOOK): caption='%s'",
             caption ? caption : "(null)");
    if (text) {
        const char* p = text;
        while (*p) {
            char chunk[512];
            int len = 0;
            while (*p && len < 500) chunk[len++] = *p++;
            chunk[len] = '\0';
            ProxyLog("    text: %s", chunk);
        }
    }
    return IDOK;
}

static void InlineHookMessageBoxA(void) {
    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    BYTE* fn;
    DWORD oldProt;
    LONG offset;

    if (!hUser32) hUser32 = LoadLibraryA("user32.dll");
    if (!hUser32) return;
    fn = (BYTE*)GetProcAddress(hUser32, "MessageBoxA");
    if (!fn) return;

    if (!VirtualProtect(fn, 5, PAGE_EXECUTE_READWRITE, &oldProt)) return;
    fn[0] = 0xE9;
    offset = (LONG)((BYTE*)InlineHookedMBA - (fn + 5));
    memcpy(fn + 1, &offset, 4);
    VirtualProtect(fn, 5, oldProt, &oldProt);
    ProxyLog("  Inline-hooked MessageBoxA -> %p", InlineHookedMBA);
}

/* ================================================================
 * IAT patching
 * ================================================================ */
static int PatchIATEntry(FARPROC origFn, FARPROC newFn, const char* name) {
    HMODULE hExe = GetModuleHandleA(NULL);
    BYTE* pBase = (BYTE*)hExe;
    IMAGE_DOS_HEADER* pDOS = (IMAGE_DOS_HEADER*)pBase;
    IMAGE_NT_HEADERS* pNT;
    IMAGE_IMPORT_DESCRIPTOR* pImport;
    DWORD importRVA;

    if (pDOS->e_magic != 0x5A4D) return 0;
    pNT = (IMAGE_NT_HEADERS*)(pBase + pDOS->e_lfanew);
    importRVA = pNT->OptionalHeader.DataDirectory[1].VirtualAddress;
    if (!importRVA) return 0;
    pImport = (IMAGE_IMPORT_DESCRIPTOR*)(pBase + importRVA);

    while (pImport->Name) {
        IMAGE_THUNK_DATA* pThunk = (IMAGE_THUNK_DATA*)(pBase + pImport->FirstThunk);
        while (pThunk->u1.Function) {
            if ((FARPROC)pThunk->u1.Function == origFn) {
                DWORD oldProt;
                VirtualProtect(&pThunk->u1.Function, sizeof(FARPROC),
                               PAGE_READWRITE, &oldProt);
                pThunk->u1.Function = (DWORD)newFn;
                VirtualProtect(&pThunk->u1.Function, sizeof(FARPROC),
                               oldProt, &oldProt);
                ProxyLog("  IAT: Hooked %s", name);
                return 1;
            }
            pThunk++;
        }
        pImport++;
    }
    return 0;
}

static void HookGameIAT(void) {
    FARPROC pfnEP = (FARPROC)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitProcess");
    FARPROC pfnMBA = (FARPROC)GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxA");
    FARPROC pfnST = NULL;
    HMODULE hWs2 = GetModuleHandleA("ws2_32.dll");
    HMODULE hWsock = GetModuleHandleA("wsock32.dll");

    if (pfnEP) {
        g_pfnOrigExitProcess = (PFN_ExitProcess)pfnEP;
        PatchIATEntry(pfnEP, (FARPROC)HookedExitProcess, "ExitProcess");
    }
    if (pfnMBA) {
        g_pfnOrigMessageBoxA = (PFN_MessageBoxA)pfnMBA;
        PatchIATEntry(pfnMBA, (FARPROC)HookedMessageBoxA, "MessageBoxA");
    }
    /* Hook sendto to monitor all outbound UDP traffic */
    if (hWs2)
        pfnST = (FARPROC)GetProcAddress(hWs2, "sendto");
    if (!pfnST && hWsock)
        pfnST = (FARPROC)GetProcAddress(hWsock, "sendto");
    if (pfnST) {
        g_pfnOrigSendto = (PFN_sendto)pfnST;
        if (!PatchIATEntry(pfnST, (FARPROC)HookedSendto, "sendto")) {
            ProxyLog("  IAT: sendto not in IAT, trying wsock32");
            /* Try the other DLL's sendto in case IAT uses a different one */
            if (hWsock) {
                FARPROC pfnST2 = (FARPROC)GetProcAddress(hWsock, "sendto");
                if (pfnST2 && pfnST2 != pfnST) {
                    g_pfnOrigSendto = (PFN_sendto)pfnST2;
                    PatchIATEntry(pfnST2, (FARPROC)HookedSendto, "sendto(wsock32)");
                }
            }
        }
    }
    /* Hook recvfrom to monitor all inbound UDP traffic */
    {
        FARPROC pfnRF = NULL;
        if (hWs2)
            pfnRF = (FARPROC)GetProcAddress(hWs2, "recvfrom");
        if (!pfnRF && hWsock)
            pfnRF = (FARPROC)GetProcAddress(hWsock, "recvfrom");
        if (pfnRF) {
            g_pfnOrigRecvfrom = (PFN_recvfrom)pfnRF;
            if (!PatchIATEntry(pfnRF, (FARPROC)HookedRecvfrom, "recvfrom")) {
                if (hWsock) {
                    FARPROC pfnRF2 = (FARPROC)GetProcAddress(hWsock, "recvfrom");
                    if (pfnRF2 && pfnRF2 != pfnRF) {
                        g_pfnOrigRecvfrom = (PFN_recvfrom)pfnRF2;
                        PatchIATEntry(pfnRF2, (FARPROC)HookedRecvfrom, "recvfrom(wsock32)");
                    }
                }
            }
        }
    }
}

/* ================================================================
 * Globals
 * ================================================================ */
BOOL           g_bStubMode = FALSE;
HWND           g_hGameWindow = NULL;
static HMODULE g_hRealDDraw = NULL;
static FILE*   g_pLog = NULL;
char           g_szBasePath[MAX_PATH] = {0};
char           g_szDeviceName[512] = "BC Dedicated Server";

/* Real DDraw function pointers (for forward mode) */
typedef HRESULT (WINAPI *PFN_DirectDrawCreate)(GUID*, void**, void*);
typedef HRESULT (WINAPI *PFN_DirectDrawCreateEx)(GUID*, void**, const GUID*, void*);
typedef HRESULT (WINAPI *PFN_DirectDrawEnumerateA)(void*, void*);
typedef HRESULT (WINAPI *PFN_DirectDrawEnumerateExA)(void*, void*, DWORD);
static PFN_DirectDrawCreate      g_pfnDDCreate = NULL;
static PFN_DirectDrawCreateEx    g_pfnDDCreateEx = NULL;
static PFN_DirectDrawEnumerateA  g_pfnDDEnumA = NULL;
static PFN_DirectDrawEnumerateExA g_pfnDDEnumExA = NULL;

/* Forwarded function pointers */
FARPROC g_pfnAcquireDDThreadLock = NULL;
FARPROC g_pfnReleaseDDThreadLock = NULL;
FARPROC g_pfnCompleteCreateSysmemSurface = NULL;
FARPROC g_pfnD3DParseUnknownCommand = NULL;
FARPROC g_pfnDDGetAttachedSurfaceLcl = NULL;
FARPROC g_pfnDDInternalLock = NULL;
FARPROC g_pfnDDInternalUnlock = NULL;
FARPROC g_pfnDSoundHelp = NULL;
FARPROC g_pfnDirectDrawCreateClipper = NULL;
FARPROC g_pfnGetDDSurfaceLocal = NULL;
FARPROC g_pfnGetOLEThunkData = NULL;
FARPROC g_pfnGetSurfaceFromDC = NULL;
FARPROC g_pfnRegisterSpecialCase = NULL;
FARPROC g_pfnSetAppCompatData = NULL;

/* External vtables (defined in other .c files) */
extern void* g_DDraw7Vtbl[];
extern void* g_Surface7Vtbl[];
extern void* g_D3D7Vtbl[];
extern void* g_Device7Vtbl[];
extern void* g_VB7Vtbl[];

static void* g_ClipperVtbl[9];

/* ================================================================
 * Logging
 * ================================================================ */
void ProxyLog(const char* fmt, ...) {
    if (!g_pLog) return;
    {
        va_list ap;
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(g_pLog, "[%02d:%02d:%02d.%03d] ",
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        va_start(ap, fmt);
        vfprintf(g_pLog, fmt, ap);
        va_end(ap);
        fprintf(g_pLog, "\n");
        fflush(g_pLog);
    }
}

/* ================================================================
 * IDirectDrawClipper stub
 * ================================================================ */
static HRESULT WINAPI Clip_QueryInterface(ProxyClipper* This, const GUID* riid, void** ppv) {
    *ppv = This; This->refCount++; return S_OK;
}
static ULONG WINAPI Clip_AddRef(ProxyClipper* This) { return ++This->refCount; }
static ULONG WINAPI Clip_Release(ProxyClipper* This) {
    if (--This->refCount <= 0) { HeapFree(GetProcessHeap(), 0, This); return 0; }
    return This->refCount;
}
static HRESULT WINAPI Clip_GetClipList(ProxyClipper* This, RECT* r, void* rd, DWORD* s) {
    (void)This; (void)r; (void)rd; (void)s; return DDERR_GENERIC;
}
static HRESULT WINAPI Clip_GetHWnd(ProxyClipper* This, HWND* phwnd) {
    *phwnd = This->hwnd; return DD_OK;
}
static HRESULT WINAPI Clip_Initialize(ProxyClipper* This, void* pDD, DWORD flags) {
    (void)This; (void)pDD; (void)flags; return DD_OK;
}
static HRESULT WINAPI Clip_IsClipListChanged(ProxyClipper* This, BOOL* changed) {
    (void)This; *changed = FALSE; return DD_OK;
}
static HRESULT WINAPI Clip_SetClipList(ProxyClipper* This, void* rd, DWORD flags) {
    (void)This; (void)rd; (void)flags; return DD_OK;
}
static HRESULT WINAPI Clip_SetHWnd(ProxyClipper* This, DWORD flags, HWND hwnd) {
    (void)flags; This->hwnd = hwnd; return DD_OK;
}

ProxyClipper* CreateProxyClipper(void) {
    ProxyClipper* p = (ProxyClipper*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*p));
    if (!p) return NULL;
    g_ClipperVtbl[0] = Clip_QueryInterface;
    g_ClipperVtbl[1] = Clip_AddRef;
    g_ClipperVtbl[2] = Clip_Release;
    g_ClipperVtbl[3] = Clip_GetClipList;
    g_ClipperVtbl[4] = Clip_GetHWnd;
    g_ClipperVtbl[5] = Clip_Initialize;
    g_ClipperVtbl[6] = Clip_IsClipListChanged;
    g_ClipperVtbl[7] = Clip_SetClipList;
    g_ClipperVtbl[8] = Clip_SetHWnd;
    p->lpVtbl = g_ClipperVtbl;
    p->refCount = 1;
    return p;
}

/* ================================================================
 * Factory functions for proxy objects
 * ================================================================ */

ProxyDDraw7* CreateProxyDDraw7(void) {
    ProxyDDraw7* p = (ProxyDDraw7*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*p));
    if (!p) return NULL;
    p->lpVtbl = g_DDraw7Vtbl;
    p->refCount = 1;
    p->displayWidth = 1024;
    p->displayHeight = 768;
    p->displayBpp = 16;
    ProxyLog("CreateProxyDDraw7: %p", p);
    return p;
}

ProxySurface7* CreateProxySurface7(DWORD width, DWORD height, DWORD bpp, DWORD caps) {
    ProxySurface7* p = (ProxySurface7*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*p));
    if (!p) return NULL;
    p->lpVtbl = g_Surface7Vtbl;
    p->refCount = 1;
    p->width = width ? width : 1;
    p->height = height ? height : 1;
    p->bpp = bpp ? bpp : 16;
    p->caps = caps;
    p->pitch = (LONG)(p->width * (p->bpp / 8));
    if (p->pitch < 4) p->pitch = 4;
    p->pixelDataSize = (DWORD)(p->pitch * p->height);
    p->pixelData = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, p->pixelDataSize);
    if (p->bpp == 16)
        SetPixelFormat565(&p->pixelFormat);
    else if (p->bpp == 32)
        SetPixelFormat8888(&p->pixelFormat);
    else
        SetPixelFormat565(&p->pixelFormat);
    return p;
}

ProxyD3D7* CreateProxyD3D7(ProxyDDraw7* parent) {
    ProxyD3D7* p = (ProxyD3D7*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*p));
    if (!p) return NULL;
    p->lpVtbl = g_D3D7Vtbl;
    p->refCount = 1;
    p->parent = parent;
    ProxyLog("CreateProxyD3D7: %p (parent=%p)", p, parent);
    return p;
}

ProxyDevice7* CreateProxyDevice7(ProxySurface7* renderTarget) {
    ProxyDevice7* p = (ProxyDevice7*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*p));
    if (!p) return NULL;
    p->lpVtbl = g_Device7Vtbl;
    p->refCount = 1;
    p->renderTarget = renderTarget;
    ProxyLog("CreateProxyDevice7: %p (target=%p)", p, renderTarget);
    return p;
}

ProxyVB7* CreateProxyVB7(DWORD fvf, DWORD numVertices) {
    ProxyVB7* p = (ProxyVB7*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*p));
    DWORD vertexSize = 0;
    if (!p) return NULL;
    p->lpVtbl = g_VB7Vtbl;
    p->refCount = 1;
    p->fvf = fvf;
    p->numVertices = numVertices ? numVertices : 1;
    /* Calculate vertex size from FVF flags */
    if (fvf & 0x002) vertexSize += 12;  /* D3DFVF_XYZ */
    if (fvf & 0x004) vertexSize += 16;  /* D3DFVF_XYZRHW */
    if (fvf & 0x010) vertexSize += 12;  /* D3DFVF_NORMAL */
    if (fvf & 0x040) vertexSize += 4;   /* D3DFVF_DIFFUSE */
    if (fvf & 0x080) vertexSize += 4;   /* D3DFVF_SPECULAR */
    vertexSize += ((fvf >> 8) & 0xF) * 8; /* Texture coordinate sets */
    if (vertexSize == 0) vertexSize = 32;
    p->dataSize = vertexSize * p->numVertices;
    p->data = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, p->dataSize);
    return p;
}

/* ================================================================
 * Parse GPU device name from Options.cfg
 * ================================================================ */
static void ParseDeviceNameFromConfig(void) {
    char cfgPath[MAX_PATH];
    char cfgBuf[4096];
    DWORD bytesRead = 0;
    HANDLE hFile;

    lstrcpynA(cfgPath, g_szBasePath, MAX_PATH);
    lstrcatA(cfgPath, "Options.cfg");
    hFile = CreateFileA(cfgPath, GENERIC_READ, FILE_SHARE_READ,
                         NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        ProxyLog("  Options.cfg not found, using default device name");
        return;
    }

    ReadFile(hFile, cfgBuf, sizeof(cfgBuf) - 1, &bytesRead, NULL);
    CloseHandle(hFile);

    if (bytesRead > 0) {
        char *found, *val, *eol, *onPos;
        DWORD i;
        for (i = 0; i < bytesRead; i++) {
            if (cfgBuf[i] == '\0') cfgBuf[i] = ' ';
        }
        cfgBuf[bytesRead] = '\0';

        found = strstr(cfgBuf, "Display Device=");
        if (!found) found = strstr(cfgBuf, "Display Device-");
        if (found) {
            val = found;
            while (*val && *val != '=' && *val != '-') val++;
            if (*val) val++;
            eol = val;
            while (*eol && *eol != '\r' && *eol != '\n') eol++;
            ProxyLog("  Options.cfg Display Device: '%.*s'", (int)(eol - val), val);
            onPos = strstr(val, " on ");
            if (onPos && onPos < eol) {
                char *gpuName = onPos + 4;
                int len = (int)(eol - gpuName);
                if (len > 0 && len < (int)sizeof(g_szDeviceName)) {
                    memcpy(g_szDeviceName, gpuName, len);
                    g_szDeviceName[len] = '\0';
                }
            } else {
                int len = (int)(eol - val);
                if (len > 0 && len < (int)sizeof(g_szDeviceName)) {
                    memcpy(g_szDeviceName, val, len);
                    g_szDeviceName[len] = '\0';
                }
            }
        }
    }
    ProxyLog("  Device name: '%s'", g_szDeviceName);
}

/* ================================================================
 * Utilities
 * ================================================================ */
static HANDLE g_hMainThread = NULL;
static DWORD g_dwMainThreadId = 0;

static void ResolveAddr(DWORD addr, char* out, int outLen) {
    MEMORY_BASIC_INFORMATION mbi;
    char modName[MAX_PATH];
    if (VirtualQuery((void*)addr, &mbi, sizeof(mbi)) && mbi.AllocationBase) {
        if (GetModuleFileNameA((HMODULE)mbi.AllocationBase, modName, MAX_PATH)) {
            char* slash = modName;
            char* p;
            for (p = modName; *p; p++)
                if (*p == '\\' || *p == '/') slash = p + 1;
            wsprintfA(out, "0x%08X [%s+0x%X]", addr, slash,
                      addr - (DWORD)mbi.AllocationBase);
            return;
        }
    }
    wsprintfA(out, "0x%08X", addr);
}

/* Find and auto-dismiss CRT abort dialogs */
static BOOL CALLBACK FindAbortDialog(HWND hwnd, LPARAM lParam) {
    char cls[64] = {0};
    char title[256] = {0};
    (void)lParam;
    GetClassNameA(hwnd, cls, sizeof(cls));
    if (lstrcmpA(cls, "#32770") == 0) {
        GetWindowTextA(hwnd, title, sizeof(title));
        if (strstr(title, "Runtime") || strstr(title, "Error") ||
            strstr(title, "Visual C++") || strstr(title, "Assert")) {
            ProxyLog("  AUTO-DISMISS: Found error dialog '%s'", title);
            {
                HWND child = GetWindow(hwnd, GW_CHILD);
                while (child) {
                    char childText[2048] = {0};
                    if (GetWindowTextA(child, childText, sizeof(childText)) > 0)
                        ProxyLog("  AUTO-DISMISS: '%s'", childText);
                    child = GetWindow(child, GW_HWNDNEXT);
                }
            }
            {
                HWND btn = FindWindowExA(hwnd, NULL, "Button", "OK");
                if (!btn) btn = FindWindowExA(hwnd, NULL, "Button", "&OK");
                if (btn)
                    PostMessageA(hwnd, WM_COMMAND, MAKEWPARAM(GetDlgCtrlID(btn), BN_CLICKED), (LPARAM)btn);
                else
                    PostMessageA(hwnd, WM_CLOSE, 0, 0);
            }
        }
    }
    return TRUE;
}

/* ================================================================
 * Heartbeat thread - periodic logging, dialog dismissal, timer setup
 *
 * Sets up a 16ms WM_TIMER on the game window to keep the message
 * pump running even when the game has nothing to render.
 * ================================================================ */
static DWORD WINAPI HeartbeatThread(LPVOID param) {
    DWORD count = 0;
    BOOL timerSet = FALSE;
    int i;
    (void)param;

    /* For the first 30 seconds, check every 500ms for error dialogs */
    for (i = 0; i < 60; i++) {
        Sleep(500);
        EnumThreadWindows(g_dwMainThreadId, FindAbortDialog, 0);
        /* Check game state at 5s and 15s */
        if (i == 10 || i == 30) {
            DWORD pyInit = 0, wsnPtr = 0;
            if (!IsBadReadPtr((void*)0x0099EE34, 4))
                pyInit = *(DWORD*)0x0099EE34;
            if (!IsBadReadPtr((void*)0x0097FA78, 4))
                wsnPtr = *(DWORD*)0x0097FA78;
            ProxyLog("  STATE CHECK (%ds): Py_Initialized=%u WSN=0x%08X",
                     i / 2, pyInit, wsnPtr);

            /* One-shot Python diagnostic at 15s */
            if (i == 30 && pyInit) {
                /* Check Python internals step by step */
                typedef void* (__cdecl *pfn_void)(void);
                typedef void* (__cdecl *pfn_str)(const char*);
                typedef void* (__cdecl *pfn_dict)(void*);
                typedef void* (__cdecl *pfn_run4)(const char*, int, void*, void*);
                typedef int (__cdecl *pfn_PyRun)(const char*);
                typedef void (__cdecl *pfn_errprint)(void);

                pfn_void  PySys_GetModules   = (pfn_void)0x0075b250;
                pfn_str   PyImport_AddModule = (pfn_str)0x0075b890;
                pfn_dict  PyModule_GetDict   = (pfn_dict)0x00773990;
                pfn_run4  PyRun_String       = (pfn_run4)0x0074b640;
                pfn_PyRun PyRunSimple        = (pfn_PyRun)0x0074ae80;
                pfn_errprint PyErr_Print     = (pfn_errprint)0x0074af10;

                void *modules, *mainMod, *mainDict, *result;

                /* Dump frozen modules table */
                {
                    DWORD* pFrozenPtr = (DWORD*)0x00975860;
                    if (!IsBadReadPtr(pFrozenPtr, 4)) {
                        BYTE* entry = (BYTE*)(*(DWORD*)pFrozenPtr);
                        int idx;
                        ProxyLog("  PY_DIAG: FrozenModules table at %p", entry);
                        for (idx = 0; idx < 50 && entry; idx++) {
                            char* name = *(char**)entry;
                            if (!name || IsBadReadPtr(name, 1)) break;
                            ProxyLog("  FROZEN[%d]: '%s' code=%p size=%d",
                                     idx, name,
                                     *(void**)(entry + 4),
                                     *(int*)(entry + 8));
                            entry += 12;
                        }
                    }
                }

                modules = PySys_GetModules();
                ProxyLog("  PY_DIAG: sys.modules = %p", modules);

                mainMod = PyImport_AddModule("__main__");
                ProxyLog("  PY_DIAG: __main__ module = %p", mainMod);

                if (mainMod) {
                    mainDict = PyModule_GetDict(mainMod);
                    ProxyLog("  PY_DIAG: __main__.__dict__ = %p", mainDict);

                    /* Try simplest possible statement */
                    result = PyRun_String("pass\n", 0x101, mainDict, mainDict);
                    ProxyLog("  PY_DIAG: PyRun_String('pass') = %p", result);
                    if (!result) {
                        ProxyLog("  PY_DIAG: Python execution failed, calling PyErr_Print");
                        PyErr_Print();
                    }

                    /* Try writing diagnostic file */
                    result = PyRun_String(
                        "import sys, traceback\n"
                        "f = open('py_diag.log', 'w')\n"
                        "mods = sys.modules.keys()\n"
                        "mods.sort()\n"
                        "f.write('Modules: ' + str(mods) + '\\n')\n"
                        "f.write('Path: ' + str(sys.path) + '\\n')\n"
                        "try:\n"
                        "    import App\n"
                        "    f.write('import App: OK, App=' + str(App) + '\\n')\n"
                        "    attrs = dir(App)\n"
                        "    f.write('App has ' + str(len(attrs)) + ' attrs\\n')\n"
                        "    net = filter(lambda x: 'WSN' in x or 'Winsock' in x or 'Network' in x, attrs)\n"
                        "    f.write('Network attrs: ' + str(net) + '\\n')\n"
                        "except:\n"
                        "    f.write('import App: FAILED\\n')\n"
                        "    traceback.print_exc(file=f)\n"
                        "try:\n"
                        "    import Local\n"
                        "    f.write('import Local: OK\\n')\n"
                        "except:\n"
                        "    f.write('import Local: FAILED\\n')\n"
                        "    traceback.print_exc(file=f)\n"
                        "f.close()\n",
                        0x101, mainDict, mainDict);
                    ProxyLog("  PY_DIAG: diag write = %p", result);
                    if (!result) PyErr_Print();
                }
            }
        }
        /* Set up timer to keep the message pump running */
        if (g_hGameWindow && !timerSet) {
            SetTimer(g_hGameWindow, 1, 16, NULL);
            timerSet = TRUE;
            ProxyLog("  Heartbeat: Set 16ms timer on game window %p", g_hGameWindow);
        }
    }
    /* Long-running heartbeat: check every 5 seconds */
    while (1) {
        Sleep(5000);
        count++;
        EnumThreadWindows(g_dwMainThreadId, FindAbortDialog, 0);
        if (count <= 6 || count % 12 == 0) {
            DWORD wsnPtr = 0;
            if (!IsBadReadPtr((void*)0x0097FA78, 4))
                wsnPtr = *(DWORD*)0x0097FA78;
            ProxyLog("HEARTBEAT #%u (%u sec) WSN=0x%08X",
                     count, count * 5 + 30, wsnPtr);
            /* Track module loading from C API (read-only, safe from background thread) */
            if (count <= 3) LogPyModules("HEARTBEAT-MODS");
        }
    }
    return 0;
}

/* ================================================================
 * DllMain
 * ================================================================ */
BOOL WINAPI DllMain(HINSTANCE hInstDLL, DWORD reason, LPVOID reserved) {
    char sysPath[MAX_PATH];
    char filePath[MAX_PATH];
    char *lastSlash;
    HANDLE hCfg;

    (void)reserved;

    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInstDLL);

        /* Allocate 64KB dummy object for NULL this-pointer fixups */
        g_pNullDummy = (BYTE*)VirtualAlloc(NULL, 65536, MEM_COMMIT | MEM_RESERVE,
                                            PAGE_EXECUTE_READWRITE);
        if (g_pNullDummy) {
            BYTE* stub = g_pNullDummy + 0xFF00;
            DWORD* vtable = (DWORD*)(g_pNullDummy + 0x8000);
            DWORD stubAddr = (DWORD)stub;
            int i;
            stub[0] = 0x31; stub[1] = 0xC0;  /* xor eax, eax */
            stub[2] = 0xC3;                    /* ret */
            stub[3] = 0x31; stub[4] = 0xC0;  /* xor eax, eax */
            stub[5] = 0xC2; stub[6] = 0x04; stub[7] = 0x00;  /* ret 4 */
            stub[8] = 0x31; stub[9] = 0xC0;  /* xor eax, eax */
            stub[10] = 0xC2; stub[11] = 0x08; stub[12] = 0x00; /* ret 8 */
            *(DWORD*)g_pNullDummy = (DWORD)vtable;
            for (i = 0; i < 7424; i++)
                vtable[i] = stubAddr;
        }
        AddVectoredExceptionHandler(1, CrashHandler);

        g_dwMainThreadId = GetCurrentThreadId();
        DuplicateHandle(GetCurrentProcess(), GetCurrentThread(),
                        GetCurrentProcess(), &g_hMainThread,
                        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                        FALSE, 0);

        /* Resolve base path */
        GetModuleFileNameA(hInstDLL, g_szBasePath, MAX_PATH);
        lastSlash = g_szBasePath;
        for (char *p = g_szBasePath; *p; p++) {
            if (*p == '\\' || *p == '/') lastSlash = p;
        }
        if (lastSlash != g_szBasePath) *(lastSlash + 1) = '\0';
        else lstrcatA(g_szBasePath, "\\");

        /* Open log file */
        lstrcpynA(filePath, g_szBasePath, MAX_PATH);
        lstrcatA(filePath, "ddraw_proxy.log");
        g_pLog = fopen(filePath, "w");
        ProxyLog("DDraw Proxy loaded (minimal shim mode)");
        ProxyLog("Base path: %s", g_szBasePath);

        /* Check for dedicated server mode */
        lstrcpynA(filePath, g_szBasePath, MAX_PATH);
        lstrcatA(filePath, "dedicated.cfg");
        hCfg = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ,
                            NULL, OPEN_EXISTING, 0, NULL);
        if (hCfg != INVALID_HANDLE_VALUE) {
            CloseHandle(hCfg);
            g_bStubMode = TRUE;
            ProxyLog("dedicated.cfg found - STUB MODE (dedicated server)");

            /* Redirect stdout/stderr for Python print capture.
               SetStdHandle only changes Win32 console handles, but Python 1.5
               print uses C runtime FILE* (msvcrt stdout). GUI apps have no
               console so stdout fd is disconnected. We must freopen msvcrt's
               _iob[1] (stdout) and _iob[2] (stderr) to a file. */
            {
                char logPath[MAX_PATH];
                lstrcpynA(logPath, g_szBasePath, MAX_PATH);
                lstrcatA(logPath, "dedicated_console.log");

                /* Also set Win32 handle for completeness */
                {
                    HANDLE hLogFile = CreateFileA(logPath, GENERIC_WRITE,
                                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                                            NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                    if (hLogFile != INVALID_HANDLE_VALUE) {
                        SetStdHandle(STD_OUTPUT_HANDLE, hLogFile);
                        SetStdHandle(STD_ERROR_HANDLE, hLogFile);
                    }
                }

                /* Redirect CRT stdout/stderr via msvcrt.
                   Approach: use _open_osfhandle + _dup2 to redirect fd 1/2,
                   then freopen on _iob as belt-and-suspenders. */
                {
                    HMODULE hCRT = GetModuleHandleA("msvcrt.dll");
                    if (!hCRT) hCRT = LoadLibraryA("msvcrt.dll");
                    if (hCRT) {
                        typedef int (__cdecl *pfn_open)(const char*, int, ...);
                        typedef int (__cdecl *pfn_dup2)(int, int);
                        typedef int (__cdecl *pfn_fflush)(void*);
                        typedef int (__cdecl *pfn_fprintf)(void*, const char*, ...);
                        typedef void* (__cdecl *pfn_freopen)(const char*, const char*, void*);

                        pfn_open fn_open = (pfn_open)GetProcAddress(hCRT, "_open");
                        pfn_dup2 fn_dup2 = (pfn_dup2)GetProcAddress(hCRT, "_dup2");
                        pfn_fflush fn_fflush = (pfn_fflush)GetProcAddress(hCRT, "fflush");
                        pfn_fprintf fn_fprintf = (pfn_fprintf)GetProcAddress(hCRT, "fprintf");
                        pfn_freopen fn_freopen = (pfn_freopen)GetProcAddress(hCRT, "freopen");
                        BYTE* p_iob = (BYTE*)GetProcAddress(hCRT, "_iob");

                        ProxyLog("  msvcrt: _open=%p _dup2=%p freopen=%p _iob=%p",
                                 fn_open, fn_dup2, fn_freopen, p_iob);

                        /* Method 1: _open + _dup2 at fd level */
                        if (fn_open && fn_dup2) {
                            /* _O_WRONLY=0x0001, _O_CREAT=0x0100, _O_TRUNC=0x0200 */
                            int logFd = fn_open(logPath, 0x0301, 0x180);
                            ProxyLog("  _open(\"%s\") -> fd=%d", logPath, logFd);
                            if (logFd >= 0) {
                                int r1 = fn_dup2(logFd, 1); /* stdout */
                                int r2 = fn_dup2(logFd, 2); /* stderr */
                                ProxyLog("  _dup2 stdout=%d stderr=%d", r1, r2);
                            }
                        }

                        /* Method 2: freopen on _iob (32 bytes per FILE in x86 msvcrt) */
                        if (fn_freopen && p_iob) {
                            void* msvc_stdout = (void*)(p_iob + 32);
                            void* msvc_stderr = (void*)(p_iob + 64);
                            fn_freopen(logPath, "w", msvc_stdout);
                            fn_freopen(logPath, "a", msvc_stderr);
                        }

                        /* Test: write directly to msvcrt stdout */
                        if (fn_fprintf && fn_fflush && p_iob) {
                            void* msvc_stdout = (void*)(p_iob + 32);
                            fn_fprintf(msvc_stdout, "[DDraw] Console redirect test OK\n");
                            fn_fflush(msvc_stdout);
                        }

                        ProxyLog("  Console output redirected to dedicated_console.log");
                    }
                }
            }

            /* Suppress CRT abort dialogs */
            SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
            {
                HMODULE hCRT = GetModuleHandleA("msvcrt.dll");
                if (!hCRT) hCRT = LoadLibraryA("msvcrt.dll");
                if (hCRT) {
                    typedef int (__cdecl *pfn_sab)(unsigned int, unsigned int);
                    typedef void (__cdecl *sighandler_t)(int);
                    typedef sighandler_t (__cdecl *pfn_signal)(int, sighandler_t);
                    pfn_sab fn_sab = (pfn_sab)GetProcAddress(hCRT, "_set_abort_behavior");
                    pfn_signal fn_signal = (pfn_signal)GetProcAddress(hCRT, "signal");
                    if (fn_sab) fn_sab(0, 3);
                    if (fn_signal) fn_signal(22, SigAbrtHandler);
                }
            }

            /* Apply patches for stub mode */
            HookGameIAT();
            InlineHookMessageBoxA();
            HookAbort();
            PatchNullSurface();
            PatchRenderTick();
            PatchRendererCtorEntry(); /* Neuter renderer ctor at entry (all callers) */
            /* NOTE: Don't use PatchSkipRendererCtor - we WANT the neutered ctor to run
               so the renderer object is non-NULL with a proper vtable. */
            PatchInitAbort();         /* Prevent abort when init check fails */
            PatchPyFatalError();      /* Make Py_FatalError return instead of tail-calling abort */
            PatchCreateAppModule();   /* Create SWIG "App" module before init imports it */
            PatchNullGlobals();       /* Pre-fill NULL globals with dummy */
            PatchSkipRendererSetup(); /* Skip pipeline after caps check */
            PatchSkipDeviceLost();    /* Skip device-lost recreation path */
            PatchRendererMethods();   /* Stub specific renderer methods */
            PatchHeadlessCrashSites(); /* NOP mission UI functions that crash headless */
            PatchDisableDebugConsole(); /* Auto-resume Python exceptions (log to stderr) */
            /* PatchChecksumAlwaysPass REMOVED - flag=0 means "no mismatches"
             * which is CORRECT for first player (no peers to compare against).
             * Forcing flag=1 corrupted the settings packet with bogus mismatch data. */

            /* Let the game boot and run Python naturally.
               Python automation in DedicatedServer.py drives multiplayer. */

            /* Start heartbeat thread */
            CreateThread(NULL, 0, HeartbeatThread, NULL, 0, NULL);
        } else {
            g_bStubMode = FALSE;
            ProxyLog("No dedicated.cfg - FORWARD MODE (normal play)");
        }

        /* Always load real ddraw.dll from System32 */
        GetSystemDirectoryA(sysPath, MAX_PATH);
        lstrcatA(sysPath, "\\ddraw.dll");
        g_hRealDDraw = LoadLibraryA(sysPath);
        if (g_hRealDDraw) {
            g_pfnDDCreate = (PFN_DirectDrawCreate)GetProcAddress(g_hRealDDraw, "DirectDrawCreate");
            g_pfnDDCreateEx = (PFN_DirectDrawCreateEx)GetProcAddress(g_hRealDDraw, "DirectDrawCreateEx");
            g_pfnDDEnumA = (PFN_DirectDrawEnumerateA)GetProcAddress(g_hRealDDraw, "DirectDrawEnumerateA");
            g_pfnDDEnumExA = (PFN_DirectDrawEnumerateExA)GetProcAddress(g_hRealDDraw, "DirectDrawEnumerateExA");
            g_pfnAcquireDDThreadLock = GetProcAddress(g_hRealDDraw, "AcquireDDThreadLock");
            g_pfnReleaseDDThreadLock = GetProcAddress(g_hRealDDraw, "ReleaseDDThreadLock");
            g_pfnCompleteCreateSysmemSurface = GetProcAddress(g_hRealDDraw, "CompleteCreateSysmemSurface");
            g_pfnD3DParseUnknownCommand = GetProcAddress(g_hRealDDraw, "D3DParseUnknownCommand");
            g_pfnDDGetAttachedSurfaceLcl = GetProcAddress(g_hRealDDraw, "DDGetAttachedSurfaceLcl");
            g_pfnDDInternalLock = GetProcAddress(g_hRealDDraw, "DDInternalLock");
            g_pfnDDInternalUnlock = GetProcAddress(g_hRealDDraw, "DDInternalUnlock");
            g_pfnDSoundHelp = GetProcAddress(g_hRealDDraw, "DSoundHelp");
            g_pfnDirectDrawCreateClipper = GetProcAddress(g_hRealDDraw, "DirectDrawCreateClipper");
            g_pfnGetDDSurfaceLocal = GetProcAddress(g_hRealDDraw, "GetDDSurfaceLocal");
            g_pfnGetOLEThunkData = GetProcAddress(g_hRealDDraw, "GetOLEThunkData");
            g_pfnGetSurfaceFromDC = GetProcAddress(g_hRealDDraw, "GetSurfaceFromDC");
            g_pfnRegisterSpecialCase = GetProcAddress(g_hRealDDraw, "RegisterSpecialCase");
            g_pfnSetAppCompatData = GetProcAddress(g_hRealDDraw, "SetAppCompatData");
            ProxyLog("Real ddraw.dll loaded from %s", sysPath);
        } else {
            ProxyLog("WARNING: Could not load real ddraw.dll from %s", sysPath);
        }
    }
    else if (reason == DLL_PROCESS_DETACH) {
        ProxyLog("DDraw Proxy unloading");
        if (g_hRealDDraw) {
            FreeLibrary(g_hRealDDraw);
            g_hRealDDraw = NULL;
        }
        if (g_pLog) {
            fclose(g_pLog);
            g_pLog = NULL;
        }
    }
    return TRUE;
}

/* ================================================================
 * Exported functions
 * ================================================================ */
HRESULT WINAPI DirectDrawCreate(GUID* lpGUID, void** lplpDD, void* pUnkOuter) {
    ProxyLog("DirectDrawCreate called");
    if (g_bStubMode) {
        *lplpDD = CreateProxyDDraw7();
        return *lplpDD ? DD_OK : DDERR_GENERIC;
    }
    if (g_pfnDDCreate) return g_pfnDDCreate(lpGUID, lplpDD, pUnkOuter);
    return DDERR_GENERIC;
}

HRESULT WINAPI DirectDrawCreateEx(GUID* lpGUID, void** lplpDD,
                                                         const GUID* iid, void* pUnkOuter) {
    ProxyLog("DirectDrawCreateEx called");
    if (g_bStubMode) {
        *lplpDD = CreateProxyDDraw7();
        return *lplpDD ? DD_OK : DDERR_GENERIC;
    }
    if (g_pfnDDCreateEx) return g_pfnDDCreateEx(lpGUID, lplpDD, iid, pUnkOuter);
    return DDERR_GENERIC;
}

HRESULT WINAPI DirectDrawEnumerateA(void* lpCallback, void* lpContext) {
    ProxyLog("DirectDrawEnumerateA called");
    if (g_bStubMode) {
        typedef BOOL (CALLBACK *LPDDENUMCALLBACKA)(GUID*, char*, char*, void*);
        LPDDENUMCALLBACKA cb = (LPDDENUMCALLBACKA)lpCallback;
        if (cb) cb(NULL, g_szDeviceName, "display", lpContext);
        return DD_OK;
    }
    if (g_pfnDDEnumA) return g_pfnDDEnumA(lpCallback, lpContext);
    return DDERR_GENERIC;
}

HRESULT WINAPI DirectDrawEnumerateExA(void* lpCallback, void* lpContext, DWORD dwFlags) {
    ProxyLog("DirectDrawEnumerateExA called");
    if (g_bStubMode) {
        typedef BOOL (CALLBACK *LPDDENUMCALLBACKEXA)(GUID*, char*, char*, void*, HMONITOR);
        LPDDENUMCALLBACKEXA cb = (LPDDENUMCALLBACKEXA)lpCallback;
        if (cb) cb(NULL, g_szDeviceName, "display", lpContext, NULL);
        return DD_OK;
    }
    if (g_pfnDDEnumExA) return g_pfnDDEnumExA(lpCallback, lpContext, dwFlags);
    return DDERR_GENERIC;
}

HRESULT WINAPI DirectDrawEnumerateW(void* lpCallback, void* lpContext) {
    (void)lpCallback; (void)lpContext; return DD_OK;
}

HRESULT WINAPI DirectDrawEnumerateExW(void* lpCallback, void* lpContext, DWORD dwFlags) {
    (void)lpCallback; (void)lpContext; (void)dwFlags; return DD_OK;
}

HRESULT WINAPI DllCanUnloadNow(void) { return S_FALSE; }
HRESULT WINAPI DllGetClassObject(const GUID* rclsid, const GUID* riid, void** ppv) {
    (void)rclsid; (void)riid; (void)ppv; return E_NOTIMPL;
}

/* ================================================================
 * Naked forwarding stubs for standard ddraw.dll exports
 * ================================================================ */
__attribute__((naked)) void __cdecl ForwardStub_NullFallback(void) {
    __asm__("xorl %eax, %eax\n\tret");
}

#define FORWARD_FUNC(name) \
    __attribute__((naked)) void __stdcall name(void) { \
        __asm__("movl _g_pfn" #name ", %eax\n\t" \
                "testl %eax, %eax\n\t" \
                "jz _ForwardStub_NullFallback\n\t" \
                "jmp *%eax"); \
    }

FORWARD_FUNC(AcquireDDThreadLock)
FORWARD_FUNC(ReleaseDDThreadLock)
FORWARD_FUNC(CompleteCreateSysmemSurface)
FORWARD_FUNC(D3DParseUnknownCommand)
FORWARD_FUNC(DDGetAttachedSurfaceLcl)
FORWARD_FUNC(DDInternalLock)
FORWARD_FUNC(DDInternalUnlock)
FORWARD_FUNC(DSoundHelp)
FORWARD_FUNC(DirectDrawCreateClipper)
FORWARD_FUNC(GetDDSurfaceLocal)
FORWARD_FUNC(GetOLEThunkData)
FORWARD_FUNC(GetSurfaceFromDC)
FORWARD_FUNC(RegisterSpecialCase)
FORWARD_FUNC(SetAppCompatData)
