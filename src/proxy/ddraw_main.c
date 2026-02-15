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

/* Forward declarations */
static void ResolveAddr(DWORD addr, char* out, int outLen);
void ODSLog(const char* fmt, ...);

/*
 * Split implementation units (included into one translation unit to keep
 * behavior, symbol visibility, and patch ordering unchanged).
 */
#include "ddraw_main/packet_trace_and_decode.inc.c"
#include "ddraw_main/message_factory_hooks.inc.c"
#include "ddraw_main/function_tracer.inc.c"
#include "ddraw_main/socket_and_input_hooks.inc.c"
#include "ddraw_main/binary_patches_and_python_bridge.inc.c"
#include "ddraw_main/game_loop_and_bootstrap.inc.c"
#include "ddraw_main/runtime_hooks_and_iat.inc.c"
#include "ddraw_main/core_runtime_and_exports.inc.c"
