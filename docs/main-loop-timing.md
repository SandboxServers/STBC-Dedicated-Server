# STBC Main Loop & Timing Architecture

## Executive Summary

Bridge Commander uses the standard NetImmerse/Gamebryo `NiApplication` main loop pattern:
a **PeekMessage-based busy loop** with **no Sleep, no fixed timestep, and no vsync waiting**.
The tick rate is determined entirely by how fast the CPU can execute one frame.

In the **stock game with renderer**, the practical frame rate is bounded by:
1. GPU vsync (if enabled in driver) or GPU render time
2. A soft frame rate cap of **60 FPS** (`m_fMinFramePeriod = 1/60`)

In the **stock dedicated server** (headless, no renderer), the loop runs as a **100% CPU busy loop**
with no throttling whatsoever -- limited only by how fast the CPU can run through game logic.

In **our proxy-based dedicated server**, we inject `GameLoopTimerProc` via Windows `SetTimer`,
which runs at the multimedia timer resolution (~16ms = ~60 Hz by default).

---

## Architecture Overview

### Class Hierarchy

```
NiApplication                  (engine base, Gb 1.2 source available)
  +-- TGApp                    (Totally Games application layer)
       +-- UtopiaApp           (Bridge Commander specific)
```

### Vtable Map (key slots)

| Slot | Offset | Function | Address (UtopiaApp) | Notes |
|------|--------|----------|---------------------|-------|
| 0  | 0x00 | ~dtor | 0x006cdaf0 | |
| 1  | 0x04 | Initialize | 0x007b7c70 | NiApp base (not overridden by UtopiaApp) |
| 12 | 0x30 | EnableFrameRate | 0x006cdfd0 | Overridden |
| 21 | 0x54 | UpdateInput | 0x006cddd0 | Overridden |
| 24 | 0x60 | OnIdle | 0x006cdd20 (UtopiaApp) | **Key: called every frame** |
| 29 | 0x74 | MeasureTime | 0x007b8780 | **STUB** (returns false always) |
| 30 | 0x78 | Process | 0x007b8790 | **NOT overridden** (base NiApp) |
| 31 | 0x7C | OnWindowResize | 0x006cdff0 | Overridden |
| 37 | 0x94 | UpdateTime | 0x006cdc00 | TGApp time scaling |

### Vtable Addresses

| Class | Vtable Address | Notes |
|-------|---------------|-------|
| NiApplication (base) | 0x008988d4 | Set in FUN_007b7180 |
| BC-mid (TGApp) | 0x00889a98 | Set in FUN_00437fb0 |
| UtopiaApp (final) | 0x00895b8c | Set in FUN_006cd790 |

---

## The Main Loop

### Entry Point

```
entry() -> FUN_0086eff0 (WinMain equivalent)
  -> FUN_00437f50() creates UtopiaApp (size 0xBC)
  -> vtable[1]()  = Initialize
  -> FUN_007ba5a0() = MainLoop
  -> vtable[2]()  = Terminate
```

### MainLoop (FUN_007ba5a0)

```c
void MainLoop() {
    int retval;
    do {
        // Process() returns false on WM_QUIT
        result = this->Process(&retval);  // vtable[30]
    } while (result != false);
}
```

Assembly at 0x007ba5a0:
```asm
007ba5a0: PUSH ECX                    ; local for retval
007ba5a1: MOV  ECX, [0x009a09d0]      ; ECX = g_Clock (= NiApp singleton)
007ba5a7: LEA  EDX, [ESP]             ; &retval
007ba5ab: PUSH EDX
007ba5ac: MOV  EAX, [ECX]             ; vtable
007ba5ae: CALL [EAX+0x78]             ; vtable[30] = Process()
007ba5b1: TEST AL, AL
007ba5b3: JNZ  0x007ba5a1             ; loop while Process returns true
007ba5b5: MOV  EAX, [ESP]
007ba5b9: POP  ECX
007ba5ba: RET
```

### Process() (FUN_007b8790, vtable slot 30)

**NOT overridden by BC** -- uses the stock NiApplication implementation.

```c
bool NiApplication::Process(int* pRetval) {
    MSG msg;
    if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
        if (msg.message == WM_QUIT) {
            *pRetval = msg.wParam;
            return false;  // exit main loop
        }
        TranslateAccelerator(...);
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    } else {
        this->OnIdle();  // vtable[32], offset 0x80
    }
    return true;  // continue looping
}
```

**Key insight**: This is a standard Win32 PeekMessage idle loop. When there are no Windows messages,
it calls OnIdle(). There is **no Sleep(), no WaitMessage(), no yield**. If OnIdle returns quickly,
the loop immediately calls PeekMessage again.

### OnIdle() -- UtopiaApp override (FUN_006cdd20, vtable slot 32)

```c
void UtopiaApp::OnIdle() {
    this->UpdateTime();           // vtable[37] -- time computation + scaling

    // Frame rate limiter check
    if (m_fMinFramePeriod + m_fLastFrame <= m_fAccumTime) {
        m_fLastFrame = m_fAccumTime;
        this->readyToRender = true;
    } else {
        this->readyToRender = false;
    }

    // Frame rate display
    if (m_bFrameRateEnabled && m_pkFrameRate) {
        m_pkFrameRate->TakeSample();
        m_pkFrameRate->Update();
    }

    // Sound update
    FUN_006e6420();
    FUN_006e6430(&DAT_009992f0);

    m_iClicks++;  // +0x64

    // State machine for app transitions
    if (this->appState == 1) {
        this->BeginGame();    // vtable[40]
        this->appState = 2;
    }
    if (this->appState == 3) {
        this->EndGame();      // vtable[41]
        this->appState = 0;
    }
}
```

**CRITICAL**: `MeasureTime()` (vtable slot 29) is a **stub** in BC's NI 3.1 build -- it
always returns false. The Gb 1.2 NiApplication::OnIdle() checks MeasureTime() as a frame rate
gate, but BC's overridden OnIdle() does its own check directly against
`m_fMinFramePeriod + m_fLastFrame <= m_fAccumTime`.

The frame rate limiter only gates **rendering readiness** (the `readyToRender` flag). It does NOT
prevent OnIdle from running. Game logic (via MainTick) runs every iteration regardless.

### MainTick (FUN_0043b4f0, vtable slot ~61 in BC-mid)

Called from OnIdle -> UpdateTime -> eventually reaches MainTick. Actually, looking more carefully,
MainTick is in the BC-mid vtable at slot 61 (offset 0xF4) and is called from the scene graph update
path at step 10 (FUN_0043b790).

**Wait** -- re-checking the call graph: MainTick (0x0043b4f0) is referenced from vtable data at
0x00889b8c, which is BC-mid vtable slot 61. From the decompilation of OnIdle, it calls vtable[37]
(UpdateTime at 0x006cdc00). Let me trace more carefully.

Actually, MainTick is the **BC-mid's override of the NiApplication OnIdle equivalent** -- it's what
gets called as the main game frame. The scene update function FUN_0043b790 (called FROM MainTick)
does the actual game update.

### MainTick Call Sequence (FUN_0043b4f0)

```
1. FUN_0071a9e0(0x99c6b0)            -- NiClock::Update (reads timeGetTime/QPC)
2. FUN_006dc490(0x0097f898, gameTime) -- TGTimerManager#1.Update(gameTime)
3. FUN_006dc490(0x0097f810, frameTime)-- TGTimerManager#2.Update(frameTime)
4. FUN_006da2c0(0x0097f838)           -- TGEventManager.ProcessEvents
5. FUN_004721b0(0x9817a8)             -- Update (purpose TBD)
6. FUN_0046f420()                     -- Frame budget scheduler (updateables)
7. FUN_00443ac0()                     -- Save game processing
8. FUN_004447f0()                     -- Load game filename
9. FUN_00444840()                     -- Load game data
10. FUN_0043b790()                    -- Scene graph update + Python OnIdle
11. vtable[0x54] if renderer exists   -- Renderer::Update(frameTime)
12. FUN_004433e0() or renderer path   -- Render frame / display
13. FUN_00727a40(0x99d040)            -- Scene manager update
14. FUN_0070f7e0(0x0099ba00, 1)       -- Post-frame update
```

---

## Time Sources

### NiClock Object (0x0099c6b0)

A global timer object, separate from the NiApplication singleton. Updated once per MainTick.

| Offset | Type | Name | Description |
|--------|------|------|-------------|
| +0x08 | DWORD | lastTimeMs | Previous timeGetTime() value |
| +0x0C | float | accumTimeSec | Running total wall-clock seconds |
| +0x10 | DWORD | accumTimeMs | Running total wall-clock milliseconds |
| +0x14 | float | deltaTimeSec | Frame delta in seconds |
| +0x18 | DWORD | deltaTimeMs | Frame delta in milliseconds |
| +0x1C | bool | useQPC | If true, use QueryPerformanceCounter |
| +0x20 | LARGE_INTEGER | qpcBase | QPC base value (set on first update) |
| +0x28 | LONGLONG | qpcFreq | QPC frequency (from QueryPerformanceFrequency) |
| +0x34 | bool | resetFlag | Forces re-read of base time on next update |
| +0x38 | int | frameCount | Incremented each update |

**FUN_0071a9e0** (NiClock::Update):
```c
void NiClock::Update() {
    frameCount++;
    if (resetFlag) {
        resetFlag = false;
        lastTimeMs = timeGetTime();
    }
    DWORD now = timeGetTime();
    DWORD deltaMs = now - lastTimeMs;
    lastTimeMs = now;
    deltaTimeMs = deltaMs;
    float deltaSec = deltaMs * 0.001f;  // DAT_00894a1c = 0.001
    accumTimeMs += deltaMs;
    deltaTimeSec = deltaSec;
    accumTimeSec += deltaSec;
    if (useQPC) {
        QueryPerformanceCounter(&qpcCurrent);
    }
}
```

**FUN_0071acc0** (NiClock::GetCurrentTimeInSec):
```c
double NiClock::GetCurrentTimeInSec() {
    if (useQPC) {
        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);
        return (double)(now - qpcBase) / (double)qpcFreq;
    }
    return (double)(timeGetTime() - lastTimeMs) * 0.001;
}
```

### NiApplication Time Fields (g_Clock = 0x009a09d0)

| Offset | Type | Gb 1.2 Name | Description |
|--------|------|-------------|-------------|
| +0x54 | float | m_fCurrentTime | Wall-clock time in seconds (passed to TGTimerManager#2) |
| +0x58 | float | m_fLastTime | Previous m_fCurrentTime (-1.0 = uninitialized) |
| +0x5C | float | m_fDeltaTime | Frame delta in seconds |
| +0x60 | float | m_fAccumTime | Accumulated time in seconds |
| +0x64 | int | m_iClicks | Frame counter |
| +0x74 | float | m_fMinFramePeriod | **1/60 = 0.01667** (BC override from base 1/100) |
| +0x78 | float | m_fLastFrame | Last frame's accumTime (for rate limiter) |

### TGApp Time Fields (g_Clock + 0x8C)

| Offset | Type | Name | Description |
|--------|------|------|-------------|
| +0x8C | int | ??? | Unknown (initialized 0) |
| +0x90 | float | gameTime | Scaled game time (passed to TGTimerManager#1) |
| +0x94 | float | timeScaleMax | Time scale upper bound |
| +0x98 | float | ??? | Unknown (initialized 0) |
| +0x9C | float | timeRate | Game time rate multiplier (default 1.0) |
| +0xA0 | float | maxTimeRate | Maximum allowed time rate (default 1.0) |
| +0xA4 | bool | ??? | Flag (default true) |

The `gameTime` at +0x90 advances as `gameTime += deltaTime * timeRate`. When timeRate=1.0,
gameTime tracks wall-clock time. The SWIG function `UtopiaModule.SetTimeRate()` modifies +0x9C.

---

## TGTimerManager

Two instances:
- **0x0097F898**: Updated with `gameTime` (g_Clock+0x90) -- game-logic timers
- **0x0097F810**: Updated with `frameTime` (g_Clock+0x54) -- wall-clock timers

**FUN_006dc490** (TGTimerManager::Update):
Walks a sorted list of TGTimer objects. For each timer whose fire time <= current time,
posts the timer's event to the TGEventManager. Handles repeating timers by rescheduling.

---

## Frame Budget Scheduler (FUN_0046f420)

This is the **game update dispatcher** that calls registered updateable objects (ships, AI, physics, etc.).

Key behavior:
- Maintains a **16-sample ring buffer** of frame times (at DAT_00981560)
- Computes an **average frame time** (excluding min/max outliers) as the budget
- Objects are organized into **4 priority tiers** (1-3 + high-priority tier 0)
- Each tier gets time-sliced: objects update until the budget is exhausted
- Uses a **round-robin counter** (DAT_009815e4) to alternate which tier gets first pick
- If budget remains after the first tier, subsequent tiers can use it

This ensures heavy objects (like AI pathfinding) don't starve lightweight ones (like input processing).

---

## What Determines Tick Rate?

### Stock Game (with Renderer)

1. **Main loop**: `PeekMessage` busy loop, no sleep
2. **Frame rate limiter**: `m_fMinFramePeriod = 1/60` (60 FPS cap)
   - Only gates rendering readiness, NOT game logic execution
   - OnIdle still runs even when frame is "too fast"
3. **GPU bottleneck**: `SwapBuffers()` / `Present()` blocks if vsync is on
4. **Effective rate**: Typically 30-60 FPS depending on GPU, monitor, vsync settings
5. **Game logic runs every iteration** of the main loop (not frame-rate-limited)

### Stock Dedicated Server (Headless)

1. **Main loop**: Same PeekMessage busy loop
2. **No renderer**: The `SwapBuffers` / `Present` path is never reached
3. **Frame rate limiter**: Still 1/60, but only gates a `readyToRender` flag that nothing checks
4. **No Sleep anywhere**: None of the 4 Sleep call sites are in the main loop:
   - `FUN_006acda0` (Sleep wrapper) -- GameSpy query response loop only
   - `py_time_sleep` (0x00768330) -- Python `time.sleep()` only
   - 0x0085867b, 0x0085cd47 -- CRT thread synchronization, Sleep(1)
5. **Result**: **100% CPU busy loop** at thousands of FPS
6. **Game time advances correctly** because deltaTime is computed from timeGetTime()

### Our Proxy Server (GameLoopTimerProc)

We bypass the native main loop entirely. Our `GameLoopTimerProc` is called by Windows `SetTimer`
at approximately 60 Hz (16ms intervals). Each invocation calls:
1. `UTOPIA_MAIN_TICK(UTOPIA_APP_OBJ, NULL)` -- the same MainTick as the native loop
2. `TGNETWORK_UPDATE(wsn, NULL)` -- explicit network pump

This gives us a stable ~60 Hz tick rate without burning 100% CPU.

---

## Sleep Usage in stbc.exe

Only 4 call sites in the entire binary, **none in the main loop**:

| Address | Context | Duration |
|---------|---------|----------|
| 0x006acda5 | GameSpy query loop (`FUN_006aa680`) | 10ms |
| 0x00768988 | `py_time_sleep` (Python `time.sleep()`) | variable |
| 0x0085867b | CRT thread sync | 1ms |
| 0x0085cd47 | CRT thread sync | 1ms |

---

## Key Constants

| Address | Value | Name | Usage |
|---------|-------|------|-------|
| 0x00894a1c | 0.001f | MS_TO_SEC | timeGetTime delta -> seconds |
| 0x008958cc | 15.0f | NET_TIME_BUDGET | Network processing time budget (seconds) |
| BC ctor | 0x3c888889 (1/60) | m_fMinFramePeriod | Frame rate limiter period |
| NiApp ctor | 0x3c23d70a (1/100) | m_fMinFramePeriod_base | Base class default (100 FPS cap) |

---

## Implications for OpenBC

1. **No fixed timestep**: BC uses variable deltaTime everywhere. All physics, damage, repair, power
   systems multiply by `dt`. A reimplementation MUST use variable timestep or carefully convert.

2. **No Sleep in main loop**: The stock dedicated server burns 100% CPU. A reimplementation should
   add explicit Sleep/yield to maintain target tick rate without wasting CPU.

3. **Two timer managers**: Game timers (scaled by timeRate) and wall-clock timers (unscaled) are
   separate systems. timeRate can be modified via Python (`UtopiaModule.SetTimeRate()`).

4. **Frame budget scheduler**: The updateable priority system ensures fair time-slicing across
   game objects. This is not strictly necessary for a reimplementation but explains why the stock
   game remains responsive even under heavy load.

5. **Network is pumped from MainTick**: `TGWinsockNetwork::Update` (0x006b4560) is called from
   the frame budget scheduler as a registered updateable, not directly from MainTick. It has a
   15-second time budget for processing incoming messages before yielding.
