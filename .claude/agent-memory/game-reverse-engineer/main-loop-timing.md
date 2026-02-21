# Main Loop & Timing Architecture (2026-02-20)

## Main Loop = PeekMessage Busy Loop (NO Sleep)

Standard NiApplication pattern from Gb 1.2:
```
MainLoop:
  while (Process()) {}

Process():
  if PeekMessage -> dispatch
  else -> OnIdle()
  return true  (return false on WM_QUIT)
```

Process() is NOT overridden by BC. Uses base NiApplication at 0x007b8790.
OnIdle() IS overridden: UtopiaApp at 0x006cdd20.

## NiApplication Vtable (UtopiaApp: 0x00895b8c)

Key slots:
- Slot 29 (+0x74): MeasureTime = 0x007b8780 = **STUB** (XOR AL,AL; RET) -- always returns false
- Slot 30 (+0x78): Process = 0x007b8790 = NiApp base (PeekMessage loop)
- Slot 32 (+0x80): OnIdle = 0x006cdd20 = UtopiaApp override
- Slot 37 (+0x94): UpdateTime = 0x006cdc00 = TGApp time scaling

Other vtables: BC-mid at 0x00889a98, NiApp base at 0x008988d4.

## OnIdle -> MainTick Call Chain

OnIdle (0x006cdd20):
  1. vtable[37] = UpdateTime (0x006cdc00) -- computes frame/game time
  2. Frame rate limiter check (m_fMinFramePeriod=1/60 at +0x74)
     - Only gates `readyToRender` flag -- does NOT skip game logic
  3. Sound update
  4. Increment m_iClicks
  5. App state transitions (BeginGame/EndGame)

MainTick (FUN_0043b4f0, called from BC-mid vtable slot 61):
  1. NiClock::Update(0x99c6b0) -- reads timeGetTime/QPC
  2. TGTimerManager#1.Update(gameTime) on 0x0097f898
  3. TGTimerManager#2.Update(frameTime) on 0x0097f810
  4. TGEventManager.ProcessEvents on 0x0097f838
  5. Frame budget scheduler (FUN_0046f420) -- updateables with priority tiers
  6. Save/Load processing
  7. Scene graph update + Python (FUN_0043b790)
  8. Renderer update (if renderer exists)
  9. Post-frame updates

## Time Sources

### NiClock (0x0099c6b0) -- Updated by FUN_0071a9e0
- +0x08: lastTimeMs (DWORD, timeGetTime)
- +0x0C: accumTimeSec (float)
- +0x14: deltaTimeSec (float)
- +0x18: deltaTimeMs (DWORD)
- +0x1C: useQPC flag (bool)
- +0x20: QPC base (LARGE_INTEGER)
- +0x38: frameCount (int)

Conversion: deltaMs * 0.001f (DAT_00894a1c) = deltaSec

### NiApplication (g_Clock = *(void**)0x009a09d0)
- +0x54: m_fCurrentTime (wall-clock seconds, = frameTime)
- +0x58: m_fLastTime
- +0x5C: m_fDeltaTime
- +0x60: m_fAccumTime
- +0x74: m_fMinFramePeriod = 1/60 (0x3c888889, BC override from base 1/100)
- +0x78: m_fLastFrame

### TGApp (g_Clock + 0x8C)
- +0x90: gameTime (may differ from frameTime if timeRate != 1.0)
- +0x9C: timeRate (default 1.0, modified by UtopiaModule.SetTimeRate())
- +0xA0: maxTimeRate (1.0)

## Sleep Calls in stbc.exe (4 total, NONE in main loop)
- 0x006acda5: GameSpy query loop, Sleep(10)
- 0x00768988: py_time_sleep (Python time.sleep)
- 0x0085867b: CRT sync, Sleep(1)
- 0x0085cd47: CRT sync, Sleep(1)
Sleep IAT entry: 0x00888090

## Key Constants
- 0x00894a1c: 0.001f (ms->sec)
- 0x008958cc: 15.0f (network time budget)
- BC ctor: 0x3c888889 = 1/60 (m_fMinFramePeriod)
- NiApp base: 0x3c23d70a = 1/100 (base m_fMinFramePeriod)

## Frame Budget Scheduler (FUN_0046f420)
- 16-sample ring buffer of frame times
- Average minus outliers = frame budget
- 4 priority tiers (0=high priority, 1-3=normal)
- Round-robin tier selection via counter
- Objects update until budget exhausted
- Network (TGWinsockNetwork::Update) runs as registered updateable

## Stock Dedicated Server (Headless)
**100% CPU busy loop** -- no renderer, no Sleep, no yield.
Frame rate limiter only gates readyToRender flag which nothing checks headlessly.
Game time still correct because deltaTime from timeGetTime.

## Our Proxy Server
GameLoopTimerProc via SetTimer at ~60Hz. Calls MainTick + TGNetwork::Update explicitly.
