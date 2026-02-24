# Ghidra Function Naming Passes

## Pass 5 (2026-02-23) - 35 renames

### AI Class Hierarchy (8 renames)
| Address | Name | Vtable |
|---------|------|--------|
| 0x00470520 | BaseAI__Constructor | 0x0088bb54 |
| 0x0048cc40 | PlainAI__Constructor | 0x0088c0d8 |
| 0x00478a50 | ConditionalAI__Constructor | 0x0088bc84 |
| 0x0048fcb0 | PriorityListAI__Constructor | 0x0088c188 |
| 0x00491370 | RandomAI__Constructor | 0x0088c1dc |
| 0x004927d0 | SequenceAI__Constructor | 0x0088c230 |
| 0x00475fb0 | BuilderAI__Constructor | 0x0088bbe0 |
| 0x0048e2b0 | PreprocessingAI__Constructor | 0x0088c12c |

AI Hierarchy: BaseAI -> PlainAI, ConditionalAI, PriorityListAI, RandomAI, SequenceAI
              BaseAI -> PreprocessingAI -> BuilderAI

7 AllocAndConstruct wrappers also named (cdecl, NiAlloc + ctor call).

### NiDX7Renderer Pipeline (18 renames)
| Address | Name |
|---------|------|
| 0x007c48b0 | NiDX7Renderer__LogError |
| 0x007c4880 | NiDX7Renderer__LogWarning |
| 0x007c4850 | NiDX7Renderer__LogInfo |
| 0x007c99e0 | NiDX7Renderer__CreateZBuffer |
| 0x007c9020 | NiDX7Renderer__SetDisplayMode |
| 0x007c96c0 | NiDX7Renderer__CreateFrontBuffer |
| 0x007c98c0 | NiDX7Renderer__CreateBackBuffer |
| 0x007d5080 | NiDX7Renderer__CreateTextureManager |
| 0x007ce9c0 | NiDX7Renderer__DetectMultitextureModes |
| 0x007ba2e0 | NiDX7Renderer__CreateFromDialog |
| 0x007b9ef0 | NiDX7Renderer__BuildDeviceSelectionDialog |
| 0x007d62a0 | NiDX7Texture__CreateSurface |
| 0x007d6380 | NiDX7Texture__ComputeTextureKey |
| 0x007d3460 | NiDX7TextureManager__QueryTextureFormats |
| 0x00438290 | UtopiaApp__CreateRenderer |
| 0x006a3560 | NetFile__RegisterHandlerNames |

### Game Code (9 renames)
| Address | Name |
|---------|------|
| 0x0050fea0 | NamedReticleWindow__Constructor |
| 0x00550770 | EngRepairPane__Constructor |
| 0x004722d0 | Ship__ProcessAITick |
| 0x004721b0 | Ship__AITickScheduler |

### Naming Methodology
- Primary: Debug string cross-references (xrefs to string -> containing function)
- Secondary: SWIG Create wrapper -> AllocAndConstruct -> thiscall ctor (vtable write confirms class)
- All renames HIGH confidence only
- Total ~6,066 functions named across all passes (~33.2% of 18,247)

### Areas Exhausted After Pass 5
- All 22 Priority 1 debug strings already named from previous passes
- All AI constructor classes identified and named
- NiDX7Renderer subsystem well-covered (25 functions named)
- No collision-specific debug strings found in binary
- Game handler registration strings ("Class::Handler") all point to already-named functions
- Diminishing returns from string-based search approach

## Pass 6 (2026-02-23) - 55 renames

### Strategies Used
1. **Constructor callee walking** - Decompile named constructors, name callees
2. **Known function callee chains** - Trace DoDamage/ProcessDamage/SaveToFile callees
3. **SWIG wrapper target tracing** - Decompile SWIG wrappers, name C++ targets
4. **Event string cross-reference** - ET_ string table (135 entries cataloged, xrefs to handlers)

### NiMatrix3 Math (2 renames)
| Address | Name | Evidence |
|---------|------|----------|
| 0x00813a40 | NiMatrix3__TransformVector | 3x3 matrix * vec3, `this` is rotation matrix at +0x00..+0x20, Gb 1.2 pattern |
| 0x00813aa0 | NiMatrix3__TransposeTransformVector | Transpose multiply (param_3 cols not rows), Gb 1.2 cross-ref |

### DamageInfo Class (4 renames)
| Address | Name | Evidence |
|---------|------|----------|
| 0x004bbde0 | DamageInfo__ctor | Called from DoDamage with position+radius+type, sets vtable 0x0088c6c4 |
| 0x004bbe90 | DamageInfo__SetRadius | Sets +0x14=r, +0x18=r^2, recomputes bounding box |
| 0x004bbeb0 | DamageInfo__SetDamageType | Sets +0x1c field |
| 0x004bbec0 | DamageInfo__ComputeBoundingBox | center +/- radius -> min/max at +0x20..+0x34 |

### Ship Combat/Damage (5 renames)
| Address | Name | Evidence |
|---------|------|----------|
| 0x00593f30 | Ship__CreateDamageNotification | Creates visual notification obj, gated on IsHost==0 (client-only) |
| 0x005aecc0 | Ship__FindSubsystemsInDamageRadius | Walks +0x284 linked list, collects subsystems within radius |
| 0x005aeb90 | Ship__CollectSubsystemsInRadius | Recursive distance check per subsystem, adds to result list |
| 0x005666e0 | TGLinkedList__RemoveNode | Unlinks node from doubly-linked list, returns value |
| 0x00486be0 | TGLinkedList__AllocNode | Pool allocator: chunks of N*12 bytes, free list at +0xC |

### Ship Navigation/Targeting (14 renames)
| Address | Name | Evidence |
|---------|------|----------|
| 0x005ae1e0 | Ship__SetTarget | SWIG ShipClass_SetTarget -> this; calls FindObjectByID + SetTargetInternal |
| 0x005ae170 | Ship__GetTarget | SWIG ShipClass_GetTarget; reads +0x21C target ID, validates alive |
| 0x005ae210 | Ship__SetTargetInternal | Fires ET_TARGET_WAS_CHANGED (0x800058), stops weapons, updates subsystems |
| 0x005ae2c0 | Ship__OnTargetChanged | Updates weapon offsets, fires ET_TARGET_SUBSYSTEM_SET (0x80005A) |
| 0x005ae430 | Ship__UpdateWeaponTargets | Walks +0x284 subsystems, updates weapon target entries |
| 0x005ae650 | Ship__GetTargetOffset | Returns +0x228 target offset (manual or auto from target bounds) |
| 0x005ae630 | Ship__GetTargetSubsystemObject | Resolves +0x220 target subsystem ID via ForwardEvent |
| 0x005ae6d0 | Ship__GetNextTarget | Cycles through sorted targets via +0x87 index |
| 0x005ad3a0 | Ship__TurnTowardLocation | Normalizes direction to target, calls TurnTowardDirection |
| 0x005ad450 | Ship__TurnTowardDirection | Gets orientation, computes turn via ComputeTurnAngularVelocity |
| 0x005ad4d0 | Ship__TurnTowardDifference | SWIG ShipClass_TurnTowardDifference target |
| 0x005ad910 | Ship__ComputeTurnAngularVelocity | Quaternion slerp-style turn with up/forward constraints |
| 0x005ad290 | Ship__SetTargetAngularVelocityDirect | SWIG target: sets angular velocity directly |
| 0x005ac6e0 | Ship__InSystemWarp | SWIG ShipClass_InSystemWarp; pathfinding + obstacle avoidance |

### Ship State (8 renames)
| Address | Name | Evidence |
|---------|------|----------|
| 0x005ac250 | Ship__RunDeathScript | SWIG target; calls "Effects.ObjectExploding" or custom death script |
| 0x005b0bb0 | Ship__StopFiringWeapons | SWIG target; walks +0x284, finds WeaponSystems via IsA(0x801D) |
| 0x005ac470 | Ship__SetImpulse | SWIG target; clamps 0..1, sets +0x1F8/+0x1FC direction/speed |
| 0x005ac590 | Ship__SetSpeed | SWIG target; divides by max speed then calls SetImpulse |
| 0x005ac450 | Ship__IsCloaked | SWIG target; reads cloaking subsystem +0xAC state flag |
| 0x005ae140 | Ship__IsPlayerShip | SWIG target; host: checks +0x2E4 (netPlayerID), client: == GetPlayerShip() |
| 0x005b3e50 | Ship__AddSubsystem | SWIG target; adds to +0x280 list, classifies by IsA checks |
| 0x005acdb0 | Ship__StopInSystemWarp | Clears warp state, fires ET_EXITED_WARP, restores velocity |

### Subsystem/Weapon Helpers (6 renames)
| Address | Name | Evidence |
|---------|------|----------|
| 0x0056c340 | Subsystem__IsActive | Reads property+0x25 active flag via +0x18 |
| 0x0056b940 | Subsystem__GetRadius | Reads property+0x44 (radius float) |
| 0x0056c570 | Subsystem__GetChild | Array bounds check, returns child at index from +0x20 |
| 0x00583f60 | Subsystem__AsWeaponSystem | IsA(0x801D) cast check |
| 0x00585360 | WeaponSystem__FindTargetEntry | Searches +0xC4 target list by object ID |
| 0x00584080 | WeaponSystem__FindTargetByObjectID | Extracts obj+4 ID, delegates to FindTargetEntry |
| 0x00585580 | WeaponSystem__SetTargetOffset | Updates target entry offset + clears child subsystem targets |

### Subsystem Property/Type (3 renames)
| Address | Name | Evidence |
|---------|------|----------|
| 0x00560fc0 | Subsystem__GetProperty | Returns +0x18 (SubsystemProperty pointer) |
| 0x005822d0 | PoweredSubsystem__GetEfficiency | Returns +0xFC / +0xF8 (received/wanted), clamped |
| 0x005623c0 | PoweredSubsystem__SetPowerSource | Delegates to PoweredMaster__SetPowerSource |

### Combat Subsystem Functions (5 renames)
| Address | Name | Evidence |
|---------|------|----------|
| 0x00574200 | PhaserSystem__SetPowerLevel | SWIG target; fires ET_SET_PHASER_LEVEL(0x8000E0), sets child modes |
| 0x00570b20 | Subsystem__AsPhaserSubsystem | IsA(0x802C) cast check |
| 0x0057b230 | TorpedoSystem__SetAmmoType | SWIG target; sets ammo type with reload flag |
| 0x00567190 | SensorSubsystem__GetSensorRange | SWIG target; computes effective range from efficiency |
| 0x00567880 | SensorSubsystem__IdentifyObject | SWIG target; force-identify target object |
| 0x0055f3e0 | CloakingSubsystem__InstantCloak | SWIG target |

### Ship Subsystem Iterator (2 renames)
| Address | Name | Evidence |
|---------|------|----------|
| 0x005ac370 | Ship__StartGetSubsystemMatch | SWIG target; allocates iterator for type matching |
| 0x005ac390 | Ship__GetNextSubsystemMatch | SWIG target; returns next subsystem matching type |

### Engine Subsystem (2 renames)
| Address | Name | Evidence |
|---------|------|----------|
| 0x00561330 | ImpulseEngineSubsystem__GetEffectiveSpeed | Computes max speed from child health + power efficiency |
| 0x00561230 | ImpulseEngineSubsystem__GetEffectiveAcceleration | Same pattern for acceleration |

### TGObject/Scene Graph (4 renames)
| Address | Name | Evidence |
|---------|------|----------|
| 0x005ab670 | TGObject__AsShip | IsA(0x8008) cast, returns NULL if not ship |
| 0x005a04c0 | TGObject__SetVelocity | Sets NiAVObject+0x98/+0x9C/+0xA0 velocity via +0x18 |
| 0x006d5e80 | TGObject__SetDirtyFlag | Sets/clears bit 2 of +0x18 flags word |
| 0x00434cd0 | GetForwardDirection | Returns global forward direction vector from DAT_00980df0 |

### Scene Graph Lookup (2 renames)
| Address | Name | Evidence |
|---------|------|----------|
| 0x00434e70 | TGSceneGraph__FindObjectByID | Searches by ID across scene roots; used by Ship__SetTarget |
| 0x00434e00 | TGSceneGraph__GetObjectByID | Hash lookup then IsA(0x8003) cast |
| 0x0040fe00 | TGObjectTree__FindByHashAndTrack | Hash bucket walk + tracking call |
| 0x0040fe80 | TGObjectTree__GetNextSorted | Binary search in sorted array, wraps on boundary |

### TGFileStream/Save System (10 renames)
| Address | Name | Evidence |
|---------|------|----------|
| 0x006d1fc0 | TGFileStream__ctor | Sets vtable 0x00895d60, allocates status object |
| 0x006d2050 | TGFileStream__dtor | Restores vtable, closes handle, frees status |
| 0x006d20e0 | TGFileStream__CloseHandle | fclose on +0x08 FILE* |
| 0x006d2080 | TGFileStream__OpenFile | fopen via CRT, sets +0x08 handle |
| 0x006d23c0 | TGFileStream__WriteString | strlen + write_size + write_data |
| 0x006d31f0 | TGFileStream__GetError | Returns *(*(+0x04)) error code |
| 0x006d32d0 | TGBufferedFileStream__ctor | Extends TGFileStream, vtable 0x00895e58, adds buffer |
| 0x006d3350 | TGBufferedFileStream__Open | Opens file, checks 'w'/'W' for write mode |
| 0x006d33c0 | TGBufferedFileStream__Close | Flushes buffer, frees memory, closes file |
| 0x006d3470 | TGBufferedFileStream__Flush | Writes buffered data to file, resets position |
| 0x006d3950 | TGBufferedFileStream__WriteFloat | Grow-check + write 4 bytes at buffer offset |
| 0x006d38d0 | TGBufferedFileStream__WriteInt | Same pattern as WriteFloat |
| 0x006d3910 | TGBufferedFileStream__WriteUInt | Same pattern |
| 0x006d39d0 | TGBufferedFileStream__WriteID | Virtual dispatch via +0x6C |

### Save Game Helpers (3 renames)
| Address | Name | Evidence |
|---------|------|----------|
| 0x006f9fb0 | SaveGame__InitPickler | Creates cPickle.Pickler for Python state serialization |
| 0x006fa020 | SaveGame__FlushPickler | Calls marshal.dump + getvalue, writes pickled data to stream |
| 0x006dd5b0 | SaveGame__SaveDirtyObjects | Walks hash table of dirty objects, serializes each |
| 0x00444470 | SaveGame__DeleteTempSaveFiles | FindFirstFile *.msv in TEMP_MISSION_SAVE_FOLDER, calls delete helper |

### Discarded Candidates (medium/low confidence)
| Address | Candidate | Reason |
|---------|-----------|--------|
| 0x006d3220 | TGStreamStatus__ctor | Called from TGFileStream__ctor with NiAlloc(0x14), but unclear if it's a status object or general error tracker |
| 0x006d21a0 | TGFileStream__WriteRawData | Appears to write raw bytes but calling convention unclear |
| 0x006d31a0 | TGFileStream__GetPosition | Reads position but could be tell or ftell wrapper |
| 0x005ad4d0 | Ship__ApplyTurnRate | Initially considered but behavior clearly matches TurnTowardDifference |
| 0x0046f380 | TGTimer__ctor | Initializes timer-like object at +0x00..+0x28, vtable 0x0088bb14, but not enough context |
| 0x0046f720 | TGTimer__SetInterval | Sets +0x08 field, reinserts into timer list, but naming uncertain |
| 0x005a7cf0 | CollisionQuery__Create | Creates collision query object for spatial search, but class name uncertain |
| 0x005a8320 | CollisionQuery__GetNextResult | Iterator over collision results, but might be SceneQuery |
| 0x005a8350 | CollisionQuery__Destroy | Cleanup, but class uncertain |
| 0x004570d0 | RaySphereIntersect | Line-sphere intersection test, but could be named differently |
| 0x00431030 | TGObject__CompareID | Comparison function for sorted arrays, but could be generic comparator |

### Summary
- **55 successful renames** in Pass 6
- **11 discarded candidates** (medium confidence, insufficient evidence)
- **Total across all passes: ~6,121 functions named (~33.5% of 18,247)**
- **Strategies yielding most results**: SWIG wrapper tracing (22 renames), callee chain walking (20 renames), save system tracing (13 renames)

## Pass 7 (2026-02-23) - 164 renames

### Strategy: Deep SWIG Wrapper Mining (PRIMARY)
Systematic decompilation of SWIG wrappers across 25+ modules. Pattern: `swig_ClassName_Method` -> PyArg_ParseTuple -> SWIG_GetPointerObj -> direct `FUN_xxx()` call = nameable target.

Key insight: ~60% of SWIG wrappers use vtable-indirect calls `(**(code **)(*param + offset))()` which cannot yield callee names. Only direct `FUN_xxx()` calls are nameable.

### TGModelManager (3 renames, from previous session)
| # | Address | Old Name | New Name |
|---|---------|----------|----------|
| 33 | 0x006c39a0 | FUN_006c39a0 | TGModelManager__Unrefer |
| 34 | 0x006c3e20 | FUN_006c3e20 | TGModelManager__GetCamera |
| 35 | 0x006c4010 | FUN_006c4010 | TGModelManager__ClearIncrementalLoadQueue |

### TGSound (22 renames)
| # | Address | Old Name | New Name |
|---|---------|----------|----------|
| 36 | 0x005d92f0 | FUN_005d92f0 | TGSound__ctor |
| 37 | 0x0070b730 | FUN_0070b730 | TGSound__Load |
| 38 | 0x0070ba10 | FUN_0070ba10 | TGSound__Play |
| 39 | 0x0070bbf0 | FUN_0070bbf0 | TGSound__Stop |
| 40 | 0x0070b930 | FUN_0070b930 | TGSound__Unload |
| 41 | 0x0070bd50 | FUN_0070bd50 | TGSound__AttachToNode |
| 42 | 0x0070b9b0 | FUN_0070b9b0 | TGSound__SetGroup |
| 43 | 0x0070bd00 | FUN_0070bd00 | TGSound__GetStatus |
| 44 | 0x0070ba60 | FUN_0070ba60 | TGSound__PlayAndNotify |
| 45 | 0x0070bcb0 | FUN_0070bcb0 | TGSound__Rewind |
| 46 | 0x0070bcc0 | FUN_0070bcc0 | TGSound__Pause |
| 47 | 0x0070bce0 | FUN_0070bce0 | TGSound__Unpause |
| 48 | 0x0070bd90 | FUN_0070bd90 | TGSound__DetachFromNode |
| 49 | 0x0070bdf0 | FUN_0070bdf0 | TGSound__GetParentNode |
| 50 | 0x0070c0b0 | FUN_0070c0b0 | TGSound__SetVolume |
| 51 | 0x0070c170 | FUN_0070c170 | TGSound__SetPitch |
| 52 | 0x0070c1b0 | FUN_0070c1b0 | TGSound__GetPitch |
| 53 | 0x0070bf00 | FUN_0070bf00 | TGSound__SetPosition |
| 54 | 0x0070c2a0 | FUN_0070c2a0 | TGSound__Update |
| 55 | 0x0070c270 | FUN_0070c270 | TGSound__GetDurationSeconds |
| 56-64 | (9 more) | | TGSound__SetEndEvent thru ClearFadePoints |

### Engine Subsystems (4 renames)
| # | Address | New Name |
|---|---------|----------|
| 65 | 0x00561050 | ImpulseEngineSubsystem__ctor |
| 66 | 0x0056de70 | WarpEngineSubsystem__ctor |
| 67 | 0x0056e7d0 | WarpEngineSubsystem__TransitionToState |
| 68 | 0x0057b020 | TorpedoSystem__ctor |

### BridgeObjectClass (2 renames)
| # | Address | New Name |
|---|---------|----------|
| 69 | 0x006641c0 | BridgeObjectClass__CreateEffect |
| 70 | 0x00664880 | BridgeObjectClass__GoToRedAlert |

### Network (2 renames)
| # | Address | New Name |
|---|---------|----------|
| 71 | 0x006b9bb0 | TGWinsockNetwork__SetPortNumber |
| 72 | 0x006ba160 | TGWinsockNetwork__BanPlayerByIP |

### TGScriptAction (2 renames)
| # | Address | New Name |
|---|---------|----------|
| 73 | 0x006ff6e0 | TGScriptAction__ctor |
| 74 | 0x006ff940 | TGScriptAction__AddParam |

### Timer/Event (3 renames)
| # | Address | New Name |
|---|---------|----------|
| 75 | 0x006dc3f0 | TGTimerManager__AddTimer |
| 76 | 0x006dc470 | TGTimerManager__DeleteTimer |
| 77 | 0x006db590 | TGEventHandlerTable__RemoveAllHandlersForObject |

### TGSoundManager (10 renames)
| # | Address | New Name |
|---|---------|----------|
| 78 | 0x0070f400 | TGSoundManager__Reload |
| 79 | 0x0070fcd0 | TGSoundManager__PlaySound |
| 80 | 0x0070fd00 | TGSoundManager__StopSound |
| 81 | 0x0070fe70 | TGSoundManager__StopAllSounds |
| 82 | 0x0070ff40 | TGSoundManager__DeleteSound |
| 83 | 0x0070fbb0 | TGSoundManager__GetSound |
| 84 | 0x007100a0 | TGSoundManager__DeleteAllSounds |
| 85 | 0x0070fc10 | TGSoundManager__GetPlayingSound |
| 86 | 0x00710140 | TGSoundManager__DeleteAllSoundsInGroup |
| 87 | 0x0070feb0 | TGSoundManager__StopAllSoundsInGroup |

### Strategy 4: Previously Discarded (4 renames)
| # | Address | New Name | Justification |
|---|---------|----------|---------------|
| 88 | 0x004570d0 | RaySphereIntersect | Clear ray-sphere math, returns 0/1/2 |
| 89 | 0x005a7cf0 | CollisionQuery__Execute | Complex sweep-and-prune collision |
| 90 | 0x005a8320 | CollisionQuery__GetNextResult | Iterator over collision results |
| 91 | 0x005a8350 | CollisionQuery__Destroy | Cleanup/free function |

### TGPoint3 Math (5 renames)
| # | Address | New Name |
|---|---------|----------|
| 92 | 0x0045c1a0 | TGPoint3__Cross |
| 93 | 0x00581e60 | TGPoint3__UnitCross |
| 94 | 0x0045e8d0 | TGPoint3__MultMatrix |
| 95 | 0x00811b10 | TGPoint3__LoadBinary |
| 96 | 0x00811b50 | TGPoint3__SaveBinary |

### TGString (5 renames)
| # | Address | New Name |
|---|---------|----------|
| 97 | 0x006f4260 | TGString__Find |
| 98 | 0x006f41e0 | TGString__FindC |
| 99 | 0x006f4450 | TGString__Compare |
| 100 | 0x006f43e0 | TGString__CompareC |
| 101 | 0x006f47c0 | TGString__SetString |

### TGMatrix3 (9 renames)
| # | Address | New Name |
|---|---------|----------|
| 102 | 0x00459e60 | TGMatrix3__Inverse |
| 103 | 0x0045b3a0 | TGMatrix3__FromEulerAnglesXYZ |
| 104 | 0x0045a8e0 | TGMatrix3__EigenSolveSymmetric |
| 105 | 0x0045a590 | TGMatrix3__Congruence |
| 106-110 | (5 more) | TGMatrix3__FromEulerAngles{XZY,YXZ,YZX,ZXY,ZYX} |

### TGTimer (1 rename)
| 111 | 0x006dd270 | TGTimer__SetEvent |

### CharacterClass (20 renames)
| # | Address | New Name |
|---|---------|----------|
| 112 | 0x0066c020 | CharacterClass__SayLine |
| 113 | 0x0066b680 | CharacterClass__MoveTo |
| 114 | 0x0066be00 | CharacterClass__PlayAnimation |
| 115 | 0x0066c200 | CharacterClass__Blink |
| 116 | 0x0066b3d0 | CharacterClass__SetLocation |
| 117 | 0x0066bd10 | CharacterClass__Breathe |
| 118 | 0x0066b760 | CharacterClass__GlanceAt |
| 119 | 0x0066b840 | CharacterClass__GlanceAway |
| 120 | 0x0066a7f0 | CharacterClass__ClearAnimations |
| 121 | 0x0066c7f0 | CharacterClass__SetCharacterName |
| 122 | 0x0066cb90 | CharacterClass__AddSoundToQueue |
| 123 | 0x0066ae50 | CharacterClass__ClearAnimationsOfType |
| 124 | 0x0066ae90 | CharacterClass__SetAnimationDoneEvent |
| 125 | 0x0066aef0 | CharacterClass__SetCurrentAnimation |
| 126 | 0x0066ada0 | CharacterClass__SetBlinkAnimation |
| 127 | 0x0066beb0 | CharacterClass__PlayAnimationFile |
| 128 | 0x0066b610 | CharacterClass__SetLocationName |
| 129 | 0x0066cf20 | CharacterClass__LookAtMe |
| 130 | 0x00668430 | CharacterClass__ReplaceBodyAndHead |
| 131 | 0x00668f60 | CharacterClass__AddFacialImage |
| 132 | 0x00669050 | CharacterClass__AddPhoneme |
| 133 | 0x0066dc10 | CharacterClass__SetDatabase |
| 134 | 0x00669d10 | CharacterClass__SetStatus |
| 135 | 0x00669cc0 | CharacterClass__GetStatus |

### SensorSubsystem (1 rename)
| 136 | 0x005678b0 | SensorSubsystem__ForceObjectIdentified |

### CloakingSubsystem (1 rename)
| 137 | 0x0055f560 | CloakingSubsystem__InstantDecloak |

### TGEvent (3 renames)
| # | Address | New Name |
|---|---------|----------|
| 138 | 0x006d6270 | TGEvent__SetSource |
| 139 | 0x006d62b0 | TGEvent__SetDestination |
| 140 | 0x006d6810 | TGEvent__Duplicate |

### STMenu (1 rename)
| 141 | 0x00525ce0 | STMenu__ForceUpdate |

### ObjectClass (4 renames)
| # | Address | New Name |
|---|---------|----------|
| 142 | 0x00435220 | ObjectClass__PlaceObjectByName |
| 143 | 0x00435f90 | ObjectClass__ReplaceTexture |
| 144 | 0x00436080 | ObjectClass__RefreshReplacedTextures |
| 145 | 0x00435ec0 | ObjectClass__LineCollides |

### SetClass (3 renames)
| # | Address | New Name |
|---|---------|----------|
| 146 | 0x0040f920 | SetClass__DeleteObjectFromSet |
| 147 | 0x00412e50 | SetClass__DeleteCameraFromSet |
| 148 | 0x004139e0 | SetClass__GetDotProductToObject |

### CameraObjectClass (2 renames)
| # | Address | New Name |
|---|---------|----------|
| 149 | 0x0042acd0 | CameraObjectClass__PushCameraMode |
| 150 | 0x0042bcb0 | CameraObjectClass__LookToward |

### Nebula / STButton (2 renames)
| 151 | 0x00599290 | Nebula__IsObjectInNebula |
| 152 | 0x00519f30 | STButton__SetColorBasedOnFlags |

### TopWindow (11 renames)
| # | Address | New Name |
|---|---------|----------|
| 153 | 0x0050da30 | TopWindow__ToggleBridgeAndTactical |
| 154 | 0x0050d830 | TopWindow__ToggleCinematicWindow |
| 155 | 0x0050d7e0 | TopWindow__ToggleConsole |
| 156 | 0x0050d4d0 | TopWindow__ToggleMapWindow |
| 157 | 0x0050d890 | TopWindow__ToggleEditMode |
| 158 | 0x0050e220 | TopWindow__Initialize |
| 159 | 0x0050d8d0 | TopWindow__ForceBridgeVisible |
| 160 | 0x0050d980 | TopWindow__ForceTacticalVisible |
| 161 | 0x0050e070 | TopWindow__FadeIn |
| 162 | 0x0050dea0 | TopWindow__AbortCutscene |
| 163 | 0x0050e0e0 | TopWindow__AbortFade |
| 164 | 0x0050d550 | TopWindow__ShowBadConnectionText |

### Modules Exhausted (vtable-only or inline field accesses)
- TGBufferStream (35 wrappers): ALL vtable-indirect calls
- ShipProperty (24): ALL inline field accessors
- SubsystemProperty (21): ALL inline field accessors or func_0x
- PoweredSubsystem (15): ALL vtable calls or already-named callees
- PowerSubsystem (23): ALL already-named callees
- ShieldClass (20): ALL already-named or inline field reads
- TractorBeamSystem (4): ALL inline field access
- TGPane (26): ALL vtable calls
- STMenu (48): ALL vtable calls except ForceUpdate
- STButton (30): mostly vtable or func_0x
- ShipClass (75): Most call already-named functions or use vtable/inline

### Discarded Candidates
| Address | Candidate Name | Reason |
|---------|---------------|--------|
| func_0x00666ee0 | CharacterClass__AddAnimation | func_0x not a defined function in Ghidra |
| func_0x0066c7c0 | CharacterClass__SetName | func_0x not a defined function |
| func_0x0066c1e0 | CharacterClass__SetStanding | func_0x not a defined function |
| func_0x0066ae10 | CharacterClass__SetActive | func_0x not a defined function |
| func_0x0066ab00 | CharacterClass__AddRandomAnimation | func_0x not a defined function |
| func_0x00667e10 | CharacterClass__MorphBody | func_0x not a defined function |
| func_0x0066a720 | CharacterClass__GetCharacterFromMenu | func_0x not a defined function |
| func_0x00669f70 | CharacterClass__ClearStatus | func_0x not a defined function |
| func_0x0066c530 | CharacterClass__AddPositionZoom | func_0x not a defined function |
| func_0x0048cd50 | PlainAI__SetScriptModule | func_0x not a defined function |
| func_0x00567960 | SensorSubsystem__ScanAllObjects | func_0x not a defined function |
| func_0x00567010 | SensorSubsystem__AddProbe | func_0x not a defined function |
| func_0x0056a9c0 | ShieldClass__RedistributeShields | func_0x not a defined function |
| func_0x0056aad0 | ShieldClass__GetOppositeShield | func_0x not a defined function |
| func_0x006a2830 | MPGame__DeleteObjectFromGame | func_0x not a defined function |
| func_0x006a2750 | MPGame__DeletePlayerShipsAndTorps | func_0x not a defined function |
| func_0x006a2720 | MPGame__IsPlayerInGame | func_0x not a defined function |
| func_0x006a2a00 | MPGame__IsPlayerUsingModem | func_0x not a defined function |
| func_0x005b0780 | Ship__CompleteStop | func_0x not a defined function |
| func_0x00412b10 | SetClass__CreateCamera | func_0x not a defined function |
| func_0x004133d0 | SetClass__CreateDirectionalLight | func_0x not a defined function |
| func_0x00413350 | SetClass__CreateAmbientLight | func_0x not a defined function |
| func_0x0050dc90 | TopWindow__StartCutscene | func_0x not a defined function |
| func_0x0050df00 | TopWindow__FadeOut | func_0x not a defined function |
| func_0x0050de70 | TopWindow__EndCutscene | func_0x not a defined function |
| func_0x00519ce0 | STButton__SetJustification | func_0x not a defined function |
| func_0x00598380 | Nebula__SetupDamage | func_0x not a defined function |
| func_0x005b0780 | Ship__CompleteStop | func_0x not a defined function |
| func_0x0060b1b0 | Ship__GetTargetAngVelocityTG | func_0x not a defined function |

### Statistics
- **164 successful renames** in Pass 7
- **29 discarded candidates** (all func_0x addresses not defined as functions in Ghidra)
- **~25 SWIG modules explored**, 17+ yielded at least 1 rename
- **Highest yield modules**: TGSound (22), CharacterClass (24), TopWindow (11), TGSoundManager (10)
- **Total across all passes: ~6,285 functions named (~34.4% of 18,247)**

## Pass 8C (2026-02-24) - TGEventManager & Event Dispatch System - 61 renames + 6 globals

### Method
Deep-dive of the TGEventManager, TGEventHandlerTable, TGConditionHandler, TGCallback, and supporting
infrastructure. Started from known named functions, followed all unnamed callees through the full
event dispatch chain: PostEvent -> DispatchToBroadcastHandlers -> DispatchEvent -> InvokeCallback.

### TGEventHandlerTable (10 new)
| Address | Name | Description |
|---------|------|-------------|
| 0x006d5850 | TGEventHandlerTable__RegisterObject | Create handler chain for object in global table |
| 0x006d8230 | TGEventHandlerTable__FindHandlerChain | Hash table lookup for event type |
| 0x006d8270 | TGEventHandlerTable__FindHandlerInParentChain | Walk parent chain to find handler |
| 0x006d82b0 | TGEventHandlerTable__RemoveAllHandlers | Iterate all buckets, remove handlers |
| 0x006d83e0 | TGEventHandlerTable__DispatchToNextHandler | Walk chain, invoke via TGConditionHandler |
| 0x006daf70 | TGEventHandlerTable__SaveBroadcastHandlers | Serialize broadcast handler table |
| 0x006db020 | TGEventHandlerTable__LoadBroadcastHandlers | Deserialize broadcast handler table |
| 0x006db1b0 | TGEventHandlerTable__FixupBroadcastRefs | Fixup broadcast handler object references |
| 0x006db230 | TGEventHandlerTable__FixupBroadcastComplete | Complete broadcast handler reference fixup |
| 0x006db670 | TGEventHandlerTable__ClearBroadcastHandlers | Remove and free all broadcast handler chains |

### TGInstanceHandlerTable (5 new)
Per-object handler table (0x25 buckets hash table, lives at TGEventHandlerObject+0x10).
| Address | Name | Description |
|---------|------|-------------|
| 0x006d7b30 | TGInstanceHandlerTable__ctor | Create hash table (0x25 buckets) |
| 0x006d7b80 | TGInstanceHandlerTable__dtor | Destroy hash table |
| 0x006d7c30 | TGInstanceHandlerTable__SaveToStream | Serialize handler chains |
| 0x006d7d00 | TGInstanceHandlerTable__LoadFromStream | Deserialize handler chains |
| 0x006d7eb0 | TGInstanceHandlerTable__AddHandler | Add callback for event type |

### TGCallback (8 new)
0x14-byte object (vtable 0x008960f4). Wraps C++ function pointer or Python callable.
Fields: +0x00=vtable, +0x04=flags(bit0=isMethod,bit1=isPython,bit2=active,bit3=pendingDelete), +0x08=nextChain, +0x0C=sentinel, +0x10=funcPtr/string
| Address | Name | Description |
|---------|------|-------------|
| 0x006e09e0 | TGCallback__ctor | Initialize 5 fields |
| 0x006e0a00 | TGCallback__dtor | Restore vtable, free string |
| 0x006e0a10 | TGCallback__FreeString | Free owned string at +0x10 |
| 0x006e0d40 | TGCallback__InvokePythonFunction | Import module.func, call |
| 0x006e0e00 | TGCallback__SetFunctionByName | Named C++ function (string copy) |
| 0x006e0e70 | TGCallback__SetFunctionByHash | Lookup by hash in name table |
| 0x006e0ec0 | TGCallback__SetIsPythonCallback | Set/clear bit 1 |
| 0x006e0ee0 | TGCallback__SetIsMethodCallback | Set/clear bit 0 |

### TGConditionHandler (16 new)
Manages sorted handler arrays with binary search. Vtable 0x00896104. Two arrays: broadcast (this+0x00) and per-object (this+0x18). Supports deferred add/remove during dispatch (reentrant).
| Address | Name | Description |
|---------|------|-------------|
| 0x006e1870 | TGConditionHandler__ctor | Allocate two sorted arrays |
| 0x006e1900 | TGConditionHandler__dtor | Free sorted arrays |
| 0x006e1960 | TGConditionHandler__SaveHandlerEntries | Serialize entries with object IDs |
| 0x006e1a30 | TGConditionHandler__LoadHandlerEntries | Deserialize, rebuild sorted array |
| 0x006e1c00 | TGConditionHandler__FixupReferences | Resolve object IDs to pointers |
| 0x006e1c50 | TGConditionHandler__FixupComplete | Complete reference fixup |
| 0x006e1cd0 | TGConditionHandler__AddEntry | Create node, insert sorted |
| 0x006e1d60 | TGConditionHandler__InsertSorted | Insert with sort key |
| 0x006e1ed0 | TGConditionHandler__RemoveByName | Find and remove by name hash |
| 0x006e2030 | TGConditionHandler__MatchEntry | Compare by object + name |
| 0x006e20b0 | TGConditionHandler__RemoveAllForObject | Remove all for given object |
| 0x006e2310 | TGConditionHandler__RemoveAllEntries | Iterate all, remove each |
| 0x006e2330 | TGConditionHandler__FindInsertionPoint | Binary search for index |
| 0x006e2380 | TGConditionHandler__FindFirstByKey | Binary search for first match |
| 0x006e23f0 | TGConditionHandler__RemoveAtIndex | Remove at specific index |
| 0x006e24d0 | TGConditionHandler__SetAtIndex | Set with active-count tracking |
| 0x006e25a0 | TGConditionHandler__Resize | Reallocate sorted array |

### TGHandlerListEntry (3 new)
0xC-byte linked list node: +0x00=objectPtr, +0x04=callbackPtr, +0x08=deleted
| Address | Name | Description |
|---------|------|-------------|
| 0x006e2f60 | TGHandlerListEntry__ctor | Zero 3 fields |
| 0x006e2f70 | TGHandlerListEntry__dtor | Destroy callback, free |
| 0x006e2f90 | TGHandlerListEntry__GetObjectID | Get object ID from chain |

### TGEvent Infrastructure (2 new)
| Address | Name | Description |
|---------|------|-------------|
| 0x006d63a0 | TGEvent__LookupInEventTable | Lookup by objID in g_pTGEventObjectTable |
| 0x006d63f0 | TGEvent__RegisterInEventTable | Register in g_pTGEventObjectTable hash table |

### TGLinkedList (2 new)
| Address | Name | Description |
|---------|------|-------------|
| 0x006d6f80 | TGLinkedList__Pop | Pop front from singly-linked list |
| 0x006d7100 | TGDoublyLinkedList__Remove | Remove node (head/tail/mid) |

### TGEventQueue (6 new)
| Address | Name | Description |
|---------|------|-------------|
| 0x006de1d0 | TGEventQueue__SaveToStream | Serialize queue |
| 0x006de240 | TGEventQueue__LoadFromStream | Deserialize queue |
| 0x006de280 | TGEventQueue__FixupReferences | Resolve references |
| 0x006de2c0 | TGEventQueue__FixupComplete | Complete fixup |
| 0x006de310 | TGEventQueue__Clear | Dequeue all events |
| 0x006dee60 | TGEventQueue__ctor_inner | Init (head=0, tail=0, count=0) |

### Other (9 new)
| Address | Name | Description |
|---------|------|-------------|
| 0x006d9330 | TGEventHandlerObject__EnsureInstanceTable | Lazy-init per-object table |
| 0x006da3d0 | TGHandlerNameTable__Register | Register name + hash |
| 0x006da450 | TGHandlerNameTable__LookupByHash | Lookup function by hash |
| 0x006dc240 | TGTimerManager__ctor | Stores event mgr at +0x08 |
| 0x006dc5d0 | TGTimerManager__Init | Sets +0x04=0 |
| 0x006f8bd0 | TG_CallPythonFunctionSimple | Wrapper: no-safe, no-decref |
| 0x006f8c00 | TG_CallPythonFunctionEx | With safe-call + decref control |
| 0x006f8cf0 | TG_CallPythonMethod | Call method on Python object |

### Globals (6 new)
| Address | Name | Description |
|---------|------|-------------|
| 0x0097f838 | g_TGEventManager | TGEventManager singleton |
| 0x009983a4 | g_pTGEventObjectTable | Event tracking hash table |
| 0x009983a8 | g_pTGEventHandlerTable | Global handler table (0xFB buckets) |
| 0x00998638 | g_TGHandlerNameTable | Handler name registry |
| 0x0095adfc | g_pTGEvent_NullTarget | Null-target sentinel |
| 0x0095adf8 | g_pTGEvent_BroadcastMarker | Broadcast marker sentinel |

### Rejected Candidates
None - all 61 renames were high-confidence based on decompiled code analysis.

### Architecture Insights
**TGEventManager Layout (size ~0x40):**
- +0x00..+0x0B: Primary event queue (head, tail, count) - synchronous events
- +0x0C..+0x17: Secondary event queue (deferred events)
- +0x18..+0x2B: Instance handler table (per-object handlers)
- +0x2C..+0x3F: Broadcast handler table (global handlers)

**Event Dispatch Flow:**
1. `PostEvent` checks destination object; if valid, calls ProcessEvent vtable slot (+0x50)
2. If event is not private (bit 1 of +0x18), dispatches to broadcast handlers at +0x2C
3. If event is logged (bit 0 of +0x18), enqueues for deferred processing
4. `ProcessEvents` drains queue: dequeue -> increment refcount -> PostEvent -> Release

**Handler Registration:** Two levels:
- **Broadcast handlers** via TGEventManager::RegisterHandler -> global table at +0x2C
- **Instance handlers** via TGEventHandlerObject::AddPythonFuncHandler -> per-object table at +0x10

**TGCallback dispatch:** Checks bit 1 (isPython):
- C++ callback: direct function pointer call, with or without handler object parameter
- Python callback: getattr method or import+call function, via safe-call wrapper

### Statistics
- **61 successful renames + 6 globals** in Pass 8C
- **Total across all passes: ~6,346 functions named (~34.8% of 18,247)**

## Pass 8A (2026-02-24) - Multiplayer Handler Callees - 38 renames

### Method
Systematic decompilation of all 15 multiplayer game dispatcher handler functions (opcodes 0x02-0x2A),
identifying unnamed callees (FUN_XXXXXXXX) in each handler and tracing them to determine purpose.
Additionally followed the PyErr_PrintEx call chain deep into statically-linked Python C API.

### Game-Specific Functions (9 renames)
| Address | Name | Evidence |
|---------|------|----------|
| 0x00423480 | NiPoint3__Copy | Copies 3 floats (12 bytes) between NiPoint3 structs |
| 0x004166d0 | WString__Clear | Clear/reset MSVC basic_string<unsigned short> buffer |
| 0x00416bc0 | WString__AssignSubstring | Assign substring from another WString (offset+length) |
| 0x00459cb0 | NiMatrix3__TransformPoint | 3x3 matrix * vector rotation |
| 0x0055c690 | TGDisplayTextAction__ctor_tgl | Floating text ctor from TGL resource entry |
| 0x0055c790 | TGDisplayTextAction__ctor_string | Floating text ctor from C string |
| 0x006cf6a0 | TGBufferStream__vReadInt | 2-instruction vtable dispatch: MOV EAX,[ECX]; JMP [EAX+0x68] |
| 0x006d04f0 | TGLManager__ReleaseFile | Decrement refcount on loaded TGL file |
| 0x006d30e0 | TGBufferStream__ReadCompressedVector4_ByteScale | Read 4 bytes + decompress with custom scale |

### Python C API Functions (29 renames)
Statically-linked Python 1.5.2 C API functions, traced from PyErr_PrintEx call chain.
| Address | Name |
|---------|------|
| 0x0074af10 | PyErr_Print |
| 0x0074af20 | PyErr_PrintEx |
| 0x0074b490 | PyErr_ParseSyntaxError |
| 0x0074bb10 | Py_HandleSystemExit |
| 0x0074bc90 | PyObject_Print |
| 0x0074bdb0 | PyObject_Repr |
| 0x0074be20 | PyObject_Str |
| 0x0074c100 | PyObject_Hash |
| 0x0074c200 | PyObject_SetAttr |
| 0x0074c7c0 | PyInt_AsLong |
| 0x00751b80 | PyString_InternFromString |
| 0x00751cf0 | PyDict_GetItem |
| 0x00752cd0 | PyDict_GetItemString |
| 0x00752d10 | PyDict_SetItemString |
| 0x00752d70 | PyDict_DelItemString |
| 0x00752db0 | PyErr_Restore |
| 0x00752e40 | PyErr_SetObject |
| 0x00752e80 | PyErr_SetString |
| 0x00752ec0 | PyErr_Occurred |
| 0x00752ed0 | PyErr_GivenExceptionMatches |
| 0x00752f90 | PyErr_NormalizeException |
| 0x00753110 | PyErr_Fetch |
| 0x00753140 | PyErr_Clear |
| 0x00753150 | PyErr_BadArgument |
| 0x00753230 | PyErr_SetNone |
| 0x00753240 | PyErr_BadInternalCall |
| 0x007506c0 | PyString_FromString |
| 0x007507d0 | PyString_AsString |
| 0x00776c90 | Py_FlushLine |
| 0x00779f90 | PySys_GetObject |
| 0x00779fe0 | PySys_SetObject |
| 0x0077c130 | PyThreadState_Get |
| 0x007835d0 | PyFile_SoftSpace |
| 0x00783690 | PyFile_WriteObject |
| 0x00783800 | PyFile_WriteString |
| 0x00783ce0 | PyTraceBack_Print |

### Rejected Candidates (3)
| Address | Candidate | Reason |
|---------|-----------|--------|
| 0x0057d110 | TorpedoTube__ProcessNetworkFire | Already named TorpedoTube__LaunchLocal |
| 0x00578320 | Torpedo__SetFiringShipID | Already named Torpedo__SetOwnerShipID |
| 0x0069f9e0 | MultiplayerGame__SettingsHandler | Wrongly named — contains torpedo fire code, 0 xrefs, likely Ghidra split artifact |

### Key Discoveries
1. **TGDisplayTextAction** (vtable 0x0088b568): Used by DeletePlayerAnimHandler (0x18) and NewPlayerInGameHandler (0x2A) for floating join/leave text. Two ctor variants: one from TGL resource, one from C string.
2. **Python C API addresses differ from python_capi script**: The annotation script `ghidra_annotate_python_capi.py` has entries at different addresses. The functions renamed here are the actual implementations used at runtime.
3. **MultiplayerGame__SettingsHandler at 0x0069f9e0 is MISNAMED**: Contains torpedo fire code identical to TorpedoFireHandler. Zero xrefs. Ghidra function split artifact — left alone.

### Statistics
- **38 successful renames** (9 game + 29 Python C API)
- **3 rejected candidates**
- **Total across all passes: ~6,384 functions named (~35.0% of 18,247)**

## Pass 8H (2026-02-24) - Cross-Reference Mining - 103 renames

### Strategy
Systematic xref analysis from high-value functions: TGEvent__SetSource, Ship__GetVelocity,
Game__GetPlayerShip, TGEventHandlerObject__CallNextHandler, NiAlloc, TGObject__LookupByID.
For each: get_xrefs_to -> decompile unnamed callers -> name if HIGH confidence.

### Categories and Counts
| Category | Count | Key Functions |
|----------|-------|---------------|
| Weapons Display | 11 | HandleFireButton, HandleCloakButton, UpdateFiringStatus, CycleTorpedoType |
| Sensor/Target Menu | 5 | PopulateItems, HandleTargetSelected, RefreshTargetList |
| Sound System | 5 | CopyFrom, CacheLoad, FileEntry, AllocNodes, RegisterEvent |
| Main Window | 4 | UpdateVisibleNames, ObjectClicked, ObjectEntered, TargetChanged |
| Camera/Trail | 4 | UpdateCameraAnimation, RecordPosition, InterpolateRotation/Position |
| AI Attack | 4 | ctor, BestEvasionDirection, ThreatsAndEvade, PredictTarget |
| Weapons Control Pane | 3 | TorpedoControls, PhaserControls, TractorCloakControls |
| VarManager | 3 | SetName, SetVariable, SetKey |
| TGL System | 3 | AddResource, ReadHeader, ReadEntries |
| Physics | 3 | CheckCollision, IntegrateMotion, WriteToStream |
| NiTimeController/Path | 3 | StartAnimation, BuildPath, ControlPoints |
| Input Manager | 3 | MouseTimestamp, KeyTimestamp, ProcessInput |
| Character/Animation | 3 | dtor, AnimAction ctor/dtor |
| Target Reticle | 3 | Initialize, UpdateLayout, UpdateTargetArrow |
| Other (2 each) | 28 | DamageDisplay, CameraMode, Shields, Torpedo, NiNode, STTimerButton, etc. |
| Singles | 14 | MapWindow, TacWeaponsCtrl, InterfaceModule, WarpEffect, etc. |

### Key Discoveries
- **PhysicsObjectClass__CheckCollision (0x005a88e0)**: Gates on g_SettingsByte1, IsPlayerShip, velocity thresholds
- **AttackAI evasion**: 26-direction search with ProximityManager threat scoring
- **CallNextHandler**: 100 callers — chain-of-responsibility across entire UI
- **NiNode__BuildPropertyState**: Recursive parent-to-child property accumulation

### Rejected Candidates (~15)
- Free-list allocator template instantiations (~8): Identical code, no class distinction
- FixupReferences/ResolveObjectRefs (~7): Generic ID-to-pointer, too many identical patterns

### Statistics
- **103 successful renames** in Pass 8H
- **Total across all passes: ~6,487 functions named (~35.6% of 18,247)**

## Pass 8I (2026-02-24) - Mission/Episode/Game Class Hierarchies - 29 renames

### Strategy
Deep-dive of high-level game flow classes: MissionBase, Episode, Mission, PlayWindow ("Game" in SWIG),
MultiplayerGame, MultiplayerWindow, STMissionLog, LoadMissionAction, LoadEpisodeAction.
Methods: constructor decompilation for vtable/hierarchy, SWIG wrapper target tracing, RegisterHandlerNames
misname correction pattern (discover_strings systematic error).

### Class Hierarchy Discovered
```
TGEventHandlerObject (base)
  -> MissionBase (vtable at ctor, +0x14=moduleName, +0x1C=type, +0x28=flag, +0x2C/0x30/0x34=zeroed)
       -> Episode (vtable 0x00888738, size 0x44, type 0x808001)
            +0x38=unknown, +0x3C=currentMission(Mission*), +0x40=completionEvent
       -> Mission (size 0x60, +0x4C=2, +0x50-0x5C=ObjectGroups)
       -> PlayWindow (vtable 0x008887e8, size 0x74, type 0x804001) = "Game" in SWIG API
            +0x38=score, +0x3C=rating, +0x40=kills, +0x50=lastSavedGame, +0x54=playerShip,
            +0x58=playerGroup, +0x5C=playerCamera, +0x60=godMode, +0x62=initialized,
            +0x64=preLoadDoneEvent, +0x68=pendingEvent, +0x6C=terminateEvent, +0x70=episode
            -> MultiplayerGame (vtable 0x0088b480, +0x74=playerSlots[16], +0x1F8=readyForNewPlayers, +0x1FC=maxPlayers)

TGAction -> TGScriptAction
  -> LoadMissionAction (vtable 0x008886d8, size 0x34, +0x2C=game, +0x30=episode)
  -> LoadEpisodeAction (vtable 0x008885dc, size 0x2C)

MainWindow -> TGScrollablePane
  -> PlayViewWindow (vtable 0x0088e344, 0x004fc480) -- NOT the same as PlayWindow!
```

### TWO PlayWindow Classes (CRITICAL DISAMBIGUATION)
- PlayWindow at 0x00405c10 (MissionBase subclass) = "Game" object in SWIG API, manages game state
- PlayViewWindow at 0x004fc480 (MainWindow/TGScrollablePane subclass) = UI rendering area
- These are COMPLETELY DIFFERENT classes that happened to share the name "PlayWindow" in Ghidra

### RegisterHandlerNames Misname Pattern (SYSTEMATIC)
The discover_strings script (Pass 7/8) assigns debug string references to functions. When a function
calls `TGObject__RegisterHandlerWithName(handlerAddr, "Class::HandlerName")`, the script names the
CALLING function after the handler string, not the handler itself. This produced systematic misnames.

**Correction rule**: Functions calling RegisterHandlerWithName = "RegisterHandlerNames" (name registration).
Functions calling RegisterEventHandler = "RegisterHandlers" (actual event binding).
The `_B` suffix in prior passes often indicates the TRUE RegisterHandlers (uses RegisterEventHandler).

### Corrections of Misnamed Functions (8 renames)
| # | Address | Old Name | New Name | Evidence |
|---|---------|----------|----------|----------|
| 1 | 0x00406a30 | Game__DestroyedPlayer | PlayWindow__RegisterHandlerNames | Calls RegisterHandlerWithName for 8 handlers |
| 2 | 0x00406a90 | Game__ReallyTerminate | PlayWindow__RegisterHandlers | Calls RegisterEventHandler |
| 3 | 0x00404730 | Episode__LoadMissionHandler | Episode__RegisterHandlerNames | Calls RegisterHandlerWithName |
| 4 | 0x00404760 | Episode__ReportGoalInfoHandler | Episode__RegisterHandlers | Calls RegisterEventHandler |
| 5 | 0x00408720 | Mission__PlayerDied | Mission__RegisterHandlerNames | Calls RegisterHandlerWithName |
| 6 | 0x0069f250 | MultiplayerGame__KillGameHandler | MultiplayerGame__RegisterMPHandlers | Calls RegisterEventHandler for KillGame+RetryConnect |
| 7 | 0x0069f9e0 | MultiplayerGame__SettingsHandler | MultiplayerGame__TorpedoFireHandler_Relay | Contains torpedo relay code, Ghidra function split artifact |
| 8 | 0x005046b0 | MultiplayerWindow__ReceiveMessageHandler | MultiplayerWindow__RegisterHandlerNames | Calls RegisterHandlerWithName for 9 handlers |

### STMissionLog Corrections (4 renames)
| # | Address | Old Name | New Name | Evidence |
|---|---------|----------|----------|----------|
| 9 | 0x00528e10 | STMissionLog__RegisterHandlers | STMissionLog__RegisterHandlerNames | Calls RegisterHandlerWithName |
| 10 | 0x00528e50 | STMissionLog__RegisterHandlers_B | STMissionLog__RegisterHandlers | Calls RegisterEventHandler |
| 11 | 0x00529170 | FUN_00529170 | STMissionLog__Close | Unpauses game, hides self, called from RegisterHandlerNames |
| 12 | 0x00528c20 | FUN_00528c20 | STMissionLog__AddLine | Called from swig_STMissionLog_AddLine |

### STMissionLog SWIG Targets (2 renames)
| # | Address | Old Name | New Name | Evidence |
|---|---------|----------|----------|----------|
| 13 | 0x00528d70 | FUN_00528d70 | STMissionLog__ClearLines | swig_STMissionLog_ClearLines target |
| 14 | 0x00528b70 | FUN_00528b70 | STMissionLog__SetNumStoredLines | swig_STMissionLog_SetNumStoredLines target |

### New PlayWindow Names (8 renames)
| # | Address | Old Name | New Name | Evidence |
|---|---------|----------|----------|----------|
| 15 | 0x004062d0 | FUN_004062d0 | PlayWindow__ReallyTerminate | Actual game termination: calls MissionBase__Terminate, FreeAllModels, "GameEnded", "ResetViewscreen" |
| 16 | 0x00406770 | FUN_00406770 | PlayWindow__SetUIShipID | SWIG Game_SetUIShipID target |
| 17 | 0x00406640 | FUN_00406640 | PlayWindow__SetLastSavedGame | SWIG Game_SetLastSavedGame target |
| 18 | 0x004062b0 | FUN_004062b0 | PlayWindow__TerminateWithEvent | Called from PlayWindow__ReallyTerminate, sets +0x6C terminate event |
| 19 | 0x00406d80 | FUN_00406d80 | PlayWindow__WriteToStream | Save serialization: writes score/rating/kills/etc |
| 20 | 0x00407070 | FUN_00407070 | PlayWindow__ResolveIDs | Stream fixup: resolves object IDs to pointers |
| 21 | 0x004070f0 | FUN_004070f0 | PlayWindow__RestoreIDsToPointers | Final fixup phase |
| 22 | 0x00405a90 | FUN_00405a90 | PlayWindow__InitHandlerTable | Initializes handler table entries |

### PlayViewWindow Disambiguation (2 renames)
| # | Address | Old Name | New Name | Evidence |
|---|---------|----------|----------|----------|
| 23 | 0x004fc480 | PlayWindow__ctor | PlayViewWindow__ctor | MainWindow subclass (UI), NOT MissionBase subclass |
| 24 | 0x004fc5e0 | FUN_004fc5e0 | PlayViewWindow__ctor_stream | Stream constructor for same class |

### Action/Mission/Episode (5 renames)
| # | Address | Old Name | New Name | Evidence |
|---|---------|----------|----------|----------|
| 25 | 0x00403460 | FUN_00403460 | LoadMissionAction__ctor | Sets vtable 0x008886d8, size 0x34 |
| 26 | 0x004027d0 | FUN_004027d0 | LoadEpisodeAction__ctor | Sets vtable 0x008885dc, size 0x2C |
| 27 | 0x00409270 | FUN_00409270 | Mission__PlayerChangedHandler | Event handler for player ship changed |
| 28 | 0x00409170 | FUN_00409170 | Mission__PlayerExitedSetHandler | Event handler for player exiting set |
| 29 | 0x0043d8b0 | FUN_0043d8b0 | Episode__ctor_stream | Stream constructor for Episode |

### Other (already counted above)
| # | Address | Old Name | New Name |
|---|---------|----------|----------|
| -- | 0x00442940 | FUN_00442940 | MultiplayerGame__scalar_deleting_dtor |

### Failed Renames (no function defined at address)
| Address | Intended Name | Reason |
|---------|---------------|--------|
| 0x00404a60 | Episode__RemoveGoal | func_0x, orphan code, not a Ghidra function |
| 0x004047e0 | Episode__GetNextEventType | func_0x, not a Ghidra function |
| 0x00408410 | Mission__AddPrecreatedShip | func_0x, not a Ghidra function |
| 0x004085b0 | Mission__GetPrecreatedShip | func_0x, not a Ghidra function |
| 0x00408cd0 | Mission__GetNextEventType | func_0x, not a Ghidra function |
| 0x006a2720 | MultiplayerGame__IsPlayerInGame | func_0x, not a Ghidra function |
| 0x006a2a00 | MultiplayerGame__IsPlayerUsingModem | func_0x, not a Ghidra function |
| 0x006a2750 | MultiplayerGame__DeletePlayerShipsAndTorps | func_0x, not a Ghidra function |
| 0x006a2830 | MultiplayerGame__DeleteObjectFromGame | func_0x, not a Ghidra function |
| 0x00506b80 | MultiplayerWindow__IsAnyChildVisible | func_0x, not a Ghidra function |
| 0x004067e0 | PlayWindow__SetDifficulty | func_0x, not a Ghidra function |
| 0x00406820 | PlayWindow__SetDifficultyMultipliers | func_0x, not a Ghidra function |
| 0x00406cd0 | PlayWindow__GetNextEventType | func_0x, not a Ghidra function |
| 29 LAB_ addresses | MultiplayerGame handler addresses | All 29 handler addresses from RegisterHandlerNames (LAB_006a0c60 through LAB_006a2a40) are orphan code blocks, not function starts |

### Rejected Candidates (not renamed)
| Address | Candidate | Reason |
|---------|-----------|--------|
| Various SWIG wrappers | ~40 Game/Episode/Mission accessors | Inline field reads (e.g., `param_2[0xf]` for +0x3C), no separate C++ function to name |
| 0x00406250 | MissionBase__OnIdle | Already named by prior pass |
| Various `_B` suffixed | EngPowerCtrl, Editor, etc. | Same misname pattern found but OUT OF SCOPE for game flow classes (future pass target) |
| 0x004a2950 | unknown_cleanup | Walks hash table, destroys objects — unclear class ownership |
| 0x0058c180 | unknown_cleanup | Walks array, calls vtable dtor — unclear class ownership |

### MultiplayerGame Handler Address Map (from RegisterHandlerNames)
All 29 registered handlers, with the debug string name and code address. These are LAB_/DAT_
addresses in Ghidra (orphan code, not functions), so they cannot be renamed via MCP API.
Documented here for future Ghidra manual function creation.

| LAB/DAT Address | Debug Name | Notes |
|-----------------|-----------|-------|
| 0x006a0c60 | SystemChecksumPassedHandler | LAB_ |
| 0x006a0c90 | SystemChecksumFailedHandler | DAT_ |
| 0x006a0ca0 | DeletePlayerHandler | LAB_ |
| 0x006a0f90 | ObjectCreatedHandler | LAB_ |
| 0x006a1150 | HostEventHandler | LAB_ |
| 0x006a1240 | ObjectExplodingHandler | LAB_ |
| 0x006a1590 | NewPlayerInGameHandler | LAB_ |
| 0x006a1790 | StartFiringHandler | LAB_ |
| 0x006a17a0 | StartWarpHandler | LAB_ |
| 0x006a17b0 | TorpedoTypeChangeHandler | LAB_ |
| 0x006a18d0 | StopFiringHandler | LAB_ |
| 0x006a18e0 | StopFiringAtTargetHandler | LAB_ |
| 0x006a18f0 | StartCloakingHandler | LAB_ |
| 0x006a1900 | StopCloakingHandler | LAB_ |
| 0x006a1910 | SubsystemStatusHandler | LAB_ |
| 0x006a1920 | AddToRepairListHandler | LAB_ |
| 0x006a1930 | ClientEventHandler | LAB_ |
| 0x006a1940 | RepairListPriorityHandler | LAB_ |
| 0x006a1970 | SetPhaserLevelHandler | LAB_ |
| 0x006a1a60 | DeleteObjectHandler | DAT_ |
| 0x006a1a70 | ChangedTargetHandler | LAB_ |
| 0x006a0a10 | ExitedWarpHandler | DAT_ |
| 0x006a2640 | KillGameHandler | LAB_ |
| 0x006a2a40 | RetryConnectHandler | LAB_ |

Additionally, 5 handlers that ARE defined as functions in Ghidra and already named:
- MultiplayerGame__ReceiveMessage (registered as "ReceiveMessageHandler")
- MultiplayerGame__EnterSetEventHandler (registered as "DisconnectHandler")
- MultiplayerGame__NewPlayerHandler (registered as "NewPlayerHandler")
- MultiplayerGame__ChecksumCompleteHandler (registered as "ChecksumCompleteHandler")
- MultiplayerGame__RequestObjEventHandler (registered as "EnterSetHandler")

### Known Remaining Misnames (OUT OF SCOPE, future pass)
The RegisterHandlerNames pattern exists in ~15 more classes with `_B` suffix:
- EngPowerCtrl__RegisterHandlers should be EngPowerCtrl__RegisterHandlerNames
- EngRepairPane__RegisterHandlers should be EngRepairPane__RegisterHandlerNames
- Editor__RegisterHandlers should be Editor__RegisterHandlerNames
- STMenu__RegisterHandlers should be STMenu__RegisterHandlerNames
- STSubPane__RegisterHandlers should be STSubPane__RegisterHandlerNames
- And ~10 more (STComponentMenu, STLoadDialog, STNumericBar, STSaveDialog, STStylizedWindow, STSubsystemMenu, etc.)

### Statistics
- **29 successful renames** in Pass 8I (8 corrections + 21 new)
- **~13 failed renames** (func_0x addresses not defined as Ghidra functions)
- **29 orphan handler addresses documented** for future manual function creation
- **~15 out-of-scope misnames identified** for future correction pass
- **Total across all passes: ~6,516 functions named (~35.7% of 18,247)**

## Pass 8J (2026-02-24) - Weapon/Projectile Class Hierarchy - 86 renames

### Strategy
Deep-dive of weapon and projectile class hierarchies: Torpedo (projectile entity), TorpedoTube,
TorpedoSystem, PhaserBank, PhaserSystem, EnergyWeapon, PulseWeapon, TractorBeam, WeaponSystem,
WeaponSubsystem, FiringChain, WeaponTargetEntry. For each: decompile ctor/vtable, trace lifecycle
(creation -> firing -> hit detection -> damage), name serialization (Read/WriteToStream, Read/WriteState),
identify helper functions (arc checking, damage scaling, guidance).

### Class Hierarchy (confirmed from vtable analysis)
```
ShipSubsystem
  -> WeaponSubsystem (0x583280, +0x8C=target, +0x9C=enabled)
       -> EnergyWeapon (0x56f950, +0xA0=charge, +0xBC=chargeRatio)
            -> PhaserBank (0x570d70, +0x11C-0x124=restPos, 0x128 size)
            -> TractorBeam (0x581350, +0xFC=mode)
            -> PulseWeapon (0x574fd0, +0xC8/CC/D0 fields)
       -> TorpedoTube (0x57c4b0, +0xA0=ammoLoaded, +0xA4=reloadTimer, +0xAC=readySlots)

PoweredSubsystem -> WeaponSystem (0x5840a0, +0xC4=targetList, +0xDC=firingChains, +0xB4=lastFired)
  -> PhaserSystem (0x573c90, +0xF0=powerLevel)
  -> TorpedoSystem (0x57b020, +0x114=ammoType)
  -> TractorBeamSystem (0x582080, powerMode=1)
  -> PulseWeaponSystem (0x5773b0)

PhysicsObjectClass -> Torpedo (0x5783d0, 0x170 bytes, vtable 0x00893458)
  +0x108=subObject, +0x118=targetID, +0x128=ownerShipID
  +0x134=turnRateScale, +0x138=maxSpeed, +0x144=damageRadius
  +0x14C=isDumbFire, +0x148=hasSkewFire

FiringChain: bitmask-based (32-bit, group indices 1-31)
WeaponTargetEntry: [objectID, offsetX, offsetY, offsetZ] (16 bytes)
```

### Renames by Class

#### Torpedo (8 renames)
| Address | Name |
|---------|------|
| 0x00578800 | Torpedo__OrientToVelocity |
| 0x00578cb0 | Torpedo__UpdateGuidance |
| 0x00579530 | Torpedo__ApplyTorque |
| 0x00579610 | Torpedo__ComputeSplineTurnTime |
| 0x00579a30 | Torpedo__GetVelocity |
| 0x00579a90 | Torpedo__SetClampedAngularAcceleration |
| 0x00579cc0 | Torpedo__WriteNetworkState |

#### TorpedoTube (14 renames)
| Address | Name |
|---------|------|
| 0x00574f40 | TorpedoTube__GetArcHeightAngleMin |
| 0x00574f50 | TorpedoTube__GetArcHeightAngleMax |
| 0x00574f60 | TorpedoTube__GetArcWidthAngleMin |
| 0x00574f70 | TorpedoTube__GetArcWidthAngleMax |
| 0x00574f80 | TorpedoTube__GetArcHeightAngleRange |
| 0x00574fa0 | TorpedoTube__GetArcWidthAngleRange |
| 0x00574fc0 | TorpedoTube__GetLaunchSpeed |
| 0x00575230 | TorpedoTube__GetDamageForPowerLevel |
| 0x00575a60 | TorpedoTube__IsTargetInFiringArc |
| 0x00575db0 | TorpedoTube__ComputeRandomDirectionInArc |
| 0x0057c740 | TorpedoTube__ClearReadySlots |
| 0x0057de90 | TorpedoTube__GetWorldDirection |
| 0x0057df40 | TorpedoTube__WriteToStream |
| 0x0057dfd0 | TorpedoTube__ReadFromStream |

#### TorpedoSystem (3 renames)
| Address | Name |
|---------|------|
| 0x0057b780 | TorpedoSystem__WriteToStream |
| 0x0057b7b0 | TorpedoSystem__ReadFromStream |
| 0x0057b8e0 | TorpedoSystem__ResolveObjectRefs |

#### EnergyWeapon (11 renames)
| Address | Name |
|---------|------|
| 0x0056f8d0 | EnergyWeapon__GetProperty |
| 0x0056f8e0 | EnergyWeapon__GetRechargeRate |
| 0x0056f920 | EnergyWeapon__GetFireSoundBase |
| 0x0056f930 | EnergyWeapon__GetMaxDamage |
| 0x0056f940 | EnergyWeapon__GetMaxCharge |
| 0x0056fbd0 | EnergyWeapon__SetPropertyAndInit |
| 0x0056fd70 | EnergyWeapon__UpdateChargeLevel |
| 0x0056fdc0 | EnergyWeapon__Update |
| 0x0056fe30 | EnergyWeapon__WriteToStream |
| 0x0056feb0 | EnergyWeapon__ReadFromStream |
| 0x0056ff40 | EnergyWeapon__ResolveObjectRefs |
| 0x0056ff60 | EnergyWeapon__FixupObjectRefs |

#### PhaserBank (12 renames)
| Address | Name |
|---------|------|
| 0x0056fc10 | PhaserBank__GetFireStartSoundName |
| 0x0056fcc0 | PhaserBank__GetFireLoopSoundName |
| 0x005714a0 | PhaserBank__ComputeFiringArcToTarget |
| 0x00571a00 | PhaserBank__CanFireAtTarget |
| 0x00571ab0 | PhaserBank__ComputeBeamEndpoint |
| 0x00571ee0 | PhaserBank__IsAngleInFiringArc |
| 0x00572b00 | PhaserBank__GetDischargeRateForPowerLevel |
| 0x00572c50 | PhaserBank__GetArcCenterWorldDir |
| 0x00572f00 | PhaserBank__ComputeRestPosition |
| 0x00573040 | PhaserBank__WriteToStream |
| 0x005730a0 | PhaserBank__ReadFromStream |

#### PhaserSystem (3 renames)
| Address | Name |
|---------|------|
| 0x00574010 | PhaserSystem__StopFiringAtTarget |
| 0x005741a0 | PhaserSystem__WriteState |
| 0x005741d0 | PhaserSystem__ReadState |

#### PulseWeapon (2 renames)
| Address | Name |
|---------|------|
| 0x005769a0 | PulseWeapon__WriteToStream |
| 0x005769f0 | PulseWeapon__ReadFromStream |

#### TractorBeam (10 renames)
| Address | Name |
|---------|------|
| 0x0057fcd0 | TractorBeam__ApplyMode0_Drag |
| 0x0057ff60 | TractorBeam__ApplyMode1_Push |
| 0x00580590 | TractorBeam__ApplyMode2_Hold |
| 0x00580740 | TractorBeam__ApplyMode3_Repel |
| 0x00580910 | TractorBeam__ApplyMode5_Dock |
| 0x00580d70 | TractorBeam__InitBeamAndStartFiring |
| 0x00580e90 | TractorBeam__SetBeamEndpoints |
| 0x00580f50 | TractorBeam__ComputeDamageForBeam |
| 0x005814f0 | TractorBeam__WriteToStream |
| 0x00581550 | TractorBeam__ReadFromStream |

#### WeaponSubsystem (2 renames)
| Address | Name |
|---------|------|
| 0x00583400 | WeaponSubsystem__WriteToStream |
| 0x00583440 | WeaponSubsystem__ReadFromStream |

#### WeaponSystem (16 renames)
| Address | Name |
|---------|------|
| 0x00584070 | WeaponSystem__GetSingleFireMode |
| 0x00584390 | WeaponSystem__StartFiringAtTarget |
| 0x00584560 | WeaponSystem__StopFiringAll |
| 0x005847d0 | WeaponSystem__Update |
| 0x00585020 | WeaponSystem__ParseFiringChains |
| 0x005852a0 | WeaponSystem__GetTargetWorldPosition |
| 0x00585390 | WeaponSystem__RemoveTarget |
| 0x005856b0 | WeaponSystem__OnDisabled |
| 0x005856d0 | WeaponSystem__BuildVisibleTargetList |
| 0x005859d0 | WeaponSystem__IsTargetVisible |
| 0x00585a10 | WeaponSystem__WriteState |
| 0x00585a40 | WeaponSystem__ReadState |
| 0x00585a70 | WeaponSystem__WriteToStream |
| 0x00585b80 | WeaponSystem__ReadFromStream |
| 0x00585f40 | WeaponSystem__GetTargets_Py |

#### WeaponTargetEntry (2 renames)
| Address | Name |
|---------|------|
| 0x00585ec0 | WeaponTargetEntry__WriteToStream |
| 0x00585f00 | WeaponTargetEntry__ReadFromStream |

#### FiringChain (3 renames)
| Address | Name |
|---------|------|
| 0x00586220 | FiringChain__GetFirstGroupIndex |
| 0x00586250 | FiringChain__GetNextGroupIndex |
| 0x00586280 | FiringChain__WriteToStream |

#### Misc (3 renames)
| Address | Name |
|---------|------|
| 0x004068c0 | GetDifficultyDamageScale |
| 0x005965f0 | ForceVector__Init |
| 0x00586c50 | TGPoolAllocator__Init |

### Rejected Candidates
| Address | Candidate | Reason |
|---------|-----------|--------|
| 0x0056fdf0 | EnergyWeapon__GetFiringArcRatio | Already correctly named EnergyWeapon__GetChargePercentage |
| 0x0056f8a0 | EnergyWeapon__DynCast | Dynamic cast to 0x802b - too generic |
| 0x00574f00 | PulseWeapon__DynCast | Dynamic cast to 0x802d - too generic |
| 0x0057ea60 | TractorBeam__DynCast | Dynamic cast to 0x802e - too generic |
| 0x0057ea90 | TractorBeam__GetPropertyPtr | Simple +0x18 getter, too trivial |
| 0x00570eb0 | PhaserBank__scalar_deleting_dtor | Standard dtor pattern |
| 0x0057c5c0 | TorpedoTube__scalar_deleting_dtor | Standard dtor pattern |
| 0x0057b140 | TorpedoSystem__scalar_deleting_dtor | Standard dtor pattern |
| 0x00584240 | WeaponSystem__scalar_deleting_dtor | Standard dtor pattern |
| 0x005750e0 | PulseWeapon__scalar_deleting_dtor | Standard dtor pattern |
| 0x00573100 | PhaserBank__ctor_alternate | Alternate ctor with different vtable 0x893228, uncertain |
| ~50 FUN_ addresses | Various thunks, static initializers | FUN_00855f23/FUN_008594e4/FUN_00856fd1 thunks, TGInstanceHandlerTable__ctor statics |

### Key Weapon System Insights
1. **Torpedo homing**: PredictPositionAtTime for lead targeting + clamped angular acceleration = smooth pursuit curves
2. **Phaser power levels**: 3 levels (0/1/2) each with different discharge rate constants at 0x893170/74/78
3. **FiringChain bitmask**: 32-bit mask parsed from string "123:456" format, groups weapons into fire sequences
4. **Tractor 6 modes**: 0=drag, 1=push, 2=hold, 3=repel, 4=push-variant, 5=dock (cut content partially)
5. **WeaponHitEvent (0x60 bytes)**: Carries position, normal, damage, weapon type (0=phaser, 1=torpedo), firing player
6. **Difficulty damage scaling**: 3 levels via GetDifficultyDamageScale (0x004068c0)
7. **Client non-player recharge**: PhaserBank__UpdateCharge recharges at 2x rate for client non-player ships

### Statistics
- **86 successful renames** in Pass 8J (across 2 sessions)
- **~12 rejected candidates** (dynamic casts, dtors, thunks, one misidentification)
- **Total across all passes: ~6,602 functions named (~36.2% of 18,247)**

## Pass 8D (2026-02-24) - UI System Classes - 135 renames

### Classes Touched (20 UI classes)
TGPane(21), TGUIObject(16), TGRootPane(12), TGWindow(5), STWidget(7), STMenu(13),
MultiplayerWindow(11), TopWindow(7), MainWindow(6), TGIcon(7), TGTextBlock(4),
TGParagraph(3), TGDialogWindow(4), STStylizedWindow(4), BridgeWindow(2),
CinematicWindow(2), NamedReticleWindow(2), ModalDialogWindow(1), STButton(1),
STToggle(1), PlayWindow(1), TacticalWindow(1), SortedRegionMenuWindow(1),
TGRect(2), Misc(1)

### TGPane Base (21)
0x0072de40 TGPane__dtor, 0x0072e000 TGPane__KillChildren, 0x0072e060 TGPane__Render,
0x0072e0a0 TGPane__Update, 0x0072e5b0 TGPane__RemoveChild, 0x0072e6c0 TGPane__DeleteChild,
0x0072e7e0 TGPane__SetFocus, 0x0072e920 TGPane__MoveToFront, 0x0072e970 TGPane__MoveToBack,
0x0072eac0 TGPane__MoveTowardsBack, 0x0072ec60 TGPane__GetFocusLeaf,
0x0072ec80 TGPane__InvalidateAllChildPolys, 0x0072ecb0 TGPane__SetClipRectOnChildren,
0x0072ece0 TGPane__BuildPolyList, 0x0072ed80 TGPane__GetNthChild,
0x0072edd0 TGPane__GetFirstVisibleChild, 0x0072eeb0 TGPane__SetNotVisibleRecursive,
0x0072ef50 TGPane__SetEnabledRecursive, 0x0072efa0 TGPane__ClearDirtyAndLayoutChildren,
0x0072f060 TGPane__WriteToStream, 0x0072f0e0 TGPane__ReadFromStream

### TGUIObject Base (16)
0x0072fd70 TGUIObject__dtor, 0x0072fe00 TGUIObject__ClearCallbackList,
0x0072fe40 TGUIObject__GetConceptualParent, 0x0072fed0 TGUIObject__SetEnabled,
0x0072ff10 TGUIObject__SetDisabled, 0x0072ff30 TGUIObject__SetBounds,
0x0072ff80 TGUIObject__GetScreenOffset, 0x0072ffc0 TGUIObject__GetClipRect,
0x007300e0 TGUIObject__Move, 0x007302f0 TGUIObject__SetPosition,
0x007305d0 TGUIObject__AlignTo, 0x00731030 TGUIObject__WriteToStream,
0x007310a0 TGUIObject__ReadFromStream, 0x00731120 TGUIObject__ResolveIDs,
0x00730b80 TGUIObject__GetRenderTarget, 0x00730df0 TGUIObject__IsFocused

### TGRootPane (12)
0x00727620 ctor, 0x00727760 scalar_dtor, 0x00727840 dtor, 0x007278a0 DestroyAll,
0x00727920 DestroyCursor, 0x00727940 CreateTooltip, 0x00727a10 ReleaseCursor,
0x00727b30 SetMouseCursor, 0x00727e30 RestorePreviousCursor, 0x00727ee0 PushCursor,
0x00727fa0 PopCursor, 0x00728720 UnregisterFocus

### MultiplayerWindow (11)
0x00504360 Cast, 0x00504530 scalar_dtor, 0x00504560 dtor, 0x00505480 HideAllChildren,
0x00505500 WriteToStream, 0x00505660 ReadFromStream, 0x00505770 ResolveIDs,
0x00505880 RestoreIDsToPointers, 0x00505d70 ButtonSelectionHandler,
0x00506910 InitClientUI, 0x00506eb0 SetVisible

### TopWindow (7)
0x0050e110 IsBridgeVisible, 0x0050e130 IsTacticalVisible, 0x0050e170 SetLastRenderedSet,
0x0050e190 GetLastRenderedSet, 0x0050e630 WriteToStream, 0x0050e7c0 ReadFromStream,
0x0050e910 ClearGlobal

### MainWindow (6)
0x0050ea00 scalar_dtor, 0x0050ea30 ToggleVisibility, 0x0050eab0 IsCurrentWindow,
0x0050eb00 SetVisibleWithFocus, 0x0050f480 AddToObjectList, 0x0050f590 RemoveFromObjectList

### TGIcon (7), TGTextBlock (4), TGParagraph (3), TGDialogWindow (4)
See full tables in detailed notes above.

### Rejected Candidates (10)
1. LAB_0072e3a0/0072e3d0 - code labels, not functions
2. 17+ TopWindow__RegisterHandlers LABs - same issue
3. FUN_007322b0, 00732420 - rendering internals
4. FUN_00739f00, 00739fc0 - generic rect utilities
5. FUN_00739e20, 007309e0 - no-op stubs

### Key Findings
- **UI hierarchy**: TGEventHandlerObject -> TGUIObject -> TGPane -> (TGWindow, STWidget, TGIcon...)
- **MainWindow type IDs**: 0=Bridge, 1=Tactical, 2=Console, 5=Play, 7=StarMap, 8=MP, 9=PlayView, 10=Cinematic
- **Event types**: 0x800494-498 (input toggles), 0x8000B6-BA (resolution), 0x8000CE-D1 (dialogs)
- **TGDialogWindow button flags**: bitfield for OK/Cancel/Yes/No/Abort/Retry/Continue/Ignore
- **TGUIObject flags (+0x28)**: 0x08=visible, 0x80=dirty, 0x100=hidden, 0x200=disabled

### Statistics
- **135 successful renames** in Pass 8D
- **2 failed renames** (LAB_ addresses)
- **10 rejected candidates**
- **Total across all passes: ~6,737 functions named (~36.9% of 18,247)**

## Pass 8E (2026-02-24) - Subsystem Class Hierarchy Virtual Methods - 45 renames

### Overview
Deep-dive into the ShipSubsystem class hierarchy, mapping vtable layouts, identifying overrides,
and fixing several misnamed functions from prior annotation passes. Produced comprehensive vtable
documentation at `subsystem-vtable-map.md`.

### Class Hierarchy Discovered
```
TGEventHandlerObject (vtable 0x00896044, 22 slots)
  ShipSubsystem (vtable 0x00892fc4, 30 slots)
    PoweredSubsystem (vtable 0x00892d98, 34 slots)
      ShieldSubsystem (0x00892f34) | ImpulseEngineSubsystem (0x00892d10) |
      WarpEngineSubsystem (0x00893040) | SensorSubsystem (0x00892eac) |
      RepairSubsystem (0x00892e24) | CloakingSubsystem (0x00892c04)
      WeaponSystem (vtable 0x008938c4, 55 slots)
        PhaserSystem (0x00893240) | TorpedoSystem (0x00893598) |
        TractorBeamSystem (0x00893794) | PulseWeaponSystem (0x008933b0)
      PoweredMaster (0x0088a1f0) [EPS system]
    PowerSubsystem (0x00892c98) [reactor, NOT PoweredSubsystem]
    WeaponSubsystem (0x00893834)
      PhaserSubsystem/EnergyWeapon (0x008930d8)
        PulseWeapon (0x00893318)
```

### Critical Naming Corrections (5 misnames fixed)
| Old Name | New Name | Evidence |
|----------|----------|----------|
| ShieldProperty__SetPower | ShipSubsystem__SetParentShip | SWIG SetParentShip at vtable+0x58 |
| ShieldSubsystem__SetPowerLevel | PoweredSubsystem__SetParentShip | Override of slot 22 |
| Subsystem__IsActive | ShipSubsystem__IsTargetable | SWIG IsTargetable confirms |
| ShieldProperty__GetCurrentPower | ShipSubsystem__GetDisabledPercentage | SWIG confirms |
| ShieldSubsystem__ReadState | ShieldSubsystem__WriteState_B | Decompiled: writes, not reads |

### New Function Names (40 renames)
**ShipSubsystem base (7):**
0x0056bb60 ScalarDeletingDtor, 0x0056b920 GetPosition, 0x0056d170 ResolveObjectRefs,
0x0056d1f0 FixupObjectRefs, ShipSubsystem__SetPropertyAndRestoreHP -> SetProperty,
Subsystem__GetRadius -> GetRadius, Subsystem__GetChild -> GetChild

**CloakingSubsystem (6):**
0x0055e2b0 ctor, 0x0055fa30 WriteToStream, 0x0055faa0 ReadFromStream,
0x0055f970 WriteState_A, 0x0055f9a0 ReadState_A, 0x0055f930 TurnOff, 0x0055e500 Update

**ShieldSubsystem (3):**
0x0056a160 ScalarDeletingDtor, 0x0056acc0 ResolveObjectRefs, 0x0056ad00 FixupObjectRefs

**WarpEngineSubsystem (3):**
0x0056ed40 WriteToStream, 0x0056ee20 ReadFromStream, 0x0056dfa0 ScalarDeletingDtor

**ImpulseEngineSubsystem (3):**
0x005616a0 WriteToStream, 0x00561710 ReadFromStream, 0x00561140 ScalarDeletingDtor

**RepairSubsystem (2):**
0x00565e80 ReadFromStream, 0x00565190 ScalarDeletingDtor

**SensorSubsystem (1):**
0x00566e20 ScalarDeletingDtor

**WeaponSubsystem (2):**
0x005833e0 Update, 0x005833a0 ScalarDeletingDtor

**WeaponSystem (2):**
0x00584240 ScalarDeletingDtor, 0x00573ea0 PhaserSystem__StartFiringAtTarget

**TractorBeamSystem (3):**
0x00582710 WriteToStream, 0x00582780 ReadFromStream, 0x00582170 ScalarDeletingDtor

**TorpedoSystem (1):**
0x0057b140 ScalarDeletingDtor

**PulseWeaponSystem (1):**
0x00577480 ScalarDeletingDtor

**PulseWeapon (1):**
0x005750e0 ScalarDeletingDtor

**PhaserSubsystem (1):**
0x0056fb30 ScalarDeletingDtor

**PoweredSubsystem (1):**
0x00562330 ScalarDeletingDtor

**PoweredMaster (2):**
0x004401d0 ScalarDeletingDtor, 0x00563f00 WriteToStream

### Rejected Candidates
- ~15-20 vtable entries point to undefined code (Ghidra auto-analysis didn't create functions)
  Examples: 0x00561180 (ImpulseEngine Update), 0x005652a0 (Repair Update), 0x005670b0 (Sensor Update)
  These need `createFunction` before renaming, which is outside rename scope.
- PhaserSystem__StopFiringAtTarget already named by prior pass (rename returned "failed" but name was correct)

### Key Vtable Slot Map (ShipSubsystem, 30 slots)
| Slot | Offset | Method |
|------|--------|--------|
| 0 | 0x00 | ScalarDeletingDtor |
| 4-5 | 0x10-0x14 | WriteToStream / ReadFromStream |
| 6-7 | 0x18-0x1C | ResolveObjectRefs / FixupObjectRefs |
| 20 | 0x50 | ProcessEvent |
| 21 | 0x54 | GetPosition |
| 22 | 0x58 | SetParentShip |
| 24 | 0x60 | SetProperty |
| 25 | 0x64 | Update |
| 26-29 | 0x68-0x74 | WriteState_A / ReadState_A / WriteState_B / ReadState_B |

PoweredSubsystem adds slots 30-33: GetNormalPowerWanted(0x78), TurnOn(0x7C), TurnOff(0x80), unk(0x84)
WeaponSystem adds slots 34-54 (weapon virtuals, StartFiringAtTarget=34, StopFiringAll=36)

### Statistics
- **45 successful renames** in Pass 8E (5 corrections + 40 new)
- **3 decompiler comments** added to vtable data addresses
- **~15-20 undefined vtable entries** noted but not renameable
- **Full documentation**: subsystem-vtable-map.md
- **Total across all passes: ~6,782 functions named (~37.2% of 18,247)**

## Pass 8B (2026-02-24) - Ship Vtable Mining - 23 renames

### Strategy
Mine the Ship class vtable (0x00894340, 92 slots) by tracing full TG inheritance chain,
reading all 92 vtable entries, cross-referencing parent vtables, and decompiling identifiable functions.

### Key Discovery
TG hierarchy uses DIFFERENT vtable layout from NiObject: slot 0 = scalar_deleting_dtor (NOT GetRTTI).
Ship does NOT inherit from NiObject. Chain: TGObject -> TGStreamedObject -> TGStreamedObjectEx ->
TGEventHandlerObject -> TGSceneObject -> ObjectClass -> PhysicsObjectClass -> DamageableObject -> Ship.
DamageableObject: 90 slots; Ship adds 2 (90-91).

### Renames (23 across 8 classes)

**TGObject (2):** InvokePythonHandler(0x006f15c0, slot 8), DebugPrint(0x006f1650, slot 3)
**TGStreamedObject (2):** WriteToStreamChain(0x006f2750, slot 12), AddEventHandler(0x006f3400, slot 14)
**TGStreamedObjectEx (1):** PostDeserialize(0x006f2810, slot 7)
**TGEventHandlerObject (2):** HandleEvent(0x006d9240, slot 20), RegisterConditionHandler(0x006da4e0)
**TGSceneObject (3):** Update(0x00430cf0, slot 21), SetScene(0x00430e20, slot 22), ResolveObjectRefs(0x00431e20, slot 6)
**ObjectClass (1):** CreateCollisionProxy(0x004356a0)
**PhysicsObjectClass (4):** SerializeToBuffer(0x005a1cf0, slot 67), DeserializeFromNetwork(0x005a2060), SetTargetObject(0x005a15a0), WriteNetworkState(0x005a1dc0, slot 68, renamed from WriteToStream)
**DamageableObject (6):** RayIntersect(0x00594310), CollisionTest_A(0x00594440), CollisionTest_B(0x005945b0), RegisterEventHandlers(0x00590980), UnregisterEventHandlers(0x005909b0), ctor_stream(0x00590ec0)
**Ship (2 renames):** Ship__AreAllSubsystemObjectsValid -> ResolveObjectRefs(0x005b1500, slot 6), Ship__RebuildSubsystemSerializationList -> PostDeserialize(0x005b1550, slot 7)

### ~40 Unresolvable Vtable Entries
Many entries point to addresses not recognized as functions in Ghidra (small stubs/thunks).

### Documentation
- [docs/engine/tg-hierarchy-vtables.md](../../docs/engine/tg-hierarchy-vtables.md) - Complete Ship vtable map + TG hierarchy layout
- ghidra_annotate_globals.py: Ship section 44->56 entries, all duplicates resolved (2302 unique)

### Statistics
- **23 successful renames** across 8 classes
- **Total across all passes: ~6,805 functions named (~37.3% of 18,247)**

## Pass 8F (2026-02-24) - NetImmerse 3.1 Scene Graph Deep-Dive - 81 renames

Focus: NiStream/NiNode/NiAVObject/NiTimeController/NiTArray/NiBound.
Cross-referenced with Gamebryo 1.2 source (NiTimeController.h/cpp, NiNode.h, NiAVObject.h).

### Summary by Class
- NiObject: 2 (ctor, dtor)
- NiObjectNET: 6 (GetName, GetExtraData, PrependController, RemoveController, dtor, ProcessClone)
- NiAVObject: 9 (SetParent, GetProperty, RemoveProperty, AttachProperty, UpdateEffects, CullAgainstPlanes, TestBoundIntersection x2, GetObjectByName)
- NiNode: 25 (full vtable: ctor/dtor/AttachChild/DetachChild/DetachChildAt/SetAt, traversal, stream I/O, cloning)
- NiDynamicEffect: 2 (AttachAffectedNode, DetachAffectedNode)
- NiTimeController: 8 (dtor, Start, Stop, SetTarget, StartAnimations, StopAnimations, ProcessClone, ItemsInList)
- NiStream: 8 (ctor, dtor, ReadHeader, LoadFromBuffer, PostLinkObjects, HashIndex, CleanupHashTable, GetObjectFromLinkID)
- NiFile/NiMemStream/NiAssetLoader: 5
- NiTArray/NiSmartPtr/NiTList: 18 template instantiations
- NiBound: 8, NiPropertyState/NiDynamicEffectState: 5, NiPoint3/NiMatrix3: 7, Utility: 3

### Key Findings
- **Vtable slot 22 (+0x58) = GetObjectByName** (NOT UpdateWorldData as previously documented)
- **NiObject ctor** was mislabeled NiColorData_ctor; many NiNode methods were NiBezierMesh_* or NiFltAnimationNode_*
- **NiTimeController member layout**: flags+0x08, freq+0x0C, phase+0x10, loKey+0x14, hiKey+0x18, startTime+0x1C, lastTime+0x20, target+0x28, m_spNext+0x2C

### Statistics
- **81 successful renames**, 0 failures, 13 rejected
- **Total across all passes: ~6,886 functions named (~37.7% of 18,247)**
