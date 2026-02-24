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
