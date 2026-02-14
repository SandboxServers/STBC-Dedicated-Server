/* ================================================================
 * Packet Trace System
 *
 * Dedicated log file (packet_trace.log) with:
 * - Session header with timestamp
 * - Direction labels (S->C / C->S)
 * - Peer address tracking
 * - AlbyRules! cipher decryption (game packets shown decrypted)
 * - Known opcode decoding from decrypted data
 * - Full hex+ASCII dumps
 * ================================================================ */
static FILE* g_pPacketLog = NULL;
static volatile LONG g_packetSeq = 0;

/* Peer tracking: map IP:port to a short label */
#define MAX_PEERS 16
static struct {
    DWORD ip;
    WORD  port;
    char  label[32]; /* e.g. "Client#1(192.168.1.5:22101)" */
} g_peers[MAX_PEERS];
static int g_numPeers = 0;

static const char* PktGetPeerLabel(const struct sockaddr_in* sin) {
    static char buf[48];
    int i;
    DWORD ip = sin->sin_addr.s_addr;
    WORD port = sin->sin_port; /* network byte order */
    for (i = 0; i < g_numPeers; i++) {
        if (g_peers[i].ip == ip && g_peers[i].port == port)
            return g_peers[i].label;
    }
    /* New peer - register it */
    if (g_numPeers < MAX_PEERS) {
        i = g_numPeers++;
        g_peers[i].ip = ip;
        g_peers[i].port = port;
        sprintf(g_peers[i].label, "Peer#%d(%d.%d.%d.%d:%d)", i,
                (unsigned char)((char*)&ip)[0], (unsigned char)((char*)&ip)[1],
                (unsigned char)((char*)&ip)[2], (unsigned char)((char*)&ip)[3],
                ntohs(port));
        if (g_pPacketLog) {
            fprintf(g_pPacketLog, "# NEW PEER: %s\n", g_peers[i].label);
            fflush(g_pPacketLog);
        }
        return g_peers[i].label;
    }
    sprintf(buf, "%d.%d.%d.%d:%d",
            (unsigned char)((char*)&ip)[0], (unsigned char)((char*)&ip)[1],
            (unsigned char)((char*)&ip)[2], (unsigned char)((char*)&ip)[3],
            ntohs(port));
    return buf;
}

/* ================================================================
 * "AlbyRules!" Stream Cipher (TGWinsockNetwork encryption)
 *
 * All TGNetwork UDP payloads are encrypted with a custom stream cipher
 * using the hardcoded key "AlbyRules!" (at 0x0095abb4 in stbc.exe).
 * Byte 0 of each UDP packet (direction flag) is NOT encrypted.
 * Reimplemented from FUN_006c2280/006c22f0/006c23c0/006c2490/006c2520.
 * ================================================================ */

typedef struct {
    int  temp_a;
    int  temp_c;
    int  temp_d;
    int  state_a;
    int  running_sum;
    int  key_word[5];
    unsigned int prng_output;
    int  round_counter;
    unsigned int accumulator;
    unsigned char key_string[10];
    int  byte_state;
} BCCipherState;

static const char BC_KEY[10] = {'A','l','b','y','R','u','l','e','s','!'};

static void BC_Reset(BCCipherState *s) {
    memset(s, 0, sizeof(*s));
    memcpy(s->key_string, BC_KEY, 10);
}

static void BC_PRNGStep(BCCipherState *s) {
    int rnd = s->round_counter;
    int kw  = s->key_word[rnd];
    int mix = s->running_sum + rnd;
    int cross1 = mix * 0x4E35;
    int cross2 = kw * 0x15A;
    int new_rsum = s->state_a + cross1 + cross2;
    int new_kw = kw * 0x4E35 + 1;
    s->running_sum = new_rsum;
    s->state_a = cross2;
    s->key_word[rnd] = new_kw;
    s->prng_output = (unsigned int)new_rsum ^ (unsigned int)new_kw;
    s->round_counter = rnd + 1;
}

static void BC_KeySchedule(BCCipherState *s) {
    unsigned char *k = s->key_string;
    s->key_word[0] = (int)((unsigned int)k[0] * 256 + k[1]);
    BC_PRNGStep(s);
    s->accumulator = s->prng_output;

    s->key_word[1] = (int)(((unsigned int)k[2] * 256 + k[3]) ^ (unsigned int)s->key_word[0]);
    BC_PRNGStep(s);
    s->accumulator ^= s->prng_output;

    s->key_word[2] = (int)(((unsigned int)k[4] * 256 + k[5]) ^ (unsigned int)s->key_word[1]);
    BC_PRNGStep(s);
    s->accumulator ^= s->prng_output;

    s->key_word[3] = (int)(((unsigned int)k[6] * 256 + k[7]) ^ (unsigned int)s->key_word[2]);
    BC_PRNGStep(s);
    s->accumulator ^= s->prng_output;

    s->key_word[4] = (int)(((unsigned int)k[8] * 256 + k[9]) ^ (unsigned int)s->key_word[3]);
    BC_PRNGStep(s);
    s->round_counter = 0;
    s->accumulator ^= s->prng_output;
}

static void BC_DecryptPayload(const unsigned char *in, unsigned char *out, int len) {
    BCCipherState s;
    int i, j;
    BC_Reset(&s);
    for (i = 0; i < len; i++) {
        s.byte_state = (int)(signed char)in[i];  /* MOVSX: sign-extend */
        BC_KeySchedule(&s);
        s.byte_state = (int)((unsigned int)s.byte_state
                             ^ (s.accumulator & 0xFF)
                             ^ (s.accumulator >> 8));
        for (j = 0; j < 10; j++)
            s.key_string[j] ^= (unsigned char)s.byte_state;
        out[i] = (unsigned char)s.byte_state;
    }
}

/* Decrypt a full BC UDP packet. Byte 0 (dir flag) is not encrypted. */
static void BC_DecryptPacket(const unsigned char *wire, unsigned char *plain, int len) {
    if (len <= 0) return;
    plain[0] = wire[0];  /* direction flag: 0x01=server, 0x02=client, 0xFF=init */
    if (len > 1)
        BC_DecryptPayload(wire + 1, plain + 1, len - 1);
}

/* ================================================================
 * Packet Decoder - Structured decode of decrypted TGNetwork packets
 *
 * Framing: [dir:1][peer_id:1][sequence:1][messages...]
 * Messages are either raw transport types or 0x32 reliable wrappers.
 * Inside reliable wrappers: [0x32][len][flags][seq_hi][seq_lo][payload]
 * The payload contains game opcodes (0x00-0x1E) or checksum opcodes (0x20-0x27).
 *
 * Implements all compression formats from wire-format-spec.md:
 * - CompressedFloat16 (logarithmic 16-bit float)
 * - CompressedVector3 (3 direction bytes + magnitude)
 * - Bit packing (up to 5 bools per byte)
 * ================================================================ */

/* --- Decoder read cursor --- */
typedef struct {
    const unsigned char* data;
    int len;
    int pos;
    int bitPackPos;  /* position of current bit-pack byte, -1 if none */
    int bitPackIdx;  /* which bit we're on (0-4) */
    int bitPackCount;/* total bits in current pack byte */
} PktCursor;

static void PktCursorInit(PktCursor* c, const unsigned char* data, int len, int startPos) {
    c->data = data;
    c->len = len;
    c->pos = startPos;
    c->bitPackPos = -1;
    c->bitPackIdx = 0;
    c->bitPackCount = 0;
}

static int PktHas(PktCursor* c, int n) { return c->pos + n <= c->len; }

static unsigned char PktReadU8(PktCursor* c) {
    if (c->pos >= c->len) return 0;
    c->bitPackPos = -1; /* reset bit packing on any byte read */
    return c->data[c->pos++];
}

static unsigned short PktReadU16(PktCursor* c) {
    unsigned short v;
    if (c->pos + 2 > c->len) return 0;
    c->bitPackPos = -1;
    v = c->data[c->pos] | (c->data[c->pos + 1] << 8);
    c->pos += 2;
    return v;
}

static unsigned int PktReadU32(PktCursor* c) {
    unsigned int v;
    if (c->pos + 4 > c->len) return 0;
    c->bitPackPos = -1;
    v = c->data[c->pos] | (c->data[c->pos+1]<<8) | (c->data[c->pos+2]<<16) | (c->data[c->pos+3]<<24);
    c->pos += 4;
    return v;
}

static float PktReadFloat(PktCursor* c) {
    union { unsigned int u; float f; } conv;
    conv.u = PktReadU32(c);
    return conv.f;
}

static int PktReadBit(PktCursor* c) {
    unsigned char packed;
    int val;
    if (c->bitPackPos >= 0 && c->bitPackIdx < c->bitPackCount) {
        /* still consuming bits from current pack byte */
        val = (c->data[c->bitPackPos] >> c->bitPackIdx) & 1;
        c->bitPackIdx++;
        return val;
    }
    /* need a new bit-pack byte */
    if (c->pos >= c->len) return 0;
    packed = c->data[c->pos];
    c->bitPackPos = c->pos;
    c->pos++;
    c->bitPackCount = ((packed >> 5) & 7) + 1; /* upper 3 bits = count-1 */
    c->bitPackIdx = 1; /* we're about to return bit 0 */
    return packed & 1;
}

/* --- CompressedFloat16 decoder --- */
static float PktDecodeCompressedFloat16(unsigned short raw) {
    unsigned short mantissa = raw & 0xFFF;
    unsigned char rawScale = (unsigned char)(raw >> 12);
    int isNeg = (rawScale >> 3) & 1;
    unsigned char scale = rawScale & 0x7;
    float rangeLo = 0.0f, rangeHi = 0.001f;
    unsigned char i;
    float result;
    for (i = 0; i < scale; i++) {
        rangeLo = rangeHi;
        rangeHi *= 10.0f;
    }
    result = rangeLo + (mantissa / 4095.0f) * (rangeHi - rangeLo);
    return isNeg ? -result : result;
}

/* --- CompressedVector3 decoder: 3 dir bytes → unit direction --- */
static void PktDecodeDirection(signed char dx, signed char dy, signed char dz,
                               float* outX, float* outY, float* outZ) {
    *outX = (float)dx / 127.0f;
    *outY = (float)dy / 127.0f;
    *outZ = (float)dz / 127.0f;
}

/* --- Opcode name lookup --- */
static const char* PktGameOpcodeName(unsigned char op) {
    switch (op) {
    case 0x00: return "Settings";
    case 0x01: return "GameInit";
    case 0x02: return "ObjCreate";
    case 0x03: return "ObjCreateTeam";
    case 0x04: return "BootPlayer";
    case 0x06: return "PythonEvent";
    case 0x07: return "StartFiring";
    case 0x08: return "StopFiring";
    case 0x09: return "StopFiringAt";
    case 0x0A: return "SubsysStatus";
    case 0x0B: return "EventFwd_DF";
    case 0x0C: return "EventFwd";
    case 0x0D: return "PythonEvent2";
    case 0x0E: return "StartCloak";
    case 0x0F: return "StopCloak";
    case 0x10: return "StartWarp";
    case 0x13: return "HostMsg";
    case 0x14: return "DestroyObj";
    case 0x15: return "Unknown_15";
    case 0x16: return "UISettings";
    case 0x17: return "DeletePlayerUI";
    case 0x18: return "DeletePlayerAnim";
    case 0x19: return "TorpedoFire";
    case 0x1A: return "BeamFire";
    case 0x1B: return "TorpTypeChange";
    case 0x1C: return "StateUpdate";
    case 0x1D: return "ObjNotFound";
    case 0x1E: return "RequestObj";
    case 0x1F: return "EnterSet";
    case 0x29: return "Explosion";
    case 0x2A: return "NewPlayerInGame";
    /* Checksum opcodes */
    case 0x20: return "ChecksumReq";
    case 0x21: return "ChecksumResp";
    case 0x22: return "VersionMismatch";
    case 0x23: return "SysChecksumFail";
    case 0x25: return "FileTransfer";
    case 0x27: return "FileTransferACK";
    case 0x28: return "Unknown_28";
    case 0x2C: return "ChatMessage";
    case 0x35: return "GameState";
    case 0x37: return "PlayerRoster";
    default: return NULL;
    }
}

static const char* PktSubsystemIndexName(unsigned char idx) {
    switch (idx) {
    case 0x00: return "PowerReactor";
    case 0x01: return "RepairSubsystem";
    case 0x02: return "CloakingDevice";
    case 0x03: return "PoweredSubsystem";
    case 0x04: return "LifeSupport";
    case 0x05: return "ShieldGenerator";
    case 0x06: return "TorpedoTube#1";
    case 0x07: return "TorpedoTube#2";
    case 0x08: return "TorpedoTube#3";
    case 0x09: return "TorpedoTube#4";
    case 0x0A: return "TorpedoTube#5";
    case 0x0B: return "TorpedoTube#6";
    case 0x0C: return "PhaserEmitter#1";
    case 0x0D: return "PhaserEmitter#2";
    case 0x0E: return "PhaserEmitter#3";
    case 0x0F: return "PhaserEmitter#4";
    case 0x10: return "PhaserEmitter#5";
    case 0x11: return "PhaserEmitter#6";
    case 0x12: return "PhaserEmitter#7";
    case 0x13: return "PhaserEmitter#8";
    case 0x14: return "ImpulseEngine#1";
    case 0x15: return "ImpulseEngine#2";
    case 0x16: return "ImpulseEngine#3";
    case 0x17: return "ImpulseEngine#4";
    case 0x18: return "WarpDrive";
    case 0x19: return "PhaserController";
    case 0x1A: return "PulseWeapon";
    case 0x1B: return "SensorArray";
    case 0x1C: return "PowerReactor#2";
    case 0x1D: return "TractorBeam#1";
    case 0x1E: return "TractorBeam#2";
    case 0x1F: return "TractorBeam#3";
    case 0x20: return "TractorBeam#4";
    default: return NULL;
    }
}

static const char* PktEventCodeName(unsigned int code) {
    switch (code) {
    case 0x0080006C: return "SubsystemStatusChanged";
    case 0x008000D7: return "StartFiring";
    case 0x008000D9: return "StopFiring";
    case 0x008000DB: return "StopFiringAtTarget";
    case 0x008000DF: return "EventForward_DF";
    case 0x008000E3: return "StartCloaking";
    case 0x008000E5: return "StopCloaking";
    case 0x008000ED: return "StartWarp";
    case 0x008000FD: return "TorpedoTypeChanged";
    default: return NULL;
    }
}

static float PktU32ToFloat(unsigned int raw) {
    union { unsigned int u; float f; } conv;
    conv.u = raw;
    return conv.f;
}

static int PktU32IsFiniteFloat(unsigned int raw) {
    return (raw & 0x7F800000U) != 0x7F800000U;
}

static unsigned int PktReadU32AtLE(const unsigned char* p) {
    return (unsigned int)p[0] |
           ((unsigned int)p[1] << 8) |
           ((unsigned int)p[2] << 16) |
           ((unsigned int)p[3] << 24);
}

static unsigned int PktReadU32AtBE(const unsigned char* p) {
    return ((unsigned int)p[0] << 24) |
           ((unsigned int)p[1] << 16) |
           ((unsigned int)p[2] << 8) |
           (unsigned int)p[3];
}

/* --- Phase 1: Settings (0x00) decoder --- */
static void PktDecodeSettings(FILE* f, PktCursor* c) {
    float gameTime;
    int settings1, settings2;
    unsigned char playerSlot;
    unsigned short mapLen;
    int checksumFlag;
    int i;

    if (!PktHas(c, 4)) { fprintf(f, "      (truncated)\n"); return; }
    gameTime = PktReadFloat(c);
    settings1 = PktReadBit(c);
    settings2 = PktReadBit(c);
    playerSlot = PktReadU8(c);
    mapLen = PktReadU16(c);

    fprintf(f, "      gameTime=%.2f collisionDmg=%d friendlyFire=%d slot=%d",
            gameTime, settings1, settings2, playerSlot);

    if (mapLen > 0 && PktHas(c, mapLen)) {
        fprintf(f, " map=\"");
        for (i = 0; i < mapLen && i < 128; i++)
            fputc(c->data[c->pos + i], f);
        c->pos += mapLen;
        fprintf(f, "\"");
    }
    checksumFlag = PktReadBit(c);
    fprintf(f, " checksumCorrection=%d\n", checksumFlag);
}

/* --- Phase 1: BootPlayer (0x04) decoder --- */
static void PktDecodeBootPlayer(FILE* f, PktCursor* c) {
    unsigned char reason;
    if (!PktHas(c, 1)) return;
    reason = PktReadU8(c);
    fprintf(f, "      reason=%d (%s)\n", reason,
            reason == 2 ? "server full" :
            reason == 3 ? "game in progress" :
            reason == 4 ? "kicked" : "unknown");
}

/* --- Phase 2: State Update (0x1C) decoder --- */
static void PktDecodeStateUpdate(FILE* f, PktCursor* c, int msgEnd) {
    unsigned int objId;
    float gameTime;
    unsigned char flags;
    float px, py, pz;
    int hasHash;
    unsigned short hash;
    signed char dx, dy, dz;
    unsigned short mag;
    float fx, fy, fz, ux, uy, uz;
    float speed;
    unsigned char startIdx, cloakState;

    if (!PktHas(c, 9)) { fprintf(f, "      (truncated)\n"); return; }
    objId = PktReadU32(c);
    gameTime = PktReadFloat(c);
    flags = PktReadU8(c);

    fprintf(f, "      obj=0x%08X t=%.2f flags=0x%02X [", objId, gameTime, flags);
    if (flags & 0x01) fprintf(f, "POS ");
    if (flags & 0x02) fprintf(f, "DELTA ");
    if (flags & 0x04) fprintf(f, "FWD ");
    if (flags & 0x08) fprintf(f, "UP ");
    if (flags & 0x10) fprintf(f, "SPD ");
    if (flags & 0x20) fprintf(f, "SUB ");
    if (flags & 0x40) fprintf(f, "CLK ");
    if (flags & 0x80) fprintf(f, "WPN ");
    fprintf(f, "]\n");

    /* Flag 0x01: Absolute position */
    if (flags & 0x01) {
        if (!PktHas(c, 12)) return;
        px = PktReadFloat(c);
        py = PktReadFloat(c);
        pz = PktReadFloat(c);
        fprintf(f, "        pos=(%.1f, %.1f, %.1f)", px, py, pz);
        hasHash = PktReadBit(c);
        if (hasHash) {
            hash = PktReadU16(c);
            fprintf(f, " subsysHash=0x%04X", hash);
        }
        fprintf(f, "\n");
    }

    /* Flag 0x02: Position delta (CompressedVector4, param4=1 → 5 bytes) */
    if (flags & 0x02) {
        if (!PktHas(c, 5)) return;
        dx = (signed char)PktReadU8(c);
        dy = (signed char)PktReadU8(c);
        dz = (signed char)PktReadU8(c);
        mag = PktReadU16(c);
        PktDecodeDirection(dx, dy, dz, &fx, &fy, &fz);
        speed = PktDecodeCompressedFloat16(mag);
        fprintf(f, "        delta dir=(%.2f,%.2f,%.2f) mag=%.3f\n",
                fx, fy, fz, speed);
    }

    /* Flag 0x04: Forward orientation (CompressedVector3 = 3 bytes dir only) */
    if (flags & 0x04) {
        if (!PktHas(c, 3)) return;
        dx = (signed char)PktReadU8(c);
        dy = (signed char)PktReadU8(c);
        dz = (signed char)PktReadU8(c);
        PktDecodeDirection(dx, dy, dz, &fx, &fy, &fz);
        fprintf(f, "        fwd=(%.2f, %.2f, %.2f)\n", fx, fy, fz);
    }

    /* Flag 0x08: Up orientation (CompressedVector3 = 3 bytes dir only) */
    if (flags & 0x08) {
        if (!PktHas(c, 3)) return;
        dx = (signed char)PktReadU8(c);
        dy = (signed char)PktReadU8(c);
        dz = (signed char)PktReadU8(c);
        PktDecodeDirection(dx, dy, dz, &ux, &uy, &uz);
        fprintf(f, "        up=(%.2f, %.2f, %.2f)\n", ux, uy, uz);
    }

    /* Flag 0x10: Speed (CompressedFloat16) */
    if (flags & 0x10) {
        if (!PktHas(c, 2)) return;
        mag = PktReadU16(c);
        speed = PktDecodeCompressedFloat16(mag);
        fprintf(f, "        speed=%.3f\n", speed);
    }

    /* Flag 0x40: Cloak state (read before 0x20 in the receiver) */
    if (flags & 0x40) {
        cloakState = (unsigned char)PktReadBit(c);
        fprintf(f, "        cloak=%s\n", cloakState ? "ON" : "OFF");
    }

    /* Flag 0x20: Subsystem states (round-robin, variable length) */
    if (flags & 0x20) {
        const char* startName;
        int dataStart;
        int changed;
        int i;
        int bytesRead;
        if (!PktHas(c, 1)) return;
        startIdx = PktReadU8(c);
        startName = PktSubsystemIndexName(startIdx);
        fprintf(f, "        subsystems startIdx=%d", startIdx);
        if (startName) fprintf(f, " (%s)", startName);
        fprintf(f, " data=[");
        dataStart = c->pos;
        bytesRead = 0;
        while (PktHas(c, 1) && bytesRead < 20 && c->pos < msgEnd) {
            fprintf(f, "%02X ", c->data[c->pos]);
            c->pos++;
            bytesRead++;
        }
        fprintf(f, "]\n");

        changed = 0;
        for (i = 0; i < bytesRead; i++) {
            unsigned char b = c->data[dataStart + i];
            if (b != 0xFF) {
                if (!changed) {
                    fprintf(f, "        subsysBytes(non-FF):");
                    changed = 1;
                }
                fprintf(f, " +%d=0x%02X", i, b);
            }
        }
        if (changed) fprintf(f, "\n");

        if (startName) {
            int k;
            fprintf(f, "        subsystemCycle:");
            for (k = 0; k < 6; k++) {
                unsigned char idx = (unsigned char)((startIdx + k) % 0x21);
                const char* nm = PktSubsystemIndexName(idx);
                if (nm) fprintf(f, " %d:%s", idx, nm);
                else fprintf(f, " %d:?", idx);
            }
            fprintf(f, "\n");
        }
    }

    /* Flag 0x80: Weapon states (round-robin, variable length) */
    if (flags & 0x80) {
        int bytesRead = 0;
        fprintf(f, "        weapons data=[");
        while (PktHas(c, 2) && bytesRead < 12 && c->pos < msgEnd) {
            unsigned char wIdx = c->data[c->pos];
            unsigned char wHealth = c->data[c->pos + 1];
            fprintf(f, "%d:%.0f%% ", wIdx, (float)wHealth / 204.0f * 100.0f);
            c->pos += 2;
            bytesRead += 2;
        }
        fprintf(f, "]\n");
    }
}

/* --- Phase 3: Explosion (0x0F) decoder --- */
static void PktDecodeExplosion(FILE* f, PktCursor* c) {
    unsigned int objId;
    signed char dx, dy, dz;
    unsigned short mag;
    unsigned short dmgRaw, radRaw;
    float ix, iy, iz, impactMag, damage, radius;

    if (!PktHas(c, 4 + 5 + 2 + 2)) { fprintf(f, "      (truncated)\n"); return; }
    objId = PktReadU32(c);
    /* CompressedVector4 with uint16 magnitude = 5 bytes */
    dx = (signed char)PktReadU8(c);
    dy = (signed char)PktReadU8(c);
    dz = (signed char)PktReadU8(c);
    mag = PktReadU16(c);
    PktDecodeDirection(dx, dy, dz, &ix, &iy, &iz);
    impactMag = PktDecodeCompressedFloat16(mag);
    ix *= impactMag; iy *= impactMag; iz *= impactMag;

    dmgRaw = PktReadU16(c);
    radRaw = PktReadU16(c);
    damage = PktDecodeCompressedFloat16(dmgRaw);
    radius = PktDecodeCompressedFloat16(radRaw);

    fprintf(f, "      obj=0x%08X impact=(%.1f,%.1f,%.1f) dmg=%.1f radius=%.1f\n",
            objId, ix, iy, iz, damage, radius);
}

/* --- Phase 3: TorpedoFire (0x19) decoder --- */
/* Sender: FUN_0057cb10 TorpedoSystem::SendFireMessage
 * Format: objectId(i32), flags1(u8), flags2(u8 with has_arc, has_target bits),
 *         velocity(cv3), [targetId(i32), impactPoint(cv4)] */
static void PktDecodeTorpedoFire(FILE* f, PktCursor* c) {
    unsigned int objId;
    unsigned char flags1, flags2;
    signed char dx, dy, dz;
    float vx, vy, vz;
    int hasArc, hasTarget;

    if (!PktHas(c, 4)) { fprintf(f, "      (truncated)\n"); return; }
    objId = PktReadU32(c);

    if (!PktHas(c, 2)) return;
    flags1 = PktReadU8(c);
    flags2 = PktReadU8(c);
    hasArc = (flags2 >> 0) & 1;
    hasTarget = (flags2 >> 1) & 1;

    /* velocity (CompressedVector3 = 3 bytes direction) */
    if (!PktHas(c, 3)) return;
    dx = (signed char)PktReadU8(c);
    dy = (signed char)PktReadU8(c);
    dz = (signed char)PktReadU8(c);
    PktDecodeDirection(dx, dy, dz, &vx, &vy, &vz);

    fprintf(f, "      obj=0x%08X flags=0x%02X,0x%02X vel=(%.2f,%.2f,%.2f)",
            objId, flags1, flags2, vx, vy, vz);

    if (hasTarget && PktHas(c, 4)) {
        unsigned int targetId = PktReadU32(c);
        fprintf(f, " target=0x%08X", targetId);
        /* impact point as CompressedVector4 (3 dir bytes + CF16 magnitude) */
        if (PktHas(c, 5)) {
            signed char ix, iy, iz;
            unsigned short mag;
            float ipx, ipy, ipz, impactMag;
            ix = (signed char)PktReadU8(c);
            iy = (signed char)PktReadU8(c);
            iz = (signed char)PktReadU8(c);
            mag = PktReadU16(c);
            PktDecodeDirection(ix, iy, iz, &ipx, &ipy, &ipz);
            impactMag = PktDecodeCompressedFloat16(mag);
            ipx *= impactMag; ipy *= impactMag; ipz *= impactMag;
            fprintf(f, " impact=(%.1f,%.1f,%.1f)", ipx, ipy, ipz);
        }
    }
    if (hasArc) fprintf(f, " +arc");
    fprintf(f, "\n");
}

/* --- Phase 3: BeamFire (0x1A) decoder --- */
/* Sender: FUN_00575480 PhaserSystem::SendFireMessage
 * Format: objectId(i32), flags(u8), targetPos(cv3), moreFlags(u8), [targetId(i32)] */
static void PktDecodeBeamFire(FILE* f, PktCursor* c) {
    unsigned int objId;
    unsigned char flags, moreFlags;
    signed char dx, dy, dz;
    float tx, ty, tz;
    int hasTarget;
    unsigned int targetId;

    if (!PktHas(c, 4)) { fprintf(f, "      (truncated)\n"); return; }
    objId = PktReadU32(c);
    if (!PktHas(c, 1)) return;
    flags = PktReadU8(c);

    /* target position (CompressedVector3 = 3 bytes) */
    if (!PktHas(c, 3)) return;
    dx = (signed char)PktReadU8(c);
    dy = (signed char)PktReadU8(c);
    dz = (signed char)PktReadU8(c);
    PktDecodeDirection(dx, dy, dz, &tx, &ty, &tz);

    if (!PktHas(c, 1)) return;
    moreFlags = PktReadU8(c);
    hasTarget = moreFlags & 1;

    fprintf(f, "      obj=0x%08X flags=0x%02X targetDir=(%.2f,%.2f,%.2f)",
            objId, flags, tx, ty, tz);
    if (hasTarget && PktHas(c, 4)) {
        targetId = PktReadU32(c);
        fprintf(f, " target=0x%08X", targetId);
    }
    fprintf(f, "\n");
}

/* --- Phase 3: Event forward (0x07-0x0B, 0x0E-0x10, 0x1B) decoder --- */
/* These are generic event messages forwarded via FUN_006a17c0/FUN_0069FDA0.
 * Format: objectId(i32) + event-specific payload (variable) */
static void PktDecodeEventForward(FILE* f, PktCursor* c, int msgEnd) {
    unsigned int objId;
    int remaining;
    if (!PktHas(c, 4)) { fprintf(f, "      (truncated)\n"); return; }
    objId = PktReadU32(c);
    remaining = msgEnd - c->pos;
    fprintf(f, "      obj=0x%08X", objId);
    if (remaining > 0) {
        int i;
        fprintf(f, " data=[");
        for (i = 0; i < remaining && i < 32; i++)
            fprintf(f, "%02X ", c->data[c->pos + i]);
        if (remaining > 32) fprintf(f, "...");
        fprintf(f, "] (%d bytes)", remaining);
    }
    fprintf(f, "\n");
    c->pos = msgEnd;
}

/* --- Phase 3: Python message (0x07/0x08) decoder --- */
static void PktDecodePythonMsg(FILE* f, PktCursor* c, int msgEnd) {
    unsigned int eventCode;
    const char* evName;
    int remaining;
    const unsigned char* payload;
    unsigned char pyType;
    unsigned int innerEventLE, innerEventBE;
    const char* innerNameLE;
    const char* innerNameBE;
    unsigned int innerEventBEBase;
    unsigned char pyEventIdx;
    const char* pyEventIdxName;
    int argLen;
    unsigned char arg0Byte;
    int wordCount;
    int maxWords;
    int i;

    if (!PktHas(c, 4)) { fprintf(f, "      (truncated)\n"); return; }
    eventCode = PktReadU32(c);
    remaining = msgEnd - c->pos;
    if (remaining < 0) remaining = 0;
    evName = PktEventCodeName(eventCode);

    fprintf(f, "      eventCode=0x%08X", eventCode);
    if (evName) fprintf(f, " (%s)", evName);

    if (remaining > 0) {
        payload = c->data + c->pos;
        pyType = payload[0];
        innerEventLE = 0;
        innerEventBE = 0;
        innerNameLE = NULL;
        innerNameBE = NULL;
        innerEventBEBase = 0;
        pyEventIdx = 0;
        pyEventIdxName = NULL;

        /* Python payload byte 0 is the message type discriminator. */
        fprintf(f, " pyType=%d", pyType);

        if (remaining >= 5) {
            innerEventLE = PktReadU32AtLE(payload + 1);
            innerEventBE = PktReadU32AtBE(payload + 1);
            innerNameLE = PktEventCodeName(innerEventLE);
            innerNameBE = PktEventCodeName(innerEventBE);
            fprintf(f, " pyEventLE=0x%08X", innerEventLE);
            if (innerNameLE) fprintf(f, "(%s)", innerNameLE);
            if (innerEventBE != innerEventLE) {
                fprintf(f, " pyEventBE=0x%08X", innerEventBE);
                if (innerNameBE) fprintf(f, "(%s)", innerNameBE);
            }
            innerEventBEBase = innerEventBE & 0xFFFFFF00U;
            if (innerEventBEBase == 0x00800000U) {
                pyEventIdx = (unsigned char)(innerEventBE & 0xFFU);
                pyEventIdxName = PktSubsystemIndexName(pyEventIdx);
                fprintf(f, " pyEventIdx=%u", (unsigned int)pyEventIdx);
                if (pyEventIdxName) fprintf(f, "(%s)", pyEventIdxName);
            }
        }

        argLen = remaining - 5;
        if (argLen > 0) {
            arg0Byte = payload[5];
            fprintf(f, " argBytes=%d arg0_u8=0x%02X", argLen, arg0Byte);

            if (pyType == 223 && pyEventIdxName) {
                fprintf(f, " subsystemIdx=%u(%s)", (unsigned int)pyEventIdx, pyEventIdxName);
            }

            wordCount = argLen / 4;
            maxWords = wordCount;
            if (maxWords > 4) maxWords = 4;
            if (maxWords > 0) {
                fprintf(f, " args32=[");
                for (i = 0; i < maxWords; i++) {
                    unsigned int raw = PktReadU32AtLE(payload + 5 + (i * 4));
                    if (i > 0) fprintf(f, " ");
                    fprintf(f, "%d:0x%08X", i, raw);
                    if (PktU32IsFiniteFloat(raw))
                        fprintf(f, "/%.3f", PktU32ToFloat(raw));
                }
                if (wordCount > maxWords) fprintf(f, " ...");
                fprintf(f, "]");
            }

            if ((argLen % 4) != 0) {
                int tailStart = 5 + (argLen & ~3);
                fprintf(f, " argTail=[");
                for (i = tailStart; i < remaining; i++) {
                    fprintf(f, "%02X ", payload[i]);
                }
                fprintf(f, "]");
            }
        }

        /* Known mission payload decode for low message-type values. */
        if (pyType == 10 && remaining >= 4) {
            unsigned char pLimit = payload[1];
            unsigned char sysSpecies = payload[2];
            unsigned char timeLim = payload[3];
            fprintf(f, " MISSION_INIT playerLimit=%d sysSpecies=%d timeLimit=%d",
                    pLimit, sysSpecies, timeLim);
        }
        else if (pyType == 12 && remaining >= 17) {
            unsigned int pid = PktReadU32AtLE(payload + 1);
            unsigned int kills = PktReadU32AtLE(payload + 5);
            unsigned int deaths = PktReadU32AtLE(payload + 9);
            unsigned int score = PktReadU32AtLE(payload + 13);
            fprintf(f, " SCORE player=%u kills=%u deaths=%u score=%u", pid, kills, deaths, score);
        }
    }

    /* Dump remaining payload as hex (limited) */
    if (remaining > 0) {
        fprintf(f, " payload=[");
        for (i = 0; i < remaining && i < 32; i++)
            fprintf(f, "%02X ", c->data[c->pos + i]);
        if (remaining > 32) fprintf(f, "...");
        fprintf(f, "]");
    }
    fprintf(f, "\n");
    c->pos = msgEnd;
}

/* --- Phase 4: ChecksumRequest (0x20) decoder --- */
static void PktDecodeChecksumReq(FILE* f, PktCursor* c) {
    unsigned char reqIdx;
    unsigned short dirLen, filterLen;
    int i;
    int recursive;

    if (!PktHas(c, 1)) return;
    reqIdx = PktReadU8(c);
    dirLen = PktReadU16(c);
    fprintf(f, "      round=%d dir=\"", reqIdx);
    for (i = 0; i < dirLen && PktHas(c, 1) && i < 64; i++)
        fputc(PktReadU8(c), f);
    fprintf(f, "\" filter=\"");
    filterLen = PktReadU16(c);
    for (i = 0; i < filterLen && PktHas(c, 1) && i < 64; i++)
        fputc(PktReadU8(c), f);
    fprintf(f, "\"");
    recursive = PktReadBit(c);
    fprintf(f, " recursive=%d\n", recursive);
}

/* --- Phase 4: ChecksumResponse (0x21) decoder --- */
static void PktDecodeChecksumResp(FILE* f, PktCursor* c, int msgEnd) {
    unsigned char reqIdx;
    int remaining;
    int i;

    if (!PktHas(c, 1)) return;
    reqIdx = PktReadU8(c);
    remaining = msgEnd - c->pos;
    if (remaining < 0) remaining = 0;

    if (reqIdx == 0xFF) {
        unsigned int crc = 0;
        if (PktHas(c, 4)) crc = PktReadU32(c);
        fprintf(f, "      first-response crc=0x%08X hashData=%d bytes\n",
                crc, remaining > 4 ? remaining - 4 : 0);
    } else {
        unsigned short dirLen;
        fprintf(f, "      round=%d", reqIdx);
        dirLen = PktReadU16(c);
        fprintf(f, " dir=\"");
        for (i = 0; i < dirLen && PktHas(c, 1) && i < 64; i++)
            fputc(PktReadU8(c), f);
        fprintf(f, "\"\n");
    }
    c->pos = msgEnd;
}

/* --- Phase 4: ChecksumFail (0x22/0x23) decoder --- */
static void PktDecodeChecksumFail(FILE* f, PktCursor* c, unsigned char subOp) {
    unsigned short fnLen;
    int i;
    fprintf(f, "      %s file=\"",
            subOp == 0x22 ? "VersionMismatch" : "SystemChecksumFail");
    fnLen = PktReadU16(c);
    for (i = 0; i < fnLen && PktHas(c, 1) && i < 128; i++)
        fputc(PktReadU8(c), f);
    fprintf(f, "\"\n");
}

/* --- Phase 4: FileTransfer (0x25) decoder --- */
static void PktDecodeFileTransfer(FILE* f, PktCursor* c, int msgEnd) {
    unsigned short fnLen;
    int remaining;
    int i;
    fnLen = PktReadU16(c);
    fprintf(f, "      file=\"");
    for (i = 0; i < fnLen && PktHas(c, 1) && i < 128; i++)
        fputc(PktReadU8(c), f);
    remaining = msgEnd - c->pos;
    fprintf(f, "\" dataLen=%d\n", remaining > 0 ? remaining : 0);
    c->pos = msgEnd;
}

/* --- Decode a single game opcode payload (after the opcode byte) --- */
static void PktDecodeGameOpcode(FILE* f, unsigned char opcode, PktCursor* c, int msgEnd) {
    const char* name = PktGameOpcodeName(opcode);
    if (name)
        fprintf(f, "    [0x%02X %s]\n", opcode, name);
    else
        fprintf(f, "    [0x%02X]\n", opcode);

    switch (opcode) {
    case 0x00: PktDecodeSettings(f, c); break;
    case 0x01: fprintf(f, "      (trigger, no payload)\n"); break;
    case 0x02:
    case 0x03: {
        unsigned char owner = PktReadU8(c);
        fprintf(f, "      type=%s owner=%d", opcode==3?"team":"std", owner);
        if (opcode == 0x03 && PktHas(c, 1)) {
            unsigned char teamId = PktReadU8(c);
            fprintf(f, " team=%d", teamId);
        }
        /* Scan serialized object data for length-prefixed ASCII strings */
        {
            int scanPos = c->pos;
            int stringsFound = 0;
            while (scanPos < msgEnd - 1 && stringsFound < 4) {
                unsigned char sLen = c->data[scanPos];
                if (sLen >= 2 && sLen <= 64 && scanPos + 1 + sLen <= msgEnd) {
                    /* Check if all bytes are printable ASCII */
                    int j, allPrint = 1;
                    for (j = 0; j < sLen; j++) {
                        unsigned char ch = c->data[scanPos + 1 + j];
                        if (ch < 0x20 || ch > 0x7E) { allPrint = 0; break; }
                    }
                    if (allPrint) {
                        fprintf(f, " str%d=\"", stringsFound);
                        for (j = 0; j < sLen; j++)
                            fputc(c->data[scanPos + 1 + j], f);
                        fprintf(f, "\"");
                        scanPos += 1 + sLen;
                        stringsFound++;
                        continue;
                    }
                }
                scanPos++;
            }
        }
        fprintf(f, " objData=%d bytes\n", msgEnd - c->pos);
        c->pos = msgEnd;
        break;
    }
    case 0x04: PktDecodeBootPlayer(f, c); break;
    case 0x06:
    case 0x0D: PktDecodePythonMsg(f, c, msgEnd); break;
    /* Event forward opcodes (all use same generic format) */
    case 0x07: /* StartFiring */
    case 0x08: /* StopFiring */
    case 0x09: /* StopFiringAtTarget */
    case 0x0A: /* SubsystemStatusChanged */
    case 0x0B: /* EventFwd 0xDF */
    case 0x0C: /* EventFwd (generic) */
    case 0x0E: /* StartCloaking */
    case 0x0F: /* StopCloaking */
    case 0x10: /* StartWarp */
    case 0x1B: /* TorpedoTypeChange */
        PktDecodeEventForward(f, c, msgEnd); break;
    case 0x14: {
        unsigned int objId = PktReadU32(c);
        fprintf(f, "      destroyObj=0x%08X\n", objId);
        break;
    }
    case 0x16: {
        unsigned char raw;
        if (!PktHas(c, 1)) { fprintf(f, "      (truncated)\n"); break; }
        raw = PktReadU8(c);
        fprintf(f, "      collisionDamage=%d raw=0x%02X\n", (raw & 1) ? 1 : 0, raw);
        c->pos = msgEnd;
        break;
    }
    case 0x19: PktDecodeTorpedoFire(f, c); break;
    case 0x1A: PktDecodeBeamFire(f, c); break;
    case 0x1C: PktDecodeStateUpdate(f, c, msgEnd); break;
    case 0x1D: {
        unsigned int objId = PktReadU32(c);
        fprintf(f, "      notFoundObj=0x%08X\n", objId);
        break;
    }
    case 0x1E: {
        unsigned int objId = PktReadU32(c);
        fprintf(f, "      requestObj=0x%08X\n", objId);
        break;
    }
    case 0x1F: {
        /* EnterSet - contains set name */
        int remaining = msgEnd - c->pos;
        if (remaining > 0) {
            int i;
            fprintf(f, "      set=\"");
            for (i = 0; i < remaining && i < 64; i++)
                fputc(c->data[c->pos + i], f);
            fprintf(f, "\"\n");
            c->pos = msgEnd;
        }
        break;
    }
    case 0x29: PktDecodeExplosion(f, c); break;
    case 0x2A: fprintf(f, "      (new player in game)\n"); break;
    /* Checksum opcodes */
    case 0x20: PktDecodeChecksumReq(f, c); break;
    case 0x21: PktDecodeChecksumResp(f, c, msgEnd); break;
    case 0x22:
    case 0x23: PktDecodeChecksumFail(f, c, opcode); break;
    case 0x25: PktDecodeFileTransfer(f, c, msgEnd); break;
    case 0x27: fprintf(f, "      (ack, no payload)\n"); break;
    case 0x28: {
        int rem = msgEnd - c->pos;
        if (rem <= 0) {
            fprintf(f, "      (no payload)\n");
            break;
        }
        fprintf(f, "      preSettings=0x%02X", c->data[c->pos]);
        if (rem > 1) fprintf(f, " extra=%d bytes", rem - 1);
        fprintf(f, "\n");
        c->pos = msgEnd;
        break;
    }
    case 0x2C: {
        unsigned char senderSlot;
        unsigned char pad0, pad1, pad2;
        unsigned short textLen;
        int avail;
        int showLen;
        int i;
        if (!PktHas(c, 6)) { fprintf(f, "      (truncated)\n"); c->pos = msgEnd; break; }
        senderSlot = PktReadU8(c);
        pad0 = PktReadU8(c);
        pad1 = PktReadU8(c);
        pad2 = PktReadU8(c);
        textLen = PktReadU16(c);
        avail = msgEnd - c->pos;
        if (avail < 0) avail = 0;
        showLen = textLen;
        if (showLen > avail) showLen = avail;
        fprintf(f, "      senderSlot=%u pad=%02X %02X %02X textLen=%u text=\"",
                senderSlot, pad0, pad1, pad2, textLen);
        for (i = 0; i < showLen && i < 160; i++) {
            unsigned char ch = c->data[c->pos + i];
            fputc((ch >= 0x20 && ch <= 0x7E) ? ch : '.', f);
        }
        if (showLen > 160) fprintf(f, "...");
        fprintf(f, "\"");
        if ((int)textLen > avail) fprintf(f, " (truncated, have=%d)", avail);
        if (avail > showLen) fprintf(f, " extra=%d", avail - showLen);
        fprintf(f, "\n");
        c->pos = msgEnd;
        break;
    }
    default:
        /* Unknown opcode - dump remaining as hex */
        if (c->pos < msgEnd) {
            int i, rem = msgEnd - c->pos;
            fprintf(f, "      data=[");
            for (i = 0; i < rem && i < 32; i++)
                fprintf(f, "%02X ", c->data[c->pos + i]);
            if (rem > 32) fprintf(f, "...");
            fprintf(f, "] (%d bytes)\n", rem);
            c->pos = msgEnd;
        }
        break;
    }

    if (c->pos < msgEnd) {
        int i, rem = msgEnd - c->pos;
        fprintf(f, "      trailing=[");
        for (i = 0; i < rem && i < 32; i++)
            fprintf(f, "%02X ", c->data[c->pos + i]);
        if (rem > 32) fprintf(f, "...");
        fprintf(f, "] (%d bytes)\n", rem);
        c->pos = msgEnd;
    }
}

/* --- TGNetwork transport message type names --- */
static const char* PktTransportName(unsigned char type) {
    switch (type) {
    case 0x00: return "Keepalive";
    case 0x01: return "ACK";
    case 0x03: return "Connect";
    case 0x04: return "ConnectData";
    case 0x05: return "ConnectAck";
    case 0x06: return "Disconnect";
    case 0x32: return "Reliable";
    default: return NULL;
    }
}

/* Decode one TGNetwork transport message from the current cursor position. */
static void PktDecodeTransportMessage(FILE* f, PktCursor* cur, int frameEnd, int msgNum, const char* prefix) {
    unsigned char msgType;

    if (!PktHas(cur, 1)) return;
    msgType = PktReadU8(cur);

    if (msgType == 0x32) {
        /* Reliable message wrapper: [0x32][totalLen][flags][seq_hi?][seq_lo?][payload] */
        unsigned char totalLen, flags;
        unsigned short seqNum;
        unsigned char innerOpcode;
        int msgStart, innerStart, innerEnd;

        msgStart = cur->pos - 1; /* position of the 0x32 byte */
        if (!PktHas(cur, 2)) {
            fprintf(f, "%s[msg %d] Reliable (truncated header)\n", prefix, msgNum);
            return;
        }
        totalLen = PktReadU8(cur);
        flags = PktReadU8(cur);

        if (flags & 0x80) {
            /* Reliable: has sequence number */
            if (!PktHas(cur, 2)) {
                fprintf(f, "%s[msg %d] Reliable len=%d flags=0x%02X (truncated seq)\n",
                        prefix, msgNum, totalLen, flags);
                return;
            }
            seqNum = (unsigned short)(PktReadU8(cur) << 8) | PktReadU8(cur);
            fprintf(f, "%s[msg %d] Reliable seq=%d len=%d flags=0x%02X",
                    prefix, msgNum, seqNum, totalLen, flags);
        } else {
            /* Unreliable: no sequence */
            fprintf(f, "%s[msg %d] Unreliable len=%d flags=0x%02X",
                    prefix, msgNum, totalLen, flags);
            seqNum = 0;
        }

        /* totalLen includes the 0x32 byte itself, so end = msgStart + totalLen */
        innerStart = cur->pos;
        innerEnd = msgStart + totalLen;
        if (innerEnd > frameEnd) innerEnd = frameEnd;
        if (innerEnd < innerStart) innerEnd = innerStart;

        if (flags & 0x20) {
            /* Fragmented reliable payload:
             * first: [frag_idx][total_frags][inner_opcode][...]
             * next : [frag_idx][continuation bytes...] */
            int fragIdx = -1;
            int fragTotal = -1;
            int fragPayloadLen;

            if (cur->pos < innerEnd && PktHas(cur, 1))
                fragIdx = PktReadU8(cur);
            if (fragIdx == 0 && cur->pos < innerEnd && PktHas(cur, 1))
                fragTotal = PktReadU8(cur);

            fprintf(f, " frag=%d", fragIdx);
            if (fragTotal >= 0) fprintf(f, "/%d", fragTotal);
            fprintf(f, " more=%d", (flags & 0x01) ? 1 : 0);

            if (fragIdx == 0 && cur->pos < innerEnd && PktHas(cur, 1)) {
                innerOpcode = PktReadU8(cur);
                fprintf(f, "\n");
                PktDecodeGameOpcode(f, innerOpcode, cur, innerEnd);
            } else {
                fragPayloadLen = innerEnd - cur->pos;
                if (fragPayloadLen < 0) fragPayloadLen = 0;
                fprintf(f, " continuation=%d bytes\n", fragPayloadLen);
            }
            cur->pos = innerEnd; /* advance past this message */
            return;
        }

        if (PktHas(cur, 1) && cur->pos < innerEnd) {
            innerOpcode = PktReadU8(cur);
            fprintf(f, "\n");
            PktDecodeGameOpcode(f, innerOpcode, cur, innerEnd);
        } else {
            fprintf(f, " (empty)\n");
        }
        cur->pos = innerEnd; /* advance past this message */
        return;
    }

    if (msgType == 0x01) {
        /* ACK message: [01][seq][00][flags] = fixed 4 bytes total */
        if (PktHas(cur, 3)) {
            unsigned char ackSeq = PktReadU8(cur);
            PktReadU8(cur); /* padding */
            PktReadU8(cur); /* flags */
            fprintf(f, "%s[msg %d] ACK seq=%d\n", prefix, msgNum, ackSeq);
        } else {
            fprintf(f, "%s[msg %d] ACK (truncated)\n", prefix, msgNum);
        }
        return;
    }

    /* All other transport types: [type][totalLen][data...] */
    {
        const char* tName = PktTransportName(msgType);
        int msgStart = cur->pos - 1; /* position of type byte */
        int msgEnd;

        if (PktHas(cur, 1)) {
            unsigned char msgLen = PktReadU8(cur);
            msgEnd = msgStart + msgLen;
            if (msgEnd > frameEnd) msgEnd = frameEnd;
            if (msgEnd < cur->pos) msgEnd = cur->pos;
            fprintf(f, "%s[msg %d] %s (0x%02X) len=%d body=%d\n", prefix, msgNum,
                    tName ? tName : "Transport", msgType, msgLen, msgEnd - cur->pos);
            cur->pos = msgEnd;
        } else {
            fprintf(f, "%s[msg %d] %s (0x%02X)\n", prefix, msgNum,
                    tName ? tName : "Unknown", msgType);
        }
    }
}

#ifdef OBSERVE_ONLY
/* Decode a single message blob that starts with TGNetwork message type. */
static void PktDecodeMessageBlob(FILE* f, const unsigned char* msgData, int msgLen) {
    PktCursor cur;
    if (!f || !msgData || msgLen <= 0) return;
    PktCursorInit(&cur, msgData, msgLen, 0);
    PktDecodeTransportMessage(f, &cur, msgLen, 0, "  ");
    if (cur.pos < msgLen) {
        fprintf(f, "  [msg 0] trailing=%d bytes\n", msgLen - cur.pos);
    }
}
#endif

/* --- Main packet decoder: parses framing and dispatches to opcode decoders --- */
static void PktDecodePacket(FILE* f, const unsigned char* dec, int len) {
    PktCursor cur;
    unsigned char dir, msgCount;
    const char* dirStr;
    int msgNum;

    if (len < 2) return;

    dir = dec[0];
    msgCount = dec[1];

    dirStr = (dir == 0x01) ? "S" : (dir == 0x02) ? "C" : (dir == 0xFF) ? "INIT" : "?";
    fprintf(f, "  DECODE: dir=%s msgs=%d\n", dirStr, msgCount);

    PktCursorInit(&cur, dec, len, 2);

    for (msgNum = 0; msgNum < msgCount && PktHas(&cur, 1); msgNum++) {
        PktDecodeTransportMessage(f, &cur, len, msgNum, "  ");
    }
}

/* Quick opcode label for the packet header line (legacy compat) */
static const char* PktIdentifyOpcode(const unsigned char* dec, int len) {
    unsigned char msgType;
    if (len < 3) {
        if (len <= 1) return "";
        return "[short]";
    }
    msgType = dec[2]; /* first message type byte after [dir][msgCount] */
    switch (msgType) {
    case 0x00: return "[Keepalive]";
    case 0x01: return "[ACK]";
    case 0x03: return "[Connect]";
    case 0x05: return "[ConnectAck]";
    case 0x06: return "[Disconnect]";
    case 0x32: return "[Reliable]";
    }
    return "";
}

static void PktHexDump(FILE* f, const unsigned char* data, int len) {
    int off, i, rowLen;
    int maxDump = len < 2048 ? len : 2048;
    for (off = 0; off < maxDump; off += 16) {
        rowLen = maxDump - off;
        if (rowLen > 16) rowLen = 16;
        fprintf(f, "    %04X: ", off);
        for (i = 0; i < rowLen; i++)
            fprintf(f, "%02X ", data[off + i]);
        for (i = rowLen; i < 16; i++)
            fprintf(f, "   ");
        fprintf(f, " |");
        for (i = 0; i < rowLen; i++) {
            unsigned char c = data[off + i];
            fputc((c >= 0x20 && c <= 0x7E) ? c : '.', f);
        }
        fprintf(f, "|\n");
    }
    if (len > 2048)
        fprintf(f, "    ... (%d bytes truncated)\n", len - 2048);
}

static void PktLog(const char* dir, const struct sockaddr_in* peer,
                    const unsigned char* data, int len, int rc) {
    SYSTEMTIME st;
    LONG seq;
    const char* label;
    const char* opcode;
    unsigned char decBuf[2048];
    int isGamePacket;
    if (!g_pPacketLog) return;
    GetLocalTime(&st);
    seq = InterlockedIncrement(&g_packetSeq);
    label = peer ? PktGetPeerLabel(peer) : "unknown";

    /* GameSpy packets start with '\' (0x5C) - plaintext, not encrypted.
     * TGNetwork game packets start with 0x01/0x02/0xFF - encrypted. */
    isGamePacket = (len > 0 && data[0] != '\\');

    if (isGamePacket && len > 1 && len <= (int)sizeof(decBuf)) {
        BC_DecryptPacket(data, decBuf, len);
        opcode = PktIdentifyOpcode(decBuf, len);
        fprintf(g_pPacketLog,
                "[%02d:%02d:%02d.%03d] #%ld %s %s len=%d rc=%d %s\n",
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                seq, dir, label, len, rc, opcode);
        fprintf(g_pPacketLog, "  Decrypted:\n");
        PktHexDump(g_pPacketLog, decBuf, len);
        PktDecodePacket(g_pPacketLog, decBuf, len);
    } else {
        opcode = "";
        fprintf(g_pPacketLog,
                "[%02d:%02d:%02d.%03d] #%ld %s %s len=%d rc=%d %s\n",
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                seq, dir, label, len, rc, opcode);
        fprintf(g_pPacketLog, "  Plaintext:\n");
        PktHexDump(g_pPacketLog, data, len);
    }
    fprintf(g_pPacketLog, "\n");
    fflush(g_pPacketLog);
}

/* Open packet trace log - called from DllMain after g_szBasePath is set */
static void PktTraceOpen(void) {
    char path[MAX_PATH];
    SYSTEMTIME st;
    GetLocalTime(&st);
    lstrcpynA(path, g_szBasePath, MAX_PATH);
    lstrcatA(path, "packet_trace.log");
    g_pPacketLog = fopen(path, "w");
    if (g_pPacketLog) {
        fprintf(g_pPacketLog,
                "# STBC Dedicated Server - Packet Trace (DECRYPTED)\n"
                "# Session started: %04d-%02d-%02d %02d:%02d:%02d\n"
                "# Format: [time] #seq DIR peer len=N rc=N [opcode]\n"
                "# DIR: S->C = server to client, C->S = client to server\n"
                "# Game packets decrypted with AlbyRules! cipher + structured decode\n"
                "# Framing: [dir:1][peer:1][msgCount:1][messages...]\n"
                "# Transport: 0x00=Keepalive 0x01=ACK 0x03=Connect 0x05=ConnectAck 0x06=Disconnect\n"
                "# Reliable wrapper: [0x32][len][flags][seq_hi][seq_lo][game_opcode][payload]\n"
                "# Game opcodes: 0x00=Settings 0x01=GameInit 0x02/03=ObjCreate 0x04=Boot\n"
                "#   0x06/0D=Python 0x07=StartFire 0x08=StopFire 0x09=StopFireAt 0x0A=SubsysStatus\n"
                "#   0x0E=StartCloak 0x0F=StopCloak 0x10=StartWarp 0x14=DestroyObj\n"
                "#   0x19=TorpedoFire 0x1A=BeamFire 0x1B=TorpTypeChange 0x1C=StateUpdate\n"
                "#   0x1D=ObjNotFound 0x1E=RequestObj 0x1F=EnterSet 0x29=Explosion 0x2A=NewPlayer\n"
                "# Checksum: 0x20=Req 0x21=Resp 0x22/23=Fail 0x25=FileXfer 0x27=ACK\n"
                "# StateUpdate flags: POS=0x01 DELTA=0x02 FWD=0x04 UP=0x08\n"
                "#   SPD=0x10 SUB=0x20 CLK=0x40 WPN=0x80\n"
                "# GameSpy packets (start with '\\') shown as plaintext (not encrypted)\n"
                "# ============================================================\n\n",
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond);
        fflush(g_pPacketLog);
    }
}
