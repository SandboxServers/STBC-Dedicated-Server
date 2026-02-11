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
    default: return NULL;
    }
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
        int bytesRead;
        if (!PktHas(c, 1)) return;
        startIdx = PktReadU8(c);
        fprintf(f, "        subsystems startIdx=%d data=[", startIdx);
        bytesRead = 0;
        while (PktHas(c, 1) && bytesRead < 20 && c->pos < msgEnd) {
            fprintf(f, "%02X ", c->data[c->pos]);
            c->pos++;
            bytesRead++;
        }
        fprintf(f, "]\n");
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
    int remaining;
    int i;

    if (!PktHas(c, 4)) { fprintf(f, "      (truncated)\n"); return; }
    eventCode = PktReadU32(c);
    remaining = msgEnd - c->pos;
    if (remaining < 0) remaining = 0;

    fprintf(f, "      eventCode=0x%08X", eventCode);

    /* Try to decode known Python message types by peeking at first payload byte */
    if (remaining > 0) {
        unsigned char pyType = c->data[c->pos];
        /* Python message type byte is offset from App.MAX_MESSAGE_TYPES base
         * Known types: +1=CHAT, +10=MISSION_INIT, +11=SCORE_CHANGE,
         *              +12=SCORE, +13=END_GAME, +14=RESTART, +20=SCORE_INIT */
        fprintf(f, " pyType=%d", pyType);

        /* Try to decode MISSION_INIT (+10): [type][playerLimit][systemSpecies][timeLimit][if!=255:endTime(int)][fragLimit] */
        if (pyType == 10 && remaining >= 4) {
            unsigned char pLimit = c->data[c->pos + 1];
            unsigned char sysSpecies = c->data[c->pos + 2];
            unsigned char timeLim = c->data[c->pos + 3];
            fprintf(f, " MISSION_INIT playerLimit=%d sysSpecies=%d timeLimit=%d",
                    pLimit, sysSpecies, timeLim);
        }
        /* SCORE (+12): [type][playerID(4)][kills(4)][deaths(4)][score(4)] */
        else if (pyType == 12 && remaining >= 17) {
            int pOff = c->pos + 1;
            unsigned int pid = c->data[pOff]|(c->data[pOff+1]<<8)|(c->data[pOff+2]<<16)|(c->data[pOff+3]<<24);
            unsigned int kills = c->data[pOff+4]|(c->data[pOff+5]<<8)|(c->data[pOff+6]<<16)|(c->data[pOff+7]<<24);
            unsigned int deaths = c->data[pOff+8]|(c->data[pOff+9]<<8)|(c->data[pOff+10]<<16)|(c->data[pOff+11]<<24);
            unsigned int score = c->data[pOff+12]|(c->data[pOff+13]<<8)|(c->data[pOff+14]<<16)|(c->data[pOff+15]<<24);
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
        unsigned char msgType = PktReadU8(&cur);

        if (msgType == 0x32) {
            /* Reliable message wrapper: [0x32][totalLen][flags][seq_hi?][seq_lo?][payload] */
            unsigned char totalLen, flags;
            unsigned short seqNum;
            unsigned char innerOpcode;
            int msgStart, innerStart, innerEnd;

            msgStart = cur.pos - 1; /* position of the 0x32 byte */
            if (!PktHas(&cur, 2)) break;
            totalLen = PktReadU8(&cur);
            flags = PktReadU8(&cur);

            if (flags & 0x80) {
                /* Reliable: has sequence number */
                if (!PktHas(&cur, 2)) break;
                seqNum = (unsigned short)(PktReadU8(&cur) << 8) | PktReadU8(&cur);
                fprintf(f, "  [msg %d] Reliable seq=%d len=%d", msgNum, seqNum, totalLen);
            } else {
                /* Unreliable: no sequence */
                fprintf(f, "  [msg %d] Unreliable len=%d", msgNum, totalLen);
                seqNum = 0;
            }

            /* totalLen includes the 0x32 byte itself, so end = msgStart + totalLen */
            innerStart = cur.pos;
            innerEnd = msgStart + totalLen;
            if (innerEnd > len) innerEnd = len;
            if (innerEnd < innerStart) innerEnd = innerStart;

            if (PktHas(&cur, 1) && cur.pos < innerEnd) {
                innerOpcode = PktReadU8(&cur);
                fprintf(f, "\n");
                PktDecodeGameOpcode(f, innerOpcode, &cur, innerEnd);
            } else {
                fprintf(f, " (empty)\n");
            }
            cur.pos = innerEnd; /* advance past this message */

        } else if (msgType == 0x01) {
            /* ACK message: [01][seq][00][flags] = fixed 4 bytes total */
            if (PktHas(&cur, 3)) {
                unsigned char ackSeq = PktReadU8(&cur);
                PktReadU8(&cur); /* padding */
                PktReadU8(&cur); /* flags */
                fprintf(f, "  [msg %d] ACK seq=%d\n", msgNum, ackSeq);
            }

        } else {
            /* All other transport types: [type][totalLen][data...]
             * totalLen includes the type byte. Known types:
             * 0x00=Data, 0x03=Connect, 0x04=ConnectData, 0x05=ConnectAck, 0x06=Disconnect */
            const char* tName = PktTransportName(msgType);
            int msgStart = cur.pos - 1; /* position of type byte */
            int msgEnd;

            if (PktHas(&cur, 1)) {
                unsigned char totalLen = PktReadU8(&cur);
                msgEnd = msgStart + totalLen;
                if (msgEnd > len) msgEnd = len;
                if (msgEnd < cur.pos) msgEnd = cur.pos;
                fprintf(f, "  [msg %d] %s (0x%02X) len=%d\n", msgNum,
                        tName ? tName : "Transport", msgType, totalLen);
                cur.pos = msgEnd;
            } else {
                fprintf(f, "  [msg %d] %s (0x%02X)\n", msgNum,
                        tName ? tName : "Unknown", msgType);
            }
        }
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
 * Known message types (from static analysis):
 *   0x00: FUN_006bc6a0  0x01: FUN_006bd1f0  0x02: FUN_006bdd10
 *   0x03: FUN_006be860  0x04: FUN_006badb0  0x05: FUN_006bf410
 *   0x32: FUN_006b83f0
 *
 * The game-layer opcodes (settings, checksums, etc.) are carried
 * as payloads WITHIN these network messages.
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
                "# Followed by hex dump of decoded message body\n"
                "# Known types: 0x00-0x05 (core network), 0x32 (connection mgmt)\n"
                "# Game opcodes are in the message PAYLOAD (visible in hex dump)\n"
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

        /* Hex dump message body (opcode byte + payload) */
        dumpLen = (msgSize > 0 && msgSize < 256) ? msgSize : 64;
        PktHexDump(g_pMsgLog, data, dumpLen);
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

/* sendto hook for monitoring outbound UDP traffic */
typedef int (WSAAPI *PFN_sendto)(SOCKET, const char*, int, int,
                                  const struct sockaddr*, int);
static PFN_sendto g_pfnOrigSendto = NULL;
static volatile LONG g_sendtoCount = 0;

/* Forward declaration - defined in PatchDebugConsoleToFile section */
static void __cdecl ReplacementDebugConsole(void);

/* F12 state dump - C-level polling (avoids breaking event system) */
static int g_f12WasDown = 0;
static DWORD g_f12LastDump = 0;

static void TryF12StateDump(void) {
    int isDown = (GetAsyncKeyState(VK_F12) & 0x8000) ? 1 : 0;
    if (isDown && !g_f12WasDown) {
        /* Edge: key just pressed */
        DWORD now = GetTickCount();
        if (now - g_f12LastDump > 2000) { /* 2s cooldown */
            g_f12LastDump = now;
            ProxyLog("  F12 detected - triggering state dump from C");
            /* Use PyRun_String (NOT PyRun_SimpleString) so the exception
             * from dump_state's "raise text" is preserved in the error
             * indicator. We then call ReplacementDebugConsole directly
             * to write the dump text to state_dump.log. */
            {
                typedef void* (__cdecl *pfn_PyImport_AddModule)(const char*);
                typedef void* (__cdecl *pfn_PyModule_GetDict)(void*);
                typedef void* (__cdecl *pfn_PyRun_String)(const char*, int, void*, void*);
                #define _AddModule  ((pfn_PyImport_AddModule)0x0075b890)
                #define _GetDict    ((pfn_PyModule_GetDict)0x00773990)
                #define _RunString  ((pfn_PyRun_String)0x0074b640)
                #define PY_FILE_INPUT 257

                void* mod = _AddModule("__main__");
                if (mod) {
                    void* dict = _GetDict(mod);
                    if (dict) {
                        void* result = _RunString(
                            "import Custom.StateDumper\n"
                            "Custom.StateDumper.dump_state('F12 MANUAL DUMP')\n",
                            PY_FILE_INPUT, dict, dict);
                        if (!result) {
                            /* Exception raised (the dump text) - write to file */
                            ReplacementDebugConsole();
                        }
                    }
                }

                #undef _AddModule
                #undef _GetDict
                #undef _RunString
                #undef PY_FILE_INPUT
            }
        }
    }
    g_f12WasDown = isDown;
}

/* ================================================================
 * Tick State Logger - CSV trace of key engine state every game tick
 *
 * Writes one line per ~33ms to tick_trace.log with key memory values.
 * Designed to be cheap: just memory reads + fprintf, no Python.
 * Called from HookedSendto (OBSERVE_ONLY) or GameLoopTimerProc (server).
 *
 * Columns:
 *   seq       - monotonic sequence number
 *   ms        - GetTickCount() timestamp
 *   gt        - gameTime float from clock object
 *   mpg       - MultiplayerGame pointer (0 = no game)
 *   players   - WSN player count
 *   conn      - WSN connection state (2=host, 3=client)
 *   isCli     - IsClient byte at 0x0097FA88 (0=host, 1=client)
 *   isHost    - IsHost byte at 0x0097FA89 (1=host, 0=client)
 *   isMp      - IsMultiplayer byte at 0x0097FA8A
 *   mpgB0     - MPG+0xB0 (object gate for message processing)
 *   mpg1F8    - MPG+0x1F8 (ReadyForNewPlayers)
 *   emQ       - Event manager queue counter
 *   pUQ       - Peer[0] unreliable send queue size
 *   pRQ       - Peer[0] reliable send queue size
 *   pPQ       - Peer[0] priority send queue size
 * ================================================================ */
static FILE* g_pTickLog = NULL;
static DWORD g_tickLastMs = 0;
static DWORD g_tickSeq = 0;

static void TickLogger(void) {
    DWORD now = GetTickCount();
    DWORD wsnPtr = 0, mpg = 0, clockPtr = 0;
    float gameTime = 0.0f;
    int playerCount = 0, connState = 0;
    BYTE isClient = 0, isHost = 0, isMp = 0, mpg1F8 = 0;
    DWORD mpgB0 = 0, emQ = 0;
    int pUQ = 0, pRQ = 0, pPQ = 0;

    /* Throttle: one sample per ~33ms (game tick rate) */
    if (now - g_tickLastMs < 33) return;
    g_tickLastMs = now;

    /* Open log on first call */
    if (!g_pTickLog) {
        char path[MAX_PATH];
        if (g_szBasePath[0])
            _snprintf(path, sizeof(path), "%stick_trace.log", g_szBasePath);
        else
            _snprintf(path, sizeof(path), "tick_trace.log");
        path[sizeof(path)-1] = '\0';
        g_pTickLog = fopen(path, "w");
        if (!g_pTickLog) return;
        fprintf(g_pTickLog, "# Tick Trace Log - session %lu\n", (unsigned long)now);
        fprintf(g_pTickLog, "# seq,ms,gt,mpg,players,conn,isCli,isHost,isMp,mpgB0,mpg1F8,emQ,pUQ,pRQ,pPQ\n");
        fflush(g_pTickLog);
    }

    /* Read key addresses */
    if (!IsBadReadPtr((void*)0x0097FA78, 4))
        wsnPtr = *(DWORD*)0x0097FA78;
    if (!IsBadReadPtr((void*)0x0097e238, 4))
        mpg = *(DWORD*)0x0097e238;
    if (!IsBadReadPtr((void*)0x009a09d0, 4))
        clockPtr = *(DWORD*)0x009a09d0;
    if (clockPtr && !IsBadReadPtr((void*)(clockPtr + 0x90), 4))
        gameTime = *(float*)(clockPtr + 0x90);
    if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x30), 4))
        playerCount = *(int*)(wsnPtr + 0x30);
    if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x14), 4))
        connState = *(int*)(wsnPtr + 0x14);
    if (!IsBadReadPtr((void*)0x0097FA88, 1))
        isClient = *(BYTE*)0x0097FA88;
    if (!IsBadReadPtr((void*)0x0097FA89, 1))
        isHost = *(BYTE*)0x0097FA89;
    if (!IsBadReadPtr((void*)0x0097FA8A, 1))
        isMp = *(BYTE*)0x0097FA8A;
    if (mpg && !IsBadReadPtr((void*)(mpg + 0xB0), 4))
        mpgB0 = *(DWORD*)(mpg + 0xB0);
    if (mpg && !IsBadReadPtr((void*)(mpg + 0x1F8), 1))
        mpg1F8 = *(BYTE*)(mpg + 0x1F8);
    if (!IsBadReadPtr((void*)0x0097F840, 4))
        emQ = *(DWORD*)0x0097F840;

    /* Peer[0] send queue sizes */
    if (wsnPtr && playerCount > 0) {
        DWORD pArray = 0;
        if (!IsBadReadPtr((void*)(wsnPtr + 0x2C), 4))
            pArray = *(DWORD*)(wsnPtr + 0x2C);
        if (pArray) {
            DWORD pp = 0;
            if (!IsBadReadPtr((void*)pArray, 4))
                pp = *(DWORD*)pArray;
            if (pp && !IsBadReadPtr((void*)(pp + 0xB4), 4)) {
                pUQ = *(int*)(pp + 0x7C);
                pRQ = *(int*)(pp + 0x98);
                pPQ = *(int*)(pp + 0xB4);
            }
        }
    }

    /* Write CSV line */
    fprintf(g_pTickLog, "%lu,%lu,%.3f,0x%08lX,%d,%d,%d,%d,%d,0x%08lX,%d,%lu,%d,%d,%d\n",
            (unsigned long)g_tickSeq++, (unsigned long)now, gameTime,
            (unsigned long)mpg, playerCount, connState, (int)isClient, (int)isHost, (int)isMp,
            (unsigned long)mpgB0, (int)mpg1F8, (unsigned long)emQ, pUQ, pRQ, pPQ);

    /* Flush every 30 lines (~1 second) to balance I/O and data safety */
    if (g_tickSeq % 30 == 0)
        fflush(g_pTickLog);
}

static int WSAAPI HookedSendto(SOCKET s, const char* buf, int len, int flags,
                                const struct sockaddr* to, int tolen) {
    int rc;
#ifdef OBSERVE_ONLY
    if (!g_factoryHooked) TryInstallFactoryHooks();
    TryF12StateDump();
    TickLogger();
#endif
    rc = g_pfnOrigSendto(s, buf, len, flags, to, tolen);
    InterlockedIncrement(&g_sendtoCount);
    if (to && tolen >= (int)sizeof(struct sockaddr_in)) {
        PktLog("S->C", (const struct sockaddr_in*)to,
               (const unsigned char*)buf, len, rc);
    } else {
        PktLog("S->?", NULL, (const unsigned char*)buf, len, rc);
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
    int rc;
#ifdef OBSERVE_ONLY
    if (!g_factoryHooked) TryInstallFactoryHooks();
#endif
    rc = g_pfnOrigRecvfrom(s, buf, len, flags, from, fromlen);
    if (rc > 0 && !(flags & MSG_PEEK)) {
        InterlockedIncrement(&g_recvfromCount);
        if (from && fromlen && *fromlen >= (int)sizeof(struct sockaddr_in)) {
            PktLog("C->S", (const struct sockaddr_in*)from,
                   (const unsigned char*)buf, rc, rc);
        } else {
            PktLog("C->S", NULL, (const unsigned char*)buf, rc, rc);
        }
    }
    return rc;
}

/* OutputDebugStringA hook - captures game debug output */
typedef void (WINAPI *PFN_OutputDebugStringA)(LPCSTR);
static PFN_OutputDebugStringA g_pfnOrigODS = NULL;

static void WINAPI HookedOutputDebugStringA(LPCSTR lpOutputString) {
    if (lpOutputString && lpOutputString[0]) {
        ProxyLog("[ODS] %s", lpOutputString);
    }
    if (g_pfnOrigODS)
        g_pfnOrigODS(lpOutputString);
}

/* (VEH crash handler removed - replaced by CrashDumpHandler via SetUnhandledExceptionFilter) */

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

/* PatchSkipRendererCtor REMOVED - renderer constructor now runs normally.
 * The D3D proxy provides valid COM objects so the constructor succeeds. */

/* PatchRendererCtorEntry REMOVED - the real NiDX7Renderer constructor
 * runs so the renderer has valid internal state (arrays, matrices, frustum). */

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

/* PatchSkipRendererSetup REMOVED - the full renderer pipeline now runs.
 * Dev_GetDirect3D returns a valid ProxyD3D7, so pipeline ctors get valid
 * COM objects. All D3D calls go through our proxy (no real GPU needed). */

/* ================================================================
 * PatchSkipDeviceLost - Skip "device lost" recreation path
 *
 * Vtable method at 0x007C1330 (offset +0x98 in renderer wrapper vtable
 * 0x00898984) is called every frame. It calls FUN_007c45b0 to check
 * device status. When the device appears "lost" (always true for stubs),
 * it tries to destroy+recreate pipeline objects at offsets 0xC4, 0xC0,
 * 0xB8, 0xBC - which may be NULL or stub pointers from the proxy pipeline.
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
 * PatchSkipDisplayModeSearch - Skip display mode list search
 *
 * FUN_007c9020 (NiDX7Renderer SetDisplayMode) checks this+0x190 for
 * a display mode enumeration list. If non-NULL, it searches for the
 * requested resolution+depth. On modern displays the enumerated modes
 * may not include old modes (e.g. 640x480x16bpp), failing with
 * "Desired fullscreen display mode not supported".
 *
 * The alternative path (this+0x190 == NULL) calls
 * IDirectDraw7::SetDisplayMode directly (our hook returns DD_OK).
 *
 * Patch: 007C90EE JE +0x2E (74 2E) -> JMP +0x2E (EB 2E)
 * ================================================================ */
static void PatchSkipDisplayModeSearch(void) {
    BYTE* target = (BYTE*)0x007C90EE;
    DWORD oldProt;

    if (IsBadReadPtr(target, 2) || target[0] != 0x74 || target[1] != 0x2E) {
        ProxyLog("  PatchSkipDisplayModeSearch: unexpected bytes at 0x007C90EE (%02X %02X), skipped",
                 target[0], target[1]);
        return;
    }

    VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, &oldProt);
    target[0] = 0xEB; /* JE -> JMP short */
    VirtualProtect(target, 1, oldProt, &oldProt);

    ProxyLog("  PatchSkipDisplayModeSearch: 007C90EE JE->JMP (skip mode list, use direct SetDisplayMode)");
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
    static const BYTE p_ret18[]     = { 0xC2, 0x18, 0x00 };
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
        /* FUN_007c16f0 (vtable+0xa4): SetCameraData - copies camera/frustum
         * params into renderer, then calls internal functions that dereference
         * NULL pointers in headless mode. Not needed for headless server.
         * thiscall, 6 stack params (24 bytes) → RET 0x18 */
        { 0x007C16F0, 0x83, p_ret18, 3,
          "FUN_007c16f0 (vtable+0xa4 SetCameraData) -> RET 0x18" },
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
 * PatchDeviceCapsRawCopy - Skip raw memory copy from Device7 object
 *
 * FUN_007d1ff0 (NiD3DTextureManager ctor) copies 59 DWORDs (236 bytes)
 * directly from the IDirect3DDevice7 object starting at offset 0x00.
 * This bypasses COM and reads the internal Microsoft D3D7 memory layout.
 * Our ProxyDevice7 has a COM vtable pointer at offset 0, refCount at +4,
 * etc. - completely different from Microsoft's layout. The copied garbage
 * gets interpreted as D3D caps data by downstream pipeline constructors
 * (FUN_007ccd10), causing EIP=0x0 crash from NULL vtable entry dereference.
 *
 * Fix: Change MOV ECX,0x3B at 0x007d2118 to MOV ECX,0x00.
 * REP MOVSD with ECX=0 is a no-op. The destination stays zeroed (from
 * HEAP_ZERO_MEMORY allocation), meaning "no device caps" - safe for
 * a headless server that never renders.
 * ================================================================ */
static void PatchDeviceCapsRawCopy(void) {
    /* MOV ECX,0x3B at 0x007d2118 = B9 3B 00 00 00
     * The 0x3B immediate is at instruction_start+1 = 0x007d2119 */
    BYTE* target = (BYTE*)0x007d2119;
    DWORD oldProt;

    if (IsBadReadPtr(target, 1) || *target != 0x3B) {
        ProxyLog("  PatchDeviceCapsRawCopy: unexpected byte %02X at 0x007d2119 (expected 3B), skipped",
                 *target);
        return;
    }
    VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, &oldProt);
    *target = 0x00;
    VirtualProtect(target, 1, oldProt, &oldProt);
    ProxyLog("  PatchDeviceCapsRawCopy: MOV ECX,0x3B -> MOV ECX,0x00 at 0x007d2118 (skip 236-byte Device7 raw copy)");
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
        /* FUN_0055c890: subtitle remove callback - same pattern as 0x0055c810.
         * Looks up pane #5 via FUN_0050e1b0, passes NULL to FUN_00508120 -> crash.
         * __fastcall, PUSH ESI -> safe to RET. */
        { 0x0055c890, 0x56, "FUN_0055c890 (subtitle remove callback)" },
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
/* PatchDisableDebugConsole - REPLACED by PatchDebugConsoleToFile above.
 * Previously: patched FUN_006f9470 to RET and set flag to 0.
 * Now: PatchDebugConsoleToFile redirects to our file-logging replacement. */

/* ================================================================
 * PatchNullThunk_00419960 - Fix NULL dereference in vtable thunk
 *
 * The 8-byte thunk at 0x00419960 does:
 *   MOV ECX, [ECX+0x1C]   ; get sub-object pointer
 *   MOV EAX, [ECX]         ; get vtable
 *   JMP [EAX+0x34]         ; call vtable slot 13
 *
 * When [ECX+0x1C] is NULL (e.g. AsteroidField with uninitialized
 * NiAVObject member), the second instruction crashes reading [0x00000000].
 * This fires after a client connects and game objects are iterated.
 *
 * Fix: Redirect to a code cave that checks [ECX+0x1C] for NULL.
 * If NULL, return pointer to a static zeroed bounding struct so
 * callers that read floats from the return value don't crash.
 * ================================================================ */
static void PatchNullThunk_00419960(void) {
    /* Code cave layout (48 bytes total):
     * [0..23]:  6 zeroed DWORDs = dummy bounding box (min/max vectors)
     * [24]:     MOV ECX, [ECX+0x1C]    ; 8B 49 1C
     * [27]:     TEST ECX, ECX           ; 85 C9
     * [29]:     JZ .null                ; 74 05
     * [31]:     MOV EAX, [ECX]          ; 8B 01
     * [33]:     JMP [EAX+0x34]          ; FF 60 34
     * .null: [36]
     * [36]:     MOV EAX, <cave_base>    ; B8 XX XX XX XX
     * [41]:     RET                     ; C3
     */
    static BYTE cave[] = {
        /* 24 bytes of zeros = dummy bounding box (6 floats) */
        0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
        /* code starts at offset 24 */
        0x8B, 0x49, 0x1C,       /* MOV ECX, [ECX+0x1C] */
        0x85, 0xC9,             /* TEST ECX, ECX       */
        0x74, 0x05,             /* JZ  +5 (.null)      */
        0x8B, 0x01,             /* MOV EAX, [ECX]      */
        0xFF, 0x60, 0x34,       /* JMP [EAX+0x34]      */
        /* .null: */
        0xB8, 0x00, 0x00, 0x00, 0x00,  /* MOV EAX, <cave_base> (fixup) */
        0xC3                    /* RET                  */
    };
    BYTE* pCave;
    BYTE* target = (BYTE*)0x00419960;
    DWORD oldProt;

    /* Verify expected bytes: 8B 49 1C 8B 01 FF 60 34 */
    if (IsBadReadPtr(target, 8) ||
        target[0] != 0x8B || target[1] != 0x49 || target[2] != 0x1C ||
        target[3] != 0x8B || target[4] != 0x01) {
        ProxyLog("  PatchNullThunk_00419960: unexpected bytes at 0x00419960, skipped");
        return;
    }

    pCave = (BYTE*)VirtualAlloc(NULL, sizeof(cave),
                                MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE);
    if (!pCave) {
        ProxyLog("  PatchNullThunk_00419960: VirtualAlloc failed");
        return;
    }
    memcpy(pCave, cave, sizeof(cave));

    /* Fix up MOV EAX, <cave_base>: point to the zeroed data at start of cave */
    *(DWORD*)(pCave + 37) = (DWORD)pCave;  /* cave[0..23] = zeroed bounding box */

    /* Overwrite thunk entry: JMP to cave CODE (offset 24), 5 bytes + 3 NOPs */
    VirtualProtect(target, 8, PAGE_EXECUTE_READWRITE, &oldProt);
    target[0] = 0xE9;  /* JMP rel32 */
    *(DWORD*)(target + 1) = (DWORD)(pCave + 24) - (0x00419960 + 5);
    target[5] = 0x90;  /* NOP */
    target[6] = 0x90;  /* NOP */
    target[7] = 0x90;  /* NOP */
    VirtualProtect(target, 8, oldProt, &oldProt);

    ProxyLog("  PatchNullThunk_00419960: 0x00419960 -> cave at %p (NULL returns zeroed bound at %p)",
             pCave + 24, pCave);
}

/* ================================================================
 * PatchStreamReadNullBuffer - Fix NULL buffer in stream read function
 *
 * FUN_006CF625 is a small stream read function:
 *   MOV ESI, [ECX+0x1C]    ; get buffer pointer
 *   MOV AX, [ESI+EAX]      ; read 16-bit value at offset EAX
 *   MOV [ECX+0x24], EDX    ; store read position
 *   POP ESI
 *   RET
 *
 * Called during network state update deserialization (from 0x005B2619).
 * When the stream buffer at [ECX+0x1C] is NULL (no subsystem/weapon
 * data to deserialize), ESI=0 and the read crashes.
 *
 * Fix: Code cave checks [ECX+0x1C] for NULL, returns AX=0 if so.
 * ================================================================ */
static void PatchStreamReadNullBuffer(void) {
    /* Code cave: complete replacement of the 12-byte function
     * MOV ESI, [ECX+0x1C]  ; get buffer ptr
     * TEST ESI, ESI         ; NULL check
     * JZ .null
     * MOV AX, [ESI+EAX]    ; read 16-bit (original)
     * MOV [ECX+0x24], EDX  ; update position (original)
     * POP ESI
     * RET
     * .null:
     * XOR AX, AX            ; return 0
     * POP ESI
     * RET
     */
    static BYTE cave[] = {
        0x8B, 0x71, 0x1C,             /* MOV ESI, [ECX+0x1C] */
        0x85, 0xF6,                   /* TEST ESI, ESI       */
        0x74, 0x09,                   /* JZ  +9 (.null)      */
        0x66, 0x8B, 0x04, 0x06,       /* MOV AX, [ESI+EAX]  */
        0x89, 0x51, 0x24,             /* MOV [ECX+0x24], EDX */
        0x5E,                         /* POP ESI             */
        0xC3,                         /* RET                 */
        /* .null: */
        0x66, 0x33, 0xC0,             /* XOR AX, AX          */
        0x5E,                         /* POP ESI             */
        0xC3                          /* RET                 */
    };
    BYTE* pCave;
    BYTE* target = (BYTE*)0x006CF625;
    DWORD oldProt;

    /* Verify expected bytes: 8B 71 1C 66 8B 04 06 */
    if (IsBadReadPtr(target, 7) ||
        target[0] != 0x8B || target[1] != 0x71 || target[2] != 0x1C ||
        target[3] != 0x66 || target[4] != 0x8B) {
        ProxyLog("  PatchStreamReadNullBuffer: unexpected bytes at 0x006CF625, skipped");
        return;
    }

    pCave = (BYTE*)VirtualAlloc(NULL, sizeof(cave),
                                MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE);
    if (!pCave) {
        ProxyLog("  PatchStreamReadNullBuffer: VirtualAlloc failed");
        return;
    }
    memcpy(pCave, cave, sizeof(cave));

    /* Overwrite function entry: JMP to cave (5 bytes) + NOP remaining 7 */
    VirtualProtect(target, 12, PAGE_EXECUTE_READWRITE, &oldProt);
    target[0] = 0xE9;  /* JMP rel32 */
    *(DWORD*)(target + 1) = (DWORD)pCave - (0x006CF625 + 5);
    memset(target + 5, 0x90, 7);  /* NOP remaining bytes */
    VirtualProtect(target, 12, oldProt, &oldProt);

    ProxyLog("  PatchStreamReadNullBuffer: 0x006CF625 -> cave at %p (NULL buffer returns AX=0)",
             pCave);

    /* Patch error path in FUN_006cf1c0 (stream cleanup/reset):
     * When buffer at [this+0x1C] is NULL, it tries to write 0xFFFFFFFE to
     * *[this+4]. If [this+4] points to read-only .rdata, this crashes.
     *
     * Original 10 bytes: 8B 41 04 C7 00 FE FF FF FF C3
     *   MOV EAX, [ECX+4]; MOV [EAX], 0xFFFFFFFE; RET
     *
     * Replacement: Also zero this+0x08 (FILE* field) to prevent fclose on
     * stale pointer in the base class destructor (STATUS_INVALID_HANDLE crash).
     *   C7 41 08 00 00 00 00 C3 90 90
     *   MOV DWORD PTR [ECX+0x8], 0; RET; NOP; NOP
     */
    {
        BYTE* target2 = (BYTE*)0x006CF1DC;
        DWORD oldProt2;
        /* Replacement: zero FILE* at this+0x08 then RET (10 bytes) */
        static const BYTE replacement[] = {
            0xC7, 0x41, 0x08, 0x00, 0x00, 0x00, 0x00,  /* MOV DWORD PTR [ECX+8], 0 */
            0xC3,                                         /* RET */
            0x90, 0x90                                    /* NOP NOP */
        };
        if (!IsBadReadPtr(target2, 3)) {
            ProxyLog("  PatchStreamReadNullBuffer: bytes at 006CF1DC: %02X %02X %02X",
                     target2[0], target2[1], target2[2]);
            /* Check if already patched from previous run (0xC3 or 0xC7) */
            if (target2[0] == 0xC3 || target2[0] == 0xC7) {
                VirtualProtect(target2, 10, PAGE_EXECUTE_READWRITE, &oldProt2);
                memcpy(target2, replacement, 10);
                VirtualProtect(target2, 10, oldProt2, &oldProt2);
                ProxyLog("  PatchStreamReadNullBuffer: 006CF1DC -> zero FILE* + RET");
            } else if (target2[0] == 0x8B && target2[1] == 0x41 && target2[2] == 0x04) {
                VirtualProtect(target2, 10, PAGE_EXECUTE_READWRITE, &oldProt2);
                memcpy(target2, replacement, 10);
                VirtualProtect(target2, 10, oldProt2, &oldProt2);
                ProxyLog("  PatchStreamReadNullBuffer: 006CF1DC -> zero FILE* + RET");
            } else {
                ProxyLog("  PatchStreamReadNullBuffer: 006CF1DC unexpected bytes, trying scan...");
                /* Scan for the error pattern: 8B 41 04 C7 00 FE FF FF FF C3 */
                int off;
                for (off = -16; off <= 16; off++) {
                    BYTE* scan = target2 + off;
                    if (!IsBadReadPtr(scan, 10) &&
                        scan[0] == 0x8B && scan[1] == 0x41 && scan[2] == 0x04 &&
                        scan[3] == 0xC7 && scan[4] == 0x00 &&
                        scan[5] == 0xFE && scan[6] == 0xFF) {
                        VirtualProtect(scan, 10, PAGE_EXECUTE_READWRITE, &oldProt2);
                        memcpy(scan, replacement, 10);
                        VirtualProtect(scan, 10, oldProt2, &oldProt2);
                        ProxyLog("  PatchStreamReadNullBuffer: found error pattern at 0x%08X -> zero FILE* + RET",
                                 (unsigned)(scan));
                        break;
                    }
                }
            }
        }
    }
}

/* ================================================================
 * PatchTGLFindEntry - Fix NULL+0x1C sentinel from TGL lookup
 *
 * FUN_006D1E10 (TGL::FindEntry) returns `this + 0x1C` as a pointer
 * to the default/empty entry. When the TGL file fails to load in
 * headless mode, `this` is NULL, so the function returns 0x1C --
 * a non-NULL invalid pointer that passes all NULL checks downstream
 * and crashes when dereferenced (reads at address 0x24 = 0x1C+8).
 *
 * Fix: Insert a check at function entry. If ECX (this) is NULL,
 * return NULL immediately (XOR EAX,EAX / RET 4). Otherwise, fall
 * through to the original code.
 *
 * Original bytes at 0x006D1E10:
 *   8B 44 24 04   MOV EAX,[ESP+4]   (4 bytes)
 *   56            PUSH ESI           (1 byte)
 *   85 C0         TEST EAX,EAX       (continues at 0x006D1E15)
 * ================================================================ */
static void PatchTGLFindEntry(void) {
    static BYTE cave[] = {
        0x85, 0xC9,             /* TEST ECX,ECX          */
        0x75, 0x05,             /* JNZ  +5 (.original)   */
        0x33, 0xC0,             /* XOR  EAX,EAX          */
        0xC2, 0x04, 0x00,       /* RET  4                */
        /* .original: */
        0x8B, 0x44, 0x24, 0x04, /* MOV  EAX,[ESP+4]      */
        0x56,                   /* PUSH ESI               */
        0xE9, 0x00, 0x00, 0x00, 0x00  /* JMP 0x006D1E15  (fixup) */
    };
    BYTE* pCave;
    DWORD oldProt;
    DWORD jmpFrom, jmpTo;

    pCave = (BYTE*)VirtualAlloc(NULL, sizeof(cave),
                                MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE);
    if (!pCave) {
        ProxyLog("  PatchTGLFindEntry: VirtualAlloc failed");
        return;
    }
    memcpy(pCave, cave, sizeof(cave));

    /* Fix up JMP rel32: offset = target - (addr_after_jmp) */
    jmpFrom = (DWORD)(pCave + 19);   /* address after the JMP instruction */
    jmpTo   = 0x006D1E15;            /* original TEST EAX,EAX */
    *(DWORD*)(pCave + 15) = jmpTo - jmpFrom;

    /* Overwrite function entry: JMP to cave (exactly 5 bytes) */
    VirtualProtect((void*)0x006D1E10, 5, PAGE_EXECUTE_READWRITE, &oldProt);
    *(BYTE*)0x006D1E10 = 0xE9;       /* JMP rel32 */
    *(DWORD*)0x006D1E11 = (DWORD)pCave - (0x006D1E10 + 5);
    VirtualProtect((void*)0x006D1E10, 5, oldProt, &oldProt);

    ProxyLog("  PatchTGLFindEntry: 0x006D1E10 -> cave at %p (NULL this returns NULL)",
             pCave);
}

/* ================================================================
 * PatchNetworkUpdateNullLists - Fix malformed update packets for headless ships
 *
 * FUN_005b17f0 (network object state update) builds a flags byte that
 * indicates which data sections follow in the update packet. Bit 0x20
 * means "subsystem data follows" and bit 0x80 means "weapon data".
 *
 * In headless mode, ship objects have no subsystems or weapons (the
 * linked lists at object+0x284 are NULL). The flags byte is written
 * to the stream with these bits set, but the loops that would write
 * the actual data crash (or are VEH-skipped). This produces a packet
 * where the flags promise data that doesn't exist, causing the client
 * to misparse the packet and interpret the ship as destroyed.
 *
 * Fix: Code cave at the flags-byte-write point (0x005b1d57). Before
 * writing the flags, check if ESI+0x284 (subsystem/weapon list) is
 * NULL. If NULL, clear bits 0x20 and 0x80 so the client knows to
 * skip those sections.
 *
 * Patched bytes at 0x005b1d57 (5 bytes):
 *   8B 4C 24 14  MOV ECX,[ESP+0x14]  (4 bytes)
 *   51           PUSH ECX            (1 byte)
 *   -> replaced with JMP to code cave
 *   Code cave executes the check, then these two instructions, then
 *   JMP back to 0x005b1d5c.
 * ================================================================ */
static void PatchNetworkUpdateNullLists(void) {
    static BYTE cave[] = {
        /* Save EAX (we need it for the check) */
        0x50,                               /* PUSH EAX                    */
        /* Check if subsystem/weapon list pointer is NULL */
        0x8B, 0x86, 0x84, 0x02, 0x00, 0x00, /* MOV EAX,[ESI+0x284]        */
        0x85, 0xC0,                         /* TEST EAX,EAX                */
        0x75, 0x05,                         /* JNZ +5 (.has_lists)         */
        /* List is NULL: clear bits 0x20 and 0x80 from flags */
        0x80, 0x64, 0x24, 0x18, 0x5F,       /* AND byte [ESP+0x18],0x5F   */
        /* .has_lists: */
        0x58,                               /* POP EAX                     */
        /* Execute original 2 instructions we overwrote */
        0x8B, 0x4C, 0x24, 0x14,             /* MOV ECX,[ESP+0x14]          */
        0x51,                               /* PUSH ECX                    */
        /* Jump back to original code */
        0xE9, 0x00, 0x00, 0x00, 0x00        /* JMP 0x005b1d5c (fixup)     */
    };
    BYTE* pCave;
    DWORD oldProt;
    DWORD jmpFrom, jmpTo;

    pCave = (BYTE*)VirtualAlloc(NULL, sizeof(cave),
                                MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE);
    if (!pCave) {
        ProxyLog("  PatchNetworkUpdateNullLists: VirtualAlloc failed");
        return;
    }
    memcpy(pCave, cave, sizeof(cave));

    /* Fix up JMP rel32 in cave: offset = target - addr_after_jmp */
    jmpFrom = (DWORD)(pCave + sizeof(cave));   /* address after the JMP */
    jmpTo   = 0x005b1d5c;                      /* LEA ECX,[ESP+0x74] */
    *(DWORD*)(pCave + sizeof(cave) - 4) = jmpTo - jmpFrom;

    /* Overwrite 5 bytes at 0x005b1d57: JMP to cave */
    VirtualProtect((void*)0x005b1d57, 5, PAGE_EXECUTE_READWRITE, &oldProt);
    *(BYTE*)0x005b1d57 = 0xE9;
    *(DWORD*)0x005b1d58 = (DWORD)pCave - (0x005b1d57 + 5);
    VirtualProtect((void*)0x005b1d57, 5, oldProt, &oldProt);

    ProxyLog("  PatchNetworkUpdateNullLists: 0x005b1d57 -> cave at %p "
             "(clear subsys/weapon flags when lists NULL)", pCave);
}

/* PatchChecksumAlwaysPass REMOVED - flag=0 means "no mismatches" which is
 * correct for first player connecting (no peers to compare against).
 * Forcing flag=1 corrupted the Settings packet with bogus mismatch data. */

/* ================================================================
 * PatchSubsystemHashCheck - Fix false-positive anti-cheat kicks
 *
 * FUN_005b21c0 (ship network state update receiver) processes incoming
 * opcode 0x1C packets. It computes a hash over all ship subsystem states
 * (shields, weapons, hull, power, sensors) via FUN_005b5eb0(this+0x27c)
 * and compares it with the hash sent by the client.
 *
 * On our headless server, ships have no subsystem objects (the linked
 * list at this+0x284 is NULL). FUN_005b5eb0 iterates this list and
 * returns 0/garbage when it's empty. This ALWAYS mismatches the client's
 * valid hash, triggering false-positive cheat detection:
 *   -> Posts ET_BOOT_PLAYER event (0x8000f6)
 *   -> BootPlayerHandler sends type=4 sub-command=4 (kick) to client
 *   -> Client disconnects: "You have been disconnected from the host"
 *
 * Fix: Code cave replaces the CALL to FUN_005b5eb0 at 0x005b22b5.
 * Before computing the hash, check if the subsystem linked list head
 * at [ESI+0x284] is NULL. If NULL (no subsystems to hash), return the
 * RECEIVED hash value (EDI) so the comparison naturally passes. If the
 * list is valid, call the real FUN_005b5eb0 for normal anti-cheat.
 *
 * This keeps anti-cheat ACTIVE for any ship that has proper subsystem
 * data, while preventing false kicks for headless ships without it.
 *
 * Assembly context at 0x005b22af-0x005b22c9:
 *   005b22af: LEA ECX,[ESI+0x27c]   ; subsystem data base
 *   005b22b5: CALL FUN_005b5eb0     ; compute hash (5 bytes: E8 xx xx xx xx)
 *   005b22ba: MOV EDX,EAX
 *   005b22bc: SAR EDX,0x10
 *   005b22bf: MOVSX ECX,DX          ; high16
 *   005b22c2: MOVSX EAX,AX          ; low16
 *   005b22c5: XOR ECX,EAX           ; computed = high16 ^ low16
 *   005b22c7: CMP ECX,EDI           ; compare computed vs received
 *   005b22c9: JZ  005b2338          ; skip boot if equal
 * ================================================================ */

/* Code cave: check subsystem list, delegate or return received hash */
static BYTE g_subsysHashCave[32];

static void PatchSubsystemHashCheck(void) {
    BYTE* callSite = (BYTE*)0x005b22b5;  /* CALL FUN_005b5eb0 */
    DWORD oldProt;

    if (IsBadReadPtr(callSite, 5)) {
        ProxyLog("  PatchSubsystemHashCheck: address 0x005b22b5 not readable, skipped");
        return;
    }

    /* Verify it's a CALL rel32 (E8 xx xx xx xx) */
    if (callSite[0] != 0xE8) {
        ProxyLog("  PatchSubsystemHashCheck: expected E8 at 0x005b22b5, got 0x%02X - skipped",
                 (int)callSite[0]);
        return;
    }

    /* Build code cave:
     *   CMP DWORD PTR [ESI+0x284], 0   ; check subsystem list head
     *   JNE .call_real                  ; if list exists, compute real hash
     *   ; No subsystems: forge a hash that will match the received value (EDI)
     *   ; We need EAX to produce the same final result as EDI after:
     *   ;   MOV EDX,EAX / SAR EDX,10 / MOVSX ECX,DX / MOVSX EAX,AX / XOR ECX,EAX
     *   ; Simplest: return to AFTER the XOR (005b22c7) with ECX=EDI
     *   ; so CMP ECX,EDI succeeds immediately
     *   MOV ECX, EDI                   ; set computed = received
     *   JMP 0x005b22c7                 ; jump to CMP ECX,EDI (will match)
     * .call_real:
     *   JMP FUN_005b5eb0              ; original hash computation
     */
    BYTE* cave = g_subsysHashCave;
    DWORD caveAddr = (DWORD)cave;
    int i = 0;

    /* CMP DWORD PTR [ESI+0x284], 0  (81 BE 84 02 00 00 00 00 00 00) */
    cave[i++] = 0x81; cave[i++] = 0xBE;
    cave[i++] = 0x84; cave[i++] = 0x02; cave[i++] = 0x00; cave[i++] = 0x00;  /* offset 0x284 */
    cave[i++] = 0x00; cave[i++] = 0x00; cave[i++] = 0x00; cave[i++] = 0x00;  /* imm32 = 0 */

    /* JNE .call_real (75 XX) - jump over the next 7 bytes */
    cave[i++] = 0x75;
    cave[i++] = 0x07;  /* skip MOV ECX,EDI (2) + JMP rel32 (5) = 7 bytes */

    /* MOV ECX, EDI  (89 F9) */
    cave[i++] = 0x89; cave[i++] = 0xF9;

    /* JMP 0x005b22c7  (E9 xx xx xx xx) - jump to CMP ECX,EDI */
    cave[i++] = 0xE9;
    {
        DWORD jmpTarget = 0x005b22c7;
        DWORD jmpFrom = caveAddr + i + 4;  /* address after this JMP instruction */
        DWORD rel = jmpTarget - jmpFrom;
        cave[i++] = (BYTE)(rel);
        cave[i++] = (BYTE)(rel >> 8);
        cave[i++] = (BYTE)(rel >> 16);
        cave[i++] = (BYTE)(rel >> 24);
    }

    /* .call_real: JMP FUN_005b5eb0  (E9 xx xx xx xx) */
    cave[i++] = 0xE9;
    {
        DWORD jmpTarget = 0x005b5eb0;
        DWORD jmpFrom = caveAddr + i + 4;
        DWORD rel = jmpTarget - jmpFrom;
        cave[i++] = (BYTE)(rel);
        cave[i++] = (BYTE)(rel >> 8);
        cave[i++] = (BYTE)(rel >> 16);
        cave[i++] = (BYTE)(rel >> 24);
    }

    /* Make code cave executable */
    VirtualProtect(cave, sizeof(g_subsysHashCave), PAGE_EXECUTE_READWRITE, &oldProt);

    /* Patch the CALL at 0x005b22b5 to point to our cave instead of FUN_005b5eb0 */
    VirtualProtect(callSite, 5, PAGE_EXECUTE_READWRITE, &oldProt);
    {
        DWORD rel = caveAddr - ((DWORD)callSite + 5);
        callSite[1] = (BYTE)(rel);
        callSite[2] = (BYTE)(rel >> 8);
        callSite[3] = (BYTE)(rel >> 16);
        callSite[4] = (BYTE)(rel >> 24);
    }
    VirtualProtect(callSite, 5, oldProt, &oldProt);

    ProxyLog("  PatchSubsystemHashCheck: code cave at %p, redirected CALL at 0x005b22b5",
             (void*)cave);
    ProxyLog("    -> NULL subsystem list [ESI+0x284]: skip hash (match received)");
    ProxyLog("    -> Valid subsystem list: call real FUN_005b5eb0 for anti-cheat");
}

/* ================================================================
 * PatchCompressedVectorRead - Prevent cascading crash in FUN_006d2eb0
 *
 * FUN_006d2eb0 reads a compressed 3-byte vector from a network stream
 * using four vtable calls: three ReadByte calls (vtable+0x50) and one
 * decode call (vtable+0xB8 with 6 stack params, __thiscall, callee-clean).
 *
 * If the stream reader object's vtable pointer is corrupted (e.g. from
 * a prior memory corruption or stack misalignment), ALL four vtable calls
 * fail. The VEH handler recovers from each by popping the return address,
 * but the fourth call's callee was supposed to clean 24 bytes of params
 * via RET 0x18. Since the callee never runs, those params remain on the
 * stack. The function's epilogue (POP ESI; ADD ESP,0xC; RET 0xC) then
 * uses the wrong stack offsets, popping garbage as the return address.
 *
 * The VEH handler finds the real return address deeper on the stack and
 * adjusts ESP, but this leaves the CALLER's stack misaligned by 12 bytes.
 * The next call to FUN_006d2eb0 uses a wrong `this` pointer (offset by
 * 12 bytes into wrong memory), reads a garbage "vtable" = 1, and crashes
 * fatally at CALL [1 + 0x50] -> access violation at 0x00000051.
 *
 * Fix: Code cave at FUN_006d2eb0 entry (0x006D2EB0). Validate that the
 * vtable pointer (first DWORD of the this object) is in the valid .rdata
 * range for stbc.exe (0x00800000-0x008FFFFF). If invalid, skip the
 * function entirely: zero-fill the 3 output float params and RET 0xC.
 *
 * Overwritten bytes at 0x006D2EB0 (6 bytes):
 *   83 EC 0C     SUB ESP,0xC
 *   56           PUSH ESI
 *   8B F1        MOV ESI,ECX
 *   -> replaced with: E9 xx xx xx xx  JMP cave
 *                      90              NOP
 *   Cave executes validation, then these 6 bytes, then JMP back.
 *
 * Also protects FUN_006d2fd0 (0x006D2FD0) which has the same structure
 * and the same cascading failure risk. Its first 6 bytes are identical.
 * ================================================================ */
static void PatchCompressedVectorRead(void) {
    /* We patch TWO functions: FUN_006d2eb0 and FUN_006d2fd0.
     * Both have identical prologues and identical vtable-crash risk.
     * Each gets its own code cave. */
    static BYTE cave1[80]; /* cave for FUN_006d2eb0 (RET 0xC) */
    static BYTE cave2[80]; /* cave for FUN_006d2fd0 (RET 0x10) */
    DWORD oldProt;
    int i;

    /* --- Cave 1: FUN_006d2eb0 (3 params, RET 0xC) --- */
    {
        BYTE* site = (BYTE*)0x006D2EB0;
        BYTE* cave = cave1;
        DWORD caveAddr = (DWORD)cave;

        /* Verify original bytes: 83 EC 0C 56 8B F1 */
        if (IsBadReadPtr(site, 6)) {
            ProxyLog("  PatchCompressedVectorRead: 0x006D2EB0 not readable, skipped");
            goto patch2;
        }
        if (site[0] != 0x83 || site[1] != 0xEC || site[2] != 0x0C ||
            site[3] != 0x56 || site[4] != 0x8B || site[5] != 0xF1) {
            ProxyLog("  PatchCompressedVectorRead: unexpected bytes at 0x006D2EB0, skipped");
            goto patch2;
        }

        i = 0;
        /* Validate this pointer (ECX) and its vtable pointer */
        cave[i++] = 0x85; cave[i++] = 0xC9;             /* TEST ECX,ECX                */
        cave[i++] = 0x74;                                 /* JZ .bad_vtable              */
        cave[i++] = 0x00; /* placeholder */
        {
            int jz_offset_pos = i - 1;

            cave[i++] = 0x8B; cave[i++] = 0x01;         /* MOV EAX,[ECX]               */
            cave[i++] = 0x3D;                             /* CMP EAX, imm32              */
            cave[i++] = 0x00; cave[i++] = 0x00;
            cave[i++] = 0x80; cave[i++] = 0x00;           /* 0x00800000                  */
            cave[i++] = 0x72; /* JB .bad_vtable */
            cave[i++] = 0x00; /* placeholder */
            {
                int jb_offset_pos = i - 1;

                cave[i++] = 0x3D;                         /* CMP EAX, imm32              */
                cave[i++] = 0x00; cave[i++] = 0x00;
                cave[i++] = 0x90; cave[i++] = 0x00;       /* 0x00900000                  */
                cave[i++] = 0x73; /* JAE .bad_vtable */
                cave[i++] = 0x00; /* placeholder */
                {
                    int jae_offset_pos = i - 1;

                /* VALID vtable: execute original 6 bytes and return to function body */
                cave[i++] = 0x83; cave[i++] = 0xEC; cave[i++] = 0x0C; /* SUB ESP,0xC    */
                cave[i++] = 0x56;                                       /* PUSH ESI        */
                cave[i++] = 0x8B; cave[i++] = 0xF1;                    /* MOV ESI,ECX     */
                cave[i++] = 0xE9;                                       /* JMP back        */
                {
                    DWORD from = caveAddr + i + 4;
                    DWORD to   = 0x006D2EB6;  /* instruction after the overwritten bytes */
                    DWORD rel = to - from;
                    cave[i++] = (BYTE)(rel);
                    cave[i++] = (BYTE)(rel >> 8);
                    cave[i++] = (BYTE)(rel >> 16);
                    cave[i++] = (BYTE)(rel >> 24);
                }

                    /* .bad_vtable: zero-fill 3 output float params and return cleanly */
                    {
                        int bad_vtable_pos = i;
                        cave[jz_offset_pos]  = (BYTE)(bad_vtable_pos - (jz_offset_pos + 1));
                        cave[jb_offset_pos]  = (BYTE)(bad_vtable_pos - (jb_offset_pos + 1));
                        cave[jae_offset_pos] = (BYTE)(bad_vtable_pos - (jae_offset_pos + 1));
                    }
                    /* The 3 params are pointers to floats on the caller's stack.
                     * [ESP+4] = param_1 (float*), [ESP+8] = param_2 (float*), [ESP+C] = param_3 (float*)
                     * (ESP+0 is the return address since we haven't done SUB ESP yet) */
                    cave[i++] = 0x8B; cave[i++] = 0x44; cave[i++] = 0x24; cave[i++] = 0x04;
                                                               /* MOV EAX,[ESP+4] (param_1)  */
                    cave[i++] = 0xC7; cave[i++] = 0x00;
                    cave[i++] = 0x00; cave[i++] = 0x00; cave[i++] = 0x00; cave[i++] = 0x00;
                                                               /* MOV DWORD [EAX], 0          */
                    cave[i++] = 0x8B; cave[i++] = 0x44; cave[i++] = 0x24; cave[i++] = 0x08;
                                                               /* MOV EAX,[ESP+8] (param_2)  */
                    cave[i++] = 0xC7; cave[i++] = 0x00;
                    cave[i++] = 0x00; cave[i++] = 0x00; cave[i++] = 0x00; cave[i++] = 0x00;
                                                               /* MOV DWORD [EAX], 0          */
                    cave[i++] = 0x8B; cave[i++] = 0x44; cave[i++] = 0x24; cave[i++] = 0x0C;
                                                               /* MOV EAX,[ESP+C] (param_3)  */
                    cave[i++] = 0xC7; cave[i++] = 0x00;
                    cave[i++] = 0x00; cave[i++] = 0x00; cave[i++] = 0x00; cave[i++] = 0x00;
                                                               /* MOV DWORD [EAX], 0          */
                    cave[i++] = 0xC2; cave[i++] = 0x0C; cave[i++] = 0x00;
                                                               /* RET 0xC (clean 3 params)    */
                }
            }
        }

        /* Make cave executable */
        VirtualProtect(cave, sizeof(cave1), PAGE_EXECUTE_READWRITE, &oldProt);

        /* Overwrite FUN_006d2eb0 entry: JMP cave + NOP */
        VirtualProtect(site, 6, PAGE_EXECUTE_READWRITE, &oldProt);
        site[0] = 0xE9;
        {
            DWORD rel = caveAddr - ((DWORD)site + 5);
            site[1] = (BYTE)(rel);
            site[2] = (BYTE)(rel >> 8);
            site[3] = (BYTE)(rel >> 16);
            site[4] = (BYTE)(rel >> 24);
        }
        site[5] = 0x90; /* NOP */
        VirtualProtect(site, 6, oldProt, &oldProt);

        ProxyLog("  PatchCompressedVectorRead: FUN_006d2eb0 -> cave at %p "
                 "(vtable validation + safe RET 0xC)", (void*)cave);
    }

patch2:
    /* --- Cave 2: FUN_006d2fd0 (4 params, RET 0x10) --- */
    {
        BYTE* site = (BYTE*)0x006D2FD0;
        BYTE* cave = cave2;
        DWORD caveAddr = (DWORD)cave;

        /* Verify original bytes: 83 EC 0C 56 8B F1 */
        if (IsBadReadPtr(site, 6)) {
            ProxyLog("  PatchCompressedVectorRead: 0x006D2FD0 not readable, skipped");
            return;
        }
        if (site[0] != 0x83 || site[1] != 0xEC || site[2] != 0x0C ||
            site[3] != 0x56 || site[4] != 0x8B || site[5] != 0xF1) {
            ProxyLog("  PatchCompressedVectorRead: unexpected bytes at 0x006D2FD0, skipped");
            return;
        }

        i = 0;
        /* Same validation logic as cave1 */
        cave[i++] = 0x85; cave[i++] = 0xC9;             /* TEST ECX,ECX                */
        cave[i++] = 0x74;                                 /* JZ .bad_vtable              */
        cave[i++] = 0x00; /* placeholder */
        {
            int jz_offset_pos = i - 1;

            cave[i++] = 0x8B; cave[i++] = 0x01;         /* MOV EAX,[ECX]               */
            cave[i++] = 0x3D;
            cave[i++] = 0x00; cave[i++] = 0x00;
            cave[i++] = 0x80; cave[i++] = 0x00;           /* CMP EAX, 0x00800000         */
            cave[i++] = 0x72;
            cave[i++] = 0x00; /* JB placeholder */
            {
                int jb_offset_pos = i - 1;

                cave[i++] = 0x3D;
                cave[i++] = 0x00; cave[i++] = 0x00;
                cave[i++] = 0x90; cave[i++] = 0x00;       /* CMP EAX, 0x00900000         */
                cave[i++] = 0x73;
                cave[i++] = 0x00; /* JAE placeholder */
                {
                    int jae_offset_pos = i - 1;

                    /* VALID: execute original bytes and continue */
                    cave[i++] = 0x83; cave[i++] = 0xEC; cave[i++] = 0x0C;
                    cave[i++] = 0x56;
                    cave[i++] = 0x8B; cave[i++] = 0xF1;
                    cave[i++] = 0xE9;
                    {
                        DWORD from = caveAddr + i + 4;
                        DWORD to   = 0x006D2FD6;
                        DWORD rel = to - from;
                        cave[i++] = (BYTE)(rel);
                        cave[i++] = (BYTE)(rel >> 8);
                        cave[i++] = (BYTE)(rel >> 16);
                        cave[i++] = (BYTE)(rel >> 24);
                    }

                    /* .bad_vtable: zero-fill 3 output params (skip param_4) and RET 0x10 */
                    {
                        int bad_vtable_pos = i;
                        cave[jz_offset_pos]  = (BYTE)(bad_vtable_pos - (jz_offset_pos + 1));
                        cave[jb_offset_pos]  = (BYTE)(bad_vtable_pos - (jb_offset_pos + 1));
                        cave[jae_offset_pos] = (BYTE)(bad_vtable_pos - (jae_offset_pos + 1));
                    }
                    /* FUN_006d2fd0 params: [ESP+4]=p1, [ESP+8]=p2, [ESP+C]=p3, [ESP+10]=p4(char) */
                    cave[i++] = 0x8B; cave[i++] = 0x44; cave[i++] = 0x24; cave[i++] = 0x04;
                    cave[i++] = 0xC7; cave[i++] = 0x00;
                    cave[i++] = 0x00; cave[i++] = 0x00; cave[i++] = 0x00; cave[i++] = 0x00;
                    cave[i++] = 0x8B; cave[i++] = 0x44; cave[i++] = 0x24; cave[i++] = 0x08;
                    cave[i++] = 0xC7; cave[i++] = 0x00;
                    cave[i++] = 0x00; cave[i++] = 0x00; cave[i++] = 0x00; cave[i++] = 0x00;
                    cave[i++] = 0x8B; cave[i++] = 0x44; cave[i++] = 0x24; cave[i++] = 0x0C;
                    cave[i++] = 0xC7; cave[i++] = 0x00;
                    cave[i++] = 0x00; cave[i++] = 0x00; cave[i++] = 0x00; cave[i++] = 0x00;
                    cave[i++] = 0xC2; cave[i++] = 0x10; cave[i++] = 0x00;
                                                               /* RET 0x10 (clean 4 params)   */
                }
            }
        }

        VirtualProtect(cave, sizeof(cave2), PAGE_EXECUTE_READWRITE, &oldProt);

        VirtualProtect(site, 6, PAGE_EXECUTE_READWRITE, &oldProt);
        site[0] = 0xE9;
        {
            DWORD rel = caveAddr - ((DWORD)site + 5);
            site[1] = (BYTE)(rel);
            site[2] = (BYTE)(rel >> 8);
            site[3] = (BYTE)(rel >> 16);
            site[4] = (BYTE)(rel >> 24);
        }
        site[5] = 0x90;
        VirtualProtect(site, 6, oldProt, &oldProt);

        ProxyLog("  PatchCompressedVectorRead: FUN_006d2fd0 -> cave at %p "
                 "(vtable validation + safe RET 0x10)", (void*)cave);
    }
}

/* ================================================================
 * PatchDebugConsoleToFile - Replace debug console with file logging
 *
 * BC's embedded Python has ALL file I/O disabled (open, nt.open, AND
 * nt.write all fail). Python cannot write to files at all.
 *
 * Instead, we intercept the Python exception debug console function
 * (FUN_006f9470) and replace it with our own C function that:
 *   1. Calls PyErr_Fetch to get the exception
 *   2. For string exceptions (raise "text"), writes the text to state_dump.log
 *   3. Returns immediately (no popup, no "resume" prompt)
 *
 * StateDumper.py uses "raise text" to dump state. The exception propagates
 * to the C engine's exception handler (FUN_006f9b80) which calls our
 * replacement, writing the dump to file silently.
 *
 * Python C API addresses (from Ghidra analysis):
 *   PyErr_Fetch      = 0x00753110
 *   PyString_AsString = 0x007507d0  (returns ob_sval at +0x14, or 0 on type error)
 *   PyString_Type    = 0x0095e960
 *   _Py_NoneStruct   = 0x0095dd20
 * ================================================================ */
static FILE* g_pStateDump = NULL;

/* Forward-declare Python C API functions needed before the main API block */
typedef void (__cdecl *pfn_PyErr_Fetch_Early)(void**, void**, void**);
#define PY_ErrFetch_Early ((pfn_PyErr_Fetch_Early)0x00753110)

#define PY_STRING_TYPE_ADDR  ((void*)0x0095e960)
typedef const char* (__cdecl *pfn_PyString_AsString)(void*);
#define PY_StringAsString ((pfn_PyString_AsString)0x007507d0)

/* Replacement for the debug console popup (FUN_006f9470).
 * Called by FUN_006f9b80 when a Python exception occurs and the
 * debug console flag (DAT_0099add6) is 1. */
static void __cdecl ReplacementDebugConsole(void) {
    static int callCount = 0;
    void *excType = NULL, *excValue = NULL, *excTB = NULL;
    const char *text = NULL;

    callCount++;

    /* Diagnostic: log every entry to confirm handler is reached */
    if (g_pStateDump) {
        fprintf(g_pStateDump, "\n[DIAG] ReplacementDebugConsole called (#%d)\n", callCount);
        fflush(g_pStateDump);
    }
    ProxyLog("  ReplacementDebugConsole: entry #%d", callCount);

    /* Fetch the current exception (this clears the error indicator;
     * caller FUN_006f9b80 calls PY_ErrClear after us anyway) */
    PY_ErrFetch_Early(&excType, &excValue, &excTB);

    if (!excType) return;

    /* For string exceptions (raise "text"), excType IS the string.
     * Check ob_type at offset +4 against PyString_Type. */
    if (!IsBadReadPtr(excType, 24) &&
        *(void**)((char*)excType + 4) == PY_STRING_TYPE_ADDR) {
        text = PY_StringAsString(excType);
    }
    /* For class exceptions, try excValue as string */
    else if (excValue && !IsBadReadPtr(excValue, 24) &&
             *(void**)((char*)excValue + 4) == PY_STRING_TYPE_ADDR) {
        text = PY_StringAsString(excValue);
    }

    if (text && g_pStateDump) {
        fprintf(g_pStateDump, "%s\n", text);
        fflush(g_pStateDump);
    }

    /* Log a short note to ddraw_proxy.log */
    if (text) {
        /* Show first 80 chars in proxy log */
        char preview[84];
        int i;
        for (i = 0; i < 80 && text[i]; i++) {
            preview[i] = (text[i] == '\n' || text[i] == '\r') ? ' ' : text[i];
        }
        preview[i] = '\0';
        ProxyLog("  Python exception -> state_dump.log: %.80s%s",
                 preview, text[i] ? "..." : "");
    }

    /* Leak excType/excValue/excTB refs - harmless for rare exception events.
     * Caller (FUN_006f9b80) will call PY_ErrClear which is now a no-op
     * since PY_ErrFetch already cleared the indicator. */
}

static void PatchDebugConsoleToFile(void) {
    char sdPath[MAX_PATH];
    BYTE* func = (BYTE*)0x006f9470;
    DWORD oldProt;

    /* Open state_dump.log */
    lstrcpynA(sdPath, g_szBasePath, MAX_PATH);
    lstrcatA(sdPath, "state_dump.log");
    g_pStateDump = fopen(sdPath, "w");
    if (g_pStateDump) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(g_pStateDump,
                "# STBC State Dump Log\n"
                "# Session started: %04d-%02d-%02d %02d:%02d:%02d\n"
                "# Press F12 at any time to dump engine state.\n"
                "# ============================================================\n\n",
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond);
        fflush(g_pStateDump);
        ProxyLog("  PatchDebugConsoleToFile: opened %s", sdPath);
    } else {
        ProxyLog("  PatchDebugConsoleToFile: WARNING could not open %s", sdPath);
    }

    /* Patch FUN_006f9470 entry: MOV EAX, <addr>; JMP EAX (7 bytes) */
    if (!IsBadReadPtr(func, 7)) {
        VirtualProtect(func, 7, PAGE_EXECUTE_READWRITE, &oldProt);
        func[0] = 0xB8;  /* MOV EAX, imm32 */
        *(DWORD*)(func + 1) = (DWORD)ReplacementDebugConsole;
        func[5] = 0xFF;  /* JMP EAX */
        func[6] = 0xE0;
        VirtualProtect(func, 7, oldProt, &oldProt);
        ProxyLog("  PatchDebugConsoleToFile: patched FUN_006f9470 -> 0x%08X",
                 (unsigned)(DWORD)ReplacementDebugConsole);
    }

    /* Ensure debug console flag (DAT_0099add6) is 1 so our path is taken
     * in FUN_006f9b80 (the exception handler dispatcher) */
    {
        BYTE* flag = (BYTE*)0x0099add6;
        if (!IsBadReadPtr(flag, 1)) {
            VirtualProtect(flag, 1, PAGE_READWRITE, &oldProt);
            *flag = 1;
            VirtualProtect(flag, 1, oldProt, &oldProt);
        }
    }
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

/* ================================================================
 * NewPlayerInGame - FUN_006a1e70
 *
 * REMOVED: Manual FUN_006a1e70 call from GameLoopTimerProc.
 *
 * Investigation (2026-02-10) found the engine's normal dispatcher at
 * 0x0069f2a0 ALREADY handles the client's 0x2A (NewPlayerInGame) by
 * calling FUN_006a1e70 internally. The client DOES send 0x2A after
 * receiving Settings+GameInit. Our manual call was redundant, causing:
 *   - Duplicate 0x35/0x37/0x17 messages
 *   - Client ACK storm (16 ACKs repeated 3x)
 *   - Double ObjNotFound for the same object
 *   - VEH crash cascade at 0x006CF1DC (double cleanup of stack buffer)
 *
 * The engine's natural path handles everything:
 *   - FUN_006a1e70 fires NewPlayerInGame event -> Python NewPlayerHandler
 *     runs and registers scoring dicts (g_kKillsDictionary, g_kDeathsDictionary)
 *   - FUN_006a1e70 calls Python InitNetwork -> sends MISSION_INIT_MESSAGE
 *     + SCORE_MESSAGEs to the joining client
 *   - FUN_006a1e70 iterates existing game objects and sends them to new player
 * ================================================================ */

/* Flag for HeartbeatThread to request Python diagnostics on main thread.
 * Python 1.5.2's allocator has NO locks - all Python C API calls MUST
 * happen on the main thread to avoid GIL violations and heap corruption. */
static volatile int g_runPyDiag = 0;

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

    /* One-time renderer pipeline verification at tick 1.
     * With PatchSkipRendererSetup active, pipeline objects at renderer offsets
     * 0xB8, 0xBC, 0xC0, 0xC4 will be NULL (pipeline creation is skipped).
     * The renderer ptr is at *(DWORD*)(appObj + 0x0C) where appObj = *(DWORD*)0x009a09d0. */
    {
        static int pipelineChecked = 0;
        if (!pipelineChecked && tickCount == 1) {
            DWORD appPtr = 0, rendPtr = 0;
            DWORD p_b8 = 0, p_bc = 0, p_c0 = 0, p_c4 = 0;
            pipelineChecked = 1;

            if (!IsBadReadPtr((void*)0x009a09d0, 4))
                appPtr = *(DWORD*)0x009a09d0;
            if (appPtr && !IsBadReadPtr((void*)(appPtr + 0x0c), 4))
                rendPtr = *(DWORD*)(appPtr + 0x0c);
            if (rendPtr) {
                if (!IsBadReadPtr((void*)(rendPtr + 0xb8), 4))
                    p_b8 = *(DWORD*)(rendPtr + 0xb8);
                if (!IsBadReadPtr((void*)(rendPtr + 0xbc), 4))
                    p_bc = *(DWORD*)(rendPtr + 0xbc);
                if (!IsBadReadPtr((void*)(rendPtr + 0xc0), 4))
                    p_c0 = *(DWORD*)(rendPtr + 0xc0);
                if (!IsBadReadPtr((void*)(rendPtr + 0xc4), 4))
                    p_c4 = *(DWORD*)(rendPtr + 0xc4);
            }
            ProxyLog("  PIPELINE CHECK: app=0x%08X renderer=0x%08X", appPtr, rendPtr);
            ProxyLog("    +0xB8=0x%08X +0xBC=0x%08X +0xC0=0x%08X +0xC4=0x%08X",
                     p_b8, p_bc, p_c0, p_c4);
            if (rendPtr && p_b8 && p_bc && p_c0 && p_c4)
                ProxyLog("    Pipeline objects ALL populated - FUN_007c3480 succeeded");
            else if (rendPtr)
                ProxyLog("    WARNING: Some pipeline objects NULL - FUN_007c3480 may have failed");
            else
                ProxyLog("    WARNING: Renderer pointer NULL - renderer not created");
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

    /* Log tick state (server build) */
    TickLogger();

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
            int connState = -1;
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

    /* Run deferred Python diagnostics requested by HeartbeatThread.
     * Must execute on main thread to avoid GIL/allocator corruption. */
    if (g_runPyDiag) {
        g_runPyDiag = 0;
        ProxyLog("  PY_DIAG: Running deferred diagnostics on main thread");
        {
            DWORD* pFrozenPtr = (DWORD*)0x00975860;
            if (!IsBadReadPtr(pFrozenPtr, 4)) {
                BYTE* entry = (BYTE*)(*(DWORD*)pFrozenPtr);
                int idx;
                ProxyLog("  PY_DIAG: FrozenModules table at %p", entry);
                for (idx = 0; idx < 5 && entry; idx++) {
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
        {
            void *modules = PY_GetModuleDict();
            ProxyLog("  PY_DIAG: sys.modules = %p", modules);
        }
        RunPyCode("pass\n");
        ProxyLog("  PY_DIAG: RunPyCode('pass') OK");
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

        /* Direct memory writes for critical flags
         * 0x0097FA88 = IsClient (0=host, 1=client) - NOT "IsHost"!
         * 0x0097FA89 = IsHost   (1=host, 0=client) - the REAL IsHost flag
         * 0x0097FA8A = IsMultiplayer (1=MP active)
         * Stock host: IsClient=0, IsHost=1, IsMp=1
         * Stock client: IsClient=1, IsHost=0, IsMp=0
         */
        VirtualProtect((void*)0x0097FA88, 4, PAGE_READWRITE, &oldProt);
        *(BYTE*)0x0097FA88 = 0;  /* IsClient = 0 (we are the host, NOT a client) */
        *(BYTE*)0x0097FA89 = 1;  /* IsHost = 1 (we ARE the host) */
        *(BYTE*)0x0097FA8A = 1;  /* IsMultiplayer = 1 */
        VirtualProtect((void*)0x0097FA88, 4, oldProt, &oldProt);

        ProxyLog("  DS_TIMER[0]: Direct flags: IsClient=%d IsHost=%d IsMultiplayer=%d",
                 (int)*(BYTE*)0x0097FA88, (int)*(BYTE*)0x0097FA89,
                 (int)*(BYTE*)0x0097FA8A);

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
            "        'Multiplayer Options', 'Player_Name', 'Dedicated Server')\n"
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
         * It also runs AI_Setup.GameInit and loads Multiplayer.tgl.
         *
         * NOTE: pCreate() enters an internal message loop, so our timer
         * fires recursively inside it. Guard against re-entrancy. */
        typedef void (__cdecl *pfn_CreateMPGame)(void);
        pfn_CreateMPGame pCreate = (pfn_CreateMPGame)0x00504f10;
        DWORD twPtr;
        static BOOL inCreate = FALSE;

        if (inCreate) {
            /* Re-entrant timer tick inside pCreate()'s message loop.
               Check if TopWindow was created while pCreate() is running. */
            twPtr = 0;
            if (!IsBadReadPtr((void*)0x0097e238, 4))
                twPtr = *(DWORD*)0x0097e238;
            if (twPtr != 0) {
                static int logOnce = 0;
                if (!logOnce) {
                    ProxyLog("  DS_TIMER[2]: TopWindow created inside pCreate(): 0x%08X", twPtr);
                    logOnce = 1;
                }
                g_iDedState = 3;
            }
            break;
        }
        ProxyLog("  DS_TIMER[2]: Creating MultiplayerGame (poll %d, nest=%d)", polls, nestLvl);
        inCreate = TRUE;
        pCreate();
        inCreate = FALSE;

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

        /* First check if Custom.DedicatedServer is loaded */
        {
            int chk = RunPyCode(
                "import sys\n"
                "_has_ds = sys.modules.has_key('Custom.DedicatedServer')\n"
                "_mods = filter(lambda k: k[:6]=='Custom', sys.modules.keys())\n"
                "print 'DS_TIMER3: has_DS=' + str(_has_ds) + ' custom_mods=' + str(_mods)\n");
            ProxyLog("  DS_TIMER[3]: pre-check rc=%d", chk);
        }

        rc = RunPyCode(
            "import sys\n"
            "try:\n"
            "    import App\n"
            "    tw = App.TopWindow_GetTopWindow()\n"
            "    print 'DS_TIMER3: tw=' + str(tw) + ' type=' + str(type(tw))\n"
            "    if tw is not None:\n"
            "        if sys.modules.has_key('Custom.DedicatedServer'):\n"
            "            ds = sys.modules['Custom.DedicatedServer']\n"
            "            print 'DS_TIMER3: calling TopWindowInitialized'\n"
            "            ds.TopWindowInitialized(tw)\n"
            "            n = ds.PatchLoadedMissionModules()\n"
            "            f = open('dedicated_init.log', 'a')\n"
            "            f.write('DS_TIMER: TopWindowInitialized called OK\\n')\n"
            "            f.write('DS_TIMER: PatchLoadedMissionModules = ' + str(n) + '\\n')\n"
            "            f.close()\n"
            "        else:\n"
            "            print 'DS_TIMER3: Custom.DedicatedServer NOT in sys.modules!'\n"
            "            f = open('dedicated_init.log', 'a')\n"
            "            f.write('DS_TIMER ERROR: Custom.DedicatedServer not loaded\\n')\n"
            "            f.close()\n"
            "    else:\n"
            "        print 'DS_TIMER3: TopWindow is None'\n"
            "        f = open('dedicated_init.log', 'a')\n"
            "        f.write('DS_TIMER: TopWindow_GetTopWindow returned None\\n')\n"
            "        f.close()\n"
            "except:\n"
            "    ei = sys.exc_info()\n"
            "    print 'DS_TIMER3 ERROR: ' + str(ei[0]) + ': ' + str(ei[1])\n"
            "    try:\n"
            "        f = open('dedicated_init.log', 'a')\n"
            "        f.write('DS_TIMER Phase3 ERROR: ' + str(ei[0]) + ': ' + str(ei[1]) + '\\n')\n"
            "        f.close()\n"
            "    except:\n"
            "        print 'DS_TIMER3: ALSO FAILED to write log!'\n");

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
         * Reinforce correct flag state after MultiplayerGame creation:
         *   0x0097FA88 = IsClient = 0 (we are the host)
         *   0x0097FA89 = IsHost = 1 (we ARE the host)
         * This is needed because CreateMultiplayerGame may alter these flags. */
        {
            DWORD oldProt;
            VirtualProtect((void*)0x0097FA88, 2, PAGE_READWRITE, &oldProt);
            *(BYTE*)0x0097FA88 = 0;  /* IsClient = 0 */
            *(BYTE*)0x0097FA89 = 1;  /* IsHost = 1 */
            VirtualProtect((void*)0x0097FA88, 2, oldProt, &oldProt);
            ProxyLog("  DS_TIMER[3]: Reinforced IsClient=0 IsHost=1 for dedicated server mode");
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

        /* Minimize the game window now that init is complete.
         * This releases the fullscreen exclusive display, freeing the GPU.
         * The game loop continues via WM_TIMER regardless of window state. */
        if (g_hGameWindow) {
            ShowWindow(g_hGameWindow, SW_MINIMIZE);
            ProxyLog("  DS_TIMER: Minimized game window (release GPU display)");
        }
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

    /* Fix sys.path: in headless mode, Autoexec.py may not set up Scripts path.
       Use absolute paths derived from g_szBasePath for reliability. */
    {
        char pyFixPath[1024];
        char fwdPath[MAX_PATH];
        int pi, prc;
        lstrcpynA(fwdPath, g_szBasePath, MAX_PATH);
        for (pi = 0; fwdPath[pi]; pi++)
            if (fwdPath[pi] == '\\') fwdPath[pi] = '/';
        wsprintfA(pyFixPath,
            "import sys\n"
            "sys.path.insert(0, '%sScripts')\n"
            "sys.path.insert(1, '%s')\n"
            "sys.path.append('%sscripts/Icons')\n"
            "sys._ds_base_path = '%s'\n",
            fwdPath, fwdPath, fwdPath, fwdPath);
        prc = PY_RunSimpleString(pyFixPath);
        ProxyLog("  PostAutoexecCallback: path-fix rc=%d", prc);
    }

    /* Import Local.py directly via C API */
    localMod = PY_ImportModule("Local");
    ProxyLog("  PostAutoexecCallback: import Local = %p", localMod);

    if (PY_ErrOccurred()) {
        void *errType = NULL, *errValue = NULL, *errTB = NULL;
        PY_ErrFetch(&errType, &errValue, &errTB);
        if (errType) {
            const char *typeName = "(bad-ptr)";
            if (!IsBadReadPtr(errType, 16)) {
                const char *namePtr = *(const char**)((char*)errType + 12);
                if (namePtr && !IsBadReadPtr(namePtr, 4))
                    typeName = namePtr;
            }
            const char *valStr = "(no-value)";
            if (errValue && !IsBadReadPtr(errValue, 24)) {
                const char *candidate = (const char*)errValue + 20;
                if (!IsBadReadPtr(candidate, 4))
                    valStr = candidate;
            }
            ProxyLog("  PostAutoexecCallback: Local import error: %s: %s",
                     typeName, valStr);
        } else {
            ProxyLog("  PostAutoexecCallback: Local import failed (no error info)");
        }
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
 * PatchDirectDrawCreateExCache - Pre-fill DAT_009a12a4
 *
 * FUN_007c7f80 checks: if (DAT_009a12a4 != NULL) skip GetModuleHandle/GetProcAddress.
 * By setting this to OUR DirectDrawCreateEx, the game calls us directly
 * and bypasses apphelp.dll's shim (which crashes with proxy DDraw objects).
 * The adapter enumeration via FUN_007c8eb0 still runs normally through our
 * DirectDrawEnumerateExA export, populating DAT_009a1298/129c/12a0.
 * ================================================================ */
static void PatchDirectDrawCreateExCache(void) {
    DWORD oldProt;
    DWORD* pDDCreateExCache = (DWORD*)0x009A12A4;
    if (!IsBadReadPtr(pDDCreateExCache, 4) && *pDDCreateExCache == 0) {
        HMODULE hSelf = GetModuleHandleA("ddraw.dll");
        FARPROC pfn = GetProcAddress(hSelf, "DirectDrawCreateEx");
        if (pfn) {
            VirtualProtect(pDDCreateExCache, 4, PAGE_READWRITE, &oldProt);
            *pDDCreateExCache = (DWORD)pfn;
            VirtualProtect(pDDCreateExCache, 4, oldProt, &oldProt);
            ProxyLog("  PatchDirectDrawCreateExCache: [0x009A12A4] = DirectDrawCreateEx (0x%08X)",
                     (unsigned)(DWORD)pfn);
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

#ifdef OBSERVE_ONLY
/* Observer mode: minimal IAT hooks for passive logging only */
static void ObserverHookIAT(void) {
    HMODULE hWs2 = GetModuleHandleA("ws2_32.dll");
    HMODULE hWsock = GetModuleHandleA("wsock32.dll");
    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    FARPROC pfn;

    /* Hook sendto */
    pfn = NULL;
    if (hWs2) pfn = GetProcAddress(hWs2, "sendto");
    if (!pfn && hWsock) pfn = GetProcAddress(hWsock, "sendto");
    if (pfn) {
        g_pfnOrigSendto = (PFN_sendto)pfn;
        if (!PatchIATEntry(pfn, (FARPROC)HookedSendto, "sendto")) {
            if (hWsock) {
                FARPROC pfn2 = GetProcAddress(hWsock, "sendto");
                if (pfn2 && pfn2 != pfn) {
                    g_pfnOrigSendto = (PFN_sendto)pfn2;
                    PatchIATEntry(pfn2, (FARPROC)HookedSendto, "sendto(wsock32)");
                }
            }
        }
    }

    /* Hook recvfrom */
    pfn = NULL;
    if (hWs2) pfn = GetProcAddress(hWs2, "recvfrom");
    if (!pfn && hWsock) pfn = GetProcAddress(hWsock, "recvfrom");
    if (pfn) {
        g_pfnOrigRecvfrom = (PFN_recvfrom)pfn;
        if (!PatchIATEntry(pfn, (FARPROC)HookedRecvfrom, "recvfrom")) {
            if (hWsock) {
                FARPROC pfn2 = GetProcAddress(hWsock, "recvfrom");
                if (pfn2 && pfn2 != pfn) {
                    g_pfnOrigRecvfrom = (PFN_recvfrom)pfn2;
                    PatchIATEntry(pfn2, (FARPROC)HookedRecvfrom, "recvfrom(wsock32)");
                }
            }
        }
    }

    /* Hook OutputDebugStringA */
    if (hKernel) {
        pfn = GetProcAddress(hKernel, "OutputDebugStringA");
        if (pfn) {
            g_pfnOrigODS = (PFN_OutputDebugStringA)pfn;
            PatchIATEntry(pfn, (FARPROC)HookedOutputDebugStringA, "OutputDebugStringA");
        }
    }
}
#endif /* OBSERVE_ONLY */

/* ================================================================
 * Globals
 * ================================================================ */
BOOL           g_bStubMode = FALSE;
BOOL           g_bHybridMode = FALSE;  /* TRUE = use real DDraw/D3D, keep server patches */
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

ProxyDevice7* CreateProxyDevice7(ProxySurface7* renderTarget, ProxyD3D7* parent) {
    ProxyDevice7* p = (ProxyDevice7*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*p));
    if (!p) return NULL;
    p->lpVtbl = g_Device7Vtbl;
    p->refCount = 1;
    p->renderTarget = renderTarget;
    p->parent = parent;
    if (parent) parent->refCount++;
    ProxyLog("CreateProxyDevice7: %p (target=%p, parent=%p)", p, renderTarget, parent);
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

/* (ParseDeviceNameFromConfig removed - g_szDeviceName has static default) */

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

/* ================================================================
 * VEHCrashLogger - Minimal first-chance exception logger
 *
 * Catches exceptions in ALL threads (including NVIDIA driver threads)
 * that bypass SetUnhandledExceptionFilter. Only logs fatal exceptions
 * (access violations, stack overflows). Returns EXCEPTION_CONTINUE_SEARCH
 * to let normal handling proceed.
 * ================================================================ */
static LONG WINAPI VEHCrashLogger(EXCEPTION_POINTERS* ep) {
    DWORD excCode = ep->ExceptionRecord->ExceptionCode;
    static volatile LONG vehCount = 0;
    LONG count;
    /* Log ALL exception types to find the original crash that triggers cascade */
    /* Suppress cascade: only log first 10 exceptions to prevent log/stack overflow */
    count = InterlockedIncrement(&vehCount);
    if (count > 10) return EXCEPTION_CONTINUE_SEARCH;
    /* Skip benign exceptions that waste our counter */
    if (excCode == 0xE06D7363 ||  /* MSVC C++ throw */
        excCode == 0x40010006 ||  /* OutputDebugString */
        excCode == 0x406D1388) {  /* MS_VC_EXCEPTION (thread naming) */
        InterlockedDecrement(&vehCount);
        return EXCEPTION_CONTINUE_SEARCH;
    }
    /* Log minimal crash info */
    ProxyLog("!!! VEH[%ld]: exception 0x%08X at EIP=0x%08X thread=%lu ECX=0x%08X EAX=0x%08X ESP=0x%08X",
             count, excCode, (DWORD)ep->ContextRecord->Eip,
             GetCurrentThreadId(),
             (DWORD)ep->ContextRecord->Ecx,
             (DWORD)ep->ContextRecord->Eax,
             (DWORD)ep->ContextRecord->Esp);
    /* Dump stack around ESP to find return addresses */
    if (count <= 5) {
        DWORD esp = ep->ContextRecord->Esp;
        DWORD ebp = ep->ContextRecord->Ebp;
        ProxyLog("!!! VEH[%ld]: EBP=0x%08X EDX=0x%08X ESI=0x%08X EDI=0x%08X",
                 count, ebp, (DWORD)ep->ContextRecord->Edx,
                 (DWORD)ep->ContextRecord->Esi, (DWORD)ep->ContextRecord->Edi);
        /* Dump 32 DWORDs from ESP (return addresses, saved regs, etc.) */
        if (!IsBadReadPtr((void*)esp, 128)) {
            DWORD* stk = (DWORD*)esp;
            ProxyLog("!!! VEH[%ld]: STACK[ESP+00..+3C]: %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X",
                     count, stk[0], stk[1], stk[2], stk[3], stk[4], stk[5], stk[6], stk[7],
                     stk[8], stk[9], stk[10], stk[11], stk[12], stk[13], stk[14], stk[15]);
            ProxyLog("!!! VEH[%ld]: STACK[ESP+40..+7C]: %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X",
                     count, stk[16], stk[17], stk[18], stk[19], stk[20], stk[21], stk[22], stk[23],
                     stk[24], stk[25], stk[26], stk[27], stk[28], stk[29], stk[30], stk[31]);
        }
        /* Walk EBP chain looking for stbc.exe return addresses */
        {
            DWORD frame = ebp;
            int i;
            for (i = 0; i < 8 && frame > 0x10000 && frame < 0x7FFFFFFF; i++) {
                if (IsBadReadPtr((void*)frame, 8)) break;
                DWORD savedEbp = *(DWORD*)frame;
                DWORD retAddr = *(DWORD*)(frame + 4);
                ProxyLog("!!! VEH[%ld]: FRAME[%d] EBP=0x%08X RET=0x%08X", count, i, frame, retAddr);
                if (savedEbp <= frame) break; /* stack grows down, EBP should increase */
                frame = savedEbp;
            }
        }
    }
    if (g_pLog) fflush(g_pLog);
    return EXCEPTION_CONTINUE_SEARCH;
}

/* ================================================================
 * CrashDumpHandler - Log full crash diagnostics then let process die
 *
 * Registered via SetUnhandledExceptionFilter. Writes detailed crash
 * info to crash_dump.log, flushes all open log files, then returns
 * EXCEPTION_CONTINUE_SEARCH so the OS terminates the process normally.
 * ================================================================ */
static LONG WINAPI CrashDumpHandler(EXCEPTION_POINTERS* ep) {
    CONTEXT* ctx = ep->ContextRecord;
    DWORD eip = (DWORD)ctx->Eip;
    DWORD excCode = ep->ExceptionRecord->ExceptionCode;
    FILE* fp;
    char path[MAX_PATH];
    char resolved[256];
    SYSTEMTIME st;
    int i;

    /* Skip benign exceptions */
    if (excCode == 0x406D1388 ||   /* SetThreadName */
        excCode == 0x40010006 ||   /* OutputDebugString */
        excCode == 0x80000003 ||   /* INT3 breakpoint */
        excCode == 0x80000004)     /* Single-step */
        return EXCEPTION_CONTINUE_SEARCH;

    /* Open crash dump log (append so multiple crashes in one session are captured) */
    if (g_szBasePath[0])
        _snprintf(path, sizeof(path), "%scrash_dump.log", g_szBasePath);
    else
        _snprintf(path, sizeof(path), "crash_dump.log");
    path[sizeof(path)-1] = '\0';
    fp = fopen(path, "a");
    if (!fp) return EXCEPTION_CONTINUE_SEARCH;

    GetLocalTime(&st);
    fprintf(fp, "========================================\n");
    fprintf(fp, "FATAL CRASH at %04d-%02d-%02d %02d:%02d:%02d.%03d\n",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    fprintf(fp, "========================================\n\n");

    /* Exception info */
    ResolveAddr(eip, resolved, sizeof(resolved));
    fprintf(fp, "Exception: 0x%08X at EIP=%s\n", (unsigned)excCode, resolved);
    if (excCode == 0xC0000005) {
        DWORD rw = (DWORD)ep->ExceptionRecord->ExceptionInformation[0];
        DWORD faultAddr = (DWORD)ep->ExceptionRecord->ExceptionInformation[1];
        fprintf(fp, "Access violation: %s 0x%08X\n",
                rw == 0 ? "reading" : rw == 1 ? "writing" : "executing",
                (unsigned)faultAddr);
    } else if (excCode == 0xC00000FD) {
        fprintf(fp, "STACK OVERFLOW\n");
    }

    /* Register dump */
    fprintf(fp, "\nRegisters:\n");
    fprintf(fp, "  EAX=%08X  EBX=%08X  ECX=%08X  EDX=%08X\n",
            (unsigned)ctx->Eax, (unsigned)ctx->Ebx,
            (unsigned)ctx->Ecx, (unsigned)ctx->Edx);
    fprintf(fp, "  ESI=%08X  EDI=%08X  EBP=%08X  ESP=%08X\n",
            (unsigned)ctx->Esi, (unsigned)ctx->Edi,
            (unsigned)ctx->Ebp, (unsigned)ctx->Esp);
    fprintf(fp, "  EIP=%08X  EFlags=%08X\n",
            (unsigned)ctx->Eip, (unsigned)ctx->EFlags);

    /* EBP chain stack walk */
    fprintf(fp, "\nStack trace (EBP chain):\n");
    {
        DWORD* frame = (DWORD*)ctx->Ebp;
        for (i = 0; i < 32 && frame; i++) {
            DWORD retAddr;
            if (IsBadReadPtr(frame, 8)) break;
            retAddr = frame[1];
            if (retAddr == 0) break;
            ResolveAddr(retAddr, resolved, sizeof(resolved));
            fprintf(fp, "  [%2d] %s\n", i, resolved);
            frame = (DWORD*)frame[0];
            if ((DWORD)frame < 0x10000 || (DWORD)frame > 0x7FFFFFFF) break;
        }
    }

    /* Raw stack hex dump (256 bytes from ESP) */
    fprintf(fp, "\nRaw stack (256 bytes from ESP=0x%08X):\n", (unsigned)ctx->Esp);
    if (!IsBadReadPtr((void*)ctx->Esp, 256)) {
        BYTE* sp = (BYTE*)ctx->Esp;
        for (i = 0; i < 256; i += 16) {
            int j;
            fprintf(fp, "  %08X: ", (unsigned)(ctx->Esp + i));
            for (j = 0; j < 16; j++)
                fprintf(fp, "%02X ", sp[i + j]);
            fprintf(fp, " ");
            for (j = 0; j < 16; j++) {
                BYTE b = sp[i + j];
                fprintf(fp, "%c", (b >= 0x20 && b < 0x7F) ? b : '.');
            }
            fprintf(fp, "\n");
        }
    }

    /* Code bytes around crash EIP (32 before, 32 after) */
    fprintf(fp, "\nCode bytes around EIP=0x%08X:\n  ", (unsigned)eip);
    if (!IsBadReadPtr((void*)(eip - 32), 64)) {
        BYTE* code = (BYTE*)eip;
        for (i = -32; i < 32; i++) {
            if (i == 0) fprintf(fp, "[%02X] ", code[i]);
            else        fprintf(fp, "%02X ", code[i]);
        }
        fprintf(fp, "\n");
    }

    /* Memory at key register targets */
    {
        struct { const char* name; DWORD val; } regs[] = {
            {"EAX", ctx->Eax}, {"ECX", ctx->Ecx}, {"ESI", ctx->Esi},
            {"EDI", ctx->Edi}, {"EBX", ctx->Ebx}, {"EDX", ctx->Edx}
        };
        fprintf(fp, "\nMemory at registers:\n");
        for (i = 0; i < 6; i++) {
            if (regs[i].val >= 0x10000 && !IsBadReadPtr((void*)regs[i].val, 32)) {
                DWORD* p = (DWORD*)regs[i].val;
                fprintf(fp, "  [%s=0x%08lX]: %08lX %08lX %08lX %08lX %08lX %08lX %08lX %08lX\n",
                        regs[i].name, (unsigned long)regs[i].val,
                        (unsigned long)p[0], (unsigned long)p[1],
                        (unsigned long)p[2], (unsigned long)p[3],
                        (unsigned long)p[4], (unsigned long)p[5],
                        (unsigned long)p[6], (unsigned long)p[7]);
            }
        }
    }

    fprintf(fp, "\n");
    fclose(fp);

    /* Flush all open log files */
    if (g_pLog) fflush(g_pLog);
    if (g_pPacketLog) fflush(g_pPacketLog);
    if (g_pTickLog) fflush(g_pTickLog);
    if (g_pStateDump) fflush(g_pStateDump);

    /* One-liner to main proxy log */
    ResolveAddr(eip, resolved, sizeof(resolved));
    ProxyLog("!!! FATAL CRASH: exception 0x%08X at %s - see crash_dump.log",
             (unsigned)excCode, resolved);
    if (g_pLog) fflush(g_pLog);

    return EXCEPTION_CONTINUE_SEARCH;
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

            /* Request Python diagnostics on main thread at 15s.
             * NEVER call Python C API from this thread - the allocator
             * has no locks and concurrent access causes heap corruption. */
            if (i == 30 && pyInit) {
                g_runPyDiag = 1;
                ProxyLog("  HEARTBEAT: Requested Python diagnostics on main thread");
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
            /* NOTE: Do NOT call LogPyModules or any Python C API from this thread.
             * Python 1.5.2 allocator has no locks - concurrent access = heap corruption. */
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

#ifndef OBSERVE_ONLY
        /* Install crash dump handler (logs diagnostics, lets process die) */
        SetUnhandledExceptionFilter(CrashDumpHandler);
        /* Also install VEH first-chance handler to catch driver-thread crashes
         * that bypass SetUnhandledExceptionFilter. This is MINIMAL - log only,
         * no recovery, only fires for fatal exceptions. */
        AddVectoredExceptionHandler(1, VEHCrashLogger);

        g_dwMainThreadId = GetCurrentThreadId();
        DuplicateHandle(GetCurrentProcess(), GetCurrentThread(),
                        GetCurrentProcess(), &g_hMainThread,
                        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                        FALSE, 0);
#endif /* !OBSERVE_ONLY */

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
        PktTraceOpen();
        /* Set CWD to game directory - critical when launched from WSL/cmd */
        SetCurrentDirectoryA(g_szBasePath);

        ProxyLog("DDraw Proxy loaded");
        ProxyLog("Base path: %s", g_szBasePath);

#ifdef OBSERVE_ONLY
        /* OBSERVER MODE: passive logging only, no patches */
        ProxyLog("OBSERVE_ONLY build - passive packet/event logging, zero patches");
        SetEnvironmentVariableA("STBC_GAME_DIR", g_szBasePath);
        ProxyLog("Set STBC_GAME_DIR=%s", g_szBasePath);

        /* Write basepath file for Python to read (absolute path discovery) */
        {
            char bpPath[MAX_PATH];
            FILE* bpf;
            lstrcpynA(bpPath, g_szBasePath, MAX_PATH);
            lstrcatA(bpPath, "Scripts\\Custom\\_basepath");
            bpf = fopen(bpPath, "w");
            if (bpf) {
                fprintf(bpf, "%s", g_szBasePath);
                fclose(bpf);
                ProxyLog("Wrote _basepath: %s", bpPath);
            }
        }

        /* Write Python config module with game dir as constant string.
         * NOTE: BC's embedded Python has file writing disabled (open() for 'w'
         * fails for all paths including nt.open). Only the import machinery
         * can write .pyc files. Python logging must go through C hooks. */
        {
            char cfgPath[MAX_PATH];
            FILE* cfgf;
            const char* p;
            lstrcpynA(cfgPath, g_szBasePath, MAX_PATH);
            lstrcatA(cfgPath, "Scripts\\Custom\\_config.py");
            cfgf = fopen(cfgPath, "w");
            if (cfgf) {
                fprintf(cfgf, "GAME_DIR = \"");
                for (p = g_szBasePath; *p; p++) {
                    if (*p == '\\') fprintf(cfgf, "\\\\");
                    else fputc(*p, cfgf);
                }
                fprintf(cfgf, "\"\n");
                fclose(cfgf);
                ProxyLog("Wrote _config.py: %s", cfgPath);
            }
        }

        PatchDebugConsoleToFile();
        MsgTraceOpen();
        ObserverHookIAT();
#else
        /* Check for dedicated server mode */
        lstrcpynA(filePath, g_szBasePath, MAX_PATH);
        lstrcatA(filePath, "dedicated.cfg");
        hCfg = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ,
                            NULL, OPEN_EXISTING, 0, NULL);
        if (hCfg != INVALID_HANDLE_VALUE) {
            CloseHandle(hCfg);
            g_bStubMode = TRUE;
            g_bHybridMode = TRUE;  /* Use real renderer with server patches */
            ProxyLog("dedicated.cfg found - HYBRID MODE (real renderer + server patches)");

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

            /* Apply patches for hybrid mode */
            HookGameIAT();
            InlineHookMessageBoxA();
            /* PatchRenderTick REMOVED again - objects need scene graph updates to initialize properly */
            /* PatchRendererCtorEntry REMOVED - let the real NiDX7Renderer constructor
               run so the renderer has valid internal state (arrays, matrices, frustum). */
            PatchInitAbort();         /* Prevent abort when init check fails */
            PatchPyFatalError();      /* Make Py_FatalError return instead of tail-calling abort */
            PatchCreateAppModule();   /* Create SWIG "App" module before init imports it */
            /* PatchDirectDrawCreateExCache REMOVED (hybrid) - real DDCreateEx fills cache naturally */
            /* PatchSkipRendererSetup REMOVED - let the full pipeline run. */
            PatchSkipDeviceLost();    /* Skip device-lost recreation path (safety) */
            PatchSkipDisplayModeSearch(); /* Skip mode enumeration, use direct SetDisplayMode */
            /* PatchRendererMethods REMOVED (hybrid) - real renderer handles camera/frustum */
            /* PatchDeviceCapsRawCopy REMOVED (hybrid) - real Device7 has valid caps */
            PatchHeadlessCrashSites(); /* NOP subtitle/notification pane lookups (pane #5 not created in dedi boot) */
            PatchTGLFindEntry();      /* TGL FindEntry: return NULL when this==NULL */
            PatchNetworkUpdateNullLists(); /* Clear subsys/weapon flags when lists NULL (safety) */
            PatchSubsystemHashCheck(); /* Fix false-positive anti-cheat when subsystems NULL (safety) */
            PatchCompressedVectorRead(); /* Validate vtable in compressed vector read (safety) */
            PatchNullThunk_00419960(); /* NULL-check [ECX+0x1C] vtable thunk (AsteroidField tick) */
            PatchStreamReadNullBuffer(); /* NULL buffer check in stream read (network deserialization) */
            PatchDebugConsoleToFile(); /* Redirect Python exceptions to state_dump.log */
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
#endif /* !OBSERVE_ONLY */

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
        if (g_pTickLog) {
            fflush(g_pTickLog);
            fclose(g_pTickLog);
            g_pTickLog = NULL;
        }
        if (g_pPacketLog) {
            fclose(g_pPacketLog);
            g_pPacketLog = NULL;
        }
        if (g_pLog) {
            fclose(g_pLog);
            g_pLog = NULL;
        }
    }
    return TRUE;
}

/* ================================================================
 * Hybrid mode: DDraw7 vtable intercepts
 *
 * When hybrid mode is active, we patch the real IDirectDraw7 vtable to:
 * - SetCooperativeLevel (slot 20): Passthrough, capture HWND, minimize
 * - SetDisplayMode (slot 21): Force 32bpp (16bpp not supported on modern GPUs)
 *
 * Combined with PatchSkipDisplayModeSearch (which bypasses mode enumeration),
 * this lets the engine go fullscreen exclusive at a GPU-supported bit depth.
 * ================================================================ */
typedef HRESULT (WINAPI *PFN_SetCooperativeLevel)(void*, HWND, DWORD);
typedef HRESULT (WINAPI *PFN_SetDisplayMode)(void*, DWORD, DWORD, DWORD, DWORD, DWORD);
static PFN_SetCooperativeLevel g_pfnRealSetCoopLevel = NULL;
static PFN_SetDisplayMode g_pfnRealSetDisplayMode = NULL;

static HRESULT WINAPI HybridSetCooperativeLevel(void* pThis, HWND hwnd, DWORD flags) {
    HRESULT hr;
    static int logCount = 0;
    static BOOL exclusiveSet = FALSE;

    g_hGameWindow = hwnd;
    if (logCount < 10)
        ProxyLog("HYBRID SetCooperativeLevel hwnd=%p flags=0x%08X%s", hwnd, flags,
                 (exclusiveSet && !(flags & DDSCL_EXCLUSIVE)) ? " -> BLOCKED (keep exclusive)" : "");
    logCount++;

    /* Once we're in exclusive mode, block any attempt to drop to DDSCL_NORMAL.
       The engine's "fallback to windowed" path would destroy our exclusive surface chain. */
    if (exclusiveSet && !(flags & DDSCL_EXCLUSIVE)) {
        return DD_OK;  /* Pretend it succeeded, stay in exclusive mode */
    }

    hr = g_pfnRealSetCoopLevel(pThis, hwnd, flags);
    if (logCount <= 10)
        ProxyLog("  SetCooperativeLevel result=0x%08X", hr);

    if (SUCCEEDED(hr) && (flags & DDSCL_EXCLUSIVE)) {
        exclusiveSet = TRUE;
    }

    return hr;
}

static HRESULT WINAPI HybridSetDisplayMode(void* pThis, DWORD w, DWORD h, DWORD bpp,
                                           DWORD refreshRate, DWORD flags) {
    HRESULT hr;
    DWORD origBpp = bpp;
    static int logCount = 0;
    /* Force 32bpp — 16bpp fullscreen not supported on modern displays */
    if (bpp == 16) bpp = 32;
    hr = g_pfnRealSetDisplayMode(pThis, w, h, bpp, refreshRate, flags);
    if (logCount < 5)
        ProxyLog("HYBRID SetDisplayMode %lux%lu@%lu (was %lu) result=0x%08X",
                 w, h, bpp, origBpp, hr);
    logCount++;
    return hr;
}

/* ================================================================
 * Exported functions
 * ================================================================ */
HRESULT WINAPI DirectDrawCreate(GUID* lpGUID, void** lplpDD, void* pUnkOuter) {
    ProxyLog("DirectDrawCreate called");
    if (g_bStubMode && !g_bHybridMode) {
        *lplpDD = CreateProxyDDraw7();
        return *lplpDD ? DD_OK : DDERR_GENERIC;
    }
    if (g_pfnDDCreate) return g_pfnDDCreate(lpGUID, lplpDD, pUnkOuter);
    return DDERR_GENERIC;
}

HRESULT WINAPI DirectDrawCreateEx(GUID* lpGUID, void** lplpDD,
                                                         const GUID* iid, void* pUnkOuter) {
    ProxyLog("DirectDrawCreateEx called (hybrid=%d)", g_bHybridMode);
    if (g_bStubMode && !g_bHybridMode) {
        *lplpDD = CreateProxyDDraw7();
        return *lplpDD ? DD_OK : DDERR_GENERIC;
    }
    if (g_pfnDDCreateEx) {
        HRESULT hr = g_pfnDDCreateEx(lpGUID, lplpDD, iid, pUnkOuter);
        ProxyLog("  DirectDrawCreateEx result=0x%08X obj=%p", hr, *lplpDD);
        /* In hybrid mode, patch the real DDraw7 vtable for windowed operation */
        if (g_bHybridMode && SUCCEEDED(hr) && *lplpDD) {
            void** vtbl = *(void***)(*lplpDD);  /* IDirectDraw7 vtable */
            DWORD oldProt;
            /* Patch slots 20 (SetCooperativeLevel) and 21 (SetDisplayMode) */
            if (VirtualProtect(&vtbl[20], 2 * sizeof(void*), PAGE_READWRITE, &oldProt)) {
                if (!g_pfnRealSetCoopLevel) {
                    g_pfnRealSetCoopLevel = (PFN_SetCooperativeLevel)vtbl[20];
                    g_pfnRealSetDisplayMode = (PFN_SetDisplayMode)vtbl[21];
                }
                vtbl[20] = (void*)HybridSetCooperativeLevel;
                vtbl[21] = (void*)HybridSetDisplayMode;
                VirtualProtect(&vtbl[20], 2 * sizeof(void*), oldProt, &oldProt);
                ProxyLog("HYBRID: Patched DDraw7 vtable[20,21] (SetCoopLevel + SetDisplayMode)");
            }
        }
        return hr;
    }
    return DDERR_GENERIC;
}

HRESULT WINAPI DirectDrawEnumerateA(void* lpCallback, void* lpContext) {
    ProxyLog("DirectDrawEnumerateA called");
    if (g_bStubMode && !g_bHybridMode) {
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
    if (g_bStubMode && !g_bHybridMode) {
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
