> [docs](../README.md) / [networking](README.md) / gamespy-crypto-analysis.md

# GameSpy Challenge-Response Crypto Analysis

## Overview

Bridge Commander uses the standard GameSpy QR1 (Query/Reporting version 1) challenge-response
protocol for two purposes:

1. **Server-side (QR)**: When a master server sends `\secure\<challenge>` to validate a game
   server is real, the server must respond with `\validate\<hash>`.
2. **Client-side (Server List)**: When a client connects to the master server on TCP 28900 to
   browse servers, the master sends `\secure\<challenge>` and the client must respond with
   `\validate\<hash>` embedded in its `\gamename\...\validate\...\final\` response.

Both paths use identical crypto: RC4 encryption with the game's secret key, followed by a
custom base64-like encoding.

## Secret Key

**Value**: `"Nm3aZ9"` (6 bytes)
**Location**: Hardcoded at FUN_0069c3a0 (GameSpy::InitBrowser), pushed onto stack as a local:
```c
builtin_strncpy(local_c, "Nm3aZ9", 7);
```

This is then passed to `gs_list_init` (FUN_006aa100) as `param_3`, which copies it into the
server list struct at offset +0x0B (field `puVar4 + 0xb`, i.e., byte offset 0x2C from the
malloc'd base).

In the QR path (`qr_send_validate_and_final` at 0x006ac950), the secret key is at
`param_1 + 0x12` in the qr_t struct. Since `param_1` is typed as `SOCKET*` (4 bytes each),
offset `+0x12` in SOCKET-pointer units = byte offset `0x12 * 4 = 0x48` from the qr_t base.
Looking at the qr_t layout, this falls within the game name field region (qr_t+0x08 is the
game name, 32 bytes max). **However**, re-examining the decompilation more carefully:

The qr_t struct is NOT an array of SOCKETs. Ghidra typed `param_1` as `SOCKET*` because
`param_1[0]` is a SOCKET, but the struct has mixed types. `param_1 + 0x12` means
`(char*)param_1 + 0x12*sizeof(SOCKET)` = `base + 0x48` -- which is within the secret key
field at qr_t+0x28 (a separate 32-byte field for the secret key, after the game name).

Actually, looking at the gs_list_init code path more carefully:

```c
// param_1 = "bcommander", param_3 = "Nm3aZ9"
// puVar4 = malloc(0xA0) -- the server list struct

// Game name copied to offset 3 (puVar4 + 3) = byte 0x0C
pcVar9 = (char *)(puVar4 + 3);    // offset +0x0C

// Secret key copied to offset 0xB (puVar4 + 0xB) = byte 0x2C
pcVar9 = (char *)(puVar4 + 0xb);  // offset +0x2C

// Second game name(?) copied to offset 0x13 (puVar4 + 0x13) = byte 0x4C
pcVar9 = (char *)(puVar4 + 0x13); // offset +0x4C
```

And in SL_master_connect (FUN_006aa4c0):
```c
// Secret key at param_1 + 0xb = byte offset 0x2C -- matches gs_list_init!
FUN_006ac050((int)(param_1 + 0xb), 6, (int)(pcVar3 + 8), 6);
//           ^secret_key            ^key_len  ^challenge      ^challenge_len
```

## The Algorithm (3 Functions)

### 1. gs_rc4_cipher (0x006ac050) -- "gs_xor_key" / RC4 Encryption

This is a **modified RC4** stream cipher. It encrypts the challenge data in-place using the
secret key.

**Prototype**: `void __cdecl gs_rc4_cipher(int key, int keyLen, int data, int dataLen)`

**Reconstructed C code**:
```c
void gs_rc4_cipher(unsigned char *key, int keyLen,
                   unsigned char *data, int dataLen)
{
    unsigned char S[256];
    int i, j, k;

    // KSA (Key Scheduling Algorithm) -- standard RC4
    for (i = 0; i < 256; i++)
        S[i] = (unsigned char)i;

    j = 0;
    k = 0;
    for (i = 0; i < 256; i++) {
        j = (unsigned char)(S[i] + j + key[k]);
        k = (unsigned char)((k + 1) % keyLen);
        SWAP(S[i], S[j]);
    }

    // PRGA (Pseudo-Random Generation Algorithm) -- MODIFIED!
    // Standard RC4 uses: i = (i+1) % 256
    // This uses:         i = (data[n] + 1 + i) % 256
    // The data byte itself is mixed into the index!
    i = 0;
    j = 0;
    for (int n = 0; n < dataLen; n++) {
        i = (unsigned char)(data[n] + 1 + i);    // <-- NON-STANDARD
        j = (unsigned char)(S[i] + j);
        SWAP(S[i], S[j]);
        data[n] ^= S[(unsigned char)(S[j] + S[i])];
    }
}
```

**Key difference from standard RC4**: In the PRGA phase, standard RC4 increments `i` by 1
each iteration (`i = (i+1) % 256`). This implementation uses
`i = (data[n] + 1 + i) % 256` -- the plaintext byte is mixed into the index before
encryption. This makes it a **non-standard RC4 variant** specific to GameSpy's QR1 SDK.

The `FUN_006ac1c0` call is a simple byte swap:
```c
void swap_bytes(unsigned char *a, unsigned char *b) {
    unsigned char tmp = *a;
    *a = *b;
    *b = tmp;
}
```

### 2. gs_validate_encode (0x006abf70) -- Base64-like Encoding

After RC4 encryption, the binary ciphertext must be converted to printable ASCII for
embedding in the `\validate\` field. This function performs a base64-like encoding.

**Prototype**: `void __cdecl gs_validate_encode(unsigned char *src, int srcLen, unsigned char *dst)`

**Reconstructed C code**:
```c
void gs_validate_encode(unsigned char *src, int srcLen, unsigned char *dst)
{
    int i = 0;
    unsigned char triple[3];

    if (srcLen < 1) {
        *dst = 0;
        return;
    }

    do {
        // Read 3 bytes (pad with 0 if beyond srcLen)
        for (int j = 0; j < 3; j++, i++) {
            if (i < srcLen)
                triple[j] = src[i];   // Note: reads from LOCAL copy on stack
            else
                triple[j] = 0;
        }

        // Split 3 bytes (24 bits) into 4 x 6-bit values
        unsigned char a = triple[0] >> 2;
        unsigned char b = ((triple[0] & 0x03) << 4) | (triple[1] >> 4);
        unsigned char c = ((triple[1] & 0x0F) << 2) | (triple[2] >> 6);
        unsigned char d = triple[2] & 0x3F;

        // Encode each 6-bit value to a printable character
        *dst++ = gs_encode_char(a);
        *dst++ = gs_encode_char(b);
        *dst++ = gs_encode_char(c);
        *dst++ = gs_encode_char(d);

    } while (i < srcLen);

    *dst = 0;  // NULL terminate
}
```

**NOTE**: The decompilation shows the source bytes are read into what Ghidra displays as
`(int)&param_3 + iVar2` -- this is actually reading into a local stack variable (3-byte
triple buffer). Ghidra's decompilation is confused because the triple is stored in the same
stack slot as the `param_3` pointer. The actual semantics are: read 3 bytes from `src` into
a local buffer, then encode 4 output bytes.

The encoding ratio is standard base64: 3 input bytes become 4 output bytes.
For a 6-byte input (the challenge), output is 8 characters + NULL terminator.

### 3. gs_encode_char (0x006ac020) -- Character Mapping

Maps a 6-bit value (0-63) to a printable ASCII character.

**Prototype**: `unsigned char __cdecl gs_encode_char(unsigned char val)`

**Reconstructed C code**:
```c
unsigned char gs_encode_char(unsigned char val)
{
    if (val < 26)           // 0-25 -> 'A'-'Z'
        return val + 'A';   // 0x41
    if (val < 52)           // 26-51 -> 'a'-'z'
        return val + 'G';   // 0x47 (26 + 0x47 = 0x61 = 'a')
    if (val < 62)           // 52-61 -> '0'-'9'
        return val - 4;     // 0x30..0x39 (52 - 4 = 48 = '0')
    if (val == 62)          // 62 -> '+'
        return '+';         // 0x2B
    if (val == 63)          // 63 -> '/'
        return '/';         // 0x2F
    return 0;               // shouldn't happen
}
```

This is **exactly standard Base64** character mapping (RFC 4648 Table 1):
`A-Z a-z 0-9 + /`

Note: the last case `(param_1 != 0x3f) - 1U & 0x2f` resolves to:
- If val == 63: `(0) - 1 = 0xFFFFFFFF`, `& 0x2F = 0x2F = '/'`
- If val > 63: `(1) - 1 = 0`, `& 0x2F = 0x00` (never reached with 6-bit input)

## Full Validation Flow

### QR Path (Server responding to master server query)

In `qr_send_validate_and_final` (FUN_006ac950):

```
1. Master sends UDP query containing "\secure\<CHALLENGE>"
2. qr_parse_query extracts the challenge string (param_4)
3. qr_send_validate_and_final:
   a. Copy challenge to local buffer (local_248, max 128 bytes)
   b. Get secret key from qr_t+0x48 (the key stored at init time)
   c. Compute key length via strlen(secret_key)
   d. RC4-encrypt challenge in-place:
      gs_rc4_cipher(secret_key, keyLen, challenge_copy, challengeLen)
   e. Base64-encode the encrypted result:
      gs_validate_encode(challenge_copy, challengeLen, encoded_output)
   f. Format response string: sprintf(buf, "\\validate\\%s", encoded_output)
   g. Send via qr_assemble_response (FUN_006ac660)
   h. Send "\\final\\" trailer
   i. Flush buffer via qr_flush_send (FUN_006ac550)
```

### Server List Path (Client authenticating with master)

In `SL_master_connect` (FUN_006aa4c0):

```
1. Client connects to master on TCP 28900
2. Master sends: "...\secure\<CHALLENGE>..."
3. Client parses out "\secure\" prefix, gets challenge at pcVar3+8
4. RC4-encrypt the 6-byte challenge with the 6-byte secret key:
   gs_rc4_cipher(server_list+0x2C, 6, challenge_ptr+8, 6)
   // key = "Nm3aZ9" (at offset 0x2C in server list struct)
   // keyLen = 6
   // data = 6-byte challenge token
   // dataLen = 6
5. Base64-encode the result:
   gs_validate_encode(challenge_ptr+8, 6, local_40)
   // Produces 8-char encoded string
6. Format response:
   sprintf(buf, "\\gamename\\%s\\gamever\\%s\\location\\0\\validate\\%s\\final\\\\queryid\\1.1\\",
           gamename, gamever, encoded_result)
7. Send via TCP send()
```

## Reimplementation

Here is a complete, standalone C reimplementation of the GameSpy challenge-response:

```c
/*
 * GameSpy QR1 Challenge-Response Implementation
 * For Bridge Commander ("bcommander", secret key "Nm3aZ9")
 *
 * Usage:
 *   char validate[16];
 *   gs_compute_validate("Nm3aZ9", challenge_string, validate, sizeof(validate));
 *   // validate now contains the base64-encoded response
 */

#include <string.h>

static void gs_swap(unsigned char *a, unsigned char *b)
{
    unsigned char tmp = *a;
    *a = *b;
    *b = tmp;
}

static unsigned char gs_encode_char(unsigned char val)
{
    if (val < 26)  return val + 'A';        /* A-Z */
    if (val < 52)  return val + ('a' - 26); /* a-z */
    if (val < 62)  return val + ('0' - 52); /* 0-9 */
    if (val == 62) return '+';
    if (val == 63) return '/';
    return 0;
}

/*
 * GameSpy modified RC4 cipher.
 * Encrypts 'data' in-place using 'key'.
 *
 * IMPORTANT: This is NOT standard RC4!
 * The PRGA phase mixes the plaintext byte into the index:
 *   i = (data[n] + 1 + i) % 256   (standard RC4 uses i = (i+1) % 256)
 */
static void gs_rc4_cipher(const unsigned char *key, int keyLen,
                           unsigned char *data, int dataLen)
{
    unsigned char S[256];
    int n;
    unsigned char i, j, k;

    /* KSA - Key Scheduling Algorithm (standard RC4) */
    for (n = 0; n < 256; n++)
        S[n] = (unsigned char)n;

    j = 0;
    k = 0;
    for (n = 0; n < 256; n++) {
        j = (unsigned char)(S[n] + j + key[k]);
        k = (unsigned char)((k + 1) % keyLen);
        gs_swap(&S[n], &S[j]);
    }

    /* PRGA - Pseudo-Random Generation Algorithm (MODIFIED) */
    i = 0;
    j = 0;
    for (n = 0; n < dataLen; n++) {
        i = (unsigned char)(data[n] + 1 + i);   /* non-standard! */
        j = (unsigned char)(S[i] + j);
        gs_swap(&S[i], &S[j]);
        data[n] ^= S[(unsigned char)(S[j] + S[i])];
    }
}

/*
 * GameSpy base64-like encoding.
 * Encodes 'srcLen' bytes from 'src' into 'dst' as printable ASCII.
 * 'dst' must have room for (srcLen+2)/3*4 + 1 bytes.
 */
static void gs_validate_encode(const unsigned char *src, int srcLen,
                                char *dst)
{
    int i = 0;

    if (srcLen < 1) {
        *dst = 0;
        return;
    }

    while (i < srcLen) {
        unsigned char triple[3];
        unsigned char a, b, c, d;
        int j;

        /* Read up to 3 bytes, zero-pad if needed */
        for (j = 0; j < 3; j++) {
            if (i < srcLen)
                triple[j] = src[i];
            else
                triple[j] = 0;
            i++;
        }

        /* Split 24 bits into 4 x 6-bit values */
        a =  triple[0] >> 2;
        b = ((triple[0] & 0x03) << 4) | (triple[1] >> 4);
        c = ((triple[1] & 0x0F) << 2) | (triple[2] >> 6);
        d =  triple[2] & 0x3F;

        /* Encode to printable characters */
        *dst++ = gs_encode_char(a);
        *dst++ = gs_encode_char(b);
        *dst++ = gs_encode_char(c);
        *dst++ = gs_encode_char(d);
    }

    *dst = 0;  /* NULL terminate */
}

/*
 * High-level: compute the \validate\ response for a GameSpy challenge.
 *
 * secret_key: Game secret key ("Nm3aZ9" for Bridge Commander)
 * challenge:  The challenge string from \secure\<challenge>
 * out:        Output buffer for encoded validate string
 * outSize:    Size of output buffer (>= 16 for 6-byte challenges)
 */
void gs_compute_validate(const char *secret_key,
                          const char *challenge,
                          char *out, int outSize)
{
    unsigned char buf[128];
    int challengeLen = strlen(challenge);
    int keyLen = strlen(secret_key);

    if (challengeLen > (int)sizeof(buf))
        challengeLen = (int)sizeof(buf);

    /* Copy challenge -- RC4 encrypts in-place */
    memcpy(buf, challenge, challengeLen);

    /* RC4-encrypt with game secret key */
    gs_rc4_cipher((const unsigned char *)secret_key, keyLen,
                  buf, challengeLen);

    /* Base64-encode the ciphertext */
    gs_validate_encode(buf, challengeLen, out);
}
```

## Wire Format Examples

### QR (Server) Response to Master
```
Master -> Server (UDP): \secure\ABCDEF
Server -> Master (UDP): \validate\XXXXXXXX\final\\queryid\1.1\
```

### Server List (Client) Auth with Master
```
Master -> Client (TCP): ...\secure\ABCDEF...
Client -> Master (TCP): \gamename\bcommander\gamever\1.1\location\0\validate\XXXXXXXX\final\\queryid\1.1\
```

In both cases, `XXXXXXXX` is the 8-character base64-encoded result of RC4-encrypting the
6-byte challenge with "Nm3aZ9".

## Server List Struct Layout (from gs_list_init / FUN_006aa100)

The malloc'd 0xA0-byte server list struct:

| Offset | Size | Field | Set By |
|--------|------|-------|--------|
| +0x00 | 4 | State/status | FUN_006aa660 |
| +0x04 | 4 | Server entry linked list | FUN_006ad180 |
| +0x08 | 4 | Timer/poll struct | FUN_006acb30 |
| +0x0C | 32 | Game name ("bcommander") | gs_list_init, copied from param_1 |
| +0x2C | 32 | Secret key ("Nm3aZ9") | gs_list_init, copied from param_3 |
| +0x4C | 32 | Game name copy (param_2) | gs_list_init, copied from param_2 |
| +0x6C | 4 | Num basic fields (param_4=10) | gs_list_init |
| +0x70 | 4 | Basic field memory | malloc(param_4 * 0x1c) |
| +0x78 | 4 | Basic info callback | gs_list_init (param_5 = LAB_0069c420) |
| +0x7C | 4 | User data (GameSpy this ptr) | gs_list_init (param_7) |
| +0x80 | 4 | Window name ref | gs_list_init (&lpWindowName_0097dc28) |
| +0x88 | 4 | TCP socket (master conn) | gs_master_tcp_connect |
| +0x98 | 4 | Connection result | SL_master_connect |
| +0x9C | 4 | Padding/unused | |

## qr_t Struct Layout (Corrected)

The qr_t struct passed to `qr_send_validate_and_final`. Since Ghidra types the first
parameter as `SOCKET*`, all `+N` offsets mean byte offset = `N * sizeof(SOCKET)` = `N * 4`:

| Ghidra Offset | Byte Offset | Field |
|---------------|-------------|-------|
| +0x00 | +0x00 | Query socket (SOCKET) |
| +0x01 | +0x04 | Heartbeat socket (SOCKET) |
| +0x02 | +0x08 | Game name (char[32]) |
| +0x12 | +0x48 | Secret key (char[32]) |
| +0x32 | +0xC8 | Basic info callback |
| +0x33 | +0xCC | Rules callback |
| +0x34 | +0xD0 | Players callback |
| +0x36 | +0xD8 | Last heartbeat tick |
| +0x38 | +0xE0 | Query sequence counter |
| +0x39 | +0xE4 | Active flag |
| +0x3A | +0xE8 | Heartbeat retry counter |
| +0x3B | +0xEC | Total query counter |

## Can We Reimplement This?

**Yes, absolutely.** The algorithm is:

1. **Standard RC4 KSA** (key scheduling) -- identical to textbook RC4
2. **Modified RC4 PRGA** -- one-line change: `i = (data[n] + 1 + i)` instead of `i = (i + 1)`
3. **Standard Base64 encoding** with the canonical `A-Za-z0-9+/` alphabet

The secret key `"Nm3aZ9"` is publicly known (it was extracted from the binary years ago
and is documented in GameSpy open-source SDK reimplementations like OpenSpy and 333networks).

For our dedicated server:
- We can call the existing functions in the binary (at 0x006ac050 and 0x006abf70) via
  function pointer casts in our C code
- OR we can reimplement them entirely in the proxy DLL (cleaner, no dependency on exact
  binary layout)
- The challenge from the master is typically 6 random bytes; the response is always 8
  printable base64 characters

### Calling Existing Binary Functions

```c
/* Function pointer typedefs for the existing binary functions */
typedef void (__cdecl *fn_gs_rc4_cipher)(int key, int keyLen, int data, int dataLen);
typedef void (__cdecl *fn_gs_validate_encode)(unsigned char *src, int srcLen, unsigned char *dst);

#define GS_RC4_CIPHER         ((fn_gs_rc4_cipher)0x006ac050)
#define GS_VALIDATE_ENCODE    ((fn_gs_validate_encode)0x006abf70)

void compute_validate_from_binary(const char *challenge, char *out)
{
    char buf[128];
    int len = strlen(challenge);
    memcpy(buf, challenge, len);

    GS_RC4_CIPHER((int)"Nm3aZ9", 6, (int)buf, len);
    GS_VALIDATE_ENCODE((unsigned char *)buf, len, (unsigned char *)out);
}
```

## Verification Against Known Implementations

This algorithm matches the GameSpy QR1 SDK `gs_encrypt()` / `gs_encode()` functions
documented in:
- OpenSpy server source
- 333networks master server source
- Luigi Auriemma's gslist tool
- The original GameSpy SDK (leaked/archived versions)

The "modified RC4" with `data[n] + 1 + i` is the distinguishing feature of GameSpy's
implementation and is well-known in the game server emulation community.
