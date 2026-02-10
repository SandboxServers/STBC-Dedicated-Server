/*
 * ddraw_proxy.h - DirectDraw 7 Proxy/Stub for Bridge Commander Dedicated Server
 *
 * Implements minimal DirectDraw 7 + Direct3D 7 COM interfaces that satisfy
 * NetImmerse 3.1's initialization without performing any actual rendering.
 *
 * When dedicated.cfg exists: stub mode (zero rendering overhead)
 * When dedicated.cfg absent: forward to real system ddraw.dll
 */
#ifndef DDRAW_PROXY_H
#define DDRAW_PROXY_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* ================================================================
 * HRESULT / Error codes
 * ================================================================ */
#define DD_OK                   S_OK
#define DD_FALSE                S_FALSE
#define DDERR_GENERIC           E_FAIL
#define DDERR_UNSUPPORTED       E_NOTIMPL
#define DDERR_INVALIDPARAMS     E_INVALIDARG
#define DDERR_NOTFOUND          ((HRESULT)0x887600FFul)
#define DDERR_SURFACELOST       ((HRESULT)0x887600D4ul)
#define D3D_OK                  S_OK
#define D3DERR_SCENE_IN_SCENE   ((HRESULT)0x88760145ul)
#define D3DERR_SCENE_NOT_IN_SCENE ((HRESULT)0x88760146ul)

/* ================================================================
 * DDSD flags (DDSURFACEDESC2.dwFlags)
 * ================================================================ */
#define DDSD_CAPS               0x00000001
#define DDSD_HEIGHT             0x00000002
#define DDSD_WIDTH              0x00000004
#define DDSD_PITCH              0x00000008
#define DDSD_BACKBUFFERCOUNT    0x00000020
#define DDSD_ZBUFFERBITDEPTH    0x00000040
#define DDSD_PIXELFORMAT        0x00001000
#define DDSD_MIPMAPCOUNT        0x00020000
#define DDSD_LPSURFACE          0x00000800
#define DDSD_TEXTURESTAGE       0x00100000

/* ================================================================
 * DDSCAPS flags
 * ================================================================ */
#define DDSCAPS_BACKBUFFER      0x00000004
#define DDSCAPS_COMPLEX         0x00000008
#define DDSCAPS_FLIP            0x00000010
#define DDSCAPS_FRONTBUFFER     0x00000020
#define DDSCAPS_OFFSCREENPLAIN  0x00000040
#define DDSCAPS_PRIMARYSURFACE  0x00000200
#define DDSCAPS_SYSTEMMEMORY    0x00000800
#define DDSCAPS_TEXTURE         0x00001000
#define DDSCAPS_3DDEVICE        0x00002000
#define DDSCAPS_VIDEOMEMORY     0x00004000
#define DDSCAPS_ZBUFFER         0x00020000
#define DDSCAPS_MIPMAP          0x00400000
#define DDSCAPS_LOCALVIDMEM     0x10000000

/* ================================================================
 * DDCAPS flags (IDirectDraw7::GetCaps dwCaps field)
 * ================================================================ */
#define DDCAPS_3D               0x00000001
#define DDCAPS_BLT              0x00000040
#define DDCAPS_BLTSTRETCH       0x00000200
#define DDCAPS_GDI              0x00000400
#define DDCAPS_PALETTE          0x00008000
#define DDCAPS_ZBLTS            0x00100000
#define DDCAPS_COLORKEY         0x00400000
#define DDCAPS_BLTCOLORFILL     0x04000000
#define DDCAPS_BLTDEPTHFILL     0x10000000
#define DDCAPS_CANCLIP          0x20000000
#define DDCAPS_CANBLTSYSMEM     0x80000000

/* ================================================================
 * DDPF flags (DDPIXELFORMAT.dwFlags)
 * ================================================================ */
#define DDPF_ALPHAPIXELS        0x00000001
#define DDPF_FOURCC             0x00000004
#define DDPF_PALETTEINDEXED8    0x00000020
#define DDPF_RGB                0x00000040
#define DDPF_ZBUFFER            0x00000400
#define DDPF_STENCILBUFFER      0x00004000

/* ================================================================
 * DDSCL flags (SetCooperativeLevel)
 * ================================================================ */
#define DDSCL_FULLSCREEN        0x00000001
#define DDSCL_NORMAL            0x00000008
#define DDSCL_EXCLUSIVE         0x00000010

/* ================================================================
 * Render bit depth flags
 * ================================================================ */
#define DDBD_8                  0x00000800
#define DDBD_16                 0x00000400
#define DDBD_24                 0x00000200
#define DDBD_32                 0x00000100

/* ================================================================
 * D3D device capability flags
 * ================================================================ */
#define D3DDEVCAPS_FLOATTLVERTEX          0x00000001
#define D3DDEVCAPS_EXECUTESYSTEMMEMORY    0x00000010
#define D3DDEVCAPS_TLVERTEXSYSTEMMEMORY   0x00000040
#define D3DDEVCAPS_TEXTUREVIDEOMEMORY     0x00000200
#define D3DDEVCAPS_DRAWPRIMTLVERTEX       0x00000400
#define D3DDEVCAPS_CANRENDERAFTERFLIP     0x00000800
#define D3DDEVCAPS_DRAWPRIMITIVES2        0x00002000
#define D3DDEVCAPS_DRAWPRIMITIVES2EX      0x00008000
#define D3DDEVCAPS_HWTRANSFORMANDLIGHT    0x00010000
#define D3DDEVCAPS_HWRASTERIZATION        0x00080000

/* D3DPRIMCAPS misc */
#define D3DPMISCCAPS_MASKZ                0x00000002
#define D3DPMISCCAPS_CULLNONE             0x00000010
#define D3DPMISCCAPS_CULLCW               0x00000020
#define D3DPMISCCAPS_CULLCCW              0x00000040

/* D3DPRIMCAPS raster */
#define D3DPRASTERCAPS_DITHER             0x00000001
#define D3DPRASTERCAPS_ZTEST              0x00000010
#define D3DPRASTERCAPS_FOGVERTEX          0x00000080
#define D3DPRASTERCAPS_FOGTABLE           0x00000100
#define D3DPRASTERCAPS_ZBIAS              0x00004000
#define D3DPRASTERCAPS_WBUFFER            0x00040000
#define D3DPRASTERCAPS_WFOG               0x00100000
#define D3DPRASTERCAPS_ZFOG               0x00200000

/* D3DPRIMCAPS Z compare */
#define D3DPCMPCAPS_NEVER                 0x00000001
#define D3DPCMPCAPS_LESS                  0x00000002
#define D3DPCMPCAPS_EQUAL                 0x00000004
#define D3DPCMPCAPS_LESSEQUAL             0x00000008
#define D3DPCMPCAPS_GREATER               0x00000010
#define D3DPCMPCAPS_NOTEQUAL              0x00000020
#define D3DPCMPCAPS_GREATEREQUAL          0x00000040
#define D3DPCMPCAPS_ALWAYS                0x00000080

/* D3DPRIMCAPS blend */
#define D3DPBLENDCAPS_ZERO                0x00000001
#define D3DPBLENDCAPS_ONE                 0x00000002
#define D3DPBLENDCAPS_SRCCOLOR            0x00000004
#define D3DPBLENDCAPS_INVSRCCOLOR         0x00000008
#define D3DPBLENDCAPS_SRCALPHA            0x00000010
#define D3DPBLENDCAPS_INVSRCALPHA         0x00000020
#define D3DPBLENDCAPS_DESTALPHA           0x00000040
#define D3DPBLENDCAPS_INVDESTALPHA        0x00000080
#define D3DPBLENDCAPS_DESTCOLOR           0x00000100
#define D3DPBLENDCAPS_INVDESTCOLOR        0x00000200
#define D3DPBLENDCAPS_SRCALPHASAT         0x00000400

/* D3DPRIMCAPS shade */
#define D3DPSHADECAPS_COLORGOURAUDRGB     0x00000008
#define D3DPSHADECAPS_SPECULARGOURAUDRGB  0x00000200
#define D3DPSHADECAPS_ALPHAGOURAUDBLEND   0x00004000
#define D3DPSHADECAPS_FOGGOURAUD          0x00080000

/* D3DPRIMCAPS texture */
#define D3DPTEXTURECAPS_PERSPECTIVE       0x00000001
#define D3DPTEXTURECAPS_POW2              0x00000002
#define D3DPTEXTURECAPS_ALPHA             0x00000004
#define D3DPTEXTURECAPS_TRANSPARENCY      0x00000008

/* D3DPRIMCAPS texture filter */
#define D3DPTFILTERCAPS_NEAREST           0x00000001
#define D3DPTFILTERCAPS_LINEAR            0x00000002
#define D3DPTFILTERCAPS_MIPNEAREST        0x00000004
#define D3DPTFILTERCAPS_MIPLINEAR         0x00000008
#define D3DPTFILTERCAPS_LINEARMIPNEAREST  0x00000010
#define D3DPTFILTERCAPS_LINEARMIPLINEAR   0x00000020
#define D3DPTFILTERCAPS_MINFPOINT         0x00000100
#define D3DPTFILTERCAPS_MINFLINEAR        0x00000200
#define D3DPTFILTERCAPS_MIPFPOINT         0x00010000
#define D3DPTFILTERCAPS_MIPFLINEAR        0x00020000
#define D3DPTFILTERCAPS_MAGFPOINT         0x01000000
#define D3DPTFILTERCAPS_MAGFLINEAR        0x02000000

/* D3DPRIMCAPS texture address */
#define D3DPTADDRESSCAPS_WRAP             0x00000001
#define D3DPTADDRESSCAPS_MIRROR           0x00000002
#define D3DPTADDRESSCAPS_CLAMP            0x00000004
#define D3DPTADDRESSCAPS_INDEPENDENTUV    0x00000010

/* D3D texture op caps */
#define D3DTEXOPCAPS_DISABLE              0x00000001
#define D3DTEXOPCAPS_SELECTARG1           0x00000002
#define D3DTEXOPCAPS_SELECTARG2           0x00000004
#define D3DTEXOPCAPS_MODULATE             0x00000008
#define D3DTEXOPCAPS_ADD                  0x00000040

/* D3D stencil caps */
#define D3DSTENCILCAPS_KEEP               0x00000001
#define D3DSTENCILCAPS_ZERO               0x00000002
#define D3DSTENCILCAPS_REPLACE            0x00000004
#define D3DSTENCILCAPS_INCRSAT            0x00000008
#define D3DSTENCILCAPS_DECRSAT            0x00000010
#define D3DSTENCILCAPS_INVERT             0x00000020

/* D3D FVF caps */
#define D3DFVFCAPS_TEXCOORDCOUNTMASK      0x0000FFFF

/* D3D vertex processing caps */
#define D3DVTXPCAPS_DIRECTIONALLIGHTS     0x00000008
#define D3DVTXPCAPS_POSITIONALLIGHTS      0x00000010
#define D3DVTXPCAPS_LOCALVIEWER           0x00000020

/* ================================================================
 * DirectDraw Structures
 * ================================================================ */

typedef struct {
    DWORD dwColorSpaceLowValue;
    DWORD dwColorSpaceHighValue;
} DDCOLORKEY;

typedef struct {
    DWORD dwSize;
    DWORD dwFlags;
    DWORD dwFourCC;
    DWORD dwRGBBitCount;    /* union: also dwYUVBitCount, dwZBufferBitDepth, etc. */
    DWORD dwRBitMask;       /* union: also dwStencilBitDepth, etc. */
    DWORD dwGBitMask;       /* union: also dwZBitMask, etc. */
    DWORD dwBBitMask;       /* union: also dwStencilBitMask, etc. */
    DWORD dwRGBAlphaBitMask;/* union: also dwYUVAlphaBitMask, etc. */
} DDPIXELFORMAT_X;

typedef struct {
    DWORD dwCaps;
    DWORD dwCaps2;
    DWORD dwCaps3;
    DWORD dwCaps4;
} DDSCAPS2_X;

/* DDSURFACEDESC2 - 124 bytes on 32-bit */
typedef struct {
    DWORD           dwSize;             /* 0 */
    DWORD           dwFlags;            /* 4 */
    DWORD           dwHeight;           /* 8 */
    DWORD           dwWidth;            /* 12 */
    LONG            lPitch;             /* 16: also dwLinearSize */
    DWORD           dwBackBufferCount;  /* 20: also dwDepth */
    DWORD           dwMipMapCount;      /* 24: also dwRefreshRate */
    DWORD           dwAlphaBitDepth;    /* 28 */
    DWORD           dwReserved;         /* 32 */
    void*           lpSurface;          /* 36 */
    DDCOLORKEY      ddckCKDestOverlay;  /* 40 */
    DDCOLORKEY      ddckCKDestBlt;      /* 48 */
    DDCOLORKEY      ddckCKSrcOverlay;   /* 56 */
    DDCOLORKEY      ddckCKSrcBlt;       /* 64 */
    DDPIXELFORMAT_X ddpfPixelFormat;    /* 72: 32 bytes */
    DDSCAPS2_X      ddsCaps;            /* 104: 16 bytes */
    DWORD           dwTextureStage;     /* 120 */
} DDSURFACEDESC2_X;

/* DDCAPS - we only care about dwSize, dwCaps, dwCaps2, rest is padding */
#define DDCAPS_DX7_SIZE 380
typedef struct {
    DWORD dwSize;       /* 0 */
    DWORD dwCaps;       /* 4 */
    DWORD dwCaps2;      /* 8 */
    BYTE  padding[DDCAPS_DX7_SIZE - 12];
} DDCAPS_X;

/* DDDEVICEIDENTIFIER2 */
#define MAX_DDDEVICEID_STRING 512
typedef struct {
    char            szDriver[MAX_DDDEVICEID_STRING];
    char            szDescription[MAX_DDDEVICEID_STRING];
    LARGE_INTEGER   liDriverVersion;
    DWORD           dwVendorId;
    DWORD           dwDeviceId;
    DWORD           dwSubSysId;
    DWORD           dwRevision;
    GUID            guidDeviceIdentifier;
    DWORD           dwWHQLLevel;
} DDDEVICEIDENTIFIER2_X;

/* ================================================================
 * Direct3D 7 Structures
 * ================================================================ */

typedef struct { float x, y, z; } D3DVECTOR_X;

typedef struct {
    float _11, _12, _13, _14;
    float _21, _22, _23, _24;
    float _31, _32, _33, _34;
    float _41, _42, _43, _44;
} D3DMATRIX_X;

typedef struct {
    DWORD dwX, dwY, dwWidth, dwHeight;
    float dvMinZ, dvMaxZ;
} D3DVIEWPORT7_X;

typedef struct { float r, g, b, a; } D3DCOLORVALUE_X;

typedef struct {
    D3DCOLORVALUE_X dcvDiffuse;
    D3DCOLORVALUE_X dcvAmbient;
    D3DCOLORVALUE_X dcvSpecular;
    D3DCOLORVALUE_X dcvEmissive;
    float           dvPower;
} D3DMATERIAL7_X;

typedef struct {
    DWORD           dltType;
    D3DCOLORVALUE_X dcvDiffuse;
    D3DCOLORVALUE_X dcvSpecular;
    D3DCOLORVALUE_X dcvAmbient;
    D3DVECTOR_X     dvPosition;
    D3DVECTOR_X     dvDirection;
    float           dvRange;
    float           dvFalloff;
    float           dvAttenuation0;
    float           dvAttenuation1;
    float           dvAttenuation2;
    float           dvTheta;
    float           dvPhi;
} D3DLIGHT7_X;

typedef struct { LONG x1, y1, x2, y2; } D3DRECT_X;

typedef struct {
    DWORD dwSize;
    DWORD dwMiscCaps;
    DWORD dwRasterCaps;
    DWORD dwZCmpCaps;
    DWORD dwSrcBlendCaps;
    DWORD dwDestBlendCaps;
    DWORD dwAlphaCmpCaps;
    DWORD dwShadeCaps;
    DWORD dwTextureCaps;
    DWORD dwTextureFilterCaps;
    DWORD dwTextureBlendCaps;
    DWORD dwTextureAddressCaps;
    DWORD dwStippleWidth;
    DWORD dwStippleHeight;
} D3DPRIMCAPS_X;

typedef struct {
    DWORD           dwDevCaps;
    D3DPRIMCAPS_X   dpcLineCaps;
    D3DPRIMCAPS_X   dpcTriCaps;
    DWORD           dwDeviceRenderBitDepth;
    DWORD           dwDeviceZBufferBitDepth;
    DWORD           dwMinTextureWidth;
    DWORD           dwMinTextureHeight;
    DWORD           dwMaxTextureWidth;
    DWORD           dwMaxTextureHeight;
    DWORD           dwMaxTextureRepeat;
    DWORD           dwMaxTextureAspectRatio;
    DWORD           dwMaxAnisotropy;
    float           dvGuardBandLeft;
    float           dvGuardBandTop;
    float           dvGuardBandRight;
    float           dvGuardBandBottom;
    float           dvExtentsAdjust;
    DWORD           dwStencilCaps;
    DWORD           dwFVFCaps;
    DWORD           dwTextureOpCaps;
    WORD            wMaxTextureBlendStages;
    WORD            wMaxSimultaneousTextures;
    DWORD           dwMaxActiveLights;
    float           dvMaxVertexW;
    GUID            deviceGUID;
    WORD            wMaxUserClipPlanes;
    WORD            wMaxVertexBlendMatrices;
    DWORD           dwVertexProcessingCaps;
    DWORD           dwReserved1;
    DWORD           dwReserved2;
    DWORD           dwReserved3;
    DWORD           dwReserved4;
} D3DDEVICEDESC7_X;

typedef struct {
    DWORD dwSize;
    DWORD dwCaps;
    DWORD dwFVF;
    DWORD dwNumVertices;
} D3DVERTEXBUFFERDESC_X;

/* ================================================================
 * Callback typedefs
 * ================================================================ */
typedef HRESULT (CALLBACK *LPDDENUMMODESCALLBACK2)(DDSURFACEDESC2_X*, void*);
typedef HRESULT (CALLBACK *LPDDENUMSURFACESCALLBACK7)(void*, DDSURFACEDESC2_X*, void*);
typedef HRESULT (CALLBACK *LPD3DENUMDEVICESCALLBACK7)(char*, char*, D3DDEVICEDESC7_X*, void*);
typedef HRESULT (CALLBACK *LPD3DENUMPIXELFORMATSCALLBACK)(DDPIXELFORMAT_X*, void*);

/* ================================================================
 * GUIDs
 * ================================================================ */
/* IID_IDirectDraw7:   {15e65ec0-3b9c-11d2-b92f-00609797ea5b} */
static const GUID IID_IDirectDraw7 =
    {0x15e65ec0, 0x3b9c, 0x11d2, {0xb9,0x2f,0x00,0x60,0x97,0x97,0xea,0x5b}};

/* IID_IDirect3D7:     {f5049e77-4861-11d2-a407-00a0c90629a8} */
static const GUID IID_IDirect3D7 =
    {0xf5049e77, 0x4861, 0x11d2, {0xa4,0x07,0x00,0xa0,0xc9,0x06,0x29,0xa8}};

/* IID_IDirect3DHALDevice: {84e63de0-46aa-11cf-816f-0000c020156e} */
static const GUID IID_IDirect3DHALDevice =
    {0x84e63de0, 0x46aa, 0x11cf, {0x81,0x6f,0x00,0x00,0xc0,0x20,0x15,0x6e}};

/* IID_IDirect3DTnLHalDevice: {f5049e78-4861-11d2-a407-00a0c90629a8} */
static const GUID IID_IDirect3DTnLHalDevice =
    {0xf5049e78, 0x4861, 0x11d2, {0xa4,0x07,0x00,0xa0,0xc9,0x06,0x29,0xa8}};

/* IID_IDirectDrawSurface7: {06675a80-3b9b-11d2-b92f-00609797ea5b} */
static const GUID IID_IDirectDrawSurface7 =
    {0x06675a80, 0x3b9b, 0x11d2, {0xb9,0x2f,0x00,0x60,0x97,0x97,0xea,0x5b}};

/* ================================================================
 * Proxy object types
 * ================================================================ */

typedef struct ProxyDDraw7 {
    void** lpVtbl;
    LONG   refCount;
    HWND   hwnd;
    DWORD  coopLevel;
    DWORD  displayWidth;
    DWORD  displayHeight;
    DWORD  displayBpp;
} ProxyDDraw7;

typedef struct ProxySurface7 {
    void** lpVtbl;
    LONG   refCount;
    DWORD  width;
    DWORD  height;
    DWORD  bpp;
    LONG   pitch;
    DWORD  caps;
    BYTE*  pixelData;
    DWORD  pixelDataSize;
    DDPIXELFORMAT_X pixelFormat;
    struct ProxySurface7* backBuffer;
    struct ProxySurface7* zBuffer;
    struct ProxySurface7* mipmap;    /* next mipmap level (half-size) */
    void*  clipper;
} ProxySurface7;

typedef struct ProxyD3D7 {
    void** lpVtbl;
    LONG   refCount;
    ProxyDDraw7* parent;
} ProxyD3D7;

typedef struct ProxyDevice7 {
    void** lpVtbl;
    LONG   refCount;
    ProxySurface7* renderTarget;
    BOOL   inScene;
    struct ProxyD3D7* parent;  /* back-ref for GetDirect3D */
    BYTE   _niPadding[236];   /* NI reads 59 DWORDs (236 bytes) from Device7 ptr directly,
                                  bypassing COM. Zeros are safe (NULL ptrs, disabled caps). */
} ProxyDevice7;

typedef struct ProxyClipper {
    void** lpVtbl;
    LONG   refCount;
    HWND   hwnd;
} ProxyClipper;

typedef struct ProxyVB7 {
    void** lpVtbl;
    LONG   refCount;
    BYTE*  data;
    DWORD  dataSize;
    DWORD  fvf;
    DWORD  numVertices;
} ProxyVB7;

/* ================================================================
 * Helpers
 * ================================================================ */
static __inline BOOL IsEqualGUID_X(const GUID* a, const GUID* b) {
    return memcmp(a, b, sizeof(GUID)) == 0;
}

/* Setup standard 16-bit 565 pixel format */
static __inline void SetPixelFormat565(DDPIXELFORMAT_X* pf) {
    memset(pf, 0, sizeof(*pf));
    pf->dwSize = sizeof(DDPIXELFORMAT_X);
    pf->dwFlags = DDPF_RGB;
    pf->dwRGBBitCount = 16;
    pf->dwRBitMask = 0xF800;
    pf->dwGBitMask = 0x07E0;
    pf->dwBBitMask = 0x001F;
}

/* Setup 32-bit ARGB pixel format */
static __inline void SetPixelFormat8888(DDPIXELFORMAT_X* pf) {
    memset(pf, 0, sizeof(*pf));
    pf->dwSize = sizeof(DDPIXELFORMAT_X);
    pf->dwFlags = DDPF_RGB | DDPF_ALPHAPIXELS;
    pf->dwRGBBitCount = 32;
    pf->dwRBitMask = 0x00FF0000;
    pf->dwGBitMask = 0x0000FF00;
    pf->dwBBitMask = 0x000000FF;
    pf->dwRGBAlphaBitMask = 0xFF000000;
}

/* Setup 16-bit Z-buffer pixel format */
static __inline void SetPixelFormatZ16(DDPIXELFORMAT_X* pf) {
    memset(pf, 0, sizeof(*pf));
    pf->dwSize = sizeof(DDPIXELFORMAT_X);
    pf->dwFlags = DDPF_ZBUFFER;
    pf->dwRGBBitCount = 16; /* dwZBufferBitDepth */
    pf->dwRBitMask = 0;     /* dwStencilBitDepth */
    pf->dwGBitMask = 0xFFFF;/* dwZBitMask */
}

/* Fill D3DPRIMCAPS with reasonable HAL-like capabilities */
static __inline void FillPrimCaps(D3DPRIMCAPS_X* caps) {
    memset(caps, 0, sizeof(*caps));
    caps->dwSize = sizeof(D3DPRIMCAPS_X);
    caps->dwMiscCaps = D3DPMISCCAPS_MASKZ | D3DPMISCCAPS_CULLNONE |
                       D3DPMISCCAPS_CULLCW | D3DPMISCCAPS_CULLCCW;
    caps->dwRasterCaps = D3DPRASTERCAPS_DITHER | D3DPRASTERCAPS_ZTEST |
                         D3DPRASTERCAPS_FOGVERTEX | D3DPRASTERCAPS_FOGTABLE |
                         D3DPRASTERCAPS_WBUFFER | D3DPRASTERCAPS_WFOG |
                         D3DPRASTERCAPS_ZFOG;
    caps->dwZCmpCaps = D3DPCMPCAPS_NEVER | D3DPCMPCAPS_LESS | D3DPCMPCAPS_EQUAL |
                       D3DPCMPCAPS_LESSEQUAL | D3DPCMPCAPS_GREATER |
                       D3DPCMPCAPS_NOTEQUAL | D3DPCMPCAPS_GREATEREQUAL |
                       D3DPCMPCAPS_ALWAYS;
    caps->dwSrcBlendCaps = D3DPBLENDCAPS_ZERO | D3DPBLENDCAPS_ONE |
                           D3DPBLENDCAPS_SRCCOLOR | D3DPBLENDCAPS_INVSRCCOLOR |
                           D3DPBLENDCAPS_SRCALPHA | D3DPBLENDCAPS_INVSRCALPHA |
                           D3DPBLENDCAPS_DESTALPHA | D3DPBLENDCAPS_INVDESTALPHA |
                           D3DPBLENDCAPS_DESTCOLOR | D3DPBLENDCAPS_INVDESTCOLOR |
                           D3DPBLENDCAPS_SRCALPHASAT;
    caps->dwDestBlendCaps = caps->dwSrcBlendCaps;
    caps->dwAlphaCmpCaps = caps->dwZCmpCaps;
    caps->dwShadeCaps = D3DPSHADECAPS_COLORGOURAUDRGB | D3DPSHADECAPS_SPECULARGOURAUDRGB |
                        D3DPSHADECAPS_ALPHAGOURAUDBLEND | D3DPSHADECAPS_FOGGOURAUD;
    caps->dwTextureCaps = D3DPTEXTURECAPS_PERSPECTIVE | D3DPTEXTURECAPS_ALPHA |
                          D3DPTEXTURECAPS_TRANSPARENCY;
    caps->dwTextureFilterCaps = D3DPTFILTERCAPS_NEAREST | D3DPTFILTERCAPS_LINEAR |
                                D3DPTFILTERCAPS_MIPNEAREST | D3DPTFILTERCAPS_MIPLINEAR |
                                D3DPTFILTERCAPS_LINEARMIPNEAREST | D3DPTFILTERCAPS_LINEARMIPLINEAR |
                                D3DPTFILTERCAPS_MINFPOINT | D3DPTFILTERCAPS_MINFLINEAR |
                                D3DPTFILTERCAPS_MIPFPOINT | D3DPTFILTERCAPS_MIPFLINEAR |
                                D3DPTFILTERCAPS_MAGFPOINT | D3DPTFILTERCAPS_MAGFLINEAR;
    caps->dwTextureAddressCaps = D3DPTADDRESSCAPS_WRAP | D3DPTADDRESSCAPS_MIRROR |
                                 D3DPTADDRESSCAPS_CLAMP | D3DPTADDRESSCAPS_INDEPENDENTUV;
}

/* ================================================================
 * Logging and globals
 * ================================================================ */
void ProxyLog(const char* fmt, ...);
extern BOOL g_bStubMode;               /* TRUE = stub mode, FALSE = forward */
extern HWND g_hGameWindow;             /* Game's main window handle */
extern char g_szBasePath[MAX_PATH];     /* DLL's directory (game root) */
extern char g_szDeviceName[512];        /* GPU name parsed from Options.cfg */

/* ================================================================
 * Creation functions
 * ================================================================ */
ProxyDDraw7*   CreateProxyDDraw7(void);
ProxySurface7* CreateProxySurface7(DWORD width, DWORD height, DWORD bpp, DWORD caps);
ProxyD3D7*     CreateProxyD3D7(ProxyDDraw7* parent);
ProxyDevice7*  CreateProxyDevice7(ProxySurface7* renderTarget, ProxyD3D7* parent);
ProxyClipper*  CreateProxyClipper(void);
ProxyVB7*      CreateProxyVB7(DWORD fvf, DWORD numVertices);

#endif /* DDRAW_PROXY_H */
