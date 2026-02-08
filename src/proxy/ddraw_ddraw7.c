/*
 * ddraw_ddraw7.c - IDirectDraw7 interface implementation (30 vtable entries)
 */
#include "ddraw_proxy.h"

/* ================================================================
 * IDirectDraw7 Methods
 * ================================================================ */

/* 0: QueryInterface */
static HRESULT WINAPI DD7_QueryInterface(ProxyDDraw7* This, const GUID* riid, void** ppv) {
    ProxyLog("DD7::QueryInterface");
    if (!ppv) return DDERR_INVALIDPARAMS;

    if (IsEqualGUID_X(riid, &IID_IDirect3D7)) {
        ProxyLog("  -> Creating IDirect3D7");
        *ppv = CreateProxyD3D7(This);
        return *ppv ? S_OK : DDERR_GENERIC;
    }
    if (IsEqualGUID_X(riid, &IID_IDirectDraw7)) {
        *ppv = This;
        This->refCount++;
        return S_OK;
    }
    ProxyLog("  -> Unknown IID");
    *ppv = NULL;
    return E_NOINTERFACE;
}

/* 1: AddRef */
static ULONG WINAPI DD7_AddRef(ProxyDDraw7* This) {
    return ++This->refCount;
}

/* 2: Release */
static ULONG WINAPI DD7_Release(ProxyDDraw7* This) {
    LONG ref = --This->refCount;
    if (ref <= 0) {
        ProxyLog("DD7::Release -> destroying");
        HeapFree(GetProcessHeap(), 0, This);
    }
    return ref;
}

/* 3: Compact */
static HRESULT WINAPI DD7_Compact(ProxyDDraw7* This) { ProxyLog("DD7::Compact"); return DD_OK; }

/* 4: CreateClipper */
static HRESULT WINAPI DD7_CreateClipper(ProxyDDraw7* This, DWORD flags, void** lplpClipper, void* unk) {
    ProxyLog("DD7::CreateClipper");
    *lplpClipper = CreateProxyClipper();
    return *lplpClipper ? DD_OK : DDERR_GENERIC;
}

/* 5: CreatePalette */
static HRESULT WINAPI DD7_CreatePalette(ProxyDDraw7* This, DWORD flags, void* entries, void** ppPal, void* unk) {
    ProxyLog("DD7::CreatePalette (stub)");
    if (ppPal) *ppPal = NULL;
    return DDERR_UNSUPPORTED;
}

/* 6: CreateSurface */
static HRESULT WINAPI DD7_CreateSurface(ProxyDDraw7* This, DDSURFACEDESC2_X* desc,
                                         void** ppSurf, void* unk) {
    DWORD w, h, bpp, caps;
    ProxySurface7* primary;
    ProxySurface7* back;

    if (!desc || !ppSurf) return DDERR_INVALIDPARAMS;

    caps = desc->ddsCaps.dwCaps;
    w = (desc->dwFlags & DDSD_WIDTH) ? desc->dwWidth : This->displayWidth;
    h = (desc->dwFlags & DDSD_HEIGHT) ? desc->dwHeight : This->displayHeight;
    bpp = This->displayBpp;

    if (desc->dwFlags & DDSD_PIXELFORMAT) {
        bpp = desc->ddpfPixelFormat.dwRGBBitCount;
        if (bpp == 0) bpp = This->displayBpp;
    }

    /* For texture surfaces, add MIPMAP flag so mipmap chains can be
       traversed.  Real DDraw drivers typically auto-create mipmap levels
       for all textures.  The engine expects this. */
    if ((caps & DDSCAPS_TEXTURE) && !(caps & DDSCAPS_ZBUFFER)) {
        caps |= DDSCAPS_MIPMAP;
    }

    ProxyLog("DD7::CreateSurface caps=0x%08X %dx%dx%d flags=0x%08X mipCount=%d caps2=0x%08X",
             caps, w, h, bpp, desc->dwFlags, desc->dwMipMapCount, desc->ddsCaps.dwCaps2);

    primary = CreateProxySurface7(w, h, bpp, caps);
    if (!primary) return DDERR_GENERIC;

    /* If primary + complex + flip, auto-create back buffer */
    if ((caps & DDSCAPS_PRIMARYSURFACE) && (caps & DDSCAPS_COMPLEX) && (caps & DDSCAPS_FLIP)) {
        back = CreateProxySurface7(w, h, bpp, DDSCAPS_BACKBUFFER | DDSCAPS_3DDEVICE);
        primary->backBuffer = back;
        ProxyLog("  -> Auto-created back buffer");
    }

    /* Z-buffer: set pixel format */
    if (caps & DDSCAPS_ZBUFFER) {
        SetPixelFormatZ16(&primary->pixelFormat);
        primary->bpp = 16;
    }

    *ppSurf = primary;
    return DD_OK;
}

/* 7: DuplicateSurface */
static HRESULT WINAPI DD7_DuplicateSurface(ProxyDDraw7* This, void* src, void** dst) {
    ProxyLog("DD7::DuplicateSurface (stub)");
    if (dst) *dst = NULL;
    return DDERR_UNSUPPORTED;
}

/* 8: EnumDisplayModes */
static HRESULT WINAPI DD7_EnumDisplayModes(ProxyDDraw7* This, DWORD flags,
                                            DDSURFACEDESC2_X* filter, void* ctx,
                                            LPDDENUMMODESCALLBACK2 cb) {
    DDSURFACEDESC2_X desc;
    static const struct { DWORD w, h, bpp; } modes[] = {
        {640, 480, 16}, {800, 600, 16}, {1024, 768, 16},
        {640, 480, 32}, {800, 600, 32}, {1024, 768, 32},
    };
    int i;

    ProxyLog("DD7::EnumDisplayModes");
    if (!cb) return DDERR_INVALIDPARAMS;

    for (i = 0; i < 6; i++) {
        memset(&desc, 0, sizeof(desc));
        desc.dwSize = sizeof(DDSURFACEDESC2_X);
        desc.dwFlags = DDSD_WIDTH | DDSD_HEIGHT | DDSD_PIXELFORMAT | DDSD_PITCH;
        desc.dwWidth = modes[i].w;
        desc.dwHeight = modes[i].h;
        desc.lPitch = (LONG)(modes[i].w * (modes[i].bpp / 8));
        desc.dwMipMapCount = 60; /* dwRefreshRate */
        if (modes[i].bpp == 32)
            SetPixelFormat8888(&desc.ddpfPixelFormat);
        else
            SetPixelFormat565(&desc.ddpfPixelFormat);
        desc.ddsCaps.dwCaps = DDSCAPS_PRIMARYSURFACE | DDSCAPS_FLIP | DDSCAPS_COMPLEX |
                              DDSCAPS_3DDEVICE | DDSCAPS_VIDEOMEMORY | DDSCAPS_LOCALVIDMEM;
        {
            HRESULT cbRet = cb(&desc, ctx);
            ProxyLog("  Mode %dx%dx%d cb returned 0x%08X", modes[i].w, modes[i].h, modes[i].bpp, (unsigned)cbRet);
            if (cbRet == 0) break; /* DDENUMRET_CANCEL */
        }
    }
    return DD_OK;
}

/* 9: EnumSurfaces */
static HRESULT WINAPI DD7_EnumSurfaces(ProxyDDraw7* This, DWORD flags, DDSURFACEDESC2_X* desc,
                                        void* ctx, LPDDENUMSURFACESCALLBACK7 cb) {
    ProxyLog("DD7::EnumSurfaces");
    return DD_OK;
}

/* 10: FlipToGDISurface */
static HRESULT WINAPI DD7_FlipToGDISurface(ProxyDDraw7* This) { ProxyLog("DD7::FlipToGDISurface"); return DD_OK; }

/* 11: GetCaps */
static HRESULT WINAPI DD7_GetCaps(ProxyDDraw7* This, DDCAPS_X* halCaps, DDCAPS_X* helCaps) {
    ProxyLog("DD7::GetCaps");
    if (halCaps) {
        memset(halCaps, 0, sizeof(DDCAPS_X));
        halCaps->dwSize = DDCAPS_DX7_SIZE;
        halCaps->dwCaps = DDCAPS_3D | DDCAPS_BLT | DDCAPS_BLTSTRETCH | DDCAPS_GDI |
                          DDCAPS_PALETTE | DDCAPS_ZBLTS | DDCAPS_COLORKEY |
                          DDCAPS_BLTCOLORFILL | DDCAPS_BLTDEPTHFILL | DDCAPS_CANCLIP |
                          DDCAPS_CANBLTSYSMEM;
        halCaps->dwCaps2 = 0x10A81200; /* WIDESURFACES|CANRENDERWINDOWED|FLIPINTERVAL|FLIPNOVSYNC|CANMANAGETEXTURE|CANMANAGERESOURCE */
        /* dwZBufferBitDepths at offset 56 */
        *(DWORD*)((BYTE*)halCaps + 56) = DDBD_16 | DDBD_32;
        /* dwVidMemTotal at offset 60, dwVidMemFree at offset 64 */
        *(DWORD*)((BYTE*)halCaps + 60) = 256 * 1024 * 1024;
        *(DWORD*)((BYTE*)halCaps + 64) = 250 * 1024 * 1024;
        /* ddsCaps (legacy DDSCAPS) at offset 132 */
        *(DWORD*)((BYTE*)halCaps + 132) = DDSCAPS_3DDEVICE | DDSCAPS_ZBUFFER |
            DDSCAPS_TEXTURE | DDSCAPS_MIPMAP | DDSCAPS_FLIP |
            DDSCAPS_PRIMARYSURFACE | DDSCAPS_OFFSCREENPLAIN |
            DDSCAPS_VIDEOMEMORY | DDSCAPS_LOCALVIDMEM;
        /* ddsCaps2.dwCaps at offset 364 (DDSCAPS2) */
        *(DWORD*)((BYTE*)halCaps + 364) = DDSCAPS_3DDEVICE | DDSCAPS_ZBUFFER |
            DDSCAPS_TEXTURE | DDSCAPS_MIPMAP | DDSCAPS_FLIP |
            DDSCAPS_PRIMARYSURFACE | DDSCAPS_OFFSCREENPLAIN |
            DDSCAPS_VIDEOMEMORY | DDSCAPS_LOCALVIDMEM;
    }
    if (helCaps) {
        memset(helCaps, 0, sizeof(DDCAPS_X));
        helCaps->dwSize = DDCAPS_DX7_SIZE;
        helCaps->dwCaps = DDCAPS_3D | DDCAPS_BLT | DDCAPS_BLTCOLORFILL;
    }
    return DD_OK;
}

/* 12: GetDisplayMode */
static HRESULT WINAPI DD7_GetDisplayMode(ProxyDDraw7* This, DDSURFACEDESC2_X* desc) {
    ProxyLog("DD7::GetDisplayMode");
    if (!desc) return DDERR_INVALIDPARAMS;
    memset(desc, 0, sizeof(DDSURFACEDESC2_X));
    desc->dwSize = sizeof(DDSURFACEDESC2_X);
    desc->dwFlags = DDSD_WIDTH | DDSD_HEIGHT | DDSD_PIXELFORMAT | DDSD_PITCH;
    desc->dwWidth = This->displayWidth;
    desc->dwHeight = This->displayHeight;
    desc->lPitch = (LONG)(This->displayWidth * (This->displayBpp / 8));
    if (This->displayBpp == 32)
        SetPixelFormat8888(&desc->ddpfPixelFormat);
    else
        SetPixelFormat565(&desc->ddpfPixelFormat);
    return DD_OK;
}

/* 13: GetFourCCCodes */
static HRESULT WINAPI DD7_GetFourCCCodes(ProxyDDraw7* This, DWORD* num, DWORD* codes) {
    ProxyLog("DD7::GetFourCCCodes");
    if (num) *num = 0;
    return DD_OK;
}

/* 14: GetGDISurface */
static HRESULT WINAPI DD7_GetGDISurface(ProxyDDraw7* This, void** ppSurf) {
    ProxyLog("DD7::GetGDISurface");
    if (ppSurf) *ppSurf = NULL;
    return DDERR_NOTFOUND;
}

/* 15: GetMonitorFrequency */
static HRESULT WINAPI DD7_GetMonitorFrequency(ProxyDDraw7* This, DWORD* freq) {
    ProxyLog("DD7::GetMonitorFrequency");
    if (freq) *freq = 60;
    return DD_OK;
}

/* 16: GetScanLine */
static HRESULT WINAPI DD7_GetScanLine(ProxyDDraw7* This, DWORD* scanline) {
    ProxyLog("DD7::GetScanLine");
    if (scanline) *scanline = 0;
    return DD_OK;
}

/* 17: GetVerticalBlankStatus */
static HRESULT WINAPI DD7_GetVerticalBlankStatus(ProxyDDraw7* This, BOOL* status) {
    ProxyLog("DD7::GetVerticalBlankStatus");
    if (status) *status = TRUE;
    return DD_OK;
}

/* 18: Initialize */
static HRESULT WINAPI DD7_Initialize(ProxyDDraw7* This, GUID* guid) { ProxyLog("DD7::Initialize"); return DD_OK; }

/* 19: RestoreAllSurfaces (IDirectDraw version) */
static HRESULT WINAPI DD7_RestoreAllSurfaces(ProxyDDraw7* This) { ProxyLog("DD7::RestoreAllSurfaces"); return DD_OK; }

/* 20: SetCooperativeLevel */
static HRESULT WINAPI DD7_SetCooperativeLevel(ProxyDDraw7* This, HWND hwnd, DWORD flags) {
    ProxyLog("DD7::SetCooperativeLevel hwnd=%p flags=0x%08X", hwnd, flags);
    This->hwnd = hwnd;
    This->coopLevel = flags;
    g_hGameWindow = hwnd;
    if (g_bStubMode && hwnd) {
        /* In dedicated server mode, hide the window completely.
           The message pump still works on hidden windows. */
        SetWindowLongA(hwnd, GWL_STYLE, WS_OVERLAPPEDWINDOW);
        SetWindowLongA(hwnd, GWL_EXSTYLE, 0);
        SetWindowPos(hwnd, NULL, 0, 0, 1, 1,
                     SWP_NOZORDER | SWP_FRAMECHANGED | SWP_NOACTIVATE);
        ShowWindow(hwnd, SW_HIDE);
        ProxyLog("  Stub mode: window hidden (1x1)");
    }
    return DD_OK;
}

/* 21: SetDisplayMode */
static HRESULT WINAPI DD7_SetDisplayMode(ProxyDDraw7* This, DWORD w, DWORD h,
                                          DWORD bpp, DWORD refresh, DWORD flags) {
    ProxyLog("DD7::SetDisplayMode %dx%dx%d @%dHz", w, h, bpp, refresh);
    This->displayWidth = w;
    This->displayHeight = h;
    This->displayBpp = bpp;
    return DD_OK;
}

/* 22: WaitForVerticalBlank */
static HRESULT WINAPI DD7_WaitForVerticalBlank(ProxyDDraw7* This, DWORD flags, HANDLE event) {
    ProxyLog("DD7::WaitForVerticalBlank");
    return DD_OK;
}

/* 23: GetAvailableVidMem */
static HRESULT WINAPI DD7_GetAvailableVidMem(ProxyDDraw7* This, DDSCAPS2_X* caps,
                                              DWORD* total, DWORD* free_mem) {
    ProxyLog("DD7::GetAvailableVidMem");
    if (total) *total = 256 * 1024 * 1024;
    if (free_mem) *free_mem = 250 * 1024 * 1024;
    return DD_OK;
}

/* 24: GetSurfaceFromDC */
static HRESULT WINAPI DD7_GetSurfaceFromDC(ProxyDDraw7* This, HDC hdc, void** ppSurf) {
    ProxyLog("DD7::GetSurfaceFromDC");
    if (ppSurf) *ppSurf = NULL;
    return DDERR_NOTFOUND;
}

/* 25: RestoreAllSurfaces (IDirectDraw4 version - second vtable entry) */
static HRESULT WINAPI DD7_RestoreAllSurfaces2(ProxyDDraw7* This) { ProxyLog("DD7::RestoreAllSurfaces2"); return DD_OK; }

/* 26: TestCooperativeLevel */
static HRESULT WINAPI DD7_TestCooperativeLevel(ProxyDDraw7* This) { ProxyLog("DD7::TestCooperativeLevel"); return DD_OK; }

/* 27: GetDeviceIdentifier
 * NetImmerse constructs device names like "Direct3D T&L HAL on <description>"
 * and matches against Options.cfg "Display Device". We parse Options.cfg to
 * report a matching description so the game accepts our stub device. */
static HRESULT WINAPI DD7_GetDeviceIdentifier(ProxyDDraw7* This, DDDEVICEIDENTIFIER2_X* ident, DWORD flags) {
    /* Must provide realistic data - game crashes on NULL/zero fields */
    static const GUID fakeDeviceGUID =
        {0xd7b78e66, 0x6a40, 0x11cf, {0x96, 0x3b, 0x00, 0xaa, 0x00, 0x55, 0x59, 0x5a}};

    ProxyLog("DD7::GetDeviceIdentifier -> '%s'", g_szDeviceName);
    if (!ident) return DDERR_INVALIDPARAMS;
    memset(ident, 0, sizeof(DDDEVICEIDENTIFIER2_X));

    lstrcpynA(ident->szDriver, "nv4_disp.dll", MAX_DDDEVICEID_STRING);
    lstrcpynA(ident->szDescription, g_szDeviceName, MAX_DDDEVICEID_STRING);
    /* Driver version: 30.0.15.1000 packed as LARGE_INTEGER */
    ident->liDriverVersion.HighPart = (30 << 16) | 0;
    ident->liDriverVersion.LowPart  = (15 << 16) | 1000;
    ident->dwVendorId = 0x10DE;  /* NVIDIA */
    ident->dwDeviceId = 0x2684;  /* RTX 4090 */
    ident->dwSubSysId = 0x16CA1043;
    ident->dwRevision = 0xA1;
    memcpy(&ident->guidDeviceIdentifier, &fakeDeviceGUID, sizeof(GUID));
    ident->dwWHQLLevel = 1;  /* WHQL certified */
    return DD_OK;
}

/* 28: StartModeTest */
static HRESULT WINAPI DD7_StartModeTest(ProxyDDraw7* This, SIZE* modes, DWORD count, DWORD flags) {
    ProxyLog("DD7::StartModeTest");
    return DD_OK;
}

/* 29: EvaluateMode */
static HRESULT WINAPI DD7_EvaluateMode(ProxyDDraw7* This, DWORD flags, DWORD* timeout) {
    ProxyLog("DD7::EvaluateMode");
    return DD_OK;
}

/* ================================================================
 * IDirectDraw7 vtable (30 entries)
 * ================================================================ */
void* g_DDraw7Vtbl[30] = {
    DD7_QueryInterface,       /* 0 */
    DD7_AddRef,               /* 1 */
    DD7_Release,              /* 2 */
    DD7_Compact,              /* 3 */
    DD7_CreateClipper,        /* 4 */
    DD7_CreatePalette,        /* 5 */
    DD7_CreateSurface,        /* 6 */
    DD7_DuplicateSurface,     /* 7 */
    DD7_EnumDisplayModes,     /* 8 */
    DD7_EnumSurfaces,         /* 9 */
    DD7_FlipToGDISurface,     /* 10 */
    DD7_GetCaps,              /* 11 */
    DD7_GetDisplayMode,       /* 12 */
    DD7_GetFourCCCodes,       /* 13 */
    DD7_GetGDISurface,        /* 14 */
    DD7_GetMonitorFrequency,  /* 15 */
    DD7_GetScanLine,          /* 16 */
    DD7_GetVerticalBlankStatus,/* 17 */
    DD7_Initialize,           /* 18 */
    DD7_RestoreAllSurfaces,   /* 19 */
    DD7_SetCooperativeLevel,  /* 20 */
    DD7_SetDisplayMode,       /* 21 */
    DD7_WaitForVerticalBlank, /* 22 */
    DD7_GetAvailableVidMem,   /* 23 */
    DD7_GetSurfaceFromDC,     /* 24 */
    DD7_RestoreAllSurfaces2,  /* 25 */
    DD7_TestCooperativeLevel, /* 26 */
    DD7_GetDeviceIdentifier,  /* 27 */
    DD7_StartModeTest,        /* 28 */
    DD7_EvaluateMode,         /* 29 */
};
