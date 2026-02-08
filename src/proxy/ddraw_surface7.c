/*
 * ddraw_surface7.c - IDirectDrawSurface7 interface implementation (49 vtable entries)
 */
#include "ddraw_proxy.h"

/* ================================================================
 * IDirectDrawSurface7 Methods
 * ================================================================ */

/* 0: QueryInterface */
static HRESULT WINAPI Surf_QueryInterface(ProxySurface7* This, const GUID* riid, void** ppv) {
    if (IsEqualGUID_X(riid, &IID_IDirectDrawSurface7)) {
        *ppv = This;
        This->refCount++;
        return S_OK;
    }
    *ppv = NULL;
    return E_NOINTERFACE;
}

/* 1: AddRef */
static ULONG WINAPI Surf_AddRef(ProxySurface7* This) { return ++This->refCount; }

/* Helper: recursively release a surface and its children */
static void DestroySurface(ProxySurface7* s) {
    if (!s) return;
    /* Recurse into mipmap chain */
    if (s->mipmap) {
        DestroySurface(s->mipmap);
        s->mipmap = NULL;
    }
    if (s->pixelData) HeapFree(GetProcessHeap(), 0, s->pixelData);
    HeapFree(GetProcessHeap(), 0, s);
}

/* 2: Release */
static ULONG WINAPI Surf_Release(ProxySurface7* This) {
    LONG ref = --This->refCount;
    if (ref <= 0) {
        if (This->backBuffer) {
            This->backBuffer->refCount--;
            if (This->backBuffer->refCount <= 0)
                DestroySurface(This->backBuffer);
        }
        if (This->zBuffer) {
            This->zBuffer->refCount--;
            if (This->zBuffer->refCount <= 0)
                DestroySurface(This->zBuffer);
        }
        /* Mipmap chain is owned by this surface, destroy recursively */
        if (This->mipmap) {
            DestroySurface(This->mipmap);
            This->mipmap = NULL;
        }
        if (This->pixelData) HeapFree(GetProcessHeap(), 0, This->pixelData);
        HeapFree(GetProcessHeap(), 0, This);
    }
    return ref;
}

/* 3: AddAttachedSurface */
static HRESULT WINAPI Surf_AddAttachedSurface(ProxySurface7* This, ProxySurface7* attach) {
    ProxyLog("Surface::AddAttachedSurface");
    if (!attach) return DDERR_INVALIDPARAMS;
    if (attach->caps & DDSCAPS_ZBUFFER) {
        This->zBuffer = attach;
        attach->refCount++;
    } else if (attach->caps & DDSCAPS_BACKBUFFER) {
        This->backBuffer = attach;
        attach->refCount++;
    }
    return DD_OK;
}

/* 4: AddOverlayDirtyRect */
static HRESULT WINAPI Surf_AddOverlayDirtyRect(ProxySurface7* This, RECT* r) { return DD_OK; }

/* 5: Blt - main blit operation (no-op for stub) */
static HRESULT WINAPI Surf_Blt(ProxySurface7* This, RECT* dstRect, ProxySurface7* src,
                                RECT* srcRect, DWORD flags, void* bltfx) {
    return DD_OK;
}

/* 6: BltBatch */
static HRESULT WINAPI Surf_BltBatch(ProxySurface7* This, void* ops, DWORD count, DWORD flags) {
    return DD_OK;
}

/* 7: BltFast */
static HRESULT WINAPI Surf_BltFast(ProxySurface7* This, DWORD x, DWORD y,
                                    ProxySurface7* src, RECT* srcRect, DWORD flags) {
    return DD_OK;
}

/* 8: DeleteAttachedSurface */
static HRESULT WINAPI Surf_DeleteAttachedSurface(ProxySurface7* This, DWORD flags, ProxySurface7* attach) {
    if (attach == This->zBuffer) This->zBuffer = NULL;
    if (attach == This->backBuffer) This->backBuffer = NULL;
    return DD_OK;
}

/* 9: EnumAttachedSurfaces */
static HRESULT WINAPI Surf_EnumAttachedSurfaces(ProxySurface7* This, void* ctx, void* cb) {
    return DD_OK;
}

/* 10: EnumOverlayZOrders */
static HRESULT WINAPI Surf_EnumOverlayZOrders(ProxySurface7* This, DWORD flags, void* ctx, void* cb) {
    return DD_OK;
}

/* 11: Flip - present back buffer (no-op for stub) */
static DWORD g_dwFlipCount = 0;
static HRESULT WINAPI Surf_Flip(ProxySurface7* This, ProxySurface7* target, DWORD flags) {
    g_dwFlipCount++;
    if (g_dwFlipCount == 1 || (g_dwFlipCount % 500) == 0) {
        ProxyLog("Surface::Flip #%u", g_dwFlipCount);
    }
    return DD_OK;
}

/* 12: GetAttachedSurface */
static HRESULT WINAPI Surf_GetAttachedSurface(ProxySurface7* This, DDSCAPS2_X* caps, void** ppSurf) {
    ProxyLog("Surface::GetAttachedSurface caps=0x%08X on %dx%d", caps ? caps->dwCaps : 0, This->width, This->height);
    if (!caps || !ppSurf) return DDERR_INVALIDPARAMS;

    if ((caps->dwCaps & DDSCAPS_BACKBUFFER) && This->backBuffer) {
        *ppSurf = This->backBuffer;
        This->backBuffer->refCount++;
        return DD_OK;
    }
    if ((caps->dwCaps & DDSCAPS_ZBUFFER) && This->zBuffer) {
        *ppSurf = This->zBuffer;
        This->zBuffer->refCount++;
        return DD_OK;
    }
    /* If looking for a 3D device capable surface, return back buffer */
    if ((caps->dwCaps & DDSCAPS_3DDEVICE) && This->backBuffer) {
        *ppSurf = This->backBuffer;
        This->backBuffer->refCount++;
        return DD_OK;
    }
    /* Mipmap chain traversal.  The engine calls GetAttachedSurface(MIPMAP)
       on texture surfaces to walk the mipmap chain.

       CRITICAL: Some engine code paths (splash screen texture loader at
       0x7CB325) do NOT check the HRESULT and use *ppSurf directly. If
       *ppSurf is NULL, the engine crashes.  VEH crash patching works but
       leaves the engine in an inconsistent state, triggering abort().

       Solution: ALWAYS set *ppSurf to a valid surface, even when returning
       DDERR_NOTFOUND.  Code that checks HRESULT (font loader) will stop.
       Code that ignores HRESULT (splash loader) gets a valid pointer and
       doesn't crash.

       Strategy: build mipmap chain down to 1x1.  At 1x1, create one last
       sentinel surface (also 1x1) and return DDERR_NOTFOUND with the
       sentinel as *ppSurf.  This way both code paths work correctly. */
    if (caps->dwCaps & DDSCAPS_MIPMAP) {
        /* Chain termination: if this surface is at 1x1, no more mipmaps.
           This matches real DDraw behavior where the bottom-of-chain
           surface returns DDERR_NOTFOUND from GetAttachedSurface.
           NOTE: We do NOT create an extra sentinel surface - doing so
           would add one too many levels and overflow game-internal
           fixed-size mipmap arrays. */
        if (This->width <= 1 && This->height <= 1) {
            ProxyLog("  -> Chain end: 1x1 surface, returning DDERR_NOTFOUND");
            return DDERR_NOTFOUND;
        }
        if (!(This->caps & DDSCAPS_MIPMAP)) {
            ProxyLog("  -> No-MIPMAP surface, returning DDERR_NOTFOUND");
            return DDERR_NOTFOUND;
        }
        if (!This->mipmap) {
            DWORD mipW = This->width / 2;
            DWORD mipH = This->height / 2;
            DWORD mipCaps;
            if (mipW < 1) mipW = 1;
            if (mipH < 1) mipH = 1;
            /* Last level (1x1): strip MIPMAP flag so chain terminates
               naturally on the next GetAttachedSurface call. */
            if (mipW <= 1 && mipH <= 1) {
                mipCaps = DDSCAPS_TEXTURE | DDSCAPS_SYSTEMMEMORY;
            } else {
                mipCaps = DDSCAPS_TEXTURE | DDSCAPS_SYSTEMMEMORY | DDSCAPS_MIPMAP;
            }
            This->mipmap = CreateProxySurface7(mipW, mipH, This->bpp, mipCaps);
        }
        if (This->mipmap) {
            *ppSurf = This->mipmap;
            This->mipmap->refCount++;
            return DD_OK;
        }
        return DDERR_GENERIC;
    }

    *ppSurf = NULL;
    return DDERR_NOTFOUND;
}

/* 13: GetBltStatus */
static HRESULT WINAPI Surf_GetBltStatus(ProxySurface7* This, DWORD flags) { return DD_OK; }

/* 14: GetCaps */
static HRESULT WINAPI Surf_GetCaps(ProxySurface7* This, DDSCAPS2_X* caps) {
    if (!caps) return DDERR_INVALIDPARAMS;
    memset(caps, 0, sizeof(DDSCAPS2_X));
    caps->dwCaps = This->caps;
    return DD_OK;
}

/* 15: GetClipper */
static HRESULT WINAPI Surf_GetClipper(ProxySurface7* This, void** ppClipper) {
    if (This->clipper) {
        *ppClipper = This->clipper;
        ((ProxyClipper*)This->clipper)->refCount++;
        return DD_OK;
    }
    *ppClipper = NULL;
    return DDERR_NOTFOUND;
}

/* 16: GetColorKey */
static HRESULT WINAPI Surf_GetColorKey(ProxySurface7* This, DWORD flags, DDCOLORKEY* ck) {
    if (ck) memset(ck, 0, sizeof(DDCOLORKEY));
    return DD_OK;
}

/* 17: GetDC */
static HRESULT WINAPI Surf_GetDC(ProxySurface7* This, HDC* phdc) {
    /* Create a compatible DC for the surface - some code paths need this */
    if (!phdc) return DDERR_INVALIDPARAMS;
    *phdc = CreateCompatibleDC(NULL);
    return *phdc ? DD_OK : DDERR_GENERIC;
}

/* 18: GetFlipStatus */
static HRESULT WINAPI Surf_GetFlipStatus(ProxySurface7* This, DWORD flags) { return DD_OK; }

/* 19: GetOverlayPosition */
static HRESULT WINAPI Surf_GetOverlayPosition(ProxySurface7* This, LONG* x, LONG* y) {
    if (x) *x = 0;
    if (y) *y = 0;
    return DD_OK;
}

/* 20: GetPalette */
static HRESULT WINAPI Surf_GetPalette(ProxySurface7* This, void** ppPal) {
    if (ppPal) *ppPal = NULL;
    return DDERR_NOTFOUND;
}

/* 21: GetPixelFormat */
static HRESULT WINAPI Surf_GetPixelFormat(ProxySurface7* This, DDPIXELFORMAT_X* pf) {
    if (!pf) return DDERR_INVALIDPARAMS;
    memcpy(pf, &This->pixelFormat, sizeof(DDPIXELFORMAT_X));
    return DD_OK;
}

/* Helper: calculate mipmap level count from dimensions */
static DWORD CalcMipMapCount(DWORD w, DWORD h) {
    DWORD count = 1; /* base level */
    while (w > 1 || h > 1) {
        w = (w > 1) ? w / 2 : 1;
        h = (h > 1) ? h / 2 : 1;
        count++;
    }
    return count;
}

/* 22: GetSurfaceDesc */
static HRESULT WINAPI Surf_GetSurfaceDesc(ProxySurface7* This, DDSURFACEDESC2_X* desc) {
    ProxyLog("Surface::GetSurfaceDesc %dx%d caps=0x%08X", This->width, This->height, This->caps);
    if (!desc) return DDERR_INVALIDPARAMS;
    memset(desc, 0, sizeof(DDSURFACEDESC2_X));
    desc->dwSize = sizeof(DDSURFACEDESC2_X);
    desc->dwFlags = DDSD_CAPS | DDSD_WIDTH | DDSD_HEIGHT | DDSD_PITCH | DDSD_PIXELFORMAT;
    desc->dwWidth = This->width;
    desc->dwHeight = This->height;
    desc->lPitch = This->pitch;
    memcpy(&desc->ddpfPixelFormat, &This->pixelFormat, sizeof(DDPIXELFORMAT_X));
    desc->ddsCaps.dwCaps = This->caps;
    /* Report mipmap count for mipmap-capable surfaces */
    if (This->caps & DDSCAPS_MIPMAP) {
        desc->dwFlags |= DDSD_MIPMAPCOUNT;
        desc->dwMipMapCount = CalcMipMapCount(This->width, This->height);
    }
    return DD_OK;
}

/* 23: Initialize */
static HRESULT WINAPI Surf_Initialize(ProxySurface7* This, void* dd, DDSURFACEDESC2_X* desc) {
    return DD_OK;
}

/* 24: IsLost */
static HRESULT WINAPI Surf_IsLost(ProxySurface7* This) { return DD_OK; }

/* 25: Lock - critical: must return valid memory pointer */
static HRESULT WINAPI Surf_Lock(ProxySurface7* This, RECT* destRect,
                                 DDSURFACEDESC2_X* desc, DWORD flags, HANDLE event) {
    {
        static int lockCount = 0;
        lockCount++;
        if (lockCount <= 10 || lockCount % 1000000 == 0) {
            DWORD retAddr = (DWORD)__builtin_return_address(0);
            ProxyLog("Surface::Lock %dx%d flags=0x%08X (#%d) caller=0x%08X",
                     This->width, This->height, flags, lockCount, retAddr);
        }
        /* Throttle render loop for primary surface to ~60fps.
           Without this, the game runs millions of ticks per second and
           burns 100% CPU. The 16ms sleep simulates vsync timing. */
        if (This->width >= 640 && This->height >= 480 && g_bStubMode)
            Sleep(16);
    }
    if (!desc) return DDERR_INVALIDPARAMS;

    /* Allocate pixel data on first lock */
    if (!This->pixelData) {
        This->pixelDataSize = This->pitch * This->height;
        if (This->pixelDataSize == 0) This->pixelDataSize = 1024 * 1024; /* 1MB fallback */
        This->pixelData = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, This->pixelDataSize);
        if (!This->pixelData) return DDERR_GENERIC;
    }

    memset(desc, 0, sizeof(DDSURFACEDESC2_X));
    desc->dwSize = sizeof(DDSURFACEDESC2_X);
    desc->dwFlags = DDSD_CAPS | DDSD_WIDTH | DDSD_HEIGHT | DDSD_PITCH |
                    DDSD_PIXELFORMAT | DDSD_LPSURFACE;
    desc->dwWidth = This->width;
    desc->dwHeight = This->height;
    desc->lPitch = This->pitch;
    desc->lpSurface = This->pixelData;
    memcpy(&desc->ddpfPixelFormat, &This->pixelFormat, sizeof(DDPIXELFORMAT_X));
    desc->ddsCaps.dwCaps = This->caps;
    return DD_OK;
}

/* 26: ReleaseDC */
static HRESULT WINAPI Surf_ReleaseDC(ProxySurface7* This, HDC hdc) {
    if (hdc) DeleteDC(hdc);
    return DD_OK;
}

/* 27: Restore */
static HRESULT WINAPI Surf_Restore(ProxySurface7* This) { return DD_OK; }

/* 28: SetClipper */
static HRESULT WINAPI Surf_SetClipper(ProxySurface7* This, ProxyClipper* clipper) {
    This->clipper = clipper;
    return DD_OK;
}

/* 29: SetColorKey */
static HRESULT WINAPI Surf_SetColorKey(ProxySurface7* This, DWORD flags, DDCOLORKEY* ck) {
    return DD_OK;
}

/* 30: SetOverlayPosition */
static HRESULT WINAPI Surf_SetOverlayPosition(ProxySurface7* This, LONG x, LONG y) { return DD_OK; }

/* 31: SetPalette */
static HRESULT WINAPI Surf_SetPalette(ProxySurface7* This, void* pal) { return DD_OK; }

/* 32: Unlock */
static HRESULT WINAPI Surf_Unlock(ProxySurface7* This, RECT* r) { return DD_OK; }

/* 33: UpdateOverlay */
static HRESULT WINAPI Surf_UpdateOverlay(ProxySurface7* This, RECT* src, ProxySurface7* dst,
                                          RECT* dstRect, DWORD flags, void* fx) {
    return DD_OK;
}

/* 34: UpdateOverlayDisplay */
static HRESULT WINAPI Surf_UpdateOverlayDisplay(ProxySurface7* This, DWORD flags) { return DD_OK; }

/* 35: UpdateOverlayZOrder */
static HRESULT WINAPI Surf_UpdateOverlayZOrder(ProxySurface7* This, DWORD flags, ProxySurface7* ref) {
    return DD_OK;
}

/* 36: GetDDInterface */
static HRESULT WINAPI Surf_GetDDInterface(ProxySurface7* This, void** ppDD) {
    if (ppDD) *ppDD = NULL;
    return DDERR_GENERIC;
}

/* 37: PageLock */
static HRESULT WINAPI Surf_PageLock(ProxySurface7* This, DWORD flags) { return DD_OK; }

/* 38: PageUnlock */
static HRESULT WINAPI Surf_PageUnlock(ProxySurface7* This, DWORD flags) { return DD_OK; }

/* 39: SetSurfaceDesc */
static HRESULT WINAPI Surf_SetSurfaceDesc(ProxySurface7* This, DDSURFACEDESC2_X* desc, DWORD flags) {
    if (desc) {
        if (desc->dwFlags & DDSD_WIDTH) This->width = desc->dwWidth;
        if (desc->dwFlags & DDSD_HEIGHT) This->height = desc->dwHeight;
        if (desc->dwFlags & DDSD_PITCH) This->pitch = desc->lPitch;
        if (desc->dwFlags & DDSD_LPSURFACE) {
            /* Game is providing its own surface memory */
            This->pixelData = (BYTE*)desc->lpSurface;
        }
    }
    return DD_OK;
}

/* 40: SetPrivateData */
static HRESULT WINAPI Surf_SetPrivateData(ProxySurface7* This, const GUID* tag,
                                           void* data, DWORD size, DWORD flags) {
    return DD_OK;
}

/* 41: GetPrivateData */
static HRESULT WINAPI Surf_GetPrivateData(ProxySurface7* This, const GUID* tag,
                                           void* data, DWORD* size) {
    return DDERR_NOTFOUND;
}

/* 42: FreePrivateData */
static HRESULT WINAPI Surf_FreePrivateData(ProxySurface7* This, const GUID* tag) { return DD_OK; }

/* 43: GetUniquenessValue */
static HRESULT WINAPI Surf_GetUniquenessValue(ProxySurface7* This, DWORD* val) {
    if (val) *val = 0;
    return DD_OK;
}

/* 44: ChangeUniquenessValue */
static HRESULT WINAPI Surf_ChangeUniquenessValue(ProxySurface7* This) { return DD_OK; }

/* 45: SetPriority */
static HRESULT WINAPI Surf_SetPriority(ProxySurface7* This, DWORD prio) { return DD_OK; }

/* 46: GetPriority */
static HRESULT WINAPI Surf_GetPriority(ProxySurface7* This, DWORD* prio) {
    if (prio) *prio = 0;
    return DD_OK;
}

/* 47: SetLOD */
static HRESULT WINAPI Surf_SetLOD(ProxySurface7* This, DWORD lod) { return DD_OK; }

/* 48: GetLOD */
static HRESULT WINAPI Surf_GetLOD(ProxySurface7* This, DWORD* lod) {
    if (lod) *lod = 0;
    return DD_OK;
}

/* ================================================================
 * IDirectDrawSurface7 vtable (49 entries)
 * ================================================================ */
void* g_Surface7Vtbl[49] = {
    Surf_QueryInterface,        /* 0 */
    Surf_AddRef,                /* 1 */
    Surf_Release,               /* 2 */
    Surf_AddAttachedSurface,    /* 3 */
    Surf_AddOverlayDirtyRect,   /* 4 */
    Surf_Blt,                   /* 5 */
    Surf_BltBatch,              /* 6 */
    Surf_BltFast,               /* 7 */
    Surf_DeleteAttachedSurface, /* 8 */
    Surf_EnumAttachedSurfaces,  /* 9 */
    Surf_EnumOverlayZOrders,    /* 10 */
    Surf_Flip,                  /* 11 */
    Surf_GetAttachedSurface,    /* 12 */
    Surf_GetBltStatus,          /* 13 */
    Surf_GetCaps,               /* 14 */
    Surf_GetClipper,            /* 15 */
    Surf_GetColorKey,           /* 16 */
    Surf_GetDC,                 /* 17 */
    Surf_GetFlipStatus,         /* 18 */
    Surf_GetOverlayPosition,    /* 19 */
    Surf_GetPalette,            /* 20 */
    Surf_GetPixelFormat,        /* 21 */
    Surf_GetSurfaceDesc,        /* 22 */
    Surf_Initialize,            /* 23 */
    Surf_IsLost,                /* 24 */
    Surf_Lock,                  /* 25 */
    Surf_ReleaseDC,             /* 26 */
    Surf_Restore,               /* 27 */
    Surf_SetClipper,            /* 28 */
    Surf_SetColorKey,           /* 29 */
    Surf_SetOverlayPosition,    /* 30 */
    Surf_SetPalette,            /* 31 */
    Surf_Unlock,                /* 32 */
    Surf_UpdateOverlay,         /* 33 */
    Surf_UpdateOverlayDisplay,  /* 34 */
    Surf_UpdateOverlayZOrder,   /* 35 */
    Surf_GetDDInterface,        /* 36 */
    Surf_PageLock,              /* 37 */
    Surf_PageUnlock,            /* 38 */
    Surf_SetSurfaceDesc,        /* 39 */
    Surf_SetPrivateData,        /* 40 */
    Surf_GetPrivateData,        /* 41 */
    Surf_FreePrivateData,       /* 42 */
    Surf_GetUniquenessValue,    /* 43 */
    Surf_ChangeUniquenessValue, /* 44 */
    Surf_SetPriority,           /* 45 */
    Surf_GetPriority,           /* 46 */
    Surf_SetLOD,                /* 47 */
    Surf_GetLOD,                /* 48 */
};
