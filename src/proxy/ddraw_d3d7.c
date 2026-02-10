/*
 * ddraw_d3d7.c - IDirect3D7 + IDirect3DDevice7 + IDirect3DVertexBuffer7
 */
#include "ddraw_proxy.h"

/* ================================================================
 * IDirect3D7 Methods (8 entries)
 * ================================================================ */

static HRESULT WINAPI D3D7_QueryInterface(ProxyD3D7* This, const GUID* riid, void** ppv) {
    if (IsEqualGUID_X(riid, &IID_IDirect3D7)) {
        *ppv = This;
        This->refCount++;
        return S_OK;
    }
    if (IsEqualGUID_X(riid, &IID_IDirectDraw7)) {
        *ppv = This->parent;
        This->parent->refCount++;
        return S_OK;
    }
    *ppv = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI D3D7_AddRef(ProxyD3D7* This) {
    DWORD retAddr = (DWORD)__builtin_return_address(0);
    ProxyLog("D3D7::AddRef (this=%p, refCount=%lu->%lu, caller=0x%08X)", This, This->refCount, This->refCount+1, retAddr);
    return ++This->refCount;
}

static ULONG WINAPI D3D7_Release(ProxyD3D7* This) {
    LONG ref = --This->refCount;
    if (ref <= 0) {
        ProxyLog("D3D7::Release -> destroying");
        HeapFree(GetProcessHeap(), 0, This);
    }
    return ref;
}

/* 3: EnumDevices - critical: NetImmerse uses this to find a D3D device */
static HRESULT WINAPI D3D7_EnumDevices(ProxyD3D7* This, LPD3DENUMDEVICESCALLBACK7 cb, void* ctx) {
    D3DDEVICEDESC7_X desc;

    ProxyLog("D3D7::EnumDevices");
    if (!cb) return DDERR_INVALIDPARAMS;

    memset(&desc, 0, sizeof(desc));

    /* Report as a Hardware T&L device */
    desc.dwDevCaps = D3DDEVCAPS_FLOATTLVERTEX | D3DDEVCAPS_EXECUTESYSTEMMEMORY |
                     D3DDEVCAPS_TLVERTEXSYSTEMMEMORY | D3DDEVCAPS_TEXTUREVIDEOMEMORY |
                     D3DDEVCAPS_DRAWPRIMTLVERTEX | D3DDEVCAPS_CANRENDERAFTERFLIP |
                     D3DDEVCAPS_DRAWPRIMITIVES2 | D3DDEVCAPS_DRAWPRIMITIVES2EX |
                     D3DDEVCAPS_HWTRANSFORMANDLIGHT | D3DDEVCAPS_HWRASTERIZATION;

    FillPrimCaps(&desc.dpcLineCaps);
    FillPrimCaps(&desc.dpcTriCaps);

    desc.dwDeviceRenderBitDepth = DDBD_16 | DDBD_32;
    desc.dwDeviceZBufferBitDepth = DDBD_16 | DDBD_32;
    desc.dwMinTextureWidth = 1;
    desc.dwMinTextureHeight = 1;
    desc.dwMaxTextureWidth = 2048;
    desc.dwMaxTextureHeight = 2048;
    desc.dwMaxTextureRepeat = 2048;
    desc.dwMaxTextureAspectRatio = 2048;
    desc.dwMaxAnisotropy = 16;
    desc.dvGuardBandLeft = -8192.0f;
    desc.dvGuardBandTop = -8192.0f;
    desc.dvGuardBandRight = 8192.0f;
    desc.dvGuardBandBottom = 8192.0f;
    desc.dvExtentsAdjust = 0.0f;
    desc.dwStencilCaps = D3DSTENCILCAPS_KEEP | D3DSTENCILCAPS_ZERO |
                         D3DSTENCILCAPS_REPLACE | D3DSTENCILCAPS_INCRSAT |
                         D3DSTENCILCAPS_DECRSAT | D3DSTENCILCAPS_INVERT;
    desc.dwFVFCaps = 8; /* 8 texture coordinate sets */
    desc.dwTextureOpCaps = D3DTEXOPCAPS_DISABLE | D3DTEXOPCAPS_SELECTARG1 |
                           D3DTEXOPCAPS_SELECTARG2 | D3DTEXOPCAPS_MODULATE |
                           D3DTEXOPCAPS_ADD;
    desc.wMaxTextureBlendStages = 8;
    desc.wMaxSimultaneousTextures = 4;
    desc.dwMaxActiveLights = 8;
    desc.dvMaxVertexW = 1e10f;
    desc.wMaxUserClipPlanes = 6;
    desc.wMaxVertexBlendMatrices = 4;
    desc.dwVertexProcessingCaps = D3DVTXPCAPS_DIRECTIONALLIGHTS |
                                   D3DVTXPCAPS_POSITIONALLIGHTS |
                                   D3DVTXPCAPS_LOCALVIEWER;

    /* Enumerate only HAL device (no TnL) to avoid NetImmerse trying to
     * initialize hardware vertex processing pipelines that crash in stub mode.
     * NetImmerse constructs the display device name as:
     * "Direct3D HAL on <DDraw description>" */
    memcpy(&desc.deviceGUID, &IID_IDirect3DHALDevice, sizeof(GUID));
    ProxyLog("  Enumerating HAL device");
    {
        HRESULT cbRet = cb("Direct3D HAL", "Direct3D HAL", &desc, ctx);
        ProxyLog("  HAL callback returned: 0x%08X", (unsigned)cbRet);
    }

    return D3D_OK;
}

/* 4: CreateDevice */
static HRESULT WINAPI D3D7_CreateDevice(ProxyD3D7* This, const GUID* devGuid,
                                         ProxySurface7* renderTarget, void** ppDevice) {
    ProxyLog("D3D7::CreateDevice");
    if (!ppDevice) return DDERR_INVALIDPARAMS;
    *ppDevice = CreateProxyDevice7(renderTarget, This);
    return *ppDevice ? D3D_OK : DDERR_GENERIC;
}

/* 5: CreateVertexBuffer */
static HRESULT WINAPI D3D7_CreateVertexBuffer(ProxyD3D7* This, D3DVERTEXBUFFERDESC_X* desc,
                                               void** ppVB, DWORD flags) {
    ProxyLog("D3D7::CreateVertexBuffer fvf=0x%X verts=%d", desc ? desc->dwFVF : 0,
             desc ? desc->dwNumVertices : 0);
    if (!desc || !ppVB) return DDERR_INVALIDPARAMS;
    *ppVB = CreateProxyVB7(desc->dwFVF, desc->dwNumVertices);
    return *ppVB ? D3D_OK : DDERR_GENERIC;
}

/* 6: EnumZBufferFormats - critical: NetImmerse needs at least one valid z-buffer format */
static HRESULT WINAPI D3D7_EnumZBufferFormats(ProxyD3D7* This, const GUID* devGuid,
                                               LPD3DENUMPIXELFORMATSCALLBACK cb, void* ctx) {
    DDPIXELFORMAT_X pf;

    ProxyLog("D3D7::EnumZBufferFormats");
    if (!cb) return DDERR_INVALIDPARAMS;

    /* 16-bit Z-buffer */
    SetPixelFormatZ16(&pf);
    cb(&pf, ctx);

    /* 24-bit Z + 8-bit stencil */
    memset(&pf, 0, sizeof(pf));
    pf.dwSize = sizeof(DDPIXELFORMAT_X);
    pf.dwFlags = DDPF_ZBUFFER | DDPF_STENCILBUFFER;
    pf.dwRGBBitCount = 32;  /* dwZBufferBitDepth */
    pf.dwRBitMask = 8;      /* dwStencilBitDepth */
    pf.dwGBitMask = 0x00FFFFFF; /* dwZBitMask */
    pf.dwBBitMask = 0xFF000000; /* dwStencilBitMask */

    cb(&pf, ctx);
    return D3D_OK;
}

/* 7: EvictManagedTextures */
static HRESULT WINAPI D3D7_EvictManagedTextures(ProxyD3D7* This) { return D3D_OK; }

/* ================================================================
 * IDirect3D7 vtable (8 entries)
 * ================================================================ */
void* g_D3D7Vtbl[8] = {
    D3D7_QueryInterface,       /* 0 */
    D3D7_AddRef,               /* 1 */
    D3D7_Release,              /* 2 */
    D3D7_EnumDevices,          /* 3 */
    D3D7_CreateDevice,         /* 4 */
    D3D7_CreateVertexBuffer,   /* 5 */
    D3D7_EnumZBufferFormats,   /* 6 */
    D3D7_EvictManagedTextures, /* 7 */
};

/* ================================================================
 * IDirect3DDevice7 Methods (49 entries)
 * ================================================================ */

static HRESULT WINAPI Dev_QueryInterface(ProxyDevice7* This, const GUID* riid, void** ppv) {
    *ppv = This;
    This->refCount++;
    return S_OK;
}
static ULONG WINAPI Dev_AddRef(ProxyDevice7* This) {
    DWORD retAddr = (DWORD)__builtin_return_address(0);
    ProxyLog("Device7::AddRef (this=%p, refCount=%lu->%lu, caller=0x%08X)", This, This->refCount, This->refCount+1, retAddr);
    return ++This->refCount;
}
static ULONG WINAPI Dev_Release(ProxyDevice7* This) {
    LONG ref = --This->refCount;
    if (ref <= 0) {
        ProxyLog("Device7::Release -> destroying");
        if (This->renderTarget) This->renderTarget->refCount--;
        HeapFree(GetProcessHeap(), 0, This);
    }
    return ref;
}

/* 3: GetCaps */
static HRESULT WINAPI Dev_GetCaps(ProxyDevice7* This, D3DDEVICEDESC7_X* desc) {
    DWORD retAddr = (DWORD)__builtin_return_address(0);
    ProxyLog("Device7::GetCaps (caller=0x%08X)", retAddr);
    if (!desc) return DDERR_INVALIDPARAMS;
    memset(desc, 0, sizeof(D3DDEVICEDESC7_X));
    /* NOTE: Deliberately omit HWTRANSFORMANDLIGHT. Reporting T&L causes
       NetImmerse to initialize HW vertex processing pipelines that crash
       without a real GPU. Software vertex processing is sufficient for
       a dedicated server. */
    desc->dwDevCaps = D3DDEVCAPS_FLOATTLVERTEX | D3DDEVCAPS_EXECUTESYSTEMMEMORY |
                      D3DDEVCAPS_TLVERTEXSYSTEMMEMORY | D3DDEVCAPS_TEXTUREVIDEOMEMORY |
                      D3DDEVCAPS_DRAWPRIMTLVERTEX | D3DDEVCAPS_CANRENDERAFTERFLIP |
                      D3DDEVCAPS_DRAWPRIMITIVES2 | D3DDEVCAPS_DRAWPRIMITIVES2EX |
                      D3DDEVCAPS_HWRASTERIZATION;
    FillPrimCaps(&desc->dpcLineCaps);
    FillPrimCaps(&desc->dpcTriCaps);
    desc->dwDeviceRenderBitDepth = DDBD_16 | DDBD_32;
    desc->dwDeviceZBufferBitDepth = DDBD_16 | DDBD_32;
    desc->dwMinTextureWidth = 1;
    desc->dwMinTextureHeight = 1;
    desc->dwMaxTextureWidth = 2048;
    desc->dwMaxTextureHeight = 2048;
    desc->dwMaxTextureRepeat = 2048;
    desc->dwMaxTextureAspectRatio = 2048;
    desc->dwMaxAnisotropy = 16;
    desc->wMaxTextureBlendStages = 8;
    desc->wMaxSimultaneousTextures = 4;
    desc->dwMaxActiveLights = 8;
    desc->dvMaxVertexW = 1e10f;
    memcpy(&desc->deviceGUID, &IID_IDirect3DHALDevice, sizeof(GUID));
    return D3D_OK;
}

/* 4: EnumTextureFormats */
static HRESULT WINAPI Dev_EnumTextureFormats(ProxyDevice7* This,
                                              LPD3DENUMPIXELFORMATSCALLBACK cb, void* ctx) {
    DDPIXELFORMAT_X pf;
    ProxyLog("Device7::EnumTextureFormats");
    if (!cb) return DDERR_INVALIDPARAMS;

    /* 16-bit 565 */
    SetPixelFormat565(&pf);
    if (cb(&pf, ctx) == 0) return D3D_OK;

    /* 16-bit 1555 (alpha) */
    memset(&pf, 0, sizeof(pf));
    pf.dwSize = sizeof(pf);
    pf.dwFlags = DDPF_RGB | DDPF_ALPHAPIXELS;
    pf.dwRGBBitCount = 16;
    pf.dwRBitMask = 0x7C00;
    pf.dwGBitMask = 0x03E0;
    pf.dwBBitMask = 0x001F;
    pf.dwRGBAlphaBitMask = 0x8000;
    if (cb(&pf, ctx) == 0) return D3D_OK;

    /* 32-bit ARGB */
    SetPixelFormat8888(&pf);
    cb(&pf, ctx);

    return D3D_OK;
}

/* 5: BeginScene */
static DWORD g_dwSceneCount = 0;
static HRESULT WINAPI Dev_BeginScene(ProxyDevice7* This) {
    g_dwSceneCount++;
    if (g_dwSceneCount == 1 || (g_dwSceneCount % 500) == 0) {
        ProxyLog("Device7::BeginScene #%u", g_dwSceneCount);
    }
    if (This->inScene) return D3DERR_SCENE_IN_SCENE;
    This->inScene = TRUE;
    return D3D_OK;
}

/* 6: EndScene */
static HRESULT WINAPI Dev_EndScene(ProxyDevice7* This) {
    /* ProxyLog("Device7::EndScene"); -- too verbose */
    if (!This->inScene) return D3DERR_SCENE_NOT_IN_SCENE;
    This->inScene = FALSE;
    return D3D_OK;
}

/* 7: GetDirect3D */
static HRESULT WINAPI Dev_GetDirect3D(ProxyDevice7* This, void** ppD3D) {
    ProxyLog("Device7::GetDirect3D (this=%p, parent=%p)", This, This ? This->parent : NULL);
    if (!ppD3D) return DDERR_INVALIDPARAMS;
    if (This->parent) {
        *ppD3D = This->parent;
        This->parent->refCount++;
        return D3D_OK;
    }
    *ppD3D = NULL;
    return DDERR_GENERIC;
}

/* 8: SetRenderTarget */
static HRESULT WINAPI Dev_SetRenderTarget(ProxyDevice7* This, ProxySurface7* target, DWORD flags) {
    if (target) {
        if (This->renderTarget) This->renderTarget->refCount--;
        This->renderTarget = target;
        target->refCount++;
    }
    return D3D_OK;
}

/* 9: GetRenderTarget */
static HRESULT WINAPI Dev_GetRenderTarget(ProxyDevice7* This, void** ppSurf) {
    if (!ppSurf) return DDERR_INVALIDPARAMS;
    *ppSurf = This->renderTarget;
    if (This->renderTarget) This->renderTarget->refCount++;
    return D3D_OK;
}

/* 10: Clear */
static HRESULT WINAPI Dev_Clear(ProxyDevice7* This, DWORD count, D3DRECT_X* rects,
                                 DWORD flags, DWORD color, float z, DWORD stencil) {
    return D3D_OK;
}

/* 11-15: Transform and viewport */
static HRESULT WINAPI Dev_SetTransform(ProxyDevice7* This, DWORD state, D3DMATRIX_X* mat) { return D3D_OK; }
static HRESULT WINAPI Dev_GetTransform(ProxyDevice7* This, DWORD state, D3DMATRIX_X* mat) {
    if (mat) {
        memset(mat, 0, sizeof(D3DMATRIX_X));
        mat->_11 = mat->_22 = mat->_33 = mat->_44 = 1.0f; /* Identity */
    }
    return D3D_OK;
}
static HRESULT WINAPI Dev_SetViewport(ProxyDevice7* This, D3DVIEWPORT7_X* vp) { return D3D_OK; }
static HRESULT WINAPI Dev_MultiplyTransform(ProxyDevice7* This, DWORD state, D3DMATRIX_X* mat) { return D3D_OK; }
static HRESULT WINAPI Dev_GetViewport(ProxyDevice7* This, D3DVIEWPORT7_X* vp) {
    if (vp) {
        memset(vp, 0, sizeof(D3DVIEWPORT7_X));
        vp->dwWidth = 800;
        vp->dwHeight = 600;
        vp->dvMaxZ = 1.0f;
    }
    return D3D_OK;
}

/* 16-19: Material and light */
static HRESULT WINAPI Dev_SetMaterial(ProxyDevice7* This, D3DMATERIAL7_X* mat) { return D3D_OK; }
static HRESULT WINAPI Dev_GetMaterial(ProxyDevice7* This, D3DMATERIAL7_X* mat) {
    if (mat) memset(mat, 0, sizeof(D3DMATERIAL7_X));
    return D3D_OK;
}
static HRESULT WINAPI Dev_SetLight(ProxyDevice7* This, DWORD index, D3DLIGHT7_X* light) { return D3D_OK; }
static HRESULT WINAPI Dev_GetLight(ProxyDevice7* This, DWORD index, D3DLIGHT7_X* light) {
    if (light) memset(light, 0, sizeof(D3DLIGHT7_X));
    return D3D_OK;
}

/* 20-21: Render state */
static HRESULT WINAPI Dev_SetRenderState(ProxyDevice7* This, DWORD state, DWORD value) { return D3D_OK; }
static HRESULT WINAPI Dev_GetRenderState(ProxyDevice7* This, DWORD state, DWORD* value) {
    if (value) *value = 0;
    return D3D_OK;
}

/* 22-23: State blocks */
static HRESULT WINAPI Dev_BeginStateBlock(ProxyDevice7* This) { return D3D_OK; }
static HRESULT WINAPI Dev_EndStateBlock(ProxyDevice7* This, DWORD* handle) {
    if (handle) *handle = 1; /* Return a dummy handle */
    return D3D_OK;
}

/* 24: PreLoad */
static HRESULT WINAPI Dev_PreLoad(ProxyDevice7* This, ProxySurface7* surf) { return D3D_OK; }

/* 25-26: Draw primitives (no-op) */
static HRESULT WINAPI Dev_DrawPrimitive(ProxyDevice7* This, DWORD type, DWORD fvf,
                                         void* verts, DWORD vertCount, DWORD flags) {
    return D3D_OK;
}
static HRESULT WINAPI Dev_DrawIndexedPrimitive(ProxyDevice7* This, DWORD type, DWORD fvf,
                                                void* verts, DWORD vertCount,
                                                WORD* indices, DWORD indexCount, DWORD flags) {
    return D3D_OK;
}

/* 27-28: Clip status */
static HRESULT WINAPI Dev_SetClipStatus(ProxyDevice7* This, void* cs) { return D3D_OK; }
static HRESULT WINAPI Dev_GetClipStatus(ProxyDevice7* This, void* cs) {
    if (cs) memset(cs, 0, 32); /* D3DCLIPSTATUS size */
    return D3D_OK;
}

/* 29-32: Strided/VB draw (no-op) */
static HRESULT WINAPI Dev_DrawPrimitiveStrided(ProxyDevice7* This, DWORD type,
                                                DWORD fvf, void* data, DWORD count, DWORD flags) {
    return D3D_OK;
}
static HRESULT WINAPI Dev_DrawIndexedPrimitiveStrided(ProxyDevice7* This, DWORD type,
                                                       DWORD fvf, void* data, DWORD vertCount,
                                                       WORD* indices, DWORD indexCount, DWORD flags) {
    return D3D_OK;
}
static HRESULT WINAPI Dev_DrawPrimitiveVB(ProxyDevice7* This, DWORD type, void* vb,
                                           DWORD startVert, DWORD numVerts, DWORD flags) {
    return D3D_OK;
}
static HRESULT WINAPI Dev_DrawIndexedPrimitiveVB(ProxyDevice7* This, DWORD type, void* vb,
                                                  DWORD startVert, DWORD numVerts,
                                                  WORD* indices, DWORD indexCount, DWORD flags) {
    return D3D_OK;
}

/* 33: ComputeSphereVisibility */
static HRESULT WINAPI Dev_ComputeSphereVisibility(ProxyDevice7* This, void* centers,
                                                    float* radii, DWORD count, DWORD flags,
                                                    DWORD* results) {
    DWORD i;
    if (results) {
        for (i = 0; i < count; i++) results[i] = 0; /* All visible */
    }
    return D3D_OK;
}

/* 34-35: Texture */
static HRESULT WINAPI Dev_GetTexture(ProxyDevice7* This, DWORD stage, void** ppTex) {
    if (ppTex) *ppTex = NULL;
    return D3D_OK;
}
static HRESULT WINAPI Dev_SetTexture(ProxyDevice7* This, DWORD stage, void* tex) {
    /* ProxyLog("Device7::SetTexture stage=%d tex=%p", stage, tex); -- too verbose */
    return D3D_OK;
}

/* 36-37: Texture stage state */
static HRESULT WINAPI Dev_GetTextureStageState(ProxyDevice7* This, DWORD stage,
                                                DWORD type, DWORD* value) {
    if (value) *value = 0;
    return D3D_OK;
}
static HRESULT WINAPI Dev_SetTextureStageState(ProxyDevice7* This, DWORD stage,
                                                DWORD type, DWORD value) {
    return D3D_OK;
}

/* 38: ValidateDevice */
static HRESULT WINAPI Dev_ValidateDevice(ProxyDevice7* This, DWORD* passes) {
    if (passes) *passes = 1;
    return D3D_OK;
}

/* 39-42: State block operations */
static HRESULT WINAPI Dev_ApplyStateBlock(ProxyDevice7* This, DWORD handle) { return D3D_OK; }
static HRESULT WINAPI Dev_CaptureStateBlock(ProxyDevice7* This, DWORD handle) { return D3D_OK; }
static HRESULT WINAPI Dev_DeleteStateBlock(ProxyDevice7* This, DWORD handle) { return D3D_OK; }
static HRESULT WINAPI Dev_CreateStateBlock(ProxyDevice7* This, DWORD type, DWORD* handle) {
    if (handle) *handle = 1;
    return D3D_OK;
}

/* 43: Load (texture load) */
static HRESULT WINAPI Dev_Load(ProxyDevice7* This, void* dst, void* dstPoint,
                                void* src, void* srcRect, DWORD flags) {
    return D3D_OK;
}

/* 44-45: Light enable */
static HRESULT WINAPI Dev_LightEnable(ProxyDevice7* This, DWORD index, BOOL enable) { return D3D_OK; }
static HRESULT WINAPI Dev_GetLightEnable(ProxyDevice7* This, DWORD index, BOOL* enable) {
    if (enable) *enable = FALSE;
    return D3D_OK;
}

/* 46-47: Clip plane */
static HRESULT WINAPI Dev_SetClipPlane(ProxyDevice7* This, DWORD index, float* plane) { return D3D_OK; }
static HRESULT WINAPI Dev_GetClipPlane(ProxyDevice7* This, DWORD index, float* plane) {
    if (plane) { plane[0] = plane[1] = plane[2] = plane[3] = 0.0f; }
    return D3D_OK;
}

/* 48: GetInfo */
static HRESULT WINAPI Dev_GetInfo(ProxyDevice7* This, DWORD devInfoId, void* devInfoStruct, DWORD size) {
    if (devInfoStruct) memset(devInfoStruct, 0, size);
    return S_FALSE;
}

/* ================================================================
 * IDirect3DDevice7 vtable (49 entries)
 * ================================================================ */
void* g_Device7Vtbl[49] = {
    Dev_QueryInterface,         /* 0 */
    Dev_AddRef,                 /* 1 */
    Dev_Release,                /* 2 */
    Dev_GetCaps,                /* 3 */
    Dev_EnumTextureFormats,     /* 4 */
    Dev_BeginScene,             /* 5 */
    Dev_EndScene,               /* 6 */
    Dev_GetDirect3D,            /* 7 */
    Dev_SetRenderTarget,        /* 8 */
    Dev_GetRenderTarget,        /* 9 */
    Dev_Clear,                  /* 10 */
    Dev_SetTransform,           /* 11 */
    Dev_GetTransform,           /* 12 */
    Dev_SetViewport,            /* 13 */
    Dev_MultiplyTransform,      /* 14 */
    Dev_GetViewport,            /* 15 */
    Dev_SetMaterial,            /* 16 */
    Dev_GetMaterial,            /* 17 */
    Dev_SetLight,               /* 18 */
    Dev_GetLight,               /* 19 */
    Dev_SetRenderState,         /* 20 */
    Dev_GetRenderState,         /* 21 */
    Dev_BeginStateBlock,        /* 22 */
    Dev_EndStateBlock,          /* 23 */
    Dev_PreLoad,                /* 24 */
    Dev_DrawPrimitive,          /* 25 */
    Dev_DrawIndexedPrimitive,   /* 26 */
    Dev_SetClipStatus,          /* 27 */
    Dev_GetClipStatus,          /* 28 */
    Dev_DrawPrimitiveStrided,   /* 29 */
    Dev_DrawIndexedPrimitiveStrided, /* 30 */
    Dev_DrawPrimitiveVB,        /* 31 */
    Dev_DrawIndexedPrimitiveVB, /* 32 */
    Dev_ComputeSphereVisibility,/* 33 */
    Dev_GetTexture,             /* 34 */
    Dev_SetTexture,             /* 35 */
    Dev_GetTextureStageState,   /* 36 */
    Dev_SetTextureStageState,   /* 37 */
    Dev_ValidateDevice,         /* 38 */
    Dev_ApplyStateBlock,        /* 39 */
    Dev_CaptureStateBlock,      /* 40 */
    Dev_DeleteStateBlock,       /* 41 */
    Dev_CreateStateBlock,       /* 42 */
    Dev_Load,                   /* 43 */
    Dev_LightEnable,            /* 44 */
    Dev_GetLightEnable,         /* 45 */
    Dev_SetClipPlane,           /* 46 */
    Dev_GetClipPlane,           /* 47 */
    Dev_GetInfo,                /* 48 */
};

/* ================================================================
 * IDirect3DVertexBuffer7 Methods (8 entries)
 * ================================================================ */

static HRESULT WINAPI VB_QueryInterface(ProxyVB7* This, const GUID* riid, void** ppv) {
    *ppv = This;
    This->refCount++;
    return S_OK;
}
static ULONG WINAPI VB_AddRef(ProxyVB7* This) { return ++This->refCount; }
static ULONG WINAPI VB_Release(ProxyVB7* This) {
    LONG ref = --This->refCount;
    if (ref <= 0) {
        if (This->data) HeapFree(GetProcessHeap(), 0, This->data);
        HeapFree(GetProcessHeap(), 0, This);
    }
    return ref;
}

static HRESULT WINAPI VB_Lock(ProxyVB7* This, DWORD flags, void** ppData, DWORD* pSize) {
    if (ppData) *ppData = This->data;
    if (pSize) *pSize = This->dataSize;
    return D3D_OK;
}

static HRESULT WINAPI VB_Unlock(ProxyVB7* This) { return D3D_OK; }

static HRESULT WINAPI VB_ProcessVertices(ProxyVB7* This, DWORD op, DWORD destIdx,
                                          DWORD count, ProxyVB7* src, DWORD srcIdx,
                                          void* device, DWORD flags) {
    return D3D_OK;
}

static HRESULT WINAPI VB_GetVertexBufferDesc(ProxyVB7* This, D3DVERTEXBUFFERDESC_X* desc) {
    if (!desc) return DDERR_INVALIDPARAMS;
    desc->dwSize = sizeof(D3DVERTEXBUFFERDESC_X);
    desc->dwFVF = This->fvf;
    desc->dwNumVertices = This->numVertices;
    desc->dwCaps = 0;
    return D3D_OK;
}

static HRESULT WINAPI VB_Optimize(ProxyVB7* This, void* device, DWORD flags) { return D3D_OK; }

/* ================================================================
 * IDirect3DVertexBuffer7 vtable (8 entries)
 * ================================================================ */
void* g_VB7Vtbl[8] = {
    VB_QueryInterface,    /* 0 */
    VB_AddRef,            /* 1 */
    VB_Release,           /* 2 */
    VB_Lock,              /* 3 */
    VB_Unlock,            /* 4 */
    VB_ProcessVertices,   /* 5 */
    VB_GetVertexBufferDesc,/* 6 */
    VB_Optimize,          /* 7 */
};
