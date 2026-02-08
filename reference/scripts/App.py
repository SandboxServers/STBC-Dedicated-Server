# This file was created automatically by SWIG.
import Appc
import new
class NiAVObject:
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C NiAVObject instance at %s>" % (self.this,)
class NiAVObjectPtr(NiAVObject):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = NiAVObject



class NiCamera:
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C NiCamera instance at %s>" % (self.this,)
class NiCameraPtr(NiCamera):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = NiCamera



class NiFrustum:
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_NiFrustum(self)
    __setmethods__ = {
        "m_fLeft" : Appc.NiFrustum_m_fLeft_set,
        "m_fRight" : Appc.NiFrustum_m_fRight_set,
        "m_fTop" : Appc.NiFrustum_m_fTop_set,
        "m_fBottom" : Appc.NiFrustum_m_fBottom_set,
        "m_fNear" : Appc.NiFrustum_m_fNear_set,
        "m_fFar" : Appc.NiFrustum_m_fFar_set,
    }
    def __setattr__(self,name,value):
        if (name == "this") or (name == "thisown"): self.__dict__[name] = value; return
        method = NiFrustum.__setmethods__.get(name,None)
        if method: return method(self,value)
        self.__dict__[name] = value
    __getmethods__ = {
        "m_fLeft" : Appc.NiFrustum_m_fLeft_get,
        "m_fRight" : Appc.NiFrustum_m_fRight_get,
        "m_fTop" : Appc.NiFrustum_m_fTop_get,
        "m_fBottom" : Appc.NiFrustum_m_fBottom_get,
        "m_fNear" : Appc.NiFrustum_m_fNear_get,
        "m_fFar" : Appc.NiFrustum_m_fFar_get,
    }
    def __getattr__(self,name):
        method = NiFrustum.__getmethods__.get(name,None)
        if method: return method(self)
        raise AttributeError,name
    def __repr__(self):
        return "<C NiFrustum instance at %s>" % (self.this,)
class NiFrustumPtr(NiFrustum):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = NiFrustum



class NiColor:
    def __init__(self,*args):
        self.this = apply(Appc.new_NiColor,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_NiColor(self)
    __setmethods__ = {
        "r" : Appc.NiColor_r_set,
        "g" : Appc.NiColor_g_set,
        "b" : Appc.NiColor_b_set,
    }
    def __setattr__(self,name,value):
        if (name == "this") or (name == "thisown"): self.__dict__[name] = value; return
        method = NiColor.__setmethods__.get(name,None)
        if method: return method(self,value)
        self.__dict__[name] = value
    __getmethods__ = {
        "r" : Appc.NiColor_r_get,
        "g" : Appc.NiColor_g_get,
        "b" : Appc.NiColor_b_get,
    }
    def __getattr__(self,name):
        method = NiColor.__getmethods__.get(name,None)
        if method: return method(self)
        raise AttributeError,name
    def __repr__(self):
        return "<C NiColor instance at %s>" % (self.this,)
class NiColorPtr(NiColor):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = NiColor



class NiColorA:
    def __init__(self,*args):
        self.this = apply(Appc.new_NiColorA,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_NiColorA(self)
    __setmethods__ = {
        "r" : Appc.NiColorA_r_set,
        "g" : Appc.NiColorA_g_set,
        "b" : Appc.NiColorA_b_set,
        "a" : Appc.NiColorA_a_set,
    }
    def __setattr__(self,name,value):
        if (name == "this") or (name == "thisown"): self.__dict__[name] = value; return
        method = NiColorA.__setmethods__.get(name,None)
        if method: return method(self,value)
        self.__dict__[name] = value
    __getmethods__ = {
        "r" : Appc.NiColorA_r_get,
        "g" : Appc.NiColorA_g_get,
        "b" : Appc.NiColorA_b_get,
        "a" : Appc.NiColorA_a_get,
    }
    def __getattr__(self,name):
        method = NiColorA.__getmethods__.get(name,None)
        if method: return method(self)
        raise AttributeError,name
    def __repr__(self):
        return "<C NiColorA instance at %s>" % (self.this,)
class NiColorAPtr(NiColorA):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = NiColorA



class NiPoint2:
    def __init__(self,*args):
        self.this = apply(Appc.new_NiPoint2,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_NiPoint2(self)
    __setmethods__ = {
        "x" : Appc.NiPoint2_x_set,
        "y" : Appc.NiPoint2_y_set,
    }
    def __setattr__(self,name,value):
        if (name == "this") or (name == "thisown"): self.__dict__[name] = value; return
        method = NiPoint2.__setmethods__.get(name,None)
        if method: return method(self,value)
        self.__dict__[name] = value
    __getmethods__ = {
        "x" : Appc.NiPoint2_x_get,
        "y" : Appc.NiPoint2_y_get,
    }
    def __getattr__(self,name):
        method = NiPoint2.__getmethods__.get(name,None)
        if method: return method(self)
        raise AttributeError,name
    def __repr__(self):
        return "<C NiPoint2 instance at %s>" % (self.this,)
class NiPoint2Ptr(NiPoint2):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = NiPoint2


NiPoint2.Length = new.instancemethod(Appc.NiPoint2_Length, None, NiPoint2)
NiPoint2.SqrLength = new.instancemethod(Appc.NiPoint2_SqrLength, None, NiPoint2)
NiPoint2.Dot = new.instancemethod(Appc.NiPoint2_Dot, None, NiPoint2)
NiPoint2.Unitize = new.instancemethod(Appc.NiPoint2_Unitize, None, NiPoint2)

class NiPoint3:
    def __init__(self,*args):
        self.this = apply(Appc.new_NiPoint3,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_NiPoint3(self)
    def Cross(*args):
        val = apply(Appc.NiPoint3_Cross,args)
        if val: val = NiPoint3Ptr(val) ; val.thisown = 1
        return val
    def UnitCross(*args):
        val = apply(Appc.NiPoint3_UnitCross,args)
        if val: val = NiPoint3Ptr(val) ; val.thisown = 1
        return val
    def Perpendicular(*args):
        val = apply(Appc.NiPoint3_Perpendicular,args)
        if val: val = NiPoint3Ptr(val) ; val.thisown = 1
        return val
    __setmethods__ = {
        "x" : Appc.NiPoint3_x_set,
        "y" : Appc.NiPoint3_y_set,
        "z" : Appc.NiPoint3_z_set,
    }
    def __setattr__(self,name,value):
        if (name == "this") or (name == "thisown"): self.__dict__[name] = value; return
        method = NiPoint3.__setmethods__.get(name,None)
        if method: return method(self,value)
        self.__dict__[name] = value
    __getmethods__ = {
        "x" : Appc.NiPoint3_x_get,
        "y" : Appc.NiPoint3_y_get,
        "z" : Appc.NiPoint3_z_get,
    }
    def __getattr__(self,name):
        method = NiPoint3.__getmethods__.get(name,None)
        if method: return method(self)
        raise AttributeError,name
    def __repr__(self):
        return "<C NiPoint3 instance at %s>" % (self.this,)
class NiPoint3Ptr(NiPoint3):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = NiPoint3


NiPoint3.Length = new.instancemethod(Appc.NiPoint3_Length, None, NiPoint3)
NiPoint3.SqrLength = new.instancemethod(Appc.NiPoint3_SqrLength, None, NiPoint3)
NiPoint3.Dot = new.instancemethod(Appc.NiPoint3_Dot, None, NiPoint3)
NiPoint3.Unitize = new.instancemethod(Appc.NiPoint3_Unitize, None, NiPoint3)

class TGModelUtils:
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C TGModelUtils instance at %s>" % (self.this,)
class TGModelUtilsPtr(TGModelUtils):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGModelUtils



class TGSystemWrapperClass:
    IMAGE_FORMAT_TGA = Appc.TGSystemWrapperClass_IMAGE_FORMAT_TGA
    IMAGE_FORMAT_BMP = Appc.TGSystemWrapperClass_IMAGE_FORMAT_BMP
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C TGSystemWrapperClass instance at %s>" % (self.this,)
class TGSystemWrapperClassPtr(TGSystemWrapperClass):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGSystemWrapperClass


TGSystemWrapperClass.GetTimeSinceFrameStart = new.instancemethod(Appc.TGSystemWrapperClass_GetTimeSinceFrameStart, None, TGSystemWrapperClass)
TGSystemWrapperClass.GetTimeInSeconds = new.instancemethod(Appc.TGSystemWrapperClass_GetTimeInSeconds, None, TGSystemWrapperClass)
TGSystemWrapperClass.GetTimeInMilliseconds = new.instancemethod(Appc.TGSystemWrapperClass_GetTimeInMilliseconds, None, TGSystemWrapperClass)
TGSystemWrapperClass.GetTimeElapsedInSeconds = new.instancemethod(Appc.TGSystemWrapperClass_GetTimeElapsedInSeconds, None, TGSystemWrapperClass)
TGSystemWrapperClass.GetTimeElapsedInMilliseconds = new.instancemethod(Appc.TGSystemWrapperClass_GetTimeElapsedInMilliseconds, None, TGSystemWrapperClass)
TGSystemWrapperClass.GetUpdateNumber = new.instancemethod(Appc.TGSystemWrapperClass_GetUpdateNumber, None, TGSystemWrapperClass)
TGSystemWrapperClass.GetVerticalAspectRatio = new.instancemethod(Appc.TGSystemWrapperClass_GetVerticalAspectRatio, None, TGSystemWrapperClass)
TGSystemWrapperClass.IsForeground = new.instancemethod(Appc.TGSystemWrapperClass_IsForeground, None, TGSystemWrapperClass)
TGSystemWrapperClass.GetRandomNumber = new.instancemethod(Appc.TGSystemWrapperClass_GetRandomNumber, None, TGSystemWrapperClass)
TGSystemWrapperClass.SetRandomSeed = new.instancemethod(Appc.TGSystemWrapperClass_SetRandomSeed, None, TGSystemWrapperClass)
TGSystemWrapperClass.GetIniInt = new.instancemethod(Appc.TGSystemWrapperClass_GetIniInt, None, TGSystemWrapperClass)
TGSystemWrapperClass.GetIniFloat = new.instancemethod(Appc.TGSystemWrapperClass_GetIniFloat, None, TGSystemWrapperClass)
TGSystemWrapperClass.GetIniString = new.instancemethod(Appc.TGSystemWrapperClass_GetIniString, None, TGSystemWrapperClass)
TGSystemWrapperClass.TakeScreenshot = new.instancemethod(Appc.TGSystemWrapperClass_TakeScreenshot, None, TGSystemWrapperClass)
TGSystemWrapperClass.SetDefaultScreenShotPath = new.instancemethod(Appc.TGSystemWrapperClass_SetDefaultScreenShotPath, None, TGSystemWrapperClass)

class TGProfilingInfo:
    def __init__(self,*args):
        self.this = apply(Appc.new_TGProfilingInfo,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGProfilingInfo(self)
    def __repr__(self):
        return "<C TGProfilingInfo instance at %s>" % (self.this,)
class TGProfilingInfoPtr(TGProfilingInfo):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGProfilingInfo



class TGConfigMapping:
    def __init__(self,this):
        self.this = this

    def GetTGStringValue(*args):
        val = apply(Appc.TGConfigMapping_GetTGStringValue,args)
        if val: val = TGStringPtr(val) 
        return val
    def __repr__(self):
        return "<C TGConfigMapping instance at %s>" % (self.this,)
class TGConfigMappingPtr(TGConfigMapping):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGConfigMapping


TGConfigMapping.GetFloatValue = new.instancemethod(Appc.TGConfigMapping_GetFloatValue, None, TGConfigMapping)
TGConfigMapping.GetIntValue = new.instancemethod(Appc.TGConfigMapping_GetIntValue, None, TGConfigMapping)
TGConfigMapping.GetStringValue = new.instancemethod(Appc.TGConfigMapping_GetStringValue, None, TGConfigMapping)
TGConfigMapping.SetFloatValue = new.instancemethod(Appc.TGConfigMapping_SetFloatValue, None, TGConfigMapping)
TGConfigMapping.SetIntValue = new.instancemethod(Appc.TGConfigMapping_SetIntValue, None, TGConfigMapping)
TGConfigMapping.SetStringValue = new.instancemethod(Appc.TGConfigMapping_SetStringValue, None, TGConfigMapping)
TGConfigMapping.SetTGStringValue = new.instancemethod(Appc.TGConfigMapping_SetTGStringValue, None, TGConfigMapping)
TGConfigMapping.HasValue = new.instancemethod(Appc.TGConfigMapping_HasValue, None, TGConfigMapping)
TGConfigMapping.LoadConfigFile = new.instancemethod(Appc.TGConfigMapping_LoadConfigFile, None, TGConfigMapping)
TGConfigMapping.SaveConfigFile = new.instancemethod(Appc.TGConfigMapping_SaveConfigFile, None, TGConfigMapping)

class TGPoolManager:
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C TGPoolManager instance at %s>" % (self.this,)
class TGPoolManagerPtr(TGPoolManager):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGPoolManager


TGPoolManager.Purge = new.instancemethod(Appc.TGPoolManager_Purge, None, TGPoolManager)
TGPoolManager.PrintPoolSummary = new.instancemethod(Appc.TGPoolManager_PrintPoolSummary, None, TGPoolManager)
TGPoolManager.WalkObjects = new.instancemethod(Appc.TGPoolManager_WalkObjects, None, TGPoolManager)
TGPoolManager.PrintFull = new.instancemethod(Appc.TGPoolManager_PrintFull, None, TGPoolManager)
TGPoolManager.PrintSummary = new.instancemethod(Appc.TGPoolManager_PrintSummary, None, TGPoolManager)
TGPoolManager.DumpFile = new.instancemethod(Appc.TGPoolManager_DumpFile, None, TGPoolManager)
TGPoolManager.DumpBlocks = new.instancemethod(Appc.TGPoolManager_DumpBlocks, None, TGPoolManager)
TGPoolManager.DumpObjects = new.instancemethod(Appc.TGPoolManager_DumpObjects, None, TGPoolManager)
TGPoolManager.DisplayFile = new.instancemethod(Appc.TGPoolManager_DisplayFile, None, TGPoolManager)

class TGObject:
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C TGObject instance at %s>" % (self.this,)
class TGObjectPtr(TGObject):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGObject


TGObject.GetObjType = new.instancemethod(Appc.TGObject_GetObjType, None, TGObject)
TGObject.IsTypeOf = new.instancemethod(Appc.TGObject_IsTypeOf, None, TGObject)
TGObject.GetObjID = new.instancemethod(Appc.TGObject_GetObjID, None, TGObject)
TGObject.Destroy = new.instancemethod(Appc.TGObject_Destroy, None, TGObject)
TGObject.Print = new.instancemethod(Appc.TGObject_Print, None, TGObject)

class TGAttrObject(TGObject):
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C TGAttrObject instance at %s>" % (self.this,)
class TGAttrObjectPtr(TGAttrObject):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGAttrObject


TGAttrObject.LookupAttrValue = new.instancemethod(Appc.TGAttrObject_LookupAttrValue, None, TGAttrObject)
TGAttrObject.GetAttrValue = new.instancemethod(Appc.TGAttrObject_GetAttrValue, None, TGAttrObject)
TGAttrObject.SetAttrValue = new.instancemethod(Appc.TGAttrObject_SetAttrValue, None, TGAttrObject)
TGAttrObject.RemoveAttr = new.instancemethod(Appc.TGAttrObject_RemoveAttr, None, TGAttrObject)
TGAttrObject.LookupAttrInt = new.instancemethod(Appc.TGAttrObject_LookupAttrInt, None, TGAttrObject)
TGAttrObject.GetAttrInt = new.instancemethod(Appc.TGAttrObject_GetAttrInt, None, TGAttrObject)
TGAttrObject.SetAttrInt = new.instancemethod(Appc.TGAttrObject_SetAttrInt, None, TGAttrObject)

class TGTemplatedAttrObject(TGAttrObject):
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C TGTemplatedAttrObject instance at %s>" % (self.this,)
class TGTemplatedAttrObjectPtr(TGTemplatedAttrObject):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGTemplatedAttrObject


TGTemplatedAttrObject.LookupLocalAttrValue = new.instancemethod(Appc.TGTemplatedAttrObject_LookupLocalAttrValue, None, TGTemplatedAttrObject)

class TGString:
    def __init__(self,*args):
        self.this = apply(Appc.new_TGString,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGString(self)
    def Append(*args):
        val = apply(Appc.TGString_Append,args)
        if val: val = TGStringPtr(val) ; val.thisown = 1
        return val
    def __repr__(self):
        return "<C TGString instance at %s>" % (self.this,)
class TGStringPtr(TGString):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGString


TGString.GetLength = new.instancemethod(Appc.TGString_GetLength, None, TGString)
TGString.SetString = new.instancemethod(Appc.TGString_SetString, None, TGString)
TGString.FindC = new.instancemethod(Appc.TGString_FindC, None, TGString)
TGString.Find = new.instancemethod(Appc.TGString_Find, None, TGString)
TGString.CompareC = new.instancemethod(Appc.TGString_CompareC, None, TGString)
TGString.Compare = new.instancemethod(Appc.TGString_Compare, None, TGString)

class TGStream:
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C TGStream instance at %s>" % (self.this,)
class TGStreamPtr(TGStream):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGStream



class TGBufferStream(TGStream):
    def __init__(self,*args):
        self.this = apply(Appc.new_TGBufferStream,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGBufferStream(self)
    def __repr__(self):
        return "<C TGBufferStream instance at %s>" % (self.this,)
class TGBufferStreamPtr(TGBufferStream):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGBufferStream


TGBufferStream.Close = new.instancemethod(Appc.TGBufferStream_Close, None, TGBufferStream)
TGBufferStream.SetWriteMode = new.instancemethod(Appc.TGBufferStream_SetWriteMode, None, TGBufferStream)
TGBufferStream.GetWriteMode = new.instancemethod(Appc.TGBufferStream_GetWriteMode, None, TGBufferStream)
TGBufferStream.Read = new.instancemethod(Appc.TGBufferStream_Read, None, TGBufferStream)
TGBufferStream.Write = new.instancemethod(Appc.TGBufferStream_Write, None, TGBufferStream)
TGBufferStream.ReadCLine = new.instancemethod(Appc.TGBufferStream_ReadCLine, None, TGBufferStream)
TGBufferStream.WriteCLine = new.instancemethod(Appc.TGBufferStream_WriteCLine, None, TGBufferStream)
TGBufferStream.ReadCString = new.instancemethod(Appc.TGBufferStream_ReadCString, None, TGBufferStream)
TGBufferStream.WriteCString = new.instancemethod(Appc.TGBufferStream_WriteCString, None, TGBufferStream)
TGBufferStream.ReadCWLine = new.instancemethod(Appc.TGBufferStream_ReadCWLine, None, TGBufferStream)
TGBufferStream.WriteCWLine = new.instancemethod(Appc.TGBufferStream_WriteCWLine, None, TGBufferStream)
TGBufferStream.ReadWChar = new.instancemethod(Appc.TGBufferStream_ReadWChar, None, TGBufferStream)
TGBufferStream.WriteWChar = new.instancemethod(Appc.TGBufferStream_WriteWChar, None, TGBufferStream)
TGBufferStream.ReadChar = new.instancemethod(Appc.TGBufferStream_ReadChar, None, TGBufferStream)
TGBufferStream.ReadBool = new.instancemethod(Appc.TGBufferStream_ReadBool, None, TGBufferStream)
TGBufferStream.ReadShort = new.instancemethod(Appc.TGBufferStream_ReadShort, None, TGBufferStream)
TGBufferStream.ReadInt = new.instancemethod(Appc.TGBufferStream_ReadInt, None, TGBufferStream)
TGBufferStream.ReadLong = new.instancemethod(Appc.TGBufferStream_ReadLong, None, TGBufferStream)
TGBufferStream.ReadFloat = new.instancemethod(Appc.TGBufferStream_ReadFloat, None, TGBufferStream)
TGBufferStream.ReadDouble = new.instancemethod(Appc.TGBufferStream_ReadDouble, None, TGBufferStream)
TGBufferStream.WriteBool = new.instancemethod(Appc.TGBufferStream_WriteBool, None, TGBufferStream)
TGBufferStream.WriteChar = new.instancemethod(Appc.TGBufferStream_WriteChar, None, TGBufferStream)
TGBufferStream.WriteShort = new.instancemethod(Appc.TGBufferStream_WriteShort, None, TGBufferStream)
TGBufferStream.WriteInt = new.instancemethod(Appc.TGBufferStream_WriteInt, None, TGBufferStream)
TGBufferStream.WriteLong = new.instancemethod(Appc.TGBufferStream_WriteLong, None, TGBufferStream)
TGBufferStream.WriteFloat = new.instancemethod(Appc.TGBufferStream_WriteFloat, None, TGBufferStream)
TGBufferStream.WriteDouble = new.instancemethod(Appc.TGBufferStream_WriteDouble, None, TGBufferStream)
TGBufferStream.ReadID = new.instancemethod(Appc.TGBufferStream_ReadID, None, TGBufferStream)
TGBufferStream.WriteID = new.instancemethod(Appc.TGBufferStream_WriteID, None, TGBufferStream)
TGBufferStream.GetBuffer = new.instancemethod(Appc.TGBufferStream_GetBuffer, None, TGBufferStream)
TGBufferStream.OpenBuffer = new.instancemethod(Appc.TGBufferStream_OpenBuffer, None, TGBufferStream)
TGBufferStream.CloseBuffer = new.instancemethod(Appc.TGBufferStream_CloseBuffer, None, TGBufferStream)
TGBufferStream.GetPos = new.instancemethod(Appc.TGBufferStream_GetPos, None, TGBufferStream)
TGBufferStream.GetLength = new.instancemethod(Appc.TGBufferStream_GetLength, None, TGBufferStream)
TGBufferStream.Eof = new.instancemethod(Appc.TGBufferStream_Eof, None, TGBufferStream)

class TGLocalizationDatabase:
    def __init__(self,this):
        self.this = this

    def GetString(*args):
        val = apply(Appc.TGLocalizationDatabase_GetString,args)
        if val: val = TGStringPtr(val) 
        return val
    def __repr__(self):
        return "<C TGLocalizationDatabase instance at %s>" % (self.this,)
class TGLocalizationDatabasePtr(TGLocalizationDatabase):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGLocalizationDatabase


TGLocalizationDatabase.HasString = new.instancemethod(Appc.TGLocalizationDatabase_HasString, None, TGLocalizationDatabase)
TGLocalizationDatabase.GetFilename = new.instancemethod(Appc.TGLocalizationDatabase_GetFilename, None, TGLocalizationDatabase)

class TGLocalizationManager:
    def __init__(self,this):
        self.this = this

    def Load(*args):
        val = apply(Appc.TGLocalizationManager_Load,args)
        if val: val = TGLocalizationDatabasePtr(val) 
        return val
    def GetIfRegistered(*args):
        val = apply(Appc.TGLocalizationManager_GetIfRegistered,args)
        if val: val = TGLocalizationDatabasePtr(val) 
        return val
    def __repr__(self):
        return "<C TGLocalizationManager instance at %s>" % (self.this,)
class TGLocalizationManagerPtr(TGLocalizationManager):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGLocalizationManager


TGLocalizationManager.Unload = new.instancemethod(Appc.TGLocalizationManager_Unload, None, TGLocalizationManager)
TGLocalizationManager.DeleteAll = new.instancemethod(Appc.TGLocalizationManager_DeleteAll, None, TGLocalizationManager)
TGLocalizationManager.Purge = new.instancemethod(Appc.TGLocalizationManager_Purge, None, TGLocalizationManager)
TGLocalizationManager.RegisterDatabase = new.instancemethod(Appc.TGLocalizationManager_RegisterDatabase, None, TGLocalizationManager)

class NiNode:
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C NiNode instance at %s>" % (self.this,)
class NiNodePtr(NiNode):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = NiNode



class TGAnimNode(NiNode):
    def __init__(self,this):
        self.this = this

    def GetRootNode(*args):
        val = apply(Appc.TGAnimNode_GetRootNode,args)
        if val: val = NiNodePtr(val) 
        return val
    def FindNode(*args):
        val = apply(Appc.TGAnimNode_FindNode,args)
        if val: val = NiNodePtr(val) 
        return val
    def __repr__(self):
        return "<C TGAnimNode instance at %s>" % (self.this,)
class TGAnimNodePtr(TGAnimNode):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGAnimNode


TGAnimNode.UseAnimation = new.instancemethod(Appc.TGAnimNode_UseAnimation, None, TGAnimNode)
TGAnimNode.SetExclusiveAnimation = new.instancemethod(Appc.TGAnimNode_SetExclusiveAnimation, None, TGAnimNode)
TGAnimNode.SetNonExclusiveAnimation = new.instancemethod(Appc.TGAnimNode_SetNonExclusiveAnimation, None, TGAnimNode)
TGAnimNode.StopNonExclusiveAnimation = new.instancemethod(Appc.TGAnimNode_StopNonExclusiveAnimation, None, TGAnimNode)
TGAnimNode.SetExclusiveAnimationUseDefault = new.instancemethod(Appc.TGAnimNode_SetExclusiveAnimationUseDefault, None, TGAnimNode)
TGAnimNode.Stop = new.instancemethod(Appc.TGAnimNode_Stop, None, TGAnimNode)
TGAnimNode.Copy = new.instancemethod(Appc.TGAnimNode_Copy, None, TGAnimNode)
TGAnimNode.IsAnimate = new.instancemethod(Appc.TGAnimNode_IsAnimate, None, TGAnimNode)
TGAnimNode.UseAnimationPosition = new.instancemethod(Appc.TGAnimNode_UseAnimationPosition, None, TGAnimNode)
TGAnimNode.SetRootNode = new.instancemethod(Appc.TGAnimNode_SetRootNode, None, TGAnimNode)
TGAnimNode.SetBlendTime = new.instancemethod(Appc.TGAnimNode_SetBlendTime, None, TGAnimNode)
TGAnimNode.GetBlendTime = new.instancemethod(Appc.TGAnimNode_GetBlendTime, None, TGAnimNode)

class TGAnimationManagerClass:
    SAT_NORMAL = Appc.TGAnimationManagerClass_SAT_NORMAL
    SAT_SPECIAL = Appc.TGAnimationManagerClass_SAT_SPECIAL
    SAT_MOVES_PELVIS = Appc.TGAnimationManagerClass_SAT_MOVES_PELVIS
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C TGAnimationManagerClass instance at %s>" % (self.this,)
class TGAnimationManagerClassPtr(TGAnimationManagerClass):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGAnimationManagerClass


TGAnimationManagerClass.LoadAnimation = new.instancemethod(Appc.TGAnimationManagerClass_LoadAnimation, None, TGAnimationManagerClass)
TGAnimationManagerClass.MapDefaultAnimation = new.instancemethod(Appc.TGAnimationManagerClass_MapDefaultAnimation, None, TGAnimationManagerClass)
TGAnimationManagerClass.FreeAnimation = new.instancemethod(Appc.TGAnimationManagerClass_FreeAnimation, None, TGAnimationManagerClass)
TGAnimationManagerClass.UseAnimation = new.instancemethod(Appc.TGAnimationManagerClass_UseAnimation, None, TGAnimationManagerClass)
TGAnimationManagerClass.BlendAnimation = new.instancemethod(Appc.TGAnimationManagerClass_BlendAnimation, None, TGAnimationManagerClass)
TGAnimationManagerClass.UseDefault = new.instancemethod(Appc.TGAnimationManagerClass_UseDefault, None, TGAnimationManagerClass)
TGAnimationManagerClass.GetAnimationLength = new.instancemethod(Appc.TGAnimationManagerClass_GetAnimationLength, None, TGAnimationManagerClass)
TGAnimationManagerClass.IsLoaded = new.instancemethod(Appc.TGAnimationManagerClass_IsLoaded, None, TGAnimationManagerClass)
TGAnimationManagerClass.ClearAnimations = new.instancemethod(Appc.TGAnimationManagerClass_ClearAnimations, None, TGAnimationManagerClass)
TGAnimationManagerClass.PositionUsingAnimation = new.instancemethod(Appc.TGAnimationManagerClass_PositionUsingAnimation, None, TGAnimationManagerClass)

class TGModelManager:
    def __init__(self,this):
        self.this = this

    def GetModel(*args):
        val = apply(Appc.TGModelManager_GetModel,args)
        if val: val = TGAnimNodePtr(val) 
        return val
    def GetCamera(*args):
        val = apply(Appc.TGModelManager_GetCamera,args)
        if val: val = NiCameraPtr(val) 
        return val
    def CloneModel(*args):
        val = apply(Appc.TGModelManager_CloneModel,args)
        if val: val = TGAnimNodePtr(val) 
        return val
    def CloneCamera(*args):
        val = apply(Appc.TGModelManager_CloneCamera,args)
        if val: val = NiCameraPtr(val) 
        return val
    def CopyModel(*args):
        val = apply(Appc.TGModelManager_CopyModel,args)
        if val: val = TGAnimNodePtr(val) 
        return val
    def __repr__(self):
        return "<C TGModelManager instance at %s>" % (self.this,)
class TGModelManagerPtr(TGModelManager):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGModelManager


TGModelManager.LoadModel = new.instancemethod(Appc.TGModelManager_LoadModel, None, TGModelManager)
TGModelManager.LoadModelIncremental = new.instancemethod(Appc.TGModelManager_LoadModelIncremental, None, TGModelManager)
TGModelManager.IsModelLoaded = new.instancemethod(Appc.TGModelManager_IsModelLoaded, None, TGModelManager)
TGModelManager.AddModel = new.instancemethod(Appc.TGModelManager_AddModel, None, TGModelManager)
TGModelManager.FreeModel = new.instancemethod(Appc.TGModelManager_FreeModel, None, TGModelManager)
TGModelManager.FreeAllModels = new.instancemethod(Appc.TGModelManager_FreeAllModels, None, TGModelManager)
TGModelManager.Refer = new.instancemethod(Appc.TGModelManager_Refer, None, TGModelManager)
TGModelManager.Unrefer = new.instancemethod(Appc.TGModelManager_Unrefer, None, TGModelManager)
TGModelManager.UnreferAll = new.instancemethod(Appc.TGModelManager_UnreferAll, None, TGModelManager)
TGModelManager.Purge = new.instancemethod(Appc.TGModelManager_Purge, None, TGModelManager)
TGModelManager.DoIncrementalLoad = new.instancemethod(Appc.TGModelManager_DoIncrementalLoad, None, TGModelManager)
TGModelManager.ClearIncrementalLoadQueue = new.instancemethod(Appc.TGModelManager_ClearIncrementalLoadQueue, None, TGModelManager)

class TGEvent(TGObject):
    def __init__(self,*args):
        self.this = apply(Appc.new_TGEvent,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEvent(self)
    def Duplicate(*args):
        val = apply(Appc.TGEvent_Duplicate,args)
        if val: val = TGEventPtr(val) 
        return val
    def GetSource(*args):
        val = apply(Appc.TGEvent_GetSource,args)
        if val: val = TGObjectPtr(val) 
        return val
    def GetDestination(*args):
        val = apply(Appc.TGEvent_GetDestination,args)
        if val: val = TGEventHandlerObjectPtr(val) 
        return val
    def __repr__(self):
        return "<C TGEvent instance at %s>" % (self.this,)
class TGEventPtr(TGEvent):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGEvent


TGEvent.Copy = new.instancemethod(Appc.TGEvent_Copy, None, TGEvent)
TGEvent.GetEventType = new.instancemethod(Appc.TGEvent_GetEventType, None, TGEvent)
TGEvent.GetTimestamp = new.instancemethod(Appc.TGEvent_GetTimestamp, None, TGEvent)
TGEvent.SetEventType = new.instancemethod(Appc.TGEvent_SetEventType, None, TGEvent)
TGEvent.SetSource = new.instancemethod(Appc.TGEvent_SetSource, None, TGEvent)
TGEvent.SetDestination = new.instancemethod(Appc.TGEvent_SetDestination, None, TGEvent)
TGEvent.SetTimestamp = new.instancemethod(Appc.TGEvent_SetTimestamp, None, TGEvent)
TGEvent.SetLogged = new.instancemethod(Appc.TGEvent_SetLogged, None, TGEvent)
TGEvent.IsLogged = new.instancemethod(Appc.TGEvent_IsLogged, None, TGEvent)
TGEvent.SetPrivate = new.instancemethod(Appc.TGEvent_SetPrivate, None, TGEvent)
TGEvent.IsPrivate = new.instancemethod(Appc.TGEvent_IsPrivate, None, TGEvent)
TGEvent.SetNotSaved = new.instancemethod(Appc.TGEvent_SetNotSaved, None, TGEvent)
TGEvent.IsNotSaved = new.instancemethod(Appc.TGEvent_IsNotSaved, None, TGEvent)
TGEvent.IncRefCount = new.instancemethod(Appc.TGEvent_IncRefCount, None, TGEvent)
TGEvent.DecRefCount = new.instancemethod(Appc.TGEvent_DecRefCount, None, TGEvent)
TGEvent.GetRefCount = new.instancemethod(Appc.TGEvent_GetRefCount, None, TGEvent)

class TGBoolEvent(TGEvent):
    def __init__(self,*args):
        self.this = apply(Appc.new_TGBoolEvent,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEvent(self)
    def __repr__(self):
        return "<C TGBoolEvent instance at %s>" % (self.this,)
class TGBoolEventPtr(TGBoolEvent):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGBoolEvent


TGBoolEvent.GetBool = new.instancemethod(Appc.TGBoolEvent_GetBool, None, TGBoolEvent)
TGBoolEvent.SetBool = new.instancemethod(Appc.TGBoolEvent_SetBool, None, TGBoolEvent)
TGBoolEvent.ToggleBool = new.instancemethod(Appc.TGBoolEvent_ToggleBool, None, TGBoolEvent)

class TGCharEvent(TGEvent):
    def __init__(self,*args):
        self.this = apply(Appc.new_TGCharEvent,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEvent(self)
    def __repr__(self):
        return "<C TGCharEvent instance at %s>" % (self.this,)
class TGCharEventPtr(TGCharEvent):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGCharEvent


TGCharEvent.GetChar = new.instancemethod(Appc.TGCharEvent_GetChar, None, TGCharEvent)
TGCharEvent.SetChar = new.instancemethod(Appc.TGCharEvent_SetChar, None, TGCharEvent)

class TGShortEvent(TGEvent):
    def __init__(self,*args):
        self.this = apply(Appc.new_TGShortEvent,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEvent(self)
    def __repr__(self):
        return "<C TGShortEvent instance at %s>" % (self.this,)
class TGShortEventPtr(TGShortEvent):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGShortEvent


TGShortEvent.GetShort = new.instancemethod(Appc.TGShortEvent_GetShort, None, TGShortEvent)
TGShortEvent.SetShort = new.instancemethod(Appc.TGShortEvent_SetShort, None, TGShortEvent)

class TGIntEvent(TGEvent):
    def __init__(self,*args):
        self.this = apply(Appc.new_TGIntEvent,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEvent(self)
    def __repr__(self):
        return "<C TGIntEvent instance at %s>" % (self.this,)
class TGIntEventPtr(TGIntEvent):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGIntEvent


TGIntEvent.GetInt = new.instancemethod(Appc.TGIntEvent_GetInt, None, TGIntEvent)
TGIntEvent.SetInt = new.instancemethod(Appc.TGIntEvent_SetInt, None, TGIntEvent)

class TGFloatEvent(TGEvent):
    def __init__(self,*args):
        self.this = apply(Appc.new_TGFloatEvent,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEvent(self)
    def __repr__(self):
        return "<C TGFloatEvent instance at %s>" % (self.this,)
class TGFloatEventPtr(TGFloatEvent):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGFloatEvent


TGFloatEvent.GetFloat = new.instancemethod(Appc.TGFloatEvent_GetFloat, None, TGFloatEvent)
TGFloatEvent.SetFloat = new.instancemethod(Appc.TGFloatEvent_SetFloat, None, TGFloatEvent)

class TGStringEvent(TGEvent):
    def __init__(self,*args):
        self.this = apply(Appc.new_TGStringEvent,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEvent(self)
    def __repr__(self):
        return "<C TGStringEvent instance at %s>" % (self.this,)
class TGStringEventPtr(TGStringEvent):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGStringEvent


TGStringEvent.GetString = new.instancemethod(Appc.TGStringEvent_GetString, None, TGStringEvent)
TGStringEvent.SetString = new.instancemethod(Appc.TGStringEvent_SetString, None, TGStringEvent)

class TGVoidPtrEvent(TGEvent):
    def __init__(self,*args):
        self.this = apply(Appc.new_TGVoidPtrEvent,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEvent(self)
    def __repr__(self):
        return "<C TGVoidPtrEvent instance at %s>" % (self.this,)
class TGVoidPtrEventPtr(TGVoidPtrEvent):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGVoidPtrEvent


TGVoidPtrEvent.GetVoidPtr = new.instancemethod(Appc.TGVoidPtrEvent_GetVoidPtr, None, TGVoidPtrEvent)
TGVoidPtrEvent.SetVoidPtr = new.instancemethod(Appc.TGVoidPtrEvent_SetVoidPtr, None, TGVoidPtrEvent)

class TGObjPtrEvent(TGEvent):
    def __init__(self,*args):
        self.this = apply(Appc.new_TGObjPtrEvent,args)
        self.thisown = 1

    def GetObjPtr(*args):
        val = apply(Appc.TGObjPtrEvent_GetObjPtr,args)
        if val: val = TGObjectPtr(val) 
        return val
    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEvent(self)
    def __repr__(self):
        return "<C TGObjPtrEvent instance at %s>" % (self.this,)
class TGObjPtrEventPtr(TGObjPtrEvent):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGObjPtrEvent


TGObjPtrEvent.SetObjPtr = new.instancemethod(Appc.TGObjPtrEvent_SetObjPtr, None, TGObjPtrEvent)

class TGEventHandlerObject(TGTemplatedAttrObject):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEventHandlerObject(self)
    def __repr__(self):
        return "<C TGEventHandlerObject instance at %s>" % (self.this,)
class TGEventHandlerObjectPtr(TGEventHandlerObject):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGEventHandlerObject


TGEventHandlerObject.ProcessEvent = new.instancemethod(Appc.TGEventHandlerObject_ProcessEvent, None, TGEventHandlerObject)
TGEventHandlerObject.CallNextHandler = new.instancemethod(Appc.TGEventHandlerObject_CallNextHandler, None, TGEventHandlerObject)
TGEventHandlerObject.AddPythonFuncHandlerForInstance = new.instancemethod(Appc.TGEventHandlerObject_AddPythonFuncHandlerForInstance, None, TGEventHandlerObject)
TGEventHandlerObject.AddPythonMethodHandlerForInstance = new.instancemethod(Appc.TGEventHandlerObject_AddPythonMethodHandlerForInstance, None, TGEventHandlerObject)
TGEventHandlerObject.RemoveHandlerForInstance = new.instancemethod(Appc.TGEventHandlerObject_RemoveHandlerForInstance, None, TGEventHandlerObject)
TGEventHandlerObject.RemoveAllInstanceHandlers = new.instancemethod(Appc.TGEventHandlerObject_RemoveAllInstanceHandlers, None, TGEventHandlerObject)

class TGEventManager:
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C TGEventManager instance at %s>" % (self.this,)
class TGEventManagerPtr(TGEventManager):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGEventManager


TGEventManager.AddBroadcastPythonFuncHandler = new.instancemethod(Appc.TGEventManager_AddBroadcastPythonFuncHandler, None, TGEventManager)
TGEventManager.AddBroadcastPythonMethodHandler = new.instancemethod(Appc.TGEventManager_AddBroadcastPythonMethodHandler, None, TGEventManager)
TGEventManager.RemoveBroadcastHandler = new.instancemethod(Appc.TGEventManager_RemoveBroadcastHandler, None, TGEventManager)
TGEventManager.RemoveAllBroadcastHandlersForObject = new.instancemethod(Appc.TGEventManager_RemoveAllBroadcastHandlersForObject, None, TGEventManager)
TGEventManager.AddEvent = new.instancemethod(Appc.TGEventManager_AddEvent, None, TGEventManager)

class TGTimer(TGObject):
    def __init__(self,*args):
        self.this = apply(Appc.new_TGTimer,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGTimer(self)
    def GetEvent(*args):
        val = apply(Appc.TGTimer_GetEvent,args)
        if val: val = TGEventPtr(val) 
        return val
    def __repr__(self):
        return "<C TGTimer instance at %s>" % (self.this,)
class TGTimerPtr(TGTimer):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGTimer


TGTimer.SetTimerStart = new.instancemethod(Appc.TGTimer_SetTimerStart, None, TGTimer)
TGTimer.SetDelay = new.instancemethod(Appc.TGTimer_SetDelay, None, TGTimer)
TGTimer.SetDuration = new.instancemethod(Appc.TGTimer_SetDuration, None, TGTimer)
TGTimer.SetEvent = new.instancemethod(Appc.TGTimer_SetEvent, None, TGTimer)
TGTimer.GetTimerStart = new.instancemethod(Appc.TGTimer_GetTimerStart, None, TGTimer)
TGTimer.GetDelay = new.instancemethod(Appc.TGTimer_GetDelay, None, TGTimer)
TGTimer.GetDuration = new.instancemethod(Appc.TGTimer_GetDuration, None, TGTimer)

class TGTimerManager:
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C TGTimerManager instance at %s>" % (self.this,)
class TGTimerManagerPtr(TGTimerManager):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGTimerManager


TGTimerManager.AddTimer = new.instancemethod(Appc.TGTimerManager_AddTimer, None, TGTimerManager)
TGTimerManager.RemoveTimer = new.instancemethod(Appc.TGTimerManager_RemoveTimer, None, TGTimerManager)
TGTimerManager.DeleteTimer = new.instancemethod(Appc.TGTimerManager_DeleteTimer, None, TGTimerManager)

class TGPythonInstanceWrapper(TGEventHandlerObject):
    def __init__(self,*args):
        self.this = apply(Appc.new_TGPythonInstanceWrapper,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEventHandlerObject(self)
    def __repr__(self):
        return "<C TGPythonInstanceWrapper instance at %s>" % (self.this,)
class TGPythonInstanceWrapperPtr(TGPythonInstanceWrapper):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGPythonInstanceWrapper



class TGIEvent(TGEvent):
    def __init__(self,*args):
        self.this = apply(Appc.new_TGIEvent,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEvent(self)
    def __repr__(self):
        return "<C TGIEvent instance at %s>" % (self.this,)
class TGIEventPtr(TGIEvent):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGIEvent


TGIEvent.EventHandled = new.instancemethod(Appc.TGIEvent_EventHandled, None, TGIEvent)
TGIEvent.SetHandled = new.instancemethod(Appc.TGIEvent_SetHandled, None, TGIEvent)

class TGMouseEvent(TGIEvent):
    MEF_BUTTON_DOWN = Appc.TGMouseEvent_MEF_BUTTON_DOWN
    MEF_BUTTON_UP = Appc.TGMouseEvent_MEF_BUTTON_UP
    MEF_BUTTON_MASK = Appc.TGMouseEvent_MEF_BUTTON_MASK
    MEF_BUTTON_NUM_MASK = Appc.TGMouseEvent_MEF_BUTTON_NUM_MASK
    MEF_BUTTON_LEFT = Appc.TGMouseEvent_MEF_BUTTON_LEFT
    MEF_BUTTON_RIGHT = Appc.TGMouseEvent_MEF_BUTTON_RIGHT
    MEF_BUTTON_MIDDLE = Appc.TGMouseEvent_MEF_BUTTON_MIDDLE
    def __init__(self,*args):
        self.this = apply(Appc.new_TGMouseEvent,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEvent(self)
    def __repr__(self):
        return "<C TGMouseEvent instance at %s>" % (self.this,)
class TGMouseEventPtr(TGMouseEvent):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGMouseEvent


TGMouseEvent.Copy = new.instancemethod(Appc.TGMouseEvent_Copy, None, TGMouseEvent)
TGMouseEvent.IsButtonEvent = new.instancemethod(Appc.TGMouseEvent_IsButtonEvent, None, TGMouseEvent)
TGMouseEvent.GetButtonNum = new.instancemethod(Appc.TGMouseEvent_GetButtonNum, None, TGMouseEvent)
TGMouseEvent.GetFlags = new.instancemethod(Appc.TGMouseEvent_GetFlags, None, TGMouseEvent)
TGMouseEvent.SetFlags = new.instancemethod(Appc.TGMouseEvent_SetFlags, None, TGMouseEvent)
TGMouseEvent.GetX = new.instancemethod(Appc.TGMouseEvent_GetX, None, TGMouseEvent)
TGMouseEvent.GetY = new.instancemethod(Appc.TGMouseEvent_GetY, None, TGMouseEvent)

class TGKeyboardEvent(TGIEvent):
    KS_NORMAL = Appc.TGKeyboardEvent_KS_NORMAL
    KS_KEYDOWN = Appc.TGKeyboardEvent_KS_KEYDOWN
    KS_KEYUP = Appc.TGKeyboardEvent_KS_KEYUP
    def __init__(self,*args):
        self.this = apply(Appc.new_TGKeyboardEvent,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEvent(self)
    def __repr__(self):
        return "<C TGKeyboardEvent instance at %s>" % (self.this,)
class TGKeyboardEventPtr(TGKeyboardEvent):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGKeyboardEvent


TGKeyboardEvent.Copy = new.instancemethod(Appc.TGKeyboardEvent_Copy, None, TGKeyboardEvent)
TGKeyboardEvent.GetUnicode = new.instancemethod(Appc.TGKeyboardEvent_GetUnicode, None, TGKeyboardEvent)
TGKeyboardEvent.SetUnicode = new.instancemethod(Appc.TGKeyboardEvent_SetUnicode, None, TGKeyboardEvent)
TGKeyboardEvent.GetKeyData = new.instancemethod(Appc.TGKeyboardEvent_GetKeyData, None, TGKeyboardEvent)
TGKeyboardEvent.SetKeyData = new.instancemethod(Appc.TGKeyboardEvent_SetKeyData, None, TGKeyboardEvent)
TGKeyboardEvent.GetKeyState = new.instancemethod(Appc.TGKeyboardEvent_GetKeyState, None, TGKeyboardEvent)
TGKeyboardEvent.SetKeyState = new.instancemethod(Appc.TGKeyboardEvent_SetKeyState, None, TGKeyboardEvent)

class TGGamepadEvent(TGIEvent):
    PS_AXIS = Appc.TGGamepadEvent_PS_AXIS
    PS_BTNDOWN = Appc.TGGamepadEvent_PS_BTNDOWN
    PS_BTNUP = Appc.TGGamepadEvent_PS_BTNUP
    def __init__(self,*args):
        self.this = apply(Appc.new_TGGamepadEvent,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEvent(self)
    def __repr__(self):
        return "<C TGGamepadEvent instance at %s>" % (self.this,)
class TGGamepadEventPtr(TGGamepadEvent):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGGamepadEvent


TGGamepadEvent.Copy = new.instancemethod(Appc.TGGamepadEvent_Copy, None, TGGamepadEvent)
TGGamepadEvent.GetInfo = new.instancemethod(Appc.TGGamepadEvent_GetInfo, None, TGGamepadEvent)
TGGamepadEvent.SetInfo = new.instancemethod(Appc.TGGamepadEvent_SetInfo, None, TGGamepadEvent)

class TGInputManager:
    TG_KEYBOARD = Appc.TGInputManager_TG_KEYBOARD
    TG_MOUSE = Appc.TGInputManager_TG_MOUSE
    TG_GAMEPAD = Appc.TGInputManager_TG_GAMEPAD
    TG_NO_BUTTONS = Appc.TGInputManager_TG_NO_BUTTONS
    TG_LMBUTTON = Appc.TGInputManager_TG_LMBUTTON
    TG_CMBUTTON = Appc.TGInputManager_TG_CMBUTTON
    TG_RMBUTTON = Appc.TGInputManager_TG_RMBUTTON
    TG_BUTTON4 = Appc.TGInputManager_TG_BUTTON4
    KS_MOVE = Appc.TGInputManager_KS_MOVE
    KS_DOWN = Appc.TGInputManager_KS_DOWN
    KS_UP = Appc.TGInputManager_KS_UP
    KS_NORMAL = Appc.TGInputManager_KS_NORMAL
    KS_MOVE_DELTA = Appc.TGInputManager_KS_MOVE_DELTA
    LEFT_DOWN = Appc.TGInputManager_LEFT_DOWN
    MIDDLE_DOWN = Appc.TGInputManager_MIDDLE_DOWN
    RIGHT_DOWN = Appc.TGInputManager_RIGHT_DOWN
    def __init__(self,this):
        self.this = this

    def GetMousePos(*args):
        val = apply(Appc.TGInputManager_GetMousePos,args)
        if val: val = NiPoint2Ptr(val) ; val.thisown = 1
        return val
    def GetMouseDelta(*args):
        val = apply(Appc.TGInputManager_GetMouseDelta,args)
        if val: val = NiPoint2Ptr(val) ; val.thisown = 1
        return val
    def GetDisplayStringFromUnicode(*args):
        val = apply(Appc.TGInputManager_GetDisplayStringFromUnicode,args)
        if val: val = TGStringPtr(val) ; val.thisown = 1
        return val
    def __repr__(self):
        return "<C TGInputManager instance at %s>" % (self.this,)
class TGInputManagerPtr(TGInputManager):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGInputManager


TGInputManager.Poll = new.instancemethod(Appc.TGInputManager_Poll, None, TGInputManager)
TGInputManager.UpdateDevices = new.instancemethod(Appc.TGInputManager_UpdateDevices, None, TGInputManager)
TGInputManager.KeyEvent = new.instancemethod(Appc.TGInputManager_KeyEvent, None, TGInputManager)
TGInputManager.MouseEvent = new.instancemethod(Appc.TGInputManager_MouseEvent, None, TGInputManager)
TGInputManager.SetMousePosition = new.instancemethod(Appc.TGInputManager_SetMousePosition, None, TGInputManager)
TGInputManager.GetMouseDeltaX = new.instancemethod(Appc.TGInputManager_GetMouseDeltaX, None, TGInputManager)
TGInputManager.GetMouseDeltaY = new.instancemethod(Appc.TGInputManager_GetMouseDeltaY, None, TGInputManager)
TGInputManager.GetMouseX = new.instancemethod(Appc.TGInputManager_GetMouseX, None, TGInputManager)
TGInputManager.GetMouseY = new.instancemethod(Appc.TGInputManager_GetMouseY, None, TGInputManager)
TGInputManager.GetCenterMouse = new.instancemethod(Appc.TGInputManager_GetCenterMouse, None, TGInputManager)
TGInputManager.SetCenterMouse = new.instancemethod(Appc.TGInputManager_SetCenterMouse, None, TGInputManager)
TGInputManager.GamepadEvent = new.instancemethod(Appc.TGInputManager_GamepadEvent, None, TGInputManager)
TGInputManager.RegisterUnicodeKey = new.instancemethod(Appc.TGInputManager_RegisterUnicodeKey, None, TGInputManager)
TGInputManager.RegisterDeadKey = new.instancemethod(Appc.TGInputManager_RegisterDeadKey, None, TGInputManager)
TGInputManager.GetUnicodeKey = new.instancemethod(Appc.TGInputManager_GetUnicodeKey, None, TGInputManager)
TGInputManager.GetScanCode = new.instancemethod(Appc.TGInputManager_GetScanCode, None, TGInputManager)
TGInputManager.SetCurrentUnicodeKeyList = new.instancemethod(Appc.TGInputManager_SetCurrentUnicodeKeyList, None, TGInputManager)
TGInputManager.SetDisplayStringForUnicode = new.instancemethod(Appc.TGInputManager_SetDisplayStringForUnicode, None, TGInputManager)
TGInputManager.SetKeyboardInputEnabled = new.instancemethod(Appc.TGInputManager_SetKeyboardInputEnabled, None, TGInputManager)
TGInputManager.MoveMouseCursorTo = new.instancemethod(Appc.TGInputManager_MoveMouseCursorTo, None, TGInputManager)
TGInputManager.PauseMouseCursorMoveTo = new.instancemethod(Appc.TGInputManager_PauseMouseCursorMoveTo, None, TGInputManager)
TGInputManager.ResumeMouseCursorMoveTo = new.instancemethod(Appc.TGInputManager_ResumeMouseCursorMoveTo, None, TGInputManager)

class TGUIModule:
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C TGUIModule instance at %s>" % (self.this,)
class TGUIModulePtr(TGUIModule):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGUIModule



class TGRect:
    NOT_WITHIN_RECT = Appc.TGRect_NOT_WITHIN_RECT
    COMPLETELY_WITHIN_RECT = Appc.TGRect_COMPLETELY_WITHIN_RECT
    PARTIALLY_WITHIN_RECT = Appc.TGRect_PARTIALLY_WITHIN_RECT
    def __init__(self,*args):
        self.this = apply(Appc.new_TGRect,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGRect(self)
    def __repr__(self):
        return "<C TGRect instance at %s>" % (self.this,)
class TGRectPtr(TGRect):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGRect


TGRect.Set = new.instancemethod(Appc.TGRect_Set, None, TGRect)
TGRect.GetLeft = new.instancemethod(Appc.TGRect_GetLeft, None, TGRect)
TGRect.GetTop = new.instancemethod(Appc.TGRect_GetTop, None, TGRect)
TGRect.GetWidth = new.instancemethod(Appc.TGRect_GetWidth, None, TGRect)
TGRect.GetHeight = new.instancemethod(Appc.TGRect_GetHeight, None, TGRect)
TGRect.GetRight = new.instancemethod(Appc.TGRect_GetRight, None, TGRect)
TGRect.GetBottom = new.instancemethod(Appc.TGRect_GetBottom, None, TGRect)
TGRect.GetPosition = new.instancemethod(Appc.TGRect_GetPosition, None, TGRect)
TGRect.SetLeft = new.instancemethod(Appc.TGRect_SetLeft, None, TGRect)
TGRect.SetTop = new.instancemethod(Appc.TGRect_SetTop, None, TGRect)
TGRect.SetWidth = new.instancemethod(Appc.TGRect_SetWidth, None, TGRect)
TGRect.SetHeight = new.instancemethod(Appc.TGRect_SetHeight, None, TGRect)
TGRect.SetRight = new.instancemethod(Appc.TGRect_SetRight, None, TGRect)
TGRect.SetBottom = new.instancemethod(Appc.TGRect_SetBottom, None, TGRect)
TGRect.SetPosition = new.instancemethod(Appc.TGRect_SetPosition, None, TGRect)
TGRect.IsEmpty = new.instancemethod(Appc.TGRect_IsEmpty, None, TGRect)
TGRect.IsClear = new.instancemethod(Appc.TGRect_IsClear, None, TGRect)
TGRect.DoesIntersect = new.instancemethod(Appc.TGRect_DoesIntersect, None, TGRect)
TGRect.IsWithin = new.instancemethod(Appc.TGRect_IsWithin, None, TGRect)
TGRect.ClipTo = new.instancemethod(Appc.TGRect_ClipTo, None, TGRect)
TGRect.Clear = new.instancemethod(Appc.TGRect_Clear, None, TGRect)

class TGUIObject(TGEventHandlerObject):
    ALIGN_UL = Appc.TGUIObject_ALIGN_UL
    ALIGN_UR = Appc.TGUIObject_ALIGN_UR
    ALIGN_BL = Appc.TGUIObject_ALIGN_BL
    ALIGN_BR = Appc.TGUIObject_ALIGN_BR
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGUIObject(self)
    def GetParent(*args):
        val = apply(Appc.TGUIObject_GetParent,args)
        if val: val = TGPanePtr(val) 
        return val
    def GetConceptualParent(*args):
        val = apply(Appc.TGUIObject_GetConceptualParent,args)
        if val: val = TGPanePtr(val) 
        return val
    def GetCommonAncestor(*args):
        val = apply(Appc.TGUIObject_GetCommonAncestor,args)
        if val: val = TGUIObjectPtr(val) 
        return val
    def GetFocusLeaf(*args):
        val = apply(Appc.TGUIObject_GetFocusLeaf,args)
        if val: val = TGUIObjectPtr(val) 
        return val
    def __repr__(self):
        return "<C TGUIObject instance at %s>" % (self.this,)
class TGUIObjectPtr(TGUIObject):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGUIObject


TGUIObject.SetParent = new.instancemethod(Appc.TGUIObject_SetParent, None, TGUIObject)
TGUIObject.GetBounds = new.instancemethod(Appc.TGUIObject_GetBounds, None, TGUIObject)
TGUIObject.SetBounds = new.instancemethod(Appc.TGUIObject_SetBounds, None, TGUIObject)
TGUIObject.GetLeft = new.instancemethod(Appc.TGUIObject_GetLeft, None, TGUIObject)
TGUIObject.GetTop = new.instancemethod(Appc.TGUIObject_GetTop, None, TGUIObject)
TGUIObject.GetRight = new.instancemethod(Appc.TGUIObject_GetRight, None, TGUIObject)
TGUIObject.GetBottom = new.instancemethod(Appc.TGUIObject_GetBottom, None, TGUIObject)
TGUIObject.GetWidth = new.instancemethod(Appc.TGUIObject_GetWidth, None, TGUIObject)
TGUIObject.GetHeight = new.instancemethod(Appc.TGUIObject_GetHeight, None, TGUIObject)
TGUIObject.IsWithin = new.instancemethod(Appc.TGUIObject_IsWithin, None, TGUIObject)
TGUIObject.GetPosition = new.instancemethod(Appc.TGUIObject_GetPosition, None, TGUIObject)
TGUIObject.SetPosition = new.instancemethod(Appc.TGUIObject_SetPosition, None, TGUIObject)
TGUIObject.GetFlags = new.instancemethod(Appc.TGUIObject_GetFlags, None, TGUIObject)
TGUIObject.GetScreenOffset = new.instancemethod(Appc.TGUIObject_GetScreenOffset, None, TGUIObject)
TGUIObject.GetClipRect = new.instancemethod(Appc.TGUIObject_GetClipRect, None, TGUIObject)
TGUIObject.Move = new.instancemethod(Appc.TGUIObject_Move, None, TGUIObject)
TGUIObject.Resize = new.instancemethod(Appc.TGUIObject_Resize, None, TGUIObject)
TGUIObject.AlignTo = new.instancemethod(Appc.TGUIObject_AlignTo, None, TGUIObject)
TGUIObject.GotFocus = new.instancemethod(Appc.TGUIObject_GotFocus, None, TGUIObject)
TGUIObject.GotTrueFocus = new.instancemethod(Appc.TGUIObject_GotTrueFocus, None, TGUIObject)
TGUIObject.GotTrueFocusPath = new.instancemethod(Appc.TGUIObject_GotTrueFocusPath, None, TGUIObject)
TGUIObject.LostFocus = new.instancemethod(Appc.TGUIObject_LostFocus, None, TGUIObject)
TGUIObject.LostTrueFocus = new.instancemethod(Appc.TGUIObject_LostTrueFocus, None, TGUIObject)
TGUIObject.LostTrueFocusPath = new.instancemethod(Appc.TGUIObject_LostTrueFocusPath, None, TGUIObject)
TGUIObject.HasFocus = new.instancemethod(Appc.TGUIObject_HasFocus, None, TGUIObject)
TGUIObject.HasTrueFocus = new.instancemethod(Appc.TGUIObject_HasTrueFocus, None, TGUIObject)
TGUIObject.HasAncestor = new.instancemethod(Appc.TGUIObject_HasAncestor, None, TGUIObject)
TGUIObject.IsInTrueFocusPath = new.instancemethod(Appc.TGUIObject_IsInTrueFocusPath, None, TGUIObject)
TGUIObject.FocusHeight = new.instancemethod(Appc.TGUIObject_FocusHeight, None, TGUIObject)
TGUIObject.GetDesiredSize = new.instancemethod(Appc.TGUIObject_GetDesiredSize, None, TGUIObject)
TGUIObject.MouseEntered = new.instancemethod(Appc.TGUIObject_MouseEntered, None, TGUIObject)
TGUIObject.MouseExited = new.instancemethod(Appc.TGUIObject_MouseExited, None, TGUIObject)
TGUIObject.IsCompletelyEnabled = new.instancemethod(Appc.TGUIObject_IsCompletelyEnabled, None, TGUIObject)
TGUIObject.IsEnabled = new.instancemethod(Appc.TGUIObject_IsEnabled, None, TGUIObject)
TGUIObject.SetEnabled = new.instancemethod(Appc.TGUIObject_SetEnabled, None, TGUIObject)
TGUIObject.SetDisabled = new.instancemethod(Appc.TGUIObject_SetDisabled, None, TGUIObject)
TGUIObject.ToggleEnabled = new.instancemethod(Appc.TGUIObject_ToggleEnabled, None, TGUIObject)
TGUIObject.SetEnabledFlag = new.instancemethod(Appc.TGUIObject_SetEnabledFlag, None, TGUIObject)
TGUIObject.IsSelected = new.instancemethod(Appc.TGUIObject_IsSelected, None, TGUIObject)
TGUIObject.SetSelected = new.instancemethod(Appc.TGUIObject_SetSelected, None, TGUIObject)
TGUIObject.SetNotSelected = new.instancemethod(Appc.TGUIObject_SetNotSelected, None, TGUIObject)
TGUIObject.ToggleSelected = new.instancemethod(Appc.TGUIObject_ToggleSelected, None, TGUIObject)
TGUIObject.SetSelectedFlag = new.instancemethod(Appc.TGUIObject_SetSelectedFlag, None, TGUIObject)
TGUIObject.IsHighlighted = new.instancemethod(Appc.TGUIObject_IsHighlighted, None, TGUIObject)
TGUIObject.SetHighlighted = new.instancemethod(Appc.TGUIObject_SetHighlighted, None, TGUIObject)
TGUIObject.SetNotHighlighted = new.instancemethod(Appc.TGUIObject_SetNotHighlighted, None, TGUIObject)
TGUIObject.ToggleHighlighted = new.instancemethod(Appc.TGUIObject_ToggleHighlighted, None, TGUIObject)
TGUIObject.SetHighlightedFlag = new.instancemethod(Appc.TGUIObject_SetHighlightedFlag, None, TGUIObject)
TGUIObject.IsCompletelyVisible = new.instancemethod(Appc.TGUIObject_IsCompletelyVisible, None, TGUIObject)
TGUIObject.IsVisible = new.instancemethod(Appc.TGUIObject_IsVisible, None, TGUIObject)
TGUIObject.SetVisible = new.instancemethod(Appc.TGUIObject_SetVisible, None, TGUIObject)
TGUIObject.SetNotVisible = new.instancemethod(Appc.TGUIObject_SetNotVisible, None, TGUIObject)
TGUIObject.ToggleVisible = new.instancemethod(Appc.TGUIObject_ToggleVisible, None, TGUIObject)
TGUIObject.SetVisibleFlag = new.instancemethod(Appc.TGUIObject_SetVisibleFlag, None, TGUIObject)
TGUIObject.IsExclusive = new.instancemethod(Appc.TGUIObject_IsExclusive, None, TGUIObject)
TGUIObject.SetExclusive = new.instancemethod(Appc.TGUIObject_SetExclusive, None, TGUIObject)
TGUIObject.SetNotExclusive = new.instancemethod(Appc.TGUIObject_SetNotExclusive, None, TGUIObject)
TGUIObject.ToggleExclusive = new.instancemethod(Appc.TGUIObject_ToggleExclusive, None, TGUIObject)
TGUIObject.SetExclusiveFlag = new.instancemethod(Appc.TGUIObject_SetExclusiveFlag, None, TGUIObject)
TGUIObject.IsSkipParent = new.instancemethod(Appc.TGUIObject_IsSkipParent, None, TGUIObject)
TGUIObject.SetSkipParent = new.instancemethod(Appc.TGUIObject_SetSkipParent, None, TGUIObject)
TGUIObject.SetNoSkipParent = new.instancemethod(Appc.TGUIObject_SetNoSkipParent, None, TGUIObject)
TGUIObject.ToggleSkipParent = new.instancemethod(Appc.TGUIObject_ToggleSkipParent, None, TGUIObject)
TGUIObject.SetSkipParentFlag = new.instancemethod(Appc.TGUIObject_SetSkipParentFlag, None, TGUIObject)
TGUIObject.IsAlwaysHandleEvents = new.instancemethod(Appc.TGUIObject_IsAlwaysHandleEvents, None, TGUIObject)
TGUIObject.SetAlwaysHandleEvents = new.instancemethod(Appc.TGUIObject_SetAlwaysHandleEvents, None, TGUIObject)
TGUIObject.SetNotAlwaysHandleEvents = new.instancemethod(Appc.TGUIObject_SetNotAlwaysHandleEvents, None, TGUIObject)
TGUIObject.ToggleAlwaysHandleEvents = new.instancemethod(Appc.TGUIObject_ToggleAlwaysHandleEvents, None, TGUIObject)
TGUIObject.SetAlwaysHandleEventsFlag = new.instancemethod(Appc.TGUIObject_SetAlwaysHandleEventsFlag, None, TGUIObject)
TGUIObject.IsUseParentBatch = new.instancemethod(Appc.TGUIObject_IsUseParentBatch, None, TGUIObject)
TGUIObject.SetUseParentBatch = new.instancemethod(Appc.TGUIObject_SetUseParentBatch, None, TGUIObject)
TGUIObject.SetNotUseParentBatch = new.instancemethod(Appc.TGUIObject_SetNotUseParentBatch, None, TGUIObject)
TGUIObject.ToggleUseParentBatch = new.instancemethod(Appc.TGUIObject_ToggleUseParentBatch, None, TGUIObject)
TGUIObject.SetUseParentBatchFlag = new.instancemethod(Appc.TGUIObject_SetUseParentBatchFlag, None, TGUIObject)
TGUIObject.IsBatchChildPolys = new.instancemethod(Appc.TGUIObject_IsBatchChildPolys, None, TGUIObject)
TGUIObject.SetBatchChildPolys = new.instancemethod(Appc.TGUIObject_SetBatchChildPolys, None, TGUIObject)
TGUIObject.SetNotBatchChildPolys = new.instancemethod(Appc.TGUIObject_SetNotBatchChildPolys, None, TGUIObject)
TGUIObject.ToggleBatchChildPolys = new.instancemethod(Appc.TGUIObject_ToggleBatchChildPolys, None, TGUIObject)
TGUIObject.SetBatchChildPolysFlag = new.instancemethod(Appc.TGUIObject_SetBatchChildPolysFlag, None, TGUIObject)
TGUIObject.IsNoFocus = new.instancemethod(Appc.TGUIObject_IsNoFocus, None, TGUIObject)
TGUIObject.SetNoFocus = new.instancemethod(Appc.TGUIObject_SetNoFocus, None, TGUIObject)
TGUIObject.SetNotNoFocus = new.instancemethod(Appc.TGUIObject_SetNotNoFocus, None, TGUIObject)
TGUIObject.ToggleNoFocus = new.instancemethod(Appc.TGUIObject_ToggleNoFocus, None, TGUIObject)
TGUIObject.SetNoFocusFlag = new.instancemethod(Appc.TGUIObject_SetNoFocusFlag, None, TGUIObject)
TGUIObject.Print = new.instancemethod(Appc.TGUIObject_Print, None, TGUIObject)
TGUIObject.Layout = new.instancemethod(Appc.TGUIObject_Layout, None, TGUIObject)

class TGPane(TGUIObject):
    def __init__(self,*args):
        self.this = apply(Appc.new_TGPane,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGPane(self)
    def GetFirstChild(*args):
        val = apply(Appc.TGPane_GetFirstChild,args)
        if val: val = TGUIObjectPtr(val) 
        return val
    def GetLastChild(*args):
        val = apply(Appc.TGPane_GetLastChild,args)
        if val: val = TGUIObjectPtr(val) 
        return val
    def GetNthChild(*args):
        val = apply(Appc.TGPane_GetNthChild,args)
        if val: val = TGUIObjectPtr(val) 
        return val
    def GetNextChild(*args):
        val = apply(Appc.TGPane_GetNextChild,args)
        if val: val = TGUIObjectPtr(val) 
        return val
    def GetPrevChild(*args):
        val = apply(Appc.TGPane_GetPrevChild,args)
        if val: val = TGUIObjectPtr(val) 
        return val
    def GetFocus(*args):
        val = apply(Appc.TGPane_GetFocus,args)
        if val: val = TGUIObjectPtr(val) 
        return val
    def GetFocusLeaf(*args):
        val = apply(Appc.TGPane_GetFocusLeaf,args)
        if val: val = TGUIObjectPtr(val) 
        return val
    def GetTrueNthChild(*args):
        val = apply(Appc.TGPane_GetTrueNthChild,args)
        if val: val = TGUIObjectPtr(val) 
        return val
    def __repr__(self):
        return "<C TGPane instance at %s>" % (self.this,)
class TGPanePtr(TGPane):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGPane


TGPane.AddChild = new.instancemethod(Appc.TGPane_AddChild, None, TGPane)
TGPane.PrependChild = new.instancemethod(Appc.TGPane_PrependChild, None, TGPane)
TGPane.InsertChild = new.instancemethod(Appc.TGPane_InsertChild, None, TGPane)
TGPane.RemoveChild = new.instancemethod(Appc.TGPane_RemoveChild, None, TGPane)
TGPane.DeleteChild = new.instancemethod(Appc.TGPane_DeleteChild, None, TGPane)
TGPane.GetNumChildren = new.instancemethod(Appc.TGPane_GetNumChildren, None, TGPane)
TGPane.FindPos = new.instancemethod(Appc.TGPane_FindPos, None, TGPane)
TGPane.KillChildren = new.instancemethod(Appc.TGPane_KillChildren, None, TGPane)
TGPane.MoveToFront = new.instancemethod(Appc.TGPane_MoveToFront, None, TGPane)
TGPane.MoveTowardsFront = new.instancemethod(Appc.TGPane_MoveTowardsFront, None, TGPane)
TGPane.MoveToBack = new.instancemethod(Appc.TGPane_MoveToBack, None, TGPane)
TGPane.MoveTowardsBack = new.instancemethod(Appc.TGPane_MoveTowardsBack, None, TGPane)
TGPane.SetFocus = new.instancemethod(Appc.TGPane_SetFocus, None, TGPane)
TGPane.MoveFocus = new.instancemethod(Appc.TGPane_MoveFocus, None, TGPane)
TGPane.FocusHeight = new.instancemethod(Appc.TGPane_FocusHeight, None, TGPane)
TGPane.GetTrueNumChildren = new.instancemethod(Appc.TGPane_GetTrueNumChildren, None, TGPane)

class TGIcon(TGUIObject):
    def __init__(self,*args):
        self.this = apply(Appc.new_TGIcon,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGIcon(self)
    def GetIconPoly(*args):
        val = apply(Appc.TGIcon_GetIconPoly,args)
        if val: val = TGIconPolyPtr(val) 
        return val
    def __repr__(self):
        return "<C TGIcon instance at %s>" % (self.this,)
class TGIconPtr(TGIcon):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGIcon


TGIcon.SetIconNum = new.instancemethod(Appc.TGIcon_SetIconNum, None, TGIcon)
TGIcon.GetIconNum = new.instancemethod(Appc.TGIcon_GetIconNum, None, TGIcon)
TGIcon.SetColor = new.instancemethod(Appc.TGIcon_SetColor, None, TGIcon)
TGIcon.GetColor = new.instancemethod(Appc.TGIcon_GetColor, None, TGIcon)
TGIcon.SizeToArtwork = new.instancemethod(Appc.TGIcon_SizeToArtwork, None, TGIcon)
TGIcon.SetClamp = new.instancemethod(Appc.TGIcon_SetClamp, None, TGIcon)
TGIcon.GetClamp = new.instancemethod(Appc.TGIcon_GetClamp, None, TGIcon)
TGIcon.GetIconGroupName = new.instancemethod(Appc.TGIcon_GetIconGroupName, None, TGIcon)
TGIcon.SetIconGroupName = new.instancemethod(Appc.TGIcon_SetIconGroupName, None, TGIcon)

class TGFrame(TGUIObject):
    FRAME_STRETCH_TO_FIT = Appc.TGFrame_FRAME_STRETCH_TO_FIT
    FRAME_WRAP_TEXTURES_TO_FIT = Appc.TGFrame_FRAME_WRAP_TEXTURES_TO_FIT
    FRAME_TILE_POLYS_TO_FIT = Appc.TGFrame_FRAME_TILE_POLYS_TO_FIT
    STRETCH_NONE = Appc.TGFrame_STRETCH_NONE
    NO_STRETCH_TB = Appc.TGFrame_NO_STRETCH_TB
    NO_STRETCH_LR = Appc.TGFrame_NO_STRETCH_LR
    def __init__(self,*args):
        self.this = apply(Appc.new_TGFrame,args)
        self.thisown = 1

    def GetInnerRect(*args):
        val = apply(Appc.TGFrame_GetInnerRect,args)
        if val: val = TGRectPtr(val) ; val.thisown = 1
        return val
    def GetNiColor(*args):
        val = apply(Appc.TGFrame_GetNiColor,args)
        if val: val = NiColorAPtr(val) ; val.thisown = 1
        return val
    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGUIObject(self)
    def __repr__(self):
        return "<C TGFrame instance at %s>" % (self.this,)
class TGFramePtr(TGFrame):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGFrame


TGFrame.SetIconGroupName = new.instancemethod(Appc.TGFrame_SetIconGroupName, None, TGFrame)
TGFrame.SetScale = new.instancemethod(Appc.TGFrame_SetScale, None, TGFrame)
TGFrame.SetStretchType = new.instancemethod(Appc.TGFrame_SetStretchType, None, TGFrame)
TGFrame.SetFirstIconNum = new.instancemethod(Appc.TGFrame_SetFirstIconNum, None, TGFrame)
TGFrame.SetNiColor = new.instancemethod(Appc.TGFrame_SetNiColor, None, TGFrame)
TGFrame.SetEdgeStretch = new.instancemethod(Appc.TGFrame_SetEdgeStretch, None, TGFrame)
TGFrame.GetEdgeStretch = new.instancemethod(Appc.TGFrame_GetEdgeStretch, None, TGFrame)

class TGButtonBase(TGPane):
    def __init__(self,*args):
        self.this = apply(Appc.new_TGButtonBase,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGButtonBase(self)
    def GetActivationEvent(*args):
        val = apply(Appc.TGButtonBase_GetActivationEvent,args)
        if val: val = TGEventPtr(val) 
        return val
    def __repr__(self):
        return "<C TGButtonBase instance at %s>" % (self.this,)
class TGButtonBasePtr(TGButtonBase):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGButtonBase


TGButtonBase.ClearActivationEvent = new.instancemethod(Appc.TGButtonBase_ClearActivationEvent, None, TGButtonBase)
TGButtonBase.SetActivationEvent = new.instancemethod(Appc.TGButtonBase_SetActivationEvent, None, TGButtonBase)
TGButtonBase.SendActivationEvent = new.instancemethod(Appc.TGButtonBase_SendActivationEvent, None, TGButtonBase)
TGButtonBase.SetMouseDownEvent = new.instancemethod(Appc.TGButtonBase_SetMouseDownEvent, None, TGButtonBase)
TGButtonBase.SendMouseDownEvent = new.instancemethod(Appc.TGButtonBase_SendMouseDownEvent, None, TGButtonBase)
TGButtonBase.SetMouseUpEvent = new.instancemethod(Appc.TGButtonBase_SetMouseUpEvent, None, TGButtonBase)
TGButtonBase.SendMouseUpEvent = new.instancemethod(Appc.TGButtonBase_SendMouseUpEvent, None, TGButtonBase)
TGButtonBase.ClearMouseDown = new.instancemethod(Appc.TGButtonBase_ClearMouseDown, None, TGButtonBase)

class TGButton(TGButtonBase):
    def __init__(self,*args):
        self.this = apply(Appc.new_TGButton,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGButton(self)
    def __repr__(self):
        return "<C TGButton instance at %s>" % (self.this,)
class TGButtonPtr(TGButton):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGButton


TGButton.SetIcons = new.instancemethod(Appc.TGButton_SetIcons, None, TGButton)
TGButton.SetIconColor = new.instancemethod(Appc.TGButton_SetIconColor, None, TGButton)
TGButton.GetFirstIconNum = new.instancemethod(Appc.TGButton_GetFirstIconNum, None, TGButton)

class TGTextButton(TGButtonBase):
    FRAME_STRETCH_TO_FIT = Appc.TGTextButton_FRAME_STRETCH_TO_FIT
    FRAME_WRAP_TEXTURES_TO_FIT = Appc.TGTextButton_FRAME_WRAP_TEXTURES_TO_FIT
    FRAME_TILE_POLYS_TO_FIT = Appc.TGTextButton_FRAME_TILE_POLYS_TO_FIT
    ALIGN_LEFT = Appc.TGTextButton_ALIGN_LEFT
    ALIGN_CENTER = Appc.TGTextButton_ALIGN_CENTER
    ALIGN_RIGHT = Appc.TGTextButton_ALIGN_RIGHT
    ALIGN_TOP = Appc.TGTextButton_ALIGN_TOP
    ALIGN_MIDDLE = Appc.TGTextButton_ALIGN_MIDDLE
    ALIGN_BOTTOM = Appc.TGTextButton_ALIGN_BOTTOM
    def __init__(self,*args):
        self.this = apply(Appc.new_TGTextButton,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGTextButton(self)
    def __repr__(self):
        return "<C TGTextButton instance at %s>" % (self.this,)
class TGTextButtonPtr(TGTextButton):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGTextButton


TGTextButton.SetText = new.instancemethod(Appc.TGTextButton_SetText, None, TGTextButton)
TGTextButton.SetTextW = new.instancemethod(Appc.TGTextButton_SetTextW, None, TGTextButton)
TGTextButton.SetIcons = new.instancemethod(Appc.TGTextButton_SetIcons, None, TGTextButton)
TGTextButton.SetTextWrapWidth = new.instancemethod(Appc.TGTextButton_SetTextWrapWidth, None, TGTextButton)
TGTextButton.AlignTextHorizontal = new.instancemethod(Appc.TGTextButton_AlignTextHorizontal, None, TGTextButton)
TGTextButton.AlignTextVertical = new.instancemethod(Appc.TGTextButton_AlignTextVertical, None, TGTextButton)
TGTextButton.GetInnerRect = new.instancemethod(Appc.TGTextButton_GetInnerRect, None, TGTextButton)

class TGRootPane(TGPane):
    MCPP_VERTICAL_TOP = Appc.TGRootPane_MCPP_VERTICAL_TOP
    MCPP_VERTICAL_CENTER = Appc.TGRootPane_MCPP_VERTICAL_CENTER
    MCPP_VERTICAL_BOTTOM = Appc.TGRootPane_MCPP_VERTICAL_BOTTOM
    MCPP_VERTICAL_MASK = Appc.TGRootPane_MCPP_VERTICAL_MASK
    MCPP_HORIZONTAL_LEFT = Appc.TGRootPane_MCPP_HORIZONTAL_LEFT
    MCPP_HORIZONTAL_CENTER = Appc.TGRootPane_MCPP_HORIZONTAL_CENTER
    MCPP_HORIZONTAL_RIGHT = Appc.TGRootPane_MCPP_HORIZONTAL_RIGHT
    MCPP_HORIZONTAL_MASK = Appc.TGRootPane_MCPP_HORIZONTAL_MASK
    def __init__(self,this):
        self.this = this

    def GetMouseCursor(*args):
        val = apply(Appc.TGRootPane_GetMouseCursor,args)
        if val: val = TGIconPtr(val) 
        return val
    def GetMouseGrabOwner(*args):
        val = apply(Appc.TGRootPane_GetMouseGrabOwner,args)
        if val: val = TGUIObjectPtr(val) 
        return val
    def GetTrueFocus(*args):
        val = apply(Appc.TGRootPane_GetTrueFocus,args)
        if val: val = TGUIObjectPtr(val) 
        return val
    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGPane(self)
    def __repr__(self):
        return "<C TGRootPane instance at %s>" % (self.this,)
class TGRootPanePtr(TGRootPane):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGRootPane


TGRootPane.SetMouseCursor = new.instancemethod(Appc.TGRootPane_SetMouseCursor, None, TGRootPane)
TGRootPane.SetCursorVisible = new.instancemethod(Appc.TGRootPane_SetCursorVisible, None, TGRootPane)
TGRootPane.PushCursor = new.instancemethod(Appc.TGRootPane_PushCursor, None, TGRootPane)
TGRootPane.PopCursor = new.instancemethod(Appc.TGRootPane_PopCursor, None, TGRootPane)
TGRootPane.GrabMouse = new.instancemethod(Appc.TGRootPane_GrabMouse, None, TGRootPane)
TGRootPane.ReleaseMouse = new.instancemethod(Appc.TGRootPane_ReleaseMouse, None, TGRootPane)
TGRootPane.UpdateTrueFocus = new.instancemethod(Appc.TGRootPane_UpdateTrueFocus, None, TGRootPane)
TGRootPane.ShowFPS = new.instancemethod(Appc.TGRootPane_ShowFPS, None, TGRootPane)
TGRootPane.HideFPS = new.instancemethod(Appc.TGRootPane_HideFPS, None, TGRootPane)
TGRootPane.Layout = new.instancemethod(Appc.TGRootPane_Layout, None, TGRootPane)

class TGParagraph(TGPane):
    TGPF_READ_ONLY = Appc.TGParagraph_TGPF_READ_ONLY
    TGPF_INSERT_MODE = Appc.TGParagraph_TGPF_INSERT_MODE
    TGPF_WORD_WRAP = Appc.TGParagraph_TGPF_WORD_WRAP
    TGPF_RECALC_BOUNDS = Appc.TGParagraph_TGPF_RECALC_BOUNDS
    TGPF_FLAGS_MASK = Appc.TGParagraph_TGPF_FLAGS_MASK
    def __init__(self,*args):
        self.this = apply(Appc.new_TGParagraph,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGParagraph(self)
    def GetFontGroup(*args):
        val = apply(Appc.TGParagraph_GetFontGroup,args)
        if val: val = TGFontGroupPtr(val) 
        return val
    def __repr__(self):
        return "<C TGParagraph instance at %s>" % (self.this,)
class TGParagraphPtr(TGParagraph):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGParagraph


TGParagraph.SetFontGroup = new.instancemethod(Appc.TGParagraph_SetFontGroup, None, TGParagraph)
TGParagraph.SetColor = new.instancemethod(Appc.TGParagraph_SetColor, None, TGParagraph)
TGParagraph.SetReadOnly = new.instancemethod(Appc.TGParagraph_SetReadOnly, None, TGParagraph)
TGParagraph.IsReadOnly = new.instancemethod(Appc.TGParagraph_IsReadOnly, None, TGParagraph)
TGParagraph.GetString = new.instancemethod(Appc.TGParagraph_GetString, None, TGParagraph)
TGParagraph.GetWrapWidth = new.instancemethod(Appc.TGParagraph_GetWrapWidth, None, TGParagraph)
TGParagraph.SetWrapWidth = new.instancemethod(Appc.TGParagraph_SetWrapWidth, None, TGParagraph)
TGParagraph.SetMaxChars = new.instancemethod(Appc.TGParagraph_SetMaxChars, None, TGParagraph)
TGParagraph.GetMaxChars = new.instancemethod(Appc.TGParagraph_GetMaxChars, None, TGParagraph)
TGParagraph.InsertChild = new.instancemethod(Appc.TGParagraph_InsertChild, None, TGParagraph)
TGParagraph.InsertChar = new.instancemethod(Appc.TGParagraph_InsertChar, None, TGParagraph)
TGParagraph.RecalcBounds = new.instancemethod(Appc.TGParagraph_RecalcBounds, None, TGParagraph)
TGParagraph.AppendChar = new.instancemethod(Appc.TGParagraph_AppendChar, None, TGParagraph)
TGParagraph.InsertString = new.instancemethod(Appc.TGParagraph_InsertString, None, TGParagraph)
TGParagraph.AppendString = new.instancemethod(Appc.TGParagraph_AppendString, None, TGParagraph)
TGParagraph.InsertStringW = new.instancemethod(Appc.TGParagraph_InsertStringW, None, TGParagraph)
TGParagraph.AppendStringW = new.instancemethod(Appc.TGParagraph_AppendStringW, None, TGParagraph)
TGParagraph.SetString = new.instancemethod(Appc.TGParagraph_SetString, None, TGParagraph)
TGParagraph.SetStringW = new.instancemethod(Appc.TGParagraph_SetStringW, None, TGParagraph)
TGParagraph.SetIgnoreString = new.instancemethod(Appc.TGParagraph_SetIgnoreString, None, TGParagraph)
TGParagraph.SetIgnoreStringW = new.instancemethod(Appc.TGParagraph_SetIgnoreStringW, None, TGParagraph)
TGParagraph.SetCursorPosition = new.instancemethod(Appc.TGParagraph_SetCursorPosition, None, TGParagraph)
TGParagraph.MoveCursorToStart = new.instancemethod(Appc.TGParagraph_MoveCursorToStart, None, TGParagraph)
TGParagraph.MoveCursorToEnd = new.instancemethod(Appc.TGParagraph_MoveCursorToEnd, None, TGParagraph)

class TGIconGroup:
    ROTATE_0 = Appc.TGIconGroup_ROTATE_0
    ROTATE_90 = Appc.TGIconGroup_ROTATE_90
    ROTATE_180 = Appc.TGIconGroup_ROTATE_180
    ROTATE_270 = Appc.TGIconGroup_ROTATE_270
    MIRROR_NONE = Appc.TGIconGroup_MIRROR_NONE
    MIRROR_HORIZONTAL = Appc.TGIconGroup_MIRROR_HORIZONTAL
    MIRROR_VERTICAL = Appc.TGIconGroup_MIRROR_VERTICAL
    def __init__(self,*args):
        self.this = apply(Appc.new_TGIconGroup,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGIconGroup(self)
    def __repr__(self):
        return "<C TGIconGroup instance at %s>" % (self.this,)
class TGIconGroupPtr(TGIconGroup):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGIconGroup


TGIconGroup.Reset = new.instancemethod(Appc.TGIconGroup_Reset, None, TGIconGroup)
TGIconGroup.SetName = new.instancemethod(Appc.TGIconGroup_SetName, None, TGIconGroup)
TGIconGroup.GetName = new.instancemethod(Appc.TGIconGroup_GetName, None, TGIconGroup)
TGIconGroup.LoadIconTexture = new.instancemethod(Appc.TGIconGroup_LoadIconTexture, None, TGIconGroup)
TGIconGroup.SetIconLocation = new.instancemethod(Appc.TGIconGroup_SetIconLocation, None, TGIconGroup)
TGIconGroup.GetIconPixelWidth = new.instancemethod(Appc.TGIconGroup_GetIconPixelWidth, None, TGIconGroup)
TGIconGroup.GetIconPixelHeight = new.instancemethod(Appc.TGIconGroup_GetIconPixelHeight, None, TGIconGroup)
TGIconGroup.GetIconScreenWidth = new.instancemethod(Appc.TGIconGroup_GetIconScreenWidth, None, TGIconGroup)
TGIconGroup.GetIconScreenHeight = new.instancemethod(Appc.TGIconGroup_GetIconScreenHeight, None, TGIconGroup)
TGIconGroup.GetPyWrapper = new.instancemethod(Appc.TGIconGroup_GetPyWrapper, None, TGIconGroup)
TGIconGroup.IsNumValid = new.instancemethod(Appc.TGIconGroup_IsNumValid, None, TGIconGroup)
TGIconGroup.GoToFirstPos = new.instancemethod(Appc.TGIconGroup_GoToFirstPos, None, TGIconGroup)
TGIconGroup.GetCount = new.instancemethod(Appc.TGIconGroup_GetCount, None, TGIconGroup)
TGIconGroup.GetNext = new.instancemethod(Appc.TGIconGroup_GetNext, None, TGIconGroup)

class TGIconManager:
    CLAMP_NONE = Appc.TGIconManager_CLAMP_NONE
    CLAMP_T = Appc.TGIconManager_CLAMP_T
    CLAMP_S = Appc.TGIconManager_CLAMP_S
    CLAMP_S_AND_T = Appc.TGIconManager_CLAMP_S_AND_T
    def __init__(self,this):
        self.this = this

    def CreateIconGroup(*args):
        val = apply(Appc.TGIconManager_CreateIconGroup,args)
        if val: val = TGIconGroupPtr(val) 
        return val
    def GetIconGroup(*args):
        val = apply(Appc.TGIconManager_GetIconGroup,args)
        if val: val = TGIconGroupPtr(val) 
        return val
    def __repr__(self):
        return "<C TGIconManager instance at %s>" % (self.this,)
class TGIconManagerPtr(TGIconManager):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGIconManager


TGIconManager.RegisterIconGroup = new.instancemethod(Appc.TGIconManager_RegisterIconGroup, None, TGIconManager)
TGIconManager.AddIconGroup = new.instancemethod(Appc.TGIconManager_AddIconGroup, None, TGIconManager)
TGIconManager.DeleteIconGroup = new.instancemethod(Appc.TGIconManager_DeleteIconGroup, None, TGIconManager)
TGIconManager.GetScreenWidth = new.instancemethod(Appc.TGIconManager_GetScreenWidth, None, TGIconManager)
TGIconManager.GetScreenHeight = new.instancemethod(Appc.TGIconManager_GetScreenHeight, None, TGIconManager)
TGIconManager.SetScreenWidth = new.instancemethod(Appc.TGIconManager_SetScreenWidth, None, TGIconManager)
TGIconManager.SetScreenHeight = new.instancemethod(Appc.TGIconManager_SetScreenHeight, None, TGIconManager)
TGIconManager.Purge = new.instancemethod(Appc.TGIconManager_Purge, None, TGIconManager)
TGIconManager.SetScale = new.instancemethod(Appc.TGIconManager_SetScale, None, TGIconManager)
TGIconManager.GetScale = new.instancemethod(Appc.TGIconManager_GetScale, None, TGIconManager)
TGIconManager.SetPixelCenterAdj = new.instancemethod(Appc.TGIconManager_SetPixelCenterAdj, None, TGIconManager)
TGIconManager.GetPixelCenterAdj = new.instancemethod(Appc.TGIconManager_GetPixelCenterAdj, None, TGIconManager)
TGIconManager.SetDisplayInfo = new.instancemethod(Appc.TGIconManager_SetDisplayInfo, None, TGIconManager)
TGIconManager.GetCamera = new.instancemethod(Appc.TGIconManager_GetCamera, None, TGIconManager)
TGIconManager.SetCamera = new.instancemethod(Appc.TGIconManager_SetCamera, None, TGIconManager)
TGIconManager.Draw = new.instancemethod(Appc.TGIconManager_Draw, None, TGIconManager)

class TGFontGroup(TGIconGroup):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGIconGroup(self)
    def __repr__(self):
        return "<C TGFontGroup instance at %s>" % (self.this,)
class TGFontGroupPtr(TGFontGroup):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGFontGroup


TGFontGroup.GetFontName = new.instancemethod(Appc.TGFontGroup_GetFontName, None, TGFontGroup)
TGFontGroup.GetFontSize = new.instancemethod(Appc.TGFontGroup_GetFontSize, None, TGFontGroup)
TGFontGroup.MapChar = new.instancemethod(Appc.TGFontGroup_MapChar, None, TGFontGroup)
TGFontGroup.SetSpaceWidth = new.instancemethod(Appc.TGFontGroup_SetSpaceWidth, None, TGFontGroup)
TGFontGroup.GetPixelSpaceWidth = new.instancemethod(Appc.TGFontGroup_GetPixelSpaceWidth, None, TGFontGroup)
TGFontGroup.GetScreenSpaceWidth = new.instancemethod(Appc.TGFontGroup_GetScreenSpaceWidth, None, TGFontGroup)
TGFontGroup.SetTabWidth = new.instancemethod(Appc.TGFontGroup_SetTabWidth, None, TGFontGroup)
TGFontGroup.GetPixelTabWidth = new.instancemethod(Appc.TGFontGroup_GetPixelTabWidth, None, TGFontGroup)
TGFontGroup.GetScreenTabWidth = new.instancemethod(Appc.TGFontGroup_GetScreenTabWidth, None, TGFontGroup)
TGFontGroup.SetHorizontalSpacing = new.instancemethod(Appc.TGFontGroup_SetHorizontalSpacing, None, TGFontGroup)
TGFontGroup.GetPixelHorizontalSpacing = new.instancemethod(Appc.TGFontGroup_GetPixelHorizontalSpacing, None, TGFontGroup)
TGFontGroup.GetScreenHorizontalSpacing = new.instancemethod(Appc.TGFontGroup_GetScreenHorizontalSpacing, None, TGFontGroup)
TGFontGroup.SetVerticalSpacing = new.instancemethod(Appc.TGFontGroup_SetVerticalSpacing, None, TGFontGroup)
TGFontGroup.GetPixelVerticalSpacing = new.instancemethod(Appc.TGFontGroup_GetPixelVerticalSpacing, None, TGFontGroup)
TGFontGroup.GetScreenVerticalSpacing = new.instancemethod(Appc.TGFontGroup_GetScreenVerticalSpacing, None, TGFontGroup)
TGFontGroup.GetPixelMaxHeight = new.instancemethod(Appc.TGFontGroup_GetPixelMaxHeight, None, TGFontGroup)
TGFontGroup.GetScreenMaxHeight = new.instancemethod(Appc.TGFontGroup_GetScreenMaxHeight, None, TGFontGroup)

class TGFontManager:
    def __init__(self,*args):
        self.this = apply(Appc.new_TGFontManager,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGFontManager(self)
    def CreateFontGroup(*args):
        val = apply(Appc.TGFontManager_CreateFontGroup,args)
        if val: val = TGFontGroupPtr(val) 
        return val
    def GetDefaultFont(*args):
        val = apply(Appc.TGFontManager_GetDefaultFont,args)
        if val: val = TGFontGroupPtr(val) 
        return val
    def GetFontGroup(*args):
        val = apply(Appc.TGFontManager_GetFontGroup,args)
        if val: val = TGFontGroupPtr(val) 
        return val
    def __repr__(self):
        return "<C TGFontManager instance at %s>" % (self.this,)
class TGFontManagerPtr(TGFontManager):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGFontManager


TGFontManager.RegisterFont = new.instancemethod(Appc.TGFontManager_RegisterFont, None, TGFontManager)
TGFontManager.AddFontGroup = new.instancemethod(Appc.TGFontManager_AddFontGroup, None, TGFontManager)
TGFontManager.SetDefaultFont = new.instancemethod(Appc.TGFontManager_SetDefaultFont, None, TGFontManager)
TGFontManager.Purge = new.instancemethod(Appc.TGFontManager_Purge, None, TGFontManager)
TGFontManager.RemoveGroup = new.instancemethod(Appc.TGFontManager_RemoveGroup, None, TGFontManager)

class TGWindow(TGPane):
    def __init__(self,*args):
        self.this = apply(Appc.new_TGWindow,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGWindow(self)
    def GetSubPane(*args):
        val = apply(Appc.TGWindow_GetSubPane,args)
        if val: val = TGPanePtr(val) 
        return val
    def __repr__(self):
        return "<C TGWindow instance at %s>" % (self.this,)
class TGWindowPtr(TGWindow):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGWindow


TGWindow.SetIndent = new.instancemethod(Appc.TGWindow_SetIndent, None, TGWindow)

class TGFrameWindow(TGWindow):
    def __init__(self,*args):
        self.this = apply(Appc.new_TGFrameWindow,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGFrameWindow(self)
    def GetFramePane(*args):
        val = apply(Appc.TGFrameWindow_GetFramePane,args)
        if val: val = TGFramePtr(val) 
        return val
    def __repr__(self):
        return "<C TGFrameWindow instance at %s>" % (self.this,)
class TGFrameWindowPtr(TGFrameWindow):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGFrameWindow



class TGDialogWindow(TGFrameWindow):
    DFT_OK = Appc.TGDialogWindow_DFT_OK
    DFT_CANCEL = Appc.TGDialogWindow_DFT_CANCEL
    DFT_YES = Appc.TGDialogWindow_DFT_YES
    DFT_NO = Appc.TGDialogWindow_DFT_NO
    DFT_ABORT = Appc.TGDialogWindow_DFT_ABORT
    DFT_RETRY = Appc.TGDialogWindow_DFT_RETRY
    DFT_CONTINUE = Appc.TGDialogWindow_DFT_CONTINUE
    DFT_IGNORE = Appc.TGDialogWindow_DFT_IGNORE
    DFT_HELP = Appc.TGDialogWindow_DFT_HELP
    DFT_OKCANCEL = Appc.TGDialogWindow_DFT_OKCANCEL
    DFT_YESNO = Appc.TGDialogWindow_DFT_YESNO
    DFT_YESNOCANCEL = Appc.TGDialogWindow_DFT_YESNOCANCEL
    DFT_ABORTRETRYCONTINUE = Appc.TGDialogWindow_DFT_ABORTRETRYCONTINUE
    DFT_OKCANCELHELP = Appc.TGDialogWindow_DFT_OKCANCELHELP
    DFT_YESNOHELP = Appc.TGDialogWindow_DFT_YESNOHELP
    DFT_DEFAULTBUTTON1 = Appc.TGDialogWindow_DFT_DEFAULTBUTTON1
    DFT_DEFAULTBUTTON2 = Appc.TGDialogWindow_DFT_DEFAULTBUTTON2
    DFT_DEFAULTBUTTON3 = Appc.TGDialogWindow_DFT_DEFAULTBUTTON3
    DFT_DEFAULTBUTTON4 = Appc.TGDialogWindow_DFT_DEFAULTBUTTON4
    DFT_HIDETITLE = Appc.TGDialogWindow_DFT_HIDETITLE
    DFT_DRAGGABLE = Appc.TGDialogWindow_DFT_DRAGGABLE
    DFT_BUTTONMASK = Appc.TGDialogWindow_DFT_BUTTONMASK
    DFT_FEATUREMASK = Appc.TGDialogWindow_DFT_FEATUREMASK
    def __init__(self,*args):
        self.this = apply(Appc.new_TGDialogWindow,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGDialogWindow(self)
    def __repr__(self):
        return "<C TGDialogWindow instance at %s>" % (self.this,)
class TGDialogWindowPtr(TGDialogWindow):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGDialogWindow


TGDialogWindow.SetEventType = new.instancemethod(Appc.TGDialogWindow_SetEventType, None, TGDialogWindow)
TGDialogWindow.GetEventType = new.instancemethod(Appc.TGDialogWindow_GetEventType, None, TGDialogWindow)

class TGUITheme:
    def __init__(self,*args):
        self.this = apply(Appc.new_TGUITheme,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGUITheme(self)
    def __repr__(self):
        return "<C TGUITheme instance at %s>" % (self.this,)
class TGUIThemePtr(TGUITheme):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGUITheme


TGUITheme.SetThemeName = new.instancemethod(Appc.TGUITheme_SetThemeName, None, TGUITheme)
TGUITheme.Copy = new.instancemethod(Appc.TGUITheme_Copy, None, TGUITheme)
TGUITheme.SetWindowFrameName = new.instancemethod(Appc.TGUITheme_SetWindowFrameName, None, TGUITheme)
TGUITheme.SetButtonFrameName = new.instancemethod(Appc.TGUITheme_SetButtonFrameName, None, TGUITheme)
TGUITheme.SetDialogFrameName = new.instancemethod(Appc.TGUITheme_SetDialogFrameName, None, TGUITheme)
TGUITheme.SetWindowFrameScale = new.instancemethod(Appc.TGUITheme_SetWindowFrameScale, None, TGUITheme)
TGUITheme.SetButtonFrameScale = new.instancemethod(Appc.TGUITheme_SetButtonFrameScale, None, TGUITheme)
TGUITheme.SetDialogFrameScale = new.instancemethod(Appc.TGUITheme_SetDialogFrameScale, None, TGUITheme)
TGUITheme.GetWindowFrameName = new.instancemethod(Appc.TGUITheme_GetWindowFrameName, None, TGUITheme)
TGUITheme.GetWindowFrameScale = new.instancemethod(Appc.TGUITheme_GetWindowFrameScale, None, TGUITheme)
TGUITheme.GetButtonFrameName = new.instancemethod(Appc.TGUITheme_GetButtonFrameName, None, TGUITheme)
TGUITheme.GetButtonFrameScale = new.instancemethod(Appc.TGUITheme_GetButtonFrameScale, None, TGUITheme)
TGUITheme.GetDialogFrameName = new.instancemethod(Appc.TGUITheme_GetDialogFrameName, None, TGUITheme)
TGUITheme.GetDialogFrameScale = new.instancemethod(Appc.TGUITheme_GetDialogFrameScale, None, TGUITheme)
TGUITheme.GetThemeName = new.instancemethod(Appc.TGUITheme_GetThemeName, None, TGUITheme)

class TGUIThemeManager:
    def __init__(self,this):
        self.this = this

    def FindTheme(*args):
        val = apply(Appc.TGUIThemeManager_FindTheme,args)
        if val: val = TGUIThemePtr(val) 
        return val
    def GetCurrentTheme(*args):
        val = apply(Appc.TGUIThemeManager_GetCurrentTheme,args)
        if val: val = TGUIThemePtr(val) 
        return val
    def __repr__(self):
        return "<C TGUIThemeManager instance at %s>" % (self.this,)
class TGUIThemeManagerPtr(TGUIThemeManager):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGUIThemeManager


TGUIThemeManager.SetCurrentTheme = new.instancemethod(Appc.TGUIThemeManager_SetCurrentTheme, None, TGUIThemeManager)
TGUIThemeManager.AddTheme = new.instancemethod(Appc.TGUIThemeManager_AddTheme, None, TGUIThemeManager)

class TGConsole(TGPane):
    def __init__(self,*args):
        self.this = apply(Appc.new_TGConsole,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGConsole(self)
    def __repr__(self):
        return "<C TGConsole instance at %s>" % (self.this,)
class TGConsolePtr(TGConsole):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGConsole


TGConsole.EvalString = new.instancemethod(Appc.TGConsole_EvalString, None, TGConsole)
TGConsole.AddConsoleString = new.instancemethod(Appc.TGConsole_AddConsoleString, None, TGConsole)
TGConsole.SetConsoleFont = new.instancemethod(Appc.TGConsole_SetConsoleFont, None, TGConsole)

class TGPrompt(TGParagraph):
    def __init__(self,*args):
        self.this = apply(Appc.new_TGPrompt,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGParagraph(self)
    def __repr__(self):
        return "<C TGPrompt instance at %s>" % (self.this,)
class TGPromptPtr(TGPrompt):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGPrompt


TGPrompt.GetString = new.instancemethod(Appc.TGPrompt_GetString, None, TGPrompt)
TGPrompt.GetCString = new.instancemethod(Appc.TGPrompt_GetCString, None, TGPrompt)
TGPrompt.SetCursorPosition = new.instancemethod(Appc.TGPrompt_SetCursorPosition, None, TGPrompt)

class TGSound:
    LS_3D = Appc.TGSound_LS_3D
    LS_STREAMED = Appc.TGSound_LS_STREAMED
    LS_DELAY_LOADING = Appc.TGSound_LS_DELAY_LOADING
    SS_PLAYING = Appc.TGSound_SS_PLAYING
    SS_STOPPED = Appc.TGSound_SS_STOPPED
    SS_UNLOADED = Appc.TGSound_SS_UNLOADED
    SS_UNKNOWN = Appc.TGSound_SS_UNKNOWN
    def __init__(self,this):
        self.this = this

    def GetParentNode(*args):
        val = apply(Appc.TGSound_GetParentNode,args)
        if val: val = NiNodePtr(val) 
        return val
    def GetPosition(*args):
        val = apply(Appc.TGSound_GetPosition,args)
        if val: val = NiPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetEndEvent(*args):
        val = apply(Appc.TGSound_GetEndEvent,args)
        if val: val = TGEventPtr(val) 
        return val
    def __repr__(self):
        return "<C TGSound instance at %s>" % (self.this,)
class TGSoundPtr(TGSound):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGSound


TGSound.Load = new.instancemethod(Appc.TGSound_Load, None, TGSound)
TGSound.Unload = new.instancemethod(Appc.TGSound_Unload, None, TGSound)
TGSound.SetGroup = new.instancemethod(Appc.TGSound_SetGroup, None, TGSound)
TGSound.GetGroup = new.instancemethod(Appc.TGSound_GetGroup, None, TGSound)
TGSound.Play = new.instancemethod(Appc.TGSound_Play, None, TGSound)
TGSound.PlayAndNotify = new.instancemethod(Appc.TGSound_PlayAndNotify, None, TGSound)
TGSound.Stop = new.instancemethod(Appc.TGSound_Stop, None, TGSound)
TGSound.Rewind = new.instancemethod(Appc.TGSound_Rewind, None, TGSound)
TGSound.Pause = new.instancemethod(Appc.TGSound_Pause, None, TGSound)
TGSound.IsPaused = new.instancemethod(Appc.TGSound_IsPaused, None, TGSound)
TGSound.Unpause = new.instancemethod(Appc.TGSound_Unpause, None, TGSound)
TGSound.SetSingleShot = new.instancemethod(Appc.TGSound_SetSingleShot, None, TGSound)
TGSound.IsSingleShot = new.instancemethod(Appc.TGSound_IsSingleShot, None, TGSound)
TGSound.GetStatus = new.instancemethod(Appc.TGSound_GetStatus, None, TGSound)
TGSound.GetSoundName = new.instancemethod(Appc.TGSound_GetSoundName, None, TGSound)
TGSound.GetFileName = new.instancemethod(Appc.TGSound_GetFileName, None, TGSound)
TGSound.Is3D = new.instancemethod(Appc.TGSound_Is3D, None, TGSound)
TGSound.IsStreamed = new.instancemethod(Appc.TGSound_IsStreamed, None, TGSound)
TGSound.IsLoaded = new.instancemethod(Appc.TGSound_IsLoaded, None, TGSound)
TGSound.SetSFX = new.instancemethod(Appc.TGSound_SetSFX, None, TGSound)
TGSound.IsSFX = new.instancemethod(Appc.TGSound_IsSFX, None, TGSound)
TGSound.SetVoice = new.instancemethod(Appc.TGSound_SetVoice, None, TGSound)
TGSound.IsVoice = new.instancemethod(Appc.TGSound_IsVoice, None, TGSound)
TGSound.SetInterface = new.instancemethod(Appc.TGSound_SetInterface, None, TGSound)
TGSound.IsInterface = new.instancemethod(Appc.TGSound_IsInterface, None, TGSound)
TGSound.AttachToNode = new.instancemethod(Appc.TGSound_AttachToNode, None, TGSound)
TGSound.DetachFromNode = new.instancemethod(Appc.TGSound_DetachFromNode, None, TGSound)
TGSound.SetOrientation = new.instancemethod(Appc.TGSound_SetOrientation, None, TGSound)
TGSound.GetOrientation = new.instancemethod(Appc.TGSound_GetOrientation, None, TGSound)
TGSound.SetPosition = new.instancemethod(Appc.TGSound_SetPosition, None, TGSound)
TGSound.SetConeData = new.instancemethod(Appc.TGSound_SetConeData, None, TGSound)
TGSound.GetConeData = new.instancemethod(Appc.TGSound_GetConeData, None, TGSound)
TGSound.SetMinMaxDistance = new.instancemethod(Appc.TGSound_SetMinMaxDistance, None, TGSound)
TGSound.GetMinMaxDistance = new.instancemethod(Appc.TGSound_GetMinMaxDistance, None, TGSound)
TGSound.SetLooping = new.instancemethod(Appc.TGSound_SetLooping, None, TGSound)
TGSound.GetLooping = new.instancemethod(Appc.TGSound_GetLooping, None, TGSound)
TGSound.SetVolume = new.instancemethod(Appc.TGSound_SetVolume, None, TGSound)
TGSound.GetVolume = new.instancemethod(Appc.TGSound_GetVolume, None, TGSound)
TGSound.SetPitch = new.instancemethod(Appc.TGSound_SetPitch, None, TGSound)
TGSound.GetPitch = new.instancemethod(Appc.TGSound_GetPitch, None, TGSound)
TGSound.SetPlayPositionSeconds = new.instancemethod(Appc.TGSound_SetPlayPositionSeconds, None, TGSound)
TGSound.GetPlayPositionSeconds = new.instancemethod(Appc.TGSound_GetPlayPositionSeconds, None, TGSound)
TGSound.SetPlayPosition = new.instancemethod(Appc.TGSound_SetPlayPosition, None, TGSound)
TGSound.GetPlayPosition = new.instancemethod(Appc.TGSound_GetPlayPosition, None, TGSound)
TGSound.GetDurationSeconds = new.instancemethod(Appc.TGSound_GetDurationSeconds, None, TGSound)
TGSound.SetPriority = new.instancemethod(Appc.TGSound_SetPriority, None, TGSound)
TGSound.GetPriority = new.instancemethod(Appc.TGSound_GetPriority, None, TGSound)
TGSound.SetEndEvent = new.instancemethod(Appc.TGSound_SetEndEvent, None, TGSound)
TGSound.Update = new.instancemethod(Appc.TGSound_Update, None, TGSound)
TGSound.GetNiSourceObj = new.instancemethod(Appc.TGSound_GetNiSourceObj, None, TGSound)
TGSound.AddFadePoint = new.instancemethod(Appc.TGSound_AddFadePoint, None, TGSound)
TGSound.ClearFadePoints = new.instancemethod(Appc.TGSound_ClearFadePoints, None, TGSound)

class TGSoundManager(TGEventHandlerObject):
    def __init__(self,this):
        self.this = this

    def GetSound(*args):
        val = apply(Appc.TGSoundManager_GetSound,args)
        if val: val = TGSoundPtr(val) 
        return val
    def GetPlayingSound(*args):
        val = apply(Appc.TGSoundManager_GetPlayingSound,args)
        if val: val = TGSoundPtr(val) 
        return val
    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEventHandlerObject(self)
    def __repr__(self):
        return "<C TGSoundManager instance at %s>" % (self.this,)
class TGSoundManagerPtr(TGSoundManager):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGSoundManager


TGSoundManager.Reload = new.instancemethod(Appc.TGSoundManager_Reload, None, TGSoundManager)
TGSoundManager.SetEnabled = new.instancemethod(Appc.TGSoundManager_SetEnabled, None, TGSoundManager)
TGSoundManager.IsEnabled = new.instancemethod(Appc.TGSoundManager_IsEnabled, None, TGSoundManager)
TGSoundManager.SetMaxSoundsAtOnce = new.instancemethod(Appc.TGSoundManager_SetMaxSoundsAtOnce, None, TGSoundManager)
TGSoundManager.GetMaxSoundsAtOnce = new.instancemethod(Appc.TGSoundManager_GetMaxSoundsAtOnce, None, TGSoundManager)
TGSoundManager.SetUnitsPerMeter = new.instancemethod(Appc.TGSoundManager_SetUnitsPerMeter, None, TGSoundManager)
TGSoundManager.GetUnitsPerMeter = new.instancemethod(Appc.TGSoundManager_GetUnitsPerMeter, None, TGSoundManager)
TGSoundManager.SetMasterVolume = new.instancemethod(Appc.TGSoundManager_SetMasterVolume, None, TGSoundManager)
TGSoundManager.GetMasterVolume = new.instancemethod(Appc.TGSoundManager_GetMasterVolume, None, TGSoundManager)
TGSoundManager.SetSFXVolume = new.instancemethod(Appc.TGSoundManager_SetSFXVolume, None, TGSoundManager)
TGSoundManager.GetSFXVolume = new.instancemethod(Appc.TGSoundManager_GetSFXVolume, None, TGSoundManager)
TGSoundManager.SetSFXEnabled = new.instancemethod(Appc.TGSoundManager_SetSFXEnabled, None, TGSoundManager)
TGSoundManager.IsSFXEnabled = new.instancemethod(Appc.TGSoundManager_IsSFXEnabled, None, TGSoundManager)
TGSoundManager.SetVoiceVolume = new.instancemethod(Appc.TGSoundManager_SetVoiceVolume, None, TGSoundManager)
TGSoundManager.GetVoiceVolume = new.instancemethod(Appc.TGSoundManager_GetVoiceVolume, None, TGSoundManager)
TGSoundManager.SetVoiceEnabled = new.instancemethod(Appc.TGSoundManager_SetVoiceEnabled, None, TGSoundManager)
TGSoundManager.IsVoiceEnabled = new.instancemethod(Appc.TGSoundManager_IsVoiceEnabled, None, TGSoundManager)
TGSoundManager.SetInterfaceVolume = new.instancemethod(Appc.TGSoundManager_SetInterfaceVolume, None, TGSoundManager)
TGSoundManager.GetInterfaceVolume = new.instancemethod(Appc.TGSoundManager_GetInterfaceVolume, None, TGSoundManager)
TGSoundManager.PlaySound = new.instancemethod(Appc.TGSoundManager_PlaySound, None, TGSoundManager)
TGSoundManager.StopSound = new.instancemethod(Appc.TGSoundManager_StopSound, None, TGSoundManager)
TGSoundManager.SetSFXAdjustmentMinimum = new.instancemethod(Appc.TGSoundManager_SetSFXAdjustmentMinimum, None, TGSoundManager)
TGSoundManager.StopAllSounds = new.instancemethod(Appc.TGSoundManager_StopAllSounds, None, TGSoundManager)
TGSoundManager.StopAllSoundsInGroup = new.instancemethod(Appc.TGSoundManager_StopAllSoundsInGroup, None, TGSoundManager)
TGSoundManager.DeleteSound = new.instancemethod(Appc.TGSoundManager_DeleteSound, None, TGSoundManager)
TGSoundManager.DeleteAllSounds = new.instancemethod(Appc.TGSoundManager_DeleteAllSounds, None, TGSoundManager)
TGSoundManager.DeleteAllSoundsInGroup = new.instancemethod(Appc.TGSoundManager_DeleteAllSoundsInGroup, None, TGSoundManager)
TGSoundManager.GetNumSoundsAllocated = new.instancemethod(Appc.TGSoundManager_GetNumSoundsAllocated, None, TGSoundManager)
TGSoundManager.GetRoughMemoryUsage = new.instancemethod(Appc.TGSoundManager_GetRoughMemoryUsage, None, TGSoundManager)
TGSoundManager.IsA3DSupported = new.instancemethod(Appc.TGSoundManager_IsA3DSupported, None, TGSoundManager)
TGSoundManager.IsEAXSupported = new.instancemethod(Appc.TGSoundManager_IsEAXSupported, None, TGSoundManager)

class TGRedbookClass:
    MAX_CD_TRACKS = Appc.TGRedbookClass_MAX_CD_TRACKS
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C TGRedbookClass instance at %s>" % (self.this,)
class TGRedbookClassPtr(TGRedbookClass):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGRedbookClass


TGRedbookClass.OpenRedbookCD = new.instancemethod(Appc.TGRedbookClass_OpenRedbookCD, None, TGRedbookClass)
TGRedbookClass.PlayRedbookCDTrack = new.instancemethod(Appc.TGRedbookClass_PlayRedbookCDTrack, None, TGRedbookClass)
TGRedbookClass.StopRedbookCDTrack = new.instancemethod(Appc.TGRedbookClass_StopRedbookCDTrack, None, TGRedbookClass)
TGRedbookClass.CloseRedbookCD = new.instancemethod(Appc.TGRedbookClass_CloseRedbookCD, None, TGRedbookClass)
TGRedbookClass.IsRedbookCDTrackFinishedPlaying = new.instancemethod(Appc.TGRedbookClass_IsRedbookCDTrackFinishedPlaying, None, TGRedbookClass)
TGRedbookClass.GetCDID = new.instancemethod(Appc.TGRedbookClass_GetCDID, None, TGRedbookClass)
TGRedbookClass.SetCDDonePlaying = new.instancemethod(Appc.TGRedbookClass_SetCDDonePlaying, None, TGRedbookClass)
TGRedbookClass.GetCDTrackLengthInMilliseconds = new.instancemethod(Appc.TGRedbookClass_GetCDTrackLengthInMilliseconds, None, TGRedbookClass)
TGRedbookClass.SetRedbookCDVolume = new.instancemethod(Appc.TGRedbookClass_SetRedbookCDVolume, None, TGRedbookClass)
TGRedbookClass.FadeRedbookCDVolume = new.instancemethod(Appc.TGRedbookClass_FadeRedbookCDVolume, None, TGRedbookClass)
TGRedbookClass.UpdateRedbookCD = new.instancemethod(Appc.TGRedbookClass_UpdateRedbookCD, None, TGRedbookClass)

class TGMusic(TGEventHandlerObject):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEventHandlerObject(self)
    def __repr__(self):
        return "<C TGMusic instance at %s>" % (self.this,)
class TGMusicPtr(TGMusic):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGMusic


TGMusic.LoadMusic = new.instancemethod(Appc.TGMusic_LoadMusic, None, TGMusic)
TGMusic.UnloadMusic = new.instancemethod(Appc.TGMusic_UnloadMusic, None, TGMusic)
TGMusic.StartMusic = new.instancemethod(Appc.TGMusic_StartMusic, None, TGMusic)
TGMusic.StopMusic = new.instancemethod(Appc.TGMusic_StopMusic, None, TGMusic)
TGMusic.PlayFanfare = new.instancemethod(Appc.TGMusic_PlayFanfare, None, TGMusic)
TGMusic.SetEnabled = new.instancemethod(Appc.TGMusic_SetEnabled, None, TGMusic)
TGMusic.IsEnabled = new.instancemethod(Appc.TGMusic_IsEnabled, None, TGMusic)
TGMusic.SetVolume = new.instancemethod(Appc.TGMusic_SetVolume, None, TGMusic)
TGMusic.GetVolume = new.instancemethod(Appc.TGMusic_GetVolume, None, TGMusic)

class TGSoundRegion(TGObject):
    FT_NONE = Appc.TGSoundRegion_FT_NONE
    FT_MUTE = Appc.TGSoundRegion_FT_MUTE
    FT_MUFFLE = Appc.TGSoundRegion_FT_MUFFLE
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C TGSoundRegion instance at %s>" % (self.this,)
class TGSoundRegionPtr(TGSoundRegion):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGSoundRegion


TGSoundRegion.AddSound = new.instancemethod(Appc.TGSoundRegion_AddSound, None, TGSoundRegion)
TGSoundRegion.RemoveSound = new.instancemethod(Appc.TGSoundRegion_RemoveSound, None, TGSoundRegion)
TGSoundRegion.SetFilter = new.instancemethod(Appc.TGSoundRegion_SetFilter, None, TGSoundRegion)

class PyEmbed:
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C PyEmbed instance at %s>" % (self.this,)
class PyEmbedPtr(PyEmbed):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = PyEmbed



class TGModelProperty(TGObject):
    def __init__(self,*args):
        self.this = apply(Appc.new_TGModelProperty,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGModelProperty(self)
    def GetName(*args):
        val = apply(Appc.TGModelProperty_GetName,args)
        if val: val = TGStringPtr(val) ; val.thisown = 1
        return val
    def Duplicate(*args):
        val = apply(Appc.TGModelProperty_Duplicate,args)
        if val: val = TGModelPropertyPtr(val) 
        return val
    def __repr__(self):
        return "<C TGModelProperty instance at %s>" % (self.this,)
class TGModelPropertyPtr(TGModelProperty):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGModelProperty


TGModelProperty.GetRefCount = new.instancemethod(Appc.TGModelProperty_GetRefCount, None, TGModelProperty)
TGModelProperty.DecRefCount = new.instancemethod(Appc.TGModelProperty_DecRefCount, None, TGModelProperty)
TGModelProperty.IncRefCount = new.instancemethod(Appc.TGModelProperty_IncRefCount, None, TGModelProperty)
TGModelProperty.WriteInit = new.instancemethod(Appc.TGModelProperty_WriteInit, None, TGModelProperty)
TGModelProperty.Edit = new.instancemethod(Appc.TGModelProperty_Edit, None, TGModelProperty)
TGModelProperty.SetName = new.instancemethod(Appc.TGModelProperty_SetName, None, TGModelProperty)
TGModelProperty.SetNameW = new.instancemethod(Appc.TGModelProperty_SetNameW, None, TGModelProperty)

class TGModelPropertyManager:
    GLOBAL_TEMPLATES = Appc.TGModelPropertyManager_GLOBAL_TEMPLATES
    LOCAL_TEMPLATES = Appc.TGModelPropertyManager_LOCAL_TEMPLATES
    def __init__(self,this):
        self.this = this

    def FindByNameAndType(*args):
        val = apply(Appc.TGModelPropertyManager_FindByNameAndType,args)
        if val: val = TGModelPropertyPtr(val) 
        return val
    def FindByName(*args):
        val = apply(Appc.TGModelPropertyManager_FindByName,args)
        if val: val = TGModelPropertyPtr(val) 
        return val
    def __repr__(self):
        return "<C TGModelPropertyManager instance at %s>" % (self.this,)
class TGModelPropertyManagerPtr(TGModelPropertyManager):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGModelPropertyManager


TGModelPropertyManager.IsLocalTemplate = new.instancemethod(Appc.TGModelPropertyManager_IsLocalTemplate, None, TGModelPropertyManager)
TGModelPropertyManager.IsGlobalTemplate = new.instancemethod(Appc.TGModelPropertyManager_IsGlobalTemplate, None, TGModelPropertyManager)
TGModelPropertyManager.RegisterLocalTemplate = new.instancemethod(Appc.TGModelPropertyManager_RegisterLocalTemplate, None, TGModelPropertyManager)
TGModelPropertyManager.RegisterGlobalTemplate = new.instancemethod(Appc.TGModelPropertyManager_RegisterGlobalTemplate, None, TGModelPropertyManager)
TGModelPropertyManager.ClearGlobalTemplates = new.instancemethod(Appc.TGModelPropertyManager_ClearGlobalTemplates, None, TGModelPropertyManager)
TGModelPropertyManager.ClearLocalTemplates = new.instancemethod(Appc.TGModelPropertyManager_ClearLocalTemplates, None, TGModelPropertyManager)
TGModelPropertyManager.ClearRegisteredFilters = new.instancemethod(Appc.TGModelPropertyManager_ClearRegisteredFilters, None, TGModelPropertyManager)
TGModelPropertyManager.RegisterFilter = new.instancemethod(Appc.TGModelPropertyManager_RegisterFilter, None, TGModelPropertyManager)
TGModelPropertyManager.AddFilter = new.instancemethod(Appc.TGModelPropertyManager_AddFilter, None, TGModelPropertyManager)
TGModelPropertyManager.ApplyFilters = new.instancemethod(Appc.TGModelPropertyManager_ApplyFilters, None, TGModelPropertyManager)
TGModelPropertyManager.ClearCurrentFilters = new.instancemethod(Appc.TGModelPropertyManager_ClearCurrentFilters, None, TGModelPropertyManager)
TGModelPropertyManager.RemoveFilter = new.instancemethod(Appc.TGModelPropertyManager_RemoveFilter, None, TGModelPropertyManager)
TGModelPropertyManager.RemoveTemplate = new.instancemethod(Appc.TGModelPropertyManager_RemoveTemplate, None, TGModelPropertyManager)

class TGModelPropertySet(TGObject):
    def __init__(self,*args):
        self.this = apply(Appc.new_TGModelPropertySet,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGModelPropertySet(self)
    def GetPropertyList(*args):
        val = apply(Appc.TGModelPropertySet_GetPropertyList,args)
        if val: val = TGModelPropertyListPtr(val) 
        return val
    def GetPropertiesByType(*args):
        val = apply(Appc.TGModelPropertySet_GetPropertiesByType,args)
        if val: val = TGModelPropertyListPtr(val) 
        return val
    def __repr__(self):
        return "<C TGModelPropertySet instance at %s>" % (self.this,)
class TGModelPropertySetPtr(TGModelPropertySet):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGModelPropertySet


TGModelPropertySet.AddToSet = new.instancemethod(Appc.TGModelPropertySet_AddToSet, None, TGModelPropertySet)

class TGModelPropertyInstance:
    def __init__(self,*args):
        self.this = apply(Appc.new_TGModelPropertyInstance,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGModelPropertyInstance(self)
    def GetProperty(*args):
        val = apply(Appc.TGModelPropertyInstance_GetProperty,args)
        if val: val = TGModelPropertyPtr(val) 
        return val
    def GetOriginalTemplate(*args):
        val = apply(Appc.TGModelPropertyInstance_GetOriginalTemplate,args)
        if val: val = TGModelPropertyPtr(val) 
        return val
    def __repr__(self):
        return "<C TGModelPropertyInstance instance at %s>" % (self.this,)
class TGModelPropertyInstancePtr(TGModelPropertyInstance):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGModelPropertyInstance


TGModelPropertyInstance.UseOriginalTemplate = new.instancemethod(Appc.TGModelPropertyInstance_UseOriginalTemplate, None, TGModelPropertyInstance)
TGModelPropertyInstance.GetHardpointName = new.instancemethod(Appc.TGModelPropertyInstance_GetHardpointName, None, TGModelPropertyInstance)

class TGModelPropertyList:
    def __init__(self,*args):
        self.this = apply(Appc.new_TGModelPropertyList,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGModelPropertyList(self)
    def TGGetNext(*args):
        val = apply(Appc.TGModelPropertyList_TGGetNext,args)
        if val: val = TGModelPropertyInstancePtr(val) 
        return val
    def __repr__(self):
        return "<C TGModelPropertyList instance at %s>" % (self.this,)
class TGModelPropertyListPtr(TGModelPropertyList):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGModelPropertyList


TGModelPropertyList.TGBeginIteration = new.instancemethod(Appc.TGModelPropertyList_TGBeginIteration, None, TGModelPropertyList)
TGModelPropertyList.TGDoneIterating = new.instancemethod(Appc.TGModelPropertyList_TGDoneIterating, None, TGModelPropertyList)
TGModelPropertyList.TGDestroy = new.instancemethod(Appc.TGModelPropertyList_TGDestroy, None, TGModelPropertyList)
TGModelPropertyList.TGGetNumItems = new.instancemethod(Appc.TGModelPropertyList_TGGetNumItems, None, TGModelPropertyList)

class TGAction(TGObject):
    def __init__(self,this):
        self.this = this

    def GetSequence(*args):
        val = apply(Appc.TGAction_GetSequence,args)
        if val: val = TGSequencePtr(val) 
        return val
    def __repr__(self):
        return "<C TGAction instance at %s>" % (self.this,)
class TGActionPtr(TGAction):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGAction


TGAction.IsPlaying = new.instancemethod(Appc.TGAction_IsPlaying, None, TGAction)
TGAction.ConstructDescription = new.instancemethod(Appc.TGAction_ConstructDescription, None, TGAction)
TGAction.SetupEditControls = new.instancemethod(Appc.TGAction_SetupEditControls, None, TGAction)
TGAction.ExtractControlValues = new.instancemethod(Appc.TGAction_ExtractControlValues, None, TGAction)
TGAction.Play = new.instancemethod(Appc.TGAction_Play, None, TGAction)
TGAction.Restart = new.instancemethod(Appc.TGAction_Restart, None, TGAction)
TGAction.Skip = new.instancemethod(Appc.TGAction_Skip, None, TGAction)
TGAction.Abort = new.instancemethod(Appc.TGAction_Abort, None, TGAction)
TGAction.IsSkippable = new.instancemethod(Appc.TGAction_IsSkippable, None, TGAction)
TGAction.SetSkippable = new.instancemethod(Appc.TGAction_SetSkippable, None, TGAction)
TGAction.AddCompletedEvent = new.instancemethod(Appc.TGAction_AddCompletedEvent, None, TGAction)
TGAction.IsPartOfSequence = new.instancemethod(Appc.TGAction_IsPartOfSequence, None, TGAction)
TGAction.Completed = new.instancemethod(Appc.TGAction_Completed, None, TGAction)
TGAction.SetUseRealTime = new.instancemethod(Appc.TGAction_SetUseRealTime, None, TGAction)
TGAction.IsUseRealTime = new.instancemethod(Appc.TGAction_IsUseRealTime, None, TGAction)
TGAction.SetSurviveGlobalAbort = new.instancemethod(Appc.TGAction_SetSurviveGlobalAbort, None, TGAction)
TGAction.IsGlobalAbortSurvivor = new.instancemethod(Appc.TGAction_IsGlobalAbortSurvivor, None, TGAction)

class TGActionManager(TGEventHandlerObject):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEventHandlerObject(self)
    def __repr__(self):
        return "<C TGActionManager instance at %s>" % (self.this,)
class TGActionManagerPtr(TGActionManager):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGActionManager



class TGSequence(TGAction):
    def __init__(self,this):
        self.this = this

    def GetAction(*args):
        val = apply(Appc.TGSequence_GetAction,args)
        if val: val = TGActionPtr(val) 
        return val
    def __repr__(self):
        return "<C TGSequence instance at %s>" % (self.this,)
class TGSequencePtr(TGSequence):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGSequence


TGSequence.AddAction = new.instancemethod(Appc.TGSequence_AddAction, None, TGSequence)
TGSequence.AppendAction = new.instancemethod(Appc.TGSequence_AppendAction, None, TGSequence)
TGSequence.Play = new.instancemethod(Appc.TGSequence_Play, None, TGSequence)
TGSequence.Skip = new.instancemethod(Appc.TGSequence_Skip, None, TGSequence)
TGSequence.GetNumActions = new.instancemethod(Appc.TGSequence_GetNumActions, None, TGSequence)

class TGScriptAction(TGAction):
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C TGScriptAction instance at %s>" % (self.this,)
class TGScriptActionPtr(TGScriptAction):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGScriptAction


TGScriptAction.Play = new.instancemethod(Appc.TGScriptAction_Play, None, TGScriptAction)

class TGTimedAction(TGAction):
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C TGTimedAction instance at %s>" % (self.this,)
class TGTimedActionPtr(TGTimedAction):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGTimedAction


TGTimedAction.SetDuration = new.instancemethod(Appc.TGTimedAction_SetDuration, None, TGTimedAction)
TGTimedAction.GetDuration = new.instancemethod(Appc.TGTimedAction_GetDuration, None, TGTimedAction)

class TGSoundAction(TGAction):
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C TGSoundAction instance at %s>" % (self.this,)
class TGSoundActionPtr(TGSoundAction):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGSoundAction


TGSoundAction.Play = new.instancemethod(Appc.TGSoundAction_Play, None, TGSoundAction)
TGSoundAction.Restart = new.instancemethod(Appc.TGSoundAction_Restart, None, TGSoundAction)
TGSoundAction.Completed = new.instancemethod(Appc.TGSoundAction_Completed, None, TGSoundAction)
TGSoundAction.Skip = new.instancemethod(Appc.TGSoundAction_Skip, None, TGSoundAction)
TGSoundAction.SetPriority = new.instancemethod(Appc.TGSoundAction_SetPriority, None, TGSoundAction)
TGSoundAction.SetNode = new.instancemethod(Appc.TGSoundAction_SetNode, None, TGSoundAction)

class TGAnimAction(TGTimedAction):
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C TGAnimAction instance at %s>" % (self.this,)
class TGAnimActionPtr(TGAnimAction):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGAnimAction


TGAnimAction.Play = new.instancemethod(Appc.TGAnimAction_Play, None, TGAnimAction)
TGAnimAction.Restart = new.instancemethod(Appc.TGAnimAction_Restart, None, TGAnimAction)
TGAnimAction.Completed = new.instancemethod(Appc.TGAnimAction_Completed, None, TGAnimAction)
TGAnimAction.Skip = new.instancemethod(Appc.TGAnimAction_Skip, None, TGAnimAction)

class TGAnimPosition(TGAction):
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C TGAnimPosition instance at %s>" % (self.this,)
class TGAnimPositionPtr(TGAnimPosition):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGAnimPosition


TGAnimPosition.Play = new.instancemethod(Appc.TGAnimPosition_Play, None, TGAnimPosition)

class TGCondition(TGObject):
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C TGCondition instance at %s>" % (self.this,)
class TGConditionPtr(TGCondition):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGCondition


TGCondition.GetStatus = new.instancemethod(Appc.TGCondition_GetStatus, None, TGCondition)
TGCondition.SetStatus = new.instancemethod(Appc.TGCondition_SetStatus, None, TGCondition)
TGCondition.AddHandler = new.instancemethod(Appc.TGCondition_AddHandler, None, TGCondition)
TGCondition.RemoveHandler = new.instancemethod(Appc.TGCondition_RemoveHandler, None, TGCondition)
TGCondition.SetActive = new.instancemethod(Appc.TGCondition_SetActive, None, TGCondition)
TGCondition.SetInactive = new.instancemethod(Appc.TGCondition_SetInactive, None, TGCondition)
TGCondition.IsActive = new.instancemethod(Appc.TGCondition_IsActive, None, TGCondition)

class TGConditionHandler:
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C TGConditionHandler instance at %s>" % (self.this,)
class TGConditionHandlerPtr(TGConditionHandler):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGConditionHandler


TGConditionHandler.ConditionChanged = new.instancemethod(Appc.TGConditionHandler_ConditionChanged, None, TGConditionHandler)
TGConditionHandler.AddCondition = new.instancemethod(Appc.TGConditionHandler_AddCondition, None, TGConditionHandler)
TGConditionHandler.RemoveCondition = new.instancemethod(Appc.TGConditionHandler_RemoveCondition, None, TGConditionHandler)

class TGConditionAction(TGAction,TGConditionHandler):
    TGCA_WAIT = Appc.TGConditionAction_TGCA_WAIT
    TGCA_COMPLETED = Appc.TGConditionAction_TGCA_COMPLETED
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C TGConditionAction instance at %s>" % (self.this,)
class TGConditionActionPtr(TGConditionAction):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGConditionAction


TGConditionAction.Play = new.instancemethod(Appc.TGConditionAction_Play, None, TGConditionAction)

class TGMessage:
    TGMESSAGE_SAME_BACKOFF = Appc.TGMessage_TGMESSAGE_SAME_BACKOFF
    TGMESSAGE_LINEAR_BACKOFF = Appc.TGMessage_TGMESSAGE_LINEAR_BACKOFF
    TGMESSAGE_DOUBLE_BACKOFF = Appc.TGMessage_TGMESSAGE_DOUBLE_BACKOFF
    def __init__(self,*args):
        self.this = apply(Appc.new_TGMessage,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGMessage(self)
    def Copy(*args):
        val = apply(Appc.TGMessage_Copy,args)
        if val: val = TGMessagePtr(val) 
        return val
    def GetBufferStream(*args):
        val = apply(Appc.TGMessage_GetBufferStream,args)
        if val: val = TGBufferStreamPtr(val) 
        return val
    def __repr__(self):
        return "<C TGMessage instance at %s>" % (self.this,)
class TGMessagePtr(TGMessage):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGMessage


TGMessage.Serialize = new.instancemethod(Appc.TGMessage_Serialize, None, TGMessage)
TGMessage.Merge = new.instancemethod(Appc.TGMessage_Merge, None, TGMessage)
TGMessage.OverrideOldPackets = new.instancemethod(Appc.TGMessage_OverrideOldPackets, None, TGMessage)
TGMessage.SetData = new.instancemethod(Appc.TGMessage_SetData, None, TGMessage)
TGMessage.GetData = new.instancemethod(Appc.TGMessage_GetData, None, TGMessage)
TGMessage.GetDataLength = new.instancemethod(Appc.TGMessage_GetDataLength, None, TGMessage)
TGMessage.SetDataNoCopy = new.instancemethod(Appc.TGMessage_SetDataNoCopy, None, TGMessage)
TGMessage.SetDataFromStream = new.instancemethod(Appc.TGMessage_SetDataFromStream, None, TGMessage)
TGMessage.SetGuaranteed = new.instancemethod(Appc.TGMessage_SetGuaranteed, None, TGMessage)
TGMessage.IsGuaranteed = new.instancemethod(Appc.TGMessage_IsGuaranteed, None, TGMessage)
TGMessage.SetHighPriority = new.instancemethod(Appc.TGMessage_SetHighPriority, None, TGMessage)
TGMessage.IsHighPriority = new.instancemethod(Appc.TGMessage_IsHighPriority, None, TGMessage)
TGMessage.GetFromID = new.instancemethod(Appc.TGMessage_GetFromID, None, TGMessage)
TGMessage.GetFromAddress = new.instancemethod(Appc.TGMessage_GetFromAddress, None, TGMessage)
TGMessage.SetFirstResendTime = new.instancemethod(Appc.TGMessage_SetFirstResendTime, None, TGMessage)
TGMessage.GetFirstResendTime = new.instancemethod(Appc.TGMessage_GetFirstResendTime, None, TGMessage)
TGMessage.SetBackoffType = new.instancemethod(Appc.TGMessage_SetBackoffType, None, TGMessage)
TGMessage.GetBackoffType = new.instancemethod(Appc.TGMessage_GetBackoffType, None, TGMessage)
TGMessage.SetBackoffFactor = new.instancemethod(Appc.TGMessage_SetBackoffFactor, None, TGMessage)
TGMessage.GetBackoffFactor = new.instancemethod(Appc.TGMessage_GetBackoffFactor, None, TGMessage)
TGMessage.ReadyToResend = new.instancemethod(Appc.TGMessage_ReadyToResend, None, TGMessage)
TGMessage.GetBufferSpaceRequired = new.instancemethod(Appc.TGMessage_GetBufferSpaceRequired, None, TGMessage)
TGMessage.SetSequenceNumber = new.instancemethod(Appc.TGMessage_SetSequenceNumber, None, TGMessage)
TGMessage.GetSequenceNumber = new.instancemethod(Appc.TGMessage_GetSequenceNumber, None, TGMessage)
TGMessage.SetFromID = new.instancemethod(Appc.TGMessage_SetFromID, None, TGMessage)
TGMessage.SetFromAddress = new.instancemethod(Appc.TGMessage_SetFromAddress, None, TGMessage)
TGMessage.SetToID = new.instancemethod(Appc.TGMessage_SetToID, None, TGMessage)
TGMessage.GetToID = new.instancemethod(Appc.TGMessage_GetToID, None, TGMessage)
TGMessage.SetNumRetries = new.instancemethod(Appc.TGMessage_SetNumRetries, None, TGMessage)
TGMessage.IncrementNumRetries = new.instancemethod(Appc.TGMessage_IncrementNumRetries, None, TGMessage)
TGMessage.GetNumRetries = new.instancemethod(Appc.TGMessage_GetNumRetries, None, TGMessage)
TGMessage.SetBackoffTime = new.instancemethod(Appc.TGMessage_SetBackoffTime, None, TGMessage)
TGMessage.GetBackoffTime = new.instancemethod(Appc.TGMessage_GetBackoffTime, None, TGMessage)
TGMessage.SetTimeStamp = new.instancemethod(Appc.TGMessage_SetTimeStamp, None, TGMessage)
TGMessage.GetTimeStamp = new.instancemethod(Appc.TGMessage_GetTimeStamp, None, TGMessage)
TGMessage.SetFirstSendTime = new.instancemethod(Appc.TGMessage_SetFirstSendTime, None, TGMessage)
TGMessage.GetFirstSendTime = new.instancemethod(Appc.TGMessage_GetFirstSendTime, None, TGMessage)
TGMessage.SetMultiPartSequenceNumber = new.instancemethod(Appc.TGMessage_SetMultiPartSequenceNumber, None, TGMessage)
TGMessage.GetMultiPartSequenceNumber = new.instancemethod(Appc.TGMessage_GetMultiPartSequenceNumber, None, TGMessage)
TGMessage.SetMultiPartCount = new.instancemethod(Appc.TGMessage_SetMultiPartCount, None, TGMessage)
TGMessage.GetMultiPartCount = new.instancemethod(Appc.TGMessage_GetMultiPartCount, None, TGMessage)
TGMessage.SetMultiPart = new.instancemethod(Appc.TGMessage_SetMultiPart, None, TGMessage)
TGMessage.IsMultiPart = new.instancemethod(Appc.TGMessage_IsMultiPart, None, TGMessage)
TGMessage.SetAggregate = new.instancemethod(Appc.TGMessage_SetAggregate, None, TGMessage)
TGMessage.IsAggregate = new.instancemethod(Appc.TGMessage_IsAggregate, None, TGMessage)
TGMessage.BreakUpMessage = new.instancemethod(Appc.TGMessage_BreakUpMessage, None, TGMessage)

class TGPlayerList:
    def __init__(self,*args):
        self.this = apply(Appc.new_TGPlayerList,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGPlayerList(self)
    def GetPlayerAtIndex(*args):
        val = apply(Appc.TGPlayerList_GetPlayerAtIndex,args)
        if val: val = TGNetPlayerPtr(val) 
        return val
    def GetPlayer(*args):
        val = apply(Appc.TGPlayerList_GetPlayer,args)
        if val: val = TGNetPlayerPtr(val) 
        return val
    def GetPlayerFromAddress(*args):
        val = apply(Appc.TGPlayerList_GetPlayerFromAddress,args)
        if val: val = TGNetPlayerPtr(val) 
        return val
    def __repr__(self):
        return "<C TGPlayerList instance at %s>" % (self.this,)
class TGPlayerListPtr(TGPlayerList):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGPlayerList


TGPlayerList.AddPlayer = new.instancemethod(Appc.TGPlayerList_AddPlayer, None, TGPlayerList)
TGPlayerList.DeletePlayer = new.instancemethod(Appc.TGPlayerList_DeletePlayer, None, TGPlayerList)
TGPlayerList.DeletePlayerAtIndex = new.instancemethod(Appc.TGPlayerList_DeletePlayerAtIndex, None, TGPlayerList)
TGPlayerList.GetNumPlayers = new.instancemethod(Appc.TGPlayerList_GetNumPlayers, None, TGPlayerList)
TGPlayerList.GetPlayerList = new.instancemethod(Appc.TGPlayerList_GetPlayerList, None, TGPlayerList)
TGPlayerList.ChangePlayerNetID = new.instancemethod(Appc.TGPlayerList_ChangePlayerNetID, None, TGPlayerList)
TGPlayerList.DeleteAllPlayers = new.instancemethod(Appc.TGPlayerList_DeleteAllPlayers, None, TGPlayerList)
TGPlayerList.DeletePlayerByAddress = new.instancemethod(Appc.TGPlayerList_DeletePlayerByAddress, None, TGPlayerList)

class TGNetwork(TGEventHandlerObject):
    TGNETWORK_MAX_SENDS_PENDING = Appc.TGNetwork_TGNETWORK_MAX_SENDS_PENDING
    TGNETWORK_MAX_LOG_ENTRIES = Appc.TGNetwork_TGNETWORK_MAX_LOG_ENTRIES
    TGNETWORK_MAX_SEQUENCE_DIFFERENCE = Appc.TGNetwork_TGNETWORK_MAX_SEQUENCE_DIFFERENCE
    TGNETWORK_INVALID_ID = Appc.TGNetwork_TGNETWORK_INVALID_ID
    TGNETWORK_GAMESPY_PLAYER_ID = Appc.TGNetwork_TGNETWORK_GAMESPY_PLAYER_ID
    TGNETWORK_NULL_ID = Appc.TGNetwork_TGNETWORK_NULL_ID
    DEFAULT_BOOT = Appc.TGNetwork_DEFAULT_BOOT
    TIMED_OUT = Appc.TGNetwork_TIMED_OUT
    INCORRECT_PASSWORD = Appc.TGNetwork_INCORRECT_PASSWORD
    TOO_MANY_PLAYERS = Appc.TGNetwork_TOO_MANY_PLAYERS
    SERVER_BOOTED_YOU = Appc.TGNetwork_SERVER_BOOTED_YOU
    YOU_ARE_BANNED = Appc.TGNetwork_YOU_ARE_BANNED
    def __init__(self,*args):
        self.this = apply(Appc.new_TGNetwork,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGNetwork(self)
    def GetName(*args):
        val = apply(Appc.TGNetwork_GetName,args)
        if val: val = TGStringPtr(val) 
        return val
    def GetNextMessage(*args):
        val = apply(Appc.TGNetwork_GetNextMessage,args)
        if val: val = TGMessagePtr(val) 
        return val
    def GetHostName(*args):
        val = apply(Appc.TGNetwork_GetHostName,args)
        if val: val = TGStringPtr(val) 
        return val
    def GetPlayerList(*args):
        val = apply(Appc.TGNetwork_GetPlayerList,args)
        if val: val = TGPlayerListPtr(val) 
        return val
    def GetPassword(*args):
        val = apply(Appc.TGNetwork_GetPassword,args)
        if val: val = TGStringPtr(val) 
        return val
    def GetGroup(*args):
        val = apply(Appc.TGNetwork_GetGroup,args)
        if val: val = TGNetGroupPtr(val) 
        return val
    def __repr__(self):
        return "<C TGNetwork instance at %s>" % (self.this,)
class TGNetworkPtr(TGNetwork):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGNetwork


TGNetwork.Update = new.instancemethod(Appc.TGNetwork_Update, None, TGNetwork)
TGNetwork.Connect = new.instancemethod(Appc.TGNetwork_Connect, None, TGNetwork)
TGNetwork.Disconnect = new.instancemethod(Appc.TGNetwork_Disconnect, None, TGNetwork)
TGNetwork.GetConnectStatus = new.instancemethod(Appc.TGNetwork_GetConnectStatus, None, TGNetwork)
TGNetwork.CreateLocalPlayer = new.instancemethod(Appc.TGNetwork_CreateLocalPlayer, None, TGNetwork)
TGNetwork.DeleteLocalPlayer = new.instancemethod(Appc.TGNetwork_DeleteLocalPlayer, None, TGNetwork)
TGNetwork.SetName = new.instancemethod(Appc.TGNetwork_SetName, None, TGNetwork)
TGNetwork.GetCName = new.instancemethod(Appc.TGNetwork_GetCName, None, TGNetwork)
TGNetwork.SendTGMessage = new.instancemethod(Appc.TGNetwork_SendTGMessage, None, TGNetwork)
TGNetwork.SendTGMessageToGroup = new.instancemethod(Appc.TGNetwork_SendTGMessageToGroup, None, TGNetwork)
TGNetwork.SetSendTimeout = new.instancemethod(Appc.TGNetwork_SetSendTimeout, None, TGNetwork)
TGNetwork.SetConnectionTimeout = new.instancemethod(Appc.TGNetwork_SetConnectionTimeout, None, TGNetwork)
TGNetwork.GetHostID = new.instancemethod(Appc.TGNetwork_GetHostID, None, TGNetwork)
TGNetwork.GetLocalID = new.instancemethod(Appc.TGNetwork_GetLocalID, None, TGNetwork)
TGNetwork.IsHost = new.instancemethod(Appc.TGNetwork_IsHost, None, TGNetwork)
TGNetwork.GetNumPlayers = new.instancemethod(Appc.TGNetwork_GetNumPlayers, None, TGNetwork)
TGNetwork.SetPassword = new.instancemethod(Appc.TGNetwork_SetPassword, None, TGNetwork)
TGNetwork.GetLocalIPAddress = new.instancemethod(Appc.TGNetwork_GetLocalIPAddress, None, TGNetwork)
TGNetwork.SetEncryptor = new.instancemethod(Appc.TGNetwork_SetEncryptor, None, TGNetwork)
TGNetwork.GetEncryptor = new.instancemethod(Appc.TGNetwork_GetEncryptor, None, TGNetwork)
TGNetwork.AddGroup = new.instancemethod(Appc.TGNetwork_AddGroup, None, TGNetwork)
TGNetwork.DeleteGroup = new.instancemethod(Appc.TGNetwork_DeleteGroup, None, TGNetwork)
TGNetwork.SetBootReason = new.instancemethod(Appc.TGNetwork_SetBootReason, None, TGNetwork)
TGNetwork.GetBootReason = new.instancemethod(Appc.TGNetwork_GetBootReason, None, TGNetwork)
TGNetwork.EnableProfiling = new.instancemethod(Appc.TGNetwork_EnableProfiling, None, TGNetwork)
TGNetwork.GetIPPacketHeaderSize = new.instancemethod(Appc.TGNetwork_GetIPPacketHeaderSize, None, TGNetwork)
TGNetwork.GetTimeElapsedSinceLastHostPing = new.instancemethod(Appc.TGNetwork_GetTimeElapsedSinceLastHostPing, None, TGNetwork)
TGNetwork.ReceiveMessageHandler = new.instancemethod(Appc.TGNetwork_ReceiveMessageHandler, None, TGNetwork)

class TGWinsockNetwork(TGNetwork):
    TGWINSOCK_MAX_PACKET_SIZE = Appc.TGWinsockNetwork_TGWINSOCK_MAX_PACKET_SIZE
    WINSOCK_VERSION_NUMBER = Appc.TGWinsockNetwork_WINSOCK_VERSION_NUMBER
    WINSOCK_PORT = Appc.TGWinsockNetwork_WINSOCK_PORT
    def __init__(self,*args):
        self.this = apply(Appc.new_TGWinsockNetwork,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGWinsockNetwork(self)
    def __repr__(self):
        return "<C TGWinsockNetwork instance at %s>" % (self.this,)
class TGWinsockNetworkPtr(TGWinsockNetwork):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGWinsockNetwork


TGWinsockNetwork.SetPortNumber = new.instancemethod(Appc.TGWinsockNetwork_SetPortNumber, None, TGWinsockNetwork)
TGWinsockNetwork.GetPortNumber = new.instancemethod(Appc.TGWinsockNetwork_GetPortNumber, None, TGWinsockNetwork)
TGWinsockNetwork.GetLocalIPAddress = new.instancemethod(Appc.TGWinsockNetwork_GetLocalIPAddress, None, TGWinsockNetwork)
TGWinsockNetwork.GetIPPacketHeaderSize = new.instancemethod(Appc.TGWinsockNetwork_GetIPPacketHeaderSize, None, TGWinsockNetwork)

class TGNameChangeMessage(TGMessage):
    def __init__(self,*args):
        self.this = apply(Appc.new_TGNameChangeMessage,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGNameChangeMessage(self)
    def Copy(*args):
        val = apply(Appc.TGNameChangeMessage_Copy,args)
        if val: val = TGMessagePtr(val) 
        return val
    def __repr__(self):
        return "<C TGNameChangeMessage instance at %s>" % (self.this,)
class TGNameChangeMessagePtr(TGNameChangeMessage):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGNameChangeMessage


TGNameChangeMessage.Serialize = new.instancemethod(Appc.TGNameChangeMessage_Serialize, None, TGNameChangeMessage)
TGNameChangeMessage.GetBufferSpaceRequired = new.instancemethod(Appc.TGNameChangeMessage_GetBufferSpaceRequired, None, TGNameChangeMessage)

class TGAckMessage(TGMessage):
    def __init__(self,*args):
        self.this = apply(Appc.new_TGAckMessage,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGAckMessage(self)
    def Copy(*args):
        val = apply(Appc.TGAckMessage_Copy,args)
        if val: val = TGMessagePtr(val) 
        return val
    def __repr__(self):
        return "<C TGAckMessage instance at %s>" % (self.this,)
class TGAckMessagePtr(TGAckMessage):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGAckMessage


TGAckMessage.Serialize = new.instancemethod(Appc.TGAckMessage_Serialize, None, TGAckMessage)
TGAckMessage.GetBufferSpaceRequired = new.instancemethod(Appc.TGAckMessage_GetBufferSpaceRequired, None, TGAckMessage)
TGAckMessage.SetSystemMessage = new.instancemethod(Appc.TGAckMessage_SetSystemMessage, None, TGAckMessage)
TGAckMessage.IsSystemMessage = new.instancemethod(Appc.TGAckMessage_IsSystemMessage, None, TGAckMessage)

class TGDoNothingMessage(TGMessage):
    def __init__(self,*args):
        self.this = apply(Appc.new_TGDoNothingMessage,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGDoNothingMessage(self)
    def Copy(*args):
        val = apply(Appc.TGDoNothingMessage_Copy,args)
        if val: val = TGMessagePtr(val) 
        return val
    def __repr__(self):
        return "<C TGDoNothingMessage instance at %s>" % (self.this,)
class TGDoNothingMessagePtr(TGDoNothingMessage):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGDoNothingMessage


TGDoNothingMessage.Serialize = new.instancemethod(Appc.TGDoNothingMessage_Serialize, None, TGDoNothingMessage)
TGDoNothingMessage.GetBufferSpaceRequired = new.instancemethod(Appc.TGDoNothingMessage_GetBufferSpaceRequired, None, TGDoNothingMessage)

class TGBootPlayerMessage(TGMessage):
    def __init__(self,*args):
        self.this = apply(Appc.new_TGBootPlayerMessage,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGBootPlayerMessage(self)
    def Copy(*args):
        val = apply(Appc.TGBootPlayerMessage_Copy,args)
        if val: val = TGMessagePtr(val) 
        return val
    def __repr__(self):
        return "<C TGBootPlayerMessage instance at %s>" % (self.this,)
class TGBootPlayerMessagePtr(TGBootPlayerMessage):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGBootPlayerMessage


TGBootPlayerMessage.Serialize = new.instancemethod(Appc.TGBootPlayerMessage_Serialize, None, TGBootPlayerMessage)
TGBootPlayerMessage.SetBootReason = new.instancemethod(Appc.TGBootPlayerMessage_SetBootReason, None, TGBootPlayerMessage)
TGBootPlayerMessage.GetBootReason = new.instancemethod(Appc.TGBootPlayerMessage_GetBootReason, None, TGBootPlayerMessage)
TGBootPlayerMessage.GetBufferSpaceRequired = new.instancemethod(Appc.TGBootPlayerMessage_GetBufferSpaceRequired, None, TGBootPlayerMessage)

class TGConnectMessage(TGMessage):
    def __init__(self,*args):
        self.this = apply(Appc.new_TGConnectMessage,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGConnectMessage(self)
    def Copy(*args):
        val = apply(Appc.TGConnectMessage_Copy,args)
        if val: val = TGMessagePtr(val) 
        return val
    def __repr__(self):
        return "<C TGConnectMessage instance at %s>" % (self.this,)
class TGConnectMessagePtr(TGConnectMessage):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGConnectMessage


TGConnectMessage.Serialize = new.instancemethod(Appc.TGConnectMessage_Serialize, None, TGConnectMessage)
TGConnectMessage.GetBufferSpaceRequired = new.instancemethod(Appc.TGConnectMessage_GetBufferSpaceRequired, None, TGConnectMessage)

class TGDisconnectMessage(TGMessage):
    def __init__(self,*args):
        self.this = apply(Appc.new_TGDisconnectMessage,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGDisconnectMessage(self)
    def Copy(*args):
        val = apply(Appc.TGDisconnectMessage_Copy,args)
        if val: val = TGMessagePtr(val) 
        return val
    def __repr__(self):
        return "<C TGDisconnectMessage instance at %s>" % (self.this,)
class TGDisconnectMessagePtr(TGDisconnectMessage):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGDisconnectMessage


TGDisconnectMessage.Serialize = new.instancemethod(Appc.TGDisconnectMessage_Serialize, None, TGDisconnectMessage)
TGDisconnectMessage.GetBufferSpaceRequired = new.instancemethod(Appc.TGDisconnectMessage_GetBufferSpaceRequired, None, TGDisconnectMessage)

class TGMessageEvent(TGEvent):
    def __init__(self,*args):
        self.this = apply(Appc.new_TGMessageEvent,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGMessageEvent(self)
    def GetMessage(*args):
        val = apply(Appc.TGMessageEvent_GetMessage,args)
        if val: val = TGMessagePtr(val) 
        return val
    def __repr__(self):
        return "<C TGMessageEvent instance at %s>" % (self.this,)
class TGMessageEventPtr(TGMessageEvent):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGMessageEvent


TGMessageEvent.SetMessage = new.instancemethod(Appc.TGMessageEvent_SetMessage, None, TGMessageEvent)

class TGPlayerEvent(TGEvent):
    def __init__(self,*args):
        self.this = apply(Appc.new_TGPlayerEvent,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGPlayerEvent(self)
    def __repr__(self):
        return "<C TGPlayerEvent instance at %s>" % (self.this,)
class TGPlayerEventPtr(TGPlayerEvent):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGPlayerEvent


TGPlayerEvent.SetPlayerID = new.instancemethod(Appc.TGPlayerEvent_SetPlayerID, None, TGPlayerEvent)
TGPlayerEvent.GetPlayerID = new.instancemethod(Appc.TGPlayerEvent_GetPlayerID, None, TGPlayerEvent)

class TGGroupPlayer:
    def __init__(self,this):
        self.this = this

    __setmethods__ = {
        "m_iNetID" : Appc.TGGroupPlayer_m_iNetID_set,
    }
    def __setattr__(self,name,value):
        if (name == "this") or (name == "thisown"): self.__dict__[name] = value; return
        method = TGGroupPlayer.__setmethods__.get(name,None)
        if method: return method(self,value)
        self.__dict__[name] = value
    __getmethods__ = {
        "m_iNetID" : Appc.TGGroupPlayer_m_iNetID_get,
    }
    def __getattr__(self,name):
        method = TGGroupPlayer.__getmethods__.get(name,None)
        if method: return method(self)
        raise AttributeError,name
    def __repr__(self):
        return "<C TGGroupPlayer instance at %s>" % (self.this,)
class TGGroupPlayerPtr(TGGroupPlayer):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGGroupPlayer



class TGNetGroup:
    def __init__(self,*args):
        self.this = apply(Appc.new_TGNetGroup,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGNetGroup(self)
    def Copy(*args):
        val = apply(Appc.TGNetGroup_Copy,args)
        if val: val = TGNetGroupPtr(val) 
        return val
    def __repr__(self):
        return "<C TGNetGroup instance at %s>" % (self.this,)
class TGNetGroupPtr(TGNetGroup):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGNetGroup


TGNetGroup.SetName = new.instancemethod(Appc.TGNetGroup_SetName, None, TGNetGroup)
TGNetGroup.GetName = new.instancemethod(Appc.TGNetGroup_GetName, None, TGNetGroup)
TGNetGroup.GetPlayerList = new.instancemethod(Appc.TGNetGroup_GetPlayerList, None, TGNetGroup)
TGNetGroup.Validate = new.instancemethod(Appc.TGNetGroup_Validate, None, TGNetGroup)
TGNetGroup.AddPlayerToGroup = new.instancemethod(Appc.TGNetGroup_AddPlayerToGroup, None, TGNetGroup)
TGNetGroup.DeletePlayerFromGroup = new.instancemethod(Appc.TGNetGroup_DeletePlayerFromGroup, None, TGNetGroup)
TGNetGroup.IsPlayerInGroup = new.instancemethod(Appc.TGNetGroup_IsPlayerInGroup, None, TGNetGroup)

class TGNetPlayer:
    def __init__(self,*args):
        self.this = apply(Appc.new_TGNetPlayer,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGNetPlayer(self)
    def GetName(*args):
        val = apply(Appc.TGNetPlayer_GetName,args)
        if val: val = TGStringPtr(val) 
        return val
    def Copy(*args):
        val = apply(Appc.TGNetPlayer_Copy,args)
        if val: val = TGNetPlayerPtr(val) 
        return val
    def __repr__(self):
        return "<C TGNetPlayer instance at %s>" % (self.this,)
class TGNetPlayerPtr(TGNetPlayer):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGNetPlayer


TGNetPlayer.SetName = new.instancemethod(Appc.TGNetPlayer_SetName, None, TGNetPlayer)
TGNetPlayer.SetNetID = new.instancemethod(Appc.TGNetPlayer_SetNetID, None, TGNetPlayer)
TGNetPlayer.GetNetID = new.instancemethod(Appc.TGNetPlayer_GetNetID, None, TGNetPlayer)
TGNetPlayer.SetNetAddress = new.instancemethod(Appc.TGNetPlayer_SetNetAddress, None, TGNetPlayer)
TGNetPlayer.GetNetAddress = new.instancemethod(Appc.TGNetPlayer_GetNetAddress, None, TGNetPlayer)
TGNetPlayer.SetDisconnected = new.instancemethod(Appc.TGNetPlayer_SetDisconnected, None, TGNetPlayer)
TGNetPlayer.IsDisconnected = new.instancemethod(Appc.TGNetPlayer_IsDisconnected, None, TGNetPlayer)
TGNetPlayer.SetConnectUID = new.instancemethod(Appc.TGNetPlayer_SetConnectUID, None, TGNetPlayer)
TGNetPlayer.GetConnectUID = new.instancemethod(Appc.TGNetPlayer_GetConnectUID, None, TGNetPlayer)
TGNetPlayer.SetConnectAddress = new.instancemethod(Appc.TGNetPlayer_SetConnectAddress, None, TGNetPlayer)
TGNetPlayer.GetConnectAddress = new.instancemethod(Appc.TGNetPlayer_GetConnectAddress, None, TGNetPlayer)
TGNetPlayer.GetBytesPerSecondTo = new.instancemethod(Appc.TGNetPlayer_GetBytesPerSecondTo, None, TGNetPlayer)
TGNetPlayer.GetBytesPerSecondFrom = new.instancemethod(Appc.TGNetPlayer_GetBytesPerSecondFrom, None, TGNetPlayer)
TGNetPlayer.Compare = new.instancemethod(Appc.TGNetPlayer_Compare, None, TGNetPlayer)

class TGMovieAction(TGAction):
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C TGMovieAction instance at %s>" % (self.this,)
class TGMovieActionPtr(TGMovieAction):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGMovieAction


TGMovieAction.Play = new.instancemethod(Appc.TGMovieAction_Play, None, TGMovieAction)
TGMovieAction.Skip = new.instancemethod(Appc.TGMovieAction_Skip, None, TGMovieAction)
TGMovieAction.Completed = new.instancemethod(Appc.TGMovieAction_Completed, None, TGMovieAction)
TGMovieAction.SetOffset = new.instancemethod(Appc.TGMovieAction_SetOffset, None, TGMovieAction)
TGMovieAction.GetOffsetX = new.instancemethod(Appc.TGMovieAction_GetOffsetX, None, TGMovieAction)
TGMovieAction.GetOffsetY = new.instancemethod(Appc.TGMovieAction_GetOffsetY, None, TGMovieAction)
TGMovieAction.Repeats = new.instancemethod(Appc.TGMovieAction_Repeats, None, TGMovieAction)
TGMovieAction.AddFrameAction = new.instancemethod(Appc.TGMovieAction_AddFrameAction, None, TGMovieAction)
TGMovieAction.DeleteFrameAction = new.instancemethod(Appc.TGMovieAction_DeleteFrameAction, None, TGMovieAction)

class TGCreditAction(TGTimedAction):
    JUSTIFY_LEFT = Appc.TGCreditAction_JUSTIFY_LEFT
    JUSTIFY_RIGHT = Appc.TGCreditAction_JUSTIFY_RIGHT
    JUSTIFY_TOP = Appc.TGCreditAction_JUSTIFY_TOP
    JUSTIFY_BOTTOM = Appc.TGCreditAction_JUSTIFY_BOTTOM
    JUSTIFY_CENTER = Appc.TGCreditAction_JUSTIFY_CENTER
    def __init__(self,*args):
        self.this = apply(Appc.new_TGCreditAction,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGCreditAction(self)
    def __repr__(self):
        return "<C TGCreditAction instance at %s>" % (self.this,)
class TGCreditActionPtr(TGCreditAction):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGCreditAction


TGCreditAction.SetColor = new.instancemethod(Appc.TGCreditAction_SetColor, None, TGCreditAction)
TGCreditAction.Play = new.instancemethod(Appc.TGCreditAction_Play, None, TGCreditAction)

class TGMovieManager:
    MAX_MOVIES_AT_ONCE = Appc.TGMovieManager_MAX_MOVIES_AT_ONCE
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C TGMovieManager instance at %s>" % (self.this,)
class TGMovieManagerPtr(TGMovieManager):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGMovieManager


TGMovieManager.IsAnyPlaying = new.instancemethod(Appc.TGMovieManager_IsAnyPlaying, None, TGMovieManager)
TGMovieManager.PlayNextFrame = new.instancemethod(Appc.TGMovieManager_PlayNextFrame, None, TGMovieManager)
TGMovieManager.SwitchToMovieMode = new.instancemethod(Appc.TGMovieManager_SwitchToMovieMode, None, TGMovieManager)
TGMovieManager.SwitchOutOfMovieMode = new.instancemethod(Appc.TGMovieManager_SwitchOutOfMovieMode, None, TGMovieManager)
TGMovieManager.SetMovieVolume = new.instancemethod(Appc.TGMovieManager_SetMovieVolume, None, TGMovieManager)
TGMovieManager.LoadForcedMovie = new.instancemethod(Appc.TGMovieManager_LoadForcedMovie, None, TGMovieManager)

class TGGeomUtils:
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C TGGeomUtils instance at %s>" % (self.this,)
class TGGeomUtilsPtr(TGGeomUtils):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGGeomUtils



class UtopiaModule:
    CLIENT_RANGE = Appc.UtopiaModule_CLIENT_RANGE
    def __init__(self,this):
        self.this = this

    def GetCamera(*args):
        val = apply(Appc.UtopiaModule_GetCamera,args)
        if val: val = NiCameraPtr(val) 
        return val
    def GetCaptainName(*args):
        val = apply(Appc.UtopiaModule_GetCaptainName,args)
        if val: val = TGStringPtr(val) ; val.thisown = 1
        return val
    def GetNetwork(*args):
        val = apply(Appc.UtopiaModule_GetNetwork,args)
        if val: val = TGNetworkPtr(val) 
        return val
    def GetGameSpy(*args):
        val = apply(Appc.UtopiaModule_GetGameSpy,args)
        if val: val = GameSpyPtr(val) 
        return val
    def __repr__(self):
        return "<C UtopiaModule instance at %s>" % (self.this,)
class UtopiaModulePtr(UtopiaModule):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = UtopiaModule


UtopiaModule.RenderDefaultCamera = new.instancemethod(Appc.UtopiaModule_RenderDefaultCamera, None, UtopiaModule)
UtopiaModule.GetGameTime = new.instancemethod(Appc.UtopiaModule_GetGameTime, None, UtopiaModule)
UtopiaModule.SetGameTime = new.instancemethod(Appc.UtopiaModule_SetGameTime, None, UtopiaModule)
UtopiaModule.GetRealTime = new.instancemethod(Appc.UtopiaModule_GetRealTime, None, UtopiaModule)
UtopiaModule.IsGamePaused = new.instancemethod(Appc.UtopiaModule_IsGamePaused, None, UtopiaModule)
UtopiaModule.SetTimeRate = new.instancemethod(Appc.UtopiaModule_SetTimeRate, None, UtopiaModule)
UtopiaModule.SetTimeScale = new.instancemethod(Appc.UtopiaModule_SetTimeScale, None, UtopiaModule)
UtopiaModule.IsDirectStart = new.instancemethod(Appc.UtopiaModule_IsDirectStart, None, UtopiaModule)
UtopiaModule.Pause = new.instancemethod(Appc.UtopiaModule_Pause, None, UtopiaModule)
UtopiaModule.ForceUnpause = new.instancemethod(Appc.UtopiaModule_ForceUnpause, None, UtopiaModule)
UtopiaModule.LoadEpisodeSounds = new.instancemethod(Appc.UtopiaModule_LoadEpisodeSounds, None, UtopiaModule)
UtopiaModule.CDCheck = new.instancemethod(Appc.UtopiaModule_CDCheck, None, UtopiaModule)
UtopiaModule.SaveToFile = new.instancemethod(Appc.UtopiaModule_SaveToFile, None, UtopiaModule)
UtopiaModule.LoadFromFile = new.instancemethod(Appc.UtopiaModule_LoadFromFile, None, UtopiaModule)
UtopiaModule.SetLoadFromFileName = new.instancemethod(Appc.UtopiaModule_SetLoadFromFileName, None, UtopiaModule)
UtopiaModule.SetInternalLoadFileName = new.instancemethod(Appc.UtopiaModule_SetInternalLoadFileName, None, UtopiaModule)
UtopiaModule.GetSaveFilename = new.instancemethod(Appc.UtopiaModule_GetSaveFilename, None, UtopiaModule)
UtopiaModule.GetLoadFilename = new.instancemethod(Appc.UtopiaModule_GetLoadFilename, None, UtopiaModule)
UtopiaModule.SaveMissionState = new.instancemethod(Appc.UtopiaModule_SaveMissionState, None, UtopiaModule)
UtopiaModule.LoadMissionState = new.instancemethod(Appc.UtopiaModule_LoadMissionState, None, UtopiaModule)
UtopiaModule.SetIsClient = new.instancemethod(Appc.UtopiaModule_SetIsClient, None, UtopiaModule)
UtopiaModule.IsClient = new.instancemethod(Appc.UtopiaModule_IsClient, None, UtopiaModule)
UtopiaModule.SetMultiplayer = new.instancemethod(Appc.UtopiaModule_SetMultiplayer, None, UtopiaModule)
UtopiaModule.IsMultiplayer = new.instancemethod(Appc.UtopiaModule_IsMultiplayer, None, UtopiaModule)
UtopiaModule.SetIsHost = new.instancemethod(Appc.UtopiaModule_SetIsHost, None, UtopiaModule)
UtopiaModule.IsHost = new.instancemethod(Appc.UtopiaModule_IsHost, None, UtopiaModule)
UtopiaModule.DetermineModemConnection = new.instancemethod(Appc.UtopiaModule_DetermineModemConnection, None, UtopiaModule)
UtopiaModule.IsModemConnection = new.instancemethod(Appc.UtopiaModule_IsModemConnection, None, UtopiaModule)
UtopiaModule.SetProcessingPackets = new.instancemethod(Appc.UtopiaModule_SetProcessingPackets, None, UtopiaModule)
UtopiaModule.IsProcessingPackets = new.instancemethod(Appc.UtopiaModule_IsProcessingPackets, None, UtopiaModule)
UtopiaModule.SetPlayerNumber = new.instancemethod(Appc.UtopiaModule_SetPlayerNumber, None, UtopiaModule)
UtopiaModule.GetPlayerNumber = new.instancemethod(Appc.UtopiaModule_GetPlayerNumber, None, UtopiaModule)
UtopiaModule.SetCaptainName = new.instancemethod(Appc.UtopiaModule_SetCaptainName, None, UtopiaModule)
UtopiaModule.IsLoading = new.instancemethod(Appc.UtopiaModule_IsLoading, None, UtopiaModule)
UtopiaModule.InitializeNetwork = new.instancemethod(Appc.UtopiaModule_InitializeNetwork, None, UtopiaModule)
UtopiaModule.TerminateNetwork = new.instancemethod(Appc.UtopiaModule_TerminateNetwork, None, UtopiaModule)
UtopiaModule.CreateGameSpy = new.instancemethod(Appc.UtopiaModule_CreateGameSpy, None, UtopiaModule)
UtopiaModule.TerminateGameSpy = new.instancemethod(Appc.UtopiaModule_TerminateGameSpy, None, UtopiaModule)
UtopiaModule.SetUnusedClientID = new.instancemethod(Appc.UtopiaModule_SetUnusedClientID, None, UtopiaModule)
UtopiaModule.GetUnusedClientID = new.instancemethod(Appc.UtopiaModule_GetUnusedClientID, None, UtopiaModule)
UtopiaModule.IncrementClientID = new.instancemethod(Appc.UtopiaModule_IncrementClientID, None, UtopiaModule)
UtopiaModule.SetIgnoreClientIDForObjectCreation = new.instancemethod(Appc.UtopiaModule_SetIgnoreClientIDForObjectCreation, None, UtopiaModule)
UtopiaModule.IsIgnoreClientIDForObjectCreation = new.instancemethod(Appc.UtopiaModule_IsIgnoreClientIDForObjectCreation, None, UtopiaModule)
UtopiaModule.SetMaxTorpedoLoad = new.instancemethod(Appc.UtopiaModule_SetMaxTorpedoLoad, None, UtopiaModule)
UtopiaModule.GetMaxTorpedoLoad = new.instancemethod(Appc.UtopiaModule_GetMaxTorpedoLoad, None, UtopiaModule)
UtopiaModule.SetCurrentStarbaseTorpedoLoad = new.instancemethod(Appc.UtopiaModule_SetCurrentStarbaseTorpedoLoad, None, UtopiaModule)
UtopiaModule.GetCurrentStarbaseTorpedoLoad = new.instancemethod(Appc.UtopiaModule_GetCurrentStarbaseTorpedoLoad, None, UtopiaModule)
UtopiaModule.SetGameName = new.instancemethod(Appc.UtopiaModule_SetGameName, None, UtopiaModule)
UtopiaModule.SetGamePath = new.instancemethod(Appc.UtopiaModule_SetGamePath, None, UtopiaModule)
UtopiaModule.SetDataPath = new.instancemethod(Appc.UtopiaModule_SetDataPath, None, UtopiaModule)
UtopiaModule.GetGameName = new.instancemethod(Appc.UtopiaModule_GetGameName, None, UtopiaModule)
UtopiaModule.GetGamePath = new.instancemethod(Appc.UtopiaModule_GetGamePath, None, UtopiaModule)
UtopiaModule.GetDataPath = new.instancemethod(Appc.UtopiaModule_GetDataPath, None, UtopiaModule)
UtopiaModule.GetFriendlyFireTolerance = new.instancemethod(Appc.UtopiaModule_GetFriendlyFireTolerance, None, UtopiaModule)
UtopiaModule.SetMaxFriendlyFire = new.instancemethod(Appc.UtopiaModule_SetMaxFriendlyFire, None, UtopiaModule)
UtopiaModule.GetCurrentFriendlyFire = new.instancemethod(Appc.UtopiaModule_GetCurrentFriendlyFire, None, UtopiaModule)
UtopiaModule.SetCurrentFriendlyFire = new.instancemethod(Appc.UtopiaModule_SetCurrentFriendlyFire, None, UtopiaModule)
UtopiaModule.GetFriendlyFireWarningPoints = new.instancemethod(Appc.UtopiaModule_GetFriendlyFireWarningPoints, None, UtopiaModule)
UtopiaModule.SetFriendlyFireWarningPoints = new.instancemethod(Appc.UtopiaModule_SetFriendlyFireWarningPoints, None, UtopiaModule)
UtopiaModule.GetFriendlyTractorTime = new.instancemethod(Appc.UtopiaModule_GetFriendlyTractorTime, None, UtopiaModule)
UtopiaModule.SetFriendlyTractorTime = new.instancemethod(Appc.UtopiaModule_SetFriendlyTractorTime, None, UtopiaModule)
UtopiaModule.GetFriendlyTractorWarning = new.instancemethod(Appc.UtopiaModule_GetFriendlyTractorWarning, None, UtopiaModule)
UtopiaModule.SetFriendlyTractorWarning = new.instancemethod(Appc.UtopiaModule_SetFriendlyTractorWarning, None, UtopiaModule)
UtopiaModule.GetMaxFriendlyTractorTime = new.instancemethod(Appc.UtopiaModule_GetMaxFriendlyTractorTime, None, UtopiaModule)
UtopiaModule.SetMaxFriendlyTractorTime = new.instancemethod(Appc.UtopiaModule_SetMaxFriendlyTractorTime, None, UtopiaModule)
UtopiaModule.GetTestMenuState = new.instancemethod(Appc.UtopiaModule_GetTestMenuState, None, UtopiaModule)

class UtopiaApp:
    def __init__(self,*args):
        self.this = apply(Appc.new_UtopiaApp,args)
        self.thisown = 1

    def __repr__(self):
        return "<C UtopiaApp instance at %s>" % (self.this,)
class UtopiaAppPtr(UtopiaApp):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = UtopiaApp


UtopiaApp.IsFullscreen = new.instancemethod(Appc.UtopiaApp_IsFullscreen, None, UtopiaApp)
UtopiaApp.GetWidth = new.instancemethod(Appc.UtopiaApp_GetWidth, None, UtopiaApp)
UtopiaApp.GetHeight = new.instancemethod(Appc.UtopiaApp_GetHeight, None, UtopiaApp)
UtopiaApp.GetBitDepth = new.instancemethod(Appc.UtopiaApp_GetBitDepth, None, UtopiaApp)
UtopiaApp.GetDeviceDesc = new.instancemethod(Appc.UtopiaApp_GetDeviceDesc, None, UtopiaApp)
UtopiaApp.IsDirectStart = new.instancemethod(Appc.UtopiaApp_IsDirectStart, None, UtopiaApp)
UtopiaApp.GetTestMenuState = new.instancemethod(Appc.UtopiaApp_GetTestMenuState, None, UtopiaApp)
UtopiaApp.SetTestMenuState = new.instancemethod(Appc.UtopiaApp_SetTestMenuState, None, UtopiaApp)
UtopiaApp.SetFrameRate = new.instancemethod(Appc.UtopiaApp_SetFrameRate, None, UtopiaApp)

class NiMatrix3:
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C NiMatrix3 instance at %s>" % (self.this,)
class NiMatrix3Ptr(NiMatrix3):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = NiMatrix3



class TGMatrix3(NiMatrix3):
    def __init__(self,*args):
        self.this = apply(Appc.new_TGMatrix3,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGMatrix3(self)
    def Inverse(*args):
        val = apply(Appc.TGMatrix3_Inverse,args)
        if val: val = TGMatrix3Ptr(val) ; val.thisown = 1
        return val
    def Transpose(*args):
        val = apply(Appc.TGMatrix3_Transpose,args)
        if val: val = TGMatrix3Ptr(val) ; val.thisown = 1
        return val
    def MultMatrix(*args):
        val = apply(Appc.TGMatrix3_MultMatrix,args)
        if val: val = TGMatrix3Ptr(val) ; val.thisown = 1
        return val
    def MultMatrixLeft(*args):
        val = apply(Appc.TGMatrix3_MultMatrixLeft,args)
        if val: val = TGMatrix3Ptr(val) ; val.thisown = 1
        return val
    def TransposeTimes(*args):
        val = apply(Appc.TGMatrix3_TransposeTimes,args)
        if val: val = TGMatrix3Ptr(val) ; val.thisown = 1
        return val
    def Congruence(*args):
        val = apply(Appc.TGMatrix3_Congruence,args)
        if val: val = TGMatrix3Ptr(val) ; val.thisown = 1
        return val
    def __repr__(self):
        return "<C TGMatrix3 instance at %s>" % (self.this,)
class TGMatrix3Ptr(TGMatrix3):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGMatrix3


TGMatrix3.GetRow = new.instancemethod(Appc.TGMatrix3_GetRow, None, TGMatrix3)
TGMatrix3.SetRow = new.instancemethod(Appc.TGMatrix3_SetRow, None, TGMatrix3)
TGMatrix3.GetCol = new.instancemethod(Appc.TGMatrix3_GetCol, None, TGMatrix3)
TGMatrix3.SetCol = new.instancemethod(Appc.TGMatrix3_SetCol, None, TGMatrix3)
TGMatrix3.GetEntry = new.instancemethod(Appc.TGMatrix3_GetEntry, None, TGMatrix3)
TGMatrix3.SetEntry = new.instancemethod(Appc.TGMatrix3_SetEntry, None, TGMatrix3)
TGMatrix3.MakeZero = new.instancemethod(Appc.TGMatrix3_MakeZero, None, TGMatrix3)
TGMatrix3.MakeIdentity = new.instancemethod(Appc.TGMatrix3_MakeIdentity, None, TGMatrix3)
TGMatrix3.MakeDiagonal = new.instancemethod(Appc.TGMatrix3_MakeDiagonal, None, TGMatrix3)
TGMatrix3.MakeXRotation = new.instancemethod(Appc.TGMatrix3_MakeXRotation, None, TGMatrix3)
TGMatrix3.MakeYRotation = new.instancemethod(Appc.TGMatrix3_MakeYRotation, None, TGMatrix3)
TGMatrix3.MakeZRotation = new.instancemethod(Appc.TGMatrix3_MakeZRotation, None, TGMatrix3)
TGMatrix3.MakeRotation = new.instancemethod(Appc.TGMatrix3_MakeRotation, None, TGMatrix3)
TGMatrix3.Set = new.instancemethod(Appc.TGMatrix3_Set, None, TGMatrix3)
TGMatrix3.ExtractAngleAndAxis = new.instancemethod(Appc.TGMatrix3_ExtractAngleAndAxis, None, TGMatrix3)
TGMatrix3.ToEulerAnglesXYZ = new.instancemethod(Appc.TGMatrix3_ToEulerAnglesXYZ, None, TGMatrix3)
TGMatrix3.ToEulerAnglesXZY = new.instancemethod(Appc.TGMatrix3_ToEulerAnglesXZY, None, TGMatrix3)
TGMatrix3.ToEulerAnglesYXZ = new.instancemethod(Appc.TGMatrix3_ToEulerAnglesYXZ, None, TGMatrix3)
TGMatrix3.ToEulerAnglesYZX = new.instancemethod(Appc.TGMatrix3_ToEulerAnglesYZX, None, TGMatrix3)
TGMatrix3.ToEulerAnglesZXY = new.instancemethod(Appc.TGMatrix3_ToEulerAnglesZXY, None, TGMatrix3)
TGMatrix3.ToEulerAnglesZYX = new.instancemethod(Appc.TGMatrix3_ToEulerAnglesZYX, None, TGMatrix3)
TGMatrix3.FromEulerAnglesXYZ = new.instancemethod(Appc.TGMatrix3_FromEulerAnglesXYZ, None, TGMatrix3)
TGMatrix3.FromEulerAnglesXZY = new.instancemethod(Appc.TGMatrix3_FromEulerAnglesXZY, None, TGMatrix3)
TGMatrix3.FromEulerAnglesYXZ = new.instancemethod(Appc.TGMatrix3_FromEulerAnglesYXZ, None, TGMatrix3)
TGMatrix3.FromEulerAnglesYZX = new.instancemethod(Appc.TGMatrix3_FromEulerAnglesYZX, None, TGMatrix3)
TGMatrix3.FromEulerAnglesZXY = new.instancemethod(Appc.TGMatrix3_FromEulerAnglesZXY, None, TGMatrix3)
TGMatrix3.FromEulerAnglesZYX = new.instancemethod(Appc.TGMatrix3_FromEulerAnglesZYX, None, TGMatrix3)
TGMatrix3.Reorthogonalize = new.instancemethod(Appc.TGMatrix3_Reorthogonalize, None, TGMatrix3)
TGMatrix3.EigenSolveSymmetric = new.instancemethod(Appc.TGMatrix3_EigenSolveSymmetric, None, TGMatrix3)

class TGPoint3(NiPoint3):
    def __init__(self,*args):
        self.this = apply(Appc.new_TGPoint3,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGPoint3(self)
    def Cross(*args):
        val = apply(Appc.TGPoint3_Cross,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def UnitCross(*args):
        val = apply(Appc.TGPoint3_UnitCross,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetAlignedComponent(*args):
        val = apply(Appc.TGPoint3_GetAlignedComponent,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetPerpendicularComponent(*args):
        val = apply(Appc.TGPoint3_GetPerpendicularComponent,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    __setmethods__ = {
        "x" : Appc.TGPoint3_x_set,
        "y" : Appc.TGPoint3_y_set,
        "z" : Appc.TGPoint3_z_set,
    }
    def __setattr__(self,name,value):
        if (name == "this") or (name == "thisown"): self.__dict__[name] = value; return
        method = TGPoint3.__setmethods__.get(name,None)
        if method: return method(self,value)
        self.__dict__[name] = value
    __getmethods__ = {
        "x" : Appc.TGPoint3_x_get,
        "y" : Appc.TGPoint3_y_get,
        "z" : Appc.TGPoint3_z_get,
    }
    def __getattr__(self,name):
        method = TGPoint3.__getmethods__.get(name,None)
        if method: return method(self)
        raise AttributeError,name
    def __repr__(self):
        return "<C TGPoint3 instance at %s>" % (self.this,)
class TGPoint3Ptr(TGPoint3):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGPoint3


TGPoint3.GetX = new.instancemethod(Appc.TGPoint3_GetX, None, TGPoint3)
TGPoint3.GetY = new.instancemethod(Appc.TGPoint3_GetY, None, TGPoint3)
TGPoint3.GetZ = new.instancemethod(Appc.TGPoint3_GetZ, None, TGPoint3)
TGPoint3.SetX = new.instancemethod(Appc.TGPoint3_SetX, None, TGPoint3)
TGPoint3.SetY = new.instancemethod(Appc.TGPoint3_SetY, None, TGPoint3)
TGPoint3.SetZ = new.instancemethod(Appc.TGPoint3_SetZ, None, TGPoint3)
TGPoint3.SetXYZ = new.instancemethod(Appc.TGPoint3_SetXYZ, None, TGPoint3)
TGPoint3.MultMatrix = new.instancemethod(Appc.TGPoint3_MultMatrix, None, TGPoint3)
TGPoint3.MultMatrixLeft = new.instancemethod(Appc.TGPoint3_MultMatrixLeft, None, TGPoint3)
TGPoint3.Add = new.instancemethod(Appc.TGPoint3_Add, None, TGPoint3)
TGPoint3.Subtract = new.instancemethod(Appc.TGPoint3_Subtract, None, TGPoint3)
TGPoint3.Scale = new.instancemethod(Appc.TGPoint3_Scale, None, TGPoint3)
TGPoint3.Set = new.instancemethod(Appc.TGPoint3_Set, None, TGPoint3)
TGPoint3.LoadBinary = new.instancemethod(Appc.TGPoint3_LoadBinary, None, TGPoint3)
TGPoint3.SaveBinary = new.instancemethod(Appc.TGPoint3_SaveBinary, None, TGPoint3)

class TGColorA(NiColorA):
    def __init__(self,*args):
        self.this = apply(Appc.new_TGColorA,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGColorA(self)
    __setmethods__ = {
        "r" : Appc.TGColorA_r_set,
        "g" : Appc.TGColorA_g_set,
        "b" : Appc.TGColorA_b_set,
        "a" : Appc.TGColorA_a_set,
    }
    def __setattr__(self,name,value):
        if (name == "this") or (name == "thisown"): self.__dict__[name] = value; return
        method = TGColorA.__setmethods__.get(name,None)
        if method: return method(self,value)
        self.__dict__[name] = value
    __getmethods__ = {
        "r" : Appc.TGColorA_r_get,
        "g" : Appc.TGColorA_g_get,
        "b" : Appc.TGColorA_b_get,
        "a" : Appc.TGColorA_a_get,
    }
    def __getattr__(self,name):
        method = TGColorA.__getmethods__.get(name,None)
        if method: return method(self)
        raise AttributeError,name
    def __repr__(self):
        return "<C TGColorA instance at %s>" % (self.this,)
class TGColorAPtr(TGColorA):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGColorA


TGColorA.GetR = new.instancemethod(Appc.TGColorA_GetR, None, TGColorA)
TGColorA.GetG = new.instancemethod(Appc.TGColorA_GetG, None, TGColorA)
TGColorA.GetB = new.instancemethod(Appc.TGColorA_GetB, None, TGColorA)
TGColorA.GetA = new.instancemethod(Appc.TGColorA_GetA, None, TGColorA)
TGColorA.SetR = new.instancemethod(Appc.TGColorA_SetR, None, TGColorA)
TGColorA.SetG = new.instancemethod(Appc.TGColorA_SetG, None, TGColorA)
TGColorA.SetB = new.instancemethod(Appc.TGColorA_SetB, None, TGColorA)
TGColorA.SetA = new.instancemethod(Appc.TGColorA_SetA, None, TGColorA)
TGColorA.SetRGBA = new.instancemethod(Appc.TGColorA_SetRGBA, None, TGColorA)
TGColorA.Copy = new.instancemethod(Appc.TGColorA_Copy, None, TGColorA)
TGColorA.ScaleRGB = new.instancemethod(Appc.TGColorA_ScaleRGB, None, TGColorA)

class SetClass(TGEventHandlerObject):
    def __init__(self,this):
        self.this = this

    def GetProximityManager(*args):
        val = apply(Appc.SetClass_GetProximityManager,args)
        if val: val = ProximityManagerPtr(val) 
        return val
    def RemoveObjectFromSet(*args):
        val = apply(Appc.SetClass_RemoveObjectFromSet,args)
        if val: val = ObjectClassPtr(val) 
        return val
    def GetObject(*args):
        val = apply(Appc.SetClass_GetObject,args)
        if val: val = ObjectClassPtr(val) 
        return val
    def GetObjectByID(*args):
        val = apply(Appc.SetClass_GetObjectByID,args)
        if val: val = ObjectClassPtr(val) 
        return val
    def GetFirstObject(*args):
        val = apply(Appc.SetClass_GetFirstObject,args)
        if val: val = ObjectClassPtr(val) 
        return val
    def GetNextObject(*args):
        val = apply(Appc.SetClass_GetNextObject,args)
        if val: val = ObjectClassPtr(val) 
        return val
    def GetPreviousObject(*args):
        val = apply(Appc.SetClass_GetPreviousObject,args)
        if val: val = ObjectClassPtr(val) 
        return val
    def GetSceneRoot(*args):
        val = apply(Appc.SetClass_GetSceneRoot,args)
        if val: val = NiNodePtr(val) 
        return val
    def GetEffectRoot(*args):
        val = apply(Appc.SetClass_GetEffectRoot,args)
        if val: val = NiNodePtr(val) 
        return val
    def GetBackdropRoot(*args):
        val = apply(Appc.SetClass_GetBackdropRoot,args)
        if val: val = NiNodePtr(val) 
        return val
    def GetForegroundRoot(*args):
        val = apply(Appc.SetClass_GetForegroundRoot,args)
        if val: val = NiNodePtr(val) 
        return val
    def GetCamera(*args):
        val = apply(Appc.SetClass_GetCamera,args)
        if val: val = CameraObjectClassPtr(val) 
        return val
    def GetActiveCamera(*args):
        val = apply(Appc.SetClass_GetActiveCamera,args)
        if val: val = CameraObjectClassPtr(val) 
        return val
    def GetLight(*args):
        val = apply(Appc.SetClass_GetLight,args)
        if val: val = LightObjectClassPtr(val) 
        return val
    def GetPickedObject(*args):
        val = apply(Appc.SetClass_GetPickedObject,args)
        if val: val = ObjectClassPtr(val) 
        return val
    def GetNebula(*args):
        val = apply(Appc.SetClass_GetNebula,args)
        if val: val = NebulaPtr(val) 
        return val
    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEventHandlerObject(self)
    def __repr__(self):
        return "<C SetClass instance at %s>" % (self.this,)
class SetClassPtr(SetClass):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = SetClass


SetClass.SetProximityManagerActive = new.instancemethod(Appc.SetClass_SetProximityManagerActive, None, SetClass)
SetClass.SetRegionModule = new.instancemethod(Appc.SetClass_SetRegionModule, None, SetClass)
SetClass.GetRegionModule = new.instancemethod(Appc.SetClass_GetRegionModule, None, SetClass)
SetClass.AddObjectToSet = new.instancemethod(Appc.SetClass_AddObjectToSet, None, SetClass)
SetClass.IsRendered = new.instancemethod(Appc.SetClass_IsRendered, None, SetClass)
SetClass.CalcIsRendered = new.instancemethod(Appc.SetClass_CalcIsRendered, None, SetClass)
SetClass.AddBackdropToSet = new.instancemethod(Appc.SetClass_AddBackdropToSet, None, SetClass)
SetClass.RemoveBackdropFromSet = new.instancemethod(Appc.SetClass_RemoveBackdropFromSet, None, SetClass)
SetClass.SetBackgroundModel = new.instancemethod(Appc.SetClass_SetBackgroundModel, None, SetClass)
SetClass.RemoveBackgroundModel = new.instancemethod(Appc.SetClass_RemoveBackgroundModel, None, SetClass)
SetClass.DeleteObjectFromSet = new.instancemethod(Appc.SetClass_DeleteObjectFromSet, None, SetClass)
SetClass.IsLocationEmptyTG = new.instancemethod(Appc.SetClass_IsLocationEmptyTG, None, SetClass)
SetClass.GetDisplayName = new.instancemethod(Appc.SetClass_GetDisplayName, None, SetClass)
SetClass.GetName = new.instancemethod(Appc.SetClass_GetName, None, SetClass)
SetClass.SetName = new.instancemethod(Appc.SetClass_SetName, None, SetClass)
SetClass.CreateCamera = new.instancemethod(Appc.SetClass_CreateCamera, None, SetClass)
SetClass.AddCameraToSet = new.instancemethod(Appc.SetClass_AddCameraToSet, None, SetClass)
SetClass.RemoveCameraFromSet = new.instancemethod(Appc.SetClass_RemoveCameraFromSet, None, SetClass)
SetClass.DeleteCameraFromSet = new.instancemethod(Appc.SetClass_DeleteCameraFromSet, None, SetClass)
SetClass.SetActiveCamera = new.instancemethod(Appc.SetClass_SetActiveCamera, None, SetClass)
SetClass.CreateAmbientLight = new.instancemethod(Appc.SetClass_CreateAmbientLight, None, SetClass)
SetClass.CreateDirectionalLight = new.instancemethod(Appc.SetClass_CreateDirectionalLight, None, SetClass)
SetClass.DeleteLightFromSet = new.instancemethod(Appc.SetClass_DeleteLightFromSet, None, SetClass)
SetClass.StartPick = new.instancemethod(Appc.SetClass_StartPick, None, SetClass)
SetClass.GetDotProductToObject = new.instancemethod(Appc.SetClass_GetDotProductToObject, None, SetClass)
SetClass.GetDotProductToVector = new.instancemethod(Appc.SetClass_GetDotProductToVector, None, SetClass)
SetClass.SetGlowIntensity = new.instancemethod(Appc.SetClass_SetGlowIntensity, None, SetClass)

class SetManager:
    def __init__(self,this):
        self.this = this

    def GetSet(*args):
        val = apply(Appc.SetManager_GetSet,args)
        if val: val = SetClassPtr(val) 
        return val
    def GetRenderedSet(*args):
        val = apply(Appc.SetManager_GetRenderedSet,args)
        if val: val = SetClassPtr(val) 
        return val
    def __repr__(self):
        return "<C SetManager instance at %s>" % (self.this,)
class SetManagerPtr(SetManager):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = SetManager


SetManager.Terminate = new.instancemethod(Appc.SetManager_Terminate, None, SetManager)
SetManager.AddSet = new.instancemethod(Appc.SetManager_AddSet, None, SetManager)
SetManager.RemoveSet = new.instancemethod(Appc.SetManager_RemoveSet, None, SetManager)
SetManager.DeleteSet = new.instancemethod(Appc.SetManager_DeleteSet, None, SetManager)
SetManager.DeleteAllSets = new.instancemethod(Appc.SetManager_DeleteAllSets, None, SetManager)
SetManager.GetNumSets = new.instancemethod(Appc.SetManager_GetNumSets, None, SetManager)
SetManager.ClearRenderedSet = new.instancemethod(Appc.SetManager_ClearRenderedSet, None, SetManager)
SetManager.MakeRenderedSet = new.instancemethod(Appc.SetManager_MakeRenderedSet, None, SetManager)

class ScriptObject(TGEventHandlerObject):
    def __init__(self,*args):
        self.this = apply(Appc.new_ScriptObject,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_ScriptObject(self)
    def LoadSound(*args):
        val = apply(Appc.ScriptObject_LoadSound,args)
        if val: val = TGSoundPtr(val) 
        return val
    def LoadDatabaseSound(*args):
        val = apply(Appc.ScriptObject_LoadDatabaseSound,args)
        if val: val = TGSoundPtr(val) 
        return val
    def SetDatabase(*args):
        val = apply(Appc.ScriptObject_SetDatabase,args)
        if val: val = TGLocalizationDatabasePtr(val) 
        return val
    def GetDatabase(*args):
        val = apply(Appc.ScriptObject_GetDatabase,args)
        if val: val = TGLocalizationDatabasePtr(val) 
        return val
    def __repr__(self):
        return "<C ScriptObject instance at %s>" % (self.this,)
class ScriptObjectPtr(ScriptObject):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = ScriptObject


ScriptObject.GetInstanceNextEventType = new.instancemethod(Appc.ScriptObject_GetInstanceNextEventType, None, ScriptObject)
ScriptObject.GetScript = new.instancemethod(Appc.ScriptObject_GetScript, None, ScriptObject)
ScriptObject.SetEventCount = new.instancemethod(Appc.ScriptObject_SetEventCount, None, ScriptObject)
ScriptObject.SetOnIdleFunc = new.instancemethod(Appc.ScriptObject_SetOnIdleFunc, None, ScriptObject)
ScriptObject.SetAssetsLoaded = new.instancemethod(Appc.ScriptObject_SetAssetsLoaded, None, ScriptObject)
ScriptObject.AreAssetsLoaded = new.instancemethod(Appc.ScriptObject_AreAssetsLoaded, None, ScriptObject)
ScriptObject.PreLoadAssets = new.instancemethod(Appc.ScriptObject_PreLoadAssets, None, ScriptObject)
ScriptObject.Initialize = new.instancemethod(Appc.ScriptObject_Initialize, None, ScriptObject)
ScriptObject.Load = new.instancemethod(Appc.ScriptObject_Load, None, ScriptObject)
ScriptObject.OnIdle = new.instancemethod(Appc.ScriptObject_OnIdle, None, ScriptObject)
ScriptObject.Unload = new.instancemethod(Appc.ScriptObject_Unload, None, ScriptObject)
ScriptObject.Terminate = new.instancemethod(Appc.ScriptObject_Terminate, None, ScriptObject)
ScriptObject.AddPersistentModule = new.instancemethod(Appc.ScriptObject_AddPersistentModule, None, ScriptObject)

class Game(ScriptObject):
    EASY = Appc.Game_EASY
    MEDIUM = Appc.Game_MEDIUM
    HARD = Appc.Game_HARD
    def __init__(self,*args):
        self.this = apply(Appc.new_Game,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_Game(self)
    def GetCurrentEpisode(*args):
        val = apply(Appc.Game_GetCurrentEpisode,args)
        if val: val = EpisodePtr(val) 
        return val
    def LoadSoundInGroup(*args):
        val = apply(Appc.Game_LoadSoundInGroup,args)
        if val: val = TGSoundPtr(val) 
        return val
    def LoadDatabaseSoundInGroup(*args):
        val = apply(Appc.Game_LoadDatabaseSoundInGroup,args)
        if val: val = TGSoundPtr(val) 
        return val
    def GetPlayer(*args):
        val = apply(Appc.Game_GetPlayer,args)
        if val: val = ShipClassPtr(val) 
        return val
    def GetPlayerGroup(*args):
        val = apply(Appc.Game_GetPlayerGroup,args)
        if val: val = ObjectGroupPtr(val) 
        return val
    def GetPlayerSet(*args):
        val = apply(Appc.Game_GetPlayerSet,args)
        if val: val = SetClassPtr(val) 
        return val
    def GetPlayerCamera(*args):
        val = apply(Appc.Game_GetPlayerCamera,args)
        if val: val = CameraObjectClassPtr(val) 
        return val
    def __repr__(self):
        return "<C Game instance at %s>" % (self.this,)
class GamePtr(Game):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = Game


Game.SetPlayer = new.instancemethod(Appc.Game_SetPlayer, None, Game)
Game.SetLastSavedGame = new.instancemethod(Appc.Game_SetLastSavedGame, None, Game)
Game.SetPreLoadDoneEvent = new.instancemethod(Appc.Game_SetPreLoadDoneEvent, None, Game)
Game.LoadEpisode = new.instancemethod(Appc.Game_LoadEpisode, None, Game)
Game.GetScore = new.instancemethod(Appc.Game_GetScore, None, Game)
Game.GetRating = new.instancemethod(Appc.Game_GetRating, None, Game)
Game.GetKills = new.instancemethod(Appc.Game_GetKills, None, Game)
Game.GetTorpsFired = new.instancemethod(Appc.Game_GetTorpsFired, None, Game)
Game.GetTorpsHit = new.instancemethod(Appc.Game_GetTorpsHit, None, Game)
Game.GetLastSavedGame = new.instancemethod(Appc.Game_GetLastSavedGame, None, Game)
Game.SetUIShipID = new.instancemethod(Appc.Game_SetUIShipID, None, Game)
Game.SetGodMode = new.instancemethod(Appc.Game_SetGodMode, None, Game)
Game.InGodMode = new.instancemethod(Appc.Game_InGodMode, None, Game)
Game.Terminate = new.instancemethod(Appc.Game_Terminate, None, Game)

class Episode(ScriptObject):
    def __init__(self,this):
        self.this = this

    def GetCurrentMission(*args):
        val = apply(Appc.Episode_GetCurrentMission,args)
        if val: val = MissionPtr(val) 
        return val
    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_ScriptObject(self)
    def __repr__(self):
        return "<C Episode instance at %s>" % (self.this,)
class EpisodePtr(Episode):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = Episode


Episode.LoadMission = new.instancemethod(Appc.Episode_LoadMission, None, Episode)
Episode.RegisterGoal = new.instancemethod(Appc.Episode_RegisterGoal, None, Episode)
Episode.RemoveGoal = new.instancemethod(Appc.Episode_RemoveGoal, None, Episode)

class Mission(ScriptObject):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_Mission(self)
    def GetPrecreatedShip(*args):
        val = apply(Appc.Mission_GetPrecreatedShip,args)
        if val: val = ShipClassPtr(val) 
        return val
    def __repr__(self):
        return "<C Mission instance at %s>" % (self.this,)
class MissionPtr(Mission):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = Mission


Mission.AddPrecreatedShip = new.instancemethod(Appc.Mission_AddPrecreatedShip, None, Mission)

class BaseObjectClass(TGEventHandlerObject):
    def __init__(self,this):
        self.this = this

    def GetNode(*args):
        val = apply(Appc.BaseObjectClass_GetNode,args)
        if val: val = NiNodePtr(val) 
        return val
    def GetContainingSet(*args):
        val = apply(Appc.BaseObjectClass_GetContainingSet,args)
        if val: val = SetClassPtr(val) 
        return val
    def GetNiObject(*args):
        val = apply(Appc.BaseObjectClass_GetNiObject,args)
        if val: val = NiAVObjectPtr(val) 
        return val
    def GetAnimNode(*args):
        val = apply(Appc.BaseObjectClass_GetAnimNode,args)
        if val: val = TGAnimNodePtr(val) 
        return val
    def GetWorldLocation(*args):
        val = apply(Appc.BaseObjectClass_GetWorldLocation,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetTranslate(*args):
        val = apply(Appc.BaseObjectClass_GetTranslate,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetRotation(*args):
        val = apply(Appc.BaseObjectClass_GetRotation,args)
        if val: val = TGMatrix3Ptr(val) ; val.thisown = 1
        return val
    def GetWorldRotation(*args):
        val = apply(Appc.BaseObjectClass_GetWorldRotation,args)
        if val: val = TGMatrix3Ptr(val) ; val.thisown = 1
        return val
    def GetDisplayName(*args):
        val = apply(Appc.BaseObjectClass_GetDisplayName,args)
        if val: val = TGStringPtr(val) ; val.thisown = 1
        return val
    def GetWorldForwardTG(*args):
        val = apply(Appc.BaseObjectClass_GetWorldForwardTG,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetWorldBackwardTG(*args):
        val = apply(Appc.BaseObjectClass_GetWorldBackwardTG,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetWorldUpTG(*args):
        val = apply(Appc.BaseObjectClass_GetWorldUpTG,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetWorldDownTG(*args):
        val = apply(Appc.BaseObjectClass_GetWorldDownTG,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetWorldRightTG(*args):
        val = apply(Appc.BaseObjectClass_GetWorldRightTG,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetWorldLeftTG(*args):
        val = apply(Appc.BaseObjectClass_GetWorldLeftTG,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEventHandlerObject(self)
    def __repr__(self):
        return "<C BaseObjectClass instance at %s>" % (self.this,)
class BaseObjectClassPtr(BaseObjectClass):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = BaseObjectClass


BaseObjectClass.Update = new.instancemethod(Appc.BaseObjectClass_Update, None, BaseObjectClass)
BaseObjectClass.UpdateNodeOnly = new.instancemethod(Appc.BaseObjectClass_UpdateNodeOnly, None, BaseObjectClass)
BaseObjectClass.AttachObject = new.instancemethod(Appc.BaseObjectClass_AttachObject, None, BaseObjectClass)
BaseObjectClass.DetachObject = new.instancemethod(Appc.BaseObjectClass_DetachObject, None, BaseObjectClass)
BaseObjectClass.SetDeleteMe = new.instancemethod(Appc.BaseObjectClass_SetDeleteMe, None, BaseObjectClass)
BaseObjectClass.SetHidden = new.instancemethod(Appc.BaseObjectClass_SetHidden, None, BaseObjectClass)
BaseObjectClass.IsHidden = new.instancemethod(Appc.BaseObjectClass_IsHidden, None, BaseObjectClass)
BaseObjectClass.SetName = new.instancemethod(Appc.BaseObjectClass_SetName, None, BaseObjectClass)
BaseObjectClass.GetName = new.instancemethod(Appc.BaseObjectClass_GetName, None, BaseObjectClass)
BaseObjectClass.SetDisplayName = new.instancemethod(Appc.BaseObjectClass_SetDisplayName, None, BaseObjectClass)
BaseObjectClass.Rotate = new.instancemethod(Appc.BaseObjectClass_Rotate, None, BaseObjectClass)
BaseObjectClass.SetTranslateXYZ = new.instancemethod(Appc.BaseObjectClass_SetTranslateXYZ, None, BaseObjectClass)
BaseObjectClass.SetTranslate = new.instancemethod(Appc.BaseObjectClass_SetTranslate, None, BaseObjectClass)
BaseObjectClass.SetAngleAxisRotation = new.instancemethod(Appc.BaseObjectClass_SetAngleAxisRotation, None, BaseObjectClass)
BaseObjectClass.SetMatrixRotation = new.instancemethod(Appc.BaseObjectClass_SetMatrixRotation, None, BaseObjectClass)
BaseObjectClass.SetScale = new.instancemethod(Appc.BaseObjectClass_SetScale, None, BaseObjectClass)
BaseObjectClass.GetScale = new.instancemethod(Appc.BaseObjectClass_GetScale, None, BaseObjectClass)
BaseObjectClass.AlignToVectors = new.instancemethod(Appc.BaseObjectClass_AlignToVectors, None, BaseObjectClass)

class ObjectClass(BaseObjectClass):
    CFB_NO_COLLISIONS = Appc.ObjectClass_CFB_NO_COLLISIONS
    CFB_IN_PROXIMITY_MANAGER = Appc.ObjectClass_CFB_IN_PROXIMITY_MANAGER
    CFB_MEMBER_GROUP_1 = Appc.ObjectClass_CFB_MEMBER_GROUP_1
    CFB_COLLIDES_WITH_GROUP_1 = Appc.ObjectClass_CFB_COLLIDES_WITH_GROUP_1
    CFB_MEMBER_GROUP_2 = Appc.ObjectClass_CFB_MEMBER_GROUP_2
    CFB_COLLIDES_WITH_GROUP_2 = Appc.ObjectClass_CFB_COLLIDES_WITH_GROUP_2
    CFB_MEMBER_GROUP_3 = Appc.ObjectClass_CFB_MEMBER_GROUP_3
    CFB_COLLIDES_WITH_GROUP_3 = Appc.ObjectClass_CFB_COLLIDES_WITH_GROUP_3
    CFB_MEMBER_MASK = Appc.ObjectClass_CFB_MEMBER_MASK
    CFB_COLLISION_MASK = Appc.ObjectClass_CFB_COLLISION_MASK
    CFB_DEFAULTS = Appc.ObjectClass_CFB_DEFAULTS
    def __init__(self,this):
        self.this = this

    def GetRandomPointOnModel(*args):
        val = apply(Appc.ObjectClass_GetRandomPointOnModel,args)
        if val: val = NiAVObjectPtr(val) 
        return val
    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEventHandlerObject(self)
    def __repr__(self):
        return "<C ObjectClass instance at %s>" % (self.this,)
class ObjectClassPtr(ObjectClass):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = ObjectClass


ObjectClass.GetRadius = new.instancemethod(Appc.ObjectClass_GetRadius, None, ObjectClass)
ObjectClass.PlaceObjectByName = new.instancemethod(Appc.ObjectClass_PlaceObjectByName, None, ObjectClass)
ObjectClass.RandomOrientation = new.instancemethod(Appc.ObjectClass_RandomOrientation, None, ObjectClass)
ObjectClass.AlignToObject = new.instancemethod(Appc.ObjectClass_AlignToObject, None, ObjectClass)
ObjectClass.IsTargetable = new.instancemethod(Appc.ObjectClass_IsTargetable, None, ObjectClass)
ObjectClass.CanTargetObject = new.instancemethod(Appc.ObjectClass_CanTargetObject, None, ObjectClass)
ObjectClass.SetHailable = new.instancemethod(Appc.ObjectClass_SetHailable, None, ObjectClass)
ObjectClass.IsHailable = new.instancemethod(Appc.ObjectClass_IsHailable, None, ObjectClass)
ObjectClass.SetScannable = new.instancemethod(Appc.ObjectClass_SetScannable, None, ObjectClass)
ObjectClass.IsScannable = new.instancemethod(Appc.ObjectClass_IsScannable, None, ObjectClass)
ObjectClass.GetLocalRandomPointAndNormalOnModel = new.instancemethod(Appc.ObjectClass_GetLocalRandomPointAndNormalOnModel, None, ObjectClass)
ObjectClass.SetCollisionFlags = new.instancemethod(Appc.ObjectClass_SetCollisionFlags, None, ObjectClass)
ObjectClass.GetCollisionFlags = new.instancemethod(Appc.ObjectClass_GetCollisionFlags, None, ObjectClass)
ObjectClass.LineCollides = new.instancemethod(Appc.ObjectClass_LineCollides, None, ObjectClass)
ObjectClass.ReplaceTexture = new.instancemethod(Appc.ObjectClass_ReplaceTexture, None, ObjectClass)
ObjectClass.RefreshReplacedTextures = new.instancemethod(Appc.ObjectClass_RefreshReplacedTextures, None, ObjectClass)

class CameraObjectClass(BaseObjectClass):
    def __init__(self,this):
        self.this = this

    def GetNiFrustum(*args):
        val = apply(Appc.CameraObjectClass_GetNiFrustum,args)
        if val: val = NiFrustumPtr(val) ; val.thisown = 1
        return val
    def GetCurrentCameraMode(*args):
        val = apply(Appc.CameraObjectClass_GetCurrentCameraMode,args)
        if val: val = CameraModePtr(val) 
        return val
    def GetNamedCameraMode(*args):
        val = apply(Appc.CameraObjectClass_GetNamedCameraMode,args)
        if val: val = CameraModePtr(val) 
        return val
    def GetWorldForward(*args):
        val = apply(Appc.CameraObjectClass_GetWorldForward,args)
        if val: val = NiPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetWorldUp(*args):
        val = apply(Appc.CameraObjectClass_GetWorldUp,args)
        if val: val = NiPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetWorldRight(*args):
        val = apply(Appc.CameraObjectClass_GetWorldRight,args)
        if val: val = NiPoint3Ptr(val) ; val.thisown = 1
        return val
    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEventHandlerObject(self)
    def __repr__(self):
        return "<C CameraObjectClass instance at %s>" % (self.this,)
class CameraObjectClassPtr(CameraObjectClass):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = CameraObjectClass


CameraObjectClass.SetFrustumValues = new.instancemethod(Appc.CameraObjectClass_SetFrustumValues, None, CameraObjectClass)
CameraObjectClass.SetFrustum = new.instancemethod(Appc.CameraObjectClass_SetFrustum, None, CameraObjectClass)
CameraObjectClass.SetNearAndFarDistance = new.instancemethod(Appc.CameraObjectClass_SetNearAndFarDistance, None, CameraObjectClass)
CameraObjectClass.SetNiFrustum = new.instancemethod(Appc.CameraObjectClass_SetNiFrustum, None, CameraObjectClass)
CameraObjectClass.PushCameraMode = new.instancemethod(Appc.CameraObjectClass_PushCameraMode, None, CameraObjectClass)
CameraObjectClass.PopCameraMode = new.instancemethod(Appc.CameraObjectClass_PopCameraMode, None, CameraObjectClass)
CameraObjectClass.AddModeHierarchy = new.instancemethod(Appc.CameraObjectClass_AddModeHierarchy, None, CameraObjectClass)
CameraObjectClass.AddNamedCameraMode = new.instancemethod(Appc.CameraObjectClass_AddNamedCameraMode, None, CameraObjectClass)
CameraObjectClass.Zoom = new.instancemethod(Appc.CameraObjectClass_Zoom, None, CameraObjectClass)
CameraObjectClass.LookToward = new.instancemethod(Appc.CameraObjectClass_LookToward, None, CameraObjectClass)

class SpaceCamera(CameraObjectClass):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEventHandlerObject(self)
    def __repr__(self):
        return "<C SpaceCamera instance at %s>" % (self.this,)
class SpaceCameraPtr(SpaceCamera):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = SpaceCamera


SpaceCamera.IsSpaceDustEnabled = new.instancemethod(Appc.SpaceCamera_IsSpaceDustEnabled, None, SpaceCamera)
SpaceCamera.SetSpaceDustForCamera = new.instancemethod(Appc.SpaceCamera_SetSpaceDustForCamera, None, SpaceCamera)

class LightObjectClass(BaseObjectClass):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEventHandlerObject(self)
    def __repr__(self):
        return "<C LightObjectClass instance at %s>" % (self.this,)
class LightObjectClassPtr(LightObjectClass):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = LightObjectClass


LightObjectClass.SetIntensity = new.instancemethod(Appc.LightObjectClass_SetIntensity, None, LightObjectClass)
LightObjectClass.GetIntensity = new.instancemethod(Appc.LightObjectClass_GetIntensity, None, LightObjectClass)
LightObjectClass.AddIlluminatedObject = new.instancemethod(Appc.LightObjectClass_AddIlluminatedObject, None, LightObjectClass)
LightObjectClass.RemoveIlluminatedObject = new.instancemethod(Appc.LightObjectClass_RemoveIlluminatedObject, None, LightObjectClass)
LightObjectClass.IlluminateEntireSet = new.instancemethod(Appc.LightObjectClass_IlluminateEntireSet, None, LightObjectClass)
LightObjectClass.UnilluminateEntireSet = new.instancemethod(Appc.LightObjectClass_UnilluminateEntireSet, None, LightObjectClass)

class CameraMode(TGEventHandlerObject):
    def __init__(self,this):
        self.this = this

    def GetAttrIDObject(*args):
        val = apply(Appc.CameraMode_GetAttrIDObject,args)
        if val: val = ObjectClassPtr(val) 
        return val
    def GetAttrPoint(*args):
        val = apply(Appc.CameraMode_GetAttrPoint,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEventHandlerObject(self)
    def __repr__(self):
        return "<C CameraMode instance at %s>" % (self.this,)
class CameraModePtr(CameraMode):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = CameraMode


CameraMode.SetAttrFloat = new.instancemethod(Appc.CameraMode_SetAttrFloat, None, CameraMode)
CameraMode.GetAttrFloat = new.instancemethod(Appc.CameraMode_GetAttrFloat, None, CameraMode)
CameraMode.SetAttrID = new.instancemethod(Appc.CameraMode_SetAttrID, None, CameraMode)
CameraMode.SetAttrIDObject = new.instancemethod(Appc.CameraMode_SetAttrIDObject, None, CameraMode)
CameraMode.GetAttrID = new.instancemethod(Appc.CameraMode_GetAttrID, None, CameraMode)
CameraMode.SetAttrPoint = new.instancemethod(Appc.CameraMode_SetAttrPoint, None, CameraMode)
CameraMode.SnapToIdealPosition = new.instancemethod(Appc.CameraMode_SnapToIdealPosition, None, CameraMode)
CameraMode.Reset = new.instancemethod(Appc.CameraMode_Reset, None, CameraMode)
CameraMode.IsValid = new.instancemethod(Appc.CameraMode_IsValid, None, CameraMode)
CameraMode.GetName = new.instancemethod(Appc.CameraMode_GetName, None, CameraMode)
CameraMode.Update = new.instancemethod(Appc.CameraMode_Update, None, CameraMode)

class Backdrop(ObjectClass):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEventHandlerObject(self)
    def __repr__(self):
        return "<C Backdrop instance at %s>" % (self.this,)
class BackdropPtr(Backdrop):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = Backdrop


Backdrop.SetModelName = new.instancemethod(Appc.Backdrop_SetModelName, None, Backdrop)
Backdrop.GetModelName = new.instancemethod(Appc.Backdrop_GetModelName, None, Backdrop)
Backdrop.SetName = new.instancemethod(Appc.Backdrop_SetName, None, Backdrop)
Backdrop.SetContainingSet = new.instancemethod(Appc.Backdrop_SetContainingSet, None, Backdrop)

class BackdropSphere(Backdrop):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEventHandlerObject(self)
    def __repr__(self):
        return "<C BackdropSphere instance at %s>" % (self.this,)
class BackdropSpherePtr(BackdropSphere):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = BackdropSphere


BackdropSphere.SetHorizontalSpan = new.instancemethod(Appc.BackdropSphere_SetHorizontalSpan, None, BackdropSphere)
BackdropSphere.SetVerticalSpan = new.instancemethod(Appc.BackdropSphere_SetVerticalSpan, None, BackdropSphere)
BackdropSphere.SetTextureFileName = new.instancemethod(Appc.BackdropSphere_SetTextureFileName, None, BackdropSphere)
BackdropSphere.SetTextureHTile = new.instancemethod(Appc.BackdropSphere_SetTextureHTile, None, BackdropSphere)
BackdropSphere.SetTextureVTile = new.instancemethod(Appc.BackdropSphere_SetTextureVTile, None, BackdropSphere)
BackdropSphere.SetDetailTextureFileName = new.instancemethod(Appc.BackdropSphere_SetDetailTextureFileName, None, BackdropSphere)
BackdropSphere.SetDetailTextureHTile = new.instancemethod(Appc.BackdropSphere_SetDetailTextureHTile, None, BackdropSphere)
BackdropSphere.SetDetailTextureVTile = new.instancemethod(Appc.BackdropSphere_SetDetailTextureVTile, None, BackdropSphere)
BackdropSphere.SetDecimate = new.instancemethod(Appc.BackdropSphere_SetDecimate, None, BackdropSphere)
BackdropSphere.Rebuild = new.instancemethod(Appc.BackdropSphere_Rebuild, None, BackdropSphere)
BackdropSphere.SetSphereRadius = new.instancemethod(Appc.BackdropSphere_SetSphereRadius, None, BackdropSphere)
BackdropSphere.SetTargetPolyCount = new.instancemethod(Appc.BackdropSphere_SetTargetPolyCount, None, BackdropSphere)
BackdropSphere.SetAlphaBlendModes = new.instancemethod(Appc.BackdropSphere_SetAlphaBlendModes, None, BackdropSphere)

class StarSphere(BackdropSphere):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEventHandlerObject(self)
    def __repr__(self):
        return "<C StarSphere instance at %s>" % (self.this,)
class StarSpherePtr(StarSphere):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = StarSphere



class AsteroidField(ObjectClass):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEventHandlerObject(self)
    def __repr__(self):
        return "<C AsteroidField instance at %s>" % (self.this,)
class AsteroidFieldPtr(AsteroidField):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = AsteroidField


AsteroidField.Update = new.instancemethod(Appc.AsteroidField_Update, None, AsteroidField)
AsteroidField.GetOuterFieldRadius = new.instancemethod(Appc.AsteroidField_GetOuterFieldRadius, None, AsteroidField)
AsteroidField.SetOuterFieldRadius = new.instancemethod(Appc.AsteroidField_SetOuterFieldRadius, None, AsteroidField)
AsteroidField.GetInnerFieldRadius = new.instancemethod(Appc.AsteroidField_GetInnerFieldRadius, None, AsteroidField)
AsteroidField.SetInnerFieldRadius = new.instancemethod(Appc.AsteroidField_SetInnerFieldRadius, None, AsteroidField)
AsteroidField.GetNumAsteroidsPerTile = new.instancemethod(Appc.AsteroidField_GetNumAsteroidsPerTile, None, AsteroidField)
AsteroidField.SetNumAsteroidsPerTile = new.instancemethod(Appc.AsteroidField_SetNumAsteroidsPerTile, None, AsteroidField)
AsteroidField.GetAsteroidSizeFactor = new.instancemethod(Appc.AsteroidField_GetAsteroidSizeFactor, None, AsteroidField)
AsteroidField.SetAsteroidSizeFactor = new.instancemethod(Appc.AsteroidField_SetAsteroidSizeFactor, None, AsteroidField)
AsteroidField.GetTileSize = new.instancemethod(Appc.AsteroidField_GetTileSize, None, AsteroidField)
AsteroidField.IsShipInside = new.instancemethod(Appc.AsteroidField_IsShipInside, None, AsteroidField)

class SetFloatVarEvent(TGEvent):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEvent(self)
    def __repr__(self):
        return "<C SetFloatVarEvent instance at %s>" % (self.this,)
class SetFloatVarEventPtr(SetFloatVarEvent):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = SetFloatVarEvent


SetFloatVarEvent.SetScope = new.instancemethod(Appc.SetFloatVarEvent_SetScope, None, SetFloatVarEvent)
SetFloatVarEvent.GetScope = new.instancemethod(Appc.SetFloatVarEvent_GetScope, None, SetFloatVarEvent)
SetFloatVarEvent.SetName = new.instancemethod(Appc.SetFloatVarEvent_SetName, None, SetFloatVarEvent)
SetFloatVarEvent.GetName = new.instancemethod(Appc.SetFloatVarEvent_GetName, None, SetFloatVarEvent)
SetFloatVarEvent.SetValue = new.instancemethod(Appc.SetFloatVarEvent_SetValue, None, SetFloatVarEvent)
SetFloatVarEvent.GetValue = new.instancemethod(Appc.SetFloatVarEvent_GetValue, None, SetFloatVarEvent)

class VarManagerClass(TGEventHandlerObject):
    def __init__(self,*args):
        self.this = apply(Appc.new_VarManagerClass,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_VarManagerClass(self)
    def __repr__(self):
        return "<C VarManagerClass instance at %s>" % (self.this,)
class VarManagerClassPtr(VarManagerClass):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = VarManagerClass


VarManagerClass.SetFloatVariable = new.instancemethod(Appc.VarManagerClass_SetFloatVariable, None, VarManagerClass)
VarManagerClass.GetFloatVariable = new.instancemethod(Appc.VarManagerClass_GetFloatVariable, None, VarManagerClass)
VarManagerClass.SetStringVariable = new.instancemethod(Appc.VarManagerClass_SetStringVariable, None, VarManagerClass)
VarManagerClass.GetStringVariable = new.instancemethod(Appc.VarManagerClass_GetStringVariable, None, VarManagerClass)
VarManagerClass.DeleteAllVariables = new.instancemethod(Appc.VarManagerClass_DeleteAllVariables, None, VarManagerClass)
VarManagerClass.DeleteAllScopedVariables = new.instancemethod(Appc.VarManagerClass_DeleteAllScopedVariables, None, VarManagerClass)
VarManagerClass.MakeEpisodeEventType = new.instancemethod(Appc.VarManagerClass_MakeEpisodeEventType, None, VarManagerClass)

class CPyDebug:
    def __init__(self,*args):
        self.this = apply(Appc.new_CPyDebug,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_CPyDebug(self)
    def __repr__(self):
        return "<C CPyDebug instance at %s>" % (self.this,)
class CPyDebugPtr(CPyDebug):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = CPyDebug


CPyDebug.Print = new.instancemethod(Appc.CPyDebug_Print, None, CPyDebug)

class ImageManagerClass:
    LOW_IMAGE_DETAIL = Appc.ImageManagerClass_LOW_IMAGE_DETAIL
    MED_IMAGE_DETAIL = Appc.ImageManagerClass_MED_IMAGE_DETAIL
    HIGH_IMAGE_DETAIL = Appc.ImageManagerClass_HIGH_IMAGE_DETAIL
    def __init__(self,this):
        self.this = this

    def GetImage(*args):
        val = apply(Appc.ImageManagerClass_GetImage,args)
        if val: val = NiImagePtr(val) 
        return val
    def __repr__(self):
        return "<C ImageManagerClass instance at %s>" % (self.this,)
class ImageManagerClassPtr(ImageManagerClass):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = ImageManagerClass


ImageManagerClass.GetImageDetail = new.instancemethod(Appc.ImageManagerClass_GetImageDetail, None, ImageManagerClass)
ImageManagerClass.SetImageDetail = new.instancemethod(Appc.ImageManagerClass_SetImageDetail, None, ImageManagerClass)
ImageManagerClass.EnableMipMaps = new.instancemethod(Appc.ImageManagerClass_EnableMipMaps, None, ImageManagerClass)
ImageManagerClass.AreMipMapsEnabled = new.instancemethod(Appc.ImageManagerClass_AreMipMapsEnabled, None, ImageManagerClass)
ImageManagerClass.FindDetailPath = new.instancemethod(Appc.ImageManagerClass_FindDetailPath, None, ImageManagerClass)
ImageManagerClass.SetDefaultTextureFilterQuality = new.instancemethod(Appc.ImageManagerClass_SetDefaultTextureFilterQuality, None, ImageManagerClass)
ImageManagerClass.GetDefaultTextureFilterQuality = new.instancemethod(Appc.ImageManagerClass_GetDefaultTextureFilterQuality, None, ImageManagerClass)

class FocusManager:
    def __init__(self,*args):
        self.this = apply(Appc.new_FocusManager,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_FocusManager(self)
    def __repr__(self):
        return "<C FocusManager instance at %s>" % (self.this,)
class FocusManagerPtr(FocusManager):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = FocusManager


FocusManager.AddObjectToTabOrder = new.instancemethod(Appc.FocusManager_AddObjectToTabOrder, None, FocusManager)
FocusManager.RemoveObjectFromTabOrder = new.instancemethod(Appc.FocusManager_RemoveObjectFromTabOrder, None, FocusManager)
FocusManager.RemoveAllObjects = new.instancemethod(Appc.FocusManager_RemoveAllObjects, None, FocusManager)
FocusManager.RemoveAllObjectsUnder = new.instancemethod(Appc.FocusManager_RemoveAllObjectsUnder, None, FocusManager)
FocusManager.Tab = new.instancemethod(Appc.FocusManager_Tab, None, FocusManager)

class LODModel:
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C LODModel instance at %s>" % (self.this,)
class LODModelPtr(LODModel):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = LODModel


LODModel.AddLOD = new.instancemethod(Appc.LODModel_AddLOD, None, LODModel)
LODModel.SetTextureSharePath = new.instancemethod(Appc.LODModel_SetTextureSharePath, None, LODModel)
LODModel.AddGlowPassTexture = new.instancemethod(Appc.LODModel_AddGlowPassTexture, None, LODModel)
LODModel.Load = new.instancemethod(Appc.LODModel_Load, None, LODModel)
LODModel.LoadIncremental = new.instancemethod(Appc.LODModel_LoadIncremental, None, LODModel)

class LODModelManager:
    def __init__(self,this):
        self.this = this

    def Create(*args):
        val = apply(Appc.LODModelManager_Create,args)
        if val: val = LODModelPtr(val) 
        return val
    def __repr__(self):
        return "<C LODModelManager instance at %s>" % (self.this,)
class LODModelManagerPtr(LODModelManager):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = LODModelManager


LODModelManager.Contains = new.instancemethod(Appc.LODModelManager_Contains, None, LODModelManager)
LODModelManager.Unrefer = new.instancemethod(Appc.LODModelManager_Unrefer, None, LODModelManager)
LODModelManager.ForgetAll = new.instancemethod(Appc.LODModelManager_ForgetAll, None, LODModelManager)
LODModelManager.Purge = new.instancemethod(Appc.LODModelManager_Purge, None, LODModelManager)
LODModelManager.AreGlowMapsEnabled = new.instancemethod(Appc.LODModelManager_AreGlowMapsEnabled, None, LODModelManager)
LODModelManager.SetGlowMapsEnabled = new.instancemethod(Appc.LODModelManager_SetGlowMapsEnabled, None, LODModelManager)
LODModelManager.AreSpecularMapsEnabled = new.instancemethod(Appc.LODModelManager_AreSpecularMapsEnabled, None, LODModelManager)
LODModelManager.SetSpecularMapsEnabled = new.instancemethod(Appc.LODModelManager_SetSpecularMapsEnabled, None, LODModelManager)
LODModelManager.IsMotionBlurEnabled = new.instancemethod(Appc.LODModelManager_IsMotionBlurEnabled, None, LODModelManager)
LODModelManager.SetMotionBlurEnabled = new.instancemethod(Appc.LODModelManager_SetMotionBlurEnabled, None, LODModelManager)
LODModelManager.SetDropLODLevel = new.instancemethod(Appc.LODModelManager_SetDropLODLevel, None, LODModelManager)
LODModelManager.GetDropLODLevel = new.instancemethod(Appc.LODModelManager_GetDropLODLevel, None, LODModelManager)

class FloatRangeWatcher:
    FRW_NONE = Appc.FloatRangeWatcher_FRW_NONE
    FRW_ABOVE = Appc.FloatRangeWatcher_FRW_ABOVE
    FRW_BELOW = Appc.FloatRangeWatcher_FRW_BELOW
    FRW_BOTH = Appc.FloatRangeWatcher_FRW_BOTH
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C FloatRangeWatcher instance at %s>" % (self.this,)
class FloatRangeWatcherPtr(FloatRangeWatcher):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = FloatRangeWatcher


FloatRangeWatcher.GetWatchedVariable = new.instancemethod(Appc.FloatRangeWatcher_GetWatchedVariable, None, FloatRangeWatcher)
FloatRangeWatcher.AddRangeCheck = new.instancemethod(Appc.FloatRangeWatcher_AddRangeCheck, None, FloatRangeWatcher)
FloatRangeWatcher.RemoveRangeCheck = new.instancemethod(Appc.FloatRangeWatcher_RemoveRangeCheck, None, FloatRangeWatcher)

class TGStringToStringMap:
    def __init__(self,*args):
        self.this = apply(Appc.new_TGStringToStringMap,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGStringToStringMap(self)
    def __repr__(self):
        return "<C TGStringToStringMap instance at %s>" % (self.this,)
class TGStringToStringMapPtr(TGStringToStringMap):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TGStringToStringMap


TGStringToStringMap.AddMapping = new.instancemethod(Appc.TGStringToStringMap_AddMapping, None, TGStringToStringMap)
TGStringToStringMap.GetDest = new.instancemethod(Appc.TGStringToStringMap_GetDest, None, TGStringToStringMap)
TGStringToStringMap.DeleteMappings = new.instancemethod(Appc.TGStringToStringMap_DeleteMappings, None, TGStringToStringMap)

class LoadMissionAction(TGScriptAction):
    def __init__(self,this):
        self.this = this

    def GetGame(*args):
        val = apply(Appc.LoadMissionAction_GetGame,args)
        if val: val = GamePtr(val) 
        return val
    def GetEpisode(*args):
        val = apply(Appc.LoadMissionAction_GetEpisode,args)
        if val: val = EpisodePtr(val) 
        return val
    def __repr__(self):
        return "<C LoadMissionAction instance at %s>" % (self.this,)
class LoadMissionActionPtr(LoadMissionAction):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = LoadMissionAction


LoadMissionAction.Play = new.instancemethod(Appc.LoadMissionAction_Play, None, LoadMissionAction)

class LoadEpisodeAction(TGScriptAction):
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C LoadEpisodeAction instance at %s>" % (self.this,)
class LoadEpisodeActionPtr(LoadEpisodeAction):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = LoadEpisodeAction


LoadEpisodeAction.Play = new.instancemethod(Appc.LoadEpisodeAction_Play, None, LoadEpisodeAction)

class ChatObjectClass(TGEventHandlerObject):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEventHandlerObject(self)
    def __repr__(self):
        return "<C ChatObjectClass instance at %s>" % (self.this,)
class ChatObjectClassPtr(ChatObjectClass):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = ChatObjectClass


ChatObjectClass.Disconnect = new.instancemethod(Appc.ChatObjectClass_Disconnect, None, ChatObjectClass)
ChatObjectClass.IsChatObjectReady = new.instancemethod(Appc.ChatObjectClass_IsChatObjectReady, None, ChatObjectClass)
ChatObjectClass.GetLocalIPAddress = new.instancemethod(Appc.ChatObjectClass_GetLocalIPAddress, None, ChatObjectClass)
ChatObjectClass.SendChatMessage = new.instancemethod(Appc.ChatObjectClass_SendChatMessage, None, ChatObjectClass)

class GraphicsModeInfo:
    RES_640x480 = Appc.GraphicsModeInfo_RES_640x480
    RES_800x600 = Appc.GraphicsModeInfo_RES_800x600
    RES_1024x768 = Appc.GraphicsModeInfo_RES_1024x768
    RES_1280x1024 = Appc.GraphicsModeInfo_RES_1280x1024
    RES_1600x1200 = Appc.GraphicsModeInfo_RES_1600x1200
    def __init__(self,*args):
        self.this = apply(Appc.new_GraphicsModeInfo,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_GraphicsModeInfo(self)
    def GetDesc(*args):
        val = apply(Appc.GraphicsModeInfo_GetDesc,args)
        if val: val = Ni3DDeviceDescPtr(val) 
        return val
    def __repr__(self):
        return "<C GraphicsModeInfo instance at %s>" % (self.this,)
class GraphicsModeInfoPtr(GraphicsModeInfo):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = GraphicsModeInfo


GraphicsModeInfo.GetDevice = new.instancemethod(Appc.GraphicsModeInfo_GetDevice, None, GraphicsModeInfo)
GraphicsModeInfo.IsWindowed = new.instancemethod(Appc.GraphicsModeInfo_IsWindowed, None, GraphicsModeInfo)
GraphicsModeInfo.GetWidth = new.instancemethod(Appc.GraphicsModeInfo_GetWidth, None, GraphicsModeInfo)
GraphicsModeInfo.GetHeight = new.instancemethod(Appc.GraphicsModeInfo_GetHeight, None, GraphicsModeInfo)
GraphicsModeInfo.GetColorDepth = new.instancemethod(Appc.GraphicsModeInfo_GetColorDepth, None, GraphicsModeInfo)
GraphicsModeInfo.IsHighZBuffer = new.instancemethod(Appc.GraphicsModeInfo_IsHighZBuffer, None, GraphicsModeInfo)
GraphicsModeInfo.GetPixelWidth = new.instancemethod(Appc.GraphicsModeInfo_GetPixelWidth, None, GraphicsModeInfo)
GraphicsModeInfo.GetPixelHeight = new.instancemethod(Appc.GraphicsModeInfo_GetPixelHeight, None, GraphicsModeInfo)
GraphicsModeInfo.GetCurrentResolution = new.instancemethod(Appc.GraphicsModeInfo_GetCurrentResolution, None, GraphicsModeInfo)
GraphicsModeInfo.GetLcarsString = new.instancemethod(Appc.GraphicsModeInfo_GetLcarsString, None, GraphicsModeInfo)
GraphicsModeInfo.GetLcarsModule = new.instancemethod(Appc.GraphicsModeInfo_GetLcarsModule, None, GraphicsModeInfo)

class TimeSliceProcess:
    UNSTOPPABLE = Appc.TimeSliceProcess_UNSTOPPABLE
    CRITICAL = Appc.TimeSliceProcess_CRITICAL
    NORMAL = Appc.TimeSliceProcess_NORMAL
    LOW = Appc.TimeSliceProcess_LOW
    NUM_PRIORITIES = Appc.TimeSliceProcess_NUM_PRIORITIES
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C TimeSliceProcess instance at %s>" % (self.this,)
class TimeSliceProcessPtr(TimeSliceProcess):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TimeSliceProcess


TimeSliceProcess.Update = new.instancemethod(Appc.TimeSliceProcess_Update, None, TimeSliceProcess)
TimeSliceProcess.SetPriority = new.instancemethod(Appc.TimeSliceProcess_SetPriority, None, TimeSliceProcess)
TimeSliceProcess.GetPriority = new.instancemethod(Appc.TimeSliceProcess_GetPriority, None, TimeSliceProcess)
TimeSliceProcess.SetDelay = new.instancemethod(Appc.TimeSliceProcess_SetDelay, None, TimeSliceProcess)
TimeSliceProcess.GetDelay = new.instancemethod(Appc.TimeSliceProcess_GetDelay, None, TimeSliceProcess)
TimeSliceProcess.SetDelayUsesGameTime = new.instancemethod(Appc.TimeSliceProcess_SetDelayUsesGameTime, None, TimeSliceProcess)
TimeSliceProcess.GetDelayUsesGameTime = new.instancemethod(Appc.TimeSliceProcess_GetDelayUsesGameTime, None, TimeSliceProcess)

class PythonMethodProcess(TimeSliceProcess):
    def __init__(self,*args):
        self.this = apply(Appc.new_PythonMethodProcess,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_PythonMethodProcess(self)
    def __repr__(self):
        return "<C PythonMethodProcess instance at %s>" % (self.this,)
class PythonMethodProcessPtr(PythonMethodProcess):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = PythonMethodProcess


PythonMethodProcess.SetFunction = new.instancemethod(Appc.PythonMethodProcess_SetFunction, None, PythonMethodProcess)

class ChangeRenderedSetAction(TGAction):
    def __init__(self,*args):
        self.this = apply(Appc.new_ChangeRenderedSetAction,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_ChangeRenderedSetAction(self)
    def __repr__(self):
        return "<C ChangeRenderedSetAction instance at %s>" % (self.this,)
class ChangeRenderedSetActionPtr(ChangeRenderedSetAction):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = ChangeRenderedSetAction


ChangeRenderedSetAction.SetName = new.instancemethod(Appc.ChangeRenderedSetAction_SetName, None, ChangeRenderedSetAction)

class ZoomCameraObjectClass(CameraObjectClass):
    def __init__(self,*args):
        self.this = apply(Appc.new_ZoomCameraObjectClass,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEventHandlerObject(self)
    def __repr__(self):
        return "<C ZoomCameraObjectClass instance at %s>" % (self.this,)
class ZoomCameraObjectClassPtr(ZoomCameraObjectClass):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = ZoomCameraObjectClass


ZoomCameraObjectClass.UpdateViewFrustum = new.instancemethod(Appc.ZoomCameraObjectClass_UpdateViewFrustum, None, ZoomCameraObjectClass)
ZoomCameraObjectClass.GetMaxZoom = new.instancemethod(Appc.ZoomCameraObjectClass_GetMaxZoom, None, ZoomCameraObjectClass)
ZoomCameraObjectClass.GetMinZoom = new.instancemethod(Appc.ZoomCameraObjectClass_GetMinZoom, None, ZoomCameraObjectClass)
ZoomCameraObjectClass.GetZoomTime = new.instancemethod(Appc.ZoomCameraObjectClass_GetZoomTime, None, ZoomCameraObjectClass)
ZoomCameraObjectClass.IsZoomed = new.instancemethod(Appc.ZoomCameraObjectClass_IsZoomed, None, ZoomCameraObjectClass)
ZoomCameraObjectClass.ToggleZoom = new.instancemethod(Appc.ZoomCameraObjectClass_ToggleZoom, None, ZoomCameraObjectClass)
ZoomCameraObjectClass.SetMaxZoom = new.instancemethod(Appc.ZoomCameraObjectClass_SetMaxZoom, None, ZoomCameraObjectClass)
ZoomCameraObjectClass.SetMinZoom = new.instancemethod(Appc.ZoomCameraObjectClass_SetMinZoom, None, ZoomCameraObjectClass)
ZoomCameraObjectClass.SetZoomTime = new.instancemethod(Appc.ZoomCameraObjectClass_SetZoomTime, None, ZoomCameraObjectClass)
ZoomCameraObjectClass.SetShake = new.instancemethod(Appc.ZoomCameraObjectClass_SetShake, None, ZoomCameraObjectClass)
ZoomCameraObjectClass.GetShake = new.instancemethod(Appc.ZoomCameraObjectClass_GetShake, None, ZoomCameraObjectClass)
ZoomCameraObjectClass.LookForward = new.instancemethod(Appc.ZoomCameraObjectClass_LookForward, None, ZoomCameraObjectClass)

class CharacterAction(TGAction):
    AT_SET_LOCATION = Appc.CharacterAction_AT_SET_LOCATION
    AT_SET_LOCATION_NAME = Appc.CharacterAction_AT_SET_LOCATION_NAME
    AT_MOVE = Appc.CharacterAction_AT_MOVE
    AT_TURN = Appc.CharacterAction_AT_TURN
    AT_TURN_NOW = Appc.CharacterAction_AT_TURN_NOW
    AT_TURN_BACK = Appc.CharacterAction_AT_TURN_BACK
    AT_TURN_BACK_NOW = Appc.CharacterAction_AT_TURN_BACK_NOW
    AT_DEFAULT = Appc.CharacterAction_AT_DEFAULT
    AT_BREATHE = Appc.CharacterAction_AT_BREATHE
    AT_FORCE_BREATHE = Appc.CharacterAction_AT_FORCE_BREATHE
    AT_SPEAK_LINE = Appc.CharacterAction_AT_SPEAK_LINE
    AT_SPEAK_LINE_NO_FLAP_LIPS = Appc.CharacterAction_AT_SPEAK_LINE_NO_FLAP_LIPS
    AT_SAY_LINE = Appc.CharacterAction_AT_SAY_LINE
    AT_SAY_LINE_AFTER_TURN = Appc.CharacterAction_AT_SAY_LINE_AFTER_TURN
    AT_PLAY_ANIMATION = Appc.CharacterAction_AT_PLAY_ANIMATION
    AT_PLAY_ANIMATION_FILE = Appc.CharacterAction_AT_PLAY_ANIMATION_FILE
    AT_LOOK_AT_ME = Appc.CharacterAction_AT_LOOK_AT_ME
    AT_LOOK_AT_ME_NOW = Appc.CharacterAction_AT_LOOK_AT_ME_NOW
    AT_WATCH_ME = Appc.CharacterAction_AT_WATCH_ME
    AT_STOP_WATCHING_ME = Appc.CharacterAction_AT_STOP_WATCHING_ME
    AT_MENU_UP = Appc.CharacterAction_AT_MENU_UP
    AT_MENU_DOWN = Appc.CharacterAction_AT_MENU_DOWN
    AT_SET_AUDIO_MODE = Appc.CharacterAction_AT_SET_AUDIO_MODE
    AT_ENABLE_RANDOM_ANIMATIONS = Appc.CharacterAction_AT_ENABLE_RANDOM_ANIMATIONS
    AT_DISABLE_RANDOM_ANIMATIONS = Appc.CharacterAction_AT_DISABLE_RANDOM_ANIMATIONS
    AT_GLANCE_AT = Appc.CharacterAction_AT_GLANCE_AT
    AT_GLANCE_AWAY = Appc.CharacterAction_AT_GLANCE_AWAY
    AT_BECOME_ACTIVE = Appc.CharacterAction_AT_BECOME_ACTIVE
    AT_BECOME_INACTIVE = Appc.CharacterAction_AT_BECOME_INACTIVE
    AT_ENABLE_MENU = Appc.CharacterAction_AT_ENABLE_MENU
    AT_DISABLE_MENU = Appc.CharacterAction_AT_DISABLE_MENU
    AT_ENABLE_INITIATIVE = Appc.CharacterAction_AT_ENABLE_INITIATIVE
    AT_DISABLE_INITIATIVE = Appc.CharacterAction_AT_DISABLE_INITIATIVE
    AT_SET_STATUS = Appc.CharacterAction_AT_SET_STATUS
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C CharacterAction instance at %s>" % (self.this,)
class CharacterActionPtr(CharacterAction):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = CharacterAction


CharacterAction.Play = new.instancemethod(Appc.CharacterAction_Play, None, CharacterAction)
CharacterAction.Completed = new.instancemethod(Appc.CharacterAction_Completed, None, CharacterAction)
CharacterAction.GetActionType = new.instancemethod(Appc.CharacterAction_GetActionType, None, CharacterAction)
CharacterAction.GetDetail = new.instancemethod(Appc.CharacterAction_GetDetail, None, CharacterAction)
CharacterAction.SetPriority = new.instancemethod(Appc.CharacterAction_SetPriority, None, CharacterAction)
CharacterAction.SetSubPriority = new.instancemethod(Appc.CharacterAction_SetSubPriority, None, CharacterAction)
CharacterAction.UseNameAndSetInsteadOfObject = new.instancemethod(Appc.CharacterAction_UseNameAndSetInsteadOfObject, None, CharacterAction)

class CharacterClass(ObjectClass):
    CS_IDLE = Appc.CharacterClass_CS_IDLE
    CS_STANDING = Appc.CharacterClass_CS_STANDING
    CS_GLANCING = Appc.CharacterClass_CS_GLANCING
    CS_TURNED = Appc.CharacterClass_CS_TURNED
    CS_UI_DISABLED = Appc.CharacterClass_CS_UI_DISABLED
    CS_HIDDEN = Appc.CharacterClass_CS_HIDDEN
    CS_INITIATIVE = Appc.CharacterClass_CS_INITIATIVE
    CS_MIDDLE = Appc.CharacterClass_CS_MIDDLE
    CS_SEATED = Appc.CharacterClass_CS_SEATED
    CS_VISIBLE = Appc.CharacterClass_CS_VISIBLE
    CS_CLEAR_GLANCE = Appc.CharacterClass_CS_CLEAR_GLANCE
    CS_CLEAR_TURNED = Appc.CharacterClass_CS_CLEAR_TURNED
    CS_UI_ENABLED = Appc.CharacterClass_CS_UI_ENABLED
    CS_STOP_INITIATIVE = Appc.CharacterClass_CS_STOP_INITIATIVE
    CAT_BREATHE = Appc.CharacterClass_CAT_BREATHE
    CAT_INTERRUPTABLE = Appc.CharacterClass_CAT_INTERRUPTABLE
    CAT_NON_INTERRUPTABLE = Appc.CharacterClass_CAT_NON_INTERRUPTABLE
    CAT_TURN = Appc.CharacterClass_CAT_TURN
    CAT_TURN_BACK = Appc.CharacterClass_CAT_TURN_BACK
    CAT_GLANCE = Appc.CharacterClass_CAT_GLANCE
    CAT_GLANCE_BACK = Appc.CharacterClass_CAT_GLANCE_BACK
    CPT_DEFAULT = Appc.CharacterClass_CPT_DEFAULT
    CPT_BLINK = Appc.CharacterClass_CPT_BLINK
    CPT_SPEAK = Appc.CharacterClass_CPT_SPEAK
    CPT_EYEBROW = Appc.CharacterClass_CPT_EYEBROW
    CAM_MUTE = Appc.CharacterClass_CAM_MUTE
    CAM_EXTREMELY_VOCAL = Appc.CharacterClass_CAM_EXTREMELY_VOCAL
    CAM_VOCAL = Appc.CharacterClass_CAM_VOCAL
    CAM_REDUCED = Appc.CharacterClass_CAM_REDUCED
    MALE = Appc.CharacterClass_MALE
    FEMALE = Appc.CharacterClass_FEMALE
    MAX_GENDERS = Appc.CharacterClass_MAX_GENDERS
    SMALL = Appc.CharacterClass_SMALL
    MEDIUM = Appc.CharacterClass_MEDIUM
    LARGE = Appc.CharacterClass_LARGE
    MAX_SIZES = Appc.CharacterClass_MAX_SIZES
    BOTH = Appc.CharacterClass_BOTH
    SITTING_ONLY = Appc.CharacterClass_SITTING_ONLY
    STANDING_ONLY = Appc.CharacterClass_STANDING_ONLY
    EST_ALERT_GREEN = Appc.CharacterClass_EST_ALERT_GREEN
    EST_ALERT_YELLOW = Appc.CharacterClass_EST_ALERT_YELLOW
    EST_ALERT_RED = Appc.CharacterClass_EST_ALERT_RED
    EST_REPORT_OVERVIEW = Appc.CharacterClass_EST_REPORT_OVERVIEW
    EST_REPORT_ENGINES = Appc.CharacterClass_EST_REPORT_ENGINES
    EST_REPORT_WEAPONS = Appc.CharacterClass_EST_REPORT_WEAPONS
    EST_REPORT_SHIELDS = Appc.CharacterClass_EST_REPORT_SHIELDS
    EST_REPORT_REPAIR = Appc.CharacterClass_EST_REPORT_REPAIR
    EST_REPORT_SENSORS = Appc.CharacterClass_EST_REPORT_SENSORS
    EST_REPORT_DESTINATION = Appc.CharacterClass_EST_REPORT_DESTINATION
    EST_REPORT_SPEED = Appc.CharacterClass_EST_REPORT_SPEED
    EST_REPORT_ETA = Appc.CharacterClass_EST_REPORT_ETA
    EST_SHIP_STATUS = Appc.CharacterClass_EST_SHIP_STATUS
    EST_TARGET_STATUS = Appc.CharacterClass_EST_TARGET_STATUS
    EST_TRANSFER_POWER_WEAPONS = Appc.CharacterClass_EST_TRANSFER_POWER_WEAPONS
    EST_TRANSFER_POWER_SHIELDS_FORE = Appc.CharacterClass_EST_TRANSFER_POWER_SHIELDS_FORE
    EST_TRANSFER_POWER_SHIELDS_AFT = Appc.CharacterClass_EST_TRANSFER_POWER_SHIELDS_AFT
    EST_TRANSFER_POWER_SHIELDS_PORT = Appc.CharacterClass_EST_TRANSFER_POWER_SHIELDS_PORT
    EST_TRANSFER_POWER_SHIELDS_STARBOARD = Appc.CharacterClass_EST_TRANSFER_POWER_SHIELDS_STARBOARD
    EST_TRANSFER_POWER_SHIELDS_DORSAL = Appc.CharacterClass_EST_TRANSFER_POWER_SHIELDS_DORSAL
    EST_TRANSFER_POWER_SHIELDS_VENTRAL = Appc.CharacterClass_EST_TRANSFER_POWER_SHIELDS_VENTRAL
    EST_TRANSFER_POWER_SENSORS = Appc.CharacterClass_EST_TRANSFER_POWER_SENSORS
    EST_TRANSFER_POWER_ENGINES = Appc.CharacterClass_EST_TRANSFER_POWER_ENGINES
    EST_REPAIR_PHASERS = Appc.CharacterClass_EST_REPAIR_PHASERS
    EST_REPAIR_TORPEDO_TUBES = Appc.CharacterClass_EST_REPAIR_TORPEDO_TUBES
    EST_REPAIR_SENSORS = Appc.CharacterClass_EST_REPAIR_SENSORS
    EST_REPAIR_IMPULSE_ENGINES = Appc.CharacterClass_EST_REPAIR_IMPULSE_ENGINES
    EST_REPAIR_WARP_ENGINES = Appc.CharacterClass_EST_REPAIR_WARP_ENGINES
    EST_REPAIR_TRACTOR_BEAM = Appc.CharacterClass_EST_REPAIR_TRACTOR_BEAM
    EST_REPAIR_ENGINEERING = Appc.CharacterClass_EST_REPAIR_ENGINEERING
    EST_SET_COURSE_TO_MISSION_AREA = Appc.CharacterClass_EST_SET_COURSE_TO_MISSION_AREA
    EST_SET_COURSE_TO_PLANET = Appc.CharacterClass_EST_SET_COURSE_TO_PLANET
    EST_SET_COURSE_INTERCEPT = Appc.CharacterClass_EST_SET_COURSE_INTERCEPT
    EST_SET_COURSE_FOLLOW = Appc.CharacterClass_EST_SET_COURSE_FOLLOW
    EST_SCAN_OBJECT = Appc.CharacterClass_EST_SCAN_OBJECT
    EST_SCAN_AREA = Appc.CharacterClass_EST_SCAN_AREA
    EST_ATTACK_BEAM_WEAPON = Appc.CharacterClass_EST_ATTACK_BEAM_WEAPON
    EST_ATTACK_WARHEAD = Appc.CharacterClass_EST_ATTACK_WARHEAD
    EST_ATTACK_IMPULSE_ENGINES = Appc.CharacterClass_EST_ATTACK_IMPULSE_ENGINES
    EST_ATTACK_WARP_ENGINES = Appc.CharacterClass_EST_ATTACK_WARP_ENGINES
    EST_ATTACK_SENSORS = Appc.CharacterClass_EST_ATTACK_SENSORS
    EST_ATTACK_ENGINEERING = Appc.CharacterClass_EST_ATTACK_ENGINEERING
    EST_ATTACK_TRACTOR_BEAM = Appc.CharacterClass_EST_ATTACK_TRACTOR_BEAM
    def __init__(self,this):
        self.this = this

    def GetDatabase(*args):
        val = apply(Appc.CharacterClass_GetDatabase,args)
        if val: val = TGLocalizationDatabasePtr(val) 
        return val
    def SetDatabase(*args):
        val = apply(Appc.CharacterClass_SetDatabase,args)
        if val: val = TGLocalizationDatabasePtr(val) 
        return val
    def GetStatusBox(*args):
        val = apply(Appc.CharacterClass_GetStatusBox,args)
        if val: val = TGPanePtr(val) 
        return val
    def GetStatus(*args):
        val = apply(Appc.CharacterClass_GetStatus,args)
        if val: val = TGParagraphPtr(val) 
        return val
    def GetMenu(*args):
        val = apply(Appc.CharacterClass_GetMenu,args)
        if val: val = STTopLevelMenuPtr(val) 
        return val
    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEventHandlerObject(self)
    def __repr__(self):
        return "<C CharacterClass instance at %s>" % (self.this,)
class CharacterClassPtr(CharacterClass):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = CharacterClass


CharacterClass.ReplaceBodyAndHead = new.instancemethod(Appc.CharacterClass_ReplaceBodyAndHead, None, CharacterClass)
CharacterClass.MorphBody = new.instancemethod(Appc.CharacterClass_MorphBody, None, CharacterClass)
CharacterClass.GetYesSir = new.instancemethod(Appc.CharacterClass_GetYesSir, None, CharacterClass)
CharacterClass.SetYesSir = new.instancemethod(Appc.CharacterClass_SetYesSir, None, CharacterClass)
CharacterClass.GetHeadHeight = new.instancemethod(Appc.CharacterClass_GetHeadHeight, None, CharacterClass)
CharacterClass.SetSize = new.instancemethod(Appc.CharacterClass_SetSize, None, CharacterClass)
CharacterClass.GetSize = new.instancemethod(Appc.CharacterClass_GetSize, None, CharacterClass)
CharacterClass.SetGender = new.instancemethod(Appc.CharacterClass_SetGender, None, CharacterClass)
CharacterClass.GetGender = new.instancemethod(Appc.CharacterClass_GetGender, None, CharacterClass)
CharacterClass.SetBlinkStages = new.instancemethod(Appc.CharacterClass_SetBlinkStages, None, CharacterClass)
CharacterClass.IsSpeaking = new.instancemethod(Appc.CharacterClass_IsSpeaking, None, CharacterClass)
CharacterClass.IsReadyToSpeak = new.instancemethod(Appc.CharacterClass_IsReadyToSpeak, None, CharacterClass)
CharacterClass.IsAnimating = new.instancemethod(Appc.CharacterClass_IsAnimating, None, CharacterClass)
CharacterClass.IsGoingToAnimate = new.instancemethod(Appc.CharacterClass_IsGoingToAnimate, None, CharacterClass)
CharacterClass.IsAnimatingInterruptable = new.instancemethod(Appc.CharacterClass_IsAnimatingInterruptable, None, CharacterClass)
CharacterClass.IsAnimatingNonInterruptable = new.instancemethod(Appc.CharacterClass_IsAnimatingNonInterruptable, None, CharacterClass)
CharacterClass.IsRandomAnimationEnabled = new.instancemethod(Appc.CharacterClass_IsRandomAnimationEnabled, None, CharacterClass)
CharacterClass.IsStanding = new.instancemethod(Appc.CharacterClass_IsStanding, None, CharacterClass)
CharacterClass.IsTurned = new.instancemethod(Appc.CharacterClass_IsTurned, None, CharacterClass)
CharacterClass.IsUIDisabled = new.instancemethod(Appc.CharacterClass_IsUIDisabled, None, CharacterClass)
CharacterClass.IsGlancing = new.instancemethod(Appc.CharacterClass_IsGlancing, None, CharacterClass)
CharacterClass.SetMenuEnabled = new.instancemethod(Appc.CharacterClass_SetMenuEnabled, None, CharacterClass)
CharacterClass.IsMenuEnabled = new.instancemethod(Appc.CharacterClass_IsMenuEnabled, None, CharacterClass)
CharacterClass.SetInitiative = new.instancemethod(Appc.CharacterClass_SetInitiative, None, CharacterClass)
CharacterClass.IsInitiativeOn = new.instancemethod(Appc.CharacterClass_IsInitiativeOn, None, CharacterClass)
CharacterClass.GetLocation = new.instancemethod(Appc.CharacterClass_GetLocation, None, CharacterClass)
CharacterClass.GetTurnTowardsLocation = new.instancemethod(Appc.CharacterClass_GetTurnTowardsLocation, None, CharacterClass)
CharacterClass.GetRandomAnimationChance = new.instancemethod(Appc.CharacterClass_GetRandomAnimationChance, None, CharacterClass)
CharacterClass.GetBlinkChance = new.instancemethod(Appc.CharacterClass_GetBlinkChance, None, CharacterClass)
CharacterClass.GetAudioMode = new.instancemethod(Appc.CharacterClass_GetAudioMode, None, CharacterClass)
CharacterClass.SetRandomAnimationEnabled = new.instancemethod(Appc.CharacterClass_SetRandomAnimationEnabled, None, CharacterClass)
CharacterClass.SetRandomAnimationChance = new.instancemethod(Appc.CharacterClass_SetRandomAnimationChance, None, CharacterClass)
CharacterClass.SetBlinkChance = new.instancemethod(Appc.CharacterClass_SetBlinkChance, None, CharacterClass)
CharacterClass.SetAudioMode = new.instancemethod(Appc.CharacterClass_SetAudioMode, None, CharacterClass)
CharacterClass.AddAnimation = new.instancemethod(Appc.CharacterClass_AddAnimation, None, CharacterClass)
CharacterClass.ClearAnimations = new.instancemethod(Appc.CharacterClass_ClearAnimations, None, CharacterClass)
CharacterClass.ClearExtraAnimations = new.instancemethod(Appc.CharacterClass_ClearExtraAnimations, None, CharacterClass)
CharacterClass.AddRandomAnimation = new.instancemethod(Appc.CharacterClass_AddRandomAnimation, None, CharacterClass)
CharacterClass.SetBlinkAnimation = new.instancemethod(Appc.CharacterClass_SetBlinkAnimation, None, CharacterClass)
CharacterClass.SetActive = new.instancemethod(Appc.CharacterClass_SetActive, None, CharacterClass)
CharacterClass.IsActive = new.instancemethod(Appc.CharacterClass_IsActive, None, CharacterClass)
CharacterClass.ClearAnimationsOfType = new.instancemethod(Appc.CharacterClass_ClearAnimationsOfType, None, CharacterClass)
CharacterClass.SetAnimationDoneEvent = new.instancemethod(Appc.CharacterClass_SetAnimationDoneEvent, None, CharacterClass)
CharacterClass.SetCurrentAnimation = new.instancemethod(Appc.CharacterClass_SetCurrentAnimation, None, CharacterClass)
CharacterClass.SetLocation = new.instancemethod(Appc.CharacterClass_SetLocation, None, CharacterClass)
CharacterClass.SetLocationName = new.instancemethod(Appc.CharacterClass_SetLocationName, None, CharacterClass)
CharacterClass.MoveTo = new.instancemethod(Appc.CharacterClass_MoveTo, None, CharacterClass)
CharacterClass.GlanceAt = new.instancemethod(Appc.CharacterClass_GlanceAt, None, CharacterClass)
CharacterClass.GlanceAway = new.instancemethod(Appc.CharacterClass_GlanceAway, None, CharacterClass)
CharacterClass.TurnTowards = new.instancemethod(Appc.CharacterClass_TurnTowards, None, CharacterClass)
CharacterClass.TurnBack = new.instancemethod(Appc.CharacterClass_TurnBack, None, CharacterClass)
CharacterClass.PlayAnimation = new.instancemethod(Appc.CharacterClass_PlayAnimation, None, CharacterClass)
CharacterClass.PlayAnimationFile = new.instancemethod(Appc.CharacterClass_PlayAnimationFile, None, CharacterClass)
CharacterClass.Breathe = new.instancemethod(Appc.CharacterClass_Breathe, None, CharacterClass)
CharacterClass.IsStateSet = new.instancemethod(Appc.CharacterClass_IsStateSet, None, CharacterClass)
CharacterClass.SetFlags = new.instancemethod(Appc.CharacterClass_SetFlags, None, CharacterClass)
CharacterClass.ClearFlags = new.instancemethod(Appc.CharacterClass_ClearFlags, None, CharacterClass)
CharacterClass.SetStanding = new.instancemethod(Appc.CharacterClass_SetStanding, None, CharacterClass)
CharacterClass.SpeakLine = new.instancemethod(Appc.CharacterClass_SpeakLine, None, CharacterClass)
CharacterClass.SayLine = new.instancemethod(Appc.CharacterClass_SayLine, None, CharacterClass)
CharacterClass.AddSoundToQueue = new.instancemethod(Appc.CharacterClass_AddSoundToQueue, None, CharacterClass)
CharacterClass.Blink = new.instancemethod(Appc.CharacterClass_Blink, None, CharacterClass)
CharacterClass.SetAsExtra = new.instancemethod(Appc.CharacterClass_SetAsExtra, None, CharacterClass)
CharacterClass.IsAnExtra = new.instancemethod(Appc.CharacterClass_IsAnExtra, None, CharacterClass)
CharacterClass.SetName = new.instancemethod(Appc.CharacterClass_SetName, None, CharacterClass)
CharacterClass.SetCharacterName = new.instancemethod(Appc.CharacterClass_SetCharacterName, None, CharacterClass)
CharacterClass.GetCharacterName = new.instancemethod(Appc.CharacterClass_GetCharacterName, None, CharacterClass)
CharacterClass.AddPositionZoom = new.instancemethod(Appc.CharacterClass_AddPositionZoom, None, CharacterClass)
CharacterClass.GetPositionZoom = new.instancemethod(Appc.CharacterClass_GetPositionZoom, None, CharacterClass)
CharacterClass.GetPositionLookAtName = new.instancemethod(Appc.CharacterClass_GetPositionLookAtName, None, CharacterClass)
CharacterClass.SetLookAtAdj = new.instancemethod(Appc.CharacterClass_SetLookAtAdj, None, CharacterClass)
CharacterClass.SetStatus = new.instancemethod(Appc.CharacterClass_SetStatus, None, CharacterClass)
CharacterClass.ClearStatus = new.instancemethod(Appc.CharacterClass_ClearStatus, None, CharacterClass)
CharacterClass.ToolTip = new.instancemethod(Appc.CharacterClass_ToolTip, None, CharacterClass)
CharacterClass.SetMenu = new.instancemethod(Appc.CharacterClass_SetMenu, None, CharacterClass)
CharacterClass.MenuUp = new.instancemethod(Appc.CharacterClass_MenuUp, None, CharacterClass)
CharacterClass.MenuDown = new.instancemethod(Appc.CharacterClass_MenuDown, None, CharacterClass)
CharacterClass.IsMenuUp = new.instancemethod(Appc.CharacterClass_IsMenuUp, None, CharacterClass)
CharacterClass.LookAtMe = new.instancemethod(Appc.CharacterClass_LookAtMe, None, CharacterClass)
CharacterClass.AddFacialImage = new.instancemethod(Appc.CharacterClass_AddFacialImage, None, CharacterClass)
CharacterClass.AddPhoneme = new.instancemethod(Appc.CharacterClass_AddPhoneme, None, CharacterClass)
CharacterClass.UsePhonemeGroup = new.instancemethod(Appc.CharacterClass_UsePhonemeGroup, None, CharacterClass)
CharacterClass.SetAnimatedSpeaking = new.instancemethod(Appc.CharacterClass_SetAnimatedSpeaking, None, CharacterClass)
CharacterClass.UsesAnimatedSpeaking = new.instancemethod(Appc.CharacterClass_UsesAnimatedSpeaking, None, CharacterClass)
CharacterClass.GetLastTalkTime = new.instancemethod(Appc.CharacterClass_GetLastTalkTime, None, CharacterClass)

class ViewScreenObject(ObjectClass):
    def __init__(self,this):
        self.this = this

    def GetRemoteCam(*args):
        val = apply(Appc.ViewScreenObject_GetRemoteCam,args)
        if val: val = CameraObjectClassPtr(val) 
        return val
    def GetMenu(*args):
        val = apply(Appc.ViewScreenObject_GetMenu,args)
        if val: val = STMenuPtr(val) 
        return val
    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEventHandlerObject(self)
    def __repr__(self):
        return "<C ViewScreenObject instance at %s>" % (self.this,)
class ViewScreenObjectPtr(ViewScreenObject):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = ViewScreenObject


ViewScreenObject.SetModel = new.instancemethod(Appc.ViewScreenObject_SetModel, None, ViewScreenObject)
ViewScreenObject.SetRemoteCam = new.instancemethod(Appc.ViewScreenObject_SetRemoteCam, None, ViewScreenObject)
ViewScreenObject.ToggleRemoteCam = new.instancemethod(Appc.ViewScreenObject_ToggleRemoteCam, None, ViewScreenObject)
ViewScreenObject.RenderingRemoteCam = new.instancemethod(Appc.ViewScreenObject_RenderingRemoteCam, None, ViewScreenObject)
ViewScreenObject.SetIsOn = new.instancemethod(Appc.ViewScreenObject_SetIsOn, None, ViewScreenObject)
ViewScreenObject.IsOn = new.instancemethod(Appc.ViewScreenObject_IsOn, None, ViewScreenObject)
ViewScreenObject.SetStaticIsOn = new.instancemethod(Appc.ViewScreenObject_SetStaticIsOn, None, ViewScreenObject)
ViewScreenObject.IsStaticOn = new.instancemethod(Appc.ViewScreenObject_IsStaticOn, None, ViewScreenObject)
ViewScreenObject.SetStaticVariation = new.instancemethod(Appc.ViewScreenObject_SetStaticVariation, None, ViewScreenObject)
ViewScreenObject.SetOffTexture = new.instancemethod(Appc.ViewScreenObject_SetOffTexture, None, ViewScreenObject)
ViewScreenObject.SetStaticTextureIconGroup = new.instancemethod(Appc.ViewScreenObject_SetStaticTextureIconGroup, None, ViewScreenObject)
ViewScreenObject.SetMenu = new.instancemethod(Appc.ViewScreenObject_SetMenu, None, ViewScreenObject)
ViewScreenObject.ClearMenu = new.instancemethod(Appc.ViewScreenObject_ClearMenu, None, ViewScreenObject)
ViewScreenObject.MenuUp = new.instancemethod(Appc.ViewScreenObject_MenuUp, None, ViewScreenObject)
ViewScreenObject.MenuDown = new.instancemethod(Appc.ViewScreenObject_MenuDown, None, ViewScreenObject)
ViewScreenObject.IsMenuUp = new.instancemethod(Appc.ViewScreenObject_IsMenuUp, None, ViewScreenObject)
ViewScreenObject.LookTowardsSpace = new.instancemethod(Appc.ViewScreenObject_LookTowardsSpace, None, ViewScreenObject)

class BridgeSet(SetClass):
    def __init__(self,*args):
        self.this = apply(Appc.new_BridgeSet,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_BridgeSet(self)
    def GetViewScreen(*args):
        val = apply(Appc.BridgeSet_GetViewScreen,args)
        if val: val = ViewScreenObjectPtr(val) 
        return val
    def __repr__(self):
        return "<C BridgeSet instance at %s>" % (self.this,)
class BridgeSetPtr(BridgeSet):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = BridgeSet


BridgeSet.SetViewScreen = new.instancemethod(Appc.BridgeSet_SetViewScreen, None, BridgeSet)
BridgeSet.SetConfig = new.instancemethod(Appc.BridgeSet_SetConfig, None, BridgeSet)
BridgeSet.GetConfig = new.instancemethod(Appc.BridgeSet_GetConfig, None, BridgeSet)
BridgeSet.IsSameConfig = new.instancemethod(Appc.BridgeSet_IsSameConfig, None, BridgeSet)

class BridgeObjectClass(ObjectClass):
    def __init__(self,this):
        self.this = this

    def GetPropertySet(*args):
        val = apply(Appc.BridgeObjectClass_GetPropertySet,args)
        if val: val = TGModelPropertySetPtr(val) 
        return val
    def GetHardpointProperty(*args):
        val = apply(Appc.BridgeObjectClass_GetHardpointProperty,args)
        if val: val = TGModelPropertyPtr(val) 
        return val
    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEventHandlerObject(self)
    def __repr__(self):
        return "<C BridgeObjectClass instance at %s>" % (self.this,)
class BridgeObjectClassPtr(BridgeObjectClass):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = BridgeObjectClass


BridgeObjectClass.CreateEffect = new.instancemethod(Appc.BridgeObjectClass_CreateEffect, None, BridgeObjectClass)
BridgeObjectClass.DoCrewReactions = new.instancemethod(Appc.BridgeObjectClass_DoCrewReactions, None, BridgeObjectClass)
BridgeObjectClass.FlickerLCARs = new.instancemethod(Appc.BridgeObjectClass_FlickerLCARs, None, BridgeObjectClass)
BridgeObjectClass.TurnLCARsOff = new.instancemethod(Appc.BridgeObjectClass_TurnLCARsOff, None, BridgeObjectClass)
BridgeObjectClass.TurnLCARsOn = new.instancemethod(Appc.BridgeObjectClass_TurnLCARsOn, None, BridgeObjectClass)
BridgeObjectClass.GoToGreenAllert = new.instancemethod(Appc.BridgeObjectClass_GoToGreenAllert, None, BridgeObjectClass)
BridgeObjectClass.GoToYellowAllert = new.instancemethod(Appc.BridgeObjectClass_GoToYellowAllert, None, BridgeObjectClass)
BridgeObjectClass.GoToRedAllert = new.instancemethod(Appc.BridgeObjectClass_GoToRedAllert, None, BridgeObjectClass)

class ArtificialIntelligence:
    US_ACTIVE = Appc.ArtificialIntelligence_US_ACTIVE
    US_DONE = Appc.ArtificialIntelligence_US_DONE
    US_DORMANT = Appc.ArtificialIntelligence_US_DORMANT
    US_INVALID = Appc.ArtificialIntelligence_US_INVALID
    US_NUM_STATUSES = Appc.ArtificialIntelligence_US_NUM_STATUSES
    def __init__(self,this):
        self.this = this

    def GetObject(*args):
        val = apply(Appc.ArtificialIntelligence_GetObject,args)
        if val: val = PhysicsObjectClassPtr(val) 
        return val
    def GetShip(*args):
        val = apply(Appc.ArtificialIntelligence_GetShip,args)
        if val: val = ShipClassPtr(val) 
        return val
    def __repr__(self):
        return "<C ArtificialIntelligence instance at %s>" % (self.this,)
class ArtificialIntelligencePtr(ArtificialIntelligence):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = ArtificialIntelligence


ArtificialIntelligence.IsActive = new.instancemethod(Appc.ArtificialIntelligence_IsActive, None, ArtificialIntelligence)
ArtificialIntelligence.HasFocus = new.instancemethod(Appc.ArtificialIntelligence_HasFocus, None, ArtificialIntelligence)
ArtificialIntelligence.Pause = new.instancemethod(Appc.ArtificialIntelligence_Pause, None, ArtificialIntelligence)
ArtificialIntelligence.Unpause = new.instancemethod(Appc.ArtificialIntelligence_Unpause, None, ArtificialIntelligence)
ArtificialIntelligence.IsPaused = new.instancemethod(Appc.ArtificialIntelligence_IsPaused, None, ArtificialIntelligence)
ArtificialIntelligence.SetInterruptable = new.instancemethod(Appc.ArtificialIntelligence_SetInterruptable, None, ArtificialIntelligence)
ArtificialIntelligence.IsInterruptable = new.instancemethod(Appc.ArtificialIntelligence_IsInterruptable, None, ArtificialIntelligence)
ArtificialIntelligence.Reset = new.instancemethod(Appc.ArtificialIntelligence_Reset, None, ArtificialIntelligence)
ArtificialIntelligence.GetID = new.instancemethod(Appc.ArtificialIntelligence_GetID, None, ArtificialIntelligence)
ArtificialIntelligence.GetName = new.instancemethod(Appc.ArtificialIntelligence_GetName, None, ArtificialIntelligence)

class PlainAI(ArtificialIntelligence):
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C PlainAI instance at %s>" % (self.this,)
class PlainAIPtr(PlainAI):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = PlainAI


PlainAI.SetScriptModule = new.instancemethod(Appc.PlainAI_SetScriptModule, None, PlainAI)
PlainAI.StopCallingActivate = new.instancemethod(Appc.PlainAI_StopCallingActivate, None, PlainAI)

class PriorityListAI(ArtificialIntelligence):
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C PriorityListAI instance at %s>" % (self.this,)
class PriorityListAIPtr(PriorityListAI):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = PriorityListAI


PriorityListAI.AddAI = new.instancemethod(Appc.PriorityListAI_AddAI, None, PriorityListAI)
PriorityListAI.RemoveAIByPriority = new.instancemethod(Appc.PriorityListAI_RemoveAIByPriority, None, PriorityListAI)
PriorityListAI.RemoveAI = new.instancemethod(Appc.PriorityListAI_RemoveAI, None, PriorityListAI)

class SequenceAI(ArtificialIntelligence):
    LOOP_INFINITE = Appc.SequenceAI_LOOP_INFINITE
    def __init__(self,this):
        self.this = this

    def GetAI(*args):
        val = apply(Appc.SequenceAI_GetAI,args)
        if val: val = ArtificialIntelligencePtr(val) 
        return val
    def __repr__(self):
        return "<C SequenceAI instance at %s>" % (self.this,)
class SequenceAIPtr(SequenceAI):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = SequenceAI


SequenceAI.SetLoopCount = new.instancemethod(Appc.SequenceAI_SetLoopCount, None, SequenceAI)
SequenceAI.GetLoopCount = new.instancemethod(Appc.SequenceAI_GetLoopCount, None, SequenceAI)
SequenceAI.SetResetIfInterrupted = new.instancemethod(Appc.SequenceAI_SetResetIfInterrupted, None, SequenceAI)
SequenceAI.SetDoubleCheckAllDone = new.instancemethod(Appc.SequenceAI_SetDoubleCheckAllDone, None, SequenceAI)
SequenceAI.SetSkipDormant = new.instancemethod(Appc.SequenceAI_SetSkipDormant, None, SequenceAI)
SequenceAI.AddAI = new.instancemethod(Appc.SequenceAI_AddAI, None, SequenceAI)
SequenceAI.RemoveAI = new.instancemethod(Appc.SequenceAI_RemoveAI, None, SequenceAI)
SequenceAI.RemoveAIByIndex = new.instancemethod(Appc.SequenceAI_RemoveAIByIndex, None, SequenceAI)

class RandomAI(ArtificialIntelligence):
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C RandomAI instance at %s>" % (self.this,)
class RandomAIPtr(RandomAI):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = RandomAI


RandomAI.AddAI = new.instancemethod(Appc.RandomAI_AddAI, None, RandomAI)

class PreprocessingAI(ArtificialIntelligence):
    PS_NORMAL = Appc.PreprocessingAI_PS_NORMAL
    PS_SKIP_ACTIVE = Appc.PreprocessingAI_PS_SKIP_ACTIVE
    PS_SKIP_DORMANT = Appc.PreprocessingAI_PS_SKIP_DORMANT
    PS_DONE = Appc.PreprocessingAI_PS_DONE
    PS_INVALID = Appc.PreprocessingAI_PS_INVALID
    PS_NUM_STATUSES = Appc.PreprocessingAI_PS_NUM_STATUSES
    FDS_NORMAL = Appc.PreprocessingAI_FDS_NORMAL
    FDS_TRUE = Appc.PreprocessingAI_FDS_TRUE
    FDS_FALSE = Appc.PreprocessingAI_FDS_FALSE
    def __init__(self,this):
        self.this = this

    def GetContainedAI(*args):
        val = apply(Appc.PreprocessingAI_GetContainedAI,args)
        if val: val = ArtificialIntelligencePtr(val) 
        return val
    def __repr__(self):
        return "<C PreprocessingAI instance at %s>" % (self.this,)
class PreprocessingAIPtr(PreprocessingAI):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = PreprocessingAI


PreprocessingAI.SetPreprocessingMethod = new.instancemethod(Appc.PreprocessingAI_SetPreprocessingMethod, None, PreprocessingAI)
PreprocessingAI.GetPreprocessingInstance = new.instancemethod(Appc.PreprocessingAI_GetPreprocessingInstance, None, PreprocessingAI)
PreprocessingAI.SetContainedAI = new.instancemethod(Appc.PreprocessingAI_SetContainedAI, None, PreprocessingAI)
PreprocessingAI.ForceUpdate = new.instancemethod(Appc.PreprocessingAI_ForceUpdate, None, PreprocessingAI)
PreprocessingAI.ForceDormantStatus = new.instancemethod(Appc.PreprocessingAI_ForceDormantStatus, None, PreprocessingAI)
PreprocessingAI.ForceStatusChange = new.instancemethod(Appc.PreprocessingAI_ForceStatusChange, None, PreprocessingAI)

class ConditionalAI(ArtificialIntelligence,TGConditionHandler):
    def __init__(self,this):
        self.this = this

    def GetContainedAI(*args):
        val = apply(Appc.ConditionalAI_GetContainedAI,args)
        if val: val = ArtificialIntelligencePtr(val) 
        return val
    def __repr__(self):
        return "<C ConditionalAI instance at %s>" % (self.this,)
class ConditionalAIPtr(ConditionalAI):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = ConditionalAI


ConditionalAI.SetContainedAI = new.instancemethod(Appc.ConditionalAI_SetContainedAI, None, ConditionalAI)

class ConditionScript(TGCondition):
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C ConditionScript instance at %s>" % (self.this,)
class ConditionScriptPtr(ConditionScript):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = ConditionScript


ConditionScript.SetActive = new.instancemethod(Appc.ConditionScript_SetActive, None, ConditionScript)
ConditionScript.SetInactive = new.instancemethod(Appc.ConditionScript_SetInactive, None, ConditionScript)

class ConditionEventCreator(TGObject,TGConditionHandler):
    def __init__(self,*args):
        self.this = apply(Appc.new_ConditionEventCreator,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_ConditionEventCreator(self)
    def __repr__(self):
        return "<C ConditionEventCreator instance at %s>" % (self.this,)
class ConditionEventCreatorPtr(ConditionEventCreator):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = ConditionEventCreator


ConditionEventCreator.ConditionChanged = new.instancemethod(Appc.ConditionEventCreator_ConditionChanged, None, ConditionEventCreator)
ConditionEventCreator.SetEvent = new.instancemethod(Appc.ConditionEventCreator_SetEvent, None, ConditionEventCreator)

class FuzzyLogic:
    def __init__(self,*args):
        self.this = apply(Appc.new_FuzzyLogic,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_FuzzyLogic(self)
    def __repr__(self):
        return "<C FuzzyLogic instance at %s>" % (self.this,)
class FuzzyLogicPtr(FuzzyLogic):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = FuzzyLogic


FuzzyLogic.SetMaxRules = new.instancemethod(Appc.FuzzyLogic_SetMaxRules, None, FuzzyLogic)
FuzzyLogic.GetMaxRules = new.instancemethod(Appc.FuzzyLogic_GetMaxRules, None, FuzzyLogic)
FuzzyLogic.AddRule = new.instancemethod(Appc.FuzzyLogic_AddRule, None, FuzzyLogic)
FuzzyLogic.GetRule = new.instancemethod(Appc.FuzzyLogic_GetRule, None, FuzzyLogic)
FuzzyLogic.RemoveRule = new.instancemethod(Appc.FuzzyLogic_RemoveRule, None, FuzzyLogic)
FuzzyLogic.SetRuleConfidence = new.instancemethod(Appc.FuzzyLogic_SetRuleConfidence, None, FuzzyLogic)
FuzzyLogic.SetPercentageInSet = new.instancemethod(Appc.FuzzyLogic_SetPercentageInSet, None, FuzzyLogic)
FuzzyLogic.GetResultBySet = new.instancemethod(Appc.FuzzyLogic_GetResultBySet, None, FuzzyLogic)

class WaypointEvent(TGEvent):
    def __init__(self,*args):
        self.this = apply(Appc.new_WaypointEvent,args)
        self.thisown = 1

    def GetPlacement(*args):
        val = apply(Appc.WaypointEvent_GetPlacement,args)
        if val: val = PlacementObjectPtr(val) 
        return val
    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEvent(self)
    def __repr__(self):
        return "<C WaypointEvent instance at %s>" % (self.this,)
class WaypointEventPtr(WaypointEvent):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = WaypointEvent


WaypointEvent.Copy = new.instancemethod(Appc.WaypointEvent_Copy, None, WaypointEvent)
WaypointEvent.SetPlacement = new.instancemethod(Appc.WaypointEvent_SetPlacement, None, WaypointEvent)

class AIScriptAssist:
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C AIScriptAssist instance at %s>" % (self.this,)
class AIScriptAssistPtr(AIScriptAssist):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = AIScriptAssist



class OptimizedFireScript(PreprocessingAI):
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C OptimizedFireScript instance at %s>" % (self.this,)
class OptimizedFireScriptPtr(OptimizedFireScript):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = OptimizedFireScript


OptimizedFireScript.AddWeaponSystem = new.instancemethod(Appc.OptimizedFireScript_AddWeaponSystem, None, OptimizedFireScript)
OptimizedFireScript.RemoveAllWeaponSystems = new.instancemethod(Appc.OptimizedFireScript_RemoveAllWeaponSystems, None, OptimizedFireScript)
OptimizedFireScript.SetEnabled = new.instancemethod(Appc.OptimizedFireScript_SetEnabled, None, OptimizedFireScript)
OptimizedFireScript.HasSubsystemTargets = new.instancemethod(Appc.OptimizedFireScript_HasSubsystemTargets, None, OptimizedFireScript)
OptimizedFireScript.IgnoreSubsystemTargets = new.instancemethod(Appc.OptimizedFireScript_IgnoreSubsystemTargets, None, OptimizedFireScript)
OptimizedFireScript.RestoreSubsystemTargets = new.instancemethod(Appc.OptimizedFireScript_RestoreSubsystemTargets, None, OptimizedFireScript)
OptimizedFireScript.SetTarget = new.instancemethod(Appc.OptimizedFireScript_SetTarget, None, OptimizedFireScript)

class OptimizedSelectTarget(PreprocessingAI):
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C OptimizedSelectTarget instance at %s>" % (self.this,)
class OptimizedSelectTargetPtr(OptimizedSelectTarget):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = OptimizedSelectTarget


OptimizedSelectTarget.AddSetTargetTree = new.instancemethod(Appc.OptimizedSelectTarget_AddSetTargetTree, None, OptimizedSelectTarget)

class BuilderAI(PreprocessingAI):
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C BuilderAI instance at %s>" % (self.this,)
class BuilderAIPtr(BuilderAI):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = BuilderAI


BuilderAI.AddAIBlock = new.instancemethod(Appc.BuilderAI_AddAIBlock, None, BuilderAI)
BuilderAI.AddDependency = new.instancemethod(Appc.BuilderAI_AddDependency, None, BuilderAI)

class PhysicsObjectClass(ObjectClass):
    DIRECTION_MODEL_SPACE = Appc.PhysicsObjectClass_DIRECTION_MODEL_SPACE
    DIRECTION_WORLD_SPACE = Appc.PhysicsObjectClass_DIRECTION_WORLD_SPACE
    def __init__(self,this):
        self.this = this

    def GetVelocity(*args):
        val = apply(Appc.PhysicsObjectClass_GetVelocity,args)
        if val: val = NiPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetAcceleration(*args):
        val = apply(Appc.PhysicsObjectClass_GetAcceleration,args)
        if val: val = NiPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetAngularAcceleration(*args):
        val = apply(Appc.PhysicsObjectClass_GetAngularAcceleration,args)
        if val: val = NiPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetVelocityTG(*args):
        val = apply(Appc.PhysicsObjectClass_GetVelocityTG,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetAngularVelocityTG(*args):
        val = apply(Appc.PhysicsObjectClass_GetAngularVelocityTG,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetAccelerationTG(*args):
        val = apply(Appc.PhysicsObjectClass_GetAccelerationTG,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetAngularAccelerationTG(*args):
        val = apply(Appc.PhysicsObjectClass_GetAngularAccelerationTG,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetAngularVelocity(*args):
        val = apply(Appc.PhysicsObjectClass_GetAngularVelocity,args)
        if val: val = NiPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetPredictedPosition(*args):
        val = apply(Appc.PhysicsObjectClass_GetPredictedPosition,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetPredictedRotationTG(*args):
        val = apply(Appc.PhysicsObjectClass_GetPredictedRotationTG,args)
        if val: val = TGMatrix3Ptr(val) ; val.thisown = 1
        return val
    def GetAI(*args):
        val = apply(Appc.PhysicsObjectClass_GetAI,args)
        if val: val = ArtificialIntelligencePtr(val) 
        return val
    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEventHandlerObject(self)
    def __repr__(self):
        return "<C PhysicsObjectClass instance at %s>" % (self.this,)
class PhysicsObjectClassPtr(PhysicsObjectClass):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = PhysicsObjectClass


PhysicsObjectClass.SetStatic = new.instancemethod(Appc.PhysicsObjectClass_SetStatic, None, PhysicsObjectClass)
PhysicsObjectClass.IsStatic = new.instancemethod(Appc.PhysicsObjectClass_IsStatic, None, PhysicsObjectClass)
PhysicsObjectClass.SetupModel = new.instancemethod(Appc.PhysicsObjectClass_SetupModel, None, PhysicsObjectClass)
PhysicsObjectClass.ApplyForce = new.instancemethod(Appc.PhysicsObjectClass_ApplyForce, None, PhysicsObjectClass)
PhysicsObjectClass.GetMass = new.instancemethod(Appc.PhysicsObjectClass_GetMass, None, PhysicsObjectClass)
PhysicsObjectClass.GetRotationalInertia = new.instancemethod(Appc.PhysicsObjectClass_GetRotationalInertia, None, PhysicsObjectClass)
PhysicsObjectClass.SetMass = new.instancemethod(Appc.PhysicsObjectClass_SetMass, None, PhysicsObjectClass)
PhysicsObjectClass.SetRotationalInertia = new.instancemethod(Appc.PhysicsObjectClass_SetRotationalInertia, None, PhysicsObjectClass)
PhysicsObjectClass.SetVelocity = new.instancemethod(Appc.PhysicsObjectClass_SetVelocity, None, PhysicsObjectClass)
PhysicsObjectClass.SetAngularVelocity = new.instancemethod(Appc.PhysicsObjectClass_SetAngularVelocity, None, PhysicsObjectClass)
PhysicsObjectClass.TurnTowardOrientation = new.instancemethod(Appc.PhysicsObjectClass_TurnTowardOrientation, None, PhysicsObjectClass)
PhysicsObjectClass.SetAcceleration = new.instancemethod(Appc.PhysicsObjectClass_SetAcceleration, None, PhysicsObjectClass)
PhysicsObjectClass.SetAngularAcceleration = new.instancemethod(Appc.PhysicsObjectClass_SetAngularAcceleration, None, PhysicsObjectClass)
PhysicsObjectClass.SetAngularAccelerationLinear = new.instancemethod(Appc.PhysicsObjectClass_SetAngularAccelerationLinear, None, PhysicsObjectClass)
PhysicsObjectClass.SetAngularDirectionType = new.instancemethod(Appc.PhysicsObjectClass_SetAngularDirectionType, None, PhysicsObjectClass)
PhysicsObjectClass.GetAngularDirectionType = new.instancemethod(Appc.PhysicsObjectClass_GetAngularDirectionType, None, PhysicsObjectClass)
PhysicsObjectClass.SetNetType = new.instancemethod(Appc.PhysicsObjectClass_SetNetType, None, PhysicsObjectClass)
PhysicsObjectClass.GetNetType = new.instancemethod(Appc.PhysicsObjectClass_GetNetType, None, PhysicsObjectClass)
PhysicsObjectClass.SetDoNetUpdate = new.instancemethod(Appc.PhysicsObjectClass_SetDoNetUpdate, None, PhysicsObjectClass)
PhysicsObjectClass.IsDoingNetUpdate = new.instancemethod(Appc.PhysicsObjectClass_IsDoingNetUpdate, None, PhysicsObjectClass)
PhysicsObjectClass.SetUsePhysics = new.instancemethod(Appc.PhysicsObjectClass_SetUsePhysics, None, PhysicsObjectClass)
PhysicsObjectClass.IsUsingPhysics = new.instancemethod(Appc.PhysicsObjectClass_IsUsingPhysics, None, PhysicsObjectClass)
PhysicsObjectClass.SetAI = new.instancemethod(Appc.PhysicsObjectClass_SetAI, None, PhysicsObjectClass)
PhysicsObjectClass.ClearAI = new.instancemethod(Appc.PhysicsObjectClass_ClearAI, None, PhysicsObjectClass)
PhysicsObjectClass.HasBuildingAIs = new.instancemethod(Appc.PhysicsObjectClass_HasBuildingAIs, None, PhysicsObjectClass)

class DamageableObject(PhysicsObjectClass):
    def __init__(self,this):
        self.this = this

    def GetPropertySet(*args):
        val = apply(Appc.DamageableObject_GetPropertySet,args)
        if val: val = TGModelPropertySetPtr(val) 
        return val
    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEventHandlerObject(self)
    def __repr__(self):
        return "<C DamageableObject instance at %s>" % (self.this,)
class DamageableObjectPtr(DamageableObject):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = DamageableObject


DamageableObject.GetClonedModelRadius = new.instancemethod(Appc.DamageableObject_GetClonedModelRadius, None, DamageableObject)
DamageableObject.HasClonedModel = new.instancemethod(Appc.DamageableObject_HasClonedModel, None, DamageableObject)
DamageableObject.GetClonedModelCount = new.instancemethod(Appc.DamageableObject_GetClonedModelCount, None, DamageableObject)
DamageableObject.RemoveVisibleDamage = new.instancemethod(Appc.DamageableObject_RemoveVisibleDamage, None, DamageableObject)
DamageableObject.SetVisibleDamageRadiusModifier = new.instancemethod(Appc.DamageableObject_SetVisibleDamageRadiusModifier, None, DamageableObject)
DamageableObject.SetVisibleDamageStrengthModifier = new.instancemethod(Appc.DamageableObject_SetVisibleDamageStrengthModifier, None, DamageableObject)
DamageableObject.SetSpecularKs = new.instancemethod(Appc.DamageableObject_SetSpecularKs, None, DamageableObject)
DamageableObject.DisableGlowAlphaMaps = new.instancemethod(Appc.DamageableObject_DisableGlowAlphaMaps, None, DamageableObject)
DamageableObject.CanCollide = new.instancemethod(Appc.DamageableObject_CanCollide, None, DamageableObject)
DamageableObject.EnableCollisionsWith = new.instancemethod(Appc.DamageableObject_EnableCollisionsWith, None, DamageableObject)
DamageableObject.SetCollisionsOn = new.instancemethod(Appc.DamageableObject_SetCollisionsOn, None, DamageableObject)
DamageableObject.AddObjectDamageVolume = new.instancemethod(Appc.DamageableObject_AddObjectDamageVolume, None, DamageableObject)
DamageableObject.AddDamage = new.instancemethod(Appc.DamageableObject_AddDamage, None, DamageableObject)
DamageableObject.DamageRefresh = new.instancemethod(Appc.DamageableObject_DamageRefresh, None, DamageableObject)
DamageableObject.SetupProperties = new.instancemethod(Appc.DamageableObject_SetupProperties, None, DamageableObject)
DamageableObject.SetLifeTime = new.instancemethod(Appc.DamageableObject_SetLifeTime, None, DamageableObject)
DamageableObject.GetLifeTime = new.instancemethod(Appc.DamageableObject_GetLifeTime, None, DamageableObject)
DamageableObject.IsDying = new.instancemethod(Appc.DamageableObject_IsDying, None, DamageableObject)
DamageableObject.IsDead = new.instancemethod(Appc.DamageableObject_IsDead, None, DamageableObject)
DamageableObject.SetDead = new.instancemethod(Appc.DamageableObject_SetDead, None, DamageableObject)
DamageableObject.SetSplashDamage = new.instancemethod(Appc.DamageableObject_SetSplashDamage, None, DamageableObject)
DamageableObject.GetSplashDamage = new.instancemethod(Appc.DamageableObject_GetSplashDamage, None, DamageableObject)
DamageableObject.GetSplashDamageRadius = new.instancemethod(Appc.DamageableObject_GetSplashDamageRadius, None, DamageableObject)

class ShipClass(DamageableObject):
    WG_INVALID = Appc.ShipClass_WG_INVALID
    WG_PRIMARY = Appc.ShipClass_WG_PRIMARY
    WG_SECONDARY = Appc.ShipClass_WG_SECONDARY
    WG_TERTIARY = Appc.ShipClass_WG_TERTIARY
    WG_TRACTOR = Appc.ShipClass_WG_TRACTOR
    GREEN_ALERT = Appc.ShipClass_GREEN_ALERT
    YELLOW_ALERT = Appc.ShipClass_YELLOW_ALERT
    RED_ALERT = Appc.ShipClass_RED_ALERT
    def __init__(self,this):
        self.this = this

    def GetHull(*args):
        val = apply(Appc.ShipClass_GetHull,args)
        if val: val = HullClassPtr(val) 
        return val
    def GetShields(*args):
        val = apply(Appc.ShipClass_GetShields,args)
        if val: val = ShieldClassPtr(val) 
        return val
    def GetPowerSubsystem(*args):
        val = apply(Appc.ShipClass_GetPowerSubsystem,args)
        if val: val = PowerSubsystemPtr(val) 
        return val
    def GetSensorSubsystem(*args):
        val = apply(Appc.ShipClass_GetSensorSubsystem,args)
        if val: val = SensorSubsystemPtr(val) 
        return val
    def GetImpulseEngineSubsystem(*args):
        val = apply(Appc.ShipClass_GetImpulseEngineSubsystem,args)
        if val: val = ImpulseEngineSubsystemPtr(val) 
        return val
    def GetWarpEngineSubsystem(*args):
        val = apply(Appc.ShipClass_GetWarpEngineSubsystem,args)
        if val: val = WarpEngineSubsystemPtr(val) 
        return val
    def GetTorpedoSystem(*args):
        val = apply(Appc.ShipClass_GetTorpedoSystem,args)
        if val: val = TorpedoSystemPtr(val) 
        return val
    def GetPhaserSystem(*args):
        val = apply(Appc.ShipClass_GetPhaserSystem,args)
        if val: val = PhaserSystemPtr(val) 
        return val
    def GetPulseWeaponSystem(*args):
        val = apply(Appc.ShipClass_GetPulseWeaponSystem,args)
        if val: val = PulseWeaponSystemPtr(val) 
        return val
    def GetShipProperty(*args):
        val = apply(Appc.ShipClass_GetShipProperty,args)
        if val: val = ShipPropertyPtr(val) 
        return val
    def GetTractorBeamSystem(*args):
        val = apply(Appc.ShipClass_GetTractorBeamSystem,args)
        if val: val = TractorBeamSystemPtr(val) 
        return val
    def GetRepairSubsystem(*args):
        val = apply(Appc.ShipClass_GetRepairSubsystem,args)
        if val: val = RepairSubsystemPtr(val) 
        return val
    def GetCloakingSubsystem(*args):
        val = apply(Appc.ShipClass_GetCloakingSubsystem,args)
        if val: val = CloakingSubsystemPtr(val) 
        return val
    def GetWeaponSystemGroup(*args):
        val = apply(Appc.ShipClass_GetWeaponSystemGroup,args)
        if val: val = WeaponSystemPtr(val) 
        return val
    def GetSubsystemByProperty(*args):
        val = apply(Appc.ShipClass_GetSubsystemByProperty,args)
        if val: val = ShipSubsystemPtr(val) 
        return val
    def GetNextSubsystemMatch(*args):
        val = apply(Appc.ShipClass_GetNextSubsystemMatch,args)
        if val: val = ShipSubsystemPtr(val) 
        return val
    def GetTargetAngularVelocityTG(*args):
        val = apply(Appc.ShipClass_GetTargetAngularVelocityTG,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetTarget(*args):
        val = apply(Appc.ShipClass_GetTarget,args)
        if val: val = ObjectClassPtr(val) 
        return val
    def GetTargetSubsystem(*args):
        val = apply(Appc.ShipClass_GetTargetSubsystem,args)
        if val: val = ShipSubsystemPtr(val) 
        return val
    def GetTargetOffsetTG(*args):
        val = apply(Appc.ShipClass_GetTargetOffsetTG,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEventHandlerObject(self)
    def __repr__(self):
        return "<C ShipClass instance at %s>" % (self.this,)
class ShipClassPtr(ShipClass):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = ShipClass


ShipClass.SetScript = new.instancemethod(Appc.ShipClass_SetScript, None, ShipClass)
ShipClass.GetScript = new.instancemethod(Appc.ShipClass_GetScript, None, ShipClass)
ShipClass.SetDeathScript = new.instancemethod(Appc.ShipClass_SetDeathScript, None, ShipClass)
ShipClass.GetDeathScript = new.instancemethod(Appc.ShipClass_GetDeathScript, None, ShipClass)
ShipClass.RunDeathScript = new.instancemethod(Appc.ShipClass_RunDeathScript, None, ShipClass)
ShipClass.SetTargetable = new.instancemethod(Appc.ShipClass_SetTargetable, None, ShipClass)
ShipClass.IsTargetable = new.instancemethod(Appc.ShipClass_IsTargetable, None, ShipClass)
ShipClass.CanTargetObject = new.instancemethod(Appc.ShipClass_CanTargetObject, None, ShipClass)
ShipClass.SetInvincible = new.instancemethod(Appc.ShipClass_SetInvincible, None, ShipClass)
ShipClass.IsInvincible = new.instancemethod(Appc.ShipClass_IsInvincible, None, ShipClass)
ShipClass.SetHurtable = new.instancemethod(Appc.ShipClass_SetHurtable, None, ShipClass)
ShipClass.IsHurtable = new.instancemethod(Appc.ShipClass_IsHurtable, None, ShipClass)
ShipClass.SetDestroyBrokenSystems = new.instancemethod(Appc.ShipClass_SetDestroyBrokenSystems, None, ShipClass)
ShipClass.IsDestroyBrokenSystems = new.instancemethod(Appc.ShipClass_IsDestroyBrokenSystems, None, ShipClass)
ShipClass.GetWeaponGroupForSystem = new.instancemethod(Appc.ShipClass_GetWeaponGroupForSystem, None, ShipClass)
ShipClass.StopFiringWeapons = new.instancemethod(Appc.ShipClass_StopFiringWeapons, None, ShipClass)
ShipClass.CompleteStop = new.instancemethod(Appc.ShipClass_CompleteStop, None, ShipClass)
ShipClass.AddSubsystem = new.instancemethod(Appc.ShipClass_AddSubsystem, None, ShipClass)
ShipClass.StartGetSubsystemMatch = new.instancemethod(Appc.ShipClass_StartGetSubsystemMatch, None, ShipClass)
ShipClass.EndGetSubsystemMatch = new.instancemethod(Appc.ShipClass_EndGetSubsystemMatch, None, ShipClass)
ShipClass.SetImpulse = new.instancemethod(Appc.ShipClass_SetImpulse, None, ShipClass)
ShipClass.GetImpulse = new.instancemethod(Appc.ShipClass_GetImpulse, None, ShipClass)
ShipClass.IsReverse = new.instancemethod(Appc.ShipClass_IsReverse, None, ShipClass)
ShipClass.SetSpeed = new.instancemethod(Appc.ShipClass_SetSpeed, None, ShipClass)
ShipClass.SetAcceleration = new.instancemethod(Appc.ShipClass_SetAcceleration, None, ShipClass)
ShipClass.SetDisabledEngineDeceleration = new.instancemethod(Appc.ShipClass_SetDisabledEngineDeceleration, None, ShipClass)
ShipClass.InSystemWarp = new.instancemethod(Appc.ShipClass_InSystemWarp, None, ShipClass)
ShipClass.IsDoingInSystemWarp = new.instancemethod(Appc.ShipClass_IsDoingInSystemWarp, None, ShipClass)
ShipClass.StopInSystemWarp = new.instancemethod(Appc.ShipClass_StopInSystemWarp, None, ShipClass)
ShipClass.SetTargetAngularVelocityFraction = new.instancemethod(Appc.ShipClass_SetTargetAngularVelocityFraction, None, ShipClass)
ShipClass.SetTargetAngularVelocityDirect = new.instancemethod(Appc.ShipClass_SetTargetAngularVelocityDirect, None, ShipClass)
ShipClass.TurnTowardLocation = new.instancemethod(Appc.ShipClass_TurnTowardLocation, None, ShipClass)
ShipClass.TurnTowardDirection = new.instancemethod(Appc.ShipClass_TurnTowardDirection, None, ShipClass)
ShipClass.TurnTowardOrientation = new.instancemethod(Appc.ShipClass_TurnTowardOrientation, None, ShipClass)
ShipClass.TurnTowardDifference = new.instancemethod(Appc.ShipClass_TurnTowardDifference, None, ShipClass)
ShipClass.TurnDirectionsToDirections = new.instancemethod(Appc.ShipClass_TurnDirectionsToDirections, None, ShipClass)
ShipClass.IsCloaked = new.instancemethod(Appc.ShipClass_IsCloaked, None, ShipClass)
ShipClass.SetDocked = new.instancemethod(Appc.ShipClass_SetDocked, None, ShipClass)
ShipClass.IsDocked = new.instancemethod(Appc.ShipClass_IsDocked, None, ShipClass)
ShipClass.SetNetPlayerID = new.instancemethod(Appc.ShipClass_SetNetPlayerID, None, ShipClass)
ShipClass.GetNetPlayerID = new.instancemethod(Appc.ShipClass_GetNetPlayerID, None, ShipClass)
ShipClass.IsPlayerShip = new.instancemethod(Appc.ShipClass_IsPlayerShip, None, ShipClass)
ShipClass.GetNextTarget = new.instancemethod(Appc.ShipClass_GetNextTarget, None, ShipClass)
ShipClass.SetTarget = new.instancemethod(Appc.ShipClass_SetTarget, None, ShipClass)
ShipClass.SetTargetSubsystem = new.instancemethod(Appc.ShipClass_SetTargetSubsystem, None, ShipClass)
ShipClass.UseTargetOffsetTG = new.instancemethod(Appc.ShipClass_UseTargetOffsetTG, None, ShipClass)
ShipClass.DamageSystem = new.instancemethod(Appc.ShipClass_DamageSystem, None, ShipClass)
ShipClass.DestroySystem = new.instancemethod(Appc.ShipClass_DestroySystem, None, ShipClass)
ShipClass.GetAffiliation = new.instancemethod(Appc.ShipClass_GetAffiliation, None, ShipClass)
ShipClass.SetAffiliation = new.instancemethod(Appc.ShipClass_SetAffiliation, None, ShipClass)
ShipClass.GetAlertLevel = new.instancemethod(Appc.ShipClass_GetAlertLevel, None, ShipClass)
ShipClass.SetAlertLevel = new.instancemethod(Appc.ShipClass_SetAlertLevel, None, ShipClass)
ShipClass.DisableCollisionDamage = new.instancemethod(Appc.ShipClass_DisableCollisionDamage, None, ShipClass)
ShipClass.IsCollisionDamageDisabled = new.instancemethod(Appc.ShipClass_IsCollisionDamageDisabled, None, ShipClass)
ShipClass.IncrementAIDoneIgnore = new.instancemethod(Appc.ShipClass_IncrementAIDoneIgnore, None, ShipClass)

class ObjectGroup(TGEventHandlerObject):
    GROUP_CHANGED = Appc.ObjectGroup_GROUP_CHANGED
    ENTERED_SET = Appc.ObjectGroup_ENTERED_SET
    EXITED_SET = Appc.ObjectGroup_EXITED_SET
    DESTROYED = Appc.ObjectGroup_DESTROYED
    def __init__(self,*args):
        self.this = apply(Appc.new_ObjectGroup,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_ObjectGroup(self)
    def __repr__(self):
        return "<C ObjectGroup instance at %s>" % (self.this,)
class ObjectGroupPtr(ObjectGroup):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = ObjectGroup


ObjectGroup.SetEventFlag = new.instancemethod(Appc.ObjectGroup_SetEventFlag, None, ObjectGroup)
ObjectGroup.ClearEventFlag = new.instancemethod(Appc.ObjectGroup_ClearEventFlag, None, ObjectGroup)
ObjectGroup.IsEventFlagSet = new.instancemethod(Appc.ObjectGroup_IsEventFlagSet, None, ObjectGroup)
ObjectGroup.AddName = new.instancemethod(Appc.ObjectGroup_AddName, None, ObjectGroup)
ObjectGroup.RemoveName = new.instancemethod(Appc.ObjectGroup_RemoveName, None, ObjectGroup)
ObjectGroup.RemoveAllNames = new.instancemethod(Appc.ObjectGroup_RemoveAllNames, None, ObjectGroup)
ObjectGroup.IsNameInGroup = new.instancemethod(Appc.ObjectGroup_IsNameInGroup, None, ObjectGroup)
ObjectGroup.GetNumActiveObjects = new.instancemethod(Appc.ObjectGroup_GetNumActiveObjects, None, ObjectGroup)

class ObjectGroupWithInfo(ObjectGroup):
    def __init__(self,*args):
        self.this = apply(Appc.new_ObjectGroupWithInfo,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_ObjectGroupWithInfo(self)
    def __repr__(self):
        return "<C ObjectGroupWithInfo instance at %s>" % (self.this,)
class ObjectGroupWithInfoPtr(ObjectGroupWithInfo):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = ObjectGroupWithInfo



class ShipSubsystem(TGEventHandlerObject):
    def __init__(self,*args):
        self.this = apply(Appc.new_ShipSubsystem,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_ShipSubsystem(self)
    def GetProperty(*args):
        val = apply(Appc.ShipSubsystem_GetProperty,args)
        if val: val = SubsystemPropertyPtr(val) 
        return val
    def GetDisplayName(*args):
        val = apply(Appc.ShipSubsystem_GetDisplayName,args)
        if val: val = TGStringPtr(val) ; val.thisown = 1
        return val
    def GetPosition(*args):
        val = apply(Appc.ShipSubsystem_GetPosition,args)
        if val: val = NiPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetPositionTG(*args):
        val = apply(Appc.ShipSubsystem_GetPositionTG,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetWorldLocation(*args):
        val = apply(Appc.ShipSubsystem_GetWorldLocation,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetParentShip(*args):
        val = apply(Appc.ShipSubsystem_GetParentShip,args)
        if val: val = ShipClassPtr(val) 
        return val
    def GetConditionWatcher(*args):
        val = apply(Appc.ShipSubsystem_GetConditionWatcher,args)
        if val: val = FloatRangeWatcherPtr(val) 
        return val
    def GetParentSubsystem(*args):
        val = apply(Appc.ShipSubsystem_GetParentSubsystem,args)
        if val: val = ShipSubsystemPtr(val) 
        return val
    def GetChildSubsystem(*args):
        val = apply(Appc.ShipSubsystem_GetChildSubsystem,args)
        if val: val = ShipSubsystemPtr(val) 
        return val
    def GetNextTargetableChildSubsystem(*args):
        val = apply(Appc.ShipSubsystem_GetNextTargetableChildSubsystem,args)
        if val: val = ShipSubsystemPtr(val) 
        return val
    def GetCombinedPercentageWatcher(*args):
        val = apply(Appc.ShipSubsystem_GetCombinedPercentageWatcher,args)
        if val: val = FloatRangeWatcherPtr(val) 
        return val
    def GetDamagePoint(*args):
        val = apply(Appc.ShipSubsystem_GetDamagePoint,args)
        if val: val = NiPoint3Ptr(val) ; val.thisown = 1
        return val
    def __repr__(self):
        return "<C ShipSubsystem instance at %s>" % (self.this,)
class ShipSubsystemPtr(ShipSubsystem):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = ShipSubsystem


ShipSubsystem.GetName = new.instancemethod(Appc.ShipSubsystem_GetName, None, ShipSubsystem)
ShipSubsystem.GetCondition = new.instancemethod(Appc.ShipSubsystem_GetCondition, None, ShipSubsystem)
ShipSubsystem.GetMaxCondition = new.instancemethod(Appc.ShipSubsystem_GetMaxCondition, None, ShipSubsystem)
ShipSubsystem.GetConditionPercentage = new.instancemethod(Appc.ShipSubsystem_GetConditionPercentage, None, ShipSubsystem)
ShipSubsystem.GetCombinedConditionPercentage = new.instancemethod(Appc.ShipSubsystem_GetCombinedConditionPercentage, None, ShipSubsystem)
ShipSubsystem.GetDamage = new.instancemethod(Appc.ShipSubsystem_GetDamage, None, ShipSubsystem)
ShipSubsystem.GetRepairPointsNeeded = new.instancemethod(Appc.ShipSubsystem_GetRepairPointsNeeded, None, ShipSubsystem)
ShipSubsystem.GetRadius = new.instancemethod(Appc.ShipSubsystem_GetRadius, None, ShipSubsystem)
ShipSubsystem.GetLastUpdateLength = new.instancemethod(Appc.ShipSubsystem_GetLastUpdateLength, None, ShipSubsystem)
ShipSubsystem.IsCritical = new.instancemethod(Appc.ShipSubsystem_IsCritical, None, ShipSubsystem)
ShipSubsystem.IsTargetable = new.instancemethod(Appc.ShipSubsystem_IsTargetable, None, ShipSubsystem)
ShipSubsystem.GetRepairComplexity = new.instancemethod(Appc.ShipSubsystem_GetRepairComplexity, None, ShipSubsystem)
ShipSubsystem.GetDisabledPercentage = new.instancemethod(Appc.ShipSubsystem_GetDisabledPercentage, None, ShipSubsystem)
ShipSubsystem.IsDisabled = new.instancemethod(Appc.ShipSubsystem_IsDisabled, None, ShipSubsystem)
ShipSubsystem.IsHittableFromLocation = new.instancemethod(Appc.ShipSubsystem_IsHittableFromLocation, None, ShipSubsystem)
ShipSubsystem.GetChildSubsystems = new.instancemethod(Appc.ShipSubsystem_GetChildSubsystems, None, ShipSubsystem)
ShipSubsystem.GetChildSubsystemIndex = new.instancemethod(Appc.ShipSubsystem_GetChildSubsystemIndex, None, ShipSubsystem)
ShipSubsystem.GetNumChildSubsystems = new.instancemethod(Appc.ShipSubsystem_GetNumChildSubsystems, None, ShipSubsystem)
ShipSubsystem.GetLastChildSubsystemIndex = new.instancemethod(Appc.ShipSubsystem_GetLastChildSubsystemIndex, None, ShipSubsystem)
ShipSubsystem.HasTargetableChildSubsystem = new.instancemethod(Appc.ShipSubsystem_HasTargetableChildSubsystem, None, ShipSubsystem)
ShipSubsystem.AddChildSubsystem = new.instancemethod(Appc.ShipSubsystem_AddChildSubsystem, None, ShipSubsystem)
ShipSubsystem.SetCondition = new.instancemethod(Appc.ShipSubsystem_SetCondition, None, ShipSubsystem)
ShipSubsystem.SetConditionPercentage = new.instancemethod(Appc.ShipSubsystem_SetConditionPercentage, None, ShipSubsystem)
ShipSubsystem.IsInvincible = new.instancemethod(Appc.ShipSubsystem_IsInvincible, None, ShipSubsystem)
ShipSubsystem.SetInvincible = new.instancemethod(Appc.ShipSubsystem_SetInvincible, None, ShipSubsystem)
ShipSubsystem.SetParentShip = new.instancemethod(Appc.ShipSubsystem_SetParentShip, None, ShipSubsystem)
ShipSubsystem.SetParentSubsystem = new.instancemethod(Appc.ShipSubsystem_SetParentSubsystem, None, ShipSubsystem)
ShipSubsystem.SetProperty = new.instancemethod(Appc.ShipSubsystem_SetProperty, None, ShipSubsystem)
ShipSubsystem.Repair = new.instancemethod(Appc.ShipSubsystem_Repair, None, ShipSubsystem)
ShipSubsystem.Update = new.instancemethod(Appc.ShipSubsystem_Update, None, ShipSubsystem)
ShipSubsystem.UpdateDamagePoint = new.instancemethod(Appc.ShipSubsystem_UpdateDamagePoint, None, ShipSubsystem)

class PoweredSubsystem(ShipSubsystem):
    def __init__(self,*args):
        self.this = apply(Appc.new_PoweredSubsystem,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_PoweredSubsystem(self)
    def GetProperty(*args):
        val = apply(Appc.PoweredSubsystem_GetProperty,args)
        if val: val = PoweredSubsystemPropertyPtr(val) 
        return val
    def __repr__(self):
        return "<C PoweredSubsystem instance at %s>" % (self.this,)
class PoweredSubsystemPtr(PoweredSubsystem):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = PoweredSubsystem


PoweredSubsystem.GetPowerPercentageWanted = new.instancemethod(Appc.PoweredSubsystem_GetPowerPercentageWanted, None, PoweredSubsystem)
PoweredSubsystem.SetPowerPercentageWanted = new.instancemethod(Appc.PoweredSubsystem_SetPowerPercentageWanted, None, PoweredSubsystem)
PoweredSubsystem.GetPowerWanted = new.instancemethod(Appc.PoweredSubsystem_GetPowerWanted, None, PoweredSubsystem)
PoweredSubsystem.GetNormalPowerWanted = new.instancemethod(Appc.PoweredSubsystem_GetNormalPowerWanted, None, PoweredSubsystem)
PoweredSubsystem.SetPowerWanted = new.instancemethod(Appc.PoweredSubsystem_SetPowerWanted, None, PoweredSubsystem)
PoweredSubsystem.SetPowerSource = new.instancemethod(Appc.PoweredSubsystem_SetPowerSource, None, PoweredSubsystem)
PoweredSubsystem.GetPowerReceived = new.instancemethod(Appc.PoweredSubsystem_GetPowerReceived, None, PoweredSubsystem)
PoweredSubsystem.GetPowerPercentage = new.instancemethod(Appc.PoweredSubsystem_GetPowerPercentage, None, PoweredSubsystem)
PoweredSubsystem.GetNormalPowerPercentage = new.instancemethod(Appc.PoweredSubsystem_GetNormalPowerPercentage, None, PoweredSubsystem)
PoweredSubsystem.TurnOn = new.instancemethod(Appc.PoweredSubsystem_TurnOn, None, PoweredSubsystem)
PoweredSubsystem.TurnOff = new.instancemethod(Appc.PoweredSubsystem_TurnOff, None, PoweredSubsystem)
PoweredSubsystem.Turn = new.instancemethod(Appc.PoweredSubsystem_Turn, None, PoweredSubsystem)
PoweredSubsystem.IsOn = new.instancemethod(Appc.PoweredSubsystem_IsOn, None, PoweredSubsystem)

class PowerSubsystem(ShipSubsystem):
    def __init__(self,*args):
        self.this = apply(Appc.new_PowerSubsystem,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_PowerSubsystem(self)
    def GetProperty(*args):
        val = apply(Appc.PowerSubsystem_GetProperty,args)
        if val: val = PowerPropertyPtr(val) 
        return val
    def GetMainBatteryWatcher(*args):
        val = apply(Appc.PowerSubsystem_GetMainBatteryWatcher,args)
        if val: val = FloatRangeWatcherPtr(val) 
        return val
    def GetBackupBatteryWatcher(*args):
        val = apply(Appc.PowerSubsystem_GetBackupBatteryWatcher,args)
        if val: val = FloatRangeWatcherPtr(val) 
        return val
    def __repr__(self):
        return "<C PowerSubsystem instance at %s>" % (self.this,)
class PowerSubsystemPtr(PowerSubsystem):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = PowerSubsystem


PowerSubsystem.GetAvailablePower = new.instancemethod(Appc.PowerSubsystem_GetAvailablePower, None, PowerSubsystem)
PowerSubsystem.GetMainBatteryPower = new.instancemethod(Appc.PowerSubsystem_GetMainBatteryPower, None, PowerSubsystem)
PowerSubsystem.GetBackupBatteryPower = new.instancemethod(Appc.PowerSubsystem_GetBackupBatteryPower, None, PowerSubsystem)
PowerSubsystem.GetPowerOutput = new.instancemethod(Appc.PowerSubsystem_GetPowerOutput, None, PowerSubsystem)
PowerSubsystem.GetMainBatteryLimit = new.instancemethod(Appc.PowerSubsystem_GetMainBatteryLimit, None, PowerSubsystem)
PowerSubsystem.GetBackupBatteryLimit = new.instancemethod(Appc.PowerSubsystem_GetBackupBatteryLimit, None, PowerSubsystem)
PowerSubsystem.GetMaxMainConduitCapacity = new.instancemethod(Appc.PowerSubsystem_GetMaxMainConduitCapacity, None, PowerSubsystem)
PowerSubsystem.GetMainConduitCapacity = new.instancemethod(Appc.PowerSubsystem_GetMainConduitCapacity, None, PowerSubsystem)
PowerSubsystem.GetBackupConduitCapacity = new.instancemethod(Appc.PowerSubsystem_GetBackupConduitCapacity, None, PowerSubsystem)
PowerSubsystem.SetAvailablePower = new.instancemethod(Appc.PowerSubsystem_SetAvailablePower, None, PowerSubsystem)
PowerSubsystem.SetMainBatteryPower = new.instancemethod(Appc.PowerSubsystem_SetMainBatteryPower, None, PowerSubsystem)
PowerSubsystem.SetBackupBatteryPower = new.instancemethod(Appc.PowerSubsystem_SetBackupBatteryPower, None, PowerSubsystem)
PowerSubsystem.AddPower = new.instancemethod(Appc.PowerSubsystem_AddPower, None, PowerSubsystem)
PowerSubsystem.DeductPower = new.instancemethod(Appc.PowerSubsystem_DeductPower, None, PowerSubsystem)
PowerSubsystem.StealPower = new.instancemethod(Appc.PowerSubsystem_StealPower, None, PowerSubsystem)
PowerSubsystem.StealPowerFromReserve = new.instancemethod(Appc.PowerSubsystem_StealPowerFromReserve, None, PowerSubsystem)
PowerSubsystem.GetPowerWanted = new.instancemethod(Appc.PowerSubsystem_GetPowerWanted, None, PowerSubsystem)
PowerSubsystem.GetPowerDispensed = new.instancemethod(Appc.PowerSubsystem_GetPowerDispensed, None, PowerSubsystem)

class Weapon(ShipSubsystem):
    def __init__(self,*args):
        self.this = apply(Appc.new_Weapon,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_Weapon(self)
    def GetProperty(*args):
        val = apply(Appc.Weapon_GetProperty,args)
        if val: val = WeaponPropertyPtr(val) 
        return val
    def CalculateRoughDirection(*args):
        val = apply(Appc.Weapon_CalculateRoughDirection,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def __repr__(self):
        return "<C Weapon instance at %s>" % (self.this,)
class WeaponPtr(Weapon):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = Weapon


Weapon.StopFiring = new.instancemethod(Appc.Weapon_StopFiring, None, Weapon)
Weapon.Fire = new.instancemethod(Appc.Weapon_Fire, None, Weapon)
Weapon.FireDumb = new.instancemethod(Appc.Weapon_FireDumb, None, Weapon)
Weapon.CanFire = new.instancemethod(Appc.Weapon_CanFire, None, Weapon)
Weapon.IsFiring = new.instancemethod(Appc.Weapon_IsFiring, None, Weapon)
Weapon.SetFiring = new.instancemethod(Appc.Weapon_SetFiring, None, Weapon)
Weapon.IsMemberOfGroup = new.instancemethod(Appc.Weapon_IsMemberOfGroup, None, Weapon)
Weapon.GetOverallConditionPercentage = new.instancemethod(Appc.Weapon_GetOverallConditionPercentage, None, Weapon)
Weapon.GetDamageRadiusFactor = new.instancemethod(Appc.Weapon_GetDamageRadiusFactor, None, Weapon)
Weapon.IsDumbFire = new.instancemethod(Appc.Weapon_IsDumbFire, None, Weapon)
Weapon.CalculateWeaponAppeal = new.instancemethod(Appc.Weapon_CalculateWeaponAppeal, None, Weapon)
Weapon.GetTargetID = new.instancemethod(Appc.Weapon_GetTargetID, None, Weapon)

class FiringChain:
    def __init__(self,*args):
        self.this = apply(Appc.new_FiringChain,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_FiringChain(self)
    def __repr__(self):
        return "<C FiringChain instance at %s>" % (self.this,)
class FiringChainPtr(FiringChain):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = FiringChain


FiringChain.GetName = new.instancemethod(Appc.FiringChain_GetName, None, FiringChain)
FiringChain.GetWeaponGroups = new.instancemethod(Appc.FiringChain_GetWeaponGroups, None, FiringChain)
FiringChain.SetName = new.instancemethod(Appc.FiringChain_SetName, None, FiringChain)
FiringChain.SetWeaponGroups = new.instancemethod(Appc.FiringChain_SetWeaponGroups, None, FiringChain)
FiringChain.HasGroup = new.instancemethod(Appc.FiringChain_HasGroup, None, FiringChain)
FiringChain.GetFirstGroup = new.instancemethod(Appc.FiringChain_GetFirstGroup, None, FiringChain)
FiringChain.GetNextGroup = new.instancemethod(Appc.FiringChain_GetNextGroup, None, FiringChain)

class WeaponSystem(PoweredSubsystem):
    def __init__(self,*args):
        self.this = apply(Appc.new_WeaponSystem,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_WeaponSystem(self)
    def GetProperty(*args):
        val = apply(Appc.WeaponSystem_GetProperty,args)
        if val: val = WeaponSystemPropertyPtr(val) 
        return val
    def GetWeapon(*args):
        val = apply(Appc.WeaponSystem_GetWeapon,args)
        if val: val = WeaponPtr(val) 
        return val
    def UpdateWeapons(*args):
        val = apply(Appc.WeaponSystem_UpdateWeapons,args)
        if val: val = WeaponPtr(val) 
        return val
    def GetFiringChain(*args):
        val = apply(Appc.WeaponSystem_GetFiringChain,args)
        if val: val = FiringChainPtr(val) 
        return val
    def GetLastWeaponFired(*args):
        val = apply(Appc.WeaponSystem_GetLastWeaponFired,args)
        if val: val = WeaponPtr(val) 
        return val
    def GetNextWeapon(*args):
        val = apply(Appc.WeaponSystem_GetNextWeapon,args)
        if val: val = WeaponPtr(val) 
        return val
    def __repr__(self):
        return "<C WeaponSystem instance at %s>" % (self.this,)
class WeaponSystemPtr(WeaponSystem):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = WeaponSystem


WeaponSystem.IsSingleFire = new.instancemethod(Appc.WeaponSystem_IsSingleFire, None, WeaponSystem)
WeaponSystem.ShouldBeAimed = new.instancemethod(Appc.WeaponSystem_ShouldBeAimed, None, WeaponSystem)
WeaponSystem.IsTryingToFire = new.instancemethod(Appc.WeaponSystem_IsTryingToFire, None, WeaponSystem)
WeaponSystem.IsFiring = new.instancemethod(Appc.WeaponSystem_IsFiring, None, WeaponSystem)
WeaponSystem.CanFire = new.instancemethod(Appc.WeaponSystem_CanFire, None, WeaponSystem)
WeaponSystem.StartFiring = new.instancemethod(Appc.WeaponSystem_StartFiring, None, WeaponSystem)
WeaponSystem.StopFiring = new.instancemethod(Appc.WeaponSystem_StopFiring, None, WeaponSystem)
WeaponSystem.StopFiringAtTarget = new.instancemethod(Appc.WeaponSystem_StopFiringAtTarget, None, WeaponSystem)
WeaponSystem.ClearTargetList = new.instancemethod(Appc.WeaponSystem_ClearTargetList, None, WeaponSystem)
WeaponSystem.IsInTargetList = new.instancemethod(Appc.WeaponSystem_IsInTargetList, None, WeaponSystem)
WeaponSystem.SetForceUpdate = new.instancemethod(Appc.WeaponSystem_SetForceUpdate, None, WeaponSystem)
WeaponSystem.RemoveFromTargetList = new.instancemethod(Appc.WeaponSystem_RemoveFromTargetList, None, WeaponSystem)
WeaponSystem.UpdateTargetList = new.instancemethod(Appc.WeaponSystem_UpdateTargetList, None, WeaponSystem)
WeaponSystem.GetGroupFireMode = new.instancemethod(Appc.WeaponSystem_GetGroupFireMode, None, WeaponSystem)
WeaponSystem.SetGroupFireMode = new.instancemethod(Appc.WeaponSystem_SetGroupFireMode, None, WeaponSystem)
WeaponSystem.GetFiringChainMode = new.instancemethod(Appc.WeaponSystem_GetFiringChainMode, None, WeaponSystem)
WeaponSystem.SetFiringChainMode = new.instancemethod(Appc.WeaponSystem_SetFiringChainMode, None, WeaponSystem)
WeaponSystem.GetNumFiringChains = new.instancemethod(Appc.WeaponSystem_GetNumFiringChains, None, WeaponSystem)
WeaponSystem.GetFiringChainName = new.instancemethod(Appc.WeaponSystem_GetFiringChainName, None, WeaponSystem)
WeaponSystem.GetLastGroupFired = new.instancemethod(Appc.WeaponSystem_GetLastGroupFired, None, WeaponSystem)
WeaponSystem.Fire = new.instancemethod(Appc.WeaponSystem_Fire, None, WeaponSystem)

class WeaponPayload:
    WP_DEFAULT = Appc.WeaponPayload_WP_DEFAULT
    WP_PHASER = Appc.WeaponPayload_WP_PHASER
    WP_TORPEDO = Appc.WeaponPayload_WP_TORPEDO
    WP_PULSE = Appc.WeaponPayload_WP_PULSE
    WP_TRACTOR = Appc.WeaponPayload_WP_TRACTOR
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C WeaponPayload instance at %s>" % (self.this,)
class WeaponPayloadPtr(WeaponPayload):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = WeaponPayload


WeaponPayload.GetID = new.instancemethod(Appc.WeaponPayload_GetID, None, WeaponPayload)
WeaponPayload.GetPayloadType = new.instancemethod(Appc.WeaponPayload_GetPayloadType, None, WeaponPayload)
WeaponPayload.GetDamageRadiusFactor = new.instancemethod(Appc.WeaponPayload_GetDamageRadiusFactor, None, WeaponPayload)
WeaponPayload.NextID = new.instancemethod(Appc.WeaponPayload_NextID, None, WeaponPayload)
WeaponPayload.SetDamageRadiusFactor = new.instancemethod(Appc.WeaponPayload_SetDamageRadiusFactor, None, WeaponPayload)

class Torpedo(PhysicsObjectClass,WeaponPayload):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_Torpedo(self)
    def __repr__(self):
        return "<C Torpedo instance at %s>" % (self.this,)
class TorpedoPtr(Torpedo):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = Torpedo


Torpedo.GetModuleName = new.instancemethod(Appc.Torpedo_GetModuleName, None, Torpedo)
Torpedo.CreateDisruptorModel = new.instancemethod(Appc.Torpedo_CreateDisruptorModel, None, Torpedo)
Torpedo.CreateTorpedoModel = new.instancemethod(Appc.Torpedo_CreateTorpedoModel, None, Torpedo)
Torpedo.GetLaunchSpeed = new.instancemethod(Appc.Torpedo_GetLaunchSpeed, None, Torpedo)
Torpedo.GetLaunchSound = new.instancemethod(Appc.Torpedo_GetLaunchSound, None, Torpedo)
Torpedo.SetParent = new.instancemethod(Appc.Torpedo_SetParent, None, Torpedo)
Torpedo.SetTarget = new.instancemethod(Appc.Torpedo_SetTarget, None, Torpedo)
Torpedo.SetTargetOffset = new.instancemethod(Appc.Torpedo_SetTargetOffset, None, Torpedo)
Torpedo.SetMaxAngularAccel = new.instancemethod(Appc.Torpedo_SetMaxAngularAccel, None, Torpedo)
Torpedo.SetGuidanceLifetime = new.instancemethod(Appc.Torpedo_SetGuidanceLifetime, None, Torpedo)
Torpedo.SetDamage = new.instancemethod(Appc.Torpedo_SetDamage, None, Torpedo)
Torpedo.SetLifetime = new.instancemethod(Appc.Torpedo_SetLifetime, None, Torpedo)
Torpedo.GetTargetID = new.instancemethod(Appc.Torpedo_GetTargetID, None, Torpedo)
Torpedo.GetParentID = new.instancemethod(Appc.Torpedo_GetParentID, None, Torpedo)
Torpedo.SetPlayerID = new.instancemethod(Appc.Torpedo_SetPlayerID, None, Torpedo)
Torpedo.GetPlayerID = new.instancemethod(Appc.Torpedo_GetPlayerID, None, Torpedo)
Torpedo.GetMaxAngularAccel = new.instancemethod(Appc.Torpedo_GetMaxAngularAccel, None, Torpedo)
Torpedo.GetDamage = new.instancemethod(Appc.Torpedo_GetDamage, None, Torpedo)
Torpedo.GetLifetime = new.instancemethod(Appc.Torpedo_GetLifetime, None, Torpedo)
Torpedo.GetGuidanceLifeTime = new.instancemethod(Appc.Torpedo_GetGuidanceLifeTime, None, Torpedo)
Torpedo.DetectCollision = new.instancemethod(Appc.Torpedo_DetectCollision, None, Torpedo)
Torpedo.TurnTowardOrientation = new.instancemethod(Appc.Torpedo_TurnTowardOrientation, None, Torpedo)

class TorpedoSystem(WeaponSystem):
    def __init__(self,*args):
        self.this = apply(Appc.new_TorpedoSystem,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TorpedoSystem(self)
    def GetProperty(*args):
        val = apply(Appc.TorpedoSystem_GetProperty,args)
        if val: val = TorpedoSystemPropertyPtr(val) 
        return val
    def GetCurrentAmmoType(*args):
        val = apply(Appc.TorpedoSystem_GetCurrentAmmoType,args)
        if val: val = TorpedoAmmoTypePtr(val) 
        return val
    def GetAmmoType(*args):
        val = apply(Appc.TorpedoSystem_GetAmmoType,args)
        if val: val = TorpedoAmmoTypePtr(val) 
        return val
    def __repr__(self):
        return "<C TorpedoSystem instance at %s>" % (self.this,)
class TorpedoSystemPtr(TorpedoSystem):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TorpedoSystem


TorpedoSystem.SetAmmoType = new.instancemethod(Appc.TorpedoSystem_SetAmmoType, None, TorpedoSystem)
TorpedoSystem.GetCurrentAmmoTypeNumber = new.instancemethod(Appc.TorpedoSystem_GetCurrentAmmoTypeNumber, None, TorpedoSystem)
TorpedoSystem.SetSkewFire = new.instancemethod(Appc.TorpedoSystem_SetSkewFire, None, TorpedoSystem)
TorpedoSystem.GetNumAmmoTypes = new.instancemethod(Appc.TorpedoSystem_GetNumAmmoTypes, None, TorpedoSystem)
TorpedoSystem.RemoveAmmoType = new.instancemethod(Appc.TorpedoSystem_RemoveAmmoType, None, TorpedoSystem)
TorpedoSystem.FillAmmoType = new.instancemethod(Appc.TorpedoSystem_FillAmmoType, None, TorpedoSystem)
TorpedoSystem.LoadAmmoType = new.instancemethod(Appc.TorpedoSystem_LoadAmmoType, None, TorpedoSystem)
TorpedoSystem.GetNumReady = new.instancemethod(Appc.TorpedoSystem_GetNumReady, None, TorpedoSystem)
TorpedoSystem.IsTubeReady = new.instancemethod(Appc.TorpedoSystem_IsTubeReady, None, TorpedoSystem)
TorpedoSystem.GetAmmoTypeNumber = new.instancemethod(Appc.TorpedoSystem_GetAmmoTypeNumber, None, TorpedoSystem)
TorpedoSystem.GetNumAvailableTorpsToType = new.instancemethod(Appc.TorpedoSystem_GetNumAvailableTorpsToType, None, TorpedoSystem)

class TorpedoTube(Weapon):
    def __init__(self,*args):
        self.this = apply(Appc.new_TorpedoTube,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TorpedoTube(self)
    def GetProperty(*args):
        val = apply(Appc.TorpedoTube_GetProperty,args)
        if val: val = TorpedoTubePropertyPtr(val) 
        return val
    def GetDirection(*args):
        val = apply(Appc.TorpedoTube_GetDirection,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetRight(*args):
        val = apply(Appc.TorpedoTube_GetRight,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def __repr__(self):
        return "<C TorpedoTube instance at %s>" % (self.this,)
class TorpedoTubePtr(TorpedoTube):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TorpedoTube


TorpedoTube.SetProperty = new.instancemethod(Appc.TorpedoTube_SetProperty, None, TorpedoTube)
TorpedoTube.SetNumReady = new.instancemethod(Appc.TorpedoTube_SetNumReady, None, TorpedoTube)
TorpedoTube.IncNumReady = new.instancemethod(Appc.TorpedoTube_IncNumReady, None, TorpedoTube)
TorpedoTube.DecNumReady = new.instancemethod(Appc.TorpedoTube_DecNumReady, None, TorpedoTube)
TorpedoTube.SetLastFireTime = new.instancemethod(Appc.TorpedoTube_SetLastFireTime, None, TorpedoTube)
TorpedoTube.SetSkewFire = new.instancemethod(Appc.TorpedoTube_SetSkewFire, None, TorpedoTube)
TorpedoTube.GetNumReady = new.instancemethod(Appc.TorpedoTube_GetNumReady, None, TorpedoTube)
TorpedoTube.GetLastFireTime = new.instancemethod(Appc.TorpedoTube_GetLastFireTime, None, TorpedoTube)
TorpedoTube.GetImmediateDelay = new.instancemethod(Appc.TorpedoTube_GetImmediateDelay, None, TorpedoTube)
TorpedoTube.GetReloadDelay = new.instancemethod(Appc.TorpedoTube_GetReloadDelay, None, TorpedoTube)
TorpedoTube.GetMaxReady = new.instancemethod(Appc.TorpedoTube_GetMaxReady, None, TorpedoTube)
TorpedoTube.IsSkewFire = new.instancemethod(Appc.TorpedoTube_IsSkewFire, None, TorpedoTube)
TorpedoTube.ReloadTorpedo = new.instancemethod(Appc.TorpedoTube_ReloadTorpedo, None, TorpedoTube)
TorpedoTube.UnloadTorpedo = new.instancemethod(Appc.TorpedoTube_UnloadTorpedo, None, TorpedoTube)
TorpedoTube.CanHit = new.instancemethod(Appc.TorpedoTube_CanHit, None, TorpedoTube)
TorpedoTube.IsInArc = new.instancemethod(Appc.TorpedoTube_IsInArc, None, TorpedoTube)

class Nebula(ObjectClass):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEventHandlerObject(self)
    def __repr__(self):
        return "<C Nebula instance at %s>" % (self.this,)
class NebulaPtr(Nebula):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = Nebula


Nebula.SetupDamage = new.instancemethod(Appc.Nebula_SetupDamage, None, Nebula)
Nebula.IsObjectInNebula = new.instancemethod(Appc.Nebula_IsObjectInNebula, None, Nebula)

class MetaNebula(Nebula):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEventHandlerObject(self)
    def __repr__(self):
        return "<C MetaNebula instance at %s>" % (self.this,)
class MetaNebulaPtr(MetaNebula):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = MetaNebula


MetaNebula.AddNebulaSphere = new.instancemethod(Appc.MetaNebula_AddNebulaSphere, None, MetaNebula)

class Planet(ObjectClass):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEventHandlerObject(self)
    def __repr__(self):
        return "<C Planet instance at %s>" % (self.this,)
class PlanetPtr(Planet):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = Planet


Planet.SetAtmosphereRadius = new.instancemethod(Appc.Planet_SetAtmosphereRadius, None, Planet)
Planet.GetAtmosphereRadius = new.instancemethod(Appc.Planet_GetAtmosphereRadius, None, Planet)
Planet.SetEnvironmentalShieldDamage = new.instancemethod(Appc.Planet_SetEnvironmentalShieldDamage, None, Planet)
Planet.SetEnvironmentalHullDamage = new.instancemethod(Appc.Planet_SetEnvironmentalHullDamage, None, Planet)

class Sun(Planet):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEventHandlerObject(self)
    def __repr__(self):
        return "<C Sun instance at %s>" % (self.this,)
class SunPtr(Sun):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = Sun



class ProximityManager:
    def __init__(self,*args):
        self.this = apply(Appc.new_ProximityManager,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_ProximityManager(self)
    def GetNextObject(*args):
        val = apply(Appc.ProximityManager_GetNextObject,args)
        if val: val = ObjectClassPtr(val) 
        return val
    def __repr__(self):
        return "<C ProximityManager instance at %s>" % (self.this,)
class ProximityManagerPtr(ProximityManager):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = ProximityManager


ProximityManager.AddObject = new.instancemethod(Appc.ProximityManager_AddObject, None, ProximityManager)
ProximityManager.RemoveObject = new.instancemethod(Appc.ProximityManager_RemoveObject, None, ProximityManager)
ProximityManager.DumpCollisions = new.instancemethod(Appc.ProximityManager_DumpCollisions, None, ProximityManager)
ProximityManager.GetNearObjects = new.instancemethod(Appc.ProximityManager_GetNearObjects, None, ProximityManager)
ProximityManager.GetLineIntersectObjects = new.instancemethod(Appc.ProximityManager_GetLineIntersectObjects, None, ProximityManager)
ProximityManager.EndObjectIteration = new.instancemethod(Appc.ProximityManager_EndObjectIteration, None, ProximityManager)
ProximityManager.Update = new.instancemethod(Appc.ProximityManager_Update, None, ProximityManager)
ProximityManager.UpdateObject = new.instancemethod(Appc.ProximityManager_UpdateObject, None, ProximityManager)

class ProximityCheck(ObjectClass):
    TT_INSIDE = Appc.ProximityCheck_TT_INSIDE
    TT_OUTSIDE = Appc.ProximityCheck_TT_OUTSIDE
    TT_INVALID = Appc.ProximityCheck_TT_INVALID
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEventHandlerObject(self)
    def __repr__(self):
        return "<C ProximityCheck instance at %s>" % (self.this,)
class ProximityCheckPtr(ProximityCheck):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = ProximityCheck


ProximityCheck.SetRadius = new.instancemethod(Appc.ProximityCheck_SetRadius, None, ProximityCheck)
ProximityCheck.SetIgnoreObjectSize = new.instancemethod(Appc.ProximityCheck_SetIgnoreObjectSize, None, ProximityCheck)
ProximityCheck.GetIgnoreObjectSize = new.instancemethod(Appc.ProximityCheck_GetIgnoreObjectSize, None, ProximityCheck)
ProximityCheck.AddObjectToCheckList = new.instancemethod(Appc.ProximityCheck_AddObjectToCheckList, None, ProximityCheck)
ProximityCheck.AddObjectToCheckListByID = new.instancemethod(Appc.ProximityCheck_AddObjectToCheckListByID, None, ProximityCheck)
ProximityCheck.AddObjectListToCheckList = new.instancemethod(Appc.ProximityCheck_AddObjectListToCheckList, None, ProximityCheck)
ProximityCheck.AddObjectTypeToCheckList = new.instancemethod(Appc.ProximityCheck_AddObjectTypeToCheckList, None, ProximityCheck)
ProximityCheck.IsObjectInCheckList = new.instancemethod(Appc.ProximityCheck_IsObjectInCheckList, None, ProximityCheck)
ProximityCheck.GetTriggerType = new.instancemethod(Appc.ProximityCheck_GetTriggerType, None, ProximityCheck)
ProximityCheck.SetTriggerType = new.instancemethod(Appc.ProximityCheck_SetTriggerType, None, ProximityCheck)
ProximityCheck.RemoveObjectFromCheckList = new.instancemethod(Appc.ProximityCheck_RemoveObjectFromCheckList, None, ProximityCheck)
ProximityCheck.RemoveObjectFromCheckListByID = new.instancemethod(Appc.ProximityCheck_RemoveObjectFromCheckListByID, None, ProximityCheck)
ProximityCheck.RemoveObjectTypeFromCheckList = new.instancemethod(Appc.ProximityCheck_RemoveObjectTypeFromCheckList, None, ProximityCheck)
ProximityCheck.ClearCheckList = new.instancemethod(Appc.ProximityCheck_ClearCheckList, None, ProximityCheck)
ProximityCheck.CheckProximity = new.instancemethod(Appc.ProximityCheck_CheckProximity, None, ProximityCheck)
ProximityCheck.RemoveAndDelete = new.instancemethod(Appc.ProximityCheck_RemoveAndDelete, None, ProximityCheck)

class ProximityEvent(TGEvent):
    def __init__(self,*args):
        self.this = apply(Appc.new_ProximityEvent,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_ProximityEvent(self)
    def GetProximityCheck(*args):
        val = apply(Appc.ProximityEvent_GetProximityCheck,args)
        if val: val = ProximityCheckPtr(val) 
        return val
    def GetObject(*args):
        val = apply(Appc.ProximityEvent_GetObject,args)
        if val: val = ObjectClassPtr(val) 
        return val
    def __repr__(self):
        return "<C ProximityEvent instance at %s>" % (self.this,)
class ProximityEventPtr(ProximityEvent):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = ProximityEvent


ProximityEvent.SetProximityCheck = new.instancemethod(Appc.ProximityEvent_SetProximityCheck, None, ProximityEvent)
ProximityEvent.SetObject = new.instancemethod(Appc.ProximityEvent_SetObject, None, ProximityEvent)
ProximityEvent.Serialize = new.instancemethod(Appc.ProximityEvent_Serialize, None, ProximityEvent)
ProximityEvent.UnSerialize = new.instancemethod(Appc.ProximityEvent_UnSerialize, None, ProximityEvent)
ProximityEvent.CanFixupPtrs = new.instancemethod(Appc.ProximityEvent_CanFixupPtrs, None, ProximityEvent)
ProximityEvent.FixupPtrs = new.instancemethod(Appc.ProximityEvent_FixupPtrs, None, ProximityEvent)

class WeaponHitEvent(TGEvent):
    PHASER = Appc.WeaponHitEvent_PHASER
    TORPEDO = Appc.WeaponHitEvent_TORPEDO
    TRACTOR_BEAM = Appc.WeaponHitEvent_TRACTOR_BEAM
    def __init__(self,this):
        self.this = this

    def GetFiringObject(*args):
        val = apply(Appc.WeaponHitEvent_GetFiringObject,args)
        if val: val = ObjectClassPtr(val) 
        return val
    def GetTargetObject(*args):
        val = apply(Appc.WeaponHitEvent_GetTargetObject,args)
        if val: val = ObjectClassPtr(val) 
        return val
    def GetObjectHitPoint(*args):
        val = apply(Appc.WeaponHitEvent_GetObjectHitPoint,args)
        if val: val = NiPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetObjectHitNormal(*args):
        val = apply(Appc.WeaponHitEvent_GetObjectHitNormal,args)
        if val: val = NiPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetWorldHitPoint(*args):
        val = apply(Appc.WeaponHitEvent_GetWorldHitPoint,args)
        if val: val = NiPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetWorldHitNormal(*args):
        val = apply(Appc.WeaponHitEvent_GetWorldHitNormal,args)
        if val: val = NiPoint3Ptr(val) ; val.thisown = 1
        return val
    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEvent(self)
    def __repr__(self):
        return "<C WeaponHitEvent instance at %s>" % (self.this,)
class WeaponHitEventPtr(WeaponHitEvent):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = WeaponHitEvent


WeaponHitEvent.GetCondition = new.instancemethod(Appc.WeaponHitEvent_GetCondition, None, WeaponHitEvent)
WeaponHitEvent.GetWeaponInstanceID = new.instancemethod(Appc.WeaponHitEvent_GetWeaponInstanceID, None, WeaponHitEvent)
WeaponHitEvent.GetRadius = new.instancemethod(Appc.WeaponHitEvent_GetRadius, None, WeaponHitEvent)
WeaponHitEvent.GetDamage = new.instancemethod(Appc.WeaponHitEvent_GetDamage, None, WeaponHitEvent)
WeaponHitEvent.GetWeaponType = new.instancemethod(Appc.WeaponHitEvent_GetWeaponType, None, WeaponHitEvent)
WeaponHitEvent.IsHullHit = new.instancemethod(Appc.WeaponHitEvent_IsHullHit, None, WeaponHitEvent)
WeaponHitEvent.SetFiringPlayerID = new.instancemethod(Appc.WeaponHitEvent_SetFiringPlayerID, None, WeaponHitEvent)
WeaponHitEvent.GetFiringPlayerID = new.instancemethod(Appc.WeaponHitEvent_GetFiringPlayerID, None, WeaponHitEvent)

class StartFiringEvent(TGEvent):
    def __init__(self,this):
        self.this = this

    def GetTarget(*args):
        val = apply(Appc.StartFiringEvent_GetTarget,args)
        if val: val = ObjectClassPtr(val) 
        return val
    def GetOffset(*args):
        val = apply(Appc.StartFiringEvent_GetOffset,args)
        if val: val = NiPoint3Ptr(val) ; val.thisown = 1
        return val
    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEvent(self)
    def __repr__(self):
        return "<C StartFiringEvent instance at %s>" % (self.this,)
class StartFiringEventPtr(StartFiringEvent):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = StartFiringEvent



class ObjectExplodingEvent(TGEvent):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEvent(self)
    def __repr__(self):
        return "<C ObjectExplodingEvent instance at %s>" % (self.this,)
class ObjectExplodingEventPtr(ObjectExplodingEvent):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = ObjectExplodingEvent


ObjectExplodingEvent.SetFiringPlayerID = new.instancemethod(Appc.ObjectExplodingEvent_SetFiringPlayerID, None, ObjectExplodingEvent)
ObjectExplodingEvent.GetFiringPlayerID = new.instancemethod(Appc.ObjectExplodingEvent_GetFiringPlayerID, None, ObjectExplodingEvent)
ObjectExplodingEvent.SetLifetime = new.instancemethod(Appc.ObjectExplodingEvent_SetLifetime, None, ObjectExplodingEvent)
ObjectExplodingEvent.GetLifetime = new.instancemethod(Appc.ObjectExplodingEvent_GetLifetime, None, ObjectExplodingEvent)

class CollisionEvent(TGEvent):
    def __init__(self,this):
        self.this = this

    def GetPoint(*args):
        val = apply(Appc.CollisionEvent_GetPoint,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEvent(self)
    def __repr__(self):
        return "<C CollisionEvent instance at %s>" % (self.this,)
class CollisionEventPtr(CollisionEvent):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = CollisionEvent


CollisionEvent.GetNumPoints = new.instancemethod(Appc.CollisionEvent_GetNumPoints, None, CollisionEvent)
CollisionEvent.GetCollisionForce = new.instancemethod(Appc.CollisionEvent_GetCollisionForce, None, CollisionEvent)

class ShieldClass(PoweredSubsystem):
    NO_SHIELD = Appc.ShieldClass_NO_SHIELD
    FRONT_SHIELDS = Appc.ShieldClass_FRONT_SHIELDS
    REAR_SHIELDS = Appc.ShieldClass_REAR_SHIELDS
    TOP_SHIELDS = Appc.ShieldClass_TOP_SHIELDS
    BOTTOM_SHIELDS = Appc.ShieldClass_BOTTOM_SHIELDS
    LEFT_SHIELDS = Appc.ShieldClass_LEFT_SHIELDS
    RIGHT_SHIELDS = Appc.ShieldClass_RIGHT_SHIELDS
    NUM_SHIELDS = Appc.ShieldClass_NUM_SHIELDS
    def __init__(self,this):
        self.this = this

    def GetProperty(*args):
        val = apply(Appc.ShieldClass_GetProperty,args)
        if val: val = ShieldPropertyPtr(val) 
        return val
    def GetShieldWatcher(*args):
        val = apply(Appc.ShieldClass_GetShieldWatcher,args)
        if val: val = FloatRangeWatcherPtr(val) 
        return val
    def GetShieldGlowColor(*args):
        val = apply(Appc.ShieldClass_GetShieldGlowColor,args)
        if val: val = TGColorAPtr(val) ; val.thisown = 1
        return val
    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_PoweredSubsystem(self)
    def __repr__(self):
        return "<C ShieldClass instance at %s>" % (self.this,)
class ShieldClassPtr(ShieldClass):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = ShieldClass


ShieldClass.GetNumShields = new.instancemethod(Appc.ShieldClass_GetNumShields, None, ShieldClass)
ShieldClass.BoostShield = new.instancemethod(Appc.ShieldClass_BoostShield, None, ShieldClass)
ShieldClass.GetShieldPercentage = new.instancemethod(Appc.ShieldClass_GetShieldPercentage, None, ShieldClass)
ShieldClass.GetSingleShieldPercentage = new.instancemethod(Appc.ShieldClass_GetSingleShieldPercentage, None, ShieldClass)
ShieldClass.SetCurShields = new.instancemethod(Appc.ShieldClass_SetCurShields, None, ShieldClass)
ShieldClass.GetCurShields = new.instancemethod(Appc.ShieldClass_GetCurShields, None, ShieldClass)
ShieldClass.GetMaxShields = new.instancemethod(Appc.ShieldClass_GetMaxShields, None, ShieldClass)
ShieldClass.IsShieldBreached = new.instancemethod(Appc.ShieldClass_IsShieldBreached, None, ShieldClass)
ShieldClass.IsAnyShieldBreached = new.instancemethod(Appc.ShieldClass_IsAnyShieldBreached, None, ShieldClass)
ShieldClass.RedistributeShields = new.instancemethod(Appc.ShieldClass_RedistributeShields, None, ShieldClass)
ShieldClass.GetShieldChargePerSecond = new.instancemethod(Appc.ShieldClass_GetShieldChargePerSecond, None, ShieldClass)
ShieldClass.IsShieldDamaged = new.instancemethod(Appc.ShieldClass_IsShieldDamaged, None, ShieldClass)
ShieldClass.SetShieldDamaged = new.instancemethod(Appc.ShieldClass_SetShieldDamaged, None, ShieldClass)
ShieldClass.GetOppositeShield = new.instancemethod(Appc.ShieldClass_GetOppositeShield, None, ShieldClass)
ShieldClass.GetShieldGlowDecay = new.instancemethod(Appc.ShieldClass_GetShieldGlowDecay, None, ShieldClass)

class HullClass(ShipSubsystem):
    def __init__(self,*args):
        self.this = apply(Appc.new_HullClass,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_HullClass(self)
    def __repr__(self):
        return "<C HullClass instance at %s>" % (self.this,)
class HullClassPtr(HullClass):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = HullClass



class EnergyWeapon(Weapon):
    EW_LOW = Appc.EnergyWeapon_EW_LOW
    EW_MEDIUM = Appc.EnergyWeapon_EW_MEDIUM
    EW_HIGH = Appc.EnergyWeapon_EW_HIGH
    def __init__(self,*args):
        self.this = apply(Appc.new_EnergyWeapon,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_EnergyWeapon(self)
    def GetProperty(*args):
        val = apply(Appc.EnergyWeapon_GetProperty,args)
        if val: val = EnergyWeaponPropertyPtr(val) 
        return val
    def GetChargeWatcher(*args):
        val = apply(Appc.EnergyWeapon_GetChargeWatcher,args)
        if val: val = FloatRangeWatcherPtr(val) 
        return val
    def __repr__(self):
        return "<C EnergyWeapon instance at %s>" % (self.this,)
class EnergyWeaponPtr(EnergyWeapon):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = EnergyWeapon


EnergyWeapon.GetRechargeRate = new.instancemethod(Appc.EnergyWeapon_GetRechargeRate, None, EnergyWeapon)
EnergyWeapon.GetNormalDischargeRate = new.instancemethod(Appc.EnergyWeapon_GetNormalDischargeRate, None, EnergyWeapon)
EnergyWeapon.GetMaxCharge = new.instancemethod(Appc.EnergyWeapon_GetMaxCharge, None, EnergyWeapon)
EnergyWeapon.GetMinFiringCharge = new.instancemethod(Appc.EnergyWeapon_GetMinFiringCharge, None, EnergyWeapon)
EnergyWeapon.GetFireSound = new.instancemethod(Appc.EnergyWeapon_GetFireSound, None, EnergyWeapon)
EnergyWeapon.GetFireStartSound = new.instancemethod(Appc.EnergyWeapon_GetFireStartSound, None, EnergyWeapon)
EnergyWeapon.GetFireLoopSound = new.instancemethod(Appc.EnergyWeapon_GetFireLoopSound, None, EnergyWeapon)
EnergyWeapon.GetPowerSetting = new.instancemethod(Appc.EnergyWeapon_GetPowerSetting, None, EnergyWeapon)
EnergyWeapon.GetMaxDamage = new.instancemethod(Appc.EnergyWeapon_GetMaxDamage, None, EnergyWeapon)
EnergyWeapon.GetMaxDamageDistance = new.instancemethod(Appc.EnergyWeapon_GetMaxDamageDistance, None, EnergyWeapon)
EnergyWeapon.GetChargeLevel = new.instancemethod(Appc.EnergyWeapon_GetChargeLevel, None, EnergyWeapon)
EnergyWeapon.GetChargePercentage = new.instancemethod(Appc.EnergyWeapon_GetChargePercentage, None, EnergyWeapon)
EnergyWeapon.SetChargeLevel = new.instancemethod(Appc.EnergyWeapon_SetChargeLevel, None, EnergyWeapon)
EnergyWeapon.SetPowerSetting = new.instancemethod(Appc.EnergyWeapon_SetPowerSetting, None, EnergyWeapon)
EnergyWeapon.UpdateCharge = new.instancemethod(Appc.EnergyWeapon_UpdateCharge, None, EnergyWeapon)
EnergyWeapon.CalculateWeaponAppeal = new.instancemethod(Appc.EnergyWeapon_CalculateWeaponAppeal, None, EnergyWeapon)

class PhaserSystem(WeaponSystem):
    PP_LOW = Appc.PhaserSystem_PP_LOW
    PP_MEDIUM = Appc.PhaserSystem_PP_MEDIUM
    PP_HIGH = Appc.PhaserSystem_PP_HIGH
    def __init__(self,*args):
        self.this = apply(Appc.new_PhaserSystem,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_PhaserSystem(self)
    def __repr__(self):
        return "<C PhaserSystem instance at %s>" % (self.this,)
class PhaserSystemPtr(PhaserSystem):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = PhaserSystem


PhaserSystem.SetPowerLevel = new.instancemethod(Appc.PhaserSystem_SetPowerLevel, None, PhaserSystem)
PhaserSystem.GetPowerLevel = new.instancemethod(Appc.PhaserSystem_GetPowerLevel, None, PhaserSystem)

class PhaserBank(EnergyWeapon):
    def __init__(self,*args):
        self.this = apply(Appc.new_PhaserBank,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_PhaserBank(self)
    def GetProperty(*args):
        val = apply(Appc.PhaserBank_GetProperty,args)
        if val: val = PhaserPropertyPtr(val) 
        return val
    def GetOrientationForward(*args):
        val = apply(Appc.PhaserBank_GetOrientationForward,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetOrientationUp(*args):
        val = apply(Appc.PhaserBank_GetOrientationUp,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetOrientationRight(*args):
        val = apply(Appc.PhaserBank_GetOrientationRight,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def __repr__(self):
        return "<C PhaserBank instance at %s>" % (self.this,)
class PhaserBankPtr(PhaserBank):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = PhaserBank


PhaserBank.GetWidth = new.instancemethod(Appc.PhaserBank_GetWidth, None, PhaserBank)
PhaserBank.GetLength = new.instancemethod(Appc.PhaserBank_GetLength, None, PhaserBank)
PhaserBank.GetPhaserTextureStart = new.instancemethod(Appc.PhaserBank_GetPhaserTextureStart, None, PhaserBank)
PhaserBank.GetPhaserTextureEnd = new.instancemethod(Appc.PhaserBank_GetPhaserTextureEnd, None, PhaserBank)
PhaserBank.GetPhaserWidth = new.instancemethod(Appc.PhaserBank_GetPhaserWidth, None, PhaserBank)
PhaserBank.GetArcWidthAngles = new.instancemethod(Appc.PhaserBank_GetArcWidthAngles, None, PhaserBank)
PhaserBank.GetArcHeightAngles = new.instancemethod(Appc.PhaserBank_GetArcHeightAngles, None, PhaserBank)
PhaserBank.GetArcWidthAngleMin = new.instancemethod(Appc.PhaserBank_GetArcWidthAngleMin, None, PhaserBank)
PhaserBank.GetArcWidthAngleMax = new.instancemethod(Appc.PhaserBank_GetArcWidthAngleMax, None, PhaserBank)
PhaserBank.GetArcHeightAngleMin = new.instancemethod(Appc.PhaserBank_GetArcHeightAngleMin, None, PhaserBank)
PhaserBank.GetArcHeightAngleMax = new.instancemethod(Appc.PhaserBank_GetArcHeightAngleMax, None, PhaserBank)
PhaserBank.UpdateCharge = new.instancemethod(Appc.PhaserBank_UpdateCharge, None, PhaserBank)
PhaserBank.CanHit = new.instancemethod(Appc.PhaserBank_CanHit, None, PhaserBank)

class PulseWeapon(EnergyWeapon):
    def __init__(self,*args):
        self.this = apply(Appc.new_PulseWeapon,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_PulseWeapon(self)
    def GetProperty(*args):
        val = apply(Appc.PulseWeapon_GetProperty,args)
        if val: val = PulseWeaponPropertyPtr(val) 
        return val
    def CalculateRoughDirection(*args):
        val = apply(Appc.PulseWeapon_CalculateRoughDirection,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def __repr__(self):
        return "<C PulseWeapon instance at %s>" % (self.this,)
class PulseWeaponPtr(PulseWeapon):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = PulseWeapon


PulseWeapon.CanHitTarget = new.instancemethod(Appc.PulseWeapon_CanHitTarget, None, PulseWeapon)
PulseWeapon.GetPowerScaled = new.instancemethod(Appc.PulseWeapon_GetPowerScaled, None, PulseWeapon)
PulseWeapon.GetDamageScale = new.instancemethod(Appc.PulseWeapon_GetDamageScale, None, PulseWeapon)
PulseWeapon.GetArcHeightAngleMin = new.instancemethod(Appc.PulseWeapon_GetArcHeightAngleMin, None, PulseWeapon)
PulseWeapon.GetArcHeightAngleMax = new.instancemethod(Appc.PulseWeapon_GetArcHeightAngleMax, None, PulseWeapon)
PulseWeapon.GetArcWidthAngleMin = new.instancemethod(Appc.PulseWeapon_GetArcWidthAngleMin, None, PulseWeapon)
PulseWeapon.GetArcWidthAngleMax = new.instancemethod(Appc.PulseWeapon_GetArcWidthAngleMax, None, PulseWeapon)
PulseWeapon.GetArcHeightAngles = new.instancemethod(Appc.PulseWeapon_GetArcHeightAngles, None, PulseWeapon)
PulseWeapon.GetArcWidthAngles = new.instancemethod(Appc.PulseWeapon_GetArcWidthAngles, None, PulseWeapon)
PulseWeapon.GetLastFireTime = new.instancemethod(Appc.PulseWeapon_GetLastFireTime, None, PulseWeapon)
PulseWeapon.GetCooldownTime = new.instancemethod(Appc.PulseWeapon_GetCooldownTime, None, PulseWeapon)
PulseWeapon.GetLaunchSpeed = new.instancemethod(Appc.PulseWeapon_GetLaunchSpeed, None, PulseWeapon)
PulseWeapon.IsInArc = new.instancemethod(Appc.PulseWeapon_IsInArc, None, PulseWeapon)
PulseWeapon.CalculateWeaponAppeal = new.instancemethod(Appc.PulseWeapon_CalculateWeaponAppeal, None, PulseWeapon)

class PulseWeaponSystem(WeaponSystem):
    def __init__(self,*args):
        self.this = apply(Appc.new_PulseWeaponSystem,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_PulseWeaponSystem(self)
    def __repr__(self):
        return "<C PulseWeaponSystem instance at %s>" % (self.this,)
class PulseWeaponSystemPtr(PulseWeaponSystem):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = PulseWeaponSystem



class SensorSubsystem(PoweredSubsystem):
    def __init__(self,*args):
        self.this = apply(Appc.new_SensorSubsystem,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_SensorSubsystem(self)
    def GetProperty(*args):
        val = apply(Appc.SensorSubsystem_GetProperty,args)
        if val: val = SensorPropertyPtr(val) 
        return val
    def ScanAllObjects(*args):
        val = apply(Appc.SensorSubsystem_ScanAllObjects,args)
        if val: val = TGSequencePtr(val) 
        return val
    def __repr__(self):
        return "<C SensorSubsystem instance at %s>" % (self.this,)
class SensorSubsystemPtr(SensorSubsystem):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = SensorSubsystem


SensorSubsystem.GetSensorRange = new.instancemethod(Appc.SensorSubsystem_GetSensorRange, None, SensorSubsystem)
SensorSubsystem.GetBaseSensorRange = new.instancemethod(Appc.SensorSubsystem_GetBaseSensorRange, None, SensorSubsystem)
SensorSubsystem.IdentifyObject = new.instancemethod(Appc.SensorSubsystem_IdentifyObject, None, SensorSubsystem)
SensorSubsystem.ForceObjectIdentified = new.instancemethod(Appc.SensorSubsystem_ForceObjectIdentified, None, SensorSubsystem)
SensorSubsystem.GetIdentificationTime = new.instancemethod(Appc.SensorSubsystem_GetIdentificationTime, None, SensorSubsystem)
SensorSubsystem.GetNumProbes = new.instancemethod(Appc.SensorSubsystem_GetNumProbes, None, SensorSubsystem)
SensorSubsystem.SetNumProbes = new.instancemethod(Appc.SensorSubsystem_SetNumProbes, None, SensorSubsystem)
SensorSubsystem.AddProbe = new.instancemethod(Appc.SensorSubsystem_AddProbe, None, SensorSubsystem)
SensorSubsystem.IsObjectVisible = new.instancemethod(Appc.SensorSubsystem_IsObjectVisible, None, SensorSubsystem)
SensorSubsystem.IsObjectNear = new.instancemethod(Appc.SensorSubsystem_IsObjectNear, None, SensorSubsystem)
SensorSubsystem.IsObjectFar = new.instancemethod(Appc.SensorSubsystem_IsObjectFar, None, SensorSubsystem)
SensorSubsystem.IsObjectKnown = new.instancemethod(Appc.SensorSubsystem_IsObjectKnown, None, SensorSubsystem)

class CloakingSubsystem(PoweredSubsystem):
    def __init__(self,*args):
        self.this = apply(Appc.new_CloakingSubsystem,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_CloakingSubsystem(self)
    def GetProperty(*args):
        val = apply(Appc.CloakingSubsystem_GetProperty,args)
        if val: val = CloakingSubsystemPropertyPtr(val) 
        return val
    def __repr__(self):
        return "<C CloakingSubsystem instance at %s>" % (self.this,)
class CloakingSubsystemPtr(CloakingSubsystem):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = CloakingSubsystem


CloakingSubsystem.StartCloaking = new.instancemethod(Appc.CloakingSubsystem_StartCloaking, None, CloakingSubsystem)
CloakingSubsystem.StopCloaking = new.instancemethod(Appc.CloakingSubsystem_StopCloaking, None, CloakingSubsystem)
CloakingSubsystem.InstantCloak = new.instancemethod(Appc.CloakingSubsystem_InstantCloak, None, CloakingSubsystem)
CloakingSubsystem.InstantDecloak = new.instancemethod(Appc.CloakingSubsystem_InstantDecloak, None, CloakingSubsystem)
CloakingSubsystem.IsCloaked = new.instancemethod(Appc.CloakingSubsystem_IsCloaked, None, CloakingSubsystem)
CloakingSubsystem.IsTryingToCloak = new.instancemethod(Appc.CloakingSubsystem_IsTryingToCloak, None, CloakingSubsystem)
CloakingSubsystem.IsCloaking = new.instancemethod(Appc.CloakingSubsystem_IsCloaking, None, CloakingSubsystem)
CloakingSubsystem.IsDecloaking = new.instancemethod(Appc.CloakingSubsystem_IsDecloaking, None, CloakingSubsystem)

class RepairSubsystem(PoweredSubsystem):
    def __init__(self,*args):
        self.this = apply(Appc.new_RepairSubsystem,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_RepairSubsystem(self)
    def GetProperty(*args):
        val = apply(Appc.RepairSubsystem_GetProperty,args)
        if val: val = RepairSubsystemPropertyPtr(val) 
        return val
    def __repr__(self):
        return "<C RepairSubsystem instance at %s>" % (self.this,)
class RepairSubsystemPtr(RepairSubsystem):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = RepairSubsystem


RepairSubsystem.AddSubsystem = new.instancemethod(Appc.RepairSubsystem_AddSubsystem, None, RepairSubsystem)
RepairSubsystem.AddToRepairList = new.instancemethod(Appc.RepairSubsystem_AddToRepairList, None, RepairSubsystem)
RepairSubsystem.IsBeingRepaired = new.instancemethod(Appc.RepairSubsystem_IsBeingRepaired, None, RepairSubsystem)

class ImpulseEngineSubsystem(PoweredSubsystem):
    def __init__(self,*args):
        self.this = apply(Appc.new_ImpulseEngineSubsystem,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_ImpulseEngineSubsystem(self)
    def GetProperty(*args):
        val = apply(Appc.ImpulseEngineSubsystem_GetProperty,args)
        if val: val = ImpulseEnginePropertyPtr(val) 
        return val
    def GetTractorBeamSystem(*args):
        val = apply(Appc.ImpulseEngineSubsystem_GetTractorBeamSystem,args)
        if val: val = TractorBeamSystemPtr(val) 
        return val
    def __repr__(self):
        return "<C ImpulseEngineSubsystem instance at %s>" % (self.this,)
class ImpulseEngineSubsystemPtr(ImpulseEngineSubsystem):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = ImpulseEngineSubsystem


ImpulseEngineSubsystem.GetMaxSpeed = new.instancemethod(Appc.ImpulseEngineSubsystem_GetMaxSpeed, None, ImpulseEngineSubsystem)
ImpulseEngineSubsystem.GetMaxAccel = new.instancemethod(Appc.ImpulseEngineSubsystem_GetMaxAccel, None, ImpulseEngineSubsystem)
ImpulseEngineSubsystem.GetMaxAngularVelocity = new.instancemethod(Appc.ImpulseEngineSubsystem_GetMaxAngularVelocity, None, ImpulseEngineSubsystem)
ImpulseEngineSubsystem.GetMaxAngularAccel = new.instancemethod(Appc.ImpulseEngineSubsystem_GetMaxAngularAccel, None, ImpulseEngineSubsystem)
ImpulseEngineSubsystem.GetCurMaxSpeed = new.instancemethod(Appc.ImpulseEngineSubsystem_GetCurMaxSpeed, None, ImpulseEngineSubsystem)
ImpulseEngineSubsystem.GetCurMaxAccel = new.instancemethod(Appc.ImpulseEngineSubsystem_GetCurMaxAccel, None, ImpulseEngineSubsystem)
ImpulseEngineSubsystem.GetCurMaxAngularVelocity = new.instancemethod(Appc.ImpulseEngineSubsystem_GetCurMaxAngularVelocity, None, ImpulseEngineSubsystem)
ImpulseEngineSubsystem.GetCurMaxAngularAccel = new.instancemethod(Appc.ImpulseEngineSubsystem_GetCurMaxAngularAccel, None, ImpulseEngineSubsystem)
ImpulseEngineSubsystem.SetTractorBeamSystem = new.instancemethod(Appc.ImpulseEngineSubsystem_SetTractorBeamSystem, None, ImpulseEngineSubsystem)

class WarpEngineSubsystem(PoweredSubsystem):
    WES_NOT_WARPING = Appc.WarpEngineSubsystem_WES_NOT_WARPING
    WES_WARP_INITIATED = Appc.WarpEngineSubsystem_WES_WARP_INITIATED
    WES_WARP_BEGINNING = Appc.WarpEngineSubsystem_WES_WARP_BEGINNING
    WES_WARP_ENDING = Appc.WarpEngineSubsystem_WES_WARP_ENDING
    WES_WARPING = Appc.WarpEngineSubsystem_WES_WARPING
    WES_DEWARP_INITIATED = Appc.WarpEngineSubsystem_WES_DEWARP_INITIATED
    WES_DEWARP_BEGINNING = Appc.WarpEngineSubsystem_WES_DEWARP_BEGINNING
    WES_DEWARP_ENDING = Appc.WarpEngineSubsystem_WES_DEWARP_ENDING
    def __init__(self,*args):
        self.this = apply(Appc.new_WarpEngineSubsystem,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_WarpEngineSubsystem(self)
    def GetProperty(*args):
        val = apply(Appc.WarpEngineSubsystem_GetProperty,args)
        if val: val = WarpEnginePropertyPtr(val) 
        return val
    def GetPlacement(*args):
        val = apply(Appc.WarpEngineSubsystem_GetPlacement,args)
        if val: val = PlacementObjectPtr(val) 
        return val
    def GetWarpExitLocation(*args):
        val = apply(Appc.WarpEngineSubsystem_GetWarpExitLocation,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetWarpExitRotation(*args):
        val = apply(Appc.WarpEngineSubsystem_GetWarpExitRotation,args)
        if val: val = TGMatrix3Ptr(val) ; val.thisown = 1
        return val
    def GetWarpSequence(*args):
        val = apply(Appc.WarpEngineSubsystem_GetWarpSequence,args)
        if val: val = TGActionPtr(val) 
        return val
    def __repr__(self):
        return "<C WarpEngineSubsystem instance at %s>" % (self.this,)
class WarpEngineSubsystemPtr(WarpEngineSubsystem):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = WarpEngineSubsystem


WarpEngineSubsystem.Warp = new.instancemethod(Appc.WarpEngineSubsystem_Warp, None, WarpEngineSubsystem)
WarpEngineSubsystem.GetWarpState = new.instancemethod(Appc.WarpEngineSubsystem_GetWarpState, None, WarpEngineSubsystem)
WarpEngineSubsystem.SetWarpState = new.instancemethod(Appc.WarpEngineSubsystem_SetWarpState, None, WarpEngineSubsystem)
WarpEngineSubsystem.TransitionToState = new.instancemethod(Appc.WarpEngineSubsystem_TransitionToState, None, WarpEngineSubsystem)
WarpEngineSubsystem.SetPlacement = new.instancemethod(Appc.WarpEngineSubsystem_SetPlacement, None, WarpEngineSubsystem)
WarpEngineSubsystem.SetExitPoint = new.instancemethod(Appc.WarpEngineSubsystem_SetExitPoint, None, WarpEngineSubsystem)

class TractorBeamProjector(EnergyWeapon):
    def __init__(self,*args):
        self.this = apply(Appc.new_TractorBeamProjector,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TractorBeamProjector(self)
    def GetProperty(*args):
        val = apply(Appc.TractorBeamProjector_GetProperty,args)
        if val: val = TractorBeamPropertyPtr(val) 
        return val
    def __repr__(self):
        return "<C TractorBeamProjector instance at %s>" % (self.this,)
class TractorBeamProjectorPtr(TractorBeamProjector):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TractorBeamProjector



class TractorBeamSystem(WeaponSystem):
    TBS_HOLD = Appc.TractorBeamSystem_TBS_HOLD
    TBS_TOW = Appc.TractorBeamSystem_TBS_TOW
    TBS_PULL = Appc.TractorBeamSystem_TBS_PULL
    TBS_PUSH = Appc.TractorBeamSystem_TBS_PUSH
    TBS_DOCK_STAGE_1 = Appc.TractorBeamSystem_TBS_DOCK_STAGE_1
    TBS_DOCK_STAGE_2 = Appc.TractorBeamSystem_TBS_DOCK_STAGE_2
    def __init__(self,*args):
        self.this = apply(Appc.new_TractorBeamSystem,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TractorBeamSystem(self)
    def __repr__(self):
        return "<C TractorBeamSystem instance at %s>" % (self.this,)
class TractorBeamSystemPtr(TractorBeamSystem):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TractorBeamSystem


TractorBeamSystem.GetMode = new.instancemethod(Appc.TractorBeamSystem_GetMode, None, TractorBeamSystem)
TractorBeamSystem.SetMode = new.instancemethod(Appc.TractorBeamSystem_SetMode, None, TractorBeamSystem)

class WarpEvent(TGEvent):
    def __init__(self,this):
        self.this = this

    def GetExitPoint(*args):
        val = apply(Appc.WarpEvent_GetExitPoint,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEvent(self)
    def __repr__(self):
        return "<C WarpEvent instance at %s>" % (self.this,)
class WarpEventPtr(WarpEvent):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = WarpEvent


WarpEvent.GetDestinationSetName = new.instancemethod(Appc.WarpEvent_GetDestinationSetName, None, WarpEvent)
WarpEvent.GetPlacementName = new.instancemethod(Appc.WarpEvent_GetPlacementName, None, WarpEvent)
WarpEvent.GetDuration = new.instancemethod(Appc.WarpEvent_GetDuration, None, WarpEvent)

class SubsystemList:
    def __init__(self,this):
        self.this = this

    def GetHead(*args):
        val = apply(Appc.SubsystemList_GetHead,args)
        if val: val = ShipSubsystemPtr(val) 
        return val
    def GetTail(*args):
        val = apply(Appc.SubsystemList_GetTail,args)
        if val: val = ShipSubsystemPtr(val) 
        return val
    def GetNext(*args):
        val = apply(Appc.SubsystemList_GetNext,args)
        if val: val = ShipSubsystemPtr(val) 
        return val
    def GetPrev(*args):
        val = apply(Appc.SubsystemList_GetPrev,args)
        if val: val = ShipSubsystemPtr(val) 
        return val
    def __repr__(self):
        return "<C SubsystemList instance at %s>" % (self.this,)
class SubsystemListPtr(SubsystemList):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = SubsystemList


SubsystemList.GetHeadPos = new.instancemethod(Appc.SubsystemList_GetHeadPos, None, SubsystemList)
SubsystemList.GetTailPos = new.instancemethod(Appc.SubsystemList_GetTailPos, None, SubsystemList)
SubsystemList.GetSize = new.instancemethod(Appc.SubsystemList_GetSize, None, SubsystemList)

class EffectController:
    LOWEST = Appc.EffectController_LOWEST
    LOW = Appc.EffectController_LOW
    MEDIUM = Appc.EffectController_MEDIUM
    HIGH = Appc.EffectController_HIGH
    HIGHEST = Appc.EffectController_HIGHEST
    def __init__(self,this):
        self.this = this

    def GetTargetCast(*args):
        val = apply(Appc.EffectController_GetTargetCast,args)
        if val: val = NiAVObjectPtr(val) 
        return val
    def __repr__(self):
        return "<C EffectController instance at %s>" % (self.this,)
class EffectControllerPtr(EffectController):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = EffectController


EffectController.SetEffectLifeTime = new.instancemethod(Appc.EffectController_SetEffectLifeTime, None, EffectController)
EffectController.GetEffectLifeTime = new.instancemethod(Appc.EffectController_GetEffectLifeTime, None, EffectController)
EffectController.CreateTarget = new.instancemethod(Appc.EffectController_CreateTarget, None, EffectController)
EffectController.SetTargetAlphaBlendModes = new.instancemethod(Appc.EffectController_SetTargetAlphaBlendModes, None, EffectController)
EffectController.AttachEffect = new.instancemethod(Appc.EffectController_AttachEffect, None, EffectController)
EffectController.DetachEffect = new.instancemethod(Appc.EffectController_DetachEffect, None, EffectController)
EffectController.AddColorKey = new.instancemethod(Appc.EffectController_AddColorKey, None, EffectController)
EffectController.RemoveAllColorKeys = new.instancemethod(Appc.EffectController_RemoveAllColorKeys, None, EffectController)
EffectController.AddAlphaKey = new.instancemethod(Appc.EffectController_AddAlphaKey, None, EffectController)
EffectController.RemoveAllAlphaKeys = new.instancemethod(Appc.EffectController_RemoveAllAlphaKeys, None, EffectController)
EffectController.AddSizeKey = new.instancemethod(Appc.EffectController_AddSizeKey, None, EffectController)
EffectController.RemoveAllSizeKeys = new.instancemethod(Appc.EffectController_RemoveAllSizeKeys, None, EffectController)

class EmitterController(EffectController):
    def __init__(self,this):
        self.this = this

    def GetEmitFromObject(*args):
        val = apply(Appc.EmitterController_GetEmitFromObject,args)
        if val: val = NiAVObjectPtr(val) 
        return val
    def __repr__(self):
        return "<C EmitterController instance at %s>" % (self.this,)
class EmitterControllerPtr(EmitterController):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = EmitterController


EmitterController.SetEmitPositionAndDirection = new.instancemethod(Appc.EmitterController_SetEmitPositionAndDirection, None, EmitterController)
EmitterController.SetEmitFromObject = new.instancemethod(Appc.EmitterController_SetEmitFromObject, None, EmitterController)
EmitterController.SetDetachEmitObject = new.instancemethod(Appc.EmitterController_SetDetachEmitObject, None, EmitterController)
EmitterController.SetInheritsVelocity = new.instancemethod(Appc.EmitterController_SetInheritsVelocity, None, EmitterController)
EmitterController.SetEmitRadius = new.instancemethod(Appc.EmitterController_SetEmitRadius, None, EmitterController)
EmitterController.SetAngleVariance = new.instancemethod(Appc.EmitterController_SetAngleVariance, None, EmitterController)
EmitterController.SetEmitVelocity = new.instancemethod(Appc.EmitterController_SetEmitVelocity, None, EmitterController)
EmitterController.SetEmitLife = new.instancemethod(Appc.EmitterController_SetEmitLife, None, EmitterController)
EmitterController.SetEmitFrequency = new.instancemethod(Appc.EmitterController_SetEmitFrequency, None, EmitterController)
EmitterController.SetEmitVelocityVariance = new.instancemethod(Appc.EmitterController_SetEmitVelocityVariance, None, EmitterController)
EmitterController.SetEmitLifeVariance = new.instancemethod(Appc.EmitterController_SetEmitLifeVariance, None, EmitterController)
EmitterController.SetEmitFrequencyVariance = new.instancemethod(Appc.EmitterController_SetEmitFrequencyVariance, None, EmitterController)
EmitterController.SetGravity = new.instancemethod(Appc.EmitterController_SetGravity, None, EmitterController)
EmitterController.SetDamping = new.instancemethod(Appc.EmitterController_SetDamping, None, EmitterController)

class PointParticleController(EmitterController):
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C PointParticleController instance at %s>" % (self.this,)
class PointParticleControllerPtr(PointParticleController):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = PointParticleController



class SparkParticleController(PointParticleController):
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C SparkParticleController instance at %s>" % (self.this,)
class SparkParticleControllerPtr(SparkParticleController):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = SparkParticleController


SparkParticleController.SetTailLength = new.instancemethod(Appc.SparkParticleController_SetTailLength, None, SparkParticleController)
SparkParticleController.SetTailFade = new.instancemethod(Appc.SparkParticleController_SetTailFade, None, SparkParticleController)

class TexturedSparksController(EmitterController):
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C TexturedSparksController instance at %s>" % (self.this,)
class TexturedSparksControllerPtr(TexturedSparksController):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TexturedSparksController



class ExplodeParticleController(PointParticleController):
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C ExplodeParticleController instance at %s>" % (self.this,)
class ExplodeParticleControllerPtr(ExplodeParticleController):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = ExplodeParticleController


ExplodeParticleController.AddIntensityKey = new.instancemethod(Appc.ExplodeParticleController_AddIntensityKey, None, ExplodeParticleController)
ExplodeParticleController.RemoveIntensityKeyAt = new.instancemethod(Appc.ExplodeParticleController_RemoveIntensityKeyAt, None, ExplodeParticleController)
ExplodeParticleController.RemoveAllIntensityKeys = new.instancemethod(Appc.ExplodeParticleController_RemoveAllIntensityKeys, None, ExplodeParticleController)
ExplodeParticleController.SetSceneRoot = new.instancemethod(Appc.ExplodeParticleController_SetSceneRoot, None, ExplodeParticleController)

class DebrisParticleController(PointParticleController):
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C DebrisParticleController instance at %s>" % (self.this,)
class DebrisParticleControllerPtr(DebrisParticleController):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = DebrisParticleController



class AnimTSParticleController(EmitterController):
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C AnimTSParticleController instance at %s>" % (self.this,)
class AnimTSParticleControllerPtr(AnimTSParticleController):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = AnimTSParticleController


AnimTSParticleController.SetDrawOldToNew = new.instancemethod(Appc.AnimTSParticleController_SetDrawOldToNew, None, AnimTSParticleController)

class EffectAction(TGTimedAction):
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C EffectAction instance at %s>" % (self.this,)
class EffectActionPtr(EffectAction):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = EffectAction



class BridgeEffectAction(EffectAction):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_BridgeEffectAction(self)
    def GetController(*args):
        val = apply(Appc.BridgeEffectAction_GetController,args)
        if val: val = EmitterControllerPtr(val) 
        return val
    def GetSparkController(*args):
        val = apply(Appc.BridgeEffectAction_GetSparkController,args)
        if val: val = SparkParticleControllerPtr(val) 
        return val
    def GetExplosionController(*args):
        val = apply(Appc.BridgeEffectAction_GetExplosionController,args)
        if val: val = ExplodeParticleControllerPtr(val) 
        return val
    def __repr__(self):
        return "<C BridgeEffectAction instance at %s>" % (self.this,)
class BridgeEffectActionPtr(BridgeEffectAction):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = BridgeEffectAction


BridgeEffectAction.GetHardpointName = new.instancemethod(Appc.BridgeEffectAction_GetHardpointName, None, BridgeEffectAction)

class WarpSet(SetClass):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEventHandlerObject(self)
    def __repr__(self):
        return "<C WarpSet instance at %s>" % (self.this,)
class WarpSetPtr(WarpSet):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = WarpSet


WarpSet.GetNumTrails = new.instancemethod(Appc.WarpSet_GetNumTrails, None, WarpSet)
WarpSet.SetNumTrails = new.instancemethod(Appc.WarpSet_SetNumTrails, None, WarpSet)
WarpSet.SetForceUpdate = new.instancemethod(Appc.WarpSet_SetForceUpdate, None, WarpSet)

class WarpSequence(TGSequence):
    PRE_WARP_SEQUENCE = Appc.WarpSequence_PRE_WARP_SEQUENCE
    DURING_WARP_SEQUENCE = Appc.WarpSequence_DURING_WARP_SEQUENCE
    POST_DURING_WARP_SEQUENCE = Appc.WarpSequence_POST_DURING_WARP_SEQUENCE
    POST_WARP_SEQUENCE = Appc.WarpSequence_POST_WARP_SEQUENCE
    WARP_BEGIN_ACTION = Appc.WarpSequence_WARP_BEGIN_ACTION
    WARP_END_ACTION = Appc.WarpSequence_WARP_END_ACTION
    DEWARP_BEGIN_ACTION = Appc.WarpSequence_DEWARP_BEGIN_ACTION
    DEWARP_END_ACTION = Appc.WarpSequence_DEWARP_END_ACTION
    WARP_ENTER_ACTION = Appc.WarpSequence_WARP_ENTER_ACTION
    DEWARP_FINISH_ACTION = Appc.WarpSequence_DEWARP_FINISH_ACTION
    MOVE_ACTION_1 = Appc.WarpSequence_MOVE_ACTION_1
    MOVE_ACTION_2 = Appc.WarpSequence_MOVE_ACTION_2
    def __init__(self,*args):
        self.this = apply(Appc.new_WarpSequence,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_WarpSequence(self)
    def GetShip(*args):
        val = apply(Appc.WarpSequence_GetShip,args)
        if val: val = ShipClassPtr(val) 
        return val
    def GetOrigin(*args):
        val = apply(Appc.WarpSequence_GetOrigin,args)
        if val: val = SetClassPtr(val) 
        return val
    def GetDestinationSet(*args):
        val = apply(Appc.WarpSequence_GetDestinationSet,args)
        if val: val = SetClassPtr(val) 
        return val
    def GetExitPoint(*args):
        val = apply(Appc.WarpSequence_GetExitPoint,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetWarpSequencePiece(*args):
        val = apply(Appc.WarpSequence_GetWarpSequencePiece,args)
        if val: val = TGActionPtr(val) 
        return val
    def __repr__(self):
        return "<C WarpSequence instance at %s>" % (self.this,)
class WarpSequencePtr(WarpSequence):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = WarpSequence


WarpSequence.Skip = new.instancemethod(Appc.WarpSequence_Skip, None, WarpSequence)
WarpSequence.AddActionBeforeWarp = new.instancemethod(Appc.WarpSequence_AddActionBeforeWarp, None, WarpSequence)
WarpSequence.AddActionDuringWarp = new.instancemethod(Appc.WarpSequence_AddActionDuringWarp, None, WarpSequence)
WarpSequence.AddActionPostDuringWarp = new.instancemethod(Appc.WarpSequence_AddActionPostDuringWarp, None, WarpSequence)
WarpSequence.AddActionAfterWarp = new.instancemethod(Appc.WarpSequence_AddActionAfterWarp, None, WarpSequence)
WarpSequence.GetDestination = new.instancemethod(Appc.WarpSequence_GetDestination, None, WarpSequence)
WarpSequence.GetTimeToWarp = new.instancemethod(Appc.WarpSequence_GetTimeToWarp, None, WarpSequence)
WarpSequence.GetPlacementName = new.instancemethod(Appc.WarpSequence_GetPlacementName, None, WarpSequence)
WarpSequence.GetDestinationMission = new.instancemethod(Appc.WarpSequence_GetDestinationMission, None, WarpSequence)
WarpSequence.GetDestinationEpisode = new.instancemethod(Appc.WarpSequence_GetDestinationEpisode, None, WarpSequence)
WarpSequence.SetExitPoint = new.instancemethod(Appc.WarpSequence_SetExitPoint, None, WarpSequence)
WarpSequence.SetPlacement = new.instancemethod(Appc.WarpSequence_SetPlacement, None, WarpSequence)
WarpSequence.SetEventDestination = new.instancemethod(Appc.WarpSequence_SetEventDestination, None, WarpSequence)

class WarpFlash(ObjectClass):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGEventHandlerObject(self)
    def __repr__(self):
        return "<C WarpFlash instance at %s>" % (self.this,)
class WarpFlashPtr(WarpFlash):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = WarpFlash



class LensFlare:
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C LensFlare instance at %s>" % (self.this,)
class LensFlarePtr(LensFlare):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = LensFlare


LensFlare.SetSource = new.instancemethod(Appc.LensFlare_SetSource, None, LensFlare)
LensFlare.AddFlare = new.instancemethod(Appc.LensFlare_AddFlare, None, LensFlare)
LensFlare.Build = new.instancemethod(Appc.LensFlare_Build, None, LensFlare)

class ExplosionPlumeController(AnimTSParticleController):
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C ExplosionPlumeController instance at %s>" % (self.this,)
class ExplosionPlumeControllerPtr(ExplosionPlumeController):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = ExplosionPlumeController


ExplosionPlumeController.SetEmitterVelocity = new.instancemethod(Appc.ExplosionPlumeController_SetEmitterVelocity, None, ExplosionPlumeController)
ExplosionPlumeController.SetUpRandomVelocity = new.instancemethod(Appc.ExplosionPlumeController_SetUpRandomVelocity, None, ExplosionPlumeController)

class SunEffect:
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C SunEffect instance at %s>" % (self.this,)
class SunEffectPtr(SunEffect):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = SunEffect



class TextureAnimTrack:
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C TextureAnimTrack instance at %s>" % (self.this,)
class TextureAnimTrackPtr(TextureAnimTrack):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TextureAnimTrack


TextureAnimTrack.SetFrame = new.instancemethod(Appc.TextureAnimTrack_SetFrame, None, TextureAnimTrack)

class TextureAnimContainer:
    def __init__(self,this):
        self.this = this

    def AddTextureTrack(*args):
        val = apply(Appc.TextureAnimContainer_AddTextureTrack,args)
        if val: val = TextureAnimTrackPtr(val) 
        return val
    def __repr__(self):
        return "<C TextureAnimContainer instance at %s>" % (self.this,)
class TextureAnimContainerPtr(TextureAnimContainer):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TextureAnimContainer



class TextureAnimManager:
    def __init__(self,this):
        self.this = this

    def AddContainer(*args):
        val = apply(Appc.TextureAnimManager_AddContainer,args)
        if val: val = TextureAnimContainerPtr(val) 
        return val
    def __repr__(self):
        return "<C TextureAnimManager instance at %s>" % (self.this,)
class TextureAnimManagerPtr(TextureAnimManager):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TextureAnimManager



class InterfaceModule:
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C InterfaceModule instance at %s>" % (self.this,)
class InterfaceModulePtr(InterfaceModule):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = InterfaceModule


InterfaceModule.PlayClickSound = new.instancemethod(Appc.InterfaceModule_PlayClickSound, None, InterfaceModule)
InterfaceModule.Mute = new.instancemethod(Appc.InterfaceModule_Mute, None, InterfaceModule)
InterfaceModule.UnMute = new.instancemethod(Appc.InterfaceModule_UnMute, None, InterfaceModule)

class TopWindow(TGPane):
    def __init__(self,*args):
        self.this = apply(Appc.new_TopWindow,args)
        self.thisown = 1

    def FindMainWindow(*args):
        val = apply(Appc.TopWindow_FindMainWindow,args)
        if val: val = MainWindowPtr(val) 
        return val
    def GetLastRenderedSet(*args):
        val = apply(Appc.TopWindow_GetLastRenderedSet,args)
        if val: val = SetClassPtr(val) 
        return val
    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGPane(self)
    def __repr__(self):
        return "<C TopWindow instance at %s>" % (self.this,)
class TopWindowPtr(TopWindow):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TopWindow


TopWindow.SetEditMode = new.instancemethod(Appc.TopWindow_SetEditMode, None, TopWindow)
TopWindow.IsEditModeEnabled = new.instancemethod(Appc.TopWindow_IsEditModeEnabled, None, TopWindow)
TopWindow.ToggleEditMode = new.instancemethod(Appc.TopWindow_ToggleEditMode, None, TopWindow)
TopWindow.ToggleOptionsMenu = new.instancemethod(Appc.TopWindow_ToggleOptionsMenu, None, TopWindow)
TopWindow.ToggleConsole = new.instancemethod(Appc.TopWindow_ToggleConsole, None, TopWindow)
TopWindow.ToggleMapWindow = new.instancemethod(Appc.TopWindow_ToggleMapWindow, None, TopWindow)
TopWindow.ToggleCinematicWindow = new.instancemethod(Appc.TopWindow_ToggleCinematicWindow, None, TopWindow)
TopWindow.ToggleBridgeAndTactical = new.instancemethod(Appc.TopWindow_ToggleBridgeAndTactical, None, TopWindow)
TopWindow.ForceBridgeVisible = new.instancemethod(Appc.TopWindow_ForceBridgeVisible, None, TopWindow)
TopWindow.ForceTacticalVisible = new.instancemethod(Appc.TopWindow_ForceTacticalVisible, None, TopWindow)
TopWindow.ToggleWireframe = new.instancemethod(Appc.TopWindow_ToggleWireframe, None, TopWindow)
TopWindow.SetLastRenderedSet = new.instancemethod(Appc.TopWindow_SetLastRenderedSet, None, TopWindow)
TopWindow.ShowBadConnectionText = new.instancemethod(Appc.TopWindow_ShowBadConnectionText, None, TopWindow)
TopWindow.Initialize = new.instancemethod(Appc.TopWindow_Initialize, None, TopWindow)
TopWindow.Update = new.instancemethod(Appc.TopWindow_Update, None, TopWindow)
TopWindow.AllowKeyboardInput = new.instancemethod(Appc.TopWindow_AllowKeyboardInput, None, TopWindow)
TopWindow.IsKeyboardInputAllowed = new.instancemethod(Appc.TopWindow_IsKeyboardInputAllowed, None, TopWindow)
TopWindow.AllowMouseInput = new.instancemethod(Appc.TopWindow_AllowMouseInput, None, TopWindow)
TopWindow.IsMouseInputAllowed = new.instancemethod(Appc.TopWindow_IsMouseInputAllowed, None, TopWindow)
TopWindow.StartCutscene = new.instancemethod(Appc.TopWindow_StartCutscene, None, TopWindow)
TopWindow.EndCutscene = new.instancemethod(Appc.TopWindow_EndCutscene, None, TopWindow)
TopWindow.AbortCutscene = new.instancemethod(Appc.TopWindow_AbortCutscene, None, TopWindow)
TopWindow.IsCutsceneMode = new.instancemethod(Appc.TopWindow_IsCutsceneMode, None, TopWindow)
TopWindow.FadeOut = new.instancemethod(Appc.TopWindow_FadeOut, None, TopWindow)
TopWindow.FadeIn = new.instancemethod(Appc.TopWindow_FadeIn, None, TopWindow)
TopWindow.AbortFade = new.instancemethod(Appc.TopWindow_AbortFade, None, TopWindow)
TopWindow.IsFading = new.instancemethod(Appc.TopWindow_IsFading, None, TopWindow)
TopWindow.IsBridgeVisible = new.instancemethod(Appc.TopWindow_IsBridgeVisible, None, TopWindow)
TopWindow.IsTacticalVisible = new.instancemethod(Appc.TopWindow_IsTacticalVisible, None, TopWindow)
TopWindow.DisableOptionsMenu = new.instancemethod(Appc.TopWindow_DisableOptionsMenu, None, TopWindow)

class MainWindow(TGPane):
    def __init__(self,*args):
        self.this = apply(Appc.new_MainWindow,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGPane(self)
    def __repr__(self):
        return "<C MainWindow instance at %s>" % (self.this,)
class MainWindowPtr(MainWindow):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = MainWindow


MainWindow.GetType = new.instancemethod(Appc.MainWindow_GetType, None, MainWindow)
MainWindow.ToggleVisibility = new.instancemethod(Appc.MainWindow_ToggleVisibility, None, MainWindow)
MainWindow.IsWindowActive = new.instancemethod(Appc.MainWindow_IsWindowActive, None, MainWindow)
MainWindow.Initialize = new.instancemethod(Appc.MainWindow_Initialize, None, MainWindow)
MainWindow.Update = new.instancemethod(Appc.MainWindow_Update, None, MainWindow)

class ConsoleWindow(MainWindow):
    def __init__(self,*args):
        self.this = apply(Appc.new_ConsoleWindow,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGPane(self)
    def __repr__(self):
        return "<C ConsoleWindow instance at %s>" % (self.this,)
class ConsoleWindowPtr(ConsoleWindow):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = ConsoleWindow



class OptionsWindow(MainWindow):
    def __init__(self,*args):
        self.this = apply(Appc.new_OptionsWindow,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGPane(self)
    def __repr__(self):
        return "<C OptionsWindow instance at %s>" % (self.this,)
class OptionsWindowPtr(OptionsWindow):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = OptionsWindow


OptionsWindow.AddToPreviouslyVisible = new.instancemethod(Appc.OptionsWindow_AddToPreviouslyVisible, None, OptionsWindow)
OptionsWindow.RemoveFromPreviouslyVisible = new.instancemethod(Appc.OptionsWindow_RemoveFromPreviouslyVisible, None, OptionsWindow)
OptionsWindow.SetHasFocusObject = new.instancemethod(Appc.OptionsWindow_SetHasFocusObject, None, OptionsWindow)
OptionsWindow.RemoveAllPreviouslyVisible = new.instancemethod(Appc.OptionsWindow_RemoveAllPreviouslyVisible, None, OptionsWindow)

class BridgeWindow(MainWindow):
    def __init__(self,*args):
        self.this = apply(Appc.new_BridgeWindow,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGPane(self)
    def __repr__(self):
        return "<C BridgeWindow instance at %s>" % (self.this,)
class BridgeWindowPtr(BridgeWindow):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = BridgeWindow



class TacticalWindow(MainWindow):
    def __init__(self,*args):
        self.this = apply(Appc.new_TacticalWindow,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGPane(self)
    def __repr__(self):
        return "<C TacticalWindow instance at %s>" % (self.this,)
class TacticalWindowPtr(TacticalWindow):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TacticalWindow



class TacticalControlWindow(TGPane):
    def __init__(self,*args):
        self.this = apply(Appc.new_TacticalControlWindow,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TacticalControlWindow(self)
    def GetWeaponsControl(*args):
        val = apply(Appc.TacticalControlWindow_GetWeaponsControl,args)
        if val: val = TacWeaponsCtrlPtr(val) 
        return val
    def GetTacticalMenu(*args):
        val = apply(Appc.TacticalControlWindow_GetTacticalMenu,args)
        if val: val = STMenuPtr(val) 
        return val
    def GetShipDisplay(*args):
        val = apply(Appc.TacticalControlWindow_GetShipDisplay,args)
        if val: val = ShipDisplayPtr(val) 
        return val
    def GetEnemyShipDisplay(*args):
        val = apply(Appc.TacticalControlWindow_GetEnemyShipDisplay,args)
        if val: val = ShipDisplayPtr(val) 
        return val
    def GetWeaponsDisplay(*args):
        val = apply(Appc.TacticalControlWindow_GetWeaponsDisplay,args)
        if val: val = WeaponsDisplayPtr(val) 
        return val
    def GetTargetMenu(*args):
        val = apply(Appc.TacticalControlWindow_GetTargetMenu,args)
        if val: val = STTargetMenuPtr(val) 
        return val
    def GetRadarDisplay(*args):
        val = apply(Appc.TacticalControlWindow_GetRadarDisplay,args)
        if val: val = RadarDisplayPtr(val) 
        return val
    def GetRadarToggle(*args):
        val = apply(Appc.TacticalControlWindow_GetRadarToggle,args)
        if val: val = STButtonPtr(val) 
        return val
    def FindMenu(*args):
        val = apply(Appc.TacticalControlWindow_FindMenu,args)
        if val: val = STTopLevelMenuPtr(val) 
        return val
    def GetMenuParentPane(*args):
        val = apply(Appc.TacticalControlWindow_GetMenuParentPane,args)
        if val: val = TGPanePtr(val) 
        return val
    def GetOpenMenu(*args):
        val = apply(Appc.TacticalControlWindow_GetOpenMenu,args)
        if val: val = STTopLevelMenuPtr(val) 
        return val
    def __repr__(self):
        return "<C TacticalControlWindow instance at %s>" % (self.this,)
class TacticalControlWindowPtr(TacticalControlWindow):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TacticalControlWindow


TacticalControlWindow.SetShipDisplay = new.instancemethod(Appc.TacticalControlWindow_SetShipDisplay, None, TacticalControlWindow)
TacticalControlWindow.SetEnemyShipDisplay = new.instancemethod(Appc.TacticalControlWindow_SetEnemyShipDisplay, None, TacticalControlWindow)
TacticalControlWindow.SetWeaponsDisplay = new.instancemethod(Appc.TacticalControlWindow_SetWeaponsDisplay, None, TacticalControlWindow)
TacticalControlWindow.SetWeaponsControl = new.instancemethod(Appc.TacticalControlWindow_SetWeaponsControl, None, TacticalControlWindow)
TacticalControlWindow.SetTargetMenu = new.instancemethod(Appc.TacticalControlWindow_SetTargetMenu, None, TacticalControlWindow)
TacticalControlWindow.SetRadarDisplay = new.instancemethod(Appc.TacticalControlWindow_SetRadarDisplay, None, TacticalControlWindow)
TacticalControlWindow.SetRadarToggle = new.instancemethod(Appc.TacticalControlWindow_SetRadarToggle, None, TacticalControlWindow)
TacticalControlWindow.SetTacticalMenu = new.instancemethod(Appc.TacticalControlWindow_SetTacticalMenu, None, TacticalControlWindow)
TacticalControlWindow.SetMousePickFire = new.instancemethod(Appc.TacticalControlWindow_SetMousePickFire, None, TacticalControlWindow)
TacticalControlWindow.GetMousePickFire = new.instancemethod(Appc.TacticalControlWindow_GetMousePickFire, None, TacticalControlWindow)
TacticalControlWindow.AddMenuToList = new.instancemethod(Appc.TacticalControlWindow_AddMenuToList, None, TacticalControlWindow)
TacticalControlWindow.IgnoreNextMouseKeyEvent = new.instancemethod(Appc.TacticalControlWindow_IgnoreNextMouseKeyEvent, None, TacticalControlWindow)
TacticalControlWindow.SetIgnoreNextMouseKeyEvent = new.instancemethod(Appc.TacticalControlWindow_SetIgnoreNextMouseKeyEvent, None, TacticalControlWindow)

class MapWindow(MainWindow):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGPane(self)
    def __repr__(self):
        return "<C MapWindow instance at %s>" % (self.this,)
class MapWindowPtr(MapWindow):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = MapWindow


MapWindow.UpdatePlayerOrientationGraphics = new.instancemethod(Appc.MapWindow_UpdatePlayerOrientationGraphics, None, MapWindow)
MapWindow.RemovePlayerOrientationGraphics = new.instancemethod(Appc.MapWindow_RemovePlayerOrientationGraphics, None, MapWindow)

class ModalDialogWindow(MainWindow):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGPane(self)
    def __repr__(self):
        return "<C ModalDialogWindow instance at %s>" % (self.this,)
class ModalDialogWindowPtr(ModalDialogWindow):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = ModalDialogWindow


ModalDialogWindow.Run = new.instancemethod(Appc.ModalDialogWindow_Run, None, ModalDialogWindow)
ModalDialogWindow.SetAsKeyboardConfig = new.instancemethod(Appc.ModalDialogWindow_SetAsKeyboardConfig, None, ModalDialogWindow)
ModalDialogWindow.Cancel = new.instancemethod(Appc.ModalDialogWindow_Cancel, None, ModalDialogWindow)

class CinematicWindow(MainWindow):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGPane(self)
    def __repr__(self):
        return "<C CinematicWindow instance at %s>" % (self.this,)
class CinematicWindowPtr(CinematicWindow):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = CinematicWindow


CinematicWindow.IsInteractive = new.instancemethod(Appc.CinematicWindow_IsInteractive, None, CinematicWindow)
CinematicWindow.SetInteractive = new.instancemethod(Appc.CinematicWindow_SetInteractive, None, CinematicWindow)

class SubtitleWindow(MainWindow):
    SM_BRIDGE = Appc.SubtitleWindow_SM_BRIDGE
    SM_TACTICAL = Appc.SubtitleWindow_SM_TACTICAL
    SM_FELIX = Appc.SubtitleWindow_SM_FELIX
    SM_NONFELIX = Appc.SubtitleWindow_SM_NONFELIX
    SM_MAP = Appc.SubtitleWindow_SM_MAP
    SM_CINEMATIC = Appc.SubtitleWindow_SM_CINEMATIC
    SM_END_CINEMATIC = Appc.SubtitleWindow_SM_END_CINEMATIC
    SM_SPECIAL_FELIX = Appc.SubtitleWindow_SM_SPECIAL_FELIX
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGPane(self)
    def __repr__(self):
        return "<C SubtitleWindow instance at %s>" % (self.this,)
class SubtitleWindowPtr(SubtitleWindow):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = SubtitleWindow


SubtitleWindow.SetPositionForMode = new.instancemethod(Appc.SubtitleWindow_SetPositionForMode, None, SubtitleWindow)
SubtitleWindow.SetOn = new.instancemethod(Appc.SubtitleWindow_SetOn, None, SubtitleWindow)
SubtitleWindow.SetOff = new.instancemethod(Appc.SubtitleWindow_SetOff, None, SubtitleWindow)
SubtitleWindow.IsOn = new.instancemethod(Appc.SubtitleWindow_IsOn, None, SubtitleWindow)

class SubtitleAction(TGTimedAction):
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C SubtitleAction instance at %s>" % (self.this,)
class SubtitleActionPtr(SubtitleAction):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = SubtitleAction



class STStylizedWindow(TGWindow):
    SCROLL_DOWN = Appc.STStylizedWindow_SCROLL_DOWN
    NO_SCROLL = Appc.STStylizedWindow_NO_SCROLL
    SCROLL_UP = Appc.STStylizedWindow_SCROLL_UP
    def __init__(self,this):
        self.this = this

    def GetName(*args):
        val = apply(Appc.STStylizedWindow_GetName,args)
        if val: val = TGStringPtr(val) ; val.thisown = 1
        return val
    def GetNameParagraph(*args):
        val = apply(Appc.STStylizedWindow_GetNameParagraph,args)
        if val: val = TGParagraphPtr(val) 
        return val
    def GetExteriorPane(*args):
        val = apply(Appc.STStylizedWindow_GetExteriorPane,args)
        if val: val = TGPanePtr(val) 
        return val
    def GetInteriorPane(*args):
        val = apply(Appc.STStylizedWindow_GetInteriorPane,args)
        if val: val = TGPanePtr(val) 
        return val
    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGWindow(self)
    def __repr__(self):
        return "<C STStylizedWindow instance at %s>" % (self.this,)
class STStylizedWindowPtr(STStylizedWindow):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = STStylizedWindow


STStylizedWindow.SetName = new.instancemethod(Appc.STStylizedWindow_SetName, None, STStylizedWindow)
STStylizedWindow.InteriorChangedSize = new.instancemethod(Appc.STStylizedWindow_InteriorChangedSize, None, STStylizedWindow)
STStylizedWindow.SetMinimized = new.instancemethod(Appc.STStylizedWindow_SetMinimized, None, STStylizedWindow)
STStylizedWindow.SetNotMinimized = new.instancemethod(Appc.STStylizedWindow_SetNotMinimized, None, STStylizedWindow)
STStylizedWindow.IsMinimized = new.instancemethod(Appc.STStylizedWindow_IsMinimized, None, STStylizedWindow)
STStylizedWindow.SetMinimizable = new.instancemethod(Appc.STStylizedWindow_SetMinimizable, None, STStylizedWindow)
STStylizedWindow.IsMinimizable = new.instancemethod(Appc.STStylizedWindow_IsMinimizable, None, STStylizedWindow)
STStylizedWindow.SetFixedSize = new.instancemethod(Appc.STStylizedWindow_SetFixedSize, None, STStylizedWindow)
STStylizedWindow.IsFixedSize = new.instancemethod(Appc.STStylizedWindow_IsFixedSize, None, STStylizedWindow)
STStylizedWindow.IsScrolling = new.instancemethod(Appc.STStylizedWindow_IsScrolling, None, STStylizedWindow)
STStylizedWindow.IsUseScrolling = new.instancemethod(Appc.STStylizedWindow_IsUseScrolling, None, STStylizedWindow)
STStylizedWindow.SetUseScrolling = new.instancemethod(Appc.STStylizedWindow_SetUseScrolling, None, STStylizedWindow)
STStylizedWindow.SetUseFocusGlass = new.instancemethod(Appc.STStylizedWindow_SetUseFocusGlass, None, STStylizedWindow)
STStylizedWindow.IsUseFocusGlass = new.instancemethod(Appc.STStylizedWindow_IsUseFocusGlass, None, STStylizedWindow)
STStylizedWindow.SetTitleBarThickness = new.instancemethod(Appc.STStylizedWindow_SetTitleBarThickness, None, STStylizedWindow)
STStylizedWindow.GetTitleBarThickness = new.instancemethod(Appc.STStylizedWindow_GetTitleBarThickness, None, STStylizedWindow)
STStylizedWindow.SetMaximumSize = new.instancemethod(Appc.STStylizedWindow_SetMaximumSize, None, STStylizedWindow)
STStylizedWindow.GetMaximumWidth = new.instancemethod(Appc.STStylizedWindow_GetMaximumWidth, None, STStylizedWindow)
STStylizedWindow.GetMaximumHeight = new.instancemethod(Appc.STStylizedWindow_GetMaximumHeight, None, STStylizedWindow)
STStylizedWindow.GetBorderWidth = new.instancemethod(Appc.STStylizedWindow_GetBorderWidth, None, STStylizedWindow)
STStylizedWindow.GetBorderHeight = new.instancemethod(Appc.STStylizedWindow_GetBorderHeight, None, STStylizedWindow)
STStylizedWindow.GetMaximumInteriorWidth = new.instancemethod(Appc.STStylizedWindow_GetMaximumInteriorWidth, None, STStylizedWindow)
STStylizedWindow.GetMaximumInteriorHeight = new.instancemethod(Appc.STStylizedWindow_GetMaximumInteriorHeight, None, STStylizedWindow)
STStylizedWindow.SetScrollViewHeight = new.instancemethod(Appc.STStylizedWindow_SetScrollViewHeight, None, STStylizedWindow)
STStylizedWindow.GetScrollViewHeight = new.instancemethod(Appc.STStylizedWindow_GetScrollViewHeight, None, STStylizedWindow)
STStylizedWindow.SetScrollSpeed = new.instancemethod(Appc.STStylizedWindow_SetScrollSpeed, None, STStylizedWindow)
STStylizedWindow.ScrollToTop = new.instancemethod(Appc.STStylizedWindow_ScrollToTop, None, STStylizedWindow)
STStylizedWindow.ScrollToBottom = new.instancemethod(Appc.STStylizedWindow_ScrollToBottom, None, STStylizedWindow)
STStylizedWindow.Scroll = new.instancemethod(Appc.STStylizedWindow_Scroll, None, STStylizedWindow)
STStylizedWindow.GetColor = new.instancemethod(Appc.STStylizedWindow_GetColor, None, STStylizedWindow)
STStylizedWindow.EnsureFocusIsVisible = new.instancemethod(Appc.STStylizedWindow_EnsureFocusIsVisible, None, STStylizedWindow)

class STMenu(TGWindow):
    STMF_TWO_CLICKS = Appc.STMenu_STMF_TWO_CLICKS
    STMF_OPENABLE = Appc.STMenu_STMF_OPENABLE
    STMF_CLOSEABLE = Appc.STMenu_STMF_CLOSEABLE
    STMF_AUTO_CHOOSE = Appc.STMenu_STMF_AUTO_CHOOSE
    STMF_FLAGS_MASK = Appc.STMenu_STMF_FLAGS_MASK
    STMF_CLICKED_ONCE = Appc.STMenu_STMF_CLICKED_ONCE
    STMF_OPENED = Appc.STMenu_STMF_OPENED
    STMF_CHOSEN = Appc.STMenu_STMF_CHOSEN
    STMF_DONT_USE_END_CAP_SPACE = Appc.STMenu_STMF_DONT_USE_END_CAP_SPACE
    STMF_DEFAULTS = Appc.STMenu_STMF_DEFAULTS
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_STMenu(self)
    def GetText(*args):
        val = apply(Appc.STMenu_GetText,args)
        if val: val = TGParagraphPtr(val) 
        return val
    def GetSubmenu(*args):
        val = apply(Appc.STMenu_GetSubmenu,args)
        if val: val = STMenuPtr(val) 
        return val
    def GetSubmenuW(*args):
        val = apply(Appc.STMenu_GetSubmenuW,args)
        if val: val = STMenuPtr(val) 
        return val
    def GetButton(*args):
        val = apply(Appc.STMenu_GetButton,args)
        if val: val = STButtonPtr(val) 
        return val
    def GetButtonW(*args):
        val = apply(Appc.STMenu_GetButtonW,args)
        if val: val = STButtonPtr(val) 
        return val
    def GetClientArea(*args):
        val = apply(Appc.STMenu_GetClientArea,args)
        if val: val = TGRectPtr(val) ; val.thisown = 1
        return val
    def GetContainingWindow(*args):
        val = apply(Appc.STMenu_GetContainingWindow,args)
        if val: val = STStylizedWindowPtr(val) 
        return val
    def __repr__(self):
        return "<C STMenu instance at %s>" % (self.this,)
class STMenuPtr(STMenu):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = STMenu


STMenu.GetActualHeight = new.instancemethod(Appc.STMenu_GetActualHeight, None, STMenu)
STMenu.GetTitleBarHeight = new.instancemethod(Appc.STMenu_GetTitleBarHeight, None, STMenu)
STMenu.GetDesiredHeight = new.instancemethod(Appc.STMenu_GetDesiredHeight, None, STMenu)
STMenu.RemoveItem = new.instancemethod(Appc.STMenu_RemoveItem, None, STMenu)
STMenu.RemoveItemW = new.instancemethod(Appc.STMenu_RemoveItemW, None, STMenu)
STMenu.UseFullTitleBar = new.instancemethod(Appc.STMenu_UseFullTitleBar, None, STMenu)
STMenu.DisableFullTitleBar = new.instancemethod(Appc.STMenu_DisableFullTitleBar, None, STMenu)
STMenu.SetAutoChoose = new.instancemethod(Appc.STMenu_SetAutoChoose, None, STMenu)
STMenu.IsAutoChoose = new.instancemethod(Appc.STMenu_IsAutoChoose, None, STMenu)
STMenu.SetChosen = new.instancemethod(Appc.STMenu_SetChosen, None, STMenu)
STMenu.IsChosen = new.instancemethod(Appc.STMenu_IsChosen, None, STMenu)
STMenu.SetUseEndCapSpace = new.instancemethod(Appc.STMenu_SetUseEndCapSpace, None, STMenu)
STMenu.IsUseEndCapSpace = new.instancemethod(Appc.STMenu_IsUseEndCapSpace, None, STMenu)
STMenu.SetTwoClicks = new.instancemethod(Appc.STMenu_SetTwoClicks, None, STMenu)
STMenu.SetSingleClick = new.instancemethod(Appc.STMenu_SetSingleClick, None, STMenu)
STMenu.IsTwoClicks = new.instancemethod(Appc.STMenu_IsTwoClicks, None, STMenu)
STMenu.SetOpenable = new.instancemethod(Appc.STMenu_SetOpenable, None, STMenu)
STMenu.SetNotOpenable = new.instancemethod(Appc.STMenu_SetNotOpenable, None, STMenu)
STMenu.IsOpenable = new.instancemethod(Appc.STMenu_IsOpenable, None, STMenu)
STMenu.SetCloseable = new.instancemethod(Appc.STMenu_SetCloseable, None, STMenu)
STMenu.SetNotCloseable = new.instancemethod(Appc.STMenu_SetNotCloseable, None, STMenu)
STMenu.IsCloseable = new.instancemethod(Appc.STMenu_IsCloseable, None, STMenu)
STMenu.SetClickedOnce = new.instancemethod(Appc.STMenu_SetClickedOnce, None, STMenu)
STMenu.ClearClickedOnce = new.instancemethod(Appc.STMenu_ClearClickedOnce, None, STMenu)
STMenu.IsClickedOnce = new.instancemethod(Appc.STMenu_IsClickedOnce, None, STMenu)
STMenu.SetOpened = new.instancemethod(Appc.STMenu_SetOpened, None, STMenu)
STMenu.ClearOpened = new.instancemethod(Appc.STMenu_ClearOpened, None, STMenu)
STMenu.IsOpened = new.instancemethod(Appc.STMenu_IsOpened, None, STMenu)
STMenu.SetUseUIHeight = new.instancemethod(Appc.STMenu_SetUseUIHeight, None, STMenu)
STMenu.SetActivationEvent = new.instancemethod(Appc.STMenu_SetActivationEvent, None, STMenu)
STMenu.ClearActivationEvent = new.instancemethod(Appc.STMenu_ClearActivationEvent, None, STMenu)
STMenu.SendActivationEvent = new.instancemethod(Appc.STMenu_SendActivationEvent, None, STMenu)
STMenu.SetName = new.instancemethod(Appc.STMenu_SetName, None, STMenu)
STMenu.GetName = new.instancemethod(Appc.STMenu_GetName, None, STMenu)
STMenu.ResetColorScheme = new.instancemethod(Appc.STMenu_ResetColorScheme, None, STMenu)
STMenu.ForceUpdate = new.instancemethod(Appc.STMenu_ForceUpdate, None, STMenu)
STMenu.Open = new.instancemethod(Appc.STMenu_Open, None, STMenu)
STMenu.Close = new.instancemethod(Appc.STMenu_Close, None, STMenu)
STMenu.ResizeToContents = new.instancemethod(Appc.STMenu_ResizeToContents, None, STMenu)

class STSubPane(TGPane):
    def __init__(self,this):
        self.this = this

    def GetSubmenu(*args):
        val = apply(Appc.STSubPane_GetSubmenu,args)
        if val: val = STMenuPtr(val) 
        return val
    def GetSubmenuW(*args):
        val = apply(Appc.STSubPane_GetSubmenuW,args)
        if val: val = STMenuPtr(val) 
        return val
    def GetButton(*args):
        val = apply(Appc.STSubPane_GetButton,args)
        if val: val = STButtonPtr(val) 
        return val
    def GetButtonW(*args):
        val = apply(Appc.STSubPane_GetButtonW,args)
        if val: val = STButtonPtr(val) 
        return val
    def GetContainingWindow(*args):
        val = apply(Appc.STSubPane_GetContainingWindow,args)
        if val: val = STStylizedWindowPtr(val) 
        return val
    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGPane(self)
    def __repr__(self):
        return "<C STSubPane instance at %s>" % (self.this,)
class STSubPanePtr(STSubPane):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = STSubPane


STSubPane.InsertChild = new.instancemethod(Appc.STSubPane_InsertChild, None, STSubPane)
STSubPane.RemoveChild = new.instancemethod(Appc.STSubPane_RemoveChild, None, STSubPane)
STSubPane.DeleteChild = new.instancemethod(Appc.STSubPane_DeleteChild, None, STSubPane)
STSubPane.ResizeToContents = new.instancemethod(Appc.STSubPane_ResizeToContents, None, STSubPane)
STSubPane.GetVertSpacing = new.instancemethod(Appc.STSubPane_GetVertSpacing, None, STSubPane)
STSubPane.SetRadioGroup = new.instancemethod(Appc.STSubPane_SetRadioGroup, None, STSubPane)
STSubPane.IsRadioGroup = new.instancemethod(Appc.STSubPane_IsRadioGroup, None, STSubPane)
STSubPane.SetExpandToFillParent = new.instancemethod(Appc.STSubPane_SetExpandToFillParent, None, STSubPane)
STSubPane.RemoveItem = new.instancemethod(Appc.STSubPane_RemoveItem, None, STSubPane)
STSubPane.RemoveItemW = new.instancemethod(Appc.STSubPane_RemoveItemW, None, STSubPane)
STSubPane.GetTotalHeightOfChildren = new.instancemethod(Appc.STSubPane_GetTotalHeightOfChildren, None, STSubPane)

class STTopLevelMenu(STMenu):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_STTopLevelMenu(self)
    def GetOwner(*args):
        val = apply(Appc.STTopLevelMenu_GetOwner,args)
        if val: val = ObjectClassPtr(val) 
        return val
    def __repr__(self):
        return "<C STTopLevelMenu instance at %s>" % (self.this,)
class STTopLevelMenuPtr(STTopLevelMenu):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = STTopLevelMenu


STTopLevelMenu.CloseMenu = new.instancemethod(Appc.STTopLevelMenu_CloseMenu, None, STTopLevelMenu)
STTopLevelMenu.SetResizeSubpane = new.instancemethod(Appc.STTopLevelMenu_SetResizeSubpane, None, STTopLevelMenu)
STTopLevelMenu.IsResizeSubpane = new.instancemethod(Appc.STTopLevelMenu_IsResizeSubpane, None, STTopLevelMenu)
STTopLevelMenu.GotFocus = new.instancemethod(Appc.STTopLevelMenu_GotFocus, None, STTopLevelMenu)
STTopLevelMenu.LostFocus = new.instancemethod(Appc.STTopLevelMenu_LostFocus, None, STTopLevelMenu)
STTopLevelMenu.SetVisible = new.instancemethod(Appc.STTopLevelMenu_SetVisible, None, STTopLevelMenu)
STTopLevelMenu.SetNotVisible = new.instancemethod(Appc.STTopLevelMenu_SetNotVisible, None, STTopLevelMenu)
STTopLevelMenu.ResizeToContents = new.instancemethod(Appc.STTopLevelMenu_ResizeToContents, None, STTopLevelMenu)
STTopLevelMenu.SetOwner = new.instancemethod(Appc.STTopLevelMenu_SetOwner, None, STTopLevelMenu)

class STCharacterMenu(STMenu):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_STMenu(self)
    def __repr__(self):
        return "<C STCharacterMenu instance at %s>" % (self.this,)
class STCharacterMenuPtr(STCharacterMenu):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = STCharacterMenu



class STButton(TGButtonBase):
    LEFT = Appc.STButton_LEFT
    CENTER = Appc.STButton_CENTER
    RIGHT = Appc.STButton_RIGHT
    def __init__(self,this):
        self.this = this

    def GetText(*args):
        val = apply(Appc.STButton_GetText,args)
        if val: val = TGParagraphPtr(val) 
        return val
    def GetContainingWindow(*args):
        val = apply(Appc.STButton_GetContainingWindow,args)
        if val: val = STStylizedWindowPtr(val) 
        return val
    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGButtonBase(self)
    def __repr__(self):
        return "<C STButton instance at %s>" % (self.this,)
class STButtonPtr(STButton):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = STButton


STButton.SetName = new.instancemethod(Appc.STButton_SetName, None, STButton)
STButton.GetName = new.instancemethod(Appc.STButton_GetName, None, STButton)
STButton.SetNormalColor = new.instancemethod(Appc.STButton_SetNormalColor, None, STButton)
STButton.SetSelectedColor = new.instancemethod(Appc.STButton_SetSelectedColor, None, STButton)
STButton.SetHighlightedColor = new.instancemethod(Appc.STButton_SetHighlightedColor, None, STButton)
STButton.SetDisabledColor = new.instancemethod(Appc.STButton_SetDisabledColor, None, STButton)
STButton.SetTextColor = new.instancemethod(Appc.STButton_SetTextColor, None, STButton)
STButton.SetHighlightedTextColor = new.instancemethod(Appc.STButton_SetHighlightedTextColor, None, STButton)
STButton.SetSelectedTextColor = new.instancemethod(Appc.STButton_SetSelectedTextColor, None, STButton)
STButton.SetDisabledTextColor = new.instancemethod(Appc.STButton_SetDisabledTextColor, None, STButton)
STButton.SetMarkerNormalColor = new.instancemethod(Appc.STButton_SetMarkerNormalColor, None, STButton)
STButton.SetMarkerHighlightedColor = new.instancemethod(Appc.STButton_SetMarkerHighlightedColor, None, STButton)
STButton.SetMarkerSelectedColor = new.instancemethod(Appc.STButton_SetMarkerSelectedColor, None, STButton)
STButton.SetJustification = new.instancemethod(Appc.STButton_SetJustification, None, STButton)
STButton.SetAutoChoose = new.instancemethod(Appc.STButton_SetAutoChoose, None, STButton)
STButton.IsAutoChoose = new.instancemethod(Appc.STButton_IsAutoChoose, None, STButton)
STButton.SetChoosable = new.instancemethod(Appc.STButton_SetChoosable, None, STButton)
STButton.IsChoosable = new.instancemethod(Appc.STButton_IsChoosable, None, STButton)
STButton.SetChosen = new.instancemethod(Appc.STButton_SetChosen, None, STButton)
STButton.IsChosen = new.instancemethod(Appc.STButton_IsChosen, None, STButton)
STButton.SetColorBasedOnFlags = new.instancemethod(Appc.STButton_SetColorBasedOnFlags, None, STButton)
STButton.SetColor = new.instancemethod(Appc.STButton_SetColor, None, STButton)
STButton.IsUsingEndCaps = new.instancemethod(Appc.STButton_IsUsingEndCaps, None, STButton)
STButton.SetUseEndCaps = new.instancemethod(Appc.STButton_SetUseEndCaps, None, STButton)
STButton.SetUseEndCapSpace = new.instancemethod(Appc.STButton_SetUseEndCapSpace, None, STButton)
STButton.IsUseEndCapSpace = new.instancemethod(Appc.STButton_IsUseEndCapSpace, None, STButton)
STButton.SetUseUIHeight = new.instancemethod(Appc.STButton_SetUseUIHeight, None, STButton)

class STRoundedButton(TGButtonBase):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGButtonBase(self)
    def __repr__(self):
        return "<C STRoundedButton instance at %s>" % (self.this,)
class STRoundedButtonPtr(STRoundedButton):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = STRoundedButton


STRoundedButton.SetName = new.instancemethod(Appc.STRoundedButton_SetName, None, STRoundedButton)
STRoundedButton.GetName = new.instancemethod(Appc.STRoundedButton_GetName, None, STRoundedButton)
STRoundedButton.SetNormalColor = new.instancemethod(Appc.STRoundedButton_SetNormalColor, None, STRoundedButton)
STRoundedButton.SetSelectedColor = new.instancemethod(Appc.STRoundedButton_SetSelectedColor, None, STRoundedButton)
STRoundedButton.SetHighlightedColor = new.instancemethod(Appc.STRoundedButton_SetHighlightedColor, None, STRoundedButton)
STRoundedButton.SetDisabledColor = new.instancemethod(Appc.STRoundedButton_SetDisabledColor, None, STRoundedButton)
STRoundedButton.SetTextColor = new.instancemethod(Appc.STRoundedButton_SetTextColor, None, STRoundedButton)
STRoundedButton.SetHighlightedTextColor = new.instancemethod(Appc.STRoundedButton_SetHighlightedTextColor, None, STRoundedButton)
STRoundedButton.SetSelectedTextColor = new.instancemethod(Appc.STRoundedButton_SetSelectedTextColor, None, STRoundedButton)
STRoundedButton.SetDisabledTextColor = new.instancemethod(Appc.STRoundedButton_SetDisabledTextColor, None, STRoundedButton)
STRoundedButton.SetColorBasedOnFlags = new.instancemethod(Appc.STRoundedButton_SetColorBasedOnFlags, None, STRoundedButton)
STRoundedButton.SetColor = new.instancemethod(Appc.STRoundedButton_SetColor, None, STRoundedButton)

class STToggle(STButton):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_STToggle(self)
    def GetPrimaryCaption(*args):
        val = apply(Appc.STToggle_GetPrimaryCaption,args)
        if val: val = TGStringPtr(val) ; val.thisown = 1
        return val
    def __repr__(self):
        return "<C STToggle instance at %s>" % (self.this,)
class STTogglePtr(STToggle):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = STToggle


STToggle.SetPrimaryCaption = new.instancemethod(Appc.STToggle_SetPrimaryCaption, None, STToggle)
STToggle.SetPrimaryCaptionW = new.instancemethod(Appc.STToggle_SetPrimaryCaptionW, None, STToggle)
STToggle.SetStateValue = new.instancemethod(Appc.STToggle_SetStateValue, None, STToggle)
STToggle.SetStateValueW = new.instancemethod(Appc.STToggle_SetStateValueW, None, STToggle)
STToggle.SetStateValues = new.instancemethod(Appc.STToggle_SetStateValues, None, STToggle)
STToggle.SetStateValuesW = new.instancemethod(Appc.STToggle_SetStateValuesW, None, STToggle)
STToggle.GetState = new.instancemethod(Appc.STToggle_GetState, None, STToggle)
STToggle.SetState = new.instancemethod(Appc.STToggle_SetState, None, STToggle)

class STFillGauge(TGPane):
    LEFT_TO_RIGHT = Appc.STFillGauge_LEFT_TO_RIGHT
    RIGHT_TO_LEFT = Appc.STFillGauge_RIGHT_TO_LEFT
    BOTTOM_TO_TOP = Appc.STFillGauge_BOTTOM_TO_TOP
    TOP_TO_BOTTOM = Appc.STFillGauge_TOP_TO_BOTTOM
    def __init__(self,*args):
        self.this = apply(Appc.new_STFillGauge,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_STFillGauge(self)
    def GetObject(*args):
        val = apply(Appc.STFillGauge_GetObject,args)
        if val: val = TGObjectPtr(val) 
        return val
    def __repr__(self):
        return "<C STFillGauge instance at %s>" % (self.this,)
class STFillGaugePtr(STFillGauge):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = STFillGauge


STFillGauge.SetObject = new.instancemethod(Appc.STFillGauge_SetObject, None, STFillGauge)
STFillGauge.SetFillColor = new.instancemethod(Appc.STFillGauge_SetFillColor, None, STFillGauge)
STFillGauge.SetEmptyColor = new.instancemethod(Appc.STFillGauge_SetEmptyColor, None, STFillGauge)
STFillGauge.SetAlternateColor = new.instancemethod(Appc.STFillGauge_SetAlternateColor, None, STFillGauge)
STFillGauge.SetPythonMethods = new.instancemethod(Appc.STFillGauge_SetPythonMethods, None, STFillGauge)
STFillGauge.UpdateGauge = new.instancemethod(Appc.STFillGauge_UpdateGauge, None, STFillGauge)
STFillGauge.SetFillDirection = new.instancemethod(Appc.STFillGauge_SetFillDirection, None, STFillGauge)

class STNumericBar(TGPane):
    def __init__(self,this):
        self.this = this

    def GetText(*args):
        val = apply(Appc.STNumericBar_GetText,args)
        if val: val = TGParagraphPtr(val) 
        return val
    def GetPercentageText(*args):
        val = apply(Appc.STNumericBar_GetPercentageText,args)
        if val: val = TGParagraphPtr(val) 
        return val
    def GetMarker(*args):
        val = apply(Appc.STNumericBar_GetMarker,args)
        if val: val = TGIconPtr(val) 
        return val
    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGPane(self)
    def __repr__(self):
        return "<C STNumericBar instance at %s>" % (self.this,)
class STNumericBarPtr(STNumericBar):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = STNumericBar


STNumericBar.SetRange = new.instancemethod(Appc.STNumericBar_SetRange, None, STNumericBar)
STNumericBar.SetValue = new.instancemethod(Appc.STNumericBar_SetValue, None, STNumericBar)
STNumericBar.SetMarkerValue = new.instancemethod(Appc.STNumericBar_SetMarkerValue, None, STNumericBar)
STNumericBar.SetKeyInterval = new.instancemethod(Appc.STNumericBar_SetKeyInterval, None, STNumericBar)
STNumericBar.SetAlternateValue = new.instancemethod(Appc.STNumericBar_SetAlternateValue, None, STNumericBar)
STNumericBar.GetRange = new.instancemethod(Appc.STNumericBar_GetRange, None, STNumericBar)
STNumericBar.GetValue = new.instancemethod(Appc.STNumericBar_GetValue, None, STNumericBar)
STNumericBar.GetKeyInterval = new.instancemethod(Appc.STNumericBar_GetKeyInterval, None, STNumericBar)
STNumericBar.GetPositionFromAbsolutePercentage = new.instancemethod(Appc.STNumericBar_GetPositionFromAbsolutePercentage, None, STNumericBar)
STNumericBar.SetNormalColor = new.instancemethod(Appc.STNumericBar_SetNormalColor, None, STNumericBar)
STNumericBar.SetEmptyColor = new.instancemethod(Appc.STNumericBar_SetEmptyColor, None, STNumericBar)
STNumericBar.SetUseMarker = new.instancemethod(Appc.STNumericBar_SetUseMarker, None, STNumericBar)
STNumericBar.SetUseAlternateColor = new.instancemethod(Appc.STNumericBar_SetUseAlternateColor, None, STNumericBar)
STNumericBar.SetUseButtons = new.instancemethod(Appc.STNumericBar_SetUseButtons, None, STNumericBar)
STNumericBar.SetUpdateEvent = new.instancemethod(Appc.STNumericBar_SetUpdateEvent, None, STNumericBar)
STNumericBar.UpdateGauge = new.instancemethod(Appc.STNumericBar_UpdateGauge, None, STNumericBar)

class STTargetMenu(STTopLevelMenu):
    def __init__(self,this):
        self.this = this

    def GetObjectEntry(*args):
        val = apply(Appc.STTargetMenu_GetObjectEntry,args)
        if val: val = STMenuPtr(val) 
        return val
    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_STTopLevelMenu(self)
    def __repr__(self):
        return "<C STTargetMenu instance at %s>" % (self.this,)
class STTargetMenuPtr(STTargetMenu):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = STTargetMenu


STTargetMenu.RebuildShipMenu = new.instancemethod(Appc.STTargetMenu_RebuildShipMenu, None, STTargetMenu)
STTargetMenu.RebuildShipMenus = new.instancemethod(Appc.STTargetMenu_RebuildShipMenus, None, STTargetMenu)
STTargetMenu.ResetAffiliationColors = new.instancemethod(Appc.STTargetMenu_ResetAffiliationColors, None, STTargetMenu)
STTargetMenu.ClearPersistentTarget = new.instancemethod(Appc.STTargetMenu_ClearPersistentTarget, None, STTargetMenu)
STTargetMenu.ClearTargetList = new.instancemethod(Appc.STTargetMenu_ClearTargetList, None, STTargetMenu)

class STFileMenu(STTopLevelMenu):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_STTopLevelMenu(self)
    def __repr__(self):
        return "<C STFileMenu instance at %s>" % (self.this,)
class STFileMenuPtr(STFileMenu):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = STFileMenu


STFileMenu.GetDir = new.instancemethod(Appc.STFileMenu_GetDir, None, STFileMenu)
STFileMenu.GetFilter = new.instancemethod(Appc.STFileMenu_GetFilter, None, STFileMenu)
STFileMenu.SetDir = new.instancemethod(Appc.STFileMenu_SetDir, None, STFileMenu)
STFileMenu.SetFilter = new.instancemethod(Appc.STFileMenu_SetFilter, None, STFileMenu)
STFileMenu.Refresh = new.instancemethod(Appc.STFileMenu_Refresh, None, STFileMenu)

class STFileDialog(TGPane):
    def __init__(self,this):
        self.this = this

    def GetFileMenu(*args):
        val = apply(Appc.STFileDialog_GetFileMenu,args)
        if val: val = STFileMenuPtr(val) 
        return val
    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGPane(self)
    def __repr__(self):
        return "<C STFileDialog instance at %s>" % (self.this,)
class STFileDialogPtr(STFileDialog):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = STFileDialog


STFileDialog.RefreshFileList = new.instancemethod(Appc.STFileDialog_RefreshFileList, None, STFileDialog)

class STLoadDialog(STFileDialog):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGPane(self)
    def __repr__(self):
        return "<C STLoadDialog instance at %s>" % (self.this,)
class STLoadDialogPtr(STLoadDialog):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = STLoadDialog



class STSaveDialog(STFileDialog):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGPane(self)
    def __repr__(self):
        return "<C STSaveDialog instance at %s>" % (self.this,)
class STSaveDialogPtr(STSaveDialog):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = STSaveDialog



class STSubsystemMenu(STMenu):
    def __init__(self,*args):
        self.this = apply(Appc.new_STSubsystemMenu,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_STSubsystemMenu(self)
    def GetShip(*args):
        val = apply(Appc.STSubsystemMenu_GetShip,args)
        if val: val = ShipClassPtr(val) 
        return val
    def __repr__(self):
        return "<C STSubsystemMenu instance at %s>" % (self.this,)
class STSubsystemMenuPtr(STSubsystemMenu):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = STSubsystemMenu


STSubsystemMenu.ShowUnknownName = new.instancemethod(Appc.STSubsystemMenu_ShowUnknownName, None, STSubsystemMenu)
STSubsystemMenu.ShowRealName = new.instancemethod(Appc.STSubsystemMenu_ShowRealName, None, STSubsystemMenu)

class STComponentMenu(STMenu):
    def __init__(self,*args):
        self.this = apply(Appc.new_STComponentMenu,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_STComponentMenu(self)
    def GetShip(*args):
        val = apply(Appc.STComponentMenu_GetShip,args)
        if val: val = ShipClassPtr(val) 
        return val
    def GetSubsystem(*args):
        val = apply(Appc.STComponentMenu_GetSubsystem,args)
        if val: val = ShipSubsystemPtr(val) 
        return val
    def __repr__(self):
        return "<C STComponentMenu instance at %s>" % (self.this,)
class STComponentMenuPtr(STComponentMenu):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = STComponentMenu



class STComponentMenuItem(STButton):
    def __init__(self,*args):
        self.this = apply(Appc.new_STComponentMenuItem,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_STComponentMenuItem(self)
    def GetSubsystem(*args):
        val = apply(Appc.STComponentMenuItem_GetSubsystem,args)
        if val: val = ShipSubsystemPtr(val) 
        return val
    def __repr__(self):
        return "<C STComponentMenuItem instance at %s>" % (self.this,)
class STComponentMenuItemPtr(STComponentMenuItem):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = STComponentMenuItem



class STTiledIcon(TGIcon):
    DIRECTION_X = Appc.STTiledIcon_DIRECTION_X
    DIRECTION_Y = Appc.STTiledIcon_DIRECTION_Y
    TILE_X = Appc.STTiledIcon_TILE_X
    TILE_Y = Appc.STTiledIcon_TILE_Y
    TILE_SIZE_X = Appc.STTiledIcon_TILE_SIZE_X
    TILE_SIZE_Y = Appc.STTiledIcon_TILE_SIZE_Y
    def __init__(self,*args):
        self.this = apply(Appc.new_STTiledIcon,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_STTiledIcon(self)
    def __repr__(self):
        return "<C STTiledIcon instance at %s>" % (self.this,)
class STTiledIconPtr(STTiledIcon):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = STTiledIcon


STTiledIcon.IsTiling = new.instancemethod(Appc.STTiledIcon_IsTiling, None, STTiledIcon)
STTiledIcon.IsTileSize = new.instancemethod(Appc.STTiledIcon_IsTileSize, None, STTiledIcon)
STTiledIcon.SetTiling = new.instancemethod(Appc.STTiledIcon_SetTiling, None, STTiledIcon)
STTiledIcon.SetTileSize = new.instancemethod(Appc.STTiledIcon_SetTileSize, None, STTiledIcon)
STTiledIcon.SetTileNum = new.instancemethod(Appc.STTiledIcon_SetTileNum, None, STTiledIcon)
STTiledIcon.GetTileNum = new.instancemethod(Appc.STTiledIcon_GetTileNum, None, STTiledIcon)

class GraphicsMenuInfo:
    def __init__(self,*args):
        self.this = apply(Appc.new_GraphicsMenuInfo,args)
        self.thisown = 1

    __setmethods__ = {
        "m_bDataWasChanged" : Appc.GraphicsMenuInfo_m_bDataWasChanged_set,
        "m_bModeWasChanged" : Appc.GraphicsMenuInfo_m_bModeWasChanged_set,
        "m_bWeAreCanceling" : Appc.GraphicsMenuInfo_m_bWeAreCanceling_set,
        "m_bWeAreUndoing" : Appc.GraphicsMenuInfo_m_bWeAreUndoing_set,
        "m_bDetect" : Appc.GraphicsMenuInfo_m_bDetect_set,
        "m_kUndoMode" : Appc.GraphicsMenuInfo_m_kUndoMode_set,
        "m_kOldMode" : Appc.GraphicsMenuInfo_m_kOldMode_set,
        "m_pSizeToggle" : Appc.GraphicsMenuInfo_m_pSizeToggle_set,
        "m_pColorDepthToggle" : Appc.GraphicsMenuInfo_m_pColorDepthToggle_set,
        "m_pApplyButton" : Appc.GraphicsMenuInfo_m_pApplyButton_set,
        "ms_pDatabase" : Appc.GraphicsMenuInfo_ms_pDatabase_set,
        "m_kSavedTitle" : Appc.GraphicsMenuInfo_m_kSavedTitle_set,
        "ms_pGraphicsMenu" : Appc.GraphicsMenuInfo_ms_pGraphicsMenu_set,
    }
    def __setattr__(self,name,value):
        if (name == "this") or (name == "thisown"): self.__dict__[name] = value; return
        method = GraphicsMenuInfo.__setmethods__.get(name,None)
        if method: return method(self,value)
        self.__dict__[name] = value
    __getmethods__ = {
        "m_bDataWasChanged" : Appc.GraphicsMenuInfo_m_bDataWasChanged_get,
        "m_bModeWasChanged" : Appc.GraphicsMenuInfo_m_bModeWasChanged_get,
        "m_bWeAreCanceling" : Appc.GraphicsMenuInfo_m_bWeAreCanceling_get,
        "m_bWeAreUndoing" : Appc.GraphicsMenuInfo_m_bWeAreUndoing_get,
        "m_bDetect" : Appc.GraphicsMenuInfo_m_bDetect_get,
        "m_kUndoMode" : lambda x : GraphicsModeInfoPtr(Appc.GraphicsMenuInfo_m_kUndoMode_get(x)),
        "m_kOldMode" : lambda x : GraphicsModeInfoPtr(Appc.GraphicsMenuInfo_m_kOldMode_get(x)),
        "m_pSizeToggle" : lambda x : STTogglePtr(Appc.GraphicsMenuInfo_m_pSizeToggle_get(x)),
        "m_pColorDepthToggle" : lambda x : STTogglePtr(Appc.GraphicsMenuInfo_m_pColorDepthToggle_get(x)),
        "m_pApplyButton" : lambda x : STButtonPtr(Appc.GraphicsMenuInfo_m_pApplyButton_get(x)),
        "ms_pDatabase" : lambda x : TGLocalizationDatabasePtr(Appc.GraphicsMenuInfo_ms_pDatabase_get(x)),
        "m_kSavedTitle" : lambda x : TGStringPtr(Appc.GraphicsMenuInfo_m_kSavedTitle_get(x)),
        "ms_pGraphicsMenu" : lambda x : GraphicsMenuPtr(Appc.GraphicsMenuInfo_ms_pGraphicsMenu_get(x)),
    }
    def __getattr__(self,name):
        method = GraphicsMenuInfo.__getmethods__.get(name,None)
        if method: return method(self)
        raise AttributeError,name
    def __repr__(self):
        return "<C GraphicsMenuInfo instance at %s>" % (self.this,)
class GraphicsMenuInfoPtr(GraphicsMenuInfo):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = GraphicsMenuInfo



class GraphicsMenu(TGPane):
    def __init__(self,this):
        self.this = this

    def GetDevicesMenu(*args):
        val = apply(Appc.GraphicsMenu_GetDevicesMenu,args)
        if val: val = STMenuPtr(val) 
        return val
    def GetSizeToggle(*args):
        val = apply(Appc.GraphicsMenu_GetSizeToggle,args)
        if val: val = STTogglePtr(val) 
        return val
    def GetColorDepthToggle(*args):
        val = apply(Appc.GraphicsMenu_GetColorDepthToggle,args)
        if val: val = STTogglePtr(val) 
        return val
    def GetResolutionMenu(*args):
        val = apply(Appc.GraphicsMenu_GetResolutionMenu,args)
        if val: val = STMenuPtr(val) 
        return val
    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGPane(self)
    def __repr__(self):
        return "<C GraphicsMenu instance at %s>" % (self.this,)
class GraphicsMenuPtr(GraphicsMenu):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = GraphicsMenu


GraphicsMenu.ChangeDisplayMode = new.instancemethod(Appc.GraphicsMenu_ChangeDisplayMode, None, GraphicsMenu)
GraphicsMenu.ResetToggles = new.instancemethod(Appc.GraphicsMenu_ResetToggles, None, GraphicsMenu)

class ShipDisplay(STStylizedWindow):
    def __init__(self,*args):
        self.this = apply(Appc.new_ShipDisplay,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_ShipDisplay(self)
    def GetShieldsDisplay(*args):
        val = apply(Appc.ShipDisplay_GetShieldsDisplay,args)
        if val: val = ShieldsDisplayPtr(val) 
        return val
    def GetDamageDisplay(*args):
        val = apply(Appc.ShipDisplay_GetDamageDisplay,args)
        if val: val = DamageDisplayPtr(val) 
        return val
    def GetHealthGauge(*args):
        val = apply(Appc.ShipDisplay_GetHealthGauge,args)
        if val: val = STFillGaugePtr(val) 
        return val
    def __repr__(self):
        return "<C ShipDisplay instance at %s>" % (self.this,)
class ShipDisplayPtr(ShipDisplay):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = ShipDisplay


ShipDisplay.SetShipID = new.instancemethod(Appc.ShipDisplay_SetShipID, None, ShipDisplay)
ShipDisplay.SetShipIDVar = new.instancemethod(Appc.ShipDisplay_SetShipIDVar, None, ShipDisplay)
ShipDisplay.GetShipID = new.instancemethod(Appc.ShipDisplay_GetShipID, None, ShipDisplay)
ShipDisplay.AddTargetChangeEvent = new.instancemethod(Appc.ShipDisplay_AddTargetChangeEvent, None, ShipDisplay)
ShipDisplay.ResizeUI = new.instancemethod(Appc.ShipDisplay_ResizeUI, None, ShipDisplay)
ShipDisplay.RepositionUI = new.instancemethod(Appc.ShipDisplay_RepositionUI, None, ShipDisplay)
ShipDisplay.SetShieldsDisplay = new.instancemethod(Appc.ShipDisplay_SetShieldsDisplay, None, ShipDisplay)
ShipDisplay.SetDamageDisplay = new.instancemethod(Appc.ShipDisplay_SetDamageDisplay, None, ShipDisplay)
ShipDisplay.SetHealthGauge = new.instancemethod(Appc.ShipDisplay_SetHealthGauge, None, ShipDisplay)

class ShieldsDisplay(TGPane):
    DISPLAY_PANE = Appc.ShieldsDisplay_DISPLAY_PANE
    TOP_PANE = Appc.ShieldsDisplay_TOP_PANE
    SHIP_ICON = Appc.ShieldsDisplay_SHIP_ICON
    BOTTOM_PANE = Appc.ShieldsDisplay_BOTTOM_PANE
    NO_TARGET = Appc.ShieldsDisplay_NO_TARGET
    UNKNOWN_OBJECT = Appc.ShieldsDisplay_UNKNOWN_OBJECT
    TOP_SHIELDS = Appc.ShieldsDisplay_TOP_SHIELDS
    FRONT_SHIELDS = Appc.ShieldsDisplay_FRONT_SHIELDS
    REAR_SHIELDS = Appc.ShieldsDisplay_REAR_SHIELDS
    LEFT_SHIELDS = Appc.ShieldsDisplay_LEFT_SHIELDS
    RIGHT_SHIELDS = Appc.ShieldsDisplay_RIGHT_SHIELDS
    BOTTOM_SHIELDS = Appc.ShieldsDisplay_BOTTOM_SHIELDS
    def __init__(self,*args):
        self.this = apply(Appc.new_ShieldsDisplay,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_ShieldsDisplay(self)
    def __repr__(self):
        return "<C ShieldsDisplay instance at %s>" % (self.this,)
class ShieldsDisplayPtr(ShieldsDisplay):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = ShieldsDisplay


ShieldsDisplay.UpdateForNewShip = new.instancemethod(Appc.ShieldsDisplay_UpdateForNewShip, None, ShieldsDisplay)
ShieldsDisplay.RemoveEvents = new.instancemethod(Appc.ShieldsDisplay_RemoveEvents, None, ShieldsDisplay)
ShieldsDisplay.ResizeUI = new.instancemethod(Appc.ShieldsDisplay_ResizeUI, None, ShieldsDisplay)
ShieldsDisplay.RepositionUI = new.instancemethod(Appc.ShieldsDisplay_RepositionUI, None, ShieldsDisplay)

class DamageIcon(TGIcon):
    def __init__(self,*args):
        self.this = apply(Appc.new_DamageIcon,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_DamageIcon(self)
    def GetSubsystem(*args):
        val = apply(Appc.DamageIcon_GetSubsystem,args)
        if val: val = ShipSubsystemPtr(val) 
        return val
    def __repr__(self):
        return "<C DamageIcon instance at %s>" % (self.this,)
class DamageIconPtr(DamageIcon):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = DamageIcon


DamageIcon.ResetPosition = new.instancemethod(Appc.DamageIcon_ResetPosition, None, DamageIcon)

class DamageDisplay(TGPane):
    def __init__(self,*args):
        self.this = apply(Appc.new_DamageDisplay,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_DamageDisplay(self)
    def GetShip(*args):
        val = apply(Appc.DamageDisplay_GetShip,args)
        if val: val = ShipClassPtr(val) 
        return val
    def __repr__(self):
        return "<C DamageDisplay instance at %s>" % (self.this,)
class DamageDisplayPtr(DamageDisplay):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = DamageDisplay


DamageDisplay.UpdateForNewShip = new.instancemethod(Appc.DamageDisplay_UpdateForNewShip, None, DamageDisplay)
DamageDisplay.RemoveEvents = new.instancemethod(Appc.DamageDisplay_RemoveEvents, None, DamageDisplay)
DamageDisplay.ResizeUI = new.instancemethod(Appc.DamageDisplay_ResizeUI, None, DamageDisplay)
DamageDisplay.RepositionUI = new.instancemethod(Appc.DamageDisplay_RepositionUI, None, DamageDisplay)

class WeaponsDisplay(STStylizedWindow):
    DISPLAY_PANE = Appc.WeaponsDisplay_DISPLAY_PANE
    ICON_PANE = Appc.WeaponsDisplay_ICON_PANE
    TOP_RIGHT_BORDER = Appc.WeaponsDisplay_TOP_RIGHT_BORDER
    TOP_BORDER = Appc.WeaponsDisplay_TOP_BORDER
    LEFT_TOP_BORDER = Appc.WeaponsDisplay_LEFT_TOP_BORDER
    LEFT_BORDER = Appc.WeaponsDisplay_LEFT_BORDER
    LEFT_BOTTOM_BORDER = Appc.WeaponsDisplay_LEFT_BOTTOM_BORDER
    RIGHT_TOP_BORDER = Appc.WeaponsDisplay_RIGHT_TOP_BORDER
    RIGHT_BORDER = Appc.WeaponsDisplay_RIGHT_BORDER
    RIGHT_BOTTOM_BORDER = Appc.WeaponsDisplay_RIGHT_BOTTOM_BORDER
    GLASS = Appc.WeaponsDisplay_GLASS
    TORPEDO_PANE = Appc.WeaponsDisplay_TORPEDO_PANE
    UPPER_PHASER_PANE = Appc.WeaponsDisplay_UPPER_PHASER_PANE
    UPPER_PHASER_INDICATOR_PANE = Appc.WeaponsDisplay_UPPER_PHASER_INDICATOR_PANE
    UPPER_DISRUPTOR_PANE = Appc.WeaponsDisplay_UPPER_DISRUPTOR_PANE
    UPPER_DISRUPTOR_INDICATOR_PANE = Appc.WeaponsDisplay_UPPER_DISRUPTOR_INDICATOR_PANE
    SHIP_ICON = Appc.WeaponsDisplay_SHIP_ICON
    LOWER_PHASER_INDICATOR_PANE = Appc.WeaponsDisplay_LOWER_PHASER_INDICATOR_PANE
    LOWER_PHASER_PANE = Appc.WeaponsDisplay_LOWER_PHASER_PANE
    LOWER_DISRUPTOR_INDICATOR_PANE = Appc.WeaponsDisplay_LOWER_DISRUPTOR_INDICATOR_PANE
    LOWER_DISRUPTOR_PANE = Appc.WeaponsDisplay_LOWER_DISRUPTOR_PANE
    SPEED_INDICATOR_PANE = Appc.WeaponsDisplay_SPEED_INDICATOR_PANE
    SPEED_INDICATOR_TEXT = Appc.WeaponsDisplay_SPEED_INDICATOR_TEXT
    SPEED_INDICATOR_SPEED = Appc.WeaponsDisplay_SPEED_INDICATOR_SPEED
    SPEED_INDICATOR_BACKGROUND = Appc.WeaponsDisplay_SPEED_INDICATOR_BACKGROUND
    def __init__(self,*args):
        self.this = apply(Appc.new_WeaponsDisplay,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_WeaponsDisplay(self)
    def __repr__(self):
        return "<C WeaponsDisplay instance at %s>" % (self.this,)
class WeaponsDisplayPtr(WeaponsDisplay):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = WeaponsDisplay


WeaponsDisplay.SetShipID = new.instancemethod(Appc.WeaponsDisplay_SetShipID, None, WeaponsDisplay)
WeaponsDisplay.GetShipID = new.instancemethod(Appc.WeaponsDisplay_GetShipID, None, WeaponsDisplay)

class RadarDisplay(STStylizedWindow):
    RADAR_SCOPE = Appc.RadarDisplay_RADAR_SCOPE
    def __init__(self,*args):
        self.this = apply(Appc.new_RadarDisplay,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_RadarDisplay(self)
    def __repr__(self):
        return "<C RadarDisplay instance at %s>" % (self.this,)
class RadarDisplayPtr(RadarDisplay):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = RadarDisplay


RadarDisplay.SetColorBasedOnFlags = new.instancemethod(Appc.RadarDisplay_SetColorBasedOnFlags, None, RadarDisplay)
RadarDisplay.ResizeUI = new.instancemethod(Appc.RadarDisplay_ResizeUI, None, RadarDisplay)
RadarDisplay.RepositionUI = new.instancemethod(Appc.RadarDisplay_RepositionUI, None, RadarDisplay)

class RadarBlip(TGIcon):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGIcon(self)
    def __repr__(self):
        return "<C RadarBlip instance at %s>" % (self.this,)
class RadarBlipPtr(RadarBlip):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = RadarBlip


RadarBlip.SetShipID = new.instancemethod(Appc.RadarBlip_SetShipID, None, RadarBlip)
RadarBlip.GetShipID = new.instancemethod(Appc.RadarBlip_GetShipID, None, RadarBlip)

class RadarScope(TGPane):
    SHIP_ICON = Appc.RadarScope_SHIP_ICON
    RADAR_RING = Appc.RadarScope_RADAR_RING
    BRACKET_PANE = Appc.RadarScope_BRACKET_PANE
    TARGET_BRACKET = Appc.RadarScope_TARGET_BRACKET
    BLIP_PANE = Appc.RadarScope_BLIP_PANE
    PHASER_LINE_PANE = Appc.RadarScope_PHASER_LINE_PANE
    BACKGROUND_PANE = Appc.RadarScope_BACKGROUND_PANE
    def __init__(self,*args):
        self.this = apply(Appc.new_RadarScope,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_RadarScope(self)
    def CreateShipIcon(*args):
        val = apply(Appc.RadarScope_CreateShipIcon,args)
        if val: val = TGIconPtr(val) 
        return val
    def __repr__(self):
        return "<C RadarScope instance at %s>" % (self.this,)
class RadarScopePtr(RadarScope):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = RadarScope


RadarScope.Update = new.instancemethod(Appc.RadarScope_Update, None, RadarScope)
RadarScope.SetTargetBracket = new.instancemethod(Appc.RadarScope_SetTargetBracket, None, RadarScope)

class TacWeaponsCtrl(STStylizedWindow):
    def __init__(self,*args):
        self.this = apply(Appc.new_TacWeaponsCtrl,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TacWeaponsCtrl(self)
    def GetPhaserIntensityToggle(*args):
        val = apply(Appc.TacWeaponsCtrl_GetPhaserIntensityToggle,args)
        if val: val = STTogglePtr(val) 
        return val
    def GetTorpTypeToggle(*args):
        val = apply(Appc.TacWeaponsCtrl_GetTorpTypeToggle,args)
        if val: val = STTogglePtr(val) 
        return val
    def GetTorpSpreadToggle(*args):
        val = apply(Appc.TacWeaponsCtrl_GetTorpSpreadToggle,args)
        if val: val = STTogglePtr(val) 
        return val
    def GetBeamToggle(*args):
        val = apply(Appc.TacWeaponsCtrl_GetBeamToggle,args)
        if val: val = STTogglePtr(val) 
        return val
    def GetCloakToggle(*args):
        val = apply(Appc.TacWeaponsCtrl_GetCloakToggle,args)
        if val: val = STTogglePtr(val) 
        return val
    def __repr__(self):
        return "<C TacWeaponsCtrl instance at %s>" % (self.this,)
class TacWeaponsCtrlPtr(TacWeaponsCtrl):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TacWeaponsCtrl


TacWeaponsCtrl.RefreshPhaserSettings = new.instancemethod(Appc.TacWeaponsCtrl_RefreshPhaserSettings, None, TacWeaponsCtrl)
TacWeaponsCtrl.RefreshTorpedoSettings = new.instancemethod(Appc.TacWeaponsCtrl_RefreshTorpedoSettings, None, TacWeaponsCtrl)
TacWeaponsCtrl.RefreshTractorToggle = new.instancemethod(Appc.TacWeaponsCtrl_RefreshTractorToggle, None, TacWeaponsCtrl)
TacWeaponsCtrl.RefreshCloakToggle = new.instancemethod(Appc.TacWeaponsCtrl_RefreshCloakToggle, None, TacWeaponsCtrl)
TacWeaponsCtrl.Init = new.instancemethod(Appc.TacWeaponsCtrl_Init, None, TacWeaponsCtrl)

class EngPowerCtrl(TGPane):
    def __init__(self,*args):
        self.this = apply(Appc.new_EngPowerCtrl,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_EngPowerCtrl(self)
    def GetBarForSubsystem(*args):
        val = apply(Appc.EngPowerCtrl_GetBarForSubsystem,args)
        if val: val = STNumericBarPtr(val) 
        return val
    def __repr__(self):
        return "<C EngPowerCtrl instance at %s>" % (self.this,)
class EngPowerCtrlPtr(EngPowerCtrl):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = EngPowerCtrl


EngPowerCtrl.Refresh = new.instancemethod(Appc.EngPowerCtrl_Refresh, None, EngPowerCtrl)

class EngPowerDisplay(TGPane):
    MAIN = Appc.EngPowerDisplay_MAIN
    BACKUP = Appc.EngPowerDisplay_BACKUP
    WARP_CORE = Appc.EngPowerDisplay_WARP_CORE
    def __init__(self,*args):
        self.this = apply(Appc.new_EngPowerDisplay,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_EngPowerDisplay(self)
    def CreateBatteryGauge(*args):
        val = apply(Appc.EngPowerDisplay_CreateBatteryGauge,args)
        if val: val = STFillGaugePtr(val) 
        return val
    def __repr__(self):
        return "<C EngPowerDisplay instance at %s>" % (self.this,)
class EngPowerDisplayPtr(EngPowerDisplay):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = EngPowerDisplay



class EngRepairPane(TGPane):
    REPAIR_AREA_LABEL = Appc.EngRepairPane_REPAIR_AREA_LABEL
    REPAIR_AREA = Appc.EngRepairPane_REPAIR_AREA
    WAITING_AREA_LABEL = Appc.EngRepairPane_WAITING_AREA_LABEL
    WAITING_AREA = Appc.EngRepairPane_WAITING_AREA
    DESTROYED_AREA_LABEL = Appc.EngRepairPane_DESTROYED_AREA_LABEL
    DESTROYED_AREA = Appc.EngRepairPane_DESTROYED_AREA
    DIVIDER = Appc.EngRepairPane_DIVIDER
    DIVIDER_2 = Appc.EngRepairPane_DIVIDER_2
    def __init__(self,*args):
        self.this = apply(Appc.new_EngRepairPane,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_EngRepairPane(self)
    def GetSubsystemButton(*args):
        val = apply(Appc.EngRepairPane_GetSubsystemButton,args)
        if val: val = STButtonPtr(val) 
        return val
    def __repr__(self):
        return "<C EngRepairPane instance at %s>" % (self.this,)
class EngRepairPanePtr(EngRepairPane):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = EngRepairPane


EngRepairPane.ResizeToContents = new.instancemethod(Appc.EngRepairPane_ResizeToContents, None, EngRepairPane)

class STWarpButton(STButton):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGButtonBase(self)
    def __repr__(self):
        return "<C STWarpButton instance at %s>" % (self.this,)
class STWarpButtonPtr(STWarpButton):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = STWarpButton


STWarpButton.SetCourseMenu = new.instancemethod(Appc.STWarpButton_SetCourseMenu, None, STWarpButton)
STWarpButton.SetWarpTime = new.instancemethod(Appc.STWarpButton_SetWarpTime, None, STWarpButton)
STWarpButton.GetWarpTime = new.instancemethod(Appc.STWarpButton_GetWarpTime, None, STWarpButton)
STWarpButton.SetShip = new.instancemethod(Appc.STWarpButton_SetShip, None, STWarpButton)
STWarpButton.AddActionBeforeWarp = new.instancemethod(Appc.STWarpButton_AddActionBeforeWarp, None, STWarpButton)
STWarpButton.AddActionBeforeDuringWarp = new.instancemethod(Appc.STWarpButton_AddActionBeforeDuringWarp, None, STWarpButton)
STWarpButton.AddActionDuringWarp = new.instancemethod(Appc.STWarpButton_AddActionDuringWarp, None, STWarpButton)
STWarpButton.AddActionAfterDuringWarp = new.instancemethod(Appc.STWarpButton_AddActionAfterDuringWarp, None, STWarpButton)
STWarpButton.AddActionAfterWarp = new.instancemethod(Appc.STWarpButton_AddActionAfterWarp, None, STWarpButton)
STWarpButton.ClearBDASequences = new.instancemethod(Appc.STWarpButton_ClearBDASequences, None, STWarpButton)
STWarpButton.SetDestination = new.instancemethod(Appc.STWarpButton_SetDestination, None, STWarpButton)
STWarpButton.GetDestination = new.instancemethod(Appc.STWarpButton_GetDestination, None, STWarpButton)
STWarpButton.GetDestinationButtonID = new.instancemethod(Appc.STWarpButton_GetDestinationButtonID, None, STWarpButton)
STWarpButton.SetUseLargeLoadingScreen = new.instancemethod(Appc.STWarpButton_SetUseLargeLoadingScreen, None, STWarpButton)
STWarpButton.SetLocation = new.instancemethod(Appc.STWarpButton_SetLocation, None, STWarpButton)
STWarpButton.SetPlacementName = new.instancemethod(Appc.STWarpButton_SetPlacementName, None, STWarpButton)

class SortedRegionMenu(STCharacterMenu):
    def __init__(self,this):
        self.this = this

    def InitializeAllSets(*args):
        val = apply(Appc.SortedRegionMenu_InitializeAllSets,args)
        if val: val = SetClassPtr(val) 
        return val
    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_STMenu(self)
    def __repr__(self):
        return "<C SortedRegionMenu instance at %s>" % (self.this,)
class SortedRegionMenuPtr(SortedRegionMenu):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = SortedRegionMenu


SortedRegionMenu.SetRegionName = new.instancemethod(Appc.SortedRegionMenu_SetRegionName, None, SortedRegionMenu)
SortedRegionMenu.SetEpisodeName = new.instancemethod(Appc.SortedRegionMenu_SetEpisodeName, None, SortedRegionMenu)
SortedRegionMenu.SetMissionName = new.instancemethod(Appc.SortedRegionMenu_SetMissionName, None, SortedRegionMenu)
SortedRegionMenu.SetPlacementName = new.instancemethod(Appc.SortedRegionMenu_SetPlacementName, None, SortedRegionMenu)
SortedRegionMenu.SetUseLargeLoadingScreen = new.instancemethod(Appc.SortedRegionMenu_SetUseLargeLoadingScreen, None, SortedRegionMenu)
SortedRegionMenu.SetWarpToHere = new.instancemethod(Appc.SortedRegionMenu_SetWarpToHere, None, SortedRegionMenu)
SortedRegionMenu.GetRegionName = new.instancemethod(Appc.SortedRegionMenu_GetRegionName, None, SortedRegionMenu)
SortedRegionMenu.GetEpisodeName = new.instancemethod(Appc.SortedRegionMenu_GetEpisodeName, None, SortedRegionMenu)
SortedRegionMenu.GetMissionName = new.instancemethod(Appc.SortedRegionMenu_GetMissionName, None, SortedRegionMenu)
SortedRegionMenu.GetPlacementName = new.instancemethod(Appc.SortedRegionMenu_GetPlacementName, None, SortedRegionMenu)
SortedRegionMenu.ClearInfo = new.instancemethod(Appc.SortedRegionMenu_ClearInfo, None, SortedRegionMenu)

class MultiplayerWindow(MainWindow):
    def __init__(self,*args):
        self.this = apply(Appc.new_MultiplayerWindow,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_MultiplayerWindow(self)
    def GetMultiplayerMenu(*args):
        val = apply(Appc.MultiplayerWindow_GetMultiplayerMenu,args)
        if val: val = TGPanePtr(val) 
        return val
    def GetHostMenu(*args):
        val = apply(Appc.MultiplayerWindow_GetHostMenu,args)
        if val: val = TGPanePtr(val) 
        return val
    def GetDedicatedServerMenu(*args):
        val = apply(Appc.MultiplayerWindow_GetDedicatedServerMenu,args)
        if val: val = TGPanePtr(val) 
        return val
    def GetJoinMenu(*args):
        val = apply(Appc.MultiplayerWindow_GetJoinMenu,args)
        if val: val = TGPanePtr(val) 
        return val
    def GetDirectJoinMenu(*args):
        val = apply(Appc.MultiplayerWindow_GetDirectJoinMenu,args)
        if val: val = TGPanePtr(val) 
        return val
    def GetMissionPane(*args):
        val = apply(Appc.MultiplayerWindow_GetMissionPane,args)
        if val: val = TGPanePtr(val) 
        return val
    def GetStatusWindow(*args):
        val = apply(Appc.MultiplayerWindow_GetStatusWindow,args)
        if val: val = TGPanePtr(val) 
        return val
    def GetEndWindow(*args):
        val = apply(Appc.MultiplayerWindow_GetEndWindow,args)
        if val: val = TGPanePtr(val) 
        return val
    def GetChatWindow(*args):
        val = apply(Appc.MultiplayerWindow_GetChatWindow,args)
        if val: val = TGPanePtr(val) 
        return val
    def GetPlayerListWindow(*args):
        val = apply(Appc.MultiplayerWindow_GetPlayerListWindow,args)
        if val: val = TGPanePtr(val) 
        return val
    def BuildMissionMenu(*args):
        val = apply(Appc.MultiplayerWindow_BuildMissionMenu,args)
        if val: val = STMenuPtr(val) 
        return val
    def __repr__(self):
        return "<C MultiplayerWindow instance at %s>" % (self.this,)
class MultiplayerWindowPtr(MultiplayerWindow):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = MultiplayerWindow


MultiplayerWindow.SetMultiplayerMenu = new.instancemethod(Appc.MultiplayerWindow_SetMultiplayerMenu, None, MultiplayerWindow)
MultiplayerWindow.SetHostMenu = new.instancemethod(Appc.MultiplayerWindow_SetHostMenu, None, MultiplayerWindow)
MultiplayerWindow.SetDedicatedServerMenu = new.instancemethod(Appc.MultiplayerWindow_SetDedicatedServerMenu, None, MultiplayerWindow)
MultiplayerWindow.SetJoinMenu = new.instancemethod(Appc.MultiplayerWindow_SetJoinMenu, None, MultiplayerWindow)
MultiplayerWindow.SetDirectJoinMenu = new.instancemethod(Appc.MultiplayerWindow_SetDirectJoinMenu, None, MultiplayerWindow)
MultiplayerWindow.SetMissionPane = new.instancemethod(Appc.MultiplayerWindow_SetMissionPane, None, MultiplayerWindow)
MultiplayerWindow.SetStatusWindow = new.instancemethod(Appc.MultiplayerWindow_SetStatusWindow, None, MultiplayerWindow)
MultiplayerWindow.SetEndWindow = new.instancemethod(Appc.MultiplayerWindow_SetEndWindow, None, MultiplayerWindow)
MultiplayerWindow.SetChatWindow = new.instancemethod(Appc.MultiplayerWindow_SetChatWindow, None, MultiplayerWindow)
MultiplayerWindow.ToggleChatWindow = new.instancemethod(Appc.MultiplayerWindow_ToggleChatWindow, None, MultiplayerWindow)
MultiplayerWindow.IsChatWindowActive = new.instancemethod(Appc.MultiplayerWindow_IsChatWindowActive, None, MultiplayerWindow)
MultiplayerWindow.IsTeamChat = new.instancemethod(Appc.MultiplayerWindow_IsTeamChat, None, MultiplayerWindow)
MultiplayerWindow.SetTeamChat = new.instancemethod(Appc.MultiplayerWindow_SetTeamChat, None, MultiplayerWindow)
MultiplayerWindow.SetPlayerListWindow = new.instancemethod(Appc.MultiplayerWindow_SetPlayerListWindow, None, MultiplayerWindow)
MultiplayerWindow.SetGameName = new.instancemethod(Appc.MultiplayerWindow_SetGameName, None, MultiplayerWindow)
MultiplayerWindow.GetGameName = new.instancemethod(Appc.MultiplayerWindow_GetGameName, None, MultiplayerWindow)
MultiplayerWindow.SetPlayerName = new.instancemethod(Appc.MultiplayerWindow_SetPlayerName, None, MultiplayerWindow)
MultiplayerWindow.GetPlayerName = new.instancemethod(Appc.MultiplayerWindow_GetPlayerName, None, MultiplayerWindow)
MultiplayerWindow.SetPassword = new.instancemethod(Appc.MultiplayerWindow_SetPassword, None, MultiplayerWindow)
MultiplayerWindow.GetPassword = new.instancemethod(Appc.MultiplayerWindow_GetPassword, None, MultiplayerWindow)
MultiplayerWindow.ClearCurrentServer = new.instancemethod(Appc.MultiplayerWindow_ClearCurrentServer, None, MultiplayerWindow)
MultiplayerWindow.IsServerSelected = new.instancemethod(Appc.MultiplayerWindow_IsServerSelected, None, MultiplayerWindow)
MultiplayerWindow.HideAllChildren = new.instancemethod(Appc.MultiplayerWindow_HideAllChildren, None, MultiplayerWindow)
MultiplayerWindow.IsAnyChildVisible = new.instancemethod(Appc.MultiplayerWindow_IsAnyChildVisible, None, MultiplayerWindow)
MultiplayerWindow.SetGameOver = new.instancemethod(Appc.MultiplayerWindow_SetGameOver, None, MultiplayerWindow)
MultiplayerWindow.IsGameOver = new.instancemethod(Appc.MultiplayerWindow_IsGameOver, None, MultiplayerWindow)
MultiplayerWindow.SetDirectJoin = new.instancemethod(Appc.MultiplayerWindow_SetDirectJoin, None, MultiplayerWindow)
MultiplayerWindow.IsDirectJoin = new.instancemethod(Appc.MultiplayerWindow_IsDirectJoin, None, MultiplayerWindow)
MultiplayerWindow.SetHostUsingModem = new.instancemethod(Appc.MultiplayerWindow_SetHostUsingModem, None, MultiplayerWindow)
MultiplayerWindow.IsHostUsingModem = new.instancemethod(Appc.MultiplayerWindow_IsHostUsingModem, None, MultiplayerWindow)

class STMissionLog(TGPane):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGPane(self)
    def __repr__(self):
        return "<C STMissionLog instance at %s>" % (self.this,)
class STMissionLogPtr(STMissionLog):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = STMissionLog


STMissionLog.SetNumStoredLines = new.instancemethod(Appc.STMissionLog_SetNumStoredLines, None, STMissionLog)
STMissionLog.AddLine = new.instancemethod(Appc.STMissionLog_AddLine, None, STMissionLog)
STMissionLog.ClearLines = new.instancemethod(Appc.STMissionLog_ClearLines, None, STMissionLog)

class KeyboardBinding:
    GET_EVENT = Appc.KeyboardBinding_GET_EVENT
    GET_INT_EVENT = Appc.KeyboardBinding_GET_INT_EVENT
    GET_BOOL_EVENT = Appc.KeyboardBinding_GET_BOOL_EVENT
    GET_FLOAT_EVENT = Appc.KeyboardBinding_GET_FLOAT_EVENT
    KBT_MANY_TO_MANY = Appc.KeyboardBinding_KBT_MANY_TO_MANY
    KBT_SINGLE_EVENT_TO_KEY = Appc.KeyboardBinding_KBT_SINGLE_EVENT_TO_KEY
    KBT_SINGLE_KEY_TO_EVENT = Appc.KeyboardBinding_KBT_SINGLE_KEY_TO_EVENT
    KBT_LOCKOUT_CHANGE = Appc.KeyboardBinding_KBT_LOCKOUT_CHANGE
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C KeyboardBinding instance at %s>" % (self.this,)
class KeyboardBindingPtr(KeyboardBinding):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = KeyboardBinding


KeyboardBinding.BindKey = new.instancemethod(Appc.KeyboardBinding_BindKey, None, KeyboardBinding)
KeyboardBinding.BindKeyChar = new.instancemethod(Appc.KeyboardBinding_BindKeyChar, None, KeyboardBinding)
KeyboardBinding.GetNumKeys = new.instancemethod(Appc.KeyboardBinding_GetNumKeys, None, KeyboardBinding)
KeyboardBinding.FindKey = new.instancemethod(Appc.KeyboardBinding_FindKey, None, KeyboardBinding)
KeyboardBinding.FindKeyString = new.instancemethod(Appc.KeyboardBinding_FindKeyString, None, KeyboardBinding)
KeyboardBinding.ClearBinding = new.instancemethod(Appc.KeyboardBinding_ClearBinding, None, KeyboardBinding)
KeyboardBinding.LaunchEvent = new.instancemethod(Appc.KeyboardBinding_LaunchEvent, None, KeyboardBinding)
KeyboardBinding.RebuildMappingFromFile = new.instancemethod(Appc.KeyboardBinding_RebuildMappingFromFile, None, KeyboardBinding)
KeyboardBinding.GenerateMappingFile = new.instancemethod(Appc.KeyboardBinding_GenerateMappingFile, None, KeyboardBinding)
KeyboardBinding.SetMaxBoundKeys = new.instancemethod(Appc.KeyboardBinding_SetMaxBoundKeys, None, KeyboardBinding)

class UITreeDialog:
    def __init__(self,this):
        self.this = this

    def __repr__(self):
        return "<C UITreeDialog instance at %s>" % (self.this,)
class UITreeDialogPtr(UITreeDialog):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = UITreeDialog


UITreeDialog.Go = new.instancemethod(Appc.UITreeDialog_Go, None, UITreeDialog)
UITreeDialog.AddTreeElement = new.instancemethod(Appc.UITreeDialog_AddTreeElement, None, UITreeDialog)

class PlacementObject(ObjectClass):
    def __init__(self,*args):
        self.this = apply(Appc.new_PlacementObject,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_PlacementObject(self)
    def FindContainingSet(*args):
        val = apply(Appc.PlacementObject_FindContainingSet,args)
        if val: val = SetClassPtr(val) 
        return val
    def __repr__(self):
        return "<C PlacementObject instance at %s>" % (self.this,)
class PlacementObjectPtr(PlacementObject):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = PlacementObject


PlacementObject.Update = new.instancemethod(Appc.PlacementObject_Update, None, PlacementObject)
PlacementObject.SetModel = new.instancemethod(Appc.PlacementObject_SetModel, None, PlacementObject)
PlacementObject.GetModelName = new.instancemethod(Appc.PlacementObject_GetModelName, None, PlacementObject)
PlacementObject.SaveObject = new.instancemethod(Appc.PlacementObject_SaveObject, None, PlacementObject)
PlacementObject.SaveObjectSecondPass = new.instancemethod(Appc.PlacementObject_SaveObjectSecondPass, None, PlacementObject)
PlacementObject.SetStatic = new.instancemethod(Appc.PlacementObject_SetStatic, None, PlacementObject)
PlacementObject.IsStatic = new.instancemethod(Appc.PlacementObject_IsStatic, None, PlacementObject)
PlacementObject.SetNavPoint = new.instancemethod(Appc.PlacementObject_SetNavPoint, None, PlacementObject)
PlacementObject.IsNavPoint = new.instancemethod(Appc.PlacementObject_IsNavPoint, None, PlacementObject)

class Waypoint(PlacementObject):
    def __init__(self,*args):
        self.this = apply(Appc.new_Waypoint,args)
        self.thisown = 1

    def GetNext(*args):
        val = apply(Appc.Waypoint_GetNext,args)
        if val: val = WaypointPtr(val) 
        return val
    def GetPrev(*args):
        val = apply(Appc.Waypoint_GetPrev,args)
        if val: val = WaypointPtr(val) 
        return val
    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_PlacementObject(self)
    def __repr__(self):
        return "<C Waypoint instance at %s>" % (self.this,)
class WaypointPtr(Waypoint):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = Waypoint


Waypoint.SetSpeed = new.instancemethod(Appc.Waypoint_SetSpeed, None, Waypoint)
Waypoint.GetSpeed = new.instancemethod(Appc.Waypoint_GetSpeed, None, Waypoint)
Waypoint.InsertAfterObj = new.instancemethod(Appc.Waypoint_InsertAfterObj, None, Waypoint)

class LightPlacement(PlacementObject):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_PlacementObject(self)
    def __repr__(self):
        return "<C LightPlacement instance at %s>" % (self.this,)
class LightPlacementPtr(LightPlacement):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = LightPlacement


LightPlacement.ConfigAmbientLight = new.instancemethod(Appc.LightPlacement_ConfigAmbientLight, None, LightPlacement)
LightPlacement.ConfigDirectionalLight = new.instancemethod(Appc.LightPlacement_ConfigDirectionalLight, None, LightPlacement)
LightPlacement.ConfigPointLight = new.instancemethod(Appc.LightPlacement_ConfigPointLight, None, LightPlacement)
LightPlacement.ConfigSpotLight = new.instancemethod(Appc.LightPlacement_ConfigSpotLight, None, LightPlacement)

class GridClass(ObjectClass):
    def __init__(self,*args):
        self.this = apply(Appc.new_GridClass,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_GridClass(self)
    def GetIntersectionPoint(*args):
        val = apply(Appc.GridClass_GetIntersectionPoint,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def __repr__(self):
        return "<C GridClass instance at %s>" % (self.this,)
class GridClassPtr(GridClass):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = GridClass


GridClass.Update = new.instancemethod(Appc.GridClass_Update, None, GridClass)
GridClass.UpdatePosition = new.instancemethod(Appc.GridClass_UpdatePosition, None, GridClass)
GridClass.SetLineLength = new.instancemethod(Appc.GridClass_SetLineLength, None, GridClass)
GridClass.GetLineLength = new.instancemethod(Appc.GridClass_GetLineLength, None, GridClass)
GridClass.SetStep = new.instancemethod(Appc.GridClass_SetStep, None, GridClass)
GridClass.GetStep = new.instancemethod(Appc.GridClass_GetStep, None, GridClass)

class AsteroidFieldPlacement(PlacementObject):
    def __init__(self,*args):
        self.this = apply(Appc.new_AsteroidFieldPlacement,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_AsteroidFieldPlacement(self)
    def GetField(*args):
        val = apply(Appc.AsteroidFieldPlacement_GetField,args)
        if val: val = AsteroidFieldPtr(val) 
        return val
    def __repr__(self):
        return "<C AsteroidFieldPlacement instance at %s>" % (self.this,)
class AsteroidFieldPlacementPtr(AsteroidFieldPlacement):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = AsteroidFieldPlacement


AsteroidFieldPlacement.GetFieldRadius = new.instancemethod(Appc.AsteroidFieldPlacement_GetFieldRadius, None, AsteroidFieldPlacement)
AsteroidFieldPlacement.SetFieldRadius = new.instancemethod(Appc.AsteroidFieldPlacement_SetFieldRadius, None, AsteroidFieldPlacement)
AsteroidFieldPlacement.GetNumTilesPerAxis = new.instancemethod(Appc.AsteroidFieldPlacement_GetNumTilesPerAxis, None, AsteroidFieldPlacement)
AsteroidFieldPlacement.SetNumTilesPerAxis = new.instancemethod(Appc.AsteroidFieldPlacement_SetNumTilesPerAxis, None, AsteroidFieldPlacement)
AsteroidFieldPlacement.GetNumAsteroidsPerTile = new.instancemethod(Appc.AsteroidFieldPlacement_GetNumAsteroidsPerTile, None, AsteroidFieldPlacement)
AsteroidFieldPlacement.SetNumAsteroidsPerTile = new.instancemethod(Appc.AsteroidFieldPlacement_SetNumAsteroidsPerTile, None, AsteroidFieldPlacement)
AsteroidFieldPlacement.GetAsteroidSizeFactor = new.instancemethod(Appc.AsteroidFieldPlacement_GetAsteroidSizeFactor, None, AsteroidFieldPlacement)
AsteroidFieldPlacement.SetAsteroidSizeFactor = new.instancemethod(Appc.AsteroidFieldPlacement_SetAsteroidSizeFactor, None, AsteroidFieldPlacement)
AsteroidFieldPlacement.ConfigField = new.instancemethod(Appc.AsteroidFieldPlacement_ConfigField, None, AsteroidFieldPlacement)
AsteroidFieldPlacement.Update = new.instancemethod(Appc.AsteroidFieldPlacement_Update, None, AsteroidFieldPlacement)

class PositionOrientationProperty(TGModelProperty):
    def __init__(self,*args):
        self.this = apply(Appc.new_PositionOrientationProperty,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_PositionOrientationProperty(self)
    def GetForward(*args):
        val = apply(Appc.PositionOrientationProperty_GetForward,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetUp(*args):
        val = apply(Appc.PositionOrientationProperty_GetUp,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetRight(*args):
        val = apply(Appc.PositionOrientationProperty_GetRight,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetPosition(*args):
        val = apply(Appc.PositionOrientationProperty_GetPosition,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def __repr__(self):
        return "<C PositionOrientationProperty instance at %s>" % (self.this,)
class PositionOrientationPropertyPtr(PositionOrientationProperty):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = PositionOrientationProperty


PositionOrientationProperty.SetOrientation = new.instancemethod(Appc.PositionOrientationProperty_SetOrientation, None, PositionOrientationProperty)
PositionOrientationProperty.SetPosition = new.instancemethod(Appc.PositionOrientationProperty_SetPosition, None, PositionOrientationProperty)

class SubsystemProperty(TGModelProperty):
    def __init__(self,*args):
        self.this = apply(Appc.new_SubsystemProperty,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_SubsystemProperty(self)
    def GetPosition(*args):
        val = apply(Appc.SubsystemProperty_GetPosition,args)
        if val: val = NiPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetPositionTG(*args):
        val = apply(Appc.SubsystemProperty_GetPositionTG,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def __repr__(self):
        return "<C SubsystemProperty instance at %s>" % (self.this,)
class SubsystemPropertyPtr(SubsystemProperty):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = SubsystemProperty


SubsystemProperty.GetMaxCondition = new.instancemethod(Appc.SubsystemProperty_GetMaxCondition, None, SubsystemProperty)
SubsystemProperty.IsCritical = new.instancemethod(Appc.SubsystemProperty_IsCritical, None, SubsystemProperty)
SubsystemProperty.IsTargetable = new.instancemethod(Appc.SubsystemProperty_IsTargetable, None, SubsystemProperty)
SubsystemProperty.IsPrimary = new.instancemethod(Appc.SubsystemProperty_IsPrimary, None, SubsystemProperty)
SubsystemProperty.GetRepairComplexity = new.instancemethod(Appc.SubsystemProperty_GetRepairComplexity, None, SubsystemProperty)
SubsystemProperty.GetDisabledPercentage = new.instancemethod(Appc.SubsystemProperty_GetDisabledPercentage, None, SubsystemProperty)
SubsystemProperty.GetRadius = new.instancemethod(Appc.SubsystemProperty_GetRadius, None, SubsystemProperty)
SubsystemProperty.SetMaxCondition = new.instancemethod(Appc.SubsystemProperty_SetMaxCondition, None, SubsystemProperty)
SubsystemProperty.SetCritical = new.instancemethod(Appc.SubsystemProperty_SetCritical, None, SubsystemProperty)
SubsystemProperty.SetTargetable = new.instancemethod(Appc.SubsystemProperty_SetTargetable, None, SubsystemProperty)
SubsystemProperty.SetPrimary = new.instancemethod(Appc.SubsystemProperty_SetPrimary, None, SubsystemProperty)
SubsystemProperty.SetRepairComplexity = new.instancemethod(Appc.SubsystemProperty_SetRepairComplexity, None, SubsystemProperty)
SubsystemProperty.SetDisabledPercentage = new.instancemethod(Appc.SubsystemProperty_SetDisabledPercentage, None, SubsystemProperty)
SubsystemProperty.SetRadius = new.instancemethod(Appc.SubsystemProperty_SetRadius, None, SubsystemProperty)
SubsystemProperty.GetPosition2D = new.instancemethod(Appc.SubsystemProperty_GetPosition2D, None, SubsystemProperty)
SubsystemProperty.SetPosition = new.instancemethod(Appc.SubsystemProperty_SetPosition, None, SubsystemProperty)
SubsystemProperty.SetPosition2D = new.instancemethod(Appc.SubsystemProperty_SetPosition2D, None, SubsystemProperty)

class PoweredSubsystemProperty(SubsystemProperty):
    def __init__(self,*args):
        self.this = apply(Appc.new_PoweredSubsystemProperty,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_PoweredSubsystemProperty(self)
    def __repr__(self):
        return "<C PoweredSubsystemProperty instance at %s>" % (self.this,)
class PoweredSubsystemPropertyPtr(PoweredSubsystemProperty):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = PoweredSubsystemProperty


PoweredSubsystemProperty.GetNormalPowerPerSecond = new.instancemethod(Appc.PoweredSubsystemProperty_GetNormalPowerPerSecond, None, PoweredSubsystemProperty)
PoweredSubsystemProperty.SetNormalPowerPerSecond = new.instancemethod(Appc.PoweredSubsystemProperty_SetNormalPowerPerSecond, None, PoweredSubsystemProperty)

class WeaponSystemProperty(PoweredSubsystemProperty):
    WST_UNKNOWN = Appc.WeaponSystemProperty_WST_UNKNOWN
    WST_PHASER = Appc.WeaponSystemProperty_WST_PHASER
    WST_TORPEDO = Appc.WeaponSystemProperty_WST_TORPEDO
    WST_PULSE = Appc.WeaponSystemProperty_WST_PULSE
    WST_TRACTOR = Appc.WeaponSystemProperty_WST_TRACTOR
    def __init__(self,*args):
        self.this = apply(Appc.new_WeaponSystemProperty,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_WeaponSystemProperty(self)
    def GetFiringChainString(*args):
        val = apply(Appc.WeaponSystemProperty_GetFiringChainString,args)
        if val: val = TGStringPtr(val) ; val.thisown = 1
        return val
    def __repr__(self):
        return "<C WeaponSystemProperty instance at %s>" % (self.this,)
class WeaponSystemPropertyPtr(WeaponSystemProperty):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = WeaponSystemProperty


WeaponSystemProperty.GetWeaponSystemType = new.instancemethod(Appc.WeaponSystemProperty_GetWeaponSystemType, None, WeaponSystemProperty)
WeaponSystemProperty.SetWeaponSystemType = new.instancemethod(Appc.WeaponSystemProperty_SetWeaponSystemType, None, WeaponSystemProperty)
WeaponSystemProperty.IsSingleFire = new.instancemethod(Appc.WeaponSystemProperty_IsSingleFire, None, WeaponSystemProperty)
WeaponSystemProperty.SetSingleFire = new.instancemethod(Appc.WeaponSystemProperty_SetSingleFire, None, WeaponSystemProperty)
WeaponSystemProperty.IsAimedWeapon = new.instancemethod(Appc.WeaponSystemProperty_IsAimedWeapon, None, WeaponSystemProperty)
WeaponSystemProperty.SetAimedWeapon = new.instancemethod(Appc.WeaponSystemProperty_SetAimedWeapon, None, WeaponSystemProperty)
WeaponSystemProperty.SetFiringChainString = new.instancemethod(Appc.WeaponSystemProperty_SetFiringChainString, None, WeaponSystemProperty)

class WeaponProperty(SubsystemProperty):
    def __init__(self,*args):
        self.this = apply(Appc.new_WeaponProperty,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_WeaponProperty(self)
    def __repr__(self):
        return "<C WeaponProperty instance at %s>" % (self.this,)
class WeaponPropertyPtr(WeaponProperty):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = WeaponProperty


WeaponProperty.IsDumbfire = new.instancemethod(Appc.WeaponProperty_IsDumbfire, None, WeaponProperty)
WeaponProperty.SetDumbfire = new.instancemethod(Appc.WeaponProperty_SetDumbfire, None, WeaponProperty)
WeaponProperty.GetWeaponID = new.instancemethod(Appc.WeaponProperty_GetWeaponID, None, WeaponProperty)
WeaponProperty.SetWeaponID = new.instancemethod(Appc.WeaponProperty_SetWeaponID, None, WeaponProperty)
WeaponProperty.IsMemberOfGroup = new.instancemethod(Appc.WeaponProperty_IsMemberOfGroup, None, WeaponProperty)
WeaponProperty.GetGroups = new.instancemethod(Appc.WeaponProperty_GetGroups, None, WeaponProperty)
WeaponProperty.SetGroups = new.instancemethod(Appc.WeaponProperty_SetGroups, None, WeaponProperty)
WeaponProperty.GetDamageRadiusFactor = new.instancemethod(Appc.WeaponProperty_GetDamageRadiusFactor, None, WeaponProperty)
WeaponProperty.SetDamageRadiusFactor = new.instancemethod(Appc.WeaponProperty_SetDamageRadiusFactor, None, WeaponProperty)
WeaponProperty.GetIconNum = new.instancemethod(Appc.WeaponProperty_GetIconNum, None, WeaponProperty)
WeaponProperty.SetIconNum = new.instancemethod(Appc.WeaponProperty_SetIconNum, None, WeaponProperty)
WeaponProperty.GetIconPositionX = new.instancemethod(Appc.WeaponProperty_GetIconPositionX, None, WeaponProperty)
WeaponProperty.SetIconPositionX = new.instancemethod(Appc.WeaponProperty_SetIconPositionX, None, WeaponProperty)
WeaponProperty.GetIconPositionY = new.instancemethod(Appc.WeaponProperty_GetIconPositionY, None, WeaponProperty)
WeaponProperty.SetIconPositionY = new.instancemethod(Appc.WeaponProperty_SetIconPositionY, None, WeaponProperty)
WeaponProperty.IsIconAboveShip = new.instancemethod(Appc.WeaponProperty_IsIconAboveShip, None, WeaponProperty)
WeaponProperty.SetIconAboveShip = new.instancemethod(Appc.WeaponProperty_SetIconAboveShip, None, WeaponProperty)

class EnergyWeaponProperty(WeaponProperty):
    def __init__(self,*args):
        self.this = apply(Appc.new_EnergyWeaponProperty,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_EnergyWeaponProperty(self)
    def __repr__(self):
        return "<C EnergyWeaponProperty instance at %s>" % (self.this,)
class EnergyWeaponPropertyPtr(EnergyWeaponProperty):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = EnergyWeaponProperty


EnergyWeaponProperty.GetRechargeRate = new.instancemethod(Appc.EnergyWeaponProperty_GetRechargeRate, None, EnergyWeaponProperty)
EnergyWeaponProperty.GetNormalDischargeRate = new.instancemethod(Appc.EnergyWeaponProperty_GetNormalDischargeRate, None, EnergyWeaponProperty)
EnergyWeaponProperty.GetMaxCharge = new.instancemethod(Appc.EnergyWeaponProperty_GetMaxCharge, None, EnergyWeaponProperty)
EnergyWeaponProperty.GetMinFiringCharge = new.instancemethod(Appc.EnergyWeaponProperty_GetMinFiringCharge, None, EnergyWeaponProperty)
EnergyWeaponProperty.GetFireSound = new.instancemethod(Appc.EnergyWeaponProperty_GetFireSound, None, EnergyWeaponProperty)
EnergyWeaponProperty.GetMaxDamage = new.instancemethod(Appc.EnergyWeaponProperty_GetMaxDamage, None, EnergyWeaponProperty)
EnergyWeaponProperty.GetMaxDamageDistance = new.instancemethod(Appc.EnergyWeaponProperty_GetMaxDamageDistance, None, EnergyWeaponProperty)
EnergyWeaponProperty.GetIndicatorIconNum = new.instancemethod(Appc.EnergyWeaponProperty_GetIndicatorIconNum, None, EnergyWeaponProperty)
EnergyWeaponProperty.GetIndicatorIconPositionX = new.instancemethod(Appc.EnergyWeaponProperty_GetIndicatorIconPositionX, None, EnergyWeaponProperty)
EnergyWeaponProperty.GetIndicatorIconPositionY = new.instancemethod(Appc.EnergyWeaponProperty_GetIndicatorIconPositionY, None, EnergyWeaponProperty)
EnergyWeaponProperty.SetFireSound = new.instancemethod(Appc.EnergyWeaponProperty_SetFireSound, None, EnergyWeaponProperty)
EnergyWeaponProperty.SetMaxDamage = new.instancemethod(Appc.EnergyWeaponProperty_SetMaxDamage, None, EnergyWeaponProperty)
EnergyWeaponProperty.SetMaxDamageDistance = new.instancemethod(Appc.EnergyWeaponProperty_SetMaxDamageDistance, None, EnergyWeaponProperty)
EnergyWeaponProperty.SetMinFiringCharge = new.instancemethod(Appc.EnergyWeaponProperty_SetMinFiringCharge, None, EnergyWeaponProperty)
EnergyWeaponProperty.SetMaxCharge = new.instancemethod(Appc.EnergyWeaponProperty_SetMaxCharge, None, EnergyWeaponProperty)
EnergyWeaponProperty.SetNormalDischargeRate = new.instancemethod(Appc.EnergyWeaponProperty_SetNormalDischargeRate, None, EnergyWeaponProperty)
EnergyWeaponProperty.SetRechargeRate = new.instancemethod(Appc.EnergyWeaponProperty_SetRechargeRate, None, EnergyWeaponProperty)
EnergyWeaponProperty.SetIndicatorIconNum = new.instancemethod(Appc.EnergyWeaponProperty_SetIndicatorIconNum, None, EnergyWeaponProperty)
EnergyWeaponProperty.SetIndicatorIconPositionX = new.instancemethod(Appc.EnergyWeaponProperty_SetIndicatorIconPositionX, None, EnergyWeaponProperty)
EnergyWeaponProperty.SetIndicatorIconPositionY = new.instancemethod(Appc.EnergyWeaponProperty_SetIndicatorIconPositionY, None, EnergyWeaponProperty)

class PhaserProperty(EnergyWeaponProperty):
    def __init__(self,*args):
        self.this = apply(Appc.new_PhaserProperty,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_PhaserProperty(self)
    def GetOrientationForward(*args):
        val = apply(Appc.PhaserProperty_GetOrientationForward,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetOrientationUp(*args):
        val = apply(Appc.PhaserProperty_GetOrientationUp,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetOuterShellColor(*args):
        val = apply(Appc.PhaserProperty_GetOuterShellColor,args)
        if val: val = NiColorAPtr(val) ; val.thisown = 1
        return val
    def GetInnerShellColor(*args):
        val = apply(Appc.PhaserProperty_GetInnerShellColor,args)
        if val: val = NiColorAPtr(val) ; val.thisown = 1
        return val
    def GetOuterCoreColor(*args):
        val = apply(Appc.PhaserProperty_GetOuterCoreColor,args)
        if val: val = NiColorAPtr(val) ; val.thisown = 1
        return val
    def GetInnerCoreColor(*args):
        val = apply(Appc.PhaserProperty_GetInnerCoreColor,args)
        if val: val = NiColorAPtr(val) ; val.thisown = 1
        return val
    def __repr__(self):
        return "<C PhaserProperty instance at %s>" % (self.this,)
class PhaserPropertyPtr(PhaserProperty):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = PhaserProperty


PhaserProperty.SetOrientation = new.instancemethod(Appc.PhaserProperty_SetOrientation, None, PhaserProperty)
PhaserProperty.SetWidth = new.instancemethod(Appc.PhaserProperty_SetWidth, None, PhaserProperty)
PhaserProperty.SetLength = new.instancemethod(Appc.PhaserProperty_SetLength, None, PhaserProperty)
PhaserProperty.SetPhaserTextureStart = new.instancemethod(Appc.PhaserProperty_SetPhaserTextureStart, None, PhaserProperty)
PhaserProperty.SetPhaserTextureEnd = new.instancemethod(Appc.PhaserProperty_SetPhaserTextureEnd, None, PhaserProperty)
PhaserProperty.SetPhaserWidth = new.instancemethod(Appc.PhaserProperty_SetPhaserWidth, None, PhaserProperty)
PhaserProperty.SetArcWidthAngles = new.instancemethod(Appc.PhaserProperty_SetArcWidthAngles, None, PhaserProperty)
PhaserProperty.SetArcHeightAngles = new.instancemethod(Appc.PhaserProperty_SetArcHeightAngles, None, PhaserProperty)
PhaserProperty.SetOuterShellColor = new.instancemethod(Appc.PhaserProperty_SetOuterShellColor, None, PhaserProperty)
PhaserProperty.SetInnerShellColor = new.instancemethod(Appc.PhaserProperty_SetInnerShellColor, None, PhaserProperty)
PhaserProperty.SetOuterCoreColor = new.instancemethod(Appc.PhaserProperty_SetOuterCoreColor, None, PhaserProperty)
PhaserProperty.SetInnerCoreColor = new.instancemethod(Appc.PhaserProperty_SetInnerCoreColor, None, PhaserProperty)
PhaserProperty.SetNumSides = new.instancemethod(Appc.PhaserProperty_SetNumSides, None, PhaserProperty)
PhaserProperty.SetMainRadius = new.instancemethod(Appc.PhaserProperty_SetMainRadius, None, PhaserProperty)
PhaserProperty.SetTaperRadius = new.instancemethod(Appc.PhaserProperty_SetTaperRadius, None, PhaserProperty)
PhaserProperty.SetCoreScale = new.instancemethod(Appc.PhaserProperty_SetCoreScale, None, PhaserProperty)
PhaserProperty.SetTaperRatio = new.instancemethod(Appc.PhaserProperty_SetTaperRatio, None, PhaserProperty)
PhaserProperty.SetTaperMinLength = new.instancemethod(Appc.PhaserProperty_SetTaperMinLength, None, PhaserProperty)
PhaserProperty.SetTaperMaxLength = new.instancemethod(Appc.PhaserProperty_SetTaperMaxLength, None, PhaserProperty)
PhaserProperty.SetLengthTextureTilePerUnit = new.instancemethod(Appc.PhaserProperty_SetLengthTextureTilePerUnit, None, PhaserProperty)
PhaserProperty.SetPerimeterTile = new.instancemethod(Appc.PhaserProperty_SetPerimeterTile, None, PhaserProperty)
PhaserProperty.SetTextureSpeed = new.instancemethod(Appc.PhaserProperty_SetTextureSpeed, None, PhaserProperty)
PhaserProperty.SetTextureName = new.instancemethod(Appc.PhaserProperty_SetTextureName, None, PhaserProperty)
PhaserProperty.GetWidth = new.instancemethod(Appc.PhaserProperty_GetWidth, None, PhaserProperty)
PhaserProperty.GetLength = new.instancemethod(Appc.PhaserProperty_GetLength, None, PhaserProperty)
PhaserProperty.GetPhaserTextureStart = new.instancemethod(Appc.PhaserProperty_GetPhaserTextureStart, None, PhaserProperty)
PhaserProperty.GetPhaserTextureEnd = new.instancemethod(Appc.PhaserProperty_GetPhaserTextureEnd, None, PhaserProperty)
PhaserProperty.GetPhaserWidth = new.instancemethod(Appc.PhaserProperty_GetPhaserWidth, None, PhaserProperty)
PhaserProperty.GetArcWidthAngles = new.instancemethod(Appc.PhaserProperty_GetArcWidthAngles, None, PhaserProperty)
PhaserProperty.GetArcHeightAngles = new.instancemethod(Appc.PhaserProperty_GetArcHeightAngles, None, PhaserProperty)
PhaserProperty.GetArcWidthAngleMin = new.instancemethod(Appc.PhaserProperty_GetArcWidthAngleMin, None, PhaserProperty)
PhaserProperty.GetArcWidthAngleMax = new.instancemethod(Appc.PhaserProperty_GetArcWidthAngleMax, None, PhaserProperty)
PhaserProperty.GetArcHeightAngleMin = new.instancemethod(Appc.PhaserProperty_GetArcHeightAngleMin, None, PhaserProperty)
PhaserProperty.GetArcHeightAngleMax = new.instancemethod(Appc.PhaserProperty_GetArcHeightAngleMax, None, PhaserProperty)
PhaserProperty.GetNumSides = new.instancemethod(Appc.PhaserProperty_GetNumSides, None, PhaserProperty)
PhaserProperty.GetMainRadius = new.instancemethod(Appc.PhaserProperty_GetMainRadius, None, PhaserProperty)
PhaserProperty.GetTaperRadius = new.instancemethod(Appc.PhaserProperty_GetTaperRadius, None, PhaserProperty)
PhaserProperty.GetCoreScale = new.instancemethod(Appc.PhaserProperty_GetCoreScale, None, PhaserProperty)
PhaserProperty.GetTaperRatio = new.instancemethod(Appc.PhaserProperty_GetTaperRatio, None, PhaserProperty)
PhaserProperty.GetTaperMinLength = new.instancemethod(Appc.PhaserProperty_GetTaperMinLength, None, PhaserProperty)
PhaserProperty.GetTaperMaxLength = new.instancemethod(Appc.PhaserProperty_GetTaperMaxLength, None, PhaserProperty)
PhaserProperty.GetLengthTextureTilePerUnit = new.instancemethod(Appc.PhaserProperty_GetLengthTextureTilePerUnit, None, PhaserProperty)
PhaserProperty.GetPerimeterTile = new.instancemethod(Appc.PhaserProperty_GetPerimeterTile, None, PhaserProperty)
PhaserProperty.GetTextureSpeed = new.instancemethod(Appc.PhaserProperty_GetTextureSpeed, None, PhaserProperty)
PhaserProperty.GetTextureName = new.instancemethod(Appc.PhaserProperty_GetTextureName, None, PhaserProperty)

class PulseWeaponProperty(EnergyWeaponProperty):
    def __init__(self,*args):
        self.this = apply(Appc.new_PulseWeaponProperty,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_PulseWeaponProperty(self)
    def GetOrientationForward(*args):
        val = apply(Appc.PulseWeaponProperty_GetOrientationForward,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetOrientationUp(*args):
        val = apply(Appc.PulseWeaponProperty_GetOrientationUp,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetOrientationRight(*args):
        val = apply(Appc.PulseWeaponProperty_GetOrientationRight,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def __repr__(self):
        return "<C PulseWeaponProperty instance at %s>" % (self.this,)
class PulseWeaponPropertyPtr(PulseWeaponProperty):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = PulseWeaponProperty


PulseWeaponProperty.SetOrientation = new.instancemethod(Appc.PulseWeaponProperty_SetOrientation, None, PulseWeaponProperty)
PulseWeaponProperty.SetArcWidthAngles = new.instancemethod(Appc.PulseWeaponProperty_SetArcWidthAngles, None, PulseWeaponProperty)
PulseWeaponProperty.SetArcHeightAngles = new.instancemethod(Appc.PulseWeaponProperty_SetArcHeightAngles, None, PulseWeaponProperty)
PulseWeaponProperty.SetCooldownTime = new.instancemethod(Appc.PulseWeaponProperty_SetCooldownTime, None, PulseWeaponProperty)
PulseWeaponProperty.SetModuleName = new.instancemethod(Appc.PulseWeaponProperty_SetModuleName, None, PulseWeaponProperty)
PulseWeaponProperty.GetArcWidthAngles = new.instancemethod(Appc.PulseWeaponProperty_GetArcWidthAngles, None, PulseWeaponProperty)
PulseWeaponProperty.GetArcHeightAngles = new.instancemethod(Appc.PulseWeaponProperty_GetArcHeightAngles, None, PulseWeaponProperty)
PulseWeaponProperty.GetArcWidthAngleMin = new.instancemethod(Appc.PulseWeaponProperty_GetArcWidthAngleMin, None, PulseWeaponProperty)
PulseWeaponProperty.GetArcWidthAngleMax = new.instancemethod(Appc.PulseWeaponProperty_GetArcWidthAngleMax, None, PulseWeaponProperty)
PulseWeaponProperty.GetArcHeightAngleMin = new.instancemethod(Appc.PulseWeaponProperty_GetArcHeightAngleMin, None, PulseWeaponProperty)
PulseWeaponProperty.GetArcHeightAngleMax = new.instancemethod(Appc.PulseWeaponProperty_GetArcHeightAngleMax, None, PulseWeaponProperty)
PulseWeaponProperty.GetCooldownTime = new.instancemethod(Appc.PulseWeaponProperty_GetCooldownTime, None, PulseWeaponProperty)
PulseWeaponProperty.GetModuleName = new.instancemethod(Appc.PulseWeaponProperty_GetModuleName, None, PulseWeaponProperty)

class TractorBeamProperty(EnergyWeaponProperty):
    def __init__(self,*args):
        self.this = apply(Appc.new_TractorBeamProperty,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TractorBeamProperty(self)
    def GetOrientationForward(*args):
        val = apply(Appc.TractorBeamProperty_GetOrientationForward,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetOrientationUp(*args):
        val = apply(Appc.TractorBeamProperty_GetOrientationUp,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetOrientationRight(*args):
        val = apply(Appc.TractorBeamProperty_GetOrientationRight,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetOuterShellColor(*args):
        val = apply(Appc.TractorBeamProperty_GetOuterShellColor,args)
        if val: val = NiColorAPtr(val) ; val.thisown = 1
        return val
    def GetInnerShellColor(*args):
        val = apply(Appc.TractorBeamProperty_GetInnerShellColor,args)
        if val: val = NiColorAPtr(val) ; val.thisown = 1
        return val
    def GetOuterCoreColor(*args):
        val = apply(Appc.TractorBeamProperty_GetOuterCoreColor,args)
        if val: val = NiColorAPtr(val) ; val.thisown = 1
        return val
    def GetInnerCoreColor(*args):
        val = apply(Appc.TractorBeamProperty_GetInnerCoreColor,args)
        if val: val = NiColorAPtr(val) ; val.thisown = 1
        return val
    def __repr__(self):
        return "<C TractorBeamProperty instance at %s>" % (self.this,)
class TractorBeamPropertyPtr(TractorBeamProperty):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TractorBeamProperty


TractorBeamProperty.SetArcWidthAngles = new.instancemethod(Appc.TractorBeamProperty_SetArcWidthAngles, None, TractorBeamProperty)
TractorBeamProperty.SetArcHeightAngles = new.instancemethod(Appc.TractorBeamProperty_SetArcHeightAngles, None, TractorBeamProperty)
TractorBeamProperty.SetOrientation = new.instancemethod(Appc.TractorBeamProperty_SetOrientation, None, TractorBeamProperty)
TractorBeamProperty.GetArcWidthAngles = new.instancemethod(Appc.TractorBeamProperty_GetArcWidthAngles, None, TractorBeamProperty)
TractorBeamProperty.GetArcHeightAngles = new.instancemethod(Appc.TractorBeamProperty_GetArcHeightAngles, None, TractorBeamProperty)
TractorBeamProperty.GetArcWidthAngleMin = new.instancemethod(Appc.TractorBeamProperty_GetArcWidthAngleMin, None, TractorBeamProperty)
TractorBeamProperty.GetArcWidthAngleMax = new.instancemethod(Appc.TractorBeamProperty_GetArcWidthAngleMax, None, TractorBeamProperty)
TractorBeamProperty.GetArcHeightAngleMin = new.instancemethod(Appc.TractorBeamProperty_GetArcHeightAngleMin, None, TractorBeamProperty)
TractorBeamProperty.GetArcHeightAngleMax = new.instancemethod(Appc.TractorBeamProperty_GetArcHeightAngleMax, None, TractorBeamProperty)
TractorBeamProperty.GetNumSides = new.instancemethod(Appc.TractorBeamProperty_GetNumSides, None, TractorBeamProperty)
TractorBeamProperty.GetMainRadius = new.instancemethod(Appc.TractorBeamProperty_GetMainRadius, None, TractorBeamProperty)
TractorBeamProperty.GetTaperRadius = new.instancemethod(Appc.TractorBeamProperty_GetTaperRadius, None, TractorBeamProperty)
TractorBeamProperty.GetCoreScale = new.instancemethod(Appc.TractorBeamProperty_GetCoreScale, None, TractorBeamProperty)
TractorBeamProperty.GetTaperRatio = new.instancemethod(Appc.TractorBeamProperty_GetTaperRatio, None, TractorBeamProperty)
TractorBeamProperty.GetTaperMinLength = new.instancemethod(Appc.TractorBeamProperty_GetTaperMinLength, None, TractorBeamProperty)
TractorBeamProperty.GetTaperMaxLength = new.instancemethod(Appc.TractorBeamProperty_GetTaperMaxLength, None, TractorBeamProperty)
TractorBeamProperty.GetLengthTextureTilePerUnit = new.instancemethod(Appc.TractorBeamProperty_GetLengthTextureTilePerUnit, None, TractorBeamProperty)
TractorBeamProperty.GetPerimeterTile = new.instancemethod(Appc.TractorBeamProperty_GetPerimeterTile, None, TractorBeamProperty)
TractorBeamProperty.GetTextureSpeed = new.instancemethod(Appc.TractorBeamProperty_GetTextureSpeed, None, TractorBeamProperty)
TractorBeamProperty.GetTextureName = new.instancemethod(Appc.TractorBeamProperty_GetTextureName, None, TractorBeamProperty)
TractorBeamProperty.GetTextureStart = new.instancemethod(Appc.TractorBeamProperty_GetTextureStart, None, TractorBeamProperty)
TractorBeamProperty.GetTextureEnd = new.instancemethod(Appc.TractorBeamProperty_GetTextureEnd, None, TractorBeamProperty)
TractorBeamProperty.GetTractorBeamWidth = new.instancemethod(Appc.TractorBeamProperty_GetTractorBeamWidth, None, TractorBeamProperty)
TractorBeamProperty.SetOuterShellColor = new.instancemethod(Appc.TractorBeamProperty_SetOuterShellColor, None, TractorBeamProperty)
TractorBeamProperty.SetInnerShellColor = new.instancemethod(Appc.TractorBeamProperty_SetInnerShellColor, None, TractorBeamProperty)
TractorBeamProperty.SetOuterCoreColor = new.instancemethod(Appc.TractorBeamProperty_SetOuterCoreColor, None, TractorBeamProperty)
TractorBeamProperty.SetInnerCoreColor = new.instancemethod(Appc.TractorBeamProperty_SetInnerCoreColor, None, TractorBeamProperty)
TractorBeamProperty.SetNumSides = new.instancemethod(Appc.TractorBeamProperty_SetNumSides, None, TractorBeamProperty)
TractorBeamProperty.SetMainRadius = new.instancemethod(Appc.TractorBeamProperty_SetMainRadius, None, TractorBeamProperty)
TractorBeamProperty.SetTaperRadius = new.instancemethod(Appc.TractorBeamProperty_SetTaperRadius, None, TractorBeamProperty)
TractorBeamProperty.SetCoreScale = new.instancemethod(Appc.TractorBeamProperty_SetCoreScale, None, TractorBeamProperty)
TractorBeamProperty.SetTaperRatio = new.instancemethod(Appc.TractorBeamProperty_SetTaperRatio, None, TractorBeamProperty)
TractorBeamProperty.SetTaperMinLength = new.instancemethod(Appc.TractorBeamProperty_SetTaperMinLength, None, TractorBeamProperty)
TractorBeamProperty.SetTaperMaxLength = new.instancemethod(Appc.TractorBeamProperty_SetTaperMaxLength, None, TractorBeamProperty)
TractorBeamProperty.SetLengthTextureTilePerUnit = new.instancemethod(Appc.TractorBeamProperty_SetLengthTextureTilePerUnit, None, TractorBeamProperty)
TractorBeamProperty.SetPerimeterTile = new.instancemethod(Appc.TractorBeamProperty_SetPerimeterTile, None, TractorBeamProperty)
TractorBeamProperty.SetTextureSpeed = new.instancemethod(Appc.TractorBeamProperty_SetTextureSpeed, None, TractorBeamProperty)
TractorBeamProperty.SetTextureName = new.instancemethod(Appc.TractorBeamProperty_SetTextureName, None, TractorBeamProperty)
TractorBeamProperty.SetTextureStart = new.instancemethod(Appc.TractorBeamProperty_SetTextureStart, None, TractorBeamProperty)
TractorBeamProperty.SetTextureEnd = new.instancemethod(Appc.TractorBeamProperty_SetTextureEnd, None, TractorBeamProperty)
TractorBeamProperty.SetTractorBeamWidth = new.instancemethod(Appc.TractorBeamProperty_SetTractorBeamWidth, None, TractorBeamProperty)

class TorpedoTubeProperty(WeaponProperty):
    def __init__(self,*args):
        self.this = apply(Appc.new_TorpedoTubeProperty,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TorpedoTubeProperty(self)
    def GetDirection(*args):
        val = apply(Appc.TorpedoTubeProperty_GetDirection,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def GetRight(*args):
        val = apply(Appc.TorpedoTubeProperty_GetRight,args)
        if val: val = TGPoint3Ptr(val) ; val.thisown = 1
        return val
    def __repr__(self):
        return "<C TorpedoTubeProperty instance at %s>" % (self.this,)
class TorpedoTubePropertyPtr(TorpedoTubeProperty):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TorpedoTubeProperty


TorpedoTubeProperty.GetImmediateDelay = new.instancemethod(Appc.TorpedoTubeProperty_GetImmediateDelay, None, TorpedoTubeProperty)
TorpedoTubeProperty.GetReloadDelay = new.instancemethod(Appc.TorpedoTubeProperty_GetReloadDelay, None, TorpedoTubeProperty)
TorpedoTubeProperty.GetMaxReady = new.instancemethod(Appc.TorpedoTubeProperty_GetMaxReady, None, TorpedoTubeProperty)
TorpedoTubeProperty.SetDirection = new.instancemethod(Appc.TorpedoTubeProperty_SetDirection, None, TorpedoTubeProperty)
TorpedoTubeProperty.SetRight = new.instancemethod(Appc.TorpedoTubeProperty_SetRight, None, TorpedoTubeProperty)
TorpedoTubeProperty.SetImmediateDelay = new.instancemethod(Appc.TorpedoTubeProperty_SetImmediateDelay, None, TorpedoTubeProperty)
TorpedoTubeProperty.SetReloadDelay = new.instancemethod(Appc.TorpedoTubeProperty_SetReloadDelay, None, TorpedoTubeProperty)
TorpedoTubeProperty.SetMaxReady = new.instancemethod(Appc.TorpedoTubeProperty_SetMaxReady, None, TorpedoTubeProperty)

class TorpedoAmmoType:
    def __init__(self,*args):
        self.this = apply(Appc.new_TorpedoAmmoType,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TorpedoAmmoType(self)
    __setmethods__ = {
        "m_iMaxTorpedoes" : Appc.TorpedoAmmoType_m_iMaxTorpedoes_set,
        "m_pcModule" : Appc.TorpedoAmmoType_m_pcModule_set,
        "m_fLaunchSpeed" : Appc.TorpedoAmmoType_m_fLaunchSpeed_set,
        "m_pcLaunchSound" : Appc.TorpedoAmmoType_m_pcLaunchSound_set,
    }
    def __setattr__(self,name,value):
        if (name == "this") or (name == "thisown"): self.__dict__[name] = value; return
        method = TorpedoAmmoType.__setmethods__.get(name,None)
        if method: return method(self,value)
        self.__dict__[name] = value
    __getmethods__ = {
        "m_iMaxTorpedoes" : Appc.TorpedoAmmoType_m_iMaxTorpedoes_get,
        "m_pcModule" : Appc.TorpedoAmmoType_m_pcModule_get,
        "m_fLaunchSpeed" : Appc.TorpedoAmmoType_m_fLaunchSpeed_get,
        "m_pcLaunchSound" : Appc.TorpedoAmmoType_m_pcLaunchSound_get,
    }
    def __getattr__(self,name):
        method = TorpedoAmmoType.__getmethods__.get(name,None)
        if method: return method(self)
        raise AttributeError,name
    def __repr__(self):
        return "<C TorpedoAmmoType instance at %s>" % (self.this,)
class TorpedoAmmoTypePtr(TorpedoAmmoType):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TorpedoAmmoType


TorpedoAmmoType.GetLaunchSpeed = new.instancemethod(Appc.TorpedoAmmoType_GetLaunchSpeed, None, TorpedoAmmoType)
TorpedoAmmoType.GetLaunchSound = new.instancemethod(Appc.TorpedoAmmoType_GetLaunchSound, None, TorpedoAmmoType)
TorpedoAmmoType.GetPowerCost = new.instancemethod(Appc.TorpedoAmmoType_GetPowerCost, None, TorpedoAmmoType)
TorpedoAmmoType.GetAmmoName = new.instancemethod(Appc.TorpedoAmmoType_GetAmmoName, None, TorpedoAmmoType)
TorpedoAmmoType.GetMaxTorpedoes = new.instancemethod(Appc.TorpedoAmmoType_GetMaxTorpedoes, None, TorpedoAmmoType)
TorpedoAmmoType.SetMaxTorpedoes = new.instancemethod(Appc.TorpedoAmmoType_SetMaxTorpedoes, None, TorpedoAmmoType)
TorpedoAmmoType.GetTorpedoScript = new.instancemethod(Appc.TorpedoAmmoType_GetTorpedoScript, None, TorpedoAmmoType)
TorpedoAmmoType.SetTorpedoScript = new.instancemethod(Appc.TorpedoAmmoType_SetTorpedoScript, None, TorpedoAmmoType)

class TorpedoSystemProperty(WeaponSystemProperty):
    def __init__(self,*args):
        self.this = apply(Appc.new_TorpedoSystemProperty,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TorpedoSystemProperty(self)
    def __repr__(self):
        return "<C TorpedoSystemProperty instance at %s>" % (self.this,)
class TorpedoSystemPropertyPtr(TorpedoSystemProperty):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = TorpedoSystemProperty


TorpedoSystemProperty.SetMaxTorpedoes = new.instancemethod(Appc.TorpedoSystemProperty_SetMaxTorpedoes, None, TorpedoSystemProperty)
TorpedoSystemProperty.GetMaxTorpedoes = new.instancemethod(Appc.TorpedoSystemProperty_GetMaxTorpedoes, None, TorpedoSystemProperty)
TorpedoSystemProperty.SetTorpedoScript = new.instancemethod(Appc.TorpedoSystemProperty_SetTorpedoScript, None, TorpedoSystemProperty)
TorpedoSystemProperty.GetTorpedoScript = new.instancemethod(Appc.TorpedoSystemProperty_GetTorpedoScript, None, TorpedoSystemProperty)
TorpedoSystemProperty.SetNumAmmoTypes = new.instancemethod(Appc.TorpedoSystemProperty_SetNumAmmoTypes, None, TorpedoSystemProperty)
TorpedoSystemProperty.GetNumAmmoTypes = new.instancemethod(Appc.TorpedoSystemProperty_GetNumAmmoTypes, None, TorpedoSystemProperty)

class EngineGlowProperty(TGModelProperty):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_TGModelProperty(self)
    def __repr__(self):
        return "<C EngineGlowProperty instance at %s>" % (self.this,)
class EngineGlowPropertyPtr(EngineGlowProperty):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = EngineGlowProperty



class ShieldProperty(PoweredSubsystemProperty):
    FRONT_SHIELDS = Appc.ShieldProperty_FRONT_SHIELDS
    REAR_SHIELDS = Appc.ShieldProperty_REAR_SHIELDS
    TOP_SHIELDS = Appc.ShieldProperty_TOP_SHIELDS
    BOTTOM_SHIELDS = Appc.ShieldProperty_BOTTOM_SHIELDS
    LEFT_SHIELDS = Appc.ShieldProperty_LEFT_SHIELDS
    RIGHT_SHIELDS = Appc.ShieldProperty_RIGHT_SHIELDS
    NUM_SHIELDS = Appc.ShieldProperty_NUM_SHIELDS
    def __init__(self,*args):
        self.this = apply(Appc.new_ShieldProperty,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_ShieldProperty(self)
    def GetShieldGlowColor(*args):
        val = apply(Appc.ShieldProperty_GetShieldGlowColor,args)
        if val: val = TGColorAPtr(val) ; val.thisown = 1
        return val
    def __repr__(self):
        return "<C ShieldProperty instance at %s>" % (self.this,)
class ShieldPropertyPtr(ShieldProperty):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = ShieldProperty


ShieldProperty.GetShieldGlowDecay = new.instancemethod(Appc.ShieldProperty_GetShieldGlowDecay, None, ShieldProperty)
ShieldProperty.GetMaxShields = new.instancemethod(Appc.ShieldProperty_GetMaxShields, None, ShieldProperty)
ShieldProperty.GetShieldChargePerSecond = new.instancemethod(Appc.ShieldProperty_GetShieldChargePerSecond, None, ShieldProperty)
ShieldProperty.SetShieldGlowColor = new.instancemethod(Appc.ShieldProperty_SetShieldGlowColor, None, ShieldProperty)
ShieldProperty.SetShieldGlowDecay = new.instancemethod(Appc.ShieldProperty_SetShieldGlowDecay, None, ShieldProperty)
ShieldProperty.SetMaxShields = new.instancemethod(Appc.ShieldProperty_SetMaxShields, None, ShieldProperty)
ShieldProperty.SetShieldChargePerSecond = new.instancemethod(Appc.ShieldProperty_SetShieldChargePerSecond, None, ShieldProperty)

class HullProperty(SubsystemProperty):
    def __init__(self,*args):
        self.this = apply(Appc.new_HullProperty,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_HullProperty(self)
    def __repr__(self):
        return "<C HullProperty instance at %s>" % (self.this,)
class HullPropertyPtr(HullProperty):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = HullProperty



class SensorProperty(PoweredSubsystemProperty):
    def __init__(self,*args):
        self.this = apply(Appc.new_SensorProperty,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_SensorProperty(self)
    def __repr__(self):
        return "<C SensorProperty instance at %s>" % (self.this,)
class SensorPropertyPtr(SensorProperty):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = SensorProperty


SensorProperty.GetBaseSensorRange = new.instancemethod(Appc.SensorProperty_GetBaseSensorRange, None, SensorProperty)
SensorProperty.SetBaseSensorRange = new.instancemethod(Appc.SensorProperty_SetBaseSensorRange, None, SensorProperty)
SensorProperty.GetMaxProbes = new.instancemethod(Appc.SensorProperty_GetMaxProbes, None, SensorProperty)
SensorProperty.SetMaxProbes = new.instancemethod(Appc.SensorProperty_SetMaxProbes, None, SensorProperty)

class CloakingSubsystemProperty(PoweredSubsystemProperty):
    def __init__(self,*args):
        self.this = apply(Appc.new_CloakingSubsystemProperty,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_CloakingSubsystemProperty(self)
    def __repr__(self):
        return "<C CloakingSubsystemProperty instance at %s>" % (self.this,)
class CloakingSubsystemPropertyPtr(CloakingSubsystemProperty):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = CloakingSubsystemProperty


CloakingSubsystemProperty.GetCloakStrength = new.instancemethod(Appc.CloakingSubsystemProperty_GetCloakStrength, None, CloakingSubsystemProperty)
CloakingSubsystemProperty.SetCloakStrength = new.instancemethod(Appc.CloakingSubsystemProperty_SetCloakStrength, None, CloakingSubsystemProperty)

class RepairSubsystemProperty(PoweredSubsystemProperty):
    def __init__(self,*args):
        self.this = apply(Appc.new_RepairSubsystemProperty,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_RepairSubsystemProperty(self)
    def __repr__(self):
        return "<C RepairSubsystemProperty instance at %s>" % (self.this,)
class RepairSubsystemPropertyPtr(RepairSubsystemProperty):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = RepairSubsystemProperty


RepairSubsystemProperty.GetMaxRepairPoints = new.instancemethod(Appc.RepairSubsystemProperty_GetMaxRepairPoints, None, RepairSubsystemProperty)
RepairSubsystemProperty.GetNumRepairTeams = new.instancemethod(Appc.RepairSubsystemProperty_GetNumRepairTeams, None, RepairSubsystemProperty)
RepairSubsystemProperty.SetMaxRepairPoints = new.instancemethod(Appc.RepairSubsystemProperty_SetMaxRepairPoints, None, RepairSubsystemProperty)
RepairSubsystemProperty.SetNumRepairTeams = new.instancemethod(Appc.RepairSubsystemProperty_SetNumRepairTeams, None, RepairSubsystemProperty)

class ShipProperty(TGModelProperty):
    def __init__(self,*args):
        self.this = apply(Appc.new_ShipProperty,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_ShipProperty(self)
    def __repr__(self):
        return "<C ShipProperty instance at %s>" % (self.this,)
class ShipPropertyPtr(ShipProperty):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = ShipProperty


ShipProperty.GetGenus = new.instancemethod(Appc.ShipProperty_GetGenus, None, ShipProperty)
ShipProperty.GetSpecies = new.instancemethod(Appc.ShipProperty_GetSpecies, None, ShipProperty)
ShipProperty.GetMass = new.instancemethod(Appc.ShipProperty_GetMass, None, ShipProperty)
ShipProperty.GetRotationalInertia = new.instancemethod(Appc.ShipProperty_GetRotationalInertia, None, ShipProperty)
ShipProperty.GetShipName = new.instancemethod(Appc.ShipProperty_GetShipName, None, ShipProperty)
ShipProperty.GetModelFilename = new.instancemethod(Appc.ShipProperty_GetModelFilename, None, ShipProperty)
ShipProperty.GetDamageResolution = new.instancemethod(Appc.ShipProperty_GetDamageResolution, None, ShipProperty)
ShipProperty.GetAffiliation = new.instancemethod(Appc.ShipProperty_GetAffiliation, None, ShipProperty)
ShipProperty.IsStationary = new.instancemethod(Appc.ShipProperty_IsStationary, None, ShipProperty)
ShipProperty.GetAIString = new.instancemethod(Appc.ShipProperty_GetAIString, None, ShipProperty)
ShipProperty.GetDeathExplosionSound = new.instancemethod(Appc.ShipProperty_GetDeathExplosionSound, None, ShipProperty)
ShipProperty.SetGenus = new.instancemethod(Appc.ShipProperty_SetGenus, None, ShipProperty)
ShipProperty.SetSpecies = new.instancemethod(Appc.ShipProperty_SetSpecies, None, ShipProperty)
ShipProperty.SetMass = new.instancemethod(Appc.ShipProperty_SetMass, None, ShipProperty)
ShipProperty.SetRotationalInertia = new.instancemethod(Appc.ShipProperty_SetRotationalInertia, None, ShipProperty)
ShipProperty.SetShipName = new.instancemethod(Appc.ShipProperty_SetShipName, None, ShipProperty)
ShipProperty.SetModelFilename = new.instancemethod(Appc.ShipProperty_SetModelFilename, None, ShipProperty)
ShipProperty.SetDamageResolution = new.instancemethod(Appc.ShipProperty_SetDamageResolution, None, ShipProperty)
ShipProperty.SetAffiliation = new.instancemethod(Appc.ShipProperty_SetAffiliation, None, ShipProperty)
ShipProperty.SetStationary = new.instancemethod(Appc.ShipProperty_SetStationary, None, ShipProperty)
ShipProperty.SetAIString = new.instancemethod(Appc.ShipProperty_SetAIString, None, ShipProperty)
ShipProperty.SetDeathExplosionSound = new.instancemethod(Appc.ShipProperty_SetDeathExplosionSound, None, ShipProperty)

class PowerProperty(SubsystemProperty):
    def __init__(self,*args):
        self.this = apply(Appc.new_PowerProperty,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_PowerProperty(self)
    def __repr__(self):
        return "<C PowerProperty instance at %s>" % (self.this,)
class PowerPropertyPtr(PowerProperty):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = PowerProperty


PowerProperty.GetMainBatteryLimit = new.instancemethod(Appc.PowerProperty_GetMainBatteryLimit, None, PowerProperty)
PowerProperty.GetBackupBatteryLimit = new.instancemethod(Appc.PowerProperty_GetBackupBatteryLimit, None, PowerProperty)
PowerProperty.GetMainConduitCapacity = new.instancemethod(Appc.PowerProperty_GetMainConduitCapacity, None, PowerProperty)
PowerProperty.GetBackupConduitCapacity = new.instancemethod(Appc.PowerProperty_GetBackupConduitCapacity, None, PowerProperty)
PowerProperty.GetPowerOutput = new.instancemethod(Appc.PowerProperty_GetPowerOutput, None, PowerProperty)
PowerProperty.SetMainBatteryLimit = new.instancemethod(Appc.PowerProperty_SetMainBatteryLimit, None, PowerProperty)
PowerProperty.SetBackupBatteryLimit = new.instancemethod(Appc.PowerProperty_SetBackupBatteryLimit, None, PowerProperty)
PowerProperty.SetMainConduitCapacity = new.instancemethod(Appc.PowerProperty_SetMainConduitCapacity, None, PowerProperty)
PowerProperty.SetBackupConduitCapacity = new.instancemethod(Appc.PowerProperty_SetBackupConduitCapacity, None, PowerProperty)
PowerProperty.SetPowerOutput = new.instancemethod(Appc.PowerProperty_SetPowerOutput, None, PowerProperty)

class ImpulseEngineProperty(PoweredSubsystemProperty):
    def __init__(self,*args):
        self.this = apply(Appc.new_ImpulseEngineProperty,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_ImpulseEngineProperty(self)
    def __repr__(self):
        return "<C ImpulseEngineProperty instance at %s>" % (self.this,)
class ImpulseEnginePropertyPtr(ImpulseEngineProperty):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = ImpulseEngineProperty


ImpulseEngineProperty.GetMaxSpeed = new.instancemethod(Appc.ImpulseEngineProperty_GetMaxSpeed, None, ImpulseEngineProperty)
ImpulseEngineProperty.GetMaxAccel = new.instancemethod(Appc.ImpulseEngineProperty_GetMaxAccel, None, ImpulseEngineProperty)
ImpulseEngineProperty.GetMaxAngularVelocity = new.instancemethod(Appc.ImpulseEngineProperty_GetMaxAngularVelocity, None, ImpulseEngineProperty)
ImpulseEngineProperty.GetMaxAngularAccel = new.instancemethod(Appc.ImpulseEngineProperty_GetMaxAngularAccel, None, ImpulseEngineProperty)
ImpulseEngineProperty.GetEngineSound = new.instancemethod(Appc.ImpulseEngineProperty_GetEngineSound, None, ImpulseEngineProperty)
ImpulseEngineProperty.SetMaxSpeed = new.instancemethod(Appc.ImpulseEngineProperty_SetMaxSpeed, None, ImpulseEngineProperty)
ImpulseEngineProperty.SetMaxAccel = new.instancemethod(Appc.ImpulseEngineProperty_SetMaxAccel, None, ImpulseEngineProperty)
ImpulseEngineProperty.SetMaxAngularVelocity = new.instancemethod(Appc.ImpulseEngineProperty_SetMaxAngularVelocity, None, ImpulseEngineProperty)
ImpulseEngineProperty.SetMaxAngularAccel = new.instancemethod(Appc.ImpulseEngineProperty_SetMaxAngularAccel, None, ImpulseEngineProperty)
ImpulseEngineProperty.SetEngineSound = new.instancemethod(Appc.ImpulseEngineProperty_SetEngineSound, None, ImpulseEngineProperty)

class WarpEngineProperty(PoweredSubsystemProperty):
    def __init__(self,*args):
        self.this = apply(Appc.new_WarpEngineProperty,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_WarpEngineProperty(self)
    def __repr__(self):
        return "<C WarpEngineProperty instance at %s>" % (self.this,)
class WarpEnginePropertyPtr(WarpEngineProperty):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = WarpEngineProperty



class EngineProperty(SubsystemProperty):
    EP_IMPULSE = Appc.EngineProperty_EP_IMPULSE
    EP_WARP = Appc.EngineProperty_EP_WARP
    def __init__(self,*args):
        self.this = apply(Appc.new_EngineProperty,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_EngineProperty(self)
    def __repr__(self):
        return "<C EngineProperty instance at %s>" % (self.this,)
class EnginePropertyPtr(EngineProperty):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = EngineProperty


EngineProperty.GetEngineType = new.instancemethod(Appc.EngineProperty_GetEngineType, None, EngineProperty)
EngineProperty.SetEngineType = new.instancemethod(Appc.EngineProperty_SetEngineType, None, EngineProperty)

class EffectEmitterProperty(PositionOrientationProperty):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_PositionOrientationProperty(self)
    def __repr__(self):
        return "<C EffectEmitterProperty instance at %s>" % (self.this,)
class EffectEmitterPropertyPtr(EffectEmitterProperty):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = EffectEmitterProperty



class SmokeEmitterProperty(EffectEmitterProperty):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_PositionOrientationProperty(self)
    def __repr__(self):
        return "<C SmokeEmitterProperty instance at %s>" % (self.this,)
class SmokeEmitterPropertyPtr(SmokeEmitterProperty):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = SmokeEmitterProperty



class SparkEmitterProperty(EffectEmitterProperty):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_PositionOrientationProperty(self)
    def __repr__(self):
        return "<C SparkEmitterProperty instance at %s>" % (self.this,)
class SparkEmitterPropertyPtr(SparkEmitterProperty):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = SparkEmitterProperty



class ExplodeEmitterProperty(EffectEmitterProperty):
    def __init__(self,this):
        self.this = this

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_PositionOrientationProperty(self)
    def __repr__(self):
        return "<C ExplodeEmitterProperty instance at %s>" % (self.this,)
class ExplodeEmitterPropertyPtr(ExplodeEmitterProperty):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = ExplodeEmitterProperty



class BlinkingLightProperty(EffectEmitterProperty):
    def __init__(self,this):
        self.this = this

    def GetColor(*args):
        val = apply(Appc.BlinkingLightProperty_GetColor,args)
        if val: val = TGColorAPtr(val) ; val.thisown = 1
        return val
    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_PositionOrientationProperty(self)
    def __repr__(self):
        return "<C BlinkingLightProperty instance at %s>" % (self.this,)
class BlinkingLightPropertyPtr(BlinkingLightProperty):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = BlinkingLightProperty


BlinkingLightProperty.GetRadius = new.instancemethod(Appc.BlinkingLightProperty_GetRadius, None, BlinkingLightProperty)
BlinkingLightProperty.GetPeriod = new.instancemethod(Appc.BlinkingLightProperty_GetPeriod, None, BlinkingLightProperty)
BlinkingLightProperty.GetDuration = new.instancemethod(Appc.BlinkingLightProperty_GetDuration, None, BlinkingLightProperty)
BlinkingLightProperty.GetTextureName = new.instancemethod(Appc.BlinkingLightProperty_GetTextureName, None, BlinkingLightProperty)
BlinkingLightProperty.SetColor = new.instancemethod(Appc.BlinkingLightProperty_SetColor, None, BlinkingLightProperty)
BlinkingLightProperty.SetRadius = new.instancemethod(Appc.BlinkingLightProperty_SetRadius, None, BlinkingLightProperty)
BlinkingLightProperty.SetPeriod = new.instancemethod(Appc.BlinkingLightProperty_SetPeriod, None, BlinkingLightProperty)
BlinkingLightProperty.SetDuration = new.instancemethod(Appc.BlinkingLightProperty_SetDuration, None, BlinkingLightProperty)
BlinkingLightProperty.SetTextureName = new.instancemethod(Appc.BlinkingLightProperty_SetTextureName, None, BlinkingLightProperty)

class ObjectEmitterProperty(PositionOrientationProperty):
    OEP_UNKNOWN = Appc.ObjectEmitterProperty_OEP_UNKNOWN
    OEP_SHUTTLE = Appc.ObjectEmitterProperty_OEP_SHUTTLE
    OEP_PROBE = Appc.ObjectEmitterProperty_OEP_PROBE
    OEP_DECOY = Appc.ObjectEmitterProperty_OEP_DECOY
    def __init__(self,*args):
        self.this = apply(Appc.new_ObjectEmitterProperty,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_ObjectEmitterProperty(self)
    def __repr__(self):
        return "<C ObjectEmitterProperty instance at %s>" % (self.this,)
class ObjectEmitterPropertyPtr(ObjectEmitterProperty):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = ObjectEmitterProperty


ObjectEmitterProperty.GetEmittedObjectType = new.instancemethod(Appc.ObjectEmitterProperty_GetEmittedObjectType, None, ObjectEmitterProperty)
ObjectEmitterProperty.SetEmittedObjectType = new.instancemethod(Appc.ObjectEmitterProperty_SetEmittedObjectType, None, ObjectEmitterProperty)

class MultiplayerGame(Game):
    MAX_PLAYERS = Appc.MultiplayerGame_MAX_PLAYERS
    def __init__(self,*args):
        self.this = apply(Appc.new_MultiplayerGame,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_MultiplayerGame(self)
    def GetPlayerName(*args):
        val = apply(Appc.MultiplayerGame_GetPlayerName,args)
        if val: val = TGStringPtr(val) 
        return val
    def GetShipFromPlayerID(*args):
        val = apply(Appc.MultiplayerGame_GetShipFromPlayerID,args)
        if val: val = ShipClassPtr(val) 
        return val
    def __repr__(self):
        return "<C MultiplayerGame instance at %s>" % (self.this,)
class MultiplayerGamePtr(MultiplayerGame):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = MultiplayerGame


MultiplayerGame.GetPlayerNumberFromID = new.instancemethod(Appc.MultiplayerGame_GetPlayerNumberFromID, None, MultiplayerGame)
MultiplayerGame.SetReadyForNewPlayers = new.instancemethod(Appc.MultiplayerGame_SetReadyForNewPlayers, None, MultiplayerGame)
MultiplayerGame.IsReadyForNewPlayers = new.instancemethod(Appc.MultiplayerGame_IsReadyForNewPlayers, None, MultiplayerGame)
MultiplayerGame.SetMaxPlayers = new.instancemethod(Appc.MultiplayerGame_SetMaxPlayers, None, MultiplayerGame)
MultiplayerGame.GetMaxPlayers = new.instancemethod(Appc.MultiplayerGame_GetMaxPlayers, None, MultiplayerGame)
MultiplayerGame.GetNumberPlayersInGame = new.instancemethod(Appc.MultiplayerGame_GetNumberPlayersInGame, None, MultiplayerGame)
MultiplayerGame.IsPlayerInGame = new.instancemethod(Appc.MultiplayerGame_IsPlayerInGame, None, MultiplayerGame)
MultiplayerGame.DeletePlayerShipsAndTorps = new.instancemethod(Appc.MultiplayerGame_DeletePlayerShipsAndTorps, None, MultiplayerGame)
MultiplayerGame.DeleteObjectFromGame = new.instancemethod(Appc.MultiplayerGame_DeleteObjectFromGame, None, MultiplayerGame)
MultiplayerGame.IsPlayerUsingModem = new.instancemethod(Appc.MultiplayerGame_IsPlayerUsingModem, None, MultiplayerGame)

class ServerListEvent(TGEvent):
    def __init__(self,*args):
        self.this = apply(Appc.new_ServerListEvent,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_ServerListEvent(self)
    def __repr__(self):
        return "<C ServerListEvent instance at %s>" % (self.this,)
class ServerListEventPtr(ServerListEvent):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = ServerListEvent


ServerListEvent.Copy = new.instancemethod(Appc.ServerListEvent_Copy, None, ServerListEvent)
ServerListEvent.SetServer = new.instancemethod(Appc.ServerListEvent_SetServer, None, ServerListEvent)
ServerListEvent.GetServer = new.instancemethod(Appc.ServerListEvent_GetServer, None, ServerListEvent)
ServerListEvent.GetServerName = new.instancemethod(Appc.ServerListEvent_GetServerName, None, ServerListEvent)
ServerListEvent.GetMissionName = new.instancemethod(Appc.ServerListEvent_GetMissionName, None, ServerListEvent)
ServerListEvent.GetAddress = new.instancemethod(Appc.ServerListEvent_GetAddress, None, ServerListEvent)
ServerListEvent.GetVersion = new.instancemethod(Appc.ServerListEvent_GetVersion, None, ServerListEvent)
ServerListEvent.GetPortNumber = new.instancemethod(Appc.ServerListEvent_GetPortNumber, None, ServerListEvent)
ServerListEvent.GetPing = new.instancemethod(Appc.ServerListEvent_GetPing, None, ServerListEvent)
ServerListEvent.GetNumPlayers = new.instancemethod(Appc.ServerListEvent_GetNumPlayers, None, ServerListEvent)
ServerListEvent.GetMaxPlayers = new.instancemethod(Appc.ServerListEvent_GetMaxPlayers, None, ServerListEvent)

class SortServerListEvent(TGEvent):
    def __init__(self,*args):
        self.this = apply(Appc.new_SortServerListEvent,args)
        self.thisown = 1

    def __del__(self,Appc=Appc):
        if self.thisown == 1 :
            Appc.delete_SortServerListEvent(self)
    def __repr__(self):
        return "<C SortServerListEvent instance at %s>" % (self.this,)
class SortServerListEventPtr(SortServerListEvent):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = SortServerListEvent


SortServerListEvent.Copy = new.instancemethod(Appc.SortServerListEvent_Copy, None, SortServerListEvent)
SortServerListEvent.SetSortBy = new.instancemethod(Appc.SortServerListEvent_SetSortBy, None, SortServerListEvent)
SortServerListEvent.GetSortBy = new.instancemethod(Appc.SortServerListEvent_GetSortBy, None, SortServerListEvent)
SortServerListEvent.SetStringField = new.instancemethod(Appc.SortServerListEvent_SetStringField, None, SortServerListEvent)
SortServerListEvent.IsStringField = new.instancemethod(Appc.SortServerListEvent_IsStringField, None, SortServerListEvent)



#-------------- FUNCTION WRAPPERS ------------------

TGLocDBWrapperSerialize = Appc.TGLocDBWrapperSerialize

TGLocDBWrapperUnserialize = Appc.TGLocDBWrapperUnserialize

IsNull = Appc.IsNull

DeleteBuffer = Appc.DeleteBuffer

Breakpoint = Appc.Breakpoint

SerializeGetState = Appc.SerializeGetState

UnserializeSetState = Appc.UnserializeSetState

TGActionManager_SkipEvents = Appc.TGActionManager_SkipEvents

TGActionManager_RegisterAction = Appc.TGActionManager_RegisterAction

TGActionManager_KillActions = Appc.TGActionManager_KillActions

TGScriptAction_Create = Appc.TGScriptAction_Create

def ChaseCameraMode_Cast(*args, **kwargs):
    val = apply(Appc.ChaseCameraMode_Cast,args,kwargs)
    if val: val = CameraModePtr(val)
    return val

def TargetCameraMode_Cast(*args, **kwargs):
    val = apply(Appc.TargetCameraMode_Cast,args,kwargs)
    if val: val = CameraModePtr(val)
    return val

def ZoomTargetMode_Cast(*args, **kwargs):
    val = apply(Appc.ZoomTargetMode_Cast,args,kwargs)
    if val: val = CameraModePtr(val)
    return val

def MapCameraMode_Cast(*args, **kwargs):
    val = apply(Appc.MapCameraMode_Cast,args,kwargs)
    if val: val = CameraModePtr(val)
    return val

def DropAndWatchMode_Cast(*args, **kwargs):
    val = apply(Appc.DropAndWatchMode_Cast,args,kwargs)
    if val: val = CameraModePtr(val)
    return val

def PlacementWatchMode_Cast(*args, **kwargs):
    val = apply(Appc.PlacementWatchMode_Cast,args,kwargs)
    if val: val = CameraModePtr(val)
    return val

def LockedPositionMode_Cast(*args, **kwargs):
    val = apply(Appc.LockedPositionMode_Cast,args,kwargs)
    if val: val = CameraModePtr(val)
    return val

def TorpCameraMode_Cast(*args, **kwargs):
    val = apply(Appc.TorpCameraMode_Cast,args,kwargs)
    if val: val = CameraModePtr(val)
    return val

def PlaceByDirectionMode_Cast(*args, **kwargs):
    val = apply(Appc.PlaceByDirectionMode_Cast,args,kwargs)
    if val: val = CameraModePtr(val)
    return val

BreakIntoSets = Appc.BreakIntoSets

ArtificialIntelligence_GetAIByID = Appc.ArtificialIntelligence_GetAIByID

ConditionScript_Create = Appc.ConditionScript_Create

FuzzyLogic_BreakIntoSets = Appc.FuzzyLogic_BreakIntoSets

AIScriptAssist_GetIncomingTorpIDsInSet = Appc.AIScriptAssist_GetIncomingTorpIDsInSet

ObjectGroup_ForceToGroup = Appc.ObjectGroup_ForceToGroup

DisplayCollisionTests = Appc.DisplayCollisionTests

SubsystemList_Cast = Appc.SubsystemList_Cast

def TGModelUtils_CastNodeToAVObject(*args, **kwargs):
    val = apply(Appc.TGModelUtils_CastNodeToAVObject,args,kwargs)
    if val: val = NiAVObjectPtr(val)
    return val

def TGModelUtils_LocalToWorldPoint(*args, **kwargs):
    val = apply(Appc.TGModelUtils_LocalToWorldPoint,args,kwargs)
    if val: val = NiPoint3Ptr(val); val.thisown = 1
    return val

def TGModelUtils_WorldToLocalPoint(*args, **kwargs):
    val = apply(Appc.TGModelUtils_WorldToLocalPoint,args,kwargs)
    if val: val = NiPoint3Ptr(val); val.thisown = 1
    return val

def TGModelUtils_LocalToLocalPoint(*args, **kwargs):
    val = apply(Appc.TGModelUtils_LocalToLocalPoint,args,kwargs)
    if val: val = NiPoint3Ptr(val); val.thisown = 1
    return val

def TGModelUtils_LocalToWorldVector(*args, **kwargs):
    val = apply(Appc.TGModelUtils_LocalToWorldVector,args,kwargs)
    if val: val = NiPoint3Ptr(val); val.thisown = 1
    return val

def TGModelUtils_WorldToLocalVector(*args, **kwargs):
    val = apply(Appc.TGModelUtils_WorldToLocalVector,args,kwargs)
    if val: val = NiPoint3Ptr(val); val.thisown = 1
    return val

def TGModelUtils_LocalToLocalVector(*args, **kwargs):
    val = apply(Appc.TGModelUtils_LocalToLocalVector,args,kwargs)
    if val: val = NiPoint3Ptr(val); val.thisown = 1
    return val

def TGModelUtils_LocalToWorldUnitVector(*args, **kwargs):
    val = apply(Appc.TGModelUtils_LocalToWorldUnitVector,args,kwargs)
    if val: val = NiPoint3Ptr(val); val.thisown = 1
    return val

def TGModelUtils_WorldToLocalUnitVector(*args, **kwargs):
    val = apply(Appc.TGModelUtils_WorldToLocalUnitVector,args,kwargs)
    if val: val = NiPoint3Ptr(val); val.thisown = 1
    return val

def TGModelUtils_LocalToLocalUnitVector(*args, **kwargs):
    val = apply(Appc.TGModelUtils_LocalToLocalUnitVector,args,kwargs)
    if val: val = NiPoint3Ptr(val); val.thisown = 1
    return val

TGProfilingInfo_EnableProfiling = Appc.TGProfilingInfo_EnableProfiling

TGProfilingInfo_DisableProfiling = Appc.TGProfilingInfo_DisableProfiling

TGProfilingInfo_StartTiming = Appc.TGProfilingInfo_StartTiming

TGProfilingInfo_StopTiming = Appc.TGProfilingInfo_StopTiming

TGProfilingInfo_SetTimingData = Appc.TGProfilingInfo_SetTimingData

TGProfilingInfo_SaveRawData = Appc.TGProfilingInfo_SaveRawData

TGProfilingInfo_Terminate = Appc.TGProfilingInfo_Terminate

TGObject_GetIndentString = Appc.TGObject_GetIndentString

TGObject_SetIncrementID = Appc.TGObject_SetIncrementID

TGObject_IsIncrementID = Appc.TGObject_IsIncrementID

def TGObject_GetTGObjectPtr(*args, **kwargs):
    val = apply(Appc.TGObject_GetTGObjectPtr,args,kwargs)
    if val: val = TGObjectPtr(val)
    return val

def TGLocalizationDatabase_Create(*args, **kwargs):
    val = apply(Appc.TGLocalizationDatabase_Create,args,kwargs)
    if val: val = TGLocalizationDatabasePtr(val)
    return val

TGLocalizationDatabase_WriteSample = Appc.TGLocalizationDatabase_WriteSample

def TGEvent_Cast(*args, **kwargs):
    val = apply(Appc.TGEvent_Cast,args,kwargs)
    if val: val = TGEventPtr(val)
    return val

def TGEvent_Create(*args, **kwargs):
    val = apply(Appc.TGEvent_Create,args,kwargs)
    if val: val = TGEventPtr(val)
    return val

def TGBoolEvent_Cast(*args, **kwargs):
    val = apply(Appc.TGBoolEvent_Cast,args,kwargs)
    if val: val = TGBoolEventPtr(val)
    return val

def TGBoolEvent_Create(*args, **kwargs):
    val = apply(Appc.TGBoolEvent_Create,args,kwargs)
    if val: val = TGBoolEventPtr(val)
    return val

def TGCharEvent_Cast(*args, **kwargs):
    val = apply(Appc.TGCharEvent_Cast,args,kwargs)
    if val: val = TGCharEventPtr(val)
    return val

def TGCharEvent_Create(*args, **kwargs):
    val = apply(Appc.TGCharEvent_Create,args,kwargs)
    if val: val = TGCharEventPtr(val)
    return val

def TGShortEvent_Cast(*args, **kwargs):
    val = apply(Appc.TGShortEvent_Cast,args,kwargs)
    if val: val = TGShortEventPtr(val)
    return val

def TGShortEvent_Create(*args, **kwargs):
    val = apply(Appc.TGShortEvent_Create,args,kwargs)
    if val: val = TGShortEventPtr(val)
    return val

def TGIntEvent_Cast(*args, **kwargs):
    val = apply(Appc.TGIntEvent_Cast,args,kwargs)
    if val: val = TGIntEventPtr(val)
    return val

def TGIntEvent_Create(*args, **kwargs):
    val = apply(Appc.TGIntEvent_Create,args,kwargs)
    if val: val = TGIntEventPtr(val)
    return val

def TGFloatEvent_Cast(*args, **kwargs):
    val = apply(Appc.TGFloatEvent_Cast,args,kwargs)
    if val: val = TGFloatEventPtr(val)
    return val

def TGFloatEvent_Create(*args, **kwargs):
    val = apply(Appc.TGFloatEvent_Create,args,kwargs)
    if val: val = TGFloatEventPtr(val)
    return val

def TGStringEvent_Cast(*args, **kwargs):
    val = apply(Appc.TGStringEvent_Cast,args,kwargs)
    if val: val = TGStringEventPtr(val)
    return val

def TGStringEvent_Create(*args, **kwargs):
    val = apply(Appc.TGStringEvent_Create,args,kwargs)
    if val: val = TGStringEventPtr(val)
    return val

def TGVoidPtrEvent_Create(*args, **kwargs):
    val = apply(Appc.TGVoidPtrEvent_Create,args,kwargs)
    if val: val = TGVoidPtrEventPtr(val)
    return val

def TGObjPtrEvent_Cast(*args, **kwargs):
    val = apply(Appc.TGObjPtrEvent_Cast,args,kwargs)
    if val: val = TGObjPtrEventPtr(val)
    return val

def TGObjPtrEvent_Create(*args, **kwargs):
    val = apply(Appc.TGObjPtrEvent_Create,args,kwargs)
    if val: val = TGObjPtrEventPtr(val)
    return val

def TGEventHandlerObject_Cast(*args, **kwargs):
    val = apply(Appc.TGEventHandlerObject_Cast,args,kwargs)
    if val: val = TGEventHandlerObjectPtr(val)
    return val

def TGTimer_Create(*args, **kwargs):
    val = apply(Appc.TGTimer_Create,args,kwargs)
    if val: val = TGTimerPtr(val)
    return val

def TGTimer_GetTGTimerPtr(*args, **kwargs):
    val = apply(Appc.TGTimer_GetTGTimerPtr,args,kwargs)
    if val: val = TGTimerPtr(val)
    return val

def TGPythonInstanceWrapper_Create(*args, **kwargs):
    val = apply(Appc.TGPythonInstanceWrapper_Create,args,kwargs)
    if val: val = TGPythonInstanceWrapperPtr(val)
    return val

def TGMouseEvent_Create(*args, **kwargs):
    val = apply(Appc.TGMouseEvent_Create,args,kwargs)
    if val: val = TGMouseEventPtr(val)
    return val

def TGKeyboardEvent_Create(*args, **kwargs):
    val = apply(Appc.TGKeyboardEvent_Create,args,kwargs)
    if val: val = TGKeyboardEventPtr(val)
    return val

def TGUIModule_PixelAlignRect(*args, **kwargs):
    val = apply(Appc.TGUIModule_PixelAlignRect,args,kwargs)
    if val: val = TGRectPtr(val); val.thisown = 1
    return val

def TGUIModule_PixelAlignPoint(*args, **kwargs):
    val = apply(Appc.TGUIModule_PixelAlignPoint,args,kwargs)
    if val: val = NiPoint2Ptr(val); val.thisown = 1
    return val

TGUIModule_PixelAlignValue = Appc.TGUIModule_PixelAlignValue

def TGPane_Create(*args, **kwargs):
    val = apply(Appc.TGPane_Create,args,kwargs)
    if val: val = TGPanePtr(val)
    return val

def TGPane_Cast(*args, **kwargs):
    val = apply(Appc.TGPane_Cast,args,kwargs)
    if val: val = TGPanePtr(val)
    return val

def TGIcon_Create(*args, **kwargs):
    val = apply(Appc.TGIcon_Create,args,kwargs)
    if val: val = TGIconPtr(val)
    return val

def TGIcon_Cast(*args, **kwargs):
    val = apply(Appc.TGIcon_Cast,args,kwargs)
    if val: val = TGIconPtr(val)
    return val

def TGFrame_Cast(*args, **kwargs):
    val = apply(Appc.TGFrame_Cast,args,kwargs)
    if val: val = TGFramePtr(val)
    return val

def TGFrame_Create(*args, **kwargs):
    val = apply(Appc.TGFrame_Create,args,kwargs)
    if val: val = TGFramePtr(val)
    return val

def TGButtonBase_Create(*args, **kwargs):
    val = apply(Appc.TGButtonBase_Create,args,kwargs)
    if val: val = TGButtonBasePtr(val)
    return val

def TGButtonBase_Cast(*args, **kwargs):
    val = apply(Appc.TGButtonBase_Cast,args,kwargs)
    if val: val = TGButtonBasePtr(val)
    return val

def TGButton_Create(*args, **kwargs):
    val = apply(Appc.TGButton_Create,args,kwargs)
    if val: val = TGButtonPtr(val)
    return val

def TGButton_Cast(*args, **kwargs):
    val = apply(Appc.TGButton_Cast,args,kwargs)
    if val: val = TGButtonPtr(val)
    return val

def TGTextButton_Create(*args, **kwargs):
    val = apply(Appc.TGTextButton_Create,args,kwargs)
    if val: val = TGTextButtonPtr(val)
    return val

def TGTextButton_CreateW(*args, **kwargs):
    val = apply(Appc.TGTextButton_CreateW,args,kwargs)
    if val: val = TGTextButtonPtr(val)
    return val

def TGTextButton_Cast(*args, **kwargs):
    val = apply(Appc.TGTextButton_Cast,args,kwargs)
    if val: val = TGTextButtonPtr(val)
    return val

def TGParagraph_Create(*args, **kwargs):
    val = apply(Appc.TGParagraph_Create,args,kwargs)
    if val: val = TGParagraphPtr(val)
    return val

def TGParagraph_CreateW(*args, **kwargs):
    val = apply(Appc.TGParagraph_CreateW,args,kwargs)
    if val: val = TGParagraphPtr(val)
    return val

def TGParagraph_Cast(*args, **kwargs):
    val = apply(Appc.TGParagraph_Cast,args,kwargs)
    if val: val = TGParagraphPtr(val)
    return val

TGParagraph_SetCursorBlinkInterval = Appc.TGParagraph_SetCursorBlinkInterval

def TGWindow_Create(*args, **kwargs):
    val = apply(Appc.TGWindow_Create,args,kwargs)
    if val: val = TGWindowPtr(val)
    return val

def TGWindow_Cast(*args, **kwargs):
    val = apply(Appc.TGWindow_Cast,args,kwargs)
    if val: val = TGWindowPtr(val)
    return val

def TGFrameWindow_CreateFromTheme(*args, **kwargs):
    val = apply(Appc.TGFrameWindow_CreateFromTheme,args,kwargs)
    if val: val = TGFrameWindowPtr(val)
    return val

def TGFrameWindow_Create(*args, **kwargs):
    val = apply(Appc.TGFrameWindow_Create,args,kwargs)
    if val: val = TGFrameWindowPtr(val)
    return val

def TGFrameWindow_Cast(*args, **kwargs):
    val = apply(Appc.TGFrameWindow_Cast,args,kwargs)
    if val: val = TGFrameWindowPtr(val)
    return val

def TGDialogWindow_CreateFromTheme(*args, **kwargs):
    val = apply(Appc.TGDialogWindow_CreateFromTheme,args,kwargs)
    if val: val = TGDialogWindowPtr(val)
    return val

def TGDialogWindow_Create(*args, **kwargs):
    val = apply(Appc.TGDialogWindow_Create,args,kwargs)
    if val: val = TGDialogWindowPtr(val)
    return val

def TGDialogWindow_Cast(*args, **kwargs):
    val = apply(Appc.TGDialogWindow_Cast,args,kwargs)
    if val: val = TGDialogWindowPtr(val)
    return val

def TGUITheme_Create(*args, **kwargs):
    val = apply(Appc.TGUITheme_Create,args,kwargs)
    if val: val = TGUIThemePtr(val)
    return val

TGConsole_GetPyString = Appc.TGConsole_GetPyString

def TGConsole_Cast(*args, **kwargs):
    val = apply(Appc.TGConsole_Cast,args,kwargs)
    if val: val = TGConsolePtr(val)
    return val

TGConsole_SetTextIndent = Appc.TGConsole_SetTextIndent

TGConsole_GetTextIndent = Appc.TGConsole_GetTextIndent

def TGSound_Create(*args, **kwargs):
    val = apply(Appc.TGSound_Create,args,kwargs)
    if val: val = TGSoundPtr(val)
    return val

def TGSoundRegion_Create(*args, **kwargs):
    val = apply(Appc.TGSoundRegion_Create,args,kwargs)
    if val: val = TGSoundRegionPtr(val)
    return val

def TGSoundRegion_GetRegion(*args, **kwargs):
    val = apply(Appc.TGSoundRegion_GetRegion,args,kwargs)
    if val: val = TGSoundRegionPtr(val)
    return val

PyEmbed_SerializeModule = Appc.PyEmbed_SerializeModule

PyEmbed_UnserializeModule = Appc.PyEmbed_UnserializeModule

PyEmbed_StartSave = Appc.PyEmbed_StartSave

PyEmbed_FinishSave = Appc.PyEmbed_FinishSave

PyEmbed_StartLoad = Appc.PyEmbed_StartLoad

PyEmbed_FinishLoad = Appc.PyEmbed_FinishLoad

def TGModelProperty_Cast(*args, **kwargs):
    val = apply(Appc.TGModelProperty_Cast,args,kwargs)
    if val: val = TGModelPropertyPtr(val)
    return val

def TGModelProperty_Create(*args, **kwargs):
    val = apply(Appc.TGModelProperty_Create,args,kwargs)
    if val: val = TGModelPropertyPtr(val)
    return val

def TGModelPropertySet_Create(*args, **kwargs):
    val = apply(Appc.TGModelPropertySet_Create,args,kwargs)
    if val: val = TGModelPropertySetPtr(val)
    return val

def TGAction_CreateNull(*args, **kwargs):
    val = apply(Appc.TGAction_CreateNull,args,kwargs)
    if val: val = TGActionPtr(val)
    return val

def TGAction_Cast(*args, **kwargs):
    val = apply(Appc.TGAction_Cast,args,kwargs)
    if val: val = TGActionPtr(val)
    return val

def TGSequence_Create(*args, **kwargs):
    val = apply(Appc.TGSequence_Create,args,kwargs)
    if val: val = TGSequencePtr(val)
    return val

def TGSequence_Cast(*args, **kwargs):
    val = apply(Appc.TGSequence_Cast,args,kwargs)
    if val: val = TGSequencePtr(val)
    return val

def TGSoundAction_Create(*args, **kwargs):
    val = apply(Appc.TGSoundAction_Create,args,kwargs)
    if val: val = TGSoundActionPtr(val)
    return val

def TGAnimAction_Create(*args, **kwargs):
    val = apply(Appc.TGAnimAction_Create,args,kwargs)
    if val: val = TGAnimActionPtr(val)
    return val

def TGAnimPosition_Create(*args, **kwargs):
    val = apply(Appc.TGAnimPosition_Create,args,kwargs)
    if val: val = TGAnimPositionPtr(val)
    return val

def TGCondition_Cast(*args, **kwargs):
    val = apply(Appc.TGCondition_Cast,args,kwargs)
    if val: val = TGConditionPtr(val)
    return val

def TGConditionAction_Create(*args, **kwargs):
    val = apply(Appc.TGConditionAction_Create,args,kwargs)
    if val: val = TGConditionActionPtr(val)
    return val

def TGMessage_Create(*args, **kwargs):
    val = apply(Appc.TGMessage_Create,args,kwargs)
    if val: val = TGMessagePtr(val)
    return val

def TGMessage_UnSerialize(*args, **kwargs):
    val = apply(Appc.TGMessage_UnSerialize,args,kwargs)
    if val: val = TGMessagePtr(val)
    return val

TGNetwork_RegisterMessageType = Appc.TGNetwork_RegisterMessageType

TGNetwork_GetTGNetworkList = Appc.TGNetwork_GetTGNetworkList

TGNetwork_RegisterHandlers = Appc.TGNetwork_RegisterHandlers

TGNetwork_AddClassHandlers = Appc.TGNetwork_AddClassHandlers

TGWinsockNetwork_BanPlayerByIP = Appc.TGWinsockNetwork_BanPlayerByIP

TGWinsockNetwork_BanPlayerByName = Appc.TGWinsockNetwork_BanPlayerByName

def TGNameChangeMessage_UnSerialize(*args, **kwargs):
    val = apply(Appc.TGNameChangeMessage_UnSerialize,args,kwargs)
    if val: val = TGMessagePtr(val)
    return val

def TGAckMessage_UnSerialize(*args, **kwargs):
    val = apply(Appc.TGAckMessage_UnSerialize,args,kwargs)
    if val: val = TGMessagePtr(val)
    return val

def TGDoNothingMessage_UnSerialize(*args, **kwargs):
    val = apply(Appc.TGDoNothingMessage_UnSerialize,args,kwargs)
    if val: val = TGMessagePtr(val)
    return val

def TGBootPlayerMessage_UnSerialize(*args, **kwargs):
    val = apply(Appc.TGBootPlayerMessage_UnSerialize,args,kwargs)
    if val: val = TGMessagePtr(val)
    return val

def TGConnectMessage_UnSerialize(*args, **kwargs):
    val = apply(Appc.TGConnectMessage_UnSerialize,args,kwargs)
    if val: val = TGMessagePtr(val)
    return val

def TGDisconnectMessage_UnSerialize(*args, **kwargs):
    val = apply(Appc.TGDisconnectMessage_UnSerialize,args,kwargs)
    if val: val = TGMessagePtr(val)
    return val

def TGMessageEvent_Create(*args, **kwargs):
    val = apply(Appc.TGMessageEvent_Create,args,kwargs)
    if val: val = TGMessageEventPtr(val)
    return val

def TGPlayerEvent_Create(*args, **kwargs):
    val = apply(Appc.TGPlayerEvent_Create,args,kwargs)
    if val: val = TGPlayerEventPtr(val)
    return val

def TGMovieAction_Create(*args, **kwargs):
    val = apply(Appc.TGMovieAction_Create,args,kwargs)
    if val: val = TGMovieActionPtr(val)
    return val

def TGCreditAction_Create(*args, **kwargs):
    val = apply(Appc.TGCreditAction_Create,args,kwargs)
    if val: val = TGCreditActionPtr(val)
    return val

def TGCreditAction_CreateSTR(*args, **kwargs):
    val = apply(Appc.TGCreditAction_CreateSTR,args,kwargs)
    if val: val = TGCreditActionPtr(val)
    return val

TGCreditAction_SetDefaultColor = Appc.TGCreditAction_SetDefaultColor

TGGeomUtils_LineSphereIntersection = Appc.TGGeomUtils_LineSphereIntersection

TGGeomUtils_CalcAngularDifferenceSingle = Appc.TGGeomUtils_CalcAngularDifferenceSingle

UtopiaModule_GetNextEventType = Appc.UtopiaModule_GetNextEventType

UtopiaModule_GetGameVersion = Appc.UtopiaModule_GetGameVersion

UtopiaModule_ConvertGameUnitsToKilometers = Appc.UtopiaModule_ConvertGameUnitsToKilometers

UtopiaModule_ConvertKilometersToGameUnits = Appc.UtopiaModule_ConvertKilometersToGameUnits

UtopiaModule_SetGameUnitConversionFactor = Appc.UtopiaModule_SetGameUnitConversionFactor

def UtopiaApp_GetApp(*args, **kwargs):
    val = apply(Appc.UtopiaApp_GetApp,args,kwargs)
    if val: val = UtopiaAppPtr(val)
    return val

TGMatrix3_TransformVertices = Appc.TGMatrix3_TransformVertices

TGMatrix3_TransformNormals = Appc.TGMatrix3_TransformNormals

TGMatrix3_TransformVerticesAndNormals = Appc.TGMatrix3_TransformVerticesAndNormals

def TGPoint3_GetRandomUnitVector(*args, **kwargs):
    val = apply(Appc.TGPoint3_GetRandomUnitVector,args,kwargs)
    if val: val = TGPoint3Ptr(val); val.thisown = 1
    return val

def TGPoint3_GetModelForward(*args, **kwargs):
    val = apply(Appc.TGPoint3_GetModelForward,args,kwargs)
    if val: val = TGPoint3Ptr(val); val.thisown = 1
    return val

def TGPoint3_GetModelBackward(*args, **kwargs):
    val = apply(Appc.TGPoint3_GetModelBackward,args,kwargs)
    if val: val = TGPoint3Ptr(val); val.thisown = 1
    return val

def TGPoint3_GetModelUp(*args, **kwargs):
    val = apply(Appc.TGPoint3_GetModelUp,args,kwargs)
    if val: val = TGPoint3Ptr(val); val.thisown = 1
    return val

def TGPoint3_GetModelDown(*args, **kwargs):
    val = apply(Appc.TGPoint3_GetModelDown,args,kwargs)
    if val: val = TGPoint3Ptr(val); val.thisown = 1
    return val

def TGPoint3_GetModelRight(*args, **kwargs):
    val = apply(Appc.TGPoint3_GetModelRight,args,kwargs)
    if val: val = TGPoint3Ptr(val); val.thisown = 1
    return val

def TGPoint3_GetModelLeft(*args, **kwargs):
    val = apply(Appc.TGPoint3_GetModelLeft,args,kwargs)
    if val: val = TGPoint3Ptr(val); val.thisown = 1
    return val

TGPoint3_UnitizeVectors = Appc.TGPoint3_UnitizeVectors

TGPoint3_UnitizeVector = Appc.TGPoint3_UnitizeVector

TGPoint3_VectorLength = Appc.TGPoint3_VectorLength

def SetClass_Create(*args, **kwargs):
    val = apply(Appc.SetClass_Create,args,kwargs)
    if val: val = SetClassPtr(val)
    return val

def SetClass_GetNull(*args, **kwargs):
    val = apply(Appc.SetClass_GetNull,args,kwargs)
    if val: val = SetClassPtr(val)
    return val

def SetClass_Cast(*args, **kwargs):
    val = apply(Appc.SetClass_Cast,args,kwargs)
    if val: val = SetClassPtr(val)
    return val

SetClass_SetGlowEnabled = Appc.SetClass_SetGlowEnabled

SetClass_IsGlowEnabled = Appc.SetClass_IsGlowEnabled

SetClass_CanGlowBeEnabled = Appc.SetClass_CanGlowBeEnabled

def SetClass_MakeDisplayName(*args, **kwargs):
    val = apply(Appc.SetClass_MakeDisplayName,args,kwargs)
    if val: val = TGStringPtr(val); val.thisown = 1
    return val

SetClass_SetSplitLargeZRenders = Appc.SetClass_SetSplitLargeZRenders

SetClass_GetSplitLargeZRenders = Appc.SetClass_GetSplitLargeZRenders

def Game_Create(*args, **kwargs):
    val = apply(Appc.Game_Create,args,kwargs)
    if val: val = GamePtr(val)
    return val

Game_GetNextEventType = Appc.Game_GetNextEventType

def Game_GetCurrentGame(*args, **kwargs):
    val = apply(Appc.Game_GetCurrentGame,args,kwargs)
    if val: val = GamePtr(val)
    return val

def Game_GetCurrentPlayer(*args, **kwargs):
    val = apply(Appc.Game_GetCurrentPlayer,args,kwargs)
    if val: val = ShipClassPtr(val)
    return val

Game_GetDifficulty = Appc.Game_GetDifficulty

Game_SetDifficulty = Appc.Game_SetDifficulty

Game_SetDifficultyReallyIMeanIt = Appc.Game_SetDifficultyReallyIMeanIt

Game_SetDifficultyMultipliers = Appc.Game_SetDifficultyMultipliers

Game_SetDefaultDifficultyMultipliers = Appc.Game_SetDefaultDifficultyMultipliers

Game_GetOffensiveDifficultyMultiplier = Appc.Game_GetOffensiveDifficultyMultiplier

Game_GetDefensiveDifficultyMultiplier = Appc.Game_GetDefensiveDifficultyMultiplier

Game_SetPlayerHardpointFileName = Appc.Game_SetPlayerHardpointFileName

Game_GetPlayerHardpointFileName = Appc.Game_GetPlayerHardpointFileName

Episode_GetNextEventType = Appc.Episode_GetNextEventType

Mission_GetNextEventType = Appc.Mission_GetNextEventType

def BaseObjectClass_Create(*args, **kwargs):
    val = apply(Appc.BaseObjectClass_Create,args,kwargs)
    if val: val = BaseObjectClassPtr(val)
    return val

def BaseObjectClass_Cast(*args, **kwargs):
    val = apply(Appc.BaseObjectClass_Cast,args,kwargs)
    if val: val = BaseObjectClassPtr(val)
    return val

def BaseObjectClass_GetObject(*args, **kwargs):
    val = apply(Appc.BaseObjectClass_GetObject,args,kwargs)
    if val: val = BaseObjectClassPtr(val)
    return val

BaseObjectClass_GetNumClassObjects = Appc.BaseObjectClass_GetNumClassObjects

def ObjectClass_Cast(*args, **kwargs):
    val = apply(Appc.ObjectClass_Cast,args,kwargs)
    if val: val = ObjectClassPtr(val)
    return val

def ObjectClass_Create(*args, **kwargs):
    val = apply(Appc.ObjectClass_Create,args,kwargs)
    if val: val = ObjectClassPtr(val)
    return val

ObjectClass_SetMaximumNumberOfLights = Appc.ObjectClass_SetMaximumNumberOfLights

ObjectClass_GetMaximumNumberOfLights = Appc.ObjectClass_GetMaximumNumberOfLights

def ObjectClass_GetObject(*args, **kwargs):
    val = apply(Appc.ObjectClass_GetObject,args,kwargs)
    if val: val = ObjectClassPtr(val)
    return val

def ObjectClass_GetObjectByID(*args, **kwargs):
    val = apply(Appc.ObjectClass_GetObjectByID,args,kwargs)
    if val: val = ObjectClassPtr(val)
    return val

ObjectClass_GetNumClassObjects = Appc.ObjectClass_GetNumClassObjects

def CameraObjectClass_Create(*args, **kwargs):
    val = apply(Appc.CameraObjectClass_Create,args,kwargs)
    if val: val = CameraObjectClassPtr(val)
    return val

def CameraObjectClass_CreateFromNiCamera(*args, **kwargs):
    val = apply(Appc.CameraObjectClass_CreateFromNiCamera,args,kwargs)
    if val: val = CameraObjectClassPtr(val)
    return val

def CameraObjectClass_Cast(*args, **kwargs):
    val = apply(Appc.CameraObjectClass_Cast,args,kwargs)
    if val: val = CameraObjectClassPtr(val)
    return val

def CameraObjectClass_GetObject(*args, **kwargs):
    val = apply(Appc.CameraObjectClass_GetObject,args,kwargs)
    if val: val = CameraObjectClassPtr(val)
    return val

CameraObjectClass_GetNumClassObjects = Appc.CameraObjectClass_GetNumClassObjects

def SpaceCamera_Create(*args, **kwargs):
    val = apply(Appc.SpaceCamera_Create,args,kwargs)
    if val: val = SpaceCameraPtr(val)
    return val

SpaceCamera_IsSpaceDustEnabledInGame = Appc.SpaceCamera_IsSpaceDustEnabledInGame

SpaceCamera_SetSpaceDustInGame = Appc.SpaceCamera_SetSpaceDustInGame

def SpaceCamera_GetObject(*args, **kwargs):
    val = apply(Appc.SpaceCamera_GetObject,args,kwargs)
    if val: val = SpaceCameraPtr(val)
    return val

SpaceCamera_GetNumClassObjects = Appc.SpaceCamera_GetNumClassObjects

def LightObjectClass_Cast(*args, **kwargs):
    val = apply(Appc.LightObjectClass_Cast,args,kwargs)
    if val: val = LightObjectClassPtr(val)
    return val

def LightObjectClass_GetObject(*args, **kwargs):
    val = apply(Appc.LightObjectClass_GetObject,args,kwargs)
    if val: val = LightObjectClassPtr(val)
    return val

LightObjectClass_GetNumClassObjects = Appc.LightObjectClass_GetNumClassObjects

def CameraMode_Create(*args, **kwargs):
    val = apply(Appc.CameraMode_Create,args,kwargs)
    if val: val = CameraModePtr(val)
    return val

def Backdrop_Create(*args, **kwargs):
    val = apply(Appc.Backdrop_Create,args,kwargs)
    if val: val = BackdropPtr(val)
    return val

def Backdrop_Cast(*args, **kwargs):
    val = apply(Appc.Backdrop_Cast,args,kwargs)
    if val: val = BackdropPtr(val)
    return val

def Backdrop_GetObject(*args, **kwargs):
    val = apply(Appc.Backdrop_GetObject,args,kwargs)
    if val: val = BackdropPtr(val)
    return val

Backdrop_GetNumClassObjects = Appc.Backdrop_GetNumClassObjects

def BackdropSphere_Create(*args, **kwargs):
    val = apply(Appc.BackdropSphere_Create,args,kwargs)
    if val: val = BackdropSpherePtr(val)
    return val

def BackdropSphere_Cast(*args, **kwargs):
    val = apply(Appc.BackdropSphere_Cast,args,kwargs)
    if val: val = BackdropSpherePtr(val)
    return val

def BackdropSphere_GetObject(*args, **kwargs):
    val = apply(Appc.BackdropSphere_GetObject,args,kwargs)
    if val: val = BackdropSpherePtr(val)
    return val

BackdropSphere_GetNumClassObjects = Appc.BackdropSphere_GetNumClassObjects

def StarSphere_Create(*args, **kwargs):
    val = apply(Appc.StarSphere_Create,args,kwargs)
    if val: val = StarSpherePtr(val)
    return val

def StarSphere_Cast(*args, **kwargs):
    val = apply(Appc.StarSphere_Cast,args,kwargs)
    if val: val = StarSpherePtr(val)
    return val

def AsteroidField_Cast(*args, **kwargs):
    val = apply(Appc.AsteroidField_Cast,args,kwargs)
    if val: val = AsteroidFieldPtr(val)
    return val

def AsteroidField_Create(*args, **kwargs):
    val = apply(Appc.AsteroidField_Create,args,kwargs)
    if val: val = AsteroidFieldPtr(val)
    return val

def AsteroidField_GetObject(*args, **kwargs):
    val = apply(Appc.AsteroidField_GetObject,args,kwargs)
    if val: val = AsteroidFieldPtr(val)
    return val

AsteroidField_GetNumClassObjects = Appc.AsteroidField_GetNumClassObjects

def SetFloatVarEvent_Create(*args, **kwargs):
    val = apply(Appc.SetFloatVarEvent_Create,args,kwargs)
    if val: val = SetFloatVarEventPtr(val)
    return val

def LoadMissionAction_Create(*args, **kwargs):
    val = apply(Appc.LoadMissionAction_Create,args,kwargs)
    if val: val = LoadMissionActionPtr(val)
    return val

def LoadEpisodeAction_Create(*args, **kwargs):
    val = apply(Appc.LoadEpisodeAction_Create,args,kwargs)
    if val: val = LoadEpisodeActionPtr(val)
    return val

def ChatObjectClass_Create(*args, **kwargs):
    val = apply(Appc.ChatObjectClass_Create,args,kwargs)
    if val: val = ChatObjectClassPtr(val)
    return val

def GraphicsModeInfo_GetCurrentMode(*args, **kwargs):
    val = apply(Appc.GraphicsModeInfo_GetCurrentMode,args,kwargs)
    if val: val = GraphicsModeInfoPtr(val)
    return val

def ChangeRenderedSetAction_Create(*args, **kwargs):
    val = apply(Appc.ChangeRenderedSetAction_Create,args,kwargs)
    if val: val = ChangeRenderedSetActionPtr(val)
    return val

def ChangeRenderedSetAction_CreateFromSet(*args, **kwargs):
    val = apply(Appc.ChangeRenderedSetAction_CreateFromSet,args,kwargs)
    if val: val = ChangeRenderedSetActionPtr(val)
    return val

def ZoomCameraObjectClass_Create(*args, **kwargs):
    val = apply(Appc.ZoomCameraObjectClass_Create,args,kwargs)
    if val: val = ZoomCameraObjectClassPtr(val)
    return val

def ZoomCameraObjectClass_Cast(*args, **kwargs):
    val = apply(Appc.ZoomCameraObjectClass_Cast,args,kwargs)
    if val: val = ZoomCameraObjectClassPtr(val)
    return val

def ZoomCameraObjectClass_GetObject(*args, **kwargs):
    val = apply(Appc.ZoomCameraObjectClass_GetObject,args,kwargs)
    if val: val = ZoomCameraObjectClassPtr(val)
    return val

ZoomCameraObjectClass_GetNumClassObjects = Appc.ZoomCameraObjectClass_GetNumClassObjects

def CharacterAction_Create(*args, **kwargs):
    val = apply(Appc.CharacterAction_Create,args,kwargs)
    if val: val = CharacterActionPtr(val)
    return val

def CharacterAction_CreateByName(*args, **kwargs):
    val = apply(Appc.CharacterAction_CreateByName,args,kwargs)
    if val: val = CharacterActionPtr(val)
    return val

def CharacterAction_Cast(*args, **kwargs):
    val = apply(Appc.CharacterAction_Cast,args,kwargs)
    if val: val = CharacterActionPtr(val)
    return val

CharacterAction_ConvertFolderLWVs = Appc.CharacterAction_ConvertFolderLWVs

CharacterAction_SetSkipAllLines = Appc.CharacterAction_SetSkipAllLines

def CharacterClass_Create(*args, **kwargs):
    val = apply(Appc.CharacterClass_Create,args,kwargs)
    if val: val = CharacterClassPtr(val)
    return val

def CharacterClass_CreateNull(*args, **kwargs):
    val = apply(Appc.CharacterClass_CreateNull,args,kwargs)
    if val: val = CharacterClassPtr(val)
    return val

def CharacterClass_Cast(*args, **kwargs):
    val = apply(Appc.CharacterClass_Cast,args,kwargs)
    if val: val = CharacterClassPtr(val)
    return val

CharacterClass_SetAllowExtras = Appc.CharacterClass_SetAllowExtras

CharacterClass_SetWalkOnChance = Appc.CharacterClass_SetWalkOnChance

CharacterClass_GetWalkOnChance = Appc.CharacterClass_GetWalkOnChance

CharacterClass_IsSomeoneSpeaking = Appc.CharacterClass_IsSomeoneSpeaking

CharacterClass_SetToolTipsEnabled = Appc.CharacterClass_SetToolTipsEnabled

CharacterClass_AreToolTipsEnabled = Appc.CharacterClass_AreToolTipsEnabled

CharacterClass_SetCollisionAlertEnabled = Appc.CharacterClass_SetCollisionAlertEnabled

CharacterClass_IsCollisionAlertEnabled = Appc.CharacterClass_IsCollisionAlertEnabled

CharacterClass_SetVolumeForLineType = Appc.CharacterClass_SetVolumeForLineType

CharacterClass_GetVolumeForLineType = Appc.CharacterClass_GetVolumeForLineType

CharacterClass_SetCurrentToolTipOwner = Appc.CharacterClass_SetCurrentToolTipOwner

def CharacterClass_GetCurrentToolTipOwner(*args, **kwargs):
    val = apply(Appc.CharacterClass_GetCurrentToolTipOwner,args,kwargs)
    if val: val = CharacterClassPtr(val)
    return val

def CharacterClass_GetCharacterFromMenu(*args, **kwargs):
    val = apply(Appc.CharacterClass_GetCharacterFromMenu,args,kwargs)
    if val: val = CharacterClassPtr(val)
    return val

CharacterClass_ShowPhonemeDebugging = Appc.CharacterClass_ShowPhonemeDebugging

def CharacterClass_GetObject(*args, **kwargs):
    val = apply(Appc.CharacterClass_GetObject,args,kwargs)
    if val: val = CharacterClassPtr(val)
    return val

CharacterClass_GetNumClassObjects = Appc.CharacterClass_GetNumClassObjects

def ViewScreenObject_Cast(*args, **kwargs):
    val = apply(Appc.ViewScreenObject_Cast,args,kwargs)
    if val: val = ViewScreenObjectPtr(val)
    return val

def ViewScreenObject_Create(*args, **kwargs):
    val = apply(Appc.ViewScreenObject_Create,args,kwargs)
    if val: val = ViewScreenObjectPtr(val)
    return val

def ViewScreenObject_CreateNull(*args, **kwargs):
    val = apply(Appc.ViewScreenObject_CreateNull,args,kwargs)
    if val: val = ViewScreenObjectPtr(val)
    return val

def ViewScreenObject_GetObject(*args, **kwargs):
    val = apply(Appc.ViewScreenObject_GetObject,args,kwargs)
    if val: val = ViewScreenObjectPtr(val)
    return val

ViewScreenObject_GetNumClassObjects = Appc.ViewScreenObject_GetNumClassObjects

def BridgeSet_Create(*args, **kwargs):
    val = apply(Appc.BridgeSet_Create,args,kwargs)
    if val: val = BridgeSetPtr(val)
    return val

def BridgeSet_Cast(*args, **kwargs):
    val = apply(Appc.BridgeSet_Cast,args,kwargs)
    if val: val = BridgeSetPtr(val)
    return val

def BridgeObjectClass_Create(*args, **kwargs):
    val = apply(Appc.BridgeObjectClass_Create,args,kwargs)
    if val: val = BridgeObjectClassPtr(val)
    return val

def BridgeObjectClass_Cast(*args, **kwargs):
    val = apply(Appc.BridgeObjectClass_Cast,args,kwargs)
    if val: val = BridgeObjectClassPtr(val)
    return val

def BridgeObjectClass_GetObject(*args, **kwargs):
    val = apply(Appc.BridgeObjectClass_GetObject,args,kwargs)
    if val: val = BridgeObjectClassPtr(val)
    return val

BridgeObjectClass_GetNumClassObjects = Appc.BridgeObjectClass_GetNumClassObjects

ArtificialIntelligence_LogAITree = Appc.ArtificialIntelligence_LogAITree

def PlainAI_Create(*args, **kwargs):
    val = apply(Appc.PlainAI_Create,args,kwargs)
    if val: val = PlainAIPtr(val)
    return val

def PriorityListAI_Create(*args, **kwargs):
    val = apply(Appc.PriorityListAI_Create,args,kwargs)
    if val: val = PriorityListAIPtr(val)
    return val

def SequenceAI_Create(*args, **kwargs):
    val = apply(Appc.SequenceAI_Create,args,kwargs)
    if val: val = SequenceAIPtr(val)
    return val

def RandomAI_Create(*args, **kwargs):
    val = apply(Appc.RandomAI_Create,args,kwargs)
    if val: val = RandomAIPtr(val)
    return val

def PreprocessingAI_Create(*args, **kwargs):
    val = apply(Appc.PreprocessingAI_Create,args,kwargs)
    if val: val = PreprocessingAIPtr(val)
    return val

def PreprocessingAI_Cast(*args, **kwargs):
    val = apply(Appc.PreprocessingAI_Cast,args,kwargs)
    if val: val = PreprocessingAIPtr(val)
    return val

def ConditionalAI_Create(*args, **kwargs):
    val = apply(Appc.ConditionalAI_Create,args,kwargs)
    if val: val = ConditionalAIPtr(val)
    return val

def ConditionScript_Cast(*args, **kwargs):
    val = apply(Appc.ConditionScript_Cast,args,kwargs)
    if val: val = ConditionScriptPtr(val)
    return val

def WaypointEvent_Create(*args, **kwargs):
    val = apply(Appc.WaypointEvent_Create,args,kwargs)
    if val: val = WaypointEventPtr(val)
    return val

AIScriptAssist_TorpIsIncoming = Appc.AIScriptAssist_TorpIsIncoming

def BuilderAI_Create(*args, **kwargs):
    val = apply(Appc.BuilderAI_Create,args,kwargs)
    if val: val = BuilderAIPtr(val)
    return val

def PhysicsObjectClass_Cast(*args, **kwargs):
    val = apply(Appc.PhysicsObjectClass_Cast,args,kwargs)
    if val: val = PhysicsObjectClassPtr(val)
    return val

def PhysicsObjectClass_ConstCast(*args, **kwargs):
    val = apply(Appc.PhysicsObjectClass_ConstCast,args,kwargs)
    if val: val = PhysicsObjectClassPtr(val)
    return val

def PhysicsObjectClass_Create(*args, **kwargs):
    val = apply(Appc.PhysicsObjectClass_Create,args,kwargs)
    if val: val = PhysicsObjectClassPtr(val)
    return val

def PhysicsObjectClass_GetObject(*args, **kwargs):
    val = apply(Appc.PhysicsObjectClass_GetObject,args,kwargs)
    if val: val = PhysicsObjectClassPtr(val)
    return val

PhysicsObjectClass_GetNumClassObjects = Appc.PhysicsObjectClass_GetNumClassObjects

def DamageableObject_Cast(*args, **kwargs):
    val = apply(Appc.DamageableObject_Cast,args,kwargs)
    if val: val = DamageableObjectPtr(val)
    return val

def DamageableObject_Create(*args, **kwargs):
    val = apply(Appc.DamageableObject_Create,args,kwargs)
    if val: val = DamageableObjectPtr(val)
    return val

def DamageableObject_GetObjectByID(*args, **kwargs):
    val = apply(Appc.DamageableObject_GetObjectByID,args,kwargs)
    if val: val = DamageableObjectPtr(val)
    return val

def DamageableObject_GetObject(*args, **kwargs):
    val = apply(Appc.DamageableObject_GetObject,args,kwargs)
    if val: val = DamageableObjectPtr(val)
    return val

DamageableObject_GetNumClassObjects = Appc.DamageableObject_GetNumClassObjects

DamageableObject_SetDamageGeometryEnabled = Appc.DamageableObject_SetDamageGeometryEnabled

DamageableObject_IsDamageGeometryEnabled = Appc.DamageableObject_IsDamageGeometryEnabled

DamageableObject_SetVolumeDamageGeometryEnabled = Appc.DamageableObject_SetVolumeDamageGeometryEnabled

DamageableObject_IsVolumeDamageGeometryEnabled = Appc.DamageableObject_IsVolumeDamageGeometryEnabled

DamageableObject_SetBreakableComponentsEnabled = Appc.DamageableObject_SetBreakableComponentsEnabled

DamageableObject_IsBreakableComponentsEnabled = Appc.DamageableObject_IsBreakableComponentsEnabled

def ShipClass_Cast(*args, **kwargs):
    val = apply(Appc.ShipClass_Cast,args,kwargs)
    if val: val = ShipClassPtr(val)
    return val

def ShipClass_Create(*args, **kwargs):
    val = apply(Appc.ShipClass_Create,args,kwargs)
    if val: val = ShipClassPtr(val)
    return val

def ShipClass_GetObject(*args, **kwargs):
    val = apply(Appc.ShipClass_GetObject,args,kwargs)
    if val: val = ShipClassPtr(val)
    return val

ShipClass_GetNumClassObjects = Appc.ShipClass_GetNumClassObjects

def ShipClass_GetObjectByID(*args, **kwargs):
    val = apply(Appc.ShipClass_GetObjectByID,args,kwargs)
    if val: val = ShipClassPtr(val)
    return val

def ObjectGroup_FromModule(*args, **kwargs):
    val = apply(Appc.ObjectGroup_FromModule,args,kwargs)
    if val: val = ObjectGroupPtr(val)
    return val

def ObjectGroupWithInfo_Cast(*args, **kwargs):
    val = apply(Appc.ObjectGroupWithInfo_Cast,args,kwargs)
    if val: val = ObjectGroupWithInfoPtr(val)
    return val

def ShipSubsystem_Cast(*args, **kwargs):
    val = apply(Appc.ShipSubsystem_Cast,args,kwargs)
    if val: val = ShipSubsystemPtr(val)
    return val

def ShipSubsystem_Create(*args, **kwargs):
    val = apply(Appc.ShipSubsystem_Create,args,kwargs)
    if val: val = ShipSubsystemPtr(val)
    return val

def PoweredSubsystem_Cast(*args, **kwargs):
    val = apply(Appc.PoweredSubsystem_Cast,args,kwargs)
    if val: val = PoweredSubsystemPtr(val)
    return val

def PowerSubsystem_Cast(*args, **kwargs):
    val = apply(Appc.PowerSubsystem_Cast,args,kwargs)
    if val: val = PowerSubsystemPtr(val)
    return val

def PowerSubsystem_Create(*args, **kwargs):
    val = apply(Appc.PowerSubsystem_Create,args,kwargs)
    if val: val = PowerSubsystemPtr(val)
    return val

def Weapon_Cast(*args, **kwargs):
    val = apply(Appc.Weapon_Cast,args,kwargs)
    if val: val = WeaponPtr(val)
    return val

def WeaponSystem_Cast(*args, **kwargs):
    val = apply(Appc.WeaponSystem_Cast,args,kwargs)
    if val: val = WeaponSystemPtr(val)
    return val

def WeaponSystem_Create(*args, **kwargs):
    val = apply(Appc.WeaponSystem_Create,args,kwargs)
    if val: val = WeaponSystemPtr(val)
    return val

def Torpedo_Create(*args, **kwargs):
    val = apply(Appc.Torpedo_Create,args,kwargs)
    if val: val = TorpedoPtr(val)
    return val

def Torpedo_Cast(*args, **kwargs):
    val = apply(Appc.Torpedo_Cast,args,kwargs)
    if val: val = TorpedoPtr(val)
    return val

Torpedo_GetMaxLifetime = Appc.Torpedo_GetMaxLifetime

def Torpedo_GetObject(*args, **kwargs):
    val = apply(Appc.Torpedo_GetObject,args,kwargs)
    if val: val = TorpedoPtr(val)
    return val

def Torpedo_GetObjectByID(*args, **kwargs):
    val = apply(Appc.Torpedo_GetObjectByID,args,kwargs)
    if val: val = TorpedoPtr(val)
    return val

Torpedo_GetNumClassObjects = Appc.Torpedo_GetNumClassObjects

def TorpedoSystem_Cast(*args, **kwargs):
    val = apply(Appc.TorpedoSystem_Cast,args,kwargs)
    if val: val = TorpedoSystemPtr(val)
    return val

def TorpedoSystem_Create(*args, **kwargs):
    val = apply(Appc.TorpedoSystem_Create,args,kwargs)
    if val: val = TorpedoSystemPtr(val)
    return val

def TorpedoTube_Create(*args, **kwargs):
    val = apply(Appc.TorpedoTube_Create,args,kwargs)
    if val: val = TorpedoTubePtr(val)
    return val

def TorpedoTube_Cast(*args, **kwargs):
    val = apply(Appc.TorpedoTube_Cast,args,kwargs)
    if val: val = TorpedoTubePtr(val)
    return val

def Nebula_Cast(*args, **kwargs):
    val = apply(Appc.Nebula_Cast,args,kwargs)
    if val: val = NebulaPtr(val)
    return val

def Nebula_Create(*args, **kwargs):
    val = apply(Appc.Nebula_Create,args,kwargs)
    if val: val = NebulaPtr(val)
    return val

def Nebula_GetObject(*args, **kwargs):
    val = apply(Appc.Nebula_GetObject,args,kwargs)
    if val: val = NebulaPtr(val)
    return val

def Nebula_GetObjectByID(*args, **kwargs):
    val = apply(Appc.Nebula_GetObjectByID,args,kwargs)
    if val: val = NebulaPtr(val)
    return val

Nebula_GetNumClassObjects = Appc.Nebula_GetNumClassObjects

def MetaNebula_Cast(*args, **kwargs):
    val = apply(Appc.MetaNebula_Cast,args,kwargs)
    if val: val = MetaNebulaPtr(val)
    return val

def MetaNebula_Create(*args, **kwargs):
    val = apply(Appc.MetaNebula_Create,args,kwargs)
    if val: val = MetaNebulaPtr(val)
    return val

def Planet_Cast(*args, **kwargs):
    val = apply(Appc.Planet_Cast,args,kwargs)
    if val: val = PlanetPtr(val)
    return val

def Planet_Create(*args, **kwargs):
    val = apply(Appc.Planet_Create,args,kwargs)
    if val: val = PlanetPtr(val)
    return val

def Planet_GetObject(*args, **kwargs):
    val = apply(Appc.Planet_GetObject,args,kwargs)
    if val: val = PlanetPtr(val)
    return val

Planet_GetNumClassObjects = Appc.Planet_GetNumClassObjects

def Sun_Cast(*args, **kwargs):
    val = apply(Appc.Sun_Cast,args,kwargs)
    if val: val = SunPtr(val)
    return val

def Sun_Create(*args, **kwargs):
    val = apply(Appc.Sun_Create,args,kwargs)
    if val: val = SunPtr(val)
    return val

ProximityManager_SetPlayerCollisionsEnabled = Appc.ProximityManager_SetPlayerCollisionsEnabled

ProximityManager_GetPlayerCollisionsEnabled = Appc.ProximityManager_GetPlayerCollisionsEnabled

ProximityManager_SetMultiplayerPlayerCollisionsEnabled = Appc.ProximityManager_SetMultiplayerPlayerCollisionsEnabled

def ProximityCheck_Create(*args, **kwargs):
    val = apply(Appc.ProximityCheck_Create,args,kwargs)
    if val: val = ProximityCheckPtr(val)
    return val

def ProximityCheck_CreateWithEvent(*args, **kwargs):
    val = apply(Appc.ProximityCheck_CreateWithEvent,args,kwargs)
    if val: val = ProximityCheckPtr(val)
    return val

def ProximityCheck_Cast(*args, **kwargs):
    val = apply(Appc.ProximityCheck_Cast,args,kwargs)
    if val: val = ProximityCheckPtr(val)
    return val

def ProximityCheck_GetObject(*args, **kwargs):
    val = apply(Appc.ProximityCheck_GetObject,args,kwargs)
    if val: val = ProximityCheckPtr(val)
    return val

ProximityCheck_GetNumClassObjects = Appc.ProximityCheck_GetNumClassObjects

def ShieldClass_Create(*args, **kwargs):
    val = apply(Appc.ShieldClass_Create,args,kwargs)
    if val: val = ShieldClassPtr(val)
    return val

def ShieldClass_Cast(*args, **kwargs):
    val = apply(Appc.ShieldClass_Cast,args,kwargs)
    if val: val = ShieldClassPtr(val)
    return val

def HullClass_Create(*args, **kwargs):
    val = apply(Appc.HullClass_Create,args,kwargs)
    if val: val = HullClassPtr(val)
    return val

def HullClass_Cast(*args, **kwargs):
    val = apply(Appc.HullClass_Cast,args,kwargs)
    if val: val = HullClassPtr(val)
    return val

def EnergyWeapon_Cast(*args, **kwargs):
    val = apply(Appc.EnergyWeapon_Cast,args,kwargs)
    if val: val = EnergyWeaponPtr(val)
    return val

def PhaserSystem_Cast(*args, **kwargs):
    val = apply(Appc.PhaserSystem_Cast,args,kwargs)
    if val: val = PhaserSystemPtr(val)
    return val

def PhaserSystem_Create(*args, **kwargs):
    val = apply(Appc.PhaserSystem_Create,args,kwargs)
    if val: val = PhaserSystemPtr(val)
    return val

def PhaserBank_Cast(*args, **kwargs):
    val = apply(Appc.PhaserBank_Cast,args,kwargs)
    if val: val = PhaserBankPtr(val)
    return val

def PhaserBank_Create(*args, **kwargs):
    val = apply(Appc.PhaserBank_Create,args,kwargs)
    if val: val = PhaserBankPtr(val)
    return val

PhaserBank_GetMaxPhaserRange = Appc.PhaserBank_GetMaxPhaserRange

PhaserBank_SetMaxPhaserRange = Appc.PhaserBank_SetMaxPhaserRange

def PulseWeapon_Cast(*args, **kwargs):
    val = apply(Appc.PulseWeapon_Cast,args,kwargs)
    if val: val = PulseWeaponPtr(val)
    return val

def PulseWeapon_Create(*args, **kwargs):
    val = apply(Appc.PulseWeapon_Create,args,kwargs)
    if val: val = PulseWeaponPtr(val)
    return val

def PulseWeaponSystem_Cast(*args, **kwargs):
    val = apply(Appc.PulseWeaponSystem_Cast,args,kwargs)
    if val: val = PulseWeaponSystemPtr(val)
    return val

def PulseWeaponSystem_Create(*args, **kwargs):
    val = apply(Appc.PulseWeaponSystem_Create,args,kwargs)
    if val: val = PulseWeaponSystemPtr(val)
    return val

def SensorSubsystem_Cast(*args, **kwargs):
    val = apply(Appc.SensorSubsystem_Cast,args,kwargs)
    if val: val = SensorSubsystemPtr(val)
    return val

def SensorSubsystem_Create(*args, **kwargs):
    val = apply(Appc.SensorSubsystem_Create,args,kwargs)
    if val: val = SensorSubsystemPtr(val)
    return val

def CloakingSubsystem_Cast(*args, **kwargs):
    val = apply(Appc.CloakingSubsystem_Cast,args,kwargs)
    if val: val = CloakingSubsystemPtr(val)
    return val

def CloakingSubsystem_Create(*args, **kwargs):
    val = apply(Appc.CloakingSubsystem_Create,args,kwargs)
    if val: val = CloakingSubsystemPtr(val)
    return val

CloakingSubsystem_SetCloakTime = Appc.CloakingSubsystem_SetCloakTime

CloakingSubsystem_GetCloakTime = Appc.CloakingSubsystem_GetCloakTime

CloakingSubsystem_SetShieldDelay = Appc.CloakingSubsystem_SetShieldDelay

CloakingSubsystem_GetShieldDelay = Appc.CloakingSubsystem_GetShieldDelay

def RepairSubsystem_Cast(*args, **kwargs):
    val = apply(Appc.RepairSubsystem_Cast,args,kwargs)
    if val: val = RepairSubsystemPtr(val)
    return val

def RepairSubsystem_Create(*args, **kwargs):
    val = apply(Appc.RepairSubsystem_Create,args,kwargs)
    if val: val = RepairSubsystemPtr(val)
    return val

def ImpulseEngineSubsystem_Cast(*args, **kwargs):
    val = apply(Appc.ImpulseEngineSubsystem_Cast,args,kwargs)
    if val: val = ImpulseEngineSubsystemPtr(val)
    return val

def ImpulseEngineSubsystem_Create(*args, **kwargs):
    val = apply(Appc.ImpulseEngineSubsystem_Create,args,kwargs)
    if val: val = ImpulseEngineSubsystemPtr(val)
    return val

def WarpEngineSubsystem_Cast(*args, **kwargs):
    val = apply(Appc.WarpEngineSubsystem_Cast,args,kwargs)
    if val: val = WarpEngineSubsystemPtr(val)
    return val

def WarpEngineSubsystem_Create(*args, **kwargs):
    val = apply(Appc.WarpEngineSubsystem_Create,args,kwargs)
    if val: val = WarpEngineSubsystemPtr(val)
    return val

WarpEngineSubsystem_GetWarpEffectTime = Appc.WarpEngineSubsystem_GetWarpEffectTime

WarpEngineSubsystem_SetWarpEffectTime = Appc.WarpEngineSubsystem_SetWarpEffectTime

WarpEngineSubsystem_GetWarpSpeed = Appc.WarpEngineSubsystem_GetWarpSpeed

WarpEngineSubsystem_SetWarpSpeed = Appc.WarpEngineSubsystem_SetWarpSpeed

def TractorBeamProjector_Cast(*args, **kwargs):
    val = apply(Appc.TractorBeamProjector_Cast,args,kwargs)
    if val: val = TractorBeamProjectorPtr(val)
    return val

def TractorBeamProjector_Create(*args, **kwargs):
    val = apply(Appc.TractorBeamProjector_Create,args,kwargs)
    if val: val = TractorBeamProjectorPtr(val)
    return val

def TractorBeamSystem_Cast(*args, **kwargs):
    val = apply(Appc.TractorBeamSystem_Cast,args,kwargs)
    if val: val = TractorBeamSystemPtr(val)
    return val

def TractorBeamSystem_Create(*args, **kwargs):
    val = apply(Appc.TractorBeamSystem_Create,args,kwargs)
    if val: val = TractorBeamSystemPtr(val)
    return val

EffectController_GetEffectLevel = Appc.EffectController_GetEffectLevel

EffectController_SetEffectLevel = Appc.EffectController_SetEffectLevel

def PointParticleController_Create(*args, **kwargs):
    val = apply(Appc.PointParticleController_Create,args,kwargs)
    if val: val = PointParticleControllerPtr(val)
    return val

def SparkParticleController_Create(*args, **kwargs):
    val = apply(Appc.SparkParticleController_Create,args,kwargs)
    if val: val = SparkParticleControllerPtr(val)
    return val

def ExplodeParticleController_Create(*args, **kwargs):
    val = apply(Appc.ExplodeParticleController_Create,args,kwargs)
    if val: val = ExplodeParticleControllerPtr(val)
    return val

def DebrisParticleController_Create(*args, **kwargs):
    val = apply(Appc.DebrisParticleController_Create,args,kwargs)
    if val: val = DebrisParticleControllerPtr(val)
    return val

def AnimTSParticleController_Create(*args, **kwargs):
    val = apply(Appc.AnimTSParticleController_Create,args,kwargs)
    if val: val = AnimTSParticleControllerPtr(val)
    return val

def EffectAction_Create(*args, **kwargs):
    val = apply(Appc.EffectAction_Create,args,kwargs)
    if val: val = EffectActionPtr(val)
    return val

def BridgeEffectAction_Create(*args, **kwargs):
    val = apply(Appc.BridgeEffectAction_Create,args,kwargs)
    if val: val = BridgeEffectActionPtr(val)
    return val

def BridgeEffectAction_CreateSparks(*args, **kwargs):
    val = apply(Appc.BridgeEffectAction_CreateSparks,args,kwargs)
    if val: val = BridgeEffectActionPtr(val)
    return val

def BridgeEffectAction_CreateSmoke(*args, **kwargs):
    val = apply(Appc.BridgeEffectAction_CreateSmoke,args,kwargs)
    if val: val = BridgeEffectActionPtr(val)
    return val

def BridgeEffectAction_CreateExplosion(*args, **kwargs):
    val = apply(Appc.BridgeEffectAction_CreateExplosion,args,kwargs)
    if val: val = BridgeEffectActionPtr(val)
    return val

def BridgeEffectAction_CreateDebris(*args, **kwargs):
    val = apply(Appc.BridgeEffectAction_CreateDebris,args,kwargs)
    if val: val = BridgeEffectActionPtr(val)
    return val

def WarpSet_Create(*args, **kwargs):
    val = apply(Appc.WarpSet_Create,args,kwargs)
    if val: val = WarpSetPtr(val)
    return val

def WarpSet_Cast(*args, **kwargs):
    val = apply(Appc.WarpSet_Cast,args,kwargs)
    if val: val = WarpSetPtr(val)
    return val

def WarpSequence_Create(*args, **kwargs):
    val = apply(Appc.WarpSequence_Create,args,kwargs)
    if val: val = WarpSequencePtr(val)
    return val

def WarpSequence_Cast(*args, **kwargs):
    val = apply(Appc.WarpSequence_Cast,args,kwargs)
    if val: val = WarpSequencePtr(val)
    return val

def WarpSequence_GetWarpSet(*args, **kwargs):
    val = apply(Appc.WarpSequence_GetWarpSet,args,kwargs)
    if val: val = SetClassPtr(val)
    return val

def WarpFlash_Create(*args, **kwargs):
    val = apply(Appc.WarpFlash_Create,args,kwargs)
    if val: val = WarpFlashPtr(val)
    return val

def WarpFlash_CreateWithoutShip(*args, **kwargs):
    val = apply(Appc.WarpFlash_CreateWithoutShip,args,kwargs)
    if val: val = WarpFlashPtr(val)
    return val

def LensFlare_Create(*args, **kwargs):
    val = apply(Appc.LensFlare_Create,args,kwargs)
    if val: val = LensFlarePtr(val)
    return val

def ExplosionPlumeController_Create(*args, **kwargs):
    val = apply(Appc.ExplosionPlumeController_Create,args,kwargs)
    if val: val = ExplosionPlumeControllerPtr(val)
    return val

def SunEffect_Create(*args, **kwargs):
    val = apply(Appc.SunEffect_Create,args,kwargs)
    if val: val = NiAVObjectPtr(val)
    return val

InterfaceModule_IsUIElement = Appc.InterfaceModule_IsUIElement

InterfaceModule_HasUIElement = Appc.InterfaceModule_HasUIElement

def InterfaceModule_GetFirstUIElement(*args, **kwargs):
    val = apply(Appc.InterfaceModule_GetFirstUIElement,args,kwargs)
    if val: val = TGUIObjectPtr(val)
    return val

def InterfaceModule_GetLastUIElement(*args, **kwargs):
    val = apply(Appc.InterfaceModule_GetLastUIElement,args,kwargs)
    if val: val = TGUIObjectPtr(val)
    return val

def InterfaceModule_GetPrevUIElement(*args, **kwargs):
    val = apply(Appc.InterfaceModule_GetPrevUIElement,args,kwargs)
    if val: val = TGUIObjectPtr(val)
    return val

def InterfaceModule_GetNextUIElement(*args, **kwargs):
    val = apply(Appc.InterfaceModule_GetNextUIElement,args,kwargs)
    if val: val = TGUIObjectPtr(val)
    return val

InterfaceModule_ForceFocusOnObject = Appc.InterfaceModule_ForceFocusOnObject

InterfaceModule_SwitchFonts = Appc.InterfaceModule_SwitchFonts

InterfaceModule_DoTheRightThing = Appc.InterfaceModule_DoTheRightThing

def TopWindow_GetTopWindow(*args, **kwargs):
    val = apply(Appc.TopWindow_GetTopWindow,args,kwargs)
    if val: val = TopWindowPtr(val)
    return val

def OptionsWindow_Cast(*args, **kwargs):
    val = apply(Appc.OptionsWindow_Cast,args,kwargs)
    if val: val = OptionsWindowPtr(val)
    return val

def BridgeWindow_Cast(*args, **kwargs):
    val = apply(Appc.BridgeWindow_Cast,args,kwargs)
    if val: val = BridgeWindowPtr(val)
    return val

def TacticalWindow_Cast(*args, **kwargs):
    val = apply(Appc.TacticalWindow_Cast,args,kwargs)
    if val: val = TacticalWindowPtr(val)
    return val

TacticalWindow_SpaceCameraRotation = Appc.TacticalWindow_SpaceCameraRotation

def TacticalControlWindow_Create(*args, **kwargs):
    val = apply(Appc.TacticalControlWindow_Create,args,kwargs)
    if val: val = TacticalControlWindowPtr(val)
    return val

def TacticalControlWindow_Cast(*args, **kwargs):
    val = apply(Appc.TacticalControlWindow_Cast,args,kwargs)
    if val: val = TacticalControlWindowPtr(val)
    return val

def TacticalControlWindow_GetTacticalControlWindow(*args, **kwargs):
    val = apply(Appc.TacticalControlWindow_GetTacticalControlWindow,args,kwargs)
    if val: val = TacticalControlWindowPtr(val)
    return val

def MapWindow_Cast(*args, **kwargs):
    val = apply(Appc.MapWindow_Cast,args,kwargs)
    if val: val = MapWindowPtr(val)
    return val

def ModalDialogWindow_Cast(*args, **kwargs):
    val = apply(Appc.ModalDialogWindow_Cast,args,kwargs)
    if val: val = ModalDialogWindowPtr(val)
    return val

def CinematicWindow_Cast(*args, **kwargs):
    val = apply(Appc.CinematicWindow_Cast,args,kwargs)
    if val: val = CinematicWindowPtr(val)
    return val

def SubtitleWindow_Create(*args, **kwargs):
    val = apply(Appc.SubtitleWindow_Create,args,kwargs)
    if val: val = SubtitleWindowPtr(val)
    return val

def SubtitleWindow_Cast(*args, **kwargs):
    val = apply(Appc.SubtitleWindow_Cast,args,kwargs)
    if val: val = SubtitleWindowPtr(val)
    return val

def SubtitleAction_Create(*args, **kwargs):
    val = apply(Appc.SubtitleAction_Create,args,kwargs)
    if val: val = SubtitleActionPtr(val)
    return val

def SubtitleAction_CreateC(*args, **kwargs):
    val = apply(Appc.SubtitleAction_CreateC,args,kwargs)
    if val: val = SubtitleActionPtr(val)
    return val

def STStylizedWindow_CreateW(*args, **kwargs):
    val = apply(Appc.STStylizedWindow_CreateW,args,kwargs)
    if val: val = STStylizedWindowPtr(val)
    return val

def STStylizedWindow_Create(*args, **kwargs):
    val = apply(Appc.STStylizedWindow_Create,args,kwargs)
    if val: val = STStylizedWindowPtr(val)
    return val

def STStylizedWindow_Cast(*args, **kwargs):
    val = apply(Appc.STStylizedWindow_Cast,args,kwargs)
    if val: val = STStylizedWindowPtr(val)
    return val

def STMenu_Create(*args, **kwargs):
    val = apply(Appc.STMenu_Create,args,kwargs)
    if val: val = STMenuPtr(val)
    return val

def STMenu_CreateW(*args, **kwargs):
    val = apply(Appc.STMenu_CreateW,args,kwargs)
    if val: val = STMenuPtr(val)
    return val

def STMenu_CreateNull(*args, **kwargs):
    val = apply(Appc.STMenu_CreateNull,args,kwargs)
    if val: val = STMenuPtr(val)
    return val

def STMenu_Cast(*args, **kwargs):
    val = apply(Appc.STMenu_Cast,args,kwargs)
    if val: val = STMenuPtr(val)
    return val

def STSubPane_Create(*args, **kwargs):
    val = apply(Appc.STSubPane_Create,args,kwargs)
    if val: val = STSubPanePtr(val)
    return val

def STSubPane_Cast(*args, **kwargs):
    val = apply(Appc.STSubPane_Cast,args,kwargs)
    if val: val = STSubPanePtr(val)
    return val

def STTopLevelMenu_Create(*args, **kwargs):
    val = apply(Appc.STTopLevelMenu_Create,args,kwargs)
    if val: val = STTopLevelMenuPtr(val)
    return val

def STTopLevelMenu_CreateW(*args, **kwargs):
    val = apply(Appc.STTopLevelMenu_CreateW,args,kwargs)
    if val: val = STTopLevelMenuPtr(val)
    return val

def STTopLevelMenu_CreateNull(*args, **kwargs):
    val = apply(Appc.STTopLevelMenu_CreateNull,args,kwargs)
    if val: val = STTopLevelMenuPtr(val)
    return val

def STTopLevelMenu_Cast(*args, **kwargs):
    val = apply(Appc.STTopLevelMenu_Cast,args,kwargs)
    if val: val = STTopLevelMenuPtr(val)
    return val

def STTopLevelMenu_GetOpenMenu(*args, **kwargs):
    val = apply(Appc.STTopLevelMenu_GetOpenMenu,args,kwargs)
    if val: val = STTopLevelMenuPtr(val)
    return val

def STCharacterMenu_Create(*args, **kwargs):
    val = apply(Appc.STCharacterMenu_Create,args,kwargs)
    if val: val = STCharacterMenuPtr(val)
    return val

def STCharacterMenu_CreateW(*args, **kwargs):
    val = apply(Appc.STCharacterMenu_CreateW,args,kwargs)
    if val: val = STCharacterMenuPtr(val)
    return val

def STButton_Create(*args, **kwargs):
    val = apply(Appc.STButton_Create,args,kwargs)
    if val: val = STButtonPtr(val)
    return val

def STButton_CreateW(*args, **kwargs):
    val = apply(Appc.STButton_CreateW,args,kwargs)
    if val: val = STButtonPtr(val)
    return val

def STButton_Cast(*args, **kwargs):
    val = apply(Appc.STButton_Cast,args,kwargs)
    if val: val = STButtonPtr(val)
    return val

def STRoundedButton_Create(*args, **kwargs):
    val = apply(Appc.STRoundedButton_Create,args,kwargs)
    if val: val = STRoundedButtonPtr(val)
    return val

def STRoundedButton_CreateW(*args, **kwargs):
    val = apply(Appc.STRoundedButton_CreateW,args,kwargs)
    if val: val = STRoundedButtonPtr(val)
    return val

def STRoundedButton_Cast(*args, **kwargs):
    val = apply(Appc.STRoundedButton_Cast,args,kwargs)
    if val: val = STRoundedButtonPtr(val)
    return val

def STToggle_Create(*args, **kwargs):
    val = apply(Appc.STToggle_Create,args,kwargs)
    if val: val = STTogglePtr(val)
    return val

def STToggle_CreateW(*args, **kwargs):
    val = apply(Appc.STToggle_CreateW,args,kwargs)
    if val: val = STTogglePtr(val)
    return val

def STToggle_CreateUnsizedW(*args, **kwargs):
    val = apply(Appc.STToggle_CreateUnsizedW,args,kwargs)
    if val: val = STTogglePtr(val)
    return val

def STToggle_Cast(*args, **kwargs):
    val = apply(Appc.STToggle_Cast,args,kwargs)
    if val: val = STTogglePtr(val)
    return val

def STFillGauge_Create(*args, **kwargs):
    val = apply(Appc.STFillGauge_Create,args,kwargs)
    if val: val = STFillGaugePtr(val)
    return val

def STFillGauge_Cast(*args, **kwargs):
    val = apply(Appc.STFillGauge_Cast,args,kwargs)
    if val: val = STFillGaugePtr(val)
    return val

def STNumericBar_Create(*args, **kwargs):
    val = apply(Appc.STNumericBar_Create,args,kwargs)
    if val: val = STNumericBarPtr(val)
    return val

def STNumericBar_Cast(*args, **kwargs):
    val = apply(Appc.STNumericBar_Cast,args,kwargs)
    if val: val = STNumericBarPtr(val)
    return val

def STTargetMenu_CreateW(*args, **kwargs):
    val = apply(Appc.STTargetMenu_CreateW,args,kwargs)
    if val: val = STTargetMenuPtr(val)
    return val

def STTargetMenu_Cast(*args, **kwargs):
    val = apply(Appc.STTargetMenu_Cast,args,kwargs)
    if val: val = STTargetMenuPtr(val)
    return val

def STTargetMenu_GetTargetMenu(*args, **kwargs):
    val = apply(Appc.STTargetMenu_GetTargetMenu,args,kwargs)
    if val: val = STTargetMenuPtr(val)
    return val

def STFileMenu_Create(*args, **kwargs):
    val = apply(Appc.STFileMenu_Create,args,kwargs)
    if val: val = STFileMenuPtr(val)
    return val

def STFileMenu_CreateW(*args, **kwargs):
    val = apply(Appc.STFileMenu_CreateW,args,kwargs)
    if val: val = STFileMenuPtr(val)
    return val

def STFileMenu_Cast(*args, **kwargs):
    val = apply(Appc.STFileMenu_Cast,args,kwargs)
    if val: val = STFileMenuPtr(val)
    return val

def STFileDialog_Create(*args, **kwargs):
    val = apply(Appc.STFileDialog_Create,args,kwargs)
    if val: val = STFileDialogPtr(val)
    return val

def STLoadDialog_Create(*args, **kwargs):
    val = apply(Appc.STLoadDialog_Create,args,kwargs)
    if val: val = STLoadDialogPtr(val)
    return val

def STSaveDialog_Create(*args, **kwargs):
    val = apply(Appc.STSaveDialog_Create,args,kwargs)
    if val: val = STSaveDialogPtr(val)
    return val

def STSubsystemMenu_Cast(*args, **kwargs):
    val = apply(Appc.STSubsystemMenu_Cast,args,kwargs)
    if val: val = STSubsystemMenuPtr(val)
    return val

def STComponentMenu_Cast(*args, **kwargs):
    val = apply(Appc.STComponentMenu_Cast,args,kwargs)
    if val: val = STComponentMenuPtr(val)
    return val

def STComponentMenuItem_Cast(*args, **kwargs):
    val = apply(Appc.STComponentMenuItem_Cast,args,kwargs)
    if val: val = STComponentMenuItemPtr(val)
    return val

def STTiledIcon_Create(*args, **kwargs):
    val = apply(Appc.STTiledIcon_Create,args,kwargs)
    if val: val = STTiledIconPtr(val)
    return val

def STTiledIcon_Cast(*args, **kwargs):
    val = apply(Appc.STTiledIcon_Cast,args,kwargs)
    if val: val = STTiledIconPtr(val)
    return val

def GraphicsMenu_CreateW(*args, **kwargs):
    val = apply(Appc.GraphicsMenu_CreateW,args,kwargs)
    if val: val = GraphicsMenuPtr(val)
    return val

def GraphicsMenu_Cast(*args, **kwargs):
    val = apply(Appc.GraphicsMenu_Cast,args,kwargs)
    if val: val = GraphicsMenuPtr(val)
    return val

def GraphicsMenu_GetGraphicsMenu(*args, **kwargs):
    val = apply(Appc.GraphicsMenu_GetGraphicsMenu,args,kwargs)
    if val: val = GraphicsMenuPtr(val)
    return val

def ShipDisplay_Create(*args, **kwargs):
    val = apply(Appc.ShipDisplay_Create,args,kwargs)
    if val: val = ShipDisplayPtr(val)
    return val

def ShipDisplay_Cast(*args, **kwargs):
    val = apply(Appc.ShipDisplay_Cast,args,kwargs)
    if val: val = ShipDisplayPtr(val)
    return val

def ShieldsDisplay_Create(*args, **kwargs):
    val = apply(Appc.ShieldsDisplay_Create,args,kwargs)
    if val: val = ShieldsDisplayPtr(val)
    return val

def ShieldsDisplay_Cast(*args, **kwargs):
    val = apply(Appc.ShieldsDisplay_Cast,args,kwargs)
    if val: val = ShieldsDisplayPtr(val)
    return val

def DamageIcon_Cast(*args, **kwargs):
    val = apply(Appc.DamageIcon_Cast,args,kwargs)
    if val: val = DamageIconPtr(val)
    return val

def DamageDisplay_Create(*args, **kwargs):
    val = apply(Appc.DamageDisplay_Create,args,kwargs)
    if val: val = DamageDisplayPtr(val)
    return val

def DamageDisplay_Cast(*args, **kwargs):
    val = apply(Appc.DamageDisplay_Cast,args,kwargs)
    if val: val = DamageDisplayPtr(val)
    return val

def WeaponsDisplay_Create(*args, **kwargs):
    val = apply(Appc.WeaponsDisplay_Create,args,kwargs)
    if val: val = WeaponsDisplayPtr(val)
    return val

def WeaponsDisplay_Cast(*args, **kwargs):
    val = apply(Appc.WeaponsDisplay_Cast,args,kwargs)
    if val: val = WeaponsDisplayPtr(val)
    return val

def RadarDisplay_Create(*args, **kwargs):
    val = apply(Appc.RadarDisplay_Create,args,kwargs)
    if val: val = RadarDisplayPtr(val)
    return val

def RadarDisplay_Cast(*args, **kwargs):
    val = apply(Appc.RadarDisplay_Cast,args,kwargs)
    if val: val = RadarDisplayPtr(val)
    return val

def RadarBlip_Create(*args, **kwargs):
    val = apply(Appc.RadarBlip_Create,args,kwargs)
    if val: val = RadarBlipPtr(val)
    return val

def RadarScope_Create(*args, **kwargs):
    val = apply(Appc.RadarScope_Create,args,kwargs)
    if val: val = RadarScopePtr(val)
    return val

def TacWeaponsCtrl_Create(*args, **kwargs):
    val = apply(Appc.TacWeaponsCtrl_Create,args,kwargs)
    if val: val = TacWeaponsCtrlPtr(val)
    return val

def TacWeaponsCtrl_Cast(*args, **kwargs):
    val = apply(Appc.TacWeaponsCtrl_Cast,args,kwargs)
    if val: val = TacWeaponsCtrlPtr(val)
    return val

def TacWeaponsCtrl_GetTacWeaponsCtrl(*args, **kwargs):
    val = apply(Appc.TacWeaponsCtrl_GetTacWeaponsCtrl,args,kwargs)
    if val: val = TacWeaponsCtrlPtr(val)
    return val

def EngPowerCtrl_GetPowerCtrl(*args, **kwargs):
    val = apply(Appc.EngPowerCtrl_GetPowerCtrl,args,kwargs)
    if val: val = EngPowerCtrlPtr(val)
    return val

def EngPowerCtrl_Create(*args, **kwargs):
    val = apply(Appc.EngPowerCtrl_Create,args,kwargs)
    if val: val = EngPowerCtrlPtr(val)
    return val

def EngPowerDisplay_Create(*args, **kwargs):
    val = apply(Appc.EngPowerDisplay_Create,args,kwargs)
    if val: val = EngPowerDisplayPtr(val)
    return val

def EngPowerDisplay_Cast(*args, **kwargs):
    val = apply(Appc.EngPowerDisplay_Cast,args,kwargs)
    if val: val = EngPowerDisplayPtr(val)
    return val

def EngPowerDisplay_GetPowerDisplay(*args, **kwargs):
    val = apply(Appc.EngPowerDisplay_GetPowerDisplay,args,kwargs)
    if val: val = EngPowerDisplayPtr(val)
    return val

def EngRepairPane_Create(*args, **kwargs):
    val = apply(Appc.EngRepairPane_Create,args,kwargs)
    if val: val = EngRepairPanePtr(val)
    return val

def EngRepairPane_GetRepairPane(*args, **kwargs):
    val = apply(Appc.EngRepairPane_GetRepairPane,args,kwargs)
    if val: val = EngRepairPanePtr(val)
    return val

def EngRepairPane_Cast(*args, **kwargs):
    val = apply(Appc.EngRepairPane_Cast,args,kwargs)
    if val: val = EngRepairPanePtr(val)
    return val

def STWarpButton_Create(*args, **kwargs):
    val = apply(Appc.STWarpButton_Create,args,kwargs)
    if val: val = STWarpButtonPtr(val)
    return val

def STWarpButton_CreateW(*args, **kwargs):
    val = apply(Appc.STWarpButton_CreateW,args,kwargs)
    if val: val = STWarpButtonPtr(val)
    return val

def STWarpButton_Cast(*args, **kwargs):
    val = apply(Appc.STWarpButton_Cast,args,kwargs)
    if val: val = STWarpButtonPtr(val)
    return val

def SortedRegionMenu_Create(*args, **kwargs):
    val = apply(Appc.SortedRegionMenu_Create,args,kwargs)
    if val: val = SortedRegionMenuPtr(val)
    return val

def SortedRegionMenu_CreateW(*args, **kwargs):
    val = apply(Appc.SortedRegionMenu_CreateW,args,kwargs)
    if val: val = SortedRegionMenuPtr(val)
    return val

def SortedRegionMenu_Cast(*args, **kwargs):
    val = apply(Appc.SortedRegionMenu_Cast,args,kwargs)
    if val: val = SortedRegionMenuPtr(val)
    return val

def SortedRegionMenu_CreateNull(*args, **kwargs):
    val = apply(Appc.SortedRegionMenu_CreateNull,args,kwargs)
    if val: val = SortedRegionMenuPtr(val)
    return val

SortedRegionMenu_SetWarpButton = Appc.SortedRegionMenu_SetWarpButton

def SortedRegionMenu_GetWarpButton(*args, **kwargs):
    val = apply(Appc.SortedRegionMenu_GetWarpButton,args,kwargs)
    if val: val = STWarpButtonPtr(val)
    return val

SortedRegionMenu_ClearSetCourseMenu = Appc.SortedRegionMenu_ClearSetCourseMenu

SortedRegionMenu_SetPauseSorting = Appc.SortedRegionMenu_SetPauseSorting

SortedRegionMenu_IsSortingPaused = Appc.SortedRegionMenu_IsSortingPaused

def SortedRegionMenu_GetRoot(*args, **kwargs):
    val = apply(Appc.SortedRegionMenu_GetRoot,args,kwargs)
    if val: val = SortedRegionMenuPtr(val)
    return val

def MultiplayerWindow_Cast(*args, **kwargs):
    val = apply(Appc.MultiplayerWindow_Cast,args,kwargs)
    if val: val = MultiplayerWindowPtr(val)
    return val

MultiplayerWindow_SetStatusMessage = Appc.MultiplayerWindow_SetStatusMessage

def STMissionLog_GetMissionLog(*args, **kwargs):
    val = apply(Appc.STMissionLog_GetMissionLog,args,kwargs)
    if val: val = STMissionLogPtr(val)
    return val

def UITreeDialog_Create(*args, **kwargs):
    val = apply(Appc.UITreeDialog_Create,args,kwargs)
    if val: val = UITreeDialogPtr(val)
    return val

def PlacementObject_Create(*args, **kwargs):
    val = apply(Appc.PlacementObject_Create,args,kwargs)
    if val: val = PlacementObjectPtr(val)
    return val

def PlacementObject_Cast(*args, **kwargs):
    val = apply(Appc.PlacementObject_Cast,args,kwargs)
    if val: val = PlacementObjectPtr(val)
    return val

def PlacementObject_GetObject(*args, **kwargs):
    val = apply(Appc.PlacementObject_GetObject,args,kwargs)
    if val: val = PlacementObjectPtr(val)
    return val

def PlacementObject_GetObjectBySetName(*args, **kwargs):
    val = apply(Appc.PlacementObject_GetObjectBySetName,args,kwargs)
    if val: val = PlacementObjectPtr(val)
    return val

def Waypoint_Create(*args, **kwargs):
    val = apply(Appc.Waypoint_Create,args,kwargs)
    if val: val = WaypointPtr(val)
    return val

def Waypoint_Cast(*args, **kwargs):
    val = apply(Appc.Waypoint_Cast,args,kwargs)
    if val: val = WaypointPtr(val)
    return val

def LightPlacement_Create(*args, **kwargs):
    val = apply(Appc.LightPlacement_Create,args,kwargs)
    if val: val = LightPlacementPtr(val)
    return val

def LightPlacement_Cast(*args, **kwargs):
    val = apply(Appc.LightPlacement_Cast,args,kwargs)
    if val: val = LightPlacementPtr(val)
    return val

def GridClass_Create(*args, **kwargs):
    val = apply(Appc.GridClass_Create,args,kwargs)
    if val: val = GridClassPtr(val)
    return val

def GridClass_GetObject(*args, **kwargs):
    val = apply(Appc.GridClass_GetObject,args,kwargs)
    if val: val = GridClassPtr(val)
    return val

GridClass_GetNumClassObjects = Appc.GridClass_GetNumClassObjects

def AsteroidFieldPlacement_Create(*args, **kwargs):
    val = apply(Appc.AsteroidFieldPlacement_Create,args,kwargs)
    if val: val = AsteroidFieldPlacementPtr(val)
    return val

def AsteroidFieldPlacement_Cast(*args, **kwargs):
    val = apply(Appc.AsteroidFieldPlacement_Cast,args,kwargs)
    if val: val = AsteroidFieldPlacementPtr(val)
    return val

def AsteroidFieldPlacement_GetObject(*args, **kwargs):
    val = apply(Appc.AsteroidFieldPlacement_GetObject,args,kwargs)
    if val: val = AsteroidFieldPlacementPtr(val)
    return val

def AsteroidFieldPlacement_GetObjectBySetName(*args, **kwargs):
    val = apply(Appc.AsteroidFieldPlacement_GetObjectBySetName,args,kwargs)
    if val: val = AsteroidFieldPlacementPtr(val)
    return val

def PositionOrientationProperty_Cast(*args, **kwargs):
    val = apply(Appc.PositionOrientationProperty_Cast,args,kwargs)
    if val: val = PositionOrientationPropertyPtr(val)
    return val

def PositionOrientationProperty_Create(*args, **kwargs):
    val = apply(Appc.PositionOrientationProperty_Create,args,kwargs)
    if val: val = PositionOrientationPropertyPtr(val)
    return val

def SubsystemProperty_Cast(*args, **kwargs):
    val = apply(Appc.SubsystemProperty_Cast,args,kwargs)
    if val: val = SubsystemPropertyPtr(val)
    return val

def SubsystemProperty_Create(*args, **kwargs):
    val = apply(Appc.SubsystemProperty_Create,args,kwargs)
    if val: val = SubsystemPropertyPtr(val)
    return val

def PoweredSubsystemProperty_Cast(*args, **kwargs):
    val = apply(Appc.PoweredSubsystemProperty_Cast,args,kwargs)
    if val: val = PoweredSubsystemPropertyPtr(val)
    return val

def PoweredSubsystemProperty_Create(*args, **kwargs):
    val = apply(Appc.PoweredSubsystemProperty_Create,args,kwargs)
    if val: val = PoweredSubsystemPropertyPtr(val)
    return val

def WeaponSystemProperty_Cast(*args, **kwargs):
    val = apply(Appc.WeaponSystemProperty_Cast,args,kwargs)
    if val: val = WeaponSystemPropertyPtr(val)
    return val

def WeaponSystemProperty_Create(*args, **kwargs):
    val = apply(Appc.WeaponSystemProperty_Create,args,kwargs)
    if val: val = WeaponSystemPropertyPtr(val)
    return val

def WeaponProperty_Cast(*args, **kwargs):
    val = apply(Appc.WeaponProperty_Cast,args,kwargs)
    if val: val = WeaponPropertyPtr(val)
    return val

def WeaponProperty_Create(*args, **kwargs):
    val = apply(Appc.WeaponProperty_Create,args,kwargs)
    if val: val = WeaponPropertyPtr(val)
    return val

def EnergyWeaponProperty_Cast(*args, **kwargs):
    val = apply(Appc.EnergyWeaponProperty_Cast,args,kwargs)
    if val: val = EnergyWeaponPropertyPtr(val)
    return val

def EnergyWeaponProperty_Create(*args, **kwargs):
    val = apply(Appc.EnergyWeaponProperty_Create,args,kwargs)
    if val: val = EnergyWeaponPropertyPtr(val)
    return val

def PhaserProperty_Cast(*args, **kwargs):
    val = apply(Appc.PhaserProperty_Cast,args,kwargs)
    if val: val = PhaserPropertyPtr(val)
    return val

def PhaserProperty_Create(*args, **kwargs):
    val = apply(Appc.PhaserProperty_Create,args,kwargs)
    if val: val = PhaserPropertyPtr(val)
    return val

def PulseWeaponProperty_Cast(*args, **kwargs):
    val = apply(Appc.PulseWeaponProperty_Cast,args,kwargs)
    if val: val = PulseWeaponPropertyPtr(val)
    return val

def PulseWeaponProperty_Create(*args, **kwargs):
    val = apply(Appc.PulseWeaponProperty_Create,args,kwargs)
    if val: val = PulseWeaponPropertyPtr(val)
    return val

def TractorBeamProperty_Cast(*args, **kwargs):
    val = apply(Appc.TractorBeamProperty_Cast,args,kwargs)
    if val: val = TractorBeamPropertyPtr(val)
    return val

def TractorBeamProperty_Create(*args, **kwargs):
    val = apply(Appc.TractorBeamProperty_Create,args,kwargs)
    if val: val = TractorBeamPropertyPtr(val)
    return val

def TorpedoTubeProperty_Cast(*args, **kwargs):
    val = apply(Appc.TorpedoTubeProperty_Cast,args,kwargs)
    if val: val = TorpedoTubePropertyPtr(val)
    return val

def TorpedoTubeProperty_Create(*args, **kwargs):
    val = apply(Appc.TorpedoTubeProperty_Create,args,kwargs)
    if val: val = TorpedoTubePropertyPtr(val)
    return val

def TorpedoSystemProperty_Cast(*args, **kwargs):
    val = apply(Appc.TorpedoSystemProperty_Cast,args,kwargs)
    if val: val = TorpedoSystemPropertyPtr(val)
    return val

def TorpedoSystemProperty_Create(*args, **kwargs):
    val = apply(Appc.TorpedoSystemProperty_Create,args,kwargs)
    if val: val = TorpedoSystemPropertyPtr(val)
    return val

def EngineGlowProperty_Cast(*args, **kwargs):
    val = apply(Appc.EngineGlowProperty_Cast,args,kwargs)
    if val: val = EngineGlowPropertyPtr(val)
    return val

def EngineGlowProperty_Create(*args, **kwargs):
    val = apply(Appc.EngineGlowProperty_Create,args,kwargs)
    if val: val = EngineGlowPropertyPtr(val)
    return val

def ShieldProperty_Cast(*args, **kwargs):
    val = apply(Appc.ShieldProperty_Cast,args,kwargs)
    if val: val = ShieldPropertyPtr(val)
    return val

def ShieldProperty_Create(*args, **kwargs):
    val = apply(Appc.ShieldProperty_Create,args,kwargs)
    if val: val = ShieldPropertyPtr(val)
    return val

def HullProperty_Cast(*args, **kwargs):
    val = apply(Appc.HullProperty_Cast,args,kwargs)
    if val: val = HullPropertyPtr(val)
    return val

def HullProperty_Create(*args, **kwargs):
    val = apply(Appc.HullProperty_Create,args,kwargs)
    if val: val = HullPropertyPtr(val)
    return val

def SensorProperty_Cast(*args, **kwargs):
    val = apply(Appc.SensorProperty_Cast,args,kwargs)
    if val: val = SensorPropertyPtr(val)
    return val

def SensorProperty_Create(*args, **kwargs):
    val = apply(Appc.SensorProperty_Create,args,kwargs)
    if val: val = SensorPropertyPtr(val)
    return val

def CloakingSubsystemProperty_Cast(*args, **kwargs):
    val = apply(Appc.CloakingSubsystemProperty_Cast,args,kwargs)
    if val: val = CloakingSubsystemPropertyPtr(val)
    return val

def CloakingSubsystemProperty_Create(*args, **kwargs):
    val = apply(Appc.CloakingSubsystemProperty_Create,args,kwargs)
    if val: val = CloakingSubsystemPropertyPtr(val)
    return val

def RepairSubsystemProperty_Cast(*args, **kwargs):
    val = apply(Appc.RepairSubsystemProperty_Cast,args,kwargs)
    if val: val = RepairSubsystemPropertyPtr(val)
    return val

def RepairSubsystemProperty_Create(*args, **kwargs):
    val = apply(Appc.RepairSubsystemProperty_Create,args,kwargs)
    if val: val = RepairSubsystemPropertyPtr(val)
    return val

def ShipProperty_Cast(*args, **kwargs):
    val = apply(Appc.ShipProperty_Cast,args,kwargs)
    if val: val = ShipPropertyPtr(val)
    return val

def ShipProperty_Create(*args, **kwargs):
    val = apply(Appc.ShipProperty_Create,args,kwargs)
    if val: val = ShipPropertyPtr(val)
    return val

def PowerProperty_Cast(*args, **kwargs):
    val = apply(Appc.PowerProperty_Cast,args,kwargs)
    if val: val = PowerPropertyPtr(val)
    return val

def PowerProperty_Create(*args, **kwargs):
    val = apply(Appc.PowerProperty_Create,args,kwargs)
    if val: val = PowerPropertyPtr(val)
    return val

def ImpulseEngineProperty_Cast(*args, **kwargs):
    val = apply(Appc.ImpulseEngineProperty_Cast,args,kwargs)
    if val: val = ImpulseEnginePropertyPtr(val)
    return val

def ImpulseEngineProperty_Create(*args, **kwargs):
    val = apply(Appc.ImpulseEngineProperty_Create,args,kwargs)
    if val: val = ImpulseEnginePropertyPtr(val)
    return val

def WarpEngineProperty_Cast(*args, **kwargs):
    val = apply(Appc.WarpEngineProperty_Cast,args,kwargs)
    if val: val = WarpEnginePropertyPtr(val)
    return val

def WarpEngineProperty_Create(*args, **kwargs):
    val = apply(Appc.WarpEngineProperty_Create,args,kwargs)
    if val: val = WarpEnginePropertyPtr(val)
    return val

def EngineProperty_Cast(*args, **kwargs):
    val = apply(Appc.EngineProperty_Cast,args,kwargs)
    if val: val = EnginePropertyPtr(val)
    return val

def EngineProperty_Create(*args, **kwargs):
    val = apply(Appc.EngineProperty_Create,args,kwargs)
    if val: val = EnginePropertyPtr(val)
    return val

def EffectEmitterProperty_Cast(*args, **kwargs):
    val = apply(Appc.EffectEmitterProperty_Cast,args,kwargs)
    if val: val = EffectEmitterPropertyPtr(val)
    return val

def EffectEmitterProperty_Create(*args, **kwargs):
    val = apply(Appc.EffectEmitterProperty_Create,args,kwargs)
    if val: val = EffectEmitterPropertyPtr(val)
    return val

def SmokeEmitterProperty_Cast(*args, **kwargs):
    val = apply(Appc.SmokeEmitterProperty_Cast,args,kwargs)
    if val: val = SmokeEmitterPropertyPtr(val)
    return val

def SmokeEmitterProperty_Create(*args, **kwargs):
    val = apply(Appc.SmokeEmitterProperty_Create,args,kwargs)
    if val: val = SmokeEmitterPropertyPtr(val)
    return val

def SparkEmitterProperty_Cast(*args, **kwargs):
    val = apply(Appc.SparkEmitterProperty_Cast,args,kwargs)
    if val: val = SparkEmitterPropertyPtr(val)
    return val

def SparkEmitterProperty_Create(*args, **kwargs):
    val = apply(Appc.SparkEmitterProperty_Create,args,kwargs)
    if val: val = SparkEmitterPropertyPtr(val)
    return val

def ExplodeEmitterProperty_Cast(*args, **kwargs):
    val = apply(Appc.ExplodeEmitterProperty_Cast,args,kwargs)
    if val: val = ExplodeEmitterPropertyPtr(val)
    return val

def ExplodeEmitterProperty_Create(*args, **kwargs):
    val = apply(Appc.ExplodeEmitterProperty_Create,args,kwargs)
    if val: val = ExplodeEmitterPropertyPtr(val)
    return val

def BlinkingLightProperty_Cast(*args, **kwargs):
    val = apply(Appc.BlinkingLightProperty_Cast,args,kwargs)
    if val: val = BlinkingLightPropertyPtr(val)
    return val

def BlinkingLightProperty_Create(*args, **kwargs):
    val = apply(Appc.BlinkingLightProperty_Create,args,kwargs)
    if val: val = BlinkingLightPropertyPtr(val)
    return val

def ObjectEmitterProperty_Cast(*args, **kwargs):
    val = apply(Appc.ObjectEmitterProperty_Cast,args,kwargs)
    if val: val = ObjectEmitterPropertyPtr(val)
    return val

def ObjectEmitterProperty_Create(*args, **kwargs):
    val = apply(Appc.ObjectEmitterProperty_Create,args,kwargs)
    if val: val = ObjectEmitterPropertyPtr(val)
    return val

def MultiplayerGame_Cast(*args, **kwargs):
    val = apply(Appc.MultiplayerGame_Cast,args,kwargs)
    if val: val = MultiplayerGamePtr(val)
    return val

def MultiplayerGame_Create(*args, **kwargs):
    val = apply(Appc.MultiplayerGame_Create,args,kwargs)
    if val: val = MultiplayerGamePtr(val)
    return val

def ServerListEvent_Create(*args, **kwargs):
    val = apply(Appc.ServerListEvent_Create,args,kwargs)
    if val: val = ServerListEventPtr(val)
    return val

def SortServerListEvent_Create(*args, **kwargs):
    val = apply(Appc.SortServerListEvent_Create,args,kwargs)
    if val: val = SortServerListEventPtr(val)
    return val



#-------------- VARIABLE WRAPPERS ------------------

UTOPIA_MAJOR_VERSION_NUMBER = Appc.UTOPIA_MAJOR_VERSION_NUMBER
UTOPIA_MINOR_VERSION_NUMBER = Appc.UTOPIA_MINOR_VERSION_NUMBER
CT_TEMP_TYPE = Appc.CT_TEMP_TYPE
CT_BASE_OBJECT = Appc.CT_BASE_OBJECT
CT_OBJECT = Appc.CT_OBJECT
CT_PLANET = Appc.CT_PLANET
CT_SUN = Appc.CT_SUN
CT_PHYSICS_OBJECT = Appc.CT_PHYSICS_OBJECT
CT_DAMAGEABLE_OBJECT = Appc.CT_DAMAGEABLE_OBJECT
CT_SHIP = Appc.CT_SHIP
CT_TORPEDO = Appc.CT_TORPEDO
CT_DEBRIS = Appc.CT_DEBRIS
CT_BACKDROP = Appc.CT_BACKDROP
CT_BACKDROP_SPHERE = Appc.CT_BACKDROP_SPHERE
CT_STAR_SPHERE = Appc.CT_STAR_SPHERE
CT_NEBULA = Appc.CT_NEBULA
CT_META_NEBULA = Appc.CT_META_NEBULA
CT_RETICLE = Appc.CT_RETICLE
CT_OBJECT_GROUP = Appc.CT_OBJECT_GROUP
CT_OBJECT_GROUP_WITH_INFO = Appc.CT_OBJECT_GROUP_WITH_INFO
CT_WARP_FLASH = Appc.CT_WARP_FLASH
CT_ASTEROID_FIELD = Appc.CT_ASTEROID_FIELD
CT_ASTEROID_TILE = Appc.CT_ASTEROID_TILE
CT_CHARACTER = Appc.CT_CHARACTER
CT_CHARACTER_SPEAKING_QUEUE = Appc.CT_CHARACTER_SPEAKING_QUEUE
CT_CHARACTER_ACTION = Appc.CT_CHARACTER_ACTION
CT_BRIDGE_OBJECT = Appc.CT_BRIDGE_OBJECT
CT_VIEWSCREEN = Appc.CT_VIEWSCREEN
CT_SHIP_SUBSYSTEM = Appc.CT_SHIP_SUBSYSTEM
CT_POWERED_SUBSYSTEM = Appc.CT_POWERED_SUBSYSTEM
CT_WEAPON_SYSTEM = Appc.CT_WEAPON_SYSTEM
CT_TORPEDO_SYSTEM = Appc.CT_TORPEDO_SYSTEM
CT_PHASER_SYSTEM = Appc.CT_PHASER_SYSTEM
CT_PULSE_WEAPON_SYSTEM = Appc.CT_PULSE_WEAPON_SYSTEM
CT_TRACTOR_BEAM_SYSTEM = Appc.CT_TRACTOR_BEAM_SYSTEM
CT_POWER_SUBSYSTEM = Appc.CT_POWER_SUBSYSTEM
CT_SENSOR_SUBSYSTEM = Appc.CT_SENSOR_SUBSYSTEM
CT_CLOAKING_SUBSYSTEM = Appc.CT_CLOAKING_SUBSYSTEM
CT_WARP_ENGINE_SUBSYSTEM = Appc.CT_WARP_ENGINE_SUBSYSTEM
CT_IMPULSE_ENGINE_SUBSYSTEM = Appc.CT_IMPULSE_ENGINE_SUBSYSTEM
CT_HULL_SUBSYSTEM = Appc.CT_HULL_SUBSYSTEM
CT_SHIELD_SUBSYSTEM = Appc.CT_SHIELD_SUBSYSTEM
CT_REPAIR_SUBSYSTEM = Appc.CT_REPAIR_SUBSYSTEM
CT_WEAPON = Appc.CT_WEAPON
CT_ENERGY_WEAPON = Appc.CT_ENERGY_WEAPON
CT_PHASER_BANK = Appc.CT_PHASER_BANK
CT_PULSE_WEAPON = Appc.CT_PULSE_WEAPON
CT_TRACTOR_BEAM_PROJECTOR = Appc.CT_TRACTOR_BEAM_PROJECTOR
CT_TORPEDO_TUBE = Appc.CT_TORPEDO_TUBE
CT_AI = Appc.CT_AI
CT_PLAIN_AI = Appc.CT_PLAIN_AI
CT_PRIORITY_LIST_AI = Appc.CT_PRIORITY_LIST_AI
CT_SEQUENCE_AI = Appc.CT_SEQUENCE_AI
CT_PREPROCESSING_AI = Appc.CT_PREPROCESSING_AI
CT_CONDITIONAL_AI = Appc.CT_CONDITIONAL_AI
CT_CONDITION = Appc.CT_CONDITION
CT_CONDITION_SCRIPT = Appc.CT_CONDITION_SCRIPT
CT_CONDITION_EVENT_CREATOR = Appc.CT_CONDITION_EVENT_CREATOR
CT_SHIP_STATUS_WINDOW = Appc.CT_SHIP_STATUS_WINDOW
CT_OST_EVENT_HANDLER = Appc.CT_OST_EVENT_HANDLER
CT_OPTIMIZED_AI_FIRST = Appc.CT_OPTIMIZED_AI_FIRST
CT_OPTIMIZED_AI_LAST = Appc.CT_OPTIMIZED_AI_LAST
CT_LIGHT_OBJECT = Appc.CT_LIGHT_OBJECT
CT_PULSING_LIGHT = Appc.CT_PULSING_LIGHT
CT_CAMERA_OBJECT = Appc.CT_CAMERA_OBJECT
CT_SPACE_CAMERA = Appc.CT_SPACE_CAMERA
CT_ZOOM_CAMERA_OBJECT = Appc.CT_ZOOM_CAMERA_OBJECT
CT_VIEWSCREEN_CAMERA = Appc.CT_VIEWSCREEN_CAMERA
CT_CAMERA_MODE = Appc.CT_CAMERA_MODE
CT_IDEAL_CONTROLLED_CAMERA_MODE = Appc.CT_IDEAL_CONTROLLED_CAMERA_MODE
CT_CHASE_CAMERA_MODE = Appc.CT_CHASE_CAMERA_MODE
CT_TARGET_CAMERA_MODE = Appc.CT_TARGET_CAMERA_MODE
CT_ZOOM_TARGET_MODE = Appc.CT_ZOOM_TARGET_MODE
CT_MAP_CAMERA_MODE = Appc.CT_MAP_CAMERA_MODE
CT_DROP_AND_WATCH_MODE = Appc.CT_DROP_AND_WATCH_MODE
CT_PLACEMENT_WATCH_MODE = Appc.CT_PLACEMENT_WATCH_MODE
CT_LOCKED_POSITION_MODE = Appc.CT_LOCKED_POSITION_MODE
CT_TORP_CAMERA_MODE = Appc.CT_TORP_CAMERA_MODE
CT_PLACE_BY_DIRECTION_MODE = Appc.CT_PLACE_BY_DIRECTION_MODE
CT_SCRIPT_OBJECT = Appc.CT_SCRIPT_OBJECT
CT_GAME = Appc.CT_GAME
CT_EPISODE = Appc.CT_EPISODE
CT_MISSION = Appc.CT_MISSION
CT_SET = Appc.CT_SET
CT_BRIDGE_SET = Appc.CT_BRIDGE_SET
CT_WARP_SET = Appc.CT_WARP_SET
CT_MULTIPLAYER_GAME = Appc.CT_MULTIPLAYER_GAME
CT_MULTIPLAYER_WINDOW = Appc.CT_MULTIPLAYER_WINDOW
CT_NET_FILE = Appc.CT_NET_FILE
CT_GAMESPY = Appc.CT_GAMESPY
CT_SERVER_LIST_EVENT = Appc.CT_SERVER_LIST_EVENT
CT_SORT_SERVER_LIST_EVENT = Appc.CT_SORT_SERVER_LIST_EVENT
CT_EDITOR = Appc.CT_EDITOR
CT_PLACEMENT_EDITOR = Appc.CT_PLACEMENT_EDITOR
CT_SUB_EDITOR = Appc.CT_SUB_EDITOR
CT_BACKGROUND_EDITOR = Appc.CT_BACKGROUND_EDITOR
CT_PLACEMENT = Appc.CT_PLACEMENT
CT_ASTEROID_FIELD_PLACEMENT = Appc.CT_ASTEROID_FIELD_PLACEMENT
CT_WAYPOINT = Appc.CT_WAYPOINT
CT_LIGHT_PLACEMENT = Appc.CT_LIGHT_PLACEMENT
CT_GRID = Appc.CT_GRID
CT_ST_MENU = Appc.CT_ST_MENU
CT_ST_TOP_LEVEL_MENU = Appc.CT_ST_TOP_LEVEL_MENU
CT_ST_CHARACTER_MENU = Appc.CT_ST_CHARACTER_MENU
CT_ST_FILE_MENU = Appc.CT_ST_FILE_MENU
CT_ST_FILE_DIALOG = Appc.CT_ST_FILE_DIALOG
CT_ST_LOAD_DIALOG = Appc.CT_ST_LOAD_DIALOG
CT_ST_SAVE_DIALOG = Appc.CT_ST_SAVE_DIALOG
CT_ST_SUB_PANE = Appc.CT_ST_SUB_PANE
CT_ST_TARGET_MENU_SUB_PANE = Appc.CT_ST_TARGET_MENU_SUB_PANE
CT_ST_BUTTON = Appc.CT_ST_BUTTON
CT_ST_ROUNDED_BUTTON = Appc.CT_ST_ROUNDED_BUTTON
CT_ST_REPAIR_BUTTON = Appc.CT_ST_REPAIR_BUTTON
CT_ST_TOGGLE = Appc.CT_ST_TOGGLE
CT_ST_FILL_GAUGE = Appc.CT_ST_FILL_GAUGE
CT_ST_NUMERIC_BAR = Appc.CT_ST_NUMERIC_BAR
CT_ST_TARGET_MENU = Appc.CT_ST_TARGET_MENU
CT_ST_SUBSYSTEM_MENU = Appc.CT_ST_SUBSYSTEM_MENU
CT_ST_COMPONENT_MENU = Appc.CT_ST_COMPONENT_MENU
CT_ST_COMPONENT_MENU_ITEM = Appc.CT_ST_COMPONENT_MENU_ITEM
CT_ST_CHECKBOX = Appc.CT_ST_CHECKBOX
CT_ST_STYLIZED_WINDOW = Appc.CT_ST_STYLIZED_WINDOW
CT_ST_MISSION_LOG = Appc.CT_ST_MISSION_LOG
CT_ST_KEYBOARD_REMAPPING = Appc.CT_ST_KEYBOARD_REMAPPING
CT_ST_TILED_ICON = Appc.CT_ST_TILED_ICON
CT_CHANGE_RENDERED_SET_ACTION = Appc.CT_CHANGE_RENDERED_SET_ACTION
CT_SORTED_REGION_MENU = Appc.CT_SORTED_REGION_MENU
CT_ST_WARP_BUTTON = Appc.CT_ST_WARP_BUTTON
CT_WARP_SEQUENCE = Appc.CT_WARP_SEQUENCE
CT_SHIELDS_DISPLAY = Appc.CT_SHIELDS_DISPLAY
CT_DAMAGE_DISPLAY = Appc.CT_DAMAGE_DISPLAY
CT_DAMAGE_ICON = Appc.CT_DAMAGE_ICON
CT_WEAPONS_DISPLAY = Appc.CT_WEAPONS_DISPLAY
CT_RADAR_DISPLAY = Appc.CT_RADAR_DISPLAY
CT_RADAR_SCOPE = Appc.CT_RADAR_SCOPE
CT_RADAR_BLIP = Appc.CT_RADAR_BLIP
CT_TAC_WEAPONS_CTRL = Appc.CT_TAC_WEAPONS_CTRL
CT_ENG_POWER_CTRL = Appc.CT_ENG_POWER_CTRL
CT_ENG_POWER_DISPLAY = Appc.CT_ENG_POWER_DISPLAY
CT_ENG_REPAIR_PANE = Appc.CT_ENG_REPAIR_PANE
CT_RETICLE_MANAGER_WINDOW = Appc.CT_RETICLE_MANAGER_WINDOW
CT_RETICLE_WINDOW = Appc.CT_RETICLE_WINDOW
CT_PLAYER_RETICLE_WINDOW = Appc.CT_PLAYER_RETICLE_WINDOW
CT_NAMED_RETICLE_WINDOW = Appc.CT_NAMED_RETICLE_WINDOW
CT_TOP_WINDOW = Appc.CT_TOP_WINDOW
CT_MAIN_WINDOW = Appc.CT_MAIN_WINDOW
CT_BRIDGE_WINDOW = Appc.CT_BRIDGE_WINDOW
CT_TACTICAL_WINDOW = Appc.CT_TACTICAL_WINDOW
CT_TACTICAL_CONTROL_WINDOW = Appc.CT_TACTICAL_CONTROL_WINDOW
CT_CONSOLE_WINDOW = Appc.CT_CONSOLE_WINDOW
CT_OPTIONS_WINDOW = Appc.CT_OPTIONS_WINDOW
CT_SUBTITLE_WINDOW = Appc.CT_SUBTITLE_WINDOW
CT_MAP_MODE_WINDOW = Appc.CT_MAP_MODE_WINDOW
CT_CINEMATIC_WINDOW = Appc.CT_CINEMATIC_WINDOW
CT_GRAPHICS_MENU_MANAGER = Appc.CT_GRAPHICS_MENU_MANAGER
CT_CD_CHECK_WINDOW = Appc.CT_CD_CHECK_WINDOW
CT_CHARACTER_MENU_WINDOW = Appc.CT_CHARACTER_MENU_WINDOW
CT_MODAL_DIALOG_WINDOW = Appc.CT_MODAL_DIALOG_WINDOW
CT_SUBTITLE_ACTION = Appc.CT_SUBTITLE_ACTION
CT_SHIP_DISPLAY = Appc.CT_SHIP_DISPLAY
CT_VAR_MANAGER = Appc.CT_VAR_MANAGER
CT_SHIP_EVENT = Appc.CT_SHIP_EVENT
CT_WAYPOINT_EVENT = Appc.CT_WAYPOINT_EVENT
CT_SET_FLOAT_VAR_EVENT = Appc.CT_SET_FLOAT_VAR_EVENT
CT_EXIT_SET_EVENT = Appc.CT_EXIT_SET_EVENT
CT_SAY_LINE_EVENT = Appc.CT_SAY_LINE_EVENT
CT_COLLISION_EVENT = Appc.CT_COLLISION_EVENT
CT_PROXIMITY_CHECK = Appc.CT_PROXIMITY_CHECK
CT_PROXIMITY_EVENT = Appc.CT_PROXIMITY_EVENT
CT_WEAPON_HIT_EVENT = Appc.CT_WEAPON_HIT_EVENT
CT_START_FIRING_EVENT = Appc.CT_START_FIRING_EVENT
CT_OBJECT_EXPLODING_EVENT = Appc.CT_OBJECT_EXPLODING_EVENT
CT_WARP_EVENT = Appc.CT_WARP_EVENT
CT_SUBSYSTEM_PROPERTY = Appc.CT_SUBSYSTEM_PROPERTY
CT_POWERED_SUBSYSTEM_PROPERTY = Appc.CT_POWERED_SUBSYSTEM_PROPERTY
CT_POSITION_ORIENTATION_PROPERTY = Appc.CT_POSITION_ORIENTATION_PROPERTY
CT_SHIP_PROPERTY = Appc.CT_SHIP_PROPERTY
CT_WEAPON_SYSTEM_PROPERTY = Appc.CT_WEAPON_SYSTEM_PROPERTY
CT_WEAPON_PROPERTY = Appc.CT_WEAPON_PROPERTY
CT_ENERGY_WEAPON_PROPERTY = Appc.CT_ENERGY_WEAPON_PROPERTY
CT_PHASER_PROPERTY = Appc.CT_PHASER_PROPERTY
CT_TORPEDO_SYSTEM_PROPERTY = Appc.CT_TORPEDO_SYSTEM_PROPERTY
CT_TORPEDO_TUBE_PROPERTY = Appc.CT_TORPEDO_TUBE_PROPERTY
CT_PULSE_WEAPON_PROPERTY = Appc.CT_PULSE_WEAPON_PROPERTY
CT_TRACTOR_BEAM_PROPERTY = Appc.CT_TRACTOR_BEAM_PROPERTY
CT_SHIELD_PROPERTY = Appc.CT_SHIELD_PROPERTY
CT_HULL_PROPERTY = Appc.CT_HULL_PROPERTY
CT_SENSOR_PROPERTY = Appc.CT_SENSOR_PROPERTY
CT_CLOAKING_SUBSYSTEM_PROPERTY = Appc.CT_CLOAKING_SUBSYSTEM_PROPERTY
CT_WARP_ENGINE_PROPERTY = Appc.CT_WARP_ENGINE_PROPERTY
CT_IMPULSE_ENGINE_PROPERTY = Appc.CT_IMPULSE_ENGINE_PROPERTY
CT_ENGINE_PROPERTY = Appc.CT_ENGINE_PROPERTY
CT_POWER_PROPERTY = Appc.CT_POWER_PROPERTY
CT_REPAIR_SUBSYSTEM_PROPERTY = Appc.CT_REPAIR_SUBSYSTEM_PROPERTY
CT_ENGINE_GLOW_PROPERTY = Appc.CT_ENGINE_GLOW_PROPERTY
CT_EFFECT_EMITTER_PROPERTY = Appc.CT_EFFECT_EMITTER_PROPERTY
CT_SMOKE_EMITTER_PROPERTY = Appc.CT_SMOKE_EMITTER_PROPERTY
CT_SPARK_EMITTER_PROPERTY = Appc.CT_SPARK_EMITTER_PROPERTY
CT_EXPLODE_EMITTER_PROPERTY = Appc.CT_EXPLODE_EMITTER_PROPERTY
CT_BLINKING_LIGHT_PROPERTY = Appc.CT_BLINKING_LIGHT_PROPERTY
CT_OBJECT_EMITTER_PROPERTY = Appc.CT_OBJECT_EMITTER_PROPERTY
CT_CHAT_OBJECT = Appc.CT_CHAT_OBJECT
ET_TEMP_TYPE = Appc.ET_TEMP_TYPE
ET_QUIT = Appc.ET_QUIT
ET_SET_LOAD_FILE = Appc.ET_SET_LOAD_FILE
ET_CANCEL_LOAD = Appc.ET_CANCEL_LOAD
ET_NEW_GAME = Appc.ET_NEW_GAME
ET_LOAD_GAME = Appc.ET_LOAD_GAME
ET_SAVE_GAME = Appc.ET_SAVE_GAME
ET_QUICK_SAVE = Appc.ET_QUICK_SAVE
ET_QUICK_LOAD = Appc.ET_QUICK_LOAD
ET_GAME_SAVED = Appc.ET_GAME_SAVED
ET_GAME_LOADED = Appc.ET_GAME_LOADED
ET_LOAD_EPISODE = Appc.ET_LOAD_EPISODE
ET_LOAD_MISSION = Appc.ET_LOAD_MISSION
ET_SET_PLAYER = Appc.ET_SET_PLAYER
ET_OBJECT_DELETED = Appc.ET_OBJECT_DELETED
ET_OBJECT_GROUP_CHANGED = Appc.ET_OBJECT_GROUP_CHANGED
ET_OBJECT_GROUP_OBJECT_ENTERED_SET = Appc.ET_OBJECT_GROUP_OBJECT_ENTERED_SET
ET_OBJECT_GROUP_OBJECT_EXITED_SET = Appc.ET_OBJECT_GROUP_OBJECT_EXITED_SET
ET_OBJECT_GROUP_OBJECT_DESTROYED = Appc.ET_OBJECT_GROUP_OBJECT_DESTROYED
ET_EPISODE_START = Appc.ET_EPISODE_START
ET_MISSION_START = Appc.ET_MISSION_START
ET_AI_DONE = Appc.ET_AI_DONE
ET_AI_DORMANT = Appc.ET_AI_DORMANT
ET_AI_REACHED_WAYPOINT = Appc.ET_AI_REACHED_WAYPOINT
ET_AI_END_FIRING_RUN = Appc.ET_AI_END_FIRING_RUN
ET_AI_INTERNAL_PROX_EVENT = Appc.ET_AI_INTERNAL_PROX_EVENT
ET_AI_INTERNAL_DELETE_EVENT = Appc.ET_AI_INTERNAL_DELETE_EVENT
ET_SHIP_STATUS_UPDATE = Appc.ET_SHIP_STATUS_UPDATE
ET_AI_CONDITION_CHANGED = Appc.ET_AI_CONDITION_CHANGED
ET_AI_SHIELD_WATCHER = Appc.ET_AI_SHIELD_WATCHER
ET_AI_SYSTEM_STATUS_WATCHER = Appc.ET_AI_SYSTEM_STATUS_WATCHER
ET_AI_TIMER = Appc.ET_AI_TIMER
ET_AI_WARP_DONE = Appc.ET_AI_WARP_DONE
ET_AI_ORBITTING = Appc.ET_AI_ORBITTING
ET_PLAYER_DOCKED_WITH_STARBASE = Appc.ET_PLAYER_DOCKED_WITH_STARBASE
ET_AI_FINISHED_BUILDING = Appc.ET_AI_FINISHED_BUILDING
ET_CONDITION_ATK_FORGIVE = Appc.ET_CONDITION_ATK_FORGIVE
ET_CONDITION_ATK_REMOVE_DAMAGE = Appc.ET_CONDITION_ATK_REMOVE_DAMAGE
ET_CONDITION_FIPSS_TIMER = Appc.ET_CONDITION_FIPSS_TIMER
ET_MUSIC_CONDITION_CHANGED = Appc.ET_MUSIC_CONDITION_CHANGED
ET_PLAY_ANIMATION_EVENT_TYPE = Appc.ET_PLAY_ANIMATION_EVENT_TYPE
ET_SET_FLOAT_VAR = Appc.ET_SET_FLOAT_VAR
ET_RANDOM_ANIMATION_DONE = Appc.ET_RANDOM_ANIMATION_DONE
ET_REPORT = Appc.ET_REPORT
ET_COMMUNICATE = Appc.ET_COMMUNICATE
ET_OBJECTIVES = Appc.ET_OBJECTIVES
ET_SET_COURSE = Appc.ET_SET_COURSE
ET_ORBIT_PLANET = Appc.ET_ORBIT_PLANET
ET_DOCK = Appc.ET_DOCK
ET_SCAN = Appc.ET_SCAN
ET_LAUNCH_PROBE = Appc.ET_LAUNCH_PROBE
ET_HAIL = Appc.ET_HAIL
ET_MANEUVER = Appc.ET_MANEUVER
ET_FIRE = Appc.ET_FIRE
ET_CANT_FIRE = Appc.ET_CANT_FIRE
ET_SET_ALERT_LEVEL = Appc.ET_SET_ALERT_LEVEL
ET_DAMAGE_REPORT = Appc.ET_DAMAGE_REPORT
ET_SB12_REPAIR = Appc.ET_SB12_REPAIR
ET_SB12_RELOAD = Appc.ET_SB12_RELOAD
ET_ALL_STOP = Appc.ET_ALL_STOP
ET_CONTACT_STARFLEET = Appc.ET_CONTACT_STARFLEET
ET_CONTACT_ENGINEERING = Appc.ET_CONTACT_ENGINEERING
ET_SHOW_MISSION_LOG = Appc.ET_SHOW_MISSION_LOG
ET_TACTICAL_SHIELD_LEVEL_CHANGE = Appc.ET_TACTICAL_SHIELD_LEVEL_CHANGE
ET_TACTICAL_SHIELD_0_LEVEL_CHANGE = Appc.ET_TACTICAL_SHIELD_0_LEVEL_CHANGE
ET_TACTICAL_SHIELD_1_LEVEL_CHANGE = Appc.ET_TACTICAL_SHIELD_1_LEVEL_CHANGE
ET_TACTICAL_SHIELD_2_LEVEL_CHANGE = Appc.ET_TACTICAL_SHIELD_2_LEVEL_CHANGE
ET_TACTICAL_SHIELD_3_LEVEL_CHANGE = Appc.ET_TACTICAL_SHIELD_3_LEVEL_CHANGE
ET_TACTICAL_SHIELD_4_LEVEL_CHANGE = Appc.ET_TACTICAL_SHIELD_4_LEVEL_CHANGE
ET_TACTICAL_SHIELD_5_LEVEL_CHANGE = Appc.ET_TACTICAL_SHIELD_5_LEVEL_CHANGE
ET_TACTICAL_HULL_LEVEL_CHANGE = Appc.ET_TACTICAL_HULL_LEVEL_CHANGE
ET_MAIN_BATTERY_LEVEL_CHANGE = Appc.ET_MAIN_BATTERY_LEVEL_CHANGE
ET_BACKUP_BATTERY_LEVEL_CHANGE = Appc.ET_BACKUP_BATTERY_LEVEL_CHANGE
ET_CHARACTER_ANIMATION_DONE = Appc.ET_CHARACTER_ANIMATION_DONE
ET_CHARACTER_SOUND_DONE = Appc.ET_CHARACTER_SOUND_DONE
ET_CHARACTER_MENU = Appc.ET_CHARACTER_MENU
ET_CAMERA_ANIMATION_DONE = Appc.ET_CAMERA_ANIMATION_DONE
ET_OBJECT_EXPLODING = Appc.ET_OBJECT_EXPLODING
ET_OBJECT_DESTROYED = Appc.ET_OBJECT_DESTROYED
ET_OBJECT_COLLISION = Appc.ET_OBJECT_COLLISION
ET_SHIELD_COLLISION = Appc.ET_SHIELD_COLLISION
ET_PLANET_COLLISION = Appc.ET_PLANET_COLLISION
ET_CLOAKED_COLLISION = Appc.ET_CLOAKED_COLLISION
ET_PLANET_ATMOSPHERE_COLLISION = Appc.ET_PLANET_ATMOSPHERE_COLLISION
ET_DEAD_OBJECT_REMOVAL_CHECK = Appc.ET_DEAD_OBJECT_REMOVAL_CHECK
ET_OBJECT_CONVERTED_TO_HULK = Appc.ET_OBJECT_CONVERTED_TO_HULK
ET_ENVIRONMENT_DAMAGE = Appc.ET_ENVIRONMENT_DAMAGE
ET_TARGET_WAS_CHANGED = Appc.ET_TARGET_WAS_CHANGED
ET_TARGET_OFFSET_CHANGED = Appc.ET_TARGET_OFFSET_CHANGED
ET_TARGETED_SUBSYSTEM_CHANGED = Appc.ET_TARGETED_SUBSYSTEM_CHANGED
ET_RESTORE_PERSISTENT_TARGET = Appc.ET_RESTORE_PERSISTENT_TARGET
ET_TORPEDO_ENTERED_SET = Appc.ET_TORPEDO_ENTERED_SET
ET_ENTERED_SET = Appc.ET_ENTERED_SET
ET_TORPEDO_EXITED_SET = Appc.ET_TORPEDO_EXITED_SET
ET_EXITED_SET = Appc.ET_EXITED_SET
ET_ENTERED_NEBULA = Appc.ET_ENTERED_NEBULA
ET_EXITED_NEBULA = Appc.ET_EXITED_NEBULA
ET_PROXIMITY_ASTEROID_FIELD = Appc.ET_PROXIMITY_ASTEROID_FIELD
ET_PROXIMITY_PLANET = Appc.ET_PROXIMITY_PLANET
ET_WEAPON_HIT = Appc.ET_WEAPON_HIT
ET_TORPEDO_RELOAD = Appc.ET_TORPEDO_RELOAD
ET_TORPEDO_FIRED = Appc.ET_TORPEDO_FIRED
ET_PLAYER_TORPEDO_COUNT_CHANGED = Appc.ET_PLAYER_TORPEDO_COUNT_CHANGED
ET_PLAYER_TORPEDO_TYPE_CHANGED = Appc.ET_PLAYER_TORPEDO_TYPE_CHANGED
ET_WEAPON_CHARGE_UPDATED = Appc.ET_WEAPON_CHARGE_UPDATED
ET_WEAPON_DISPLAY_REFRESH_TIMER = Appc.ET_WEAPON_DISPLAY_REFRESH_TIMER
ET_SUBSYSTEM_DAMAGED = Appc.ET_SUBSYSTEM_DAMAGED
ET_SUBSYSTEM_STATE_CHANGED = Appc.ET_SUBSYSTEM_STATE_CHANGED
ET_SUBSYSTEM_DISABLED = Appc.ET_SUBSYSTEM_DISABLED
ET_SUBSYSTEM_OPERATIONAL = Appc.ET_SUBSYSTEM_OPERATIONAL
ET_SUBSYSTEM_DESTROYED = Appc.ET_SUBSYSTEM_DESTROYED
ET_SUBSYSTEM_REBUILT = Appc.ET_SUBSYSTEM_REBUILT
ET_SUBSYSTEM_COMPLETELY_DESTROYED = Appc.ET_SUBSYSTEM_COMPLETELY_DESTROYED
ET_SUBSYSTEM_COMPLETELY_DISABLED = Appc.ET_SUBSYSTEM_COMPLETELY_DISABLED
ET_SUBSYSTEM_PARTIALLY_OPERATIONAL = Appc.ET_SUBSYSTEM_PARTIALLY_OPERATIONAL
ET_REPAIR_COMPLETED = Appc.ET_REPAIR_COMPLETED
ET_REPAIR_CANNOT_BE_COMPLETED = Appc.ET_REPAIR_CANNOT_BE_COMPLETED
ET_REPAIR_INCREASE_PRIORITY = Appc.ET_REPAIR_INCREASE_PRIORITY
ET_CLOAK_BEGINNING = Appc.ET_CLOAK_BEGINNING
ET_CLOAK_COMPLETED = Appc.ET_CLOAK_COMPLETED
ET_DECLOAK_BEGINNING = Appc.ET_DECLOAK_BEGINNING
ET_DECLOAK_COMPLETED = Appc.ET_DECLOAK_COMPLETED
ET_SHIELDS_SET_STATE = Appc.ET_SHIELDS_SET_STATE
ET_WEAPON_FIRED = Appc.ET_WEAPON_FIRED
ET_TRACTOR_BEAM_STARTED_FIRING = Appc.ET_TRACTOR_BEAM_STARTED_FIRING
ET_TRACTOR_BEAM_STARTED_HITTING = Appc.ET_TRACTOR_BEAM_STARTED_HITTING
ET_TRACTOR_BEAM_STOPPED_FIRING = Appc.ET_TRACTOR_BEAM_STOPPED_FIRING
ET_TRACTOR_BEAM_STOPPED_HITTING = Appc.ET_TRACTOR_BEAM_STOPPED_HITTING
ET_PHASER_STARTED_FIRING = Appc.ET_PHASER_STARTED_FIRING
ET_PHASER_STARTED_HITTING = Appc.ET_PHASER_STARTED_HITTING
ET_PHASER_STOPPED_FIRING = Appc.ET_PHASER_STOPPED_FIRING
ET_PHASER_STOPPED_HITTING = Appc.ET_PHASER_STOPPED_HITTING
ET_TRACTOR_TARGET_DOCKED = Appc.ET_TRACTOR_TARGET_DOCKED
ET_TORPEDO_START_HOMING = Appc.ET_TORPEDO_START_HOMING
ET_SENSORS_RANGE_CHANGED = Appc.ET_SENSORS_RANGE_CHANGED
ET_SENSORS_SHIP_IDENTIFIED = Appc.ET_SENSORS_SHIP_IDENTIFIED
ET_SENSORS_SHIP_NEAR_PROXIMITY = Appc.ET_SENSORS_SHIP_NEAR_PROXIMITY
ET_SENSORS_SHIP_FAR_PROXIMITY = Appc.ET_SENSORS_SHIP_FAR_PROXIMITY
ET_SENSORS_PERIODIC_SCAN = Appc.ET_SENSORS_PERIODIC_SCAN
ET_SUBSYSTEM_POWER_CHANGED = Appc.ET_SUBSYSTEM_POWER_CHANGED
ET_POWER_CONTROL_REFRESH_TIMER = Appc.ET_POWER_CONTROL_REFRESH_TIMER
ET_POWER_DISPLAY_REFRESH_TIMER = Appc.ET_POWER_DISPLAY_REFRESH_TIMER
ET_POWER_CONTROL_ARROW = Appc.ET_POWER_CONTROL_ARROW
ET_MANAGE_POWER = Appc.ET_MANAGE_POWER
ET_UI_SWITCH_ICON_GROUPS = Appc.ET_UI_SWITCH_ICON_GROUPS
ET_UI_RESIZE = Appc.ET_UI_RESIZE
ET_UI_REPOSITION = Appc.ET_UI_REPOSITION
ET_ST_MINIMIZE = Appc.ET_ST_MINIMIZE
ET_ST_BUTTON_CLICKED = Appc.ET_ST_BUTTON_CLICKED
ET_ST_SCROLL = Appc.ET_ST_SCROLL
ET_ST_PERIODIC_SCROLL_UP = Appc.ET_ST_PERIODIC_SCROLL_UP
ET_ST_PERIODIC_SCROLL_DOWN = Appc.ET_ST_PERIODIC_SCROLL_DOWN
ET_ST_FILE_DIALOG_DONE = Appc.ET_ST_FILE_DIALOG_DONE
ET_ST_FILE_DIALOG_FILE_CHOSEN = Appc.ET_ST_FILE_DIALOG_FILE_CHOSEN
ET_ST_FILE_DIALOG_DELETE = Appc.ET_ST_FILE_DIALOG_DELETE
ET_ST_FILE_DIALOG_DELETE2 = Appc.ET_ST_FILE_DIALOG_DELETE2
ET_ST_SAVE_DIALOG_SAVE = Appc.ET_ST_SAVE_DIALOG_SAVE
ET_ST_LOAD_DIALOG_LOAD = Appc.ET_ST_LOAD_DIALOG_LOAD
ET_RADAR_TOGGLE_CLICKED = Appc.ET_RADAR_TOGGLE_CLICKED
ET_TARGET_LIST_CLICKED = Appc.ET_TARGET_LIST_CLICKED
ET_TARGET_LIST_PERIODIC_UPDATE = Appc.ET_TARGET_LIST_PERIODIC_UPDATE
ET_TARGET_LIST_OBJECT_ADDED = Appc.ET_TARGET_LIST_OBJECT_ADDED
ET_TARGET_LIST_OBJECT_REMOVED = Appc.ET_TARGET_LIST_OBJECT_REMOVED
ET_MAP_WINDOW_PERIODIC_UPDATE = Appc.ET_MAP_WINDOW_PERIODIC_UPDATE
ET_SUBSYSTEM_LIST_CLICKED = Appc.ET_SUBSYSTEM_LIST_CLICKED
ET_COMPONENT_LIST_CLICKED = Appc.ET_COMPONENT_LIST_CLICKED
ET_SHIELD_LEVEL_CHANGE = Appc.ET_SHIELD_LEVEL_CHANGE
ET_RADAR_DISPLAY_OBJECT_UPDATE = Appc.ET_RADAR_DISPLAY_OBJECT_UPDATE
ET_RADAR_DISPLAY_RANGE_TOGGLE_CLICKED = Appc.ET_RADAR_DISPLAY_RANGE_TOGGLE_CLICKED
ET_RADAR_DISPLAY_BRACKET_EXPIRE = Appc.ET_RADAR_DISPLAY_BRACKET_EXPIRE
ET_RADAR_DISPLAY_BLIP_CLICKED = Appc.ET_RADAR_DISPLAY_BLIP_CLICKED
ET_PHASER_INTENSITY_TOGGLE_CLICKED = Appc.ET_PHASER_INTENSITY_TOGGLE_CLICKED
ET_TORP_TYPE_TOGGLE_CLICKED = Appc.ET_TORP_TYPE_TOGGLE_CLICKED
ET_TORP_SPREAD_TOGGLE_CLICKED = Appc.ET_TORP_SPREAD_TOGGLE_CLICKED
ET_OTHER_BEAM_TOGGLE_CLICKED = Appc.ET_OTHER_BEAM_TOGGLE_CLICKED
ET_OTHER_CLOAK_TOGGLE_CLICKED = Appc.ET_OTHER_CLOAK_TOGGLE_CLICKED
ET_TIMER_CLOAK_TOGGLE_REFRESH = Appc.ET_TIMER_CLOAK_TOGGLE_REFRESH
ET_DAMAGE_ICON_EXPIRE = Appc.ET_DAMAGE_ICON_EXPIRE
ET_DAMAGE_ICON_BLINK = Appc.ET_DAMAGE_ICON_BLINK
ET_DAMAGE_DISPLAY_REFRESH = Appc.ET_DAMAGE_DISPLAY_REFRESH
ET_GRAPHICS_DEVICE_CHANGE = Appc.ET_GRAPHICS_DEVICE_CHANGE
ET_GRAPHICS_RESOLUTION_CHANGE = Appc.ET_GRAPHICS_RESOLUTION_CHANGE
ET_GRAPHICS_RESOLUTION_CHANGE_STAGE2 = Appc.ET_GRAPHICS_RESOLUTION_CHANGE_STAGE2
ET_GRAPHICS_RESOLUTION_CHANGE_STAGE3 = Appc.ET_GRAPHICS_RESOLUTION_CHANGE_STAGE3
ET_GRAPHICS_RESOLUTION_CHANGE_STAGE4 = Appc.ET_GRAPHICS_RESOLUTION_CHANGE_STAGE4
ET_GRAPHICS_RESOLUTION_REVERT = Appc.ET_GRAPHICS_RESOLUTION_REVERT
ET_GRAPHICS_BUTTON_CLICKED = Appc.ET_GRAPHICS_BUTTON_CLICKED
ET_EDITOR_MENU = Appc.ET_EDITOR_MENU
ET_PLACEMENT_MENU = Appc.ET_PLACEMENT_MENU
ET_PLACEMENT_LIGHT_CONFIG = Appc.ET_PLACEMENT_LIGHT_CONFIG
ET_ASTEROID_FIELD_CONFIG = Appc.ET_ASTEROID_FIELD_CONFIG
ET_BACKGROUND_MENU = Appc.ET_BACKGROUND_MENU
ET_NAV_POINT_CHANGED = Appc.ET_NAV_POINT_CHANGED
ET_WAYPOINT_CONFIG = Appc.ET_WAYPOINT_CONFIG
ET_SET_WAYPOINT_SPEED = Appc.ET_SET_WAYPOINT_SPEED
ET_SHIP_ACTION_AI_DELETED = Appc.ET_SHIP_ACTION_AI_DELETED
ET_EXITED_WARP = Appc.ET_EXITED_WARP
ET_NEW_MULTIPLAYER_GAME = Appc.ET_NEW_MULTIPLAYER_GAME
ET_WARP_BUTTON_PRESSED = Appc.ET_WARP_BUTTON_PRESSED
ET_OBJECT_CREATED = Appc.ET_OBJECT_CREATED
ET_OBJECT_CREATED_NOTIFY = Appc.ET_OBJECT_CREATED_NOTIFY
ET_CREATE_SERVER = Appc.ET_CREATE_SERVER
ET_CREATE_CLIENT = Appc.ET_CREATE_CLIENT
ET_CREATE_CLIENT_AND_SERVER = Appc.ET_CREATE_CLIENT_AND_SERVER
ET_CREATE_DIRECT_CLIENT = Appc.ET_CREATE_DIRECT_CLIENT
ET_OKAY = Appc.ET_OKAY
ET_CANCEL = Appc.ET_CANCEL
ET_EXIT_GAME = Appc.ET_EXIT_GAME
ET_EXIT_PROGRAM = Appc.ET_EXIT_PROGRAM
ET_LOCAL_INTERNET_HOST = Appc.ET_LOCAL_INTERNET_HOST
ET_START = Appc.ET_START
ET_SELECT_MISSION = Appc.ET_SELECT_MISSION
ET_CANCEL_BINDING = Appc.ET_CANCEL_BINDING
ET_CLEAR_BINDINGS = Appc.ET_CLEAR_BINDINGS
ET_START_FIRING = Appc.ET_START_FIRING
ET_START_FIRING_NOTIFY = Appc.ET_START_FIRING_NOTIFY
ET_STOP_FIRING = Appc.ET_STOP_FIRING
ET_STOP_FIRING_NOTIFY = Appc.ET_STOP_FIRING_NOTIFY
ET_STOP_FIRING_AT_TARGET = Appc.ET_STOP_FIRING_AT_TARGET
ET_STOP_FIRING_AT_TARGET_NOTIFY = Appc.ET_STOP_FIRING_AT_TARGET_NOTIFY
ET_SUBSYSTEM_STATE_CHANGED_NOTIFY = Appc.ET_SUBSYSTEM_STATE_CHANGED_NOTIFY
ET_ADD_TO_REPAIR_LIST_NOTIFY = Appc.ET_ADD_TO_REPAIR_LIST_NOTIFY
ET_ADD_TO_REPAIR_LIST = Appc.ET_ADD_TO_REPAIR_LIST
ET_SET_PHASER_LEVEL = Appc.ET_SET_PHASER_LEVEL
ET_SET_TARGET = Appc.ET_SET_TARGET
ET_START_CLOAKING_NOTIFY = Appc.ET_START_CLOAKING_NOTIFY
ET_START_CLOAKING = Appc.ET_START_CLOAKING
ET_STOP_CLOAKING_NOTIFY = Appc.ET_STOP_CLOAKING_NOTIFY
ET_STOP_CLOAKING = Appc.ET_STOP_CLOAKING
ET_CHECKSUM_COMPLETE = Appc.ET_CHECKSUM_COMPLETE
ET_SYSTEM_CHECKSUM_FAILED = Appc.ET_SYSTEM_CHECKSUM_FAILED
ET_SYSTEM_CHECKSUM_COMPLETE = Appc.ET_SYSTEM_CHECKSUM_COMPLETE
ET_KILL_GAME = Appc.ET_KILL_GAME
ET_END_GAME_OKAY = Appc.ET_END_GAME_OKAY
ET_CANCEL_CONNECT = Appc.ET_CANCEL_CONNECT
ET_START_WARP_NOTIFY = Appc.ET_START_WARP_NOTIFY
ET_START_WARP = Appc.ET_START_WARP
ET_SET_WARP_SEQUENCE = Appc.ET_SET_WARP_SEQUENCE
ET_IN_SYSTEM_WARP = Appc.ET_IN_SYSTEM_WARP
ET_SET_MISSION_NAME = Appc.ET_SET_MISSION_NAME
ET_NEW_PLAYER_IN_GAME = Appc.ET_NEW_PLAYER_IN_GAME
ET_SET_GAME_MODE = Appc.ET_SET_GAME_MODE
ET_SERVER_LIST_PERCENTAGE = Appc.ET_SERVER_LIST_PERCENTAGE
ET_SERVER_LIST_STATE = Appc.ET_SERVER_LIST_STATE
ET_SERVER_ENTRY_EVENT = Appc.ET_SERVER_ENTRY_EVENT
ET_PLAYER_BOOT_EVENT = Appc.ET_PLAYER_BOOT_EVENT
ET_REFRESH_SERVER_LIST = Appc.ET_REFRESH_SERVER_LIST
ET_REFRESH_SERVER_LIST_DONE = Appc.ET_REFRESH_SERVER_LIST_DONE
ET_SELECT_SERVER_ENTRY = Appc.ET_SELECT_SERVER_ENTRY
ET_SERVER_PLAYER_EVENT = Appc.ET_SERVER_PLAYER_EVENT
ET_SORT_SERVER_LIST = Appc.ET_SORT_SERVER_LIST
ET_HOST_OBJECT_COLLISION = Appc.ET_HOST_OBJECT_COLLISION
ET_NET_TORPEDO_TYPE_CHANGED = Appc.ET_NET_TORPEDO_TYPE_CHANGED
ET_NET_TORPEDO_TYPE_CHANGED_NOTIFY = Appc.ET_NET_TORPEDO_TYPE_CHANGED_NOTIFY
ET_RETRY_CONNECTION = Appc.ET_RETRY_CONNECTION
ET_REPORT_GOAL_INFO = Appc.ET_REPORT_GOAL_INFO
ET_RETRY_CD = Appc.ET_RETRY_CD
ET_ABORT_ATTEMPT = Appc.ET_ABORT_ATTEMPT
ET_SHOW_RETRY_DIALOG = Appc.ET_SHOW_RETRY_DIALOG
ET_FRIENDLY_FIRE_DAMAGE = Appc.ET_FRIENDLY_FIRE_DAMAGE
ET_FRIENDLY_FIRE_REPORT = Appc.ET_FRIENDLY_FIRE_REPORT
ET_FRIENDLY_TRACTOR_REPORT = Appc.ET_FRIENDLY_TRACTOR_REPORT
ET_FRIENDLY_FIRE_GAME_OVER = Appc.ET_FRIENDLY_FIRE_GAME_OVER
ET_HAILABLE_CHANGE = Appc.ET_HAILABLE_CHANGE
ET_NAME_CHANGE = Appc.ET_NAME_CHANGE
ET_SCANNABLE_CHANGE = Appc.ET_SCANNABLE_CHANGE
ET_SUBPANE_GIVE_FOCUS_FIRST_CHILD = Appc.ET_SUBPANE_GIVE_FOCUS_FIRST_CHILD
ET_FIRST_INPUT_EVENT = Appc.ET_FIRST_INPUT_EVENT
ET_LAST_INPUT_EVENT = Appc.ET_LAST_INPUT_EVENT
ET_FIRST_SCRIPT_EVENT = Appc.ET_FIRST_SCRIPT_EVENT
ET_FIRST_APP_SCRIPT_EVENT = Appc.ET_FIRST_APP_SCRIPT_EVENT
ET_LAST_APP_SCRIPT_EVENT = Appc.ET_LAST_APP_SCRIPT_EVENT
ET_FIRST_GAME_SCRIPT_EVENT = Appc.ET_FIRST_GAME_SCRIPT_EVENT
ET_LAST_GAME_SCRIPT_EVENT = Appc.ET_LAST_GAME_SCRIPT_EVENT
ET_FIRST_EPISODE_SCRIPT_EVENT = Appc.ET_FIRST_EPISODE_SCRIPT_EVENT
ET_LAST_EPISODE_SCRIPT_EVENT = Appc.ET_LAST_EPISODE_SCRIPT_EVENT
ET_FIRST_MISSION_SCRIPT_EVENT = Appc.ET_FIRST_MISSION_SCRIPT_EVENT
ET_LAST_MISSION_SCRIPT_EVENT = Appc.ET_LAST_MISSION_SCRIPT_EVENT
ET_LAST_SCRIPT_EVENT = Appc.ET_LAST_SCRIPT_EVENT
GENUS_UNKNOWN = Appc.GENUS_UNKNOWN
GENUS_SHIP = Appc.GENUS_SHIP
GENUS_STATION = Appc.GENUS_STATION
GENUS_ASTEROID = Appc.GENUS_ASTEROID
SPECIES_UNKNOWN = Appc.SPECIES_UNKNOWN
SPECIES_FEDERATION_START = Appc.SPECIES_FEDERATION_START
SPECIES_GALAXY = Appc.SPECIES_GALAXY
SPECIES_SOVEREIGN = Appc.SPECIES_SOVEREIGN
SPECIES_AKIRA = Appc.SPECIES_AKIRA
SPECIES_AMBASSADOR = Appc.SPECIES_AMBASSADOR
SPECIES_NEBULA = Appc.SPECIES_NEBULA
SPECIES_SHUTTLE = Appc.SPECIES_SHUTTLE
SPECIES_TRANSPORT = Appc.SPECIES_TRANSPORT
SPECIES_FREIGHTER = Appc.SPECIES_FREIGHTER
SPECIES_CARDASSIAN_START = Appc.SPECIES_CARDASSIAN_START
SPECIES_GALOR = Appc.SPECIES_GALOR
SPECIES_KELDON = Appc.SPECIES_KELDON
SPECIES_CARDFREIGHTER = Appc.SPECIES_CARDFREIGHTER
SPECIES_CARDHYBRID = Appc.SPECIES_CARDHYBRID
SPECIES_ROMULAN_START = Appc.SPECIES_ROMULAN_START
SPECIES_WARBIRD = Appc.SPECIES_WARBIRD
SPECIES_KLINGON_START = Appc.SPECIES_KLINGON_START
SPECIES_BIRD_OF_PREY = Appc.SPECIES_BIRD_OF_PREY
SPECIES_VORCHA = Appc.SPECIES_VORCHA
SPECIES_KESSOK_START = Appc.SPECIES_KESSOK_START
SPECIES_KESSOK_HEAVY = Appc.SPECIES_KESSOK_HEAVY
SPECIES_KESSOK_LIGHT = Appc.SPECIES_KESSOK_LIGHT
SPECIES_KESSOKMINE = Appc.SPECIES_KESSOKMINE
SPECIES_FERENGI_START = Appc.SPECIES_FERENGI_START
SPECIES_MARAUDER = Appc.SPECIES_MARAUDER
SPECIES_OTHER_START = Appc.SPECIES_OTHER_START
SPECIES_FED_STARBASE = Appc.SPECIES_FED_STARBASE
SPECIES_FED_OUTPOST = Appc.SPECIES_FED_OUTPOST
SPECIES_CARD_STARBASE = Appc.SPECIES_CARD_STARBASE
SPECIES_CARD_OUTPOST = Appc.SPECIES_CARD_OUTPOST
SPECIES_CARD_STATION = Appc.SPECIES_CARD_STATION
SPECIES_DRYDOCK = Appc.SPECIES_DRYDOCK
SPECIES_SPACE_FACILITY = Appc.SPECIES_SPACE_FACILITY
SPECIES_COMMARRAY = Appc.SPECIES_COMMARRAY
SPECIES_COMMLIGHT = Appc.SPECIES_COMMLIGHT
SPECIES_PROBE = Appc.SPECIES_PROBE
SPECIES_PROBETYPE2 = Appc.SPECIES_PROBETYPE2
SPECIES_ASTEROID = Appc.SPECIES_ASTEROID
SPECIES_SUNBUSTER = Appc.SPECIES_SUNBUSTER
SPECIES_ESCAPEPOD = Appc.SPECIES_ESCAPEPOD
SPECIES_BORG = Appc.SPECIES_BORG
TEAM_UNKNOWN = Appc.TEAM_UNKNOWN
TEAM_FEDERATION = Appc.TEAM_FEDERATION
TEAM_CARDASSIAN = Appc.TEAM_CARDASSIAN
TEAM_KLINGON = Appc.TEAM_KLINGON
TEAM_ROMULAN = Appc.TEAM_ROMULAN
TEAM_FERENGI = Appc.TEAM_FERENGI
TEAM_KESSOK = Appc.TEAM_KESSOK
TEAM_ALPHA = Appc.TEAM_ALPHA
TEAM_BETA = Appc.TEAM_BETA
TEAM_GAMMA = Appc.TEAM_GAMMA
TEAM_DELTA = Appc.TEAM_DELTA
CSP_MISSION_CRITICAL = Appc.CSP_MISSION_CRITICAL
CSP_NORMAL = Appc.CSP_NORMAL
CSP_SPONTANEOUS = Appc.CSP_SPONTANEOUS
TWO_PI = Appc.TWO_PI
PI = Appc.PI
HALF_PI = Appc.HALF_PI
FOURTH_PI = Appc.FOURTH_PI
globals = Appc.globals
g_kSystemWrapper = TGSystemWrapperClassPtr(Appc.globals.g_kSystemWrapper)
PFID_INVALID = Appc.PFID_INVALID
g_kConfigMapping = TGConfigMappingPtr(Appc.globals.g_kConfigMapping)
g_kPoolManager = TGPoolManagerPtr(Appc.globals.g_kPoolManager)
NULL_ID = Appc.NULL_ID
NULL_STRING_INDEX = Appc.NULL_STRING_INDEX
g_kLocalizationManager = TGLocalizationManagerPtr(Appc.globals.g_kLocalizationManager)
g_kAnimationManager = TGAnimationManagerClassPtr(Appc.globals.g_kAnimationManager)
g_kModelManager = TGModelManagerPtr(Appc.globals.g_kModelManager)
TGBE_BOOL_VAL = Appc.TGBE_BOOL_VAL
ANY_TARGET = TGEventHandlerObjectPtr(Appc.globals.ANY_TARGET)
INVALID_DESTINATION = TGEventHandlerObjectPtr(Appc.globals.INVALID_DESTINATION)
g_kEventManager = TGEventManagerPtr(Appc.globals.g_kEventManager)
g_kTimerManager = TGTimerManagerPtr(Appc.globals.g_kTimerManager)
g_kRealtimeTimerManager = TGTimerManagerPtr(Appc.globals.g_kRealtimeTimerManager)
CT_TGEVENT = Appc.CT_TGEVENT
CT_TGEVENTHANDLEROBJECT = Appc.CT_TGEVENTHANDLEROBJECT
CT_TGTIMER = Appc.CT_TGTIMER
CT_TG_BOOL_EVENT = Appc.CT_TG_BOOL_EVENT
CT_TG_CHAR_EVENT = Appc.CT_TG_CHAR_EVENT
CT_TG_SHORT_EVENT = Appc.CT_TG_SHORT_EVENT
CT_TG_INT_EVENT = Appc.CT_TG_INT_EVENT
CT_TG_FLOAT_EVENT = Appc.CT_TG_FLOAT_EVENT
CT_TG_STRING_EVENT = Appc.CT_TG_STRING_EVENT
CT_TG_VOID_PTR_EVENT = Appc.CT_TG_VOID_PTR_EVENT
CT_TG_PYTHON_INSTANCE_WRAPPER = Appc.CT_TG_PYTHON_INSTANCE_WRAPPER
CT_TG_OBJ_PTR_EVENT = Appc.CT_TG_OBJ_PTR_EVENT
CT_TGACTION = Appc.CT_TGACTION
FIRST_TGEVENT_MODULE_EVENT_TYPE = Appc.FIRST_TGEVENT_MODULE_EVENT_TYPE
FIRST_TG_UI_MODULE_EVENT_TYPE = Appc.FIRST_TG_UI_MODULE_EVENT_TYPE
FIRST_TG_SOUND_MODULE_EVENT_TYPE = Appc.FIRST_TG_SOUND_MODULE_EVENT_TYPE
FIRST_TG_INPUT_MODULE_EVENT_TYPE = Appc.FIRST_TG_INPUT_MODULE_EVENT_TYPE
FIRST_TG_CONTROL_MODULE_EVENT_TYPE = Appc.FIRST_TG_CONTROL_MODULE_EVENT_TYPE
FIRST_TG_SEQUENCE_MODULE_EVENT_TYPE = Appc.FIRST_TG_SEQUENCE_MODULE_EVENT_TYPE
FIRST_TGNETWORK_MODULE_EVENT_TYPE = Appc.FIRST_TGNETWORK_MODULE_EVENT_TYPE
FIRST_PROJECT_SPECIFIC_EVENT_TYPE = Appc.FIRST_PROJECT_SPECIFIC_EVENT_TYPE
ET_INVALID = Appc.ET_INVALID
ET_DELETE_OBJECT_PUBLIC = Appc.ET_DELETE_OBJECT_PUBLIC
ET_DELETE_OBJECT_PRIVATE = Appc.ET_DELETE_OBJECT_PRIVATE
CT_TG_INPUT_MONITOR = Appc.CT_TG_INPUT_MONITOR
CT_TG_I_EVENT = Appc.CT_TG_I_EVENT
CT_TG_KEYBOARD_EVENT = Appc.CT_TG_KEYBOARD_EVENT
CT_TG_MOUSE_EVENT = Appc.CT_TG_MOUSE_EVENT
CT_TG_GAMEPAD_EVENT = Appc.CT_TG_GAMEPAD_EVENT
ET_MOUSE = Appc.ET_MOUSE
ET_KEYBOARD = Appc.ET_KEYBOARD
ET_GAMEPAD = Appc.ET_GAMEPAD
ET_GAMEPAD_ADDED = Appc.ET_GAMEPAD_ADDED
ET_GAMEPAD_REMOVED = Appc.ET_GAMEPAD_REMOVED
TGINPUT_GAMEPADS = Appc.TGINPUT_GAMEPADS
TGINPUT_DEVICES = Appc.TGINPUT_DEVICES
TGINPUT_KEYBOARD = Appc.TGINPUT_KEYBOARD
TGINPUT_MOUSE = Appc.TGINPUT_MOUSE
TGINPUT_GAMEPAD0 = Appc.TGINPUT_GAMEPAD0
TGINPUT_GAMEPAD1 = Appc.TGINPUT_GAMEPAD1
TGINPUT_GAMEPAD2 = Appc.TGINPUT_GAMEPAD2
TGINPUT_GAMEPAD3 = Appc.TGINPUT_GAMEPAD3
TGINPUT_BUTTONS = Appc.TGINPUT_BUTTONS
TGINPUT_ELEMENT_BUTTON = Appc.TGINPUT_ELEMENT_BUTTON
TGINPUT_ELEMENT_POVDIR = Appc.TGINPUT_ELEMENT_POVDIR
TGINPUT_ELEMENT_POVU = Appc.TGINPUT_ELEMENT_POVU
TGINPUT_ELEMENT_POVR = Appc.TGINPUT_ELEMENT_POVR
TGINPUT_ELEMENT_POVD = Appc.TGINPUT_ELEMENT_POVD
TGINPUT_ELEMENT_POVL = Appc.TGINPUT_ELEMENT_POVL
TGINPUT_ELEMENT_AXIS = Appc.TGINPUT_ELEMENT_AXIS
TGINPUT_ELEMENT_X = Appc.TGINPUT_ELEMENT_X
TGINPUT_ELEMENT_Y = Appc.TGINPUT_ELEMENT_Y
TGINPUT_ELEMENT_Z = Appc.TGINPUT_ELEMENT_Z
TGINPUT_ELEMENT_R = Appc.TGINPUT_ELEMENT_R
TGINPUT_ELEMENT_U = Appc.TGINPUT_ELEMENT_U
TGINPUT_ELEMENT_V = Appc.TGINPUT_ELEMENT_V
TGINPUT_ELEMENT_POV = Appc.TGINPUT_ELEMENT_POV
TGINPUT_ELEMENT_SLIDERA = Appc.TGINPUT_ELEMENT_SLIDERA
TGINPUT_ELEMENT_SLIDERB = Appc.TGINPUT_ELEMENT_SLIDERB
TGIE_HANDLED = Appc.TGIE_HANDLED
MAX_DEAD_KEYS = Appc.MAX_DEAD_KEYS
MAX_DEAD_KEY_MAPPINGS = Appc.MAX_DEAD_KEY_MAPPINGS
g_kInputManager = TGInputManagerPtr(Appc.globals.g_kInputManager)
KY_0 = Appc.KY_0
KY_1 = Appc.KY_1
KY_2 = Appc.KY_2
KY_3 = Appc.KY_3
KY_4 = Appc.KY_4
KY_5 = Appc.KY_5
KY_6 = Appc.KY_6
KY_7 = Appc.KY_7
KY_8 = Appc.KY_8
KY_9 = Appc.KY_9
KY_A = Appc.KY_A
KY_B = Appc.KY_B
KY_C = Appc.KY_C
KY_D = Appc.KY_D
KY_E = Appc.KY_E
KY_F = Appc.KY_F
KY_G = Appc.KY_G
KY_H = Appc.KY_H
KY_I = Appc.KY_I
KY_J = Appc.KY_J
KY_K = Appc.KY_K
KY_L = Appc.KY_L
KY_M = Appc.KY_M
KY_N = Appc.KY_N
KY_O = Appc.KY_O
KY_P = Appc.KY_P
KY_Q = Appc.KY_Q
KY_R = Appc.KY_R
KY_S = Appc.KY_S
KY_T = Appc.KY_T
KY_U = Appc.KY_U
KY_V = Appc.KY_V
KY_W = Appc.KY_W
KY_X = Appc.KY_X
KY_Y = Appc.KY_Y
KY_Z = Appc.KY_Z
KY_EQUALS = Appc.KY_EQUALS
KY_COMMA = Appc.KY_COMMA
KY_MINUS = Appc.KY_MINUS
KY_PERIOD = Appc.KY_PERIOD
KY_SLASH = Appc.KY_SLASH
KY_ESCAPE = Appc.KY_ESCAPE
KY_TAB = Appc.KY_TAB
KY_BACKSPACE = Appc.KY_BACKSPACE
KY_RETURN = Appc.KY_RETURN
KY_BACKQUOTE = Appc.KY_BACKQUOTE
KY_QUOTE = Appc.KY_QUOTE
KY_OPEN_BRACKET = Appc.KY_OPEN_BRACKET
KY_CLOSE_BRACKET = Appc.KY_CLOSE_BRACKET
KY_SEMICOLON = Appc.KY_SEMICOLON
KY_SHIFT = Appc.KY_SHIFT
KY_RSHIFT = Appc.KY_RSHIFT
KY_CTRL = Appc.KY_CTRL
KY_RCTRL = Appc.KY_RCTRL
KY_ALT = Appc.KY_ALT
KY_ALTGR = Appc.KY_ALTGR
KY_CAPSLOCK = Appc.KY_CAPSLOCK
KY_SPACE = Appc.KY_SPACE
KY_PAGEUP = Appc.KY_PAGEUP
KY_PAGEDOWN = Appc.KY_PAGEDOWN
KY_END = Appc.KY_END
KY_HOME = Appc.KY_HOME
KY_LEFT = Appc.KY_LEFT
KY_UP = Appc.KY_UP
KY_RIGHT = Appc.KY_RIGHT
KY_DOWN = Appc.KY_DOWN
KY_PRINTSCREEN = Appc.KY_PRINTSCREEN
KY_INSERT = Appc.KY_INSERT
KY_DELETE = Appc.KY_DELETE
KY_F1 = Appc.KY_F1
KY_F2 = Appc.KY_F2
KY_F3 = Appc.KY_F3
KY_F4 = Appc.KY_F4
KY_F5 = Appc.KY_F5
KY_F6 = Appc.KY_F6
KY_F7 = Appc.KY_F7
KY_F8 = Appc.KY_F8
KY_F9 = Appc.KY_F9
KY_F10 = Appc.KY_F10
KY_F11 = Appc.KY_F11
KY_F12 = Appc.KY_F12
KY_NUMPAD0 = Appc.KY_NUMPAD0
KY_NUMPAD1 = Appc.KY_NUMPAD1
KY_NUMPAD2 = Appc.KY_NUMPAD2
KY_NUMPAD3 = Appc.KY_NUMPAD3
KY_NUMPAD4 = Appc.KY_NUMPAD4
KY_NUMPAD5 = Appc.KY_NUMPAD5
KY_NUMPAD6 = Appc.KY_NUMPAD6
KY_NUMPAD7 = Appc.KY_NUMPAD7
KY_NUMPAD8 = Appc.KY_NUMPAD8
KY_NUMPAD9 = Appc.KY_NUMPAD9
KY_MULTIPLY = Appc.KY_MULTIPLY
KY_ADD = Appc.KY_ADD
KY_SUBTRACT = Appc.KY_SUBTRACT
KY_DECIMAL = Appc.KY_DECIMAL
KY_DIVIDE = Appc.KY_DIVIDE
KY_NUMPADENTER = Appc.KY_NUMPADENTER
KY_NUMLOCK = Appc.KY_NUMLOCK
KY_SCROLL = Appc.KY_SCROLL
KY_PAUSE = Appc.KY_PAUSE
KY_SEPARATOR = Appc.KY_SEPARATOR
KY_EU_LEFT = Appc.KY_EU_LEFT
KY_EU_RIGHT = Appc.KY_EU_RIGHT
KY_SCROLL_WHEEL_UP = Appc.KY_SCROLL_WHEEL_UP
KY_SCROLL_WHEEL_DOWN = Appc.KY_SCROLL_WHEEL_DOWN
KY_LBUTTON = Appc.KY_LBUTTON
KY_RBUTTON = Appc.KY_RBUTTON
KY_MBUTTON = Appc.KY_MBUTTON
WC_BACKSPACE = Appc.WC_BACKSPACE
WC_TAB = Appc.WC_TAB
WC_LINEFEED = Appc.WC_LINEFEED
WC_RETURN = Appc.WC_RETURN
WC_SPACE = Appc.WC_SPACE
WC_EXCLAMATION = Appc.WC_EXCLAMATION
WC_DOUBLE_QUOTE = Appc.WC_DOUBLE_QUOTE
WC_NUMBER_SIGN = Appc.WC_NUMBER_SIGN
WC_DOLLAR_SIGN = Appc.WC_DOLLAR_SIGN
WC_PERCENT = Appc.WC_PERCENT
WC_AMPERSAND = Appc.WC_AMPERSAND
WC_QUOTE = Appc.WC_QUOTE
WC_OPEN_PAREN = Appc.WC_OPEN_PAREN
WC_CLOSE_PAREN = Appc.WC_CLOSE_PAREN
WC_ASTERISK = Appc.WC_ASTERISK
WC_PLUS = Appc.WC_PLUS
WC_COMMA = Appc.WC_COMMA
WC_MINUS = Appc.WC_MINUS
WC_PERIOD = Appc.WC_PERIOD
WC_SLASH = Appc.WC_SLASH
WC_0 = Appc.WC_0
WC_1 = Appc.WC_1
WC_2 = Appc.WC_2
WC_3 = Appc.WC_3
WC_4 = Appc.WC_4
WC_5 = Appc.WC_5
WC_6 = Appc.WC_6
WC_7 = Appc.WC_7
WC_8 = Appc.WC_8
WC_9 = Appc.WC_9
WC_COLON = Appc.WC_COLON
WC_SEMICOLON = Appc.WC_SEMICOLON
WC_LESS_THAN = Appc.WC_LESS_THAN
WC_EQUALS = Appc.WC_EQUALS
WC_GREATER_THAN = Appc.WC_GREATER_THAN
WC_QUESTION = Appc.WC_QUESTION
WC_AT_SIGN = Appc.WC_AT_SIGN
WC_CAPS_A = Appc.WC_CAPS_A
WC_CAPS_B = Appc.WC_CAPS_B
WC_CAPS_C = Appc.WC_CAPS_C
WC_CAPS_D = Appc.WC_CAPS_D
WC_CAPS_E = Appc.WC_CAPS_E
WC_CAPS_F = Appc.WC_CAPS_F
WC_CAPS_G = Appc.WC_CAPS_G
WC_CAPS_H = Appc.WC_CAPS_H
WC_CAPS_I = Appc.WC_CAPS_I
WC_CAPS_J = Appc.WC_CAPS_J
WC_CAPS_K = Appc.WC_CAPS_K
WC_CAPS_L = Appc.WC_CAPS_L
WC_CAPS_M = Appc.WC_CAPS_M
WC_CAPS_N = Appc.WC_CAPS_N
WC_CAPS_O = Appc.WC_CAPS_O
WC_CAPS_P = Appc.WC_CAPS_P
WC_CAPS_Q = Appc.WC_CAPS_Q
WC_CAPS_R = Appc.WC_CAPS_R
WC_CAPS_S = Appc.WC_CAPS_S
WC_CAPS_T = Appc.WC_CAPS_T
WC_CAPS_U = Appc.WC_CAPS_U
WC_CAPS_V = Appc.WC_CAPS_V
WC_CAPS_W = Appc.WC_CAPS_W
WC_CAPS_X = Appc.WC_CAPS_X
WC_CAPS_Y = Appc.WC_CAPS_Y
WC_CAPS_Z = Appc.WC_CAPS_Z
WC_OPEN_BRACKET = Appc.WC_OPEN_BRACKET
WC_BACKSLASH = Appc.WC_BACKSLASH
WC_CLOSE_BRACKET = Appc.WC_CLOSE_BRACKET
WC_CARRET = Appc.WC_CARRET
WC_UNDERSCORE = Appc.WC_UNDERSCORE
WC_BACKQUOTE = Appc.WC_BACKQUOTE
WC_A = Appc.WC_A
WC_B = Appc.WC_B
WC_C = Appc.WC_C
WC_D = Appc.WC_D
WC_E = Appc.WC_E
WC_F = Appc.WC_F
WC_G = Appc.WC_G
WC_H = Appc.WC_H
WC_I = Appc.WC_I
WC_J = Appc.WC_J
WC_K = Appc.WC_K
WC_L = Appc.WC_L
WC_M = Appc.WC_M
WC_N = Appc.WC_N
WC_O = Appc.WC_O
WC_P = Appc.WC_P
WC_Q = Appc.WC_Q
WC_R = Appc.WC_R
WC_S = Appc.WC_S
WC_T = Appc.WC_T
WC_U = Appc.WC_U
WC_V = Appc.WC_V
WC_W = Appc.WC_W
WC_X = Appc.WC_X
WC_Y = Appc.WC_Y
WC_Z = Appc.WC_Z
WC_CURLY_BRACE_OPEN = Appc.WC_CURLY_BRACE_OPEN
WC_SEPARATOR = Appc.WC_SEPARATOR
WC_CURLY_BRACE_CLOSE = Appc.WC_CURLY_BRACE_CLOSE
WC_TILDE = Appc.WC_TILDE
WC_EURO_SIGN = Appc.WC_EURO_SIGN
WC_INVERTED_DOUBLE_QUOTE = Appc.WC_INVERTED_DOUBLE_QUOTE
WC_NO_BREAK_SPACE = Appc.WC_NO_BREAK_SPACE
WC_INVERTED_EXCLAMATION = Appc.WC_INVERTED_EXCLAMATION
WC_CENT_SIGN = Appc.WC_CENT_SIGN
WC_POUND_SIGN = Appc.WC_POUND_SIGN
WC_CURRENCY_SIGN = Appc.WC_CURRENCY_SIGN
WC_YEN_SIGN = Appc.WC_YEN_SIGN
WC_BROKEN_BAR = Appc.WC_BROKEN_BAR
WC_SECTION_SIGN = Appc.WC_SECTION_SIGN
WC_DIAERESIS = Appc.WC_DIAERESIS
WC_COPYRIGHT_SIGN = Appc.WC_COPYRIGHT_SIGN
WC_FEMININE_ORDINAL = Appc.WC_FEMININE_ORDINAL
WC_LEFT_DOUBLE_ANGLE = Appc.WC_LEFT_DOUBLE_ANGLE
WC_NOT_SIGN = Appc.WC_NOT_SIGN
WC_SOFT_HYPHEN = Appc.WC_SOFT_HYPHEN
WC_REGISTERED_SIGN = Appc.WC_REGISTERED_SIGN
WC_MACRON = Appc.WC_MACRON
WC_DEGREE_SIGN = Appc.WC_DEGREE_SIGN
WC_PLUS_MINUS_SIGN = Appc.WC_PLUS_MINUS_SIGN
WC_SUPERSCRIPT_TWO = Appc.WC_SUPERSCRIPT_TWO
WC_SUPERSCRIPT_THREE = Appc.WC_SUPERSCRIPT_THREE
WC_ACUTE_ACCENT = Appc.WC_ACUTE_ACCENT
WC_MICRO_SIGN = Appc.WC_MICRO_SIGN
WC_PILCROW_SIGN = Appc.WC_PILCROW_SIGN
WC_MIDDLE_DOT = Appc.WC_MIDDLE_DOT
WC_CEDILLA = Appc.WC_CEDILLA
WC_SUPERSCRIPT_ONE = Appc.WC_SUPERSCRIPT_ONE
WC_MASCULINE_ORDINAL = Appc.WC_MASCULINE_ORDINAL
WC_RIGHT_DOUBLE_ANGLE = Appc.WC_RIGHT_DOUBLE_ANGLE
WC_FRACTION_ONE_QUARTER = Appc.WC_FRACTION_ONE_QUARTER
WC_FRACTION_ONE_HALF = Appc.WC_FRACTION_ONE_HALF
WC_FRACTION_THREE_QUARTERS = Appc.WC_FRACTION_THREE_QUARTERS
WC_INVERTED_QUESTION_MARK = Appc.WC_INVERTED_QUESTION_MARK
WC_CAPS_A_GRAVE = Appc.WC_CAPS_A_GRAVE
WC_CAPS_A_ACUTE = Appc.WC_CAPS_A_ACUTE
WC_CAPS_A_CIRCUMFLEX = Appc.WC_CAPS_A_CIRCUMFLEX
WC_CAPS_A_TILDE = Appc.WC_CAPS_A_TILDE
WC_CAPS_A_DIAERESIS = Appc.WC_CAPS_A_DIAERESIS
WC_CAPS_A_RING_ABOVE = Appc.WC_CAPS_A_RING_ABOVE
WC_CAPS_AE = Appc.WC_CAPS_AE
WC_CAPS_C_CEDILLA = Appc.WC_CAPS_C_CEDILLA
WC_CAPS_E_GRAVE = Appc.WC_CAPS_E_GRAVE
WC_CAPS_E_ACUTE = Appc.WC_CAPS_E_ACUTE
WC_CAPS_E_CIRCUMFLEX = Appc.WC_CAPS_E_CIRCUMFLEX
WC_CAPS_E_DIAERESIS = Appc.WC_CAPS_E_DIAERESIS
WC_CAPS_I_GRAVE = Appc.WC_CAPS_I_GRAVE
WC_CAPS_I_ACUTE = Appc.WC_CAPS_I_ACUTE
WC_CAPS_I_CIRCUMFLEX = Appc.WC_CAPS_I_CIRCUMFLEX
WC_CAPS_I_DIAERESIS = Appc.WC_CAPS_I_DIAERESIS
WC_CAPS_ETH = Appc.WC_CAPS_ETH
WC_CAPS_N_TILDE = Appc.WC_CAPS_N_TILDE
WC_CAPS_O_GRAVE = Appc.WC_CAPS_O_GRAVE
WC_CAPS_O_ACUTE = Appc.WC_CAPS_O_ACUTE
WC_CAPS_O_CIRCUMFLEX = Appc.WC_CAPS_O_CIRCUMFLEX
WC_CAPS_O_TILDE = Appc.WC_CAPS_O_TILDE
WC_CAPS_O_DIAERESIS = Appc.WC_CAPS_O_DIAERESIS
WC_MULTIPLICATION_SIGN = Appc.WC_MULTIPLICATION_SIGN
WC_CAPS_O_STROKE = Appc.WC_CAPS_O_STROKE
WC_CAPS_U_GRAVE = Appc.WC_CAPS_U_GRAVE
WC_CAPS_U_ACUTE = Appc.WC_CAPS_U_ACUTE
WC_CAPS_U_CIRCUMFLEX = Appc.WC_CAPS_U_CIRCUMFLEX
WC_CAPS_U_DIAERESIS = Appc.WC_CAPS_U_DIAERESIS
WC_CAPS_Y_ACUTE = Appc.WC_CAPS_Y_ACUTE
WC_CAPS_THORN = Appc.WC_CAPS_THORN
WC_SHARP_S = Appc.WC_SHARP_S
WC_A_GRAVE = Appc.WC_A_GRAVE
WC_A_ACUTE = Appc.WC_A_ACUTE
WC_A_CIRCUMFLEX = Appc.WC_A_CIRCUMFLEX
WC_A_TILDE = Appc.WC_A_TILDE
WC_A_DIAERESIS = Appc.WC_A_DIAERESIS
WC_A_RING_ABOVE = Appc.WC_A_RING_ABOVE
WC_AE = Appc.WC_AE
WC_C_CEDILLA = Appc.WC_C_CEDILLA
WC_E_GRAVE = Appc.WC_E_GRAVE
WC_E_ACUTE = Appc.WC_E_ACUTE
WC_E_CIRCUMFLEX = Appc.WC_E_CIRCUMFLEX
WC_E_DIAERESIS = Appc.WC_E_DIAERESIS
WC_I_GRAVE = Appc.WC_I_GRAVE
WC_I_ACUTE = Appc.WC_I_ACUTE
WC_I_CIRCUMFLEX = Appc.WC_I_CIRCUMFLEX
WC_I_DIAERESIS = Appc.WC_I_DIAERESIS
WC_ETH = Appc.WC_ETH
WC_N_TILDE = Appc.WC_N_TILDE
WC_O_GRAVE = Appc.WC_O_GRAVE
WC_O_ACUTE = Appc.WC_O_ACUTE
WC_O_CIRCUMFLEX = Appc.WC_O_CIRCUMFLEX
WC_O_TILDE = Appc.WC_O_TILDE
WC_O_DIAERESIS = Appc.WC_O_DIAERESIS
WC_O_DIVISION_SIGN = Appc.WC_O_DIVISION_SIGN
WC_O_STROKE = Appc.WC_O_STROKE
WC_U_GRAVE = Appc.WC_U_GRAVE
WC_U_ACUTE = Appc.WC_U_ACUTE
WC_U_CIRCUMFLEX = Appc.WC_U_CIRCUMFLEX
WC_U_DIAERESIS = Appc.WC_U_DIAERESIS
WC_Y_ACUTE = Appc.WC_Y_ACUTE
WC_THORN = Appc.WC_THORN
WC_PRIVATE_USE_START = Appc.WC_PRIVATE_USE_START
WC_ESCAPE = Appc.WC_ESCAPE
WC_SHIFT = Appc.WC_SHIFT
WC_CTRL = Appc.WC_CTRL
WC_ALT = Appc.WC_ALT
WC_CAPSLOCK = Appc.WC_CAPSLOCK
WC_ALTGR = Appc.WC_ALTGR
WC_LEFT = Appc.WC_LEFT
WC_UP = Appc.WC_UP
WC_RIGHT = Appc.WC_RIGHT
WC_DOWN = Appc.WC_DOWN
WC_PRINTSCREEN = Appc.WC_PRINTSCREEN
WC_SCROLL = Appc.WC_SCROLL
WC_PAUSE = Appc.WC_PAUSE
WC_INSERT = Appc.WC_INSERT
WC_DELETE = Appc.WC_DELETE
WC_NUMLOCK = Appc.WC_NUMLOCK
WC_PAGEUP = Appc.WC_PAGEUP
WC_PAGEDOWN = Appc.WC_PAGEDOWN
WC_END = Appc.WC_END
WC_HOME = Appc.WC_HOME
WC_F1 = Appc.WC_F1
WC_F2 = Appc.WC_F2
WC_F3 = Appc.WC_F3
WC_F4 = Appc.WC_F4
WC_F5 = Appc.WC_F5
WC_F6 = Appc.WC_F6
WC_F7 = Appc.WC_F7
WC_F8 = Appc.WC_F8
WC_F9 = Appc.WC_F9
WC_F10 = Appc.WC_F10
WC_F11 = Appc.WC_F11
WC_F12 = Appc.WC_F12
WC_NUMPAD0 = Appc.WC_NUMPAD0
WC_NUMPAD1 = Appc.WC_NUMPAD1
WC_NUMPAD2 = Appc.WC_NUMPAD2
WC_NUMPAD3 = Appc.WC_NUMPAD3
WC_NUMPAD4 = Appc.WC_NUMPAD4
WC_NUMPAD5 = Appc.WC_NUMPAD5
WC_NUMPAD6 = Appc.WC_NUMPAD6
WC_NUMPAD7 = Appc.WC_NUMPAD7
WC_NUMPAD8 = Appc.WC_NUMPAD8
WC_NUMPAD9 = Appc.WC_NUMPAD9
WC_DECIMAL = Appc.WC_DECIMAL
WC_ADD = Appc.WC_ADD
WC_SUBTRACT = Appc.WC_SUBTRACT
WC_MULTIPLY = Appc.WC_MULTIPLY
WC_DIVIDE = Appc.WC_DIVIDE
WC_NUMPADENTER = Appc.WC_NUMPADENTER
WC_ALT_A = Appc.WC_ALT_A
WC_ALT_B = Appc.WC_ALT_B
WC_ALT_C = Appc.WC_ALT_C
WC_ALT_D = Appc.WC_ALT_D
WC_ALT_E = Appc.WC_ALT_E
WC_ALT_F = Appc.WC_ALT_F
WC_ALT_G = Appc.WC_ALT_G
WC_ALT_H = Appc.WC_ALT_H
WC_ALT_I = Appc.WC_ALT_I
WC_ALT_J = Appc.WC_ALT_J
WC_ALT_K = Appc.WC_ALT_K
WC_ALT_L = Appc.WC_ALT_L
WC_ALT_M = Appc.WC_ALT_M
WC_ALT_N = Appc.WC_ALT_N
WC_ALT_O = Appc.WC_ALT_O
WC_ALT_P = Appc.WC_ALT_P
WC_ALT_Q = Appc.WC_ALT_Q
WC_ALT_R = Appc.WC_ALT_R
WC_ALT_S = Appc.WC_ALT_S
WC_ALT_T = Appc.WC_ALT_T
WC_ALT_U = Appc.WC_ALT_U
WC_ALT_V = Appc.WC_ALT_V
WC_ALT_W = Appc.WC_ALT_W
WC_ALT_X = Appc.WC_ALT_X
WC_ALT_Y = Appc.WC_ALT_Y
WC_ALT_Z = Appc.WC_ALT_Z
WC_ALT_1 = Appc.WC_ALT_1
WC_ALT_2 = Appc.WC_ALT_2
WC_ALT_3 = Appc.WC_ALT_3
WC_ALT_4 = Appc.WC_ALT_4
WC_ALT_5 = Appc.WC_ALT_5
WC_ALT_6 = Appc.WC_ALT_6
WC_ALT_7 = Appc.WC_ALT_7
WC_ALT_8 = Appc.WC_ALT_8
WC_ALT_9 = Appc.WC_ALT_9
WC_ALT_0 = Appc.WC_ALT_0
WC_ALT_F1 = Appc.WC_ALT_F1
WC_ALT_F2 = Appc.WC_ALT_F2
WC_ALT_F3 = Appc.WC_ALT_F3
WC_ALT_F4 = Appc.WC_ALT_F4
WC_ALT_F5 = Appc.WC_ALT_F5
WC_ALT_F6 = Appc.WC_ALT_F6
WC_ALT_F7 = Appc.WC_ALT_F7
WC_ALT_F8 = Appc.WC_ALT_F8
WC_ALT_F9 = Appc.WC_ALT_F9
WC_ALT_F10 = Appc.WC_ALT_F10
WC_ALT_F11 = Appc.WC_ALT_F11
WC_ALT_F12 = Appc.WC_ALT_F12
WC_CTRL_A = Appc.WC_CTRL_A
WC_CTRL_B = Appc.WC_CTRL_B
WC_CTRL_C = Appc.WC_CTRL_C
WC_CTRL_D = Appc.WC_CTRL_D
WC_CTRL_E = Appc.WC_CTRL_E
WC_CTRL_F = Appc.WC_CTRL_F
WC_CTRL_G = Appc.WC_CTRL_G
WC_CTRL_H = Appc.WC_CTRL_H
WC_CTRL_I = Appc.WC_CTRL_I
WC_CTRL_J = Appc.WC_CTRL_J
WC_CTRL_K = Appc.WC_CTRL_K
WC_CTRL_L = Appc.WC_CTRL_L
WC_CTRL_M = Appc.WC_CTRL_M
WC_CTRL_N = Appc.WC_CTRL_N
WC_CTRL_O = Appc.WC_CTRL_O
WC_CTRL_P = Appc.WC_CTRL_P
WC_CTRL_Q = Appc.WC_CTRL_Q
WC_CTRL_R = Appc.WC_CTRL_R
WC_CTRL_S = Appc.WC_CTRL_S
WC_CTRL_T = Appc.WC_CTRL_T
WC_CTRL_U = Appc.WC_CTRL_U
WC_CTRL_V = Appc.WC_CTRL_V
WC_CTRL_W = Appc.WC_CTRL_W
WC_CTRL_X = Appc.WC_CTRL_X
WC_CTRL_Y = Appc.WC_CTRL_Y
WC_CTRL_Z = Appc.WC_CTRL_Z
WC_CTRL_1 = Appc.WC_CTRL_1
WC_CTRL_2 = Appc.WC_CTRL_2
WC_CTRL_3 = Appc.WC_CTRL_3
WC_CTRL_4 = Appc.WC_CTRL_4
WC_CTRL_5 = Appc.WC_CTRL_5
WC_CTRL_6 = Appc.WC_CTRL_6
WC_CTRL_7 = Appc.WC_CTRL_7
WC_CTRL_8 = Appc.WC_CTRL_8
WC_CTRL_9 = Appc.WC_CTRL_9
WC_CTRL_0 = Appc.WC_CTRL_0
WC_CTRL_F1 = Appc.WC_CTRL_F1
WC_CTRL_F2 = Appc.WC_CTRL_F2
WC_CTRL_F3 = Appc.WC_CTRL_F3
WC_CTRL_F4 = Appc.WC_CTRL_F4
WC_CTRL_F5 = Appc.WC_CTRL_F5
WC_CTRL_F6 = Appc.WC_CTRL_F6
WC_CTRL_F7 = Appc.WC_CTRL_F7
WC_CTRL_F8 = Appc.WC_CTRL_F8
WC_CTRL_F9 = Appc.WC_CTRL_F9
WC_CTRL_F10 = Appc.WC_CTRL_F10
WC_CTRL_F11 = Appc.WC_CTRL_F11
WC_CTRL_F12 = Appc.WC_CTRL_F12
WC_EU_LEFT = Appc.WC_EU_LEFT
WC_EU_RIGHT = Appc.WC_EU_RIGHT
WC_SCROLL_WHEEL_UP = Appc.WC_SCROLL_WHEEL_UP
WC_SCROLL_WHEEL_DOWN = Appc.WC_SCROLL_WHEEL_DOWN
WC_LBUTTON = Appc.WC_LBUTTON
WC_MBUTTON = Appc.WC_MBUTTON
WC_RBUTTON = Appc.WC_RBUTTON
WC_CURSOR = Appc.WC_CURSOR
WC_FIRST_EXTRA_CHAR = Appc.WC_FIRST_EXTRA_CHAR
TGUIO_ENABLED = Appc.TGUIO_ENABLED
TGUIO_SELECTED = Appc.TGUIO_SELECTED
TGUIO_HIGHLIGHTED = Appc.TGUIO_HIGHLIGHTED
TGUIO_VISIBLE = Appc.TGUIO_VISIBLE
TGUIO_EXCLUSIVE = Appc.TGUIO_EXCLUSIVE
TGUIO_SKIP_PARENT = Appc.TGUIO_SKIP_PARENT
TGUIO_ALWAYS_HANDLE_EVENTS = Appc.TGUIO_ALWAYS_HANDLE_EVENTS
TGUIO_USE_PARENT_BATCH = Appc.TGUIO_USE_PARENT_BATCH
TGUIO_NO_FOCUS = Appc.TGUIO_NO_FOCUS
TGUIO_BATCH_CHILD_POLYS = Appc.TGUIO_BATCH_CHILD_POLYS
TGUIO_COMPLETELY_VISIBLE = Appc.TGUIO_COMPLETELY_VISIBLE
BIGGEST_POSITIVE_INT = Appc.BIGGEST_POSITIVE_INT
TGTB_WIDTH_INDENT = Appc.TGTB_WIDTH_INDENT
TGTB_HEIGHT_INDENT = Appc.TGTB_HEIGHT_INDENT
g_kRootWindow = TGRootPanePtr(Appc.globals.g_kRootWindow)
g_kIconManager = TGIconManagerPtr(Appc.globals.g_kIconManager)
TGIP_BUFFER_SIZE = Appc.TGIP_BUFFER_SIZE
TGIM_DEFAULT_PIXEL_CENTER_ADJUSTMENT = Appc.TGIM_DEFAULT_PIXEL_CENTER_ADJUSTMENT
g_kFontManager = TGFontManagerPtr(Appc.globals.g_kFontManager)
TGFM_DEFAULT_TEXT_SCREEN_ADJUSTMENT = Appc.TGFM_DEFAULT_TEXT_SCREEN_ADJUSTMENT
TGWINDOW_SIMPLE_RESIZE = Appc.TGWINDOW_SIMPLE_RESIZE
g_kUIThemeManager = TGUIThemeManagerPtr(Appc.globals.g_kUIThemeManager)
TGCONSOLE_DEFAULT_TEXT_INDENT = Appc.TGCONSOLE_DEFAULT_TEXT_INDENT
PSID_INVALID = Appc.PSID_INVALID
PSID_BASE_OFFSET = Appc.PSID_BASE_OFFSET
DEFAULT_MAX_SOUNDS_AT_ONCE = Appc.DEFAULT_MAX_SOUNDS_AT_ONCE
CT_SOUND_MANAGER = Appc.CT_SOUND_MANAGER
CT_MUSIC = Appc.CT_MUSIC
CT_SOUND_REGION = Appc.CT_SOUND_REGION
CT_TG_SOUND_EVENT = Appc.CT_TG_SOUND_EVENT
CT_TG_SOUND_ID_EVENT = Appc.CT_TG_SOUND_ID_EVENT
CT_MUSIC_FADE_EVENT = Appc.CT_MUSIC_FADE_EVENT
ET_MUSIC_FADE = Appc.ET_MUSIC_FADE
ET_MUSIC_DONE = Appc.ET_MUSIC_DONE
ET_DELETE_SOUND = Appc.ET_DELETE_SOUND
g_kSoundManager = TGSoundManagerPtr(Appc.globals.g_kSoundManager)
g_kRedbook = TGRedbookClassPtr(Appc.globals.g_kRedbook)
g_kMusicManager = TGMusicPtr(Appc.globals.g_kMusicManager)
PY_EXPRESSION = Appc.PY_EXPRESSION
PY_STATEMENT = Appc.PY_STATEMENT
g_kModelPropertyManager = TGModelPropertyManagerPtr(Appc.globals.g_kModelPropertyManager)
g_kTGActionManager = TGActionManagerPtr(Appc.globals.g_kTGActionManager)
TGSAF_RESTART = Appc.TGSAF_RESTART
TGSAF_ALLOW_DUPLICATES = Appc.TGSAF_ALLOW_DUPLICATES
TGSAF_LOOPING = Appc.TGSAF_LOOPING
TGSAF_ALLOW_SOUND_TO_CONTINUE_PLAYING_WHEN_STOPPED = Appc.TGSAF_ALLOW_SOUND_TO_CONTINUE_PLAYING_WHEN_STOPPED
TGSAF_VOICE = Appc.TGSAF_VOICE
TGSAF_DEFAULTS = Appc.TGSAF_DEFAULTS
CT_TG_ACTION = Appc.CT_TG_ACTION
CT_TG_ACTION_MANAGER = Appc.CT_TG_ACTION_MANAGER
CT_TG_SEQUENCE_OBJECT = Appc.CT_TG_SEQUENCE_OBJECT
CT_TG_SEQUENCE_EVENT = Appc.CT_TG_SEQUENCE_EVENT
CT_TG_CONDITION = Appc.CT_TG_CONDITION
CT_TG_CONDITION_ACTION = Appc.CT_TG_CONDITION_ACTION
CT_TG_SEQUENCE = Appc.CT_TG_SEQUENCE
CT_TG_TIMED_ACTION = Appc.CT_TG_TIMED_ACTION
CT_TG_ANIM_ACTION = Appc.CT_TG_ANIM_ACTION
CT_TG_SCRIPT_ACTION = Appc.CT_TG_SCRIPT_ACTION
CT_TG_ANIM_POSITION = Appc.CT_TG_ANIM_POSITION
CT_TG_SOUND_ACTION = Appc.CT_TG_SOUND_ACTION
CT_TG_PHONEME_ACTION = Appc.CT_TG_PHONEME_ACTION
CT_TG_OVERLAY_ACTION = Appc.CT_TG_OVERLAY_ACTION
CT_TG_PHONEME_SEQUENCE = Appc.CT_TG_PHONEME_SEQUENCE
ET_ACTION_COMPLETED = Appc.ET_ACTION_COMPLETED
ET_ACTION_SKIP = Appc.ET_ACTION_SKIP
ET_SEQUENCE_PLAY_ACTION = Appc.ET_SEQUENCE_PLAY_ACTION
ET_SEQUENCE_ACTION_COMPLETED = Appc.ET_SEQUENCE_ACTION_COMPLETED
ET_SEQUENCE_PLAY_ACTION_DELAYED = Appc.ET_SEQUENCE_PLAY_ACTION_DELAYED
ET_CONDITION_CHANGED = Appc.ET_CONDITION_CHANGED
TGNETWORK_OKAY = Appc.TGNETWORK_OKAY
TGNETWORK_ERROR = Appc.TGNETWORK_ERROR
TGNETWORK_CONNECTED = Appc.TGNETWORK_CONNECTED
TGNETWORK_CONNECT_IN_PROGRESS = Appc.TGNETWORK_CONNECT_IN_PROGRESS
TGNETWORK_ERROR_NOT_CONNECTED = Appc.TGNETWORK_ERROR_NOT_CONNECTED
TGNETWORK_ERROR_DISCONNECTED = Appc.TGNETWORK_ERROR_DISCONNECTED
TGNETWORK_ERROR_CONNECT_DENIED = Appc.TGNETWORK_ERROR_CONNECT_DENIED
TGNETWORK_ERROR_CONNECT_REQUIRE_PASSWORD = Appc.TGNETWORK_ERROR_CONNECT_REQUIRE_PASSWORD
TGNETWORK_ERROR_CONNECT_TIMED_OUT = Appc.TGNETWORK_ERROR_CONNECT_TIMED_OUT
TGNETWORK_ERROR_ALREADY_CONNECTED = Appc.TGNETWORK_ERROR_ALREADY_CONNECTED
TGNETWORK_ERROR_TOO_MANY_SENDS_PENDING = Appc.TGNETWORK_ERROR_TOO_MANY_SENDS_PENDING
TGNETWORK_ERROR_INVALID_ADDRESS = Appc.TGNETWORK_ERROR_INVALID_ADDRESS
TGNETWORK_ERROR_LARGE_PACKET_NOT_GUARANTEED = Appc.TGNETWORK_ERROR_LARGE_PACKET_NOT_GUARANTEED
TGNETWORK_ERROR_DRIVER_STARTUP = Appc.TGNETWORK_ERROR_DRIVER_STARTUP
TGNETWORK_ERROR_SHUTDOWN_FAILED = Appc.TGNETWORK_ERROR_SHUTDOWN_FAILED
TGNETWORK_ERROR_DO_BEFORE_CONNECTION = Appc.TGNETWORK_ERROR_DO_BEFORE_CONNECTION
TGNETWORK_ERROR_GROUP_NOT_FOUND = Appc.TGNETWORK_ERROR_GROUP_NOT_FOUND
TGMESSAGE_NAME_CHANGE = Appc.TGMESSAGE_NAME_CHANGE
TGMESSAGE_ACKNOWLEDGE = Appc.TGMESSAGE_ACKNOWLEDGE
TGMESSAGE_DONOTHING = Appc.TGMESSAGE_DONOTHING
TGMESSAGE_CONNECT = Appc.TGMESSAGE_CONNECT
TGMESSAGE_BOOT_PLAYER = Appc.TGMESSAGE_BOOT_PLAYER
TGMESSAGE_DISCONNECT = Appc.TGMESSAGE_DISCONNECT
TGMESSAGE_APP_START = Appc.TGMESSAGE_APP_START
TGMESSAGE_STANDARD = Appc.TGMESSAGE_STANDARD
CT_NETWORK = Appc.CT_NETWORK
CT_MESSAGE_EVENT = Appc.CT_MESSAGE_EVENT
CT_PLAYER_EVENT = Appc.CT_PLAYER_EVENT
CT_GAMESPY_EVENT = Appc.CT_GAMESPY_EVENT
ET_NETWORK_MESSAGE_EVENT = Appc.ET_NETWORK_MESSAGE_EVENT
ET_NETWORK_CONNECT_EVENT = Appc.ET_NETWORK_CONNECT_EVENT
ET_NETWORK_DISCONNECT_EVENT = Appc.ET_NETWORK_DISCONNECT_EVENT
ET_NETWORK_NEW_PLAYER = Appc.ET_NETWORK_NEW_PLAYER
ET_NETWORK_DELETE_PLAYER = Appc.ET_NETWORK_DELETE_PLAYER
ET_NETWORK_GAMESPY_MESSAGE = Appc.ET_NETWORK_GAMESPY_MESSAGE
ET_NETWORK_NAME_CHANGE_EVENT = Appc.ET_NETWORK_NAME_CHANGE_EVENT
CT_TG_MOVIE_ACTION = Appc.CT_TG_MOVIE_ACTION
CT_TG_CREDIT_ACTION = Appc.CT_TG_CREDIT_ACTION
MM_DISPLAY_MODE_WIDTH = Appc.MM_DISPLAY_MODE_WIDTH
MM_DISPLAY_MODE_HEIGHT = Appc.MM_DISPLAY_MODE_HEIGHT
g_kMovieManager = TGMovieManagerPtr(Appc.globals.g_kMovieManager)
g_kUtopiaModule = UtopiaModulePtr(Appc.globals.g_kUtopiaModule)
MAX_ENGINE_NOISES = Appc.MAX_ENGINE_NOISES
g_kSetManager = SetManagerPtr(Appc.globals.g_kSetManager)
g_kVarManager = VarManagerClassPtr(Appc.globals.g_kVarManager)
g_kImageManager = ImageManagerClassPtr(Appc.globals.g_kImageManager)
g_kFocusManager = FocusManagerPtr(Appc.globals.g_kFocusManager)
g_kLODModelManager = LODModelManagerPtr(Appc.globals.g_kLODModelManager)
ET_INPUT_TOGGLE_MAP_MODE = Appc.ET_INPUT_TOGGLE_MAP_MODE
ET_INPUT_TOGGLE_CINEMATIC_MODE = Appc.ET_INPUT_TOGGLE_CINEMATIC_MODE
ET_INPUT_FIRE_PRIMARY = Appc.ET_INPUT_FIRE_PRIMARY
ET_INPUT_FIRE_SECONDARY = Appc.ET_INPUT_FIRE_SECONDARY
ET_INPUT_FIRE_TERTIARY = Appc.ET_INPUT_FIRE_TERTIARY
ET_INPUT_FIRE_TRACTOR = Appc.ET_INPUT_FIRE_TRACTOR
ET_INPUT_TOGGLE_PICK_FIRE = Appc.ET_INPUT_TOGGLE_PICK_FIRE
ET_INPUT_SET_IMPULSE = Appc.ET_INPUT_SET_IMPULSE
ET_INPUT_TURN_LEFT = Appc.ET_INPUT_TURN_LEFT
ET_INPUT_TURN_RIGHT = Appc.ET_INPUT_TURN_RIGHT
ET_INPUT_TURN_UP = Appc.ET_INPUT_TURN_UP
ET_INPUT_TURN_DOWN = Appc.ET_INPUT_TURN_DOWN
ET_INPUT_ROLL_LEFT = Appc.ET_INPUT_ROLL_LEFT
ET_INPUT_ROLL_RIGHT = Appc.ET_INPUT_ROLL_RIGHT
ET_INPUT_INCREASE_SPEED = Appc.ET_INPUT_INCREASE_SPEED
ET_INPUT_DECREASE_SPEED = Appc.ET_INPUT_DECREASE_SPEED
ET_INPUT_SELF_DESTRUCT = Appc.ET_INPUT_SELF_DESTRUCT
ET_INPUT_INTERCEPT = Appc.ET_INPUT_INTERCEPT
ET_INPUT_CYCLE_CAMERA = Appc.ET_INPUT_CYCLE_CAMERA
ET_INPUT_ZOOM = Appc.ET_INPUT_ZOOM
ET_INPUT_CHASE_PLAYER = Appc.ET_INPUT_CHASE_PLAYER
ET_INPUT_CHASE_NEXT = Appc.ET_INPUT_CHASE_NEXT
ET_INPUT_TARGET_NEXT = Appc.ET_INPUT_TARGET_NEXT
ET_INPUT_TARGET_PREV = Appc.ET_INPUT_TARGET_PREV
ET_INPUT_REVERSE_CHASE = Appc.ET_INPUT_REVERSE_CHASE
ET_INPUT_ZOOM_TARGET = Appc.ET_INPUT_ZOOM_TARGET
ET_INPUT_ALLOW_CAMERA_ROTATION = Appc.ET_INPUT_ALLOW_CAMERA_ROTATION
ET_INPUT_TARGET_NEAREST = Appc.ET_INPUT_TARGET_NEAREST
ET_INPUT_TARGET_NEXT_ENEMY = Appc.ET_INPUT_TARGET_NEXT_ENEMY
ET_INPUT_TARGET_NEXT_NAVPOINT = Appc.ET_INPUT_TARGET_NEXT_NAVPOINT
ET_INPUT_TARGET_NEXT_PLANET = Appc.ET_INPUT_TARGET_NEXT_PLANET
ET_INPUT_TARGET_TARGETS_ATTACKER = Appc.ET_INPUT_TARGET_TARGETS_ATTACKER
ET_INPUT_VIEWSCREEN_TARGET = Appc.ET_INPUT_VIEWSCREEN_TARGET
ET_INPUT_VIEWSCREEN_FORWARD = Appc.ET_INPUT_VIEWSCREEN_FORWARD
ET_INPUT_VIEWSCREEN_LEFT = Appc.ET_INPUT_VIEWSCREEN_LEFT
ET_INPUT_VIEWSCREEN_RIGHT = Appc.ET_INPUT_VIEWSCREEN_RIGHT
ET_INPUT_VIEWSCREEN_BACKWARD = Appc.ET_INPUT_VIEWSCREEN_BACKWARD
ET_INPUT_VIEWSCREEN_UP = Appc.ET_INPUT_VIEWSCREEN_UP
ET_INPUT_VIEWSCREEN_DOWN = Appc.ET_INPUT_VIEWSCREEN_DOWN
ET_INPUT_FIRSTPERSON = Appc.ET_INPUT_FIRSTPERSON
ET_INPUT_CLEAR_TARGET = Appc.ET_INPUT_CLEAR_TARGET
ET_INPUT_CINEMATIC_DROPANDWATCH = Appc.ET_INPUT_CINEMATIC_DROPANDWATCH
ET_INPUT_CINEMATIC_CHASE = Appc.ET_INPUT_CINEMATIC_CHASE
ET_INPUT_CINEMATIC_TARGET = Appc.ET_INPUT_CINEMATIC_TARGET
ET_INPUT_CINEMATIC_TORPCAM = Appc.ET_INPUT_CINEMATIC_TORPCAM
ET_INPUT_CINEMATIC_WIDETARGET = Appc.ET_INPUT_CINEMATIC_WIDETARGET
ET_INPUT_CINEMATIC_FREEORBIT = Appc.ET_INPUT_CINEMATIC_FREEORBIT
ET_INPUT_CINEMATIC_1 = Appc.ET_INPUT_CINEMATIC_1
ET_INPUT_CINEMATIC_2 = Appc.ET_INPUT_CINEMATIC_2
ET_INPUT_TOGGLE_CURSOR = Appc.ET_INPUT_TOGGLE_CURSOR
ET_INPUT_SET_SLOW_MODE = Appc.ET_INPUT_SET_SLOW_MODE
ET_INPUT_TALK_TO_HELM = Appc.ET_INPUT_TALK_TO_HELM
ET_INPUT_TALK_TO_TACTICAL = Appc.ET_INPUT_TALK_TO_TACTICAL
ET_INPUT_TALK_TO_XO = Appc.ET_INPUT_TALK_TO_XO
ET_INPUT_TALK_TO_SCIENCE = Appc.ET_INPUT_TALK_TO_SCIENCE
ET_INPUT_TALK_TO_ENGINEERING = Appc.ET_INPUT_TALK_TO_ENGINEERING
ET_INPUT_TALK_TO_GUEST = Appc.ET_INPUT_TALK_TO_GUEST
ET_INPUT_SKIP_EVENTS = Appc.ET_INPUT_SKIP_EVENTS
ET_INPUT_DEBUG_KILL_TARGET = Appc.ET_INPUT_DEBUG_KILL_TARGET
ET_INPUT_DEBUG_QUICK_REPAIR = Appc.ET_INPUT_DEBUG_QUICK_REPAIR
ET_INPUT_DEBUG_GOD_MODE = Appc.ET_INPUT_DEBUG_GOD_MODE
ET_INPUT_DEBUG_LOAD_QUANTUMS = Appc.ET_INPUT_DEBUG_LOAD_QUANTUMS
ET_INPUT_DEBUG_TOGGLE_EDIT_MODE = Appc.ET_INPUT_DEBUG_TOGGLE_EDIT_MODE
ET_INPUT_TOGGLE_SCORE_WINDOW = Appc.ET_INPUT_TOGGLE_SCORE_WINDOW
ET_INPUT_TOGGLE_CHAT_WINDOW = Appc.ET_INPUT_TOGGLE_CHAT_WINDOW
ET_INPUT_SELECT_X = Appc.ET_INPUT_SELECT_X
ET_INPUT_PRE_SELECT_OPTION = Appc.ET_INPUT_PRE_SELECT_OPTION
ET_INPUT_SELECT_OPTION = Appc.ET_INPUT_SELECT_OPTION
ET_INPUT_CLOSE_MENU = Appc.ET_INPUT_CLOSE_MENU
ET_INPUT_TOGGLE_CONSOLE = Appc.ET_INPUT_TOGGLE_CONSOLE
ET_INPUT_TOGGLE_OPTIONS = Appc.ET_INPUT_TOGGLE_OPTIONS
ET_INPUT_TAB_FOCUS_CHANGE = Appc.ET_INPUT_TAB_FOCUS_CHANGE
ET_INPUT_PRINT_SCREEN = Appc.ET_INPUT_PRINT_SCREEN
ET_INPUT_TOGGLE_BRIDGE_AND_TACTICAL = Appc.ET_INPUT_TOGGLE_BRIDGE_AND_TACTICAL
CT_OPT_TORPS_READY = Appc.CT_OPT_TORPS_READY
CT_OPT_TR_EVENT_HANDLER = Appc.CT_OPT_TR_EVENT_HANDLER
RULENUM_INVALID = Appc.RULENUM_INVALID
g_kTextureAnimManager = TextureAnimManagerPtr(Appc.globals.g_kTextureAnimManager)
g_kInterfaceModule = InterfaceModulePtr(Appc.globals.g_kInterfaceModule)
MWT_BRIDGE = Appc.MWT_BRIDGE
MWT_TACTICAL = Appc.MWT_TACTICAL
MWT_CONSOLE = Appc.MWT_CONSOLE
MWT_EDITOR = Appc.MWT_EDITOR
MWT_OPTIONS = Appc.MWT_OPTIONS
MWT_SUBTITLE = Appc.MWT_SUBTITLE
MWT_TACTICAL_MAP = Appc.MWT_TACTICAL_MAP
MWT_CINEMATIC = Appc.MWT_CINEMATIC
MWT_MULTIPLAYER = Appc.MWT_MULTIPLAYER
MWT_CD_CHECK = Appc.MWT_CD_CHECK
MWT_MODAL_DIALOG = Appc.MWT_MODAL_DIALOG
ST_MAX_LEVEL_COLORS = Appc.ST_MAX_LEVEL_COLORS
g_kSTButtonColors = NiColorAPtr(Appc.globals.g_kSTButtonColors)
g_kSTButtonMarkerDefault = NiColorAPtr(Appc.globals.g_kSTButtonMarkerDefault)
g_kSTButtonMarkerHighlighted = NiColorAPtr(Appc.globals.g_kSTButtonMarkerHighlighted)
g_kSTButtonMarkerSelected = NiColorAPtr(Appc.globals.g_kSTButtonMarkerSelected)
g_kSTButtonMarkerGray = NiColorAPtr(Appc.globals.g_kSTButtonMarkerGray)
g_kSTButtonCheckmarkOn = NiColorAPtr(Appc.globals.g_kSTButtonCheckmarkOn)
g_kSTButtonCheckmarkOff = NiColorAPtr(Appc.globals.g_kSTButtonCheckmarkOff)
g_kSTMenuArrowColor = NiColorAPtr(Appc.globals.g_kSTMenuArrowColor)
g_kSTMenu1NormalBase = NiColorAPtr(Appc.globals.g_kSTMenu1NormalBase)
g_kSTMenu1HighlightedBase = NiColorAPtr(Appc.globals.g_kSTMenu1HighlightedBase)
g_kSTMenu1Disabled = NiColorAPtr(Appc.globals.g_kSTMenu1Disabled)
g_kSTMenu1OpenedHighlightedBase = NiColorAPtr(Appc.globals.g_kSTMenu1OpenedHighlightedBase)
g_kSTMenu1Selected = NiColorAPtr(Appc.globals.g_kSTMenu1Selected)
g_kSTMenu2NormalBase = NiColorAPtr(Appc.globals.g_kSTMenu2NormalBase)
g_kSTMenu2HighlightedBase = NiColorAPtr(Appc.globals.g_kSTMenu2HighlightedBase)
g_kSTMenu2Disabled = NiColorAPtr(Appc.globals.g_kSTMenu2Disabled)
g_kSTMenu2OpenedHighlightedBase = NiColorAPtr(Appc.globals.g_kSTMenu2OpenedHighlightedBase)
g_kSTMenu2Selected = NiColorAPtr(Appc.globals.g_kSTMenu2Selected)
g_kSTMenu3NormalBase = NiColorAPtr(Appc.globals.g_kSTMenu3NormalBase)
g_kSTMenu3HighlightedBase = NiColorAPtr(Appc.globals.g_kSTMenu3HighlightedBase)
g_kSTMenu3Disabled = NiColorAPtr(Appc.globals.g_kSTMenu3Disabled)
g_kSTMenu3OpenedHighlightedBase = NiColorAPtr(Appc.globals.g_kSTMenu3OpenedHighlightedBase)
g_kSTMenu3Selected = NiColorAPtr(Appc.globals.g_kSTMenu3Selected)
g_kSTMenu4NormalBase = NiColorAPtr(Appc.globals.g_kSTMenu4NormalBase)
g_kSTMenu4HighlightedBase = NiColorAPtr(Appc.globals.g_kSTMenu4HighlightedBase)
g_kSTMenu4Disabled = NiColorAPtr(Appc.globals.g_kSTMenu4Disabled)
g_kSTMenu4OpenedHighlightedBase = NiColorAPtr(Appc.globals.g_kSTMenu4OpenedHighlightedBase)
g_kSTMenu4Selected = NiColorAPtr(Appc.globals.g_kSTMenu4Selected)
g_kSTMenuTextColor = NiColorAPtr(Appc.globals.g_kSTMenuTextColor)
g_kSTMenuTextSelectedColor = NiColorAPtr(Appc.globals.g_kSTMenuTextSelectedColor)
g_kSTMenuTextHighlightColor = NiColorAPtr(Appc.globals.g_kSTMenuTextHighlightColor)
g_kTitleColor = NiColorAPtr(Appc.globals.g_kTitleColor)
g_kInterfaceBorderColor = NiColorAPtr(Appc.globals.g_kInterfaceBorderColor)
g_kLeftSeparatorColor = NiColorAPtr(Appc.globals.g_kLeftSeparatorColor)
g_kSTRadarBorderHighlighted = NiColorAPtr(Appc.globals.g_kSTRadarBorderHighlighted)
g_kTextEntryColor = NiColorAPtr(Appc.globals.g_kTextEntryColor)
g_kTextHighlightColor = NiColorAPtr(Appc.globals.g_kTextHighlightColor)
g_kTextEntryBackgroundColor = NiColorAPtr(Appc.globals.g_kTextEntryBackgroundColor)
g_kTextEntryBackgroundHighlightColor = NiColorAPtr(Appc.globals.g_kTextEntryBackgroundHighlightColor)
g_kSubsystemFillColor = NiColorAPtr(Appc.globals.g_kSubsystemFillColor)
g_kSubsystemEmptyColor = NiColorAPtr(Appc.globals.g_kSubsystemEmptyColor)
g_kSubsystemDisabledColor = NiColorAPtr(Appc.globals.g_kSubsystemDisabledColor)
g_kTacWeaponsCtrlHeaderTextColor = NiColorAPtr(Appc.globals.g_kTacWeaponsCtrlHeaderTextColor)
g_kRadarBorder = NiColorAPtr(Appc.globals.g_kRadarBorder)
g_kSTRadarIncomingTorpColor = NiColorAPtr(Appc.globals.g_kSTRadarIncomingTorpColor)
g_kRadarFriendlyColor = NiColorAPtr(Appc.globals.g_kRadarFriendlyColor)
g_kRadarEnemyColor = NiColorAPtr(Appc.globals.g_kRadarEnemyColor)
g_kRadarNeutralColor = NiColorAPtr(Appc.globals.g_kRadarNeutralColor)
g_kRadarUnknownColor = NiColorAPtr(Appc.globals.g_kRadarUnknownColor)
g_pConditionColors = NiColorAPtr(Appc.globals.g_pConditionColors)
g_kTIPhotonReadyColor = NiColorAPtr(Appc.globals.g_kTIPhotonReadyColor)
g_kTIPhotonNotReadyColor = NiColorAPtr(Appc.globals.g_kTIPhotonNotReadyColor)
g_kMainMenuButtonColor = NiColorAPtr(Appc.globals.g_kMainMenuButtonColor)
g_kMainMenuButtonHighlightedColor = NiColorAPtr(Appc.globals.g_kMainMenuButtonHighlightedColor)
g_kMainMenuButtonSelectedColor = NiColorAPtr(Appc.globals.g_kMainMenuButtonSelectedColor)
g_kMainMenuButton1Color = NiColorAPtr(Appc.globals.g_kMainMenuButton1Color)
g_kMainMenuButton1HighlightedColor = NiColorAPtr(Appc.globals.g_kMainMenuButton1HighlightedColor)
g_kMainMenuButton1SelectedColor = NiColorAPtr(Appc.globals.g_kMainMenuButton1SelectedColor)
g_kMainMenuButton2Color = NiColorAPtr(Appc.globals.g_kMainMenuButton2Color)
g_kMainMenuButton2HighlightedColor = NiColorAPtr(Appc.globals.g_kMainMenuButton2HighlightedColor)
g_kMainMenuButton2SelectedColor = NiColorAPtr(Appc.globals.g_kMainMenuButton2SelectedColor)
g_kMainMenuButton3Color = NiColorAPtr(Appc.globals.g_kMainMenuButton3Color)
g_kMainMenuButton3HighlightedColor = NiColorAPtr(Appc.globals.g_kMainMenuButton3HighlightedColor)
g_kMainMenuButton3SelectedColor = NiColorAPtr(Appc.globals.g_kMainMenuButton3SelectedColor)
g_kMainMenuBorderMainColor = NiColorAPtr(Appc.globals.g_kMainMenuBorderMainColor)
g_kMainMenuBorderOffColor = NiColorAPtr(Appc.globals.g_kMainMenuBorderOffColor)
g_kMainMenuBorderBlock1Color = NiColorAPtr(Appc.globals.g_kMainMenuBorderBlock1Color)
g_kMainMenuBorderTopColor = NiColorAPtr(Appc.globals.g_kMainMenuBorderTopColor)
g_kDamageDisplayDestroyedColor = NiColorAPtr(Appc.globals.g_kDamageDisplayDestroyedColor)
g_kDamageDisplayDamagedColor = NiColorAPtr(Appc.globals.g_kDamageDisplayDamagedColor)
g_kDamageDisplayDisabledColor = NiColorAPtr(Appc.globals.g_kDamageDisplayDisabledColor)
g_kEngineeringShieldsColor = NiColorAPtr(Appc.globals.g_kEngineeringShieldsColor)
g_kEngineeringEnginesColor = NiColorAPtr(Appc.globals.g_kEngineeringEnginesColor)
g_kEngineeringWeaponsColor = NiColorAPtr(Appc.globals.g_kEngineeringWeaponsColor)
g_kEngineeringSensorsColor = NiColorAPtr(Appc.globals.g_kEngineeringSensorsColor)
g_kEngineeringCloakColor = NiColorAPtr(Appc.globals.g_kEngineeringCloakColor)
g_kEngineeringTractorColor = NiColorAPtr(Appc.globals.g_kEngineeringTractorColor)
g_kEngineeringWarpCoreColor = NiColorAPtr(Appc.globals.g_kEngineeringWarpCoreColor)
g_kEngineeringMainPowerColor = NiColorAPtr(Appc.globals.g_kEngineeringMainPowerColor)
g_kEngineeringBackupPowerColor = NiColorAPtr(Appc.globals.g_kEngineeringBackupPowerColor)
g_kEngineeringCtrlBkgndLineColor = NiColorAPtr(Appc.globals.g_kEngineeringCtrlBkgndLineColor)
g_kQuickBattleBrightRed = NiColorAPtr(Appc.globals.g_kQuickBattleBrightRed)
g_kMultiplayerBorderBlue = NiColorAPtr(Appc.globals.g_kMultiplayerBorderBlue)
g_kMultiplayerBorderPurple = NiColorAPtr(Appc.globals.g_kMultiplayerBorderPurple)
g_kMultiplayerStylizedPurple = NiColorAPtr(Appc.globals.g_kMultiplayerStylizedPurple)
g_kMultiplayerButtonPurple = NiColorAPtr(Appc.globals.g_kMultiplayerButtonPurple)
g_kMultiplayerButtonOrange = NiColorAPtr(Appc.globals.g_kMultiplayerButtonOrange)
g_kMultiplayerDividerPurple = NiColorAPtr(Appc.globals.g_kMultiplayerDividerPurple)
STBSF_SIZE_TO_PARENT = Appc.STBSF_SIZE_TO_PARENT
STBSF_SIZE_TO_TEXT = Appc.STBSF_SIZE_TO_TEXT
STB_CHOSEN = Appc.STB_CHOSEN
STB_AUTO_CHOOSE = Appc.STB_AUTO_CHOOSE
STB_CHOOSABLE = Appc.STB_CHOOSABLE
STB_DONT_USE_END_CAP_SPACE = Appc.STB_DONT_USE_END_CAP_SPACE
STBSF_WRAP_BUTTON_TEXT = Appc.STBSF_WRAP_BUTTON_TEXT
STB_DEFAULTS = Appc.STB_DEFAULTS
MAX_ARC_LEVEL_INDEX = Appc.MAX_ARC_LEVEL_INDEX
g_kKeyboardBinding = KeyboardBindingPtr(Appc.globals.g_kKeyboardBinding)
AT_ONE = Appc.AT_ONE
AT_TWO = Appc.AT_TWO
AT_THREE = Appc.AT_THREE
AT_FOUR = Appc.AT_FOUR
AT_MAX_NUM_AMMO_TYPES = Appc.AT_MAX_NUM_AMMO_TYPES
GAME_INITIALIZE_MESSAGE = Appc.GAME_INITIALIZE_MESSAGE
GAME_INITIALIZE_DONE_MESSAGE = Appc.GAME_INITIALIZE_DONE_MESSAGE
CREATE_OBJECT_MESSAGE = Appc.CREATE_OBJECT_MESSAGE
CREATE_PLAYER_OBJECT_MESSAGE = Appc.CREATE_PLAYER_OBJECT_MESSAGE
DESTROY_OBJECT_MESSAGE = Appc.DESTROY_OBJECT_MESSAGE
TORPEDO_POSITION_MESSAGE = Appc.TORPEDO_POSITION_MESSAGE
HOST_EVENT_MESSAGE = Appc.HOST_EVENT_MESSAGE
START_FIRING_MESSAGE = Appc.START_FIRING_MESSAGE
STOP_FIRING_MESSAGE = Appc.STOP_FIRING_MESSAGE
STOP_FIRING_AT_TARGET_MESSAGE = Appc.STOP_FIRING_AT_TARGET_MESSAGE
SUBSYSTEM_STATE_CHANGED_MESSAGE = Appc.SUBSYSTEM_STATE_CHANGED_MESSAGE
ADD_TO_REPAIR_LIST_MESSAGE = Appc.ADD_TO_REPAIR_LIST_MESSAGE
CLIENT_EVENT_MESSAGE = Appc.CLIENT_EVENT_MESSAGE
CHANGED_TARGET_MESSAGE = Appc.CHANGED_TARGET_MESSAGE
START_CLOAKING_MESSAGE = Appc.START_CLOAKING_MESSAGE
STOP_CLOAKING_MESSAGE = Appc.STOP_CLOAKING_MESSAGE
START_WARP_MESSAGE = Appc.START_WARP_MESSAGE
REPAIR_LIST_PRIORITY_MESSAGE = Appc.REPAIR_LIST_PRIORITY_MESSAGE
SET_PHASER_LEVEL_MESSAGE = Appc.SET_PHASER_LEVEL_MESSAGE
SELF_DESTRUCT_REQUEST_MESSAGE = Appc.SELF_DESTRUCT_REQUEST_MESSAGE
DELETE_OBJECT_FROM_GAME_MESSAGE = Appc.DELETE_OBJECT_FROM_GAME_MESSAGE
CLIENT_COLLISION_MESSAGE = Appc.CLIENT_COLLISION_MESSAGE
COLLISION_ENABLED_MESSAGE = Appc.COLLISION_ENABLED_MESSAGE
NEW_PLAYER_IN_GAME_MESSAGE = Appc.NEW_PLAYER_IN_GAME_MESSAGE
DELETE_PLAYER_FROM_GAME_MESSAGE = Appc.DELETE_PLAYER_FROM_GAME_MESSAGE
CREATE_TORP_MESSAGE = Appc.CREATE_TORP_MESSAGE
CREATE_PULSE_MESSAGE = Appc.CREATE_PULSE_MESSAGE
TORPEDO_TYPE_CHANGED_MESSAGE = Appc.TORPEDO_TYPE_CHANGED_MESSAGE
SHIP_UPDATE_MESSAGE = Appc.SHIP_UPDATE_MESSAGE
VERIFY_ENTER_SET_MESSAGE = Appc.VERIFY_ENTER_SET_MESSAGE
SEND_OBJECT_MESSAGE = Appc.SEND_OBJECT_MESSAGE
VERIFY_EXITED_WARP_MESSAGE = Appc.VERIFY_EXITED_WARP_MESSAGE
DO_CHECKSUM_MESSAGE = Appc.DO_CHECKSUM_MESSAGE
CHECKSUM_MESSAGE = Appc.CHECKSUM_MESSAGE
SYSTEM_CHECKSUM_FAILED = Appc.SYSTEM_CHECKSUM_FAILED
VERSION_DIFFERENT = Appc.VERSION_DIFFERENT
BEGIN_SEND_FILE_MESSAGE = Appc.BEGIN_SEND_FILE_MESSAGE
FILE_MESSAGE = Appc.FILE_MESSAGE
DIRECTORY_MESSAGE = Appc.DIRECTORY_MESSAGE
FILE_RECEIVED_ACK_MESSAGE = Appc.FILE_RECEIVED_ACK_MESSAGE
SEND_FILE_COMPLETED_MESSAGE = Appc.SEND_FILE_COMPLETED_MESSAGE
DAMAGE_VOLUME_MESSAGE = Appc.DAMAGE_VOLUME_MESSAGE
CLIENT_READY_MESSAGE = Appc.CLIENT_READY_MESSAGE
MAX_MESSAGE_TYPES = Appc.MAX_MESSAGE_TYPES
NiColor_WHITE = NiColorPtr(Appc.globals.NiColor_WHITE)
NiColor_BLACK = NiColorPtr(Appc.globals.NiColor_BLACK)
NiColorA_WHITE = NiColorAPtr(Appc.globals.NiColorA_WHITE)
NiColorA_BLACK = NiColorAPtr(Appc.globals.NiColorA_BLACK)
NiPoint2_ZERO = NiPoint2Ptr(Appc.globals.NiPoint2_ZERO)
NiPoint2_UNIT_X = NiPoint2Ptr(Appc.globals.NiPoint2_UNIT_X)
NiPoint2_UNIT_Y = NiPoint2Ptr(Appc.globals.NiPoint2_UNIT_Y)
TGColorA_WHITE = NiColorAPtr(Appc.globals.TGColorA_WHITE)
TGColorA_BLACK = NiColorAPtr(Appc.globals.TGColorA_BLACK)
