# C:\Utopia\Current\Build\scripts\ships\Hardpoints\rankuf.py
# This file was automatically generated - modify at your own risk.
# 

import App
import GlobalPropertyTemplates
	# The line below is needed by the editor to restore
	# the name of the parent script.
ParentPropertyScript = "ships.Hardpoints.birdofprey"
if not ('g_bIsModelPropertyEditor' in dir(App)):
	ParentModule = __import__("ships.Hardpoints.birdofprey", globals(), locals(), ['*'])
	reload(ParentModule)
# Setting up local templates.
#################################################
FwdTorpedo = App.TorpedoTubeProperty_Create("Fwd Torpedo")

FwdTorpedo.SetMaxCondition(3000.000000)
FwdTorpedo.SetCritical(0)
FwdTorpedo.SetTargetable(1)
FwdTorpedo.SetPrimary(1)
FwdTorpedo.SetPosition(0.000000, 0.816025, -0.033764)
FwdTorpedo.SetPosition2D(64.000000, 10.000000)
FwdTorpedo.SetRepairComplexity(2.000000)
FwdTorpedo.SetDisabledPercentage(0.750000)
FwdTorpedo.SetRadius(0.080000)
FwdTorpedo.SetDumbfire(1)
FwdTorpedo.SetWeaponID(1)
FwdTorpedo.SetGroups(1)
FwdTorpedo.SetDamageRadiusFactor(0.200000)
FwdTorpedo.SetIconNum(370)
FwdTorpedo.SetIconPositionX(75.000000)
FwdTorpedo.SetIconPositionY(35.000000)
FwdTorpedo.SetIconAboveShip(1)
FwdTorpedo.SetImmediateDelay(0.250000)
FwdTorpedo.SetReloadDelay(20.000000)
FwdTorpedo.SetMaxReady(1)
FwdTorpedoDirection = App.TGPoint3()
FwdTorpedoDirection.SetXYZ(0.000000, 1.000000, 0.000000)
FwdTorpedo.SetDirection(FwdTorpedoDirection)
FwdTorpedoRight = App.TGPoint3()
FwdTorpedoRight.SetXYZ(1.000000, 0.000000, 0.000000)
FwdTorpedo.SetRight(FwdTorpedoRight)
App.g_kModelPropertyManager.RegisterLocalTemplate(FwdTorpedo)
#################################################
ShieldGenerator = App.ShieldProperty_Create("Shield Generator")

ShieldGenerator.SetMaxCondition(4000.000000)
ShieldGenerator.SetCritical(0)
ShieldGenerator.SetTargetable(1)
ShieldGenerator.SetPrimary(1)
ShieldGenerator.SetPosition(0.000000, 0.020000, 0.120000)
ShieldGenerator.SetPosition2D(64.000000, 60.000000)
ShieldGenerator.SetRepairComplexity(2.000000)
ShieldGenerator.SetDisabledPercentage(0.750000)
ShieldGenerator.SetRadius(0.120000)
ShieldGenerator.SetNormalPowerPerSecond(50.000000)
ShieldGeneratorShieldGlowColor = App.TGColorA()
ShieldGeneratorShieldGlowColor.SetRGBA(0.266667, 0.729412, 0.301961, 0.466667)
ShieldGenerator.SetShieldGlowColor(ShieldGeneratorShieldGlowColor)
ShieldGenerator.SetShieldGlowDecay(1.000000)
ShieldGenerator.SetMaxShields(ShieldGenerator.FRONT_SHIELDS, 4500.000000)
ShieldGenerator.SetMaxShields(ShieldGenerator.REAR_SHIELDS, 4500.000000)
ShieldGenerator.SetMaxShields(ShieldGenerator.TOP_SHIELDS, 4500.000000)
ShieldGenerator.SetMaxShields(ShieldGenerator.BOTTOM_SHIELDS, 4500.000000)
ShieldGenerator.SetMaxShields(ShieldGenerator.LEFT_SHIELDS, 4500.000000)
ShieldGenerator.SetMaxShields(ShieldGenerator.RIGHT_SHIELDS, 4500.000000)
ShieldGenerator.SetShieldChargePerSecond(ShieldGenerator.FRONT_SHIELDS, 24.000000)
ShieldGenerator.SetShieldChargePerSecond(ShieldGenerator.REAR_SHIELDS, 8.000000)
ShieldGenerator.SetShieldChargePerSecond(ShieldGenerator.TOP_SHIELDS, 8.000000)
ShieldGenerator.SetShieldChargePerSecond(ShieldGenerator.BOTTOM_SHIELDS, 4.000000)
ShieldGenerator.SetShieldChargePerSecond(ShieldGenerator.LEFT_SHIELDS, 8.000000)
ShieldGenerator.SetShieldChargePerSecond(ShieldGenerator.RIGHT_SHIELDS, 8.000000)
App.g_kModelPropertyManager.RegisterLocalTemplate(ShieldGenerator)
#################################################
Hull = App.HullProperty_Create("Hull")

Hull.SetMaxCondition(7000.000000)
Hull.SetCritical(1)
Hull.SetTargetable(1)
Hull.SetPrimary(1)
Hull.SetPosition(0.000000, -0.150000, 0.000000)
Hull.SetPosition2D(64.000000, 60.000000)
Hull.SetRepairComplexity(1.000000)
Hull.SetDisabledPercentage(0.000000)
Hull.SetRadius(0.500000)
App.g_kModelPropertyManager.RegisterLocalTemplate(Hull)
#################################################
WarpCore = App.PowerProperty_Create("Warp Core")

WarpCore.SetMaxCondition(5000.000000)
WarpCore.SetCritical(1)
WarpCore.SetTargetable(1)
WarpCore.SetPrimary(1)
WarpCore.SetPosition(0.000000, -0.350000, 0.000000)
WarpCore.SetPosition2D(64.000000, 75.000000)
WarpCore.SetRepairComplexity(1.000000)
WarpCore.SetDisabledPercentage(0.500000)
WarpCore.SetRadius(0.170000)
WarpCore.SetMainBatteryLimit(100000.000000)
WarpCore.SetBackupBatteryLimit(100000.000000)
WarpCore.SetMainConduitCapacity(500.000000)
WarpCore.SetBackupConduitCapacity(300.000000)
WarpCore.SetPowerOutput(400.000000)
App.g_kModelPropertyManager.RegisterLocalTemplate(WarpCore)
#################################################
Torpedoes = App.TorpedoSystemProperty_Create("Torpedoes")

Torpedoes.SetMaxCondition(400.000000)
Torpedoes.SetCritical(0)
Torpedoes.SetTargetable(0)
Torpedoes.SetPrimary(1)
Torpedoes.SetPosition(0.000000, 0.650000, 0.040000)
Torpedoes.SetPosition2D(64.000000, 40.000000)
Torpedoes.SetRepairComplexity(6.000000)
Torpedoes.SetDisabledPercentage(0.750000)
Torpedoes.SetRadius(0.090000)
Torpedoes.SetNormalPowerPerSecond(5.000000)
Torpedoes.SetWeaponSystemType(Torpedoes.WST_TORPEDO)
Torpedoes.SetSingleFire(0)
Torpedoes.SetAimedWeapon(1)
kFiringChainString = App.TGString()
kFiringChainString.SetString("")
Torpedoes.SetFiringChainString(kFiringChainString)
Torpedoes.SetMaxTorpedoes(0, 150)
Torpedoes.SetTorpedoScript(0, "Tactical.Projectiles.KlingonTorpedo")
Torpedoes.SetMaxTorpedoes(1, 10)
Torpedoes.SetTorpedoScript(1, "Tactical.Projectiles.AntimatterTorpedo")
Torpedoes.SetNumAmmoTypes(2)
App.g_kModelPropertyManager.RegisterLocalTemplate(Torpedoes)
#################################################
Engineering = App.RepairSubsystemProperty_Create("Engineering")

Engineering.SetMaxCondition(400.000000)
Engineering.SetCritical(0)
Engineering.SetTargetable(0)
Engineering.SetPrimary(1)
Engineering.SetPosition(0.000000, -0.100000, 0.100000)
Engineering.SetPosition2D(64.000000, 80.000000)
Engineering.SetRepairComplexity(4.000000)
Engineering.SetDisabledPercentage(0.100000)
Engineering.SetRadius(0.150000)
Engineering.SetNormalPowerPerSecond(1.000000)
Engineering.SetMaxRepairPoints(30.000000)
Engineering.SetNumRepairTeams(2)
App.g_kModelPropertyManager.RegisterLocalTemplate(Engineering)

# Property load function.
def LoadPropertySet(pObj):
	"Sets up the object's properties."
	if not ('g_bIsModelPropertyEditor' in dir(App)):
		ParentModule.LoadPropertySet(pObj)
	prop = App.g_kModelPropertyManager.FindByName("Hull", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
	prop = App.g_kModelPropertyManager.FindByName("Shield Generator", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
	prop = App.g_kModelPropertyManager.FindByName("Warp Core", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
	prop = App.g_kModelPropertyManager.FindByName("Engineering", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
	prop = App.g_kModelPropertyManager.FindByName("Fwd Torpedo", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
