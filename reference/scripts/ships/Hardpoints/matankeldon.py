# C:\Utopia\Current\Build\scripts\ships\Hardpoints\matankeldon.py
# This file was automatically generated - modify at your own risk.
# 

import App
import GlobalPropertyTemplates
	# The line below is needed by the editor to restore
	# the name of the parent script.
ParentPropertyScript = "ships.Hardpoints.keldon"
if not ('g_bIsModelPropertyEditor' in dir(App)):
	ParentModule = __import__("ships.Hardpoints.keldon", globals(), locals(), ['*'])
	reload(ParentModule)
# Setting up local templates.
#################################################
Hull = App.HullProperty_Create("Hull")

Hull.SetMaxCondition(12000.000000)
Hull.SetCritical(1)
Hull.SetTargetable(1)
Hull.SetPrimary(1)
Hull.SetPosition(0.000000, -0.184000, -0.080000)
Hull.SetPosition2D(64.000000, 50.000000)
Hull.SetRepairComplexity(1.000000)
Hull.SetDisabledPercentage(0.000000)
Hull.SetRadius(1.100000)
App.g_kModelPropertyManager.RegisterLocalTemplate(Hull)
#################################################
ShieldGenerator = App.ShieldProperty_Create("Shield Generator")

ShieldGenerator.SetMaxCondition(12000.000000)
ShieldGenerator.SetCritical(0)
ShieldGenerator.SetTargetable(1)
ShieldGenerator.SetPrimary(1)
ShieldGenerator.SetPosition(0.000000, -0.800000, 0.400000)
ShieldGenerator.SetPosition2D(64.000000, 50.000000)
ShieldGenerator.SetRepairComplexity(4.000000)
ShieldGenerator.SetDisabledPercentage(0.750000)
ShieldGenerator.SetRadius(0.350000)
ShieldGenerator.SetNormalPowerPerSecond(70.000000)
ShieldGeneratorShieldGlowColor = App.TGColorA()
ShieldGeneratorShieldGlowColor.SetRGBA(1.000000, 0.647059, 0.192157, 0.466667)
ShieldGenerator.SetShieldGlowColor(ShieldGeneratorShieldGlowColor)
ShieldGenerator.SetShieldGlowDecay(1.000000)
ShieldGenerator.SetMaxShields(ShieldGenerator.FRONT_SHIELDS, 8000.000000)
ShieldGenerator.SetMaxShields(ShieldGenerator.REAR_SHIELDS, 3000.000000)
ShieldGenerator.SetMaxShields(ShieldGenerator.TOP_SHIELDS, 5000.000000)
ShieldGenerator.SetMaxShields(ShieldGenerator.BOTTOM_SHIELDS, 4000.000000)
ShieldGenerator.SetMaxShields(ShieldGenerator.LEFT_SHIELDS, 5000.000000)
ShieldGenerator.SetMaxShields(ShieldGenerator.RIGHT_SHIELDS, 5000.000000)
ShieldGenerator.SetShieldChargePerSecond(ShieldGenerator.FRONT_SHIELDS, 15.000000)
ShieldGenerator.SetShieldChargePerSecond(ShieldGenerator.REAR_SHIELDS, 5.000000)
ShieldGenerator.SetShieldChargePerSecond(ShieldGenerator.TOP_SHIELDS, 8.000000)
ShieldGenerator.SetShieldChargePerSecond(ShieldGenerator.BOTTOM_SHIELDS, 5.000000)
ShieldGenerator.SetShieldChargePerSecond(ShieldGenerator.LEFT_SHIELDS, 8.000000)
ShieldGenerator.SetShieldChargePerSecond(ShieldGenerator.RIGHT_SHIELDS, 8.000000)
App.g_kModelPropertyManager.RegisterLocalTemplate(ShieldGenerator)
#################################################
WarpCore = App.PowerProperty_Create("Warp Core")

WarpCore.SetMaxCondition(5000.000000)
WarpCore.SetCritical(0)
WarpCore.SetTargetable(1)
WarpCore.SetPrimary(1)
WarpCore.SetPosition(0.000000, -0.500000, 0.000000)
WarpCore.SetPosition2D(64.000000, 65.000000)
WarpCore.SetRepairComplexity(2.000000)
WarpCore.SetDisabledPercentage(0.750000)
WarpCore.SetRadius(0.470000)
WarpCore.SetMainBatteryLimit(160000.000000)
WarpCore.SetBackupBatteryLimit(50000.000000)
WarpCore.SetMainConduitCapacity(1200.000000)
WarpCore.SetBackupConduitCapacity(600.000000)
WarpCore.SetPowerOutput(900.000000)
App.g_kModelPropertyManager.RegisterLocalTemplate(WarpCore)
#################################################
RepairSubsystem = App.RepairSubsystemProperty_Create("Repair Subsystem")

RepairSubsystem.SetMaxCondition(2000.000000)
RepairSubsystem.SetCritical(0)
RepairSubsystem.SetTargetable(0)
RepairSubsystem.SetPrimary(1)
RepairSubsystem.SetPosition(0.023350, -2.369420, -0.010000)
RepairSubsystem.SetPosition2D(64.000000, 65.000000)
RepairSubsystem.SetRepairComplexity(4.000000)
RepairSubsystem.SetDisabledPercentage(0.100000)
RepairSubsystem.SetRadius(0.100000)
RepairSubsystem.SetNormalPowerPerSecond(1.000000)
RepairSubsystem.SetMaxRepairPoints(20.000000)
RepairSubsystem.SetNumRepairTeams(2)
App.g_kModelPropertyManager.RegisterLocalTemplate(RepairSubsystem)
#################################################
CloakingDevice = App.CloakingSubsystemProperty_Create("Cloaking Device")

CloakingDevice.SetMaxCondition(1000.000000)
CloakingDevice.SetCritical(0)
CloakingDevice.SetTargetable(1)
CloakingDevice.SetPrimary(1)
CloakingDevice.SetPosition(0.000000, -1.200000, 0.400000)
CloakingDevice.SetPosition2D(80.000000, 60.000000)
CloakingDevice.SetRepairComplexity(6.000000)
CloakingDevice.SetDisabledPercentage(0.750000)
CloakingDevice.SetRadius(0.300000)
CloakingDevice.SetNormalPowerPerSecond(120.000000)
CloakingDevice.SetCloakStrength(100.000000)
App.g_kModelPropertyManager.RegisterLocalTemplate(CloakingDevice)

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
	prop = App.g_kModelPropertyManager.FindByName("Repair Subsystem", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
	prop = App.g_kModelPropertyManager.FindByName("Cloaking Device", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
