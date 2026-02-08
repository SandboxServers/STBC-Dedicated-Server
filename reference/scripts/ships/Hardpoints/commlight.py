# C:\Utopia\Current\Build\scripts\ships\Hardpoints\commlight.py
# This file was automatically generated - modify at your own risk.
# 

import App
import GlobalPropertyTemplates
# Setting up local templates.
#################################################
Hull = App.HullProperty_Create("Hull")

Hull.SetMaxCondition(2000.000000)
Hull.SetCritical(1)
Hull.SetTargetable(1)
Hull.SetPrimary(1)
Hull.SetPosition(0.000000, 0.000000, 0.150000)
Hull.SetPosition2D(64.000000, 64.000000)
Hull.SetRepairComplexity(3.000000)
Hull.SetDisabledPercentage(0.000000)
Hull.SetRadius(1.500000)
App.g_kModelPropertyManager.RegisterLocalTemplate(Hull)
#################################################
ShieldGenerator = App.ShieldProperty_Create("Shield Generator")

ShieldGenerator.SetMaxCondition(1000.000000)
ShieldGenerator.SetCritical(0)
ShieldGenerator.SetTargetable(0)
ShieldGenerator.SetPrimary(1)
ShieldGenerator.SetPosition(0.000000, 0.000000, 0.100000)
ShieldGenerator.SetPosition2D(64.000000, 64.000000)
ShieldGenerator.SetRepairComplexity(2.000000)
ShieldGenerator.SetDisabledPercentage(0.750000)
ShieldGenerator.SetRadius(1.000000)
ShieldGenerator.SetNormalPowerPerSecond(1.000000)
ShieldGeneratorShieldGlowColor = App.TGColorA()
ShieldGeneratorShieldGlowColor.SetRGBA(1.000000, 0.647059, 0.192157, 0.466667)
ShieldGenerator.SetShieldGlowColor(ShieldGeneratorShieldGlowColor)
ShieldGenerator.SetShieldGlowDecay(1.000000)
ShieldGenerator.SetMaxShields(ShieldGenerator.FRONT_SHIELDS, 0.000000)
ShieldGenerator.SetMaxShields(ShieldGenerator.REAR_SHIELDS, 0.000000)
ShieldGenerator.SetMaxShields(ShieldGenerator.TOP_SHIELDS, 0.000000)
ShieldGenerator.SetMaxShields(ShieldGenerator.BOTTOM_SHIELDS, 0.000000)
ShieldGenerator.SetMaxShields(ShieldGenerator.LEFT_SHIELDS, 0.000000)
ShieldGenerator.SetMaxShields(ShieldGenerator.RIGHT_SHIELDS, 0.000000)
ShieldGenerator.SetShieldChargePerSecond(ShieldGenerator.FRONT_SHIELDS, 0.000000)
ShieldGenerator.SetShieldChargePerSecond(ShieldGenerator.REAR_SHIELDS, 0.000000)
ShieldGenerator.SetShieldChargePerSecond(ShieldGenerator.TOP_SHIELDS, 0.000000)
ShieldGenerator.SetShieldChargePerSecond(ShieldGenerator.BOTTOM_SHIELDS, 0.000000)
ShieldGenerator.SetShieldChargePerSecond(ShieldGenerator.LEFT_SHIELDS, 0.000000)
ShieldGenerator.SetShieldChargePerSecond(ShieldGenerator.RIGHT_SHIELDS, 0.000000)
App.g_kModelPropertyManager.RegisterLocalTemplate(ShieldGenerator)
#################################################
PowerPlant = App.PowerProperty_Create("Power Plant")

PowerPlant.SetMaxCondition(3000.000000)
PowerPlant.SetCritical(1)
PowerPlant.SetTargetable(1)
PowerPlant.SetPrimary(1)
PowerPlant.SetPosition(0.000000, 0.000000, -0.900000)
PowerPlant.SetPosition2D(64.000000, 100.000000)
PowerPlant.SetRepairComplexity(2.000000)
PowerPlant.SetDisabledPercentage(0.500000)
PowerPlant.SetRadius(0.500000)
PowerPlant.SetMainBatteryLimit(180000.000000)
PowerPlant.SetBackupBatteryLimit(5000.000000)
PowerPlant.SetMainConduitCapacity(1000.000000)
PowerPlant.SetBackupConduitCapacity(400.000000)
PowerPlant.SetPowerOutput(600.000000)
App.g_kModelPropertyManager.RegisterLocalTemplate(PowerPlant)
#################################################
CommArray = App.ShipProperty_Create("Comm Array")

CommArray.SetGenus(2)
CommArray.SetSpecies(708)
CommArray.SetMass(50.000000)
CommArray.SetRotationalInertia(20000.000000)
CommArray.SetShipName("Comm Array")
CommArray.SetModelFilename("data/Models/Bases/SpaceFacility/SpaceFacility.nif")
CommArray.SetDamageResolution(15.000000)
CommArray.SetAffiliation(0)
CommArray.SetStationary(0)
CommArray.SetAIString("StarbaseAttack")
CommArray.SetDeathExplosionSound("g_lsBigDeathExplosions")
App.g_kModelPropertyManager.RegisterLocalTemplate(CommArray)
#################################################
Transmitter = App.HullProperty_Create("Transmitter")

Transmitter.SetMaxCondition(3000.000000)
Transmitter.SetCritical(0)
Transmitter.SetTargetable(1)
Transmitter.SetPrimary(0)
Transmitter.SetPosition(0.000000, 0.000000, 0.800000)
Transmitter.SetPosition2D(64.000000, 40.000000)
Transmitter.SetRepairComplexity(2.000000)
Transmitter.SetDisabledPercentage(0.000000)
Transmitter.SetRadius(0.400000)
App.g_kModelPropertyManager.RegisterLocalTemplate(Transmitter)
#################################################
Receiver1 = App.HullProperty_Create("Receiver 1")

Receiver1.SetMaxCondition(2000.000000)
Receiver1.SetCritical(0)
Receiver1.SetTargetable(1)
Receiver1.SetPrimary(0)
Receiver1.SetPosition(1.200000, 0.010000, 0.150000)
Receiver1.SetPosition2D(32.000000, 64.000000)
Receiver1.SetRepairComplexity(2.000000)
Receiver1.SetDisabledPercentage(0.000000)
Receiver1.SetRadius(1.000000)
App.g_kModelPropertyManager.RegisterLocalTemplate(Receiver1)
#################################################
Receiver2 = App.HullProperty_Create("Receiver 2")

Receiver2.SetMaxCondition(2000.000000)
Receiver2.SetCritical(0)
Receiver2.SetTargetable(1)
Receiver2.SetPrimary(0)
Receiver2.SetPosition(-1.200000, 0.010000, 0.150000)
Receiver2.SetPosition2D(96.000000, 64.000000)
Receiver2.SetRepairComplexity(2.000000)
Receiver2.SetDisabledPercentage(0.000000)
Receiver2.SetRadius(1.000000)
App.g_kModelPropertyManager.RegisterLocalTemplate(Receiver2)
#################################################
ImpulseEngines = App.ImpulseEngineProperty_Create("Impulse Engines")

ImpulseEngines.SetMaxCondition(200.000000)
ImpulseEngines.SetCritical(0)
ImpulseEngines.SetTargetable(0)
ImpulseEngines.SetPrimary(1)
ImpulseEngines.SetPosition(0.000000, 0.000000, 0.000000)
ImpulseEngines.SetPosition2D(64.000000, 90.000000)
ImpulseEngines.SetRepairComplexity(3.000000)
ImpulseEngines.SetDisabledPercentage(0.500000)
ImpulseEngines.SetRadius(0.250000)
ImpulseEngines.SetNormalPowerPerSecond(1.000000)
ImpulseEngines.SetMaxAccel(2.000000)
ImpulseEngines.SetMaxAngularAccel(0.100000)
ImpulseEngines.SetMaxAngularVelocity(0.250000)
ImpulseEngines.SetMaxSpeed(4.000000)
ImpulseEngines.SetEngineSound("Federation Engines")
App.g_kModelPropertyManager.RegisterLocalTemplate(ImpulseEngines)
#################################################
Impulse = App.EngineProperty_Create("Impulse")

Impulse.SetMaxCondition(500.000000)
Impulse.SetCritical(0)
Impulse.SetTargetable(0)
Impulse.SetPrimary(1)
Impulse.SetPosition(0.000000, 0.000000, 0.150000)
Impulse.SetPosition2D(64.000000, 90.000000)
Impulse.SetRepairComplexity(2.000000)
Impulse.SetDisabledPercentage(0.500000)
Impulse.SetRadius(0.500000)
Impulse.SetEngineType(Impulse.EP_IMPULSE)
App.g_kModelPropertyManager.RegisterLocalTemplate(Impulse)

# Property load function.
def LoadPropertySet(pObj):
	"Sets up the object's properties."
	prop = App.g_kModelPropertyManager.FindByName("Hull", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
	prop = App.g_kModelPropertyManager.FindByName("Shield Generator", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
	prop = App.g_kModelPropertyManager.FindByName("Power Plant", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
	prop = App.g_kModelPropertyManager.FindByName("Comm Array", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
	prop = App.g_kModelPropertyManager.FindByName("Transmitter", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
	prop = App.g_kModelPropertyManager.FindByName("Receiver 1", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
	prop = App.g_kModelPropertyManager.FindByName("Receiver 2", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
	prop = App.g_kModelPropertyManager.FindByName("Impulse Engines", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
	prop = App.g_kModelPropertyManager.FindByName("Impulse", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
