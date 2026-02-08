# C:\Utopia\Current\Build\scripts\ships\Hardpoints\commarray.py
# This file was automatically generated - modify at your own risk.
# 

import App
import GlobalPropertyTemplates
# Setting up local templates.
#################################################
Hull = App.HullProperty_Create("Hull")

Hull.SetMaxCondition(15000.000000)
Hull.SetCritical(1)
Hull.SetTargetable(1)
Hull.SetPrimary(1)
Hull.SetPosition(0.000000, 0.000000, 0.000000)
Hull.SetPosition2D(67.000000, 65.000000)
Hull.SetRepairComplexity(3.000000)
Hull.SetDisabledPercentage(0.000000)
Hull.SetRadius(8.000000)
App.g_kModelPropertyManager.RegisterLocalTemplate(Hull)
#################################################
ShieldGenerator = App.ShieldProperty_Create("Shield Generator")

ShieldGenerator.SetMaxCondition(6000.000000)
ShieldGenerator.SetCritical(0)
ShieldGenerator.SetTargetable(0)
ShieldGenerator.SetPrimary(1)
ShieldGenerator.SetPosition(0.000000, 0.000000, 0.000000)
ShieldGenerator.SetPosition2D(67.000000, 65.000000)
ShieldGenerator.SetRepairComplexity(2.000000)
ShieldGenerator.SetDisabledPercentage(0.750000)
ShieldGenerator.SetRadius(5.000000)
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

PowerPlant.SetMaxCondition(9000.000000)
PowerPlant.SetCritical(1)
PowerPlant.SetTargetable(1)
PowerPlant.SetPrimary(1)
PowerPlant.SetPosition(0.000000, 0.000000, -8.000000)
PowerPlant.SetPosition2D(67.000000, 100.000000)
PowerPlant.SetRepairComplexity(2.000000)
PowerPlant.SetDisabledPercentage(0.500000)
PowerPlant.SetRadius(5.000000)
PowerPlant.SetMainBatteryLimit(10000.000000)
PowerPlant.SetBackupBatteryLimit(5000.000000)
PowerPlant.SetMainConduitCapacity(700.000000)
PowerPlant.SetBackupConduitCapacity(200.000000)
PowerPlant.SetPowerOutput(600.000000)
App.g_kModelPropertyManager.RegisterLocalTemplate(PowerPlant)
#################################################
CommArray = App.ShipProperty_Create("Comm Array")

CommArray.SetGenus(2)
CommArray.SetSpecies(708)
CommArray.SetMass(40.000000)
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
Transmitter1 = App.HullProperty_Create("Transmitter 1")

Transmitter1.SetMaxCondition(4000.000000)
Transmitter1.SetCritical(0)
Transmitter1.SetTargetable(1)
Transmitter1.SetPrimary(0)
Transmitter1.SetPosition(0.000000, 0.000000, 8.000000)
Transmitter1.SetPosition2D(67.000000, 25.000000)
Transmitter1.SetRepairComplexity(1.000000)
Transmitter1.SetDisabledPercentage(0.000000)
Transmitter1.SetRadius(2.000000)
App.g_kModelPropertyManager.RegisterLocalTemplate(Transmitter1)
#################################################
Transmitter2 = App.HullProperty_Create("Transmitter 2")

Transmitter2.SetMaxCondition(4000.000000)
Transmitter2.SetCritical(0)
Transmitter2.SetTargetable(1)
Transmitter2.SetPrimary(0)
Transmitter2.SetPosition(10.000000, 0.000000, -0.300000)
Transmitter2.SetPosition2D(114.000000, 64.000000)
Transmitter2.SetRepairComplexity(1.000000)
Transmitter2.SetDisabledPercentage(0.000000)
Transmitter2.SetRadius(3.000000)
App.g_kModelPropertyManager.RegisterLocalTemplate(Transmitter2)
#################################################
Receiver = App.HullProperty_Create("Receiver")

Receiver.SetMaxCondition(4000.000000)
Receiver.SetCritical(0)
Receiver.SetTargetable(1)
Receiver.SetPrimary(0)
Receiver.SetPosition(-10.000000, 0.000000, -0.200000)
Receiver.SetPosition2D(15.000000, 64.000000)
Receiver.SetRepairComplexity(1.000000)
Receiver.SetDisabledPercentage(0.000000)
Receiver.SetRadius(3.000000)
App.g_kModelPropertyManager.RegisterLocalTemplate(Receiver)
#################################################
ImpulseEngines = App.ImpulseEngineProperty_Create("Impulse Engines")

ImpulseEngines.SetMaxCondition(1000.000000)
ImpulseEngines.SetCritical(0)
ImpulseEngines.SetTargetable(0)
ImpulseEngines.SetPrimary(1)
ImpulseEngines.SetPosition(0.000000, 0.000000, 0.000000)
ImpulseEngines.SetPosition2D(0.000000, 0.000000)
ImpulseEngines.SetRepairComplexity(2.000000)
ImpulseEngines.SetDisabledPercentage(0.500000)
ImpulseEngines.SetRadius(1.000000)
ImpulseEngines.SetNormalPowerPerSecond(1.000000)
ImpulseEngines.SetMaxAccel(1.000000)
ImpulseEngines.SetMaxAngularAccel(0.100000)
ImpulseEngines.SetMaxAngularVelocity(0.250000)
ImpulseEngines.SetMaxSpeed(4.000000)
ImpulseEngines.SetEngineSound("Federation Engines")
App.g_kModelPropertyManager.RegisterLocalTemplate(ImpulseEngines)
#################################################
Impulse = App.EngineProperty_Create("Impulse")

Impulse.SetMaxCondition(2000.000000)
Impulse.SetCritical(0)
Impulse.SetTargetable(0)
Impulse.SetPrimary(1)
Impulse.SetPosition(0.000000, 0.000000, -4.000000)
Impulse.SetPosition2D(64.000000, 75.000000)
Impulse.SetRepairComplexity(2.000000)
Impulse.SetDisabledPercentage(0.500000)
Impulse.SetRadius(2.000000)
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
	prop = App.g_kModelPropertyManager.FindByName("Transmitter 1", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
	prop = App.g_kModelPropertyManager.FindByName("Transmitter 2", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
	prop = App.g_kModelPropertyManager.FindByName("Receiver", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
	prop = App.g_kModelPropertyManager.FindByName("Impulse Engines", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
	prop = App.g_kModelPropertyManager.FindByName("Impulse", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
