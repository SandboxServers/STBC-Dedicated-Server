# C:\Utopia\Current\Build\scripts\ships\Hardpoints\spacefacility.py
# This file was automatically generated - modify at your own risk.
# 

import App
import GlobalPropertyTemplates
# Setting up local templates.
#################################################
Hull = App.HullProperty_Create("Hull")

Hull.SetMaxCondition(55000.000000)
Hull.SetCritical(1)
Hull.SetTargetable(1)
Hull.SetPrimary(1)
Hull.SetPosition(0.000000, 0.000000, 0.500000)
Hull.SetPosition2D(62.000000, 60.000000)
Hull.SetRepairComplexity(3.000000)
Hull.SetDisabledPercentage(0.000000)
Hull.SetRadius(11.000000)
App.g_kModelPropertyManager.RegisterLocalTemplate(Hull)
#################################################
ShieldGenerator = App.ShieldProperty_Create("Shield Generator")

ShieldGenerator.SetMaxCondition(40000.000000)
ShieldGenerator.SetCritical(0)
ShieldGenerator.SetTargetable(1)
ShieldGenerator.SetPrimary(1)
ShieldGenerator.SetPosition(0.000000, 0.000000, -0.200000)
ShieldGenerator.SetPosition2D(62.000000, 60.000000)
ShieldGenerator.SetRepairComplexity(4.000000)
ShieldGenerator.SetDisabledPercentage(0.750000)
ShieldGenerator.SetRadius(2.000000)
ShieldGenerator.SetNormalPowerPerSecond(200.000000)
ShieldGeneratorShieldGlowColor = App.TGColorA()
ShieldGeneratorShieldGlowColor.SetRGBA(0.203922, 0.631373, 1.000000, 0.466667)
ShieldGenerator.SetShieldGlowColor(ShieldGeneratorShieldGlowColor)
ShieldGenerator.SetShieldGlowDecay(1.000000)
ShieldGenerator.SetMaxShields(ShieldGenerator.FRONT_SHIELDS, 6000.000000)
ShieldGenerator.SetMaxShields(ShieldGenerator.REAR_SHIELDS, 6000.000000)
ShieldGenerator.SetMaxShields(ShieldGenerator.TOP_SHIELDS, 6000.000000)
ShieldGenerator.SetMaxShields(ShieldGenerator.BOTTOM_SHIELDS, 6000.000000)
ShieldGenerator.SetMaxShields(ShieldGenerator.LEFT_SHIELDS, 6000.000000)
ShieldGenerator.SetMaxShields(ShieldGenerator.RIGHT_SHIELDS, 6000.000000)
ShieldGenerator.SetShieldChargePerSecond(ShieldGenerator.FRONT_SHIELDS, 10.000000)
ShieldGenerator.SetShieldChargePerSecond(ShieldGenerator.REAR_SHIELDS, 10.000000)
ShieldGenerator.SetShieldChargePerSecond(ShieldGenerator.TOP_SHIELDS, 10.000000)
ShieldGenerator.SetShieldChargePerSecond(ShieldGenerator.BOTTOM_SHIELDS, 10.000000)
ShieldGenerator.SetShieldChargePerSecond(ShieldGenerator.LEFT_SHIELDS, 10.000000)
ShieldGenerator.SetShieldChargePerSecond(ShieldGenerator.RIGHT_SHIELDS, 10.000000)
App.g_kModelPropertyManager.RegisterLocalTemplate(ShieldGenerator)
#################################################
SensorArray = App.SensorProperty_Create("Sensor Array")

SensorArray.SetMaxCondition(16000.000000)
SensorArray.SetCritical(0)
SensorArray.SetTargetable(1)
SensorArray.SetPrimary(1)
SensorArray.SetPosition(0.000000, 0.000000, 5.700000)
SensorArray.SetPosition2D(62.000000, 20.000000)
SensorArray.SetRepairComplexity(1.000000)
SensorArray.SetDisabledPercentage(0.500000)
SensorArray.SetRadius(2.700000)
SensorArray.SetNormalPowerPerSecond(100.000000)
SensorArray.SetBaseSensorRange(5000.000000)
SensorArray.SetMaxProbes(10)
App.g_kModelPropertyManager.RegisterLocalTemplate(SensorArray)
#################################################
PowerPlant = App.PowerProperty_Create("Power Plant")

PowerPlant.SetMaxCondition(20000.000000)
PowerPlant.SetCritical(1)
PowerPlant.SetTargetable(1)
PowerPlant.SetPrimary(1)
PowerPlant.SetPosition(0.000000, 0.000000, -7.000000)
PowerPlant.SetPosition2D(62.000000, 105.000000)
PowerPlant.SetRepairComplexity(4.000000)
PowerPlant.SetDisabledPercentage(0.750000)
PowerPlant.SetRadius(1.700000)
PowerPlant.SetMainBatteryLimit(400000.000000)
PowerPlant.SetBackupBatteryLimit(200000.000000)
PowerPlant.SetMainConduitCapacity(3000.000000)
PowerPlant.SetBackupConduitCapacity(1500.000000)
PowerPlant.SetPowerOutput(2000.000000)
App.g_kModelPropertyManager.RegisterLocalTemplate(PowerPlant)
#################################################
Engineering = App.RepairSubsystemProperty_Create("Engineering")

Engineering.SetMaxCondition(3000.000000)
Engineering.SetCritical(0)
Engineering.SetTargetable(0)
Engineering.SetPrimary(1)
Engineering.SetPosition(0.000000, 0.000000, 4.000000)
Engineering.SetPosition2D(63.000000, 27.000000)
Engineering.SetRepairComplexity(10.000000)
Engineering.SetDisabledPercentage(0.100000)
Engineering.SetRadius(1.000000)
Engineering.SetNormalPowerPerSecond(1.000000)
Engineering.SetMaxRepairPoints(40.000000)
Engineering.SetNumRepairTeams(4)
App.g_kModelPropertyManager.RegisterLocalTemplate(Engineering)
#################################################
Spacefacility = App.ShipProperty_Create("Spacefacility")

Spacefacility.SetGenus(2)
Spacefacility.SetSpecies(707)
Spacefacility.SetMass(500.000000)
Spacefacility.SetRotationalInertia(49999998976.000000)
Spacefacility.SetShipName("Space Facility")
Spacefacility.SetModelFilename("data/Models/Bases/SpaceFacility/SpaceFacility.nif")
Spacefacility.SetDamageResolution(15.000000)
Spacefacility.SetAffiliation(0)
Spacefacility.SetStationary(0)
Spacefacility.SetAIString("StarbaseAttack")
Spacefacility.SetDeathExplosionSound("g_lsBigDeathExplosions")
App.g_kModelPropertyManager.RegisterLocalTemplate(Spacefacility)
#################################################
ShuttleBay1 = App.ObjectEmitterProperty_Create("Shuttle Bay 1")

ShuttleBay1Forward = App.TGPoint3()
ShuttleBay1Forward.SetXYZ(-1.000000, 0.000000, 0.000000)
ShuttleBay1Up = App.TGPoint3()
ShuttleBay1Up.SetXYZ(0.000000, 0.000000, 1.000000)
ShuttleBay1Right = App.TGPoint3()
ShuttleBay1Right.SetXYZ(0.000000, -1.000000, 0.000000)
ShuttleBay1.SetOrientation(ShuttleBay1Forward, ShuttleBay1Up, ShuttleBay1Right)
ShuttleBay1Position = App.TGPoint3()
ShuttleBay1Position.SetXYZ(-4.700000, -0.090000, 1.500000)
ShuttleBay1.SetPosition(ShuttleBay1Position)
ShuttleBay1.SetEmittedObjectType(ShuttleBay1.OEP_SHUTTLE)
App.g_kModelPropertyManager.RegisterLocalTemplate(ShuttleBay1)
#################################################
ShuttleBay2 = App.ObjectEmitterProperty_Create("Shuttle Bay 2")

ShuttleBay2Forward = App.TGPoint3()
ShuttleBay2Forward.SetXYZ(1.000000, 0.000000, 0.000000)
ShuttleBay2Up = App.TGPoint3()
ShuttleBay2Up.SetXYZ(0.000000, 0.000000, 1.000000)
ShuttleBay2Right = App.TGPoint3()
ShuttleBay2Right.SetXYZ(0.000000, 1.000000, 0.000000)
ShuttleBay2.SetOrientation(ShuttleBay2Forward, ShuttleBay2Up, ShuttleBay2Right)
ShuttleBay2Position = App.TGPoint3()
ShuttleBay2Position.SetXYZ(4.700000, -0.120000, 1.500000)
ShuttleBay2.SetPosition(ShuttleBay2Position)
ShuttleBay2.SetEmittedObjectType(ShuttleBay2.OEP_SHUTTLE)
App.g_kModelPropertyManager.RegisterLocalTemplate(ShuttleBay2)

# Property load function.
def LoadPropertySet(pObj):
	"Sets up the object's properties."
	prop = App.g_kModelPropertyManager.FindByName("Hull", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
	prop = App.g_kModelPropertyManager.FindByName("Shield Generator", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
	prop = App.g_kModelPropertyManager.FindByName("Sensor Array", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
	prop = App.g_kModelPropertyManager.FindByName("Power Plant", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
	prop = App.g_kModelPropertyManager.FindByName("Engineering", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
	prop = App.g_kModelPropertyManager.FindByName("Spacefacility", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
	prop = App.g_kModelPropertyManager.FindByName("Shuttle Bay 1", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
	prop = App.g_kModelPropertyManager.FindByName("Shuttle Bay 2", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
