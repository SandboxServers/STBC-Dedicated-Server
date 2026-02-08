# C:\Utopia\Current\Build\scripts\ships\Hardpoints\e2m0warbird.py
# This file was automatically generated - modify at your own risk.
# 

import App
import GlobalPropertyTemplates
	# The line below is needed by the editor to restore
	# the name of the parent script.
ParentPropertyScript = "ships.Hardpoints.warbird"
if not ('g_bIsModelPropertyEditor' in dir(App)):
	ParentModule = __import__("ships.Hardpoints.warbird", globals(), locals(), ['*'])
	reload(ParentModule)
# Setting up local templates.
#################################################
PortWarp = App.EngineProperty_Create("Port Warp")

PortWarp.SetMaxCondition(8000.000000)
PortWarp.SetCritical(0)
PortWarp.SetTargetable(1)
PortWarp.SetPrimary(1)
PortWarp.SetPosition(-4.700000, 0.900000, 0.066000)
PortWarp.SetPosition2D(4.000000, 60.000000)
PortWarp.SetRepairComplexity(3.000000)
PortWarp.SetDisabledPercentage(0.250000)
PortWarp.SetRadius(1.000000)
PortWarp.SetEngineType(PortWarp.EP_WARP)
App.g_kModelPropertyManager.RegisterLocalTemplate(PortWarp)
#################################################
StarWarp = App.EngineProperty_Create("Star Warp")

StarWarp.SetMaxCondition(8000.000000)
StarWarp.SetCritical(0)
StarWarp.SetTargetable(1)
StarWarp.SetPrimary(1)
StarWarp.SetPosition(4.700000, 0.900000, 0.066000)
StarWarp.SetPosition2D(124.000000, 60.000000)
StarWarp.SetRepairComplexity(3.000000)
StarWarp.SetDisabledPercentage(0.250000)
StarWarp.SetRadius(1.000000)
StarWarp.SetEngineType(StarWarp.EP_WARP)
App.g_kModelPropertyManager.RegisterLocalTemplate(StarWarp)
#################################################
ForwardTorpedo = App.TorpedoTubeProperty_Create("Forward Torpedo")

ForwardTorpedo.SetMaxCondition(3200.000000)
ForwardTorpedo.SetCritical(0)
ForwardTorpedo.SetTargetable(1)
ForwardTorpedo.SetPrimary(1)
ForwardTorpedo.SetPosition(0.000000, 6.050000, -0.600000)
ForwardTorpedo.SetPosition2D(64.000000, 5.000000)
ForwardTorpedo.SetRepairComplexity(6.000000)
ForwardTorpedo.SetDisabledPercentage(0.750000)
ForwardTorpedo.SetRadius(0.500000)
ForwardTorpedo.SetDumbfire(1)
ForwardTorpedo.SetWeaponID(0)
ForwardTorpedo.SetGroups(1)
ForwardTorpedo.SetDamageRadiusFactor(0.200000)
ForwardTorpedo.SetIconNum(370)
ForwardTorpedo.SetIconPositionX(76.000000)
ForwardTorpedo.SetIconPositionY(18.000000)
ForwardTorpedo.SetIconAboveShip(1)
ForwardTorpedo.SetImmediateDelay(5.000000)
ForwardTorpedo.SetReloadDelay(30.000000)
ForwardTorpedo.SetMaxReady(1)
ForwardTorpedoDirection = App.TGPoint3()
ForwardTorpedoDirection.SetXYZ(0.000000, 1.000000, 0.000000)
ForwardTorpedo.SetDirection(ForwardTorpedoDirection)
ForwardTorpedoRight = App.TGPoint3()
ForwardTorpedoRight.SetXYZ(1.000000, 0.000000, 0.000000)
ForwardTorpedo.SetRight(ForwardTorpedoRight)
App.g_kModelPropertyManager.RegisterLocalTemplate(ForwardTorpedo)
#################################################
AftTorpedo = App.TorpedoTubeProperty_Create("Aft Torpedo")

AftTorpedo.SetMaxCondition(3200.000000)
AftTorpedo.SetCritical(0)
AftTorpedo.SetTargetable(1)
AftTorpedo.SetPrimary(1)
AftTorpedo.SetPosition(0.000000, -5.800000, -0.400000)
AftTorpedo.SetPosition2D(64.000000, 110.000000)
AftTorpedo.SetRepairComplexity(6.000000)
AftTorpedo.SetDisabledPercentage(0.750000)
AftTorpedo.SetRadius(0.500000)
AftTorpedo.SetDumbfire(1)
AftTorpedo.SetWeaponID(1)
AftTorpedo.SetGroups(2)
AftTorpedo.SetDamageRadiusFactor(0.200000)
AftTorpedo.SetIconNum(370)
AftTorpedo.SetIconPositionX(76.000000)
AftTorpedo.SetIconPositionY(126.000000)
AftTorpedo.SetIconAboveShip(1)
AftTorpedo.SetImmediateDelay(5.000000)
AftTorpedo.SetReloadDelay(30.000000)
AftTorpedo.SetMaxReady(1)
AftTorpedoDirection = App.TGPoint3()
AftTorpedoDirection.SetXYZ(0.000000, -1.000000, 0.000000)
AftTorpedo.SetDirection(AftTorpedoDirection)
AftTorpedoRight = App.TGPoint3()
AftTorpedoRight.SetXYZ(-1.000000, 0.000000, 0.000000)
AftTorpedo.SetRight(AftTorpedoRight)
App.g_kModelPropertyManager.RegisterLocalTemplate(AftTorpedo)
#################################################
ImpulseEngines = App.ImpulseEngineProperty_Create("Impulse Engines")

ImpulseEngines.SetMaxCondition(3200.000000)
ImpulseEngines.SetCritical(0)
ImpulseEngines.SetTargetable(0)
ImpulseEngines.SetPrimary(1)
ImpulseEngines.SetPosition(0.908000, 0.400000, -1.200000)
ImpulseEngines.SetPosition2D(78.000000, 59.000000)
ImpulseEngines.SetRepairComplexity(2.000000)
ImpulseEngines.SetDisabledPercentage(0.500000)
ImpulseEngines.SetRadius(0.250000)
ImpulseEngines.SetNormalPowerPerSecond(300.000000)
ImpulseEngines.SetMaxAccel(1.000000)
ImpulseEngines.SetMaxAngularAccel(0.070000)
ImpulseEngines.SetMaxAngularVelocity(0.200000)
ImpulseEngines.SetMaxSpeed(4.500000)
ImpulseEngines.SetEngineSound("Romulan Engines")
App.g_kModelPropertyManager.RegisterLocalTemplate(ImpulseEngines)
#################################################
PortImpulse = App.EngineProperty_Create("Port Impulse")

PortImpulse.SetMaxCondition(2000.000000)
PortImpulse.SetCritical(0)
PortImpulse.SetTargetable(1)
PortImpulse.SetPrimary(1)
PortImpulse.SetPosition(-4.700000, -0.890000, 0.040000)
PortImpulse.SetPosition2D(4.000000, 75.000000)
PortImpulse.SetRepairComplexity(4.000000)
PortImpulse.SetDisabledPercentage(0.500000)
PortImpulse.SetRadius(0.700000)
PortImpulse.SetEngineType(PortImpulse.EP_IMPULSE)
App.g_kModelPropertyManager.RegisterLocalTemplate(PortImpulse)
#################################################
StarImpulse = App.EngineProperty_Create("Star Impulse")

StarImpulse.SetMaxCondition(2000.000000)
StarImpulse.SetCritical(0)
StarImpulse.SetTargetable(1)
StarImpulse.SetPrimary(1)
StarImpulse.SetPosition(4.700000, -0.890000, 0.040000)
StarImpulse.SetPosition2D(124.000000, 75.000000)
StarImpulse.SetRepairComplexity(4.000000)
StarImpulse.SetDisabledPercentage(0.500000)
StarImpulse.SetRadius(0.700000)
StarImpulse.SetEngineType(StarImpulse.EP_IMPULSE)
App.g_kModelPropertyManager.RegisterLocalTemplate(StarImpulse)

# Property load function.
def LoadPropertySet(pObj):
	"Sets up the object's properties."
	if not ('g_bIsModelPropertyEditor' in dir(App)):
		ParentModule.LoadPropertySet(pObj)
	prop = App.g_kModelPropertyManager.FindByName("Port Warp", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
	prop = App.g_kModelPropertyManager.FindByName("Star Warp", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
	prop = App.g_kModelPropertyManager.FindByName("Forward Torpedo", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
	prop = App.g_kModelPropertyManager.FindByName("Aft Torpedo", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
	prop = App.g_kModelPropertyManager.FindByName("Impulse Engines", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
	prop = App.g_kModelPropertyManager.FindByName("Port Impulse", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
	prop = App.g_kModelPropertyManager.FindByName("Star Impulse", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
