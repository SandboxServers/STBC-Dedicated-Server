###############################################################################
#	Filename:	SSDiag.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Utility functions for diagnosing subsystems and what they're doing.
#
#		Subsystems
#		Powered subsystems
#		Impulse engines
#		Warp engines
#		Cloaking
#		Hull
#		Shields
#		Repair subsystem
#		Sensor subsystem
#	
#	Created:	9/6/00 -	Erik Novales
###############################################################################

import App

iToggle = 1

def SetPrintDestination(iDest):
	"Sets the destination of the printed output. 0 for console, 1 for debug window."
	global iToggle

	if (iDest != 0):
		iToggle = 1
	else:
		iToggle = 0

def SSPrint(kText):
	"Prints text to either the console or debug window."
	global iToggle

	if (iToggle == 0):
		print kText
	else:
		App.CPyDebug().Print(kText)


###############################################################################
#	Subsystem(pShip, pSubsystem)
#	
#	Prints out diagnostic information for a subsystem.
#	
#	Args:	pShip - the ship
#			pSubsystem - the subsystem to be examined
#	
#	Return:	none
###############################################################################
def Subsystem(pShip, pSubsystem):
	"Prints out information regarding one subsystem."

	if (pSubsystem == None):
		SSPrint("Invalid subsystem.")
		return

	SSPrint("-------------------------------------------------------")
	SSPrint("Condition: %f/%f" % (pSubsystem.GetCondition(), pSubsystem.GetMaxCondition()))
	SSPrint("Disabled percentage: %f" % (pSubsystem.GetDisabledPercentage()))
	SSPrint("Critical: %d" % (pSubsystem.IsCritical()))
	SSPrint("Targetable: %d" % (pSubsystem.IsTargetable()))
	SSPrint("Number of child subsystems: %d" % (pSubsystem.GetNumChildSubsystems()))

###############################################################################
#	PoweredSubsystem(pShip, pSubsystem)
#	
#	Prints out diagnostic information for a powered subsystem.
#	
#	Args:	pShip - the ship
#			pSubsystem - the subsystem to be examined
#	
#	Return:	none
###############################################################################
def PoweredSubsystem(pShip, pSubsystem):
	"Prints out information regarding a powered subsystem."

	if (pSubsystem == None):
		SSPrint("Invalid powered subsystem.")
		return

	Subsystem(pShip, pSubsystem)
	SSPrint("On: %d" % (pSubsystem.IsOn()))
	SSPrint("Power wanted per second: %f" % (pSubsystem.GetPowerWanted()))
	SSPrint("Current power percentage/desired: %f/%f" % (pSubsystem.GetNormalPowerPercentage(), \
													   pSubsystem.GetPowerPercentageWanted()))

###############################################################################
#	ImpulseEngines(pShip, pSubsystem)
#	
#	Prints out diagnostic information for impulse engine systems.
#	
#	Args:	pShip - the ship
#			pSubsystem - the engine system to examine -- if 0, then the primary
#				impulse engine system will be used
#	
#	Return:	none
###############################################################################
def ImpulseEngines(pShip, pSubsystem = 0):
	"Prints out diagnostic information regarding the engine system of the ship."
	if (pSubsystem == 0):
		pEngines = pShip.GetImpulseEngineSubsystem()
	else:
		pEngines = pSubsystem

	if (pEngines == None):
		SSPrint("No impulse engine subsystem on this ship.")
		return

	PoweredSubsystem(pShip, pEngines)
	SSPrint("Maximum/current max speed: %f, %f" % (pEngines.GetMaxSpeed(), pEngines.GetCurMaxSpeed()))
	SSPrint("Maximum/current max acceleration: %f, %f" % (pEngines.GetMaxAccel(), pEngines.GetCurMaxAccel()))
	SSPrint("Maximum/current max angular velocity: %f, %f" % (pEngines.GetMaxAngularVelocity(), pEngines.GetCurMaxAngularVelocity()))
	SSPrint("Maximum/current max angular acceleration: %f, %f" % (pEngines.GetMaxAngularAccel(), pEngines.GetCurMaxAngularAccel()))

###############################################################################
#	WarpEngines(pShip, pSubsystem)
#	
#	Prints out diagnostic information for the warp engine system.
#	
#	Args:	pShip - the ship
#			pSubsystem - the warp engine subsystem to examine. If 0, the
#				primary one will be used.
#	
#	Return:	none
###############################################################################
def WarpEngines(pShip, pSubsystem = 0):
	"Prints out diagnostic information regarding the warp engines of the ship."
	if (pSubsystem == 0):
		pEngines = pShip.GetWarpEngineSubsystem()
	else:
		pEngines = pSubsystem

	if (pEngines == None):
		SSPrint("No warp engine subsystem on this ship.")
		return

	PoweredSubsystem(pShip, pEngines)
	
###############################################################################
#	Engines(pShip)
#	
#	Prints out diagnostic information for each engine on the ship.
#	
#	Args:	pShip - the ship for which you want to get information.
#	
#	Return:	none
###############################################################################
def Engines(pShip):
	"Prints out information for each engine on the ship."
	# Loop over individual engines.
	pIter = pShip.StartGetSubsystemMatch(App.CT_SHIP_SUBSYSTEM)

	while 1:
		pSystem = pShip.GetNextSubsystemMatch(pIter)
		if (pSystem == None):
			break

		if (App.ImpulseEngineSubsystem_Cast(pSystem) != None) or \
		   (App.WarpEngineSubsystem_Cast(pSystem) != None):
			for iIter in range(pSystem.GetNumChildSubsystems()):
				pChild = pSystem.GetChildSubsystem(iIter)
				Subsystem(pShip, pChild)

	pShip.EndGetSubsystemMatch(pIter)
	return

###############################################################################
#	Cloaking(pShip, pSubsystem)
#	
#	Prints out diagnostic information for the cloaking system.
#	
#	Args:	pShip - the ship
#			pSubsystem - the cloaking subsystem to examine. If 0, the
#				primary one will be used.
#	
#	Return:	none
###############################################################################
def Cloaking(pShip, pSubsystem = 0):
	"Prints out diagnostic information regarding the cloaking subsystem of the ship."
	if (pSubsystem == 0):
		pCloak = pShip.GetCloakingSubsystem()
	else:
		pCloak = pSubsystem

	if (pCloak == None):
		SSPrint("No cloaking subsystem on this ship.")
		return

	PoweredSubsystem(pShip, pCloak)

###############################################################################
#	Hull(pShip, pSubsystem = 0)
#	
#	Prints out diagnostic information for the hull.
#	
#	Args:	pShip - the ship
#			pSubsystem - the hull to examine. If 0, all hulls on the ship will
#				be examined.
#	
#	Return:	none
###############################################################################
def Hull(pShip, pSubsystem = 0):
	"Prints out diagnostic information for the hull of the ship."

	if (pSubsystem == 0):
		# Print out information for each hull on the ship.
		kIter = pShip.StartGetSubsystemMatch(App.CT_HULL_SUBSYSTEM)
		while 1:
			pSystem = pShip.GetNextSubsystemMatch(kIter)
			if (pSystem == None):
				break
			Subsystem(pShip, App.HullClass_Cast(pSystem))
		return
	else:
		pHull = pSubsystem

	if (pHull == None):
		SSPrint("No hull on this ship. (?!)")
		return

	Subsystem(pShip, pHull)

###############################################################################
#	Shields(pShip, pSubsystem = 0)
#	
#	Prints out diagnostic information for the shield system.
#	
#	Args:	pShip - the ship
#			pSubsystem - the shield system to examine. If 0, all shield systems
#				on the ship will be examined.
#	
#	Return:	none
###############################################################################
def Shields(pShip, pSubsystem = 0):
	"Prints out diagnostic information for the shields of the ship."

	if (pSubsystem == 0):
		# Print out information for each shield on the ship. There
		# should only be one, BTW.
		kIter = pShip.StartGetSubsystemMatch(App.CT_SHIELD_SUBSYSTEM)
		while 1:
			pSystem = pShip.GetNextSubsystemMatch(kIter)
			if (pSystem == None):
				break
			Shields(pShip, App.ShieldClass_Cast(pSystem))
		return
	else:
		pShield = pSubsystem

	if (pShield == None):
		SSPrint("No shield subsystem on this ship.")
		return

	PoweredSubsystem(pShip, pShield)
	SSPrint("Current/max shield values (front/rear, top/bottom, left/right):")
	SSPrint("%f/%f\t%f/%f" % \
		(pShield.GetCurShields(pShield.FRONT_SHIELDS),	\
		 pShield.GetMaxShields(pShield.FRONT_SHIELDS),	\
		 pShield.GetCurShields(pShield.REAR_SHIELDS),	\
		 pShield.GetMaxShields(pShield.REAR_SHIELDS)))
	SSPrint("%f/%f\t%f/%f" % \
		(pShield.GetCurShields(pShield.TOP_SHIELDS),	\
		 pShield.GetMaxShields(pShield.TOP_SHIELDS),	\
		 pShield.GetCurShields(pShield.BOTTOM_SHIELDS), \
		 pShield.GetMaxShields(pShield.BOTTOM_SHIELDS)))
	SSPrint("%f/%f\t%f/%f" % \
		(pShield.GetCurShields(pShield.LEFT_SHIELDS),	\
		 pShield.GetMaxShields(pShield.LEFT_SHIELDS),	\
		 pShield.GetCurShields(pShield.RIGHT_SHIELDS),	\
		 pShield.GetMaxShields(pShield.RIGHT_SHIELDS)))
	SSPrint("Recharge rates (front, rear, top, bottom, left, right):")
	SSPrint("%f, %f, %f, %f, %f, %f" % \
		(pShield.GetShieldChargePerSecond(pShield.FRONT_SHIELDS),	\
		 pShield.GetShieldChargePerSecond(pShield.REAR_SHIELDS),	\
		 pShield.GetShieldChargePerSecond(pShield.TOP_SHIELDS),		\
		 pShield.GetShieldChargePerSecond(pShield.BOTTOM_SHIELDS),	\
		 pShield.GetShieldChargePerSecond(pShield.LEFT_SHIELDS),	\
		 pShield.GetShieldChargePerSecond(pShield.RIGHT_SHIELDS)))

###############################################################################
#	Repair(pShip, pSubsystem = 0)
#	
#	Prints out diagnostic information for the repair subsystem.
#	
#	Args:	pShip - the ship
#			pSubsystem - the repair system to examine. If 0, all repair systems
#				on the ship will be examined.
#	
#	Return:	none
###############################################################################
def Repair(pShip, pSubsystem = 0):
	"Prints out diagnostic information for the repair subsystem of the ship."

	if (pSubsystem == 0):
		# Print out information for each repair subsystem on the ship. There
		# should only be one, BTW.
		kIter = pShip.StartGetSubsystemMatch(App.CT_REPAIR_SUBSYSTEM)
		while 1:
			pSystem = pShip.GetNextSubsystemMatch(kIter)
			if (pSystem == None):
				break
			Repair(pShip, App.RepairSubsystem.Cast(pSystem))
		return
	else:
		pRepair = pSubsystem

	if (pRepair == None):
		SSPrint("No repair subsystem on this ship.")
		return

	PoweredSubsystem(pShip, pRepair)
	SSPrint("Repair teams: %d" % (pRepair.GetProperty().GetNumRepairTeams()))
	SSPrint("Repair points: %d" % (pRepair.GetProperty().GetMaxRepairPoints()))

###############################################################################
#	Sensors(pShip, pSubsystem = 0)
#	
#	Prints out diagnostic information for the sensor subsystem.
#	
#	Args:	pShip - the ship
#			pSubsystem - the sensor system to examine. If 0, all sensor systems
#				on the ship will be examined.
#	
#	Return:	none
###############################################################################
def Sensors(pShip, pSubsystem = 0):
	"Prints out diagnostic information for the sensor subsystem of the ship."

	if (pSubsystem == 0):
		# Print out information for each repair subsystem on the ship. There
		# should only be one, BTW.
		kIter = pShip.StartGetSubsystemMatch(App.CT_SENSOR_SUBSYSTEM)
		while 1:
			pSystem = pShip.GetNextSubsystemMatch(kIter)
			if (pSystem == None):
				break
			Sensors(pShip, App.SensorSubsystem_Cast(pSystem))
		return
	else:
		pSensor = pSubsystem

	if (pSensor == None):
		SSPrint("No sensor subsystem on this ship.")
		return

	PoweredSubsystem(pShip, pSensor)
	SSPrint("Sensor range (meaningless right now): %f" % (pSensor.GetSensorRange()))

###############################################################################
#	Weapons(pShip)
#	
#	Prints out basic information for weapons on the ship.
#	
#	Args:	pShip - the ship to check
#	
#	Return:	none
###############################################################################
def Weapons(pShip):
	"Prints out basic information for weapons on the ship."

	# Loop over individual engines.
	pIter = pShip.StartGetSubsystemMatch(App.CT_SHIP_SUBSYSTEM)

	while 1:
		pSystem = pShip.GetNextSubsystemMatch(pIter)
		if (pSystem == None):
			break

		if (App.PhaserSystem_Cast(pSystem) != None) or \
		   (App.TorpedoSystem_Cast(pSystem) != None) or \
		   (App.PulseWeaponSystem_Cast(pSystem) != None) or \
		   (App.TractorBeamSystem_Cast(pSystem) != None):
			for iIter in range(pSystem.GetNumChildSubsystems()):
				pChild = pSystem.GetChildSubsystem(iIter)
				Subsystem(pShip, pChild)

	pShip.EndGetSubsystemMatch(pIter)
	return
