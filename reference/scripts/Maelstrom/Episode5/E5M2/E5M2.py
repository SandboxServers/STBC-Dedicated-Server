###############################################################################
#	Filename:	E5M2.py
#
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#
#	Episode 5 Mission 2
#
#	Created:	10/09/00 -	Bill Morrison
#	Modified:	01/10/02 - 	Tony Evans
###############################################################################
import App
import loadspacehelper
import MissionLib
import Bridge.ScienceCharacterHandlers

# For debugging
#kDebugObj = App.CPyDebug()

#
# Event types
#
ET_ONE_MINUTE			= App.Mission_GetNextEventType()
ET_FIRST_GROUP			= App.Mission_GetNextEventType()
ET_SECOND_GROUP			= App.Mission_GetNextEventType()
ET_PROD_TIMER			= App.Mission_GetNextEventType()
ET_HAIL_STARFLEET		= App.Mission_GetNextEventType()
ET_SUMMARIZE			= App.Mission_GetNextEventType()
ET_PLAY_LOG				= App.Mission_GetNextEventType()


#
# Global variables
#

pMissionDatabase	= None
pEpisodeDatabase	= None
pGeneralDatabase	= None
pDatabase			= None
pEnemies			= None
pNeutrals			= None

iProdTimer			= 0
iGroup1Destroyed	= 0
iNumPhasers			= 0
iNumDisruptors		= 0
pOutpost			= None

AwayTeam			= None
BACK				= 0
AWAY				= 1
LOSS				= 0
WIN					= 1
INCOMPLETE			= 2
SCANNED				= 1
NOT_SCANNED			= 0

g_PowerFlag			= 0
g_bBaseDetected		= 0
g_bBaseID			= 0
g_bBaseInRange		= 0
g_bBasePowered		= 0
g_bBaseDisabled		= 0
g_bBaseAlive		= 1
g_bSequenceAppended = 0
g_bGerScanned		= 0
g_bLogsPlayed		= 0
g_idSequence		= App.NULL_ID
g_idSequence2		= App.NULL_ID
BaseScanned			= NOT_SCANNED
Prendel1Scanned		= NOT_SCANNED
Prendel2Scanned		= NOT_SCANNED
Prendel3Scanned		= NOT_SCANNED
Prendel4Scanned		= NOT_SCANNED
Prendel5Scanned		= NOT_SCANNED
KiskaComm			= 0
FelixComm			= 0
MiguelComm			= 0
SaffiComm			= 0
BrexComm			= 0
DataComm			= 0

MissionState		= INCOMPLETE

fStartTime			= 0
kStartupSoundID		= App.PSID_INVALID

###############################################################################
#	PreLoadAssets()
#
#	This is called once, at the beginning of the mission before Initialize()
#	to allow us to add models to be pre loaded
#
#	Args:	pMission	- the Mission object
#
#	Return:	none
###############################################################################
def PreLoadAssets(pMission):

	loadspacehelper.PreloadShip("Sovereign", 1)
	loadspacehelper.PreloadShip("Akira", 1)
	loadspacehelper.PreloadShip("FedStarbase", 1)

	loadspacehelper.PreloadShip("CardOutpost", 1)
	loadspacehelper.PreloadShip("Galor", 3)



###############################################################################
#
# Initialize()
#
# Called to initialize our mission
#
###############################################################################
def Initialize(pMission):
#	kDebugObj.Print ("Initializing Episode 5, Mission 2.\n")

	global pMissionDatabase, pEpisodeDatabase, pGeneralDatabase, pDatabase
	global iGroup1Destroyed, iNumPhasers, iNumDisruptors, MissionState
	global Prendel1Scanned, Prendel2Scanned, Prendel3Scanned, Prendel4Scanned, Prendel5Scanned, AwayTeam
	global g_bBaseDetected, g_bBaseID, g_bBaseInRange, g_bBasePowered, g_bBaseAlive, g_PowerFlag, g_bGerScanned
	global g_bSequenceAppended, g_idSequence, g_idSequence2, g_bLogsPlayed, g_bBaseDisabled

	pMissionDatabase = pMission.SetDatabase("data/TGL/Maelstrom/Episode 5/E5M2.tgl")
	pEpisodeDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 5/Episode5.tgl")
	pGeneralDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	iGroup1Destroyed	= 0
	iNumPhasers			= 0
	iNumDisruptors		= 0
	g_PowerFlag			= 0
	g_bBaseDetected		= 0
	g_bBaseID			= 0
	g_bBaseInRange		= 0
	g_bBasePowered		= 0
	g_bBaseDisabled		= 0
	g_bBaseAlive		= 1
	g_bSequenceAppended = 0
	g_bGerScanned		= 0
	g_bLogsPlayed		= 0
	g_idSequence		= App.NULL_ID
	g_idSequence2		= App.NULL_ID
	AwayTeam			= INCOMPLETE
	MissionState		= INCOMPLETE
	Prendel1Scanned		= NOT_SCANNED
	Prendel2Scanned		= NOT_SCANNED
	Prendel3Scanned		= NOT_SCANNED
	Prendel4Scanned		= NOT_SCANNED
	Prendel5Scanned		= NOT_SCANNED

	# Specify (and load if necessary) our bridge
	import LoadBridge
	LoadBridge.Load("SovereignBridge")

	# Add Data to the bridge
	pBridgeSet = App.g_kSetManager.GetSet("bridge")
	import Bridge.Characters.Data
	pData = App.CharacterClass_GetObject(pBridgeSet, "Data")
	if not (pData):
		pData = Bridge.Characters.Data.CreateCharacter(pBridgeSet)
		Bridge.Characters.Data.ConfigureForSovereign(pData)

	# Adjust the Guest Chair
	import Bridge.Characters.CommonAnimations
	Bridge.Characters.CommonAnimations.PutGuestChairIn()

	#Init the Characters
	InitCharacters()

	# Create and load basic stuff.  See below for the definitions of these
	# 4 functions.
	import Systems.Starbase12.Starbase12
	Systems.Starbase12.Starbase12.Initialize()
	pSet2 = Systems.Starbase12.Starbase12.GetSet()

	import Systems.Prendel.Prendel3
	Systems.Prendel.Prendel3.Initialize()
	pSet = Systems.Prendel.Prendel3.GetSet()

	import Systems.Prendel.Prendel5
	Systems.Prendel.Prendel5.Initialize()
	pPrendel5 = Systems.Prendel.Prendel5.GetSet()

	LoadMiscellaneous(pSet)

	# Load our placements into this set
	import Prendel3_P
	Prendel3_P.LoadPlacements(pSet.GetName())

	import EBridge_P
	EBridge_P.LoadPlacements(pBridgeSet.GetName())

	import SB12_P
	SB12_P.LoadPlacements(pSet2.GetName())

	# Create character sets
	pLBridgeSet = MissionLib.SetupBridgeSet("LBridgeSet", "data/Models/Sets/StarbaseControl/starbasecontrolRM.nif")
	pLiu = MissionLib.SetupCharacter("Bridge.Characters.Admiral_Liu", "LBridgeSet")

	pBaseSet = MissionLib.SetupBridgeSet("BaseSet", "data/Models/Sets/CardStation/Cardstation.nif")
	pData2 = MissionLib.SetupCharacter("Bridge.Characters.Data", "BaseSet")
	pData2.SetLocation("CardassianStationSeated")

	# Create the ships and set their stats
#	kDebugObj.Print ("Creating ships.\n")

	pPlayer = MissionLib.CreatePlayerShip("Sovereign", pSet2, "player", "Player Start" )
	pStarbase = loadspacehelper.CreateShip( "FedStarbase", pSet2, "Starbase 12", "Starbase12 Location" )
	CreateGeronimo(pSet2)

	global pOutpost
	pOutpost = loadspacehelper.CreateShip( "CardOutpost", pSet, "Outpost", "Base Location" )
	
	######################
	# Setup Affiliations #
	######################
	global pEnemies, pNeutrals

	pFriendlies = pMission.GetFriendlyGroup()
	pFriendlies.AddName("player")
	pFriendlies.AddName("Starbase 12")
	pFriendlies.AddName("USS Geronimo")
	pEnemies = pMission.GetEnemyGroup()
	pEnemies.AddName("Galor1")
	pEnemies.AddName("Galor2")
	pEnemies.AddName("Galor3")
	pNeutrals = pMission.GetNeutralGroup()
	pNeutrals.AddName("Outpost")

	MissionLib.SetupFriendlyFire()

	#################
	# Setup ship AI #
	#################

	import OutpostAI
	pOutpost.SetAI(OutpostAI.CreateAI(pOutpost))
	pOutpost.SetTargetable(0)
	pRepair = pOutpost.GetRepairSubsystem()
	pRepair.TurnOff()
	pOutpost.SetHidden(1)
	OutpostGreen(None)

	###############
	# End Ship AI #
	###############



	#######################################

	########################################
	# Setup up Warp Menu Buttons for Helm  #
	########################################

	import Systems.Starbase12.Starbase
	pSBMenu = Systems.Starbase12.Starbase.CreateMenus()

	MissionLib.AddGoal("E5LocateOutpostGoal")

	# Setup more mission-specific events.
	SetupEventHandlers()

	MissionLib.SetTotalTorpsAtStarbase("Photon", 600)
	MissionLib.SetTotalTorpsAtStarbase("Quantum", 0)
	MissionLib.SetMaxTorpsForPlayer("Photon", 200)
	MissionLib.SetMaxTorpsForPlayer("Quantum", 60)

	E5Intro(None)

	MissionLib.SaveGame("E5M1-")



###############################################################################
#
# CreateGeronimo
#
###############################################################################
def CreateGeronimo(pSet):

#	print("Creating Geronimo")

	pShip = loadspacehelper.CreateShip( "Akira", pSet, "USS Geronimo", "Geronimo" )
	pShip.ReplaceTexture("Data/Models/Ships/Akira/Geronimo.tga", "ID")
	pShip.SetAlertLevel(App.ShipClass.GREEN_ALERT)

	# Add Visible Damage
	import DamageAkira
	DamageAkira.AddDamage(pShip)

	# Damage the ship...
	pRepair = pShip.GetRepairSubsystem()
	pRepair.TurnOff()	
		
	# Destroy the shield generator
	pShields = pShip.GetShields()
	pShip.DamageSystem(pShields, 5000)

	# Damage the Power Planet - 1000 pts of damage
	pShip.DamageSystem(pShip.GetPowerSubsystem(), 1000)
	# Damage the hull - 2000 pts of damage
	pShip.DamageSystem(pShip.GetHull(), 2000)
	# Damage the Impulse engines - 0 pts each
	pImpulse = pShip.GetImpulseEngineSubsystem()
	pShip.DamageSystem(pImpulse.GetChildSubsystem(0), 2200)
	pShip.DamageSystem(pImpulse.GetChildSubsystem(1), 2400)


###############################################################################
#
# InitCharacters()
#
###############################################################################
def InitCharacters():
	global pSaffi, pMiguel, pFelix, pKiska, pBrex, pData

	# Get the Characters
	pBridge = App.g_kSetManager.GetSet("bridge")
	pSaffi = App.CharacterClass_GetObject (pBridge, "XO")
	pKiska = App.CharacterClass_GetObject (pBridge, "Helm")
	pFelix = App.CharacterClass_GetObject (pBridge, "Tactical")
	pBrex = App.CharacterClass_GetObject (pBridge, "Engineer")
	pMiguel = App.CharacterClass_GetObject (pBridge, "Science")
	pData = App.CharacterClass_GetObject (pBridge, "Data")

	# Initialize the Communicate Counters
	global KiskaComm, FelixComm, MiguelComm, SaffiComm, BrexComm, DataComm

	KiskaComm			= 0
	FelixComm			= 0
	MiguelComm			= 0
	SaffiComm			= 0
	BrexComm			= 0
	DataComm			= 0


###############################################################################
#
# LoadMiscellaneous()
#
###############################################################################
def LoadMiscellaneous(pSet):
	#Load and place the grid.
	pGrid = App.GridClass_Create ()
	pSet.AddObjectToSet (pGrid, "grid")
	pGrid.SetHidden (1)

###############################################################################
#
# SetupEventHandlers()
#
###############################################################################
def SetupEventHandlers():
	"Setup any event handlers to listen for broadcast events that we'll need."
	pMission = App.Game_GetCurrentGame().GetCurrentEpisode().GetCurrentMission()

	# AI Done event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_AI_DONE, pMission, __name__+".AIDone")
	# Ship entrance event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_ENTERED_SET, pMission, __name__+".EnterSet")
	# Ship exit event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_EXITED_SET, pMission, __name__+".ExitSet")
	# Object destroyed event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_EXPLODING, pMission, __name__ + ".ObjectDestroyed")

	# Target is ID'd by sensors event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_SENSORS_SHIP_IDENTIFIED, pMission, __name__+".ShipIdentified")
	# Handler for Outpost's Weapons getting disabled
	pOutpost.AddPythonFuncHandlerForInstance(App.ET_SUBSYSTEM_DISABLED, __name__ + ".SubsystemDisabled")

	pWarpButton = App.SortedRegionMenu_GetWarpButton()
	if (pWarpButton):
		pWarpButton.AddPythonFuncHandlerForInstance(App.ET_WARP_BUTTON_PRESSED,	__name__ + ".WarpCheck")

	# SAFFI HANDLERS
	# Contact Starfleet
	pSaffi.GetMenu().AddPythonFuncHandlerForInstance(App.ET_CONTACT_STARFLEET, __name__+".HailStarfleet")
	# Communicate
	pSaffi.GetMenu().AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	# MIGUEL HANDLERS
	# Science Scan event
	pMiguel.GetMenu().AddPythonFuncHandlerForInstance(App.ET_SCAN, __name__+".ScanHandler")
	# Communicate with Miguel event
	pMiguel.GetMenu().AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	# Communicate with Felix event
	pFelix.GetMenu().AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	# Communicate with Kiska event
	pKiska.GetMenu().AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	# Communicate with Brex event
	pBrex.GetMenu().AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	# Communicate with Data event
	pData.GetMenu().AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")


#############################
# Mission Related Functions #
#############################
###############################################################################
#
# AIDone()
#
###############################################################################
def AIDone(TGObject, pEvent):
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
#	kDebugObj.Print("AIDone() called for %s" % pShip.GetName())

	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)


###############################################################################
#
# EnterSet()
#
###############################################################################
def EnterSet(TGObject, pEvent):
	"An event triggered whenever an object enters a set."
	# Check if it's a ship.
	pShip = App.ShipClass_Cast(pEvent.GetDestination())

	if (pShip):
		# It's a ship.
		pSet = pShip.GetContainingSet()
		sSetName = pSet.GetName()

#		kDebugObj.Print("Ship \"%s\" entered set \"%s\"" % (pShip.GetName(), pSet.GetName()))

		if (pShip.GetName() == "player") and (sSetName[:len("Prendel")] == "Prendel") and (not Prendel3Scanned):
			pAction = App.TGScriptAction_Create(__name__, "StartProdTimer", 15)
			pAction.Play()
			
			if (sSetName == "Prendel5"):
				MissionLib.RemoveGoal("E5SearchPrendelGoal")

		if (pShip.GetName() == "player") and (pSet.GetName() == "warp"):
			# Player entered warp set.
			# Adjust Communicate Counters
			global KiskaComm, FelixComm, MiguelComm, SaffiComm, BrexComm, DataComm

			DataComm = 0
			KiskaComm = 0
			SaffiComm = 0
			MiguelComm = 1

	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)

###############################################################################
#
# ExitSet()
#
###############################################################################
def ExitSet(TGObject, pEvent):
	"Triggered whenever an object leaves a set."
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	sSetName = pEvent.GetCString()

	if (pShip):
		# It's a ship.
#		kDebugObj.Print("Ship \"%s\" exited set \"%s\"" % (pShip.GetName(), sSetName))

		global iGroup1Destroyed
		if ((pShip.GetName() == "Galor1") or (pShip.GetName() == "Galor2") or (pShip.GetName() == "Galor3")):
			if (sSetName == "Prendel3"):
				iGroup1Destroyed = iGroup1Destroyed +1
#				kDebugObj.Print("iGroup1Destroyed = %d" % iGroup1Destroyed)

		if (iGroup1Destroyed == 3):
			iGroup1Destroyed = 4
#			kDebugObj.Print("Cards are gone")

			# Set Saffi's Communicate Flag
			global SaffiComm, FelixComm
			SaffiComm = 0
			FelixComm = 0

			AwayTeamReturn()

	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)

###############################################################################
#
# ObjectDestroyed()
#
###############################################################################
def ObjectDestroyed(TGObject, pEvent):
#	kDebugObj.Print("Object Destroyed")
	pShip = App.ObjectClass_Cast(pEvent.GetDestination())
#	kDebugObj.Print("Ship \"%s\" was destroyed" % pShip.GetName())

	if (pShip):

		if (pShip.GetName() == "Outpost"):
			global g_bBaseAlive
			g_bBaseAlive = 0
		
			MissionLib.ViewscreenWatchObject(pOutpost)

			if (AwayTeam == INCOMPLETE) or (AwayTeam == AWAY):
				pAction = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M2OutpostDestroyed1", None, 0, pMissionDatabase)
				pAction.Play()
				MissionLoss()

			# After ordered to destroy
			elif (AwayTeam == BACK):
				pSequence = App.TGSequence_Create()
				pAction1 = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M2OutpostDestroyed2", None, 0, pMissionDatabase)
				pSequence.AddAction(pAction1)

				if (MissionState == BACK):
					pAction2 = App.TGScriptAction_Create(__name__, "MissionWin")
					pSequence.AppendAction(pAction2, 2)
				
				pSequence.Play()

				MissionLib.RemoveGoal("E5DestroyOutpostGoal")

		elif (pShip.GetName() == "USS Geronimo"):
	
			pSequence = App.TGSequence_Create()
			pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_LOOK_AT_ME)		
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "DontShoot7", "Captain", 1, pGeneralDatabase)			
			pSequence.AppendAction(pAction)
			
			MissionLib.GameOver(None, pSequence)			


	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)

###############################################################################
#
# SubsystemDisabled()
#
###############################################################################
def SubsystemDisabled(pShip, pEvent):
	
	if (pShip.GetName() != "Outpost"):
#		kDebugObj.Print("System does not belong to outpost... bypassing")
		pShip.CallNextHandler(pEvent)
		return

	global iNumPhasers, iNumDisruptors

	# Check if this is one of the phaser arcs..
	pPhaserBank = App.PhaserBank_Cast( pEvent.GetSource() )
	if pPhaserBank:
		# It's one of the phaser banks.
#		kDebugObj.Print("Phaser Disabled")
		iNumPhasers = iNumPhasers + 1

		if iNumPhasers == 1:
			pAction = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M2Defense3", None, 0, pMissionDatabase)
			pAction.Play()

		elif iNumPhasers == 2:
			pAction = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M2Defense4", None, 0, pMissionDatabase)
			pAction.Play()

		elif iNumPhasers == 3:
			pAction = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M2Defense5", None, 0, pMissionDatabase)
			pAction.Play()

		elif iNumPhasers == 6:
			pAction = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M2Defense6", None, 0, pMissionDatabase)
			pAction.Play()


	# Check if it's a pulse weapon arc..
	pPulse = App.PulseWeapon_Cast( pEvent.GetSource() )
	if pPulse:
		# It's one of the pulse weapons...
#		kDebugObj.Print("Pulse weapon disabled")
		iNumDisruptors = iNumDisruptors + 1

		if iNumDisruptors == 1:
			pAction = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M2Disrupt1", None, 0, pMissionDatabase)
			pAction.Play()

		if iNumDisruptors == 3:
			pAction = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M2Disrupt2", None, 0, pMissionDatabase)
			pAction.Play()

		if iNumDisruptors == 6:
			pAction = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M2Disrupt3", None, 0, pMissionDatabase)
			pAction.Play()

	pCore = App.PowerSubsystem_Cast( pEvent.GetSource() )
	if pCore:
		pAction = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M2Core", None, 0, pMissionDatabase)
		pAction.Play()

	pShip.CallNextHandler(pEvent)


###############################################################################
#
# ShipIdentified():
#
###############################################################################
def ShipIdentified(pObject, pEvent):
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	if (pShip == None):
		return
	sShipName = pShip.GetName()

	# If the ship is the Outpost, do stuff
	# and don't CallNextHandler
	if (sShipName == "Outpost"):
	
		global g_bBaseID, g_bSequenceAppended
		g_bBaseID = 1

		if (g_bBaseDetected):
			if not (g_bSequenceAppended):
				
				pSequence = App.TGSequence_Create()
				
				pAction1 = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E5M2OutpostFound", None, 0, pMissionDatabase)
				pAction2 = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5ScanOutpostGoalAudio", "Captain", 1, pEpisodeDatabase)

				pSequence.AddAction(pAction1)
				pSequence.AddAction(pAction2, pAction1)

				QueueSequence(pSequence)


			MissionLib.RemoveGoal("E5LocateOutpostGoal")
			MissionLib.AddGoal("E5ScanOutpostGoal")

			return

#		else:
#			print("Base Detected too early")

	# We're done. Let any other event handlers for this event handle it.
	pObject.CallNextHandler(pEvent)



###############################################################################
#
# BaseAppears()
#
# Called from OutpostAI when player is close enough
# And in LineOfSight of the Outpost
#
###############################################################################
def BaseAppears():
	
	pPlayer = MissionLib.GetPlayer()

	pOutpost.SetHidden(0)
	pOutpost.SetTargetable(1)

	StopProdTimer()

	pPlayer.SetTarget("Outpost")

	global g_bBaseDetected, Prendel3Scanned, g_idSequence, g_bSequenceAppended, MiguelComm
	g_bBaseDetected = 1
	Prendel3Scanned = SCANNED
	MiguelComm = 0

	pSequence = App.TGSequence_Create()
	
	g_idSequence = pSequence.GetObjID()
	
	pAction1 = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M2OutpostDetected", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction1)	
	pAction2 = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M2OutpostDetected2", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction2)
	pAction3 = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M2OutpostDetected3", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction3)
	pAction4 = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M2OutpostDetected4", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction4)
	
	if (g_bBaseID):
		pAction5 = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E5M2OutpostFound", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction5)	
		pAction6 = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5ScanOutpostGoalAudio", "Captain", 1, pEpisodeDatabase)
		pSequence.AppendAction(pAction6)		

		g_bSequenceAppended = 1

		MissionLib.RemoveGoal("E5LocateOutpostGoal")
		MissionLib.AddGoal("E5ScanOutpostGoal")	

	pSequence.Play()


###############################################################################
#
# BaseInRange()
#
# Called from OutpostAI when player is close enough to scan
#
###############################################################################
def BaseInScanningRange():

#	print("* BASE IS IN SCANNING RANGE!!! *")

	global g_bBaseInRange
	g_bBaseInRange = 1

	pSequence = App.TGSequence_Create()
	pAction1 = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M2OutpostRange2", "Captain", 1, pMissionDatabase)
	pSequence.AddAction(pAction1)

	QueueSequence(pSequence)

	# Reset Saffi's Communicate Button
	global SaffiComm, DataComm
	SaffiComm = 0
	DataComm = 0


def QueueSequence(pSequence):
	
	global g_idSequence2

	# Which existing sequence does this need to be appended to?
	# Is Sequence 2 not currently playing?
	if ((g_idSequence2 == None) or (App.TGObject_GetTGObjectPtr(g_idSequence2) == None)):
		g_idSequence2 = pSequence.GetObjID()
		
		# If Sequence 1 is playing -  Append to it
		if ((g_idSequence != None) and (App.TGObject_GetTGObjectPtr(g_idSequence) != None)):
			pSequence1 = App.TGSequence_Cast(App.TGObject_GetTGObjectPtr(g_idSequence))
			pSequence1.AppendAction(pSequence)
		else:
			pSequence.Play()

	else:
		pSequence2 = App.TGSequence_Cast(App.TGObject_GetTGObjectPtr(g_idSequence2))
		pSequence2.AppendAction(pSequence)


###############################################################################
#
# BasePowersUp()
#
# Called from OutpostAI when player is close enough to trigger defenses
#
###############################################################################
def BasePowersUp(pAction):
#	print("******* BASE IS POWERING UP!!! *******")

	if g_PowerFlag:
#		print("This function has already been triggered... bypassing")
		return 0

	global g_bBasePowered, g_PowerFlag, pEnemies
	g_bBasePowered = 1
	g_PowerFlag = 1
	pEnemies.AddName("Outpost")

	pSequence = App.TGSequence_Create()
	pAction1 = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M2PowerSurge", None, 0, pMissionDatabase)
	pAction2 = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M2Defense1", "Captain", 1, pMissionDatabase)
	pRed	 = App.TGScriptAction_Create(__name__, "OutpostRed")
	pAddAI	 = App.TGScriptAction_Create(__name__, "AssignOutpostAI")
	pAction3 = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M2Defense2", None, 0, pMissionDatabase)
	pAction4 = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E5M2DataSuggest", "Captain", 1, pMissionDatabase)

	pSequence.AddAction(pAction1)
	pSequence.AddAction(pAction2, pAction1)
	pSequence.AddAction(pRed, pAction2)
	pSequence.AddAction(pAddAI, pAction2, 1)
	pSequence.AddAction(pAction3, pAction2)
	pSequence.AddAction(pAction4, pAction3)

	MissionLib.QueueActionToPlay(pSequence)

	MissionLib.AddGoal("E5DisableOutpostGoal")

	# Set Communicate Flags
	global FelixComm, BrexComm, SaffiComm, MiguelComm, DataComm
	FelixComm = 1
	BrexComm = 1
	DataComm = 3
	SaffiComm = 4
	MiguelComm = 5

	return 0
	
###############################################################################
#
#	OutpostPhasersOut():
#
#	Called from OutpostAI, when all phasers have been
#	destroyed.
#
###############################################################################
def OutpostPhasersOut():
#	print("Relevent subsystems have been disabled")

	global g_bBasePowered, g_bBaseDisabled
	g_bBaseDisabled = 1
	g_bBasePowered = 0

	# Stop Felix from attacking further
	MissionLib.StopFelix()
	
	# Remove the Subsystem reporting handler
	pOutpost.RemoveHandlerForInstance(App.ET_SUBSYSTEM_DISABLED, __name__ + ".SubsystemDisabled")
	
	pSequence = App.TGSequence_Create()

	pAction1 = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M2Defense7", None, 0, pMissionDatabase)
	pAction2 = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M2PowerDown", None, 0, pMissionDatabase)	
	pAction3 = App.TGScriptAction_Create(__name__, "AwayTeamLeaves")
	pAction4 = App.TGScriptAction_Create(__name__, "OutpostDormant")

	pSequence.AddAction(pAction1, None, 3)
	pSequence.AddAction(pAction2, pAction1)
	pSequence.AddAction(pAction3, pAction2, 2)
	pSequence.AddAction(pAction4, pAction3)

	MissionLib.QueueActionToPlay(pSequence)

	MissionLib.RemoveGoal("E5DisableOutpostGoal")

	# Set Communicate Flags for Felix and Brex
	global FelixComm, BrexComm, SaffiComm, DataComm, MiguelComm
	FelixComm = 0
	BrexComm = 0
	SaffiComm = 0
	DataComm = 0
	MiguelComm = 0

###############################################################################
#
#	OutpostDormant():
#
#	Called from OutpostAI, when all phasers have been
#	destroyed.
#
###############################################################################
def OutpostDormant(pAction):
	global pEnemies, pNeutrals

	import OutpostAI2
	pOutpost.SetAI(OutpostAI2.CreateAI(pOutpost))

	OutpostGreen(None)

	pEnemies.RemoveName("Outpost")
	pNeutrals.AddName("Outpost")

	return 0


def OutpostRed(pAction):
#	print("Outpost going to Red Alert")
	
	pOutpost.SetAlertLevel(App.ShipClass.RED_ALERT)
	
	return 0

def OutpostGreen(pAction):
#	print("Oupost Going to Green Alert")

	pOutpost.SetAlertLevel(App.ShipClass.GREEN_ALERT)

	return 0

def AssignOutpostAI(pAction):

	if g_bBaseDisabled == 1:
		return 0

	import OutpostAI3
	pOutpost.SetAI(OutpostAI3.CreateAI(pOutpost))

	return 0

###############################################################################
#
# WarpCheck(pObject, pEvent)
#
###############################################################################
def WarpCheck(pObject, pEvent):
	if (g_bBaseDisabled) and (AwayTeam != BACK):
		pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "WarpStop2", None, 0, pGeneralDatabase)
		pAction.Play()

	else:
		pObject.CallNextHandler(pEvent)

###################################################
#
# Episode Intro, Miguel's Log
#
###################################################
def E5Intro(pAction):

	if MissionLib.IsPlayerWarping():
		# Delay sequence 2 seconds. 
		pSequence = App.TGSequence_Create()
		pRePlayIntro = App.TGScriptAction_Create(__name__, "E5Intro")
		pSequence.AppendAction(pRePlayIntro, 2)
		pSequence.Play()

		return 0

	pSequence = App.TGSequence_Create()

	pStartCamera = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "bridge")
	pSequence.AppendAction(pStartCamera)

	pBridgeCam	= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge")
	pSequence.AppendAction(pBridgeCam)

	pAction	= App.TGScriptAction_Create("MissionLib", "StartCutscene")
	pSequence.AppendAction(pAction)

	pScienceCam	= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Miguel Head", "Miguel Cam1", 1)
	pSequence.AppendAction(pScienceCam)

	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "FadeOut", 0))
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "FadeIn", 3))

	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "EpisodeTitleAction", "Ep5Title"))

	pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SPEAK_LINE_NO_FLAP_LIPS, "E5Intro1", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction, 3)

	pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SPEAK_LINE_NO_FLAP_LIPS, "E5Intro2", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)

	pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SPEAK_LINE_NO_FLAP_LIPS, "E5Intro3", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)

	pFelixCam	= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Felix Head", "Felix Cam", 1)
	pSequence.AppendAction(pFelixCam)

	pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SPEAK_LINE_NO_FLAP_LIPS, "E5Intro4", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)

	pSaffiCam	= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1", 1)
	pSequence.AppendAction(pSaffiCam)

	pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SPEAK_LINE_NO_FLAP_LIPS, "E5Intro5", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)

	pPlayerCam	= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam", 1)
	pSequence.AppendAction(pPlayerCam)

	pBriefing	= App.TGScriptAction_Create(__name__, "Briefing")
	pSequence.AppendAction(pBriefing)

	pSequence.Play()

	return 0

###################################################
#
# Briefing from Liu
#
###################################################
def Briefing(pAction):
	pLBridgeSet = App.g_kSetManager.GetSet("LBridgeSet")
	pLiu = App.CharacterClass_GetObject (pLBridgeSet, "Liu")
	pLiu.SetHidden(0)

	pSequence = App.TGSequence_Create()

	pAction = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "IncomingMsg5","Captain", 1, pGeneralDatabase)
	pAction1 = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LBridgeSet", "Liu")
	pAction2 = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E5M2BriefA", None, 0, pMissionDatabase)
	pAction3 = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E5M2BriefB", None, 0, pMissionDatabase)
	pAction4 = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M2BriefC", None, 0, pMissionDatabase)
	pAction5 = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E5M2Brief1", None, 0, pMissionDatabase)
	pAction6 = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E5M2Brief2", None, 0, pMissionDatabase)
	pAction7 = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E5M2Brief3", None, 0, pMissionDatabase)
	pAction8 = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pAction9 = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E5M2L006", "Captain", 1, pMissionDatabase)
	pAction10 = App.TGScriptAction_Create(__name__, "AddDataButtons")
	pCineEnd  = App.TGScriptAction_Create("MissionLib", "EndCutscene")
	pProdTimer = App.TGScriptAction_Create(__name__, "StartProdTimer", 30)
	pEndCam  = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "bridge")

	pSequence.AddAction(pAction)
	pSequence.AddAction(pAction1, pAction)
	pSequence.AddAction(pAction2, pAction1)
	pSequence.AddAction(pAction3, pAction2)
	pSequence.AddAction(pAction4, pAction3)
	pSequence.AddAction(pAction5, pAction4)
	pSequence.AddAction(pAction6, pAction5)
	pSequence.AddAction(pAction7, pAction6)
	pSequence.AddAction(pAction8, pAction7)
	pSequence.AddAction(pAction9, pAction8)
	pSequence.AddAction(pAction10, pAction9)
	pSequence.AddAction(pProdTimer, pAction10)  # This starts the Prod Timer for Saffi
	pSequence.AddAction(pCineEnd, pAction8)	
	pSequence.AddAction(pEndCam, pCineEnd)

	pSequence.Play()

	MissionLib.AddGoal("E5LocateOutpostGoal")

	global DataComm, SaffiComm
	DataComm = 4
	SaffiComm = 5

	return 0

###################################################
#
# DataSummarize(pObject, pEvent)
#
###################################################
def DataSummarize(pObject, pEvent):

	StopProdTimer()

	pSequence = App.TGSequence_Create()
	pAction = App.TGScriptAction_Create(__name__, "RemoveDataButtons")
	pSequence.AddAction(pAction)
	pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E5M2L007", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M2L009", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction, 3)
	pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E5M2L010", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction, 1)
	pAction = App.TGScriptAction_Create("MissionLib", "AddGoalAction", "E5SearchPrendelGoal")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "AddPrendelLocation")	
	pSequence.AppendAction(pAction)
	pSequence.Play()

	global DataComm, SaffiComm, g_bLogsPlayed
	DataComm = 0
	SaffiComm = 0
	g_bLogsPlayed = 1


###################################################
#
# DataPlayLog(pObject, pEvent)
#
###################################################
def DataPlayLog(pObject, pEvent):

	StopProdTimer()

	pSequence = App.TGSequence_Create()
	pAction = App.TGScriptAction_Create(__name__, "RemoveDataButtons")
	pSequence.AddAction(pAction)
	pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E5M2L013", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pMissionDatabase, "E5M2L015", "MacCray")
	pSequence.AppendAction(pAction, 1)	
	pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pMissionDatabase, "E5M2L016", "MacCray")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pMissionDatabase, "E5M2L017", "MacCray")
	pSequence.AppendAction(pAction, 1)
	pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pMissionDatabase, "E5M2L018", "MacCray")
	pSequence.AppendAction(pAction, 1)
	pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E5M2L019", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction, 1)
	pAction = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M2L020", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M2L021", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "AddGoalAction", "E5SearchPrendelGoal")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "AddPrendelLocation")	
	pSequence.AppendAction(pAction)
	pSequence.Play()

	global DataComm, SaffiComm, g_bLogsPlayed
	DataComm = 0
	SaffiComm = 0
	g_bLogsPlayed = 1

###################################################
#
# Debriefing from Liu
#
###################################################
def HailStarfleet(pObject, pEvent):
	pLBridgeSet = App.g_kSetManager.GetSet("LBridgeSet")
	pLiu = App.CharacterClass_GetObject (pLBridgeSet, "Liu")
	pLiu.SetHidden(0)

	if (MissionState == WIN):

		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "CallWaiting", 1)
		pSequence.AddAction(pAction)
		pAction =  App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "HailStarfleet3", None, 0, pGeneralDatabase)
		pSequence.AppendAction(pAction)
		pAction =  App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "HailStarfleet5", None, 0, pGeneralDatabase)
		pSequence.AppendAction(pAction)
		pAction =  App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "HailStarfleet7", None, 0, pGeneralDatabase)
		pSequence.AppendAction(pAction, 4)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LBridgeSet", "Liu")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E5M2Debrief4", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction, 1)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction, 1)
		pAction = App.TGScriptAction_Create("MissionLib", "CallWaiting", 0)
		pSequence.AppendAction(pAction)

		pSequence.Play()

		return 0

	else:
		pObject.CallNextHandler(pEvent)

		return 0

###################################################
#
# CommunicateHandler()
#
###################################################
def CommunicateHandler(pObject, pEvent):
#	print("Communicating with crew")

	pMenu = App.STTopLevelMenu_Cast(pEvent.GetDestination())
	pPlayer = MissionLib.GetPlayer()
	if not pPlayer or not pMenu:
		return
	pSet = pPlayer.GetContainingSet()

	pBridge = App.g_kSetManager.GetSet("bridge")

	pSaffiMenu = pSaffi.GetMenu()
	pFelixMenu = pFelix.GetMenu()
	pKiskaMenu = pKiska.GetMenu()
	pMiguelMenu = pMiguel.GetMenu()
	pBrexMenu = pBrex.GetMenu()
	pDataMenu = pData.GetMenu()

	pAction = 0
	pSequence = 0

	if pMenu.GetObjID() == pKiskaMenu.GetObjID():
#		print("Communicating with Kiska")

		if (KiskaComm == 1):
			pAction = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E5M2KiskaProd1", None, 0, pMissionDatabase)

	elif pMenu.GetObjID() == pSaffiMenu.GetObjID():
#		print("Communicating with Saffi")

		if (SaffiComm == 1):
			pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M2SaffiProd1", None, 0, pMissionDatabase)
			StopProdTimer()

		elif (SaffiComm == 2):
			pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M2SaffiProd2", None, 0, pMissionDatabase)
			StopProdTimer()

		elif (SaffiComm == 3):
			pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M2SaffiProd3", None, 0, pMissionDatabase)
			StopProdTimer()

		elif (SaffiComm == 4):
			pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M2Defense2", None, 0, pMissionDatabase)

		elif (SaffiComm == 5):
			pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M2SaffiProd4", None, 0, pMissionDatabase)


	elif pMenu.GetObjID() == pMiguelMenu.GetObjID():
#		print("Communicating with Miguel")

		if (MiguelComm == 1):
#			print("Setting Miguel to prompt to scan")
			pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M2MiguelProd1", None, 0, pMissionDatabase)
			StopProdTimer()

		if (MiguelComm == 2):
			pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M2MiguelProd2", None, 0, pMissionDatabase)
			StopProdTimer()

		if (MiguelComm == 3):
			pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M2MiguelProd3", None, 0, pMissionDatabase)
			StopProdTimer()

		if (MiguelComm == 4):
			pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M2MiguelProd4", None, 0, pMissionDatabase)
			StopProdTimer()

		if (MiguelComm == 5):
			pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M2MiguelProd5", None, 0, pMissionDatabase)
			StopProdTimer()

	elif pMenu.GetObjID() == pFelixMenu.GetObjID():
#		print("Communicating with Felix")

		if (FelixComm == 1):
			pAction = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M2FelixProd1", None, 0, pMissionDatabase)

		if (FelixComm == 2):
			pAction = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M2FelixProd2", None, 0, pMissionDatabase)


	elif pMenu.GetObjID() == pBrexMenu.GetObjID():
#		print("Communicating with Brex")

		if (BrexComm == 1):
		
			pSequence = App.TGSequence_Create()
			pAction0 = App.CharacterAction_Create(pBrex, App.CharacterAction.AT_SAY_LINE, "E5M2BrexProd1b", None, 0, pMissionDatabase)
			pAction1 = App.CharacterAction_Create(pBrex, App.CharacterAction.AT_SAY_LINE, "E5M2BrexProd1", None, 0, pMissionDatabase)
			pAction2 = App.CharacterAction_Create(pBrex, App.CharacterAction.AT_SAY_LINE, "E5M2BrexProd1a", None, 0, pMissionDatabase)
			pSequence.AddAction(pAction0)
			pSequence.AddAction(pAction1, pAction0)
			pSequence.AddAction(pAction2, pAction1)

	else:
#		print("Communicating with Data")

		if (DataComm == 1):
			pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E5M2DataProd1", None, 0, pMissionDatabase)

		elif (DataComm == 2):
			pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E5M2DataProd2", None, 0, pMissionDatabase)

		elif (DataComm == 3):
			pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E5M2DataProd3", None, 0, pMissionDatabase)

		elif (DataComm == 4):
			pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E5M2L006", None, 0, pMissionDatabase)

		else:
			pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E5M2DataNoProd", None, 0, pMissionDatabase)

#	print pAction

	if pAction:
		pAction.Play()

	elif pSequence:
		pSequence.Play()

	else:
#		print("Nothing special to handle.  Continue normal Communicate handler.")
		pObject.CallNextHandler(pEvent)

###################################################
#
# ScanHandler()
#
###################################################
def ScanHandler(pObject, pEvent):
#	kDebugObj.Print("Scanning")

	iScanType = pEvent.GetInt()

	global KiskaComm, FelixComm, MiguelComm, SaffiComm, BrexComm, DataComm

	pPlayer = MissionLib.GetPlayer()
	pSet = pPlayer.GetContainingSet()
	pSensors = pPlayer.GetSensorSubsystem()

	if (pSensors == None):
		pObject.CallNextHandler(pEvent)
		return

	if (pSensors.IsOn() == 0):
		pObject.CallNextHandler(pEvent)
		return

	pSequence = App.TGSequence_Create()


	if (iScanType == App.CharacterClass.EST_SCAN_AREA):
		pcSetName = pSet.GetName()
		
		if (pcSetName == "Starbase12"):
			pObject.CallNextHandler(pEvent)
			return

		elif ((pcSetName[:len("Prendel")] == "Prendel") and (pcSetName != "Prendel3")) and (not Prendel5Scanned):
#			kDebugObj.Print("Scanning at Prendel")

			StopProdTimer()

			pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence()
			pSequence.AppendAction(pScanSequence)
			pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M2PrendelScan1", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
			pSequence.AppendAction(pEnableScanMenu)		
			pAction = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M2PrendelScan2", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M2PrendelScan3", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M2PrendelScan4", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E5M2PrendelScan5", "T", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M2PrendelScan6", "H", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M2PrendelScan7", "T", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M2PrendelScan8", "S", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M2Suggest1", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E5M2Suggest2", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create(__name__, "StartProdTimer", 20)
			pSequence.AppendAction(pAction)

			global Prendel5Scanned
			Prendel5Scanned = SCANNED

			# Set Communicate Flags
			DataComm = 1
			SaffiComm = 1
			KiskaComm = 1
			MiguelComm = 4

			pSequence.Play()
			return

		elif (pcSetName == "Prendel4") and (not Prendel4Scanned):
#			kDebugObj.Print("Scanning at Prendel4")

			pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence()
			pAction			= App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M2Prend4Scan", "Captain", 1, pMissionDatabase)
			pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")	

			pSequence.AppendAction(pScanSequence)		
			pSequence.AppendAction(pAction)
			pSequence.AppendAction(pEnableScanMenu)

			global Prendel4Scanned
			Prendel4Scanned = SCANNED

			# Set Communicate Flags
			DataComm = 1
			SaffiComm = 1
			KiskaComm = 1
			MiguelComm = 4

			pSequence.Play()
			return

		elif (pcSetName == "Prendel3"):
			if not (Prendel3Scanned):
#				kDebugObj.Print("Scanning at Prendel3")

				StopProdTimer()

				pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence()
				pSequence.AppendAction(pScanSequence)		
				pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M2Prend3Scan1", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")	
				pSequence.AppendAction(pEnableScanMenu)
				pAction = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E5M2NavPoint", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create(__name__, "AddNavPoint")
				pSequence.AppendAction(pAction)

				global Prendel3Scanned
				Prendel3Scanned = SCANNED

				# Set Communicate Flags
				SaffiComm = 2
				MiguelComm = 3
				DataComm = 2

				pSequence.Play()
				return
				
			elif (Prendel3Scanned) and not (g_bBaseDetected):
	
				pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence()		
				pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M2Prend3Scan1", None, 0, pMissionDatabase)				
				pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")	

				pSequence.AppendAction(pScanSequence)		
				pSequence.AppendAction(pAction)
				pSequence.AppendAction(pEnableScanMenu)

				# Set Communicate Flags
				SaffiComm = 2
				MiguelComm = 3
				DataComm = 2

				pSequence.Play()
				return

			else:
				
				pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence()
				pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M2PrendelScan1", "Captain", 1, pMissionDatabase)				
				pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")	

				pSequence.AppendAction(pScanSequence)		
				pSequence.AppendAction(pAction)
				pSequence.AppendAction(pEnableScanMenu)
				
				# Set Communicate Flags
				SaffiComm = 0
				MiguelComm = 0
				DataComm = 0

				pSequence.Play()
				return

		elif (pcSetName == "Prendel2") and (not Prendel2Scanned):
#			kDebugObj.Print("Scanning at Prendel2")

			pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence()
			pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M2Prend2Scan", "Captain", 1, pMissionDatabase)
			pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")				

			pSequence.AppendAction(pScanSequence)		
			pSequence.AppendAction(pAction)
			pSequence.AppendAction(pEnableScanMenu)

			global Prendel2Scanned
			Prendel2Scanned = SCANNED

			# Set Communicate Flags
			DataComm = 1
			SaffiComm = 1
			KiskaComm = 1
			MiguelComm = 4
	
			pSequence.Play()
			return

		elif (pcSetName == "Prendel1") and (not Prendel1Scanned):
#			kDebugObj.Print("Scanning at Prendel1")

			pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence()		
			pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M2Prend1Scan", "Captain", 1, pMissionDatabase)
			pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")	

			pSequence.AppendAction(pScanSequence)		
			pSequence.AppendAction(pAction)
			pSequence.AppendAction(pEnableScanMenu)

			global Prendel1Scanned
			Prendel1Scanned = SCANNED

			# Set Communicate Flags
			DataComm = 1
			SaffiComm = 1
			KiskaComm = 1
			MiguelComm = 4

			pSequence.Play()
			return

		else:
#			print("Nothing detected")

			pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence()			
			pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M2PrendelScan1", "Captain", 1, pMissionDatabase)
			pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")	

			pSequence.AppendAction(pScanSequence)		
			pSequence.AppendAction(pAction)
			pSequence.AppendAction(pEnableScanMenu)

			# Set Communicate Flags
			DataComm = 1
			SaffiComm = 1
			KiskaComm = 1
			MiguelComm = 4

			pSequence.Play()
			return
	
			
	elif (iScanType == App.CharacterClass.EST_SCAN_OBJECT):

		pTarget = App.ObjectClass_Cast(pEvent.GetSource())
		if not (pTarget):
			pTarget = pPlayer.GetTarget()

		if pTarget == None:
			pSequence.Completed()
			return

		pcTargetName = pTarget.GetName()

		if (pcTargetName == "Outpost"):
			if ((g_bBaseInRange) and (not g_bBasePowered)):
#				kDebugObj.Print("Scanning the Base.. no power")

				pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence()
				pAction3 = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M2Outpost1", "Captain", 1, pMissionDatabase)
				pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")		
				pAction4 = App.TGScriptAction_Create(__name__, "BasePowersUp")

				pSequence.AppendAction(pScanSequence)		
				pSequence.AppendAction(pAction3)
				pSequence.AppendAction(pEnableScanMenu)
				pSequence.AppendAction(pAction4)			
		
				# Set Communicate Flags
				MiguelComm = 0

				pSequence.Play()
				return


			elif ((g_bBaseInRange) and (g_bBasePowered)):
#				kDebugObj.Print("Scanning the Base.. it is powered")

				pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence()
				pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M2Outpost1a", "Captain", 1, pMissionDatabase)
				pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")	

				pSequence.AppendAction(pScanSequence)		
				pSequence.AppendAction(pAction)
				pSequence.AppendAction(pEnableScanMenu)

				pSequence.Play()
				return

				# Set Communicate Flags
				MiguelComm = 0

			elif (not g_bBaseInRange):
				pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence()	
				pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M2OutpostRange1", "Captain", 1, pMissionDatabase)
				pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")	

				pSequence.AppendAction(pScanSequence)		
				pSequence.AppendAction(pAction)
				pSequence.AppendAction(pEnableScanMenu)

				pSequence.Play()
				return

		elif (pcTargetName == "USS Geronimo") and not(g_bGerScanned):
#			print("Scanning the Geronimo")
			
			global g_bGerScanned
			g_bGerScanned = 1
			ScanGeronimo()
		
			return

		else:
#			print("Nothing detected")

			pObject.CallNextHandler(pEvent)
			return


def AddNavPoint(pAction):

	# Add Nav Point
	import MissionLib
	MissionLib.AddNavPoints("Prendel3", "Strange Readings")

	return 0 

###################################################
#
# ScanGeronimo()
#
###################################################
def ScanGeronimo():
#	kDebugObj.Print("Scanning the Geronimo, finding torps")
	
	# First, find out if the user has 60 quantums already.
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
	pTorpSys = pPlayer.GetTorpedoSystem()
	iNumQuantumsLeft = 0
	if (pTorpSys):
		# Find proper torps..
		iNumTypes = pTorpSys.GetNumAmmoTypes()
		for iType in range(iNumTypes):
			pTorpType = pTorpSys.GetAmmoType(iType)
			# set iNumQuantumsLeft to equal the number of quantums the user has.
			if (pTorpType.GetAmmoName() == "Quantum"):
				iNumQuantumsLeft = pTorpSys.GetNumAvailableTorpsToType(iType)

	pSequence = App.TGSequence_Create()

	pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence()
	pSequence.AppendAction(pScanSequence)

	if (iNumQuantumsLeft != 60):
		pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M2ScanGer1", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M2ScanGer2", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pBrex, App.CharacterAction.AT_SAY_LINE, "E5M2ScanGer3", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction	= App.TGScriptAction_Create("MissionLib", "LoadTorpedoes", "Quantum", 30)
		pSequence.AppendAction(pAction)

	else:
#		print("Don't need Torps")
		pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M2ScanGer1", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)

	pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
	pSequence.AppendAction(pEnableScanMenu)

	pSequence.Play()

###################################################
#
# AwayTeamLeaves()
#
###################################################
def AwayTeamLeaves(pAction):
#	kDebugObj.Print("Trigger away team dialogue")

	pBaseSet = App.g_kSetManager.GetSet("BaseSet")
	pData2 = App.CharacterClass_GetObject (pBaseSet, "Data")
	pData2.SetHidden(0)
	
	pSequence = App.TGSequence_Create()
	
	App.TGActionManager_RegisterAction(pSequence, "TeamLeaves")

	pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E5M2Outpost2", None, 0, pMissionDatabase)
	pAction1 = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M2Outpost3", "Captain", 1, pMissionDatabase)
	pAction2 = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E5M2Outpost4", None, 0, pMissionDatabase)
	pAction3 = App.CharacterAction_Create(pBrex, App.CharacterAction.AT_MOVE, "E2")
	pAction4 = App.CharacterAction_Create(pData, App.CharacterAction.AT_MOVE, "L1")
	pTrans1 = App.CharacterAction_Create(pBrex, App.CharacterAction.AT_SAY_LINE, "E5M2Transport1", None, 1, pMissionDatabase)
	pShieldCheck = App.TGScriptAction_Create(__name__, "ShieldCheck")
	pTrans2 = App.CharacterAction_Create(pBrex, App.CharacterAction.AT_SAY_LINE, "E5M2Transport2", None, 1, pMissionDatabase)
	pGone	 = App.TGScriptAction_Create(__name__, "AwayTeamGone")
	pMessage = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E5M2Incoming", None, 0, pMissionDatabase)
	pAction6 = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "BaseSet", "Data")
	pAction7 = App.CharacterAction_Create(pData2, App.CharacterAction.AT_SAY_LINE, "E5M2DataReport1", None, 0, pMissionDatabase)
	pAction8 = App.CharacterAction_Create(pData2, App.CharacterAction.AT_SAY_LINE, "E5M2DataReport2", None, 0, pMissionDatabase)
	pRepairO = App.TGScriptAction_Create("Actions.ShipScriptActions", "RepairShipFully", pOutpost.GetObjID())
	pAction9 = App.CharacterAction_Create(pData2, App.CharacterAction.AT_SAY_LINE, "E5M2DataReport4", None, 0, pMissionDatabase)
	pAction10 = App.CharacterAction_Create(pData2, App.CharacterAction.AT_SAY_LINE, "E5M2DataReport5", None, 0, pMissionDatabase)
	pAction11 = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pRedAlert = App.TGScriptAction_Create(__name__, "OutpostRed")
	pAction12 = App.TGScriptAction_Create(__name__, "FirstGroup")
	pAction13 = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M2Attack1", "Captain", 1, pMissionDatabase)
	pAction14 = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M2Attack3", None, 1, pMissionDatabase)
	pAction15 = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "BaseSet", "Data")
	pAction16 = App.CharacterAction_Create(pData2, App.CharacterAction.AT_SAY_LINE, "E5M2Attack4", None, 0, pMissionDatabase)
	pAction17 = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M2Attack5", None, 0, pMissionDatabase)
	pAction18 = App.CharacterAction_Create(pData2, App.CharacterAction.AT_SAY_LINE, "E5M2Attack6", None, 0, pMissionDatabase)
	pAction19 = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pAction20 = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M2Attack7", "Captain", 1, pMissionDatabase)

	pSequence.AddAction(pAction)
	pSequence.AddAction(pAction1, pAction)
	pSequence.AddAction(pAction2, pAction1)
	pSequence.AddAction(pAction3, pAction1, 4)
	pSequence.AddAction(pAction4, pAction1, 2)
	pSequence.AddAction(pTrans1, pAction4, 10)
	pSequence.AddAction(pShieldCheck, pTrans1)
	pSequence.AddAction(pTrans2, pShieldCheck, 2)
	pSequence.AddAction(pGone, pTrans2)
	pSequence.AddAction(pMessage, pTrans2, 2)
	pSequence.AddAction(pAction6, pMessage, 2)
	pSequence.AddAction(pAction7, pAction6)
	pSequence.AddAction(pAction8, pAction7)
	pSequence.AddAction(pAction9, pAction8)
	pSequence.AddAction(pAction10, pAction9)
	pSequence.AddAction(pAction11, pAction10)
	pSequence.AddAction(pRedAlert, pAction11)
	pSequence.AddAction(pAction12, pAction11, 3)
	pSequence.AddAction(pAction13, pAction12, 1)
	pSequence.AddAction(pAction14, pAction13)
	pSequence.AddAction(pAction15, pAction14, 5)
	pSequence.AddAction(pAction16, pAction15)
	pSequence.AddAction(pAction17, pAction16)
	pSequence.AddAction(pAction18, pAction17)
	pSequence.AddAction(pAction19, pAction18)
	pSequence.AddAction(pAction20, pAction19)
	MissionLib.QueueActionToPlay(pSequence)


	return 0

###################################################
#
# FirstGroup()  - Creates the First Group of attacking Cardies
#
###################################################
def FirstGroup(pAction):
#	kDebugObj.Print("Creating first group of Cardies")

	pSet = App.g_kSetManager.GetSet("Prendel3")
	pGalor1 = loadspacehelper.CreateShip( "Galor", pSet, "Galor1", "Galor Start" )
	pGalor2 = loadspacehelper.CreateShip( "Galor", pSet, "Galor2", "Galor2 Start" )
	pGalor3 = loadspacehelper.CreateShip( "Galor", pSet, "Galor3", "Galor3 Start" )

	import Galor1AI
	import Galor2AI
	import Galor3AI

	pGalor1.SetAI(Galor1AI.CreateAI(pGalor1))
	pGalor2.SetAI(Galor2AI.CreateAI(pGalor2))
	pGalor3.SetAI(Galor3AI.CreateAI(pGalor3))

	MissionLib.AddGoal("E5ProtectAwayTeamGoal")

	# Set Saffi's Communicate Flag
	global SaffiComm, FelixComm
	SaffiComm = 3
	FelixComm = 2

	return 0


###################################################
#
# AwayTeamReturn()  - Brings back Data from the other set
#
###################################################
def AwayTeamReturn():
#	kDebugObj.Print("Away team return")

	MissionLib.RemoveGoal("E5ProtectAwayTeamGoal")
	MissionLib.RemoveGoal("E5ScanOutpostGoal")

	pBaseSet = App.g_kSetManager.GetSet("BaseSet")
	pData2 = App.CharacterClass_GetObject (pBaseSet, "Data")

	global g_idSequence

	pSequence = App.TGSequence_Create()

	App.TGActionManager_RegisterAction(pSequence, "TeamReturns")

	pAnimOff = App.CharacterAction_Create(pData, App.CharacterAction.AT_DISABLE_RANDOM_ANIMATIONS)
	pMessage = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E5M2Incoming", None, 0, pMissionDatabase)
	pAction1 = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "BaseSet", "Data")
	pAction2 = App.CharacterAction_Create(pData2, App.CharacterAction.AT_SAY_LINE, "E5M2Success1", None, 0, pMissionDatabase)
	pAction3 = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M2Success2", None, 0, pMissionDatabase)
	pAction4 = App.CharacterAction_Create(pData2, App.CharacterAction.AT_SAY_LINE, "E5M2Success3", None, 0, pMissionDatabase)
	pAction5 = App.CharacterAction_Create(pData2, App.CharacterAction.AT_SAY_LINE, "E5M2Success4b", None, 0, pMissionDatabase)
	pAction5c = App.CharacterAction_Create(pData2, App.CharacterAction.AT_SAY_LINE, "E5M2Success4c", None, 0, pMissionDatabase)
	pAction5d = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M2Success4d", None, 0, pMissionDatabase)
	pAction5e = App.CharacterAction_Create(pData2, App.CharacterAction.AT_SAY_LINE, "E5M2Success4e", None, 0, pMissionDatabase)
	pAction6 = App.CharacterAction_Create(pData2, App.CharacterAction.AT_SAY_LINE, "E5M2Success5", None, 0, pMissionDatabase)
	pGreen   = App.TGScriptAction_Create(__name__, "OutpostGreen")
	pAction7 = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pShieldCheck = App.TGScriptAction_Create(__name__, "ShieldCheck")
	pAction8 = App.CharacterAction_Create(pBrex, App.CharacterAction.AT_SAY_LINE, "E5M2Success8", None, 0, pMissionDatabase)
	pAction9 = App.CharacterAction_Create(pBrex, App.CharacterAction.AT_MOVE, "E")
	pBack	 = App.TGScriptAction_Create(__name__, "AwayTeamBack")
	pAction10 = App.CharacterAction_Create(pData, App.CharacterAction.AT_MOVE, "X2")
	pAction11 = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E5M2Success9", "Captain", 1, pMissionDatabase)
	pAction12 = App.CharacterAction_Create(pData, App.CharacterAction.AT_MOVE, "X")
	pAction13 = App.TGScriptAction_Create(__name__, "OutpostCheck")
	pAnimOn = App.CharacterAction_Create(pData, App.CharacterAction.AT_ENABLE_RANDOM_ANIMATIONS)

	pSequence.AddAction(pMessage)
	pSequence.AddAction(pAnimOff)
	pSequence.AddAction(pAction1, pMessage, 1)
	pSequence.AddAction(pAction2, pAction1, 2)
	pSequence.AddAction(pAction3, pAction2)
	pSequence.AddAction(pAction4, pAction3)
	pSequence.AddAction(pAction5, pAction4)
	pSequence.AddAction(pAction5c, pAction5)
	pSequence.AddAction(pAction5d, pAction5c)
	pSequence.AddAction(pAction5e, pAction5d)
	pSequence.AddAction(pAction6, pAction5e)
	pSequence.AddAction(pAction7, pAction6)
	pSequence.AddAction(pGreen, pAction6)
	pSequence.AddAction(pShieldCheck, pAction7, 5)
	pSequence.AddAction(pAction8, pShieldCheck)
	pSequence.AddAction(pBack, pShieldCheck)
	pSequence.AddAction(pAction9, pAction8)
	pSequence.AddAction(pAction10, pAction8, 6)
	pSequence.AddAction(pAction11, pAction10)
	pSequence.AddAction(pAction12, pAction11)
	pSequence.AddAction(pAction13, pAction11)
	pSequence.AddAction(pAnimOn, pAction12)

	MissionLib.QueueActionToPlay(pSequence)

	return 0


def OutpostCheck(pAction):

	global MissionState
	MissionState = BACK

	if (g_bBaseAlive):
		pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M2Destroy Outpost", "Captain", 1, pMissionDatabase)
		MissionLib.AddGoal("E5DestroyOutpostGoal")
		
	else:
		pAction = App.TGScriptAction_Create(__name__, "MissionWin")
	
	pAction.Play()
		
	return 0 


def AwayTeamGone(pAction):
	global AwayTeam
	AwayTeam = AWAY
	return 0

def AwayTeamBack(pAction):
	global AwayTeam
	AwayTeam = BACK
	return 0

###################################################
#
# ShieldCheck() 
#
###################################################
def ShieldCheck(pAction):
	
	pPlayer = MissionLib.GetPlayer()
	pShields = pPlayer.GetShields()

	if pShields.IsOn():
		pSequence = App.TGSequence_Create()
		
		pAction = App.CharacterAction_Create(pBrex, App.CharacterAction.AT_SAY_LINE, "LoweringShields", None, 0, pGeneralDatabase)
		pSequence.AppendAction(pAction)

		pAction = App.TGScriptAction_Create("Actions.ShipScriptActions", "FlickerShields")
		pSequence.AppendAction(pAction)

		pSequence.Play()

	return 0

##########################################################################
#
# MissionWin()  - Function that handles the win conditions of the mission 
#
##########################################################################
def MissionWin(pAction):
#	kDebugObj.Print("Mission Successful")

	pLBridgeSet = App.g_kSetManager.GetSet("LBridgeSet")
	pLiu = App.CharacterClass_GetObject (pLBridgeSet, "Liu")
	pLiu.SetHidden(0)

	global MissionState
	MissionState = WIN

	import Maelstrom.Episode5.Episode5

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "CallWaiting", 1)
	pSequence.AddAction(pAction)
	pAction =  App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "HailStarfleet2", None, 0, pGeneralDatabase)
	pSequence.AppendAction(pAction)
	pAction =  App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "HailStarfleet8", None, 0, pGeneralDatabase)
	pSequence.AppendAction(pAction, 3)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LBridgeSet", "Liu")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E5M2Debrief1", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E5M2Debrief2", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E5M2Debrief3", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E5M2Debrief4", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "CallWaiting", 0)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "AddGoalAction", "E5HeadHomeGoal")
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)


	import Systems.Starbase12.Starbase
	pSBMenu = Systems.Starbase12.Starbase.CreateMenus()
	pSBMenu.SetMissionName("Maelstrom.Episode5.E5M4.E5M4")

	pMiguel.GetMenu().RemoveHandlerForInstance(App.ET_SCAN, __name__+".ScanHandler")

	RemoveHooks()

	return 0

############################################################################
#
# MissionLoss()  - Function that handles the Loss conditions of the mission 
#
############################################################################
def MissionLoss():
#	kDebugObj.Print("*************** Mission Failed ***************")

	MissionLib.DeleteQueuedActions()

	pSequence = App.TGSequence_Create()
	
	pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_LOOK_AT_ME)

	if (AwayTeam == AWAY):
		pAction1 = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M2Lose2", "Captain", 0, pMissionDatabase)	
	
	else:
		pAction1 = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M2Lose1", "Captain", 0, pMissionDatabase)	

	pAction2 = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M2Lose3", "Captain", 0, pMissionDatabase)
	
	pSequence.AddAction(pAction, None, 5)	
	pSequence.AddAction(pAction1, pAction)
	pSequence.AddAction(pAction2, pAction1)
		
	MissionLib.GameOver(None, pSequence)


###################################################
#
# RemoveHooks()
#
###################################################
def RemoveHooks():

	import Systems.Prendel.Prendel
	pPrendelMenu = Systems.Prendel.Prendel.CreateMenus()

################################################################################
##	StartProdTimer()
##
##	Starts a timer to prod the player, called as a TGScriptAction
##
##	Args:	pTGAction	- Script action object
##			iTime 		- The length of time in seconds that the timer will run for.
##
##	Return:	0	- Return 0 so sequence that calls won't choke
################################################################################
def StartProdTimer(pTGAction, iTime):
#	kDebugObj.Print("Creating prod timer for " + str(iTime) + " seconds.")

	# Stop the old prod timer.
	StopProdTimer()

	# Start a new prod timer.
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	pTimer = MissionLib.CreateTimer(ET_PROD_TIMER, __name__+".ProdPlayer", fStartTime + iTime, 0, 0)

	# Save the ID of the prod timer, so we can stop it later.
	global iProdTimer
	iProdTimer = pTimer.GetObjID()
#	kDebugObj.Print("New prod timer ID is " + str(iProdTimer))

	return 0

################################################################################
##	StopProdTimer()
##
##	Removes old timer if goal is reached.
##
##	Args:	None
##
##	Return:	None
################################################################################
def StopProdTimer():
#	kDebugObj.Print("Trying to stop the HurryUp timer...")
	global iProdTimer
	if (iProdTimer != App.NULL_ID):
#		kDebugObj.Print("Timer exists with ID " + str(iProdTimer) + ".  Removing it.")
		bSuccess = App.g_kTimerManager.DeleteTimer(iProdTimer)
#		if bSuccess:
#			kDebugObj.Print("Successfully removed.")
#		else:
#			kDebugObj.Print("Failed to remove timer.  Prod warning may trigger inappropriately.  :(")
		iProdTimer = App.NULL_ID

################################################################################
##	ProdPlayer()
##
##	Figure out what kind of prodding the player need and call the correct
##	function.
##
##	Args:	pTGObject	- The TGObject object
##			pEvent		- The event that was sent to the object
##
##	Return:	None
##
################################################################################
def ProdPlayer(pTGObject, pEvent):

	pGame = App.Game_GetCurrentGame()
	pPlayer = App.ShipClass_Cast(pGame.GetPlayer())
	pSet = pPlayer.GetContainingSet()
	sSetName = pSet.GetName()

	# If the Player hasn't scanned the area at all
	if ((sSetName == "Prendel5" and not (Prendel5Scanned)) or (sSetName == "Prendel4" and not (Prendel4Scanned))
		or (sSetName == "Prendel2" and not (Prendel2Scanned)) or (sSetName == "Prendel1" and not (Prendel1Scanned))):
#		print("Prompting player to scan")
		pAction1 = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M2MiguelProd1", "Captain", 1, pMissionDatabase)
		pAction = App.TGScriptAction_Create(__name__, "StartProdTimer", 30)
		pAction1.Play()
		pAction.Play()
		return


	# If the player hasn't Listened to McCray's Logs
	elif (sSetName == "Starbase12") and (not g_bLogsPlayed):
#		print("Prompting the player to talk to Data")
		pAction1 = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M2SaffiProd4", "Captain", 1, pMissionDatabase)
		pAction2 = App.TGScriptAction_Create(__name__, "StartProdTimer", 30)
		pAction1.Play()
		pAction2.Play()
		return

	# if the player IS at Prendel 3, but hasn't scanned yet
	elif (pSet.GetName() == "Prendel3") and (not Prendel3Scanned):
#		print("Prompt the player to scan now that we're at Prendel3")
		pAction1 = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M2MiguelProd2", "Captain", 1, pMissionDatabase)
		pAction = App.TGScriptAction_Create(__name__, "StartProdTimer", 30)
		pAction1.Play()
		pAction.Play()
		return

###################################################
#
#	AddDataButtons() - Adds buttons in Data's menu
#
###################################################
def AddDataButtons(pAction):
	
	pDataMenu = pData.GetMenu()

	pData.AddPythonFuncHandlerForInstance(ET_SUMMARIZE, __name__ + ".DataSummarize")
	pData.AddPythonFuncHandlerForInstance(ET_PLAY_LOG, __name__ + ".DataPlayLog")	
	pDataMenu.AddChild(CreateBridgeMenuButton(pMissionDatabase.GetString("Summarize"), ET_SUMMARIZE, 0, pData))
	pDataMenu.AddChild(CreateBridgeMenuButton(pMissionDatabase.GetString("PlayLog"), ET_PLAY_LOG, 0, pData))

	return 0

###################################################
#
#	RemoveDataButtons() - Removes buttons in Data's menu
#
###################################################
def RemoveDataButtons(pAction):

	pDataMenu = pData.GetMenu()
	pDataMenu.RemoveItemW(pMissionDatabase.GetString("Summarize"))
	pDataMenu.RemoveItemW(pMissionDatabase.GetString("PlayLog"))

	return 0

###################################################
#
# AddPrendelLocation
#
###################################################
def AddPrendelLocation(pAction):

	import Systems.Prendel.Prendel
	pPrendelMenu = Systems.Prendel.Prendel.CreateMenus()
	pPrendelMenu.SetMissionName("Maelstrom.Episode5.E5M2.E5M2")

	return 0


###############################################################################
#	CreateBridgeMenuButton()
#
#	Helper function for creating menu buttons
#
#	Args:	pName		- button name string
#			eType		- Event type sent on button press
#			iSubType	- Event subtype
#			pCharacter	- Character to send event to
#
#	Return:	none
###############################################################################
def CreateBridgeMenuButton(pName, eType, iSubType, pCharacter):
	pEvent = App.TGIntEvent_Create()
	pEvent.SetEventType(eType)
	pEvent.SetDestination(pCharacter)
	pEvent.SetInt(iSubType)
	BridgeMenuButton = App.STButton_CreateW(pName, pEvent)
	return BridgeMenuButton


###################################################
#
# Terminate()
#
# Unload our mission database
#
###################################################
def Terminate(pMission):
#	kDebugObj.Print ("Terminating Episode 5, Mission 2.\n")

	MissionLib.ShutdownFriendlyFire()
	MissionLib.DeleteAllGoals()

	###################################
	# Remove Character Event Handlers #
	###################################
	pSaffi.GetMenu().RemoveHandlerForInstance(App.ET_CONTACT_STARFLEET, __name__+".HailStarfleet")
	pSaffi.GetMenu().RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	pMiguel.GetMenu().RemoveHandlerForInstance(App.ET_SCAN, __name__+".ScanHandler")
	pMiguel.GetMenu().RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	pFelix.GetMenu().RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	pKiska.GetMenu().RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	pBrex.GetMenu().RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	pMenu = pData.GetMenu()
	pMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	if(pGeneralDatabase):
		App.g_kLocalizationManager.Unload(pGeneralDatabase)
	if(pDatabase):
		App.g_kLocalizationManager.Unload(pDatabase)

	pMenu = pKiska.GetMenu()
	pSetCourse = pMenu.GetSubmenuW(pDatabase.GetString("Set Course"))
	pPrendel = pSetCourse.GetSubmenu("Prendel")
	pSetCourse.DeleteChild(pPrendel)

	import Bridge.BridgeUtils
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	pWarpButton.RemoveHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpCheck")

	StopProdTimer()

	# Clear globals that may no longer be valid, in case
	# save & load tries to save us.
	global pSaffi, pMiguel, pFelix, pKiska, pBrex, pData
	pSaffi = None
	pKiska = None
	pFelix = None
	pBrex = None
	pMiguel = None
	pData = None
