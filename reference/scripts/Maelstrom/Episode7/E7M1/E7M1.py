###############################################################################
#	Filename:	E7M1.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Episode, Mission 1 script
#	
#	Created:	09/14/00 -	DLitwin (added header)
#	Updated:	01/16/02 - 	TEvans
###############################################################################

import App
import loadspacehelper
import MissionLib
import Maelstrom.Maelstrom
import LoadBridge
import Effects
import Bridge.Characters.Saalek
import Bridge.BridgeMenus
import Bridge.BridgeUtils
import Bridge.ScienceCharacterHandlers
import Bridge.XOCharacterHandlers
import Systems.Starbase12.Starbase
import Systems.Starbase12.Starbase12
import Systems.Starbase12.Starbase12_S
import Systems.Albirea.Albirea
import E7M1_P
import EBridge_P
import E7M1StarbaseAI
import KeldonAI
import Keldon2AI
import Kessok1AI
import Kessok2AI
import RamStarbaseAI
import RamStarbaseSlowAI
import FriendlyAI
import WarpAI
import WarpSB12AI

#
# Event types
#
ET_CREATE_ENTERPRISE	= App.Mission_GetNextEventType()
ET_ONE_MINUTE			= App.Mission_GetNextEventType()
ET_CREATE_GERONIMO		= App.Mission_GetNextEventType()
ET_LOOK_AHEAD			= App.Mission_GetNextEventType()
ET_FIRST_WAVE			= App.Mission_GetNextEventType()
ET_SECOND_WAVE			= App.Mission_GetNextEventType()
ET_THIRD_WAVE			= App.Mission_GetNextEventType()
ET_KESSOK_INFO			= App.Mission_GetNextEventType()
ET_SAALEK_PROD			= App.Mission_GetNextEventType()
ET_STARBASE_COLLISION	= App.Mission_GetNextEventType()
ET_FREIGHTERS_GONE		= App.Mission_GetNextEventType()

# Set up global variables
bDebugPrint			= 0

g_pKiska			= None
g_pFelix			= None
g_pSaffi			= None
g_pMiguel			= None
g_pBrex				= None

g_pSaffiMenu		= None
g_pFelixMenu		= None
g_pKiskaMenu		= None
g_pMiguelMenu		= None
g_pBrexMenu			= None

TRUE			= 1
FALSE			= 0

HASNT_ARRIVED	= 0
HAS_ARRIVED		= 1
MISS_WIN		= 1
MISS_LOST		= 2
MISS_INCOMPLETE	= 3
MISS_WIN_NOT	= 4

pMissionDatabase	= None
pGeneralDatabase	= None
pMenuDatabase		= None
pEpisodeDatabase	= None

idInterruptSequence	= App.NULL_ID

bMissionTerminate	= FALSE
bFirstCollision		= FALSE
bBrexShields		= FALSE
bCardGroup1			= HASNT_ARRIVED
bCardGroup2			= HASNT_ARRIVED
bKessokGroup		= HASNT_ARRIVED
bPicardAlive		= TRUE
bStarbaseAlive		= TRUE
bAreaScanned 		= FALSE
bStarbaseCollision	= FALSE
bStarbaseCritical	= FALSE
bEnterpriseCritical	= FALSE
bGeronimoCritical	= FALSE
bGeronimoArrive 	= FALSE
bEnterpriseArrive 	= FALSE
bAttackRepelled		= FALSE

bKessoksScanned		= FALSE
bFreightersScanned 	= FALSE

bDocking			= FALSE

iShipsDefeated		= 0
iMissionState		= 0
iDamageStage		= 0
iFreightersLeft		= 0
iSaalekProdCount	= 0
iSaalekChat			= 0

fStartTime			= 0

bAllowDamageDialogue = 0		#Allows the damage dialogue to be spoken and not overlap

kCargoHold1			= []
kCargoHold2			= []
kCargoHold3			= []
kCargoHold4			= []
kCargoHold5			= []
kCargoHold6			= []

g_bGraffWarned 		= FALSE
g_bMacCrayWarned 	= FALSE
g_bPicardWarned 	= FALSE


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
	loadspacehelper.PreloadShip("FedStarbase", 1)
	loadspacehelper.PreloadShip("Enterprise", 1)
	loadspacehelper.PreloadShip("Geronimo", 1)
	loadspacehelper.PreloadShip("BombFreighter", 6)
	loadspacehelper.PreloadShip("KessokLight", 3)
	loadspacehelper.PreloadShip("Keldon", 6)


###############################################################################
#	Initialize()
#
#	Called to initialize our mission
#
#	Args:	pMission	- the Mission object
#
#	Return:	none
###############################################################################
def Initialize(pMission):
#	DebugPrint("Initializing Episode 7, Mission 1.\n")

	# Specify (and load if necessary) our bridge
	LoadBridge.Load("SovereignBridge")

	# Initialize global pointers to the bridge crew
	InitializeCrewPointers()

	# Set bMissionTerminate here so it sets value correctly
	# if mission is reloaded
	global bMissionTerminate
	bMissionTerminate = FALSE

	# If mission is lost or won
	global iMissionState

	global pMissionDatabase, pGeneralDatabase, pMenuDatabase, pEpisodeDatabase
	pMissionDatabase = pMission.SetDatabase("data/TGL/Maelstrom/Episode 7/E7M1.tgl")
	pGeneralDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")
	pMenuDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pEpisodeDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 7/Episode7.tgl")

	# Create the Starbase 12 region/set.
	Systems.Starbase12.Starbase12.Initialize()
	pSet = Systems.Starbase12.Starbase12.GetSet()

	# Load our placements for Starbase 12
	E7M1_P.LoadPlacements(pSet.GetName())
	
	# Load custom placements for bridge.
	pBridgeSet = App.g_kSetManager.GetSet("bridge")
	EBridge_P.LoadPlacements(pBridgeSet.GetName())

	# Create characters and their sets
#	DebugPrint("Creating characters and their sets")

	MissionLib.SetupBridgeSet("LiuSet", "data/Models/Sets/StarbaseControl/starbasecontrolRM.nif", -40, 65, -1.55)
	MissionLib.SetupCharacter("Bridge.Characters.Admiral_Liu", "LiuSet", 0, 0, 5)
	
	MissionLib.SetupBridgeSet("FedOutpostSet", "data/Models/Sets/FedOutpost/fedoutpost.nif", -30, 65, -1.55)
	MissionLib.SetupCharacter("Bridge.Characters.Graff", "FedOutpostSet")

	MissionLib.SetupBridgeSet("EBridgeSet", "data/Models/Sets/EBridge/EBridge.nif", -40, 65, -1.55)
	MissionLib.SetupCharacter("Bridge.Characters.MacCray", "EBridgeSet")
	pPicard = MissionLib.SetupCharacter("Bridge.Characters.Picard", "EBridgeSet")
	pPicard.SetLocation("SovereignSeated")

	# Create the ships and set their stats
#	DebugPrint("Creating ships.\n")

	# Create the ships that will appear at mission start
	pPlayer = MissionLib.CreatePlayerShip("Sovereign", pSet, "player", "Player Start")
	pStarbase = loadspacehelper.CreateShip( "FedStarbase", pSet, "Starbase 12", "Starbase Location" )

	# Start the friendly fire watches
	MissionLib.SetupFriendlyFire()

	######################
	# Setup Affiliations #
	######################
	global pFriendlies
	global pEnemies
	
	pFriendlies = pMission.GetFriendlyGroup()
	pFriendlies.AddName("player")
	pFriendlies.AddName("Starbase 12")
	pFriendlies.AddName("USS Geronimo")
	pFriendlies.AddName("USS Enterprise")

	pEnemies = pMission.GetEnemyGroup()
	pEnemies.AddName("Keldon1")
	pEnemies.AddName("Keldon2")
	pEnemies.AddName("Keldon3")
	pEnemies.AddName("Keldon4")
	pEnemies.AddName("Keldon5")
	pEnemies.AddName("Keldon6")
	pEnemies.AddName("Kessok1")
	pEnemies.AddName("Kessok2")
	pEnemies.AddName("Kessok3")
	pEnemies.AddName("Freighter1")
	pEnemies.AddName("Freighter2")
	pEnemies.AddName("Freighter3")
	pEnemies.AddName("Freighter4")
	pEnemies.AddName("Freighter5")
	pEnemies.AddName("Freighter6")

	#################
	# Setup ship AI #
	#################

	# Starbase AI #
	###############
	pStarbase.SetAI(E7M1StarbaseAI.CreateAI(pStarbase))	

	###############################
	# Setup up Warp Menu Buttons for Kiska #
	###############################	
	pSB12Menu = Systems.Starbase12.Starbase.CreateMenus()

	# Setup mission-specific events.
	SetupEventHandlers()

	MissionLib.SaveGame("E7M1-")

	MissionLib.SetTotalTorpsAtStarbase("Photon", -1)
	MissionLib.SetTotalTorpsAtStarbase("Quantum", -1)
	MissionLib.SetMaxTorpsForPlayer("Photon", 300)
	MissionLib.SetMaxTorpsForPlayer("Quantum", 60)

	# Disable Starbase Repairs
	Systems.Starbase12.Starbase12_S.StarbaseRepairsEnabled(0) 


################################################################################
#	InitializeCrewPointers()
#
#	Initializes the global pointers to the bridge crew members.
#	NOTE: This must be called after the bridge is loaded.
#
#	Args:	None
#
#	Return:	None
################################################################################
def InitializeCrewPointers():
	# Get the bridge set
	pBridge = App.g_kSetManager.GetSet("bridge")
	
	# Set the pointer for the crew
	global g_pKiska
	global g_pFelix
	global g_pSaffi
	global g_pMiguel
	global g_pBrex
	
	g_pKiska	= App.CharacterClass_GetObject(pBridge, "Helm")
	g_pFelix	= App.CharacterClass_GetObject(pBridge, "Tactical")
	g_pSaffi	= App.CharacterClass_GetObject(pBridge, "XO")
	g_pMiguel	= App.CharacterClass_GetObject(pBridge, "Science")
	g_pBrex		= App.CharacterClass_GetObject(pBridge, "Engineer")
	
	global g_pSaffiMenu
	global g_pFelixMenu
	global g_pKiskaMenu
	global g_pMiguelMenu
	global g_pBrexMenu
	
	g_pSaffiMenu = g_pSaffi.GetMenu()
	g_pFelixMenu = g_pFelix.GetMenu()
	g_pKiskaMenu = g_pKiska.GetMenu()
	g_pMiguelMenu = g_pMiguel.GetMenu()
	g_pBrexMenu = g_pBrex.GetMenu()


###############################################################################
#	SetupEventHandlers()
#
#	Setup Mission event handlers
#
#	Args:	none
#
#	Return:	none
###############################################################################
def SetupEventHandlers():
	# Setup any event handlers to listen for broadcast events that we'll need.
	pEpisode = App.Game_GetCurrentGame().GetCurrentEpisode()
	pMission = pEpisode.GetCurrentMission()
	
	# Ship entrance event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_ENTERED_SET, pMission, __name__ + ".EnterSet")
	# Ship exit event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_EXITED_SET, pMission, __name__ + ".ExitSet")
	# Ship destroyed event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_DESTROYED, pMission, __name__ + ".ObjectDestroyed")
	# Ship exploding event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_EXPLODING, pMission, __name__ + ".ObjectExploding")

	# Instance handler for friendly fire warnings
	pMission.AddPythonFuncHandlerForInstance(App.ET_FRIENDLY_FIRE_REPORT, __name__ + ".FriendlyFireReportHandler")

	# Contact Starfleet event
	g_pSaffiMenu.AddPythonFuncHandlerForInstance(App.ET_CONTACT_STARFLEET, __name__ + ".HailStarfleet")
	# Science Scan event
	g_pMiguelMenu.AddPythonFuncHandlerForInstance(App.ET_SCAN, __name__ + ".ScanHandler")
	# Instance handler for Kiska's dock button
	g_pKiskaMenu.AddPythonFuncHandlerForInstance(App.ET_DOCK, __name__+ ".DockHandler")
	# Warp event
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	if (pWarpButton != None):
		pWarpButton.AddPythonFuncHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpHandler")
	# Hail event
	g_pKiskaMenu.AddPythonFuncHandlerForInstance(App.ET_HAIL, __name__ + ".HailHandler")

#	DebugPrint("Adding Crew Communicate Handlers")
	# Communicate with Saffi event
	g_pSaffiMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	# Communicate with Felix event
	g_pFelixMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	# Communicate with Kiska event
	g_pKiskaMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	# Communicate with Miguel event
	g_pMiguelMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	# Communicate with Brex event
	g_pBrexMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")


################################################################################
#	DebugPrint(pcString)
#
#	Wrapper for print function that checks debug flag.
#
#	Args:	pcString, string to print.
#
#	Return:	None
################################################################################
def DebugPrint(pcString):
	if(bDebugPrint):
		print(pcString)


###############################################################################
#	EnterSet()
#
#	A ship has entered the set.  Check it for anything we care about.
#
#	Args:	pObject	- TGObject object
#			pEvent	- TGEvent object
#
#	Return:	none
###############################################################################
def EnterSet(pObject, pEvent):
	# An event triggered whenever an object enters a set.
	# Check if it's a ship.
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	pSet = App.g_kSetManager.GetRenderedSet()
	if not App.IsNull(pShip):
		# It's a ship.
		pSet = pShip.GetContainingSet()
#		DebugPrint("Ship \"%s\" entered set \"%s\"" % (pShip.GetName(), pSet.GetName()))
		
		if (pShip.GetName() == "player") and (pSet.GetName() == "Starbase12"):
			# Remove Goal
#			DebugPrint("GoToStarbase12 Goal complete!\n")
			MissionLib.DeleteGoal("E7GoToStarbase12Goal")

			PlayerArrive()

	# We're done.  Let any other handlers for this event handle it.
	pObject.CallNextHandler(pEvent)


###############################################################################
#	ExitSet()
#
#	A ship has exited the set.  Check it for anything we care about.
#
#	Args:	pObject	- TGObject object
#			pEvent	- TGEvent object
#
#	Return:	none
###############################################################################
def ExitSet(TGObject, pEvent):
	# Triggered whenever an object leaves a set.
	# Check and see if mission is terminating, if so return
	if (bMissionTerminate == TRUE):
		return

	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	sSetName = pEvent.GetCString()

	if (pShip):
		sShipName = pShip.GetName()
		# It's a ship.
#		DebugPrint("Ship \"%s\" exited set \"%s\"" % (sShipName, sSetName))
		
		if (sSetName == "Starbase12"):		
			if (pEnemies.IsNameInGroup(sShipName)):

				global iShipsDefeated
				iShipsDefeated = iShipsDefeated + 1

				if iShipsDefeated == 9:
					iShipsDefeated = 10

				# If the ship is a Kessok, make all enemies flee
				if (sShipName[:len("Kessok")] == "Kessok") and not bAttackRepelled:
					global bAttackRepelled
					bAttackRepelled = TRUE

					pSet = App.g_kSetManager.GetSet("Starbase12")

					# Index through ALL objects in the set, and sets Enemies to flee
					pObject = pSet.GetFirstObject()
					pFirstObject = pObject
					while not (App.IsNull(pObject)):
						if pEnemies.IsNameInGroup(pObject.GetName()):
							pEnemy = App.ShipClass_Cast(pObject)
							if not pEnemy == None:
#								DebugPrint(pEnemy.GetName() + " is fleeing!")
								# Set delay 5 to 14 seconds
								fNum = App.g_kSystemWrapper.GetRandomNumber(10)
								fNum = fNum + 5
								# Set AI
								pEnemy.SetAI(WarpAI.CreateAI(pEnemy, fNum))
		
						pObject = pSet.GetNextObject(pObject.GetObjID())
		
						if (pObject.GetObjID() == pFirstObject.GetObjID()):
#							DebugPrint("Exiting loop.")
							pObject = None

					# Remove Goals
#					DebugPrint("Starbase12Survive, EnterpriseSurvive and RepelCardassians Goals complete!\n")
					MissionLib.RemoveGoal("E7Starbase12SurviveGoal", "E7RepelCardassiansGoal", "E7EnterpriseSurviveGoal")

					if bPicardAlive and bStarbaseAlive:
						global iMissionState
						iMissionState = MISS_WIN_NOT
		
					AttackRepelled()

	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)


#
# The handler for object exploding event.
#
def ObjectExploding(TGObject, pEvent):
	pShip	= App.ShipClass_Cast(pEvent.GetDestination())
	if (pShip == None):
		return

	sShipName = pShip.GetName()

	if (pShip.GetName() == "Starbase 12"):
		global iMissionState, bStarbaseAlive

		iMissionState = MISS_LOST
		bStarbaseAlive = FALSE

		# Abort Sequence, if any is going on
		global idInterruptSequence
		pInterruptSequence = App.TGSequence_Cast(App.TGObject_GetTGObjectPtr(idInterruptSequence))
		if (pInterruptSequence):
			pInterruptSequence.Completed()
			idInterruptSequence = App.NULL_ID
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
			pAction.Play()

		# Starbase 12 is destroyed.  Failed mission.
#		DebugPrint("Starbase 12 destroyed! Mission failed.")

		if bPicardAlive:
			pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet") 
			pPicard = App.CharacterClass_GetObject(pEBridgeSet, "Picard")

			pSet = App.g_kSetManager.GetSet("Starbase12")
			pEnterprise = App.ShipClass_GetObject(pSet, "USS Enterprise")

			pSequence = App.TGSequence_Create()

			pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
			pSequence.AppendAction(pAction)

			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_LOOK_AT_ME)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1StarbaseDestroyed", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)

			if not pEnterprise:
#				DebugPrint("Picard warps to Starbase")
				# Create the Enterprise
				pEnterprise = loadspacehelper.CreateShip( "Enterprise", pSet, "USS Enterprise", "Nebula Way1", 1 )
				pEnterprise.ReplaceTexture("Data/Models/Ships/Sovereign/Enterprise.tga", "ID")
				
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1Freighters13b", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_LOOK_AT_ME)
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M1Freighters14b", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)

			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M1PicardHail1", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "Picard")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E7M1FailedLostStarbase1", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E7M1FailedLostStarbase2", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
			pSequence.AppendAction(pAction)

			MissionLib.GameOver(None, pSequence)

		else:
			# Both the Enterprise and Starbase are dead
			MissionLib.GameOver(None)

	elif ((sShipName == "Freighter1") or (sShipName == "Freighter2") or (sShipName == "Freighter3") or (sShipName == "Freighter4") or (sShipName == "Freighter5") or (sShipName == "Freighter6")):

		pSet = App.g_kSetManager.GetSet("Starbase12")
		pShip = App.ShipClass_GetObject(pSet, sShipName)

		if not (pShip == None):
			global iFreightersLeft
			iFreightersLeft = iFreightersLeft - 1
	
#			DebugPrint(str(iFreightersLeft) + " Freighters left.")
	
			if (iFreightersLeft == 0):
#				DebugPrint("The Freighters are all gone")
	
				# Wait and see if Starbase got destroyed by the last freighter
				fStartTime = App.g_kUtopiaModule.GetGameTime()
				MissionLib.CreateTimer(ET_FREIGHTERS_GONE, __name__ + ".FreightersAllGone", fStartTime + 12, 0, 0)

		return

	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)


#
# FreightersAllGone()
#
def FreightersAllGone(pObject, pEvent):
	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create(__name__, "DisableContactStarfleet")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M1Freighters12", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)

	if bStarbaseAlive == TRUE:
#		DebugPrint("Mission Win")

		# Remove Goals
#		DebugPrint("Starbase12Survive2 and RepelCardassians2 Goals complete!\n")
		MissionLib.RemoveGoal("E7RepelCardassians2Goal", "E7Starbase12Survive2Goal")

		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1Freighters13", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M1Freighters14", "S", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M1Freighters15", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "SaalekBriefing")
		pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)


###############################################################################
#	ObjectDestroyed()
#
#	A ship has been destroyed.  Check it for anything we care about.
#
#	Args:	pObject	- TGObject object
#			pEvent	- TGEvent object
#
#	Return:	none
###############################################################################
def ObjectDestroyed(pObject, pEvent):

	pShip = App.ShipClass_Cast(pEvent.GetDestination())

	if (pShip):
		sShipName = pShip.GetName()
		# It's a ship.
#		DebugPrint("Ship \"%s\" was destroyed" % sShipName)

		if (sShipName == "USS Enterprise"):
			global iMissionState, bPicardAlive

			iMissionState = MISS_LOST
			bPicardAlive = FALSE
			g_pMiguel.SayLine(pMissionDatabase, "E7M1EnterpriseDestroyed", "Captain", 1)
			MissionLib.DeleteGoal("E7EnterpriseSurviveGoal")
			# Enterprise is destroyed.  Failed mission.
#			DebugPrint("Enterprise destroyed! Mission failed.")

		elif (sShipName == "USS Geronimo"):
			# Geronimo is destroyed, so E7M4 will not happen
			Maelstrom.Maelstrom.bGeronimoAlive = FALSE
			g_pMiguel.SayLine(pMissionDatabase, "E7M1GeronimoDestroyed", "Captain", 1)
#			DebugPrint("Geronimo destroyed!")

	# We're done.  Let any other handlers for this event handle it.
	pObject.CallNextHandler(pEvent)


#
# AddPhasedTorpedoes() - Set up sequence to add phased torpedoes next time you dock with Starbase 12
#
def AddPhasedTorpedoes():
#	DebugPrint("Set up sequence to add phased torpedoes next time you dock with Starbase 12")

	pFedOutpostSet = App.g_kSetManager.GetSet("FedOutpostSet")
	pGraff = App.CharacterClass_GetObject(pFedOutpostSet, "Graff")

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create(__name__, "ToggleDockingFlag")
	pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create(__name__, "FixTorpMax", "Phased", 20)
	pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create("MissionLib", "LoadTorpedoes", "Phased", 20)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_CreateByName("FedOutpostSet_Graff", "Graff", App.CharacterAction.AT_SAY_LINE, "E7M1NewTorps01", None, 0, pEpisodeDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_CreateByName("FedOutpostSet_Graff", "Graff", App.CharacterAction.AT_SAY_LINE, "E7M1NewTorps02", None, 0, pEpisodeDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_CreateByName("FedOutpostSet_Graff", "Graff", App.CharacterAction.AT_SAY_LINE, "E7M1NewTorps03", None, 0, pEpisodeDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_CreateByName("FedOutpostSet_Graff", "Graff", App.CharacterAction.AT_SAY_LINE, "E7M1NewTorps04", None, 0, pEpisodeDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)
	pAction	= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "bridge")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Miguel Head", "Miguel Cam1", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1NewTorps05", "Captain", 1, pEpisodeDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Brex Head", "Brex Cam1", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M1NewTorps06", "S", 0, pEpisodeDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "SaffiWatchLMed", "SaffiCamLMed", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M1NewTorps07", "E", 0, pEpisodeDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M1NewTorps08", "C", 0, pEpisodeDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M1NewTorps09", "E", 0, pEpisodeDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Brex Head", "Brex Cam1", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M1NewTorps10", "C", 1, pEpisodeDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "LookForward")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "bridge")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "ToggleDockingFlag")
	pSequence.AppendAction(pAction)

	Systems.Starbase12.Starbase12_S.SetGraffDockingAction(pSequence)

###############################################################################
#	FixTorpMax(pAction, sType, iMax)
#	
#	Fixes the torpedo max for phased plasma torpedoes for the player.
#	
#	Args:	pAction	- the action
#			sType	- the type name
#			iMax	- the new maximum for this torpedo type
#	
#	Return:	zero for end
###############################################################################
def FixTorpMax(pAction, sType, iMax):
	pPlayer = App.Game_GetCurrentPlayer()
	if not pPlayer:
		return 0

	pTorps = pPlayer.GetTorpedoSystem()
	if not pTorps:
		return 0

	pProp = pTorps.GetProperty()
	if not pProp:
		return 0

	# Find proper torps..
	iNumTypes = pTorps.GetNumAmmoTypes()
	for iType in range(iNumTypes):
		pTorpType = pTorps.GetAmmoType(iType)

		if (pTorpType.GetAmmoName() == sType):
			# Set the maximum.
			pProp.SetMaxTorpedoes(iType, iMax)

	return 0


#
# ToggleDockingFlag() - Toggles the docking flag
#
def ToggleDockingFlag(pAction = None):
	global bDocking

	if bDocking:
		bDocking = FALSE
	else:
		bDocking = TRUE

	return 0

################################################################################
##	FriendlyFireReportHandler()
##
##	Handler called if player has done enough damage to a friendly ship to get a 
##  warning.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def FriendlyFireReportHandler(TGObject, pEvent):
	# Get the ship that was hit
	pShip	= App.ShipClass_Cast(pEvent.GetSource())
	if (pShip == None):
		return
	sShipName = pShip.GetName()
	
	# If its the Starbase, have Graff complain the first time
	if (sShipName == "Starbase 12") and (g_bGraffWarned == FALSE):
#		DebugPrint("Graff warns you about hitting Starbase")

		global g_bGraffWarned
		g_bGraffWarned = TRUE

		pFedOutpostSet = App.g_kSetManager.GetSet("FedOutpostSet")
		pGraff = App.CharacterClass_GetObject(pFedOutpostSet, "Graff")

		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)
	
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M1Arrive3", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction, 3)

		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "FedOutpostSet", "Graff")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pGraff, App.CharacterAction.AT_SAY_LINE, "E7M1HitStarbase", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)

		return

	elif (sShipName == "USS Geronimo") and (g_bMacCrayWarned == FALSE):
#		DebugPrint("MacCray warns you about hitting the Geronimo")

		global g_bMacCrayWarned
		g_bMacCrayWarned = TRUE

		pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
		pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")

		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)
	
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M1GeronimoArrive3", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction, 3)

		pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M1HitGeronimo", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)

		return

	elif (sShipName == "USS Enterprise") and (g_bPicardWarned == FALSE):
#		DebugPrint("Picard warns you about hitting the Enterprise")

		global g_bPicardWarned
		g_bPicardWarned = TRUE

		pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
		pPicard = App.CharacterClass_GetObject (pEBridgeSet, "Picard")

		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)
	
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M1PicardHail1", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction, 3)

		pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "Picard")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E7M1HitEnterprise", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)

		return

	# All done, so call our next handler
	TGObject.CallNextHandler(pEvent)


#
# HailHandler()
#
def HailHandler(pObject, pEvent):
#	DebugPrint("Handling Hail")

	pPlayer = MissionLib.GetPlayer()
	pTarget = App.ObjectClass_Cast(pEvent.GetSource())
	if not (pTarget):
		pTarget = pPlayer.GetTarget()
	
	if pTarget == None:
		return
	
	sTarget = pTarget.GetName()

	pSequence = Bridge.HelmMenuHandlers.GetHailSequence()
	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	if (sTarget == "USS Geronimo"):
		pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
		pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")

		pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M1HailingMacCray", None, 0, pMissionDatabase)

	elif (sTarget == "USS Enterprise"):
		pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
		pPicard = App.CharacterClass_GetObject(pEBridgeSet, "Picard")

		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "Picard")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E7M1HailingPicard", None, 0, pMissionDatabase)

	elif (sTarget == "Starbase 12"):
		pFedOutpostSet = App.g_kSetManager.GetSet("FedOutpostSet")
		pGraff = App.CharacterClass_GetObject(pFedOutpostSet, "Graff")

		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "FedOutpostSet", "Graff")
		pSequence.AppendAction(pAction)

		if not (iMissionState == MISS_WIN):

			if (bCardGroup1 == HAS_ARRIVED):
				pAction = App.CharacterAction_Create(pGraff, App.CharacterAction.AT_SAY_LINE, "E7M1HailingGraff1", None, 0, pMissionDatabase)

			else:
				pAction = App.CharacterAction_Create(pGraff, App.CharacterAction.AT_SAY_LINE, "E7M1Arrive5", None, 0, pMissionDatabase)

		else:
			pAction = App.CharacterAction_Create(pGraff, App.CharacterAction.AT_SAY_LINE, "E7M1HailingGraff2", None, 0, pMissionDatabase)

	else:
		pSequence.Completed()
		pObject.CallNextHandler(pEvent)

		return

	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)
	MissionLib.QueueActionToPlay(pSequence)


#
# CommunicateHandler()
#
def CommunicateHandler(pObject, pEvent):
#	DebugPrint("Communicating with crew")

	pMenu = App.STTopLevelMenu_Cast(pEvent.GetDestination())
	pPlayer = MissionLib.GetPlayer()
	if not pPlayer or not pMenu:
#		DebugPrint("ERROR - Player or menu not valid")
		return
	pSet = pPlayer.GetContainingSet()

	pBridge = App.g_kSetManager.GetSet("bridge")
	pSaalek = App.CharacterClass_GetObject (pBridge, "Saalek")

	g_pSaffiMenu = g_pSaffi.GetMenu()
	g_pFelixMenu = g_pFelix.GetMenu()
	g_pKiskaMenu = g_pKiska.GetMenu()
	g_pMiguelMenu = g_pMiguel.GetMenu()
	g_pBrexMenu = g_pBrex.GetMenu()
	if not (pSaalek == None):
		pSaalekMenu = pSaalek.GetMenu()

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	if pMenu.GetObjID() == g_pKiskaMenu.GetObjID():
#		DebugPrint("Communicating with Kiska")

		if (iMissionState == MISS_INCOMPLETE) and (bCardGroup1 == HAS_ARRIVED):
#			DebugPrint("We should intercept the enemy ships")
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M1CommunicateKiska2", None, 0, pMissionDatabase)

		elif (iFreightersLeft > 0):
#			DebugPrint("Disable Freighter's Impulse Engines")
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M1CommunicateKiska3", None, 0, pMissionDatabase)

		elif (iSaalekProdCount > 0):
#			DebugPrint("We should go to Albirea")
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M1CommunicateKiska4", None, 0, pMissionDatabase)

		else:
#			DebugPrint("Nothing special to handle.  Continue normal Communicate handler.")

			pSequence.Completed()
			pObject.CallNextHandler(pEvent)

			return

	elif pMenu.GetObjID() == g_pFelixMenu.GetObjID():
#		DebugPrint("Communicating with Felix")

		if (iMissionState == MISS_INCOMPLETE) and (bKessokGroup == HAS_ARRIVED):
#			DebugPrint("We should take out the Kessoks")
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M1CommunicateFelix2", None, 0, pMissionDatabase)

		elif (iMissionState == MISS_INCOMPLETE) and (bCardGroup1 == HAS_ARRIVED):
#			DebugPrint("We should target the nearest enemy and kill them")
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M1CommunicateFelix1", None, 0, pMissionDatabase)

		else:
#			DebugPrint("Nothing special to handle.  Continue normal Communicate handler.")

			pSequence.Completed()
			pObject.CallNextHandler(pEvent)

			return

	elif pMenu.GetObjID() == g_pSaffiMenu.GetObjID():
#		DebugPrint("Communicating with Saffi")

		if (iMissionState == MISS_INCOMPLETE) and (bCardGroup1 == HAS_ARRIVED):

			if (bStarbaseCritical == TRUE):
#				DebugPrint("Starbase is in bad shape")
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M1CommunicateSaffi3", None, 0, pMissionDatabase)
	
			elif (bEnterpriseCritical == TRUE) and (bPicardAlive == TRUE):
#				DebugPrint("Enterprise is in bad shape")
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M1CommunicateSaffi4", None, 0, pMissionDatabase)

			elif (bGeronimoCritical == TRUE) and (Maelstrom.Maelstrom.bGeronimoAlive == TRUE):
#				DebugPrint("Geronimo is in bad shape")
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M1CommunicateSaffi5", None, 0, pMissionDatabase)

			else:
#				DebugPrint("We should protect the Starbase")
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M1CommunicateSaffi2", None, 0, pMissionDatabase)

		elif (iFreightersLeft > 0):

			if (bStarbaseCritical == TRUE):
#				DebugPrint("Starbase is in bad shape")
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M1CommunicateSaffi3", None, 0, pMissionDatabase)
	
			else:
#				DebugPrint("We should protect the Starbase")
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M1CommunicateSaffi2", None, 0, pMissionDatabase)

		elif (iMissionState == MISS_LOST):
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7MissionFailed", None, 0, pEpisodeDatabase)

		elif (iSaalekProdCount > 0):
#			DebugPrint("We should go to Albirea")
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M1SaalekProd2", None, 0, pMissionDatabase)

		else:
#			DebugPrint("Nothing special to handle.  Continue normal Communicate handler.")

			pSequence.Completed()
			pObject.CallNextHandler(pEvent)

			return

	elif pMenu.GetObjID() == g_pMiguelMenu.GetObjID():
#		DebugPrint("Communicating with Miguel")

		if (iMissionState == MISS_INCOMPLETE) and (bKessokGroup == HAS_ARRIVED) and (bKessoksScanned == FALSE):
#			DebugPrint("Shall I scan the Kessoks?")
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1CommunicateMiguel1", None, 0, pMissionDatabase)

		elif (iFreightersLeft > 1) and (bFreightersScanned == FALSE):
#			DebugPrint("Shall I scan the Freighters?")
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1CommunicateMiguel2", None, 0, pMissionDatabase)

		else:
#			DebugPrint("Nothing special to handle.  Continue normal Communicate handler.")

			pSequence.Completed()
			pObject.CallNextHandler(pEvent)

			return

	elif pMenu.GetObjID() == g_pBrexMenu.GetObjID():
#		DebugPrint("Communicating with Brex")

		if (iMissionState == MISS_INCOMPLETE) and (bCardGroup1 == HAS_ARRIVED) and not IsUsingQuantums():
#			DebugPrint("Recommend you switch to Quantums")

			pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M1CommunicateBrex1", None, 0, pMissionDatabase)

		elif (iMissionState == MISS_INCOMPLETE) and (bKessokGroup == HAS_ARRIVED) and (bKessoksScanned == FALSE):
#			DebugPrint("Shall I scan the Kessoks?")
			pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M1CommunicateBrex3", None, 0, pMissionDatabase)

		elif (iFreightersLeft > 1) and (bFreightersScanned == FALSE):
#			DebugPrint("Scan the Freighters")
			pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M1CommunicateBrex4", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1CommunicateMiguel2", "Captain", 1, pMissionDatabase)

		elif (bBrexShields == FALSE) and (bCardGroup1 == HAS_ARRIVED) and not (pPlayer.GetAlertLevel() == pPlayer.GREEN_ALERT):
			pPlayer = MissionLib.GetPlayer()
			if pPlayer == None:
				pSequence.Completed()
				pObject.CallNextHandler(pEvent)

				return
	
			pShields = pPlayer.GetShields()
	
			if pShields == None:
				pSequence.Completed()
				pObject.CallNextHandler(pEvent)
	
				return

			if (pShields.GetShieldPercentage() < .5):
#				DebugPrint("Brex bugs you about the shields")
	
				global bBrexShields
				bBrexShields = TRUE
	
				pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M1CommunicateBrex2", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M1CommunicateBrex2b", "E", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1CommunicateBrex2c", "E", 1, pMissionDatabase)

			else:
#				DebugPrint("Nothing special to handle.  Continue normal Communicate handler.")
	
				pSequence.Completed()
				pObject.CallNextHandler(pEvent)
	
				return

		else:
#			DebugPrint("Nothing special to handle.  Continue normal Communicate handler.")

			pSequence.Completed()
			pObject.CallNextHandler(pEvent)

			return

	elif (pSaalek == None):
#		DebugPrint("ERROR - Saalek not valid")
		pSequence.Completed()
		pObject.CallNextHandler(pEvent)

		return

	elif pMenu.GetObjID() == pSaalekMenu.GetObjID():
#		DebugPrint("Communicating with Saalek")

		global iSaalekChat
		iSaalekChat = iSaalekChat + 1

		if (iSaalekChat == 1):
			pAction = App.CharacterAction_Create(pSaalek, App.CharacterAction.AT_SAY_LINE, "E7M1SaalekKlingons1", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M1SaalekKlingons2", "Captain", 1, pMissionDatabase)

		elif (iSaalekChat == 2):
			pAction = App.CharacterAction_Create(pSaalek, App.CharacterAction.AT_SAY_LINE, "E7M1SaalekRomulans1", "Captain", 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pSaalek, App.CharacterAction.AT_SAY_LINE, "E7M1SaalekRomulans2", "Captain", 1, pMissionDatabase)

		else:
			pAction = App.CharacterAction_Create(pSaalek, App.CharacterAction.AT_SAY_LINE, "E7M1SaalekProd1", "Captain", 1, pMissionDatabase)

	else:
#		DebugPrint("Wrong Character.  Continue normal Communicate handler.")
		pSequence.Completed()
		pObject.CallNextHandler(pEvent)

		return

	pSequence.AppendAction(pAction)
	pSequence.Play()


################################################################################
#	IsUsingQuantums()
#
#	Helper function to tell us if player has Quantum torpedoes currently selected.
#
#	Args:	None
#
#	Return:	Bool, 1-True, 0-False
################################################################################
def IsUsingQuantums():
	pPlayer = MissionLib.GetPlayer()
	if pPlayer is None:
		return FALSE

	pTorpSys = pPlayer.GetTorpedoSystem()
	if(pTorpSys):
		pAmmoType = pTorpSys.GetCurrentAmmoType()
		if(pAmmoType):
			import Tactical.Projectiles.QuantumTorpedo
			if pAmmoType.GetAmmoName() == Tactical.Projectiles.QuantumTorpedo.GetName():
				return TRUE
	return FALSE


#
# ScanHandler()
#
def ScanHandler(pObject, pEvent):
#	DebugPrint("Scanning")

	pPlayer = MissionLib.GetPlayer()
	if pPlayer == None:
		return
	pSet = pPlayer.GetContainingSet()

	iScanType = pEvent.GetInt()

	pSequence = Bridge.ScienceCharacterHandlers.GetScanSequence()

	if not (pSequence):
		return

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	if (iScanType == App.CharacterClass.EST_SCAN_OBJECT):
#		DebugPrint("Scanning Target")

		pTarget = App.ObjectClass_Cast(pEvent.GetSource())
		if not (pTarget):
			pTarget = pPlayer.GetTarget()
	
		if pTarget == None:
			pSequence.Completed()
			return
	
		sTarget = pTarget.GetName()

		if (bKessoksScanned == FALSE) and (sTarget[:len("Kessok")] == "Kessok"):
#			DebugPrint("Scanning Kessok")

			global bKessoksScanned
			bKessoksScanned = TRUE

			# Create a Timer that triggers the KessokInfo Function
			fStartTime = App.g_kUtopiaModule.GetGameTime()
			MissionLib.CreateTimer(ET_KESSOK_INFO, __name__ +".KessokInfo", fStartTime + 60, 0, 0)
	
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1ScanKessok", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M1KessokInfo1", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M1KessokInfo2", "S", 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1KessokInfo3", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M1KessokInfo4", "S", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)

		elif (bFreightersScanned == FALSE) and (sTarget[:len("Freighter")] == "Freighter"):
#			DebugPrint("Scanning Freighter")

			global bFreightersScanned
			bFreightersScanned = TRUE

			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1ScanFreighter1", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create(__name__, "MakeCargoHoldVisible")
			pSequence.AppendAction(pAction, 2)
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M1ScanFreighter2", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)

		else:
#			DebugPrint("Nothing new detected")
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1ScanNothing", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)

	elif (bAreaScanned == FALSE) and (iScanType == App.CharacterClass.EST_SCAN_AREA):
#		DebugPrint("Scanning Starbase12")

		global bAreaScanned
		bAreaScanned = TRUE

		if (bCardGroup1 == HASNT_ARRIVED):
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1ScanArea1", "Captain", 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M1FirstWave4", "S", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1FirstWave5", "E", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)

		elif (bGeronimoArrive == FALSE):
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1ScanArea4", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M1ScanArea4b", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)

		elif (bCardGroup2 == HASNT_ARRIVED):
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1ScanArea2", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)

		elif (bEnterpriseArrive == FALSE):
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1ScanArea5", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)

		elif (bKessokGroup == HASNT_ARRIVED):
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1ScanArea3", "Captain", 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M1ScanArea3b", "S", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1ScanArea3c", "C", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)

		else:
#			DebugPrint("Nothing new detected")
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1ScanNothing", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)

	else:
#		DebugPrint("Nothing new detected.")
	
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1ScanNothing", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)


#
# MakeCargoHoldVisible() - Makes the Cargo hold visible on the Freighters.
#
def MakeCargoHoldVisible(pAction):

	global kCargoHold1, kCargoHold2, kCargoHold3, kCargoHold4, kCargoHold5, kCargoHold6

	if kCargoHold1:
#		DebugPrint("CargoHold1 Targetable")
		MissionLib.ShowSubsystems(kCargoHold1)
		kCargoHold1 = 0
	if kCargoHold2:
#		DebugPrint("CargoHold2 Targetable")
		MissionLib.ShowSubsystems(kCargoHold2)
		kCargoHold2 = 0
	if kCargoHold3:
#		DebugPrint("CargoHold3 Targetable")
		MissionLib.ShowSubsystems(kCargoHold3)
		kCargoHold3 = 0
	if kCargoHold4:
#		DebugPrint("CargoHold4 Targetable")
		MissionLib.ShowSubsystems(kCargoHold4)
		kCargoHold4 = 0
	if kCargoHold5:
#		DebugPrint("CargoHold5 Targetable")
		MissionLib.ShowSubsystems(kCargoHold5)
		kCargoHold5 = 0
	if kCargoHold6:
#		DebugPrint("CargoHold6 Targetable")
		MissionLib.ShowSubsystems(kCargoHold6)
		kCargoHold6 = 0

	return 0


#
#	FreighterExploding() - Makes a huge explosion when the Freighter is destroyed
#
def FreighterExploding(TGObject):
	pObject = App.DamageableObject_Cast(TGObject)

	if (pObject == None):
#		debug("Unexpected NULL Ptr")
		return

	# we need a set to put it in
	# this should never be null, but you never know
	pSet = pObject.GetContainingSet()
	if (pSet == None):
#		debug("Unexpected NULL Set Ptr")
		return

	sSetName = pSet.GetName()

	# death only takes 2 seconds
	pObject.SetLifeTime (4.0)
	
	# Turn the collisions off on the freighter
	TGObject.SetCollisionsOn(FALSE)

	pSequence = App.TGSequence_Create()

	pEmitPos = pObject.GetRandomPointOnModel()

	pSparks = Effects.CreateDebrisSparks(1.0, pEmitPos, 0, pSet.GetEffectRoot())
	pSequence.AppendAction(pSparks)

	pExplosion = Effects.CreateDebrisExplosion(pObject.GetRadius() * 10.0, 1.5, pEmitPos, 1, pSet.GetEffectRoot())
	pSequence.AddAction(pExplosion, pSparks)

	pSound = App.TGSoundAction_Create("Big Death Explosion " + str(App.g_kSystemWrapper.GetRandomNumber(8)+1), 0, sSetName)
	pSound.SetNode(pObject.GetNode())
	pSequence.AddAction(pSound, pSparks)
	
	pEmitPos = pObject.GetRandomPointOnModel()
	pExplosion2 = Effects.CreateDebrisExplosion(pObject.GetRadius() * 20.0, 1.5, pEmitPos, 1, pSet.GetEffectRoot())
	pSequence.AddAction(pExplosion2, pSparks, 2)

	pSound2 = App.TGSoundAction_Create("Big Death Explosion " + str(App.g_kSystemWrapper.GetRandomNumber(8)+1), 0, sSetName)
	pSound2.SetNode(pObject.GetNode())
	pSequence.AddAction(pSound2, pSparks, 2)

	pSequence.Play()

	return


###############################################################################
#	SetRedAlert()
#
#	Go to Red Alert
#
#	Args: none
#
#	Return:	none
###############################################################################

def SetRedAlert(pAction):
#	DebugPrint("Going to Red Alert")	

	pPlayer = MissionLib.GetPlayer()
	if pPlayer == None:
		return 0

	pAlertEvent = App.TGIntEvent_Create()
	pAlertEvent.SetDestination(pPlayer)
	pAlertEvent.SetEventType(App.ET_SET_ALERT_LEVEL)
	pAlertEvent.SetInt(pPlayer.RED_ALERT)
	App.g_kEventManager.AddEvent(pAlertEvent)
	App.TGSoundAction_Create("RedAlert").Play()

	return 0

###############################################################################
#	CreateFirstWave()
#
#	Create the first wave of Cardassian ships
#
#	Args:	pObject	- TGObject object
#			pEvent	- TGEvent object
#
#	Return:	none
###############################################################################
def CreateFirstWave(pObject, pEvent):
#	DebugPrint("Creating first wave of Cardassians")	

	#Set the Cardassian Group 1 Flag to Arrived
	global bCardGroup1
	bCardGroup1 = HAS_ARRIVED

	pSet = App.g_kSetManager.GetSet("Starbase12")

	# Create ships
	pKeldon1 = loadspacehelper.CreateShip( "Keldon", pSet, "Keldon1", "Attacker 1 Start", 1 )
	pKeldon2 = loadspacehelper.CreateShip( "Keldon", pSet, "Keldon2", "Attacker 3 Start", 1 )
	pKeldon3 = loadspacehelper.CreateShip( "Keldon", pSet, "Keldon3", "Attacker 2 Start", 1 )

	#####################
	# Set up AI for all the ships 
	# we've just created
	#####################

	# Keldon AI: They will randomly attack either the Starbase or all friendlies

	iNum = App.g_kSystemWrapper.GetRandomNumber(2)
	if (iNum == 1):
		pKeldon1.SetAI(KeldonAI.CreateAI(pKeldon1))
	else:
		pKeldon1.SetAI(Keldon2AI.CreateAI(pKeldon1))

	iNum = App.g_kSystemWrapper.GetRandomNumber(2)
	if (iNum == 1):
		pKeldon2.SetAI(KeldonAI.CreateAI(pKeldon2))
	else:
		pKeldon2.SetAI(Keldon2AI.CreateAI(pKeldon2))

	iNum = App.g_kSystemWrapper.GetRandomNumber(2)
	if (iNum == 1):
		pKeldon3.SetAI(KeldonAI.CreateAI(pKeldon3))
	else:
		pKeldon3.SetAI(Keldon2AI.CreateAI(pKeldon3))

	pPlayer = MissionLib.GetPlayer()
	if pPlayer == None:
		return

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M1FirstWave1", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)

	if not(pPlayer.GetAlertLevel() == pPlayer.RED_ALERT):
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M1RedAlert", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "SetRedAlert")
		pSequence.AppendAction(pAction)

	if (bAreaScanned == FALSE):
		pAction2 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_MOVE, "C1")
		pSequence.AppendAction(pAction2)
		pAction3 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M1FirstWave2", "T", 0, pMissionDatabase)
		pSequence.AddAction(pAction3, pAction)
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M1FirstWave3", "C", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M1FirstWave4", "T", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1FirstWave5", "E", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_MOVE, "C")
		pSequence.AppendAction(pAction)

	else:
		global bAreaScanned
		bAreaScanned = FALSE

	MissionLib.QueueActionToPlay(pSequence)


###############################################################################
#	CreateSecondWave()
#
#	Create the second wave of Cardassian ships
#
#	Args:	pObject	- TGObject object
#			pEvent	- TGEvent object
#
#	Return:	none
###############################################################################
def CreateSecondWave(pObject, pEvent):

	global iMissionState

	if (iMissionState == MISS_LOST):
#		DebugPrint("Bypassing Second Wave")
		return	

	#Set the Cardassian Group 1 Flag to Arrived
	global bCardGroup2
	bCardGroup2 = HAS_ARRIVED

	global bAreaScanned
	bAreaScanned = FALSE
    	
#	DebugPrint("Creating second wave of Cardassians")	

	pSet = App.g_kSetManager.GetSet("Starbase12")

	# Create ships
	pKeldon4 = loadspacehelper.CreateShip( "Keldon", pSet, "Keldon4", "Attacker 1 Start", 1 )
	pKeldon5 = loadspacehelper.CreateShip( "Keldon", pSet, "Keldon5", "Attacker 2 Start", 1 )
	pKeldon6 = loadspacehelper.CreateShip( "Keldon", pSet, "Keldon6", "Attacker 3 Start", 1 )


	#####################
	# Set up AI for all the ships 
	# we've just created
	#####################

	# Keldon AI: They will randomly attack either the Starbase or all friendlies

	iNum = App.g_kSystemWrapper.GetRandomNumber(2)
	if (iNum == 1):
		pKeldon4.SetAI(KeldonAI.CreateAI(pKeldon4))
	else:
		pKeldon4.SetAI(Keldon2AI.CreateAI(pKeldon4))

	iNum = App.g_kSystemWrapper.GetRandomNumber(2)
	if (iNum == 1):
		pKeldon5.SetAI(KeldonAI.CreateAI(pKeldon5))
	else:
		pKeldon5.SetAI(Keldon2AI.CreateAI(pKeldon5))

	iNum = App.g_kSystemWrapper.GetRandomNumber(2)
	if (iNum == 1):
		pKeldon6.SetAI(KeldonAI.CreateAI(pKeldon6))
	else:
		pKeldon6.SetAI(Keldon2AI.CreateAI(pKeldon6))

	g_pFelix.SayLine(pMissionDatabase, "E7M1SecondWave1", "Captain", 1)


###############################################################################
#	CreateThirdWave()
#
#	Create the third wave of the Cardassian strike force
#
#	Args:	pObject	- TGObject object
#			pEvent	- TGEvent object
#
#	Return:	none
###############################################################################
def CreateThirdWave(pObject, pEvent):

	global iMissionState

	if (iMissionState == MISS_LOST):
#		DebugPrint("Bypassing Third Wave")
		return	

	global bKessokGroup, bAreaScanned
	bKessokGroup = HAS_ARRIVED
	bAreaScanned = FALSE

#	DebugPrint("Creating third wave of Cardassians")	
	pSet = App.g_kSetManager.GetSet("Starbase12")

	# Create ships
	pKessok1 = loadspacehelper.CreateShip( "KessokLight", pSet, "Kessok1", "Attacker 3 Start", 1 )
	pKessok2 = loadspacehelper.CreateShip( "KessokLight", pSet, "Kessok2", "Attacker 2 Start", 1 )
	pKessok3 = loadspacehelper.CreateShip( "KessokLight", pSet, "Kessok3", "Attacker 1 Start", 1 )

#	DebugPrint ("Making Kessok Impulse and Warp Engines invincible.")
	pWarp = pKessok1.GetWarpEngineSubsystem()
	pImpulse = pKessok1.GetImpulseEngineSubsystem()
	if (pWarp and pImpulse):
		MissionLib.MakeSubsystemsInvincible(pImpulse, pWarp)
	pWarp = pKessok2.GetWarpEngineSubsystem()
	pImpulse = pKessok2.GetImpulseEngineSubsystem()
	if (pWarp and pImpulse):
		MissionLib.MakeSubsystemsInvincible(pImpulse, pWarp)
	pWarp = pKessok3.GetWarpEngineSubsystem()
	pImpulse = pKessok3.GetImpulseEngineSubsystem()
	if (pWarp and pImpulse):
		MissionLib.MakeSubsystemsInvincible(pImpulse, pWarp)

	# Kessok AIs - They will randomly attack either the Starbase or all friendlies
	iNum = App.g_kSystemWrapper.GetRandomNumber(2)
	if (iNum == 1):
		pKessok1.SetAI(Kessok1AI.CreateAI(pKessok1))
	else:
		pKessok1.SetAI(Kessok2AI.CreateAI(pKessok1))

	iNum = App.g_kSystemWrapper.GetRandomNumber(2)
	if (iNum == 1):
		pKessok2.SetAI(Kessok1AI.CreateAI(pKessok2))
	else:
		pKessok2.SetAI(Kessok2AI.CreateAI(pKessok2))

	iNum = App.g_kSystemWrapper.GetRandomNumber(2)
	if (iNum == 1):
		pKessok3.SetAI(Kessok1AI.CreateAI(pKessok3))
	else:
		pKessok3.SetAI(Kessok2AI.CreateAI(pKessok3))

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M1ThirdWave1", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M1ThirdWave2", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1ThirdWave3", "C", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)


###############################################################################
#	CreateKamikazeFreighters()
#
#	Create the Kamikaze Freighters
#
#	Args:	pObject	- TGObject object
#			pEvent	- TGEvent object
#
#	Return:	none
###############################################################################
def CreateKamikazeFreighters(pAction):

	global iMissionState

	if (iMissionState == MISS_LOST):
#		DebugPrint("Bypassing Kamikaze Freighters")
		return 0

#	DebugPrint("Creating Kamikaze Freighters")	
	pSet = App.g_kSetManager.GetSet("Starbase12")
	pStarbase = App.ShipClass_GetObject(pSet, "Starbase 12")

	# Check to see if collision with Starbase has happened
	pStarbase.AddPythonFuncHandlerForInstance( App.ET_OBJECT_COLLISION, __name__ + ".StarbaseCollision" )

	# Create ships
	pFreighter1 = loadspacehelper.CreateShip( "BombFreighter", pSet, "Freighter1", "Freighter 1 Start", 1 )
	pFreighter2 = loadspacehelper.CreateShip( "BombFreighter", pSet, "Freighter2", "Freighter 2 Start", 1 )
	pFreighter3 = loadspacehelper.CreateShip( "BombFreighter", pSet, "Freighter3", "Freighter 3 Start", 1 )
	pFreighter4 = loadspacehelper.CreateShip( "BombFreighter", pSet, "Freighter4", "Freighter 4 Start", 1 )
	pFreighter5 = loadspacehelper.CreateShip( "BombFreighter", pSet, "Freighter5", "Freighter 5 Start", 1 )
	pFreighter6 = loadspacehelper.CreateShip( "BombFreighter", pSet, "Freighter6", "Freighter 6 Start", 1 )

	# Set custom death explosions for Freighters
	pFreighter1.SetDeathScript (__name__ + ".FreighterExploding")
	pFreighter2.SetDeathScript (__name__ + ".FreighterExploding")
	pFreighter3.SetDeathScript (__name__ + ".FreighterExploding")
	pFreighter4.SetDeathScript (__name__ + ".FreighterExploding")
	pFreighter5.SetDeathScript (__name__ + ".FreighterExploding")
	pFreighter6.SetDeathScript (__name__ + ".FreighterExploding")

	fRadius = pFreighter1.GetRadius() * 20.0

	# Set splash damage for Freighter explosions
	pFreighter1.SetSplashDamage(1000, fRadius)
	pFreighter2.SetSplashDamage(1000, fRadius)
	pFreighter3.SetSplashDamage(1000, fRadius)
	pFreighter4.SetSplashDamage(1000, fRadius)
	pFreighter5.SetSplashDamage(1000, fRadius)
	pFreighter6.SetSplashDamage(1000, fRadius)

	# Freighters do not leave hulks when destroyed
	pFreighter1.AddPythonFuncHandlerForInstance(App.ET_OBJECT_CONVERTED_TO_HULK, "MissionLib.IgnoreEvent")
	pFreighter2.AddPythonFuncHandlerForInstance(App.ET_OBJECT_CONVERTED_TO_HULK, "MissionLib.IgnoreEvent")
	pFreighter3.AddPythonFuncHandlerForInstance(App.ET_OBJECT_CONVERTED_TO_HULK, "MissionLib.IgnoreEvent")
	pFreighter4.AddPythonFuncHandlerForInstance(App.ET_OBJECT_CONVERTED_TO_HULK, "MissionLib.IgnoreEvent")
	pFreighter5.AddPythonFuncHandlerForInstance(App.ET_OBJECT_CONVERTED_TO_HULK, "MissionLib.IgnoreEvent")
	pFreighter6.AddPythonFuncHandlerForInstance(App.ET_OBJECT_CONVERTED_TO_HULK, "MissionLib.IgnoreEvent")

	global kCargoHold1, kCargoHold2, kCargoHold3, kCargoHold4, kCargoHold5, kCargoHold6

	pCargo = MissionLib.GetSubsystemByName(pFreighter1, "Cargo Hold")
	if (pCargo):
#		DebugPrint("Hiding Cargo Hold for Freighters")
		# Hide Cargo Hold
		MissionLib.HideSubsystem(pCargo, kCargoHold1)

		pCargo = MissionLib.GetSubsystemByName(pFreighter2, "Cargo Hold")
		MissionLib.HideSubsystem(pCargo, kCargoHold2)

		pCargo = MissionLib.GetSubsystemByName(pFreighter3, "Cargo Hold")
		MissionLib.HideSubsystem(pCargo, kCargoHold3)

		pCargo = MissionLib.GetSubsystemByName(pFreighter4, "Cargo Hold")
		MissionLib.HideSubsystem(pCargo, kCargoHold4)

		pCargo = MissionLib.GetSubsystemByName(pFreighter5, "Cargo Hold")
		MissionLib.HideSubsystem(pCargo, kCargoHold5)

		pCargo = MissionLib.GetSubsystemByName(pFreighter6, "Cargo Hold")
		MissionLib.HideSubsystem(pCargo, kCargoHold6)

	# Get our difficulity level and make Freighters slower if on Easy
	eDifficulty = App.Game_GetDifficulty()
	if (eDifficulty == App.Game.EASY):
		# Make the Freighters ram the Starbase (slower)
		pFreighter1.SetAI( RamStarbaseSlowAI.CreateAI(pFreighter1) )
		pFreighter2.SetAI( RamStarbaseSlowAI.CreateAI(pFreighter2) )
		pFreighter3.SetAI( RamStarbaseSlowAI.CreateAI(pFreighter3) )
		pFreighter4.SetAI( RamStarbaseSlowAI.CreateAI(pFreighter4) )
		pFreighter5.SetAI( RamStarbaseSlowAI.CreateAI(pFreighter5) )
		pFreighter6.SetAI( RamStarbaseSlowAI.CreateAI(pFreighter6) )
	else:
		# Make the Freighters ram the Starbase
		pFreighter1.SetAI( RamStarbaseAI.CreateAI(pFreighter1) )
		pFreighter2.SetAI( RamStarbaseAI.CreateAI(pFreighter2) )
		pFreighter3.SetAI( RamStarbaseAI.CreateAI(pFreighter3) )
		pFreighter4.SetAI( RamStarbaseAI.CreateAI(pFreighter4) )
		pFreighter5.SetAI( RamStarbaseAI.CreateAI(pFreighter5) )
		pFreighter6.SetAI( RamStarbaseAI.CreateAI(pFreighter6) )

	global iFreightersLeft
	iFreightersLeft = 6

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M1Freighters01", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M1Freighters02", "T", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M1Freighters03", "C", 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M1Freighters04", "T", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M1Freighters05", "T", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M1Freighters06", "E", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M1Freighters07", "S", 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1Freighters08", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)		
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M1Freighters09", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "AddEvenMoreObjectives")
	pSequence.AppendAction(pAction)
	pAction2 = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1Freighters09b", "Captain", 1, pMissionDatabase)
	pSequence.AddAction(pAction2, pAction, 5)

#	DebugPrint("Setting up Conditional Actions, to tell the player if a freighter is about to hit the Starbase")	
	pConditionAction1 = App.TGConditionAction_Create()
	pConditionAction1.AddCondition(App.ConditionScript_Create ("Conditions.ConditionInRange", "ConditionInRange", 100, "Starbase 12", "Freighter1"))
	pSequence.AppendAction(pConditionAction1)
	pAction1 = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1Freighters10", "Captain", 1, pMissionDatabase)
	pSequence.AddAction(pAction1, pConditionAction1)

	pConditionAction2 = App.TGConditionAction_Create()
	pConditionAction2.AddCondition(App.ConditionScript_Create ("Conditions.ConditionInRange", "ConditionInRange", 100, "Starbase 12", "Freighter2"))
	pSequence.AppendAction(pConditionAction2)
	pAction2 = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1Freighters10b", "Captain", 1, pMissionDatabase)
	pSequence.AddAction(pAction2, pConditionAction2)

	pConditionAction3 = App.TGConditionAction_Create()
	pConditionAction3.AddCondition(App.ConditionScript_Create ("Conditions.ConditionInRange", "ConditionInRange", 100, "Starbase 12", "Freighter3"))
	pSequence.AppendAction(pConditionAction3)
	pAction3 = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1Freighters10c", "Captain", 1, pMissionDatabase)
	pSequence.AddAction(pAction3, pConditionAction3)

	pConditionAction4 = App.TGConditionAction_Create()
	pConditionAction4.AddCondition(App.ConditionScript_Create ("Conditions.ConditionInRange", "ConditionInRange", 100, "Starbase 12", "Freighter4"))
	pSequence.AppendAction(pConditionAction4)
	pAction4 = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1Freighters10", "Captain", 1, pMissionDatabase)
	pSequence.AddAction(pAction4, pConditionAction4)

	pConditionAction5 = App.TGConditionAction_Create()
	pConditionAction5.AddCondition(App.ConditionScript_Create ("Conditions.ConditionInRange", "ConditionInRange", 100, "Starbase 12", "Freighter5"))
	pSequence.AppendAction(pConditionAction5)
	pAction5 = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1Freighters10b", "Captain", 1, pMissionDatabase)
	pSequence.AddAction(pAction5, pConditionAction5)

	pConditionAction6 = App.TGConditionAction_Create()
	pConditionAction6.AddCondition(App.ConditionScript_Create ("Conditions.ConditionInRange", "ConditionInRange", 100, "Starbase 12", "Freighter6"))
	pSequence.AppendAction(pConditionAction6)
	pAction6 = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1Freighters10c", "Captain", 1, pMissionDatabase)
	pSequence.AddAction(pAction6, pConditionAction6)

	pSequence.Play()

	return 0


#
# StarbaseCollision()  - A Freighter collides with the Starbase
#
def StarbaseCollision(pObject, pEvent):
	# Get the two objects that collided.
#	DebugPrint("Starbase Collision!")

	pStarbase = App.ShipClass_Cast(pEvent.GetDestination())
	pFreighter = App.ShipClass_Cast(pEvent.GetSource())

	if pStarbase and pFreighter and (bStarbaseCollision == FALSE):
		# Check if the freighters collided with the Starbase
		if ((pFreighter.GetName() == "Freighter1") or (pFreighter.GetName() == "Freighter2") or (pFreighter.GetName() == "Freighter3") or (pFreighter.GetName() == "Freighter4") or (pFreighter.GetName() == "Freighter5") or (pFreighter.GetName() == "Freighter6")):
#			DebugPrint(pFreighter.GetName() + " collided with Starbase!")
			
			global bStarbaseCollision
			bStarbaseCollision = TRUE

			# Start a timer to assign starbase damage and reset collision damage
			fStartTime = App.g_kUtopiaModule.GetGameTime()
			MissionLib.CreateTimer(ET_STARBASE_COLLISION, __name__ + ".CollisionAftermath", fStartTime + 10, 0, 0)

			pSystem = pFreighter.GetHull()
			if (pSystem):
#				DebugPrint("Destroying " + pFreighter.GetName())
				MissionLib.SetConditionPercentage (pSystem, 0)

	pObject.CallNextHandler(pEvent)


#
# 	CollisionAftermath()  - Assign Starbase damage and reset collision damage
#
def CollisionAftermath(pObject, pEvent):
#	DebugPrint("Starbase takes massive damage!")

	pSet = App.g_kSetManager.GetSet("Starbase12")
	pStarbase = App.ShipClass_GetObject(pSet, "Starbase 12")

	if not (pStarbase == None):
		# Do between 30-50% damage to the Starbase
		pSystem = pStarbase.GetHull()
		if (pSystem):
			r = App.g_kSystemWrapper.GetRandomNumber(100)
			r = r / 100.0
			r = r * (.2)
			r = r + .3
			r = pSystem.GetConditionPercentage() - r
#			DebugPrint("Damaging Starbase Hull to " + str(r))
			MissionLib.SetConditionPercentage (pSystem, r)
	
		if not bFirstCollision:
	
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1Freighters11", "Captain", 1, pMissionDatabase)
			pAction.Play()
	
			global bFirstCollision
			bFirstCollision = TRUE
	
		global bStarbaseCollision
		bStarbaseCollision = FALSE


###############################################################################
#	KessokInfo()
#
#	Continued dialogue for Miguel analyzing the Kessok ships
#
#	Args:	pObject	- TGObject object
#			pEvent	- TGEvent object
#
#	Return:	none
###############################################################################
def KessokInfo(pObject, pEvent):
#	DebugPrint("Kessok info dialogue")

	pSet = App.g_kSetManager.GetSet("Starbase12")

	pKessok1 = App.ShipClass_GetObject(pSet, "Kessok1")
	pKessok2 = App.ShipClass_GetObject(pSet, "Kessok2")
	pKessok3 = App.ShipClass_GetObject(pSet, "Kessok3")

	# If Kessok ships are in the set
	if(pKessok1 or pKessok2 or pKessok3):

		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)

		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1KessokInfo5", "Captain", 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1KessokInfo6", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M1KessokInfo7", "S", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M1KessokInfo8", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)

#	else:
#		DebugPrint("No Kessoks in set. Bypassing dialogue...")	


###############################################################################
#	CreateGeronimo()
#
#	Create the Geronimo and bring them into the fray
#
#	Args:	pObject	- TGObject object
#			pEvent	- TGEvent object
#
#	Return:	none
###############################################################################
def CreateGeronimo(pObject, pEvent):
#	DebugPrint("Creating Geronimo\n")	

	#Get the set
	pSet = App.g_kSetManager.GetSet("Starbase12")

	#Create the Geronimo
	pGeronimo = loadspacehelper.CreateShip( "Geronimo", pSet, "USS Geronimo", "Nebula Start", 1 )
	pGeronimo.ReplaceTexture("Data/Models/Ships/Akira/Geronimo.tga", "ID")

	global bGeronimoArrive, bAreaScanned
	bGeronimoArrive = TRUE
	bAreaScanned = FALSE

#	DebugPrint ("Making the Geronimo's Warp and Impulse Engines invincible.")
	pWarp = pGeronimo.GetWarpEngineSubsystem()
	if (pWarp):
		MissionLib.MakeSubsystemsInvincible(pWarp)
	pImpulse = pGeronimo.GetImpulseEngineSubsystem()
	if (pImpulse):
		MissionLib.MakeSubsystemsInvincible(pImpulse)

	pGeronimo.SetAI( FriendlyAI.CreateAI(pGeronimo) )

	# Set up Sequence for MacCray's Arrival Speech	
	pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet") 
	pFedOutpostSet = App.g_kSetManager.GetSet("FedOutpostSet")

	pMacCray = App.CharacterClass_GetObject(pEBridgeSet, "MacCray")
	pGraff = App.CharacterClass_GetObject(pFedOutpostSet, "Graff")

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M1GeronimoArrive1", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M1GeronimoArrive2", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction2 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_MOVE, "C1")
	pSequence.AppendAction(pAction2)
	pAction3 = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M1GeronimoArrive3", None, 0, pMissionDatabase)
	pSequence.AddAction(pAction3, pAction)
	pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M1GeronimoArrive4", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff", 0)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "FedOutpostSet", "Graff")
	pSequence.AppendAction(pAction, .5)
	pAction = App.CharacterAction_Create(pGraff, App.CharacterAction.AT_SAY_LINE, "E7M1GeronimoArrive5", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff", 0)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
	pSequence.AppendAction(pAction, .5)
	pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M1GeronimoArrive6", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_MOVE, "C")
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)


###############################################################################
#	CreateEnterprise()
#
#	Create the Enterprise and bring them into the fray
#
#	Args:	pObject	- TGObject object
#			pEvent	- TGEvent object
#
#	Return:	none
###############################################################################
def CreateEnterprise(pObject, pEvent):
#	DebugPrint("Creating Enterprise\n")	
	
	#Get the set
	pSet = App.g_kSetManager.GetSet("Starbase12")

	#Create the Enterprise
	pEnt_E = loadspacehelper.CreateShip( "Enterprise", pSet, "USS Enterprise", "Nebula Way1", 1 )
	pEnt_E.ReplaceTexture("Data/Models/Ships/Sovereign/Enterprise.tga", "ID")

	global bEnterpriseArrive, bAreaScanned
	bEnterpriseArrive = TRUE
	bAreaScanned = FALSE

#	DebugPrint ("Making the Enterprise's Warp and Impulse Engines invincible.")
	pWarp = pEnt_E.GetWarpEngineSubsystem()
	if (pWarp):
		MissionLib.MakeSubsystemsInvincible(pWarp)
	pImpulse = pEnt_E.GetImpulseEngineSubsystem()
	if (pImpulse):
		MissionLib.MakeSubsystemsInvincible(pImpulse)

	pEnt_E.SetAI( FriendlyAI.CreateAI(pEnt_E) )

	# Set up Sequence for Picard's Arrival Speech	
	pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet") 
	pFedOutpostSet = App.g_kSetManager.GetSet("FedOutpostSet")
	pPicard = App.CharacterClass_GetObject(pEBridgeSet, "Picard")
	pGraff = App.CharacterClass_GetObject(pFedOutpostSet, "Graff")

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M1PicardArrive1", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M1PicardArrive2", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M1PicardArrive3", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "Picard")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E7M1PicardArrive4", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff", 0)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "FedOutpostSet", "Graff")
	pSequence.AppendAction(pAction, .5)

	if iShipsDefeated < 3:
		pAction = App.CharacterAction_Create(pGraff, App.CharacterAction.AT_SAY_LINE, "E7M1PicardArrive5", None, 0, pMissionDatabase)

	else:
		pAction = App.CharacterAction_Create(pGraff, App.CharacterAction.AT_SAY_LINE, "E7M1PicardArrive5b", None, 0, pMissionDatabase)

	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff", 0)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "Picard")
	pSequence.AppendAction(pAction, .5)
	pAction = App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E7M1PicardArrive6", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "AddAnotherObjective")
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)


###############################################################################
#	AddObjectives()
#
#	Adds Goals and timers after briefing
#
#	Args:	none
#			
#	Return:	none
###############################################################################
def AddObjectives(pAction):

#	DebugPrint("Adding GoToStarbase12, Starbase12Survive and RepelCardassians Goals.\n")

	# Add our Objectives
	MissionLib.AddGoal("E7Starbase12SurviveGoal", "E7RepelCardassiansGoal")

	fStartTime = App.g_kUtopiaModule.GetGameTime()

	# Create a Timer that triggers the CreateFirstWave Function
	MissionLib.CreateTimer(ET_FIRST_WAVE, __name__ + ".CreateFirstWave", fStartTime + 90, 0, 0)

	# Start a timer to create the Geronimo
	MissionLib.CreateTimer(ET_CREATE_GERONIMO, __name__ + ".CreateGeronimo", fStartTime + 150, 0, 0)

	# Create a Timer that triggers the CreateSecondWave Function
	MissionLib.CreateTimer(ET_SECOND_WAVE, __name__ + ".CreateSecondWave", fStartTime + 210, 0, 0)

	# Start a timer to create the Enterprise
	MissionLib.CreateTimer(ET_CREATE_ENTERPRISE, __name__ + ".CreateEnterprise", fStartTime + 270, 0, 0)

	# Create a Timer that triggers the CreateThirdWave Function
	MissionLib.CreateTimer(ET_THIRD_WAVE, __name__ + ".CreateThirdWave", fStartTime + 330, 0, 0)

	return 0


###############################################################################
#	AddAnotherObjective()
#
#	Adds Goal after Enterprise arrives
#
#	Args:	none
#
#	Return:	none
###############################################################################
def AddAnotherObjective(pAction):

#	DebugPrint("Adding EnterpriseSurvive Goal.\n")

	# Add new Objective
	MissionLib.AddGoal("E7EnterpriseSurviveGoal")

	return 0


###############################################################################
#	AddEvenMoreObjectives()
#
#	Adds the goals for the Kamikaze freighter attack
#
#	Args:	none
#
#	Return:	none
###############################################################################
def AddEvenMoreObjectives(pAction):

#	DebugPrint("Adding Starbase12Survive2 and RepelCardassians2 Goals.\n")

	# Add our Objectives
	MissionLib.AddGoal("E7Starbase12Survive2Goal", "E7RepelCardassians2Goal")

	return 0


###############################################################################
#	CourseSet()
#
#	Called as a script action, I believe (I'm just adding the header)
#
#	Args:	pAction
#
#	Return:	none
###############################################################################
def CourseSet(pAction):
#	DebugPrint("Warping to Starbase 12")

	pPlayer = MissionLib.GetPlayer()
	pPlayer.SetAI(WarpSB12AI.CreateAI(pPlayer))

	return 0


###############################################################################
#	PlayerArrive()
#
#	The player arrives at the Starbase12 set, handle it as needed
#
#	Args:	none
#
#	Return:	none
###############################################################################
def PlayerArrive():
	pFedOutpostSet = App.g_kSetManager.GetSet("FedOutpostSet")
	pGraff = App.CharacterClass_GetObject(pFedOutpostSet, "Graff")

	# Set the Mission State
	global iMissionState
	iMissionState = MISS_INCOMPLETE

#	DebugPrint("Commander Graff Spiel, pre-Cardassians")

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_LOOK_AT_ME)
	pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create("MissionLib", "StartCutscene")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M1Arrive1", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M1Arrive2", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction	= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M1Arrive3", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "FedOutpostSet", "Graff")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pGraff, App.CharacterAction.AT_SAY_LINE, "E7M1Arrive4", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pGraff, App.CharacterAction.AT_SAY_LINE, "E7M1Arrive5", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pGraff, App.CharacterAction.AT_SAY_LINE, "E7M1Arrive5b", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "EndCutscene")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "AddObjectives")
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)


###############################################################################
#	LookAhead()
#
#	Force the bridge camera view ahead
#
#	Args:	pObject	- TGObject object
#			pEvent	- TGEvent object
#
#	Return:	none
###############################################################################
def LookAhead(pObject, pEvent):
#	DebugPrint("Looking ahead")
	pSet = App.g_kSetManager.GetSet("bridge")
	pCamera = App.ZoomCameraObjectClass_GetObject(pSet, "maincamera")
	pCamera.LookForward()


###############################################################################
#	WarpAfterKessoks()
#
#	Tells Enterprise and Geronimo to warp to Deep Space after the Kessoks leave
#
#	Args:	none
#
#	Return:	none
###############################################################################
def WarpAfterKessoks(pAction):

	pSet = App.g_kSetManager.GetSet("Starbase12")
	pEnt_E = App.ShipClass_GetObject(pSet, "USS Enterprise")
	pGeronimo = App.ShipClass_GetObject(pSet, "USS Geronimo")

	if(pEnt_E):
#		DebugPrint("Picard warps after the fleeing enemies")
		pEnt_E.SetAI( WarpAI.CreateAI(pEnt_E, 1) )

	if(pGeronimo):
#		DebugPrint("MacCray warps after the fleeing enemies")
		pGeronimo.SetAI( WarpAI.CreateAI(pGeronimo, 1) )

	return 0


###############################################################################
#	AttackRepelled()
#
#	The attack has been repelled
#
#	Args:	none
#
#	Return:	none
###############################################################################
def AttackRepelled():
#	DebugPrint("Attack repelled...")

	pLiuSet = App.g_kSetManager.GetSet("LiuSet")
	pLiu = App.CharacterClass_GetObject(pLiuSet, "Liu")

	pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
	pMacCray = App.CharacterClass_GetObject(pEBridgeSet, "MacCray")
	pPicard = App.CharacterClass_GetObject(pEBridgeSet, "Picard")

	if iMissionState == MISS_WIN_NOT:
	
#		DebugPrint("The enemy is retreating!")
		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)

		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M1Retreat1", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction, 6)
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M1PicardHail2", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "Picard")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E7M1Retreat2", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

		if Maelstrom.Maelstrom.bGeronimoAlive:
			# The Geronimo is alive
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M1Retreat3", None, 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
			pSequence.AppendAction(pAction)

		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_MOVE, "C")
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "WarpAfterKessoks")
		pSequence.AppendAction(pAction)

		if Maelstrom.Maelstrom.bGeronimoAlive:
			pAction2 = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1Retreat4", "Captain", 1, pMissionDatabase)

		else:
			pAction2 = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1Retreat5", "Captain", 1, pMissionDatabase)

		pSequence.AddAction(pAction2, pAction, 5)
		pAction3 = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M1Freighters15", None, 0, pMissionDatabase)
		pSequence.AddAction(pAction3, pAction2, 2)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LiuSet", "Liu")
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "LookForward")
		pSequence.AppendAction(pAction)

		if Maelstrom.Maelstrom.bGeronimoAlive:
			# Geronimo is alive
			pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M1Victory1", None, 0, pMissionDatabase)

		else:
			# Geronimo is not alive
			pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M1Victory1b", None, 0, pMissionDatabase)

		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M1Victory2", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_GLANCE_AT, "Left")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M1Victory3", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction, 2)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_GLANCE_AWAY)
		pSequence.AppendAction(pAction, 1)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M1Victory4", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)

		if Maelstrom.Maelstrom.bGeronimoAlive:
			pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M1Victory5", None, 0, pMissionDatabase)

		else:
			pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M1Victory5b", None, 0, pMissionDatabase)

		pSequence.AppendAction(pAction)

		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "CreateKamikazeFreighters")
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "ResetInterrupt")
		pSequence.AppendAction(pAction)

		#Make this sequence interruptable
		global idInterruptSequence
		idInterruptSequence = pSequence.GetObjID()

		MissionLib.QueueActionToPlay(pSequence)

	elif bStarbaseAlive:
		# Mission failed
#		DebugPrint("Mission Failed!")

		# Starbase is alive, Picard is dead
#		DebugPrint("Starbase is alive, Picard is dead")
		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)

		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_LOOK_AT_ME)
		pSequence.AppendAction(pAction, 6)
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M1Retreat1b", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_LOOK_AT_ME)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M1Freighters15", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LiuSet", "Liu")
		pSequence.AppendAction(pAction)

		if Maelstrom.Maelstrom.bGeronimoAlive:
			pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M1Loss1", None, 0, pMissionDatabase)

		else:
			pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M1Loss1b", None, 0, pMissionDatabase)

		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M1Loss2", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)	
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

		MissionLib.GameOver(None, pSequence)


#
# ResetInterrupt()
#
def ResetInterrupt(pAction):

	global idInterruptSequence
	idInterruptSequence	= App.NULL_ID

	return 0


#
# WarpHandler()
#
def WarpHandler(pObject, pEvent):
#	DebugPrint("Handling Warp")

	pGame = App.Game_GetCurrentGame()
	pPlayerSetName = pGame.GetPlayerSet().GetName()

	if (pPlayerSetName == "Starbase12"):
		if iMissionState == MISS_WIN_NOT:
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7RepelCardassians2GoalAudio", "Captain", 1, pEpisodeDatabase)
			pAction.Play()

			return

		elif not (iMissionState == MISS_WIN):
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7RepelCardassiansGoalAudio", "Captain", 1, pEpisodeDatabase)
			pAction.Play()

			return


	pObject.CallNextHandler(pEvent)


#
#	DockHandler()
#
def DockHandler(pObject, pEvent):
#	DebugPrint("Handling Docking with Starbase 12")

	if not (iMissionState == MISS_WIN):
		if (bCardGroup1 == HAS_ARRIVED):
#			DebugPrint("Too busy to Dock")
	
			pFedOutpostSet = App.g_kSetManager.GetSet("FedOutpostSet")
			pGraff = App.CharacterClass_GetObject(pFedOutpostSet, "Graff")
	
			pSequence = App.TGSequence_Create()
	
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M1Arrive3", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "FedOutpostSet", "Graff")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pGraff, App.CharacterAction.AT_SAY_LINE, "E7M1CantDock", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
			pSequence.AppendAction(pAction)
	
			MissionLib.QueueActionToPlay(pSequence)
	
			return
	
		else:
			# Heal damaged and destroyed systems to 40%
			pPlayer = MissionLib.GetPlayer()
			lSubsystems = pPlayer.GetSubsystems()
			
			for pSubsystem in lSubsystems:
				if pSubsystem.GetConditionPercentage() <= 0.4:
					pSubsystem.SetCondition(pSubsystem.GetMaxCondition() * 0.4) # 40% health for destroyed
			
				for i in range(pSubsystem.GetNumChildSubsystems()):
					pChild = pSubsystem.GetChildSubsystem(i)
					if pChild.GetCondition() <= 0.4:
						pChild.SetCondition(pChild.GetMaxCondition() * 0.4)	# 40% health for destroyed

	pObject.CallNextHandler(pEvent)


###############################################################################
#	HailStarfleet()
#
#	Contact Starfleet
#
#	Args:	pObject	- TGObject object
#			pEvent	- TGEvent object
#
#	Return:	none
###############################################################################
def HailStarfleet(pObject, pEvent):
#	DebugPrint("Contacting Starfleet")

	if bStarbaseAlive:
		pLiuSet = App.g_kSetManager.GetSet("LiuSet")
		pLiu = App.CharacterClass_GetObject(pLiuSet, "Liu")

		pSequence = MissionLib.ContactStarfleet()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)

		if not (iMissionState == MISS_WIN):
#			DebugPrint("Mission Incomplete")
			pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M1HailLiu1", None, 0, pMissionDatabase)

		else:
#			DebugPrint("Deliver Saalek")
			pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M1HailLiu2", None, 0, pMissionDatabase)

		pSequence.AppendAction(pAction)

		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)	

		MissionLib.QueueActionToPlay(pSequence)

#	else:
#		DebugPrint("Starbase can't be hailed because it is destroyed")


#
# DisableContactStarfleet() - Disable Contact Starfleet Button
#
def DisableContactStarfleet(pAction):
#	DebugPrint ("Disable ContactStarfleet Button")

	pContactStarfleet = g_pSaffiMenu.GetButtonW(pMenuDatabase.GetString("Contact Starfleet"))
	pContactStarfleet.SetDisabled()

	return 0


#
# EnableContactStarfleet() - Re-enable Contact Starfleet Button
#
def EnableContactStarfleet(pAction):
#	DebugPrint ("Re-enable Contact Starfleet Button")

	pContactStarfleet = g_pSaffiMenu.GetButtonW(pMenuDatabase.GetString("Contact Starfleet"))
	pContactStarfleet.SetEnabled()

	return 0


#
# 	SaalekBriefing() - Liu tells you about your next glorious assignment
#
def SaalekBriefing(pAction):
#	DebugPrint ("Saalek Briefing")

	# Set up sequence to add phased torpedoes next time you dock with Starbase 12
	AddPhasedTorpedoes()

	# Re-enable Starbase Repairs
	Systems.Starbase12.Starbase12_S.StarbaseRepairsEnabled(1)

#	DebugPrint ("Adding Saalek to the Bridge")
	# Add Saalek to the bridge
	pBridgeSet = App.g_kSetManager.GetSet("bridge")

	pSaalek = App.CharacterClass_GetObject(pBridgeSet, "Saalek")
	if not (pSaalek):
		pSaalek = Bridge.Characters.Saalek.CreateCharacter(pBridgeSet)
		Bridge.Characters.Saalek.ConfigureForSovereign(pSaalek)
	pSaalek.SetLocation("EBL1M")
	pSaalek.SetRandomAnimationEnabled(0)

	# Open text database for Bridge Menus

	pDatabase = App.g_kLocalizationManager.Load("Data/TGL/Bridge Menus.tgl")

	pMenu = pSaalek.GetMenu()

	# Create Communicate Button for Saalek's menu
	pMenu.AddChild(Bridge.BridgeMenus.CreateCommunicateButton("Saalek", pMenu))
	pMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	# Unload BridgeMenus Database and disable menus to start
	App.g_kLocalizationManager.Unload(pDatabase)
	pSaalek.SetMenuEnabled(0)

	# Go to green alert
	pEvent = App.TGIntEvent_Create()
	pEvent.SetDestination(g_pSaffiMenu)
	pEvent.SetInt(App.CharacterClass.EST_ALERT_GREEN)
	pEvent.SetEventType(App.ET_SET_ALERT_LEVEL)
	App.g_kEventManager.AddEvent(pEvent)
	
	pLiuSet = App.g_kSetManager.GetSet("LiuSet") 
	pLiu = App.CharacterClass_GetObject (pLiuSet, "Liu")

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create("MissionLib", "StartCutscene")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.MissionScriptActions", "ChangeToBridge")
	pSequence.AppendAction(pAction, 2)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LiuSet", "Liu")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "LookForward")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M1Win", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M1SaalekBriefing1", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M1SaalekBriefing2", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M1SaalekBriefing4", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M1SaalekBriefing5", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M1SaalekBriefing6", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M1SaalekBriefing7", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M1SaalekBriefing8", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "AddSaalekGoal")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "bridge")
	pSequence.AppendAction(pAction, 2)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Miguel Head", "Miguel Cam1", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1SaalekComing1", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Brex Head", "Brex Cam1", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M1SaalekComing2", "S", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Miguel Head", "Miguel Cam1", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1SaalekComing3", "E", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "KiskaWatchRMed", "KiskaCamRMed")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M1SaalekComing4", "S", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M1SaalekComing5", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "bridge")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pSaalek, App.CharacterAction.AT_WATCH_ME)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pSaalek, App.CharacterAction.AT_MOVE, "X2")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pSaalek, App.CharacterAction.AT_SAY_LINE, "E7M1SaalekArrive1", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pSaalek, App.CharacterAction.AT_MOVE, "X")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pSaalek, App.CharacterAction.AT_ENABLE_MENU)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pSaalek, App.CharacterAction.AT_ENABLE_RANDOM_ANIMATIONS)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pSaalek, App.CharacterAction.AT_TURN, "Captain")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pSaalek, App.CharacterAction.AT_STOP_WATCHING_ME)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "bridge")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M1SaalekArrive2", "X", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Guest Head", "Guest Cam2", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pSaalek, App.CharacterAction.AT_SAY_LINE, "E7M1SaalekArrive3", "Captain", 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pSaalek, App.CharacterAction.AT_SAY_LINE, "E7M1SaalekArrive4", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pSaalek, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "CreateMenu")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "AlbireaCourseSet")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Kiska Head", "Kiska Cam", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M1SaalekArrive5", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "bridge")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "EndCutscene")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_TURN_BACK)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "EnableContactStarfleet")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M1SaalekArrive6", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)

	return 0


#
#	AddSaalekGoal() - Adds E7DeliverAmbassadorGoal after briefing
#
def AddSaalekGoal(pAction):
	global iMissionState
	iMissionState = MISS_WIN

#	DebugPrint ("Adding DeliverAmbassador Goal.\n")
	MissionLib.AddGoal("E7DeliverAmbassadorGoal")

	return 0


#
# CreateMenu() - Creates the Albirea Helm Menu
#
def CreateMenu(pAction):

	pAlbireaMenu = Systems.Albirea.Albirea.CreateMenus()
	pAlbireaMenu.SetMissionName("Maelstrom.Episode7.E7M2.E7M2")
	
	return 0


###############################################################################
#	AlbireaCourseSet()
#
#	Set course for Albirea
#
#	Args:	pAction
#
#	Return:	none
###############################################################################
def AlbireaCourseSet(pAction):
#	DebugPrint("Setting Course for Albirea")

	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	if (pWarpButton == None):
		return 0
	# Set the location on the warp menu
	pWarpButton.SetDestination("Systems.Albirea.Albirea3", "Maelstrom.Episode7.E7M2.E7M2")
	g_pKiskaMenu.SetFocus(pWarpButton)

	# Start Saalek prodding.
	global iSaalekProdCount
	iSaalekProdCount = 1

	fStartTime = App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_SAALEK_PROD, __name__ + ".SaalekProd", fStartTime + 60, 0, 0)

	return 0


#
#	SaalekProd() - Saalek and Saffi prod you to go to Albirea
#
def SaalekProd(pObject, pEvent):
#	DebugPrint("Saalek Prod")

	if not bDocking:
		pSet = App.g_kSetManager.GetSet("bridge")
		pSaalek = App.CharacterClass_GetObject (pSet, "Saalek")
	
		if iSaalekProdCount == 0:
			return
	
		elif iSaalekProdCount == 1:
			pAction = App.CharacterAction_Create(pSaalek, App.CharacterAction.AT_SAY_LINE, "E7M1SaalekProd1", "Captain", 1, pMissionDatabase)
			pAction.Play()
	
		else:
			pAction = App.CharacterAction_Create(pSaalek, App.CharacterAction.AT_SAY_LINE, "E7M1SaalekProd2", "Captain", 1, pMissionDatabase)
			pAction.Play()
	
		global iSaalekProdCount
		iSaalekProdCount = iSaalekProdCount + 1

	# reset Saalek prod timer.
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_SAALEK_PROD, __name__ + ".SaalekProd", fStartTime + 45, 0, 0)


###############################################################################
#	CallDamage()
#
#	Dialogue trigger for when important ships are damaged
#
#	Args:	sShipName	- Name of the ship damaged
#			sSystemName - The System damaged
#			iPercentageLeft - The percentage of the System remaining
#
#	Return:	none
###############################################################################

def CallDamage(sShipName, sSystemName, iPercentageLeft ):

	#Make sure nothing overlaps
	if (bAllowDamageDialogue == 1):
		return
	global bAllowDamageDialogue
	bAllowDamageDialogue = 1

	pFedOutpostSet = App.g_kSetManager.GetSet("FedOutpostSet")
	pGraff = App.CharacterClass_GetObject(pFedOutpostSet, "Graff")

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	if (sShipName == "USS Enterprise"):
		# Make sure player and ship are in the same set
		pGame = App.Game_GetCurrentGame()
		pEnterprise = App.ShipClass_GetObject( App.SetClass_GetNull(), "USS Enterprise")
		pEnterpriseSetName = pEnterprise.GetContainingSet().GetName()
		pPlayerSetName = pGame.GetPlayerSet().GetName()
		if (pPlayerSetName == pEnterpriseSetName):
			if (sSystemName == "Shields"):
				if (iPercentageLeft == 0):
#					DebugPrint("Enterprise shields are gone!")
	
					pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1EnterpriseShields0", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)

				elif (iPercentageLeft == 50):
#					DebugPrint("Enterprise shields down to 50 percent")
	
					pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1EnterpriseShields50", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
	
			elif (sSystemName == "HullPower"):
				if (iPercentageLeft == 25):
#					DebugPrint("Enterprise hull down to 25 percent")
	
					pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
					pPicard = App.CharacterClass_GetObject(pEBridgeSet, "Picard")

					pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M1PicardHail2", None, 0, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "Picard")
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E7M1EnterpriseHull25", None, 0, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
					pSequence.AppendAction(pAction)

					global bEnterpriseCritical
					bEnterpriseCritical = TRUE

				elif (iPercentageLeft == 50):
#					DebugPrint("Enterprise hull down to 50 percent")
	
					pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1EnterpriseHull50", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)

					global bEnterpriseCritical
					bEnterpriseCritical = TRUE
	
	elif (sShipName == "USS Geronimo"):
		# Make sure player and ship are in the same set
		pGame = App.Game_GetCurrentGame()
		pGeronimo = App.ShipClass_GetObject( App.SetClass_GetNull(), "USS Geronimo")
		pGeronimoSetName = pGeronimo.GetContainingSet().GetName()
		pPlayerSetName = pGame.GetPlayerSet().GetName()
		if (pPlayerSetName == pGeronimoSetName):
			if (sSystemName == "Shields"):
				if (iPercentageLeft == 0):
#					DebugPrint("Geronimo shields are gone!")
	
					pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1GeronimoShields0", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
	
			elif (sSystemName == "HullPower"):
				if (iPercentageLeft == 25):
#					DebugPrint("Geronimo hull down to 25 percent")
	
					pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
					pMacCray = App.CharacterClass_GetObject(pEBridgeSet, "MacCray")

					pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M1GeronimoArrive3", None, 0, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M1GeronimoHull25", None, 0, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M1GeronimoHull25b", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)

					global bGeronimoCritical
					bGeronimoCritical = TRUE

				elif (iPercentageLeft == 50):
#					DebugPrint("Geronimo hull down to 50 percent")
	
					pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1GeronimoHull50", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)

					global bGeronimoCritical
					bGeronimoCritical = TRUE

	elif (sShipName == "Starbase 12"):

		# Make sure player and ship are in the same set
		pGame = App.Game_GetCurrentGame()
		pStarbase = App.ShipClass_GetObject( App.SetClass_GetNull(), "Starbase 12")
		pLiuSetName = pStarbase.GetContainingSet().GetName()
		pPlayerSetName = pGame.GetPlayerSet().GetName()
		if (pPlayerSetName == pLiuSetName):
			if (sSystemName == "HullPower"):
				if (iPercentageLeft == 1):
#					DebugPrint("Starbase 12 hull down to 1 percent")
	
					pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1StarbaseHull1", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)

					global bStarbaseCritical
					bStarbaseCritical = TRUE

				elif (iPercentageLeft == 10):
#					DebugPrint("Starbase 12 hull down to 10 percent")

					pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1StarbaseHull10", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)

					global bStarbaseCritical
					bStarbaseCritical = TRUE

				elif (iPercentageLeft == 25):
#					DebugPrint("Starbase 12 hull down to 25 percent")
	
					pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M1Arrive7", None, 0, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "FedOutpostSet", "Graff")
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(pGraff, App.CharacterAction.AT_SAY_LINE, "E7M1StarbaseHull25", None, 0, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
					pSequence.AppendAction(pAction)

					global bStarbaseCritical
					bStarbaseCritical = TRUE

				elif (iPercentageLeft == 50):
#					DebugPrint("Starbase 12 hull down to 50 percent")
	
					pSet = App.g_kSetManager.GetSet("Starbase12")
					pEnt_E = App.ShipClass_GetObject(pSet, "USS Enterprise")
					if(pEnt_E) and not (iShipsDefeated == 10):
	
						pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
						pPicard = App.CharacterClass_GetObject(pEBridgeSet, "Picard")

						pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M1PicardHail1", None, 0, pMissionDatabase)
						pSequence.AppendAction(pAction)
						pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "Picard")
						pSequence.AppendAction(pAction)
						pAction = App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E7M1StarbaseHull50", None, 0, pMissionDatabase)
						pSequence.AppendAction(pAction)
						pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
						pSequence.AppendAction(pAction)

					global bStarbaseCritical
					bStarbaseCritical = TRUE

				if (iPercentageLeft == 75):
#					DebugPrint("Starbase 12 hull down to 75 percent")
	
					pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M1Arrive3", None, 0, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "FedOutpostSet", "Graff")
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(pGraff, App.CharacterAction.AT_SAY_LINE, "E7M1StarbaseHull75", None, 0, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
					pSequence.AppendAction(pAction)
	
	pAction = App.TGScriptAction_Create(__name__, "ReAllowDamageDialogue")
	pSequence.AppendAction(pAction)
	MissionLib.QueueActionToPlay(pSequence)

	return 0


#
# Reset the Call Damage global
# Called from script above
#
def ReAllowDamageDialogue(pAction):
	#Make sure nothing overlaps
	global bAllowDamageDialogue
	bAllowDamageDialogue = 0

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


###############################################################################
#	Terminate()
#
#	Unload our mission database
#
#	Args:	pMission	- Mission object
#
#	Return:	none
###############################################################################
def Terminate(pMission):
#	DebugPrint("Terminating Episode 7, Mission 1.\n")

	# Stop the friendly fire stuff
	MissionLib.ShutdownFriendlyFire()

	# Remove Goal buttons from menu, but add Saalek Goal back in
#	DebugPrint("Deleting E7M1 Goals")
	MissionLib.DeleteGoal("E7Starbase12Survive2Goal", "E7RepelCardassians2Goal", "E7EnterpriseSurviveGoal", "E7Starbase12SurviveGoal", "E7RepelCardassiansGoal")

	# Re-enable Starbase Repairs
	Systems.Starbase12.Starbase12_S.StarbaseRepairsEnabled(1)

	# Remove instance handlers
#	DebugPrint("Removing Instance handlers")
	# Remove handler for Contact Starfleet
	g_pSaffiMenu.RemoveHandlerForInstance(App.ET_CONTACT_STARFLEET, __name__ + ".HailStarfleet")
	# Remove Science Scan event
	g_pMiguelMenu.RemoveHandlerForInstance(App.ET_SCAN, __name__ + ".ScanHandler")
	# Remove Instance handler for Kiska's dock button
	g_pKiskaMenu.RemoveHandlerForInstance(App.ET_DOCK, __name__+ ".DockHandler")
	# Remove Warp event
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	if (pWarpButton != None):
		pWarpButton.RemoveHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpHandler")
	# Remove Hail event
	g_pKiskaMenu.RemoveHandlerForInstance(App.ET_HAIL, __name__ + ".HailHandler")

	# Remove Communicate handlers
	g_pSaffiMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")
	g_pFelixMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")
	g_pKiskaMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")
	g_pMiguelMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")
	g_pBrexMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")	
	# Remove Communicate with Saalek event
	pBridge = App.g_kSetManager.GetSet("bridge")
	pSaalek = App.CharacterClass_GetObject(pBridge, "Saalek")
	if pSaalek:
		pMenu = pSaalek.GetMenu()
		pMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	# Set our terminate flag to true
	global bMissionTerminate
	bMissionTerminate = TRUE

	if(pGeneralDatabase):
		App.g_kLocalizationManager.Unload(pGeneralDatabase)

	if(pMenuDatabase):
		App.g_kLocalizationManager.Unload(pMenuDatabase)

	if(pEpisodeDatabase):
		App.g_kLocalizationManager.Unload(pEpisodeDatabase)

	# Clear the set course menu
	App.SortedRegionMenu_ClearSetCourseMenu()