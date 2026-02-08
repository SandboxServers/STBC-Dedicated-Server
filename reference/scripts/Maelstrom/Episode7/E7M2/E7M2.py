###############################################################################
#	Filename:	E7M2.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Episode 7 Mission 2
#	
#	Created:	08/30/00 -	Bill Morrison
#	Modified:	01/11/02 -	Tony Evans
###############################################################################
import App
import loadspacehelper
import MissionLib
import LoadBridge
import Bridge.Characters.CommonAnimations
import Bridge.Characters.Saalek
import Bridge.BridgeMenus
import Bridge.BridgeUtils
import Systems.Starbase12.Starbase
import Systems.Starbase12.Starbase12
import Systems.Albirea.Albirea
import Systems.Albirea.Albirea3

# Placements
import Maelstrom.Episode7.E7M1.E7M1_P
import E7M2_Albirea_P
import EBridge_P

# AI
import E7M2_Warbird
import E7M2_Vorcha
import EnemyAI
import OutpostAI
import InterceptAI
import PlayerAI2
import VorchaSkirmishAI
import WarbirdSkirmishAI
import StayAI
import VorchaRunAI
import VorchaRamAI
import PlayerAI_Albirea
import WarpAI

# For debugging
#kDebugObj = App.CPyDebug()

#
# Event types
#
ET_SECOND_GROUP			= App.Mission_GetNextEventType()
ET_RESET_KORBUS			= App.Mission_GetNextEventType()

#
# Global variables
#
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

bDebugPrint			= 0

TRUE				= 1
FALSE				= 0

pMissionDatabase	= None
pEpisodeDatabase	= None
pGeneralDatabase	= None
pMenuDatabase		= None

idInterruptSequence	= App.NULL_ID

HASNT_ARRIVED		= 0
HAS_ARRIVED			= 1
bAlbireaFlag		= HASNT_ARRIVED
iEnemiesDestroyed	= 0
fStartTime			= 0
bPowerDiverted		= 0
bFaceOff			= 0
bAllowDamageDialogue = 0		#Allows the damage dialogue to be spoken and not overlap
bTractorTried		= 0

SHIPS_COLLIDED		= 1
VORCHA_DESTROYED	= 2
WARBIRD_DESTROYED	= 3
BOTH_DESTROYED		= 4
STATION_DESTROYED	= 5
iLossState			= 0

KS_INTERCEPTED		= 1
KS_TRACTORED		= 2
KS_ENGINES_GONE		= 3
iKorbusState		= 0

bRamming			= FALSE
bInPosition			= FALSE
bKorbusAttacked		= FALSE
bKorbusAttackWait 	= FALSE

bGroup1				= FALSE
bGroup2				= FALSE
iKeldons			= 0
iGalors				= 0

# Flag to check if mission is terminating
bMissionTerminate	= FALSE

g_bChairoWarned 	= FALSE
g_bStationWarned 	= FALSE


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
	loadspacehelper.PreloadShip("SpaceFacility", 1)
	loadspacehelper.PreloadShip("Vorcha", 1)
	loadspacehelper.PreloadShip("Warbird", 1)
	loadspacehelper.PreloadShip("Galor", 3)
	loadspacehelper.PreloadShip("Keldon", 3)


#
# Initialize() - Called to initialize our mission
#
def Initialize(pMission):
#	DebugPrint ("Initializing Episode 7, Mission 2.\n")

	# Set bMissionTerminate here so it sets value correctly
	# if mission is reloaded
	global bMissionTerminate
	bMissionTerminate = FALSE

	global pMissionDatabase, pGeneralDatabase, pMenuDatabase, pEpisodeDatabase
	pMissionDatabase = pMission.SetDatabase("data/TGL/Maelstrom/Episode 7/E7M2.tgl")
	pGeneralDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")
	pMenuDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pEpisodeDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 7/Episode7.tgl")

	# Specify (and load if necessary) our bridge
	LoadBridge.Load("SovereignBridge")

	# Initialize global pointers to the bridge crew
	InitializeCrewPointers()

	Bridge.Characters.CommonAnimations.PutGuestChairIn()

	# Create characters and their sets
#	DebugPrint("Creating characters and their sets")

	MissionLib.SetupBridgeSet("LiuSet", "data/Models/Sets/StarbaseControl/starbasecontrolRM.nif")
	MissionLib.SetupCharacter("Bridge.Characters.Admiral_Liu", "LiuSet")

	MissionLib.SetupBridgeSet("KorbusSet", "data/Models/Sets/Klingon/BOPbridge.nif")
	pKorbus = MissionLib.SetupCharacter("Bridge.Characters.Korbus", "KorbusSet")
	pKorbus.SetLocation("KlingonSeated")

	MissionLib.SetupBridgeSet("TerrikSet", "data/Models/Sets/Romulan/romulanbridge.nif")
	MissionLib.SetupCharacter("Bridge.Characters.Terrik", "TerrikSet")

	# Add Saalek to the bridge
	pBridgeSet = App.g_kSetManager.GetSet("bridge")
	pSaalek = App.CharacterClass_GetObject(pBridgeSet, "Saalek")
	if not (pSaalek):
		pSaalek = Bridge.Characters.Saalek.CreateCharacter(pBridgeSet)
		Bridge.Characters.Saalek.ConfigureForSovereign(pSaalek)
		pSaalek.SetLocation("EBGuest")

	# Create and load basic stuff.
	Systems.Starbase12.Starbase12.Initialize()
	pSet2 = Systems.Starbase12.Starbase12.GetSet()

	Systems.Albirea.Albirea3.Initialize()
	pSet = Systems.Albirea.Albirea3.GetSet()

	# Load our placements into this set
	Maelstrom.Episode7.E7M1.E7M1_P.LoadPlacements(pSet2.GetName())
	
	E7M2_Albirea_P.LoadPlacements(pSet.GetName())

	# Load custom placements for bridge.
	pBridgeSet = App.g_kSetManager.GetSet("bridge")
	EBridge_P.LoadPlacements(pBridgeSet.GetName())
	
	# Create the ships and set their stats
	pPlayer = MissionLib.CreatePlayerShip("Sovereign", pSet, "player", "Enterprise Start")
	pStarbase = loadspacehelper.CreateShip( "FedStarbase", pSet2, "Starbase 12", "Starbase Location" )
	pStation = loadspacehelper.CreateShip( "SpaceFacility", pSet, "Lyra Station", "Station Start" )

	# Start the friendly fire watches
	MissionLib.SetupFriendlyFire()

	######################
	# Setup Affiliations #
	######################

	global pFriendlies, pEnemies

	pFriendlies = pMission.GetFriendlyGroup()
	pFriendlies.AddName("player")
	pFriendlies.AddName("Starbase 12")
	pFriendlies.AddName("Lyra Station")
	pFriendlies.AddName("JonKa")
	pFriendlies.AddName("Chairo")
	pEnemies = pMission.GetEnemyGroup()
	pEnemies.AddName("Keldon1")
	pEnemies.AddName("Galor1")
	pEnemies.AddName("Galor2")
	pEnemies.AddName("Galor3")
	pEnemies.AddName("Keldon2")
	pEnemies.AddName("Keldon3")

	# Setup ship AI
	pStation.SetAI(OutpostAI.CreateAI(pStation))

	###############################
	# Setup up Warp Menu Buttons for Helm  #
	###############################	
		
	pAlbireaMenu = Systems.Albirea.Albirea.CreateMenus()
	pSBMenu = Systems.Starbase12.Starbase.CreateMenus()

	#####################################
	#
	#	Music Set up
	#
	#####################################

	# Setup more mission-specific events.
	SetupEventHandlers(pMission)

	MissionLib.SaveGame("E7M2-")

	MissionLib.SetTotalTorpsAtStarbase("Photon", -1)
	MissionLib.SetTotalTorpsAtStarbase("Quantum", -1)
	MissionLib.SetMaxTorpsForPlayer("Photon", 300)
	MissionLib.SetMaxTorpsForPlayer("Quantum", 60)




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


#
# SetupEventHandlers()
#
def SetupEventHandlers(pMission):
	# Ship entrance event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_ENTERED_SET, pMission, __name__+".EnterSet")
	# Ship exit event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_EXITED_SET, pMission, __name__+".ExitSet")
	# Ship destroyed event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_DESTROYED, pMission, __name__ + ".ObjectDestroyed")

	# Instance handler for friendly fire warnings
	pMission.AddPythonFuncHandlerForInstance(App.ET_FRIENDLY_FIRE_REPORT, __name__ + ".FriendlyFireReportHandler")

	# Contact Starfleet event
	g_pSaffiMenu.AddPythonFuncHandlerForInstance(App.ET_CONTACT_STARFLEET, __name__ + ".HailStarfleet")
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

	# Intercept button handler
	g_pKiskaMenu.AddPythonFuncHandlerForInstance(App.ET_SET_COURSE, __name__ + ".InterceptHandler")

	# Warp event
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	if (pWarpButton != None):
		pWarpButton.AddPythonFuncHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpHandler")
	# Hail event
	g_pKiskaMenu.AddPythonFuncHandlerForInstance(App.ET_HAIL, __name__ + ".HailHandler")

	#Check to see if you are tractoring the Vorcha
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_TRACTOR_BEAM_STARTED_FIRING, pMission, __name__ + ".TractorHandler")

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


############################
#Mission Related Functions #
############################

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
	pLiuSet = App.g_kSetManager.GetSet("LiuSet")
	pLiu = App.CharacterClass_GetObject(pLiuSet, "Liu")

	global iMissionState

	if (bInPosition == TRUE):
#		DebugPrint("Mission Incomplete")

		pSequence = MissionLib.ContactStarfleet()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)

		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M2HailingStarfleet2", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)	
		
		MissionLib.QueueActionToPlay(pSequence)

	else:
		# Nothing special to handle.  Do default ContactStarfleet stuff
		pObject.CallNextHandler(pEvent)


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

	if (sTarget == "JonKa"):
		pKorbusSet = App.g_kSetManager.GetSet("KorbusSet")
		pKorbus = App.CharacterClass_GetObject (pKorbusSet, "Korbus")

		pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KorbusSet", "Korbus")
		pSequence.AppendAction(pAction)

		if (bFaceOff == FALSE):
			pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E7M2HailingKorbus1", None, 0, pMissionDatabase)

		else:
			pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E7M2HailingKorbus2", None, 0, pMissionDatabase)

	elif (sTarget == "Chairo"):
		pTerrikSet = App.g_kSetManager.GetSet("TerrikSet")
		pTerrik= App.CharacterClass_GetObject(pTerrikSet, "Terrik")

		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "TerrikSet", "Terrik")
		pSequence.AppendAction(pAction)

		if (bFaceOff == FALSE):
			pAction = App.CharacterAction_Create(pTerrik, App.CharacterAction.AT_SAY_LINE, "E7M2HailingTerrik1", None, 0, pMissionDatabase)

		else:
			pAction = App.CharacterAction_Create(pTerrik, App.CharacterAction.AT_SAY_LINE, "E7M2HailingTerrik2", None, 0, pMissionDatabase)

	elif (sTarget == "Lyra Station"):

		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M2HailingStation", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)

		return

	else:
#		DebugPrint("Nothing Special to handle")

		pSequence.Completed()
		pObject.CallNextHandler(pEvent)

		return

	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)


#
# WarpHandler()
#
def WarpHandler(pObject, pEvent):
#	DebugPrint("Handling Warp")

	if (bInPosition == FALSE) and (bFaceOff == FALSE):
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M2Warp1", "Captain", 1, pMissionDatabase)
		pAction.Play()

		return

	elif bFaceOff == TRUE:
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M2Warp2", "Captain", 1, pMissionDatabase)
		pAction.Play()

		return

	pObject.CallNextHandler(pEvent)


#
#	InterceptHandler()
#
def InterceptHandler(pObject, pEvent):
	if (pEvent.GetInt() == App.CharacterClass.EST_SET_COURSE_INTERCEPT) and (bRamming == TRUE):
#		DebugPrint("Handling Intercept")
		pPlayer = MissionLib.GetPlayer()
		if (pPlayer != None):
			pTarget = pPlayer.GetTarget()
			if (pTarget != None):
				if (pTarget.GetName() == "JonKa") or (pTarget.GetName() == "Chairo"):
#					DebugPrint("Attempting to block Korbus' path")
					pAI = InterceptAI.CreateAI(pPlayer, "JonKa")
					pPlayer.SetAI(pAI)

					pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M2Intercept", None, 0, pMissionDatabase)
					pAction.Play()

					pMenu = g_pKiska.GetMenu()
					pMenu.RemoveHandlerForInstance(App.ET_SET_COURSE, __name__ + ".InterceptHandler")

					return

	pObject.CallNextHandler(pEvent)


#
# CommunicateHandler()
#
def CommunicateHandler(pObject, pEvent):
#	DebugPrint("Communicating with crew")

	pAction = 0

	pMenu = App.STTopLevelMenu_Cast(pEvent.GetDestination())

	if pMenu:
		if pMenu.GetObjID() == g_pKiskaMenu.GetObjID():
#			DebugPrint("Communicating with Kiska")

			if (bInPosition == TRUE):
#				DebugPrint("End of Mission communicate")
				pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M2EndConversation1", None, 0, pMissionDatabase)

			elif (bRamming == TRUE):
#				DebugPrint("Ramming communicate")
				pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M2RamConversation1", None, 0, pMissionDatabase)

			elif (bGroup1 == TRUE):
#				DebugPrint("Battle communicate")
				pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M2BattleConversation1", None, 0, pMissionDatabase)

		elif pMenu.GetObjID() == g_pFelixMenu.GetObjID():
#			DebugPrint("Communicating with Felix")

			if (bInPosition == TRUE):
#				DebugPrint("End of Mission communicate")
				pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M2EndConversation2", None, 0, pMissionDatabase)

			elif (bRamming == TRUE):
#				DebugPrint("Ramming communicate")
				pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M2RamConversation2", None, 0, pMissionDatabase)

			elif (bGroup1 == TRUE):
				if (iKeldons == 1) and (iGalors > 1):
#					DebugPrint("Battle communicate 1")
					pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M2BattleConversation2", None, 0, pMissionDatabase)

				elif (iKeldons > 1) and (iGalors > 1):
#					DebugPrint("Battle communicate 2")
					pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M2BattleConversation2b", None, 0, pMissionDatabase)

				else:
#					DebugPrint("Battle communicate 3")
					pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M2BattleConversation2c", None, 0, pMissionDatabase)

		elif pMenu.GetObjID() == g_pSaffiMenu.GetObjID():
#			DebugPrint("Communicating with Saffi")

			if (bInPosition == TRUE):
#				DebugPrint("End of Mission communicate")
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M2EndConversation3", None, 0, pMissionDatabase)

			elif (bRamming == TRUE):
#				DebugPrint("Ramming communicate")
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M2RamConversation3", None, 0, pMissionDatabase)

			elif (bGroup1 == TRUE):
#				DebugPrint("Battle communicate")
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M2BattleConversation3", None, 0, pMissionDatabase)

		elif pMenu.GetObjID() == g_pMiguelMenu.GetObjID():
#			DebugPrint("Communicating with Miguel")

			if (bInPosition == TRUE):
#				DebugPrint("End of Mission communicate")
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M2EndConversation4", None, 0, pMissionDatabase)

			elif (bRamming == TRUE):
#				DebugPrint("Ramming communicate")
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M2RamConversation4", None, 0, pMissionDatabase)

			elif (bGroup1 == TRUE) and (bGroup2 == FALSE):
#				DebugPrint("Battle communicate")
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M2BattleConversation4", None, 0, pMissionDatabase)

		else:
#			DebugPrint("Communicating with Brex")

			if (bInPosition == TRUE):
#				DebugPrint("End of Mission communicate")
				pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M2EndConversation5", None, 0, pMissionDatabase)

			elif (bRamming == TRUE):
#				DebugPrint("Ramming communicate")
				pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M2RamConversation5", None, 0, pMissionDatabase)

			elif (bGroup1 == TRUE):
				pPlayer = MissionLib.GetPlayer()
				pWeapons = pPlayer.GetPhaserSystem()
				pWeaponPower = pPlayer.GetPhaserSystem().GetPowerPercentageWanted()

				if pWeaponPower <= 1.2:
#					DebugPrint("Battle communicate")
					pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M2BattleConversation5", None, 0, pMissionDatabase)

	if pAction:
		pAction.Play()

	else:
#		DebugPrint("Nothing special to handle.  Continue normal Communicate handler.")
		pObject.CallNextHandler(pEvent)


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
	
	if (sShipName == "JonKa") and (bKorbusAttackWait == FALSE):
#		DebugPrint("Kiska warns you about hitting the JonKa")

		global bKorbusAttackWait
		bKorbusAttackWait = TRUE

		if (bKorbusAttacked == FALSE):
			global bKorbusAttacked
			bKorbusAttacked = TRUE

			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M2FireOnKorbus", "Captain", 1, pMissionDatabase)
			pAction.Play()

			# Create a Timer that resets Korbus's attack handler
			fStartTime = App.g_kUtopiaModule.GetGameTime()
			MissionLib.CreateTimer(ET_RESET_KORBUS, __name__ + ".ResetKorbus", fStartTime + 20, 0, 0)

			return

		elif (bKorbusAttacked == TRUE):
			global bKorbusAttacked
			bKorbusAttacked = -1

			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M2FireOnKorbus2", "Captain", 1, pMissionDatabase)
			pAction.Play()

			return

	elif (sShipName == "Chairo") and (g_bChairoWarned == FALSE):
#		DebugPrint("Kiska warns you about hitting the Chairo")

		global g_bChairoWarned
		g_bChairoWarned = TRUE

		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M2FireOnTerrik", "Captain", 1, pMissionDatabase)
		pAction.Play()

		return

	elif (sShipName == "Lyra Station") and (g_bStationWarned == FALSE):
#		DebugPrint("Kiska warns you about hitting the Station")

		global g_bStationWarned
		g_bStationWarned = TRUE

		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M2FireOnStation", "Captain", 1, pMissionDatabase)
		pAction.Play()

		return

	# All done, so call our next handler
	TGObject.CallNextHandler(pEvent)


#
#	ResetKorbus() 
#
def ResetKorbus(pObject, pEvent):
#	DebugPrint("Resetting Korbus Attack handler")

	global bKorbusAttackWait
	bKorbusAttackWait = FALSE


#
# Check to see if you are tractoring the Vorcha
#
def TractorHandler(pObject, pEvent):
#	DebugPrint ("Checking tractor beam")

	# if the FaceOff has begun
	if bRamming == TRUE:
		pSet = App.g_kSetManager.GetSet("Albirea3")
		pVorcha = App.ShipClass_GetObject(pSet, "JonKa")
		pPlayer = MissionLib.GetPlayer()

		pTacCtrlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
		pTacWeaponsCtrl = pTacCtrlWindow.GetWeaponsControl()

		# Make sure the Vorcha and the player's target are valid, so the game won't crash when I do a GetObjID
		if not (pVorcha == None):
			if not (pPlayer.GetTarget() == None):
				# If player is targeting the Vorcha
				if (pPlayer.GetTarget().GetObjID() == pVorcha.GetObjID()):
#					DebugPrint ("Tractor beam engaged!")
					#Tractor Beam engaged, play dialogue and win mission
					global iKorbusState
					iKorbusState = KS_TRACTORED

					InPosition(None)

	return 0


#
# EnterSet()
#
def EnterSet(TGObject, pEvent):
	"An event triggered whenever an object enters a set."
	# Check if it's a ship.
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	
	if not App.IsNull(pShip):
		# It's a ship.
		pSet = pShip.GetContainingSet()
#		DebugPrint("Ship \"%s\" entered set \"%s\"" % (pShip.GetName(), pSet.GetName()))
		
		global bAlbireaFlag
			
		if (pShip.GetName() == "player") and (pSet.GetName() == "Albirea3") and (bAlbireaFlag == HASNT_ARRIVED):
			bAlbireaFlag = HAS_ARRIVED

			AlbireaArrive()

	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)


#
# ExitSet()
#
def ExitSet(TGObject, pEvent):
	"Triggered whenever an object leaves a set."
	# Check and see if mission is terminating, if so return
	if (bMissionTerminate == TRUE):
		return
		
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	sSetName = pEvent.GetCString()
		
	if not App.IsNull(pShip):
		# It's a ship.
#		DebugPrint("Ship \"%s\" exited set \"%s\"" % (pShip.GetName(), sSetName))

		# If the ship is leaving, not destroyed, and not player
		if not (pShip.IsDead()) and not (pShip.GetName() == "player") and (sSetName == "Albirea3"):
			if (pShip.GetName() == "JonKa"):
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M2L0855", "Captain", 1, pMissionDatabase)
				pAction.Play()
			elif (pShip.GetName() == "Chairo"):
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M2L0865", "Captain", 1, pMissionDatabase)
				pAction.Play()
	
	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)


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

	global iLossState

	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	if (pShip):
		# It's a ship.
#		DebugPrint("Ship \"%s\" was destroyed" % pShip.GetName())

		if (pShip.GetName()[:len("Galor")] == "Galor") or (pShip.GetName()[:len("Keldon")] == "Keldon"):
			global iEnemiesDestroyed
			iEnemiesDestroyed = iEnemiesDestroyed + 1

			if (pShip.GetName()[:len("Keldon")] == "Keldon"):
				global iKeldons
				iKeldons = iKeldons - 1

			elif (pShip.GetName()[:len("Galor")] == "Galor"):
				global iGalors
				iGalors = iGalors - 1

			if (iEnemiesDestroyed == 6):
				iEnemiesDestroyed = 7
#				DebugPrint("Cardassians are destroyed")

				global bGroup1, bGroup2
				bGroup1 == FALSE
				bGroup2 == FALSE

				MissionLib.RemoveGoal("E7OutpostSurvivesGoal")

				if iLossState == 0:
					FriendliesFaceOff()

				else:
					MissionLoss(None)

		elif (pShip.GetName() == "Chairo") and not (iLossState == SHIPS_COLLIDED):
#			DebugPrint("Warbird destroyed! Mission failed.")
			MissionLib.RemoveGoal("E7WarbirdSurvivesGoal")

			pSequence = App.TGSequence_Create()

			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M2L0713", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)

			if iLossState == VORCHA_DESTROYED:
				iLossState = BOTH_DESTROYED

			elif not (iLossState == STATION_DESTROYED):
				iLossState = WARBIRD_DESTROYED

			if iEnemiesDestroyed == 7:
				# If all the enemies are destroyed, play Mission Loss cutscene
				pAction = App.TGScriptAction_Create(__name__, "MissionLoss")
				pSequence.AppendAction(pAction)

			MissionLib.QueueActionToPlay(pSequence)

		elif (pShip.GetName() == "JonKa") and not (iLossState == SHIPS_COLLIDED):
#			DebugPrint("Vorcha destroyed! Mission failed.")
			MissionLib.RemoveGoal("E7VorchaSurvivesGoal")

			pSequence = App.TGSequence_Create()

			pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
			pSequence.AppendAction(pAction)

			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M2L0711", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M2L0712", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7MissionFailed", "Captain", 1, pEpisodeDatabase)
			pSequence.AppendAction(pAction)

			if iLossState == WARBIRD_DESTROYED:
				iLossState = BOTH_DESTROYED

			elif not (iLossState == STATION_DESTROYED):
				iLossState = VORCHA_DESTROYED

			if iEnemiesDestroyed == 7:
				# If all the enemies are destroyed, play Mission Loss cutscene
				pAction = App.TGScriptAction_Create(__name__, "MissionLoss")
				pSequence.AppendAction(pAction)

			MissionLib.QueueActionToPlay(pSequence)

		elif (pShip.GetName() == "Lyra Station"):
			iLossState = STATION_DESTROYED
			MissionLib.RemoveGoal("E7OutpostSurvivesGoal")

			pSequence = App.TGSequence_Create()

			pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
			pSequence.AppendAction(pAction)

			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M2L0714", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M2L0715", "S", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M2L0716", "C", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M2L0717", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7MissionFailed", "Captain", 1, pEpisodeDatabase)
			pSequence.AppendAction(pAction)

			if iEnemiesDestroyed == 7:
				pAction = App.TGScriptAction_Create(__name__, "MissionLoss")
				pSequence.AppendAction(pAction)

			MissionLib.QueueActionToPlay(pSequence)

	# We're done.  Let any other handlers for this event handle it.
	pObject.CallNextHandler(pEvent)


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
#	RemoveGoal()
#
#	Removes E7DeliverAmbassadorGoal
#
#	Args:	none
#			
#
#	Return:	none
###############################################################################
def RemoveGoal(pAction):

#	DebugPrint ("E7DeliverAmbassadorGoal complete!\n")
	MissionLib.RemoveGoal("E7DeliverAmbassadorGoal")

	return 0


###############################################################################
#	AddMoreGoals()
#
#	Adds E7VorchaSurvivesGoal and E7WarbirdSurvivesGoal after you meet them
#
#	Args:	none
#			
#
#	Return:	none
###############################################################################
def AddMoreGoals(pAction):

#	DebugPrint ("Adding VorchaSurvives, WarbirdSurvives and Station Survives Goals.\n")
	MissionLib.AddGoal("E7VorchaSurvivesGoal", "E7WarbirdSurvivesGoal", "E7OutpostSurvivesGoal")

	return 0


#
# AlbireaArrive()  
#
def AlbireaArrive():
# 	DebugPrint("Trigger arrival dialogue")

	pPlayer = MissionLib.GetPlayer()

	# Get sets	
	pKorbusSet = App.g_kSetManager.GetSet("KorbusSet")
	pTerrikSet = App.g_kSetManager.GetSet("TerrikSet")
	pSet = App.g_kSetManager.GetSet("bridge")

	# Get characters
	pKorbus = App.CharacterClass_GetObject (pKorbusSet, "Korbus")
	pTerrik = App.CharacterClass_GetObject (pTerrikSet, "Terrik")
	pSaalek = App.CharacterClass_GetObject (pSet, "Saalek")	
	
	# Create dialogue sequence
	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create("MissionLib", "StartCutscene")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M2L018", "Captain", 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction	= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "bridge")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "KiskaWatchRMed", "KiskaCamRMed")
	pSequence.AppendAction(pAction)
	pAction2 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_MOVE, "C1")
	pSequence.AppendAction(pAction2)
	pAction3 = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M2L019", None, 0, pMissionDatabase)
	pSequence.AddAction(pAction3, pAction)
	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M2L020", "T", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "CreateAndCloak")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Felix Head", "Felix Cam")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M2L0201", "H", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "MiguelWatch 1", "Miguel Cam1")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M2L0202", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "KiskaWatchRMed", "KiskaCamRMed")
	pSequence.AppendAction(pAction)
	pAction2 = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M2L021", "Captain", 1, pMissionDatabase)
	pSequence.AddAction(pAction2, pAction)
	pAction3 = App.TGScriptAction_Create(__name__, "Decloak")
	pSequence.AddAction(pAction3, pAction, 3)
	pAction4 = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "bridge")
	pSequence.AddAction(pAction4, pAction, 3)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "Albirea3")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "Albirea3")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "LockedView", "Albirea3", "player", 0, 190, 10)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M2L0215", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction, 8)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "Albirea3")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KorbusSet", "Korbus")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E7M2L022", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M2L023", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E7M2L024", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "bridge")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "KiskaWatchRMed", "KiskaCamRMed")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M2L0245", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "TerrikSet", "Terrik")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pTerrik, App.CharacterAction.AT_SAY_LINE, "E7M2L025", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pTerrik, App.CharacterAction.AT_SAY_LINE, "E7M2L027", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pTerrik, App.CharacterAction.AT_SAY_LINE, "E7M2L028", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)
	pAction	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "bridge")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pSaalek, App.CharacterAction.AT_LOOK_AT_ME)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pSaalek, App.CharacterAction.AT_SAY_LINE, "E7M2L029", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_WATCH_ME)
	pSequence.AppendAction(pAction)
	pAction2 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M2L030", None, 0, pMissionDatabase)
	pSequence.AddAction(pAction2, pAction, 2)
	pAction3 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_MOVE, "C")
	pSequence.AddAction(pAction3, pAction)
	pAction4 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_STOP_WATCHING_ME)
	pSequence.AddAction(pAction4, pAction2)
	pAction = App.CharacterAction_Create(pSaalek, App.CharacterAction.AT_WATCH_ME)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pSaalek, App.CharacterAction.AT_SAY_LINE, "E7M2L032", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pSaalek, App.CharacterAction.AT_MOVE, "L1")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pSaalek, App.CharacterAction.AT_STOP_WATCHING_ME)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "LookForward")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "EndCutscene")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M2L035", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M2L036", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M2L037", "Captain", 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M2L038", "T", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M2L039", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M2L0395", "T", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M2L040", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create(__name__, "AlbireaArrive2")
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)


#
# AlbireaArrive2() - Continue the Albirea Arrival dialogue
#
def AlbireaArrive2(pAction):
	pPlayer = MissionLib.GetPlayer()
	# Create dialogue sequence
	pSequence = App.TGSequence_Create()

	# Play Brex line "lowering shields" if shields are up.
	pShields = pPlayer.GetShields()
	if pShields:
		if pShields.IsOn():
			pAction = App.TGScriptAction_Create("Actions.ShipScriptActions", "FlickerShields")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "LoweringShields", None, 0, pGeneralDatabase)
			pSequence.AppendAction(pAction)

	pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M2L033", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "RemoveGoal")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M2L034", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M2L0341", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M2L0342", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "FirstGroup")
	pSequence.AppendAction(pAction, 7)

	MissionLib.QueueActionToPlay(pSequence)

	return 0

################################################################################
##	CreateAndCloak()
##
##	Script action that creates and immediately cloaks the Warbird and Vorcha.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def CreateAndCloak(pTGAction):
	pSet = App.g_kSetManager.GetSet("Albirea3")
	if (pSet == None):
		return 0
		
	# Create the ships
	pWarbird	= loadspacehelper.CreateShip( "Warbird", pSet, "Chairo", "Warbird Start" )
	pVorcha		= loadspacehelper.CreateShip( "Vorcha", pSet, "JonKa", "Vorcha Start" )

	# Cloak them
	pCloak = pWarbird.GetCloakingSubsystem()
	pCloak.InstantCloak()
	pCloak = pVorcha.GetCloakingSubsystem()
	pCloak.InstantCloak()

	# Make the engines on the Vorcha and Warbird invincible
	pWarp = pWarbird.GetWarpEngineSubsystem()
	if (pWarp):
		MissionLib.MakeSubsystemsInvincible(pWarp)
	pImpulse = pWarbird.GetImpulseEngineSubsystem()
	if (pImpulse):
		MissionLib.MakeSubsystemsInvincible(pImpulse)

	pWarp = pVorcha.GetWarpEngineSubsystem()
	if (pWarp):
		MissionLib.MakeSubsystemsInvincible(pWarp)
	pImpulse = pVorcha.GetImpulseEngineSubsystem()
	if (pImpulse):
		MissionLib.MakeSubsystemsInvincible(pImpulse)

	# Add the handler for the Vorcha collision 
	if (pVorcha != None):
		# Check to see if Vorcha's Impulse Engines are disabled
		pCondition1 = App.ConditionScript_Create("Conditions.ConditionSystemDisabled", "ConditionSystemDisabled", "JonKa", App.CT_IMPULSE_ENGINE_SUBSYSTEM, 1)
		pMission = MissionLib.GetMission()
		MissionLib.CallFunctionWhenConditionChanges(pMission, __name__, "VorchaEnginesGone", pCondition1)

		# Check to see if collision with Warbird has happened
		pVorcha.AddPythonFuncHandlerForInstance( App.ET_OBJECT_COLLISION, __name__ + ".ShipsCollided" )


	return 0
	

#
# Decloak()
#
def Decloak(pAction):
	pSet = App.g_kSetManager.GetSet("Albirea3")
	pVorcha = App.ShipClass_GetObject(pSet, "JonKa")
	pWarbird = App.ShipClass_GetObject(pSet, "Chairo")
		
	if (pWarbird != None):
		pCloak = pWarbird.GetCloakingSubsystem()
		if (not App.IsNull(pCloak)):
			pCloak.StopCloaking()	
	
	if (pVorcha != None):
		pCloak = pVorcha.GetCloakingSubsystem()
		if (not App.IsNull(pCloak)):
			pCloak.StopCloaking()	
	
	return 0


#
# WatchVorcha()
#
def WatchVorcha(pAction):
	pSet = App.g_kSetManager.GetSet("Albirea3")
	pVorcha = App.ShipClass_GetObject(pSet, "JonKa")

	MissionLib.ViewscreenWatchObject(pVorcha)
	
	return 0



#
# FirstGroup()  - Creates the First Group of attacking Cardies
#
def FirstGroup(pAction):
#	DebugPrint("Creating first group of Cardies")

	global bGroup1, iKeldons, iGalors
	bGroup1 = TRUE
	iKeldons = 1
	iGalors = 2

	pSet = App.g_kSetManager.GetSet("Albirea3")

	pVorcha = App.ShipClass_GetObject(pSet, "JonKa")
	pWarbird = App.ShipClass_GetObject(pSet, "Chairo")

	pKeldon1 = loadspacehelper.CreateShip( "Keldon", pSet, "Keldon1", "Enemy1 Start", 1 )
	pGalor1 = loadspacehelper.CreateShip( "Galor", pSet, "Galor1", "Enemy2 Start", 1 )
	pGalor2 = loadspacehelper.CreateShip( "Galor", pSet, "Galor2", "Enemy3 Start", 1 )

	pWarbird.SetAI(E7M2_Warbird.CreateAI(pWarbird))
	pVorcha.SetAI(E7M2_Vorcha.CreateAI(pVorcha))

	pKeldon1.SetAI(EnemyAI.CreateAI(pKeldon1, "Enemy1 Way1"))
	pGalor1.SetAI(EnemyAI.CreateAI(pGalor1, "Enemy2 Way1"))
	pGalor2.SetAI(EnemyAI.CreateAI(pGalor2, "Enemy3 Way1"))
    
	# Set up Arrival dialogue Sequence
	pKorbusSet =App.g_kSetManager.GetSet("KorbusSet")
	pTerrikSet =App.g_kSetManager.GetSet("TerrikSet")
	pTerrik = App.CharacterClass_GetObject (pTerrikSet, "Terrik")
	pKorbus = App.CharacterClass_GetObject (pKorbusSet, "Korbus")
    	
	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M2L041", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M2L042", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M2L043", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KorbusSet", "Korbus")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E7M2L044", None, 0, pMissionDatabase)	
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff", 0)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "TerrikSet", "Terrik")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pTerrik, App.CharacterAction.AT_SAY_LINE, "E7M2L045", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M2L046", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M2L047", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M2L048", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "AddMoreGoals")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M2L050", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction, 5)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M2L051", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	
	MissionLib.QueueActionToPlay(pSequence)

	# Start a timer to create the Second Group	
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_SECOND_GROUP, __name__ + ".SecondGroup", fStartTime + 120, 0, 0)
	    	
	return 0


#
# PlayerIntercept(pAction) - Moves the player ship to engage incoming enemies
#
def PlayerIntercept(pAction):
	pGame = App.Game_GetCurrentGame()
	pPlayer = pGame.GetPlayer()

	pPlayer.SetAI(PlayerAI2.CreateAI(pPlayer))

	return 0


#
# SecondGroup()  - Creates the Second Group of attacking Cardies
#
def SecondGroup(pObject, pEvent):
#	DebugPrint("Creating second group of Cardies")

	global bGroup2, iKeldons, iGalors
	bGroup2 = TRUE
	iKeldons = iKeldons + 2
	iGalors = iGalors + 1

	pSet = App.g_kSetManager.GetSet("Albirea3")

	pKeldon2 = loadspacehelper.CreateShip( "Keldon", pSet, "Keldon2", "Enemy1 Way1", 1 )
	pKeldon3 = loadspacehelper.CreateShip( "Keldon", pSet, "Keldon3", "Enemy2 Way1", 1 )
	pGalor3 = loadspacehelper.CreateShip( "Galor", pSet, "Galor3", "Enemy3 Way1", 1 )

	pKeldon2.SetAI(EnemyAI.CreateAI(pKeldon2, "Enemy1 Way1"))
	pKeldon3.SetAI(EnemyAI.CreateAI(pKeldon3, "Enemy2 Way1"))
	pGalor3.SetAI(EnemyAI.CreateAI(pGalor3, "Enemy3 Way1"))

	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M2L056", "Captain", 1, pMissionDatabase)
	pAction.Play()


#
# StartVorchaAttack()  - changes the AI for the Vorcha
#
def StartVorchaAttack(pAction):
#	DebugPrint("Starting Korbus' attack run")

	pSet = App.g_kSetManager.GetSet("Albirea3")
	pVorcha = App.ShipClass_GetObject(pSet, "JonKa")
	pWarbird = App.ShipClass_GetObject(pSet, "Chairo")

	# Make Vorcha and Warbird invincible
	MissionLib.MakeEnginesInvincible(pVorcha)
	pVorcha.SetInvincible(TRUE)
	pWarbird.SetInvincible(TRUE)

	if not (pVorcha) or not (pWarbird):
#		DebugPrint("ERROR!!!  Vorcha or Warbird not valid.")
		return 0

	pWarbird.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".VorchaHitWarbird")

#	DebugPrint("Turning off shields")
	pShields = pVorcha.GetShields()
	pShields.TurnOff()
	pShields = pWarbird.GetShields()
	pShields.TurnOff()

#	DebugPrint("Setting new AI for Vorcha")

	pVorcha.SetAI(VorchaSkirmishAI.CreateAI(pVorcha))	

	return 0


#
#	VorchaHitWarbird() 
#
def VorchaHitWarbird(pObject, pEvent):
	pAttacker = pEvent.GetFiringObject ()

	if not pAttacker:
		pObject.CallNextHandler (pEvent)
	   	return

	if (pAttacker.GetName() == "JonKa"):
		pPlayer = MissionLib.GetPlayer()
		pTarget = pPlayer.GetTarget()

		if (pTarget == None):
			pObject.CallNextHandler (pEvent)
		   	return	

#		DebugPrint("Vorcha attacked Warbird!")

		global bFaceOff
		bFaceOff = TRUE

		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)

		pAction = App.TGScriptAction_Create(__name__, "DamageWarbird")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M2L058", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction, 1)
		pAction = App.TGScriptAction_Create(__name__, "StartWarbirdAttack")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M2L059", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)

		pSet = App.g_kSetManager.GetSet("Albirea3")

#		DebugPrint("Adding WarbirdHitVorcha instance handler")
		pVorcha = App.ShipClass_GetObject(pSet, "JonKa")
		pVorcha.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".WarbirdHitVorcha")

#		DebugPrint("Removing VorchaHitWarbird instance handler")
		pWarbird = App.ShipClass_GetObject(pSet, "Chairo")
		pWarbird.RemoveHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".VorchaHitWarbird")

	pObject.CallNextHandler(pEvent)


#
#	WarbirdHitVorcha() 
#
def WarbirdHitVorcha(pObject, pEvent):
	pAttacker = pEvent.GetFiringObject ()

	if not pAttacker:
		pObject.CallNextHandler (pEvent)
	   	return

	if (pAttacker.GetName() == "Chairo") and (bInPosition == FALSE):
		pPlayer = MissionLib.GetPlayer()
		pTarget = pPlayer.GetTarget()

		if (pTarget == None):
			pObject.CallNextHandler (pEvent)
		   	return	

#		DebugPrint("Warbird attacked Vorcha!")

		pKorbusSet = App.g_kSetManager.GetSet("KorbusSet")
		pKorbus = App.CharacterClass_GetObject (pKorbusSet, "Korbus")
	
		pTerrikSet = App.g_kSetManager.GetSet("TerrikSet")
		pTerrik = App.CharacterClass_GetObject (pTerrikSet, "Terrik")

		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)

		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M2L0595", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "DamageWarbirdAndVorcha")
		pSequence.AppendAction(pAction, 1)
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M2L0585", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "PauseSkirmish")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M2L060", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M2L061", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KorbusSet", "Korbus")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E7M2L062", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M2L0625", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff", 0)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "TerrikSet", "Terrik")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pTerrik, App.CharacterAction.AT_SAY_LINE, "E7M2L063", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff", 0)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KorbusSet", "Korbus")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E7M2L064", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "RammingSpeed")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M2L065", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M2L068", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M2L069", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
	
		pConditionAction1 = App.TGConditionAction_Create()
		pSequence.AddAction(pConditionAction1, pAction)
		pConditionAction1.AddCondition(App.ConditionScript_Create ("Conditions.ConditionInLineOfSight", "ConditionInLineOfSight", "JonKa", "Chairo", "player"))
		pConditionAction1.AddCondition(App.ConditionScript_Create ("Conditions.ConditionInRange", "ConditionInRange", 175, "player", "JonKa"))
		pInPositionAction = App.TGScriptAction_Create(__name__, "InPosition")
		pSequence.AddAction(pInPositionAction, pConditionAction1)
	
		pConditionAction2 = App.TGConditionAction_Create()
		pConditionAction2.AddCondition(App.ConditionScript_Create ("Conditions.ConditionInRange", "ConditionInRange", 100, "Chairo", "JonKa"))
		pSequence.AddAction(pConditionAction2, pAction)
		pAction1 = App.TGScriptAction_Create(__name__, "GonnaHit")
		pSequence.AddAction(pAction1, pConditionAction2)

		pSequence.Play()

#		DebugPrint("Removing WarbirdHitVorcha instance handler")
		pSet = App.g_kSetManager.GetSet("Albirea3")
		pVorcha = App.ShipClass_GetObject(pSet, "JonKa")
		pVorcha.RemoveHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".WarbirdHitVorcha")

	pObject.CallNextHandler(pEvent)


#
# StartWarbirdAttack()  - changes the AI for the Warbird
#
def StartWarbirdAttack(pAction):
#	DebugPrint("Setting new AI for Warbird")

	pSet = App.g_kSetManager.GetSet("Albirea3")
	pWarbird = App.ShipClass_GetObject(pSet, "Chairo")

	if not (pWarbird):
#		DebugPrint("ERROR!!!  Warbird not valid.")
		return 0

	pWarbird.SetAI(WarbirdSkirmishAI.CreateAI(pWarbird))

	return 0


#
# PauseSkirmish()  - pauses Skirmish
#
def PauseSkirmish(pAction):
#	DebugPrint("Pausing Skirmish")
	pSet = App.g_kSetManager.GetSet("Albirea3")
	pWarbird = App.ShipClass_GetObject(pSet, "Chairo")
	pVorcha = App.ShipClass_GetObject(pSet, "JonKa")

	if not pWarbird or not pVorcha:
		return 0

	pWarbird.SetAI(StayAI.CreateAI(pWarbird))

	pVorcha.SetAI(VorchaRunAI.CreateAI(pVorcha))

	return 0


#
# StopSkirmish()  - stops Skirmish
#
def StopSkirmish(pAction):
#	DebugPrint("Stopping Skirmish")
	pSet = App.g_kSetManager.GetSet("Albirea3")
	pWarbird = App.ShipClass_GetObject(pSet, "Chairo")
	pVorcha = App.ShipClass_GetObject(pSet, "JonKa")

	if not pWarbird or not pVorcha:
		return 0

	pWarbird.SetAI(StayAI.CreateAI(pWarbird))
	pVorcha.SetAI(StayAI.CreateAI(pVorcha))

	return 0
	

#
# RammingSpeed()  - Vorcha attempts to ram the Warbird
#
def RammingSpeed(pAction):
#	DebugPrint("RammingSpeed!")
	pSet = App.g_kSetManager.GetSet("Albirea3")
	pWarbird = App.ShipClass_GetObject(pSet, "Chairo")
	pVorcha = App.ShipClass_GetObject(pSet, "JonKa")

	# Remove invincibility
	pWarbird.SetInvincible(FALSE)
	pVorcha.SetInvincible(FALSE)
	MissionLib.MakeEnginesInvincible(pVorcha, 1)


	global bRamming
	bRamming = TRUE

	# Make JonKa and Chairo Neutral
	global pNeutrals, pFriendlies
	pMission = MissionLib.GetMission()
	pFriendlies = pMission.GetFriendlyGroup()
	pFriendlies.RemoveName("JonKa")
	pFriendlies.RemoveName("Chairo")
	pNeutrals = pMission.GetNeutralGroup()
	pNeutrals.AddName("JonKa")
	pNeutrals.AddName("Chairo")

	if not (pVorcha) or not(pWarbird):
		return 0

	pWarbird.SetAI(StayAI.CreateAI(pWarbird))
	pVorcha.SetAI(VorchaRamAI.CreateAI(pVorcha))	

	return 0


#
# DamageWarbird() - First phase of Vorcha and Warbird damage
#
def DamageWarbird(pAction):
#	DebugPrint("Damage Warbird")
	pSet = App.g_kSetManager.GetSet("Albirea3")
	pWarbird = App.ShipClass_GetObject(pSet, "Chairo")
	pVorcha = App.ShipClass_GetObject(pSet, "JonKa")

	if pVorcha and pWarbird:
#		DebugPrint("Giving VorchaRunAI")
	
		pSystem = pWarbird.GetShields()
		if (pSystem):
			MissionLib.SetConditionPercentage (pSystem, .5)
	
		pSystem = pWarbird.GetHull()
		if (pSystem):
			MissionLib.SetConditionPercentage (pSystem, .8)
	
		pSystem = pWarbird.GetTractorBeamSystem()
		if (pSystem):
			MissionLib.SetConditionPercentage (pSystem, .5)

	return 0


#
# DamageWarbirdAndVorcha() - Second phase of Vorcha and Warbird damage
#
def DamageWarbirdAndVorcha(pAction):
#	DebugPrint("Damage Warbird and Vorcha")
	pSet = App.g_kSetManager.GetSet("Albirea3")
	pWarbird = App.ShipClass_GetObject(pSet, "Chairo")
	pVorcha = App.ShipClass_GetObject(pSet, "JonKa")

	if pVorcha and pWarbird:

		pSystem = pWarbird.GetImpulseEngineSubsystem()
		if (pSystem):
			fPercent = (pSystem.GetDisabledPercentage() - .25)
			if (pSystem.GetConditionPercentage() > fPercent):
				MissionLib.SetConditionPercentage(pSystem, fPercent)
	
		pSystem = pWarbird.GetTorpedoSystem()
		if (pSystem):
			fPercent = (pSystem.GetDisabledPercentage() - .2)
			if (pSystem.GetConditionPercentage() > fPercent):
				MissionLib.SetConditionPercentage(pSystem, fPercent)

		pSystem = pVorcha.GetHull()
		if (pSystem):
			fPercent = (pSystem.GetConditionPercentage() - .15)
			MissionLib.SetConditionPercentage(pSystem, fPercent)
	
		pSystem = pVorcha.GetTorpedoSystem()
		if (pSystem):
			fPercent = (pSystem.GetDisabledPercentage() - .2)
			if (pSystem.GetConditionPercentage() > fPercent):
				MissionLib.SetConditionPercentage(pSystem, fPercent)	

		pSystem = pVorcha.GetPhaserSystem()
		if (pSystem):
			fPercent = (pSystem.GetDisabledPercentage() - .15)
			if (pSystem.GetConditionPercentage() > fPercent):
				MissionLib.SetConditionPercentage(pSystem, fPercent)	
	
		pSystem = pVorcha.GetPulseWeaponSystem()
		if (pSystem):
			fPercent = (pSystem.GetDisabledPercentage() - .16)
			if (pSystem.GetConditionPercentage() > fPercent):
				MissionLib.SetConditionPercentage(pSystem, fPercent)	
	
		pSystem = pVorcha.GetShields()
		if (pSystem):
			fPercent = (pSystem.GetDisabledPercentage() - .18)
			if (pSystem.GetConditionPercentage() > fPercent):
				MissionLib.SetConditionPercentage(pSystem, fPercent)		

		pSystem = pVorcha.GetTorpedoSystem()
		if (pSystem):
			fPercent = (pSystem.GetDisabledPercentage() - .2)
			if (pSystem.GetConditionPercentage() > fPercent):
				MissionLib.SetConditionPercentage(pSystem, fPercent)

		pSystem = pVorcha.GetPhaserSystem()
		if (pSystem):
			fPercent = (pSystem.GetDisabledPercentage() - .22)
			if (pSystem.GetConditionPercentage() > fPercent):
				MissionLib.SetConditionPercentage(pSystem, fPercent)

	return 0


#
# EnableShipDamage() - makes the Vorcha and Warbird's engines damageable again
#
def EnableShipDamage(pAction):
#	DebugPrint ("Making Vorcha and Warbird Engines damageable.")

	pSet = App.g_kSetManager.GetSet("Albirea3")
	pVorcha = App.ShipClass_GetObject(pSet, "JonKa")
	pWarbird = App.ShipClass_GetObject(pSet, "Chairo")

	pImpulse = pWarbird.GetImpulseEngineSubsystem()
	if (pImpulse):
		MissionLib.MakeSubsystemsNotInvincible(pImpulse)
	pImpulse = pVorcha.GetImpulseEngineSubsystem()
	if (pImpulse):
		MissionLib.MakeSubsystemsNotInvincible(pImpulse)

	return 0


#
# FriendliesFaceOff()  - Vorcha and Warbird square off
#
def FriendliesFaceOff():
#	DebugPrint("Warbird and Vorcha skirmish dialogue")

	pKorbusSet = App.g_kSetManager.GetSet("KorbusSet")
	pTerrikSet = App.g_kSetManager.GetSet("TerrikSet")
	pTerrik = App.CharacterClass_GetObject (pTerrikSet, "Terrik")
	pKorbus = App.CharacterClass_GetObject (pKorbusSet, "Korbus")

	pSequence = App.TGSequence_Create()
	
	pAction = App.TGScriptAction_Create(__name__, "EnableShipDamage")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "StartVorchaAttack")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M2L057", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)


#
#	GonnaHit()  - Miguel warns that the Vorcha and Chairo are going to hit
#
def GonnaHit(pAction):
	if (bRamming == TRUE):
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M2L070", "Captain", 1, pMissionDatabase)
		pAction.Play()

	return 0


#
# VorchaEnginesGone()  - Player knocks out Vorcha's engines
#
def VorchaEnginesGone(bCondition):
	if not (iKorbusState == KS_ENGINES_GONE) and (bRamming == TRUE):
#		DebugPrint ("Vorcha Engines disabled!")

		global iKorbusState
		iKorbusState = KS_ENGINES_GONE
	
		InPosition(None)
	

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

	#Make sure nothing overlaps and make sure the Cardassian attack is still happening
	if (bAllowDamageDialogue == 1) or (bFaceOff == TRUE):
		return
	global bAllowDamageDialogue
	bAllowDamageDialogue = 1

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	if (sShipName == "JonKa"):
		if (sSystemName == "Shields"):
			if (iPercentageLeft == 0):
#				DebugPrint("JonKa shields are gone!")

				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M2JonkaShields0", "Captain", 0, pMissionDatabase)
				pSequence.AppendAction(pAction)

			elif (iPercentageLeft == 50):
#				DebugPrint("JonKa shields down to 50 percent")

				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M2JonkaShields50", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)

		elif (sSystemName == "HullPower"):
			if (iPercentageLeft == 25):
#				DebugPrint("JonKa hull down to 25 percent")

				pKorbusSet = App.g_kSetManager.GetSet("KorbusSet")
				pKorbus = App.CharacterClass_GetObject(pKorbusSet, "Korbus")

				pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M2KorbusHailing", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KorbusSet", "Korbus")
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E7M2JonkaHull25", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
				pSequence.AppendAction(pAction)

			elif (iPercentageLeft == 50):
#				DebugPrint("JonKa hull down to 50 percent")

				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M2JonkaHull50", "Captain", 0, pMissionDatabase)
				pSequence.AppendAction(pAction)

	if (sShipName == "Chairo"):
		if (sSystemName == "Shields"):
			if (iPercentageLeft == 0):
#				DebugPrint("Chairo shields are gone!")

				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M2ChairoShields0", "Captain", 0, pMissionDatabase)
				pSequence.AppendAction(pAction)

			elif (iPercentageLeft == 50):
#				DebugPrint("Chairo shields down to 50 percent")

				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M2ChairoShields50", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)

		elif (sSystemName == "HullPower"):
			if (iPercentageLeft == 25):
#				DebugPrint("Chairo hull down to 25 percent")

				pTerrikSet = App.g_kSetManager.GetSet("TerrikSet")
				pTerrik = App.CharacterClass_GetObject(pTerrikSet, "Terrik")

				pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M2TerrikHailing", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "TerrikSet", "Terrik")
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pTerrik, App.CharacterAction.AT_SAY_LINE, "E7M2ChairoHull25", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
				pSequence.AppendAction(pAction)

			elif (iPercentageLeft == 50):
#				DebugPrint("Chairo hull down to 50 percent")

				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M2ChairoHull50", "Captain", 0, pMissionDatabase)
				pSequence.AppendAction(pAction)

	elif (sShipName == "Lyra Station"):
		if (sSystemName == "Shields"):
			if (iPercentageLeft == 0):
#				DebugPrint("Station shields are gone!")

				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M2L052", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)

			elif (iPercentageLeft == 50):
#				DebugPrint("Station shields down to 50 percent")

				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M2L0515", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)

		elif (sSystemName == "HullPower"):
			if (iPercentageLeft == 10):
#				DebugPrint("Starbase 12 hull down to 10 percent")

				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M2L0535", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)

			if (iPercentageLeft == 50):
#				DebugPrint("Station hull down to 50 percent")

				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M2L053", "Captain", 1, pMissionDatabase)
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


#
# ShipsCollided()  - The Ships Collide
#
def ShipsCollided(pObject, pEvent):
	# Get the two objects that collided.
	pVorcha = App.ShipClass_Cast(pEvent.GetDestination())
	pShipCollidedWith = App.ShipClass_Cast(pEvent.GetSource())

	if pVorcha and pShipCollidedWith:
		# Check if this is the other ship we're interested in
		if pShipCollidedWith.GetName() == "Chairo":
			global bRamming, iLossState
			bRamming = FALSE
			iLossState = SHIPS_COLLIDED
			DestroyShip(None, pVorcha)
			DestroyShip(None, pShipCollidedWith)
			MissionLoss(None)
	pObject.CallNextHandler(pEvent)


#
#	DestroyShip() - Destroys pShip
#
def DestroyShip(pAction, pShip):
	if pShip:
		pSystem = pShip.GetHull()
		if (pSystem):
#			DebugPrint("Destroying %s" % pShip.GetName())
			MissionLib.SetConditionPercentage(pSystem, 0)

	return 0


#
# MakeItStop()  - Prevent damage to Chairo and JonKa
#
def MakeItStop():
	# Get the JonKa and Chairo
	pSet = App.g_kSetManager.GetSet("Albirea3")
	pVorcha = App.ShipClass_GetObject(pSet, "JonKa")
	pWarbird = App.ShipClass_GetObject(pSet, "Chairo")

	# Make the JonKa and Chairo not hurtable, in case of collision or stray torpedoes
	pVorcha.SetHurtable(0)
	pWarbird.SetHurtable(0)

	# Remove JonKa's collision handler
	pVorcha.RemoveHandlerForInstance( App.ET_OBJECT_COLLISION, __name__ + ".ShipsCollided" )

	# Instantly stop the JonKa
	vZero = App.TGPoint3()
	vZero.SetXYZ(0,0,0)
	pVorcha.SetVelocity(vZero)


#
# InPosition()  - Player successfully stops the Vorcha from ramming the Warbird
#
def InPosition(pAction):
#	DebugPrint("Collision Avoided")

	if bInPosition == FALSE:
		global bFaceOff, bInPosition, bRamming
		bFaceOff = FALSE
		bInPosition	= TRUE
		bRamming = FALSE

		# Prevent damage to Chairo and JonKa
		MakeItStop()

#		DebugPrint("Creating Saalek")
		pFedOutpostSet = MissionLib.SetupBridgeSet("FedOutpostSet", "data/Models/Sets/FedOutpost/fedoutpost.nif")
		pSaalek = MissionLib.SetupCharacter("Bridge.Characters.Saalek", "FedOutpostSet")
		pSaalek.SetLocation("FederationOutpostSeated")

		pGame = App.Game_GetCurrentGame()
		pPlayer = pGame.GetPlayer()
	
		pPlayer.SetAI(PlayerAI_Albirea.CreateAI(pPlayer))
		
		pKorbusSet = App.g_kSetManager.GetSet("KorbusSet")
		pKorbus = App.CharacterClass_GetObject (pKorbusSet, "Korbus")
	
		pTerrikSet = App.g_kSetManager.GetSet("TerrikSet")
		pTerrik = App.CharacterClass_GetObject (pTerrikSet, "Terrik")
	
		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)
	
		pAction = App.TGScriptAction_Create(__name__, "StopSkirmish")
		pSequence.AppendAction(pAction)

		pAction = App.TGScriptAction_Create("MissionLib", "StartCutscene", 1.0, 0.125, 1, 1, 0)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "Albirea3")
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "Albirea3")
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "TargetWatch", "Albirea3", "player", "JonKa")
		pSequence.AppendAction(pAction)

		if (iKorbusState == KS_TRACTORED):
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M2L0676", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)

		elif (iKorbusState == KS_ENGINES_GONE):
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M2L0677", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)

		else:
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M2L076", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)

		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M2L061", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction, 2)
		pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "Albirea3")	
		pSequence.AppendAction(pAction)
		pAction	= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge")
		pSequence.AppendAction(pAction)
		pAction2 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_MOVE, "C1")
		pSequence.AppendAction(pAction2)
		pAction3 = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KorbusSet", "Korbus")
		pSequence.AddAction(pAction3, pAction)

		if iKorbusState == KS_TRACTORED:
			# Korbus caught in tractor beam dialogue
			pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E7M2L0771", None, 0, pMissionDatabase)

		elif iKorbusState == KS_ENGINES_GONE:
			# Korbus impulse engines gone dialogue
			pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E7M2L0772", None, 0, pMissionDatabase)

		else:
			# Korbus intercepted dialogue
			pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E7M2L077", None, 0, pMissionDatabase)

		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M2L0625", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff", 0)
		pSequence.AppendAction(pAction)	
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "TerrikSet", "Terrik")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pTerrik, App.CharacterAction.AT_SAY_LINE, "E7M2L078", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pTerrik, App.CharacterAction.AT_SAY_LINE, "E7M2L0785", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M2L079", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M2L080", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pTerrik, App.CharacterAction.AT_SAY_LINE, "E7M2L081", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff", 0)
		pSequence.AppendAction(pAction)	
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KorbusSet", "Korbus")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E7M2L0815", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M2L082", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M2L083", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff", 0)
		pSequence.AppendAction(pAction)	
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "FedOutpostSet", "Saalek")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pSaalek, App.CharacterAction.AT_SAY_LINE, "E7M2L0835", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pSaalek, App.CharacterAction.AT_SAY_LINE, "E7M2L0836", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff", 0)
		pSequence.AppendAction(pAction)	

		if iKorbusState == KS_TRACTORED:
			pAction = App.TGScriptAction_Create(__name__, "StopTractorBeam")
			pSequence.AppendAction(pAction)

		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KorbusSet", "Korbus")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M2L084", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E7M2L085", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)	
		pAction = App.TGScriptAction_Create(__name__, "WarpOut", 1)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "TerrikSet", "Terrik")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pTerrik, App.CharacterAction.AT_SAY_LINE, "E7M2L086", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "WarpOut", 2)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_MOVE, "C")
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "MissionWin")
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "ResetInterrupt")
		pSequence.AppendAction(pAction)

		#Make this sequence interruptable
		global idInterruptSequence
		idInterruptSequence = pSequence.GetObjID()

		MissionLib.QueueActionToPlay(pSequence)
	
		# Goals complete
#		DebugPrint("VorchaSurvives, WarbirdSurvives and StationSurvives Goals Complete!")
		MissionLib.RemoveGoal("E7VorchaSurvivesGoal", "E7WarbirdSurvivesGoal")

	return 0


#
# StopTractorBeam() - Turns off the player's tractor beam and refreshes the button
#
def StopTractorBeam(pAction = None):

	pTacCtrlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacWeaponsCtrl = pTacCtrlWindow.GetWeaponsControl()

	pPlayer = MissionLib.GetPlayer()
	pPlayer.GetTractorBeamSystem().StopFiring()
	pTacWeaponsCtrl.RefreshTractorToggle()

	return 0


#
# ResetInterrupt()
#
def ResetInterrupt(pAction):

	global idInterruptSequence
	idInterruptSequence	= App.NULL_ID

	return 0


#
# WarpOut()  - Ships warp to Deep Space
#
def WarpOut(pAction, iShip):
	pSet = App.g_kSetManager.GetSet("Albirea3")

	if iShip == 1:
#		DebugPrint("Attempting to warp out Vorcha")
		pVorcha = App.ShipClass_GetObject(pSet, "JonKa")

		if pVorcha:
			pSystem = pVorcha.GetImpulseEngineSubsystem()

			if (pSystem):
#				DebugPrint("Restoring Impulse to JonKa")
				MissionLib.SetConditionPercentage(pSystem, .99)
			pVorcha.SetAI( WarpAI.CreateAI(pVorcha) )

#		else:
#			DebugPrint("Vorcha warp failed--not present")

	elif iShip == 2:
#		DebugPrint("Attempting to warp out Warbird")
		pWarbird = App.ShipClass_GetObject(pSet, "Chairo")

		if pWarbird:
			pSystem = pWarbird.GetImpulseEngineSubsystem()

			if (pSystem):
#				DebugPrint("Restoring Impulse to Chairo")
				MissionLib.SetConditionPercentage(pSystem, .7)

			pWarbird.SetAI( WarpAI.CreateAI(pWarbird) )

#		else:
#			DebugPrint("Warbird warp failed--not present")

	return 0


#
# MissionLoss()  - Function that handles the loss conditions of the mission
#
def MissionLoss(pAction):
#	DebugPrint("Mission Failed")

	# Abort Sequence, if any is going on
	global idInterruptSequence
	pInterruptSequence = App.TGSequence_Cast(App.TGObject_GetTGObjectPtr(idInterruptSequence))
	if (pInterruptSequence):
		pInterruptSequence.Completed()
		idInterruptSequence = App.NULL_ID

	# Set up Loss dialogue Sequence
	pLiuSet = App.g_kSetManager.GetSet("LiuSet")
	pLiu = App.CharacterClass_GetObject (pLiuSet, "Liu")

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	if iLossState == SHIPS_COLLIDED:
		# The Vorcha and Warbird Collided
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_LOOK_AT_ME)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M2L071", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M2L0712", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_LOOK_AT_ME)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M2L072", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LiuSet", "Liu")
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "LookForward")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M2L073", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M2L074", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M2L075", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)	

	elif iLossState == VORCHA_DESTROYED:
		# The Vorcha was destroyed
		pAction = App.TGScriptAction_Create("MissionLib", "LookForward")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M2L072", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LiuSet", "Liu")
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "LookForward")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M2L0721", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M2L0723", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M2L075", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)	

	elif iLossState == WARBIRD_DESTROYED:
		# The Warbird was destroyed
		pAction = App.TGScriptAction_Create("MissionLib", "LookForward")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M2L072", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LiuSet", "Liu")
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "LookForward")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M2L0722", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M2L0723", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M2L075", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

	elif iLossState == BOTH_DESTROYED:
		pAction = App.TGScriptAction_Create("MissionLib", "LookForward")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M2L072", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LiuSet", "Liu")
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "LookForward")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M2L0735", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M2L0723", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M2L075", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)
	
	elif iLossState == STATION_DESTROYED:
		pAction = App.TGScriptAction_Create("MissionLib", "LookForward")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M2L072", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LiuSet", "Liu")
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "LookForward")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M2L0736", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M2L0723", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M2L075", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)	

	else:
		pSequence.Completed()

		return 0

	MissionLib.GameOver(None, pSequence)

	return 0


#
# MissionWin()  - Function that handles the win conditions of the mission (duh!)
#
def MissionWin(pAction):
#	DebugPrint("Mission Successful")

	# Set up Win dialogue Sequence
	pLiuSet = App.g_kSetManager.GetSet("LiuSet")
	pLiu = App.CharacterClass_GetObject (pLiuSet, "Liu")

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M2L072", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LiuSet", "Liu")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M2L087", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M2L088", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M2L089", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "EndCutscene")
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)

#	DebugPrint ("Adding ReturnToStarbaseGoal")
	MissionLib.AddGoal("E7ReturnToStarbaseGoal")

	RemoveHooks()

	return 0

#
#	RemoveHooks()
#
def RemoveHooks():
	App.SortedRegionMenu_SetPauseSorting(1)

	pSBMenu = Systems.Starbase12.Starbase.CreateMenus()
	pSBMenu.SetMissionName("Maelstrom.Episode7.E7M3.E7M3")
	
	pAlbireaMenu = Systems.Albirea.Albirea.CreateMenus()

	App.SortedRegionMenu_SetPauseSorting(0)


#
# Terminate()
#
# Unload our mission database
#
def Terminate(pMission):
#	DebugPrint ("Terminating Episode 7, Mission 2.\n")

	# Stop the friendly fire stuff
	MissionLib.ShutdownFriendlyFire()

	# Remove Communicate handlers
	g_pSaffiMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")
	g_pFelixMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")
	g_pKiskaMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")
	g_pMiguelMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")
	g_pBrexMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	g_pSaffiMenu.RemoveHandlerForInstance(App.ET_CONTACT_STARFLEET, __name__ + ".HailStarfleet")
	g_pKiskaMenu.RemoveHandlerForInstance(App.ET_SET_COURSE, __name__ + ".InterceptHandler")
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	if (pWarpButton != None):
		pWarpButton.RemoveHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpHandler")
	g_pKiskaMenu.RemoveHandlerForInstance(App.ET_HAIL, __name__ + ".HailHandler")

	# Remove goals from Objectives list
	MissionLib.DeleteAllGoals()

	if(pGeneralDatabase):
		App.g_kLocalizationManager.Unload(pGeneralDatabase)

	if(pMenuDatabase):
		App.g_kLocalizationManager.Unload(pMenuDatabase)

	if(pEpisodeDatabase):
		App.g_kLocalizationManager.Unload(pEpisodeDatabase)

	# Set our terminate flag to true
	global bMissionTerminate
	bMissionTerminate = TRUE

	# Clear the set course menu
	App.SortedRegionMenu_ClearSetCourseMenu()