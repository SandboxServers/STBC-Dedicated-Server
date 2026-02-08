###############################################################################
#	Filename:	Graff.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads Commander Graff and configures animations
#	
#	Created:	7/25/00 -	Colin Carley
###############################################################################

import App
import Bridge.BridgeUtils
import CharacterPaths

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print

###############################################################################
#	CreateCharacter()
#
#	Create Graff by building his character and placing him on the passed in set.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	debug("Creating Commander Graff")

	if (pSet.GetObject("Graff") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("Graff")))

	SetupEventHandlers()

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadMiguel/miguel_head.nif", None)
	pGraff = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", CharacterPaths.g_pcHeadNIFPath + "HeadMiguel/miguel_head.nif")
	pGraff.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyMaleM/FedRed_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/graff_head.tga")

	# Add the character to the set
	pSet.AddObjectToSet(pGraff, "Graff")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pGraff)
	
	# Setup the character configuration
	pGraff.SetSize(App.CharacterClass.MEDIUM)
	pGraff.SetGender(App.CharacterClass.MALE)
	pGraff.SetStanding(1)
	pGraff.SetRandomAnimationChance(.01)
	pGraff.SetBlinkChance(0.1)
	pGraff.SetCharacterName("Graff")

	pGraff.AddAnimation("TurnStation", "Bridge.Characters.CommonAnimations.GlanceLeft")
	pGraff.AddAnimation("BackStation", "Bridge.Characters.CommonAnimations.Standing")

	pGraff.AddFacialImage("Blink0", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Graff_head_blink1.tga")
	pGraff.AddFacialImage("Blink1", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Graff_head_blink2.tga")
	pGraff.AddFacialImage("Blink2", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Graff_head_eyesclosed.tga")
	pGraff.SetBlinkStages(3)

	pGraff.AddFacialImage("SpeakA", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Graff_head_a.tga")
	pGraff.AddFacialImage("SpeakE", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Graff_head_e.tga")
	pGraff.AddFacialImage("SpeakU", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Graff_head_u.tga")
	pGraff.SetAnimatedSpeaking(1)

	# Configure for the Generic bridge
	import Guest
	Guest.ConfigureForGeneric(pGraff)

	pGraff.SetDatabase("data/TGL/Bridge Crew General.tgl")

	pGraff.SetLocation("FederationOutpostSeated")

#	debug("Finished creating Commander Graff")
	return pGraff

###############################################################################
#	def SetupEventHandlers():
#	
#	Setup Graff's menu handler functions.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def SetupEventHandlers():
	# Graff's menu handlers.
	pBridgeSet = App.BridgeSet_Cast(App.g_kSetManager.GetSet("bridge"))
	assert pBridgeSet
	if(pBridgeSet is None):
		return
	pViewScreen = pBridgeSet.GetViewScreen()
	assert pViewScreen
	if(pViewScreen is None):
		return

	# Event types are defined in Common/UtopiaTypes.h
	# Event sub-types are defined in Bridge/Character.h
	pViewScreen.AddPythonFuncHandlerForInstance(App.ET_SB12_REPAIR,	
											__name__ + ".Repair")
	pViewScreen.AddPythonFuncHandlerForInstance(App.ET_SB12_RELOAD,	
											__name__ + ".Reload")

###############################################################################
#	def RemoveEventHandlers()
#	
#	Remove Graff's menu handler functions.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def RemoveEventHandlers():
	# Graff's menu handlers.
	pBridgeSet = App.BridgeSet_Cast(App.g_kSetManager.GetSet("bridge"))
	assert pBridgeSet
	if(pBridgeSet is None):
		return
	pViewScreen = pBridgeSet.GetViewScreen()
	assert pViewScreen
	if(pViewScreen is None):
		return

	# Event types are defined in Common/UtopiaTypes.h
	# Event sub-types are defined in Bridge/Character.h
	pViewScreen.RemoveHandlerForInstance(App.ET_SB12_REPAIR,	
											"Graff.Repair")
	pViewScreen.RemoveHandlerForInstance(App.ET_SB12_RELOAD,	
											"Graff.Reload")

###############################################################################
#	CreateMenu()
#	
#	Create the Starbase 12 menu. This menu is associated with Graff
#	but it is actually attatched to the viewscreen object for display.
#	
#	Args: none
#	
#	Return:	none
###############################################################################
def CreateMenu():
	pBridgeSet = App.BridgeSet_Cast(App.g_kSetManager.GetSet("bridge"))
	assert pBridgeSet
	if(pBridgeSet is None):
		return
	pViewScreen = pBridgeSet.GetViewScreen()
	assert pViewScreen
	if(pViewScreen is None):
		return

	# Load string database.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	# Create menu.
	pMenuPane = App.TGPane_Create(0.26, 0.48)
	pMenu = App.STTopLevelMenu_CreateW(pDatabase.GetString("Starbase12"))
	pMenu.AddPythonFuncHandlerForInstance(App.ET_ST_BUTTON_CLICKED,	
											"Bridge.BridgeMenus.ButtonClicked")
	pMenu.AddChild(Bridge.BridgeUtils.CreateBridgeMenuButton(pDatabase.GetString("Repair"), 
					App.ET_SB12_REPAIR, 0, pViewScreen))
	pMenu.AddChild(Bridge.BridgeUtils.CreateBridgeMenuButton(pDatabase.GetString("Reload"), 
					App.ET_SB12_RELOAD, 0, pViewScreen))

	# Unload string database.
	App.g_kLocalizationManager.Unload(pDatabase)
	
	pMenuPane.AddChild(pMenu)

	# Attatch menu to viewscreen.
	pViewScreen.SetMenu(pMenu)

	# Add Glass background.
	pcLCARS = App.GraphicsModeInfo_GetCurrentMode().GetLcarsString()
	Glass = App.TGIcon_Create(pcLCARS, 120)
	Glass.Resize(pMenuPane.GetWidth(), pMenuPane.GetHeight())
	pMenuPane.AddChild(Glass, 0, 0)
	
	pTopWindow = App.TopWindow_GetTopWindow()
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	assert pTacticalControlWindow
	if(pTacticalControlWindow):
		pTacticalControlWindow.AddChild(pMenuPane, .72, .02)
		pTacticalControlWindow.AddMenuToList(pMenu)


###############################################################################
#	SayGreeting()
#	
#	Play commander Graff's greeting.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def SayGreeting(pAction):
	# Voice lines to choose from randomly.
	import AI.Compound.DockWithStarbase
	if AI.Compound.DockWithStarbase.g_bPlayerDockedOnce:
		# The player has already docked once.  All greeting lines are available.
		lsLines = [	"gg001",	# Bringing her in again, eh?
					"gg006",	# Good to see you again, Sovereign
					"gg007",	# Welcome back.
					"gg012",	# Hello, Captain.
					"gg013" ]	# Hello, Sovereign.
	else:
		# This is the first time the player is being greeted.  Only choose between the two
		# safe lines.
		lsLines = [ "gg012", "gg013" ]

	# If the player is in a Galaxy rather than a Sovereign, change the two
	# Sovereign lines.
	pBridgeSet = App.BridgeSet_Cast(App.g_kSetManager.GetSet("bridge"))
	if pBridgeSet  and  pBridgeSet.GetConfig() == "GalaxyBridge":
		if "gg006" in lsLines:
			lsLines.remove("gg006")
			lsLines.append("gg006Daunt")
		if "gg013" in lsLines:
			lsLines.remove("gg013")
			lsLines.append("gg013Daunt")

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")
	pSB12Control = App.g_kSetManager.GetSet("FedOutpostSet_Graff")
	pGraff = App.CharacterClass_GetObject(pSB12Control, "Graff")
	assert pGraff
	if(pGraff):
		pLineAction = App.CharacterAction_Create(pGraff, App.CharacterAction.AT_SAY_LINE,
								lsLines[App.g_kSystemWrapper.GetRandomNumber(len(lsLines))],
								None, 0, pDatabase)
		if(pAction):
			pEvent = App.TGObjPtrEvent_Create()
			pEvent.SetEventType(App.ET_ACTION_COMPLETED)
			pEvent.SetDestination(App.g_kTGActionManager)
			pEvent.SetObjPtr(pAction)
			pLineAction.AddCompletedEvent(pEvent)
		pLineAction.Play()
	App.g_kLocalizationManager.Unload(pDatabase)

	return 1

###############################################################################
#	SayRepairLine()
#	
#	Play commander Graff's repair line.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def SayRepairLine():
	# Voice lines to choose from randomly.
	# Note: "gg009" is not included here because it is only used
	#		if the player's hull damage is below 50%.
	Lines = [	"gg002",
				"gg005", 
				"gg011" ]

	# Get player's ship.
	pGame = App.Game_GetCurrentGame()
	assert(pGame)
	if(pGame is None):
		return
	pShip = App.ShipClass_Cast(pGame.GetPlayer())
	assert(pShip)
	if(pShip is None):
		return
	
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")
	pSB12Control = App.g_kSetManager.GetSet("FedOutpostSet_Graff")
	pGraff = App.CharacterClass_GetObject(pSB12Control, "Graff")
	assert pGraff
	if(pGraff is None):
		App.g_kLocalizationManager.Unload(pDatabase)
		return

	# If ship damage is below 50%
	if(pShip.GetHull().GetConditionPercentage() < 0.5):
		# Play special line.
		pGraff.SayLine(pDatabase, "gg009")
	else:
		# Choose random line from list.
		pGraff.SayLine(pDatabase, Lines[App.g_kSystemWrapper.GetRandomNumber(len(Lines))])
	
	App.g_kLocalizationManager.Unload(pDatabase)

###############################################################################
#	SayReloadLine()
#	
#	Play commander Graff's voice line when asking for reload.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def SayReloadLine():
	# Voice lines to choose from randomly.
	# Note: "gg004" is not included here because it is only used
	#		if the player has used his torps too quickly.
	Lines = [	"gg003",
				"gg010" ]
	
	# Get player's ship.
	pGame = App.Game_GetCurrentGame()
	assert(pGame)
	if(pGame is None):
		return
	pShip = App.ShipClass_Cast(pGame.GetPlayer())
	assert(pShip)
	if(pShip is None):
		return

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")
	pSB12Control = App.g_kSetManager.GetSet("FedOutpostSet_Graff")
	pGraff = App.CharacterClass_GetObject(pSB12Control, "Graff")
	assert pGraff
	if(pGraff is None):
		App.g_kLocalizationManager.Unload(pDatabase)
		return		
	
	# Add condition for special case sound, "gg004".
	#pGraff.SayLine(pDatabase, "gg004")

	pGraff.SayLine(pDatabase, Lines[App.g_kSystemWrapper.GetRandomNumber(len(Lines))])
	App.g_kLocalizationManager.Unload(pDatabase)

###############################################################################
#	Repair(pObject, pEvent)
#	
#	Handles the "Repair" menu item.
#	
#	Args:	pObject		- the target of the event
#			pEvent		- the event
#	
#	Return:	none
###############################################################################
def Repair(pObject, pEvent):
	# Get player's ship.
	pGame = App.Game_GetCurrentGame()
	assert pGame
	if(pGame is None):
		pObject.CallNextHandler(pEvent)
		return
	pShip = App.ShipClass_Cast(pGame.GetPlayer())
	assert pShip
	if(pShip is None):
		pObject.CallNextHandler(pEvent)
		return

	# Play dialogue before repairing.
	SayRepairLine()

	# Repair ship completely.
	pAction = App.TGScriptAction_Create("Actions.ShipScriptActions", 
										"RepairShipFully", pShip.GetObjID())
	pAction.Play()

	pObject.CallNextHandler(pEvent)


###############################################################################
#	Reload(pObject, pEvent)
#	
#	Handles the "Reload" menu item.
#	
#	Args:	pObject		- the target of the event
#			pEvent		- the event
#	
#	Return:	none
###############################################################################
def Reload(pObject, pEvent):
	# Get player's ship.
	pGame = App.Game_GetCurrentGame()
	assert pGame
	if(pGame is None):
		pObject.CallNextHandler(pEvent)
		return
	pShip = App.ShipClass_Cast(pGame.GetPlayer())
	assert pShip
	if(pShip is None):
		pObject.CallNextHandler(pEvent)
		return

	# Play dialouge before reloading.
	SayReloadLine()

	# Reload ship.
	pAction = App.TGScriptAction_Create("Actions.ShipScriptActions",
										"ReloadShip", pShip.GetObjID())
	pAction.Play()

	pObject.CallNextHandler(pEvent)

