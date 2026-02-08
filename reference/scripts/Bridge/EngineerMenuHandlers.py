###############################################################################
#	Filename:	EngineerMenuHandlers.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Script to create the engineer's menu and handle some of its events.
#	
#	Created:	??/??/???? -	?
###############################################################################

import App
import BridgeUtils
import MissionLib

# Create debug object
#kDebugObj = App.CPyDebug()
#NonSerializedObjects = ( "kDebugObj", )

g_kPowerTitleSizes = [6, 6, 6, 6, 6]

###############################################################################
#	CreateMenus(pEngineer)
#	
#	Creates the menu for the engineer. 
#
#	Args:	none
#	
#	Return:	none
###############################################################################
def CreateMenus():
#	kDebugObj.Print("Creating Engineering Menu\n")

	# Get LCARS string.
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	pTopWindow = App.TopWindow_GetTopWindow()
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pMode = App.GraphicsModeInfo_GetCurrentMode()

	fMenuPowerSpacerWidth = 4.0 * App.globals.DEFAULT_ST_INDENT_HORIZ
	fMenuPowerSpacerHeight = 4.0 * App.globals.DEFAULT_ST_INDENT_VERT

	###############################################################################
	# Engineer
	###############################################################################
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	# The pane that contains the rain that falls mainly on the plains in Spain.
	# Actually, this pane contains the menu, as well as the power pane.
	pEngineeringPane = App.TGPane_Create(1.0, 0.50)

	pPowerWindow = App.STStylizedWindow_CreateW("StylizedWindow", "NormalStyle", pDatabase.GetString("Power Transmission Grid"))
	pPowerWindowInterior = pPowerWindow.GetInteriorPane()
	# Don't even try to batch the power display for now :)
	pPowerWindowInterior.GetParent().SetNotBatchChildPolys()
	pPowerWindow.SetMaximumSize(LCARS.POWER_AREA_WIDTH + pPowerWindow.GetBorderWidth(), 1.0)
	pPowerWindow.InteriorChangedSize()
	pPowerWindow.AddPythonFuncHandlerForInstance(App.ET_MOUSE, __name__ + ".PassMouse")

	# Change the background of the power window to be black.
	pPowerWindowExterior = pPowerWindow.GetExteriorPane()
	pGlass1 = App.TGIcon_Cast(pPowerWindowExterior.GetLastChild())
	pGlass2 = App.TGIcon_Cast(pPowerWindowExterior.GetPrevChild(pGlass1))
	pGlass3 = App.TGIcon_Cast(pPowerWindowExterior.GetPrevChild(pGlass2))

	pGlass1.SetColor(App.NiColorA_BLACK)
	pGlass2.SetColor(App.NiColorA_BLACK)
	pGlass3.SetColor(App.NiColorA_BLACK)
	pGlass1.SetIconNum(200)
	pGlass2.SetIconNum(200)
	pGlass3.SetIconNum(200)

	# Engineering main menu
	pEngineeringMenu = App.STTopLevelMenu_CreateW(pDatabase.GetString("Engineering"))
	pEngineeringMenu.Resize(1.0, 1.0, 0)
	pEngineeringMenuPane = App.STStylizedWindow_CreateW("StylizedWindow", "NoMinimize", pDatabase.GetString("Engineering"), 1.0, 1.0)
	pEngineeringMenu.AddPythonFuncHandlerForInstance(App.ET_ST_BUTTON_CLICKED, "Bridge.BridgeMenus.ButtonClicked")

	import Bridge.BridgeMenus
	pCommunicate = Bridge.BridgeMenus.CreateCommunicateButton("Engineer", pEngineeringMenu)
	pEngineeringMenu.AddChild(pCommunicate, 0.0, 0.0, 0)
	pEngineeringMenu.ResizeToContents()

	pRepairPane = App.EngRepairPane_Create(1.0, 0.4, 3)
	pEngineeringMenu.AddChild(pRepairPane, 0.0, 0.0, 0)

	# If in multiplayer, disable all single-player specific buttons	
	if (App.g_kUtopiaModule.IsMultiplayer()):
		pCommunicate.SetDisabled(0)

	pEngineeringMenuPane.AddChild(pEngineeringMenu, 0.0, 0.0, 0)

	# Unload database
	App.g_kLocalizationManager.Unload(pDatabase)

	# Attach the menu pane to the overall pane.
	pEngineeringPane.AddChild(pEngineeringMenuPane, 0.0, 0.0, 0)

	# Attach the power pane to the overall pane.
	pEngineeringPane.AddChild(pPowerWindow, pEngineeringPane.GetWidth() - pPowerWindow.GetMaximumWidth() - (2.0 * App.globals.DEFAULT_ST_INDENT_HORIZ), 
							  2.0 * App.globals.DEFAULT_ST_INDENT_VERT, 0)
	
	# Add power display.
	pPowerDisplay = App.EngPowerDisplay_Create(LCARS.POWER_AREA_WIDTH, LCARS.POWER_AREA_HEIGHT)
	pPowerWindow.AddChild(pPowerDisplay, 0.0, 0.0, 0)
	pPowerWindow.SetUseFocusGlass(1)

	# Change color of the power window's title, and its size also.
	pPowerWindowText = pPowerWindow.GetNameParagraph()
	pPowerWindowText.SetColor(App.NiColorA_WHITE)
	pPowerWindowText.SetFontGroup(App.g_kFontManager.GetFontGroup(App.g_kFontManager.GetDefaultFont().GetFontName(), 
								  g_kPowerTitleSizes[pMode.GetCurrentResolution()]))
	pPowerWindowText.Layout()
	pPowerWindow.InteriorChangedSize(1)

	# We don't want the "skip parent" behavior in this case, because otherwise
	# menu items would think that the window was their parent.
	pEngineeringMenu.SetNoSkipParent()
	
	pTacticalControlWindow.AddChild(pEngineeringPane, 0.0, 0.0, 0)
	pTacticalControlWindow.AddMenuToList(pEngineeringMenu)

	# This has to be down here because TGUIObject's clipping will return
	# a null rect if it isn't attached to the main UI tree...which will cause
	# Layout() to fail.
	pTCWParent = pTacticalControlWindow.GetParent()
	if pTCWParent and (pTCWParent.IsVisible() == 0):
		bWasVisible = 0
		pTCWParent.SetVisible(0)
	else:
		bWasVisible = 1

	# This is here to force the icon group used for backgrounds to draw first.
	pRepairPane.GetNthChild(App.EngRepairPane.DIVIDER).Layout()
	if (bWasVisible == 0) and pTCWParent:
		pTCWParent.SetNotVisible(0)

	pEngineeringPane.SetNotVisible(0)
	pEngineeringMenu.SetNotVisible(0)

	# Add function handlers
	pEngineeringMenu.AddPythonFuncHandlerForInstance(App.ET_REPORT,			"Bridge.EngineerMenuHandlers.Report")
	pEngineeringMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE,	"Bridge.Characters.CommonAnimations.NothingToAdd")

	App.TopWindow_GetTopWindow().AddPythonFuncHandlerForInstance(App.ET_MANAGE_POWER,	__name__ + ".ManagePower")

	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_REPAIR_COMPLETED, pEngineeringPane, __name__ + ".RepairCompleted")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_REPAIR_CANNOT_BE_COMPLETED, pEngineeringPane, __name__ + ".RepairCannotBeCompleted")

###############################################################################
#	ConfigureForShip(pShip)
#	
#	Configures the items in the menu that depend on the ship. For example,
#	the power gauges need to be attached to the ship.
#	
#	Args:	pShip		- the ship
#	
#	Return:	none
###############################################################################
def ConfigureForShip(pShip):
	"Configures the items in the menu that depend on the ship."
#	kDebugObj.Print("Entering EngineerMenuHandlers.ConfigureForShip...")

###############################################################################
#	RepairCompleted(pObject, pEvent)
#	
#	Handles 'repair completed' events for the player's ship.
#	
#	Args:	pObject - the target of the event
#			pEvent - the event that was sent
#	
#	Return:	none
###############################################################################
def RepairCompleted(pObject, pEvent):
	pObject.CallNextHandler(pEvent)
	return

	"Handles 'repair completed' events for the player's ship."
	pPlayer = App.ShipClass_Cast(App.Game_GetCurrentPlayer())
	pSender = App.ShipSubsystem_Cast(pEvent.GetSource())

	if (not pSender) or (pSender.GetParentShip() == None) or (pPlayer == None):
		return

	# Only do talking, etc. for these events on the player's ship.
	if (pSender.GetParentShip().GetObjID() != pPlayer.GetObjID()):
		return

	pSet = App.g_kSetManager.GetSet ("bridge")
	if (not pSet):
		return

	pEngineer = App.CharacterClass_GetObject (pSet, "Engineer")
	if (not pEngineer):
		return

	pSystem = App.ShipSubsystem_Cast(pEvent.GetObjPtr())
	if (not pSystem):
		return

	# Load localization database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")

	if (pSystem.IsTypeOf(App.CT_TORPEDO_SYSTEM)):
		pEngineer.SpeakLine(pDatabase, "ge119", App.CSP_SPONTANEOUS)
	if (pSystem.IsTypeOf(App.CT_PHASER_SYSTEM)):
		pEngineer.SpeakLine(pDatabase, "ge115", App.CSP_SPONTANEOUS)
	if (pSystem.IsTypeOf(App.CT_TRACTOR_BEAM_SYSTEM)):
		pEngineer.SpeakLine(pDatabase, "ge135", App.CSP_SPONTANEOUS)
	if (pSystem.IsTypeOf(App.CT_WARP_ENGINE_SUBSYSTEM)):
		pEngineer.SpeakLine(pDatabase, "ge131", App.CSP_SPONTANEOUS)
	if (pSystem.IsTypeOf(App.CT_IMPULSE_ENGINE_SUBSYSTEM)):
		pEngineer.SpeakLine(pDatabase, "ge127", App.CSP_SPONTANEOUS)
	if (pSystem.IsTypeOf(App.CT_SENSOR_SUBSYSTEM)):
		pEngineer.SpeakLine(pDatabase, "ge123", App.CSP_SPONTANEOUS)
	if (pSystem.IsTypeOf(App.CT_HULL_SUBSYSTEM)):
		pEngineer.SpeakLine(pDatabase, "ge111", App.CSP_SPONTANEOUS)
	if (pSystem.IsTypeOf(App.CT_SHIELD_SUBSYSTEM)):
		pEngineer.SpeakLine(pDatabase, "ge111", App.CSP_SPONTANEOUS)
	if (pSystem.IsTypeOf(App.CT_REPAIR_SUBSYSTEM)):
		pEngineer.SpeakLine(pDatabase, "ge139", App.CSP_SPONTANEOUS)
	
	# Unload database
	App.g_kLocalizationManager.Unload(pDatabase)

	pObject.CallNextHandler(pEvent)

###############################################################################
#	RepairCannotBeCompleted(pObject, pEvent)
#	
#	Handles 'repair cannot be completed' events for the player's ship.
#	
#	Args:	pObject - the target of the event
#			pEvent - the event that was sent
#	
#	Return:	none
###############################################################################
def RepairCannotBeCompleted(pObject, pEvent):
	pObject.CallNextHandler(pEvent)
	return

	"Handles 'repair cannot be completed' events for the player's ship."
	pPlayer = App.ShipClass_Cast(App.Game_GetCurrentPlayer())
	pSender = App.ShipSubsystem_Cast(pEvent.GetSource())

	# Only do talking, etc. for these events on the player's ship.
	if (not pSender):
		return

	if (pSender.GetParentShip() != pPlayer):
		return

	pSet = App.g_kSetManager.GetSet ("bridge")
	pEngineer = App.CharacterClass_GetObject (pSet, "Engineer")

	pObject.CallNextHandler(pEvent)

###############################################################################
#	Report(pObject, pEvent)
#	
#	Reports on the state of the ship or various subsystems.
#	
#	Args:	pObject - the target of the event
#			pEvent - the event that was sent
#	
#	Return:	none
###############################################################################
def Report(pObject, pEvent):
	"Reports on the state of the ship."
	pSet = App.g_kSetManager.GetSet("bridge")
	pEngineer = App.CharacterClass_GetObject(pSet, "Engineer")

	pPlayer = App.ShipClass_Cast(App.Game_GetCurrentPlayer())

	# Load localization database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")

	iType = pEvent.GetInt()

	if (iType == App.CharacterClass.EST_REPORT_OVERVIEW):
		pHull = pPlayer.GetHull()
		if (pHull.GetCombinedConditionPercentage() < 0.75):
			pEngineer.SpeakLine(pDatabase, "ge109", App.CSP_SPONTANEOUS)
		else:
			pEngineer.SpeakLine(pDatabase, "ge111", App.CSP_SPONTANEOUS)
#		kDebugObj.Print("Overview")
	elif (iType == App.CharacterClass.EST_REPORT_ENGINES):
		pEngines = pPlayer.GetImpulseEngineSubsystem()
		if (pEngines.GetCombinedConditionPercentage() < 0.75):
			pEngineer.SpeakLine(pDatabase, "ge125", App.CSP_SPONTANEOUS)
		else:
			pEngineer.SpeakLine(pDatabase, "ge127", App.CSP_SPONTANEOUS)
#		kDebugObj.Print("Engines")
	elif (iType == App.CharacterClass.EST_REPORT_WEAPONS):
		pPhasers = pPlayer.GetPhaserSystem()
		if (pPhasers.GetCombinedConditionPercentage() < 0.75):
			pEngineer.SpeakLine(pDatabase, "ge113", App.CSP_SPONTANEOUS)
		else:
			pEngineer.SpeakLine(pDatabase, "ge115", App.CSP_SPONTANEOUS)
#		kDebugObj.Print("Weapons")
	elif (iType == App.CharacterClass.EST_REPORT_SHIELDS):
		pShields = pPlayer.GetShields()
		if (pShields.GetShieldPercentage() < 0.75):
			pEngineer.SpeakLine(pDatabase, "ge109", App.CSP_SPONTANEOUS)
		else:
			pEngineer.SpeakLine(pDatabase, "ge111", App.CSP_SPONTANEOUS)
#		kDebugObj.Print("Shields")
	elif (iType == App.CharacterClass.EST_REPORT_SENSORS):
		pSensors = pPlayer.GetSensorSubsystem()
		if (pSensors.GetCombinedConditionPercentage() < 0.75):
			pEngineer.SpeakLine(pDatabase, "ge109", App.CSP_SPONTANEOUS)
		else:
			pEngineer.SpeakLine(pDatabase, "ge111", App.CSP_SPONTANEOUS)
#		kDebugObj.Print("Sensors")

	# Unload database
	App.g_kLocalizationManager.Unload(pDatabase)

	pObject.CallNextHandler(pEvent)

###############################################################################
#	TechnobabbleHandler(pShip, pEvent)
#	
#	Handles changing of hull and shields, to occasionally spew technobabble
#	
#	Args:	pShip - the player's ship
#			pEvent - the event that was sent
#	
#	Return:	none
###############################################################################
def TechnobabbleHandler(pShip, pEvent):
	"Handles spewing technobabble"
	if (App.g_kSystemWrapper.GetRandomNumber(15) > 1):
		return

	pSet = App.g_kSetManager.GetSet ("bridge")
	pEngineer = App.CharacterClass_GetObject (pSet, "Engineer")
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")

	pSequence = App.TGSequence_Create()
	pSequence.AddAction(App.CharacterAction_Create(pEngineer, App.CharacterAction.AT_SPEAK_LINE, "EBabble" + str(App.g_kSystemWrapper.GetRandomNumber(4)+1), None, 0, pDatabase, App.CSP_SPONTANEOUS), App.TGAction_CreateNull(), 5.0)
	pSequence.Play()

	# Unload database
	App.g_kLocalizationManager.Unload(pDatabase)

	pShip.CallNextHandler(pEvent)

###############################################################################
#	PassMouse(pWindow, pEvent)
#	
#	Passes mouse events through the power window, but if they come back
#	unhandled, sets them handled. This prevents things like being able to fire
#	phasers or torps on the power display.
#	
#	Args:	pWindow	- the window
#			pEvent	- the mouse event
#	
#	Return:	none
###############################################################################
def PassMouse(pWindow, pEvent):
	pWindow.CallNextHandler(pEvent)

	if pEvent.EventHandled() == 0:
		pEvent.SetHandled()

###############################################################################
#	ManagePower()
#	
#	Use hot-keys to manage our power
#	
#	Args:	pObject, pEvent	- the object and event that called us
#	
#	Return:	none
###############################################################################
def ManagePower(pObject, pEvent):
	if (pEvent.GetInt() >= 8):
		pObject.CallNextHandler(pEvent)
		return

	pPlayer = MissionLib.GetPlayer()
	if not (pPlayer):
		pObject.CallNextHandler(pEvent)
		return

	pSubsystem = None
	pPhasers = None
	pTorps = None
	pPulse = None
	pImpulse = None
	pWarp = None
	if (int(pEvent.GetInt()/2) == 0):
		pPhasers = pPlayer.GetPhaserSystem()
		pTorps = pPlayer.GetTorpedoSystem()
		pPulse = pPlayer.GetPulseWeaponSystem()

		pSubsystem = pPhasers
		if not (pSubsystem):
			pSubsystem = pTorps
			if not (pSubsystem):
				pSubsystem = pPulse

	if (int(pEvent.GetInt()/2) == 1):
		pImpulse = pPlayer.GetImpulseEngineSubsystem()
		pWarp = pPlayer.GetWarpEngineSubsystem()
		pSubsystem = pImpulse

	if (int(pEvent.GetInt()/2) == 2):
		pSubsystem = pPlayer.GetSensorSubsystem()
	if (int(pEvent.GetInt()/2) == 3):
		pSubsystem = pPlayer.GetShields()

	if not (pSubsystem):
		pObject.CallNextHandler(pEvent)
		return

	fPercentWanted = pSubsystem.GetPowerPercentageWanted()
	if (not pSubsystem.IsOn()):
		fPercentWanted = 0.0
	if (pEvent.GetInt()%2 == 0):
		fPercentWanted = fPercentWanted - 0.25
	else:
		fPercentWanted = fPercentWanted + 0.25

	if (fPercentWanted < 0.0):
		fPercentWanted = 0.0
	if (fPercentWanted > 1.25):
		fPercentWanted = 1.25

	if (not pPhasers and not pTorps and not pPulse and not pImpulse and not pWarp):
		SetPowerToSubsystem(pSubsystem, fPercentWanted)
	else:
		SetPowerToSubsystem(pImpulse, fPercentWanted)
		SetPowerToSubsystem(pWarp, fPercentWanted)

		SetPowerToSubsystem(pPhasers, fPercentWanted)
		SetPowerToSubsystem(pTorps, fPercentWanted)
		SetPowerToSubsystem(pPulse, fPercentWanted)

	App.EngPowerCtrl_GetPowerCtrl().Refresh()
	
def SetPowerToSubsystem(pSubsystem, fPercentWanted):
	if not (pSubsystem):
		return

	pSubsystem.SetPowerPercentageWanted(fPercentWanted)

	if (not pSubsystem.IsOn() and fPercentWanted > 0.0):
		pSubsystem.TurnOn()

	if (fPercentWanted == 0.0):
		pSubsystem.TurnOff()

	pPlayer = MissionLib.GetPlayer()

	pPrefsEvent = App.TGFloatEvent_Create()
	pPrefsEvent.SetSource(pSubsystem)
	pPrefsEvent.SetDestination(pPlayer)
	pPrefsEvent.SetEventType(App.ET_SUBSYSTEM_POWER_CHANGED)
	pPrefsEvent.SetFloat(fPercentWanted)
	App.g_kEventManager.AddEvent(pPrefsEvent)
