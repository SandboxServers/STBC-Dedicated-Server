###############################################################################
#	Filename:	XOMenuHandlers.py
#
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#
#	Script to create the first officer's menu, both for Bridge and
#	Tactical views
#
#	Created:	12/26/2000 -	CCarley
###############################################################################

import App
import BridgeUtils

# Create debug object
#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateMenus()
#
#	Creates the first officer's menu. This code must be called BEFORE the
#	first officer is created.
#
#	Args:	none
#
#	Return:	The newly created menu
###############################################################################
def CreateMenus():
#	kDebugObj.Print("Creating XO Menu\n")

	pTopWindow = App.TopWindow_GetTopWindow()
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()

	# Import resolution dependent LCARS module for size/placement variables.
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	###############################################################################
	# XO
	###############################################################################
	#
	#	Commander
	#		Set Alert Level
	#			Green
	#			Yellow
	#			Red
	#		Report
	#		Contact Engineering
	#		Objectives
	#		Contact Starfleet
	#
	###############################################################################

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	#pXOPane = App.TGPane_Create(LCARS.TACTICAL_MENU_WIDTH, LCARS.TACTICAL_MENU_HEIGHT)
	pXOMenu = App.STTopLevelMenu_CreateW(pDatabase.GetString("Commander"))
	pXOPane = App.STStylizedWindow_CreateW("StylizedWindow", "NoMinimize", pDatabase.GetString("Commander"), 0.0, 0.0)
	pXOPane.AddChild(pXOMenu, 0.0, 0.0, 0)

	pXOMenu.AddPythonFuncHandlerForInstance(App.ET_ST_BUTTON_CLICKED, "Bridge.BridgeMenus.ButtonClicked")

	# Communicate
	import BridgeMenus
	pCommunicate = BridgeMenus.CreateCommunicateButton("XO", pXOMenu)
	pXOMenu.AddChild(pCommunicate, 0.0, 0.0, 0)

	# Report
	pReport = BridgeUtils.CreateBridgeMenuButton(pDatabase.GetString("Damage Report"), App.ET_REPORT, 0, pXOMenu)
	pXOMenu.AddChild(pReport, 0.0, 0.0, 0)

	# Alert Levels
	pXOMenu.AddChild(BridgeUtils.CreateBridgeMenuButton(pDatabase.GetString("Green Alert"),		App.ET_SET_ALERT_LEVEL, App.CharacterClass.EST_ALERT_GREEN, pXOMenu), 0.0, 0.0, 0)
	pXOMenu.AddChild(BridgeUtils.CreateBridgeMenuButton(pDatabase.GetString("Yellow Alert"),	App.ET_SET_ALERT_LEVEL, App.CharacterClass.EST_ALERT_YELLOW, pXOMenu), 0.0, 0.0, 0)
	pXOMenu.AddChild(BridgeUtils.CreateBridgeMenuButton(pDatabase.GetString("Red Alert"),		App.ET_SET_ALERT_LEVEL, App.CharacterClass.EST_ALERT_RED, pXOMenu), 0.0, 0.0, 0)

	# Objectives
	pObjectives = App.STCharacterMenu_CreateW(pDatabase.GetString("Objectives"))
	pXOMenu.AddChild(pObjectives, 0.0, 0.0, 0)

	# Mission Log
	pShowLog = BridgeUtils.CreateBridgeMenuButton(pDatabase.GetString("Show Mission Log"),				App.ET_SHOW_MISSION_LOG, 0, pXOMenu)
	pXOMenu.AddChild(pShowLog, 0.0, 0.0, 0)

	# Contact Starfleet
	pContactStarfleet = BridgeUtils.CreateBridgeMenuButton(pDatabase.GetString("Contact Starfleet"),		App.ET_CONTACT_STARFLEET, 0, pXOMenu)
	pXOMenu.AddChild(pContactStarfleet, 0.0, 0.0, 0)

	# Contact Engineering
	pContactEngineering = BridgeUtils.CreateBridgeMenuButton(pDatabase.GetString("Contact Engineering"),	App.ET_CONTACT_ENGINEERING, 0, pXOMenu)
	pXOMenu.AddChild(pContactEngineering, 0.0, 0.0, 0)
	pContactEngineering.SetDisabled()

	# If in multiplayer, disable all single-player specific buttons	
	if (App.g_kUtopiaModule.IsMultiplayer()):
		pReport.SetDisabled()
		pCommunicate.SetDisabled()
		pObjectives.SetDisabled()
		pShowLog.SetDisabled()
		pContactStarfleet.SetDisabled()
		pContactEngineering.SetDisabled()

	###Unload database
	App.g_kLocalizationManager.Unload(pDatabase)

	pXOPane.SetNotVisible()
	pXOMenu.SetNotVisible()

	# We don't want the "skip parent" behavior in this case, because otherwise
	# menu items would think that the window was their parent.
	pXOMenu.SetNoSkipParent()

	# Add the pane to the Top window, so we can see it in both Tactical
	# and Bridge views
	pTacticalControlWindow.AddChild(pXOPane, 0.0, 0.0, 0)
	pTacticalControlWindow.AddMenuToList(pXOMenu)

	# Add Python function handlers.
	pXOMenu.AddPythonFuncHandlerForInstance(App.ET_SET_ALERT_LEVEL,		__name__ + ".SetAlertLevel")
	pXOMenu.AddPythonFuncHandlerForInstance(App.ET_OBJECTIVES,			__name__ + ".Objectives")
	pXOMenu.AddPythonFuncHandlerForInstance(App.ET_CONTACT_ENGINEERING, "Bridge.EngineerCharacterHandlers.ContactEngineering")
	pXOMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE,			"Bridge.Characters.CommonAnimations.NothingToAdd")
	pXOMenu.AddPythonFuncHandlerForInstance(App.ET_SHOW_MISSION_LOG,	__name__ + ".ShowLog")

	return pXOMenu

# XO Functions
# Report, Alert Level, Damage Report, Objectives

###############################################################################
#	SetAlertLevel(pObject, pEvent)
#
#	Handles the "set alert level" menu item.
#
#	Args:	pObject		- the target of the event
#			pEvent		- the event
#	
#	Return:	none
###############################################################################
def SetAlertLevel(pObject, pEvent):
	iType = pEvent.GetInt()

	pGame = App.Game_GetCurrentGame()
	pPlayer = App.ShipClass_Cast(pGame.GetPlayer())

	if (App.IsNull(pPlayer)):
		pObject.CallNextHandler(pEvent)
		return

	iLevel = 0
	if (iType == App.CharacterClass.EST_ALERT_GREEN):
		iLevel = pPlayer.GREEN_ALERT
	if (iType == App.CharacterClass.EST_ALERT_YELLOW):
		iLevel = pPlayer.YELLOW_ALERT
	if (iType == App.CharacterClass.EST_ALERT_RED):
		iLevel = pPlayer.RED_ALERT

	if (iLevel != pPlayer.GetAlertLevel()):
		if (iType == App.CharacterClass.EST_ALERT_GREEN):
			App.TGSoundAction_Create("GreenAlertSound").Play()
		if (iType == App.CharacterClass.EST_ALERT_YELLOW):
			App.TGSoundAction_Create("YellowAlertSound").Play()
		if (iType == App.CharacterClass.EST_ALERT_RED):
			App.TGSoundAction_Create("RedAlertSound").Play()

		# Set up an event to send to the ship, which will change its
		# alert level.
		pAlertEvent = App.TGIntEvent_Create()
		pAlertEvent.SetSource(pObject)
		pAlertEvent.SetDestination(pPlayer)
		pAlertEvent.SetEventType(App.ET_SET_ALERT_LEVEL)
		pAlertEvent.SetInt(iLevel)

		App.g_kEventManager.AddEvent(pAlertEvent)

	pObject.CallNextHandler(pEvent)

###############################################################################
#	Objectives(pObject, pEvent)
#	
#	Handles the "objectives" menu item.
#	
#	Args:	pObject		- the target of the event
#			pEvent		- the event
#	
#	Return:	none
###############################################################################
def Objectives(pObject, pEvent):
#	kDebugObj.Print("XO Objectives\n")

	pObject.CallNextHandler(pEvent)

###############################################################################
#	SetContactEngineeringEnabled()
#	
#	Allow the "Contact Engineering" button to be enabled/disabled
#	
#	Args:	bEnabled	- to be enabled or not
#	
#	Return:	none
###############################################################################
def SetContactEngineeringEnabled(bEnabled):
	pBridge = App.g_kSetManager.GetSet("bridge")
	pXO = App.CharacterClass_GetObject(pBridge, "XO")
	pMenu = pXO.GetMenu()

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	pButton = pMenu.GetButtonW(pDatabase.GetString("Contact Engineering"))
	if (pButton):
		if (bEnabled):
			pButton.SetEnabled()
		else:
			pButton.SetDisabled()

	App.g_kLocalizationManager.Unload(pDatabase)

###############################################################################
#	ShowLog()
#	
#	Shows the current mission log
#	
#	Args:	pObject		- the target of the event
#			pEvent		- the event
#	
#	Return:	none
###############################################################################
def ShowLog(pObject, pEvent):
	pLog = App.STMissionLog_GetMissionLog()
	pTopWindow = App.TopWindow_GetTopWindow()

	App.g_kUtopiaModule.Pause(1)

	pWindow = App.STStylizedWindow_Cast(pLog.GetFirstChild())
	if (pWindow != None):
		# Always show most recent mission log entries when opened.
		pWindow.ScrollToBottom()

	pTopWindow.MoveToFront(pLog)
	pLog.SetVisible()
	pTopWindow.SetFocus(pLog)
	pObject.CallNextHandler(pEvent)

