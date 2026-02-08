###############################################################################
#	Filename:	HelmMenuHandlers.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Script to create the helm menu and handle some of its events.
#	
#	Created:	??/??/???? -	?
###############################################################################

import App
import BridgeUtils
import Systems.Starbase12.Starbase12_S
import Characters.Graff
import MissionLib
import BridgeHandlers

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " module...")

# This module shouldn't be unloaded when missions or
# episodes go away.  Make it persistent at the episode level.
# During serialization/unserialization, the current game will
# be None, and we don't want to call AddPersistentModule then anyways.
pGame = App.Game_GetCurrentGame()
if pGame:
	pEpisode = pGame.GetCurrentEpisode()
	if pEpisode:
		pEpisode.AddPersistentModule(__name__)
	del pEpisode
del pGame
# del's are there because I don't want pEpisode and pGame global variables sticking around.

g_bIgnoreNextAIDone				= 0
g_bShowEnteringBanner			= 1

g_fLastCollisionAlertTime		= 0
g_fLastCollisionAlarmTime		= 0

g_sPrewarpCameraSet = None
g_sPrewarpCameraName = None

#
# ProcessWrapper
#
# PythonMethodProcess objects can't be saved directly.  This allows them to be saved
# and wraps the functionality we want in the constructor.
class ProcessWrapper:
	def __init__(self, sFunctionName, fDelay, ePriority):
		self.sFunctionName = sFunctionName
		self.fDelay = fDelay
		self.ePriority = ePriority

		self.SetupProcess()

	def __getstate__(self):
		dState = self.__dict__.copy()
		del dState["pProcess"]
		return dState

	def __setstate__(self, dict):
		self.__dict__ = dict
		self.SetupProcess()

	def SetupProcess(self):
		self.pProcess = App.PythonMethodProcess()
		self.pProcess.SetInstance(self)
		self.pProcess.SetFunction("ProcessFunc")
		self.pProcess.SetDelay( self.fDelay )
		self.pProcess.SetPriority( self.ePriority )

	def ProcessFunc(self, dTimeAvailable):
		# Call our function.
		pFunc = globals()[self.sFunctionName]
		pFunc(dTimeAvailable)

g_pCollisionCheckProcess	= None
g_pPlayerOrbitting			= None

def SetupFleetCommands():
	global ET_FLEET_COMMAND_RESUME, ET_FLEET_COMMAND_ATTACK_TARGET, ET_FLEET_COMMAND_DISABLE_TARGET
	global ET_FLEET_COMMAND_DEFEND_TARGET, ET_FLEET_COMMAND_HELP_ME, ET_FLEET_COMMAND_CUSTOM
	global ET_FLEET_COMMAND_DOCK_SB12

	# Event types used only in this file.
	ET_FLEET_COMMAND_RESUME			= App.Game_GetNextEventType()
	ET_FLEET_COMMAND_ATTACK_TARGET	= App.Game_GetNextEventType()
	ET_FLEET_COMMAND_DISABLE_TARGET	= App.Game_GetNextEventType()
	ET_FLEET_COMMAND_DEFEND_TARGET	= App.Game_GetNextEventType()
	ET_FLEET_COMMAND_HELP_ME		= App.Game_GetNextEventType()
	ET_FLEET_COMMAND_DOCK_SB12		= App.Game_GetNextEventType()
	ET_FLEET_COMMAND_CUSTOM			= App.Game_GetNextEventType()

	### AVAILABLE FLEET COMMANDS:
	# The strings on the left are the available commands.
	global g_dCommandInfo
	g_dCommandInfo = {
		"AttackTarget":
			(ET_FLEET_COMMAND_ATTACK_TARGET,	"FleetAttackTarget",	"FleetSetupNonFriendlyTargetHandlers",	"FSNFTH_CheckDisabled"),
		"DisableTarget":
			(ET_FLEET_COMMAND_DISABLE_TARGET,	"FleetDisableTarget",	"FleetSetupNonFriendlyTargetHandlers",	"FSNFTH_CheckDisabled"),
		"DefendTarget":
			(ET_FLEET_COMMAND_DEFEND_TARGET,	"FleetDefendTarget",	"FleetSetupTargetHandlers",				"FSTH_CheckDisabled"),
		"HelpMe":
			(ET_FLEET_COMMAND_HELP_ME,			"FleetHelpMe",			None,									None),
		"DockWithStarbase12":
			(ET_FLEET_COMMAND_DOCK_SB12,		"FleetDockSB12",		"FleetSetupInSB12Handlers",				"FSISB12_CheckDisabled")
		}

	# Custom commands.  Links command names with TGL database names and
	# AI creation functions.  The TGL database should be the database
	# that contains the string for the command name..   The AI creation
	# functions are passed two arguments: the ship that's being commanded
	# and the player's current target.
	global g_dCustomCommandInfo
	g_dCustomCommandInfo = {}
	# eg: "FollowMe":	("data/TGL/Bridge Menus.tgl", "Maelstrom.Episode1.E1M8.E1M8.FleetFollowMe"),

	# Information about which ships can be commanded right now,
	# for the Command Fleet menu.
	global g_dCommandableFleet
	g_dCommandableFleet = {}


###############################################################################
#	CreateMenus()
#
#	Creates the helm menu. This code must be called BEFORE the helm
#	officer is created.
#
#	Args:	none
#
#	Return:	The newly created menu
###############################################################################
def CreateMenus():
#	debug("Creating Helm Menu")

	SetupFleetCommands()

	# Event types used just in this file.
	global ET_SET_NAVPOINT_TARGET
	ET_SET_NAVPOINT_TARGET	= App.Game_GetNextEventType()

	pTopWindow = App.TopWindow_GetTopWindow()
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()

	# Get LCARS string.
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	###############################################################################
	# Helm
	###############################################################################
	#
	# Helm
	#	Report
	#	Communicate
	#	Hail
	#	Set Course
	#	Warp
	#	Orbit Planet
	#	Nav Points
	#	Intercept
	#	All Stop
	#	Dock
	#
	###############################################################################

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	#pHelmPane = App.TGPane_Create(LCARS.TACTICAL_MENU_WIDTH, LCARS.TACTICAL_MENU_HEIGHT)
	pHelmMenu = App.STTopLevelMenu_CreateW(pDatabase.GetString("Helm"))
	pHelmPane = App.STStylizedWindow_CreateW("StylizedWindow", "NoMinimize", pDatabase.GetString("Helm"), 0.0, 0.0)
	pHelmPane.AddChild(pHelmMenu, 0.0, 0.0, 0)

	pHelmMenu.AddPythonFuncHandlerForInstance(App.ET_ST_BUTTON_CLICKED,	"Bridge.BridgeMenus.ButtonClicked")

	import BridgeMenus
	pCommunicate = BridgeMenus.CreateCommunicateButton("Helm", pHelmMenu)
	pHelmMenu.AddChild(pCommunicate)
	
	# Hail
	pHail = App.STCharacterMenu_CreateW(pDatabase.GetString("Hail"))
	pHelmMenu.AddChild(pHail)
	AddFleetCommandHandlers(pHail)

	# Add some entered/exited set events so the Hail menu can change accordingly..
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_ENTERED_SET,	pHelmMenu,	__name__ + ".ObjectEnteredSet")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_SENSORS_SHIP_IDENTIFIED,	pHelmMenu,	__name__ + ".ShipIdentified")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_CLOAK_COMPLETED,	pHelmMenu,	__name__ + ".ExitedSet")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_DECLOAK_COMPLETED,	pHelmMenu,	__name__ + ".ShipIdentified")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_EXITED_SET,	pHelmMenu,	__name__ + ".ExitedSet")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_HAILABLE_CHANGE,	pHelmMenu,	__name__ + ".HailableChange")

	# Set Course
	setCourseMenu = App.SortedRegionMenu_CreateW(pDatabase.GetString("Set Course"))
	pHelmMenu.AddChild(setCourseMenu)

	# Warp
	pWarpButton = App.STWarpButton_CreateW(pDatabase.GetString("Warp"))
	pWarpButton.SetWarpTime(5)
	pHelmMenu.AddChild(pWarpButton)
	App.SortedRegionMenu_SetWarpButton(pWarpButton)

	pWarpButton.SetCourseMenu(setCourseMenu)

	# Orbit Planet.
	pOrbitMenu = App.STMenu_CreateW(pDatabase.GetString("Orbit Planet"))
	pOrbitMenu.SetNotOpenable()
	pOrbitMenu.SetDisabled()
	pHelmMenu.AddChild(pOrbitMenu)

	# Nav Points
	pNavPointMenu = App.STMenu_CreateW(pDatabase.GetString("Nav Points"))
	pNavPointMenu.SetNotOpenable()
	pNavPointMenu.SetDisabled()
	pHelmMenu.AddChild(pNavPointMenu)

	# Intercept.
	pIntercept = BridgeUtils.CreateBridgeMenuButton(pDatabase.GetString("Intercept"), App.ET_SET_COURSE, App.CharacterClass.EST_SET_COURSE_INTERCEPT, pHelmMenu)
	pHelmMenu.AddChild(pIntercept)
	pIntercept.SetDisabled()

	# All Stop.
	pAllStop = BridgeUtils.CreateBridgeMenuButton(pDatabase.GetString("All Stop"), App.ET_ALL_STOP, 0, pHelmMenu)
	pHelmMenu.AddChild(pAllStop)

	# Dock.
	pDockButton = BridgeUtils.CreateBridgeMenuButton(pDatabase.GetString("Dock"), App.ET_DOCK, 0, pHelmMenu)
	pHelmMenu.AddChild(pDockButton)
	pDockButton.SetDisabled()

	# If in multiplayer, disable all single-player specific buttons	
	if (App.g_kUtopiaModule.IsMultiplayer()):
		pCommunicate.SetDisabled()
		pHail.SetDisabled()

	###Unload database
	App.g_kLocalizationManager.Unload(pDatabase)

	pHelmPane.SetNotVisible()
	pHelmMenu.SetNotVisible()

	# We don't want the "skip parent" behavior in this case, because otherwise
	# menu items would think that the window was their parent.
	pHelmMenu.SetNoSkipParent()

	pTacticalControlWindow.AddChild(pHelmPane, 0.0, 0.0)
	pTacticalControlWindow.AddMenuToList(pHelmMenu)

	# Setup handlers for events
	pHelmMenu.AddPythonFuncHandlerForInstance(App.ET_SET_COURSE,			__name__ + ".SetCourse")
	pHelmMenu.AddPythonFuncHandlerForInstance(App.ET_DOCK,					__name__ + ".Dock")
	pHelmMenu.AddPythonFuncHandlerForInstance(App.ET_HAIL,					__name__ + ".Hail")
	pHelmMenu.AddPythonFuncHandlerForInstance(App.ET_ALL_STOP,				__name__ + ".AllStop")
	pHelmMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE,			"Bridge.Characters.CommonAnimations.NothingToAdd")

	pWarpButton = App.SortedRegionMenu_GetWarpButton()
	if (pWarpButton):
		pWarpButton.AddPythonFuncHandlerForInstance(App.ET_WARP_BUTTON_PRESSED,	__name__ + ".WarpPressed")

	# Setup handlers for the orbit and nav points menus.
	SetupOrbitAndNavMenuHandlers(pOrbitMenu, pNavPointMenu)

	# Set up a time slice process to check for collisions
	global g_pCollisionCheckProcess
	if not (g_pCollisionCheckProcess):
		g_pCollisionCheckProcess = ProcessWrapper("CollisionAlertCheck", 5.0, App.TimeSliceProcess.LOW)

	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_SET_PLAYER, pHelmMenu, __name__ + ".SetPlayer")
	SetPlayer(None, None)

	return pHelmMenu

def SetPlayer(pObject, pEvent):
	pShip = MissionLib.GetPlayer()
	if (pShip):
#		debug("Able to get ship")
		pShip.AddPythonFuncHandlerForInstance(App.ET_TARGET_WAS_CHANGED,	__name__ + ".TargetChanged")
		pShip.AddPythonFuncHandlerForInstance(App.ET_SET_TARGET,			__name__ + ".TargetChanged")
		pShip.AddPythonFuncHandlerForInstance(App.ET_CLOAKED_COLLISION,		__name__ + ".CloakedCollision")

#		print("Creating condition script")
		global g_pPlayerOrbitting

		if (g_pPlayerOrbitting):
#			debug("Destroying player orbitting conditional")
			g_pPlayerOrbitting = None

		g_pPlayerOrbitting = App.ConditionScript_Create("Conditions.ConditionPlayerOrbitting", "ConditionPlayerOrbitting")
#		print("Calling Mission Lib")
		MissionLib.CallFunctionWhenConditionChanges(pShip, __name__, "Orbitting", g_pPlayerOrbitting)
#	else:
#		debug("Unable to get ship")

	if (pObject and pEvent):
		pObject.CallNextHandler(pEvent)

###############################################################################
#	TargetChanged()
#	
#	Update the useability of the "Intercept" button
#	
#	Args:	pObject, pEvent	- the object and event that called us
#	
#	Return:	none
###############################################################################
def TargetChanged(pObject, pEvent):
	import Bridge.BridgeMenus

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()

	pHelmMenu = pTacticalControlWindow.FindMenu(pDatabase.GetString("Helm"))

	if (pHelmMenu):
		pIntercept = pHelmMenu.GetButtonW(pDatabase.GetString("Intercept"))
		if (pIntercept):
			pShip = MissionLib.GetPlayer()
			if (pShip):
				if (pShip.GetTarget()):
					if (BridgeUtils.g_bInterceptEnabled):
						pIntercept.SetEnabled()
				else:
					pIntercept.SetDisabled()
			else:
#				debug("Unable to get player, disabling Intercept")
				pIntercept.SetDisabled()

	App.g_kLocalizationManager.Unload(pDatabase)

	if (pObject and pEvent):
		pObject.CallNextHandler(pEvent)

###############################################################################
#	Orbitting()
#	
#	Called when a player changes their orbitting state
#	
#	Args:	iCondition	- the state of the condition that called us
#	
#	Return:	none
###############################################################################
def Orbitting(iCondition):
	pSequence = App.TGSequence_Create()
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "AnnounceOrbit"), 0.5)
	pSequence.Play()

def AnnounceOrbit(pAction):
	pSet = App.g_kSetManager.GetSet("bridge")
	pCharacter = App.CharacterClass_GetObject(pSet, "Helm")
	if not (pCharacter):
#		debug("No helmsman")
		return 0

	global g_pPlayerOrbitting
	if not (g_pPlayerOrbitting):
#		debug("No conditional")
		return 0

	if (g_pPlayerOrbitting.GetStatus()):
		App.CharacterAction_Create(pCharacter, App.CharacterAction.AT_SAY_LINE, "EnteringOrbit", None, 1).Play()
	else:
		App.CharacterAction_Create(pCharacter, App.CharacterAction.AT_SAY_LINE, "KiskaLeaveOrbit", None, 1).Play()

	return 0


###############################################################################
#	ObjectEnteredSet()
#	
#	An object entered a set.  If it's the player, have a text banner pop up.
#	This can be called as a function, as well.
#	
#	Args:	pObject	- the target of the event, if called as an event handler.
#					  Otherwise, the object that entered the set.
#			pEvent	- the event that called us
#	
#	Return:	none
###############################################################################
def ObjectEnteredSet(pObject, pEvent = None):
	######## NOTE: This can be called as a function as well as an event
	######## handler. (called from when ships are removed from the commandable
	######## list)
	pTop = App.TopWindow_GetTopWindow()
	pOptions = pTop.FindMainWindow(App.MWT_OPTIONS)

	if (pEvent != None):
		pObj = App.ObjectClass_Cast(pEvent.GetDestination())
	else:
		pObj = App.ObjectClass_Cast(pObject)

	pPlayer = MissionLib.GetPlayer()
	if (pPlayer and pObj):
		pSet = pPlayer.GetContainingSet()
		pObjSet = pObj.GetContainingSet()

		if (pObj.GetObjID() == pPlayer.GetObjID()):
			global g_bShowEnteringBanner
			if (pSet and g_bShowEnteringBanner):
				# Put up text banner announcing ship entrance..
				kName = App.TGString()
				pSet.GetDisplayName(kName)
				pDatabase = App.g_kLocalizationManager.Load("data/TGL/Systems.tgl")
				if (pSet.GetName() != "warp") and (pOptions.IsCompletelyVisible() == 0):
					MissionLib.TextBanner(None, pDatabase.GetString("Entering").Append(kName), 0, 0.35)
				App.g_kLocalizationManager.Unload(pDatabase)
			g_bShowEnteringBanner = 1

			# Now also go through all other objects
			pSensors = pPlayer.GetSensorSubsystem()
			if (pSet):
				pIteratedObject = pSet.GetFirstObject()
				pFirstObject = pSet.GetFirstObject()
				while (pIteratedObject != None):
					if (pIteratedObject and pIteratedObject.GetObjID() != pPlayer.GetObjID()):
						if (g_dCommandableFleet.has_key(pIteratedObject.GetName())):
							ShipIdentified(pIteratedObject, None)
						elif (pSensors != None):
							if (pSensors.IsObjectKnown(pIteratedObject) == 1):
								ShipIdentified(pIteratedObject, None)

					pIteratedObject = pSet.GetNextObject(pIteratedObject.GetObjID())

					if (pIteratedObject.GetObjID() == pFirstObject.GetObjID()):
						pIteratedObject = None

		elif (pSet and pObjSet)  and  (pSet.GetObjID() == pObjSet.GetObjID()):
			# The object has entered the set where the player is.
			pSensors = pPlayer.GetSensorSubsystem()
			if (g_dCommandableFleet.has_key(pObj.GetName())):
				ShipIdentified(pObj, None)
			elif (pSensors != None):
				if (pSensors.IsObjectKnown(pObj) == 1):
					ShipIdentified(pObj, None)

	if (pEvent != None):
		pObject.CallNextHandler(pEvent)


###############################################################################
#	CreateHailButton()
#	
#	Creates a button to hail an object
#	
#	Args:	pObject		- object to hail
#			bUseHail	- use the word Hail (commandable ships) or just the name
#	
#	Return:	pHailButton - new button
###############################################################################
def CreateHailButton(pObject, bUseHail = 0):
	pObject = App.ObjectClass_Cast(pObject)
	if not (pObject):
		return None

	if (pObject.IsHailable() == 0):
		return None

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pHelmMenu = pTacticalControlWindow.FindMenu(pDatabase.GetString("Helm"))

	pHailMenu = MissionLib.GetCharacterSubmenu("Helm", "Hail")

	pButton = pHailMenu.GetButtonW(pObject.GetDisplayName())
	if (pButton):
		App.g_kLocalizationManager.Unload(pDatabase)
		return None

	if (bUseHail == 0):
		pHailButton = App.STButton_CreateW(pObject.GetDisplayName())
	else:
		pHailButton = App.STButton_CreateW(pDatabase.GetString("Hail"))

	App.g_kLocalizationManager.Unload(pDatabase)

	pHailEvent = App.TGObjPtrEvent_Create()
	pHailEvent.SetSource(pObject)
	pHailEvent.SetDestination(pHelmMenu)
	pHailEvent.SetObjPtr(pObject)
	pHailEvent.SetEventType(App.ET_HAIL)

	pHailButton.SetActivationEvent(pHailEvent)

	return pHailButton


###############################################################################
#	ShipIdentified()
#	
#	Called when a ship has been identified
#	
#	Args:	pObject, pEvent	- the object and event that called us
#	
#	Return:	none
###############################################################################
def ShipIdentified(pObject, pEvent):
	if (pEvent):
		pIdentifiedObject = App.ObjectClass_Cast(pEvent.GetDestination())
	else:
		pIdentifiedObject = App.ObjectClass_Cast(pObject)

	if (not pIdentifiedObject)  or  (pIdentifiedObject.GetName() is None):
		if (pObject and pEvent):
			pObject.CallNextHandler(pEvent)
		return

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pHelmMenu = pTacticalControlWindow.FindMenu(pDatabase.GetString("Helm"))
	App.g_kLocalizationManager.Unload(pDatabase)

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pHailMenu = pHelmMenu.GetSubmenuW(pDatabase.GetString("Hail"))
	App.g_kLocalizationManager.Unload(pDatabase)

	if (g_dCommandableFleet.has_key(pIdentifiedObject.GetName()) and
		(pHailMenu.GetSubmenuW(pIdentifiedObject.GetDisplayName()) != None)):
		if (pObject and pEvent):
			pObject.CallNextHandler(pEvent)
		return

	if (pHailMenu.GetSubmenuW(pIdentifiedObject.GetDisplayName())):
		if (pObject and pEvent):
			pObject.CallNextHandler(pEvent)
		return

	if (pHailMenu.GetButtonW(pIdentifiedObject.GetDisplayName())):
		if (pObject and pEvent):
			pObject.CallNextHandler(pEvent)
		return

	pShip = App.ShipClass_Cast(pIdentifiedObject)
	bCreateButton = 0

	# If it's not a ship, or it's not cloaked, then make
	# a button for it. (CreateHailButton() will check to see if it's
	# hailable or not.)
	if (pShip == None) or (not pShip.IsCloaked()):
		bCreateButton = 1

	if (bCreateButton == 1):
		if (pShip != None) and (g_dCommandableFleet.has_key(pShip.GetName())):
			# Add it to the fleet command menu with the appropriate
			# commands.
			AddShipToFleetCommandMenu(pShip, g_dCommandableFleet[pShip.GetName()])
		else:
			# Add a regular hail button.
			pSequence = App.TGSequence_Create()
			pSequence.AppendAction(App.TGScriptAction_Create(__name__, "AddHailButton", pIdentifiedObject.GetObjID()), 1)
			pSequence.Play()

	if (pObject and pEvent):
		pObject.CallNextHandler(pEvent)

###############################################################################
#	AddHailButton()
#	
#	Adds a hail button for a ship
#	
#	Args:	pAction		- the action that called us
#			idObject	- the object to add a button for
#	
#	Return:	0			- to continue the sequence
###############################################################################
def AddHailButton(pAction, idObject):
	pObject = App.ObjectClass_Cast(App.TGObject_GetTGObjectPtr(idObject))
	if not (pObject):
		return 0

	pButton = CreateHailButton(pObject)

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pHelmMenu = pTacticalControlWindow.FindMenu(pDatabase.GetString("Helm"))

	pHailMenu = MissionLib.GetCharacterSubmenu("Helm", "Hail")

	App.g_kLocalizationManager.Unload(pDatabase)

	if pButton:
		pHailMenu.AddChild(pButton)

	return 0

###############################################################################
#	ExitedSet()
#	
#	An object exited the set.  If it's the player, clear the menu.  If not,
#	do special case handling to remove the button for the ship
#	
#	Args:	pObject, pEvent	- items that called us
#	
#	Return:	none
###############################################################################
def ExitedSet(pObject, pEvent = None):
	pOriginalObject = pObject

	if (pEvent):
		pObject = App.ObjectClass_Cast(pEvent.GetDestination())
	else:
		pObject = App.ObjectClass_Cast(pObject)

	if (pObject):
		pPlayer = MissionLib.GetPlayer()

		pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
		pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
		pHelmMenu = pTacticalControlWindow.FindMenu(pDatabase.GetString("Helm"))
		pHailMenu = pHelmMenu.GetSubmenuW(pDatabase.GetString("Hail"))
		App.g_kLocalizationManager.Unload(pDatabase)

		if (pPlayer is None)  or  (pPlayer.GetObjID() == pObject.GetObjID()):
			# Clear the menu
			pHailMenu.KillChildren()
		else:
			if (pObject.GetName()):
				pItem = None

				if (g_dCommandableFleet.has_key(pObject.GetName())):
					pItem = pHailMenu.GetSubmenuW(pObject.GetDisplayName())
				else:
					pItem = pHailMenu.GetButtonW(pObject.GetDisplayName())

				if (pItem):
					pHailMenu.DeleteChild(pItem)

	if (pOriginalObject and pEvent):
		pOriginalObject.CallNextHandler(pEvent)

###############################################################################
#	HailableChange()
#	
#	The 'hailability' of an object changed - update the menu accordingly
#	
#	Args:	pObject, pEvent	- the object and event that called us
#	
#	Return:	none
###############################################################################
def HailableChange(pObject, pEvent):
	pHailObj = App.ObjectClass_Cast(pEvent.GetSource())
	if (pEvent.GetBool()):
		ObjectEnteredSet(pHailObj)
	else:
		ExitedSet(pHailObj)

	pObject.CallNextHandler(pEvent)

###############################################################################
#	SetCourse(pObject, pEvent)
#
#	Handles the "set course" menu item.
#
#	Args:	pObject		- the target of the event
#			pEvent		- the event
#
#	Return:	none
###############################################################################
def SetCourse(pObject, pEvent):
	iType = pEvent.GetInt()
	if (iType == App.CharacterClass.EST_SET_COURSE_INTERCEPT):
		pGame = App.Game_GetCurrentGame()
		pPlayer = pGame.GetPlayer()
		if pPlayer == None:
			return

		pTarget = pPlayer.GetTarget()

		if (pTarget == None):
			return

		# If we're inside starbase 12, don't follow orders.
		if MissionLib.IsPlayerInsideStarbase12():
			return

		if pPlayer.GetAI():
			# Player has AI right now.  Setting this AI will trigger an AI_DONE
			# event for the old AI, and we want Helm to ignore that event.
			global g_bIgnoreNextAIDone
			g_bIgnoreNextAIDone = 1

		import AI.Player.InterceptTarget
		MissionLib.SetPlayerAI("Helm", AI.Player.InterceptTarget.CreateAI(pPlayer, pTarget))

	pObject.CallNextHandler(pEvent)

###############################################################################
#	Dock(pObject, pEvent)
#
#	Handles the "Dock" menu item.
#
#	Args:	pObject		- the target of the event
#			pEvent		- the event
#
#	Return:	none
###############################################################################
def Dock(pObject, pEvent):	
	# Just call Starbase 12 docking function for now..
	# Change this to handle general docking.

	pPlayer = App.Game_GetCurrentPlayer()
	if pPlayer:
		if pPlayer.GetAI():
			# Player has AI right now.  Setting this AI will trigger an AI_DONE
			# event for the old AI, and we want Helm to ignore that event.
			global g_bIgnoreNextAIDone
			g_bIgnoreNextAIDone = 1

		Systems.Starbase12.Starbase12_S.DockStarbase()

	pObject.CallNextHandler(pEvent)
	BridgeHandlers.DropMenusTurnBack()

###############################################################################
#	WarpPressed(pObject, pEvent)
#
#	When the warp button is pressed, drop the menu and turn back
#
#	Args:	pObject		- the target of the event
#			pEvent		- the event
#
#	Return:	none
###############################################################################
def WarpPressed(pObject, pEvent):
	pShip = MissionLib.GetPlayer()
	if not (pShip):
#		debug("No player")
		return

	pHelm = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Helm")
	pImpulseEngines = pShip.GetImpulseEngineSubsystem()
	if not pImpulseEngines:
		pObject.CallNextHandler(pEvent)
		return

	if (pImpulseEngines.GetPowerPercentageWanted() == 0.0):
		# Player is trying to warp with their engines off.
		pXO = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "XO")
		if pXO:
			MissionLib.QueueActionToPlay(App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "EngineeringNeedPowerToEngines", None, 1))
		#pObject.CallNextHandler(pEvent)
		return

	pWarpEngines = pShip.GetWarpEngineSubsystem()
	if (pWarpEngines):
		if (pWarpEngines.IsDisabled()):
#			debug("Warp engines disabled")
			if (pHelm):
				App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "CantWarp1", None, 1).Play()
			else:
				# No character, display subtitle only.
				pDatabase = App.g_kLocalizationManager.Load ("data/TGL/Bridge Crew General.tgl")
				if (pDatabase):
					pSequence = App.TGSequence_Create ()
					pSubtitleAction = App.SubtitleAction_Create (pDatabase, "CantWarp1")
					pSubtitleAction.SetDuration (3.0)
					pSequence.AddAction (pSubtitleAction)
					pSequence.Play ()
					App.g_kLocalizationManager.Unload (pDatabase)
			return

		if not (pWarpEngines.IsOn()):
#			debug("Warp engines turned off")
			if (pHelm):
				App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "CantWarp5", None, 1).Play()
			else:
				# No character, display subtitle only.
				pDatabase = App.g_kLocalizationManager.Load ("data/TGL/Bridge Crew General.tgl")
				if (pDatabase):
					pSequence = App.TGSequence_Create ()
					pSubtitleAction = App.SubtitleAction_Create (pDatabase, "CantWarp5")
					pSubtitleAction.SetDuration (3.0)
					pSequence.AddAction (pSubtitleAction)
					pSequence.Play ()
					App.g_kLocalizationManager.Unload (pDatabase)
			return
	else:
#		debug("Can't find the warp engine subsystem")
		return

	# See if we are in a nebula
	pSet = pShip.GetContainingSet()
	pNebula = pSet.GetNebula()
	if (pNebula):
		if (pNebula.IsObjectInNebula(pShip)):
#			debug("In a nebula")
			if (pHelm):
				App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "CantWarp2", None, 1).Play()
			else:
				# No character, display subtitle only.
				pDatabase = App.g_kLocalizationManager.Load ("data/TGL/Bridge Crew General.tgl")
				if (pDatabase):
					pSequence = App.TGSequence_Create ()
					pSubtitleAction = App.SubtitleAction_Create (pDatabase, "CantWarp2")
					pSubtitleAction.SetDuration (3.0)
					pSequence.AddAction (pSubtitleAction)
					pSequence.Play ()
					App.g_kLocalizationManager.Unload (pDatabase)
				
			return

	# See if we are in an asteroid field
	AsteroidFields = pSet.GetClassObjectList(App.CT_ASTEROID_FIELD)
	for i in AsteroidFields:
		pField = App.AsteroidField_Cast(i)
		if pField:
			if pField.IsShipInside(pShip):
#				debug("In an asteroid field")
				if pHelm:
					App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "CantWarp4", None, 1).Play()
				else:
					# No character, display subtitle only.
					pDatabase = App.g_kLocalizationManager.Load ("data/TGL/Bridge Crew General.tgl")
					if (pDatabase):
						pSequence = App.TGSequence_Create ()
						pSubtitleAction = App.SubtitleAction_Create (pDatabase, "CantWarp4")
						pSubtitleAction.SetDuration (3.0)
						pSequence.AddAction (pSubtitleAction)
						pSequence.Play ()
						App.g_kLocalizationManager.Unload (pDatabase)
				return
					
	pStarbase12Set = App.g_kSetManager.GetSet("Starbase12")
	if (pStarbase12Set):
		if (pShip.GetContainingSet()):
			if (pStarbase12Set.GetObjID() == pShip.GetContainingSet().GetObjID()):
				pStarbase12 = App.ShipClass_GetObject(pStarbase12Set, "Starbase 12")
				if (pStarbase12):
					import AI.Compound.DockWithStarbase
					if (AI.Compound.DockWithStarbase.IsInViewOfInsidePoints(pShip, pStarbase12)):
#						debug("In a starbase")
						if (pHelm):
							App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "CantWarp3", None, 1).Play()
						else:
							# No character, display subtitle only.
							pDatabase = App.g_kLocalizationManager.Load ("data/TGL/Bridge Crew General.tgl")
							if (pDatabase):
								pSequence = App.TGSequence_Create ()
								pSubtitleAction = App.SubtitleAction_Create (pDatabase, "CantWarp3")
								pSubtitleAction.SetDuration (3.0)
								pSequence.AddAction (pSubtitleAction)
								pSequence.Play ()
								App.g_kLocalizationManager.Unload (pDatabase)
						return

	if pShip.GetAI():
		# Player has AI right now.  Setting this AI will trigger an AI_DONE
		# event for the old AI, and we want Helm to ignore that event.
		global g_bIgnoreNextAIDone
		g_bIgnoreNextAIDone = 1

	# Get the helm menu and disable it while we're warping
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pHelmMenu = pTacticalControlWindow.FindMenu(pDatabase.GetString("Helm"))
	App.g_kLocalizationManager.Unload(pDatabase)

	pHelmMenu.SetDisabled()

	BridgeHandlers.DropMenusTurnBack()

	#MissionLib.RemoveControl(None)

	if (pHelm):
		pHelm.SetActive(1)

		App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, pHelm.GetCharacterName() + "Yes" + str(App.g_kSystemWrapper.GetRandomNumber(4)+1), None, 1).Play()

		pDatabase = App.g_kLocalizationManager.Load("data/TGL/CharacterStatus.tgl")
		pHelm.SetStatus(pDatabase.GetString("Waiting"))
		App.g_kLocalizationManager.Unload(pDatabase)

	# Remove player control, so they don't screw us up - the Warp Sequence will give it back in time
	App.TGScriptAction_Create("Actions.CameraScriptActions", "StartCinematicMode", 0).Play()
	MissionLib.RemoveControl()

	# Set up the correct cutscene camera. Generate a side offset for the camera, for a little
	# variety.
	fSideOffset = (App.g_kSystemWrapper.GetRandomNumber(1400) - 700) / 100.0
	pSeq = App.TGSequence_Create()
	pSeq.AddAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", 
											 pSet.GetName(), "PreWarpCutsceneCamera"))
	pSeq.AddAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "DropAndWatch", 
											 pSet.GetName(), pShip.GetName()))
	pSeq.AddAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "SetModeAttribute",
											 pSet.GetName(), "PreWarpCutsceneCamera", "DropAndWatch",
											 "SetAttrFloat", "AwayDistance", 100000.0))
	pSeq.AddAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "SetModeAttribute",
											 pSet.GetName(), "PreWarpCutsceneCamera", "DropAndWatch",
											 "SetAttrFloat", "ForwardOffset", -7.0))
	pSeq.AddAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "SetModeAttribute",
											 pSet.GetName(), "PreWarpCutsceneCamera", "DropAndWatch",
											 "SetAttrFloat", "SideOffset", fSideOffset))
	pSeq.AddAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "SetModeAttribute",
											 pSet.GetName(), "PreWarpCutsceneCamera", "DropAndWatch",
											 "SetAttrFloat", "RangeAngle1", 230.0))
	pSeq.AddAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "SetModeAttribute",
											 pSet.GetName(), "PreWarpCutsceneCamera", "DropAndWatch",
											 "SetAttrFloat", "RangeAngle2", 310.0))
	pSeq.AddAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "SetModeAttribute",
											 pSet.GetName(), "PreWarpCutsceneCamera", "DropAndWatch",
											 "SetAttrFloat", "RangeAngle3", -10.0))
	pSeq.AddAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "SetModeAttribute",
											 pSet.GetName(), "PreWarpCutsceneCamera", "DropAndWatch",
											 "SetAttrFloat", "RangeAngle4", 10.0))
	pSeq.AddAction(App.TGScriptAction_Create("WarpSequence", "FixCamera", pSet.GetName(), "PreWarpCutsceneCamera"))

	pSeq.Play()

	global g_sPrewarpCameraSet, g_sPrewarpCameraName
	g_sPrewarpCameraSet = pSet.GetName()
	g_sPrewarpCameraName = "PreWarpCutsceneCamera"

	pObject.CallNextHandler(pEvent)

def PostWarpEnableMenu(pAction = None):
	# Clear out the old camera.
	try:
		if g_sPrewarpCameraSet and g_sPrewarpCameraName:
			import Actions.CameraScriptActions
			Actions.CameraScriptActions.CutsceneCameraEnd(None, g_sPrewarpCameraSet, g_sPrewarpCameraName)
	except:
		pass

	# Get the helm menu and enablesable it after warping
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pHelmMenu = pTacticalControlWindow.FindMenu(pDatabase.GetString("Helm"))
	App.g_kLocalizationManager.Unload(pDatabase)

	if (pHelmMenu):
		pHelmMenu.SetEnabled()

	# Clear the player's target, and the persistent target info
	# in the target menu, so that we don't retarget the same thing
	# when we return to the old set (or if the object follows us
	# to the new set).  People thought this behavior was strange.
	pPlayer = App.Game_GetCurrentPlayer()
	if pPlayer:
		pPlayer.SetTarget(None)

		# Get the target menu, and clear its persistent target information.
		pTargetMenu = App.STTargetMenu_GetTargetMenu()
		if pTargetMenu:
			pTargetMenu.ClearPersistentTarget()

	return 0

###############################################################################
#	SetupOrbitAndNavMenuHandlers
#	
#	The orbit menu needs to react when the player moves to a new
#	set, so it can add planets from that set and remove old entries
#	in the menu.
#	
#	Args:	pOrbitMenu	- The root of the Orbit menu.
#		pNavMenu	- Root of the Nav Points menu.
#	
#	Return:	None
###############################################################################
def SetupOrbitAndNavMenuHandlers(pOrbitMenu, pNavMenu):
	# Listen for when the player changes.
	App.g_kEventManager.AddBroadcastPythonFuncHandler(
		App.ET_SET_PLAYER,
		pOrbitMenu,
		__name__ + ".OrbitMenuPlayerChanged")

	# If the player exists right now, listen for when it enters a new set.
	SetupOrbitMenuPlayerSetHandler(pOrbitMenu)

	# Setup our handler for when the player clicks on one of the
	# planets in the Orbit Planet menu.
	pOrbitMenu.AddPythonFuncHandlerForInstance(App.ET_ORBIT_PLANET, __name__ + ".OrbitPlanet")

	pNavMenu.AddPythonFuncHandlerForInstance(ET_SET_NAVPOINT_TARGET, __name__ + ".SetNavPointTarget")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_NAV_POINT_CHANGED, pNavMenu, __name__ + ".NavPointChanged")

	# If the player exists in a set right now, add planets from that set.
	pGame = App.Game_GetCurrentGame()
	if pGame:
		pSet = pGame.GetPlayerSet()
		if pSet:
			SetupOrbitMenuFromSet(pOrbitMenu, pSet)
			SetupNavPointsMenuFromSet(pSet)

###############################################################################
#	SetupOrbitMenuPlayerSetHandler
#	
#	Setup a handler that listens for when the player enters a new set.
#	
#	Args:	pOrbitMenu	- The orbit menu.
#	
#	Return:	None
###############################################################################
def SetupOrbitMenuPlayerSetHandler(pOrbitMenu):
	# Get the player, if the player exits.
	pPlayer = App.Game_GetCurrentPlayer()
	if pPlayer:
		# The player exists.  Listen for ET_ENTERED_SET events for the player.
		App.g_kEventManager.AddBroadcastPythonFuncHandler(
			App.ET_ENTERED_SET,
			pOrbitMenu,
			__name__ + ".OrbitMenuPlayerEnteredSet",
			pPlayer)

###############################################################################
#	SetupOrbitMenuFromSet
#	
#	Clear out any old entries in the Orbit Planet menu and add
#	entries for any planets in the given set.
#	
#	Args:	pOrbitMenu	- The root of the orbit menu.
#			pSet		- Set in which to look for planets.
#	
#	Return:	None
###############################################################################
def SetupOrbitMenuFromSet(pOrbitMenu, pSet):
	bOpenable = 0

	#debug("Setting up orbit menu from set: " + pSet.GetName())
	pPlayer = App.Game_GetCurrentPlayer()
	pSensors = None
	if pPlayer:
		pSensors = pPlayer.GetSensorSubsystem()

	# Clear out old entries.
	pOrbitMenu.KillChildren()

	# Look for new entries.
	lPlanets = pSet.GetClassObjectList(App.CT_PLANET)
	if lPlanets:
		for pPlanet in lPlanets:
			# If this is a sun, skip it.
			if pPlanet.IsTypeOf(App.CT_SUN):
				continue

			# Make a new button for this planet.
			# First create an event for that button.
			pEvent = App.TGEvent_Create()
			pEvent.SetEventType(App.ET_ORBIT_PLANET)
			pEvent.SetSource(pPlanet)
			pEvent.SetDestination(pOrbitMenu)

			# Now create the button..
			#debug("Adding planet \"%s\" to the orbit menu" % (pPlanet.GetName()))
			pButton = App.STButton_CreateW(pPlanet.GetDisplayName(), pEvent)
			pOrbitMenu.AddChild(pButton, 0, 0, 0)
			bOpenable = 1

			# Make sure this planet is marked as Identified for the player,
			# so the player can target it.  (All planets are automatically
			# targetable).
			if pSensors:
				pSensors.ForceObjectIdentified(pPlanet)

	if bOpenable:
		#debug("Orbit menu is openable.")
		pOrbitMenu.SetOpenable()
		pOrbitMenu.SetEnabled()
	else:
		#debug("Orbit menu is not openable.")
		pOrbitMenu.SetNotOpenable()
		pOrbitMenu.SetDisabled()

###############################################################################
#	SetupNavPointsMenuFromSet
#	
#	Clear out any old entries in the Nav Points menu and add
#	entries for any planets in the given set.
#	
#	Args:	pSet		- Set in which to look for planets.
#	
#	Return:	None
###############################################################################
def SetupNavPointsMenuFromSet(pSet):
	bOpenable = 0

	# Get the Nav Points menu...
	pTopWindow = App.TopWindow_GetTopWindow()
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pMenu = pTacticalControlWindow.FindMenu(pDatabase.GetString ("Helm"))
	pNavPointMenu = App.STMenu_Cast(pMenu.GetSubmenuW(pDatabase.GetString("Nav Points")))
	App.g_kLocalizationManager.Unload(pDatabase)

	if not pNavPointMenu:
#		debug(__name__ + ": ERROR, couldn't get Nav Points menu.")
		return

	# Clear out old entries.
	pNavPointMenu.KillChildren()

	# Look for new entries.
	lNavPoints = pSet.GetNavPoints()
	for pNavPoint in lNavPoints:
		# Make a new button for this planet.
		# First create an event for that button.
		pEvent = App.TGEvent_Create()
		pEvent.SetEventType(ET_SET_NAVPOINT_TARGET)
		pEvent.SetSource(pNavPoint)
		pEvent.SetDestination(pNavPointMenu)

		# Now create the button..
		pButton = App.STButton_CreateW(pNavPoint.GetDisplayName(), pEvent)
		pNavPointMenu.AddChild(pButton)
		bOpenable = 1

	if bOpenable:
		pNavPointMenu.SetOpenable()
		pNavPointMenu.SetEnabled()
	else:
		pNavPointMenu.SetNotOpenable()
		pNavPointMenu.SetDisabled()

	# Make sure all the nav points have been identified by the player.
	if len(lNavPoints):
		pPlayer = App.Game_GetCurrentPlayer()
		if pPlayer:
			pSensors = pPlayer.GetSensorSubsystem()
			if pSensors:
				for pNavPoint in lNavPoints:
					pSensors.IdentifyObject(pNavPoint)

###############################################################################
#	OrbitMenuPlayerChanged
#	
#	The player object has changed..  Setup an event handler listening
#	for when the player enters a new set, and setup the orbit menu for
#	the planets that are in the player's current set, if any.
#	
#	Args:	pOrbitMenu	- The root of the orbit menu
#			pEvent		- The ET_SET_PLAYER event.
#	
#	Return:	None
###############################################################################
def OrbitMenuPlayerChanged(pOrbitMenu, pEvent):
	# Add an event handler for the player entering a new set..
	SetupOrbitMenuPlayerSetHandler(pOrbitMenu)

	# If the player exists in a set right now, add planets from that set.
	pGame = App.Game_GetCurrentGame()
	if pGame:
		pSet = pGame.GetPlayerSet()
		if pSet:
			SetupOrbitMenuFromSet(pOrbitMenu, pSet)
			SetupNavPointsMenuFromSet(pSet)

	# Done.
	pOrbitMenu.CallNextHandler(pEvent)

###############################################################################
#	OrbitMenuPlayerEnteredSet
#	
#	The player has entered a new set.  Setup the orbit menu again,
#	with the planets from the new set.
#	
#	Args:	pOrbitMenu	- The root of the orbit menu.
#			pEvent		- The ET_ENTERED_SET event for the player.
#	
#	Return:	None
###############################################################################
def OrbitMenuPlayerEnteredSet(pOrbitMenu, pEvent):
	# Setup the orbit menu from the player's new set.
	pGame = App.Game_GetCurrentGame()
	if pGame:
		pSet = pGame.GetPlayerSet()
		if pSet:
			SetupOrbitMenuFromSet(pOrbitMenu, pSet)
			SetupNavPointsMenuFromSet(pSet)

	# Done.
	pOrbitMenu.CallNextHandler(pEvent)

###############################################################################
#	OrbitPlanet
#	
#	It's an Orbit Planet event.  Orbit the given planet.
#	
#	Args:	pOrbitMenu	- The orbit menu...
#			pEvent		- The Orbit Planet event that triggered us.
#	
#	Return:	None
###############################################################################
def OrbitPlanet(pOrbitMenu, pEvent):
#	debug("Orbit planet.")
	# Get the planet to orbit.
	pPlanet = App.Planet_Cast(pEvent.GetSource())
	if pPlanet:
		# Get the player.
		pGame = App.Game_GetCurrentGame()
		pPlayer = pGame.GetPlayer()
		if pPlayer:
			# If the player is in the Starbase 12 set, make sure they
			# aren't inside the starbase...
			if not MissionLib.IsPlayerInsideStarbase12():
				# Give the player Orbit Planet AI.
				import AI.Player.OrbitPlanet
				MissionLib.SetPlayerAI("Helm", AI.Player.OrbitPlanet.CreateAI(pPlayer, pPlanet))

			# Change the player's target to the planet.
			pPlayer.SetTarget( pPlanet.GetName() )

	# Close the orbit menu.
	pOrbitMenu.Close()

	pOrbitMenu.CallNextHandler(pEvent)

###############################################################################
#	SetNavPointTarget
#	
#	Set the player's target to the given nav point.
#	
#	Args:	pNavMenu	- The NavPoints menu...
#			pEvent		- The event that triggered us.
#	
#	Return:	None
###############################################################################
def SetNavPointTarget(pNavMenu, pEvent):
	# Get the point to target.
	pNavPoint = App.PlacementObject_Cast(pEvent.GetSource())
	if pNavPoint:
		pPlayer = App.Game_GetCurrentPlayer()
		if pPlayer:
			pPlayer.SetTarget(pNavPoint.GetName())

			# Target has been set.  Intercept this target.
			if not MissionLib.IsPlayerInsideStarbase12():
				import AI.Player.InterceptTarget
				MissionLib.SetPlayerAI("Helm", AI.Player.InterceptTarget.CreateAI(pPlayer, pNavPoint))

	# Close the nav menu.
	pNavMenu.Close()

	pSet = App.g_kSetManager.GetSet("bridge")
	if (pSet):
		pHelm = App.CharacterClass_GetObject(pSet, "Helm")
		if (pHelm):
			App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, pHelm.GetCharacterName() + "Yes1", "Captain", 1, pHelm.GetDatabase()).Play()

	pNavMenu.CallNextHandler(pEvent)

###############################################################################
#	NavPointChanged
#	
#	A placement object's navpointness has been changed (either it's
#	a nav point now, when it didn't used to be before, or it used
#	to be a nav point, and it isn't now).  If this happened in the
#	same set as the player, the nav point menu needs to be fixed.
#	
#	Args:	pNavMenu	- The NavPoints menu...
#			pEvent		- The event that triggered us.
#	
#	Return:	None
###############################################################################
def NavPointChanged(pNavMenu, pEvent):
	# Get the placement whose navpointness has changed.
	pPlacement = App.PlacementObject_Cast(pEvent.GetDestination())
	if not pPlacement:
		return

	pPlayer = App.Game_GetCurrentPlayer()
	if not pPlayer:
		return

	pPlayerSet = pPlayer.GetContainingSet()

	# If this is happening in the same set as the player,
	# we need to recreate the nav point menu.
	if pPlacement.IsNavPoint():
		pSet = pPlacement.GetContainingSet()
	else:
		pSet = pPlacement.FindContainingSet()

	if pSet and pPlayerSet  and  (pSet.GetName() == pPlayerSet.GetName()):
		# Same set.  Recreate the menu.
		SetupNavPointsMenuFromSet(pSet)


###############################################################################
#	GetHailSequence()
#	
#	Gets a sequence for the Hail button...
#	
#	Args:	fTime		- duration of the sequence
#			pLine		- a non-default line to say
#			pDatabase	- the database to get the line from
#	
#	Return:	pSequence	- the sequence we created
###############################################################################
def GetHailSequence(fTime = 1.5, pLine = None, pDatabase = None):
	# Get player's ship.
	pGame = App.Game_GetCurrentGame()
	assert pGame
	if(pGame is None):
		return
	pShip = App.ShipClass_Cast(pGame.GetPlayer())
	if(pShip is None):
		return

	# Get Helm character.
	pSet = App.g_kSetManager.GetSet("bridge")
	pHelm = App.CharacterClass_GetObject(pSet, "Helm")
	assert pHelm
	
	if not (pDatabase):
		pDatabase = pHelm.GetDatabase()

	App.TGScriptAction_Create("MissionLib", "CallWaiting", 1).Play()

	pSequence = App.TGSequence_Create()
	if not (pLine):
		iNum = App.g_kSystemWrapper.GetRandomNumber(2)
		if iNum == 1:
			pAction = App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "HailOpen1", None, 1, pDatabase)
	
		else:
			pAction = App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "HailOpen2", None, 1, pDatabase)
	
		pSequence.AppendAction(pAction)
	else:
		pSequence.AppendAction(App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, pLine, None, 1, pDatabase))
	pSequence.AppendAction(App.CharacterAction_Create(pHelm, App.CharacterAction.AT_PLAY_ANIMATION, "PushingButtons"))
	#pSequence.AppendAction(App.CharacterAction_Create(pHelm, App.CharacterAction.AT_BECOME_ACTIVE))
	#pSequence.AppendAction(App.CharacterAction_Create(pHelm, App.CharacterAction.AT_BECOME_INACTIVE), fTime)
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "CallWaiting", 0))

	return pSequence

	
###############################################################################
#	Hail(pObject, pEvent)
#	
#	Hail currently targeted ship.
#	
#	Args:	pObject		- the target of the event
#			pEvent		- the event that was sent
#	
#	Return:	none
###############################################################################
def Hail(pObject, pEvent):
	# Voice lines to choose from randomly.
	HailLines = [	"HailOpen1",	# Hailing ship.
					"HailOpen2", 
					"OnScreen" ]
	NoHailLines = [	"NotResponding1",	# No response.
					"NotResponding2" ]

	# Get player's ship.
	pGame = App.Game_GetCurrentGame()
	assert pGame
	if(pGame is None):
		return
	pShip = App.ShipClass_Cast(pGame.GetPlayer())
	if(pShip is None):
		return

	# Get Helm character.
	pSet = App.g_kSetManager.GetSet("bridge")
	pHelm = App.CharacterClass_GetObject(pSet, "Helm")
	assert pHelm
	
	if (pEvent):
		pTarget = App.ObjectClass_Cast(pEvent.GetObjPtr())
	else:
		pTarget = pObject

	pDatabase = pHelm.GetDatabase()
	
	if(pTarget is None):
		pObject.CallNextHandler(pEvent)
	elif(pTarget.GetName() == "Starbase 12"):
		App.TGScriptAction_Create("MissionLib", "CallWaiting", 1).Play()

		pSequence = App.TGSequence_Create()
		pSequence.AppendAction(App.CharacterAction_Create(pHelm, App.CharacterAction.AT_PLAY_ANIMATION, "PushingButtons"))
		pLineAction = App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, 
						HailLines[App.g_kSystemWrapper.GetRandomNumber(len(HailLines))],
						None, 0, pDatabase)
		pSequence.AppendAction(pLineAction)
		pHailAction = App.TGScriptAction_Create("Bridge.HelmMenuHandlers", "HailStarbase12")
		pSequence.AppendAction(pHailAction)
		pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "CallWaiting", 0))
		pSequence.Play()
		pObject.CallNextHandler(pEvent)
	else:
		pObject.CallNextHandler(pEvent)
		if(pHelm):
			App.TGScriptAction_Create("MissionLib", "CallWaiting", 1).Play()

			pSequence = App.TGSequence_Create()
			pSequence.AppendAction(App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "HailOpen2", None, 1, pHelm.GetDatabase()))
			pSequence.AppendAction(App.CharacterAction_Create(pHelm, App.CharacterAction.AT_PLAY_ANIMATION, "PushingButtons"))
			pSequence.AppendAction(App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, NoHailLines[App.g_kSystemWrapper.GetRandomNumber(len(NoHailLines))], None, 1, pHelm.GetDatabase()), 0.5)
			pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "CallWaiting", 0))
			pSequence.Play()

###############################################################################
#	HailStarbase12
#	
#	Hail Starbase 12.
#	
#	Args:	pAction	- The action triggering this function.
#	
#	Return:	0 or 1.
###############################################################################
def HailStarbase12(pAction):
	# Get Player
	pPlayer = MissionLib.GetPlayer()
	if pPlayer is None:
		return 0

	# Setup a sequence for Graff's stuff.
	pSequence = App.TGSequence_Create()

	# Set the viewscreen to watch Graff.
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "FedOutpostSet_Graff", "Graff"))

	# Have Graff say his greeting.
	pSequence.AppendAction(App.TGScriptAction_Create("Bridge.Characters.Graff", "SayGreeting"))

	# Turn off the viewscreen.
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))

	# pAction is done when pSequence is done.
	pDoneEvent = App.TGObjPtrEvent_Create()
	pDoneEvent.SetEventType(App.ET_ACTION_COMPLETED)
	pDoneEvent.SetDestination(App.g_kTGActionManager)
	pDoneEvent.SetObjPtr(pAction)
	pSequence.AddCompletedEvent(pDoneEvent)

	MissionLib.QueueActionToPlay(pSequence)

	return 1

###############################################################################
#	DockStarbase12(pAction)
#	
#	Similar to HailStarbase12 script action, but used for when the
#	player docks with the starbase, rather than just hailing it.
#	
#	Args:	pAction			- The action calling this function.
#			pGraffAction	- If this isn't None, this action will be played
#							  in place of Graff's usual greeting action.
#			bNoRepair		- If true, no repairing will be done, only reloading.
#	
#	Return:	none
###############################################################################
def DockStarbase12(pAction, pGraffAction = None, bNoRepair = 0, bFadeEnd = 1):
	# Get Player
	pPlayer = MissionLib.GetPlayer()
	if pPlayer is None:
		return 0

	# Take down Helm menu and turn character back.
	pBridgeSet = App.BridgeSet_Cast(App.g_kSetManager.GetSet("bridge"))
	pHelm = App.CharacterClass_GetObject (pBridgeSet, "Helm")
	if pHelm is None:
		return 0
	pHelm.MenuDown()
	pHelm.TurnBack()

	# Setup a sequence for Graff's stuff.
	pSequence = App.TGSequence_Create()

	# Make sure the rendered set is the Bridge.
	sOldSet = App.g_kSetManager.GetRenderedSet().GetName()
	pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge"))

	# Set the viewscreen to watch Graff.
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "FedOutpostSet_Graff", "Graff"))

	# Have Graff say his greeting.
	if pGraffAction is None:
		pSequence.AppendAction(App.TGScriptAction_Create("Bridge.Characters.Graff", "SayGreeting"))
	else:
#		debug("Triggering custom Graff action.")
		pSequence.AppendAction(pGraffAction)

	# Automatically reload & repair the player's ship.
	if not bNoRepair:
		pSequence.AppendAction(App.TGScriptAction_Create("Actions.ShipScriptActions", "RepairShipFully", pPlayer.GetObjID()))
	pSequence.AppendAction(App.TGScriptAction_Create("Actions.ShipScriptActions", "ReloadShip", pPlayer.GetObjID()))
	
	# Fade out...  Something else will fade us back in later.
	if bFadeEnd:
		pSequence.AppendAction( App.TGScriptAction_Create("MissionLib", "FadeOut") )

	# Turn off the viewscreen.
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))

	# Change the rendered set back to whatever it used to be.
	pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", sOldSet), 0.5)

	# pAction is done when pSequence is done.
	pDoneEvent = App.TGObjPtrEvent_Create()
	pDoneEvent.SetEventType(App.ET_ACTION_COMPLETED)
	pDoneEvent.SetDestination(App.g_kTGActionManager)
	pDoneEvent.SetObjPtr(pAction)
	pSequence.AddCompletedEvent(pDoneEvent)

	pSequence.Play()

	return 1

###############################################################################
#	AllStop
#	
#	Stop the ship.
#	
#	Args:	pHelmMenu	- Helm's menu, the destination for the event.
#			pEvent		- The ET_ALL_STOP event.
#	
#	Return:	None
###############################################################################
def AllStop(pHelmMenu, pEvent):
	# Give the player Stay AI.
	pPlayer = App.Game_GetCurrentPlayer()
	if pPlayer:
		import AI.Player.Stay
		MissionLib.SetPlayerAI("Helm", AI.Player.Stay.CreateAI(pPlayer))

	pHelmMenu.CallNextHandler(pEvent)

###############################################################################
#	UpdateOrders
#	
#	Update Helm's brain.  If Helm is supposed to be in control of
#	the ship, make sure they're doing so.
#	
#	Args:	bAcknowledge	- Whether or not Helm should acknowledge
#							  the orders (ie. "Yes, sir."   "Aye, Captain").
#	
#	Return:	None
###############################################################################
def UpdateOrders(bAcknowledge = 1):
	if MissionLib.GetPlayerShipController() in ( None, "Helm" ):
#		debug(__name__ + ": Helm is in control, if desired.")
		# Make sure we're controlling the ship.  If we're
		# supposed to be intercepting, warping, orbitting,
		# etc..  just make sure we're doing it.
		# ***FIXME: Implement this.
		pass

###
### Fleet Command functionality
###

###############################################################################
#	AddCommandableShip
#	RemoveCommandableShip
#	RemoveAllCommandableShips
#	
#	Change the list of ships that can be commanded by the player
#	using the player's "Command Fleet" button.  Check the MissionLib
#	version of these functions for documentation.
#	
#	Args:	sShipName	- Name of the ship to add/remove from the list.
#			lsCommands	- A list of which commands are available for that ship.
#	
#	Return:	None
###############################################################################
def AddCommandableShip(sShipName, lsCommands):
	if len(lsCommands) == 0:
		# All commands should be available.
		lsCommands = g_dCommandInfo.keys()
	else:
		# Double-check that all listed commands are available.
		for sCommand in lsCommands:
			if g_dCommandInfo.has_key(sCommand):
				continue
			elif g_dCustomCommandInfo.has_key(sCommand):
				continue
			# Invalid command.
			raise KeyError, "Unavailable fleet command: %s not in (%s) or (%s)" % (sCommand, g_dCommandInfo.keys(), g_dCustomCommandInfo.keys())

	g_dCommandableFleet[sShipName] = lsCommands

	# If this ship exists in the player's set, add it to the Fleet Command menu.
	pPlayer = App.Game_GetCurrentPlayer()
	if pPlayer:
		pSet = pPlayer.GetContainingSet()
		if pSet:
			pShip = App.ShipClass_GetObject(pSet, sShipName)
			if pShip:
				# It does.  Add it.
				AddShipToFleetCommandMenu(pShip, lsCommands)

def RemoveCommandableShip(sShipName):
	if g_dCommandableFleet.has_key(sShipName):
		del g_dCommandableFleet[sShipName]

	# If this ship exists in the player's set, remove it from the Fleet Command menu.
	pPlayer = App.Game_GetCurrentPlayer()
	if pPlayer:
		pSet = pPlayer.GetContainingSet()
		if pSet:
			pShip = App.ShipClass_GetObject(pSet, sShipName)
			if pShip:
				# It does.  Remove it.
				RemoveShipFromFleetCommandMenu(pShip)

def RemoveAllCommandableShips():
	g_dCommandableFleet = {}

###############################################################################
#	PlayerEnteredSet
#	
#	The player has entered a new set.  Remove any old entries
#	from the Fleet Command menu, and add entries for any commandable
#	ships in this set.
#	
#	Args:	pPlayerGroup	- The game's Player Group.
#			pEvent			- Event for the player entering a new set.
#	
#	Return:	
###############################################################################
def PlayerEnteredSet(pPlayerGroup, pEvent):
	pPlayer = App.ShipClass_Cast(pEvent.GetDestination())
	if pPlayer:
		pSet = pPlayer.GetContainingSet()

		# Get any friendly ships in this set.
		import MissionLib
		pMission = MissionLib.GetMission()
		pFriendlyGroup = pMission.GetFriendlyGroup()
		lpFriendlies = pFriendlyGroup.GetActiveObjectTupleInSet(pSet)

		for pFriendly in lpFriendlies:
			AddIfCommandable(pFriendly)

	pPlayerGroup.CallNextHandler(pEvent)

def AddIfCommandable(pShip):
	# Check if this ship is in the list of commandable ships.
	if g_dCommandableFleet.has_key(pShip.GetName()):
		# Yep, it's commandable.  Add it to the menu.
		AddShipToFleetCommandMenu(pShip, g_dCommandableFleet[pShip.GetName()])

###############################################################################
#	FriendlyEnteredSet
#	
#	A friendly ship is entering a set somewhere.  If it's entering
#	the player's set and it's a commandable ship, add it to the
#	Fleet Command menu.
#	
#	Args:	pFriendlyGroup	- The mission's Friendly group.
#			pEvent			- Event for the friendly entering a set.
#	
#	Return:	None
###############################################################################
def FriendlyEnteredSet(pFriendlyGroup, pEvent):
	# Get the ship that just entered a set...
	pShip = App.ShipClass_Cast(pEvent.GetObjPtr())
	if pShip:
		# Check if the set it entered is the player's set.
		pSet = pShip.GetContainingSet()
		pPlayerSet = App.Game_GetCurrentGame().GetPlayerSet()
		if (pPlayerSet):
			if pSet.GetName() == pPlayerSet.GetName():
				# Yep, the ship just entered the player's set.  Add it to
				# the list of commandable ships, if it's a commandable ship.
				AddIfCommandable(pShip)

	pFriendlyGroup.CallNextHandler(pEvent)

###############################################################################
#	FriendlyExitedSet
#	
#	A friendly ship is leaving a set somewhere.  If this ship is in
#	the Fleet Command menu, remove it.
#	
#	Args:	pFriendlyGroup	- The mission's Friendly group.
#			pEvent			- Event for the friendly leaving a set.
#	
#	Return:	None
###############################################################################
def FriendlyExitedSet(pFriendlyGroup, pEvent):
	# Get the ship that just exited a set...
	pShip = App.ShipClass_Cast(pEvent.GetObjPtr())
	if pShip:
		# If this ship has an entry in the Fleet Command menu, remove
		# that entry.
		RemoveShipFromFleetCommandMenu(pShip)

	pFriendlyGroup.CallNextHandler(pEvent)

###############################################################################
#	GetFleetCommandButton
#	
#	Handy function for getting one of the Fleet Command buttons
#	for the given ship.
#	
#	Args:	pShip	- The ship whose fleet command button we're retrieving.
#			sButton	- Name of the button to retrieve (eg. "FleetAttackTarget")
#	
#	Return:	The requested button, or None
###############################################################################
def GetFleetCommandButton(pShip, sButton):
	pHailMenu = MissionLib.GetCharacterSubmenu("Helm", "Hail")
	if not pHailMenu:
		return None

	# Got the menu.  Get the submenu for this ship.
	pShipMenu = pHailMenu.GetSubmenuW( pShip.GetDisplayName() )
	if not pShipMenu:
		return None

	# Got the ship's hail menu.  Get the specified fleet command button.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pButton = pShipMenu.GetButtonW(pDatabase.GetString(sButton))
	App.g_kLocalizationManager.Unload(pDatabase)

	return pButton

###############################################################################
#	FleetResume
#	
#	Command a ship to resume its old orders, after having been
#	ordered to do something else.
#	
#	Args:	pFleetMenu	- The Fleet Command menu.
#			pEvent		- The Attack Target event.  Source is the ship
#						  to command.
#	
#	Return:	None
###############################################################################
def FleetResume(pFleetMenu, pEvent):
#	debug("FleetResume")
	pShip = App.ShipClass_Cast(pEvent.GetSource())
	if pShip:
		StopOverridingAI(pShip)

###############################################################################
#	FleetAttackTarget
#	
#	Command a ship to attack the player's current target.
#	
#	Args:	pFleetMenu	- The Fleet Command menu.
#			pEvent		- The Attack Target event.  Source is the ship
#						  to command.
#	
#	Return:	None
###############################################################################
def FleetAttackTarget(pFleetMenu, pEvent):
#	debug("FleetAttackTarget")
	pShip = App.ShipClass_Cast(pEvent.GetSource())
	if pShip:
		# Get the player's target, for the AI.
		pPlayer = App.Game_GetCurrentPlayer()
		if pPlayer:
			pTarget = pPlayer.GetTarget()
			if pTarget:
				# Create and setup the AI.
				OverrideAI(pShip, "AI.Fleet.DestroyTarget", pShip.GetObjID(), pTarget.GetObjID())

	pFleetMenu.CallNextHandler(pEvent)

def FleetDisableTarget(pFleetMenu, pEvent):
#	debug("FleetDisableTarget")
	pShip = App.ShipClass_Cast(pEvent.GetSource())
	if pShip:
		pPlayer = App.Game_GetCurrentPlayer()
		if pPlayer:
			pTarget = pPlayer.GetTarget()
			if pTarget:
				OverrideAI(pShip, "AI.Fleet.DisableTarget", pShip.GetObjID(), pTarget.GetObjID())

	pFleetMenu.CallNextHandler(pEvent)

def FleetDefendTarget(pFleetMenu, pEvent):
#	debug("FleetDefendTarget")
	pShip = App.ShipClass_Cast(pEvent.GetSource())
	if pShip:
		pPlayer = App.Game_GetCurrentPlayer()
		if pPlayer:
			pTarget = pPlayer.GetTarget()
			if pTarget:
				OverrideAI(pShip, "AI.Fleet.DefendTarget", pShip.GetObjID(), pTarget.GetObjID())

	pFleetMenu.CallNextHandler(pEvent)

def FleetHelpMe(pFleetMenu, pEvent):
#	debug("FleetHelpMe")
	pShip = App.ShipClass_Cast(pEvent.GetSource())
	if pShip:
		OverrideAI(pShip, "AI.Fleet.HelpMe", pShip.GetObjID())

	pFleetMenu.CallNextHandler(pEvent)

def FleetDockSB12(pFleetMenu, pEvent):
#	debug("FleetDockSB12")
	pShip = App.ShipClass_Cast(pEvent.GetSource())
	if pShip:
		# Get the starbase.
		pSet = pShip.GetContainingSet()
		if pSet  and  (pSet.GetName() == "Starbase12"):
			pStarbase = App.ShipClass_GetObject(pSet, "Starbase 12")
			if pStarbase:
				# Got the starbase.  Give the Dock AI to the ship.
				import Systems.Starbase12.Starbase12_S
				OverrideAI(pShip, "AI.Fleet.DockStarbase", pShip.GetObjID(), pStarbase.GetObjID(), None, NoRepair = not Systems.Starbase12.Starbase12_S.g_bRepairsEnabled)

	pFleetMenu.CallNextHandler(pEvent)

###############################################################################
#	AddFleetCommandHandlers
#	
#	Add event handlers for the Fleet Command menu.
#	
#	Args:	pHailMenu	- the helm menu to listen for these
#	
#	Return:	None
###############################################################################
def AddFleetCommandHandlers(pHailMenu):
	# Need a handler for when the player enters a new set, and when friendly
	# ships enter or exit sets, so we can enable or disable parts of the menu.
	pGame = App.Game_GetCurrentGame()
	pPlayerGroup = pGame.GetPlayerGroup()
	if pPlayerGroup:
		pPlayerGroup.SetEventFlag( App.ObjectGroup.ENTERED_SET )
		pPlayerGroup.AddPythonFuncHandlerForInstance(
			App.ET_OBJECT_GROUP_OBJECT_ENTERED_SET,
			__name__ + ".PlayerEnteredSet")

	pMission = pGame.GetCurrentEpisode().GetCurrentMission()
	pFriendlyGroup = pMission.GetFriendlyGroup()
	if pFriendlyGroup:
		pFriendlyGroup.SetEventFlag( App.ObjectGroup.ENTERED_SET )
		pFriendlyGroup.SetEventFlag( App.ObjectGroup.EXITED_SET )
		pFriendlyGroup.AddPythonFuncHandlerForInstance(
			App.ET_OBJECT_GROUP_OBJECT_ENTERED_SET,
			__name__ + ".FriendlyEnteredSet")
		pFriendlyGroup.AddPythonFuncHandlerForInstance(
			App.ET_OBJECT_GROUP_OBJECT_EXITED_SET,
			__name__ + ".FriendlyExitedSet")

	# Add event handlers for fleet commands...  These events are sent
	# directly to the fleet command menu, even though they apply to a
	# ship underneath that menu.  The event source is the ship the event
	# applies to.
	for eEvent, sHandler in (
		( ET_FLEET_COMMAND_RESUME,			__name__ + ".FleetResume" ),
		( ET_FLEET_COMMAND_ATTACK_TARGET,	__name__ + ".FleetAttackTarget" ),
		( ET_FLEET_COMMAND_DISABLE_TARGET,	__name__ + ".FleetDisableTarget" ),
		( ET_FLEET_COMMAND_DEFEND_TARGET,	__name__ + ".FleetDefendTarget" ),
		( ET_FLEET_COMMAND_HELP_ME,			__name__ + ".FleetHelpMe" ),
		( ET_FLEET_COMMAND_DOCK_SB12,		__name__ + ".FleetDockSB12" ),
		( ET_FLEET_COMMAND_CUSTOM,			__name__ + ".FleetCommandCustom" )):

		# Add an instance handler for this event.
		pHailMenu.AddPythonFuncHandlerForInstance(eEvent, sHandler)

###############################################################################
#	AddShipToFleetCommandMenu
#	
#	Add a ship to the list of ships available under the Fleet Command menu.
#	
#	Args:	pShip		- The ship to add.
#			lsCommands	- The list of commands to make available for
#						  this ship.  See the available commands at
#						  the top of this file.
#	
#	Return:	None
###############################################################################
def AddShipToFleetCommandMenu(pShip, lsCommands):
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	# Get the Hail menu.
	pHailMenu = MissionLib.GetCharacterSubmenu("Helm", "Hail")
	if not pHailMenu:
#		debug("Error: Unable to get Command Fleet menu for AddShipToFleetCommandMenu.")
		return

	# Got the menu.  Add this ship to the menu if it isn't already there.
	pDisplayName = pShip.GetDisplayName ()
	pShipMenu = pHailMenu.GetSubmenuW(pDisplayName)
	if pShipMenu:
		# It's already there.  Do nothing.
		App.g_kLocalizationManager.Unload(pDatabase)
		return

	pShipButton = pHailMenu.GetButtonW(pDisplayName)
	if pShipButton:
		# They had a button already in the Hail menu. Remove it.
		pHailMenu.DeleteChild(pShipButton)

	pShipMenu = App.STMenu_CreateW(pDisplayName)
	if not pShipMenu:
		App.g_kLocalizationManager.Unload(pDatabase)
		return

	pButton = CreateHailButton(pShip, 1)
	if pButton:
		pShipMenu.AddChild(pButton)

	# Add the available commands for this ship.
	# Make sure lsCommands is a list, not a tuple.
	lsCommands = list(lsCommands)
	if len(lsCommands):
		# First command is always the "Resume old orders" command.
		pEvent = App.TGEvent_Create()
		pEvent.SetEventType(ET_FLEET_COMMAND_RESUME)
		pEvent.SetDestination(pHailMenu)
		pEvent.SetSource(pShip)
		pName = pDatabase.GetString("FleetResume")
		pButton = App.STButton_CreateW(pName, pEvent)
		pButton.SetDisabled(0)
		pShipMenu.AddChild(pButton)

		# Done adding the Resume button.
		# Sort the ship's available commands.  Gotta get their info first.
		lInfo = []
		for sCommand in lsCommands:
			if g_dCommandInfo.has_key(sCommand):
				#debug("Adding normal command %s(%s)" % (sCommand, str(g_dCommandInfo[sCommand])))
				lInfo.append( g_dCommandInfo[sCommand] )

		# Sort..  And add the commands.
		lInfo.sort()
		for eEventType, sCommandName, sButtonSetupFunc, sCheckFunc in lInfo:
			# Make an event for the button.
			pEvent = App.TGEvent_Create()
			pEvent.SetEventType(eEventType)
			pEvent.SetDestination(pHailMenu)
			pEvent.SetSource(pShip)

			pName = pDatabase.GetString(sCommandName)
			pButton = App.STButton_CreateW(pName, pEvent)

			# Add event handlers to this button, or do other
			# setup necessary to ensure the proper behavior of this button.
			if sButtonSetupFunc:
				globals()[sButtonSetupFunc](pButton)

			pShipMenu.AddChild(pButton)

		# Add custom commands.  Sorted alphabetically...
		lsCommands.sort()
		for sCommand in lsCommands:
			if g_dCustomCommandInfo.has_key(sCommand):
				# Make an event from the button.
#				debug("Adding custom command %s (key value %s)" % (sCommand, str(g_dCustomCommandInco[sCommand])))
				pEvent = App.TGStringEvent_Create()
				pEvent.SetEventType(ET_FLEET_COMMAND_CUSTOM)
				pEvent.SetDestination(pHailMenu)
				pEvent.SetString( g_dCustomCommandInfo[sCommand][1] )
				pEvent.SetSource(pShip)

				pCustomDatabase = App.g_kLocalizationManager.Load( g_dCustomCommandInfo[sCommand][0] )
				pName = pCustomDatabase.GetString(sCommand)
				App.g_kLocalizationManager.Unload(pCustomDatabase)

				pButton = App.STButton_CreateW(pName, pEvent)
				pShipMenu.AddChild(pButton)
	else:
		# No available commands.  Have the menu be disabled.
		pShipMenu.SetDisabled()

	pHailMenu.AddChild(pShipMenu)

	# Done with the string database...
	App.g_kLocalizationManager.Unload(pDatabase)

def RemoveShipFromFleetCommandMenu(pShip):
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	# Get the Hail menu.
	pHailMenu = MissionLib.GetCharacterSubmenu("Helm", "Hail")

	# Got the menu.  Look for this ship in the menu...
	pShipMenu = pHailMenu.GetSubmenuW(pShip.GetDisplayName())
	if pShipMenu:
		# Found it.  Get rid of it.
		pHailMenu.DeleteChild(pShipMenu)
		# Call "entered set" on it, to deal with potentially re-adding it
		# to the hail menu.
		ObjectEnteredSet(pShip, None)

	# Done with the string database...
	App.g_kLocalizationManager.Unload(pDatabase)

###############################################################################
#	FleetSetupNonFriendlyTargetHandlers
#	
#	Function for setting up event handlers for one of the
#	Command Fleet buttons.  This sets up event handlers so
#	the button is only enabled when the player has a non-friendly
#	target.
#	
#	Args:	pButton	- The button to setup.
#	
#	Return:	None
###############################################################################
def FleetSetupNonFriendlyTargetHandlers(pButton):
	# Need to know when the player changes, so we can change our
	# event handlers.
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_SET_PLAYER, pButton, __name__ + ".FSNFTH_PlayerChanged")
	# That event handler will setup our handlers for the player...
	FSNFTH_PlayerChanged(pButton)

#
# Helper function to FleetSetupNonFriendlyTargetHandlers
#
def FSNFTH_PlayerChanged(pButton, pEvent = None):
	# Remove any handlers based on the old player...
	if pEvent:
		pOldPlayer = App.ShipClass_Cast(pEvent.GetSource())
		if pOldPlayer:
			App.g_kEventManager.RemoveBroadcastHandler(
				App.ET_TARGET_WAS_CHANGED, pButton, __name__ + ".FSNFTH_PlayerTargetChanged", pOldPlayer)

	# Add handlers based on the new player.
	pNewPlayer = App.Game_GetCurrentPlayer()
	if pNewPlayer:
		App.g_kEventManager.AddBroadcastPythonFuncHandler(
			App.ET_TARGET_WAS_CHANGED, pButton, __name__ + ".FSNFTH_PlayerTargetChanged", pNewPlayer)

	# Check our current status.
	FSNFTH_CheckDisabled(pButton, pNewPlayer)

#
# Helper function to FleetSetupNonFriendlyTargetHandlers
#
def FSNFTH_PlayerTargetChanged(pButton, pEvent):
	pPlayer = App.ShipClass_Cast(pEvent.GetDestination())
	FSNFTH_CheckDisabled(pButton, pPlayer)

#
# Helper function to FleetSetupNonFriendlyTargetHandlers
#
def FSNFTH_CheckDisabled(pButton, pPlayer):
	# Need to enable or disable the button based on what the player's current
	# target is.
	bDisabled = 1

	# If this button should be disabled right now due to
	# usage, make sure it stays disabled.
	if pButton.GetObjID() not in g_lidFleetCommandsDisabled:
		# Check the player's target...
		if pPlayer:
			pTarget = pPlayer.GetTarget()
			if pTarget:
				# Player has a target.  Is it a friendly target?
				pMission = MissionLib.GetMission()
				if pMission:
					pFriendlyGroup = pMission.GetFriendlyGroup()
					if not pFriendlyGroup.IsNameInGroup( pTarget.GetName() ):
						# It's not a friendly target.  Button should be enabled.
						bDisabled = 0

	if bDisabled:
		pButton.SetDisabled()
	else:
		pButton.SetEnabled()

###############################################################################
#	FleetSetupTargetHandlers
#	
#	Function for setting up event handlers for one of the
#	Command Fleet buttons.  This sets up event handlers so
#	the button is only enabled when the player has a target.
#	
#	Args:	pButton	- The button to setup.
#	
#	Return:	None
###############################################################################
def FleetSetupTargetHandlers(pButton):
	# Need to know when the player changes, so we can change our
	# event handlers.
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_SET_PLAYER, pButton, __name__ + ".FSTH_PlayerChanged")
	# That event handler will setup our handlers for the player...
	FSTH_PlayerChanged(pButton)

#
# Helper function to FleetSetupTargetHandlers
#
def FSTH_PlayerChanged(pButton, pEvent = None):
	# Remove any handlers based on the old player...
	if pEvent:
		pOldPlayer = App.ShipClass_Cast(pEvent.GetSource())
		if pOldPlayer:
			App.g_kEventManager.RemoveBroadcastHandler(
				App.ET_TARGET_WAS_CHANGED, pButton, __name__ + ".FSTH_PlayerTargetChanged", pOldPlayer)

	# Add handlers based on the new player.
	pNewPlayer = App.Game_GetCurrentPlayer()
	if pNewPlayer:
		App.g_kEventManager.AddBroadcastPythonFuncHandler(
			App.ET_TARGET_WAS_CHANGED, pButton, __name__ + ".FSTH_PlayerTargetChanged", pNewPlayer)

	# Check our current status.
	FSTH_CheckDisabled(pButton, pNewPlayer)

#
# Helper function to FleetSetupTargetHandlers
#
def FSTH_PlayerTargetChanged(pButton, pEvent):
	# If the player has a target right now, the button should be
	# enabled.  Otherwise, it needs to be disabled.
	pPlayer = App.ShipClass_Cast(pEvent.GetDestination())
	FSTH_CheckDisabled(pButton, pPlayer)

#
# Helper function to FleetSetupTargetHandlers
#
def FSTH_CheckDisabled(pButton, pPlayer):
	# If this button should be disabled right now due to
	# usage, make sure it stays disabled.
	if pButton.GetObjID() not in g_lidFleetCommandsDisabled:
		# Check the player's target.
		if pPlayer:
			pTarget = pPlayer.GetTarget()
			if pTarget:
				# Check if this target is the ship that's being commanded...
				pDisplayName = pTarget.GetDisplayName()
				pMenu = App.STMenu_Cast( pButton.GetConceptualParent() )
				if not pMenu:
					return
				pMenuName = pMenu.GetText()
				if pMenuName and pDisplayName:
					kString = App.TGString()
					pMenuName.GetString(kString)
					if kString.Compare(pDisplayName, 1):
						# They're not the same.  The button should be enabled.
						pButton.SetEnabled()
						return

	# The button should be disabled.
	pButton.SetDisabled()

###############################################################################
#	FleetSetupInSB12Handlers
#	
#	Function for setting up event handlers for one of the
#	Command Fleet buttons.  This sets up event handlers so
#	the button is only enabled when the ship and the player
#	is in the Starbase 12 set.
#	
#	Args:	pButton	- The button to setup.
#	
#	Return:	None
###############################################################################
def FleetSetupInSB12Handlers(pButton):
	# Need to know when the player changes, so we can change our
	# event handlers.
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_SET_PLAYER, pButton, __name__ + ".FSISB12_PlayerChanged")
	# That event handler will setup our handlers for the player...
	FSISB12_PlayerChanged(pButton)

#
# Helper function to FleetSetupInSB12Handlers
#
def FSISB12_PlayerChanged(pButton, pEvent = None):
	# Remove any handlers based on the old player...
	if pEvent:
		pOldPlayer = App.ShipClass_Cast(pEvent.GetSource())
		if pOldPlayer:
			App.g_kEventManager.RemoveBroadcastHandler(
				App.ET_ENTERED_SET, pButton, __name__ + ".FSISB12_EnteredSet", pOldPlayer)

	# Add handlers based on the new player.
	pNewPlayer = App.Game_GetCurrentPlayer()
	if pNewPlayer:
		App.g_kEventManager.AddBroadcastPythonFuncHandler(
			App.ET_ENTERED_SET, pButton, __name__ + ".FSISB12_EnteredSet", pNewPlayer)

	# Check our current status.
	FSISB12_CheckDisabled(pButton, pNewPlayer)

#
# Helper function to FleetSetupInSB12Handlers
#
def FSISB12_EnteredSet(pButton, pEvent):
	# The player has entered a new set.  If it's the Starbase12 set,
	# enable this button.
	pPlayer = App.ShipClass_Cast(pEvent.GetDestination())
	FSISB12_CheckDisabled(pButton, pPlayer)

#
# Helper function to FleetSetupInSB12Handlers
#
def FSISB12_CheckDisabled(pButton, pPlayer):
	bDisabled = 1

	# If this button should be disabled right now due to
	# usage, make sure it stays disabled.
	if pButton.GetObjID() not in g_lidFleetCommandsDisabled:
		# Check if the player is in the Starbase12 set.
		try:
			if pPlayer.GetContainingSet().GetName() == "Starbase12":
				bDisabled = 0
		except AttributeError: pass

	if bDisabled:
		pButton.SetDisabled()
	else:
		pButton.SetEnabled()


###############################################################################
#	AddCommandableShip
#	RemoveCommandableShip
#	RemoveAllCommandableShips
#	
#	Change the list of ships that can be commanded by the player
#	using the player's "Command Fleet" button.  Check the MissionLib
#	version of these functions for documentation.
#	
#	Args:	sShipName	- Name of the ship to add/remove from the list.
#			lsCommands	- A list of which commands are available for that ship.
#	
#	Return:	None
###############################################################################
def AddCustomFleetCommand(sCommandName, sTGLDatabasePath, sAIFunction):
	global g_dCustomCommandInfo
	g_dCustomCommandInfo[sCommandName] = (sTGLDatabasePath, sAIFunction)


def FleetCommandCustom(pFleetMenu, pEvent):
	sFunction = pEvent.GetCString()
#	debug("Custom fleet command: " + str(sFunction))

	pFleetMenu.CallNextHandler(pEvent)

###############################################################################
#	OverrideAI
#	
#	Override the specified ship's AI with a Fleet Command AI.
#	
#	Args:	pShip	- The ship whose AI we're overriding.
#	
#	Return:	None
###############################################################################
g_dOverrideAIs = {}
def OverrideAI(pShip, sAIModule, *lAICreateArgs, **dAICreateKeywords):
	# Send the orders and disable the orders in the hail menu.
	# Disable all the other fleet command buttons until the
	# acknowledgement sequence is played (or time has passed,
	# if that sequence won't be played).
	DisableFleetCommandButtons(pShip)

	# If we have a bridge and helmsman, have them tell us what's going on...
	pSequence = App.TGSequence_Create()
	pSet = App.g_kSetManager.GetSet("bridge")
	if (pSet):
		pHelm = App.CharacterClass_GetObject(pSet, "Helm")
		if (pHelm):
			pSequence.AppendAction(App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "SendingOrders" + str(App.g_kSystemWrapper.GetRandomNumber(2) + 1), "Captain", 1))

	# Try to override the AI.
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "OverrideAIMid", pShip.GetObjID(), sAIModule, lAICreateArgs, dAICreateKeywords))
	pSequence.Play()

def OverrideAIMid(pAction, idShip, sAIModule, lAICreateArgs, dAICreateKeywords):
	pShip = App.ShipClass_GetObjectByID(None, idShip)
	if not pShip:
		return 0

	# Check if the ship has building AI's.
	if pShip.HasBuildingAIs():
		# Can't override AI just yet...  Try again in a little while.
		#debug("Can't override AI yet.  Delaying attempt...")
		pSeq = App.TGSequence_Create()
		pSeq.AppendAction( App.TGScriptAction_Create(__name__, "OverrideAIMid", idShip, sAIModule, lAICreateArgs, dAICreateKeywords), 0.5 )
		pSeq.Play()
		return 0

	# Ship has no building AI's.  We can safely replace its AI.
	# Create the new AI...
	pAIModule = __import__(sAIModule)
	pNewAI = apply(getattr(pAIModule, "CreateAI"), lAICreateArgs, dAICreateKeywords)
	if pNewAI:
		OverrideAIInternal(pShip, pNewAI)

	# Reenable fleet commands and say the command has been acknowledged.
	#debug("AI overridden.")
	pSequence = App.TGSequence_Create()
	if pNewAI:
		pSet = App.g_kSetManager.GetSet("bridge")
		if pSet:
			pHelm = App.CharacterClass_GetObject(pSet, "Helm")
			if pHelm:
				pSequence.AppendAction(App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SPEAK_LINE, "OrdersAcknowledged" + str(App.g_kSystemWrapper.GetRandomNumber(2) + 1)), 0.5)

	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "EnableFleetCommandButtons", idShip))
	pSequence.Play()

	return 0

def OverrideAIInternal(pShip, pNewAI):
	# Check for an old AI.
	global g_dOverrideAIs
	pOldAI = pShip.GetAI()
	pOverrideAI = None
	if pOldAI:
		if g_dOverrideAIs.has_key(pShip.GetObjID()):
			# Already have an override AI for this ship.  Check if
			# that AI is still in place.
			pOverrideAI = App.ArtificialIntelligence_GetAIByID(g_dOverrideAIs[pShip.GetObjID()])
			if (not pOverrideAI)  or  (pOverrideAI.GetID() != pOldAI.GetID()):
				# It's not in place.  Gotta make a new one.
				pOverrideAI = None
			else:
				# It's still in place.  Remove whatever was in
				# the priority 1 slot (whatever the player told
				# this ship to do before).
				pOverrideAI.RemoveAIByPriority(1)

	if not pOverrideAI:
		# Make a new Override AI.
		pOverrideAI = App.PriorityListAI_Create(pShip, "FleetCommandOverrideAI")
		pOverrideAI.SetInterruptable(1)

		# Second AI in the list is the current AI.
		if pOldAI:
			pOverrideAI.AddAI(pOldAI, 2)

	# First AI in the list is the AI to override the old one.
	pOverrideAI.AddAI(pNewAI, 1)

	# Replace the ship's AI with the override AI.  The 0 here
	# tells the game not to delete the old AI.
	pShip.ClearAI(0, pOldAI)
	pShip.SetAI(pOverrideAI)

	# Save info about this override AI.
	g_dOverrideAIs[pShip.GetObjID()] = pOverrideAI.GetID()

def StopOverridingAI(pShip):
	global g_dOverrideAIs
	pOldAI = pShip.GetAI()
	pOverrideAI = None
	if pOldAI:
		if g_dOverrideAIs.has_key(pShip.GetObjID()):
			# Have an override AI for this ship.  Check if
			# that AI is still in place.
			pOverrideAI = App.ArtificialIntelligence_GetAIByID(g_dOverrideAIs[pShip.GetObjID()])
			if pOverrideAI  and  (pOverrideAI.GetID() == pOldAI.GetID()):
				# It's still in place.  Remove whatever was in
				# the priority 1 slot (whatever the player told
				# this ship to do before).
				pOverrideAI.RemoveAIByPriority(1)

	# Disable the FleetResume button again.
	pResume = GetFleetCommandButton(pShip, "FleetResume")
	if pResume:
		pResume.SetDisabled(1)

###############################################################################
#	DisableFleetCommandButtons
#	
#	Disable the fleet command orders for the given ship temporarily,
#	due to usage.  This doesn't disable the FleetResume command.
#	
#	Args:	pShip	- The ship whose command buttons we're disabling.
#	
#	Return:	None
###############################################################################
g_lidFleetCommandsDisabled = []
def DisableFleetCommandButtons(pShip):
	# Loop through the available commands...
	for sCommand in g_dCommandInfo.keys():
		pButton = GetFleetCommandButton(pShip, g_dCommandInfo[sCommand][1])
		if pButton:
			# Disable this button...
			pButton.SetDisabled(1)
			g_lidFleetCommandsDisabled.append(pButton.GetObjID())

###############################################################################
#	EnableFleetCommandButtons
#	
#	Reenable the fleet command orders for the specified ship, after
#	a call to DisableFleetCommandButtons.
#	
#	Args:	idShip	- Object ID of the ship whose commands we're reenabling.
#	
#	Return:	None
###############################################################################
def EnableFleetCommandButtons(pAction, idShip):
	pShip = App.ShipClass_GetObjectByID(None, idShip)
	if not pShip:
		return 0

	# Loop through the available commands...
	for sCommand in g_dCommandInfo.keys():
		pButton = GetFleetCommandButton(pShip, g_dCommandInfo[sCommand][1])
		if pButton:
			# This button should no longer be in the list of disabled buttons.
			try:
				g_lidFleetCommandsDisabled.remove(pButton.GetObjID())
			except ValueError: pass

			# If this button has a special function for checking its
			# enabled/disabled status, run that.  Otherwise, just enable it.
			sCheckFunc = g_dCommandInfo[sCommand][3]
			if sCheckFunc:
				globals()[sCheckFunc](pButton, App.Game_GetCurrentPlayer())
			else:
				pButton.SetEnabled(1)

	# Enable the FleetResume button for this ship.
	pResume = GetFleetCommandButton(pShip, "FleetResume")
	if pResume:
		pResume.SetEnabled(1)

	return 0

###############################################################################
#	CollisionAlertCheck()
#	
#	Checks for any impending collisions
#	
#	Args:	dTimeLeft
#	
#	Return:	none
###############################################################################
def CollisionAlertCheck(dTimeLeft):
	kProfiling = App.TGProfilingInfo("HelmMenuHandlers.CollisionAlertCheck")

	if not (App.CharacterClass_IsCollisionAlertEnabled()):
		return

	pShip = MissionLib.GetPlayer()
	if not (pShip):
		#debug("There is no current player, thus no collision worries")
		return

	pSet = pShip.GetContainingSet()
	if not (pSet):
		#debug("There is no set containing the player.  This is probably bad")
		return

	pProxManager = pSet.GetProximityManager()
	if not (pProxManager):
		#debug("Ack, no proximity manager??!?")
		return

	pTopWindow = App.TopWindow_GetTopWindow()
	if (pTopWindow.IsCutsceneMode()):
		#debug("We're in cutscene mode, don't call out")
		return

	if (pTopWindow.IsBridgeVisible()):
		#debug("We're on the bridge, so Helm's got the wheel")
		return

	kLocation = pShip.GetWorldLocation()
	fSpeed = pShip.GetVelocityTG().Length()
	if (fSpeed < 0.05):
		#debug("Going too slow to worry")
		return

	if (pShip.IsDocked()):
		#debug("Ship is docked, don't bother")
		return

	if (pShip.IsDoingInSystemWarp()):
		#debug("Ship is intercepting, don't bother")
		return

	pWarpEngines = pShip.GetWarpEngineSubsystem()
	if (pWarpEngines):
		if (pWarpEngines.GetWarpState() != pWarpEngines.WES_NOT_WARPING):
			#debug("Ship is warping, don't bother")
			return

	if (MissionLib.GetPlayerShipController() != "Captain"):
		#debug("Kiska or Felix is flying, not the Captain")
		return

	global g_fLastCollisionAlertTime
	global g_fLastCollisionAlarmTime
	fTime = App.g_kUtopiaModule.GetGameTime()
	if (fTime - g_fLastCollisionAlertTime < 30.0 and fTime - g_fLastCollisionAlarmTime < 5.0):
		#debug("Enough alredy, we know we're in danger")
		return

	idTarget = App.NULL_ID
	pTarget = pShip.GetTarget()
	if (pTarget):
		idTarget = pTarget.GetObjID()

	# Grab the helm, if any (not needed)
	pHelm = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Helm")

	# The ship is 4 units long.. see what we'll hit within 3 ship lengths + the next 8 seconds after that..
	fRadius = 12.0 + 10.0*fSpeed
	#debug("Collision check, range = " + str(fRadius))

	# Loop through the near objects..
	pIterator = pProxManager.GetNearObjects(kLocation, fRadius)
	if (pIterator):
		pObject = pProxManager.GetNextObject(pIterator)
		while (pObject != None):
			if (pObject and pObject.GetObjID() != idTarget):
				pPlanet = App.Planet_Cast(pObject)
				pOtherShip = App.ShipClass_Cast(pObject)
				pPhysicsObject = App.PhysicsObjectClass_Cast(pObject)

				bCall = 0
				if (pPlanet):
					bCall = DoPlanetCheck(pShip, pPlanet)
				elif (pOtherShip):
					bCall = DoShipCheck(pShip, pOtherShip)
				elif (pPhysicsObject):
					bCall = DoObjectCheck(pShip, pPhysicsObject)

				#debug("DoCall = " + str(bCall))

				if (bCall != 0):
					if (fTime - g_fLastCollisionAlertTime > 30.0):
						#debug("Time for a voice line")

						kLines = []

						# If we're on a collision course with them, not the other way around
						if (bCall == 1):
							kLines.append("CollisionAlert1")
							kLines.append("CollisionAlert2")

						if (pPlanet):
							if (pPlanet.IsTypeOf(App.CT_SUN)):
								kLines.append("CollisionAlert11")
							else:
								kLines.append("CollisionAlert10")
						elif (pOtherShip):
							pProp = pOtherShip.GetShipProperty()
							if (pProp.GetGenus() == App.GENUS_STATION and pObject.GetName()[:8] != "Dry Dock"):
								kLines.append("CollisionAlert7")
							else:
								kLines.append("CollisionAlert3")
								if (bCall == 2):
									kLines.append("CollisionAlert4")
						else:
							kLines.append("CollisionAlert5")
							kLines.append("CollisionAlert6")

						g_fLastCollisionAlertTime = fTime
						if (pHelm and len(kLines) > 0):
							App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SPEAK_LINE, kLines[App.g_kSystemWrapper.GetRandomNumber(len(kLines))]).Play()
					elif (fTime - g_fLastCollisionAlarmTime > 5.0):
						#debug("Time for sound")

						g_fLastCollisionAlarmTime = fTime
						App.TGSoundAction_Create("CollisionAlertSound").Play()

			# Get the next object to check
			pObject = pProxManager.GetNextObject(pIterator)

	pProxManager.EndObjectIteration(pIterator)

	return

###############################################################################
#	DoPlanetCheck(), DoShipCheck(), DoObjectCheck()
#	
#	Check to see if we should alert the player to an impending collision
#	
#	Args:	pShip	- the player's ship
#			pObject	- the object to test
#	
#	Return:	bCall	- if we want to out/played sound
###############################################################################
def DoPlanetCheck(pShip, pObject):
	# Are we facing the planet?
	kForward = pShip.GetWorldForwardTG()
	kLocation = pShip.GetWorldLocation()
	kTheirLocation = pObject.GetWorldLocation()
	kTheirForward = pObject.GetWorldForwardTG()

	kToPlanet = kTheirLocation
	kToPlanet.Subtract(kLocation)

	kToPlanet.Unitize()
	fDotProd = kForward.Dot(kToPlanet)
	if (fDotProd < 0.7):
		# We aren't, so be quiet
		return 0

	return 1

def DoShipCheck(pShip, pObject):
	if (pObject.IsCloaked()):
		#debug("Don't call out about cloaked ships")
		return 0

	kForward = pShip.GetWorldForwardTG()
	kLocation = pShip.GetWorldLocation()
	kTheirLocation = pObject.GetWorldLocation()
	kTheirForward = pObject.GetWorldForwardTG()

	kToShip = kTheirLocation
	kToShip.Subtract(kLocation)

	if (kToShip.Length() > 40):
		pProp = pObject.GetShipProperty()
		#debug("Ship " + pObject.GetName() + " is " + str(kToShip.Length()) + " away, genus " + str(pProp.GetGenus()))
		if (pProp.GetGenus() != App.GENUS_STATION):
			# They're probably to far away, don't worry about it
			#debug("Ship " + pObject.GetName() + " is too far away")
			return 0
		elif (pObject.GetName()[:8] == "Dry Dock"):
#			debug("Dry dock is pretty small, no fears")
			return 0
		#else:
		#	debug("That's no ship... it's a space station!")

	kToShip.Unitize()
	fDotProd = kForward.Dot(kToShip)
	if (fDotProd > 0.85):
		# We are!
		return 1
	
	fDotProd2 = kTheirForward.Dot(kToShip)
	if (fDotProd2 < -0.9):
		# Make sure they have some speed..
		fSpeed = pObject.GetVelocityTG().Length()
		if (fSpeed > 0.1):
			# They are!
			return 2

	return 0

def DoObjectCheck(pShip, pObject):
	if (pObject.IsTypeOf(App.CT_TORPEDO)):
		#debug("Don't call out about torps")
		return 0

	kForward = pShip.GetWorldForwardTG()
	kLocation = pShip.GetWorldLocation()
	kTheirLocation = pObject.GetWorldLocation()
	kTheirForward = pObject.GetWorldForwardTG()

	kToObject = kTheirLocation
	kToObject.Subtract(kLocation)

	if (kToObject.Length() > 70):
		# They're probably to far away, don't worry about it
		return 0

	kToObject.Unitize()
	fDotProd = kForward.Dot(kToObject)
	if (fDotProd < 0.85):
		# We aren't, so be quiet
		return 0

	return 1

###############################################################################
#	CloakedCollision()
#	
#	We hit a cloaked ship!
#	
#	Args:	pObject, pEvent	- the object and event that called us
#	
#	Return:	none
###############################################################################
def CloakedCollision(pObject, pEvent):
	pSet = App.g_kSetManager.GetSet("bridge")
	if not (pSet):
		pObject.CallNextHandler(pEvent)
		return

	pHelm = App.CharacterClass_GetObject(pSet, "Helm")
	if not (pHelm):
		pObject.CallNextHandler(pEvent)
		return

	global g_fLastCollisionAlertTime
	if (App.g_kUtopiaModule.GetGameTime() - g_fLastCollisionAlertTime < 5.0):
		pObject.CallNextHandler(pEvent)
		return

	g_fLastCollisionAlertTime = App.g_kUtopiaModule.GetGameTime()

	App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "CollidedWithCloakedShip", None, 1).Play()

	pObject.CallNextHandler(pEvent)
