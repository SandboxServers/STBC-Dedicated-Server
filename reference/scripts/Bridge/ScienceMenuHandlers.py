###############################################################################
#	Filename:	ScienceMenuHandlers.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Script to create the science menu and handle some of its events.
#	
#	Created:	01/22/2001 -	Alberto Fonseca
###############################################################################

import App
import BridgeUtils
import MissionLib
import EngineerMenuHandlers
import Systems.Starbase12
import Characters.Graff

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " module...")

###############################################################################
#	CreateMenus()
#	
#	Creates the science menu
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def CreateMenus():
#	debug("Creating Science Menu")

	pTopWindow = App.TopWindow_GetTopWindow()
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()

	###############################################################################
	# Science
	###############################################################################
	#
	# Science
	#	Report
	#	Communicate
	#	Scan
	#		Target
	#		Object
	#		Area
	#	Launch Probe
	#
	###############################################################################
	
	# Get string database.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	# Get strings from database.
	kScience	= pDatabase.GetString("Science")
	kReport		= pDatabase.GetString("Report")
	kTarget		= pDatabase.GetString("Scan Target")
	kObject		= pDatabase.GetString("Scan Object")
	kArea		= pDatabase.GetString("Scan Area")
	kLaunch		= pDatabase.GetString("Launch Probe")
	
	# Import resolution dependent LCARS module for size/placement variables.
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	#pSciencePane = App.TGPane_Create(LCARS.TACTICAL_MENU_WIDTH, LCARS.TACTICAL_MENU_HEIGHT)
	pScienceMenu = App.STTopLevelMenu_CreateW(kScience)
	pSciencePane = App.STStylizedWindow_CreateW("StylizedWindow", "NoMinimize", kScience, 0.0, 0.0)
	pSciencePane.AddChild(pScienceMenu, 0.0, 0.0, 0)
	pScienceMenu.AddPythonFuncHandlerForInstance(App.ET_ST_BUTTON_CLICKED, 
													"Bridge.BridgeMenus.ButtonClicked")

	# Communicate
	import BridgeMenus
	pCommunicate = BridgeMenus.CreateCommunicateButton("Science", pScienceMenu)
	pScienceMenu.AddChild(pCommunicate)
	
	# Scanning
	pScienceMenu.AddChild(BridgeUtils.CreateBridgeMenuButton(kArea,		App.ET_SCAN,	App.CharacterClass.EST_SCAN_AREA,	pScienceMenu))

	pScanTarget = BridgeUtils.CreateBridgeMenuButton(kTarget,	App.ET_SCAN,	App.CharacterClass.EST_SCAN_OBJECT,	pScienceMenu)
	pScienceMenu.AddChild(pScanTarget)
	pScanTarget.SetDisabled()

	# Scan Object menu
	pScanObjectMenu = App.STCharacterMenu_CreateW(kObject)
	pScienceMenu.AddChild(pScanObjectMenu)
	
	# Add handlers for when objects enter/exit scannable status...
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_SENSORS_SHIP_IDENTIFIED,		pScienceMenu,	__name__ + ".ShipIdentified")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_EXITED_SET,					pScienceMenu,	__name__ + ".ExitedSet")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_TARGET_LIST_OBJECT_REMOVED,	pScienceMenu,	__name__ + ".ExitedSet")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_TARGET_LIST_OBJECT_ADDED,		pScienceMenu,	__name__ + ".ShipIdentified")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_IN_SYSTEM_WARP,				pScienceMenu,	__name__ + ".InSystemWarp")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_NAME_CHANGE,					pScienceMenu,	__name__ + ".PropertyChange")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_SCANNABLE_CHANGE,				pScienceMenu,	__name__ + ".PropertyChange")

	# Launch Probe
	pLaunch = BridgeUtils.CreateBridgeMenuButton(kLaunch,	App.ET_LAUNCH_PROBE, 0, pScienceMenu)
	pScienceMenu.AddChild(pLaunch)

	# If in multiplayer, disable all single-player specific buttons	
	if (App.g_kUtopiaModule.IsMultiplayer()):
		pCommunicate.SetDisabled()
		pLaunch.SetDisabled()

	# Unload string database
	App.g_kLocalizationManager.Unload(pDatabase)
	
	pSciencePane.SetNotVisible()
	pScienceMenu.SetNotVisible()

	# We don't want the "skip parent" behavior in this case, because otherwise
	# menu items would think that the window was their parent.
	pScienceMenu.SetNoSkipParent()

	pTacticalControlWindow.AddChild(pSciencePane, 0.0, 0.0, 0)
	pTacticalControlWindow.AddMenuToList(pScienceMenu)

	# Add event handlers for our menu items
	pScienceMenu.AddPythonFuncHandlerForInstance(App.ET_SCAN,			__name__ + ".Scan")
	pScienceMenu.AddPythonFuncHandlerForInstance(App.ET_LAUNCH_PROBE,	__name__ + ".LaunchProbe")
	pScienceMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE,	"Bridge.Characters.CommonAnimations.NothingToAdd")

	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_SET_PLAYER, pScienceMenu, __name__ + ".SetPlayer")
	SetPlayer(None, None)

def SetPlayer(pObject, pEvent):
	pShip = MissionLib.GetPlayer()
	if (pShip):
#		debug("Able to get ship")
		pShip.AddPythonFuncHandlerForInstance(App.ET_TARGET_WAS_CHANGED,	__name__ + ".TargetChanged")
		pShip.AddPythonFuncHandlerForInstance(App.ET_SET_TARGET,			__name__ + ".TargetChanged")
#	else:
#		debug("Unable to get ship")

	BridgeUtils.ResetScanCounts()

	if (pObject and pEvent):
		pObject.CallNextHandler(pEvent)

###############################################################################
#	CreateScanButton()
#	
#	Creates a button to scan an object
#	
#	Args:	pObject	- object to create button for
#	
#	Return:	none
###############################################################################
def CreateScanButton(pObject):
	pObject = App.ObjectClass_Cast(pObject)
	if not (pObject):
		return None

	if (pObject.IsScannable() == 0):
		return None

	if not (pObject.GetName()):
		return None

	# Check if it's a cloaking ship. If so, then no big deal, we'll get another
	# event when it's ready for a scan button.
	pShip = App.ShipClass_Cast(pObject)
	if pShip:
		pCloak = pShip.GetCloakingSubsystem()
		if pCloak:
			if pCloak.IsCloaked() or pCloak.IsCloaking() or pCloak.IsDecloaking():
				return None

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pScienceMenu = pTacticalControlWindow.FindMenu(pDatabase.GetString("Science"))
	App.g_kLocalizationManager.Unload(pDatabase)

	pScanMenu = MissionLib.GetCharacterSubmenu("Science", "Scan Object")

	pButton = pScanMenu.GetButtonW(pObject.GetDisplayName())
	if (pButton):
		return None

	pScanButton = App.STButton_CreateW(pObject.GetDisplayName())

	pScanEvent = App.TGIntEvent_Create()
	pScanEvent.SetSource(pObject)
	pScanEvent.SetDestination(pScienceMenu)
	pScanEvent.SetInt(App.CharacterClass.EST_SCAN_OBJECT)
	pScanEvent.SetEventType(App.ET_SCAN)

	pScanButton.SetActivationEvent(pScanEvent)

	return pScanButton
	
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
		pScienceMenu = pTacticalControlWindow.FindMenu(pDatabase.GetString("Science"))
		pScanMenu = pScienceMenu.GetSubmenuW(pDatabase.GetString("Scan Object"))
		App.g_kLocalizationManager.Unload(pDatabase)

		if ((not pPlayer) or (pPlayer.GetObjID() == pObject.GetObjID())):
			# Clear the menu
			pScanMenu.KillChildren()
		else:
			if (pObject.GetName()):
				pScanMenu.RemoveItemW(pObject.GetDisplayName())

			# Update scan target button just in case.
			TargetChanged (None, None)

	# Don't call next handler, because we're a broadcast handler.


###############################################################################
#	ShipIdentified()
#	
#	Called when a ship has been identified
#	
#	Args:	pObject, pEvent	- the object and event that called us
#	
#	Return:	none
###############################################################################
def ShipIdentified(pObject, pEvent = None):
	if (pEvent):
		pIdentifiedObject = App.ObjectClass_Cast(pEvent.GetDestination())
	else:
		pIdentifiedObject = App.ObjectClass_Cast(pObject)

	if (not pIdentifiedObject)  or  (pIdentifiedObject.GetName() is None):
		return

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pScienceMenu = pTacticalControlWindow.FindMenu(pDatabase.GetString("Science"))
	pScanMenu = pScienceMenu.GetSubmenuW(pDatabase.GetString("Scan Object"))
	App.g_kLocalizationManager.Unload(pDatabase)

	pButton = CreateScanButton(pIdentifiedObject)
	if pButton:
		pScanMenu.AddChild(pButton)

###############################################################################
#	PropertyChange()
#	
#	A property (name, scannability) changed - deal with it
#	
#	Args:	pObject, pEvent	- the object and event that called us
#	
#	Return:	none
###############################################################################
def PropertyChange(pObject, pEvent):
	pShip = App.ObjectClass_Cast(pEvent.GetSource())
	if not (pShip):
		return

	ExitedSet(pShip)

	idPlayerSet = App.NULL_ID
	pPlayer = MissionLib.GetPlayer()
	
	pShipSet = pShip.GetContainingSet()
	if not (pShipSet):
		return 

	if (pShip.IsScannable()):
		if (pShipSet.GetObjID() == idPlayerSet):
			ShipIdentified(pShip)


###############################################################################
#	Scan(pObject, pEvent)
#	
#	Handles the "scan" menu item.
#	
#	Args:	pObject		- the target of the event
#			pEvent		- the event
#	
#	Return:	none
###############################################################################
def Scan(pObject, pEvent):
	try:
		iType = pEvent.GetInt()

		pGame = App.Game_GetCurrentGame()
		pShip = App.ShipClass_Cast(pGame.GetPlayer())
		pSensors = pShip.GetSensorSubsystem()
		pTarget = App.ShipClass_Cast(pShip.GetTarget())
		if (pEvent.GetSource()):
			if (App.ObjectClass_Cast(pEvent.GetSource())):
				pTarget = App.ObjectClass_Cast(pEvent.GetSource())
        
		if (iType == App.CharacterClass.EST_SCAN_OBJECT):
			if (pTarget):
				pSequence = App.TGSequence_Create()

				pAction3 = App.TGScriptAction_Create("Actions.ShipScriptActions", "ScanObject", pShip.GetObjID(), pTarget.GetObjID())
				pSequence.AddAction(pAction3)

				pSequence.Play()

		if (iType == App.CharacterClass.EST_SCAN_AREA):
			# Setup a sequence to scan each ship in the area.
			pSequence = pSensors.ScanAllObjects()
			if (pSequence):
				pSequence.Play()
	except:
		pass
#		debug("Exception raised in ScienceMenuHandlers.Scan()")

	import BridgeHandlers
	BridgeHandlers.TalkToScience()

	pObject.CallNextHandler(pEvent)

###############################################################################
#	LaunchProbe(pObject, pEvent)
#	
#	Launches a probe from the player's ship.
#	
#	Args:	pObject		- the target of the event
#			pEvent		- the event that was sent
#	
#	Return:	none
###############################################################################
def LaunchProbe(pObject, pEvent):
	# Launch one of them probe thingies from the player's ship.
	pShip = MissionLib.GetPlayer()

	if (pShip == None):
		pObject.CallNextHandler(pEvent)
		return

	pSet = pShip.GetContainingSet()
	pSensors = pShip.GetSensorSubsystem()
	if (not pSet) or (not pSensors):
		pObject.CallNextHandler(pEvent)
		return

	# Check the number of probes remaining.
	if pSensors.GetNumProbes() <= 0:
		# No probes remaining.
		pObject.CallNextHandler(pEvent)
		return

	# Decrement the number of probes available by one.
	pSensors.SetNumProbes(pSensors.GetNumProbes() - 1)

	pSequence = App.TGSequence_Create()

	pAction1 = App.TGScriptAction_Create("Bridge.BridgeUtils", "DisableLaunchProbe")
	pSequence.AddAction(pAction1)
	pAction2 = App.TGScriptAction_Create(__name__, "MakeLaunchProbeAction", pShip.GetObjID())
	pSequence.AddAction(pAction2, pAction1, 0.5)
	pAction3 = App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableLaunchProbe")
	pSequence.AddAction(pAction3, pAction2)

	pSequence.Play()

	pObject.CallNextHandler(pEvent)

###############################################################################
#	MakeLaunchProbeAction(pAction, iShipID)
#	
#	Makes and plays a "launch object" action with a unique probe name.
#	
#	Args:	pAction	- the action, unused
#			iShipID	- the ID of the ship launching the probe
#	
#	Return:	zero for end
###############################################################################
def MakeLaunchProbeAction(pAction, iShipID):
	pShip = App.ShipClass_Cast(App.TGObject_GetTGObjectPtr(iShipID))

	# Abort if we have no ship, or if that ship is currently doing an in-system
	# warp.
	if (pShip == None) or (pShip.IsDoingInSystemWarp() == 1):
		return(0)

	pSet = pShip.GetContainingSet()
	pSensors = pShip.GetSensorSubsystem()
	if (not pSet) or (not pSensors):
		return 0

	pProp = pSensors.GetProperty()
	if not pProp:
		return 0

	# Find an appropriate name for this probe. Start by trying the number of probes
	# that have been launched since the last repair.
	bDone = 0
	iNum = pProp.GetMaxProbes() - pSensors.GetNumProbes()
	pcName = ""
	while (bDone == 0):
		pcName = "Probe " + str(iNum)
		pOtherProbe = App.ShipClass_GetObject(pSet, pcName)
		if (pOtherProbe == None):
			bDone = 1	
		iNum = iNum + 1

	pLaunchSound = App.TGSoundAction_Create("Probe Launch", App.TGSAF_DEFAULTS, pSet.GetName())
	pLaunchSound.SetNode( pShip.GetNode() )

	pSequence = App.TGSequence_Create()
	pSequence.AppendAction(pLaunchSound)
	pSequence.AppendAction(App.TGScriptAction_Create("Actions.ShipScriptActions", "LaunchObject", iShipID, pcName, App.ObjectEmitterProperty.OEP_PROBE))
	pSequence.AppendAction(App.TGScriptAction_Create("Actions.ShipScriptActions", "PushObject", pSet.GetName(), pcName, 10.0))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "SendLaunchedProbeEventAction", pSet.GetName(), pcName, pShip.GetObjID()))
	pSequence.Play()

	return(0)

###############################################################################
#	SendLaunchedProbeEventAction(pAction, pProbeName, iShipID)
#	
#	Sends the "launched probe" event.
#	
#	Args:	pAction			- the script action, passed in automatically
#			pSetName		- the name of the set where the probe was launched
#			pProbeName		- the name of the probe
#			iShipID			- the ID of the ship that launched the probe
#	
#	Return:	zero for end
###############################################################################
def SendLaunchedProbeEventAction(pAction, pSetName, pProbeName, iShipID):
#	debug("Sending probe launch event...")
	pSet = App.g_kSetManager.GetSet(pSetName)
	if (pSet == None):
		return(0)

	pShip = App.ShipClass_Cast(App.TGObject_GetTGObjectPtr(iShipID))
	pProbe = App.ShipClass_GetObject(pSet, pProbeName)
	if (pProbe != None) and (pShip != None):
		# Send a "launched probe" event to the ship. We'll use the same event type as this one.
		pLaunchEvent = App.TGEvent_Create()
		pLaunchEvent.SetSource(pProbe)
		pLaunchEvent.SetDestination(pShip)
		pLaunchEvent.SetEventType(App.ET_LAUNCH_PROBE)
		App.g_kEventManager.AddEvent(pLaunchEvent)
	
	return(0)

###############################################################################
#	TargetChanged()
#	
#	Update the useability of the "ScanTarget" button
#	
#	Args:	pObject, pEvent	- the object and event that called us
#	
#	Return:	none
###############################################################################
def TargetChanged(pObject, pEvent):
	import Bridge.BridgeMenus

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()

	pScienceMenu = pTacticalControlWindow.FindMenu(pDatabase.GetString("Science"))

	if (pScienceMenu):
		pScanTarget = pScienceMenu.GetButtonW(pDatabase.GetString("Scan Target"))
		if (pScanTarget):
			pShip = MissionLib.GetPlayer()
			if (pShip):
				pTarget = pShip.GetTarget()
				if (pTarget):
					if (pTarget.IsScannable()):
						if (BridgeUtils.g_iScanTargetDisabledCount == 0) and (BridgeUtils.g_iScanDisabledCount == 0):
							pScanTarget.SetEnabled()
						else:
							pScanTarget.SetDisabled()
					else:
						pScanTarget.SetDisabled()
				else:
					pScanTarget.SetDisabled()
			else:
				pScanTarget.SetDisabled()

	App.g_kLocalizationManager.Unload(pDatabase)

	if (pObject and pEvent):
		pObject.CallNextHandler(pEvent)

###############################################################################
#	InSystemWarp(pMenu, pEvent)
#	
#	Called when the in-system warp status of a ship changes.
#	
#	Args:	pMenu	- the science menu
#			pEvent	- the event
#	
#	Return:	none
###############################################################################
def InSystemWarp(pMenu, pEvent):
	pPlayer = MissionLib.GetPlayer()
	pShip = App.ShipClass_Cast(pEvent.GetDestination())

	# only do enabling of probe button if not in multiplayer.  IN multiplayer,
	# you cannot launch probes.
	if (not App.g_kUtopiaModule.IsMultiplayer()):
		if pPlayer and pShip and (pPlayer.GetObjID() == pShip.GetObjID()):
			# Player's in-system warp status changed.
			if (pEvent.GetBool() == 1):
				# Player is now using in-system warp.
				BridgeUtils.DisableLaunchProbe()
			else:
				# No longer using in-system warp.
				BridgeUtils.EnableLaunchProbe()
