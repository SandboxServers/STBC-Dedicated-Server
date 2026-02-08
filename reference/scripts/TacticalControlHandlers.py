###############################################################################
#	Filename:	TacticalControlHandlers.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	User interface handlers for the Tactical Control interface.
#	
#	Created:	5/10/01 -	KDeus
###############################################################################
import App

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " interface module...")

###############################################################################
#	Initialize()
#	
#	Setup all the event handlers we'll need to handle
#	the events we need to handle.  :P
#	
#	Args:	pWindow	- The TacticalControlWindow whose interface we're handling.
#	
#	Return:	none
###############################################################################
def Initialize(pWindow):
	# Setup our event handlers.
	# A lot of our handling can be done by functions that
	# already exist in the tactical interface handlers.
	lEventHandlerMap = (
		(App.ET_INPUT_FIRE_TERTIARY,			__name__ + ".FireTertiaryWeapons"),
		(App.ET_INPUT_FIRE_SECONDARY,			__name__ + ".FireSecondaryWeapons"),
		(App.ET_INPUT_FIRE_PRIMARY,				__name__ + ".FirePrimaryWeapons"),
		(App.ET_INPUT_TOGGLE_PICK_FIRE,			__name__ + ".TogglePickFire"),
		)

	for eType, sFunc in lEventHandlerMap:
		# Add instance handlers for these events.
		pWindow.AddPythonFuncHandlerForInstance(eType, sFunc)

	# Done

###############################################################################
#	HandleMouse()
#	
#	Handles mouse events. This is registered as an event handler for
#	TacticalWindow.
#	
#	Args:	pTacCon	- The tactical control window.
#			pEvent	- mouse event
#	
#	Return:	none
###############################################################################
def HandleMouse(pTacCon, pEvent):
	# Check if anyone else wants to handle this, unless we have the mouse
	# grab.
	if ((App.g_kRootWindow.GetMouseGrabOwner() == None) or
		(App.g_kRootWindow.GetMouseGrabOwner().GetObjID() != pTacCon.GetObjID())):
		pTacCon.CallNextHandler(pEvent)

	if (pEvent.IsButtonEvent() and pEvent.EventHandled()):
		pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
		pTCW.SetIgnoreNextMouseKeyEvent(1)
		return

	# If it's a button event and we're in mouse pick fire mode,
	# we want to handle it.
	if pEvent.IsButtonEvent()  and  (pTacCon.GetMousePickFire()):
		# Nobody handled it, so we should fire weapons.
		HandleMouseButtons(pTacCon, pEvent)
		pEvent.SetHandled()

###############################################################################
#	HandleKeyboard()
#	
#	Handles keyboard events. This is registered as an event handler for
#	TacticalWindow.
#	
#	Args:	pWindow, the TacticalControlWindow
#			pEvent, the TGKeyboardEvent
#	
#	Return:	none
###############################################################################
def HandleKeyboard(pWindow, pEvent):
	if (pEvent.EventHandled() == 0):
		App.g_kKeyboardBinding.LaunchEvent(pEvent.GetUnicode(), pEvent.GetKeyState(), pWindow)

	if (pEvent.EventHandled() == 0):
		pWindow.CallNextHandler(pEvent)
	else:
		pass
		#debug("Key was handled.")
		#App.Breakpoint()

###############################################################################
#	HandleMouseButtons()
#	
#	Handles mouse buttons in the Tactical interface.
#	
#	Args:	TGMouseEvent	pEvent		- the mouse event
#	
#	Return:	none
###############################################################################
def HandleMouseButtons(pTactical, pEvent):
	"Handles mouse buttons for the Tactical interface"
	pEvent.SetHandled()

###############################################################################
#	FireWeapons(pShip, eGroup)
#	
#	Fires the specified weapon system group. (primary, secondary, tertiary)
#	
#	Args:	pShip		- the ship that is firing
#			bFiring		- whether we are starting or stopping firing
#			eGroup		- the weapon system group to look for
#						  (i.e. App.ShipClass.WG_PRIMARY, WG_SECONDARY,
#						  WG_TERTIARY)
#	
#	Return:	none
###############################################################################
def FireWeapons(pShip, bFiring, eGroup):
	if (pShip != None):
		# Check if we're starting or stopping...
		if (bFiring == 1):
			# Starting.  Check if we have a target..
			pSystem = pShip.GetWeaponSystemGroup(eGroup)
			if (pSystem != None):
				pSystem.StartFiring(pShip.GetTarget(), pShip.GetTargetOffsetTG())
				pSystem.SetForceUpdate(1) # update and fire immediately
		else:
			# Stopping.
			pSystem = pShip.GetWeaponSystemGroup(eGroup)
			if (pSystem != None):
				pSystem.StopFiring()

	return

###############################################################################
###############################################################################
##	Event handlers for input-generated events.
##	
##	Handlers for events that were (probably) generated from
##	user input.  Simple little functions that perform a single
##	task based on the event given to them..
##	
##	Args:	pObject		- The destination for the event (probably the
##						  tactical window)
##			pEvent		- The event generated.
##	
##	Return:	none
###############################################################################
###############################################################################
def FirePrimaryWeapons(pObject, pEvent):
	# Get the player's ship...
	pShip = App.Game_GetCurrentPlayer()

	FireWeapons(pShip, pEvent.GetBool(), App.ShipClass.WG_PRIMARY)
	pObject.CallNextHandler(pEvent)

def FireSecondaryWeapons(pObject, pEvent):
	# Get the player's ship...
	pShip = App.Game_GetCurrentPlayer()

	FireWeapons(pShip, pEvent.GetBool(), App.ShipClass.WG_SECONDARY)
	pObject.CallNextHandler(pEvent)

def FireTertiaryWeapons(pObject, pEvent):
	# Get the player's ship...
	pShip = App.Game_GetCurrentPlayer()

	FireWeapons(pShip, pEvent.GetBool(), App.ShipClass.WG_TERTIARY)
	pObject.CallNextHandler(pEvent)

def TogglePickFire(pObject, pEvent):
	# Get the tactical control window.
#	debug("Toggle pick fire.")
	pTacWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTop = App.TopWindow_GetTopWindow()
	if pTacWindow:
		# Toggle whether or not the mouse's location determines
		# where weapons are fired.
		pMenu = pTacWindow.GetTacticalMenu()

		if pMenu.IsCompletelyVisible() or pTop.IsTacticalVisible():
			pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
			pFireButton = App.STButton_Cast(pMenu.GetButtonW(pDatabase.GetString("Manual Aim")))
			App.g_kLocalizationManager.Unload(pDatabase)

			pFireButton.SetChosen(not pFireButton.IsChosen())
			pTacWindow.SetMousePickFire(pFireButton.IsChosen())

			# This will update Felix's menus to use "Attack maneuver" if appropriate.
			import Bridge.TacticalMenuHandlers
			Bridge.TacticalMenuHandlers.UpdateOrders(0)

	pObject.CallNextHandler(pEvent)

