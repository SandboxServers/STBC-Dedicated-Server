###############################################################################
#	Filename:	Starbase12.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Starbase 12 region. Also contains Starbase 12 control room character set.
#	
#	Created:	1/5/01 -	Alberto Fonseca
###############################################################################

import App
import Bridge.BridgeUtils
import MissionLib
import Bridge.Characters.Graff
import Bridge.HelmMenuHandlers
import Tactical.LensFlares

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " module...")

g_idDockAI = None

###############################################################################
#	Initialize()
#	
#	Initialize the Starbase 12 set.
#	
#	Args:	pSet	- The Starbase 12 set.
#	
#	Return:	none
###############################################################################
def Initialize(pSet):
	SetupEventHandlers(pSet)

	# Add a sun, far far away
	pSun = App.Sun_Create(1000.0, 1000, 500, "data/Textures/SunBlueWhite.tga", "data/Textures/Effects/SunFlaresWhite.tga")
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Blue lens flare, attached to the sun
	Tactical.LensFlares.BlueLensFlare(pSet, pSun)

	######
	# Create the Planet
	pPlanet = App.Planet_Create(400.0, "data/models/environment/planet.nif")
	pSet.AddObjectToSet(pPlanet, "New Holland")

	# Place the object at the specified location.
	pPlanet.PlaceObjectByName( "Planet1" )
	pPlanet.UpdateNodeOnly()



###############################################################################
#	SetupEventHandlers()
#	
#	Set up event handlers used by the Starbase 12 set.
#	
#	Args:	pSet	- The Starbase 12 set.
#	
#	Return:	none
###############################################################################
def SetupEventHandlers(pSet):
	pGame = App.Game_GetCurrentGame()
	pEpisode = pGame.GetCurrentEpisode()

	# Ship entrance event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_ENTERED_SET, pSet,
														__name__ + ".EnterSet")
	# Ship exit event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_EXITED_SET, pSet,
														__name__ + ".ExitSet")
	
###############################################################################
#	EnterSet(pObject, pEvent)
#	
#	Event handler for player's ship entering this set.
#	Create the Starbase 12 Control Room Set when the player enters.
#	
#	Args:	
#	
#	Return:	
###############################################################################
def EnterSet(pObject, pEvent):
	try:
		# Get ship entering set.
		pShip = App.ShipClass_Cast(pEvent.GetDestination())

		# Get player.
		pPlayer = App.Game_GetCurrentPlayer()

		if pShip.GetObjID() != pPlayer.GetObjID():
			# This ship isn't the player's ship.  We're done.
			return
	except AttributeError:
		# Ship or Player is None.  Nothing to do here.
		return

	# The player is entering a set.  If they're entering the Starbase 12
	# set, setup the SB12 Control Room.
	if pShip.GetContainingSet().GetName() == "Starbase12":
		SetupGraffSet()

###############################################################################
#	SetupGraffSet()
#	
#	Setup the Starbase 12 Control Room set, so Graff can say something
#	if the player chooses to dock.  If the set already exists, this
#	does nothing.
#	
#	Args:	None
#	
#	Return:	None
###############################################################################
def SetupGraffSet():
	pSB12Set = App.g_kSetManager.GetSet("FedOutpostSet_Graff")
	if not pSB12Set:
		pSB12Set = MissionLib.SetupBridgeSet("FedOutpostSet_Graff", "data/Models/Sets/FedOutpost/fedoutpost.nif", -30, 65, -1.55)
	if not App.CharacterClass_GetObject(pSB12Set, "Graff"):
		MissionLib.SetupCharacter("Bridge.Characters.Graff", "FedOutpostSet_Graff")

	# Enable dock button.
	pButton = Bridge.BridgeUtils.GetDockButton()
	if(pButton):
		pButton.SetEnabled()


###############################################################################
#	ExitSet(pObject, pEvent)
#	
#	Event handler for player's ship exiting this set.
#	Delete the Starbase 12 Control Room Set when the player enters.
#
#	Args:	
#	
#	Return:	
###############################################################################
def ExitSet(pObject, pEvent):
	try:
		# Get ship exiting set.
		pShip = App.ShipClass_Cast(pEvent.GetDestination())

		# Get player.
		pPlayer = App.Game_GetCurrentPlayer()

		if pShip.GetObjID() != pPlayer.GetObjID():
			# This ship isn't the player's ship.  We're done.
			return
	except AttributeError:
		# Ship or Player is None.  Nothing to do here.
		return

	# The player's ship is exiting a set.  Check if it's exiting
	# the Starbase 12 set...
	if pEvent.GetCString() == "Starbase12":
		# Delete the Starbase 12 Control Room Set.
		pStarbaseControlSet = App.g_kSetManager.GetSet("FedOutpostSet_Graff")
		if pStarbaseControlSet:
			App.g_kSetManager.DeleteSet("FedOutpostSet_Graff")
	
		Bridge.Characters.Graff.RemoveEventHandlers()

		# Disable dock button.
		pButton = Bridge.BridgeUtils.GetDockButton()
		if(pButton):
			pButton.SetDisabled()

		
###############################################################################
#	DockStarbase():
#	
#	Make Player's ship dock/undock with Starbase 12.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def DockStarbase():
	# Get Player.
	pPlayer = MissionLib.GetPlayer()
	if(pPlayer is None):
		return
	
	# Get Starbase 12 Set.	
	pStarbase12Set = App.g_kSetManager.GetSet("Starbase12")
	if(pStarbase12Set is None):
#		debug("DockStarbase() unable to get Starbase 12 set.")
		return

	# Get Starbase 12.
	pStarbase12 = pStarbase12Set.GetObject("Starbase 12")
	if(pStarbase12 is None):
#		debug("DockStarbase() unable to get Starbase 12.")
		return

	# Check if there's a special action for Graff when the
	# player docks with the starbase.
	global g_idGraffAction
	try:
		pGraffAction = App.TGAction_Cast( App.TGObject_GetTGObjectPtr( g_idGraffAction ) )
	except NameError:
		pGraffAction = None

	try:
		bFadeEnd = g_bFadeGraffEnd
	except NameError:
		bFadeEnd = 1

	# Set AI for docking/undocking.
	import AI.Compound.DockWithStarbase
	MissionLib.SetPlayerAI("Helm", AI.Compound.DockWithStarbase.CreateAI(pPlayer, pStarbase12, pGraffAction, NoRepair = not g_bRepairsEnabled, FadeEnd = bFadeEnd))

###############################################################################
#	StarbaseRepairsEnabled
#	
#	When a ship docks with the starbase, this sets whether or not
#	that ship is repaired.
#	
#	Args:	bRepairsEnabled	- 0 for no repairs, 1 to allow repairs.
#	
#	Return:	None
###############################################################################
g_bRepairsEnabled = 1
def StarbaseRepairsEnabled(bRepairsEnabled):
	global g_bRepairsEnabled
	g_bRepairsEnabled = bRepairsEnabled

###############################################################################
#	SetGraffDockingAction
#	
#	Set a special TGAction to replace Commander Graff's normal
#	response when the player docks with Starbase 12.
#	
#	Args:	pAction	- The replacement action.  If this is None,
#					  Graff's normal behavior is restored.
#			bFadeEnd- True if the camera should fade to black after
#					  Graff's cutscene finishes, as the camera switches
#					  to the Sovereign flying out of the starbase.
#	
#	Return:	None
###############################################################################
def SetGraffDockingAction(pAction = None, bFadeEnd = 1):
	global g_idGraffAction
	global g_bFadeGraffEnd
	g_bFadeGraffEnd = bFadeEnd
	# If there was a replacement action before, make sure it's cleaned up.
	try:
		pGraffAction = App.TGAction_Cast( App.TGObject_GetTGObjectPtr( g_idGraffAction ) )
		if pGraffAction:
			pGraffAction.Completed()
	except NameError: pass

	if pAction:
		g_idGraffAction = pAction.GetObjID()
	else:
		g_idGraffAction = App.NULL_ID
