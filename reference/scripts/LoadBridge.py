##############################################################################
#	Filename:	LoadBridge.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	This contains the code to load the bridge.  The type of bridge type is 
#	passed in as a string.  Currently supported bridges are: "GalaxyBridge"
#	and "SovereignBridge".  These correspond to the GalaxyBridge.py and
#	SovereignBridge.py files, and these files call into the specific
#	character scripts to setup animations for them.
#
#	The bridge set has a number of specially named objects.  These have 
#	special names so they can be accessed in any bridge generically.  These
#	often will be different objects when a bridge changes.  They are:
#	"bridge"	- the bridge set.  This is in the SetManager's namespace
#	"bridge"	- the bridge model. This is in the BridgeSet's namespace
#	"viewscreen"- the viewscreen object attached to the bridge
#	"maincamera"- the bridge camera that is the captain's view
#
#	Created:	9/12/00 -	DLitwin
###############################################################################

import App
import Tactical.Interface.TacticalControlWindow
import Bridge.Characters.Felix
import Bridge.Characters.Kiska
import Bridge.Characters.Saffi
import Bridge.Characters.Miguel
import Bridge.Characters.Brex


#
# Module globals
#
#kDebugObj = App.CPyDebug()

# Our bridge random beep event type.  Set below, default to invalid (0)
ET_BRIDGE_BEEP = 0


g_idBeepTimer = App.NULL_ID


###############################################################################
#	Load()
#
#	Load the generic bridge by creating the bridge set then add in the specific
#	bridge model and character configurations for the bridge type specified.
#
#	Args:	sBridgeConfigScript	-	The name of the script that contains
#									functions to create the bridge model and
#									configure the characters animations to that
#									bridge
#
#	Return:	none
###############################################################################
def Load(sBridgeConfigScript):
#	kDebugObj.Print("Loading the " + sBridgeConfigScript + " bridge")

	#
	# Check to see if there is a Set called "bridge" already.  If not, create
	# it for the first time.
	#
	pBridgeSet = App.BridgeSet_Cast(App.g_kSetManager.GetSet("bridge"));
	if (pBridgeSet == None):
#		kDebugObj.Print("No previous bridge")
		pBridgeSet = CreateAndPopulateBridgeSet()
	else:
		# Reset all the extras..
		ResetExtraLocations()

		#
		# If it already existed, check to see if the bridge set is configured
		# for what we are requesting.  If so, we're done.  Otherwise, unload
		# the previous config and load up with the new one
		#
		if (pBridgeSet.IsSameConfig(sBridgeConfigScript)):
#			kDebugObj.Print(sBridgeConfigScript + " is already loaded")
			return
		else:
			# Unload animations and sounds of the previous bridge
			pcOldBridgeConfigScript = pBridgeSet.GetConfig ()
			pOldMod = __import__("Bridge." + pcOldBridgeConfigScript)
			pOldMod.UnloadAnimations()
			pOldMod.UnloadSounds()


	# Save away the camera our viewscreen was displaying
	pCamera = None
	pViewScreen = pBridgeSet.GetViewScreen()
	if (pViewScreen != None):
		pCamera = pViewScreen.GetRemoteCam()

	#
	# Remove the old bridge model and viewscreen, if they existed
	#
	pBridgeSet.DeleteObjectFromSet("bridge")		# Remove the bridge, if it exists
	pBridgeSet.DeleteObjectFromSet("viewscreen")	# Remove viewscreen, if it exists
	pBridgeSet.DeleteCameraFromSet("maincamera")	# Remove maincamera, if it exists

	#
	# Now call the config script to create our bridge model, viewscreen
	# and to configure our characters to that bridge
	#
	pMod = __import__("Bridge." + sBridgeConfigScript)
	pMod.CreateBridgeModel(pBridgeSet)
	pMod.ConfigureCharacters(pBridgeSet)
	pMod.PreloadAnimations ()

	if (pCamera != None):					# reset our viewscreen to its
		pViewScreen = pBridgeSet.GetViewScreen()
		pViewScreen.SetRemoteCam(pCamera)	#   previous state, if it had one
		pViewScreen.SetIsOn(1)

	pBridgeSet.SetConfig(sBridgeConfigScript)		# store our config

	import Bridge.Characters.CommonAnimations
	Bridge.Characters.CommonAnimations.PutGuestChairOut()

#	kDebugObj.Print("Done loading the " + sBridgeConfigScript + " bridge")


###############################################################################
#	CreateCharacterMenus()
#	
#	Creates Tactical, Helm, Science, Engineering, and XO menus
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def CreateCharacterMenus():
	# Create our Tactical menus		
	import Bridge.TacticalMenuHandlers
	Bridge.TacticalMenuHandlers.CreateMenus()

	# Create our Helm menus
	import Bridge.HelmMenuHandlers
	Bridge.HelmMenuHandlers.CreateMenus()

	# Create our Science menus
	import Bridge.ScienceMenuHandlers
	Bridge.ScienceMenuHandlers.CreateMenus()

	# Create our XO menus
	import Bridge.XOMenuHandlers
	Bridge.XOMenuHandlers.CreateMenus()

	# Create our Engineering menus
	import Bridge.EngineerMenuHandlers
	Bridge.EngineerMenuHandlers.CreateMenus()

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow() 
	pMenu = pTacticalControlWindow.FindMenu(pDatabase.GetString("Tactical"))
	pPane = pTacticalControlWindow.GetMenuParentPane(pDatabase.GetString("Tactical"))
	if (pPane != None):
		pPane.SetNotVisible()
		pMenu.SetNotVisible()
	App.g_kLocalizationManager.Unload(pDatabase)

	Tactical.Interface.TacticalControlWindow.SetupBridgeNone()


###############################################################################
#	CreateAndPopulateBridgeSet()
#
#	Create the generic bridge set and add the crew without configuring them to
#	particular bridge model
#	Called only by Load() above.
#
#	Args: none
#
#	Return:	BridgeSet object	-	the BridgeSet object created
###############################################################################
def CreateAndPopulateBridgeSet():
#	kDebugObj.Print("Creating the generic bridge set")

	pBridgeSet = App.BridgeSet_Create()
	App.g_kSetManager.AddSet(pBridgeSet, "bridge")

	# Create ambient light source
	pBridgeSet.CreateAmbientLight(1.000000, 1.000000, 1.000000, 0.7000000, "ambientlight1")
	pLight = pBridgeSet.GetLight("ambientlight1")
	pLight.UnilluminateEntireSet()

	CreateCharacterMenus()

	# Load bridge characters
	Bridge.Characters.Felix.CreateCharacter(pBridgeSet)
	Bridge.Characters.Kiska.CreateCharacter(pBridgeSet)
	Bridge.Characters.Saffi.CreateCharacter(pBridgeSet)
	Bridge.Characters.Miguel.CreateCharacter(pBridgeSet)
	Bridge.Characters.Brex.CreateCharacter(pBridgeSet)

	# Load some random extras...
	import MissionLib
	for i in range(3):
		pcPath = None

		if (App.g_kSystemWrapper.GetRandomNumber(2) == 0):
			pcPath = "Bridge.Characters.FemaleExtra" + str(i+1)
		else:
			pcPath = "Bridge.Characters.MaleExtra" + str(i+1)

		pModule = __import__(pcPath)
		pModule.CreateCharacter(pBridgeSet)

	# Load up the generic bridge sounds
	LoadSounds()

	# Ambient looping bridge SFX
	pSound = App.g_kSoundManager.GetSound("AmbBridge")
	if (pSound != None):
		pSound.SetLooping(1)
		pSound.SetPriority(1.0)
		pSound.Play()

	# Setup the handler function, if it hasn't been setup already
	global ET_BRIDGE_BEEP, g_idBeepTimer
	if (ET_BRIDGE_BEEP == 0):
		ET_BRIDGE_BEEP = App.Game_GetNextEventType()
		pGame = App.Game_GetCurrentGame()
		pGame.AddPythonFuncHandlerForInstance(ET_BRIDGE_BEEP, "LoadBridge.BridgeBeep")
	g_idBeepTimer = App.NULL_ID

	# Start off the beeping immediately
	#NewBeep(0)

	# Preload any common animations common to multiple bridges
	PreloadCommonAnimations ()

#	kDebugObj.Print("End of creating the generic bridge set")
	return pBridgeSet



###############################################################################
#	ResetExtraLocations()
#	
#	Resets the locations of any extra on the bridge set
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def ResetExtraLocations():
	pSet = App.g_kSetManager.GetSet("bridge")
	if not (pSet):
		return

	lNames = ["MaleExtra1", "MaleExtra2", "MaleExtra3", "FemaleExtra1", "FemaleExtra2", "FemaleExtra3"]
	for pcName in (lNames):
		pObject = App.CharacterClass_GetObject(pSet, pcName)
		if (pObject):
			pObject.SetHidden(1)


###############################################################################
#	ConfigureForShip()
#
#	Configure the bridge for the player's ship.  This basically means letting
#	the characters configure themselves to it.
#	Called when the player's ship is created and added to the Game object.
#
#	Args:	pBridgeSet	- the Bridge Set object
#			pShip		- the players ship (ShipClass object)
#
#	Return:	none
###############################################################################
def ConfigureForShip(pBridgeSet, pShip):
	Bridge.Characters.Felix.ConfigureForShip(pBridgeSet, pShip)
	Bridge.Characters.Kiska.ConfigureForShip(pBridgeSet, pShip)
	Bridge.Characters.Saffi.ConfigureForShip(pBridgeSet, pShip)
	Bridge.Characters.Miguel.ConfigureForShip(pBridgeSet, pShip)
	Bridge.Characters.Brex.ConfigureForShip(pBridgeSet, pShip)

###############################################################################
#	NewBeep()
#
#	Create a timer that fires off an ET_BRIDGE_BEEP event to the Game object
#	after the passed in delay
#
#	Args:	fDelay	- delay from current time for the beep even to be sent
#
#	Return:	none
###############################################################################
def NewBeep(fDelay):
	# Create the event and the event timer, if the Game object is still around
	pGame = App.Game_GetCurrentGame()
	if (pGame == None):
		RemoveBeepTimer()
		return
	global ET_BRIDGE_BEEP, g_idBeepTimer
	pEvent = App.TGEvent_Create()
	pEvent.SetEventType(ET_BRIDGE_BEEP)
	pEvent.SetDestination(pGame)
	pTimer = App.TGTimer_Create()
	pTimer.SetTimerStart(App.g_kUtopiaModule.GetGameTime() + fDelay)
	pTimer.SetDelay(0)
	pTimer.SetDuration(0)
	pTimer.SetEvent(pEvent)
	g_idBeepTimer = pTimer.GetObjID()
	App.g_kTimerManager.AddTimer(pTimer)


###############################################################################
#	BridgeBeep()
#
#	Ambient Bridge random beep
#
#	Args:	pGame	- the current Game object
#			pEvent	- the ET_BRIDGE_BEEP event
#
#	Return:	none
###############################################################################
def BridgeBeep(pGame, pEvent):
	iBeepNum = App.g_kSystemWrapper.GetRandomNumber(3) + 1
	App.g_kSoundManager.PlaySound("Beep" + str(iBeepNum))
	NewBeep(App.g_kSystemWrapper.GetRandomNumber(10))


###############################################################################
#	RemoveBeepTimer()
#
#	Remove the ambient Bridge random beep
#
#	Args:	none
#
#	Return:	none
###############################################################################
def RemoveBeepTimer():
	global g_idBeepTimer
	if (g_idBeepTimer != App.NULL_ID):
#		kDebugObj.Print("********************Deleting Beep timer")
		App.g_kTimerManager.DeleteTimer(g_idBeepTimer)
		g_idBeepTimer = App.NULL_ID


###############################################################################
#	LoadSounds()
#
#	Load up sounds for the bridge
#
#	Args:	none
#
#	Return:	none
###############################################################################
def LoadSounds():
	pGame = App.Game_GetCurrentGame()

	# Get the Bridge sound region and put these sounds in that region.
	pBridgeRegion = App.TGSoundRegion_GetRegion("bridge")

	# Make sure the region has no filters muting it..
	pBridgeRegion.SetFilter(App.TGSoundRegion.FT_NONE)

	for sFile, sSound, fVolume in (
		("sfx/bridge2.loop.wav",			"AmbBridge",			1.0),
		("sfx/redalert.wav",				"RedAlertSound",		1.0),
		("sfx/yellowalert.wav",				"YellowAlertSound",		1.0),
		("sfx/greenalert.wav",				"GreenAlertSound",		1.0),
		("sfx/critical.wav",				"CollisionAlertSound",	1.0),
		("sfx/hail.wav",					"ViewOn",				1.0),
		("sfx/ViewscreenOff.WAV",			"ViewOff",				1.0),
		("sfx/Bridge/console_explo_01.wav",	"ConsoleExplosion1",	0.5),
		("sfx/Bridge/console_explo_02.wav",	"ConsoleExplosion2",	0.5),
		("sfx/Bridge/console_explo_03.wav",	"ConsoleExplosion3",	0.5),
		("sfx/Bridge/console_explo_04.wav",	"ConsoleExplosion4",	0.5),
		("sfx/Bridge/console_explo_05.wav",	"ConsoleExplosion5",	0.5),
		("sfx/Bridge/console_explo_06.wav",	"ConsoleExplosion6",	0.5),
		("sfx/Bridge/console_explo_07.wav",	"ConsoleExplosion7",	0.5),
		("sfx/Bridge/console_explo_08.wav",	"ConsoleExplosion8",	0.5),
		("sfx/Bridge/bridge_loop_warp.wav", "InSystemWarp",			1.0),
		):

		pSound = pGame.LoadSoundInGroup(sFile, sSound, "BridgeGeneric")
		pBridgeRegion.AddSound(pSound)
		pSound.SetVolume(fVolume)


###############################################################################
#	Terminate()
#
#	Stop things on the bridge
#
#	Args:	none
#
#	Return:	none
###############################################################################
def Terminate():
	# Stop the beeping!
	RemoveBeepTimer()

	# Remove all of our generic bridge sounds we loaded
	App.g_kSoundManager.DeleteAllSoundsInGroup("BridgeGeneric")

	# Unload all common animations
	UnloadCommonAnimations ()

	# Unload all prefetched animations and sounds
	pBridgeSet = App.BridgeSet_Cast(App.g_kSetManager.GetSet("bridge"));
	if (pBridgeSet):
		# Unload animations of the previous bridge
		pcOldBridgeConfigScript = pBridgeSet.GetConfig ()
		pOldMod = __import__("Bridge." + pcOldBridgeConfigScript)
		pOldMod.UnloadAnimations ()
		pOldMod.UnloadSounds ()



###############################################################################
#	PreloadCommonAnimations ()
#
#	Preload any common animations
#
#	Args:	none
#
#	Return:	none
###############################################################################
def PreloadCommonAnimations ():
	kAM = App.g_kAnimationManager

	kAM.LoadAnimation ("data/animations/DB_Door_L1.nif", "DB_Door_L1")
	kAM.LoadAnimation ("data/animations/EB_Door_L1.nif", "EB_Door_L1")
	kAM.LoadAnimation ("data/animations/eyes_open_mouth_close.nif", "eyes_open_mouth_close")
	kAM.LoadAnimation ("data/animations/twitch.NIF", "twitch")
	kAM.LoadAnimation ("data/animations/standing.NIF", "standing")
	kAM.LoadAnimation ("data/animations/standing_console.NIF", "standing_console")
	kAM.LoadAnimation ("data/animations/seated_S.nif", "seated_S")
	kAM.LoadAnimation ("data/animations/seated_M.nif", "seated_M")
	kAM.LoadAnimation ("data/animations/seated_L.nif", "seated_L")
	kAM.LoadAnimation ("data/animations/breathing.NIF", "breathing")
	kAM.LoadAnimation ("data/animations/pushing_buttons_a.NIF", "pushing_buttons_a")
	kAM.LoadAnimation ("data/animations/pushing_buttons_b.NIF", "pushing_buttons_b")
	kAM.LoadAnimation ("data/animations/pushing_buttons_c.NIF", "pushing_buttons_c")
	kAM.LoadAnimation ("data/animations/pushing_buttons_d.NIF", "pushing_buttons_d")
	kAM.LoadAnimation ("data/animations/nod.NIF", "nod")
	kAM.LoadAnimation ("data/animations/tilt_head_left.NIF", "tilt_head_left")
	kAM.LoadAnimation ("data/animations/tilt_head_right.NIF", "tilt_head_right")
	kAM.LoadAnimation ("data/animations/clapping.NIF", "clapping")
	kAM.LoadAnimation ("data/animations/at_ease.NIF", "at_ease")
	kAM.LoadAnimation ("data/animations/_standing_to_at_ease.NIF", "standing_to_at_ease")
	kAM.LoadAnimation ("data/animations/_at_ease_to_standing.NIF", "at_ease_to_standing")
	kAM.LoadAnimation ("data/animations/pointing_left.NIF", "pointing_left")			
	kAM.LoadAnimation ("data/animations/pointing_right.NIF", "pointing_right")
	kAM.LoadAnimation ("data/animations/Wiping_Brow_left.NIF", "Wiping_Brow_left")			
	kAM.LoadAnimation ("data/animations/Wiping_Brow_right.NIF", "Wiping_Brow_right")
	kAM.LoadAnimation ("data/animations/looking_left.NIF", "looking_left")
	kAM.LoadAnimation ("data/animations/looking_right.NIF", "looking_right")
	kAM.LoadAnimation ("data/animations/looking_up.NIF", "looking_up")
	kAM.LoadAnimation ("data/animations/looking_down.NIF", "looking_down")
	kAM.LoadAnimation ("data/animations/hitting_communicator.NIF", "hitting_communicator")
	kAM.LoadAnimation ("data/animations/Yawn_M.NIF", "Yawn")
	kAM.LoadAnimation ("data/animations/Sigh_M.NIF", "Sigh")
	kAM.LoadAnimation ("data/animations/Stretch_M.NIF", "Stretch")
	kAM.LoadAnimation ("data/animations/Shrug_Right_M.NIF", "Shrug_Right")
	kAM.LoadAnimation ("data/animations/Neck_Rub_M.NIF", "Neck_Rub")
	kAM.LoadAnimation ("data/animations/Laugh_M.NIF", "Laugh")
	kAM.LoadAnimation ("data/animations/Lean_M.NIF", "Lean")
	kAM.LoadAnimation ("data/animations/Head_Scratch_M.NIF", "Head_Scratch")
	kAM.LoadAnimation ("data/animations/Head_Nod_M.NIF", "Head_Nod")
	kAM.LoadAnimation ("data/animations/Hair_Wipe_M.NIF", "Hair_Wipe")
	kAM.LoadAnimation ("data/animations/Console_Look_Down.NIF", "console_down")
	kAM.LoadAnimation ("data/animations/Wall_Slide_Left.NIF", "Wall_slide_left")
	kAM.LoadAnimation ("data/animations/Wall_Slide_Right.NIF", "Wall_slide_right")
	kAM.LoadAnimation ("data/animations/Wall_Press_Left_Low.NIF", "Wall_Press_Low_left")
	kAM.LoadAnimation ("data/animations/Wall_Press_Right_Low.NIF", "Wall_Press_Low_right")
	kAM.LoadAnimation ("data/animations/Wall_Press_Left.NIF", "Wall_Press_left")
	kAM.LoadAnimation ("data/animations/Wall_Press_Right.NIF", "Wall_Press_right")
	kAM.LoadAnimation ("data/animations/Console_Look_Down_Fore_Left.NIF", "console_down_fore_left")
	kAM.LoadAnimation ("data/animations/Console_Look_Down_Fore_Right.NIF", "console_down_fore_right")
	kAM.LoadAnimation ("data/animations/Console_Look_Down_Left.NIF", "console_down_left")
	kAM.LoadAnimation ("data/animations/Console_Look_Down_Right.NIF", "console_down_right")
	kAM.LoadAnimation ("data/animations/Console_Look_Up.NIF", "console_up")
	kAM.LoadAnimation ("data/animations/Console_Look_Up_Fore_Left.NIF", "console_up_fore_left")
	kAM.LoadAnimation ("data/animations/Console_Look_Up_Fore_Right.NIF", "console_up_fore_right")
	kAM.LoadAnimation ("data/animations/Console_Look_Up_Left.NIF", "console_up_left")
	kAM.LoadAnimation ("data/animations/Console_Look_Up_Right.NIF", "console_up_right")
	kAM.LoadAnimation ("data/animations/EB_G2_Hit_Hard_Flat_Walk_M.NIF", "blast_away")
	kAM.LoadAnimation ("data/animations/EB_G3_Hit_Hard_Flat_Walk_M.NIF", "blast_away2")
	kAM.LoadAnimation ("data/animations/at_ease_looking_left.NIF", "at_ease_looking_left")
	kAM.LoadAnimation ("data/animations/at_ease_looking_right.NIF", "at_ease_looking_right")
	kAM.LoadAnimation ("data/animations/_lean_a.NIF", "lean_a")
	kAM.LoadAnimation ("data/animations/_lean_b.NIF", "lean_b")
	kAM.LoadAnimation ("data/animations/_hit_hard_a.NIF", "hit_hard_a")
	kAM.LoadAnimation ("data/animations/_hit_hard_b.NIF", "hit_hard_b")
	kAM.LoadAnimation ("data/animations/react_console_left.NIF", "react_console_left")
	kAM.LoadAnimation ("data/animations/react_console_right.NIF", "react_console_right")
	kAM.LoadAnimation ("data/animations/MouseOver_Left.NIF", "LookCaptLeft")
	kAM.LoadAnimation ("data/animations/MouseOver_Right.NIF", "LookCaptRight")

	kAM.LoadAnimation ("data/animations/db_stand_h_m.nif", "db_stand_h_m")
	kAM.LoadAnimation ("data/animations/db_stand_t_l.nif", "db_stand_t_l")
	kAM.LoadAnimation ("data/animations/db_stand_c_m.nif", "db_stand_c_m")
	kAM.LoadAnimation ("data/animations/db_StoL1_S.nif", "db_StoL1_S")
	kAM.LoadAnimation ("data/animations/db_EtoL1_s.nif", "db_EtoL1_s")
	kAM.LoadAnimation ("data/animations/DB_PtoL1_P.nif", "DB_PtoL1_P")
	kAM.LoadAnimation ("data/animations/DB_L1toH_M.nif", "DB_L1toH_M")
	kAM.LoadAnimation ("data/animations/EB_stand_h_m.nif", "EB_stand_h_m")
	kAM.LoadAnimation ("data/animations/EB_stand_t_l.nif", "EB_stand_t_l")
	kAM.LoadAnimation ("data/animations/EB_stand_c_m.nif", "EB_stand_c_m")
	kAM.LoadAnimation ("data/animations/EB_stand_s_s.nif", "EB_stand_s_s")
	kAM.LoadAnimation ("data/animations/EB_stand_e_s.nif", "EB_stand_e_s")
	kAM.LoadAnimation ("data/animations/EB_stand_X_m.nif", "EB_stand_X_m")
	kAM.LoadAnimation ("data/animations/EB_L1toH_M.nif", "EB_L1toH_M")
	kAM.LoadAnimation ("data/animations/EB_L1toT_L.nif", "EB_L1toT_L")
	kAM.LoadAnimation ("data/animations/EB_L2toG2_M.nif", "EB_L2toG2_M")

	# Partial Set Locations
	kAM.LoadAnimation ("data/animations/CardassianSeated01.NIF", "CardassianSeated01")
	kAM.LoadAnimation ("data/animations/CardStationSeated01.NIF", "CardStationSeated01")
	kAM.LoadAnimation ("data/animations/FedOutpostSeated01.NIF", "FederationOutpostSeated01")
	kAM.LoadAnimation ("data/animations/FedOutpostSeated02.NIF", "FederationOutpostSeated02")
	kAM.LoadAnimation ("data/animations/FedOutpostSeated03.NIF", "FederationOutpostSeated03")
	kAM.LoadAnimation ("data/animations/FerengiSeated01.NIF", "FerengiSeated01")
	kAM.LoadAnimation ("data/animations/GalaxyEngSeated01.NIF", "GalaxyEngSeated01")
	kAM.LoadAnimation ("data/animations/GalaxySeated01.NIF", "GalaxySeated01")
	kAM.LoadAnimation ("data/animations/KessokSeated01.NIF", "KessokSeated01")
	kAM.LoadAnimation ("data/animations/KlingonSeated01.NIF", "KlingonSeated01")
	kAM.LoadAnimation ("data/animations/MiscEng01.NIF", "MiscEngSeated01")
	kAM.LoadAnimation ("data/animations/MiscEng02.NIF", "MiscEngSeated02")
	kAM.LoadAnimation ("data/animations/RomulanSeated01.NIF", "RomulanSeated01")
	kAM.LoadAnimation ("data/animations/ShuttleSeated01.NIF", "ShuttleSeated01")
	kAM.LoadAnimation ("data/animations/ShuttleSeated02.NIF", "ShuttleSeated02")
	kAM.LoadAnimation ("data/animations/SovereignEngSeated01.NIF", "SovereignEngSeated01")
	kAM.LoadAnimation ("data/animations/SovereignSeated01.NIF", "SovereignSeated01")
	kAM.LoadAnimation ("data/animations/StarbaseSeated01.NIF", "StarbaseSeated01")
	kAM.LoadAnimation ("data/animations/StarbaseSeated02.NIF", "StarbaseSeated02")

	return

###############################################################################
#	UnloadCommonAnimations ()
#
#	Unload any common animations
#
#	Args:	none
#
#	Return:	none
###############################################################################
def UnloadCommonAnimations ():
	kAM = App.g_kAnimationManager

	kAM.FreeAnimation ("DB_Door_L1")
	kAM.FreeAnimation ("EB_Door_L1")
	kAM.FreeAnimation ("eyes_open_mouth_close")
	kAM.FreeAnimation ("twitch")
	kAM.FreeAnimation ("standing")
	kAM.FreeAnimation ("standing_console")
	kAM.FreeAnimation ("seated_S")
	kAM.FreeAnimation ("seated_M")
	kAM.FreeAnimation ("seated_L")
	kAM.FreeAnimation ("breathing")
	kAM.FreeAnimation ("pushing_buttons_a")
	kAM.FreeAnimation ("pushing_buttons_b")
	kAM.FreeAnimation ("pushing_buttons_c")
	kAM.FreeAnimation ("pushing_buttons_d")
	kAM.FreeAnimation ("nod")
	kAM.FreeAnimation ("tilt_head_left")
	kAM.FreeAnimation ("tilt_head_right")
	kAM.FreeAnimation ("clapping")
	kAM.FreeAnimation ("at_ease")
	kAM.FreeAnimation ("standing_to_at_ease")
	kAM.FreeAnimation ("at_ease_to_standing")
	kAM.FreeAnimation ("pointing_left")			
	kAM.FreeAnimation ("pointing_right")
	kAM.FreeAnimation ("Wiping_Brow_left")			
	kAM.FreeAnimation ("Wiping_Brow_right")
	kAM.FreeAnimation ("looking_left")
	kAM.FreeAnimation ("looking_right")
	kAM.FreeAnimation ("looking_up")
	kAM.FreeAnimation ("looking_down")
	kAM.FreeAnimation ("hitting_communicator")
	kAM.FreeAnimation ("Yawn")
	kAM.FreeAnimation ("Sigh")
	kAM.FreeAnimation ("Stretch")
	kAM.FreeAnimation ("Shrug_Right")
	kAM.FreeAnimation ("Neck_Rub")
	kAM.FreeAnimation ("Laugh")
	kAM.FreeAnimation ("Lean")
	kAM.FreeAnimation ("Head_Scratch")
	kAM.FreeAnimation ("Head_Nod")
	kAM.FreeAnimation ("Hair_Wipe")
	kAM.FreeAnimation ("console_down")
	kAM.FreeAnimation ("console_slide_fore_left")
	kAM.FreeAnimation ("console_slide_fore_right")
	kAM.FreeAnimation ("console_slide_left")
	kAM.FreeAnimation ("console_slide_right")
	kAM.FreeAnimation ("Wall_slide_left")
	kAM.FreeAnimation ("Wall_slide_right")
	kAM.FreeAnimation ("Wall_Press_Low_left")
	kAM.FreeAnimation ("Wall_Press_Low_right")
	kAM.FreeAnimation ("Wall_Press_left")
	kAM.FreeAnimation ("Wall_Press_right")
	kAM.FreeAnimation ("console_down_fore_left")
	kAM.FreeAnimation ("console_down_fore_right")
	kAM.FreeAnimation ("console_down_left")
	kAM.FreeAnimation ("console_down_right")
	kAM.FreeAnimation ("console_up")
	kAM.FreeAnimation ("console_up_fore_left")
	kAM.FreeAnimation ("console_up_fore_right")
	kAM.FreeAnimation ("console_up_left")
	kAM.FreeAnimation ("console_up_right")
	kAM.FreeAnimation ("blast_away")
	kAM.FreeAnimation ("blast_away2")
	kAM.FreeAnimation ("at_ease_looking_left")
	kAM.FreeAnimation ("at_ease_looking_right")
	kAM.FreeAnimation ("lean_a")
	kAM.FreeAnimation ("lean_b")
	kAM.FreeAnimation ("hit_hard_a")
	kAM.FreeAnimation ("hit_hard_b")
	kAM.FreeAnimation ("react_console_left")
	kAM.FreeAnimation ("react_console_right")
	kAM.FreeAnimation ("LookCaptLeft")
	kAM.FreeAnimation ("LookCaptRight")

	kAM.FreeAnimation ("db_stand_h_m")
	kAM.FreeAnimation ("db_stand_t_l")
	kAM.FreeAnimation ("db_stand_c_m")
	kAM.FreeAnimation ("db_StoL1_S")
	kAM.FreeAnimation ("db_EtoL1_s")
	kAM.FreeAnimation ("DB_PtoL1_P")
	kAM.FreeAnimation ("DB_L1toH_M")
	kAM.FreeAnimation ("EB_stand_h_m")
	kAM.FreeAnimation ("EB_stand_t_l")
	kAM.FreeAnimation ("EB_stand_c_m")
	kAM.FreeAnimation ("EB_stand_s_s")
	kAM.FreeAnimation ("EB_stand_e_s")
	kAM.FreeAnimation ("EB_stand_X_m")
	kAM.FreeAnimation ("EB_L1toH_M")
	kAM.FreeAnimation ("EB_L1toT_L")
	kAM.FreeAnimation ("EB_L2toG2_M")
	kAM.FreeAnimation ("CardassianSeated01")
	kAM.FreeAnimation ("FerengiSeated01")
	kAM.FreeAnimation ("GalaxyEngSeated01")
	kAM.FreeAnimation ("GalaxySeated01")
	kAM.FreeAnimation ("KessokSeated01")
	kAM.FreeAnimation ("KlingonSeated01")
	kAM.FreeAnimation ("RomulanSeated01")
	kAM.FreeAnimation ("ShuttleSeated01")
	kAM.FreeAnimation ("ShuttleSeated02")
	kAM.FreeAnimation ("SovereignEngSeated01")
	kAM.FreeAnimation ("SovereignSeated01")
	kAM.FreeAnimation ("StarbaseSeated01")

	return
