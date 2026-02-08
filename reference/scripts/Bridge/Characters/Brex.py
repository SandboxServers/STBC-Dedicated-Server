###############################################################################
#	Filename:	Brex.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads Brex, the Engineer, and configures animations.
#	
#	Created:	3/28/00 -	Erik Novales
###############################################################################

import App
import Bridge.BridgeUtils
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create Brex by building his character and placing him on the passed in set.
#	Create his menus as well.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating Brex")

	if (pSet.GetObject("Engineer") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("Engineer")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyMaleS/BodyMaleS.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadBrex/brex_head_no_mouth.nif", None)
	pBrex = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyMaleS/BodyMaleS.nif", CharacterPaths.g_pcHeadNIFPath + "HeadBrex/brex_head_no_mouth.nif")
	pBrex.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyMaleM/FedGold_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadBrex/brex_head.tga")

	pBrex.SetCharacterName("Brex")

	# Add the character to the set
	pSet.AddObjectToSet(pBrex, "Engineer")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pBrex)

	# Setup the character configuration
	pBrex.SetSize(App.CharacterClass.SMALL)
	pBrex.SetGender(App.CharacterClass.MALE)
	pBrex.SetRandomAnimationChance(.75)
	pBrex.SetBlinkChance(0.1)

	pBrex.SetDatabase("data/TGL/Bridge Crew General.tgl")

	# Load Engineering officer generic sounds
	LoadSounds()

	pBrex.AddFacialImage("Blink0", CharacterPaths.g_pcHeadTexPath + "HeadBrex/Brex_blink1.tga")
	pBrex.AddFacialImage("Blink1", CharacterPaths.g_pcHeadTexPath + "HeadBrex/Brex_blink2.tga")
	pBrex.AddFacialImage("Blink2", CharacterPaths.g_pcHeadTexPath + "HeadBrex/Brex_eyes_close.tga")
	pBrex.SetBlinkStages(3)

	pBrex.AddFacialImage("SpeakA", CharacterPaths.g_pcHeadTexPath + "HeadBrex/Brex_head_a.tga")
	pBrex.AddFacialImage("SpeakE", CharacterPaths.g_pcHeadTexPath + "HeadBrex/Brex_head_e.tga")
	pBrex.AddFacialImage("SpeakU", CharacterPaths.g_pcHeadTexPath + "HeadBrex/Brex_head_u.tga")
	pBrex.SetAnimatedSpeaking(1)

	pGame = App.Game_GetCurrentGame()
	pGame.LoadDatabaseSoundInGroup(pBrex.GetDatabase(), "BrexNothingToAdd", "BridgeGeneric")

	pMenusDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTop = App.TopWindow_GetTopWindow()
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pBrex.SetMenu(pTacticalControlWindow.FindMenu(pMenusDatabase.GetString("Engineering")))
	App.g_kLocalizationManager.Unload(pMenusDatabase)

	pBrex.AddAnimation("Place", "Bridge.Characters.CommonAnimations.Standing")
	pBrex.SetLocation("")

#	kDebugObj.Print("Finished creating Brex")
	return pBrex


###############################################################################
#	ConfigureForShip()
#
#	Configure ourselves for the particular ship object.  This involves setting
#	up range watchers that tell us how to report.
#
#	Args:	pSet	- the Set object
#			pShip	- the player's ship (ShipClass object)
#
#	Return:	none
###############################################################################
def ConfigureForShip(pSet, pShip):
	pBrex = App.CharacterClass_Cast(pSet.GetObject("Engineer"))
	if (pBrex == None):
#		kDebugObj.Print("******* Engineering officer not found *********")
		return

#	kDebugObj.Print("Attaching menu to Engineer..")
	import Bridge.EngineerCharacterHandlers
	Bridge.EngineerCharacterHandlers.AttachMenuToEngineer(pBrex)

	# Set up the status events that we need - Shield and Hull
	# Other events (repairs, subsystem reports) are generated elsewhere
	pShieldWatcher = pShip.GetShields().GetShieldWatcher(6)
	pHullWatcher = pShip.GetHull().GetCombinedPercentageWatcher()

	lWatchers = (
		( pShieldWatcher,	App.ET_TACTICAL_SHIELD_LEVEL_CHANGE ),
		( pHullWatcher,		App.ET_TACTICAL_HULL_LEVEL_CHANGE ) )

	lRanges = ( 0.05, 0.1, 0.15, 0.2, 0.25, 0.5, 0.75 )

	for pWatcher, eEventType in lWatchers:
		for fRange in lRanges:
			# Need an event for this range check..
			pEvent = App.TGFloatEvent_Create()
			pEvent.SetEventType(eEventType)
			pEvent.SetDestination(pShip)

			pWatcher.AddRangeCheck(fRange, App.FloatRangeWatcher.FRW_BELOW, pEvent)

	lWatchers = (
		( pShip.GetShields().GetShieldWatcher(0), App.ET_TACTICAL_SHIELD_0_LEVEL_CHANGE ),
		( pShip.GetShields().GetShieldWatcher(1), App.ET_TACTICAL_SHIELD_1_LEVEL_CHANGE ),
		( pShip.GetShields().GetShieldWatcher(2), App.ET_TACTICAL_SHIELD_2_LEVEL_CHANGE ),
		( pShip.GetShields().GetShieldWatcher(3), App.ET_TACTICAL_SHIELD_3_LEVEL_CHANGE ),
		( pShip.GetShields().GetShieldWatcher(4), App.ET_TACTICAL_SHIELD_4_LEVEL_CHANGE ),
		( pShip.GetShields().GetShieldWatcher(5), App.ET_TACTICAL_SHIELD_5_LEVEL_CHANGE ) )

	lRanges = ( 0.05, 0.5)

	for pWatcher, eEventType in lWatchers:
		for fRange in lRanges:
			# Need an event for this range check..
			pEvent = App.TGFloatEvent_Create()
			pEvent.SetEventType(eEventType)
			pEvent.SetDestination(pShip)

			pWatcher.AddRangeCheck(fRange, App.FloatRangeWatcher.FRW_BELOW, pEvent)


###############################################################################
#	ConfigureForGalaxy()
#
#	Configure ourselves for the Galaxy bridge
#
#	Args:	pBrex	- our Character object
#
#	Return:	none
###############################################################################
def ConfigureForGalaxy(pBrex):
#	kDebugObj.Print("Configuring Brex for the Galaxy bridge")

	# Clear out any old animations from another configuration
	pBrex.ClearAnimations()

	# Register animation mappings
	pBrex.AddAnimation("StandingDBEngineer", "Bridge.Characters.CommonAnimations.StandingConsole")
	pBrex.AddAnimation("DBL1SToE", "Bridge.Characters.Brex.MoveFromL1ToE")
	pBrex.AddAnimation("GalaxyEngSeatedToE", "Bridge.Characters.Brex.MoveFromL1ToE")
	pBrex.AddAnimation("DBEngineerToL1", "Bridge.Characters.Brex.MoveFromEToL1")
	pBrex.AddAnimation("DBEngineerTurnCaptain", "Bridge.Characters.SmallAnimations.TurnAtETowardsCaptain")
	pBrex.AddAnimation("DBEngineerBackCaptain", "Bridge.Characters.CommonAnimations.StandingConsole")
	pBrex.AddAnimation("DBEngineerGlanceCaptain", "Bridge.Characters.CommonAnimations.GlanceRight")
	pBrex.AddAnimation("DBEngineerGlanceAwayCaptain", "Bridge.Characters.CommonAnimations.StandingConsole")

	pBrex.AddAnimation("DBEngineerTurnC", "Bridge.Characters.SmallAnimations.DBETalkC")
	pBrex.AddAnimation("DBEngineerBackC", "Bridge.Characters.CommonAnimations.StandingConsole")
	pBrex.AddAnimation("DBEngineerTurnH", "Bridge.Characters.SmallAnimations.DBETalkH")
	pBrex.AddAnimation("DBEngineerBackH", "Bridge.Characters.CommonAnimations.StandingConsole")
	pBrex.AddAnimation("DBEngineerTurnS", "Bridge.Characters.SmallAnimations.DBETalkS")
	pBrex.AddAnimation("DBEngineerBackS", "Bridge.Characters.CommonAnimations.StandingConsole")
	pBrex.AddAnimation("DBEngineerTurnT", "Bridge.Characters.SmallAnimations.DBETalkT")
	pBrex.AddAnimation("DBEngineerBackT", "Bridge.Characters.CommonAnimations.StandingConsole")

	pBrex.AddAnimation("DBEngineerTurnX", "Bridge.Characters.SmallAnimations.DBETalkX")
	pBrex.AddAnimation("DBEngineerBackX", "Bridge.Characters.CommonAnimations.StandingConsole")

	# Breathing	
	pBrex.AddAnimation("DBEngineerBreathe", "Bridge.Characters.CommonAnimations.StandingConsole")
	pBrex.AddAnimation("DBEngineerBreatheTurned", "Bridge.Characters.CommonAnimations.BreathingTurned")

	# Interaction
	pBrex.AddRandomAnimation("Bridge.Characters.SmallAnimations.DBEConsoleInteraction", App.CharacterClass.SITTING_ONLY, 25, 1)

	# So the mission builders can force the call
	pBrex.AddAnimation("PushingButtons", "Bridge.Characters.SmallAnimations.DBEConsoleInteraction")

	# Hit animations
	pBrex.AddAnimation("DBEngineerHitStanding", "Bridge.Characters.CommonAnimations.HitStanding")
	pBrex.AddAnimation("DBEngineerHitHardStanding", "Bridge.Characters.CommonAnimations.HitHardStanding")
	pBrex.AddAnimation("DBEngineerReactLeftStanding", "Bridge.Characters.CommonAnimations.ReactLeft");
	pBrex.AddAnimation("DBEngineerReactRightStanding", "Bridge.Characters.CommonAnimations.ReactRight");

	# Add common animations.
	AddCommonAnimations(pBrex)

	# Brex stands on the Galaxy bridge
	pBrex.SetStanding(1)
	pBrex.SetLocation("DBEngineer")
#	kDebugObj.Print("Finished configuring Brex")


###############################################################################
#	ConfigureForSovereign()
#
#	Configure ourselves for the Sovereign bridge
#
#	Args:	pBrex	- our Character object
#
#	Return:	none
###############################################################################
def ConfigureForSovereign(pBrex):
#	kDebugObj.Print("Configuring Brex for the Sovereign bridge")

	# Clear out any old animations from another configuration
	pBrex.ClearAnimations()

	# Register animation mappings
	pBrex.AddAnimation("SeatedEBEngineer", "Bridge.Characters.CommonAnimations.SeatedS")
	pBrex.AddAnimation("EBL1SToE", "Bridge.Characters.Brex.EBMoveFromL1ToE")
	pBrex.AddAnimation("SovereignEngSeatedToE", "Bridge.Characters.Brex.EBMoveFromL1ToE")
	pBrex.AddAnimation("EBEngineerToL1", "Bridge.Characters.Brex.EBMoveFromEToL1")
	pBrex.AddAnimation("EBEngineerTurnCaptain", "Bridge.Characters.SmallAnimations.EBTurnAtETowardsCaptain")
	pBrex.AddAnimation("EBEngineerBackCaptain", "Bridge.Characters.SmallAnimations.EBTurnBackAtEFromCaptain")
	pBrex.AddAnimation("EBEngineer1ToE", "Bridge.Characters.SmallAnimations.EBMoveFromE1ToE")
	pBrex.AddAnimation("EBEngineerToE1", "Bridge.Characters.SmallAnimations.EBMoveFromEToE1")
	pBrex.AddAnimation("EBEngineer2ToE", "Bridge.Characters.SmallAnimations.EBMoveFromE2ToE")
	pBrex.AddAnimation("EBEngineerToE2", "Bridge.Characters.SmallAnimations.EBMoveFromEToE2")
	pBrex.AddAnimation("EBEngineer1ToE2", "Bridge.Characters.SmallAnimations.EBMoveFromE1ToE2")
	pBrex.AddAnimation("EBEngineer2ToE1", "Bridge.Characters.SmallAnimations.EBMoveFromE2ToE1")

	pBrex.AddAnimation("EBEngineerGlanceCaptain", "Bridge.Characters.CommonAnimations.GlanceRight")
	pBrex.AddAnimation("EBEngineerGlanceAwayCaptain", "Bridge.Characters.CommonAnimations.SeatedS")

	pBrex.AddAnimation("EBEngineerTurnC", "Bridge.Characters.SmallAnimations.EBETalkC")
	pBrex.AddAnimation("EBEngineerBackC", "Bridge.Characters.CommonAnimations.SeatedS")
	pBrex.AddAnimation("EBEngineerTurnH", "Bridge.Characters.SmallAnimations.EBETalkH")
	pBrex.AddAnimation("EBEngineerBackH", "Bridge.Characters.CommonAnimations.SeatedS")
	pBrex.AddAnimation("EBEngineerTurnS", "Bridge.Characters.SmallAnimations.EBETalkS")
	pBrex.AddAnimation("EBEngineerBackS", "Bridge.Characters.CommonAnimations.SeatedS")
	pBrex.AddAnimation("EBEngineerTurnT", "Bridge.Characters.SmallAnimations.EBETalkT")
	pBrex.AddAnimation("EBEngineerBackT", "Bridge.Characters.CommonAnimations.SeatedS")

	pBrex.AddAnimation("EBEngineerTurnX", "Bridge.Characters.SmallAnimations.EBTurnAtETowardsCaptain")
	pBrex.AddAnimation("EBEngineerBackX", "Bridge.Characters.SmallAnimations.EBTurnBackAtEFromCaptain")

	# Breathing
	pBrex.AddAnimation("EBEngineerBreathe", "Bridge.Characters.CommonAnimations.SeatedS")
	pBrex.AddAnimation("EBEngineerBreatheTurned", "Bridge.Characters.CommonAnimations.BreathingTurned")

	# Interaction
	pBrex.AddRandomAnimation("Bridge.Characters.SmallAnimations.EBEConsoleInteraction", App.CharacterClass.SITTING_ONLY, 25, 1)

	# So the mission builders can force the call
	pBrex.AddAnimation("PushingButtons", "Bridge.Characters.SmallAnimations.EBEConsoleInteraction")

	# Hit animations
	pBrex.AddAnimation("EBEngineerHitStanding", "Bridge.Characters.CommonAnimations.HitStanding")
	pBrex.AddAnimation("EBEngineerHitHardStanding", "Bridge.Characters.CommonAnimations.HitHardStanding")
	pBrex.AddAnimation("EBEngineerReactLeftStanding", "Bridge.Characters.CommonAnimations.ReactLeft");
	pBrex.AddAnimation("EBEngineerReactRightStanding", "Bridge.Characters.CommonAnimations.ReactRight");

	# Add common animations.
	AddCommonAnimations(pBrex)

	# Brex sits on the Sovereign bridge
	pBrex.SetStanding(0)
	pBrex.SetLocation("EBEngineer")
	pBrex.AddPositionZoom("EBEngineer", 0.5)
	pBrex.AddPositionZoom("EBEngineer1", 0.5)
	pBrex.AddPositionZoom("EBEngineer2", 0.6)
#	kDebugObj.Print("Finished configuring Brex")


###############################################################################
#	ConfigureForEngineering()
#
#	Configure ourselves for the Engineering partial set
#
#	Args:	pBrex	- our Character object
#
#	Return:	none
###############################################################################
def ConfigureForEngineering(pBrex):
#	kDebugObj.Print("Configuring Brex for engineering")

	pBrex = App.CharacterClass_Cast(pBrex)
	if pBrex:
		# Clear out any old animations from another configuration
		pBrex.ClearAnimations()

		# Register animation mappings
		pBrex.SetStanding(0)
		pBrex.SetLocation("SovereignEngSeated")
		AddCommonAnimations(pBrex)

#		kDebugObj.Print("Finished configuring Brex")

###############################################################################
#	AddCommonAnimations()
#
#	Since we can only clear out all animations when switching bridges (how
#	would we know which not to clear?), we can't really setup animations common
#	to all bridge configurations as we might like.  Because of this we have a
#	routine to add common animations (most of which are randoms) that both
#	configurations will call
#
#	Args:	pBrex	- our Character object
#
#	Return:	none
###############################################################################
def AddCommonAnimations(pBrex):
	pBrex.AddRandomAnimation("Bridge.Characters.SmallAnimations.ELookAroundConsoleDown", App.CharacterClass.SITTING_ONLY, 1, 1)

	#pBrex.AddRandomAnimation("Bridge.Characters.CommonAnimations.WipingBrowLeft")
	#pBrex.AddRandomAnimation("Bridge.Characters.CommonAnimations.WipingBrowRight")
	pBrex.AddRandomAnimation("Bridge.Characters.CommonAnimations.TiltHeadLeft")
	pBrex.AddRandomAnimation("Bridge.Characters.CommonAnimations.TiltHeadRight")
	pBrex.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookUp")
	pBrex.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookDown")
	#pBrex.AddRandomAnimation("Bridge.Characters.CommonAnimations.AtEase", App.CharacterClass.STANDING_ONLY)


###############################################################################
#	LoadSounds()
#
#	Load generic bridge sounds for this character
#
#	Args:	none
#
#	Return:	none
###############################################################################
def LoadSounds():
	pGame = App.Game_GetCurrentGame()
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")

	#
	# Build a list of sound to load
	#
	kSoundList =	[	"BrexSir1",		# Click Response
						"BrexSir2",
						"BrexSir3",
						"BrexSir4",
						"BrexSir5",

						"BrexYes1",		# Order Confirmation
						"BrexYes2",
						"BrexYes3",
						"BrexYes4",

						"BrexTransfer",	# Transferring Power
						"MainPowerDraining",

						"FrontShieldDraining",
						"FrontShieldFailed",
						"RearShieldDraining",
						"RearShieldFailed",
						"TopShieldDraining",
						"TopShieldFailed",
						"BottomShieldDraining",
						"BottomShieldFailed",
						"LeftShieldDraining",
						"LeftShieldFailed",
						"RightShieldDraining",
						"RightShieldFailed",
						"PhasersDisabled",
						"PhasersDestroyed",
						"ShieldsDisabled",
						"ShieldsDestroyed",
						"SensorsDisabled",
						"SensorsDestroyed",
						"TorpedoesDisabled",
						"TorpedoesDestroyed",
						"TractorDisabled",
						"TractorDestroyed",
						"ImpulseDisabled",
						"ImpulseDestroyed",
						"WarpDisabled",
						"WarpDestroyed",
						"PowerDisabled",
						"OutOfTorpedoes",
						"Hull05",
						"Hull10",
						"Hull15",
						"Hull20",
						"Hull25",
						"Hull50",
						"Hull75",
						"MultipleShieldsOffline",
						"Shields05",
						"Shields10",
						"Shields15",
						"Shields20",
						"Shields25",
						"Shields50",
						"Shields75",
						"ShieldsFailed"
					]
	#
	# Loop through that list, loading each sound in the "BridgeGeneric" group
	#
	for i in range(len(kSoundList)):
		pGame.LoadDatabaseSoundInGroup(pDatabase, kSoundList[i], "BridgeGeneric")

	App.g_kLocalizationManager.Unload(pDatabase)

###############################################################################
#	MoveFromEToL1 & MoveFromL1ToE
#	
#	Functions that turn the "Contact Engineering" button on and off
#	
#	Args:	self		- the character that called these
#	
#	Return:	pSequence	- returned by the real functions
###############################################################################
def MoveFromEToL1(self):
	import Bridge.Characters.SmallAnimations
	pEngineering = Bridge.EngineerCharacterHandlers.GetEngineeringSet("Galaxy")

	pSequence = App.TGSequence_Create()
	pSequence.AppendAction(Bridge.Characters.SmallAnimations.MoveFromEToL1(self))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "EnableContactEngineeringButton"), 15.0)
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "MoveToEngineeringSet"), 0.1)
	pSequence.AppendAction(App.CharacterAction_Create(self, App.CharacterAction.AT_SET_LOCATION, "GalaxyEngSeated"))
	return pSequence

def MoveToEngineeringSet(pAction):
#	kDebugObj.Print("Moving Brex to the Engineering set")

	pBridge = App.g_kSetManager.GetSet("bridge")
	import Bridge.EngineerCharacterHandlers
	pEngineering = Bridge.EngineerCharacterHandlers.GetEngineeringSet()
	pBrex = pBridge.RemoveObjectFromSet("Engineer")
	assert pBrex
	bSuccess = pEngineering.AddObjectToSet(pBrex, "Engineer")
	assert bSuccess

#	kDebugObj.Print("Done in MoveToEngineeringSet()")

	return 0

def EnableContactEngineeringButton(pAction):
	import Bridge.XOMenuHandlers
	Bridge.XOMenuHandlers.SetContactEngineeringEnabled(1)

	return 0
	
def MoveFromL1ToE(self):
	import Bridge.Characters.SmallAnimations
	pSequence = App.TGSequence_Create()
	#pSequence.AppendAction(App.CharacterAction_Create(self, App.CharacterAction.AT_SET_LOCATION, "DBL1S"))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "MoveToDBridgeSet"))
	pSequence.AppendAction(Bridge.Characters.SmallAnimations.MoveFromL1ToE(self))
	return pSequence

def MoveToDBridgeSet(pAction):
	import Bridge.XOMenuHandlers
	Bridge.XOMenuHandlers.SetContactEngineeringEnabled(0)
	import Bridge.Characters.SmallAnimations

	pBridge = Bridge.BridgeUtils.GetBridge()
	import Bridge.EngineerCharacterHandlers
	pEngineering = Bridge.EngineerCharacterHandlers.GetEngineeringSet("Galaxy")
	pBrex = pEngineering.RemoveObjectFromSet("Engineer")
	assert pBrex
	bSuccess = pBridge.AddObjectToSet(pBrex, "Engineer")
	assert bSuccess

	return 0

def EBMoveFromEToL1(self):
	import Bridge.Characters.SmallAnimations
	pEngineering = Bridge.EngineerCharacterHandlers.GetEngineeringSet("Sovereign")
	pSequence = App.TGSequence_Create()
	pSequence.AppendAction(Bridge.Characters.SmallAnimations.EBMoveFromEToL1(self))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "EnableContactEngineeringButton"), 5.0)
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "MoveToEngineeringSet"), 0.1)
	pSequence.AppendAction(App.CharacterAction_Create(self, App.CharacterAction.AT_SET_LOCATION, "SovereignEngSeated"))
	return pSequence

def EBMoveFromL1ToE(self):
	import Bridge.Characters.SmallAnimations
	pSequence = App.TGSequence_Create()
	#pSequence.AppendAction(App.CharacterAction_Create(self, App.CharacterAction.AT_SET_LOCATION, "EBL1S"))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "MoveToEBridgeSet"))
	pSequence.AppendAction(Bridge.Characters.SmallAnimations.EBMoveFromL1ToE(self))
	return pSequence

def MoveToEBridgeSet(pAction):
	import Bridge.XOMenuHandlers
	Bridge.XOMenuHandlers.SetContactEngineeringEnabled(0)
	import Bridge.Characters.SmallAnimations

	pBridge = Bridge.BridgeUtils.GetBridge()
	import Bridge.EngineerCharacterHandlers
	pEngineering = Bridge.EngineerCharacterHandlers.GetEngineeringSet("Sovereign")
	pBrex = pEngineering.RemoveObjectFromSet("Engineer")
	assert pBrex
	bSuccess = pBridge.AddObjectToSet(pBrex, "Engineer")
	assert bSuccess

	return 0
