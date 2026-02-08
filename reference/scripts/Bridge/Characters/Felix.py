###############################################################################
#	Filename:	Felix.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads Felix Savali, tactical officer, and configures animations.
#	
#	Created:	3/28/00 -	Erik Novales
###############################################################################

import App
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create Felix by building his character and placing him on the passed in set.
#	Create his menus as well.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating Felix")
	
	if (pSet.GetObject("Tactical") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("Tactical")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyMaleL/BodyMaleL.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadFelix/felix_head.nif", None)
	pFelix = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyMaleL/BodyMaleL.nif", CharacterPaths.g_pcHeadNIFPath + "HeadFelix/felix_head.nif")
	pFelix.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyMaleM/FedGold_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadFelix/felix_head.tga")

	pFelix.SetCharacterName("Felix")

	# Add the character to the set
	pSet.AddObjectToSet(pFelix, "Tactical")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pFelix)

	# Set up character configuration
	pFelix.SetSize(App.CharacterClass.LARGE)
	pFelix.SetGender(App.CharacterClass.MALE)
	pFelix.SetStanding(0)
	pFelix.SetRandomAnimationChance(0.75)
	pFelix.SetBlinkChance(0.1)
	pFelix.SetAudioMode(App.CharacterClass.CAM_EXTREMELY_VOCAL)
	pFelix.SetDatabase("data/TGL/Bridge Crew General.tgl")

	LoadSounds()

	pFelix.AddFacialImage("Blink0", CharacterPaths.g_pcHeadTexPath + "HeadFelix/Felix_blink1.tga")
	pFelix.AddFacialImage("Blink1", CharacterPaths.g_pcHeadTexPath + "HeadFelix/Felix_blink2.tga")
	pFelix.AddFacialImage("Blink2", CharacterPaths.g_pcHeadTexPath + "HeadFelix/Felix_eyesclosed.tga")
	pFelix.SetBlinkStages(3)

	pFelix.AddFacialImage("SpeakA", CharacterPaths.g_pcHeadTexPath + "HeadFelix/Felix_head_a.tga")
	pFelix.AddFacialImage("SpeakE", CharacterPaths.g_pcHeadTexPath + "HeadFelix/Felix_head_e.tga")
	pFelix.AddFacialImage("SpeakU", CharacterPaths.g_pcHeadTexPath + "HeadFelix/Felix_head_u.tga")
	pFelix.SetAnimatedSpeaking(1)

	pMenusDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTop = App.TopWindow_GetTopWindow()
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pFelix.SetMenu(pTacticalControlWindow.FindMenu(pMenusDatabase.GetString("Tactical")))
	App.g_kLocalizationManager.Unload(pMenusDatabase)

	pFelix.AddAnimation("Place", "Bridge.Characters.CommonAnimations.Standing")
	pFelix.SetLocation("")

#	kDebugObj.Print("Finished creating Felix")
	return pFelix

###############################################################################
#	CreateCharacterNoSounds()
#
#	Create Felix by building his character and placing him on the passed in set.
#	Create his menus as well.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacterNoSounds(pSet):
#	kDebugObj.Print("Creating Felix")
	
	import Bridge.TacticalMenuHandlers
	Bridge.TacticalMenuHandlers.CreateMenusNoSounds(pFelix)

	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyMaleL/BodyMaleL.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadFelix/felix_head.nif", None)
	pFelix = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyMaleL/BodyMaleL.nif", CharacterPaths.g_pcHeadNIFPath + "HeadFelix/felix_head.nif")
	pFelix.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyMaleM/FedGold_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadFelix/felix_head.tga")

	pFelix.SetCharacterName("Felix")

	# Add the character to the set
	pSet.AddObjectToSet(pFelix, "Tactical")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pFelix)

	# Set up character configuration
	pFelix.SetSize(App.CharacterClass.LARGE)
	pFelix.SetGender(App.CharacterClass.MALE)
	pFelix.SetStanding(0)
	pFelix.SetHidden(1)
	pFelix.SetRandomAnimationChance(0.75)
	pFelix.SetBlinkChance(0.1)
	pFelix.SetAudioMode(App.CharacterClass.CAM_EXTREMELY_VOCAL)
	pFelix.SetDatabase("data/TGL/Bridge Crew General.tgl")

	pBrex.AddAnimation("Place", "Bridge.Characters.CommonAnimations.Standing")
	pBrex.SetLocation("")

#	kDebugObj.Print("Finished creating Felix")
	return pFelix


###############################################################################
#	CreateCharacterNoMenu()
#
#	Create Felix by building his character and placing him on the passed in set.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacterNoMenu(pSet):
#	kDebugObj.Print("Creating Felix")
	
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyMaleL/BodyMaleL.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadFelix/felix_head.nif", None)
	pFelix = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyMaleL/BodyMaleL.nif", CharacterPaths.g_pcHeadNIFPath + "HeadFelix/felix_head.nif")
	pFelix.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyMaleM/FedGold_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadFelix/felix_head.tga")

	pFelix.SetCharacterName("Felix")

	# Add the character to the set
	pSet.AddObjectToSet(pFelix, "Tactical")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pFelix)

	# Set up character configuration
	pFelix.SetSize(App.CharacterClass.LARGE)
	pFelix.SetGender(App.CharacterClass.MALE)
	pFelix.SetStanding(0)
	pFelix.SetHidden(1)
	pFelix.SetRandomAnimationChance(0.75)
	pFelix.SetBlinkChance(0.1)
	pFelix.SetAudioMode(App.CharacterClass.CAM_EXTREMELY_VOCAL)
	pFelix.SetDatabase("data/TGL/Bridge Crew General.tgl")

	pFelix.AddAnimation("Place", "Bridge.Characters.CommonAnimations.Standing")
	pFelix.SetLocation("")

#	kDebugObj.Print("Finished creating Felix")
	return pFelix


###############################################################################
#	ConfigureForShip()
#
#	Configure ourselves for the particular ship object.  This involves setting
#	up range watchers that tell us how to report.
#
#	Args:	pSet	- the Set object
#			pShip	- the player's ship
#
#	Return:	none
###############################################################################
def ConfigureForShip(pSet, pShip):
	# Get our character object
	pFelix = App.CharacterClass_Cast(pSet.GetObject("Tactical"))
	if (pFelix == None):
#		kDebugObj.Print("******* Tactical officer not found *********")
		return

#	kDebugObj.Print("Attaching menu to Tactical..")
	import Bridge.TacticalCharacterHandlers
	Bridge.TacticalCharacterHandlers.AttachMenuToTactical(pFelix)


###############################################################################
#	ConfigureForGalaxy()
#
#	Configure ourselves for the Galaxy bridge
#
#	Args:	pFelix	- our Character object
#
#	Return:	none
###############################################################################
def ConfigureForGalaxy(pFelix):
#	kDebugObj.Print("Configuring Felix for the Galaxy bridge")

	# Clear out any old animations from another configuration
	pFelix.ClearAnimations()

	# Register animation mappings
	pFelix.AddAnimation("DBL1LToT", "Bridge.Characters.LargeAnimations.MoveFromL1ToT")
	pFelix.AddAnimation("DBTacticalToL1", "Bridge.Characters.LargeAnimations.MoveFromTToL1")
	pFelix.AddAnimation("DBTacticalTurnCaptain", "Bridge.Characters.LargeAnimations.TurnAtTTowardsCaptain")
	pFelix.AddAnimation("DBTacticalBackCaptain", "Bridge.Characters.LargeAnimations.TurnBackAtTFromCaptain")

	pFelix.AddAnimation("DBTacticalTurnC", "Bridge.Characters.LargeAnimations.DBTTalkC")
	pFelix.AddAnimation("DBTacticalBackC", "Bridge.Characters.LargeAnimations.DBTTalkFinC")
	pFelix.AddAnimation("DBTacticalTurnE", "Bridge.Characters.LargeAnimations.DBTTalkE")
	pFelix.AddAnimation("DBTacticalBackE", "Bridge.Characters.LargeAnimations.DBTTalkFinE")
	pFelix.AddAnimation("DBTacticalTurnH", "Bridge.Characters.LargeAnimations.DBTTalkH")
	pFelix.AddAnimation("DBTacticalBackH", "Bridge.Characters.LargeAnimations.DBTTalkFinH")
	pFelix.AddAnimation("DBTacticalTurnS", "Bridge.Characters.LargeAnimations.DBTTalkS")
	pFelix.AddAnimation("DBTacticalBackS", "Bridge.Characters.LargeAnimations.DBTTalkFinS")

	pFelix.AddAnimation("DBTacticalTurnX", "Bridge.Characters.LargeAnimations.DBTTalkX")
	pFelix.AddAnimation("DBTacticalBackX", "Bridge.Characters.LargeAnimations.DBTTalkFinX")

	pFelix.AddAnimation("DBTacticalGlanceCaptain", "Bridge.Characters.CommonAnimations.GlanceLeft")
	pFelix.AddAnimation("DBTacticalGlanceAwayCaptain", "Bridge.Characters.CommonAnimations.SeatedL")

	# Breathing
	pFelix.AddAnimation("DBTacticalBreathe", "Bridge.Characters.CommonAnimations.SeatedL")
	pFelix.AddAnimation("DBTacticalBreatheTurned", "Bridge.Characters.CommonAnimations.BreathingTurned")

	# Interaction
	pFelix.AddRandomAnimation("Bridge.Characters.LargeAnimations.DBTConsoleInteraction", App.CharacterClass.SITTING_ONLY, 25, 1)

	# So the mission builders can force the call
	pFelix.AddAnimation("PushingButtons", "Bridge.Characters.LargeAnimations.DBTConsoleInteraction")

	# Hit animations		
	pFelix.AddAnimation("DBTacticalHit", "Bridge.Characters.LargeAnimations.THit");
	pFelix.AddAnimation("DBTacticalHitHard", "Bridge.Characters.LargeAnimations.THitHard");
	pFelix.AddAnimation("DBTacticalReactLeft", "Bridge.Characters.CommonAnimations.ReactLeft");
	pFelix.AddAnimation("DBTacticalReactRight", "Bridge.Characters.CommonAnimations.ReactRight");

	# Add common animations.
	AddCommonAnimations(pFelix)
	
	pFelix.SetLocation("DBTactical")
	pFelix.AddPositionZoom("DBTactical", 0.5, "Tactical")
	pFelix.SetLookAtAdj(0, 0, 51)
#	kDebugObj.Print("Finished configuring Felix")


###############################################################################
#	ConfigureForSovereign()
#
#	Configure ourselves for the Sovereign bridge
#
#	Args:	pFelix	- our Character object
#
#	Return:	none
###############################################################################
def ConfigureForSovereign(pFelix):
#	kDebugObj.Print("Configuring Felix for the Sovereign bridge")

	# Clear out any old animations from another configuration
	pFelix.ClearAnimations()

	# Register animation mappings
	pFelix.AddAnimation("SeatedEBTactical", "Bridge.Characters.CommonAnimations.SeatedL")
	pFelix.AddAnimation("EBL1LToT", "Bridge.Characters.LargeAnimations.EBMoveFromL1ToT")
	pFelix.AddAnimation("EBTacticalToL1", "Bridge.Characters.LargeAnimations.EBMoveFromTToL1")
	pFelix.AddAnimation("EBTacticalTurnCaptain", "Bridge.Characters.LargeAnimations.EBTurnAtTTowardsCaptain")
	pFelix.AddAnimation("EBTacticalBackCaptain", "Bridge.Characters.LargeAnimations.EBTurnBackAtTFromCaptain")

	pFelix.AddAnimation("EBTacticalTurnC", "Bridge.Characters.LargeAnimations.EBTTalkC")
	pFelix.AddAnimation("EBTacticalBackC", "Bridge.Characters.LargeAnimations.EBTTalkFinC")
	pFelix.AddAnimation("EBTacticalTurnE", "Bridge.Characters.LargeAnimations.EBTTalkE")
	pFelix.AddAnimation("EBTacticalBackE", "Bridge.Characters.LargeAnimations.EBTTalkFinE")
	pFelix.AddAnimation("EBTacticalTurnH", "Bridge.Characters.LargeAnimations.EBTTalkH")
	pFelix.AddAnimation("EBTacticalBackH", "Bridge.Characters.LargeAnimations.EBTTalkFinH")
	pFelix.AddAnimation("EBTacticalTurnS", "Bridge.Characters.LargeAnimations.EBTTalkS")
	pFelix.AddAnimation("EBTacticalBackS", "Bridge.Characters.LargeAnimations.EBTTalkFinS")

	pFelix.AddAnimation("EBTacticalTurnX", "Bridge.Characters.LargeAnimations.EBTTalkE")
	pFelix.AddAnimation("EBTacticalBackX", "Bridge.Characters.LargeAnimations.EBTTalkFinE")

	pFelix.AddAnimation("EBTacticalGlanceCaptain", "Bridge.Characters.CommonAnimations.GlanceLeft")
	pFelix.AddAnimation("EBTacticalGlanceAwayCaptain", "Bridge.Characters.CommonAnimations.SeatedL")

	# Breathing
	pFelix.AddAnimation("EBTacticalBreathe", "Bridge.Characters.CommonAnimations.SeatedL")
	pFelix.AddAnimation("EBTacticalBreatheTurned", "Bridge.Characters.CommonAnimations.BreathingTurned")

	# Interaction
	pFelix.AddRandomAnimation("Bridge.Characters.LargeAnimations.EBTConsoleInteraction", App.CharacterClass.SITTING_ONLY, 25, 1)

	# So the mission builders can force the call
	pFelix.AddAnimation("PushingButtons", "Bridge.Characters.LargeAnimations.EBTConsoleInteraction")

	# Hit animations		
	#pFelix.AddAnimation("EBTacticalHit", "Bridge.Characters.LargeAnimations.THit")
	#pFelix.AddAnimation("EBTacticalHitHard", "Bridge.Characters.LargeAnimations.THitHard")
	pFelix.AddAnimation("EBTacticalReactLeft", "Bridge.Characters.CommonAnimations.ReactLeft")
	pFelix.AddAnimation("EBTacticalReactRight", "Bridge.Characters.CommonAnimations.ReactRight")

	# Add common animations.
	AddCommonAnimations(pFelix)
	
	pFelix.SetLocation("EBTactical")
	pFelix.AddPositionZoom("EBTactical", 0.5, "Tactical")
	pFelix.SetLookAtAdj(5, 0, 65)
#	kDebugObj.Print("Finished configuring Felix")



###############################################################################
#	AddCommonAnimations()
#
#	Since we can only clear out all animations when switching bridges (how
#	would we know which not to clear?), we can't really setup animations common
#	to all bridge configurations as we might like.  Because of this we have a
#	routine to add common animations (most of which are randoms) that both
#	configurations will call
#
#	Args:	pFelix	- our Character object
#
#	Return:	none
###############################################################################
def AddCommonAnimations(pFelix):
	pFelix.AddRandomAnimation("Bridge.Characters.LargeAnimations.TLookAroundConsoleDown", App.CharacterClass.SITTING_ONLY, 1, 1)

	pFelix.AddRandomAnimation("Bridge.Characters.CommonAnimations.TiltHeadLeft")
	pFelix.AddRandomAnimation("Bridge.Characters.CommonAnimations.TiltHeadRight")
	pFelix.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookUp")
	pFelix.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookDown")

	#pFelix.AddRandomAnimation("Bridge.Characters.CommonAnimations.WipingBrowLeft")
	#pFelix.AddRandomAnimation("Bridge.Characters.CommonAnimations.WipingBrowRight")
	#pFelix.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookLeft")
	#pFelix.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookRight")
	#pFelix.AddRandomAnimation("Bridge.Characters.CommonAnimations.AtEase", App.CharacterClass.STANDING_ONLY)

###############################################################################
#	OffBridgeStart
#	
#	Sets Felix's location to start in the off bridge partial set
#	
#	Args:	pFelix	- our character object
#	
#	Return:	none
###############################################################################
def OffBridgeStart(pFelix):
	pFelix = App.CharacterClass_Cast(pFelix)
	# Nothing else to do, unless you want to change his position

	#Adjust positions of bridge characters here
	pFelix.SetTranslateXYZ(0, 0, -5)

	import Bridge.Characters.CommonAnimations
	return Bridge.Characters.CommonAnimations.Standing(pFelix)


###############################################################################
#	ConfigureForOffBridge()
#
#	Configure ourselves for another partial set
#
#	Args:	pFelix	- our Character object
#
#	Return:	none
###############################################################################
def ConfigureForOffBridge(pFelix):
#	kDebugObj.Print("Configuring Felix for off bridge")

	# Clear out any old animations from another configuration
	pFelix.ClearAnimations()

	# Register animation mappings
	pFelix.SetStanding(1)
	pFelix.SetHidden(0)
	pFelix.SetLocation("KlingonSeated")
	AddCommonAnimations(pFelix)

#	kDebugObj.Print("Finished configuring Felix")

###############################################################################
#	LoadSounds
#	
#	Precache Felix's typical voice lines, so they don't hitch the
#	game when they try to play.
#	
#	Args:	None
#	
#	Return:	None
###############################################################################
def LoadSounds():
	pGame = App.Game_GetCurrentGame()
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")

	# Loop through all of Felix's voice lines that we want to preload, and load them.
	for sLine in g_lsFelixLines:
		pGame.LoadDatabaseSoundInGroup(pDatabase, sLine, "BridgeGeneric")

	App.g_kLocalizationManager.Unload(pDatabase)

#
# A list of the voice lines we want preloaded for Felix.
#
g_lsFelixLines = (
	"AttackStatus_EvadingTorps1",
	"AttackStatus_FallingBack1",
	"AttackStatus_LiningUpFront1",
	"AttackStatus_MovingIn1",
	"AttackStatus_RearTorpRun1",
	"AttackStatus_SweepingPhasers1",
	"BadTarget1",
	"BadTarget2",
	"Disengaging",
	"DontShootTac",
	"EvasiveManuvers", # Sumbody furgot to spel this rite.
	"FelixEnDes",
	"FelixNothingToAdd",
	"FelixNothingToAdd2",
	"FelixNothingToAdd3",
	"FelixSir1",
	"FelixSir2",
	"FelixSir3",
	"FelixSir4",
	"FelixSir5",
	"FelixYes1",
	"FelixYes2",
	"FelixYes3",
	"FelixYes4",
	"ForeShieldsOffline",
	"Incoming1",
	"Incoming2",
	"Incoming3",
	"Incoming4",
	"Incoming5",
	"Incoming6",
	"LoadingPhoton",
	"LoadingQuantum",
	"LoadingTorps",
	"NeedPower",
	"OutOfPhotons",
	"OutOfQuantums",
	"OutOfType",
	"TacticalManuver", # This wun to.
	"gt001",
	"gt002",
	"gt007",
	"gt029",
	"gt030",
	"gt037",
	"gt038",
	"gt212",
	"gt213",
	)
