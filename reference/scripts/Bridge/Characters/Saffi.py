###############################################################################
#	Filename:	Saffi.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads Saffi Larsen, XO, and configures animations.
#	
#	Created:	3/28/00 -	Erik Novales
###############################################################################

import App
import CharacterPaths

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print

###############################################################################
#	CreateCharacter()
#
#	Create Saffi by building her character and placing her on the passed in set.
#	Create her menus as well.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	debug("Creating Saffi")

	if (pSet.GetObject("XO") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("XO")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyFemM/BodyFemM.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadSaffi/saffi_head.nif", None)
	pSaffi = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyFemM/BodyFemM.nif", CharacterPaths.g_pcHeadNIFPath + "HeadSaffi/saffi_head.nif", 1)
	pSaffi.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyFemS/FedFemRed_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadSaffi/saffi_head.tga")

	pSaffi.SetCharacterName("Saffi")

	# Add the character to the set
	pSet.AddObjectToSet(pSaffi, "XO")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pSaffi)

	# Setup the character configuration
	pSaffi.SetSize(App.CharacterClass.MEDIUM)
	pSaffi.SetGender(App.CharacterClass.FEMALE)
	pSaffi.SetRandomAnimationChance(.75)
	pSaffi.SetBlinkChance(0.1)
	pSaffi.SetDatabase("data/TGL/Bridge Crew General.tgl")

	# Load Saffi's general dialogue lines.
	LoadSounds()

	pSaffi.AddFacialImage("Blink0", CharacterPaths.g_pcHeadTexPath + "HeadSaffi/Saffi_head_blink1.tga")
	pSaffi.AddFacialImage("Blink1", CharacterPaths.g_pcHeadTexPath + "HeadSaffi/Saffi_head_blink2.tga")
	pSaffi.AddFacialImage("Blink2", CharacterPaths.g_pcHeadTexPath + "HeadSaffi/Saffi_head_eyesclosed.tga")
	pSaffi.SetBlinkStages(3)

	pSaffi.AddFacialImage("SpeakA", CharacterPaths.g_pcHeadTexPath + "HeadSaffi/saffi_head_a.tga")
	pSaffi.AddFacialImage("SpeakE", CharacterPaths.g_pcHeadTexPath + "HeadSaffi/saffi_head_e.tga")
	pSaffi.AddFacialImage("SpeakU", CharacterPaths.g_pcHeadTexPath + "HeadSaffi/saffi_head_u.tga")
	pSaffi.SetAnimatedSpeaking(1)

	pMenusDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTop = App.TopWindow_GetTopWindow()
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pSaffi.SetMenu(pTacticalControlWindow.FindMenu(pMenusDatabase.GetString("Commander")))
	App.g_kLocalizationManager.Unload(pMenusDatabase)

#	debug("Finished creating Saffi")
	return pSaffi


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
	# Get our character object
	pSaffi = App.CharacterClass_Cast(pSet.GetObject("XO"))
	if (pSaffi == None):
#		debug("******* Commanding officer not found *********")
		return

#	debug("Attaching menu to XO..")
	import Bridge.XOCharacterHandlers
	Bridge.XOCharacterHandlers.AttachMenuToXO(pSaffi)

	#
	# This is where code to set up responses based on the ships state
	# e.g. "Main power back on line"
	#


###############################################################################
#	ConfigureForGalaxy()
#
#	Configure ourselves for the Galaxy bridge
#
#	Args:	pSaffi	- our Character object
#
#	Return:	none
###############################################################################
def ConfigureForGalaxy(pSaffi):
#	debug("Configuring Saffi for the Galaxy bridge")

	# Clear out any old animations from another configuration
	pSaffi.ClearAnimations()

	kAM = App.g_kAnimationManager

	# Greeting animations
	kAM.LoadAnimation ("data/animations/Arms_Folded_Start.nif", "Arms_Folded_Start")
	kAM.LoadAnimation ("data/animations/DB_face_capt_C1.NIF", "Face_Capt")
	kAM.LoadAnimation ("data/animations/DB_face_capt_C1_reverse.NIF", "Face_Front")


	# Register animation mappings
	pSaffi.AddAnimation("SeatedDBCommander", "Bridge.Characters.CommonAnimations.SeatedM")
	pSaffi.AddAnimation("StandingC1", "Bridge.Characters.CommonAnimations.Standing")
	pSaffi.AddAnimation("DBL1MToC", "Bridge.Characters.MediumAnimations.MoveFromL1ToC")
	pSaffi.AddAnimation("DBL1MToC2", "Bridge.Characters.MediumAnimations.MoveFromL1ToC2")
	pSaffi.AddAnimation("DBCommanderToL1", "Bridge.Characters.MediumAnimations.MoveFromCToL1")
	pSaffi.AddAnimation("DBCommanderToC1", "Bridge.Characters.MediumAnimations.MoveFromCToC1")
	pSaffi.AddAnimation("DBCommander1ToC", "Bridge.Characters.MediumAnimations.MoveFromC1ToC")
	pSaffi.AddAnimation("DBCommander1ToC2", "Bridge.Characters.MediumAnimations.MoveFromC1ToC2")
	pSaffi.AddAnimation("DBCommander2ToC", "Bridge.Characters.MediumAnimations.MoveFromC2ToC")
	pSaffi.AddAnimation("DBCommanderTurnCaptain", "Bridge.Characters.MediumAnimations.TurnAtCTowardsCaptain")
	pSaffi.AddAnimation("DBCommander1TurnCaptain", "Bridge.Characters.MediumAnimations.TurnAtC1TowardsCaptain")
	pSaffi.AddAnimation("DBCommanderBackCaptain", "Bridge.Characters.CommonAnimations.SeatedM")
	pSaffi.AddAnimation("DBCommander1BackCaptain", "Bridge.Characters.MediumAnimations.TurnBackAtC1FromCaptain")

	pSaffi.AddAnimation("DBCommanderGlanceCaptain", "Bridge.Characters.CommonAnimations.GlanceLeft")
	pSaffi.AddAnimation("DBCommanderGlanceAwayCaptain", "Bridge.Characters.CommonAnimations.SeatedM")
	pSaffi.AddAnimation("DBCommander1GlanceCaptain", "Bridge.Characters.CommonAnimations.GlanceLeft")
	pSaffi.AddAnimation("DBCommander1GlanceAwayCaptain", "Bridge.Characters.CommonAnimations.Standing")

	pSaffi.AddAnimation("DBCommanderTurnE", "Bridge.Characters.MediumAnimations.DBCTalkE")
	pSaffi.AddAnimation("DBCommanderBackE", "Bridge.Characters.CommonAnimations.SeatedM")
	pSaffi.AddAnimation("DBCommanderTurnH", "Bridge.Characters.MediumAnimations.DBCTalkH")
	pSaffi.AddAnimation("DBCommanderBackH", "Bridge.Characters.CommonAnimations.SeatedM")
	pSaffi.AddAnimation("DBCommanderTurnT", "Bridge.Characters.MediumAnimations.DBCTalkT")
	pSaffi.AddAnimation("DBCommanderBackT", "Bridge.Characters.CommonAnimations.SeatedM")
	pSaffi.AddAnimation("DBCommanderTurnS", "Bridge.Characters.MediumAnimations.DBCTalkS")
	pSaffi.AddAnimation("DBCommanderBackS", "Bridge.Characters.CommonAnimations.SeatedM")

	pSaffi.AddAnimation("DBCommanderTurnX", "Bridge.Characters.MediumAnimations.DBCTalkX")
	pSaffi.AddAnimation("DBCommanderBackX", "Bridge.Characters.CommonAnimations.SeatedM")

	pSaffi.AddAnimation("DBCommander2TurnP1", "Bridge.Characters.MediumAnimations.DBC2TalkP1")
	pSaffi.AddAnimation("DBCommander2BackP1", "Bridge.Characters.MediumAnimations.DBC2TalkFinP1")

	# Breathing	
	pSaffi.AddAnimation("DBCommanderBreathe", "Bridge.Characters.CommonAnimations.SeatedM")
	pSaffi.AddAnimation("DBCommander1Breathe", "Bridge.Characters.CommonAnimations.Standing")
	pSaffi.AddAnimation("DBCommanderBreatheTurned", "Bridge.Characters.CommonAnimations.BreathingTurned")
	pSaffi.AddAnimation("DBCommander1BreatheTurned", "Bridge.Characters.CommonAnimations.BreathingTurned")

	# So the mission builders can force the call
	pSaffi.AddAnimation("PushingButtons", "Bridge.Characters.MediumAnimations.DBCConsoleInteraction")

	# Hit animations
	pSaffi.AddAnimation("DBCommanderHit", "Bridge.Characters.MediumAnimations.CHit");
	pSaffi.AddAnimation("DBCommanderHitHard", "Bridge.Characters.MediumAnimations.CHitHard");
	pSaffi.AddAnimation("DBCommanderHitStanding", "Bridge.Characters.CommonAnimations.HitStanding");
	pSaffi.AddAnimation("DBCommanderHitHardStanding", "Bridge.Characters.CommonAnimations.HitHardStanding");
	pSaffi.AddAnimation("DBCommanderReactLeft", "Bridge.Characters.CommonAnimations.ReactLeft");
	pSaffi.AddAnimation("DBCommanderReactRight", "Bridge.Characters.CommonAnimations.ReactRight");

	# Add common animations.
	AddCommonAnimations(pSaffi)

	pSaffi.SetLocation("DBCommander")
#	debug("Finished configuring Saffi")


###############################################################################
#	ConfigureForSovereign()
#
#	Configure ourselves for the Sovereign bridge
#
#	Args:	pSaffi	- our Character object
#
#	Return:	none
###############################################################################
def ConfigureForSovereign(pSaffi):
#	debug("Configuring Saffi for the Sovereign bridge")

	# Clear out any old animations from another configuration
	pSaffi.ClearAnimations()

	# Register animation mappings
	pSaffi.AddAnimation("SeatedEBCommander", "Bridge.Characters.CommonAnimations.SeatedM")
	pSaffi.AddAnimation("StandingEBCommander1", "Bridge.Characters.CommonAnimations.Standing")
	pSaffi.AddAnimation("EBL1MToEBCommander", "Bridge.Characters.MediumAnimations.EBMoveFromL1ToC")
	pSaffi.AddAnimation("EBCommanderToL1", "Bridge.Characters.MediumAnimations.EBMoveFromCToL1")
	pSaffi.AddAnimation("EBCommanderToC1", "Bridge.Characters.MediumAnimations.EBMoveFromCToC1")
	pSaffi.AddAnimation("EBCommander1ToC", "Bridge.Characters.MediumAnimations.EBMoveFromC1ToC")
	pSaffi.AddAnimation("EBCommanderTurnCaptain", "Bridge.Characters.MediumAnimations.EBTurnAtCTowardsCaptain")
	pSaffi.AddAnimation("EBCommander1TurnCaptain", "Bridge.Characters.CommonAnimations.LookLeft")
#	pSaffi.AddAnimation("EBCommander1TurnCaptain", "Bridge.Characters.MediumAnimations.EBTurnAtC1TowardsCaptain")
	pSaffi.AddAnimation("EBCommanderBackCaptain", "Bridge.Characters.CommonAnimations.SeatedM")
	pSaffi.AddAnimation("EBCommander1BackCaptain", "Bridge.Characters.CommonAnimations.Standing")
#	pSaffi.AddAnimation("EBCommander1BackCaptain", "Bridge.Characters.MediumAnimations.EBTurnBackAtC1FromCaptain")

	pSaffi.AddAnimation("EBCommanderGlanceCaptain", "Bridge.Characters.CommonAnimations.GlanceLeft")
	pSaffi.AddAnimation("EBCommanderGlanceAwayCaptain", "Bridge.Characters.CommonAnimations.SeatedM")
	pSaffi.AddAnimation("EBCommander1GlanceCaptain", "Bridge.Characters.CommonAnimations.GlanceLeft")
	pSaffi.AddAnimation("EBCommander1GlanceAwayCaptain", "Bridge.Characters.CommonAnimations.Standing")

	pSaffi.AddAnimation("EBCommanderTurnE", "Bridge.Characters.MediumAnimations.EBCTalkE")
	pSaffi.AddAnimation("EBCommanderBackE", "Bridge.Characters.CommonAnimations.SeatedM")
	pSaffi.AddAnimation("EBCommanderTurnH", "Bridge.Characters.MediumAnimations.EBCTalkH")
	pSaffi.AddAnimation("EBCommanderBackH", "Bridge.Characters.CommonAnimations.SeatedM")
	pSaffi.AddAnimation("EBCommanderTurnT", "Bridge.Characters.MediumAnimations.EBCTalkT")
	pSaffi.AddAnimation("EBCommanderBackT", "Bridge.Characters.CommonAnimations.SeatedM")
	pSaffi.AddAnimation("EBCommanderTurnS", "Bridge.Characters.MediumAnimations.EBCTalkS")
	pSaffi.AddAnimation("EBCommanderBackS", "Bridge.Characters.CommonAnimations.SeatedM")

	pSaffi.AddAnimation("EBCommanderTurnX", "Bridge.Characters.MediumAnimations.EBCTalkE")
	pSaffi.AddAnimation("EBCommanderBackX", "Bridge.Characters.CommonAnimations.SeatedM")

	# Breathing
	pSaffi.AddAnimation("EBCommanderBreathe", "Bridge.Characters.CommonAnimations.SeatedM")
	pSaffi.AddAnimation("EBCommander1Breathe", "Bridge.Characters.CommonAnimations.Standing")
	pSaffi.AddAnimation("EBCommanderBreatheTurned", "Bridge.Characters.CommonAnimations.BreathingTurned")
	pSaffi.AddAnimation("EBCommander1BreatheTurned", "Bridge.Characters.CommonAnimations.BreathingTurned")

	# Interaction
	pSaffi.AddRandomAnimation("Bridge.Characters.MediumAnimations.EBCConsoleInteraction", App.CharacterClass.SITTING_ONLY, 25, 1)

	# So the mission builders can force the call
	pSaffi.AddAnimation("PushingButtons", "Bridge.Characters.MediumAnimations.EBCConsoleInteraction")

	# Hit animations
	#pSaffi.AddAnimation("EBCommanderHit", "Bridge.Characters.MediumAnimations.CHit")
	#pSaffi.AddAnimation("EBCommanderHitHard", "Bridge.Characters.MediumAnimations.CHitHard")
	#pSaffi.AddAnimation("EBCommanderHitStanding", "Bridge.Characters.CommonAnimations.HitStanding")
	#pSaffi.AddAnimation("EBCommanderHitHardStanding", "Bridge.Characters.CommonAnimations.HitHardStanding")
	pSaffi.AddAnimation("EBCommanderReactLeft", "Bridge.Characters.CommonAnimations.ReactLeft")
	pSaffi.AddAnimation("EBCommanderReactRight", "Bridge.Characters.CommonAnimations.ReactRight")

	# Add common animations.
	AddCommonAnimations(pSaffi)

	pSaffi.SetLocation("EBCommander")
	pSaffi.AddPositionZoom("EBCommander", 0.8)
#	debug("Finished configuring Saffi")


###############################################################################
#	AddCommonAnimations()
#
#	Since we can only clear out all animations when switching bridges (how
#	would we know which not to clear?), we can't really setup animations common
#	to all bridge configurations as we might like.  Because of this we have a
#	routine to add common animations (most of which are randoms) that both
#	configurations will call
#
#	Args:	pSaffi	- our Character object
#
#	Return:	none
###############################################################################
def AddCommonAnimations(pSaffi):
	pSaffi.AddRandomAnimation("Bridge.Characters.MediumAnimations.CLookAroundConsoleDown", App.CharacterClass.SITTING_ONLY, 1, 1)

	pSaffi.AddRandomAnimation("Bridge.Characters.CommonAnimations.TiltHeadLeft")
	pSaffi.AddRandomAnimation("Bridge.Characters.CommonAnimations.TiltHeadRight")
	pSaffi.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookLeft", App.CharacterClass.SITTING_ONLY)
	pSaffi.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookRight", App.CharacterClass.SITTING_ONLY)
	pSaffi.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookUp", App.CharacterClass.SITTING_ONLY)
	pSaffi.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookDown", App.CharacterClass.SITTING_ONLY)

###############################################################################
#	LoadSounds
#	
#	Load any of Saffi's general or spontaneous sounds, so they don't
#	hitch the game when they're played.
#	
#	Args:	None
#	
#	Return:	None
###############################################################################
def LoadSounds():
	pGame = App.Game_GetCurrentGame()
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")
	
	#
	# Build a list of sound to load
	#
	lSoundList =	[
		# Yes?
		"gf001",
		"gf002",

		# Report.
		"gf020",

		# Alert lines.
		"GreenAlert",
		"GreenAlert2",
		"GreenAlert3",
		"YellowAlert",
		"YellowAlert3",
		"YellowAlert2",
		"RedAlert",
		"RedAlert2",

		# Contacting starfleet.
		"gl004",
		"gl005",
					]
	#
	# Loop through that list, loading each sound in the "BridgeGeneric" group
	#
	for sLine in lSoundList:
		pGame.LoadDatabaseSoundInGroup(pDatabase, sLine, "BridgeGeneric")

	App.g_kLocalizationManager.Unload(pDatabase)
