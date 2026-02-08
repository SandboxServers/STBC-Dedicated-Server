###############################################################################
#	Filename:	Miguel.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads Miguel Diaz, science, and configures animations.
#	
#	Created:	3/28/00 -	Erik Novales
###############################################################################

import App
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create Miguel by building his character and placing him on the passed in set.
#	Create his menus as well.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating Miguel")

	if (pSet.GetObject("Science") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("Science")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyMaleS/BodyMaleS.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadMiguel/miguel_head.nif", None)
	pMiguel = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyMaleS/BodyMaleS.nif", CharacterPaths.g_pcHeadNIFPath + "HeadMiguel/miguel_head.nif")
	pMiguel.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyMaleM/FedTeal_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/miguel_head.tga")

	pMiguel.SetCharacterName("Miguel")

	# Add the character to the set
	pSet.AddObjectToSet(pMiguel, "Science")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pMiguel)

	# Setup the character configuration
	pMiguel.SetSize(App.CharacterClass.SMALL)
	pMiguel.SetGender(App.CharacterClass.MALE)
	pMiguel.SetRandomAnimationChance(.75)
	pMiguel.SetBlinkChance(0.1)
	pMiguel.SetDatabase("data/TGL/Bridge Crew General.tgl")

	# Load Science officer generic sounds
	LoadSounds()

	pMiguel.AddFacialImage("Blink0", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Miguel_head_blink1.tga")
	pMiguel.AddFacialImage("Blink1", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Miguel_head_blink2.tga")
	pMiguel.AddFacialImage("Blink2", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Miguel_head_eyesclosed.tga")
	pMiguel.SetBlinkStages(3)

	pMiguel.AddFacialImage("SpeakA", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Miguel_head_a.tga")
	pMiguel.AddFacialImage("SpeakE", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Miguel_head_e.tga")
	pMiguel.AddFacialImage("SpeakU", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Miguel_head_u.tga")
	pMiguel.SetAnimatedSpeaking(1)

	pGame = App.Game_GetCurrentGame()
	pGame.LoadDatabaseSoundInGroup(pMiguel.GetDatabase(), "MiguelNothingToAdd", "BridgeGeneric")

	pMenusDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTop = App.TopWindow_GetTopWindow()
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pMiguel.SetMenu(pTacticalControlWindow.FindMenu(pMenusDatabase.GetString("Science")))
	App.g_kLocalizationManager.Unload(pMenusDatabase)

#	kDebugObj.Print("Finished creating Miguel")
	return pMiguel


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
	pMiguel = App.CharacterClass_Cast(pSet.GetObject("Science"))
	if (pMiguel == None):
#		kDebugObj.Print("******* Science officer not found *********")
		return

#	kDebugObj.Print("Attaching menu to Science..")
	import Bridge.ScienceCharacterHandlers
	Bridge.ScienceCharacterHandlers.AttachMenuToScience(pMiguel)

	#
	# This is where code to set up responses based on the ships state
	# e.g. "Receiving probe data"
	#



###############################################################################
#	ConfigureForGalaxy()
#
#	Configure ourselves for the Galaxy bridge
#
#	Args:	pMiguel	- our Character object
#
#	Return:	none
###############################################################################
def ConfigureForGalaxy(pMiguel):
#	kDebugObj.Print("Configuring Miguel for the Galaxy bridge")

	# Clear out any old animations from another configuration
	pMiguel.ClearAnimations()

	# Register animation mappings
	pMiguel.AddAnimation("DBL1SToS", "Bridge.Characters.SmallAnimations.MoveFromL1ToS")
	pMiguel.AddAnimation("DBScienceToL1", "Bridge.Characters.SmallAnimations.MoveFromSToL1")
	pMiguel.AddAnimation("DBScienceTurnCaptain", "Bridge.Characters.SmallAnimations.TurnAtSTowardsCaptain")
	pMiguel.AddAnimation("DBScienceBackCaptain", "Bridge.Characters.CommonAnimations.StandingConsole")

	pMiguel.AddAnimation("DBScienceTurnC", "Bridge.Characters.SmallAnimations.DBSTalkC")
	pMiguel.AddAnimation("DBScienceBackC", "Bridge.Characters.CommonAnimations.StandingConsole")
	pMiguel.AddAnimation("DBScienceTurnH", "Bridge.Characters.SmallAnimations.DBSTalkH")
	pMiguel.AddAnimation("DBScienceBackH", "Bridge.Characters.CommonAnimations.StandingConsole")
	pMiguel.AddAnimation("DBScienceTurnE", "Bridge.Characters.SmallAnimations.DBSTalkE")
	pMiguel.AddAnimation("DBScienceBackE", "Bridge.Characters.CommonAnimations.StandingConsole")
	pMiguel.AddAnimation("DBScienceTurnT", "Bridge.Characters.SmallAnimations.DBSTalkT")
	pMiguel.AddAnimation("DBScienceBackT", "Bridge.Characters.CommonAnimations.StandingConsole")

	pMiguel.AddAnimation("DBScienceTurnX", "Bridge.Characters.SmallAnimations.DBSTalkX")
	pMiguel.AddAnimation("DBScienceBackX", "Bridge.Characters.CommonAnimations.StandingConsole")

	pMiguel.AddAnimation("DBScienceGlanceCaptain", "Bridge.Characters.CommonAnimations.GlanceLeft")
	pMiguel.AddAnimation("DBScienceGlanceAwayCaptain", "Bridge.Characters.CommonAnimations.Standing")

	pMiguel.AddAnimation("LookAroundConsole", "Bridge.Characters.CommonAnimations.LookAroundConsoleDown")

	# Breathing	
	pMiguel.AddAnimation("DBScienceBreathe", "Bridge.Characters.CommonAnimations.StandingConsole")
	pMiguel.AddAnimation("DBScienceSBreatheTurned", "Bridge.Characters.CommonAnimations.BreathingTurned")

	# Interaction
	pMiguel.AddRandomAnimation("Bridge.Characters.SmallAnimations.DBSConsoleInteraction", App.CharacterClass.SITTING_ONLY, 25, 1)

	# So the mission builders can force the call
	pMiguel.AddAnimation("PushingButtons", "Bridge.Characters.SmallAnimations.DBSConsoleInteraction")

	# Hit animations
	pMiguel.AddAnimation("DBScienceHitStanding", "Bridge.Characters.CommonAnimations.HitStanding")
	pMiguel.AddAnimation("DBScienceHitHardStanding", "Bridge.Characters.CommonAnimations.HitHardStanding")
	pMiguel.AddAnimation("DBScienceReactLeftStanding", "Bridge.Characters.CommonAnimations.ReactLeft");
	pMiguel.AddAnimation("DBScienceReactRightStanding", "Bridge.Characters.CommonAnimations.ReactRight");
	pMiguel.AddAnimation("DBScienceHitHardStandingTest", "Bridge.Characters.CommonAnimations.HitHardStanding")

	# Add common animations.
	AddCommonAnimations(pMiguel)

	# Miguel stands on the Galaxy bridge
	pMiguel.SetStanding(1)
	pMiguel.SetLocation("DBScience")
#	kDebugObj.Print("Finished configuring Miguel")


###############################################################################
#	ConfigureForSovereign()
#
#	Configure ourselves for the Sovereign bridge
#
#	Args:	pMiguel	- our Character object
#
#	Return:	none
###############################################################################
def ConfigureForSovereign(pMiguel):
#	kDebugObj.Print("Configuring Miguel for the Sovereign bridge")

	# Clear out any old animations from another configuration
	pMiguel.ClearAnimations()

	# Register animation mappings
	pMiguel.AddAnimation("EBL1SToS", "Bridge.Characters.SmallAnimations.EBMoveFromL1ToS")
	pMiguel.AddAnimation("EBScienceToL1", "Bridge.Characters.SmallAnimations.EBMoveFromSToL1")
	pMiguel.AddAnimation("EBScienceTurnCaptain", "Bridge.Characters.SmallAnimations.EBTurnAtSTowardsCaptain")
	pMiguel.AddAnimation("EBScienceBackCaptain", "Bridge.Characters.SmallAnimations.EBTurnBackAtSFromCaptain")

	pMiguel.AddAnimation("EBScienceTurnC", "Bridge.Characters.SmallAnimations.EBSTalkC")
	pMiguel.AddAnimation("EBScienceBackC", "Bridge.Characters.CommonAnimations.SeatedS")
	pMiguel.AddAnimation("EBScienceTurnH", "Bridge.Characters.SmallAnimations.EBSTalkH")
	pMiguel.AddAnimation("EBScienceBackH", "Bridge.Characters.CommonAnimations.SeatedS")
	pMiguel.AddAnimation("EBScienceTurnE", "Bridge.Characters.SmallAnimations.EBSTalkE")
	pMiguel.AddAnimation("EBScienceBackE", "Bridge.Characters.CommonAnimations.SeatedS")
	pMiguel.AddAnimation("EBScienceTurnT", "Bridge.Characters.SmallAnimations.EBSTalkT")
	pMiguel.AddAnimation("EBScienceBackT", "Bridge.Characters.CommonAnimations.SeatedS")

	pMiguel.AddAnimation("EBScienceTurnX", "Bridge.Characters.SmallAnimations.EBSTalkE")
	pMiguel.AddAnimation("EBScienceBackX", "Bridge.Characters.CommonAnimations.SeatedS")

	pMiguel.AddAnimation("EBScienceGlanceCaptain", "Bridge.Characters.CommonAnimations.GlanceLeft")
	pMiguel.AddAnimation("EBScienceGlanceAwayCaptain", "Bridge.Characters.CommonAnimations.SeatedS")

	pMiguel.AddAnimation("EBScienceToS1", "Bridge.Characters.SmallAnimations.EBMoveFromSToS1")
	pMiguel.AddAnimation("EBScience1ToS", "Bridge.Characters.SmallAnimations.EBMoveFromS1ToS")
	pMiguel.AddAnimation("EBScienceToS2", "Bridge.Characters.SmallAnimations.EBMoveFromSToS2")
	pMiguel.AddAnimation("EBScience2ToS", "Bridge.Characters.SmallAnimations.EBMoveFromS2ToS")
	pMiguel.AddAnimation("EBScience1ToS2", "Bridge.Characters.SmallAnimations.EBMoveFromS1ToS2")
	pMiguel.AddAnimation("EBScience2ToS1", "Bridge.Characters.SmallAnimations.EBMoveFromS2ToS1")

	# Breathing	
	pMiguel.AddAnimation("EBScienceBreathe", "Bridge.Characters.CommonAnimations.SeatedS")
	pMiguel.AddAnimation("EBScienceBreatheTurned", "Bridge.Characters.CommonAnimations.BreathingTurned")

	# Interaction
	pMiguel.AddRandomAnimation("Bridge.Characters.SmallAnimations.EBSConsoleInteraction", App.CharacterClass.SITTING_ONLY, 25, 1)

	# So the mission builders can force the call
	pMiguel.AddAnimation("PushingButtons", "Bridge.Characters.SmallAnimations.EBSConsoleInteraction")

	# Hit animations
	pMiguel.AddAnimation("EBScienceHitStanding", "Bridge.Characters.CommonAnimations.HitStanding")
	pMiguel.AddAnimation("EBScienceHitHardStanding", "Bridge.Characters.CommonAnimations.HitHardStanding")
	pMiguel.AddAnimation("EBScienceReactLeftStanding", "Bridge.Characters.CommonAnimations.ReactLeft");
	pMiguel.AddAnimation("EBScienceReactRightStanding", "Bridge.Characters.CommonAnimations.ReactRight");

	# Add common animations.
	AddCommonAnimations(pMiguel)

	# Miguel sits on the Sovereign bridge
	pMiguel.SetStanding(0)
	pMiguel.SetLocation("EBScience")
	pMiguel.AddPositionZoom("EBScience", 0.5)
	pMiguel.AddPositionZoom("EBScience1", 0.5)
	pMiguel.AddPositionZoom("EBScience2", 0.6)
#	kDebugObj.Print("Finished configuring Miguel")


###############################################################################
#	AddCommonAnimations()
#
#	Since we can only clear out all animations when switching bridges (how
#	would we know which not to clear?), we can't really setup animations common
#	to all bridge configurations as we might like.  Because of this we have a
#	routine to add common animations (most of which are randoms) that both
#	configurations will call
#
#	Args:	pMiguel	- our Character object
#
#	Return:	none
###############################################################################
def AddCommonAnimations(pMiguel):
	pMiguel.AddRandomAnimation("Bridge.Characters.SmallAnimations.SLookAroundConsoleDown", App.CharacterClass.SITTING_ONLY, 1, 1)

	#pMiguel.AddRandomAnimation("Bridge.Characters.CommonAnimations.WipingBrowLeft")
	#pMiguel.AddRandomAnimation("Bridge.Characters.CommonAnimations.WipingBrowRight")
	pMiguel.AddRandomAnimation("Bridge.Characters.CommonAnimations.TiltHeadLeft")
	pMiguel.AddRandomAnimation("Bridge.Characters.CommonAnimations.TiltHeadRight")
	pMiguel.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookLeft")
	pMiguel.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookRight")
	pMiguel.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookUp")
	pMiguel.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookDown")
	pMiguel.AddRandomAnimation("Bridge.Characters.CommonAnimations.Nod", App.CharacterClass.STANDING_ONLY)


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
	# Like a function pointer (GetFile() is the same as pDatabase.GetFilename())
	GetFile = pDatabase.GetFilename	# do this for horizontal space savings

	#
	# Build a list of sound to load
	#
	kSoundList =	[	"MiguelSir1",		# Click Response
						"MiguelSir2",
						"MiguelSir3",
						"MiguelSir4",
						"MiguelSir5",

						"MiguelYes1",		# Order Confirmation
						"MiguelYes2",
						"MiguelYes3",
						"MiguelYes4",

						# Scanning lines.
						"MiguelScan",
						"gs038",
						"gs039",
						"gs040",
						"gs041",

						# Launching a probe.
						"gs030",

						# Spontaneous shield callouts.
						"TargetFrontShieldFailed",
						"TargetFrontShieldDraining",
						"TargetRearShieldFailed",
						"TargetRearShieldDraining",
						"TargetLeftShieldFailed",
						"TargetLeftShieldDraining",
						"TargetRightShieldFailed",
						"TargetRightShieldDraining",
						"TargetTopShieldFailed",
						"TargetTopShieldDraining",
						"TargetBottomShieldFailed",
						"TargetBottomShieldDraining",

						# Spontaneous target system callouts..
						"TargetHull05",
						"TargetHull10",
						"TargetHull15",
						"TargetHull20",
						"TargetHull25",
						"TargetHull50",
						"TargetHull75",

						"TargetPhasersDisabled",
						"TargetShieldsDisabled",
						"TargetSensorsDisabled",
						"TargetTorpedoesDisabled",
						"TargetTractorDisabled",
						"TargetImpulseDisabled",
						"TargetWarpDisabled",

						"TargetPhasersDestroyed",
						"TargetShieldsDestroyed",
						"TargetSensorsDestroyed",
						"TargetTorpedoesDestroyed",
						"TargetTractorDestroyed",
						"TargetImpulseDestroyed",
						"TargetWarpDestroyed",
					]
	#
	# Loop through that list, loading each sound in the "BridgeGeneric" group
	#
	for i in range(len(kSoundList)):
		pGame.LoadDatabaseSoundInGroup(pDatabase, kSoundList[i], "BridgeGeneric")

	App.g_kLocalizationManager.Unload(pDatabase)
