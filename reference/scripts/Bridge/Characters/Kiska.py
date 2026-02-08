###############################################################################
#	Filename:	Kiska.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads Kiska Lomar, Helm, and configures animations
#	
#	Created:	3/28/00 -	Erik Novales
###############################################################################

import App
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create Kiska by building her character and placing her on the passed in set.
#	Create her menus as well.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating Kiska")

	if (pSet.GetObject("Helm") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("Helm")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyFemM/BodyFemM.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadKiska/kiska_head.nif", None)
	pKiska = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyFemM/BodyFemM.nif", CharacterPaths.g_pcHeadNIFPath + "HeadKiska/kiska_head.nif", 1)
	pKiska.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyFemS/FedFemGold_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadKiska/kiska_head.tga")

	pKiska.SetCharacterName("Kiska")

	# Add the character to the set
	pSet.AddObjectToSet(pKiska, "Helm")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pKiska)

	# Setup the character configuration
	pKiska.SetSize(App.CharacterClass.MEDIUM)
	pKiska.SetGender(App.CharacterClass.FEMALE)
	pKiska.SetStanding(0)
	pKiska.SetRandomAnimationChance(0.75)
	pKiska.SetBlinkChance(0.1)
	pKiska.SetDatabase("data/TGL/Bridge Crew General.tgl")

	# Load Helm officer generic sounds
	LoadSounds()

	pKiska.AddFacialImage("Blink0", CharacterPaths.g_pcHeadTexPath + "HeadKiska/Kiska_head_blink1.tga")
	pKiska.AddFacialImage("Blink1", CharacterPaths.g_pcHeadTexPath + "HeadKiska/Kiska_head_blink2.tga")
	pKiska.AddFacialImage("Blink2", CharacterPaths.g_pcHeadTexPath + "HeadKiska/Kiska_head_eyesclosed.tga")
	pKiska.SetBlinkStages(3)

	pKiska.AddFacialImage("SpeakA", CharacterPaths.g_pcHeadTexPath + "HeadKiska/Kiska_head_a.tga")
	pKiska.AddFacialImage("SpeakE", CharacterPaths.g_pcHeadTexPath + "HeadKiska/Kiska_head_e.tga")
	pKiska.AddFacialImage("SpeakU", CharacterPaths.g_pcHeadTexPath + "HeadKiska/Kiska_head_u.tga")
	pKiska.SetAnimatedSpeaking(1)

	pGame = App.Game_GetCurrentGame()
	pGame.LoadDatabaseSoundInGroup(pKiska.GetDatabase(), "KiskaNothingToAdd", "BridgeGeneric")

	pMenusDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTop = App.TopWindow_GetTopWindow()
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pKiska.SetMenu(pTacticalControlWindow.FindMenu(pMenusDatabase.GetString("Helm")))
	App.g_kLocalizationManager.Unload(pMenusDatabase)

#	kDebugObj.Print("Finished creating Kiska")
	return pKiska


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
	pKiska = App.CharacterClass_Cast(pSet.GetObject("Helm"))
	if (pKiska == None):
#		kDebugObj.Print("******* Helm officer not found *********")
		return

#	kDebugObj.Print("Attaching menu to Helm..")
	import Bridge.HelmCharacterHandlers
	Bridge.HelmCharacterHandlers.AttachMenuToHelm(pKiska)

	#
	# This is where code to set up responses based on the ships state
	# e.g. "Orbiting planet"
	#



###############################################################################
#	ConfigureForGalaxy()
#
#	Configure ourselves for the Galaxy bridge
#
#	Args:	pKiska	- our Character object
#
#	Return:	none
###############################################################################
def ConfigureForGalaxy(pKiska):
#	kDebugObj.Print("Configuring Kiska for the Galaxy bridge")

	# Clear out any old animations from another configuration
	pKiska.ClearAnimations()

	# Register animation mappings
	pKiska.AddAnimation("DBL1MToH", "Bridge.Characters.MediumAnimations.MoveFromL1ToH")
	pKiska.AddAnimation("DBHelmToL1", "Bridge.Characters.MediumAnimations.MoveFromHToL1")

	pKiska.AddAnimation("DBHelmTurnCaptain", "Bridge.Characters.MediumAnimations.TurnAtHTowardsCaptain")
	pKiska.AddAnimation("DBHelmBackCaptain", "Bridge.Characters.MediumAnimations.TurnBackAtHFromCaptain")

	pKiska.AddAnimation("DBHelmTurnC", "Bridge.Characters.MediumAnimations.DBHTalkC")
	pKiska.AddAnimation("DBHelmBackC", "Bridge.Characters.MediumAnimations.DBHTalkFinC")
	pKiska.AddAnimation("DBHelmTurnE", "Bridge.Characters.MediumAnimations.DBHTalkE")
	pKiska.AddAnimation("DBHelmBackE", "Bridge.Characters.MediumAnimations.DBHTalkFinE")
	pKiska.AddAnimation("DBHelmTurnS", "Bridge.Characters.MediumAnimations.DBHTalkS")
	pKiska.AddAnimation("DBHelmBackS", "Bridge.Characters.MediumAnimations.DBHTalkFinS")
	pKiska.AddAnimation("DBHelmTurnT", "Bridge.Characters.MediumAnimations.DBHTalkT")
	pKiska.AddAnimation("DBHelmBackT", "Bridge.Characters.MediumAnimations.DBHTalkFinT")

	pKiska.AddAnimation("DBHelmTurnX", "Bridge.Characters.MediumAnimations.DBHTalkX")
	pKiska.AddAnimation("DBHelmBackX", "Bridge.Characters.MediumAnimations.DBHTalkFinX")

	pKiska.AddAnimation("DBHelmGlanceCaptain", "Bridge.Characters.CommonAnimations.GlanceRight")
	pKiska.AddAnimation("DBHelmGlanceAwayCaptain", "Bridge.Characters.CommonAnimations.SeatedM")

	# Breathing
	pKiska.AddAnimation("DBHelmBreathe", "Bridge.Characters.CommonAnimations.SeatedM")

	# Interaction
	pKiska.AddRandomAnimation("Bridge.Characters.MediumAnimations.DBHConsoleInteraction", App.CharacterClass.SITTING_ONLY, 1, 1)

	# So the mission builders can force the call
	pKiska.AddAnimation("PushingButtons", "Bridge.Characters.MediumAnimations.DBHConsoleInteraction")

	# Hit animations
	pKiska.AddAnimation("DBHelmHit", "Bridge.Characters.MediumAnimations.HHit")
	pKiska.AddAnimation("DBHelmHitHard", "Bridge.Characters.MediumAnimations.HHitHard")
	pKiska.AddAnimation("DBHelmReactLeft", "Bridge.Characters.CommonAnimations.ReactLeft")
	pKiska.AddAnimation("DBHelmReactRight", "Bridge.Characters.CommonAnimations.ReactRight")

	# Add common animations.
	AddCommonAnimations(pKiska)

	pKiska.SetLocation("DBHelm")
	pKiska.AddPositionZoom("DBHelm", 0.45, "Helm")
	pKiska.SetLookAtAdj(2, 0, 53)
#	kDebugObj.Print("Finished configuring Kiska")
	

###############################################################################
#	ConfigureForSovereign()
#
#	Configure ourselves for the Sovereign bridge
#
#	Args:	pKiska	- our Character object
#
#	Return:	none
###############################################################################
def ConfigureForSovereign(pKiska):
#	kDebugObj.Print("Configuring Kiska for the Sovereign bridge")

	# Clear out any old animations from another configuration
	pKiska.ClearAnimations()

	# Register animation mappings
	pKiska.AddAnimation("EBL1MToH", "Bridge.Characters.MediumAnimations.EBMoveFromL1ToH")
	pKiska.AddAnimation("EBHelmToL1", "Bridge.Characters.MediumAnimations.EBMoveFromHToL1")
	pKiska.AddAnimation("EBHelmTurnCaptain", "Bridge.Characters.MediumAnimations.EBTurnAtHTowardsCaptain")
	pKiska.AddAnimation("EBHelmBackCaptain", "Bridge.Characters.MediumAnimations.EBTurnBackAtHFromCaptain")

	pKiska.AddAnimation("EBHelmTurnC", "Bridge.Characters.MediumAnimations.EBHTalkC")
	pKiska.AddAnimation("EBHelmBackC", "Bridge.Characters.MediumAnimations.EBHTalkFinC")
	pKiska.AddAnimation("EBHelmTurnE", "Bridge.Characters.MediumAnimations.EBHTalkE")
	pKiska.AddAnimation("EBHelmBackE", "Bridge.Characters.MediumAnimations.EBHTalkFinE")
	pKiska.AddAnimation("EBHelmTurnS", "Bridge.Characters.MediumAnimations.EBHTalkS")
	pKiska.AddAnimation("EBHelmBackS", "Bridge.Characters.MediumAnimations.EBHTalkFinS")
	pKiska.AddAnimation("EBHelmTurnT", "Bridge.Characters.MediumAnimations.EBHTalkT")
	pKiska.AddAnimation("EBHelmBackT", "Bridge.Characters.MediumAnimations.EBHTalkFinT")

	pKiska.AddAnimation("EBHelmTurnX", "Bridge.Characters.MediumAnimations.EBHTalkE")
	pKiska.AddAnimation("EBHelmBackX", "Bridge.Characters.MediumAnimations.EBHTalkFinE")

	pKiska.AddAnimation("EBHelmGlanceCaptain", "Bridge.Characters.CommonAnimations.GlanceRight")
	pKiska.AddAnimation("EBHelmGlanceAwayCaptain", "Bridge.Characters.CommonAnimations.SeatedM")

	# Breathing
	pKiska.AddAnimation("EBHelmBreathe", "Bridge.Characters.CommonAnimations.SeatedM")

	# Interaction
	pKiska.AddRandomAnimation("Bridge.Characters.MediumAnimations.EBHConsoleInteraction", App.CharacterClass.SITTING_ONLY, 25, 1)

	# So the mission builders can force the call
	pKiska.AddAnimation("PushingButtons", "Bridge.Characters.MediumAnimations.EBHConsoleInteraction")

	# Hit animations
	#pKiska.AddAnimation("EBHelmHit", "Bridge.Characters.MediumAnimations.HHit")
	#pKiska.AddAnimation("EBHelmHitHard", "Bridge.Characters.MediumAnimations.HHitHard")
	pKiska.AddAnimation("EBHelmReactLeft", "Bridge.Characters.CommonAnimations.ReactLeft")
	pKiska.AddAnimation("EBHelmReactRight", "Bridge.Characters.CommonAnimations.ReactRight")

	# Add common animations.
	AddCommonAnimations(pKiska)

	pKiska.SetLocation("EBHelm")
	pKiska.AddPositionZoom("EBHelm", 0.5, "Helm")
	pKiska.SetLookAtAdj(0, 0, 70)
#	kDebugObj.Print("Finished configuring Kiska")


###############################################################################
#	AddCommonAnimations()
#
#	Since we can only clear out all animations when switching bridges (how
#	would we know which not to clear?), we can't really setup animations common
#	to all bridge configurations as we might like.  Because of this we have a
#	routine to add common animations (most of which are randoms) that both
#	configurations will call
#
#	Args:	pKiska	- our Character object
#
#	Return:	none
###############################################################################
def AddCommonAnimations(pKiska):
	# Interaction with their environment
	pKiska.AddRandomAnimation("Bridge.Characters.MediumAnimations.HLookAroundConsoleDown", App.CharacterClass.SITTING_ONLY, 1, 1)

	# Just random stuff
	pKiska.AddRandomAnimation("Bridge.Characters.CommonAnimations.TiltHeadLeft")
	pKiska.AddRandomAnimation("Bridge.Characters.CommonAnimations.TiltHeadRight")
	pKiska.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookUp")
	pKiska.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookDown")

	# These look bad
	#pKiska.AddRandomAnimation("Bridge.Characters.CommonAnimations.WipingBrowLeft")
	#pKiska.AddRandomAnimation("Bridge.Characters.CommonAnimations.WipingBrowRight")

	# These force the arms up
	#pKiska.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookLeft")
	#pKiska.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookRight")

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
	lSoundList =	[	"KiskaSir1",	# Click Response
						"KiskaSir2",
						"KiskaSir3",
						"KiskaSir4",
						"KiskaSir5",
						
						"KiskaYes1",	# Order Confirmation
						"KiskaYes2",
						"KiskaYes3",
						"KiskaYes4",

						"gh075",	# Course laid in
						"gh081",	# Intercept course plotted

						"HailOpen1",
						"HailOpen2",
						"NotResponding1",
						"NotResponding2",
						"OnScreen",

						"CollisionAlert1",
						"CollisionAlert2",
						"CollisionAlert3",
						"CollisionAlert4",
						"CollisionAlert5",
						"CollisionAlert6",
						"CollisionAlert7",
						"CollisionAlert10",

						"IncomingMsg1",
						"IncomingMsg2",
						"IncomingMsg3",
						"IncomingMsg4",
						"IncomingMsg5",
						"IncomingMsg6",
					]
	#
	# Loop through that list, loading each sound in the "BridgeGeneric" group
	#
	for sLine in lSoundList:
		pGame.LoadDatabaseSoundInGroup(pDatabase, sLine, "BridgeGeneric")

	App.g_kLocalizationManager.Unload(pDatabase)
