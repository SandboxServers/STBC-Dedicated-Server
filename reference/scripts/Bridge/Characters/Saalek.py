###############################################################################
#	Filename:	Saalek.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads Ambassador Saalek, and configures animations.
#	
#	Created:	9/13/00 -	Bill Morrison
###############################################################################

import App
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create Saalek by building his character and placing him on the passed in set.
#	Create his menus as well.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating Saalek")

	if (pSet.GetObject("Saalek") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("Saalek")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadRomulan/romulan_head.nif", None)
	pSaalek = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", CharacterPaths.g_pcHeadNIFPath + "HeadRomulan/romulan_head.nif")
	pSaalek.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyMaleM/FedCivilian_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadRomulan/saalek_head.tga")

	# Add the character to the set
	pSet.AddObjectToSet(pSaalek, "Saalek")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pSaalek)

	# Setup the character configuration
	pSaalek.SetSize(App.CharacterClass.MEDIUM)
	pSaalek.SetGender(App.CharacterClass.MALE)
	pSaalek.SetRandomAnimationChance(.01)
	pSaalek.SetBlinkChance(0.1)
	pSaalek.SetCharacterName("Saalek")

	pSaalek.AddFacialImage("Blink0", CharacterPaths.g_pcHeadTexPath + "HeadRomulan/Saalek_head_blink1.tga")
	pSaalek.AddFacialImage("Blink1", CharacterPaths.g_pcHeadTexPath + "HeadRomulan/Saalek_head_blink2.tga")
	pSaalek.AddFacialImage("Blink2", CharacterPaths.g_pcHeadTexPath + "HeadRomulan/Saalek_head_eyesclosed.tga")
	pSaalek.SetBlinkStages(3)

	pSaalek.AddFacialImage("SpeakA", CharacterPaths.g_pcHeadTexPath + "HeadRomulan/Saalek_head_a.tga")
	pSaalek.AddFacialImage("SpeakE", CharacterPaths.g_pcHeadTexPath + "HeadRomulan/Saalek_head_e.tga")
	pSaalek.AddFacialImage("SpeakU", CharacterPaths.g_pcHeadTexPath + "HeadRomulan/Saalek_head_u.tga")
	pSaalek.SetAnimatedSpeaking(1)

	import Guest
	Guest.ConfigureForGeneric(pSaalek)

	pSaalek.SetDatabase("data/TGL/Saalek General.tgl")

	# Create Saalek's menus *** HE DOESN'T HAVE ANY YET ***
	import Bridge.SaalekMenuHandlers
	Bridge.SaalekMenuHandlers.CreateMenus(pSaalek)

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/CharacterStatus.tgl")
	pSaalek.SetStatus( pDatabase.GetString("Waiting") )
	App.g_kLocalizationManager.Unload(pDatabase)

#	kDebugObj.Print("Finished creating Saalek")
	return pSaalek

###############################################################################
#	ConfigureForGalaxy()
#
#	Configure ourselves for the Galaxy bridge
#
#	Args:	pSaalek	- our Character object
#
#	Return:	none
###############################################################################
def ConfigureForGalaxy(pSaalek):
#	kDebugObj.Print("Configuring Saalek for the Galaxy bridge")

	# Clear out any old animations from another configuration
	pSaalek.ClearAnimations()

	pSaalek.AddAnimation("DBGuestBreathe", "Bridge.Characters.CommonAnimations.SeatedM")
	pSaalek.AddAnimation("DBGuest1Breathe", "Bridge.Characters.CommonAnimations.Standing")
	pSaalek.AddAnimation("DBGuest2Breathe", "Bridge.Characters.CommonAnimations.Standing")

	# Turn to various crew members
	pSaalek.AddAnimation("DBGuestTurnC", "Bridge.Characters.MediumAnimations.TurnAtXTowardsCaptain")
	pSaalek.AddAnimation("DBGuestBackC", "Bridge.Characters.CommonAnimations.SeatedM")
	pSaalek.AddAnimation("DBGuestTurnH", "Bridge.Characters.MediumAnimations.DBXTalkH")
	pSaalek.AddAnimation("DBGuestBackH", "Bridge.Characters.CommonAnimations.SeatedM")
	pSaalek.AddAnimation("DBGuestTurnE", "Bridge.Characters.MediumAnimations.DBXTalkE")
	pSaalek.AddAnimation("DBGuestBackE", "Bridge.Characters.CommonAnimations.SeatedM")
	pSaalek.AddAnimation("DBGuestTurnS", "Bridge.Characters.MediumAnimations.DBXTalkS")
	pSaalek.AddAnimation("DBGuestBackS", "Bridge.Characters.CommonAnimations.SeatedM")
	pSaalek.AddAnimation("DBGuestTurnT", "Bridge.Characters.MediumAnimations.DBXTalkT")
	pSaalek.AddAnimation("DBGuestBackT", "Bridge.Characters.CommonAnimations.SeatedM")

	# Add common animations.
	AddCommonAnimations(pSaalek)

#	kDebugObj.Print("Finished configuring Saalek")


###############################################################################
#	ConfigureForSovereign()
#
#	Configure ourselves for the Sovereign bridge
#
#	Args:	pSaalek	- our Character object
#
#	Return:	none
###############################################################################
def ConfigureForSovereign(pSaalek):
#	kDebugObj.Print("Configuring Saalek for the Sovereign bridge")

	# Clear out any old animations from another configuration
	pSaalek.ClearAnimations()

	pSaalek.AddAnimation("EBGuestBreathe", "Bridge.Characters.CommonAnimations.SeatedM")
	pSaalek.AddAnimation("EBGuest1Breathe", "Bridge.Characters.CommonAnimations.Standing")
	pSaalek.AddAnimation("EBGuest2Breathe", "Bridge.Characters.CommonAnimations.Standing")

	# Register animation mappings
	pSaalek.AddAnimation("SeatedEBGuest", "Bridge.Characters.CommonAnimations.SeatedM")
	pSaalek.AddAnimation("StandingEBGuest1", "Bridge.Characters.CommonAnimations.Standing")
	pSaalek.AddAnimation("EBL1MToX", "Bridge.Characters.MediumAnimations.EBMoveFromL1ToX")
	pSaalek.AddAnimation("EBGuestToL1", "Bridge.Characters.MediumAnimations.EBMoveFromXToL1")
	pSaalek.AddAnimation("EBGuestToX1", "Bridge.Characters.MediumAnimations.EBMoveFromXToX1")
	pSaalek.AddAnimation("EBGuest1ToX", "Bridge.Characters.MediumAnimations.EBMoveFromX1ToX")
	pSaalek.AddAnimation("EBL1MToX2", "Bridge.Characters.MediumAnimations.EBMoveFromL1ToX2")
	pSaalek.AddAnimation("EBGuest2ToX", "Bridge.Characters.MediumAnimations.EBMoveFromX2ToX")
	pSaalek.AddAnimation("EBGuestTurnCaptain", "Bridge.Characters.MediumAnimations.EBTurnAtXTowardsCaptain")
	pSaalek.AddAnimation("EBGuest1TurnCaptain", "Bridge.Characters.MediumAnimations.EBTurnAtX1TowardsCaptain")
	pSaalek.AddAnimation("EBGuestBackCaptain", "Bridge.Characters.CommonAnimations.SeatedM")
	pSaalek.AddAnimation("EBGuest1BackCaptain", "Bridge.Characters.MediumAnimations.EBTurnBackAtX1FromCaptain")

	# Turn to various crew members
	pSaalek.AddAnimation("EBGuestTurnC", "Bridge.Characters.MediumAnimations.EBXTalkC")
	pSaalek.AddAnimation("EBGuestBackC", "Bridge.Characters.CommonAnimations.SeatedM")
	pSaalek.AddAnimation("EBGuestTurnH", "Bridge.Characters.CommonAnimations.SeatedM")
	pSaalek.AddAnimation("EBGuestBackH", "Bridge.Characters.CommonAnimations.SeatedM")
	pSaalek.AddAnimation("EBGuestTurnE", "Bridge.Characters.MediumAnimations.EBXTalkE")
	pSaalek.AddAnimation("EBGuestBackE", "Bridge.Characters.CommonAnimations.SeatedM")
	pSaalek.AddAnimation("EBGuestTurnS", "Bridge.Characters.MediumAnimations.EBXTalkC")
	pSaalek.AddAnimation("EBGuestBackS", "Bridge.Characters.CommonAnimations.SeatedM")
	pSaalek.AddAnimation("EBGuestTurnT", "Bridge.Characters.CommonAnimations.SeatedM")
	pSaalek.AddAnimation("EBGuestBackT", "Bridge.Characters.CommonAnimations.SeatedM")

	# Hit animations
	#pSaalek.AddAnimation("EBGuestHit", "Bridge.Characters.MediumAnimations.XHit");
	#pSaalek.AddAnimation("EBGuestHitHard", "Bridge.Characters.MediumAnimations.XHitHard");
	#pSaalek.AddAnimation("EBGuestHitStanding", "Bridge.Characters.CommonAnimations.HitStanding");
	#pSaalek.AddAnimation("EBGuestHitHardStanding", "Bridge.Characters.CommonAnimations.HitHardStanding");
	pSaalek.AddAnimation("EBGuestReactLeft", "Bridge.Characters.CommonAnimations.ReactLeft");
	pSaalek.AddAnimation("EBGuestReactRight", "Bridge.Characters.CommonAnimations.ReactRight");

	pSaalek.AddAnimation("PushingButtons", "Bridge.Characters.MediumAnimations.EBXConsoleInteraction")
	pSaalek.AddRandomAnimation("Bridge.Characters.MediumAnimations.EBXConsoleInteraction", App.CharacterClass.SITTING_ONLY)

	# Add common animations.
	AddCommonAnimations(pSaalek)

	pSaalek.SetLocation("EBGuest")
#	kDebugObj.Print("Finished configuring Saalek")


###############################################################################
#	AddCommonAnimations()
#
#	Since we can only clear out all animations when switching bridges (how
#	would we know which not to clear?), we can't really setup animations common
#	to all bridge configurations as we might like.  Because of this we have a
#	routine to add common animations (most of which are randoms) that both
#	configurations will call
#
#	Args:	pSaalek	- our Character object
#
#	Return:	none
###############################################################################
def AddCommonAnimations(pSaalek):
	pSaalek.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookLeft")
	pSaalek.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookRight")
	pSaalek.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookUp")
	pSaalek.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookDown")
	pSaalek.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookAroundConsoleDown")

