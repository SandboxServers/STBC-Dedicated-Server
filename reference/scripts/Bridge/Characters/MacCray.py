###############################################################################
#	Filename:	MacCray.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads Captain MacCray, and configures animations
#	
#	Created:	7/25/00 -	Colin Carley
###############################################################################

import App
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create MacCray by building his character and placing him on the passed in set.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating MacCray")

	if (pSet.GetObject("MacCray") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("MacCray")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadMiguel/miguel_head.nif", None)
	pMacCray = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", CharacterPaths.g_pcHeadNIFPath + "HeadMiguel/miguel_head.nif")
	pMacCray.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyMaleM/FedRed_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/mccray_head.tga")

	# Add the character to the set
	pSet.AddObjectToSet(pMacCray, "MacCray")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pMacCray)
	
	# Setup the character configuration
	pMacCray.SetSize(App.CharacterClass.MEDIUM)
	pMacCray.SetGender(App.CharacterClass.MALE)
	pMacCray.SetStanding(1)
	pMacCray.SetRandomAnimationChance(.01)
	pMacCray.SetCharacterName("MacCray")

	pMacCray.AddFacialImage("Blink0", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/McCray_head_blink1.tga")
	pMacCray.AddFacialImage("Blink1", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/McCray_head_blink2.tga")
	pMacCray.AddFacialImage("Blink2", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/McCray_head_eyesclosed.tga")
	pMacCray.SetBlinkStages(3)

	pMacCray.AddFacialImage("SpeakA", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/McCray_head_a.tga")
	pMacCray.AddFacialImage("SpeakE", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/McCray_head_e.tga")
	pMacCray.AddFacialImage("SpeakU", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/McCray_head_u.tga")
	pMacCray.SetAnimatedSpeaking(1)

	# Configure for the Generic bridge
	import Guest
	Guest.ConfigureForGeneric(pMacCray)

	pMacCray.SetLocation("SovereignSeated")
#	kDebugObj.Print("Finished creating Captain MacCray")
	return pMacCray

###############################################################################
#	ConfigureForSovereign()
#
#	Configure ourselves for the Sovereign bridge
#
#	Args:	pMacCray	- our Character object
#
#	Return:	none
###############################################################################
def ConfigureForSovereign(pMacCray):
#	kDebugObj.Print("Configuring Data for the Sovereign bridge")

	# Clear out any old animations from another configuration
	pMacCray.ClearAnimations()

	# Register animation mappings
	pMacCray.AddAnimation("PlaceX", "Bridge.Characters.MediumAnimations.EBPlaceAtX")
	pMacCray.AddAnimation("PlaceL1", "Bridge.Characters.MediumAnimations.EBPlaceAtL1")
	pMacCray.AddAnimation("SeatedX", "Bridge.Characters.CommonAnimations.SeatedM")
	pMacCray.AddAnimation("StandingX1", "Bridge.Characters.CommonAnimations.Standing")
	pMacCray.AddAnimation("L1ToX", "Bridge.Characters.MediumAnimations.EBMoveFromL1ToX")
	pMacCray.AddAnimation("L1ToX2", "Bridge.Characters.MediumAnimations.EBMoveFromL1ToX2")
	pMacCray.AddAnimation("XToL1", "Bridge.Characters.MediumAnimations.EBMoveFromXToL1")
	pMacCray.AddAnimation("XToX1", "Bridge.Characters.MediumAnimations.EBMoveFromXToX1")
	pMacCray.AddAnimation("X1ToX", "Bridge.Characters.MediumAnimations.EBMoveFromX1ToX")
	pMacCray.AddAnimation("X2ToX", "Bridge.Characters.MediumAnimations.EBMoveFromX2ToX")
	pMacCray.AddAnimation("XTurnCaptain", "Bridge.Characters.MediumAnimations.EBTurnAtXTowardsCaptain")
	pMacCray.AddAnimation("X1TurnCaptain", "Bridge.Characters.MediumAnimations.EBTurnAtX1TowardsCaptain")
	pMacCray.AddAnimation("XBackCaptain", "Bridge.Characters.CommonAnimations.Standing")#SeatedM")
	pMacCray.AddAnimation("X1BackCaptain", "Bridge.Characters.MediumAnimations.EBTurnBackAtX1FromCaptain")

	# Breathe animations
	pMacCray.AddAnimation("XBreathe", "Bridge.Characters.CommonAnimations.SeatedM")
	pMacCray.AddAnimation("X1Breathe", "Bridge.Characters.CommonAnimations.Standing")
	pMacCray.AddAnimation("XBreatheTurned", "Bridge.Characters.CommonAnimations.BreathingTurned")
	pMacCray.AddAnimation("X1BreatheTurned", "Bridge.Characters.CommonAnimations.BreathingTurned")

	# Hit animations
	pMacCray.AddAnimation("XHit", "Bridge.Characters.MediumAnimations.XHit");
	pMacCray.AddAnimation("XHitHard", "Bridge.Characters.MediumAnimations.XHitHard");
	pMacCray.AddAnimation("XHitStanding", "Bridge.Characters.CommonAnimations.HitStanding");
	pMacCray.AddAnimation("XHitHardStanding", "Bridge.Characters.CommonAnimations.HitHardStanding");
	pMacCray.AddAnimation("XReactLeft", "Bridge.Characters.CommonAnimations.ReactLeft");
	pMacCray.AddAnimation("XReactRight", "Bridge.Characters.CommonAnimations.ReactRight");

	# Add common animations.
	AddCommonAnimations(pMacCray)

	pMacCray.SetLocation("EBL1M")
#	kDebugObj.Print("Finished configuring Data")


###############################################################################
#	AddCommonAnimations()
#
#	Since we can only clear out all animations when switching bridges (how
#	would we know which not to clear?), we can't really setup animations common
#	to all bridge configurations as we might like.  Because of this we have a
#	routine to add common animations (most of which are randoms) that both
#	configurations will call
#
#	Args:	pMacCray	- our Character object
#
#	Return:	none
###############################################################################
def AddCommonAnimations(pMacCray):
	pMacCray.AddRandomAnimation("Bridge.Characters.CommonAnimations.TiltHeadLeft")
	pMacCray.AddRandomAnimation("Bridge.Characters.CommonAnimations.TiltHeadRight")
	pMacCray.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookLeft")
	pMacCray.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookRight")
	pMacCray.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookUp")
	pMacCray.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookDown")
	pMacCray.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookAroundConsoleDown")


