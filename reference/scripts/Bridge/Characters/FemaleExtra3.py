###############################################################################
#	Filename:	FemaleExtra3.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads Ambassador FemaleExtra3, and configures animations.
#	
#	Created:	10/03/00 -	CCarley
###############################################################################

import App
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create FemaleExtra3 by building his character and placing him on the passed in set.
#	Create his menus as well.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating FemaleExtra3")

	if (pSet.GetObject("FemaleExtra3") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("FemaleExtra3")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyFemM/BodyFemM.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadSaffi/saffi_head.nif", None)
	pFemaleExtra3 = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyFemM/BodyFemM.nif", CharacterPaths.g_pcHeadNIFPath + "HeadFem4/fem4_head.nif")
	pFemaleExtra3.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyFemS/FedFemGold_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadFem4/female_ensignC_head.tga")

	# Add the character to the set
	pSet.AddObjectToSet(pFemaleExtra3, "FemaleExtra3")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pFemaleExtra3)

	# Setup the character configuration
	pFemaleExtra3.SetSize(App.CharacterClass.MEDIUM)
	pFemaleExtra3.SetGender(App.CharacterClass.FEMALE)
	pFemaleExtra3.SetRandomAnimationChance(.75)
	pFemaleExtra3.SetBlinkChance(0.1)
	pFemaleExtra3.SetCharacterName("FemaleExtra3")

	pFemaleExtra3.SetHidden(1)

	# Load FemaleExtra3's generic sounds
	LoadSounds()

	# Create FemaleExtra3's menus
	#import FemaleExtra3MenuHandlers
	#FemaleExtra3MenuHandlers.CreateMenus(pFemaleExtra3)

	pFemaleExtra3.SetDatabase("data/TGL/Bridge Crew General.tgl")

	pFemaleExtra3.AddAnimation("Place", "Bridge.Characters.CommonAnimations.Standing")
	pFemaleExtra3.SetLocation("")

#	kDebugObj.Print("Finished creating FemaleExtra3")
	return pFemaleExtra3

###############################################################################
#	ConfigureForGalaxy()
#
#	Configure ourselves for the Galaxy bridge
#
#	Args:	pFemaleExtra3	- our Character object
#
#	Return:	none
###############################################################################
def ConfigureForGalaxy(pFemaleExtra3):
#	kDebugObj.Print("Configuring FemaleExtra3 for the Galaxy bridge")

	# Clear out any old animations from another configuration
	pFemaleExtra3.ClearAnimations()

	#
	# *** CURRENTLY FemaleExtra3 HAS NO GALAXY CLASS ANIMATIONS ***
	#

	# Add common animations.
	AddCommonAnimations(pFemaleExtra3)

	pFemaleExtra3.SetAsExtra(1)
	pFemaleExtra3.SetHidden(1)

	pFemaleExtra3.SetLocation("DBL1M")
#	kDebugObj.Print("Finished configuring FemaleExtra3")


###############################################################################
#	ConfigureForSovereign()
#
#	Configure ourselves for the Sovereign bridge
#
#	Args:	pFemaleExtra3	- our Character object
#
#	Return:	none
###############################################################################
def ConfigureForSovereign(pFemaleExtra3):
#	kDebugObj.Print("Configuring FemaleExtra3 for the Sovereign bridge")

	# Clear out any old animations from another configuration
	pFemaleExtra3.ClearAnimations()

	# Register animation mappings
	pFemaleExtra3.AddAnimation("EBL1MToG", "Bridge.Characters.MediumAnimations.EBL1ToG3")
	pFemaleExtra3.AddAnimation("EBG3MToL", "Bridge.Characters.MediumAnimations.EBG3ToL1")
	pFemaleExtra3.AddAnimation("StandingEBG3M", "Bridge.Characters.CommonAnimations.Standing")
	pFemaleExtra3.SetStanding(1)

	# Hit animations
	pFemaleExtra3.AddAnimation("EBG3MHitStanding", "Bridge.Characters.CommonAnimations.HitStanding")
	pFemaleExtra3.AddAnimation("EBG3MHitHardStanding", "Bridge.Characters.CommonAnimations.HitHardStanding")
	pFemaleExtra3.AddAnimation("EBG3MReactLeft", "Bridge.Characters.CommonAnimations.ReactLeft")
	pFemaleExtra3.AddAnimation("EBG3MReactRight", "Bridge.Characters.CommonAnimations.ReactRight")
	pFemaleExtra3.AddAnimation("EBG3MFly", "Bridge.Characters.CommonAnimations.Blast2")

	pFemaleExtra3.SetAsExtra(1)
	pFemaleExtra3.SetHidden(1)

	# Add common animations.
	AddCommonAnimations(pFemaleExtra3)

	pFemaleExtra3.SetLocation("EBL1M")
#	kDebugObj.Print("Finished configuring FemaleExtra3")


###############################################################################
#	AddCommonAnimations()
#
#	Since we can only clear out all animations when switching bridges (how
#	would we know which not to clear?), we can't really setup animations common
#	to all bridge configurations as we might like.  Because of this we have a
#	routine to add common animations (most of which are randoms) that both
#	configurations will call
#
#	Args:	pFemaleExtra3	- our Character object
#
#	Return:	none
###############################################################################
def AddCommonAnimations(pFemaleExtra3):
	pFemaleExtra3.AddRandomAnimation("Bridge.Characters.CommonAnimations.TiltHeadLeft")
	pFemaleExtra3.AddRandomAnimation("Bridge.Characters.CommonAnimations.TiltHeadRight")
	pFemaleExtra3.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookLeft")
	pFemaleExtra3.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookRight")
	pFemaleExtra3.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookUp")
	pFemaleExtra3.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookDown")
	pFemaleExtra3.AddRandomAnimation("Bridge.Characters.CommonAnimations.HitCommunicator")
	pFemaleExtra3.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookAroundConsoleDown")
	pFemaleExtra3.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookAroundConsoleUp")
	pFemaleExtra3.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookAroundConsole")
	pFemaleExtra3.AddRandomAnimation("Bridge.Characters.CommonAnimations.WallButtonPresses")
	pFemaleExtra3.AddRandomAnimation("Bridge.Characters.CommonAnimations.WallSlides")


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
	#
	# FemaleExtra3 has no generic bridge sounds at this time
	#
	pass
