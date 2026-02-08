###############################################################################
#	Filename:	FemaleExtra1.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads Ambassador FemaleExtra1, and configures animations.
#	
#	Created:	10/03/00 -	CCarley
###############################################################################

import App
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create FemaleExtra1 by building his character and placing him on the passed in set.
#	Create his menus as well.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating FemaleExtra1")

	if (pSet.GetObject("FemaleExtra1") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("FemaleExtra1")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyFemM/BodyFemM.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadFem3/fem3_head.nif", None)
	pFemaleExtra1 = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyFemM/BodyFemM.nif", CharacterPaths.g_pcHeadNIFPath + "HeadFem3/fem3_head.nif")
	pFemaleExtra1.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyFemS/FedFemGold_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadFem3/female_ensignB_head.tga")

	# Add the character to the set
	pSet.AddObjectToSet(pFemaleExtra1, "FemaleExtra1")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pFemaleExtra1)

	# Setup the character configuration
	pFemaleExtra1.SetSize(App.CharacterClass.MEDIUM)
	pFemaleExtra1.SetGender(App.CharacterClass.FEMALE)
	pFemaleExtra1.SetRandomAnimationChance(.75)
	pFemaleExtra1.SetBlinkChance(0.1)
	pFemaleExtra1.SetCharacterName("FemaleExtra1")

	pFemaleExtra1.SetHidden(1)

	# Load FemaleExtra1's generic sounds
	LoadSounds()

	# Create FemaleExtra1's menus
	#import FemaleExtra1MenuHandlers
	#FemaleExtra1MenuHandlers.CreateMenus(pFemaleExtra1)

	pFemaleExtra1.SetDatabase("data/TGL/Bridge Crew General.tgl")

	pFemaleExtra1.AddAnimation("Place", "Bridge.Characters.CommonAnimations.Standing")
	pFemaleExtra1.SetLocation("")

#	kDebugObj.Print("Finished creating FemaleExtra1")
	return pFemaleExtra1

###############################################################################
#	ConfigureForGalaxy()
#
#	Configure ourselves for the Galaxy bridge
#
#	Args:	pFemaleExtra1	- our Character object
#
#	Return:	none
###############################################################################
def ConfigureForGalaxy(pFemaleExtra1):
#	kDebugObj.Print("Configuring FemaleExtra1 for the Galaxy bridge")

	# Clear out any old animations from another configuration
	pFemaleExtra1.ClearAnimations()

	#
	# *** CURRENTLY FemaleExtra1 HAS NO GALAXY CLASS ANIMATIONS ***
	#

	# Add common animations.
	AddCommonAnimations(pFemaleExtra1)

	pFemaleExtra1.SetAsExtra(1)
	pFemaleExtra1.SetHidden(1)

	pFemaleExtra1.SetLocation("DBL2M")
#	kDebugObj.Print("Finished configuring FemaleExtra1")


###############################################################################
#	ConfigureForSovereign()
#
#	Configure ourselves for the Sovereign bridge
#
#	Args:	pFemaleExtra1	- our Character object
#
#	Return:	none
###############################################################################
def ConfigureForSovereign(pFemaleExtra1):
#	kDebugObj.Print("Configuring FemaleExtra1 for the Sovereign bridge")

	# Clear out any old animations from another configuration
	pFemaleExtra1.ClearAnimations()

	# Register animation mappings
	pFemaleExtra1.AddAnimation("EBL2MToG", "Bridge.Characters.MediumAnimations.EBL2ToG1")
	pFemaleExtra1.AddAnimation("EBG1MToL", "Bridge.Characters.MediumAnimations.EBG1ToL2")
	pFemaleExtra1.AddAnimation("StandingEBG1M", "Bridge.Characters.CommonAnimations.Standing")
	pFemaleExtra1.SetStanding(1)

	# Hit animations
	pFemaleExtra1.AddAnimation("EBG1MHitStanding", "Bridge.Characters.CommonAnimations.HitStanding")
	pFemaleExtra1.AddAnimation("EBG1MHitHardStanding", "Bridge.Characters.CommonAnimations.HitHardStanding")
	pFemaleExtra1.AddAnimation("EBG1MReactLeft", "Bridge.Characters.CommonAnimations.ReactLeft")
	pFemaleExtra1.AddAnimation("EBG1MReactRight", "Bridge.Characters.CommonAnimations.ReactRight")

	pFemaleExtra1.SetAsExtra(1)
	pFemaleExtra1.SetHidden(1)

	# Add common animations.
	AddCommonAnimations(pFemaleExtra1)

	pFemaleExtra1.SetLocation("EBL2M")
#	kDebugObj.Print("Finished configuring FemaleExtra1")


###############################################################################
#	AddCommonAnimations()
#
#	Since we can only clear out all animations when switching bridges (how
#	would we know which not to clear?), we can't really setup animations common
#	to all bridge configurations as we might like.  Because of this we have a
#	routine to add common animations (most of which are randoms) that both
#	configurations will call
#
#	Args:	pFemaleExtra1	- our Character object
#
#	Return:	none
###############################################################################
def AddCommonAnimations(pFemaleExtra1):
	pFemaleExtra1.AddRandomAnimation("Bridge.Characters.CommonAnimations.TiltHeadLeft")
	pFemaleExtra1.AddRandomAnimation("Bridge.Characters.CommonAnimations.TiltHeadRight")
	pFemaleExtra1.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookLeft")
	pFemaleExtra1.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookRight")
	pFemaleExtra1.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookUp")
	pFemaleExtra1.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookDown")
	pFemaleExtra1.AddRandomAnimation("Bridge.Characters.CommonAnimations.HitCommunicator")
	pFemaleExtra1.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookAroundConsoleDown")
	pFemaleExtra1.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookAroundConsoleUp")
	pFemaleExtra1.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookAroundConsole")
	pFemaleExtra1.AddRandomAnimation("Bridge.Characters.CommonAnimations.WallButtonPresses")
	pFemaleExtra1.AddRandomAnimation("Bridge.Characters.CommonAnimations.WallSlides")


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
	# FemaleExtra1 has no generic bridge sounds at this time
	#
	pass
