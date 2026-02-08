###############################################################################
#	Filename:	FemaleExtra2.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads Ambassador FemaleExtra2, and configures animations.
#	
#	Created:	10/03/00 -	CCarley
###############################################################################

import App
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create FemaleExtra2 by building his character and placing him on the passed in set.
#	Create his menus as well.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating FemaleExtra2")

	if (pSet.GetObject("FemaleExtra2") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("FemaleExtra2")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyFemM/BodyFemM.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadLiu/liu_head.nif", None)
	pFemaleExtra2 = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyFemM/BodyFemM.nif", CharacterPaths.g_pcHeadNIFPath + "HeadLiu/liu_head.nif")

	pFemaleExtra2.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyFemS/FedFemGold_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadLiu/female_ensignA_head.tga")

	# Add the character to the set
	pSet.AddObjectToSet(pFemaleExtra2, "FemaleExtra2")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pFemaleExtra2)

	# Setup the character configuration
	pFemaleExtra2.SetSize(App.CharacterClass.MEDIUM)
	pFemaleExtra2.SetGender(App.CharacterClass.FEMALE)
	pFemaleExtra2.SetRandomAnimationChance(.75)
	pFemaleExtra2.SetBlinkChance(0.1)
	pFemaleExtra2.SetCharacterName("FemaleExtra2")

	pFemaleExtra2.SetHidden(1)

	# Load FemaleExtra2's generic sounds
	LoadSounds()

	# Create FemaleExtra2's menus
	#import FemaleExtra2MenuHandlers
	#FemaleExtra2MenuHandlers.CreateMenus(pFemaleExtra2)

	pFemaleExtra2.SetDatabase("data/TGL/Bridge Crew General.tgl")

	pFemaleExtra2.AddAnimation("Place", "Bridge.Characters.CommonAnimations.Standing")
	pFemaleExtra2.SetLocation("")

#	kDebugObj.Print("Finished creating FemaleExtra2")
	return pFemaleExtra2

###############################################################################
#	ConfigureForGalaxy()
#
#	Configure ourselves for the Galaxy bridge
#
#	Args:	pFemaleExtra2	- our Character object
#
#	Return:	none
###############################################################################
def ConfigureForGalaxy(pFemaleExtra2):
#	kDebugObj.Print("Configuring FemaleExtra2 for the Galaxy bridge")

	# Clear out any old animations from another configuration
	pFemaleExtra2.ClearAnimations()

	#
	# *** CURRENTLY FemaleExtra2 HAS NO GALAXY CLASS ANIMATIONS ***
	#

	# Add common animations.
	AddCommonAnimations(pFemaleExtra2)

	pFemaleExtra2.SetAsExtra(1)
	pFemaleExtra2.SetHidden(1)

	pFemaleExtra2.SetLocation("DBL2M")
#	kDebugObj.Print("Finished configuring FemaleExtra2")


###############################################################################
#	ConfigureForSovereign()
#
#	Configure ourselves for the Sovereign bridge
#
#	Args:	pFemaleExtra2	- our Character object
#
#	Return:	none
###############################################################################
def ConfigureForSovereign(pFemaleExtra2):
#	kDebugObj.Print("Configuring FemaleExtra2 for the Sovereign bridge")

	# Clear out any old animations from another configuration
	pFemaleExtra2.ClearAnimations()

	# Register animation mappings
	pFemaleExtra2.AddAnimation("EBL2MToG", "Bridge.Characters.MediumAnimations.EBL2ToG2")
	pFemaleExtra2.AddAnimation("EBG2MToL", "Bridge.Characters.MediumAnimations.EBG2ToL2")
	pFemaleExtra2.AddAnimation("StandingEBG2M", "Bridge.Characters.CommonAnimations.Standing")
	pFemaleExtra2.SetStanding(1)

	# Hit animations
	pFemaleExtra2.AddAnimation("EBG2MHitStanding", "Bridge.Characters.CommonAnimations.HitStanding")
	pFemaleExtra2.AddAnimation("EBG2MHitHardStanding", "Bridge.Characters.CommonAnimations.HitHardStanding")
	pFemaleExtra2.AddAnimation("EBG2MReactLeft", "Bridge.Characters.CommonAnimations.ReactLeft")
	pFemaleExtra2.AddAnimation("EBG2MReactRight", "Bridge.Characters.CommonAnimations.ReactRight")
	pFemaleExtra2.AddAnimation("EBG2MFly", "Bridge.Characters.CommonAnimations.Blast")

	pFemaleExtra2.SetAsExtra(1)
	pFemaleExtra2.SetHidden(1)

	# Add common animations.
	AddCommonAnimations(pFemaleExtra2)

	pFemaleExtra2.SetLocation("EBL2M")
#	kDebugObj.Print("Finished configuring FemaleExtra2")


###############################################################################
#	AddCommonAnimations()
#
#	Since we can only clear out all animations when switching bridges (how
#	would we know which not to clear?), we can't really setup animations common
#	to all bridge configurations as we might like.  Because of this we have a
#	routine to add common animations (most of which are randoms) that both
#	configurations will call
#
#	Args:	pFemaleExtra2	- our Character object
#
#	Return:	none
###############################################################################
def AddCommonAnimations(pFemaleExtra2):
	pFemaleExtra2.AddRandomAnimation("Bridge.Characters.CommonAnimations.TiltHeadLeft")
	pFemaleExtra2.AddRandomAnimation("Bridge.Characters.CommonAnimations.TiltHeadRight")
	pFemaleExtra2.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookLeft")
	pFemaleExtra2.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookRight")
	pFemaleExtra2.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookUp")
	pFemaleExtra2.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookDown")
	pFemaleExtra2.AddRandomAnimation("Bridge.Characters.CommonAnimations.HitCommunicator")
	pFemaleExtra2.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookAroundConsoleDown")
	pFemaleExtra2.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookAroundConsoleUp")
	pFemaleExtra2.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookAroundConsole")
	pFemaleExtra2.AddRandomAnimation("Bridge.Characters.CommonAnimations.WallButtonPresses")
	pFemaleExtra2.AddRandomAnimation("Bridge.Characters.CommonAnimations.WallSlides")


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
	# FemaleExtra2 has no generic bridge sounds at this time
	#
	pass
