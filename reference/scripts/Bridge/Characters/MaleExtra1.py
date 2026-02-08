###############################################################################
#	Filename:	MaleExtra1.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads Ambassador MaleExtra1, and configures animations.
#	
#	Created:	10/03/00 -	CCarley
###############################################################################

import App
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create MaleExtra1 by building his character and placing him on the passed in set.
#	Create his menus as well.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating MaleExtra1")

	if (pSet.GetObject("MaleExtra1") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("MaleExtra1")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadPicard/Picard_head.nif", None)
	pMaleExtra1 = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", CharacterPaths.g_pcHeadNIFPath + "HeadPicard/Picard_head.nif")
	pMaleExtra1.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyMaleM/FedGold_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadPicard/Male_ensignA_head.tga")

	# Add the character to the set
	pSet.AddObjectToSet(pMaleExtra1, "MaleExtra1")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pMaleExtra1)

	# Setup the character configuration
	pMaleExtra1.SetSize(App.CharacterClass.MEDIUM)
	pMaleExtra1.SetGender(App.CharacterClass.MALE)
	pMaleExtra1.SetRandomAnimationChance(.75)
	pMaleExtra1.SetBlinkChance(0.1)
	pMaleExtra1.SetCharacterName("MaleExtra1")

	pMaleExtra1.SetHidden(1)

	# Load MaleExtra1's generic sounds
	LoadSounds()

	# Create MaleExtra1's menus
	#import MaleExtra1MenuHandlers
	#MaleExtra1MenuHandlers.CreateMenus(pMaleExtra1)

	pMaleExtra1.SetDatabase("data/TGL/Bridge Crew General.tgl")

	pGame = App.Game_GetCurrentGame()
	#pGame.LoadDatabaseSoundInGroup(pMaleExtra1.GetDatabase(), "MaleExtra1NothingToAdd", "BridgeGeneric")

#	kDebugObj.Print("Finished creating MaleExtra1")
	return pMaleExtra1

###############################################################################
#	ConfigureForGalaxy()
#
#	Configure ourselves for the Galaxy bridge
#
#	Args:	pMaleExtra1	- our Character object
#
#	Return:	none
###############################################################################
def ConfigureForGalaxy(pMaleExtra1):
#	kDebugObj.Print("Configuring MaleExtra1 for the Galaxy bridge")

	# Clear out any old animations from another configuration
	pMaleExtra1.ClearAnimations()

	#
	# *** CURRENTLY MaleExtra1 HAS NO GALAXY CLASS ANIMATIONS ***
	#

	# Add common animations.
	AddCommonAnimations(pMaleExtra1)

	pMaleExtra1.SetAsExtra(1)
	pMaleExtra1.SetHidden(1)

	pMaleExtra1.SetLocation("DBL2M")
#	kDebugObj.Print("Finished configuring MaleExtra1")


###############################################################################
#	ConfigureForSovereign()
#
#	Configure ourselves for the Sovereign bridge
#
#	Args:	pMaleExtra1	- our Character object
#
#	Return:	none
###############################################################################
def ConfigureForSovereign(pMaleExtra1):
#	kDebugObj.Print("Configuring MaleExtra1 for the Sovereign bridge")

	# Clear out any old animations from another configuration
	pMaleExtra1.ClearAnimations()

	# Register animation mappings
	pMaleExtra1.AddAnimation("EBL2MToG", "Bridge.Characters.MediumAnimations.EBL2ToG1")
	pMaleExtra1.AddAnimation("EBG1MToL", "Bridge.Characters.MediumAnimations.EBG1ToL2")
	pMaleExtra1.AddAnimation("StandingEBG1M", "Bridge.Characters.CommonAnimations.Standing")
	pMaleExtra1.SetStanding(1)

	# Hit animations
	pMaleExtra1.AddAnimation("EBG1MHitStanding", "Bridge.Characters.CommonAnimations.HitStanding")
	pMaleExtra1.AddAnimation("EBG1MHitHardStanding", "Bridge.Characters.CommonAnimations.HitHardStanding")
	pMaleExtra1.AddAnimation("EBG1MReactLeft", "Bridge.Characters.CommonAnimations.ReactLeft")
	pMaleExtra1.AddAnimation("EBG1MReactRight", "Bridge.Characters.CommonAnimations.ReactRight")

	pMaleExtra1.SetAsExtra(1)
	pMaleExtra1.SetHidden(1)

	# Add common animations.
	AddCommonAnimations(pMaleExtra1)

	pMaleExtra1.SetLocation("EBL2M")
#	kDebugObj.Print("Finished configuring MaleExtra1")


###############################################################################
#	AddCommonAnimations()
#
#	Since we can only clear out all animations when switching bridges (how
#	would we know which not to clear?), we can't really setup animations common
#	to all bridge configurations as we might like.  Because of this we have a
#	routine to add common animations (most of which are randoms) that both
#	configurations will call
#
#	Args:	pMaleExtra1	- our Character object
#
#	Return:	none
###############################################################################
def AddCommonAnimations(pMaleExtra1):
	pMaleExtra1.AddRandomAnimation("Bridge.Characters.CommonAnimations.TiltHeadLeft")
	pMaleExtra1.AddRandomAnimation("Bridge.Characters.CommonAnimations.TiltHeadRight")
	pMaleExtra1.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookLeft")
	pMaleExtra1.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookRight")
	pMaleExtra1.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookUp")
	pMaleExtra1.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookDown")
	pMaleExtra1.AddRandomAnimation("Bridge.Characters.CommonAnimations.HitCommunicator")
	pMaleExtra1.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookAroundConsoleDown")
	pMaleExtra1.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookAroundConsoleUp")
	pMaleExtra1.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookAroundConsole")
	pMaleExtra1.AddRandomAnimation("Bridge.Characters.CommonAnimations.WallButtonPresses")
	pMaleExtra1.AddRandomAnimation("Bridge.Characters.CommonAnimations.WallSlides")

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
	# MaleExtra1 has no generic bridge sounds at this time
	#
	pass
