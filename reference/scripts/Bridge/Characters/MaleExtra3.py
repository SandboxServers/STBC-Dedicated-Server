###############################################################################
#	Filename:	MaleExtra3.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads Ambassador MaleExtra3, and configures animations.
#	
#	Created:	10/03/00 -	CCarley
###############################################################################

import App
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create MaleExtra3 by building his character and placing him on the passed in set.
#	Create his menus as well.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating MaleExtra3")

	if (pSet.GetObject("MaleExtra3") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("MaleExtra3")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadData/Data_head.nif", None)
	pMaleExtra3 = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", CharacterPaths.g_pcHeadNIFPath + "HeadData/Data_head.nif")
	pMaleExtra3.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyMaleM/FedGold_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadData/Male_ensignC_head.tga")

	# Add the character to the set
	pSet.AddObjectToSet(pMaleExtra3, "MaleExtra3")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pMaleExtra3)

	# Setup the character configuration
	pMaleExtra3.SetSize(App.CharacterClass.MEDIUM)
	pMaleExtra3.SetGender(App.CharacterClass.MALE)
	pMaleExtra3.SetRandomAnimationChance(.75)
	pMaleExtra3.SetBlinkChance(0.1)
	pMaleExtra3.SetCharacterName("MaleExtra3")

	pMaleExtra3.SetHidden(1)

	# Load MaleExtra3's generic sounds
	LoadSounds()

	# Create MaleExtra3's menus
	#import MaleExtra3MenuHandlers
	#MaleExtra3MenuHandlers.CreateMenus(pMaleExtra3)

	pMaleExtra3.SetDatabase("data/TGL/Bridge Crew General.tgl")

	pGame = App.Game_GetCurrentGame()
	#pGame.LoadDatabaseSoundInGroup(pMaleExtra3.GetDatabase(), "MaleExtra3NothingToAdd", "BridgeGeneric")

#	kDebugObj.Print("Finished creating MaleExtra3")
	return pMaleExtra3

###############################################################################
#	ConfigureForGalaxy()
#
#	Configure ourselves for the Galaxy bridge
#
#	Args:	pMaleExtra3	- our Character object
#
#	Return:	none
###############################################################################
def ConfigureForGalaxy(pMaleExtra3):
#	kDebugObj.Print("Configuring MaleExtra3 for the Galaxy bridge")

	# Clear out any old animations from another configuration
	pMaleExtra3.ClearAnimations()

	#
	# *** CURRENTLY MaleExtra3 HAS NO GALAXY CLASS ANIMATIONS ***
	#

	# Add common animations.
	AddCommonAnimations(pMaleExtra3)

	pMaleExtra3.SetAsExtra(1)
	pMaleExtra3.SetHidden(1)

	pMaleExtra3.SetLocation("DBL1M")
#	kDebugObj.Print("Finished configuring MaleExtra3")


###############################################################################
#	ConfigureForSovereign()
#
#	Configure ourselves for the Sovereign bridge
#
#	Args:	pMaleExtra3	- our Character object
#
#	Return:	none
###############################################################################
def ConfigureForSovereign(pMaleExtra3):
#	kDebugObj.Print("Configuring MaleExtra3 for the Sovereign bridge")

	# Clear out any old animations from another configuration
	pMaleExtra3.ClearAnimations()

	# Register animation mappings
	pMaleExtra3.AddAnimation("EBL1MToG", "Bridge.Characters.MediumAnimations.EBL1ToG3")
	pMaleExtra3.AddAnimation("EBG3MToL", "Bridge.Characters.MediumAnimations.EBG3ToL1")
	pMaleExtra3.AddAnimation("StandingEBG3M", "Bridge.Characters.CommonAnimations.Standing")
	pMaleExtra3.SetStanding(1)

	# Hit animations
	pMaleExtra3.AddAnimation("EBG3MHitStanding", "Bridge.Characters.CommonAnimations.HitStanding")
	pMaleExtra3.AddAnimation("EBG3MHitHardStanding", "Bridge.Characters.CommonAnimations.HitHardStanding")
	pMaleExtra3.AddAnimation("EBG3MReactLeft", "Bridge.Characters.CommonAnimations.ReactLeft")
	pMaleExtra3.AddAnimation("EBG3MReactRight", "Bridge.Characters.CommonAnimations.ReactRight")
	pMaleExtra3.AddAnimation("EBG3MFly", "Bridge.Characters.CommonAnimations.Blast2")

	pMaleExtra3.SetAsExtra(1)
	pMaleExtra3.SetHidden(1)

	# Add common animations.
	AddCommonAnimations(pMaleExtra3)

	pMaleExtra3.SetLocation("EBL1M")
#	kDebugObj.Print("Finished configuring MaleExtra3")


###############################################################################
#	AddCommonAnimations()
#
#	Since we can only clear out all animations when switching bridges (how
#	would we know which not to clear?), we can't really setup animations common
#	to all bridge configurations as we might like.  Because of this we have a
#	routine to add common animations (most of which are randoms) that both
#	configurations will call
#
#	Args:	pMaleExtra3	- our Character object
#
#	Return:	none
###############################################################################
def AddCommonAnimations(pMaleExtra3):
	pMaleExtra3.AddRandomAnimation("Bridge.Characters.CommonAnimations.TiltHeadLeft")
	pMaleExtra3.AddRandomAnimation("Bridge.Characters.CommonAnimations.TiltHeadRight")
	pMaleExtra3.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookLeft")
	pMaleExtra3.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookRight")
	pMaleExtra3.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookUp")
	pMaleExtra3.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookDown")
	pMaleExtra3.AddRandomAnimation("Bridge.Characters.CommonAnimations.HitCommunicator")
	pMaleExtra3.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookAroundConsoleDown")
	pMaleExtra3.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookAroundConsoleUp")
	pMaleExtra3.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookAroundConsole")
	pMaleExtra3.AddRandomAnimation("Bridge.Characters.CommonAnimations.WallButtonPresses")
	pMaleExtra3.AddRandomAnimation("Bridge.Characters.CommonAnimations.WallSlides")


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
	# MaleExtra3 has no generic bridge sounds at this time
	#
	pass
