###############################################################################
#	Filename:	MaleExtra2.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads Ambassador MaleExtra2, and configures animations.
#	
#	Created:	10/03/00 -	CCarley
###############################################################################

import App
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create MaleExtra2 by building his character and placing him on the passed in set.
#	Create his menus as well.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating MaleExtra2")

	if (pSet.GetObject("MaleExtra2") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("MaleExtra2")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadMiguel/Miguel_head.nif", None)
	pMaleExtra2 = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", CharacterPaths.g_pcHeadNIFPath + "HeadMiguel/Miguel_head.nif")
	pMaleExtra2.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyMaleM/FedGold_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Male_ensignB_head.tga")

	# Add the character to the set
	pSet.AddObjectToSet(pMaleExtra2, "MaleExtra2")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pMaleExtra2)

	# Setup the character configuration
	pMaleExtra2.SetSize(App.CharacterClass.MEDIUM)
	pMaleExtra2.SetGender(App.CharacterClass.MALE)
	pMaleExtra2.SetRandomAnimationChance(.75)
	pMaleExtra2.SetBlinkChance(0.1)
	pMaleExtra2.SetCharacterName("MaleExtra2")

	pMaleExtra2.SetHidden(1)

	# Load MaleExtra2's generic sounds
	LoadSounds()

	# Create MaleExtra2's menus
	#import MaleExtra2MenuHandlers
	#MaleExtra2MenuHandlers.CreateMenus(pMaleExtra2)

	pMaleExtra2.SetDatabase("data/TGL/Bridge Crew General.tgl")

	pGame = App.Game_GetCurrentGame()
	#pGame.LoadDatabaseSoundInGroup(pMaleExtra2.GetDatabase(), "MaleExtra2NothingToAdd", "BridgeGeneric")

#	kDebugObj.Print("Finished creating MaleExtra2")
	return pMaleExtra2

###############################################################################
#	ConfigureForGalaxy()
#
#	Configure ourselves for the Galaxy bridge
#
#	Args:	pMaleExtra2	- our Character object
#
#	Return:	none
###############################################################################
def ConfigureForGalaxy(pMaleExtra2):
#	kDebugObj.Print("Configuring MaleExtra2 for the Galaxy bridge")

	# Clear out any old animations from another configuration
	pMaleExtra2.ClearAnimations()

	#
	# *** CURRENTLY MaleExtra2 HAS NO GALAXY CLASS ANIMATIONS ***
	#

	# Add common animations.
	AddCommonAnimations(pMaleExtra2)

	pMaleExtra2.SetAsExtra(1)
	pMaleExtra2.SetHidden(1)

	pMaleExtra2.SetLocation("DBL2M")
#	kDebugObj.Print("Finished configuring MaleExtra2")


###############################################################################
#	ConfigureForSovereign()
#
#	Configure ourselves for the Sovereign bridge
#
#	Args:	pMaleExtra2	- our Character object
#
#	Return:	none
###############################################################################
def ConfigureForSovereign(pMaleExtra2):
#	kDebugObj.Print("Configuring MaleExtra2 for the Sovereign bridge")

	# Clear out any old animations from another configuration
	pMaleExtra2.ClearAnimations()

	# Register animation mappings
	pMaleExtra2.AddAnimation("EBL2MToG", "Bridge.Characters.MediumAnimations.EBL2ToG2")
	pMaleExtra2.AddAnimation("EBG2MToL", "Bridge.Characters.MediumAnimations.EBG2ToL2")
	pMaleExtra2.AddAnimation("StandingEBG2M", "Bridge.Characters.CommonAnimations.Standing")
	pMaleExtra2.SetStanding(1)

	# Hit animations
	pMaleExtra2.AddAnimation("EBG2MHitStanding", "Bridge.Characters.CommonAnimations.HitStanding")
	pMaleExtra2.AddAnimation("EBG2MHitHardStanding", "Bridge.Characters.CommonAnimations.HitHardStanding")
	pMaleExtra2.AddAnimation("EBG2MReactLeft", "Bridge.Characters.CommonAnimations.ReactLeft")
	pMaleExtra2.AddAnimation("EBG2MReactRight", "Bridge.Characters.CommonAnimations.ReactRight")
	pMaleExtra2.AddAnimation("EBG2MFly", "Bridge.Characters.CommonAnimations.Blast")

	pMaleExtra2.SetAsExtra(1)
	pMaleExtra2.SetHidden(1)

	# Add common animations.
	AddCommonAnimations(pMaleExtra2)

	pMaleExtra2.SetLocation("EBL2M")
#	kDebugObj.Print("Finished configuring MaleExtra2")


###############################################################################
#	AddCommonAnimations()
#
#	Since we can only clear out all animations when switching bridges (how
#	would we know which not to clear?), we can't really setup animations common
#	to all bridge configurations as we might like.  Because of this we have a
#	routine to add common animations (most of which are randoms) that both
#	configurations will call
#
#	Args:	pMaleExtra2	- our Character object
#
#	Return:	none
###############################################################################
def AddCommonAnimations(pMaleExtra2):
	pMaleExtra2.AddRandomAnimation("Bridge.Characters.CommonAnimations.TiltHeadLeft")
	pMaleExtra2.AddRandomAnimation("Bridge.Characters.CommonAnimations.TiltHeadRight")
	pMaleExtra2.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookLeft")
	pMaleExtra2.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookRight")
	pMaleExtra2.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookUp")
	pMaleExtra2.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookDown")
	pMaleExtra2.AddRandomAnimation("Bridge.Characters.CommonAnimations.HitCommunicator")
	pMaleExtra2.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookAroundConsoleDown")
	pMaleExtra2.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookAroundConsoleUp")
	pMaleExtra2.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookAroundConsole")
	pMaleExtra2.AddRandomAnimation("Bridge.Characters.CommonAnimations.WallButtonPresses")
	pMaleExtra2.AddRandomAnimation("Bridge.Characters.CommonAnimations.WallSlides")


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
	# MaleExtra2 has no generic bridge sounds at this time
	#
	pass
