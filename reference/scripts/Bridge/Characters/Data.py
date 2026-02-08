###############################################################################
#	Filename:	Data.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads Data, and configures animations.
#	
#	Created:	9/13/00 -	Bill Morrison
###############################################################################

import App
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create Data by building his character and placing him on the passed in set.
#	Create his menus as well.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating Data")

	if (pSet.GetObject("Data") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("Data")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadData/data_head.nif", None)
	pData = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", CharacterPaths.g_pcHeadNIFPath + "HeadData/data_head.nif")
	pData.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyMaleM/FedGold_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadData/data_head.tga")

	# Add the character to the set
	pSet.AddObjectToSet(pData, "Data")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pData)

	# Setup the character configuration
	pData.SetSize(App.CharacterClass.MEDIUM)
	pData.SetGender(App.CharacterClass.MALE)
	pData.SetRandomAnimationChance(.01)
	pData.SetBlinkChance(0.1)
	pData.SetCharacterName("Data")

	# Load Data's generic sounds
	LoadSounds()

	pData.SetDatabase("data/TGL/Data General.tgl")

	import Bridge.DataMenuHandlers
	Bridge.DataMenuHandlers.CreateMenus(pData)

	pData.AddFacialImage("Blink0", CharacterPaths.g_pcHeadTexPath + "HeadData/Data_blink1.tga")
	pData.AddFacialImage("Blink1", CharacterPaths.g_pcHeadTexPath + "HeadData/Data_blink2.tga")
	pData.AddFacialImage("Blink2", CharacterPaths.g_pcHeadTexPath + "HeadData/Data_eyes_close.tga")
	pData.SetBlinkStages(3)

	pData.AddFacialImage("SpeakA", CharacterPaths.g_pcHeadTexPath + "HeadData/Data_head_a.tga")
	pData.AddFacialImage("SpeakE", CharacterPaths.g_pcHeadTexPath + "HeadData/Data_head_e.tga")
	pData.AddFacialImage("SpeakU", CharacterPaths.g_pcHeadTexPath + "HeadData/Data_head_u.tga")
	pData.SetAnimatedSpeaking(1)

	import Guest
	Guest.ConfigureForGeneric(pData)

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/CharacterStatus.tgl")
	pData.SetStatus( pDatabase.GetString("Waiting") )
	App.g_kLocalizationManager.Unload(pDatabase)

#	kDebugObj.Print("Finished creating Data")
	return pData


###############################################################################
#	ConfigureForGalaxy()
#
#	Configure ourselves for the Galaxy bridge
#
#	Args:	pData	- our Character object
#
#	Return:	none
###############################################################################
def ConfigureForGalaxy(pData):
#	kDebugObj.Print("Configuring Data for the Galaxy bridge")

	# Clear out any old animations from another configuration
	pData.ClearAnimations()

	pData.AddAnimation("DBGuestBreathe", "Bridge.Characters.CommonAnimations.SeatedM")
	pData.AddAnimation("DBGuest1Breathe", "Bridge.Characters.CommonAnimations.Standing")
	pData.AddAnimation("DBGuest2Breathe", "Bridge.Characters.CommonAnimations.Standing")

	# Turn to various crew members
	pData.AddAnimation("DBGuestTurnC", "Bridge.Characters.MediumAnimations.TurnAtXTowardsCaptain")
	pData.AddAnimation("DBGuestBackC", "Bridge.Characters.CommonAnimations.SeatedM")
	pData.AddAnimation("DBGuestTurnH", "Bridge.Characters.MediumAnimations.DBXTalkH")
	pData.AddAnimation("DBGuestBackH", "Bridge.Characters.CommonAnimations.SeatedM")
	pData.AddAnimation("DBGuestTurnE", "Bridge.Characters.MediumAnimations.DBXTalkE")
	pData.AddAnimation("DBGuestBackE", "Bridge.Characters.CommonAnimations.SeatedM")
	pData.AddAnimation("DBGuestTurnS", "Bridge.Characters.MediumAnimations.DBXTalkS")
	pData.AddAnimation("DBGuestBackS", "Bridge.Characters.CommonAnimations.SeatedM")
	pData.AddAnimation("DBGuestTurnT", "Bridge.Characters.MediumAnimations.DBXTalkT")
	pData.AddAnimation("DBGuestBackT", "Bridge.Characters.CommonAnimations.SeatedM")

	# Add common animations.
	AddCommonAnimations(pData)

#	kDebugObj.Print("Finished configuring Data")


###############################################################################
#	ConfigureForSovereign()
#
#	Configure ourselves for the Sovereign bridge
#
#	Args:	pData	- our Character object
#
#	Return:	none
###############################################################################
def ConfigureForSovereign(pData):
#	kDebugObj.Print("Configuring Data for the Sovereign bridge")

	# Clear out any old animations from another configuration
	pData.ClearAnimations()

	pData.AddAnimation("EBGuestBreathe", "Bridge.Characters.CommonAnimations.SeatedM")
	pData.AddAnimation("EBGuest1Breathe", "Bridge.Characters.CommonAnimations.Standing")
	pData.AddAnimation("EBGuest2Breathe", "Bridge.Characters.CommonAnimations.Standing")

	# Register animation mappings
	pData.AddAnimation("SeatedEBGuest", "Bridge.Characters.CommonAnimations.SeatedM")
	pData.AddAnimation("StandingEBGuest1", "Bridge.Characters.CommonAnimations.Standing")
	pData.AddAnimation("EBL1MToX", "Bridge.Characters.MediumAnimations.EBMoveFromL1ToX")
	pData.AddAnimation("EBGuestToL1", "Bridge.Characters.MediumAnimations.EBMoveFromXToL1")
	pData.AddAnimation("EBGuestToX1", "Bridge.Characters.MediumAnimations.EBMoveFromXToX1")
	pData.AddAnimation("EBGuest1ToX", "Bridge.Characters.MediumAnimations.EBMoveFromX1ToX")
	pData.AddAnimation("EBL1MToX2", "Bridge.Characters.MediumAnimations.EBMoveFromL1ToX2")
	pData.AddAnimation("EBGuest2ToX", "Bridge.Characters.MediumAnimations.EBMoveFromX2ToX")
	pData.AddAnimation("EBGuestTurnCaptain", "Bridge.Characters.MediumAnimations.EBTurnAtXTowardsCaptain")
	pData.AddAnimation("EBGuest1TurnCaptain", "Bridge.Characters.MediumAnimations.EBTurnAtX1TowardsCaptain")
	pData.AddAnimation("EBGuestBackCaptain", "Bridge.Characters.CommonAnimations.SeatedM")
	pData.AddAnimation("EBGuest1BackCaptain", "Bridge.Characters.MediumAnimations.EBTurnBackAtX1FromCaptain")

	# Turn to various crew members
	pData.AddAnimation("EBGuestTurnC", "Bridge.Characters.MediumAnimations.EBXTalkC")
	pData.AddAnimation("EBGuestBackC", "Bridge.Characters.CommonAnimations.SeatedM")
	pData.AddAnimation("EBGuestTurnH", "Bridge.Characters.CommonAnimations.SeatedM")
	pData.AddAnimation("EBGuestBackH", "Bridge.Characters.CommonAnimations.SeatedM")
	pData.AddAnimation("EBGuestTurnE", "Bridge.Characters.MediumAnimations.EBXTalkE")
	pData.AddAnimation("EBGuestBackE", "Bridge.Characters.CommonAnimations.SeatedM")
	pData.AddAnimation("EBGuestTurnS", "Bridge.Characters.MediumAnimations.EBXTalkC")
	pData.AddAnimation("EBGuestBackS", "Bridge.Characters.CommonAnimations.SeatedM")
	pData.AddAnimation("EBGuestTurnT", "Bridge.Characters.CommonAnimations.SeatedM")
	pData.AddAnimation("EBGuestBackT", "Bridge.Characters.CommonAnimations.SeatedM")

	# Hit animations
	#pData.AddAnimation("EBGuestHit", "Bridge.Characters.MediumAnimations.XHit");
	#pData.AddAnimation("EBGuestHitHard", "Bridge.Characters.MediumAnimations.XHitHard");
	#pData.AddAnimation("EBGuestHitStanding", "Bridge.Characters.CommonAnimations.HitStanding");
	#pData.AddAnimation("EBGuestHitHardStanding", "Bridge.Characters.CommonAnimations.HitHardStanding");
	pData.AddAnimation("EBGuestReactLeft", "Bridge.Characters.CommonAnimations.ReactLeft");
	pData.AddAnimation("EBGuestReactRight", "Bridge.Characters.CommonAnimations.ReactRight");

	pData.AddAnimation("PushingButtons", "Bridge.Characters.MediumAnimations.EBXConsoleInteraction")
	pData.AddRandomAnimation("Bridge.Characters.MediumAnimations.EBXConsoleInteraction", App.CharacterClass.SITTING_ONLY)

	# Add common animations.
	AddCommonAnimations(pData)

	pData.SetLocation ("EBGuest")
#	kDebugObj.Print("Finished configuring Data")


###############################################################################
#	ConfigureForEngineering()
#
#	Configure ourselves for the Engineering partial set
#
#	Args:	pData	- our Character object
#
#	Return:	none
###############################################################################
def ConfigureForEngineering(pData):
#	kDebugObj.Print("Configuring Data for engineering")

	# Clear out any old animations from another configuration
	pData.ClearAnimations()

	# Register animation mappings
	import Guest
	Guest.ConfigureForGeneric(pData)

	AddCommonAnimations(pData)

	pData.SetLocation("SovereignEngSeated")

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
#	Args:	pData	- our Character object
#
#	Return:	none
###############################################################################
def AddCommonAnimations(pData):
	pData.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookLeft")
	pData.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookRight")
	pData.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookUp")
	pData.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookDown")
	pData.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookAroundConsoleDown")


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
	# Data has no generic bridge sounds at this time
	#
	pass
