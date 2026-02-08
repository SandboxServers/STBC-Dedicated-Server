###############################################################################
#	Filename:	Korbus.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads Korbus, and sets up meta animations.
#	
#	Created:	9/13/00 -	Matthew Kagle
###############################################################################

import App
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create Korbus by building his character and placing him on the passed in set.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating Admiral Korbus")

	if (pSet.GetObject("Korbus") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("Korbus")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyKlingon/BodyKlingon.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadKlingon/klingon_head.nif", None)
	pKorbus = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyKlingon/BodyKlingon.nif", CharacterPaths.g_pcHeadNIFPath + "HeadKlingon/klingon_head.nif")
	pKorbus.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyKlingon/Klingon_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadKlingon/korbus_head.tga")

	# Add the character to the set
	pSet.AddObjectToSet(pKorbus, "Korbus")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pKorbus)
	
	# Setup the character configuration
	pKorbus.SetSize(App.CharacterClass.MEDIUM)
	pKorbus.SetGender(App.CharacterClass.MALE)
	pKorbus.SetStanding(1)
	pKorbus.SetRandomAnimationChance(.01)
	pKorbus.SetBlinkChance(.1)

	pKorbus.AddFacialImage("Blink0", CharacterPaths.g_pcHeadTexPath + "HeadKlingon/Korbus_head_blink1.tga")
	pKorbus.AddFacialImage("Blink1", CharacterPaths.g_pcHeadTexPath + "HeadKlingon/Korbus_head_blink2.tga")
	pKorbus.AddFacialImage("Blink2", CharacterPaths.g_pcHeadTexPath + "HeadKlingon/Korbus_head_eyesclosed.tga")
	pKorbus.SetBlinkStages(3)

	pKorbus.AddFacialImage("SpeakA", CharacterPaths.g_pcHeadTexPath + "HeadKlingon/Korbus_head_a.tga")
	pKorbus.AddFacialImage("SpeakE", CharacterPaths.g_pcHeadTexPath + "HeadKlingon/Korbus_head_e.tga")
	pKorbus.AddFacialImage("SpeakU", CharacterPaths.g_pcHeadTexPath + "HeadKlingon/Korbus_head_u.tga")
	pKorbus.SetAnimatedSpeaking(1)

	pKorbus.SetCharacterName("Korbus")

	pKorbus.SetDatabase("data/TGL/Korbus Bridge General.tgl")

	# Configure for the Generic bridge
	import Guest
	Guest.ConfigureForGeneric(pKorbus)

	pKorbus.SetLocation("KlingonSeated")
#	kDebugObj.Print("Finished creating Korbus")
	return pKorbus


###############################################################################
#	CreateBridgeCharacter()
#
#	Create Korbus by building his character and placing him on the passed in set.
#	Create his menus as well.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateBridgeCharacter(pSet):
#	kDebugObj.Print("Creating Korbus")
	
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyKlingon/BodyKlingon.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadKlingon/klingon_head.nif", None)
	pKorbus = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyKlingon/BodyKlingon.nif", CharacterPaths.g_pcHeadNIFPath + "HeadKlingon/klingon_head.nif")
	pKorbus.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyKlingon/Klingon_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadKlingon/korbus_head.tga")

	pKorbus.SetCharacterName("Felix")
#	pKorbus.SetCharacterName("Korbus")

	# Add the character to the set
	pSet.AddObjectToSet(pKorbus, "Tactical")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pKorbus)

	# Set up character configuration
	pKorbus.SetSize(App.CharacterClass.LARGE)
	pKorbus.SetGender(App.CharacterClass.MALE)
	pKorbus.SetStanding(0)
	pKorbus.SetHidden(1)
	pKorbus.SetRandomAnimationChance(0.75)
	pKorbus.SetBlinkChance(.1)
	pKorbus.SetAudioMode(App.CharacterClass.CAM_EXTREMELY_VOCAL)
	pKorbus.AddFacialImage("Blink0", CharacterPaths.g_pcHeadTexPath + "HeadKorbus/Korbus_blink1.tga")
	pKorbus.AddFacialImage("Blink1", CharacterPaths.g_pcHeadTexPath + "HeadKorbus/Korbus_blink2.tga")
	pKorbus.AddFacialImage("Blink2", CharacterPaths.g_pcHeadTexPath + "HeadKorbus/Korbus_eyes_closed.tga")
	pKorbus.SetBlinkStages(3)

	pKorbus.SetDatabase("data/TGL/Korbus Bridge General.tgl")

	# Load Tactical officer generic sounds	
	LoadSounds()

	import Bridge.TacticalCharacterHandlers
	Bridge.TacticalCharacterHandlers.AttachMenuToTactical(pKorbus)
	#TacticalCharacterHandlers.LoadSounds(pKorbus)

#	kDebugObj.Print("Finished creating Korbus")
	return pKorbus


###############################################################################
#	ConfigureForShip()
#
#	Configure ourselves for the particular ship object.  This involves setting
#	up range watchers that tell us how to report.
#
#	Args:	pSet	- the Set object
#			pShip	- the player's ship
#
#	Return:	none
###############################################################################
def ConfigureForShip(pSet, pShip):
	# Get our character object
	pKorbus = App.CharacterClass_Cast(pSet.GetObject("Tactical"))
	if (pKorbus == None):
#		kDebugObj.Print("******* Tactical officer not found *********")
		return


###############################################################################
#	ConfigureForSovereign()
#
#	Configure ourselves for the Sovereign bridge
#
#	Args:	pKorbus	- our Character object
#
#	Return:	none
###############################################################################
def ConfigureForSovereign(pKorbus):
#	kDebugObj.Print("Configuring Korbus for the Sovereign bridge")

	# Clear out any old animations from another configuration
	pKorbus.ClearAnimations()

	# Register animation mappings
	pKorbus.AddAnimation("SeatedEBTactical", "Bridge.Characters.CommonAnimations.SeatedL")
	pKorbus.AddAnimation("EBL1LToT", "Bridge.Characters.LargeAnimations.EBMoveFromL1ToT")
	pKorbus.AddAnimation("EBTacticalToL1", "Bridge.Characters.LargeAnimations.EBMoveFromTToL1")
	pKorbus.AddAnimation("EBTacticalTurnCaptain", "Bridge.Characters.LargeAnimations.EBTurnAtTTowardsCaptain")
	pKorbus.AddAnimation("EBTacticalBackCaptain", "Bridge.Characters.LargeAnimations.EBTurnBackAtTFromCaptain");

	pKorbus.AddAnimation("EBTacticalGlanceCaptain", "Bridge.Characters.CommonAnimations.GlanceLeft")
	pKorbus.AddAnimation("EBTacticalGlanceAwayCaptain", "Bridge.Characters.CommonAnimations.SeatedL")

	pKorbus.AddAnimation("EBTacticalTurnC", "Bridge.Characters.LargeAnimations.EBTTalkC")
	pKorbus.AddAnimation("EBTacticalBackC", "Bridge.Characters.LargeAnimations.EBTTalkFinC")
	pKorbus.AddAnimation("EBTacticalTurnE", "Bridge.Characters.LargeAnimations.EBTTalkE")
	pKorbus.AddAnimation("EBTacticalBackE", "Bridge.Characters.LargeAnimations.EBTTalkFinE")
	pKorbus.AddAnimation("EBTacticalTurnH", "Bridge.Characters.LargeAnimations.EBTTalkH")
	pKorbus.AddAnimation("EBTacticalBackH", "Bridge.Characters.LargeAnimations.EBTTalkFinH")
	pKorbus.AddAnimation("EBTacticalTurnS", "Bridge.Characters.LargeAnimations.EBTTalkS")
	pKorbus.AddAnimation("EBTacticalBackS", "Bridge.Characters.LargeAnimations.EBTTalkFinS")

	### TEMPORARY UNTIL WE GET FINAL ANIMATION FOR LOOKING AT GUEST ###
	pKorbus.AddAnimation("EBTacticalTurnX", "Bridge.Characters.LargeAnimations.EBTurnAtTTowardsCaptain")
	pKorbus.AddAnimation("EBTacticalBackX", "Bridge.Characters.LargeAnimations.EBTurnBackAtTFromCaptain")
	### END TEMPORARY UNTIL WE GET FINAL ANIMATION FOR LOOKING AT GUEST ###

	# Breathing
	#pKorbus.AddAnimation("EBTacticalBreathe", "Bridge.Characters.CommonAnimations.SeatedL")
	pKorbus.AddAnimation("EBTacticalBreatheTurned", "Bridge.Characters.CommonAnimations.BreathingTurned")

	# Hit animations		
	pKorbus.AddAnimation("EBTacticalHit", "Bridge.Characters.LargeAnimations.THit");
	pKorbus.AddAnimation("EBTacticalHitHard", "Bridge.Characters.LargeAnimations.THitHard");
	pKorbus.AddAnimation("EBTacticalReactLeft", "Bridge.Characters.CommonAnimations.ReactLeft");
	pKorbus.AddAnimation("EBTacticalReactRight", "Bridge.Characters.CommonAnimations.ReactRight");

	# Interaction
	pKorbus.AddRandomAnimation("Bridge.Characters.LargeAnimations.EBTConsoleInteraction", App.CharacterClass.SITTING_ONLY, 25, 1)

	# So the mission builders can force the call
	pKorbus.AddAnimation("PushingButtons", "Bridge.Characters.LargeAnimations.EBTConsoleInteraction")

	# Add common animations.
	AddCommonAnimations(pKorbus)
	
	pKorbus.SetLocation("EBL1L")
	pKorbus.AddPositionZoom("EBTactical", 0.5, "Tactical")
	pKorbus.SetLookAtAdj(5, 0, 65)

	pKorbus.SetHidden(1)

#	kDebugObj.Print("Finished configuring Korbus")



###############################################################################
#	AddCommonAnimations()
#
#	Since we can only clear out all animations when switching bridges (how
#	would we know which not to clear?), we can't really setup animations common
#	to all bridge configurations as we might like.  Because of this we have a
#	routine to add common animations (most of which are randoms) that both
#	configurations will call
#
#	Args:	pKorbus	- our Character object
#
#	Return:	none
###############################################################################
def AddCommonAnimations(pKorbus):
	#pKorbus.AddRandomAnimation("Bridge.Characters.CommonAnimations.WipingBrowLeft")
	#pKorbus.AddRandomAnimation("Bridge.Characters.CommonAnimations.WipingBrowRight")
	#pKorbus.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookLeft")
	#pKorbus.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookRight")
	pKorbus.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookUp")
	pKorbus.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookDown")
	#pKorbus.AddRandomAnimation("Bridge.Characters.CommonAnimations.AtEase", App.CharacterClass.STANDING_ONLY)


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
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Korbus Bridge General.tgl")
	# Like a function pointer (GetFile() is the same as pDatabase.GetFilename())
	GetFile = pDatabase.GetFilename	# do this for horizontal space savings

#	print("Getting Korbus Sounds")

	# Unload Felix's sounds, since Korbus will be replacing them.
	import Felix
	for sLine in Felix.g_lsFelixLines:
		App.g_kSoundManager.DeleteSound(sLine)

	kSoundList = (
		"AttackStatus_EvadingTorps1",
		"AttackStatus_FallingBack1",
		"AttackStatus_LiningUpFront1",
		"AttackStatus_MovingIn1",
		"AttackStatus_RearTorpRun1",
		"AttackStatus_SweepingPhasers1",
		"BadTarget1",
		"BadTarget2",
		"Disengaging",
		"DontShootTac",
		"EvasiveManuvers", # Sumbody furgot to spel this rite.
		"KorbusEnDes",
		"KorbusNothingToAdd",
		"KorbusNothingToAdd2",
		"KorbusNothingToAdd3",
		"KorbusSir1",
		"KorbusSir2",
		"KorbusSir3",
		"KorbusSir4",
		"KorbusSir5",
		"KorbusYes1",
		"KorbusYes2",
		"KorbusYes3",
		"KorbusYes4",
		"ForeShieldsOffline",
		"Incoming1",
		"Incoming2",
		"Incoming3",
		"Incoming4",
		"Incoming5",
		"Incoming6",
		"LoadingPhoton",
		"LoadingQuantum",
		"LoadingTorps",
		"NeedPower",
		"OutOfPhotons",
		"OutOfQuantums",
		"OutOfType",
		"TacticalManuver", # This wun to.
		"gt001",
		"gt002",
		"gt007",
		"gt029",
		"gt030",
		"gt037",
		"gt038",
		"gt212",
		"gt213",
		)
	for i in range(len(kSoundList)):
		# Delete sounds
		pGame.LoadDatabaseSoundInGroup(pDatabase, kSoundList[i], "KorbusGeneric")

	App.g_kLocalizationManager.Unload(pDatabase)

def FreeSounds ():
	App.g_kSoundManager.DeleteAllSoundsInGroup("KorbusGeneric")


