###############################################################################
#	Filename:	Picard.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads Captain Picard, and configures animations
#	
#	Created:	7/25/00 -	Colin Carley
###############################################################################

import App
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create Liu by building his character and placing him on the passed in set.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating Captain Picard")

	if (pSet.GetObject("Picard") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("Picard")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadPicard/picard_head.nif", None)
	pPicard = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", CharacterPaths.g_pcHeadNIFPath + "HeadPicard/picard_head.nif")
	pPicard.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyMaleM/FedRed_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadPicard/picard_head.tga")

	# Add the character to the set
	pSet.AddObjectToSet(pPicard, "Picard")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pPicard)
	
	# Setup the character configuration
	pPicard.SetSize(App.CharacterClass.MEDIUM)
	pPicard.SetGender(App.CharacterClass.MALE)
	pPicard.SetStanding(1)
	pPicard.SetRandomAnimationChance(.01)
	pPicard.SetCharacterName("Picard")

	pPicard.SetDatabase("data/TGL/Picard General.tgl")

	# Load Picard's generic sounds
	LoadSounds()

	pPicard.AddFacialImage("Blink0", CharacterPaths.g_pcHeadTexPath + "HeadPicard/Picard_head_blink1.tga")
	pPicard.AddFacialImage("Blink1", CharacterPaths.g_pcHeadTexPath + "HeadPicard/Picard_head_blink2.tga")
	pPicard.AddFacialImage("Blink2", CharacterPaths.g_pcHeadTexPath + "HeadPicard/Picard_head_eyesclosed.tga")
	pPicard.SetBlinkStages(3)

	pPicard.AddFacialImage("SpeakA", CharacterPaths.g_pcHeadTexPath + "HeadPicard/Picard_head_a.tga")
	pPicard.AddFacialImage("SpeakE", CharacterPaths.g_pcHeadTexPath + "HeadPicard/Picard_head_e.tga")
	pPicard.AddFacialImage("SpeakU", CharacterPaths.g_pcHeadTexPath + "HeadPicard/Picard_head_u.tga")
	pPicard.SetAnimatedSpeaking(1)

	# Configure for the Generic bridge
	import Guest
	Guest.ConfigureForGeneric(pPicard)

#	kDebugObj.Print("Finished creating Captain Picard")

	import Bridge.PicardMenuHandlers
	Bridge.PicardMenuHandlers.CreateMenus(pPicard)

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/CharacterStatus.tgl")
	pPicard.SetStatus( pDatabase.GetString("Ready to Advise") )
	App.g_kLocalizationManager.Unload(pDatabase)

	return pPicard


###############################################################################
#	ConfigureForGalaxy()
#
#	Configure ourselves for the Galaxy bridge
#
#	Args:	pPicard	- our Character object
#
#	Return:	none
###############################################################################
def ConfigureForGalaxy(pPicard):
#	kDebugObj.Print("Configuring Picard for the Galaxy bridge")
	
	kAM = App.g_kAnimationManager

	# Pointing start animations
	kAM.LoadAnimation ("data/animations/db_P_Point_C_P.nif", "db_P_Point_C_P")
	kAM.LoadAnimation ("data/animations/db_P_Point_E_P.nif", "db_P_Point_E_P")
	kAM.LoadAnimation ("data/animations/db_P_Point_H_P.nif", "db_P_Point_H_P")
	kAM.LoadAnimation ("data/animations/db_P_Point_S_P.nif", "db_P_Point_S_P")
	kAM.LoadAnimation ("data/animations/db_P_Point_T_P.nif", "db_P_Point_T_P")

	# Pointing End animations
	kAM.LoadAnimation ("data/animations/db_P_Point_C_End_P.nif", "db_P_Point_C_End_P")
	kAM.LoadAnimation ("data/animations/db_P_Point_E_End_P.nif", "db_P_Point_E_End_P")
	kAM.LoadAnimation ("data/animations/db_P_Point_H_End_P.nif", "db_P_Point_H_End_P")
	kAM.LoadAnimation ("data/animations/db_P_Point_S_End_P.nif", "db_P_Point_S_End_P")
	kAM.LoadAnimation ("data/animations/db_P_Point_T_End_P.nif", "db_P_Point_T_End_P")

	kAM.LoadAnimation ("data/animations/db_H_Turn_C_P.nif", "db_H_Turn_C_P")
	kAM.LoadAnimation ("data/animations/db_H_Turn_H_P.nif", "db_H_Turn_H_P")

	
	kAM.LoadAnimation ("data/animations/Arms_Folded_Start.nif", "Arms_Folded_Start")
	kAM.LoadAnimation ("data/animations/Arms_Folded_End.nif", "Arms_Folded_End")

	# Turn to various crew members
	pPicard.AddAnimation("DBGuestTurnC", "Bridge.Characters.MediumAnimations.TurnAtXTowardsCaptain")
	pPicard.AddAnimation("DBGuestBackC", "Bridge.Characters.CommonAnimations.SeatedM")
	pPicard.AddAnimation("DBGuestTurnH", "Bridge.Characters.MediumAnimations.DBXTalkH")
	pPicard.AddAnimation("DBGuestBackH", "Bridge.Characters.CommonAnimations.SeatedM")
	pPicard.AddAnimation("DBGuestTurnE", "Bridge.Characters.MediumAnimations.DBXTalkE")
	pPicard.AddAnimation("DBGuestBackE", "Bridge.Characters.CommonAnimations.SeatedM")
	pPicard.AddAnimation("DBGuestTurnS", "Bridge.Characters.MediumAnimations.DBXTalkS")
	pPicard.AddAnimation("DBGuestBackS", "Bridge.Characters.CommonAnimations.SeatedM")
	pPicard.AddAnimation("DBGuestTurnT", "Bridge.Characters.MediumAnimations.DBXTalkT")
	pPicard.AddAnimation("DBGuestBackT", "Bridge.Characters.CommonAnimations.SeatedM")

	pPicard.AddAnimation("DBGuest1TurnC2", "Bridge.Characters.MediumAnimations.DBP1TalkC2")
	pPicard.AddAnimation("DBGuest1BackC2", "Bridge.Characters.MediumAnimations.DBP1TalkFinC2")

	#
	# Lots of mission specific tutorial stuff will go here
	#


	import Bridge.Characters.MediumAnimations
	pPicard.AddAnimation("DBGuestTurnCaptain", "Bridge.Characters.MediumAnimations.TurnAtXTowardsCaptain")
	pPicard.AddAnimation("DBGuestBackCaptain", "Bridge.Characters.CommonAnimations.SeatedM")

	# Register animation mappings
	pPicard.AddAnimation("SeatedDBGuest", "Bridge.Characters.CommonAnimations.SeatedM")
	pPicard.AddAnimation("StandingDBGuest1", "Bridge.Characters.CommonAnimations.Standing")
	pPicard.AddAnimation("DBL1MToP1", "Bridge.Characters.PicardAnimations.MoveFromL1ToP1")
	pPicard.AddAnimation("DBGuest1ToP", "Bridge.Characters.PicardAnimations.MoveFromP1ToP")
	pPicard.AddAnimation("DBGuestToL1", "Bridge.Characters.PicardAnimations.MoveFromPToL1")
	pPicard.AddAnimation("DBGuestToH", "Bridge.Characters.PicardAnimations.MoveFromPToH")
	pPicard.AddAnimation("DBGuestHToT", "Bridge.Characters.PicardAnimations.MoveFromHToT")
	pPicard.AddAnimation("DBGuestTToC1", "Bridge.Characters.PicardAnimations.MoveFromTToC1")
	pPicard.AddAnimation("DBGuestC1ToP", "Bridge.Characters.PicardAnimations.MoveFromC1ToP")
	pPicard.AddAnimation("DBGuestHTurnCaptain", "Bridge.Characters.PicardAnimations.TurnAtHTowardsCaptain")
	pPicard.AddAnimation("DBGuestHTurnHelm", "Bridge.Characters.PicardAnimations.TurnAtHTowardsHelm")
	pPicard.AddAnimation("DBGuestPBack", "Bridge.Characters.CommonAnimations.SeatedM")
	pPicard.AddAnimation("DBGuestC1Back", "Bridge.Characters.MediumAnimations.TurnBackAtC1FromCaptain")

	pPicard.AddAnimation("DBGuestBreathe", "Bridge.Characters.CommonAnimations.SeatedM")
	pPicard.AddAnimation("DBGuest1Breathe", "Bridge.Characters.CommonAnimations.Standing")
	pPicard.AddAnimation("DBGuest2Breathe", "Bridge.Characters.CommonAnimations.Standing")

	# Hit animations
	pPicard.AddAnimation("DBGuestHit", "Bridge.Characters.PicardAnimations.PHit")
	pPicard.AddAnimation("DBGuestHitHard", "Bridge.Characters.MediumAnimations.CHitHard")
	pPicard.AddAnimation("DBGuestHitStanding", "Bridge.Characters.CommonAnimations.HitStanding")
	pPicard.AddAnimation("DBGuestHitHardStanding", "Bridge.Characters.CommonAnimations.HitHardStanding")
	pPicard.AddAnimation("DBGuestReactLeft", "Bridge.Characters.CommonAnimations.ReactLeft")
	pPicard.AddAnimation("DBGuestReactRight", "Bridge.Characters.CommonAnimations.ReactRight")

	pPicard.AddAnimation("PushingButtons", "Bridge.Characters.MediumAnimations.DBXConsoleInteraction")

	# Add common animations.
	AddCommonAnimations(pPicard)

	# Picard will need to be explicity placed in each mission
	pPicard.SetLocation("SovereignSeated")
#	kDebugObj.Print("Finished configuring Picard")

###############################################################################
#	AddCommonAnimations()
#
#	Since we can only clear out all animations when switching bridges (how
#	would we know which not to clear?), we can't really setup animations common
#	to all bridge configurations as we might like.  Because of this we have a
#	routine to add common animations (most of which are randoms) that both
#	configurations will call
#
#	Args:	pPicard	- our Character object
#
#	Return:	none
###############################################################################
def AddCommonAnimations(pPicard):
	pPicard.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookLeft", App.CharacterClass.SITTING_ONLY)
	pPicard.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookRight", App.CharacterClass.SITTING_ONLY)
	pPicard.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookUp", App.CharacterClass.SITTING_ONLY)
	pPicard.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookDown", App.CharacterClass.SITTING_ONLY)
	pPicard.AddRandomAnimation("Bridge.Characters.CommonAnimations.LookAroundConsoleDown", App.CharacterClass.SITTING_ONLY)
	
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
	# Picard has no generic bridge sounds at this time
	#

	kSoundList =	[	"PicardSir1",		# Click Response
						"PicardSir2",
						"PicardSir3",
						"PicardSir4",
						"PicardSir5",

						"PicardYes1",		# Order Confirmation
						"PicardYes2",
						"PicardYes3",
						"PicardYes4" ]

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Picard General.tgl")
	pGame = App.Game_GetCurrentGame()
	for i in range(len(kSoundList)):
		pGame.LoadDatabaseSoundInGroup(pDatabase, kSoundList[i], "Picard")

	App.g_kLocalizationManager.Unload(pDatabase)
