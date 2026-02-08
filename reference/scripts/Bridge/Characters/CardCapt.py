###############################################################################
#	Filename:	CardCapt.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads the Cardassian Captain, and sets up meta animations.
#	
#	Created:	3/09/01 -	Jess VanDerwalker
###############################################################################

import App
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create CardCapt by building him character and placing him on the passed in set.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating Cardassian Captain")

	if (pSet.GetObject("CardCapt") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("CardCapt")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyCardassian/BodyCardassian.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadCard/cardassian_head.nif", None)
	pCardCapt = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyCardassian/BodyCardassian.nif", CharacterPaths.g_pcHeadNIFPath + "HeadCard/cardassian_head.nif")
	pCardCapt.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyCardassian/Cardassian_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadCard/card_capt_head.tga")

	# Add the character to the set
	pSet.AddObjectToSet(pCardCapt, "CardCapt")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pCardCapt)
	
	# Setup the character configuration
	pCardCapt.SetSize(App.CharacterClass.MEDIUM)
	pCardCapt.SetGender(App.CharacterClass.MALE)
	pCardCapt.SetStanding(1)
	pCardCapt.SetRandomAnimationChance(.01)
	pCardCapt.SetCharacterName("CardCapt")

	pCardCapt.AddFacialImage("Blink0", CharacterPaths.g_pcHeadTexPath + "HeadCard/Card_Capt_head_blink1.tga")
	pCardCapt.AddFacialImage("Blink1", CharacterPaths.g_pcHeadTexPath + "HeadCard/Card_Capt_head_blink2.tga")
	pCardCapt.AddFacialImage("Blink2", CharacterPaths.g_pcHeadTexPath + "HeadCard/Card_Capt_head_eyes_closed.tga")
	pCardCapt.SetBlinkStages(3)

	pCardCapt.AddFacialImage("SpeakA", CharacterPaths.g_pcHeadTexPath + "HeadCard/Card_Capt_head_a.tga")
	pCardCapt.AddFacialImage("SpeakE", CharacterPaths.g_pcHeadTexPath + "HeadCard/Card_Capt_head_e.tga")
	pCardCapt.AddFacialImage("SpeakU", CharacterPaths.g_pcHeadTexPath + "HeadCard/Card_Capt_head_u.tga")
	pCardCapt.SetAnimatedSpeaking(1)

	# Configure for the Generic bridge
	import Guest
	Guest.ConfigureForGeneric(pCardCapt)

	pCardCapt.SetLocation("CardassianSeated")

#	kDebugObj.Print("Finished creating Cardassian Captain")
	return pCardCapt
