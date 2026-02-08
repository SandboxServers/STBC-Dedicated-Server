###############################################################################
#	Filename:	Soto.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads Commander Soto and configures animations
#	
#	Created:	10/28/00 - Jess VanDerwalker
###############################################################################

import App
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create Soto by building his character and placing him on the passed in set.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating Commander Soto")

	if (pSet.GetObject("Soto") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("Soto")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadData/data_head.nif", None)
	pSoto = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", CharacterPaths.g_pcHeadNIFPath + "HeadData/data_head.nif")
	pSoto.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyMaleM/FedRed_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadData/soto_head.tga")

	# Add the character to the set
	pSet.AddObjectToSet(pSoto, "Soto")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pSoto)
	
	# Setup the character configuration
	pSoto.SetSize(App.CharacterClass.MEDIUM)
	pSoto.SetGender(App.CharacterClass.MALE)
	pSoto.SetStanding(1)
	pSoto.SetRandomAnimationChance(.01)
	pSoto.SetBlinkChance(0.1)
	pSoto.SetCharacterName("Soto")

	pSoto.AddFacialImage("Blink0", CharacterPaths.g_pcHeadTexPath + "HeadData/Soto_head_blink1.tga")
	pSoto.AddFacialImage("Blink1", CharacterPaths.g_pcHeadTexPath + "HeadData/Soto_head_blink2.tga")
	pSoto.AddFacialImage("Blink2", CharacterPaths.g_pcHeadTexPath + "HeadData/Soto_head_eyesclosed.tga")
	pSoto.SetBlinkStages(3)

	pSoto.AddFacialImage("SpeakA", CharacterPaths.g_pcHeadTexPath + "HeadData/Soto_head_a.tga")
	pSoto.AddFacialImage("SpeakE", CharacterPaths.g_pcHeadTexPath + "HeadData/Soto_head_e.tga")
	pSoto.AddFacialImage("SpeakU", CharacterPaths.g_pcHeadTexPath + "HeadData/Soto_head_u.tga")
	pSoto.SetAnimatedSpeaking(1)

	# Configure for the Generic bridge
	import Guest
	Guest.ConfigureForGeneric(pSoto)

	# Set his default location
	pSoto.SetLocation("SovereignSeated")
	
#	kDebugObj.Print("Finished creating Captain Soto")
	return pSoto
