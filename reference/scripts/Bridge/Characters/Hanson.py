###############################################################################
#	Filename:	Hanson.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Loads Captain Hanson, and configures animations
#	
#	Created:	2/06/01 -	Jess VanDerwalker
###############################################################################

import App
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create Hanson by building his character and placing him on the passed in set.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating Captain Hanson")

	if (pSet.GetObject("Hanson") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("Hanson")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadData/data_head.NIF", None)
	pHanson = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", CharacterPaths.g_pcHeadNIFPath + "HeadData/data_head.NIF")
	pHanson.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyMaleM/FedCivilian_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadData/male_ensignD_head.tga")

	# Add the character to the set
	pSet.AddObjectToSet(pHanson, "Hanson")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pHanson)
	
	# Setup the character configuration
	pHanson.SetSize(App.CharacterClass.MEDIUM)
	pHanson.SetGender(App.CharacterClass.MALE)
	pHanson.SetStanding(1)
	pHanson.SetRandomAnimationChance(.01)
	pHanson.SetBlinkChance(0.1)
	pHanson.SetCharacterName("Hanson")

	pHanson.AddFacialImage("Blink0", CharacterPaths.g_pcHeadTexPath + "HeadData/Hanson_head_blink1.tga")
	pHanson.AddFacialImage("Blink1", CharacterPaths.g_pcHeadTexPath + "HeadData/Hanson_head_blink2.tga")
	pHanson.AddFacialImage("Blink2", CharacterPaths.g_pcHeadTexPath + "HeadData/Hanson_head_eyesclosed.tga")
	pHanson.SetBlinkStages(3)

	pHanson.AddFacialImage("SpeakA", CharacterPaths.g_pcHeadTexPath + "HeadData/Hanson_head_a.tga")
	pHanson.AddFacialImage("SpeakE", CharacterPaths.g_pcHeadTexPath + "HeadData/Hanson_head_e.tga")
	pHanson.AddFacialImage("SpeakU", CharacterPaths.g_pcHeadTexPath + "HeadData/Hanson_head_u.tga")
	pHanson.SetAnimatedSpeaking(1)

	# Configure for the Generic bridge
	import Guest
	Guest.ConfigureForGeneric(pHanson)

#	kDebugObj.Print("Finished creating Captain Hanson")
	return pHanson
