###############################################################################
#	Filename:	Dawson.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads Captain Dawson, and configures animations
#	
#	Created:	7/25/00 -	Matthew Kagle
###############################################################################

import App
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create Dawson by building his character and placing him on the passed in set.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating Dawson")

	if (pSet.GetObject("Dawson") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("Dawson")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadMiguel/miguel_head.nif", None)
	pDawson = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", CharacterPaths.g_pcHeadNIFPath + "HeadMiguel/miguel_head.nif")
	pDawson.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyMaleM/FedRed_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/dawson_head.tga")

	# Add the character to the set
	pSet.AddObjectToSet(pDawson, "Dawson")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pDawson)
	
	# Setup the character configuration
	pDawson.SetSize(App.CharacterClass.MEDIUM)
	pDawson.SetGender(App.CharacterClass.MALE)
	pDawson.SetStanding(1)
	pDawson.SetRandomAnimationChance(.01)
	pDawson.SetBlinkChance(0.1)
	pDawson.SetCharacterName("Dawson")

	pDawson.AddFacialImage("Blink0", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Dawson_head_blink1.tga")
	pDawson.AddFacialImage("Blink1", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Dawson_head_blink2.tga")
	pDawson.AddFacialImage("Blink2", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Dawson_head_eyesclosed.tga")
	pDawson.SetBlinkStages(3)

	pDawson.AddFacialImage("SpeakA", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Dawson_head_a.tga")
	pDawson.AddFacialImage("SpeakE", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Dawson_head_e.tga")
	pDawson.AddFacialImage("SpeakU", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Dawson_head_u.tga")
	pDawson.SetAnimatedSpeaking(1)

	# Configure for the Generic bridge
	import Guest
	Guest.ConfigureForGeneric(pDawson)
	pDawson.SetLocation("GalaxySeated")
#	kDebugObj.Print("Finished creating Captain Dawson")
	return pDawson
