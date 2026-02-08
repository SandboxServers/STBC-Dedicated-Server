###############################################################################
#	Filename:	Jadeja.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads Captain Jadeja, and configures animations
#	
#	Created:	12/12/00 -	Jess VanDerwalker
###############################################################################

import App
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create Jadeja by building his character and placing him on the passed in set.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating Captain Jadeja")

	if (pSet.GetObject("Jadeja") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("Jadeja")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadMiguel/miguel_head.nif", None)
	pJadeja = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", CharacterPaths.g_pcHeadNIFPath + "HeadMiguel/miguel_head.nif")
	pJadeja.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyMaleM/FedRed_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/jadeja_head.tga")

	# Add the character to the set
	pSet.AddObjectToSet(pJadeja, "Jadeja")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pJadeja)
	
	# Setup the character configuration
	pJadeja.SetSize(App.CharacterClass.MEDIUM)
	pJadeja.SetGender(App.CharacterClass.MALE)
	pJadeja.SetStanding(1)
	pJadeja.SetRandomAnimationChance(.01)
	pJadeja.SetBlinkChance(0.1)
	pJadeja.SetCharacterName("Jadeja")

	pJadeja.AddFacialImage("Blink0", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Jadeja_head_blink1.tga")
	pJadeja.AddFacialImage("Blink1", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Jadeja_head_blink2.tga")
	pJadeja.AddFacialImage("Blink2", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Jadeja_head_eyesclosed.tga")
	pJadeja.SetBlinkStages(3)

	pJadeja.AddFacialImage("SpeakA", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Jadeja_head_a.tga")
	pJadeja.AddFacialImage("SpeakE", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Jadeja_head_e.tga")
	pJadeja.AddFacialImage("SpeakU", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Jadeja_head_u.tga")
	pJadeja.SetAnimatedSpeaking(1)

	# Configure for the Generic bridge
	import Guest
	Guest.ConfigureForGeneric(pJadeja)
	pJadeja.SetLocation("GalaxySeated")
#	kDebugObj.Print("Finished creating Captain Jadeja")
	return pJadeja
