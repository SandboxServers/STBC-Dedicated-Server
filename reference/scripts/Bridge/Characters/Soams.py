###############################################################################
#	Filename:	Soams.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads Toban Soams and configures animations
#	
#	Created:	10/31/00 -	Jess VanDerwalker
###############################################################################

import App
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create Toban Soams by building her character and placing her on the passed in set.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating Toban Soams")

	if (pSet.GetObject("Soams") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("Soams")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadMiguel/soams_head.nif", None)
	pSoams = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", CharacterPaths.g_pcHeadNIFPath + "HeadMiguel/miguel_head.nif")
	pSoams.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyMaleM/FedCivilian_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/soams_head.tga")

	# Add the character to the set
	pSet.AddObjectToSet(pSoams, "Soams")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pSoams)
	
	# Setup the character configuration
	pSoams.SetSize(App.CharacterClass.MEDIUM)
	pSoams.SetGender(App.CharacterClass.MALE)
	pSoams.SetStanding(1)
	pSoams.SetRandomAnimationChance(.01)
	pSoams.SetCharacterName("Soams")

	pSoams.AddFacialImage("Blink0", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Soams_head_blink1.tga")
	pSoams.AddFacialImage("Blink1", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Soams_head_blink2.tga")
	pSoams.AddFacialImage("Blink2", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Soams_head_eyesclosed.tga")
	pSoams.SetBlinkStages(3)

	pSoams.AddFacialImage("SpeakA", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Soams_head_a.tga")
	pSoams.AddFacialImage("SpeakE", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Soams_head_e.tga")
	pSoams.AddFacialImage("SpeakU", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Soams_head_u.tga")
	pSoams.SetAnimatedSpeaking(1)

	# Configure for the Generic bridge
	import Guest
	Guest.ConfigureForGeneric(pSoams)

	# Set his default location
	pSoams.SetLocation("MiscEngSeated2")

#	kDebugObj.Print("Finished creating Toban Soams")
	return pSoams
