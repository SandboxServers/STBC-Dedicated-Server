###############################################################################
#	Filename:	Praag.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads Damon Praag, and sets up meta animations.
#	
#	Created:	12/20/00 -	Matthew Kagle
###############################################################################

import App
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create Praag by building her character and placing her on the passed in set.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating Damon Praag")

	if (pSet.GetObject("Praag") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("Praag")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadFerengi/ferengi_head.nif", None)
	pPraag = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", CharacterPaths.g_pcHeadNIFPath + "HeadFerengi/ferengi_head.nif")
	pPraag.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyMaleM/Ferengi_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadFerengi/praag_head.tga")

	# Add the character to the set
	pSet.AddObjectToSet(pPraag, "Praag")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pPraag)
	
	# Setup the character configuration
	pPraag.SetSize(App.CharacterClass.MEDIUM)
	pPraag.SetGender(App.CharacterClass.MALE)
	pPraag.SetStanding(1)
	pPraag.SetRandomAnimationChance(.01)
	pPraag.SetCharacterName("Praag")

	pPraag.AddFacialImage("Blink0", CharacterPaths.g_pcHeadTexPath + "HeadFerengi/Praag_head_blink1.tga")
	pPraag.AddFacialImage("Blink1", CharacterPaths.g_pcHeadTexPath + "HeadFerengi/Praag_head_blink2.tga")
	pPraag.AddFacialImage("Blink2", CharacterPaths.g_pcHeadTexPath + "HeadFerengi/Praag_head_eyesclosed.tga")
	pPraag.SetBlinkStages(3)

	pPraag.AddFacialImage("SpeakA", CharacterPaths.g_pcHeadTexPath + "HeadFerengi/Praag_head_a.tga")
	pPraag.AddFacialImage("SpeakE", CharacterPaths.g_pcHeadTexPath + "HeadFerengi/Praag_head_e.tga")
	pPraag.AddFacialImage("SpeakU", CharacterPaths.g_pcHeadTexPath + "HeadFerengi/Praag_head_u.tga")
	pPraag.SetAnimatedSpeaking(1)

	# Configure for the Generic bridge
	import Guest
	Guest.ConfigureForGeneric(pPraag)

	pPraag.SetLocation("FerengiSeated")

#	kDebugObj.Print("Finished creating Praag")
	return pPraag
