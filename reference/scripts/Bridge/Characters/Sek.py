###############################################################################
#	Filename:	Sek.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads Gul Sek, and sets up meta animations.
#	
#	Created:	9/13/00 -	Matthew Kagle
###############################################################################

import App
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create Sek by building her character and placing her on the passed in set.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating Gul Sek")

	if (pSet.GetObject("Sek") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("Sek")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyCardassian/BodyCardassian.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadCard/cardassian_head.nif", None)
	pSek = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyCardassian/BodyCardassian.nif", CharacterPaths.g_pcHeadNIFPath + "HeadCard/cardassian_head.nif")
	pSek.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyCardassian/Cardassian_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadCard/sek_head.tga")

	# Add the character to the set
	pSet.AddObjectToSet(pSek, "Sek")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pSek)
	
	# Setup the character configuration
	pSek.SetSize(App.CharacterClass.MEDIUM)
	pSek.SetGender(App.CharacterClass.MALE)
	pSek.SetStanding(1)
	pSek.SetRandomAnimationChance(.01)
	pSek.SetCharacterName("Sek")

	pSek.AddFacialImage("Blink0", CharacterPaths.g_pcHeadTexPath + "HeadCard/Sek_head_blink1.tga")
	pSek.AddFacialImage("Blink1", CharacterPaths.g_pcHeadTexPath + "HeadCard/Sek_head_blink2.tga")
	pSek.AddFacialImage("Blink2", CharacterPaths.g_pcHeadTexPath + "HeadCard/Sek_head_eyesclosed.tga")
	pSek.SetBlinkStages(3)

	pSek.AddFacialImage("SpeakA", CharacterPaths.g_pcHeadTexPath + "HeadCard/Sek_head_a.tga")
	pSek.AddFacialImage("SpeakE", CharacterPaths.g_pcHeadTexPath + "HeadCard/Sek_head_e.tga")
	pSek.AddFacialImage("SpeakU", CharacterPaths.g_pcHeadTexPath + "HeadCard/Sek_head_u.tga")
	pSek.SetAnimatedSpeaking(1)

	# Configure for the Generic bridge
	import Guest
	Guest.ConfigureForGeneric(pSek)

#	kDebugObj.Print("Finished creating Sek")
	return pSek
