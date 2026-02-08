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
#	kDebugObj.Print("Creating Captain Barel")

	if (pSet.GetObject("Barel") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("Barel")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadRomulan/romulan_head.nif", None)
	pBarel = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", CharacterPaths.g_pcHeadNIFPath + "HeadRomulan/romulan_head.nif")
	pBarel.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyMaleM/Romulan_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadRomulan/barel_head.tga")

	# Add the character to the set
	pSet.AddObjectToSet(pBarel, "Barel")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pBarel)
	
	# Setup the character configuration
	pBarel.SetSize(App.CharacterClass.MEDIUM)
	pBarel.SetGender(App.CharacterClass.MALE)
	pBarel.SetStanding(1)
	pBarel.SetRandomAnimationChance(.01)
	pBarel.SetBlinkChance(0.1)
	pBarel.SetCharacterName("Barel")

	pBarel.AddFacialImage("Blink0", CharacterPaths.g_pcHeadTexPath + "HeadRomulan/Barel_head_blink1.tga")
	pBarel.AddFacialImage("Blink1", CharacterPaths.g_pcHeadTexPath + "HeadRomulan/Barel_head_blink2.tga")
	pBarel.AddFacialImage("Blink2", CharacterPaths.g_pcHeadTexPath + "HeadRomulan/Barel_head_eyes_closed.tga")
	pBarel.SetBlinkStages(3)

	pBarel.AddFacialImage("SpeakA", CharacterPaths.g_pcHeadTexPath + "HeadRomulan/Barel_head_a.tga")
	pBarel.AddFacialImage("SpeakE", CharacterPaths.g_pcHeadTexPath + "HeadRomulan/Barel_head_e.tga")
	pBarel.AddFacialImage("SpeakU", CharacterPaths.g_pcHeadTexPath + "HeadRomulan/Barel_head_u.tga")
	pBarel.SetAnimatedSpeaking(1)

	# Configure for the Generic bridge
	import Guest
	Guest.ConfigureForGeneric(pBarel)

	pBarel.SetLocation("RomulanSeated")

#	kDebugObj.Print("Finished creating Barel")
	return pBarel
