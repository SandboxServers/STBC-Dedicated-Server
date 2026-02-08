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
#	kDebugObj.Print("Creating Captain Terrik")

	if (pSet.GetObject("Terrik") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("Terrik")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadRomulan/romulan_head.nif", None)
	pTerrik = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", CharacterPaths.g_pcHeadNIFPath + "HeadRomulan/romulan_head.nif")
	pTerrik.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyMaleM/Romulan_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadRomulan/terik_head.tga")

	# Add the character to the set
	pSet.AddObjectToSet(pTerrik, "Terrik")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pTerrik)
	
	# Setup the character configuration
	pTerrik.SetSize(App.CharacterClass.MEDIUM)
	pTerrik.SetGender(App.CharacterClass.MALE)
	pTerrik.SetStanding(1)
	pTerrik.SetRandomAnimationChance(.01)
	pTerrik.SetBlinkChance(0.1)
	pTerrik.SetCharacterName("Terrik")

	pTerrik.AddFacialImage("Blink0", CharacterPaths.g_pcHeadTexPath + "HeadRomulan/Terik_head_blink1.tga")
	pTerrik.AddFacialImage("Blink1", CharacterPaths.g_pcHeadTexPath + "HeadRomulan/Terik_head_blink2.tga")
	pTerrik.AddFacialImage("Blink2", CharacterPaths.g_pcHeadTexPath + "HeadRomulan/Terik_head_eyesclosed.tga")
	pTerrik.SetBlinkStages(3)

	pTerrik.AddFacialImage("SpeakA", CharacterPaths.g_pcHeadTexPath + "HeadRomulan/Terik_head_a.tga")
	pTerrik.AddFacialImage("SpeakE", CharacterPaths.g_pcHeadTexPath + "HeadRomulan/Terik_head_e.tga")
	pTerrik.AddFacialImage("SpeakU", CharacterPaths.g_pcHeadTexPath + "HeadRomulan/Terik_head_u.tga")
	pTerrik.SetAnimatedSpeaking(1)

	# Configure for the Generic bridge
	import Guest
	Guest.ConfigureForGeneric(pTerrik)

	pTerrik.SetLocation("RomulanSeated")

#	kDebugObj.Print("Finished creating Terrik")
	return pTerrik
