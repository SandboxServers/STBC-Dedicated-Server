###############################################################################
#	Filename:	Draxon.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Loads Korbus, and sets up meta animations.
#	
#	Created:	2/7/00 -	Jess VanDerwalker
###############################################################################

import App
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create Draxon by building his character and placing him on the passed in
#	set.  Uses kartok_head.tga for face.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating Captain Draxon")

	if (pSet.GetObject("Draxon") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("Draxon")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyKlingon/BodyKlingon.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadKlingon/klingon_head.nif", None)
	pDraxon = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyKlingon/BodyKlingon.nif", CharacterPaths.g_pcHeadNIFPath + "HeadKlingon/klingon_head.nif")
	pDraxon.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyKlingon/Klingon_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadKlingon/kartok_head.tga")

	# Add the character to the set
	pSet.AddObjectToSet(pDraxon, "Draxon")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pDraxon)
	
	# Setup the character configuration
	pDraxon.SetSize(App.CharacterClass.MEDIUM)
	pDraxon.SetGender(App.CharacterClass.MALE)
	pDraxon.SetStanding(1)
	pDraxon.SetRandomAnimationChance(.01)
	pDraxon.SetBlinkChance(0.1)
	pDraxon.SetCharacterName("Draxon")

	pDraxon.AddFacialImage("Blink0", CharacterPaths.g_pcHeadTexPath + "HeadKlingon/Kartok_head_blink1.tga")
	pDraxon.AddFacialImage("Blink1", CharacterPaths.g_pcHeadTexPath + "HeadKlingon/Kartok_head_blink2.tga")
	pDraxon.AddFacialImage("Blink2", CharacterPaths.g_pcHeadTexPath + "HeadKlingon/Kartok_head_eyesclosed.tga")
	pDraxon.SetBlinkStages(3)

	pDraxon.AddFacialImage("SpeakA", CharacterPaths.g_pcHeadTexPath + "HeadKlingon/Kartok_head_a.tga")
	pDraxon.AddFacialImage("SpeakE", CharacterPaths.g_pcHeadTexPath + "HeadKlingon/Kartok_head_e.tga")
	pDraxon.AddFacialImage("SpeakU", CharacterPaths.g_pcHeadTexPath + "HeadKlingon/Kartok_head_u.tga")
	pDraxon.SetAnimatedSpeaking(1)

	# Configure for the Generic bridge
	import Guest
	Guest.ConfigureForGeneric(pDraxon)

	pDraxon.SetLocation("KlingonSeated")

#	kDebugObj.Print("Finished creating Draxon")
	return pDraxon