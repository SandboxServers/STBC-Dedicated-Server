###############################################################################
#	Filename:	Verata.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads Captain Verata, and sets up meta animations.
#	
#	Created:	11/01/00 -	Matthew Kagle
###############################################################################

import App
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create Verata by building her character and placing her on the passed in set.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating Captain Verata")

	if (pSet.GetObject("Verata") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("Verata")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadAndorian/andorian_head.nif", None)
	pVerata = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", CharacterPaths.g_pcHeadNIFPath + "HeadAndorian/andorian_head.nif")
	pVerata.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyMaleM/FedRed_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadAndorian/verata_head.tga")

	# Add the character to the set
	pSet.AddObjectToSet(pVerata, "Verata")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pVerata)
	
	# Setup the character configuration
	pVerata.SetSize(App.CharacterClass.MEDIUM)
	pVerata.SetGender(App.CharacterClass.MALE)
	pVerata.SetStanding(1)
	pVerata.SetRandomAnimationChance(.01)
	pVerata.SetBlinkChance(0.1)
	pVerata.SetCharacterName("Verata")

	pVerata.AddFacialImage("Blink0", CharacterPaths.g_pcHeadTexPath + "HeadAndorian/Verata_head_blink1.tga")
	pVerata.AddFacialImage("Blink1", CharacterPaths.g_pcHeadTexPath + "HeadAndorian/Verata_head_blink2.tga")
	pVerata.AddFacialImage("Blink2", CharacterPaths.g_pcHeadTexPath + "HeadAndorian/Verata_head_eyesclosed.tga")
	pVerata.SetBlinkStages(3)

	pVerata.AddFacialImage("SpeakA", CharacterPaths.g_pcHeadTexPath + "HeadAndorian/Verata_head_a.tga")
	pVerata.AddFacialImage("SpeakE", CharacterPaths.g_pcHeadTexPath + "HeadAndorian/Verata_head_e.tga")
	pVerata.AddFacialImage("SpeakU", CharacterPaths.g_pcHeadTexPath + "HeadAndorian/Verata_head_u.tga")
	pVerata.SetAnimatedSpeaking(1)

	# Configure for the Generic bridge
	import Guest
	Guest.ConfigureForGeneric(pVerata)

	# Set the default location
	pVerata.SetLocation("GalaxySeated")
	
#	kDebugObj.Print("Finished creating Verata")
	return pVerata
