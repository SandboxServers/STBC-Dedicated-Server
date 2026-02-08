###############################################################################
#	Filename:	Yi.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads Captain Jae Yi, and configures animations
#	
#	Created:	11/27/00 -	Jess VanDerwalker
###############################################################################

import App
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create Yi by building his character and placing him on the passed in set.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating Captain Yi")

	if (pSet.GetObject("Yi") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("Yi")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadData/data_head.nif", None)
	pYi = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", CharacterPaths.g_pcHeadNIFPath + "HeadData/data_head.nif")
	pYi.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyMaleM/FedRed_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadData/yi_head.tga")

	# Add the character to the set
	pSet.AddObjectToSet(pYi, "Yi")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pYi)
	
	# Setup the character configuration
	pYi.SetSize(App.CharacterClass.MEDIUM)
	pYi.SetGender(App.CharacterClass.MALE)
	pYi.SetStanding(1)
	pYi.SetRandomAnimationChance(.01)
	pYi.SetBlinkChance(0.1)
	pYi.SetCharacterName("Yi")

	pYi.AddFacialImage("Blink0", CharacterPaths.g_pcHeadTexPath + "HeadData/Yi_head_blink1.tga")
	pYi.AddFacialImage("Blink1", CharacterPaths.g_pcHeadTexPath + "HeadData/Yi_head_blink2.tga")
	pYi.AddFacialImage("Blink2", CharacterPaths.g_pcHeadTexPath + "HeadData/Yi_head_eyesclosed.tga")
	pYi.SetBlinkStages(3)

	pYi.AddFacialImage("SpeakA", CharacterPaths.g_pcHeadTexPath + "HeadData/Yi_head_a.tga")
	pYi.AddFacialImage("SpeakE", CharacterPaths.g_pcHeadTexPath + "HeadData/Yi_head_e.tga")
	pYi.AddFacialImage("SpeakU", CharacterPaths.g_pcHeadTexPath + "HeadData/Yi_head_u.tga")
	pYi.SetAnimatedSpeaking(1)

	# Configure for the Generic bridge
	import Guest
	Guest.ConfigureForGeneric(pYi)
	pYi.SetLocation("GalaxySeated")
#	kDebugObj.Print("Finished creating Captain Yi")
	return pYi