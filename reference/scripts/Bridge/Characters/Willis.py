###############################################################################
#	Filename:	Willis.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads Commander Willis, and configures animations
#	
#	Created:	11/27/00 -	Jess VanDerwalker
###############################################################################

import App
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create Willis by building his character and placing him on the passed in set.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating Commander Willis")

	if (pSet.GetObject("Willis") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("Willis")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadPicard/picard_head.nif", None)
	pWillis = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", CharacterPaths.g_pcHeadNIFPath + "HeadPicard/picard_head.nif")
	pWillis.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyMaleM/FedGold_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadPicard/willis_head.tga")

	# Add the character to the set
	pSet.AddObjectToSet(pWillis, "Willis")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pWillis)
	
	# Setup the character configuration
	pWillis.SetSize(App.CharacterClass.MEDIUM)
	pWillis.SetGender(App.CharacterClass.MALE)
	pWillis.SetStanding(1)
	pWillis.SetRandomAnimationChance(.01)
	pWillis.SetBlinkChance(0.1)
	pWillis.SetCharacterName("Willis")

	pWillis.AddFacialImage("Blink0", CharacterPaths.g_pcHeadTexPath + "HeadPicard/Willis_head_blink1.tga")
	pWillis.AddFacialImage("Blink1", CharacterPaths.g_pcHeadTexPath + "HeadPicard/Willis_head_blink2.tga")
	pWillis.AddFacialImage("Blink2", CharacterPaths.g_pcHeadTexPath + "HeadPicard/Willis_head_eyesclosed.tga")
	pWillis.SetBlinkStages(3)

	pWillis.AddFacialImage("SpeakA", CharacterPaths.g_pcHeadTexPath + "HeadPicard/Willis_head_a.tga")
	pWillis.AddFacialImage("SpeakE", CharacterPaths.g_pcHeadTexPath + "HeadPicard/Willis_head_e.tga")
	pWillis.AddFacialImage("SpeakU", CharacterPaths.g_pcHeadTexPath + "HeadPicard/Willis_head_u.tga")
	pWillis.SetAnimatedSpeaking(1)

	# Configure for the Generic bridge
	import Guest
	Guest.ConfigureForGeneric(pWillis)
	pWillis.SetLocation("DBGuest")
#	kDebugObj.Print("Finished creating Commander Willis")
	return pWillis