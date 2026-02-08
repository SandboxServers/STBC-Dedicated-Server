###############################################################################
#	Filename:	Torenn.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads Torenn and configures animations
#	
#	Created:	10/31/00 -	Jess VanDerwalker
###############################################################################

import App
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create Torenn by building his character and placing him on the passed 
#	in set.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating Torenn")

	if (pSet.GetObject("Torenn") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("Torenn")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyFemM/BodyFemM.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadFemRomulan/vlin_head.nif", None)
	pTorenn = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyFemM/BodyFemM.nif", CharacterPaths.g_pcHeadNIFPath + "HeadFemRomulan/femromulan_head.nif")
	pTorenn.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyMaleM/Romulan_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadFemRomulan/vlin_head.tga")

	# Add the character to the set
	pSet.AddObjectToSet(pTorenn, "Torenn")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pTorenn)
	
	# Setup the character configuration
	pTorenn.SetSize(App.CharacterClass.MEDIUM)
	pTorenn.SetGender(App.CharacterClass.MALE)
	pTorenn.SetStanding(1)
	pTorenn.SetRandomAnimationChance(.01)
	pTorenn.SetBlinkChance(0.1)
	pTorenn.SetCharacterName("Torenn")

	pTorenn.AddFacialImage("Blink0", CharacterPaths.g_pcHeadTexPath + "HeadFemRomulan/VLin_head_blink1.tga")
	pTorenn.AddFacialImage("Blink1", CharacterPaths.g_pcHeadTexPath + "HeadFemRomulan/VLin_head_blink2.tga")
	pTorenn.AddFacialImage("Blink2", CharacterPaths.g_pcHeadTexPath + "HeadFemRomulan/VLin_head_eyesclosed.tga")
	pTorenn.SetBlinkStages(3)

	pTorenn.AddFacialImage("SpeakA", CharacterPaths.g_pcHeadTexPath + "HeadFemRomulan/VLin_head_a.tga")
	pTorenn.AddFacialImage("SpeakE", CharacterPaths.g_pcHeadTexPath + "HeadFemRomulan/VLin_head_e.tga")
	pTorenn.AddFacialImage("SpeakU", CharacterPaths.g_pcHeadTexPath + "HeadFemRomulan/VLin_head_u.tga")
	pTorenn.SetAnimatedSpeaking(1)

	# Configure for the Generic bridge
	import Guest
	Guest.ConfigureForGeneric(pTorenn)

	pTorenn.SetLocation("RomulanSeated")

#	kDebugObj.Print("Finished creating Torenn")
	return pTorenn
