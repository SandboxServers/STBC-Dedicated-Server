###############################################################################
#	Filename:	Takahara.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads Soji Takahara and configures animations
#	
#	Created:	11/2/00 -	Jess VanDerwalker
###############################################################################

import App
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create Takahara by building his character and placing him on the passed in set.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating Soji Takahara")

	if (pSet.GetObject("Takahara") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("Takahara")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadMiguel/takahara_head.nif", None)
	pTakahara = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", CharacterPaths.g_pcHeadNIFPath + "HeadMiguel/miguel_head.nif")
	pTakahara.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyMaleM/FedCivilian_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/takahara_head.tga")

	# Add the character to the set
	pSet.AddObjectToSet(pTakahara, "Takahara")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pTakahara)
	
	# Setup the character configuration
	pTakahara.SetSize(App.CharacterClass.MEDIUM)
	pTakahara.SetGender(App.CharacterClass.MALE)
	pTakahara.SetStanding(1)
	pTakahara.SetRandomAnimationChance(.01)
	pTakahara.SetBlinkChance(0.1)
	pTakahara.SetCharacterName("Takahara")

	pTakahara.AddFacialImage("Blink0", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Takahara_head_blink1.tga")
	pTakahara.AddFacialImage("Blink1", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Takahara_head_blink2.tga")
	pTakahara.AddFacialImage("Blink2", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Takahara_head_eyesclosed.tga")
	pTakahara.SetBlinkStages(3)

	pTakahara.AddFacialImage("SpeakA", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Takahara_head_a.tga")
	pTakahara.AddFacialImage("SpeakE", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Takahara_head_e.tga")
	pTakahara.AddFacialImage("SpeakU", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Takahara_head_u.tga")
	pTakahara.SetAnimatedSpeaking(1)

	# Configure for the Generic bridge
	import Guest
	Guest.ConfigureForGeneric(pTakahara)

	# Set his default location
	pTakahara.SetLocation("GalaxyEngSeated")
		
#	kDebugObj.Print("Finished creating Dr. Takahara")
	return pTakahara
