###############################################################################
#	Filename:	Martin.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads Captain Joshua Martin and configures animations
#	
#	Created:	12/5/00 -	Jess VanDerwalker
###############################################################################

import App
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create Captain Joshua Martin by building his character and placing
#	her on the passed in set.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating Captain Joshua Martin")

	if (pSet.GetObject("Martin") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("Martin")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadMiguel/martin_head.nif", None)
	pMartin = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyMaleM/BodyMaleM.nif", CharacterPaths.g_pcHeadNIFPath + "HeadMiguel/miguel_head.nif")
	pMartin.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyMaleM/FedRed_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/martin_head.tga")

	# Add the character to the set
	pSet.AddObjectToSet(pMartin, "Martin")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pMartin)
	
	# Setup the character configuration
	pMartin.SetSize(App.CharacterClass.MEDIUM)
	pMartin.SetGender(App.CharacterClass.MALE)
	pMartin.SetStanding(1)
	pMartin.SetRandomAnimationChance(.01)
	pMartin.SetCharacterName("Martin")

	pMartin.AddFacialImage("Blink0", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Martin_head_blink1.tga")
	pMartin.AddFacialImage("Blink1", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Martin_head_blink2.tga")
	pMartin.AddFacialImage("Blink2", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Martin_head_eyesclosed.tga")
	pMartin.SetBlinkStages(3)

	pMartin.AddFacialImage("SpeakA", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Martin_head_a.tga")
	pMartin.AddFacialImage("SpeakE", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Martin_head_e.tga")
	pMartin.AddFacialImage("SpeakU", CharacterPaths.g_pcHeadTexPath + "HeadMiguel/Martin_head_u.tga")
	pMartin.SetAnimatedSpeaking(1)

	# Configure for the Generic bridge
	import Guest
	Guest.ConfigureForGeneric(pMartin)
	pMartin.SetLocation("SovereignSeated")
#	kDebugObj.Print("Finished creating Captain Joshua Martin")
	return pMartin
