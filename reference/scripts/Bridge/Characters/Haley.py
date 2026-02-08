###############################################################################
#	Filename:	Haley.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads Captain Haley, and configures animations
#	
#	Created:	7/25/00 -	Matthew Kagle
###############################################################################

import App
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create Haley by building his character and placing him on the passed in set.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating Haley")

	if (pSet.GetObject("Haley") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("Haley")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyFemM/BodyFemM.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadFem3/fem3_head.nif", None)
	pHaley = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyFemM/BodyFemM.nif", CharacterPaths.g_pcHeadNIFPath + "HeadFem3/fem3_head.nif")
	pHaley.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyFemS/FedFemRed_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadFem3/haley_head.tga")

	# Add the character to the set
	pSet.AddObjectToSet(pHaley, "Haley")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pHaley)
	
	# Setup the character configuration
	pHaley.SetSize(App.CharacterClass.MEDIUM)
	pHaley.SetGender(App.CharacterClass.FEMALE)
	pHaley.SetStanding(1)
	pHaley.SetRandomAnimationChance(.01)
	pHaley.SetBlinkChance(0.1)
	pHaley.SetCharacterName("Haley")

	pHaley.AddFacialImage("Blink0", CharacterPaths.g_pcHeadTexPath + "HeadFem3/Haley_head_blink1.tga")
	pHaley.AddFacialImage("Blink1", CharacterPaths.g_pcHeadTexPath + "HeadFem3/Haley_head_blink2.tga")
	pHaley.AddFacialImage("Blink2", CharacterPaths.g_pcHeadTexPath + "HeadFem3/Haley_head_eyesclosed.tga")
	pHaley.SetBlinkStages(3)

	pHaley.AddFacialImage("SpeakA", CharacterPaths.g_pcHeadTexPath + "HeadFem3/Haley_head_a.tga")
	pHaley.AddFacialImage("SpeakE", CharacterPaths.g_pcHeadTexPath + "HeadFem3/Haley_head_e.tga")
	pHaley.AddFacialImage("SpeakU", CharacterPaths.g_pcHeadTexPath + "HeadFem3/Haley_head_u.tga")
	pHaley.SetAnimatedSpeaking(1)

	# Configure for the Generic bridge
	import Guest
	Guest.ConfigureForGeneric(pHaley)

	pHaley.SetLocation("GalaxySeated")

#	kDebugObj.Print("Finished creating Captain Haley")
	return pHaley
