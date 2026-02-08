###############################################################################
#	Filename:	Zeiss.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads Captain Zeiss, and sets up meta animations.
#	
#	Created:	11/01/00 -	Matthew Kagle
###############################################################################

import App
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create Zeiss by building her character and placing her on the passed in set.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating Captain Zeiss")

	if (pSet.GetObject("Zeiss") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("Zeiss")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyFemM/BodyFemM.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadFem3/fem3_head.nif", None)
	pZeiss = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyFemM/BodyFemM.nif", CharacterPaths.g_pcHeadNIFPath + "HeadFem3/fem3_head.nif")
	pZeiss.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyFemS/FedFemRed_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadFem3/zeiss_head.tga")

	# Add the character to the set
	pSet.AddObjectToSet(pZeiss, "Zeiss")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pZeiss)
	
	# Setup the character configuration
	pZeiss.SetSize(App.CharacterClass.MEDIUM)
	pZeiss.SetGender(App.CharacterClass.FEMALE)
	pZeiss.SetStanding(1)
	pZeiss.SetRandomAnimationChance(.01)
	pZeiss.SetBlinkChance(0.1)
	pZeiss.SetCharacterName("Zeiss")

	pZeiss.AddFacialImage("Blink0", CharacterPaths.g_pcHeadTexPath + "HeadFem3/Zeiss_head_blink1.tga")
	pZeiss.AddFacialImage("Blink1", CharacterPaths.g_pcHeadTexPath + "HeadFem3/Zeiss_head_blink2.tga")
	pZeiss.AddFacialImage("Blink2", CharacterPaths.g_pcHeadTexPath + "HeadFem3/Zeiss_head_eyesclosed.tga")
	pZeiss.SetBlinkStages(3)

	pZeiss.AddFacialImage("SpeakA", CharacterPaths.g_pcHeadTexPath + "HeadFem3/Zeiss_head_a.tga")
	pZeiss.AddFacialImage("SpeakE", CharacterPaths.g_pcHeadTexPath + "HeadFem3/Zeiss_head_e.tga")
	pZeiss.AddFacialImage("SpeakU", CharacterPaths.g_pcHeadTexPath + "HeadFem3/Zeiss_head_u.tga")
	pZeiss.SetAnimatedSpeaking(1)

	# Configure for the Generic bridge
	import Guest
	Guest.ConfigureForGeneric(pZeiss)

	pZeiss.SetLocation("GalaxySeated")
#	kDebugObj.Print("Finished creating Zeiss")
	return pZeiss
