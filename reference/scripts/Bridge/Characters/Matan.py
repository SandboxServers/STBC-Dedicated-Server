###############################################################################
#	Filename:	Matan.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads Matan, and configures animations
#	
#	Created:	9/13/00 -	Matthew Kagle
###############################################################################

import App
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create Matan by building his character and placing him on the passed in set.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating Admiral Matan")

	if (pSet.GetObject("Matan") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("Matan")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyCardassian/BodyCardassian.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadCard/cardassian_head.nif", None)
	pMatan = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyCardassian/BodyCardassian.nif", CharacterPaths.g_pcHeadNIFPath + "HeadCard/cardassian_head.nif")
	pMatan.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyCardassian/Cardassian_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadCard/matan_head.tga")

	# Add the character to the set
	pSet.AddObjectToSet(pMatan, "Matan")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pMatan)
	
	# Setup the character configuration
	pMatan.SetSize(App.CharacterClass.MEDIUM)
	pMatan.SetGender(App.CharacterClass.MALE)
	pMatan.SetStanding(1)
	pMatan.SetRandomAnimationChance(.01)
	pMatan.SetCharacterName("Matan")

	pMatan.AddFacialImage("Blink0", CharacterPaths.g_pcHeadTexPath + "HeadCard/Matan_head_blink1.tga")
	pMatan.AddFacialImage("Blink1", CharacterPaths.g_pcHeadTexPath + "HeadCard/Matan_head_blink2.tga")
	pMatan.AddFacialImage("Blink2", CharacterPaths.g_pcHeadTexPath + "HeadCard/Matan_head_eyesclosed.tga")
	pMatan.SetBlinkStages(3)

	pMatan.AddFacialImage("SpeakA", CharacterPaths.g_pcHeadTexPath + "HeadCard/Matan_head_a.tga")
	pMatan.AddFacialImage("SpeakE", CharacterPaths.g_pcHeadTexPath + "HeadCard/Matan_head_e.tga")
	pMatan.AddFacialImage("SpeakU", CharacterPaths.g_pcHeadTexPath + "HeadCard/Matan_head_u.tga")
	pMatan.SetAnimatedSpeaking(1)

	# Configure for the Generic bridge
	import Guest
	Guest.ConfigureForGeneric(pMatan)

	pMatan.SetLocation("CardassianSeated")

#	kDebugObj.Print("Finished creating Matan")
	return pMatan
