###############################################################################
#	Filename:	Kartok.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads Kartok, and configures animations
#	
#	Created:	3/15/01 -	Matthew Kagle
###############################################################################

import App
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create Kartok by building his character and placing him on the passed in set.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating Kartok")

	if (pSet.GetObject("Kartok") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("Kartok")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyKlingon/BodyKlingon.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadKlingon/klingon_head.nif", None)
	pKartok = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyKlingon/BodyKlingon.nif", CharacterPaths.g_pcHeadNIFPath + "HeadKlingon/klingon_head.nif")
	pKartok.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyKlingon/Klingon_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadKlingon/Kartok_head.tga")

	# Add the character to the set
	pSet.AddObjectToSet(pKartok, "Kartok")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pKartok)
	
	# Setup the character configuration
	pKartok.SetSize(App.CharacterClass.MEDIUM)
	pKartok.SetGender(App.CharacterClass.MALE)
	pKartok.SetStanding(1)
	pKartok.SetRandomAnimationChance (.01)
	pKartok.SetBlinkChance(0.1)
	pKartok.SetCharacterName("Kartok")

	pKartok.AddFacialImage("Blink0", CharacterPaths.g_pcHeadTexPath + "HeadKlingon/Kartok_head_blink1.tga")
	pKartok.AddFacialImage("Blink1", CharacterPaths.g_pcHeadTexPath + "HeadKlingon/Kartok_head_blink2.tga")
	pKartok.AddFacialImage("Blink2", CharacterPaths.g_pcHeadTexPath + "HeadKlingon/Kartok_head_eyesclosed.tga")
	pKartok.SetBlinkStages(3)

	pKartok.AddFacialImage("SpeakA", CharacterPaths.g_pcHeadTexPath + "HeadKlingon/Kartok_head_a.tga")
	pKartok.AddFacialImage("SpeakE", CharacterPaths.g_pcHeadTexPath + "HeadKlingon/Kartok_head_e.tga")
	pKartok.AddFacialImage("SpeakU", CharacterPaths.g_pcHeadTexPath + "HeadKlingon/Kartok_head_u.tga")
	pKartok.SetAnimatedSpeaking(1)

	# Configure for the Generic bridge
	import Guest
	Guest.ConfigureForGeneric(pKartok)

	pKartok.SetLocation("KlingonSeated")

#	kDebugObj.Print("Finished creating Kartok")
	return pKartok
