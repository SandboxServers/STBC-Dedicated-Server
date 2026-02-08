###############################################################################
#	Filename:	Kessok.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads Kessok, and configures animations
#	
#	Created:	9/13/00 -	Matthew Kagle
###############################################################################

import App
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create Kessok by building his character and placing him on the passed in set.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating Kessok")

	if (pSet.GetObject("Kessok") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("Kessok")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyKessok/BodyKessok.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadKessok/kessok_head.nif", None)
	pKessok = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyKessok/BodyKessok.nif", CharacterPaths.g_pcHeadNIFPath + "HeadKessok/kessok_head.nif")
	pKessok.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyKessok/kessok_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadKessok/kessok_head.tga")

	# Add the character to the set
	pSet.AddObjectToSet(pKessok, "Kessok")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pKessok)
	
	# Setup the character configuration
	pKessok.SetSize(App.CharacterClass.MEDIUM)
	pKessok.SetGender(App.CharacterClass.MALE)
	pKessok.SetStanding(1)
	pKessok.SetRandomAnimationChance (.01)
	pKessok.SetBlinkChance(0.1)
	pKessok.SetCharacterName("Kessok")

	# Configure for the Generic bridge
	import Guest
	Guest.ConfigureForGeneric(pKessok)

	pKessok.SetLocation("KessokSeated")

#	kDebugObj.Print("Finished creating Kessok")
	return pKessok
