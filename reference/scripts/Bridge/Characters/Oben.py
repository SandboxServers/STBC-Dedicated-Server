###############################################################################
#	Filename:	Oben.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads Gul Oben, and sets up meta animations.
#	
#	Created:	9/13/00 -	Matthew Kagle
###############################################################################

import App
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create Oben by building her character and placing her on the passed in set.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating Gul Oben")

	if (pSet.GetObject("Oben") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("Oben")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyCardassian/BodyCardassian.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadCard/cardassian_head.nif", None)
	pOben = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyCardassian/BodyCardassian.nif", CharacterPaths.g_pcHeadNIFPath + "HeadCard/cardassian_head.nif")
	pOben.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyCardassian/Cardassian_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadCard/oben_head.tga")

	# Add the character to the set
	pSet.AddObjectToSet(pOben, "Oben")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pOben)
	
	# Setup the character configuration
	pOben.SetSize(App.CharacterClass.MEDIUM)
	pOben.SetGender(App.CharacterClass.MALE)
	pOben.SetStanding(1)
	pOben.SetRandomAnimationChance(.01)
	pOben.SetCharacterName("Oben")

	pOben.AddFacialImage("Blink0", CharacterPaths.g_pcHeadTexPath + "HeadCard/Oben_head_blink1.tga")
	pOben.AddFacialImage("Blink1", CharacterPaths.g_pcHeadTexPath + "HeadCard/Oben_head_blink2.tga")
	pOben.AddFacialImage("Blink2", CharacterPaths.g_pcHeadTexPath + "HeadCard/Oben_head_eyesclosed.tga")
	pOben.SetBlinkStages(3)

	pOben.AddFacialImage("SpeakA", CharacterPaths.g_pcHeadTexPath + "HeadCard/Oben_head_a.tga")
	pOben.AddFacialImage("SpeakE", CharacterPaths.g_pcHeadTexPath + "HeadCard/Oben_head_e.tga")
	pOben.AddFacialImage("SpeakU", CharacterPaths.g_pcHeadTexPath + "HeadCard/Oben_head_u.tga")
	pOben.SetAnimatedSpeaking(1)

	# Configure for the Generic bridge
	import Guest
	Guest.ConfigureForGeneric(pOben)

	pOben.SetLocation("CardassianSeated")

#	kDebugObj.Print("Finished creating Oben")
	return pOben
