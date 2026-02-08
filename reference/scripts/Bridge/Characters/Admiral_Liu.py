###############################################################################
#	Filename:	Admiral_Liu.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Loads Admiral Liu and configures animations
#	
#	Created:	7/25/00 -	Colin Carley
###############################################################################

import App
import CharacterPaths

#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateCharacter()
#
#	Create Liu by building her character and placing her on the passed in set.
#
#	Args:	pSet	- the Set in which to place ourselves
#
#	Return:	none
###############################################################################
def CreateCharacter(pSet):
#	kDebugObj.Print("Creating Admiral Liu")

	if (pSet.GetObject("Liu") != None):
		return(App.CharacterClass_Cast(pSet.GetObject("Liu")))

	CharacterPaths.UpdatePaths()
	# Create the character
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcBodyNIFPath + "BodyFemM/BodyFemM.nif", "Bip01")
	App.g_kModelManager.LoadModel(CharacterPaths.g_pcHeadNIFPath + "HeadLiu/liu_head.nif", None)
	pLiu = App.CharacterClass_Create(CharacterPaths.g_pcBodyNIFPath + "BodyFemM/BodyFemM.nif", CharacterPaths.g_pcHeadNIFPath + "HeadLiu/liu_head.nif")
	pLiu.ReplaceBodyAndHead(CharacterPaths.g_pcBodyTexPath + "BodyFemS/FedFemRed_body.tga", CharacterPaths.g_pcHeadTexPath + "HeadLiu/liu_head.tga")

	# Add the character to the set
	pSet.AddObjectToSet(pLiu, "Liu")
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pLiu)
	
	# Setup the character configuration
	pLiu.SetSize(App.CharacterClass.MEDIUM)
	pLiu.SetGender(App.CharacterClass.FEMALE)
	pLiu.SetStanding(1)
	pLiu.SetRandomAnimationChance(.01)
	pLiu.SetBlinkChance(0.1)

	pLiu.SetCharacterName("Liu")
	pLiu.SetDatabase("data/TGL/Bridge Crew General.tgl")

	# Configure for the Generic bridge
	import Guest
	Guest.ConfigureForGeneric(pLiu)

	pLiu.AddFacialImage("Blink0", CharacterPaths.g_pcHeadTexPath + "HeadLiu/Liu_head_blink1.tga")
	pLiu.AddFacialImage("Blink1", CharacterPaths.g_pcHeadTexPath + "HeadLiu/Liu_head_blink2.tga")
	pLiu.AddFacialImage("Blink2", CharacterPaths.g_pcHeadTexPath + "HeadLiu/Liu_head_eyes_closed.tga")
	pLiu.SetBlinkStages(3)

	pLiu.AddFacialImage("SpeakA", CharacterPaths.g_pcHeadTexPath + "HeadLiu/liu_head_a.tga")
	pLiu.AddFacialImage("SpeakE", CharacterPaths.g_pcHeadTexPath + "HeadLiu/liu_head_e.tga")
	pLiu.AddFacialImage("SpeakU", CharacterPaths.g_pcHeadTexPath + "HeadLiu/liu_head_u.tga")
	pLiu.SetAnimatedSpeaking(1)

	pLiu.AddAnimation("StarbaseSeatedGlanceLeft", "Bridge.Characters.CommonAnimations.GlanceLeft")
	pLiu.AddAnimation("StarbaseSeatedGlanceAwayLeft", __name__ + ".Breathing")

	pLiu.SetLocation("StarbaseSeated")

#	kDebugObj.Print("Finished creating Admiral Liu")
	return pLiu



###############################################################################
#	Breathing()
#	
#	The starbase breathing animation
#	
#	Args:	pCharacter	- character that wants to breathe
#	
#	Return:	pSeuqence	- generated sequence
###############################################################################
def Breathing(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/StarbaseSeated01breathing.nif", "StarbaseSeated01breathing")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pAnimNode = pCharacter.GetAnimNode()
	pAction = App.TGAnimAction_Create(pAnimNode, "StarbaseSeated01breathing", 0, 0)
	pSequence.AddAction(pAction)
	return pSequence
