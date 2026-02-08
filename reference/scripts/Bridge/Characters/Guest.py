###############################################################################
#	Filename:	Guest.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Functions to configure a Guest character
#	
#	Created:	9/15/00 -	DLitwin
###############################################################################

import App

#kDebugObj = App.CPyDebug()


###############################################################################
#	ConfigureForGeneric()
#
#	Configure ourselves for a Generic bridge
#
#	Args:	pGuest	- our Character object
#
#	Return:	none
###############################################################################
def ConfigureForGeneric(pGuest):
	# Clear out any old animations from another configuration
	pGuest.ClearAnimations()

	# Register animation mappings

	pGuest.SetLocation("")

###############################################################################
#	ConfigureForSovereignM()
#
#	Configure ourselves for a Generic bridge
#
#	Args:	pGraff	- our Character object
#
#	Return:	none
###############################################################################
def ConfigureForSovereignM(pGuest):
	# First set up as generic, which clears out any pre-existing configurations
	ConfigureForGeneric(pGuest)

	pGuest.AddAnimation("PlaceX",		"Bridge.Characters.MediumAnimations.EBPlaceAtX")
	pGuest.AddAnimation("SeatedX",		"Bridge.Characters.CommonAnimations.SeatedM")
	pGuest.AddAnimation("StandingX1",	"Bridge.Characters.CommonAnimations.Standing")
	pGuest.AddAnimation("XBreathe",		"Bridge.Characters.CommonAnimations.SeatedM")

	pGuest.AddAnimation("L1ToX",		"Bridge.Characters.MediumAnimations.EBMoveFromL1ToX")
	pGuest.AddAnimation("XToL1",		"Bridge.Characters.MediumAnimations.EBMoveFromXToL1")
	pGuest.AddAnimation("XToX1",		"Bridge.Characters.MediumAnimations.EBMoveFromXToX1")
	pGuest.AddAnimation("X1ToX",		"Bridge.Characters.MediumAnimations.EBMoveFromX1ToX")
	pGuest.AddAnimation("XTurnCaptain",	"Bridge.Characters.MediumAnimations.EBTurnAtXTowardsCaptain")
	pGuest.AddAnimation("X1TurnCaptain","Bridge.Characters.CommonAnimations.LookRight")
#	pGuest.AddAnimation("X1TurnCaptain","Bridge.Characters.MediumAnimations.EBTurnAtX1TowardsCaptain")
	pGuest.AddAnimation("XBack",		"Bridge.Characters.CommonAnimations.SeatedM")
	pGuest.AddAnimation("X1Back",		"Bridge.Characters.CommonAnimations.Standing")
#	pGuest.AddAnimation("X1Back",		"Bridge.Characters.MediumAnimations.EBTurnBackAtX1FromCaptain")
