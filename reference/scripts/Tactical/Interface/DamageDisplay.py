###############################################################################
#	Filename:	DamageDisplay.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Script to create and update the damage display UI.
#	
#	Created:	5/11/2001 -	Erik Novales
###############################################################################

import App

###############################################################################
#	ResizeUI(pDisplay)
#	
#	Resizes the display.
#	
#	Args:	pDisplay	- the damage display
#	
#	Return:	None
###############################################################################
def ResizeUI(pDisplay):
	# Get string for LCARS icon group.
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	# Size ourselves
	pDisplay.Resize(LCARS.DAMAGE_DISPLAY_WIDTH, LCARS.DAMAGE_DISPLAY_HEIGHT, 0)

	for i in range(pDisplay.GetNumChildren()):
		pIcon = App.TGIcon_Cast(pDisplay.GetNthChild(i))
		if pIcon:
			pIcon.SizeToArtwork(0)

			pDamageIcon = App.DamageIcon_Cast(pIcon)
			if pDamageIcon:
				pDamageIcon.ResetPosition()

###############################################################################
#	HideIcons(pDisplay)
#	
#	Hides the damage icons.
#	
#	Args:	pDisplay	- the display
#	
#	Return:	none
###############################################################################
def HideIcons(pDisplay):
	pDisplay.SetNotVisible()

###############################################################################
#	ShowIcons(pDisplay)
#	
#	Shows the damage icons.
#	
#	Args:	pDisplay	- the display
#	
#	Return:	none
###############################################################################
def ShowIcons(pDisplay):
	pDisplay.SetVisible()
