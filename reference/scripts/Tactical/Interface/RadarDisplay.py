###############################################################################
#	Filename:	RadarDisplay.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Script to create and update the radar display UI.
#	
#	Created:	5/13/2001 -	Erik Novales
###############################################################################

import App

###############################################################################
#	Create(pDisplay)
#	
#	Fills in the display.
#	
#	Args:	pDisplay	- the radar display
#	
#	Return:	none
###############################################################################
def Create(pDisplay):
	# Get string for LCARS icon group.
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	# Set the title of this display...
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pDisplay.SetName( pDatabase.GetString("RadarLabel") )
	App.g_kLocalizationManager.Unload(pDatabase)

	# Create radar scope object.
	pRadarScope = App.RadarScope_Create(LCARS.RADAR_SCOPE_WIDTH, 
										LCARS.RADAR_SCOPE_HEIGHT)

	# Add it as next child.
	pDisplay.AddChild(pRadarScope, 0.0, 0.0, 0)

	# Set our colors.
	pDisplay.SetColorBasedOnFlags()

	ResizeUI(pDisplay)
	RepositionUI(pDisplay)
	pDisplay.InteriorChangedSize(1)

###############################################################################
#	ResizeUI(pDisplay)
#	
#	Resizes the UI for the radar display.
#	
#	Args:	pDisplay	- the display
#	
#	Return:	
###############################################################################
def ResizeUI(pDisplay):
	pRadarScope = App.TGPane_Cast(pDisplay.GetNthChild(App.RadarDisplay.RADAR_SCOPE))
	import RadarScope
	RadarScope.ResizeUI(pRadarScope)

###############################################################################
#	RepositionUI(pDisplay)
#	
#	Repositions the UI for the radar display.
#	
#	Args:	pDisplay	- the display
#	
#	Return:	none
###############################################################################
def RepositionUI(pDisplay):
	pRadarScope = App.TGPane_Cast(pDisplay.GetNthChild(App.RadarDisplay.RADAR_SCOPE))
	import RadarScope
	RadarScope.RepositionUI(pRadarScope)

	pDisplay.InteriorChangedSize()
	pDisplay.Layout()
