###############################################################################
#	Filename:	RadarScope.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Script to create and update the radar scope UI.
#	
#	Created:	5/25/2001 -	KDeus
###############################################################################

import App

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print

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
	pDisplay.SetNoFocus()

	# Get string for LCARS icon group.
	pcLCARS = App.GraphicsModeInfo_GetCurrentMode().GetLcarsString()
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	# Shrunken ship icon is first.
	pDisplay.AddChild( pDisplay.CreateShipIcon() )

	pDisplay.AddChild(App.TGIcon_Create(pcLCARS, 900))

	# Bracket pane.
	pDisplay.AddChild( App.TGPane_Create( pDisplay.GetWidth(), pDisplay.GetHeight() ) )

	# Target bracket.
	pTargetBracket = App.RadarBlip_Create(pcLCARS, 430)
	pDisplay.SetTargetBracket( pTargetBracket )
	pDisplay.AddChild(pTargetBracket)

	# Blip pane.
	pDisplay.AddChild( App.TGPane_Create( pDisplay.GetWidth(), pDisplay.GetHeight() ) )

	# Phaser line pane.
	pDisplay.AddChild( App.TGPane_Create( pDisplay.GetWidth(), pDisplay.GetHeight() ) )

	# Background pane.
	pDisplay.AddChild( CreateBackgroundPane(pDisplay) )

	ResizeUI(pDisplay)
	RepositionUI(pDisplay)

###############################################################################
#	ResizeUI
#	
#	Resizes the UI for the radar scope
#	
#	Args:	pScope	- the radar scope
#	
#	Return:	None
###############################################################################
def ResizeUI(pRadarScope):
	# Get string for LCARS icon group.
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	# Resize radar scope object.
	pRadarScope.Resize(LCARS.RADAR_SCOPE_WIDTH, LCARS.RADAR_SCOPE_HEIGHT, 0)

	# Resize the ship icon.
	pShipIcon = App.TGIcon_Cast(pRadarScope.GetNthChild(App.RadarScope.SHIP_ICON))
	pShipIcon.SizeToArtwork()
	pShipIcon.Resize(pShipIcon.GetWidth() * 0.15, pShipIcon.GetHeight() * 0.15)

	pRadarIcon = App.TGIcon_Cast(pRadarScope.GetNthChild(App.RadarScope.RADAR_RING))
	pRadarIcon.SizeToArtwork()
	pRadarIcon.Resize(pRadarIcon.GetWidth() * 0.2, pRadarIcon.GetHeight() * 0.2)

	# Resize the bracket pane.
	pBracketPane = App.TGPane_Cast(pRadarScope.GetNthChild(App.RadarScope.BRACKET_PANE))
	pBracketPane.Resize( pRadarScope.GetWidth(), pRadarScope.GetHeight(), 0 )

	# Size the blip pane and all the blips.
	pBlipPane = App.TGPane_Cast(pRadarScope.GetNthChild(App.RadarScope.BLIP_PANE))
	pBlipPane.Resize( pRadarScope.GetWidth(), pRadarScope.GetHeight(), 0 )
	for i in range(pBlipPane.GetNumChildren()):
		pBlip = App.TGIcon_Cast(pBlipPane.GetNthChild(i))
		pBlip.SizeToArtwork()

	# Resize the phaser line pane.
	pPhaserLinePane = App.TGPane_Cast(pRadarScope.GetNthChild(App.RadarScope.PHASER_LINE_PANE))
	pPhaserLinePane.Resize( pRadarScope.GetWidth(), pRadarScope.GetHeight(), 0 )

	# Resize background pane.
	pBackgroundPane = App.TGPane_Cast(pRadarScope.GetNthChild(App.RadarScope.BACKGROUND_PANE))
	pBackgroundPane.Resize(pRadarScope.GetWidth(), pRadarScope.GetHeight(), 0)

	ResizeBackgroundPane(pBackgroundPane)

###############################################################################
#	RepositionUI
#	
#	Repositions the UI for the radar scope.
#	
#	Args:	pRadarScope		- The radar scope.
#	
#	Return:	none
###############################################################################
def RepositionUI(pRadarScope):
	# Get string for LCARS icon group.
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	# Reposition the ship icon.
	pShipIcon = App.TGIcon_Cast(pRadarScope.GetNthChild(App.RadarScope.SHIP_ICON))
	pShipIcon.SetPosition((pRadarScope.GetWidth() / 2.0) - (pShipIcon.GetWidth() / 2.0),
						  (pRadarScope.GetHeight() / 2.0) - (pShipIcon.GetHeight() / 2.0), 0)

	pRadarIcon = App.TGIcon_Cast(pRadarScope.GetNthChild(App.RadarScope.RADAR_RING))
	pRadarIcon.SetPosition((pRadarScope.GetWidth() / 2.0) - (pRadarIcon.GetWidth() / 2.0),
						  (pRadarScope.GetHeight() / 2.0) - (pRadarIcon.GetHeight() / 2.0), 0)

	# Reposition background pane.
	pBackgroundPane = App.TGPane_Cast(pRadarScope.GetNthChild(App.RadarScope.BACKGROUND_PANE))
	RepositionBackgroundPane(pBackgroundPane)

	pRadarScope.Layout()


###############################################################################
#	CreateBackgroundPane(pDisplay)
#	
#	Creates the background pane for the radar display.
#	
#	Args:	pDisplay	- the display
#	
#	Return:	none
###############################################################################
def CreateBackgroundPane(pDisplay):
	# Get string for LCARS icon group.
	pcLCARS = App.GraphicsModeInfo_GetCurrentMode().GetLcarsString()
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	pBackgroundPane = App.TGPane_Create()

	for pChild in (
		App.TGIcon_Create(pcLCARS, 10, App.globals.g_kRadarBorder), # Radar circle Top Left
		App.TGIcon_Create(pcLCARS, 20, App.globals.g_kRadarBorder), # Radar circle Top Right
		App.TGIcon_Create(pcLCARS, 30, App.globals.g_kRadarBorder), # Radar circle Bottom Left
		App.TGIcon_Create(pcLCARS, 40, App.globals.g_kRadarBorder), # Radar circle Bottom Right
		):

		pBackgroundPane.AddChild( pChild, 0.0, 0.0, 0 )

	pBackgroundPane.SetNoFocus()
	return(pBackgroundPane)

def GetChildren(pPane):
	lChildren = []
	pChild = pPane.GetFirstChild()
	while pChild:
		lChildren.append(pChild)
		pChild = pPane.GetNextChild(pChild)
	return lChildren

###############################################################################
#	ResizeBackgroundPane(pPane)
#	
#	Resizes the items in the background pane.
#	
#	Args:	pPane	- the background pane
#	
#	Return:	none
###############################################################################
def ResizeBackgroundPane(pPane):
	# Get string for LCARS icon group.
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	# Get the pieces.
	pRadarBkgTL, pRadarBkgTR, pRadarBkgBL, pRadarBkgBR = GetChildren(pPane)

	# Resize all of them.
	pRadarBkgTL.Resize(LCARS.RADAR_SCOPE_WIDTH / 2.0, LCARS.RADAR_SCOPE_HEIGHT / 2.0, 0)
	pRadarBkgTR.Resize(LCARS.RADAR_SCOPE_WIDTH / 2.0, LCARS.RADAR_SCOPE_HEIGHT / 2.0, 0)
	pRadarBkgBL.Resize(LCARS.RADAR_SCOPE_WIDTH / 2.0, LCARS.RADAR_SCOPE_HEIGHT / 2.0, 0)
	pRadarBkgBR.Resize(LCARS.RADAR_SCOPE_WIDTH / 2.0, LCARS.RADAR_SCOPE_HEIGHT / 2.0, 0)

###############################################################################
#	RepositionBackgroundPane(pPane)
#	
#	Repositions the items in the background pane.
#	
#	Args:	pPane	- the pane
#	
#	Return:	none
###############################################################################
def RepositionBackgroundPane(pPane):
	# Get string for LCARS icon group.
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	# Get the pieces.
	pRadarBkgTL, pRadarBkgTR, pRadarBkgBL, pRadarBkgBR = GetChildren(pPane)

	pRadarBkgTL.SetPosition(0.0, 0.0, 0)
	pRadarBkgTR.SetPosition(pRadarBkgTL.GetRight(), pRadarBkgTL.GetTop(), 0)
	pRadarBkgBL.SetPosition(0.0, pRadarBkgTL.GetBottom(), 0)
	pRadarBkgBR.SetPosition(pRadarBkgBL.GetRight(), pRadarBkgTR.GetBottom(), 0)

