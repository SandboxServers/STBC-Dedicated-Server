###############################################################################
#	Filename:	ShipDisplay.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Scripts to create and update the ship display UI.
#	
#	Created:	5/11/2001 -	Erik Novales
###############################################################################

import App
import DamageDisplay
import ShieldsDisplay

# List of children.
TOP_LEFT_BORDER			= 0
TOP_BORDER				= 1
LEFT_SIDE_TOP_END		= 2
LEFT_SIDE_BORDER		= 3
LEFT_SIDE_BOTTOM_END	= 4
RIGHT_SIDE_TOP_END		= 5
RIGHT_SIDE_BORDER		= 6
RIGHT_SIDE_BOTTOM_END	= 7
DAMAGE_DISPLAY			= 8
SHIELDS_DISPLAY			= 9

###############################################################################
#	Create(pDisplay)
#	
#	Fills out the display that's passed in.
#	
#	Args:	pDisplay	- the ship display, ready to be filled in
#	
#	Return:	none
###############################################################################
def Create(pDisplay):
	kFillColor = App.TGColorA()
	kFillColor.SetRGBA(App.g_kSubsystemFillColor.r,
					   App.g_kSubsystemFillColor.g,
					   App.g_kSubsystemFillColor.b,
					   App.g_kSubsystemFillColor.a)
	kEmptyColor = App.TGColorA()
	kEmptyColor.SetRGBA(App.g_kSubsystemEmptyColor.r,
						App.g_kSubsystemEmptyColor.g,
						App.g_kSubsystemEmptyColor.b,
						App.g_kSubsystemEmptyColor.a)
	# Create health gauge.
	pHealthGauge = App.STFillGauge_Create()
	pHealthGauge.SetFillColor(kFillColor)
	pHealthGauge.SetEmptyColor(kEmptyColor)
	pHealthGauge.SetNotVisible(0)
	pDisplay.SetHealthGauge(pHealthGauge)
	pDisplay.AddChild(pHealthGauge, 0.0, 0.0, 0)

	# Create damage display.
	pDamageDisplay = App.DamageDisplay_Create(0.0, 0.0)
	pDamageDisplay.SetSkipParent()
	pDisplay.SetDamageDisplay(pDamageDisplay)
	pDisplay.AddChild(pDamageDisplay, 0.0, 0.0, 0)

	# Create shields display.
	pShieldsDisplay = App.ShieldsDisplay_Create(0.0, 0.0)
	pShieldsDisplay.SetSkipParent()
	pDisplay.SetShieldsDisplay(pShieldsDisplay)
	pDisplay.AddChild(pShieldsDisplay, 0.0, 0.0, 0)

	ResizeUI(pDisplay)
	RepositionUI(pDisplay)

###############################################################################
#	ResizeUI(pDisplay)
#	
#	Resizes the UI.
#	
#	Args:	pDisplay	- the display
#	
#	Return:	none
###############################################################################
def ResizeUI(pDisplay):
	# Get string for LCARS icon group.
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	pDamageDisplay = pDisplay.GetDamageDisplay()
	pShieldsDisplay = pDisplay.GetShieldsDisplay()
	pHealthGauge = pDisplay.GetHealthGauge()

	pInterior = pDisplay.GetInteriorPane()
	pInterior.Resize(LCARS.SHIELDS_DISPLAY_WIDTH, LCARS.SHIELDS_DISPLAY_HEIGHT, 0)

	DamageDisplay.ResizeUI(pDamageDisplay)
	ShieldsDisplay.ResizeUI(pShieldsDisplay)

	# Reset size of display
	fWidth = App.TGUIModule_PixelAlignValue(LCARS.SHIELDS_DISPLAY_WIDTH + pDisplay.GetBorderWidth())
	fHeight = App.TGUIModule_PixelAlignValue(LCARS.SHIELDS_DISPLAY_HEIGHT + pDisplay.GetBorderHeight(), 0)

	pDisplay.SetFixedSize(fWidth, fHeight, 0)

	pHealthGauge.Resize(pDisplay.GetMaximumInteriorWidth(), pDisplay.GetMaximumInteriorHeight() * 0.03, 0)
	pDisplay.InteriorChangedSize()

###############################################################################
#	RepositionUI(pDisplay)
#	
#	Repositions the UI.
#	
#	Args:	pDisplay	- the display
#	
#	Return:	none
###############################################################################
def RepositionUI(pDisplay):
	pDisplay.GetDamageDisplay().RepositionUI()
	ShieldsDisplay.RepositionUI(pDisplay.GetShieldsDisplay())

	pHealthGauge = pDisplay.GetHealthGauge()
	pHealthGauge.SetPosition(0.0, pDisplay.GetMaximumInteriorHeight() - pHealthGauge.GetHeight(), 0)

	pDisplay.InteriorChangedSize()
	pDisplay.Layout()


###############################################################################
#	SetShipID(pDisplay)
#	
#	Sets the ID of the ship in the display.
#	
#	Args:	pDisplay	- the display
#			idNewShip	- the ID of the new ship in the display
#	
#	Return:	none
###############################################################################
def SetShipID(pDisplay, idNewShip):
	# Get the game object.
	pGame = App.Game_GetCurrentGame()

	idShip = pDisplay.GetShipID()
	pShieldsDisplay = pDisplay.GetShieldsDisplay()
	pDamageDisplay = pDisplay.GetDamageDisplay()
	pHealthGauge = pDisplay.GetHealthGauge()

	# If we currently have a valid ship ID, remove events for it.
	if (idShip != App.NULL_ID):
		# Remove display specific events before setting new ShipID.
		pShieldsDisplay.RemoveEvents()
		pDamageDisplay.RemoveEvents()

	# Set new ship ID.
	pDisplay.SetShipIDVar(idNewShip)

	# If valid ship ID.
	if (idNewShip != App.NULL_ID):
		pHealthGauge.SetVisible(0)
	else:
		# No ship.
		pHealthGauge.SetNotVisible(0)

	# Update displays for new ship.
	pShieldsDisplay.UpdateForNewShip()
	pDamageDisplay.UpdateForNewShip()

	pShip = App.ShipClass_Cast(App.TGObject_GetTGObjectPtr(idNewShip))

	if (pShip != None):
		pHealthGauge.SetObject(pShip.GetHull())
	else:
		pHealthGauge.SetObject(pShip)

