###############################################################################
#	Filename:	ShieldsDisplay.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Script to create and update the shield display UI.
#	
#	Created:	5/11/2001 -	Erik Novales
###############################################################################

import App

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print

###############################################################################
#	Create(pDisplay)
#	
#	Fills out the display that's passed in.
#	
#	Args:	pDisplay	- the display
#	
#	Return:	none
###############################################################################
def Create(pDisplay):
	# Get string for LCARS icon group.
	pGraphicsMode = App.GraphicsModeInfo_GetCurrentMode()
	pcLCARS = pGraphicsMode.GetLcarsString()
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	pDisplayPane = App.TGPane_Create(0.0, 0.0)
	pDisplay.AddChild(pDisplayPane, 0.0, 0.0, 0)

	# TOP_PANE:	Add the container top pane for icons
	pTopPane = App.TGPane_Create(0.0, 0.0)
	pDisplayPane.AddChild(pTopPane, 0.0, 0.0, 0)
	pTopPane.SetBatchChildPolys(0)

	##	# TOP_SHIELDS: Add top shields icon
	pTopPane.AddChild(App.TGIcon_Create(pcLCARS, 280), 0.0, 0.0, 0)

	##	# FRONT_SHIELDS: Add front shield
	pTopPane.AddChild(App.TGIcon_Create(pcLCARS, 290), 0.0, 0.0, 0)

	##	# REAR_SHIELDS: Add rear shield
	pTopPane.AddChild(App.TGIcon_Create(pcLCARS, 300), 0.0, 0.0, 0)

	##	# LEFT_SHIELDS: Add left shield
	pTopPane.AddChild(App.TGIcon_Create(pcLCARS, 310), 0.0, 0.0, 0)

	##	# RIGHT_SHIELDS: Add right shield
	pTopPane.AddChild(App.TGIcon_Create(pcLCARS, 320), 0.0, 0.0, 0)

	# SHIP_ICON: Add ship icon centered in pane
	pDisplayPane.AddChild(App.TGIcon_Create("ShipIcons", App.SPECIES_GALAXY), 0.0, 0.0, 0)

	# BOTTOM_PANE: Add the container bottom pane for icons
	pBottomPane = App.TGPane_Create(0.0, 0.0)
	pDisplayPane.AddChild(pBottomPane, 0.0, 0.0, 0)
	pBottomPane.SetBatchChildPolys(0)

	##	# BOTTOM_SHIELDS: Add bottom shields icon
	pBottomPane.AddChild(App.TGIcon_Create(pcLCARS, 280), 0.0, 0.0, 0)

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Ships.tgl")
	# NO_TARGET: The text that says "No Target"
	pNoTarget = App.TGParagraph_CreateW(pDatabase.GetString("No Target"))
	pNoTarget.SetNotVisible()
	pDisplayPane.AddChild(pNoTarget, 0.0, 0.0, 0)

	# UNKNOWN_OBJECT: The text that says "Unknown Object"
	pUnknownObj = App.TGParagraph_CreateW(pDatabase.GetString("Unknown Object"))
	pUnknownObj.SetNotVisible()
	pDisplayPane.AddChild(pUnknownObj, 0.0, 0.0, 0)
	App.g_kLocalizationManager.Unload(pDatabase)

	# Set display pane not visible, until our ship ID is set.
	pDisplayPane.SetNotVisible(0)

	pDisplay.SetNoFocus()

	ResizeUI(pDisplay)
	RepositionUI(pDisplay)


###############################################################################
#	HideShipIcons()
#	
#	Hides the ship icon and associated shield icons
#	
#	Args:	pDisplay	- display that called us
#	
#	Return:	none
###############################################################################
def HideShipIcons(pDisplay):
	# Setup variables
	pDisplayPane = App.TGPane_Cast(pDisplay.GetNthChild(App.ShieldsDisplay.DISPLAY_PANE))

	pTopPane = App.TGPane_Cast(pDisplayPane.GetNthChild(App.ShieldsDisplay.TOP_PANE))
	pBottomPane = App.TGPane_Cast(pDisplayPane.GetNthChild(App.ShieldsDisplay.BOTTOM_PANE))
	pShipIcon = App.TGIcon_Cast(pDisplayPane.GetNthChild(App.ShieldsDisplay.SHIP_ICON))

	pTopShield = App.TGIcon_Cast(pTopPane.GetNthChild(App.ShieldsDisplay.TOP_SHIELDS))
	pFrontShield = App.TGIcon_Cast(pTopPane.GetNthChild(App.ShieldsDisplay.FRONT_SHIELDS))
	pRearShield = App.TGIcon_Cast(pTopPane.GetNthChild(App.ShieldsDisplay.REAR_SHIELDS))
	pLeftShield = App.TGIcon_Cast(pTopPane.GetNthChild(App.ShieldsDisplay.LEFT_SHIELDS))
	pRightShield = App.TGIcon_Cast(pTopPane.GetNthChild(App.ShieldsDisplay.RIGHT_SHIELDS))
	pBottomShield = App.TGIcon_Cast(pBottomPane.GetNthChild(App.ShieldsDisplay.BOTTOM_SHIELDS))

	pShipIcon.SetNotVisible()
	pTopShield.SetNotVisible()
	pBottomShield.SetNotVisible()
	pFrontShield.SetNotVisible()
	pRearShield.SetNotVisible()
	pLeftShield.SetNotVisible()
	pRightShield.SetNotVisible()



###############################################################################
#	ShowShipIcons()
#	
#	Shows the ship icon and associated shield icons
#	
#	Args:	pDisplay	- display that called us
#	
#	Return:	none
###############################################################################
def ShowShipIcons(pDisplay):
	# Setup variables
	pDisplayPane = App.TGPane_Cast(pDisplay.GetNthChild(App.ShieldsDisplay.DISPLAY_PANE))
	pTopPane = App.TGPane_Cast(pDisplayPane.GetNthChild(App.ShieldsDisplay.TOP_PANE))
	pBottomPane = App.TGPane_Cast(pDisplayPane.GetNthChild(App.ShieldsDisplay.BOTTOM_PANE))
	pShipIcon = App.TGIcon_Cast(pDisplayPane.GetNthChild(App.ShieldsDisplay.SHIP_ICON))

	pTopShield = App.TGIcon_Cast(pTopPane.GetNthChild(App.ShieldsDisplay.TOP_SHIELDS))
	pFrontShield = App.TGIcon_Cast(pTopPane.GetNthChild(App.ShieldsDisplay.FRONT_SHIELDS))
	pRearShield = App.TGIcon_Cast(pTopPane.GetNthChild(App.ShieldsDisplay.REAR_SHIELDS))
	pLeftShield = App.TGIcon_Cast(pTopPane.GetNthChild(App.ShieldsDisplay.LEFT_SHIELDS))
	pRightShield = App.TGIcon_Cast(pTopPane.GetNthChild(App.ShieldsDisplay.RIGHT_SHIELDS))
	pBottomShield = App.TGIcon_Cast(pBottomPane.GetNthChild(App.ShieldsDisplay.BOTTOM_SHIELDS))

	# Set everything visible
	pShipIcon.SetVisible()
	pTopShield.SetVisible()
	pBottomShield.SetVisible()
	pFrontShield.SetVisible()
	pRearShield.SetVisible()
	pLeftShield.SetVisible()
	pRightShield.SetVisible()


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

	# Setup all of our variables to point to the icons
	pDisplayPane = App.TGPane_Cast(pDisplay.GetNthChild(App.ShieldsDisplay.DISPLAY_PANE))
	pTopPane = App.TGPane_Cast(pDisplayPane.GetNthChild(App.ShieldsDisplay.TOP_PANE))
	pBottomPane = App.TGPane_Cast(pDisplayPane.GetNthChild(App.ShieldsDisplay.BOTTOM_PANE))
	pShipIcon = App.TGIcon_Cast(pDisplayPane.GetNthChild(App.ShieldsDisplay.SHIP_ICON))
	pNoTarget = App.TGParagraph_Cast(pDisplayPane.GetNthChild(App.ShieldsDisplay.NO_TARGET))
	pUnknownObj = App.TGParagraph_Cast(pDisplayPane.GetNthChild(App.ShieldsDisplay.UNKNOWN_OBJECT))

	pTopShield = App.TGIcon_Cast(pTopPane.GetNthChild(App.ShieldsDisplay.TOP_SHIELDS))
	pFrontShield = App.TGIcon_Cast(pTopPane.GetNthChild(App.ShieldsDisplay.FRONT_SHIELDS))
	pRearShield = App.TGIcon_Cast(pTopPane.GetNthChild(App.ShieldsDisplay.REAR_SHIELDS))
	pLeftShield = App.TGIcon_Cast(pTopPane.GetNthChild(App.ShieldsDisplay.LEFT_SHIELDS))
	pRightShield = App.TGIcon_Cast(pTopPane.GetNthChild(App.ShieldsDisplay.RIGHT_SHIELDS))
	pBottomShield = App.TGIcon_Cast(pBottomPane.GetNthChild(App.ShieldsDisplay.BOTTOM_SHIELDS))

	# Set everything visible
	pShipIcon.SetVisible(0)
	pTopShield.SetVisible(0)
	pBottomShield.SetVisible(0)
	pFrontShield.SetVisible(0)
	pRearShield.SetVisible(0)
	pLeftShield.SetVisible(0)
	pRightShield.SetVisible(0)

	# Size objects
	fWidth = LCARS.SHIELDS_DISPLAY_WIDTH
	fHeight = LCARS.SHIELDS_DISPLAY_HEIGHT

	pDisplay.Resize(fWidth, fHeight, 0)
	pDisplayPane.Resize(fWidth, fHeight, 0)
	pTopPane.Resize(fWidth, fHeight, 0)
	pBottomPane.Resize(fWidth, fHeight, 0)
	pNoTarget.RecalcBounds(0)
	pUnknownObj.RecalcBounds(0)

	# Resize things in case we changed screen res
	pShipIcon.SizeToArtwork(0)
	pTopShield.SizeToArtwork(0)
	pBottomShield.SizeToArtwork(0)
	pFrontShield.SizeToArtwork(0)
	pRearShield.SizeToArtwork(0)
	pLeftShield.SizeToArtwork(0)
	pRightShield.SizeToArtwork(0)

	SetShipIcon(pDisplay)

	pDisplay.Layout()


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
	# Get string for LCARS icon group.
	pMode = App.GraphicsModeInfo_GetCurrentMode()
	LCARS = __import__(pMode.GetLcarsModule())

	# Set up our variables
	pDisplayPane = App.TGPane_Cast(pDisplay.GetNthChild(App.ShieldsDisplay.DISPLAY_PANE))
	pTopPane = App.TGPane_Cast(pDisplayPane.GetNthChild(App.ShieldsDisplay.TOP_PANE))
	pBottomPane = App.TGPane_Cast(pDisplayPane.GetNthChild(App.ShieldsDisplay.BOTTOM_PANE))
	pShipIcon = App.TGIcon_Cast(pDisplayPane.GetNthChild(App.ShieldsDisplay.SHIP_ICON))
	pNoTarget = App.TGParagraph_Cast(pDisplayPane.GetNthChild(App.ShieldsDisplay.NO_TARGET))
	pUnknownObj = App.TGParagraph_Cast(pDisplayPane.GetNthChild(App.ShieldsDisplay.UNKNOWN_OBJECT))

	pTopShield = App.TGIcon_Cast(pTopPane.GetNthChild(App.ShieldsDisplay.TOP_SHIELDS))
	pFrontShield = App.TGIcon_Cast(pTopPane.GetNthChild(App.ShieldsDisplay.FRONT_SHIELDS))
	pRearShield = App.TGIcon_Cast(pTopPane.GetNthChild(App.ShieldsDisplay.REAR_SHIELDS))
	pLeftShield = App.TGIcon_Cast(pTopPane.GetNthChild(App.ShieldsDisplay.LEFT_SHIELDS))
	pRightShield = App.TGIcon_Cast(pTopPane.GetNthChild(App.ShieldsDisplay.RIGHT_SHIELDS))
	pBottomShield = App.TGIcon_Cast(pBottomPane.GetNthChild(App.ShieldsDisplay.BOTTOM_SHIELDS))

	# Set positions
	fWidth = pDisplayPane.GetWidth()
	fHeight = pDisplayPane.GetHeight()
	pTopPane.SetPosition(0.0, 0.0, 0)
	pBottomPane.SetPosition(0.0, 0.0, 0)
	pShipIcon.SetPosition((fWidth - pShipIcon.GetWidth()) / 2.0, 
							(fHeight - pShipIcon.GetHeight()) / 2.0, 0)
	pNoTarget.SetPosition((fWidth - pNoTarget.GetWidth()) / 2.0,
							(fHeight - pNoTarget.GetHeight()) / 2.0, 0)
	pUnknownObj.SetPosition((fWidth - pUnknownObj.GetWidth()) / 2.0,
							(fHeight - pUnknownObj.GetHeight()) / 2.0, 0)

	pTopShield.SetPosition((fWidth - pTopShield.GetWidth()) / 2.0, LCARS.TOP_SHIELD_Y, 0)
	pBottomShield.SetPosition(pTopShield.GetLeft(), LCARS.BOTTOM_SHIELD_Y, 0)
	pFrontShield.SetPosition((fWidth - pFrontShield.GetWidth()) / 2.0, LCARS.FRONT_SHIELD_Y, 0)
	pRearShield.SetPosition((fWidth - pRearShield.GetWidth()) / 2.0, LCARS.REAR_SHIELD_Y, 0)
	pLeftShield.SetPosition(LCARS.SIDE_SHIELDS_X_OFFSET, LCARS.SIDE_SHIELDS_Y, 0)
	pRightShield.SetPosition(pDisplayPane.GetRight() - pRightShield.GetWidth() - LCARS.SIDE_SHIELDS_X_OFFSET + pMode.GetPixelWidth(), LCARS.SIDE_SHIELDS_Y, 0)

	# Set everything visible
	pShipIcon.SetVisible(0)
	pTopShield.SetVisible(0)
	pBottomShield.SetVisible(0)
	pFrontShield.SetVisible(0)
	pRearShield.SetVisible(0)
	pLeftShield.SetVisible(0)
	pRightShield.SetVisible(0)

	SetShipIcon(pDisplay)

	pDisplay.Layout()


###############################################################################
#	SetShipIcon(pDisplay)
#	
#	Sets up the ship icon in the display.
#	
#	Args:	pDisplay	- the display
#	
#	Return:	None
###############################################################################
def SetShipIcon(pDisplay):
	import DamageDisplay

	pGame = App.Game_GetCurrentGame()
	if (pGame == None):
		return

	# our object pointers
	pDisplayPane = App.TGPane_Cast(pDisplay.GetNthChild(App.ShieldsDisplay.DISPLAY_PANE))
	pNoTarget = App.TGParagraph_Cast(pDisplayPane.GetNthChild(App.ShieldsDisplay.NO_TARGET))
	pUnknownObj = App.TGParagraph_Cast(pDisplayPane.GetNthChild(App.ShieldsDisplay.UNKNOWN_OBJECT))

	pNoTarget.SetNotVisible(0)
	pUnknownObj.SetNotVisible(0)

	# Ship display is our conceptual parent
	pParent = App.ShipDisplay_Cast(pDisplay.GetConceptualParent())
	if pParent is None:
		pNoTarget.SetVisible()
		return

	fWidth = pDisplayPane.GetWidth()
	fHeight = pDisplayPane.GetHeight()

	import MissionLib
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer):
		idPlayerTarget = App.NULL_ID
		if (pPlayer.GetTarget()):
			idPlayerTarget = pPlayer.GetTarget().GetObjID()

		idShip = pParent.GetShipID()
		if (idShip == App.NULL_ID):
			HideShipIcons(pDisplay)
			DamageDisplay.HideIcons(pParent.GetDamageDisplay())
			pNoTarget.SetPosition((fWidth - pNoTarget.GetWidth()) / 2.0, 
									(fHeight - pNoTarget.GetHeight()) / 2.0)
			pNoTarget.SetVisible(0)
			pDisplayPane.SetVisible(0)
			pDisplay.Layout()
			return

		elif (idPlayerTarget != App.NULL_ID and idPlayerTarget == idShip):
			if (pPlayer.GetSensorSubsystem().IsObjectKnown(pPlayer.GetTarget()) == 0):
				HideShipIcons(pDisplay)
				DamageDisplay.HideIcons(pParent.GetDamageDisplay())
				pUnknownObj.SetPosition((fWidth - pUnknownObj.GetWidth()) / 2.0, 
										(fHeight - pUnknownObj.GetHeight()) / 2.0)
				pUnknownObj.SetVisible(0)
				pDisplayPane.SetVisible(0)
				pDisplay.Layout()
				return
	else:
		HideShipIcons(pDisplay)
		DamageDisplay.HideIcons(pParent.GetDamageDisplay())
		pNoTarget.SetPosition((fWidth - pNoTarget.GetWidth()) / 2.0, 
								(fHeight - pNoTarget.GetHeight()) / 2.0)
		pDisplayPane.SetVisible(0)
		pNoTarget.SetVisible()
		pDisplay.Layout()

	pSet = pGame.GetPlayerSet()
	pShip = App.ShipClass_GetObjectByID(pSet, pParent.GetShipID())
	if (pShip == None):
		return

	ShowShipIcons(pDisplay)
	DamageDisplay.ShowIcons(pParent.GetDamageDisplay())

	# Get the ship property object.
	pShipProperty = pShip.GetShipProperty()

	# Get the ship's species.
	iSpecies = pShipProperty.GetSpecies()

	# Get old icon and remove it from display pane.
	pOldShipIcon = App.TGIcon_Cast(pDisplayPane.GetNthChild(App.ShieldsDisplay.SHIP_ICON))
	pDisplayPane.DeleteChild(pOldShipIcon)

	# Get new icon for this ship using species number.
	pNewShipIcon = App.TGIcon_Create("ShipIcons", iSpecies)

	# Resize icon, 85% of original.
	pNewShipIcon.Resize(pNewShipIcon.GetWidth() * 0.85, pNewShipIcon.GetHeight() * 0.85, 0)

	# Insert icon into display pane's child list in the same position.
	pDisplayPane.InsertChild(App.ShieldsDisplay.SHIP_ICON, pNewShipIcon,
							 (fWidth - pNewShipIcon.GetWidth()) / 2.0, 
							 (fHeight - pNewShipIcon.GetHeight()) / 2.0)
