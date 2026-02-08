###############################################################################
#	Filename:	WeaponsDisplay.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Script to create, resize, and reposition the UI for the weapons display.
#	
#	Created:	5/14/2001 -	Erik Novales
###############################################################################

import App

dTORP_X_BIAS		= {	
						640:	1,
						800:	1,
						1024:	2,
						1280:	3,
						1600:	3
					  }
dTORP_Y_BIAS		= {
						640:	-7,
						800:	-7,
						1024:	-7,
						1280:	-7,
						1600:	-7
					  }
dPHASER_X_BIAS		= {
						640:	1,
						800:	1,
						1024:	2,
						1280:	3,
						1600:	3
					  }
dPHASER_Y_BIAS		= {
						640:	-8,
						800:	-8,
						1024:	-8,
						1280:	-8,
						1600:	-8
					  }

###############################################################################
#	Create(pDisplay)
#	
#	Fills in the display.
#	
#	Args:	pDisplay	- the weapons display
#			fWidth		- Width of the interior of the display
#			fHeight		- Height of the interior of the display.
#	
#	Return:	none
###############################################################################
def Create(pDisplay, fWidth, fHeight):
	# Get string for LCARS icon group.
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	pDisplay.KillChildren()

	# Create display pane, where the ship info is displayed.
	pDisplayPane = App.TGPane_Create(fWidth, fHeight)

	# Add display pane as our first child.
	pDisplay.AddChild(pDisplayPane, 0.0, 0.0, 0)

	# Photon icons go into their own pane.
	pTorpedoPane = CreateTorpedoPane(fWidth, fHeight, pDisplay.GetShipID())
	pTorpedoPane.SetBatchChildPolys()
	pDisplayPane.AddChild(pTorpedoPane, 0.0, 0.0, 0)

	# Create phaser and disruptor panes.
	# Get the ship associated with this weapon display.
	pShip = App.ShipClass_GetObjectByID(None, pDisplay.GetShipID())
	pPhasers = None
	pDisruptors = None

	if (pShip != None):
		pPhasers = pShip.GetPhaserSystem()
		pDisruptors = pShip.GetPulseWeaponSystem()

	(pUPhaser, pUPhaserInd, pLPhaser, pLPhaserInd) = CreateEnergyWeaponPanes(pPhasers, fWidth, fHeight)
	(pUDisruptor, pUDisruptorInd, pLDisruptor, pLDisruptorInd) = CreateEnergyWeaponPanes(pDisruptors, fWidth, fHeight)

	pDisplayPane.AddChild(pUPhaser, 0.0, 0.0, 0)
	pDisplayPane.AddChild(pUPhaserInd, 0.0, 0.0, 0)
	pDisplayPane.AddChild(pUDisruptor, 0.0, 0.0, 0)
	pDisplayPane.AddChild(pUDisruptorInd, 0.0, 0.0, 0)

	# Add ship icon centered in pane.
	# This is temporarily using the galaxy icon until the actual ship icon is set.
	pShipIcon = App.TGIcon_Create("ShipIcons", App.SPECIES_GALAXY)
	pDisplayPane.AddChild(pShipIcon, (pDisplay.GetWidth() / 2.0) - (pShipIcon.GetWidth() / 2.0),
			(pDisplay.GetHeight() / 2.0) - (pShipIcon.GetHeight() / 2.0), 0)

	# Add lower weapon panes
	pDisplayPane.AddChild(pLPhaserInd, 0.0, 0.0, 0)
	pDisplayPane.AddChild(pLPhaser, 0.0, 0.0, 0)
	pDisplayPane.AddChild(pLDisruptorInd, 0.0, 0.0, 0)
	pDisplayPane.AddChild(pLDisruptor, 0.0, 0.0, 0)

	pDisplay.SetNoFocus()
	pDisplay.SetAlwaysHandleEvents()

	pDisplay.InteriorChangedSize()
	pDisplay.Layout()

	pDisplay.SetFixedSize(LCARS.WEAPONS_PANE_WIDTH + pDisplay.GetBorderWidth(), 
						  LCARS.WEAPONS_PANE_HEIGHT + pDisplay.GetBorderHeight(), 0)

	# Set display pane not visible, until our ship ID is set
	pDisplayPane.SetNotVisible(0)

	ResizeUI(pDisplay)
	RepositionUI(pDisplay)


###############################################################################
#	ResizeUI(pDisplay)
#	
#	Resizes the UI.
#	
#	Args:	pDisplay	- the weapons display
#	
#	Return:	none
###############################################################################
def ResizeUI(pDisplay):
	bWasMinimized = pDisplay.IsMinimized()

	if bWasMinimized:
		pDisplay.SetNotMinimized()

	pName = pDisplay.GetNameParagraph()
	if pName:
		pName.SetFontGroup(App.g_kFontManager.GetFontGroup("Crillee", 5.0))

	# Get string for LCARS icon group.
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	# Resize display pane, where the ship info is displayed.
	pDisplayPane = App.TGPane_Cast(pDisplay.GetNthChild(App.WeaponsDisplay.DISPLAY_PANE))
	pDisplayPane.Resize(LCARS.WEAPONS_PANE_WIDTH, LCARS.WEAPONS_PANE_HEIGHT, 0)

	pDisplay.SetFixedSize(LCARS.WEAPONS_PANE_WIDTH + pDisplay.GetBorderWidth(), 
						  LCARS.WEAPONS_PANE_HEIGHT + pDisplay.GetBorderHeight(), 0)
	pDisplay.InteriorChangedSize()
	pDisplay.Layout()

	# Photon icons go into their own pane.
	pTorpedoPane = App.TGPane_Cast(pDisplayPane.GetNthChild(App.WeaponsDisplay.TORPEDO_PANE))
	ResizeTorpedoPane(pTorpedoPane)

	# Resize phaser and disruptor panes.
	pUPhaser = App.TGPane_Cast(pDisplayPane.GetNthChild(App.WeaponsDisplay.UPPER_PHASER_PANE))
	pUPhaserInd = App.TGPane_Cast(pDisplayPane.GetNthChild(App.WeaponsDisplay.UPPER_PHASER_INDICATOR_PANE))
	pLPhaser = App.TGPane_Cast(pDisplayPane.GetNthChild(App.WeaponsDisplay.LOWER_PHASER_PANE))
	pLPhaserInd = App.TGPane_Cast(pDisplayPane.GetNthChild(App.WeaponsDisplay.LOWER_PHASER_INDICATOR_PANE))
	pUDisruptor = App.TGPane_Cast(pDisplayPane.GetNthChild(App.WeaponsDisplay.UPPER_DISRUPTOR_PANE))
	pUDisruptorInd = App.TGPane_Cast(pDisplayPane.GetNthChild(App.WeaponsDisplay.UPPER_DISRUPTOR_INDICATOR_PANE))
	pLDisruptor = App.TGPane_Cast(pDisplayPane.GetNthChild(App.WeaponsDisplay.LOWER_DISRUPTOR_PANE))
	pLDisruptorInd = App.TGPane_Cast(pDisplayPane.GetNthChild(App.WeaponsDisplay.LOWER_DISRUPTOR_INDICATOR_PANE))

	ResizeEnergyWeaponPanes(pUPhaser, pUPhaserInd, pLPhaser, pLPhaserInd)
	ResizeEnergyWeaponPanes(pUDisruptor, pUDisruptorInd, pLDisruptor, pLDisruptorInd)

	SetShipIcon(pDisplay)

	pDisplay.InteriorChangedSize()

	if bWasMinimized:
		pDisplay.SetMinimized()

###############################################################################
#	RepositionUI(pDisplay)
#	
#	Repositions the UI.
#	
#	Args:	pDisplay	- the weapons display
#	
#	Return:	none
###############################################################################
def RepositionUI(pDisplay):
	bWasMinimized = pDisplay.IsMinimized()

	if bWasMinimized:
		pDisplay.SetNotMinimized()

	# Get string for LCARS icon group.
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	# Reposition display pane, where the ship info is displayed.
	pDisplayPane = App.TGPane_Cast(pDisplay.GetNthChild(App.WeaponsDisplay.DISPLAY_PANE))
	pDisplayPane.SetPosition(0.0, 0.0, 0)

	# Photon icons go into their own pane.
	pTorpedoPane = App.TGPane_Cast(pDisplayPane.GetNthChild(App.WeaponsDisplay.TORPEDO_PANE))
	pTorpedoPane.SetPosition(0.0, 0.0, 0)
	RepositionTorpedoPane(pTorpedoPane)

	# Reposition phaser and disruptor panes.
	pUPhaser = App.TGPane_Cast(pDisplayPane.GetNthChild(App.WeaponsDisplay.UPPER_PHASER_PANE))
	pUPhaserInd = App.TGPane_Cast(pDisplayPane.GetNthChild(App.WeaponsDisplay.UPPER_PHASER_INDICATOR_PANE))
	pLPhaser = App.TGPane_Cast(pDisplayPane.GetNthChild(App.WeaponsDisplay.LOWER_PHASER_PANE))
	pLPhaserInd = App.TGPane_Cast(pDisplayPane.GetNthChild(App.WeaponsDisplay.LOWER_PHASER_INDICATOR_PANE))
	pUDisruptor = App.TGPane_Cast(pDisplayPane.GetNthChild(App.WeaponsDisplay.UPPER_DISRUPTOR_PANE))
	pUDisruptorInd = App.TGPane_Cast(pDisplayPane.GetNthChild(App.WeaponsDisplay.UPPER_DISRUPTOR_INDICATOR_PANE))
	pLDisruptor = App.TGPane_Cast(pDisplayPane.GetNthChild(App.WeaponsDisplay.LOWER_DISRUPTOR_PANE))
	pLDisruptorInd = App.TGPane_Cast(pDisplayPane.GetNthChild(App.WeaponsDisplay.LOWER_DISRUPTOR_INDICATOR_PANE))

	pUPhaser.SetPosition(0.0, 0.0, 0)
	pUPhaserInd.SetPosition(0.0, 0.0, 0)
	pLPhaser.SetPosition(0.0, 0.0, 0)
	pLPhaserInd.SetPosition(0.0, 0.0, 0)
	pUDisruptor.SetPosition(0.0, 0.0, 0)
	pUDisruptorInd.SetPosition(0.0, 0.0, 0)
	pLDisruptor.SetPosition(0.0, 0.0, 0)
	pLDisruptorInd.SetPosition(0.0, 0.0, 0)

	idShip = pDisplay.GetShipID()
	pShip = App.ShipClass_GetObjectByID(App.SetClass_GetNull(), idShip)
	pPhasers = None
	pDisruptors = None

	if (pShip != None):
		pPhasers = pShip.GetPhaserSystem()
		pDisruptors = pShip.GetPulseWeaponSystem()

	RepositionEnergyWeaponPanes(pPhasers, pUPhaser, pUPhaserInd, pLPhaser, pLPhaserInd)
	RepositionEnergyWeaponPanes(pDisruptors, pUDisruptor, pUDisruptorInd, pLDisruptor, pLDisruptorInd)

	SetShipIcon(pDisplay)

	pDisplay.Layout()
	pDisplay.InteriorChangedSize()
	pDisplay.Layout()

	if bWasMinimized:
		pDisplay.SetMinimized()

###############################################################################
#	CreateTorpedoPane(pDisplay)
#	
#	Creates the torpedo pane for the weapons display.
#	
#	Args:	fWidth	- Width of our parent display
#			fHeight	- Height of our parent display
#			idShip	- ID of the ship we're associated with.
#	
#	Return:	none
###############################################################################
def CreateTorpedoPane(fWidth, fHeight, idShip):
	# Get graphics mode.
	pGraphicsMode = App.GraphicsModeInfo_GetCurrentMode()

	pTorpedoPane = App.TGPane_Create(fWidth, fHeight)

	# Get the ship associated with this weapon display.
	pShip = App.ShipClass_GetObjectByID(None, idShip)

	# If there's no ship, we can bail now.
	if (pShip == None):
		return(pTorpedoPane)

	# Get the ship's torpedo system.
	pTorpedoSystem = pShip.GetTorpedoSystem()

	if (pTorpedoSystem == None):
		return(pTorpedoPane)

	# Iterate over each of the torpedo tubes.
	for i in range(pTorpedoSystem.GetNumChildSubsystems()):
		pChild = pTorpedoSystem.GetChildSubsystem(i)
		if (pChild == None):
			continue

		# Get the property associated with this weapon. It'll
		# have the necessary placement information.
		pProp = App.WeaponProperty_Cast(pChild.GetProperty())
		if (pProp == None):
			continue

		# The icon positions are based off of 640x480 screen resolution.
		fPosX = (pProp.GetIconPositionX() + dTORP_X_BIAS[pGraphicsMode.GetWidth()]) / pGraphicsMode.GetWidth()
		fPosY = (pProp.GetIconPositionY() + dTORP_Y_BIAS[pGraphicsMode.GetWidth()]) / pGraphicsMode.GetHeight()

		# Add the icon for this torpedo tube.
		pTorpedoIcon = App.TGIcon_Create("WeaponIcons", pProp.GetIconNum())
		pTorpedoPane.AddChild(pTorpedoIcon, fPosX, fPosY, 0)

	return(pTorpedoPane)

###############################################################################
#	ResizeTorpedoPane(pPane)
#	
#	Resizes the items in the torpedo pane.
#	
#	Args:	pPane	- the torpedo pane
#	
#	Return:	none
###############################################################################
def ResizeTorpedoPane(pPane):
	pParent = App.TGPane_Cast(pPane.GetParent())
	pDisplay = App.WeaponsDisplay_Cast(pParent.GetConceptualParent())
	pPane.Resize(pParent.GetWidth(), pParent.GetHeight(), 0)

	# Get the ship associated with this weapon display.
	pShip = App.ShipClass_GetObjectByID(App.SetClass_GetNull(), pDisplay.GetShipID())

	# If there's no ship, we can bail now.
	if (pShip == None):
		return

	# Get the ship's torpedo system.
	pTorpedoSystem = pShip.GetTorpedoSystem()

	if (pTorpedoSystem == None):
		return

	# Iterate over each of the torpedo tubes.
	for i in range(pTorpedoSystem.GetNumChildSubsystems()):
		pTubeIcon = App.TGIcon_Cast(pPane.GetNthChild(i))
		if (pTubeIcon != None):
			pTubeIcon.SizeToArtwork()

###############################################################################
#	RepositionTorpedoPane(pPane)
#	
#	Repositions the items in the torpedo pane.
#	
#	Args:	pPane	- the torpedo pane
#	
#	Return:	none
###############################################################################
def RepositionTorpedoPane(pPane):
	# Get graphics mode.
	pGraphicsMode = App.GraphicsModeInfo_GetCurrentMode()

	pParent = App.TGPane_Cast(pPane.GetParent())
	pDisplay = App.WeaponsDisplay_Cast(pParent.GetConceptualParent())

	# Get the ship associated with this weapon display.
	pShip = App.ShipClass_GetObjectByID(App.SetClass_GetNull(), pDisplay.GetShipID())

	# If there's no ship, we can bail now.
	if (pShip == None):
		return

	# Get the ship's torpedo system.
	pTorpedoSystem = pShip.GetTorpedoSystem()

	if (pTorpedoSystem == None):
		return

	# Iterate over each of the torpedo tubes.
	for i in range(pTorpedoSystem.GetNumChildSubsystems()):
		pChild = pTorpedoSystem.GetChildSubsystem(i)
		if (pChild == None):
			continue

		# Get the property associated with this weapon. It'll
		# have the necessary placement information.
		pProp = App.WeaponProperty_Cast(pChild.GetProperty())
		if (pProp == None):
			continue

		pTubeIcon = pPane.GetNthChild(i)

		# The icon positions are based off of 640x480 screen resolution.
		fPosX = (pProp.GetIconPositionX() + dTORP_X_BIAS[pGraphicsMode.GetWidth()]) / pGraphicsMode.GetWidth()
		fPosY = (pProp.GetIconPositionY() + dTORP_Y_BIAS[pGraphicsMode.GetWidth()]) / pGraphicsMode.GetHeight()

		# Reposition the icon for this torpedo tube.
		pTubeIcon.SetPosition(fPosX, fPosY, 0)

###############################################################################
#	CreateEnergyWeaponPanes()
#	
#	Creates the panes for an energy weapon system.  We create four panes 
#	to be the upper weapon, upper weapon indicator, lower weapon and lower
#	weapon indicators.
#	
#	Args:	pSystem		- the weapon system
#			fWidth		- the width of the panes to create
#			fHeight		- the height of the panes to create
#	
#	Return:	TGPane (pUpper, pUpperInd, pLower, pLowerInd)
###############################################################################
def CreateEnergyWeaponPanes(pSystem, fWidth, fHeight):
	pUpper = App.TGPane_Create(fWidth, fHeight)
	pUpperInd = App.TGPane_Create(fWidth, fHeight)
	pLower = App.TGPane_Create(fWidth, fHeight)
	pLowerInd = App.TGPane_Create(fWidth, fHeight)

	pUpper.SetBatchChildPolys(0)
	pUpperInd.SetBatchChildPolys(0)
	pLower.SetBatchChildPolys(0)
	pLowerInd.SetBatchChildPolys(0)

	if (pSystem == None):
		return(pUpper, pUpperInd, pLower, pLowerInd)

	# Iterate over each of the phasers.
	for i in range(pSystem.GetNumChildSubsystems()):
		pChild = pSystem.GetChildSubsystem(i)
		if (pChild == None):
			continue

		# Get the property associated with this weapon. It'll
		# have the necessary placement information.
		pProp = App.EnergyWeaponProperty_Cast(pChild.GetProperty())
		if (pProp == None):
			continue

		if (pProp.IsIconAboveShip() == 1):
			pIconPane = pUpper
			pIconPaneInd = pUpperInd
		else:
			pIconPane = pLower
			pIconPaneInd = pLowerInd

		# Add the icon for this weapon.
		pWeaponIcon = App.TGIcon_Create("WeaponIcons", pProp.GetIconNum())
		pIconPane.AddChild(pWeaponIcon, 0.0, 0.0, 0)

		# Add the firing field icon for this weapon.
		pFieldIcon = App.TGIcon_Create("WeaponIcons", pProp.GetIndicatorIconNum())
		pIconPaneInd.AddChild(pFieldIcon, 0.0, 0.0, 0)

	return (pUpper, pUpperInd, pLower, pLowerInd)

###############################################################################
#	ResizeEnergyWeaponPanes()
#	
#	Resizes the items in the energy weapon panes.
#	
#	Args:	pUpperPane		- the upper pane
#			pUpperIndPane	- the upper indicator pane
#			pLowerPane		- the lower pane
#			pLowerIndPane	- the lower indicator pane
#	
#	Return:	none
###############################################################################
def ResizeEnergyWeaponPanes(pUpperPane, pUpperIndPane, pLowerPane, pLowerIndPane):
	pParent = pUpperPane.GetParent()

	pUpperPane.Resize(pParent.GetWidth(), pParent.GetHeight(), 0)
	pUpperIndPane.Resize(pParent.GetWidth(), pParent.GetHeight(), 0)
	pLowerPane.Resize(pParent.GetWidth(), pParent.GetHeight(), 0)
	pLowerIndPane.Resize(pParent.GetWidth(), pParent.GetHeight(), 0)

	for pPane in [pUpperPane, pUpperIndPane, pLowerPane, pLowerIndPane]:
		for i in range(pPane.GetNumChildren()):
			pIcon = App.TGIcon_Cast(pPane.GetNthChild(i))
			if (pIcon != None):
				pIcon.SizeToArtwork()

	pUpperPane.Layout()
	pUpperIndPane.Layout()
	pLowerPane.Layout()
	pLowerIndPane.Layout()

###############################################################################
#	RepositionEnergyWeaponPanes()
#	
#	Repositions the items in the energy weapon panes.
#	
#	Args:	pSystem			- the weapon system
#			pUpperPane		- the upper pane
#			pUpperIndPane	- the upper indicator pane
#			pLowerPane		- the lower pane
#			pLowerIndPane	- the lower incicator pane
#	
#	Return:	None
###############################################################################
def RepositionEnergyWeaponPanes(pSystem, pUpperPane, pUpperIndPane,
								pLowerPane, pLowerIndPane):
	# Get graphics mode.
	pGraphicsMode = App.GraphicsModeInfo_GetCurrentMode()

	pParent = App.TGPane_Cast(pUpperPane.GetParent())
	pDisplay = App.WeaponsDisplay_Cast(pParent.GetConceptualParent())
	# Get the ship associated with this weapon display.
	pShip = App.ShipClass_GetObjectByID(App.SetClass_GetNull(), pDisplay.GetShipID())

	# Only iterate over the system if the ship and system exist
	if (pShip and pSystem):
		iUpperCount = 0
		iLowerCount = 0
		# Iterate over each of the phasers.
		for i in range(pSystem.GetNumChildSubsystems()):
			pChild = pSystem.GetChildSubsystem(i)
			if (pChild == None):
				continue

			# Get the property associated with this weapon. It'll
			# have the necessary placement information.
			pProp = App.EnergyWeaponProperty_Cast(pChild.GetProperty())
			if (pProp == None):
				continue

			pIcon = None
			pIndicator = None

			if (pProp.IsIconAboveShip() == 1):
				pIcon = pUpperPane.GetNthChild(iUpperCount)
				pIndicator = pUpperIndPane.GetNthChild(iUpperCount)
				iUpperCount = iUpperCount + 1
			else:
				pIcon = pLowerPane.GetNthChild(iLowerCount)
				pIndicator = pLowerIndPane.GetNthChild(iLowerCount)
				iLowerCount = iLowerCount + 1

			# The icon positions are based off of the 640x480 screen shot.
			fPosX = (pProp.GetIconPositionX() + dPHASER_X_BIAS[pGraphicsMode.GetWidth()]) / pGraphicsMode.GetWidth()
			fPosY = (pProp.GetIconPositionY() + dPHASER_Y_BIAS[pGraphicsMode.GetWidth()]) / pGraphicsMode.GetHeight()

			# Reposition the icon for this weapon.
			pIcon.SetPosition(fPosX, fPosY, 0)

			fPosX = (pProp.GetIndicatorIconPositionX() + dPHASER_X_BIAS[pGraphicsMode.GetWidth()]) / pGraphicsMode.GetWidth()
			fPosY = (pProp.GetIndicatorIconPositionY() + dPHASER_Y_BIAS[pGraphicsMode.GetWidth()]) / pGraphicsMode.GetHeight()

			# Add the firing field icon for this weapon.
			pIndicator.SetPosition(fPosX, fPosY, 0)

	pUpperPane.Layout()
	pUpperIndPane.Layout()
	pLowerPane.Layout()
	pLowerIndPane.Layout()

###############################################################################
#	SetShipIcon(pDisplay)
#	
#	Sets the ship icon used in the display.
#	
#	Args:	pDisplay	- the display
#	
#	Return:	none
###############################################################################
def SetShipIcon(pDisplay):
	# Get string for LCARS icon group.
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	# Get the game object, so we can get the player's set.
	pGame = App.Game_GetCurrentGame()
	if (pGame == None):
			return

	# Get the player's set.
	pSet = pGame.GetPlayerSet()

	# Get the ship object from the set.
	pShip = App.ShipClass_GetObjectByID(pSet, pDisplay.GetShipID())

	# Get display pane.
	pDisplayPane = App.TGPane_Cast(pDisplay.GetNthChild(App.WeaponsDisplay.DISPLAY_PANE))

	# Get old icon and remove it.
	pOldShipIcon = App.TGIcon_Cast(pDisplayPane.GetNthChild(App.WeaponsDisplay.SHIP_ICON))
	pDisplayPane.DeleteChild(pOldShipIcon)

	if (pShip == None):
		# Add ship icon centered in pane.
		# This is temporarily using the galaxy icon until the actual ship icon is set.
		pNewShipIcon = App.TGIcon_Create("ShipIcons", App.SPECIES_GALAXY)
		pDisplayPane.InsertChild(App.WeaponsDisplay.SHIP_ICON, pNewShipIcon, 
				(pDisplay.GetWidth() / 2.0) - (pNewShipIcon.GetWidth() / 2.0),
				(pDisplay.GetHeight() / 2.0) - (pNewShipIcon.GetHeight() / 2.0), 0)
	else:
		# Get the ship property object.
		pShipProperty = pShip.GetShipProperty()

		# Get the ship's species.
		iSpecies = pShipProperty.GetSpecies()

		# Get new icon for this ship using species number.
		pNewShipIcon = App.TGIcon_Create("ShipIcons", iSpecies)

		# Resize icon, 60% of original.
		pNewShipIcon.Resize(pNewShipIcon.GetWidth() * 0.6, pNewShipIcon.GetHeight() * 0.6)

		# Insert icon into our child list in the same position.
		pDisplayPane.InsertChild(App.WeaponsDisplay.SHIP_ICON, pNewShipIcon, (pDisplay.GetWidth() / 2.0) - 
									(pNewShipIcon.GetWidth() / 2.0), (pDisplay.GetHeight() / 2.0) -
									(pNewShipIcon.GetHeight() / 2.0))

