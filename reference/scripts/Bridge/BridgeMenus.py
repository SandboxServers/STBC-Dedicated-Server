###############################################################################
#	Filename:	BridgeMenus.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	
#	
#	Created:	4/8/01 -	DLitwin (added header)
###############################################################################
import App

###############################################################################
#	Initialize()
#	
#	Clean out the bridge window so its menus can be rebuilt
#	
#	Args:	
#	
#	Return:	
###############################################################################
def Initialize(pWindow):
	App.iNumFires = 0

	# Find the Bridge window
	topWindow = App.TopWindow_GetTopWindow()
	pBridge = App.BridgeWindow_Cast(topWindow.FindMainWindow(App.MWT_BRIDGE))

	# Kill children at start so we can reload this script in game.
	pBridge.KillChildren()


###############################################################################
#	CreateBridgeMenuButton()
#	
#	Create bridge menu button given name and event type.
#	
#	Args:	pcName	- name of button to create
#			eType	- EventType for it to send
#	
#	Return:			- bridge button
###############################################################################
def CreateBridgeMenuButton(pcName, eType):
	topWindow = App.TopWindow_GetTopWindow()
	pEvent = App.TGEvent_Create()
	pEvent.SetEventType(eType)
	pEvent.SetDestination(topWindow)
	pBridgeMenuButton = App.STButton_CreateW(pcName, pEvent)
	return pBridgeMenuButton


###############################################################################
#	CreateCommunicateButton()
#	
#	Create Communicate button given name and object for destination
#	
#	Args:	pcName	- name of button to create
#			pTarget	- object to be destination of button's ET_COMMUNICATE
#	
#	Return:	pButton	- created button
###############################################################################
def CreateCommunicateButton(pcName, pTarget):
	pEvent = App.TGStringEvent_Create()
	pEvent.SetEventType(App.ET_COMMUNICATE)
	pEvent.SetString(pcName)
	pEvent.SetDestination(pTarget)

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pButton = App.STButton_CreateW(pDatabase.GetString("Report"), pEvent)
	App.g_kLocalizationManager.Unload(pDatabase)

	return pButton


###############################################################################
#	ButtonClicked()
#	
#	Handler for a bridge click.  Depends on fTurnState
#	
#	Args:	pObject	- unused
#			pEvent	- unused
#	
#	Return:	None
###############################################################################
def ButtonClicked(pObject, pEvent):
	fTurnState = App.g_kVarManager.GetFloatVariable("global", "fTurnState")
	pSet = App.g_kSetManager.GetSet("bridge")

	iLineNumber = App.g_kSystemWrapper.GetRandomNumber(4) + 1

	if (fTurnState == 1):
		pTempObject = App.CharacterClass_GetObject(pSet, "Tactical")
#		pTempObject.SayLine('FelixYes' +str(iLineNumber))
	elif (fTurnState == 2):
		pTempObject = App.CharacterClass_GetObject(pSet, "Helm")
#		pTempObject.SayLine('KiskaYes' +str(iLineNumber))
	elif (fTurnState == 3):
		pTempObject = App.CharacterClass_GetObject(pSet, "XO")	
#		pTempObject.SayLine('SaffiYes' +str(iLineNumber))
	elif (fTurnState == 4):
		pTempObject = App.CharacterClass_GetObject(pSet, "Science")
#		pTempObject.SayLine('MiguelYes' +str(iLineNumber))
	elif (fTurnState == 5):
		pTempObject = App.CharacterClass_GetObject(pSet, "Engineer")
#		pTempObject.SayLine('BrexYes' +str(iLineNumber))
	else:
		return

	# Turn the character back.
	pTempObject.TurnBack()


###############################################################################
#	FindMenu()
#	
#	Finds a particular character's menu
#	
#	Args:	pDatabase	- Database which holds the name
#			pcName		- name of the character's menu
#	
#	Return:	pMenu	- the resulting menu
###############################################################################
def FindMenu(pDatabase, pcName):
	kName = pDatabase.GetString(pcName)
	kMenuName = pDatabase.GetString(pcName)

	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	for iPane in range(pTacticalControlWindow.GetNumChildren()):
		pPane = App.TGPane_Cast(pTacticalControlWindow.GetNthChild(iPane))

		iNumChildren = pPane.GetNumChildren()
		for i in range(iNumChildren):
			pMenu = App.STTopLevelMenu_Cast(pPane.GetNthChild(i))
			if (pMenu != None):
				pMenu.GetName(kMenuName)
				if (kName.Compare(kMenuName) == 0):
					return pMenu
			pNextPane = App.TGPane_Cast(pPane.GetNthChild(i))
			if (pNextPane != None):
				pMenu = App.STTopLevelMenu_Cast(pNextPane.GetNthChild(0))
				if (pMenu != None):
					pMenu.GetName(kMenuName)
					if (kName.Compare(kMenuName) == 0):
						return pMenu

#	print(kName.GetCString() + " - Unable to find menu")
	return App.STTopLevelMenu_CreateNull()


###############################################################################
#	CreateBlankCharacterMenu()
#	
#	Creates a blank character menu
#	
#	Args:	kName	- TGString to use as title of menu, usually comes from a
#						TGL database
#			fWidth	- width of the menu
#			fHeight	- height of the menu
#			fXPos	- the X position on the screen
#			fYPos	- the Y position on the screen
#	
#	Return:	pMenu	- the newly created menu
###############################################################################
def CreateBlankCharacterMenu(kName, fWidth, fHeight, fXPos, fYPos):
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	
	pMenu = App.STTopLevelMenu_CreateW(kName)
	pPane = App.STStylizedWindow_CreateW("StylizedWindow", "NoMinimize", kName, 0.0, 0.0, None, 1, fWidth, fHeight)
	pPane.AddChild(pMenu, 0.0, 0.0, 0)

	# We don't want the "skip parent" behavior in this case, because otherwise
	# menu items would think that the window was their parent.
	pMenu.SetNoSkipParent()

	# Add the menu to the TacticalControlWindow
	pTacticalControlWindow.AddChild(pPane, fXPos, fYPos)
	pTacticalControlWindow.AddMenuToList(pMenu)
	pPane.SetNotVisible()
	pMenu.SetNotVisible()

	return pMenu

###############################################################################
#	CreateCharacterTooltipBox
#	
#	Create a TGPane for the character's tooltips.
#	
#	Args:	pCharacter	- Character whose box we're creating
#	
#	Return:	The box.
###############################################################################
def CreateCharacterTooltipBox(pCharacter):
	# Import resolution dependent LCARS module for size/placement variables.
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	# Get the name of the character, for the title of the tooltip.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/CharacterStatus.tgl")
	kName = pDatabase.GetString(pCharacter.GetCharacterName())

	# Create the box.
	pBox = App.STStylizedWindow_CreateW("StylizedWindow", "RightBorder", kName)

	# Make a pane for the text, so the pane is always the same size.
	pBoxPane = App.TGPane_Create(LCARS.TOOL_TIP_WIDTH, LCARS.TOOL_TIP_HEIGHT)
	pBox.AddChild(pBoxPane, 0, 0, 0)

	App.g_kLocalizationManager.Unload(pDatabase)

	# Finish setting up the overall box.
	pBox.InteriorChangedSize()
	pBox.SetNotVisible()
	pBox.SetNoFocus()

	# Attach the box to the bridge window.
	pBridgeWindow = App.TopWindow_GetTopWindow().FindMainWindow(App.MWT_BRIDGE)
	pBridgeWindow.AddChild(pBox, (pBridgeWindow.GetWidth() - LCARS.TOOL_TIP_WIDTH) / 2.0, 0.05)

	return (pBox)

###############################################################################
#	UIFixTooltipBox(pBox)
#	
#	Fixes the tooltip box when the resolution changes.
#	
#	Args:	pBox	- the tooltip box
#	
#	Return:	none
###############################################################################
def UIFixTooltipBox(pBox):
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())
	pBox = App.STStylizedWindow_Cast(pBox)

	pBoxPane = App.TGPane_Cast(pBox.GetFirstChild())
	pBoxPane.Resize(LCARS.TOOL_TIP_WIDTH, LCARS.TOOL_TIP_HEIGHT, 0)

	pBox.InteriorChangedSize()
	pBridgeWindow = App.TopWindow_GetTopWindow().FindMainWindow(App.MWT_BRIDGE)
	pBox.SetPosition((pBridgeWindow.GetWidth() - LCARS.TOOL_TIP_WIDTH) / 2.0, 0.05, 0)
