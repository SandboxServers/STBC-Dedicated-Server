###############################################################################
#	Filename:	DataMenuHandlers.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Script to create the first officer's menu and handle some of its events.
#	
#	Created:	??/??/???? -	?
###############################################################################

import App
import BridgeUtils

###############################################################################
#	CreateMenus(pData)
#	
#	Creates Data's menu. This code must be called AFTER 
#	he is created.
#	
#	Args:	pData	- the first officer character
#	
#	Return:	none
###############################################################################
def CreateMenus(pData):
	pData = App.CharacterClass_Cast(pData)

	# Import resolution dependent LCARS module for size/placement variables.
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	import BridgeMenus
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Names.tgl")
	pDataMenu = BridgeMenus.CreateBlankCharacterMenu(pDatabase.GetString("Data"), LCARS.TACTICAL_MENU_WIDTH, LCARS.TACTICAL_MENU_HEIGHT, 0.0, 0.0)
	App.g_kLocalizationManager.Unload(pDatabase)

	# Make sure you tell Data what his menu is...
	pData.SetMenu(pDataMenu)

	import Bridge.BridgeMenus
	pCommunicate = Bridge.BridgeMenus.CreateCommunicateButton("Data", pDataMenu)
	pDataMenu.AddChild(pCommunicate)

	pDataMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, "Bridge.Characters.CommonAnimations.NothingToAdd")

	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
	pTCW.AddMenuToList(pDataMenu)
