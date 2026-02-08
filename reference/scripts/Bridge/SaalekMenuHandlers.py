###############################################################################
#	Filename:	SaalekMenuHandlers.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Script to create the ambassador's menu and handle some of its events.
#	
#	Created:	??/??/???? -	?
###############################################################################

import App
import BridgeUtils

# Create debug object
#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateMenus(pSaalek)
#	
#	Creates Saalek's menu. This code must be called AFTER 
#	he is created.
#	
#	Args:	pSaalek		- the first officer character
#	
#	Return:	none
###############################################################################
def CreateMenus(pSaalek):
#	kDebugObj.Print("Creating Saalek Menu\n")

	pSaalek = App.CharacterClass_Cast(pSaalek)

	# Import resolution dependent LCARS module for size/placement variables.
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	import BridgeMenus
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Names.tgl")
	pSaalekMenu = BridgeMenus.CreateBlankCharacterMenu(pDatabase.GetString("Saalek"), LCARS.TACTICAL_MENU_WIDTH, LCARS.TACTICAL_MENU_HEIGHT, 0.0, 0.0)
	App.g_kLocalizationManager.Unload(pDatabase)

	# Make sure you tell Saalek what his menu is...
	pSaalek.SetMenu(pSaalekMenu)

	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
	pTCW.AddMenuToList(pSaalekMenu)
