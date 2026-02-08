###############################################################################
#	Filename:	PicardMenuHandlers.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Script to create the first officer's menu and handle some of its events.
#	
#	Created:	??/??/???? -	?
###############################################################################

import App
import BridgeUtils

# Create debug object
#kDebugObj = App.CPyDebug()

###############################################################################
#	CreateMenus(pPicard)
#	
#	Creates Picard's menu. This code must be called AFTER 
#	he is created.
#	
#	Args:	pPicard		- the first officer character
#	
#	Return:	none
###############################################################################
def CreateMenus(pPicard):
#	kDebugObj.Print("Creating Picard Menu\n")

	pPicard = App.CharacterClass_Cast(pPicard)

	# Import resolution dependent LCARS module for size/placement variables.
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	import BridgeMenus
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Names.tgl")
	pPicardMenu = BridgeMenus.CreateBlankCharacterMenu(pDatabase.GetString("Picard"), LCARS.PICARD_MENU_WIDTH, LCARS.PICARD_MENU_HEIGHT, 0.0, 0.0)
	App.g_kLocalizationManager.Unload(pDatabase)

	# Make sure you tell Picard what his menu is...
	pPicard.SetMenu(pPicardMenu)

	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
	pTCW.AddMenuToList(pPicardMenu)
