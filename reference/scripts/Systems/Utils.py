###############################################################################
#	Filename:	Systems.__init__.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Initialization module for the Systems directory.  Holds some functions
#	used by the systems to create menus and things.  The file needs to be
#	here just so that "import Systems.*" will work.
#	
#	Created:	5/24/2001 -	KDeus
###############################################################################
import App

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print

###############################################################################
#	CreateSystemMenu
#	
#	Create a system menu.  Pass in the region files for the systems.
#
#	Args:	sSystemName	- Name for the system, the overall name for the menu.
#			sSystemRegi	- Region file that you go to if you select the menu.
#			lSystems	- Regions inside the system (children of the menu).
#	
#	Return:	The newly-created system menu (or an existing one, if it was
#			created before).
###############################################################################
def CreateSystemMenu(sSystemName, sSystemRegion, *lSystems):
	# Disable sorting of the menus...
	bPaused = App.SortedRegionMenu_IsSortingPaused()
	if not bPaused:
		App.SortedRegionMenu_SetPauseSorting(1)

	# Create the menu.
	pMenu = CreateSystemMenuInternal(sSystemName, sSystemRegion, lSystems)

	# Reenable sorting, if it was enabled before.
	if not bPaused:
		kProfiling2 = App.TGProfilingInfo("Systems.CreateMenus, Unpausing")
		App.SortedRegionMenu_SetPauseSorting(0)

	return pMenu

def CreateSystemMenuInternal(sSystemName, sSystemRegion, lSystems):
	# Get the Set Course menu...
	pTopWindow = App.TopWindow_GetTopWindow()
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pMenu = pTacticalControlWindow.FindMenu(pDatabase.GetString ("Helm"))
	pSetCourseMenu = pMenu.GetSubmenuW(pDatabase.GetString("Set Course"))
	App.g_kLocalizationManager.Unload(pDatabase)

	# Change the data base over to the Systems database, where all the system names will come from.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Systems.TGL")

	# Get a display name for the system.
	if pDatabase.HasString(sSystemName):
		pSystemDisplayName = pDatabase.GetString(sSystemName)
	else:
		pSystemDisplayName = App.TGString()
		pSystemDisplayName.SetString(sSystemName)

	# Check to see if we have already created this system
	pSystemMenu = pSetCourseMenu.GetSubmenuW(pSystemDisplayName)
	if pSystemMenu:
		# This system already exists.  Just clear its info.
		pSystemMenu = App.SortedRegionMenu_Cast(pSystemMenu)
		pSystemMenu.ClearInfo()

		App.g_kLocalizationManager.Unload(pDatabase)
		return pSystemMenu

	# Doesn't exist yet.  Create the system..
	pSystemMenu = App.SortedRegionMenu_CreateW(pSystemDisplayName, sSystemRegion)

	for sRegion in lSystems:
		pSystemModule = __import__(sRegion)
		sSystem = pSystemModule.GetSetName()
		pDisplayName = App.SetClass_MakeDisplayName(sSystem)

		# Create the menu for this set.
		pSetMenu = App.SortedRegionMenu_CreateW(pDisplayName, sRegion)

		# Add this set to the system menu.
		pSystemMenu.AddChild(pSetMenu, 0, 0, 0)

	if lSystems:
		# Last region in the menu gets the focus.
		if App.g_kUtopiaModule.IsMultiplayer():
			pSystemMenu.SetFocus(None, 0)
			pSystemMenu.SetNotOpenable()
		else:
			pSystemMenu.SetFocus(pSetMenu, 0)

	App.g_kLocalizationManager.Unload(pDatabase)

	# Add the system to the Set Course menu and layout.
	pSetCourseMenu.AddChild(pSystemMenu, 0, 0, 0)
	#pSetCourseMenu.Layout()

#	debug("Finished creating %s system." % sSystemName)

	# Return the menu
	return pSystemMenu
