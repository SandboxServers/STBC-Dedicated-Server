import App

# This function returns the name of the mission to be displayed in the file
# dialog.  The return must be a TGString
def GetMissionName():
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/MultiplayerMissions.tgl")

	pString = pDatabase.GetString("Mission5")

	App.g_kLocalizationManager.Unload(pDatabase)

	return pString

# This function returns the description of the mission to be displayed in the
# host dialog.  The return must be a TGString
def GetMissionDescription():
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/MultiplayerMissions.tgl")

	pString = pDatabase.GetString("Mission5 Description")

	App.g_kLocalizationManager.Unload(pDatabase)

	return pString

# This function returns a short version of the mission name for the join game browser
def GetMissionShortName():
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/MultiplayerMissions.tgl")

	pString = pDatabase.GetString("Mission5 Short Name")

	App.g_kLocalizationManager.Unload(pDatabase)

	return pString