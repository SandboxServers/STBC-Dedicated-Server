###############################################################################
#	Filename:	Mission1Menus.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Script to build the options menu.
#	
#	Created:	12/07/00 -	Alby
###############################################################################


import App	
import UIHelpers
import MissionLib


NonSerializedObjects = (
"g_pOptionsWindowBootButton",
"g_pOptionsWindowBanButton",
"g_pOptionsWindowPlayerMenu",
)

g_iIdOfCurrentlySelectedPlayer = App.TGNetwork.TGNETWORK_INVALID_ID

# Global pointers to user interface items
g_pOptionsWindowBootButton = None
g_pOptionsWindowBanButton  = None
g_pOptionsWindowPlayerMenu = None

# define event types
ET_BOOT_BUTTON_CLICKED = App.g_kVarManager.MakeEpisodeEventType(105)
ET_PLAYER_BUTTON_CLICKED = App.g_kVarManager.MakeEpisodeEventType(106)
ET_BAN_BUTTON_CLICKED = App.g_kVarManager.MakeEpisodeEventType(107)

###############################################################################
#	BuildMission1Menu()
#	
#	Builds the options menu.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def BuildMission1Menus(bRebuild = 0):
	import Multiplayer.MissionShared
	import Multiplayer.MissionMenusShared

	Multiplayer.MissionMenusShared.g_iUseScoreLimit = 1

	# Find the Multiplayer window
	pTopWindow = App.TopWindow_GetTopWindow()
	pMultWindow = App.MultiplayerWindow_Cast (pTopWindow.FindMainWindow(App.MWT_MULTIPLAYER))

	# Hide all the children so that only we will be visible.
	pMultWindow.HideAllChildren()

	pDatabase = Multiplayer.MissionShared.g_pDatabase
	
	# Create the mission menu
	pMissionPane = BuildMissionMenu (pMultWindow, pDatabase)
	pMultWindow.AddChild (pMissionPane)

	#Build the mission-specific pane that will get put inside of the options menu
	BuildMissionSpecificOptionsMenuPane(pMissionPane)

	# Build end game window.
	pMenu = Multiplayer.MissionMenusShared.BuildEndWindow(pMultWindow, pDatabase, 1)
	pMultWindow.AddChild (pMenu)
	pMenu.SetNotVisible ();

	# Build the initial player list
	RebuildPlayerList()

	if (not bRebuild):
#		print ("Not bRebuild")
		# Make multiplayer window visible.
		pMultWindow.SetVisible ()
		pTopWindow.MoveToFront (pMultWindow)

		# Hide the tactical menu
		pTactWindow = App.TacticalWindow_Cast (pTopWindow.FindMainWindow(App.MWT_TACTICAL))
		pTactWindow.SetNotVisible ()

		pOptionsWindow = App.TopWindow_GetTopWindow().FindMainWindow(App.MWT_OPTIONS);
		if pOptionsWindow.IsVisible():
			App.TopWindow_GetTopWindow().ToggleOptionsMenu()

def BuildMissionMenu (pMultWindow, pDatabase):
	import Multiplayer.MissionMenusShared
	pMissionPane = Multiplayer.MissionMenusShared.BuildMissionMenu(pMultWindow, pDatabase,
					"Death-Match Host", "Death-Match Client", "Death-Match Direct Host")

	# Add some mission specific handlers for the mission pane
	pMissionPane.AddPythonFuncHandlerForInstance(Multiplayer.MissionMenusShared.ET_FINISHED_SELECT, __name__ + ".FinishedSelectHandler")
	pMissionPane.AddPythonFuncHandlerForInstance(Multiplayer.MissionMenusShared.ET_SELECT_SHIP_SPECIES, __name__ + ".SelectSpeciesHandler")
	pMissionPane.AddPythonFuncHandlerForInstance(Multiplayer.MissionMenusShared.ET_SELECT_SYSTEM, __name__ + ".SelectSystemHandler")
	pMissionPane.AddPythonFuncHandlerForInstance(ET_BOOT_BUTTON_CLICKED, __name__ + ".HandleBootButtonClicked")
	pMissionPane.AddPythonFuncHandlerForInstance(ET_BAN_BUTTON_CLICKED, __name__ + ".HandleBanButtonClicked")
	pMissionPane.AddPythonFuncHandlerForInstance(ET_PLAYER_BUTTON_CLICKED, __name__ + ".HandlePlayerButtonClicked")

	return pMissionPane

###############################################################################
#	HandlePlayerButtonClicked()
#	
#	A button on the scoreboard has been clicked. We must activate the boot
#	button (if the player is the host).
#	
#	Args:	TGObject*	pObject	- the mission pane
#			TGEvent*	pEvent	- our ET_PLAYER_BUTTON_CLICKED event
#	
#	Return:	None
###############################################################################
def HandlePlayerButtonClicked(pObject, pEvent):
	if App.g_kUtopiaModule.IsHost():
		g_pOptionsWindowBootButton.SetEnabled()
		g_pOptionsWindowBanButton.SetEnabled()

	global g_iIdOfCurrentlySelectedPlayer
	g_iIdOfCurrentlySelectedPlayer = pEvent.GetPlayerID()

	pObject.CallNextHandler(pEvent)


###############################################################################
#	HandleBootButtonClicked()
#	
#	The boot button has been clicked. Let the multiplayer window know, and set
#	the UI back up the way it was
#	
#	Args:	TGObject*	pObject	- the mission pane
#			TGEvent*	pEvent	- our ET_BOOT_BUTTON_CLICKED event
#	
#	Return:	None
###############################################################################
def HandleBootButtonClicked(pObject, pEvent):
	g_pOptionsWindowBootButton.SetDisabled()
	g_pOptionsWindowBanButton.SetDisabled()

	global g_iIdOfCurrentlySelectedPlayer
	
	if g_iIdOfCurrentlySelectedPlayer != App.TGNetwork.TGNETWORK_INVALID_ID:
		pTopWindow = App.TopWindow_GetTopWindow()
		pMultWindow = App.MultiplayerWindow_Cast(pTopWindow.FindMainWindow(App.MWT_MULTIPLAYER))
		pEvent = App.TGPlayerEvent_Create()
		pEvent.SetEventType(App.ET_PLAYER_BOOT_EVENT)
		pEvent.SetDestination(pMultWindow)
		pEvent.SetPlayerID(g_iIdOfCurrentlySelectedPlayer)
		App.g_kEventManager.AddEvent(pEvent)
	
	g_iIdOfCurrentlySelectedPlayer = App.TGNetwork.TGNETWORK_INVALID_ID

	pObject.CallNextHandler(pEvent)

###############################################################################
#	HandleBanButtonClicked(pObject, pEvent)
#	
#	The ban button has been clicked. Do a normal boot, but also add the
#	player's IP to the ban list.
#	
#	Args:	pObject	- the mission pane
#			pEvent	- the ET_BAN_BUTTON_CLICKED event
#	
#	Return:	none
###############################################################################
def HandleBanButtonClicked(pObject, pEvent):
	g_pOptionsWindowBootButton.SetDisabled()
	g_pOptionsWindowBanButton.SetDisabled()

	global g_iIdOfCurrentlySelectedPlayer
	pNetwork = App.g_kUtopiaModule.GetNetwork()

	# Make sure we're valid, and that the selection is not the host/local player.
	if ((pNetwork == None) or 
		(g_iIdOfCurrentlySelectedPlayer == pNetwork.GetHostID()) or
	    (g_iIdOfCurrentlySelectedPlayer == pNetwork.GetLocalID())):
		g_iIdOfCurrentlySelectedPlayer = App.TGNetwork.TGNETWORK_INVALID_ID
		pObject.CallNextHandler(pEvent)
		return

	if g_iIdOfCurrentlySelectedPlayer != App.TGNetwork.TGNETWORK_INVALID_ID:
		pPlayerList = pNetwork.GetPlayerList()
		pPlayer = pPlayerList.GetPlayer(g_iIdOfCurrentlySelectedPlayer)

		if pPlayer:
			# Add them to the ban list.
			App.TGWinsockNetwork_BanPlayerByIP(pPlayer.GetNetAddress())

		# Now do a normal boot.
		pTopWindow = App.TopWindow_GetTopWindow()
		pMultWindow = App.MultiplayerWindow_Cast(pTopWindow.FindMainWindow(App.MWT_MULTIPLAYER))
		pEvent = App.TGPlayerEvent_Create()
		pEvent.SetEventType(App.ET_PLAYER_BOOT_EVENT)
		pEvent.SetDestination(pMultWindow)
		pEvent.SetPlayerID(g_iIdOfCurrentlySelectedPlayer)
		App.g_kEventManager.AddEvent(pEvent)

	g_iIdOfCurrentlySelectedPlayer = App.TGNetwork.TGNETWORK_INVALID_ID

	pObject.CallNextHandler(pEvent)
		

###############################################################################
#	RebuildPlayerList()
#	
#	Update the scoreboard with the latest data
#	
#	Args:	None
#	
#	Return:	None
###############################################################################
def RebuildPlayerList():
	import Multiplayer.MissionShared

	# We don't want to refresh the player list when the Game Over screen is up
	# 'cuz that can sometimes break the game over screen
	if Multiplayer.MissionShared.g_bGameOver:
		return
	
	import Mission1
	import MainMenu.mainmenu
	import Multiplayer.MissionShared

	if (Multiplayer.MissionShared.g_bGameOver != 0):
		# If the game is over, then don't rebuild the player list.
		return

	pNetwork = App.g_kUtopiaModule.GetNetwork ()
	if (not pNetwork):
		# Don't rebuild the list since you can't
		return

	pGame = App.Game_GetCurrentGame ()
	if (not pGame):
		# Game over.  Can't rebuild list.
		return

	pMultGame = App.MultiplayerGame_Cast (pGame)

	# Find the Multiplayer window
	pTopWindow = App.TopWindow_GetTopWindow()
	pMultWindow = App.MultiplayerWindow_Cast (pTopWindow.FindMainWindow(App.MWT_MULTIPLAYER))
	
	pEndPane = App.TGPane_Cast (pMultWindow.GetEndWindow ())
	pSortList = []

	if (pEndPane):
		# Get the menu
		import Multiplayer.MissionMenusShared
		pPane = Multiplayer.MissionMenusShared.g_pEndPlayerListPane
		pStyleWindow = Multiplayer.MissionMenusShared.g_pEndPlayerListWindow
		pMenu = Multiplayer.MissionMenusShared.g_pEndPlayerListMenu

		# Kill all the children.		
		pMenu.KillChildren ()

		# Reconstruct the menu, first storing it in a python list.
		pDict = Mission1.g_kKillsDictionary

		pPlayerList = pNetwork.GetPlayerList ()
		iNumPlayers = pPlayerList.GetNumPlayers ()
		i = 0
		while (i < iNumPlayers):
			pPlayer = pPlayerList.GetPlayerAtIndex (i)
			
			if (pMultGame):
				if (pDict.has_key (pPlayer.GetNetID ()) and pPlayer.IsDisconnected () == 0):
					# This is an actual player in the game.  Add him to the sort list for
					# later sorting/
					pSortList.append (pPlayer)
#			else:
				# On initialize.  Only the host will be here, so add him.
				# If this is the host but the host is not in the game cause he's a dedicated
				# server, don't add him to the score board.
#				if (not (App.g_kUtopiaModule.IsHost () and (not App.g_kUtopiaModule.IsClient ()))):
#					pSortList.append (pPlayer)

			# Increment the index to look at the next player.				
			i = i + 1

		# Okay, now we have a list of all the players in the game.  Sort it
		# using the ComparePlayer function to do comparisons.
		pSortList.sort (ComparePlayer)

		# Now that we've got a sorted list, we can add it into the menu
		for pPlayer in pSortList:
			pPane = CreatePlayerScoreEntry (pPlayer)
			pMenu.AddChild (pPane, 0, 0, 0)
		
		# Now call layout on the entire menu.
		pMenu.Layout()
		pStyleWindow.InteriorChangedSize ()

	# Also rebuild the scoreboard in the Options Window

	if g_pOptionsWindowPlayerMenu:

		# Set the font larger
		App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcSmallFont,
					MainMenu.mainmenu.g_kSmallFontSize[MainMenu.mainmenu.g_iRes])

		g_pOptionsWindowPlayerMenu.KillChildren()
		
		# First add an empty pane the height of an entry to push the other entries
		# down so that the top of the list is not covered by the headers
		g_pOptionsWindowPlayerMenu.AddChild(App.TGPane_Create(0.4, 0.04), 0.0, 0.0, 0)
		
		for pPlayer in pSortList:
			pPane = CreateScoreboardPlayerScoreEntry(pPlayer)
			g_pOptionsWindowPlayerMenu.AddChild(pPane, 0.0, 0.0, 0)

		# Now layout the menu. No need to call InteriorChangedSize on its parent because
		# it's an STSubPane and knows to handle that on its own.
		g_pOptionsWindowPlayerMenu.Layout()

		# Set the font back to the flight size
		App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcFlightSmallFont,
				MainMenu.mainmenu.g_kFlightSmallFontSize[MainMenu.mainmenu.g_iRes])

	# Disable the boot button, since the player it's set to boot may no longer be
	# around
	if g_pOptionsWindowBootButton:
		g_pOptionsWindowBootButton.SetDisabled()
	if g_pOptionsWindowBanButton:
		g_pOptionsWindowBanButton.SetDisabled()

	# Now rebuild the info pane
	RebuildInfoPane()

	# Close and open the score window so it'll properly re-lay itself out
	DoScoreWindow()
	DoScoreWindow()

###############################################################################
#	CreatePlayerScoreEntry()
#	
#	Create a player info entry for the in-game scoreboard
#	
#	Args:	pPlayer		- the player
#	
#	Return:	A TGPane* containing a player info entry
###############################################################################
def CreatePlayerScoreEntry (pPlayer):
	import Mission1
	# Initialize some globals
	# create a pane to hold everything.
	pPlayerEntryPane = App.TGPane_Create (0.4, 0.1)

	# Create the player name text
	pPane = App.TGPane_Create (0.2 - 0.005, 0.1)
	pText = App.TGParagraph_CreateW (pPlayer.GetName ())
	pPane.AddChild (pText, 0, 0, 0)
	pPlayerEntryPane.PrependChild (pPane, 0, 0, 0)
	fHeight = pText.GetHeight ()
	pPane.Resize (0.2 - 0.005, fHeight, 0)

	# Resize the player entry pane
	pPlayerEntryPane.Resize (0.4, fHeight, 0)
	
	iPlayerID = pPlayer.GetNetID ()

	# Create the score
	# Get the death total from the score dictionaries
	pDict = Mission1.g_kScoresDictionary

	iScore = 0
	if (pDict.has_key (iPlayerID)):
		iScore = pDict [iPlayerID]

	pPane = App.TGPane_Create (0.09 - 0.005, fHeight)
	pText = App.TGParagraph_Create (str (iScore))
	pPane.AddChild (pText, 0, 0, 0)
	pPlayerEntryPane.PrependChild (pPane, 0.20, 0, 0)

	# create kills
	# Get the kill total from the score dictionaries
	pDict = Mission1.g_kKillsDictionary

	iKills = 0
	if (pDict.has_key (iPlayerID)):
		iKills = pDict [iPlayerID]

	pPane = App.TGPane_Create (0.055 - 0.005, fHeight)
	pText = App.TGParagraph_Create (str (iKills))
	pPane.AddChild (pText, 0, 0, 0)
	pPlayerEntryPane.PrependChild (pPane, 0.285, 0, 0)

	# Create death total
	# Get the death total from the score dictionaries
	pDict = Mission1.g_kDeathsDictionary

	iDeaths = 0
	if (pDict.has_key (iPlayerID)):
		iDeaths = pDict [iPlayerID]

	pPane = App.TGPane_Create (0.070 - 0.005, fHeight)
	pText = App.TGParagraph_Create (str (iDeaths))
	pPane.AddChild (pText, 0, 0, 0)
	pPlayerEntryPane.PrependChild (pPane, 0.335, 0, 0)

	return pPlayerEntryPane
					

###############################################################################
#	CreateScoreboardPlayerScoreEntry()
#	
#	Create a player info entry for the scoreboard that's in the options window
#	
#	Args:	pPlayer		- the player
#	
#	Return:	A TGPane* containing a player info entry
###############################################################################
def CreateScoreboardPlayerScoreEntry(pPlayer):
	import Mission1
	import MainMenu.mainmenu
	# Set the font larger
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcSmallFont,
				MainMenu.mainmenu.g_kSmallFontSize[MainMenu.mainmenu.g_iRes])

	# Initialize some globals
	# create a pane to hold everything.
	pPlayerEntryPane = App.TGPane_Create(0.5, 0.04)

	# Create the event that gets sent that can be used for booting a player
	pTopWindow = App.TopWindow_GetTopWindow()
	pMultWindow = App.MultiplayerWindow_Cast (pTopWindow.FindMainWindow(App.MWT_MULTIPLAYER))
	pEvent = App.TGPlayerEvent_Create()
	pEvent.SetEventType(ET_PLAYER_BUTTON_CLICKED)
	pEvent.SetDestination(pMultWindow.GetMissionPane())
	iPlayerID = pPlayer.GetNetID()
	pEvent.SetPlayerID(iPlayerID)

	# Create the player name text
	pButton = App.STButton_CreateW(pPlayer.GetName(), pEvent, 0,
								0.225, 0.04)
	pButton.SetNormalColor(App.g_kSTMenu4NormalBase)
	pButton.SetHighlightedColor(App.g_kSTMenu4HighlightedBase)
	pButton.SetSelectedColor(App.g_kSTMenu4Selected)
	pButton.SetColorBasedOnFlags()
	pPlayerEntryPane.PrependChild(pButton, 0.0, 0.0, 0)
	
	# Create the score
	# Get the death total from the score dictionaries
	pDict = Mission1.g_kScoresDictionary

	iScore = 0
	if (pDict.has_key (iPlayerID)):
		iScore = pDict [iPlayerID]

	pText = App.TGTextButton_Create(str(iScore))
	pText.AlignTextHorizontal(App.TGTextButton.ALIGN_CENTER, 0)
	pText.AlignTextVertical(App.TGTextButton.ALIGN_MIDDLE, 0)
	pText.Resize(0.10, 0.04, 0)
	pPlayerEntryPane.PrependChild(pText, 0.25, 0.0, 0)

	# create kills
	# Get the kill total from the score dictionaries
	pDict = Mission1.g_kKillsDictionary

	iKills = 0
	if (pDict.has_key (iPlayerID)):
		iKills = pDict [iPlayerID]

	pText = App.TGTextButton_Create(str(iKills))
	pText.AlignTextHorizontal(App.TGTextButton.ALIGN_CENTER, 0)
	pText.AlignTextVertical(App.TGTextButton.ALIGN_MIDDLE, 0)
	pText.Resize(0.065, 0.04, 0)
	pPlayerEntryPane.PrependChild(pText, 0.35, 0.0, 0)

	# Create death total
	# Get the death total from the score dictionaries
	pDict = Mission1.g_kDeathsDictionary

	iDeaths = 0
	if (pDict.has_key (iPlayerID)):
		iDeaths = pDict [iPlayerID]

	pText = App.TGTextButton_Create(str(iDeaths))
	pText.AlignTextHorizontal(App.TGTextButton.ALIGN_CENTER, 0)
	pText.AlignTextVertical(App.TGTextButton.ALIGN_MIDDLE, 0)
	pText.Resize(0.065, 0.04, 0)
	pPlayerEntryPane.PrependChild(pText, 0.425, 0.0, 0)

	return pPlayerEntryPane

def ComparePlayer (pThisPlayer, pOtherPlayer):
	import Mission1
	# Get the scores and kills of this player and the other player.
	iThisID = pThisPlayer.GetNetID ()
	iOtherID = pOtherPlayer.GetNetID ()

	# Get the kill total from the score dictionaries
	pScoreDict = Mission1.g_kScoresDictionary

	iThisScore = 0
	iOtherScore = 0

	if (pScoreDict.has_key (iThisID)):
		iThisScore = pScoreDict [iThisID]

	if (pScoreDict.has_key (iOtherID)):
		iOtherScore = pScoreDict [iOtherID]
	
	# Sort by score first.
	if (iThisScore < iOtherScore):
		return 1
	elif (iThisScore == iOtherScore):
		# if scores are even, sort by kills.
		pKillsDict = Mission1.g_kKillsDictionary

		iThisKills = 0
		iOtherKills = 0
		if (pKillsDict.has_key (iThisID)):
			iThisKills = pKillsDict [iThisID]

		if (pKillsDict.has_key (iOtherID)):
			iOtherKills = pKillsDict [iOtherID]
		
		# We want lower Kills to get sorted higher
		if (iThisKills < iOtherKills):
			return -1
		elif (iThisKills > iOtherKills):
			return 1
		else:
			# Sort by deaths as last resort.
			pDeathsDict = Mission1.g_kDeathsDictionary

			iThisDeaths = 0
			iOtherDeaths = 0
			if (pDeathsDict.has_key (iThisID)):
				iThisDeaths = pDeathsDict [iThisID]

			if (pDeathsDict.has_key (iOtherID)):
				iOtherDeaths = pDeathsDict [iOtherID]
			
			# We want lower deaths to get sorted higher
			if (iThisDeaths < iOtherDeaths):
				return -1
			elif (iThisDeaths > iOtherDeaths):
				return 1
			else:
				return 0
			return 0
	else:
		return -1

	# reverse sort.  Higher kills get sorted higher.
	if (iThisKills < iOtherKills):
		return 1
	elif (iThisKills == iOtherKills):
		pDeathsDict = Mission1.g_kDeathsDictionary

		iThisDeaths = 0
		iOtherDeaths = 0
		if (pDeathsDict.has_key (iThisID)):
			iThisDeaths = pDeathsDict [iThisID]

		if (pDeathsDict.has_key (iOtherID)):
			iOtherDeaths = pDeathsDict [iOtherID]
		
		# We want lower deaths to get sorted higher
		if (iThisDeaths < iOtherDeaths):
			return -1
		elif (iThisDeaths > iOtherDeaths):
			return 1
		else:
			return 0
	else:
		return -1

def DoScoreWindow ():
	import Multiplayer.MissionMenusShared
	Multiplayer.MissionMenusShared.DoScoreWindow ()
	return 0

def DoEndGameDialog (bRestartable = 0):
	import Multiplayer.MissionMenusShared
	Multiplayer.MissionMenusShared.DoEndGameDialog(bRestartable)

	return 1

###############################################################################
#	SelectSpeciesHandler()
#	
#	Handle events for selection of a new system
#	
#	Args:	TGObject	pObject - destination object for the event
#			TGIntEvent	pEvent  - The Int in this event is the index of our new
#									species
#	
#	Return:	None
###############################################################################
def SelectSpeciesHandler (TGObject, pEvent):
	import Multiplayer.MissionMenusShared
	# Set the global species selected number.
	Multiplayer.MissionMenusShared.SelectSpecies (pEvent.GetInt ())

	# make the previously select button not chosen
	if (Multiplayer.MissionMenusShared.g_pChosenSpecies):
		Multiplayer.MissionMenusShared.g_pChosenSpecies.SetChosen (0)

	# Set the button that was clicked chosen, so it will have a different color.
	pButton = App.STButton_Cast (pEvent.GetSource ())
	pButton.SetChosen (1)
	Multiplayer.MissionMenusShared.g_pChosenSpecies = pButton

	# Make the start button visible if system and ship selected
	UpdateStartButton()

	TGObject.CallNextHandler(pEvent)

###############################################################################
#	SelectSystemHandler()
#	
#	Handle events for selection of a new system
#	
#	Args:	TGObject	pObject - destination object for the event
#			TGIntEvent	pEvent  - The Int in this event is the index of our new
#									system
#	
#	Return:	None
###############################################################################
def SelectSystemHandler(pObject, pEvent):
	import Multiplayer.MissionMenusShared
	# Set the global species selected number.
	Multiplayer.MissionMenusShared.SelectSystem (pEvent.GetInt ())

	# make the previously select button not chosen
	if (Multiplayer.MissionMenusShared.g_pChosenSystem):
		Multiplayer.MissionMenusShared.g_pChosenSystem.SetChosen (0)

	# Set the button that was clicked chosen, so it will have a different color.
	pButton = App.STButton_Cast (pEvent.GetSource ())
	pButton.SetChosen (1)
	Multiplayer.MissionMenusShared.g_pChosenSystem = pButton

	# Make the start button visible if system and ship selected
	UpdateStartButton()

	pObject.CallNextHandler(pEvent)

def FinishedSelectHandler (TGObject, pEvent):
	# Allow the Options Window to come up
#	App.TopWindow_GetTopWindow().AllowShowOptionsWindow(1)

	import Multiplayer.MissionMenusShared
	# Find the Multiplayer window
	pTopWindow = App.TopWindow_GetTopWindow()
	pMultWindow = App.MultiplayerWindow_Cast (pTopWindow.FindMainWindow(App.MWT_MULTIPLAYER))

	# Get the mission pane and hide it.
	pMissionPane = pMultWindow.GetMissionPane ()
	pMissionPane.SetNotVisible ()

	StartMission (Multiplayer.MissionMenusShared.g_iSpecies, Multiplayer.MissionMenusShared.g_iSystem)

	# If we're dedicated server, bring up the options window
	if (App.g_kUtopiaModule.IsHost () and (not App.g_kUtopiaModule.IsClient ())):
		# Bring up options again.
		# Find the multiplayer window
		pTopWindow = App.TopWindow_GetTopWindow()
		pMultWindow = App.MultiplayerWindow_Cast (pTopWindow.FindMainWindow(App.MWT_MULTIPLAYER))

		# Hide all panes, make MultiplayerPane visible.
		pMultWindow.HideAllChildren ()

		# Hide the entire window and make options window visible.
		pMain = pTopWindow.FindMainWindow(App.MWT_OPTIONS)
		pMain.SetVisible ()
		pTopWindow.MoveToFront (pMain)

	TGObject.CallNextHandler(pEvent)


###############################################################################
#	ResetLimitInfo()	
#	
#	Updates the user interface's limit buttons (time, frag, num players) to
#	reflect the accurate values of this information
#	
#	Args:	None
#	
#	Return:	None
###############################################################################
def ResetLimitInfo():
	import Multiplayer.MissionShared
	import Multiplayer.MissionMenusShared
	
	# player limit
	pcString = Multiplayer.MissionShared.g_pDatabase.GetString("Num Players").GetCString()
	pcString = pcString % str(Multiplayer.MissionMenusShared.g_iPlayerLimit)
	pString = App.TGString(pcString)
	Multiplayer.MissionMenusShared.g_pPlayerLimitButton.SetName(pString)
	
	# time limit
	if (Multiplayer.MissionMenusShared.g_iTimeLimit == -1):
		Multiplayer.MissionMenusShared.g_pTimeLimitButton.SetName(Multiplayer.MissionShared.g_pDatabase.GetString("None"))
	else:
		pString = Multiplayer.MissionShared.g_pDatabase.GetString("Num Minutes")
		pcString = pString.GetCString ()

		pcSubString = pcString % str (Multiplayer.MissionMenusShared.g_iTimeLimit)

		pNewString = App.TGString ()
		pNewString.SetString (pcSubString)

		Multiplayer.MissionMenusShared.g_pTimeLimitButton.SetName(pNewString)

	# Frag limit
	if (Multiplayer.MissionMenusShared.g_iFragLimit == -1):
		Multiplayer.MissionMenusShared.g_pFragLimitButton.SetName(Multiplayer.MissionShared.g_pDatabase.GetString("None"))
	else:
		pString = None
		pcSubString = None
		if (Multiplayer.MissionMenusShared.g_iUseScoreLimit):
			pString = Multiplayer.MissionShared.g_pDatabase.GetString("Num Points")
			pcString = pString.GetCString ()
			pcSubString = pcString % str (Multiplayer.MissionMenusShared.g_iFragLimit * 10000)
		else:
			pString = Multiplayer.MissionShared.g_pDatabase.GetString("Num Frags")
			pcString = pString.GetCString ()
			pcSubString = pcString % str (Multiplayer.MissionMenusShared.g_iFragLimit)

		pNewString = App.TGString ()
		pNewString.SetString (pcSubString)

		Multiplayer.MissionMenusShared.g_pFragLimitButton.SetName(pNewString)


def UpdateStartButton():
	import Multiplayer.MissionMenusShared
	if App.g_kUtopiaModule.IsHost() and (not App.g_kUtopiaModule.IsClient()):
		if Multiplayer.MissionMenusShared.g_iSystem != 0:
			Multiplayer.MissionMenusShared.g_pStartButton.SetEnabled ()
	else:
		if Multiplayer.MissionMenusShared.g_iSpecies != 0 and Multiplayer.MissionMenusShared.g_iSystem != 0:
			Multiplayer.MissionMenusShared.g_pStartButton.SetEnabled()
	

def StartMission (iSpecies, iSystem):
	import Multiplayer.MissionMenusShared
	import Multiplayer.SpeciesToShip
	import Multiplayer.SpeciesToSystem
	import Multiplayer.MissionShared
	import MainMenu.mainmenu
	# Specify (and load if necessary) our bridge
 
	# Get the current game.  We use this in various places below.
	pGame = App.Game_GetCurrentGame ()
	pMultGame = App.MultiplayerGame_Cast (pGame)	# Cast the game to a multiplayer game

	# Access the global variable that was created in Multiplayer.MissionShared.py to
	# get the pointer to the starting set.
	if (App.g_kUtopiaModule.IsHost ()):
		# If we're the host, create the starting set here if we haven't already started the game.
		# After teh game is started, we cannot change regions.
		if (not Multiplayer.MissionMenusShared.g_bGameStarted):
			pSet = Multiplayer.SpeciesToSystem.CreateSystemFromSpecies (iSystem)
			Multiplayer.MissionShared.g_pStartingSet = pSet
		else:
			pSet = Multiplayer.MissionShared.g_pStartingSet
	else:
		# The staring set should have been send to us from the host.
		# Use it here.
		pSet = Multiplayer.MissionShared.g_pStartingSet

	if (App.IsNull (pSet)):
		return

	###################################################
	#This next section will create the ships and set their stats

	#Determine if we need to create the player's ship.
	if (iSpecies != Multiplayer.SpeciesToShip.UNKNOWN):
		# We've got a valid species.  Create the player's ship.
		pPlayer = Multiplayer.MissionMenusShared.CreateShip (iSpecies)

		if (pPlayer != None):
			pPlayer.RandomOrientation ()
			pPlayer.UpdateNodeOnly ()

			pNetwork = App.g_kUtopiaModule.GetNetwork ()
			if (pNetwork):
				pPlayer.SetNetPlayerID (pNetwork.GetLocalID ())

			# Get the player's name from the network.
			pNetwork = App.g_kUtopiaModule.GetNetwork ()
			if (not App.IsNull (pNetwork)):
				pcName = pNetwork.GetCName ()
			else:
				pcName = "N/A"

			# Determine if there is already a ship with the same name.
			pcOrigName = pcName
			i = 0
			iCount = 1
			while (i == 0):
				pObj = App.BaseObjectClass_GetObject (None, pcName)
				if (pObj):
					# Yes, an object already exists.  We need to create
					# a new name
					pcName = pcOrigName
					pcName = pcName + str (iCount)
					iCount = iCount + 1
				else:
					i = 1

			# randomly locate the player's ship.
			fRadius = pPlayer.GetRadius () * 1.25

			kPos = Multiplayer.MissionMenusShared.FindGoodLocation (pSet, fRadius)

			pPlayer.SetTranslate (kPos)

			# Add the ship to the set.
			pSet.AddObjectToSet (pPlayer, pcName)

			pMultGame.SetPlayer(pPlayer)

			# Remove phased plasma torpedos.
			pTorpSys = pPlayer.GetTorpedoSystem()
			if(pTorpSys):
				# Find proper torps..
				iNumTypes = pTorpSys.GetNumAmmoTypes()
				for iType in range(iNumTypes):
					pTorpType = pTorpSys.GetAmmoType(iType)
					if (pTorpType.GetAmmoName() == "Phased"):
						pTorpSys.RemoveAmmoType (iType)

			# Add event handler for when this ship is destroyed.
			# Find the Multiplayer window
			pTopWindow = App.TopWindow_GetTopWindow()
			pMultWindow = App.MultiplayerWindow_Cast (pTopWindow.FindMainWindow(App.MWT_MULTIPLAYER))

			# Add broadcast handler for when an object is destroyed.  This handler will bring up the mission pane
			# again if the player's ship is destroyed.
			pMissionPane = pMultWindow.GetMissionPane ()
			App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_DELETE_OBJECT_PUBLIC, pMissionPane, "Multiplayer.MissionMenusShared.ObjectDestroyedHandler", pPlayer)


	# Hide select region menu and move ship selection menu into it's proper place
	pTopWindow = App.TopWindow_GetTopWindow()

	if (App.g_kUtopiaModule.IsHost ()):
		Multiplayer.MissionMenusShared.g_pSystemPane.SetNotVisible ()
		Multiplayer.MissionMenusShared.g_pSystemIcon.SetNotVisible ()
		Multiplayer.MissionMenusShared.g_pSystemDescPane.SetNotVisible ()

		Multiplayer.MissionMenusShared.g_pInfoPane.SetVisible ()
		if (not App.g_kUtopiaModule.IsClient ()):
			# Dedicated server.  Disable options toggling.
			pTopWindow.DisableOptionsMenu (1)	
			pResumeButton = App.STRoundedButton_Cast(App.TGObject_GetTGObjectPtr(MainMenu.mainmenu.g_idResumeButton))
			if (pResumeButton):
				pResumeButton.SetDisabled ()

	# Force tactical view
	if (App.g_kUtopiaModule.IsClient ()):
		# Now force tactical view.
		pTopWindow.ForceTacticalVisible ()

	# Ready for new players to join.  Notify the game of this.
	if (App.g_kUtopiaModule.IsHost ()):
		if (not pMultGame.IsReadyForNewPlayers ()):
			pMultGame.SetReadyForNewPlayers (1)				# Set flag to ready

		if (not Multiplayer.MissionMenusShared.g_bGameStarted):
			# Set time left for this mission if there's a time limit.
			if (Multiplayer.MissionMenusShared.g_iTimeLimit != -1):
				Multiplayer.MissionShared.CreateTimeLeftTimer(Multiplayer.MissionMenusShared.g_iTimeLimit * 60)
			Multiplayer.MissionMenusShared.g_bGameStarted = 1

	# rebuild the scoreboard to accurately display things
	RebuildPlayerList ()

def RebuildInfoPane ():
	import Mission1
	import Multiplayer.SpeciesToSystem
	import Multiplayer.MissionMenusShared
	import MainMenu.mainmenu
	import Multiplayer.MissionShared
	pNetwork = App.g_kUtopiaModule.GetNetwork ()
	if (not pNetwork):
		# Don't rebuild the list since you can't
		return

	pDatabase = Multiplayer.MissionShared.g_pDatabase

	pOrigFontGroup = App.g_kFontManager.GetDefaultFont ()

	# Set the font small
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcSmallFont,
				MainMenu.mainmenu.g_kSmallFontSize[MainMenu.mainmenu.g_iRes])

	# Kill all the children in the info pane, since we will be rebuilding it from scratch.
	Multiplayer.MissionMenusShared.g_pInfoPane.KillChildren ()
	
	pText = App.TGParagraph_CreateW (Multiplayer.MissionShared.g_pDatabase.GetString("Mission System"))
	pText.SetColor (App.g_kTitleColor)
	Multiplayer.MissionMenusShared.g_pInfoPane.AddChild (pText, Multiplayer.MissionMenusShared.SYSTEM_WINDOW_X_POS, Multiplayer.MissionMenusShared.SYSTEM_WINDOW_Y_POS - pText.GetHeight () - 0.005, 0)
	fWidth = pText.GetWidth ()

	if (Multiplayer.MissionMenusShared.g_iSystem != 0):
		pText = App.TGParagraph_CreateW (Multiplayer.MissionShared.g_pSystemDatabase.GetString (Multiplayer.SpeciesToSystem.GetScriptFromSpecies (Multiplayer.MissionMenusShared.g_iSystem)))
	else:
		pText = App.TGParagraph_CreateW (pDatabase.GetString("Unknown"))

		pText.SetColor (App.g_kSTMenuTextHighlightColor)
	Multiplayer.MissionMenusShared.g_pInfoPane.AddChild (pText, Multiplayer.MissionMenusShared.SYSTEM_WINDOW_X_POS + fWidth + 0.005, Multiplayer.MissionMenusShared.SYSTEM_WINDOW_Y_POS - pText.GetHeight () - 0.005, 0)

	# Build the stylized window.
	fHeight = Multiplayer.MissionMenusShared.SYSTEM_DESC_WINDOW_Y_POS + Multiplayer.MissionMenusShared.SYSTEM_DESC_WINDOW_HEIGHT - Multiplayer.MissionMenusShared.SYSTEM_WINDOW_Y_POS
	pWindow = App.STStylizedWindow_CreateW("StylizedWindow", "NoMinimize", pDatabase.GetString("Players In Game"), 
						0.0, 0.0, None, 1, Multiplayer.MissionMenusShared.SYSTEM_WINDOW_WIDTH, fHeight)
	pWindow.SetTitleBarThickness(Multiplayer.MissionMenusShared.SYSTEM_WINDOW_BAR_THICKNESS)
	Multiplayer.MissionMenusShared.g_pInfoPane.AddChild (pWindow, Multiplayer.MissionMenusShared.SYSTEM_WINDOW_X_POS, Multiplayer.MissionMenusShared.SYSTEM_WINDOW_Y_POS, 0)

	# Build player list pane.
	pListPane = App.STSubPane_Create (Multiplayer.MissionMenusShared.SYSTEM_WINDOW_WIDTH, 500.0)
	
	# Add players to the list.
	pSortList = []

	pDict = Mission1.g_kKillsDictionary

	pMultGame = App.MultiplayerGame_Cast (App.Game_GetCurrentGame ())

	pPlayerList = pNetwork.GetPlayerList ()
	iNumPlayers = pPlayerList.GetNumPlayers ()
	i = 0
	while (i < iNumPlayers):
		pPlayer = pPlayerList.GetPlayerAtIndex (i)
		
		if (pMultGame):
			if (pDict.has_key (pPlayer.GetNetID ()) and pPlayer.IsDisconnected () == 0):
				# This is an actual player in the game.  Add him to the sort list for
				# later sorting/
				pSortList.append (pPlayer)
#			else:
			# On initialize.  Only the host will be here, so add him.
			# If this is the host but the host is not in the game cause he's a dedicated
			# server, don't add him to the score board.
#				if (not (App.g_kUtopiaModule.IsHost () and (not App.g_kUtopiaModule.IsClient ()))):
#					pSortList.append (pPlayer)

		# Increment the index to look at the next player.				
		i = i + 1

	# Okay, now we have a list of all the players in the game.  Sort it
	# using the ComparePlayer function to do comparisons.
	pSortList.sort (ComparePlayer)

	# Now that we've got a sorted list, we can add it into the menu
	for pPlayer in pSortList:
		pPane = CreatePlayerInfoEntry (pPlayer, pMultGame)
		pListPane.AddChild (pPane, 0, 0, 0)

	pListPane.Resize (pListPane.GetWidth (), pListPane.GetTotalHeightOfChildren (), 0)

	pWindow.AddChild (pListPane, 0, 0, 0)	
	pWindow.Layout()
	pWindow.InteriorChangedSize ()
	
	# Restore default font
	App.g_kFontManager.SetDefaultFont(pOrigFontGroup.GetFontName (), pOrigFontGroup.GetFontSize ())

	Multiplayer.MissionMenusShared.g_pInfoPane.Layout ()


def CreatePlayerInfoEntry (pPlayer, pMultGame):
	import Mission1
	import Multiplayer.SpeciesToShip
	import Multiplayer.MissionShared
	import Multiplayer.MissionMenusShared
	# create a pane to hold everything.
	pPlayerEntryPane = App.TGPane_Create (Multiplayer.MissionMenusShared.SYSTEM_WINDOW_WIDTH, 0.1)

	pDatabase = Multiplayer.MissionShared.g_pDatabase

	# Create the player name text
#	pPane = App.TGPane_Create (Multiplayer.MissionMenusShared.SYSTEM_WINDOW_WIDTH - 0.1, 0.1)
	pPane = App.TGPane_Create (Multiplayer.MissionMenusShared.SYSTEM_WINDOW_WIDTH, 0.1)
	pText = App.TGParagraph_CreateW (pPlayer.GetName ())
	pPane.AddChild (pText, 0.01, 0, 0)
	pPlayerEntryPane.PrependChild (pPane, 0, 0, 0)

	fHeight = pText.GetHeight ()
	fWidth = pText.GetWidth ()

	# Resize the player entry pane
	pPlayerEntryPane.Resize (Multiplayer.MissionMenusShared.SYSTEM_WINDOW_WIDTH, fHeight, 0)

	# Create ship text
	iPlayerID = pPlayer.GetNetID ()
	pShip = pMultGame.GetShipFromPlayerID (iPlayerID)
	pcText = ""
	if (pShip):
		# Get the type from the ship.
		iType = pShip.GetNetType ()
		if (pShip.IsDying () or pShip.IsDead ()):
			pString = pDatabase.GetString ("Dead")
		else:
			if (iType == 0):
				# Don't know what ship.  Display unknown
				pString = pDatabase.GetString ("Unknown")
			else:
				pString = Multiplayer.MissionShared.g_pShipDatabase.GetString (Multiplayer.SpeciesToShip.GetScriptFromSpecies (iType))
	else:
		# Don't know what ship.  Display unknown
		pString = pDatabase.GetString ("Unknown")

	pcString = pString.GetCString ()
	pcText = " - " + pcString

	pText = App.TGParagraph_Create (pcText)

	pPane.AddChild (pText, 0.01 + fWidth, 0, 0)

	# Create the score
	# Get the death total from the score dictionaries
#	pDict = Mission1.g_kScoresDictionary

#	iScore = 0
#	if (pDict.has_key (iPlayerID)):
#		iScore = pDict [iPlayerID]
#
#	pText = App.TGParagraph_Create (str (iScore) + "pts")
#	pPlayerEntryPane.AddChild (pText, Multiplayer.MissionMenusShared.SYSTEM_WINDOW_WIDTH - 0.1, 0, 0)

	return pPlayerEntryPane



###############################################################################
#	BuildMissionSpecificOptionsMenuPane()
#	
#	Builds the scoreboard along with the boot button that you see when you
#	press ESCAPE while playing in deathmatch mode
#	
#	Args:	TGPane*	pEventPane	- the pane that handles our events
#	
#	Return:	None
###############################################################################
def BuildMissionSpecificOptionsMenuPane(pEventPane):
	import MainMenu.mainmenu
	import Multiplayer.MissionShared
	import Multiplayer.MultiplayerMenus
	import Multiplayer.MissionShared
	
	if App.g_kUtopiaModule.IsHost() and App.g_kUtopiaModule.IsClient():
		pSubtitle = Multiplayer.MissionShared.g_pDatabase.GetString("Death-Match Host")
	elif App.g_kUtopiaModule.IsClient():
		pSubtitle = Multiplayer.MissionShared.g_pDatabase.GetString("Death-Match Client")
	else:
		pSubtitle = Multiplayer.MissionShared.g_pDatabase.GetString("Death-Match Direct Host")
	pPane = Multiplayer.MultiplayerMenus.GetMissionPane(pSubtitle)

	# We want our stylized window to take up 3/4 of the available height in
	# the pane, and to be centered
	fScoreWindowWidth = 0.5125
	fScoreWindowHeight = pPane.GetHeight() * 0.75
	fScoreXPos = (pPane.GetWidth() - fScoreWindowWidth) / 2.0 
	fScoreYPos = (pPane.GetHeight() - fScoreWindowHeight) / 2.0

	# Set the font larger
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcSmallFont,
				MainMenu.mainmenu.g_kSmallFontSize[MainMenu.mainmenu.g_iRes])

	# Create Player, Kills, Deaths, and Score text
	pTextPane = App.TGPane_Create(0.175, 0.04)
	pText = App.TGParagraph_CreateW(Multiplayer.MissionShared.g_pDatabase.GetString("Player"))
	pText.SetColor(App.g_kMultiplayerBorderBlue)
	pTextPane.AddChild(pText, 0.0, 0.0, 0)
	pTextPane.Resize(0.175, pText.GetHeight(), 0)
	pPane.AddChild(pTextPane, 0.10 + fScoreXPos + 0.0105, fScoreYPos + 0.03, 0)

	pTextPane = App.TGPane_Create(0.8, 0.1)
	pText = App.TGParagraph_CreateW(Multiplayer.MissionShared.g_pDatabase.GetString("Score"))
	pText.SetColor(App.g_kMultiplayerBorderBlue)
	pTextPane.AddChild(pText, 0.0, 0.0, 0)
	pTextPane.Resize(0.14, pText.GetHeight(), 0)
	pPane.AddChild(pTextPane, 0.28 + fScoreXPos + 0.0105, fScoreYPos + 0.03, 0)

	pTextPane = App.TGPane_Create(0.065, 0.1)
	pText = App.TGParagraph_CreateW(Multiplayer.MissionShared.g_pDatabase.GetString("Kills"))
	pText.SetColor(App.g_kMultiplayerBorderBlue)
	pTextPane.AddChild(pText, 0.0, 0.0, 0)
	pTextPane.Resize(0.08, pText.GetHeight(), 0)
	pPane.AddChild(pTextPane, 0.37 + fScoreXPos + 0.0105, fScoreYPos + 0.03, 0)
	
	pTextPane = App.TGPane_Create(0.065, 0.1)
	pText = App.TGParagraph_CreateW(Multiplayer.MissionShared.g_pDatabase.GetString("Deaths"))
	pText.SetColor(App.g_kMultiplayerBorderBlue)
	pTextPane.AddChild(pText, 0.0, 0.0, 0)
	pTextPane.Resize(0.08, pText.GetHeight(), 0)
	pPane.AddChild(pTextPane, 0.435 + fScoreXPos + 0.0105, fScoreYPos + 0.03, 0)

	# Build the black header the goes behind the captions.
	# Its purpose is to cover up menu items that scroll up behind it.
	# It handles events so that they won't reach any buttons that it's
	# covering up.
	pHeader = App.TGIcon_Create(App.GraphicsModeInfo_GetCurrentMode().GetLcarsString(), 200)
	pHeader.SetColor(App.NiColorA_BLACK)
	pHeader.Resize(0.502, 0.04, 0)
	pHeader.AddPythonFuncHandlerForInstance(App.ET_MOUSE, __name__ + ".HandleMouseEventsForGlass")
	pPane.AddChild(pHeader,	fScoreXPos + 0.0105, fScoreYPos + 0.03, 0)

	# Create the stylized window in which our player list will go
	pWindow = App.STStylizedWindow_CreateW("StylizedWindow", "NoMinimize", 
		Multiplayer.MissionShared.g_pDatabase.GetString("Score Board"), 0.0,
		0.0, None, 1, fScoreWindowWidth, fScoreWindowHeight)
	pWindow.SetTitleBarThickness(0.03, 0)
	pPane.AddChild(pWindow, fScoreXPos, fScoreYPos, 0)

	# Create a subpane inside of which will go the player list. It will be the nice,
	# unassuming, docile sort of subpane which obediently resizes itself to fit snugly
	# within its parent StylizedWindow
	global g_pOptionsWindowPlayerMenu
	g_pOptionsWindowPlayerMenu = App.STSubPane_Create(0.0, 0.0, 1)
	pWindow.AddChild(g_pOptionsWindowPlayerMenu, 0.0, 0.0, 0)
	pWindow.InteriorChangedSize(1)
	
	# We want the boot button to take up about 1/3 of the space under the
	# stylized window, horizontally, 2/5 of the space under it vertically,
	# and to be centered under it along both axes. It should be disabled if we're
	# not the host
	fBootButtonWidth = fScoreWindowWidth * (1.0/3.0)
	fBootButtonHeight = (pPane.GetHeight() - (fScoreWindowHeight + fScoreYPos)) * 0.4
	fBootButtonXPos = (pPane.GetWidth() - fBootButtonWidth) / 2.0
	fBootButtonYPos = (((pPane.GetHeight() - (fScoreWindowHeight + fScoreYPos)) - fBootButtonHeight) / 2.0) + fScoreWindowHeight + fScoreYPos

	pEvent = App.TGEvent_Create ()
	pEvent.SetEventType(ET_BOOT_BUTTON_CLICKED)
	pEvent.SetDestination(pEventPane)

	pBanEvent = App.TGEvent_Create()
	pBanEvent.SetEventType(ET_BAN_BUTTON_CLICKED)
	pBanEvent.SetDestination(pEventPane)

	global g_pOptionsWindowBootButton
	global g_pOptionsWindowBanButton

	g_pOptionsWindowBootButton = App.STButton_CreateW(
		Multiplayer.MissionShared.g_pDatabase.GetString("Boot"),
		pEvent, 0, fBootButtonWidth, fBootButtonHeight)
	g_pOptionsWindowBootButton.SetJustification(App.STButton.CENTER)
	g_pOptionsWindowBootButton.SetNormalColor(App.g_kMainMenuButtonColor)
	g_pOptionsWindowBootButton.SetHighlightedColor(App.g_kMainMenuButtonHighlightedColor)
	g_pOptionsWindowBootButton.SetSelectedColor(App.g_kMainMenuButtonSelectedColor)
	g_pOptionsWindowBootButton.SetColorBasedOnFlags()
	g_pOptionsWindowBootButton.SetDisabled(0)

	g_pOptionsWindowBanButton = App.STButton_CreateW(Multiplayer.MissionShared.g_pDatabase.GetString("Ban"),
		pBanEvent, 0, fBootButtonWidth, fBootButtonHeight)
	g_pOptionsWindowBanButton.SetJustification(App.STButton.CENTER)
	g_pOptionsWindowBanButton.SetNormalColor(App.g_kMainMenuButtonColor)
	g_pOptionsWindowBanButton.SetHighlightedColor(App.g_kMainMenuButtonHighlightedColor)
	g_pOptionsWindowBanButton.SetSelectedColor(App.g_kMainMenuButtonSelectedColor)
	g_pOptionsWindowBanButton.SetColorBasedOnFlags()
	g_pOptionsWindowBanButton.SetDisabled(0)


	pPane.AddChild(g_pOptionsWindowBootButton, fBootButtonXPos, fBootButtonYPos, 0)
	pPane.AddChild(g_pOptionsWindowBanButton, 
				   fBootButtonXPos + g_pOptionsWindowBootButton.GetWidth() + (App.globals.DEFAULT_ST_INDENT_HORIZ * 2.0),
				   fBootButtonYPos, 0)

	pPane.Layout()

	# Go back to the flight font
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcFlightSmallFont,
				MainMenu.mainmenu.g_kFlightSmallFontSize[MainMenu.mainmenu.g_iRes])

###############################################################################
#	HandleMouseEventsForGlass()
#	
#	There are times that we want to cover up some UI elements with glass.
#	We have to make sure the user can't click on them, so we make the glass
#	handle mouse events before letting them pass underneath
#	
#	Args:	TGObject*	pObject	- the glass
#			TGEvent*	pEvent	- the ET_MOUSE_EVENT
#	
#	Return:	
###############################################################################
def HandleMouseEventsForGlass(pObject, pEvent):
	pEvent.SetHandled()
	pObject.CallNextHandler(pEvent)


