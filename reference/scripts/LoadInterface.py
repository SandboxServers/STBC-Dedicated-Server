###############################################################################
#	Filename:	LoadInterface.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Functions for loading things dealing with the general game interface.
#	
#	Created:	5/24/2001 -	KDeus
###############################################################################

import App

#
# List linking interface sound names to sound files.  Used by
# LoadSounds and UnloadSounds.
g_lInterfaceSounds = (
	( "UIBeep",				"sfx/Interface/mouseover.wav" ),
	( "UIButtonClicked",	"sfx/Interface/mouseclick.wav" ),
	( "UIMenuOpened",		"sfx/Interface/menu3_open.wav" ),
	( "UIMenuClosed",		"sfx/Interface/menu3_close.wav" ),
	( "UITextEntryClick",	"sfx/Interface/typing.wav" ),
	( "UIMinimize",			"sfx/Interface/minimize_window.wav" ),
	( "UIUnminimize",		"sfx/Interface/maximize_window.wav" ),
	( "UIQuit",				"sfx/Interface/exit.wav" ),
	( "UIStart",			("sfx/Interface/new_game.wav", "sfx/Interface/new_game2.wav", "sfx/Interface/new_game3.wav")[App.g_kSystemWrapper.GetRandomNumber(3)] ),
	( "UIScrolling",		"sfx/Interface/scroll_loop_1.wav" ),
	( "UINumericBarClick",	"sfx/Interface/slider_tick.wav" ),
	( "UIScanObject",		"sfx/Interface/scanning3.wav" ),
	( "UIScanArea",			"sfx/Interface/scanning.wav" ),
	( "UITorpsNotLoaded",	"sfx/Interface/fire_torp_none_ready.wav" ),
	( "UITorpsNoAmmo",		"sfx/Interface/fire_torp_no_ammo.wav" ),
	( "UICrosshair",		"sfx/Interface/crosshair.wav" ),
	)

###############################################################################
#	LoadSounds
#	
#	Load interface sounds.
#	
#	Args:	None
#	
#	Return:	None
###############################################################################
def LoadSounds():
	for sName, sFile in g_lInterfaceSounds:
		pSound = App.TGSound_Create(sFile, sName, 0)
		# All interface sounds count as sfx.
		pSound.SetSFX(0)
		pSound.SetInterface(1)

###############################################################################
#	UnloadSounds
#	
#	Unload sounds loaded by LoadSounds.
#	
#	Args:	None
#	
#	Return:	None
###############################################################################
def UnloadSounds():
	for sName, sFile in g_lInterfaceSounds:
		App.g_kSoundManager.DeleteSound(sName)

###############################################################################
#	SetupColors()
#	
#	Called to set up some standard colors for the interface.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def SetupColors():
	# STButton marker colors.
	SetupColor(App.g_kSTButtonMarkerDefault, 251.0 / 255.0, 224.0 / 255.0, 153.0 / 255.0, 1.0)
	SetupColor(App.g_kSTButtonMarkerHighlighted, 251.0 / 255.0, 224.0 / 255.0, 153.0 / 255.0, 1.0)
	SetupColor(App.g_kSTButtonMarkerSelected, 255.0 / 255.0, 252.0 / 255.0, 1.0 / 255.0, 1.0)
	#SetupColor(App.g_kSTButtonMarkerGray, 69.0 / 255.0, 66.0 / 255.0, 0.0 / 255.0, 1.0)
	SetupColor(App.g_kSTButtonMarkerGray, 104.0 / 255.0, 101.0 / 255.0, 27.0 / 255.0, 1.0)

	SetupColor(App.g_kSTButtonCheckmarkOn, 251.0 / 255.0, 255.0 / 255.0, 112.0 / 255.0, 1.0)
	SetupColor(App.g_kSTButtonCheckmarkOff, 0.0, 0.0, 0.0, 1.0)

	# Menu colors
	SetupColor(App.g_kSTMenuArrowColor, 215.0 / 255.0, 215.0 / 255.0, 215.0 / 255.0, 1.0)

	SetupColor(App.g_kSTMenu1NormalBase, 216.0 / 255.0, 94.0 / 255.0, 86.0 / 255.0, 1.0)
	SetupColor(App.g_kSTMenu1HighlightedBase, 254.0 / 255.0, 120.0 / 255.0, 86.0 / 255.0, 1.0)
	SetupColor(App.g_kSTMenu1Disabled, 0.25, 0.25, 0.25, 1.0)
	SetupColor(App.g_kSTMenu1OpenedHighlightedBase, 254.0 / 255.0, 120.0 / 255.0, 86.0 / 255.0, 1.0)
	SetupColor(App.g_kSTMenu1Selected, 127.0 / 255.0, 60.0 / 255.0, 43.0 / 255.0, 1.0)

	SetupColor(App.g_kSTMenu2NormalBase, 147.0 / 255.0, 103.0 / 255.0, 255.0 / 255.0, 1.0)
	SetupColor(App.g_kSTMenu2HighlightedBase, 173.0 / 255.0, 132.0 / 255.0, 255.0 / 255.0, 1.0)
	SetupColor(App.g_kSTMenu2Disabled, 0.25, 0.25, 0.25, 1.0)
	SetupColor(App.g_kSTMenu2OpenedHighlightedBase, 173.0 / 255.0, 132.0 / 255.0, 255.0 / 255.0, 1.0)
	SetupColor(App.g_kSTMenu2Selected, 86.5 / 255.0, 66.0 / 255.0, 127.5 / 255.0, 1.0)

	SetupColor(App.g_kSTMenu3NormalBase, 207.0 / 255.0, 96.0 / 255.0, 159.0 / 255.0, 1.0)
	SetupColor(App.g_kSTMenu3HighlightedBase, 246.0 / 255.0, 147.0 / 255.0, 204.0 / 255.0, 1.0)
	SetupColor(App.g_kSTMenu3Disabled, 0.25, 0.25, 0.25, 1.0)
	SetupColor(App.g_kSTMenu3OpenedHighlightedBase, 246.0 / 255.0, 147.0 / 255.0, 204.0 / 255.0, 1.0)
	SetupColor(App.g_kSTMenu3Selected, 103.5 / 255.0, 48.0 / 255.0, 79.5 / 255.0, 1.0)

	SetupColor(App.g_kSTMenu4NormalBase, 144.0 / 255.0, 103.0 / 255.0, 144.0 / 255.0, 1.0)
	SetupColor(App.g_kSTMenu4HighlightedBase, 175.0 / 255.0, 144.0 / 255.0, 175.0 / 255.0, 1.0)
	SetupColor(App.g_kSTMenu4Disabled, 0.25, 0.25, 0.25, 1.0)
	SetupColor(App.g_kSTMenu4OpenedHighlightedBase, 175.0 / 255.0, 144.0 / 255.0, 175.0 / 255.0, 1.0)
	SetupColor(App.g_kSTMenu4Selected, 72.0 / 255.0, 51.5 / 255.0, 72.0 / 255.0, 1.0)

	SetupColor(App.g_kSTMenuTextColor, 0.0, 0.0, 0.0, 1.0)
	SetupColor(App.g_kSTMenuTextSelectedColor, 1.0, 1.0, 1.0, 1.0)
	SetupColor(App.g_kSTMenuTextHighlightColor, 1.0, 1.0, 1.0, 1.0)

	SetupColor(App.g_kTextEntryColor, 0.5, 0.5, 0.8, 1.0)
	SetupColor(App.g_kTextHighlightColor, 0.2196, 0.4196, 0.3843, 1.0)

	SetupColor(App.g_kTextEntryBackgroundColor, 225.0 / 255.0, 183.0 / 255.0, 82.0 / 255.0, 1.0)
	SetupColor(App.g_kTextEntryBackgroundHighlightColor, 249.0 / 255.0, 232.0 / 255.0, 167.0 / 255.0, 1.0)

	# Tactical Interface Colors
	SetupColor(App.g_kTIPhotonReadyColor, 0.0, 1.0, 0.0, 1.0)
	SetupColor(App.g_kTIPhotonNotReadyColor, 1.0, 0.0, 0.0, 1.0)

	# Radar border highlight color
	SetupColor(App.g_kSTRadarBorderHighlighted, 0.95686, 0.92941, 0.43921, 1.0)

	# General Interface Colors
	SetupColor(App.g_kTitleColor, 255.0 / 255.0, 154.0 / 255.0, 2.0 / 255.0, 1.0)
	SetupColor(App.g_kInterfaceBorderColor, 216.0 / 255.0, 94.0 / 255.0, 86.0 / 255.0, 1.0)
	SetupColor(App.g_kLeftSeparatorColor, 178.0 / 255.0, 132.0 / 255.0, 178.0 / 255.0, 1.0)


	# Radar colors
	SetupColor(App.g_kRadarBorder, 0.27059, 0.23137, 0.2745, 1.0)
	SetupColor(App.g_kSTRadarIncomingTorpColor, 1.00, 1.00, 0.0, 1.0)
	SetupColor(App.g_kRadarFriendlyColor, 80.0 / 255.0, 112.0 / 255.0, 230.0 / 255.0, 1.0)
	SetupColor(App.g_kRadarEnemyColor, 216.0 / 255.0, 43.0 / 255.0, 43.0 / 255.0, 1.0)
	SetupColor(App.g_kRadarNeutralColor, 1.0, 1.0, 0.68627, 1.0)
	SetupColor(App.g_kRadarUnknownColor, 127.5 / 255.0, 127.5 / 255.0, 127.5 / 255.0, 1.0)

	# Subsystem colors, used in subsystem menus for fill gauge.
	SetupColor(App.g_kSubsystemFillColor, 183.6 / 255.0, 255.0 / 255.0, 0.0 / 255.0, 1.0)
	SetupColor(App.g_kSubsystemEmptyColor, 170.6 / 255.0, 25.0 / 255.0, 25.0 / 255.0, 1.0)
	SetupColor(App.g_kSubsystemDisabledColor, 0.6, 0.6, 0.6, 1.0)

	# Color used for header text in the tactical weapons control.
	SetupColor(App.g_kTacWeaponsCtrlHeaderTextColor, 253.0 / 255.0, 156.0 / 255.0, 0.0 / 255.0, 1.0)

	# Damage display colors.
	SetupColor(App.g_kDamageDisplayDestroyedColor, 1.00, 0.25, 0.0, 1.0)
	SetupColor(App.g_kDamageDisplayDamagedColor, 0.72, 1.00, 0.0, 1.0)
	SetupColor(App.g_kDamageDisplayDisabledColor, 0.6, 0.6, 0.6, 1.0)

	# Main menu colors, which are used elsewhere.
	SetupColor(App.g_kMainMenuButtonColor, 244.0 / 255.0, 177.0 / 255.0, 0.0, 1.0)
	SetupColor(App.g_kMainMenuButtonHighlightedColor, 251.0 / 255.0, 224.0 / 255.0, 153.0 / 255.0, 1.0)
	SetupColor(App.g_kMainMenuButtonSelectedColor, 151.0 / 255.0, 57.0 / 255.0, 28.0 / 255.0, 1.0)

	SetupColor(App.g_kMainMenuButton1Color, 221.0 / 255.0, 111.0 / 255.0, 16.0 / 255.0, 1.0)
	SetupColor(App.g_kMainMenuButton1HighlightedColor, 254.0 / 255.0, 170.0 / 255.0, 100.0 / 255.0, 1.0)
	SetupColor(App.g_kMainMenuButton1SelectedColor, 118.0 / 255.0, 77.0 / 255.0, 43.0 / 255.0, 1.0)

	SetupColor(App.g_kMainMenuButton2Color, 213.0 / 255.0, 98.0 / 255.0, 139.0 / 255.0, 1.0)
	SetupColor(App.g_kMainMenuButton2HighlightedColor, 245.0 / 255.0, 172.0 / 255.0, 199.0 / 255.0, 1.0)
	SetupColor(App.g_kMainMenuButton2SelectedColor, 121.0 / 255.0, 55.0 / 255.0, 79.0 / 255.0, 1.0)

	SetupColor(App.g_kMainMenuButton3Color, 222.0 / 255.0, 201.0 / 255.0, 60.0 / 255.0, 1.0)
	SetupColor(App.g_kMainMenuButton3HighlightedColor, 254.0 / 255.0, 242.0 / 255.0, 168.0 / 255.0, 1.0)
	SetupColor(App.g_kMainMenuButton3SelectedColor, 144.0 / 255.0, 134.0 / 255.0, 73.0 / 255.0, 1.0)

	SetupColor(App.g_kMainMenuBorderMainColor, 167.0 / 255.0, 118.0 / 255.0, 200.0 / 255.0, 1.0)
	SetupColor(App.g_kMainMenuBorderOffColor, 137.0 / 255.0, 135.0 / 255.0, 234.0 / 255.0, 1.0)
	SetupColor(App.g_kMainMenuBorderBlock1Color, 220.0 / 255.0, 94.0 / 255.0, 72.0 / 255.0, 1.0)
	SetupColor(App.g_kMainMenuBorderTopColor, 234.0 / 255.0, 140.0 / 255.0, 66.0 / 255.0, 1.0)

	# Engineering display colors.
	SetupColor(App.g_kEngineeringShieldsColor, 150.0 / 255.0, 129.0 / 255.0, 222.0 / 255.0, 1.0)
	SetupColor(App.g_kEngineeringEnginesColor, 199.0 / 255.0, 76.0 / 255.0, 200.0 / 255.0, 1.0)
	SetupColor(App.g_kEngineeringWeaponsColor, 207.0 / 255.0, 139.0 / 255.0, 76.0 / 255.0, 1.0)
	SetupColor(App.g_kEngineeringSensorsColor, 201.0 / 255.0, 203.0 / 255.0, 76.0 / 255.0, 1.0)
	SetupColor(App.g_kEngineeringCloakColor, 235.0 / 255.0, 128.0 / 255.0, 21.0 / 255.0, 1.0)
	SetupColor(App.g_kEngineeringTractorColor, 150.0 / 255.0, 129.0 / 255.0, 222.0 / 255.0, 1.0)

	SetupColor(App.g_kEngineeringWarpCoreColor, 22.0 / 255.0, 105.0 / 255.0, 207.0 / 255.0, 1.0)
	SetupColor(App.g_kEngineeringMainPowerColor, 180.0 / 255.0, 157.0 / 255.0, 64.0 / 255.0, 1.0)
	SetupColor(App.g_kEngineeringBackupPowerColor, 208.0 / 255.0, 87.0 / 255.0, 42.0 / 255.0, 1.0)

	SetupColor(App.g_kEngineeringCtrlBkgndLineColor, 157.0 / 255.0, 151.0 / 255.0, 165.0 / 255.0, 1.0)

	# QuickBattle and Multiplayer Colors
	SetupColor(App.g_kQuickBattleBrightRed, 255.0 / 255.0, 79.0 / 255.0, 45.0 / 255.0, 1.0)
	SetupColor(App.g_kMultiplayerBorderBlue, 137.0 / 255.0, 135.0 / 255.0, 234.0 / 255.0, 1.0)
	SetupColor(App.g_kMultiplayerBorderPurple, 167.0 / 255.0, 118.0 / 255.0, 200.0 / 255.0, 1.0)
	SetupColor(App.g_kMultiplayerStylizedPurple, 114.0 / 255.0, 146.0 / 255.0, 223.0 / 255.0, 1.0)
	SetupColor(App.g_kMultiplayerButtonPurple, 159.0 / 255.0, 127.0 / 255.0, 250.0 / 255.0, 1.0)
	SetupColor(App.g_kMultiplayerButtonOrange, 244.0 / 255.0, 177.0 / 255.0, 0.0 / 255.0, 1.0)
#	SetupColor(App.g_kMultiplayerRadioPink, 214.0 / 255.0, 97.0 / 255.0, 139.0 / 255.0, 1.0)
	SetupColor(App.g_kMultiplayerDividerPurple, 176.0 / 255.0, 133.0 / 255.0, 178.0 / 255.0, 1.0)


###############################################################################
#	SetupColor(kColor, fRed, fGreen, fBlue, fAlpha)
#	
#	Sets up a single color.
#	
#	Args:	kColor						- the color
#			fRed, fGreen, fBlue, fAlpha	- the color values, [0..1]
#	
#	Return:	none
###############################################################################
def SetupColor(kColor, fRed, fGreen, fBlue, fAlpha):
	kColor.r = fRed
	kColor.g = fGreen
	kColor.b = fBlue
	kColor.a = fAlpha
