###############################################################################
#	Filename:	LCARS_1600.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Interface position/dimension values and LCARS Icon Group.
#	Setup LCARS for 1600x1200
#	
#	Created:	9/20/00 -	Alberto Fonseca
###############################################################################

import App

###############################################################################
#
#	Module level values for interface icon positions and dimensions.
#
###############################################################################

g_fRepairButtonFontSize	= 5.0

# Screen dimensions
SCREEN_WIDTH			= 1.0
SCREEN_HEIGHT			= 1.0

# Screen dimensions in pixels.
SCREEN_PIXEL_WIDTH		= 1600.0
SCREEN_PIXEL_HEIGHT		= 1200.0

DEFAULT_ST_INDENT_HORIZ	= 6		/ SCREEN_PIXEL_WIDTH
DEFAULT_ST_INDENT_VERT	= 3		/ SCREEN_PIXEL_HEIGHT
MARKER_INDENT_HORIZ		= 2		/ SCREEN_PIXEL_WIDTH
TAC_WEAPONS_CTRL_INDENT_HORIZ = 8 / SCREEN_PIXEL_WIDTH
REPAIR_ST_INDENT_HORIZ	= 2		/ SCREEN_PIXEL_WIDTH

# Options menu placement info.
MAIN_MENU_X								=   3.0 / 640.0
MAIN_MENU_Y								=   0.0

MAIN_MENU_SMALL_CURVE_WIDTH				=  50.0 / 640.0
MAIN_MENU_SMALL_CURVE_HEIGHT			=  26.0 / 480.0
MAIN_MENU_SMALL_CURVE_INNER_WIDTH		=  26.0 / 640.0
MAIN_MENU_SMALL_CURVE_INNER_HEIGHT		=  15.0 / 480.0
MAIN_MENU_SMALL_CURVE_INNER_ICON_WIDTH	=   0.01
MAIN_MENU_SMALL_CURVE_INNER_ICON_HEIGHT	=   0.01
MAIN_MENU_SMALL_CURVE_OUTER_ICON_WIDTH	=   0.01
MAIN_MENU_SMALL_CURVE_OUTER_ICON_HEIGHT	=   0.01

MAIN_MENU_TOP_BUTTON_PANE_X				= 110.0 / 640.0
MAIN_MENU_TOP_BUTTON_PANE_Y				=   28.0 / 480.0
MAIN_MENU_TOP_BUTTON_PANE_WIDTH			= 0.70
MAIN_MENU_TOP_BUTTON_PANE_HEIGHT		= 0.11
MAIN_MENU_TOP_BUTTON_WIDTH				=  92.0 / 640.0
MAIN_MENU_TOP_BUTTON_HEIGHT				=  20.0 / 480.0

MAIN_MENU_MIDDLE_PANE_X					= 0.00875
MAIN_MENU_MIDDLE_PANE_Y					= 0.18333
MAIN_MENU_MIDDLE_PANE_WIDTH				= 0.878125
MAIN_MENU_MIDDLE_PANE_HEIGHT			= 0.731666

MAIN_MENU_MIDDLE_CONTENT_X				= 0.1625
MAIN_MENU_MIDDLE_CONTENT_Y				= 0.045
MAIN_MENU_MIDDLE_CONTENT_WIDTH			= 0.753125
MAIN_MENU_MIDDLE_CONTENT_HEIGHT			= 0.7375

# Background information.
MAIN_MENU_HORIZONTAL_BLOCK_HEIGHT			= 11.0	/ 480.0

# "Configure" tab info.
MAIN_MENU_CONFIGURE_TAB_X					= 0.01  
MAIN_MENU_CONFIGURE_TAB_Y					= 0.007666
MAIN_MENU_CONFIGURE_TAB_WIDTH				= 196.0 / 640.0
MAIN_MENU_CONFIGURE_TAB_HEIGHT				= 201.0 / 480.0

MAIN_MENU_CONFIGURE_CONTENT_X				= 0.33625  
MAIN_MENU_CONFIGURE_CONTENT_Y				= 0.007666
MAIN_MENU_CONFIGURE_CONTENT_WIDTH			= 0.359375  
MAIN_MENU_CONFIGURE_CONTENT_HEIGHT			= 0.70    

# File dialog placement info.
FILE_TOP_AREA_X					= 0.145
FILE_TOP_AREA_Y					= 0.0
FILE_TOP_AREA_WIDTH				= 0.3
FILE_TOP_AREA_HEIGHT			= 0.44

FILE_BUTTON_AREA_X				= 0.165
FILE_BUTTON_AREA_Y				= 0.07

FILE_LIST_AREA_X				= 0.33625	#0.50875
FILE_LIST_AREA_Y				= 0.007666	#0.052666
FILE_LIST_AREA_WIDTH			= 0.359375
FILE_LIST_AREA_HEIGHT			= 0.70

FILE_SCREENSHOT_AREA_X			= 0.0
FILE_SCREENSHOT_AREA_Y			= 0.0
FILE_SCREENSHOT_AREA_WIDTH		= 0.0
FILE_SCREENSHOT_AREA_HEIGHT		= 0.0

# Pane dimensions.
TACTICAL_MENU_WIDTH		= 146	/ SCREEN_PIXEL_WIDTH
TACTICAL_MENU_HEIGHT	= 250	/ SCREEN_PIXEL_HEIGHT
								
SHIELDS_DISPLAY_WIDTH	= 146	/ SCREEN_PIXEL_WIDTH
SHIELDS_DISPLAY_HEIGHT	= 121	/ SCREEN_PIXEL_HEIGHT

DAMAGE_DISPLAY_WIDTH	= 146	/ SCREEN_PIXEL_WIDTH
DAMAGE_DISPLAY_HEIGHT	= 121	/ SCREEN_PIXEL_HEIGHT

WEAPONS_PANE_WIDTH		= 155	/ SCREEN_PIXEL_WIDTH
WEAPONS_PANE_HEIGHT		= 137	/ SCREEN_PIXEL_HEIGHT

WEAPONS_PANE_PIXEL_WIDTH	= 155
WEAPONS_PANE_PIXEL_HEIGHT	= 131

WEAPONS_CTRL_PANE_WIDTH = 153	/ SCREEN_PIXEL_WIDTH
WEAPONS_CTRL_PANE_HEIGHT = 137	/ SCREEN_PIXEL_HEIGHT

# Picard pane dimensions
PICARD_MENU_WIDTH		= 170	/ SCREEN_PIXEL_WIDTH
PICARD_MENU_HEIGHT		= 250	/ SCREEN_PIXEL_HEIGHT

# Display placement offsets
WEAPONS_DISPLAY_GAP_X	= 2		/ SCREEN_PIXEL_WIDTH

# Radar display variables.
RADAR_SCOPE_WIDTH		= 146	/ SCREEN_PIXEL_WIDTH
RADAR_SCOPE_HEIGHT		= 146	/ SCREEN_PIXEL_HEIGHT

# Radar toggle variables
RADAR_TOGGLE_WIDTH		= 60	/ SCREEN_PIXEL_WIDTH
RADAR_TOGGLE_HEIGHT		= 14	/ SCREEN_PIXEL_HEIGHT

# Shield arc positions.
TOP_SHIELD_Y			= 17	/ SCREEN_PIXEL_HEIGHT
BOTTOM_SHIELD_Y			= 53	/ SCREEN_PIXEL_HEIGHT
FRONT_SHIELD_Y			= 5		/ SCREEN_PIXEL_HEIGHT
REAR_SHIELD_Y			= 93	/ SCREEN_PIXEL_HEIGHT
SIDE_SHIELDS_Y			= 22	/ SCREEN_PIXEL_HEIGHT
SIDE_SHIELDS_X_OFFSET	= 2		/ SCREEN_PIXEL_WIDTH

# Weapons display variables.
SHIP_Y_OFFSET			= 7		/ SCREEN_PIXEL_HEIGHT

# LeftSeparator window style variables.
PRETITLE_BAR_WIDTH		= 13	/ SCREEN_PIXEL_HEIGHT
LEFT_SEPARATOR_BOTTOM_GAP = 4	/ SCREEN_PIXEL_HEIGHT

# Separator lines
SEPERATOR_GAP_Y			= 4		/ SCREEN_PIXEL_HEIGHT

# Engineer's power interface.
POWER_AREA_WIDTH			= 0.30
POWER_AREA_HEIGHT			= 0.35

POWER_USED_BAR_WIDTH		= 0.35
POWER_USED_BAR_HEIGHT		= 15.0 / 480.0
POWER_USED_BAR_INDENT		= 0.025
POWER_GAUGE_WIDTH			= 40.0 / 1600.0
POWER_GAUGE_HEIGHT			= 104.0 / 1200.0
ELBOW_THICKNESS				= 5		# in pixels
ELBOW_THICKNESS_WIDTH		= ELBOW_THICKNESS / SCREEN_PIXEL_WIDTH

# STButton offset values...
STBUTTON_CHECK_OFFSET_X		= 7	/ SCREEN_PIXEL_WIDTH
STBUTTON_CHECK_OFFSET_Y		= 2	/ SCREEN_PIXEL_HEIGHT

# STMenu offset values...
STMENU_ARROW_OFFSET_X	= 10.0 / 23.0

# Tool-tip sizes
TOOL_TIP_WIDTH				= 250 / SCREEN_PIXEL_WIDTH
TOOL_TIP_HEIGHT				= 80 / SCREEN_PIXEL_HEIGHT

# Subtitle window values.
SUBTITLE_BRIDGE_X_POS				= 0.124
SUBTITLE_TACTICAL_X_POS				= 0.25
SUBTITLE_FELIX_X_POS				= 0.25
SUBTITLE_MAP_X_POS					= 0.01
SUBTITLE_CINEMATIC_X_POS			= 0.01

SUBTITLE_BRIDGE_CENTER_Y_POS		= 0.85
SUBTITLE_TACTICAL_CENTER_Y_POS		= 0.60
SUBTITLE_FELIX_CENTER_Y_POS			= 0.69
SUBTITLE_MAP_CENTER_Y_POS			= 0.15
SUBTITLE_CINEMATIC_CENTER_Y_POS		= 0.9375
SUBTITLE_SPECIAL_FELIX_CENTER_Y_POS		= 0.7

SUBTITLE_BRIDGE_SUBTITLE_WIDTH	 	= 0.75
SUBTITLE_TACTICAL_SUBTITLE_WIDTH 	= 0.75
SUBTITLE_FELIX_SUBTITLE_WIDTH	 	= 0.75
SUBTITLE_MAP_SUBTITLE_WIDTH			= 1.0
SUBTITLE_CINEMATIC_SUBTITLE_WIDTH	= 1.0

SUBTITLE_WIDTH_MINUS_TEXT_WIDTH		= 0.02
SUBTITLE_MAX_HEIGHT					= 0.3
SUBTITLE_FELIX_MAX_HEIGHT			= 0.3

###############################################################################
#	LoadLCARS_1600(LCARS = None)
#
#	Create LCARS icon group and add interface icons to it.
#
#	Args:	LCARS - Icon Group, if None it is created and added to icon manager.
#
#	Return:	none
###############################################################################
def LoadLCARS_1600(LCARS = None):
	# If no Icon Group passed in, create one and add to icon manager.	
	if LCARS is None:
		LCARS = App.g_kIconManager.CreateIconGroup("LCARS_1600")
		App.g_kIconManager.AddIconGroup(LCARS)
	
	# Radar Display
	#------------------

	# Radar Circle TL
	TextureHandle = LCARS.LoadIconTexture("Data/Icons/Bridge/RadarBorder.tga")
	LCARS.SetIconLocation(10, TextureHandle, 0, 0, 73, 73)
	
	# Radar Circle TR
	LCARS.SetIconLocation(20, TextureHandle, 0, 0, 73, 73, 
							App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_HORIZONTAL)

	# Radar Circle BL
	LCARS.SetIconLocation(30, TextureHandle, 0, 0, 73, 73, 
							App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_VERTICAL)

	# Radar Circle BR
	LCARS.SetIconLocation(40, TextureHandle, 0, 0, 73, 73, 
							App.TGIconGroup.ROTATE_180, App.TGIconGroup.MIRROR_NONE)

	# Radar Target Bracket
	LCARS.SetIconLocation(80, TextureHandle, 0, 110, 8, 8)

	# Range button Zoom In - 3 Icons.
	LCARS.SetIconLocation(90, TextureHandle, 0, 81, 24, 12)
	LCARS.SetIconLocation(91, TextureHandle, 0, 81, 24, 12)
	LCARS.SetIconLocation(92, TextureHandle, 0, 81, 24, 12)

	# Range button Zoom Out - 3 Icons.
	LCARS.SetIconLocation(100, TextureHandle, 0, 97, 24, 12)
	LCARS.SetIconLocation(101, TextureHandle, 0, 97, 24, 12)
	LCARS.SetIconLocation(102, TextureHandle, 0, 97, 24, 12)

	# Background Screen
	#-------------------------

	# Background Screen (glass)
	kTextureHandle = LCARS.LoadIconTexture('Data/Icons/Bridge/Background/ScreenBlock.tga')
	LCARS.SetIconLocation(120, kTextureHandle, 0, 0, 4, 4)
	LCARS.SetIconLocation(121, kTextureHandle, 4, 0, 4, 4)
	LCARS.SetIconLocation(122, kTextureHandle, 4, 4, 4, 4)
	LCARS.SetIconLocation(123, kTextureHandle, 0, 4, 4, 4)

	# Screen Curves -- used in UIHelpers.py
	kTextureHandle = LCARS.LoadIconTexture('Data/Icons/Bridge/Background/ScreenCurveLarge.tga')
	# Upper left curve icon numbers, inner curve icon first
	LCARS.SetIconLocation(140, kTextureHandle, 128, 0, 95, 95, App.TGIconGroup.ROTATE_90)
	LCARS.SetIconLocation(141, kTextureHandle, 0, 0, 128, 128, App.TGIconGroup.ROTATE_90)
	# Upper right curve icon numbers, inner curve icon first
	LCARS.SetIconLocation(142, kTextureHandle, 128, 0, 95, 95, App.TGIconGroup.ROTATE_90, App.TGIconGroup.MIRROR_HORIZONTAL)
	LCARS.SetIconLocation(143, kTextureHandle, 0, 0, 128, 128, App.TGIconGroup.ROTATE_90, App.TGIconGroup.MIRROR_HORIZONTAL)
	# Lower left curve icon numbers, inner curve icon first
	LCARS.SetIconLocation(144, kTextureHandle, 128, 0, 95, 95)
	LCARS.SetIconLocation(145, kTextureHandle, 0, 0, 128, 128)
	# Lower right curve icon numbers, inner curve icon first
	LCARS.SetIconLocation(146, kTextureHandle, 128, 0, 95, 95, App.TGIconGroup.ROTATE_270)
	LCARS.SetIconLocation(147, kTextureHandle, 0, 0, 128, 128, App.TGIconGroup.ROTATE_270)

	# Alternate screen curves
	kTextureHandle = LCARS.LoadIconTexture("Data/Icons/Bridge/Background/ScreenCurve2.tga")
	# Upper left curve icon numbers, inner curve icon first
	LCARS.SetIconLocation(150, kTextureHandle, 0, 0, 8, 8)
	LCARS.SetIconLocation(151, kTextureHandle, 8, 0, 6, 6)
	# Upper right curve icon numbers, inner curve icon first
	LCARS.SetIconLocation(152, kTextureHandle, 0, 0, 8, 8, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_HORIZONTAL)
	LCARS.SetIconLocation(153, kTextureHandle, 8, 0, 6, 6, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_HORIZONTAL)
	# Lower left curve icon numbers, inner curve icon first
	LCARS.SetIconLocation(154, kTextureHandle, 0, 0, 8, 8, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_VERTICAL)
	LCARS.SetIconLocation(155, kTextureHandle, 8, 0, 6, 6, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_VERTICAL)
	# Lower right curve icon numbers, inner curve icon first
	LCARS.SetIconLocation(156, kTextureHandle, 0, 0, 8, 8, App.TGIconGroup.ROTATE_180)
	LCARS.SetIconLocation(157, kTextureHandle, 8, 0, 6, 6, App.TGIconGroup.ROTATE_180)

	# Window Icons
	# ------------

	# ST Menu title bar
	kTextureHandle = LCARS.LoadIconTexture("Data/Icons/STMenu.tga")
	
	# White block
	LCARS.SetIconLocation(200, kTextureHandle, 12, 42, 8, 8)
	
	kTextureHandle = LCARS.LoadIconTexture('Data/Icons/WindowIcons.tga')
	
	# Ruler upper left notch
	LCARS.SetIconLocation(201, kTextureHandle, 21, 49, 5, 5)

	# Ruler upper right notch
	LCARS.SetIconLocation(202, kTextureHandle, 21, 49, 5, 5, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_HORIZONTAL)

	# Ruler lower left notch
	LCARS.SetIconLocation(203, kTextureHandle, 21, 49, 5, 5, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_VERTICAL)

	# Ruler lower right notch
	LCARS.SetIconLocation(204, kTextureHandle, 21, 49, 5, 5, App.TGIconGroup.ROTATE_180)
	
	# Pointer arrows:
	# left
	LCARS.SetIconLocation(220, kTextureHandle, 0, 0, 16, 11)
	# up-left
	LCARS.SetIconLocation(221, kTextureHandle, 18, 0, 14, 14)
	# up
	LCARS.SetIconLocation(222, kTextureHandle, 0, 0, 16, 11, App.TGIconGroup.ROTATE_90)
	# up-right
	LCARS.SetIconLocation(223, kTextureHandle, 18, 0, 14, 14, App.TGIconGroup.ROTATE_90)
	# right
	LCARS.SetIconLocation(224, kTextureHandle, 0, 0, 16, 11, App.TGIconGroup.ROTATE_180)
	# down-right
	LCARS.SetIconLocation(225, kTextureHandle, 18, 0, 14, 14, App.TGIconGroup.ROTATE_90, App.TGIconGroup.MIRROR_VERTICAL)
	# down
	LCARS.SetIconLocation(226, kTextureHandle, 0, 0, 16, 11, App.TGIconGroup.ROTATE_90, App.TGIconGroup.MIRROR_VERTICAL)
	# down-left
	LCARS.SetIconLocation(227, kTextureHandle, 18, 0, 14, 14, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_VERTICAL)
	
	# Shields Display
	# --------------
	TextureHandle = LCARS.LoadIconTexture('Data/Icons/ShieldsDisplay.tga')

	# Top/Bottom
	LCARS.SetIconLocation(280, TextureHandle, 37, 35, 75, 55)

	# Front	
	LCARS.SetIconLocation(290, TextureHandle, 30, 1, 97, 22)

	# Rear
	LCARS.SetIconLocation(300, TextureHandle, 15, 99, 112, 28)

	# Left
	LCARS.SetIconLocation(310, TextureHandle, 1, 21, 30, 75)

	# Right
	LCARS.SetIconLocation(320, TextureHandle, 1, 21, 30, 75, 
							App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_HORIZONTAL)

	# Radar Blips
	# ------------
	TextureHandle = LCARS.LoadIconTexture('Data/Icons/WindowIcons.tga')
	
	# Small
	LCARS.SetIconLocation(400, TextureHandle, 21, 60, 5, 4)
		
	# Large
	LCARS.SetIconLocation(410, TextureHandle, 27, 58, 9, 6)

	# Missile
	LCARS.SetIconLocation(420, TextureHandle, 37, 61, 3, 3)

	# Bracket
	LCARS.SetIconLocation(430, TextureHandle, 20, 39, 13, 9)

	# Main Menu Icons
	# ------------------
	# Title icon
	kTextureHandle = LCARS.LoadIconTexture('Data/Icons/BCLogo1600.tga')
	LCARS.SetIconLocation(620, kTextureHandle, 0, 0, 238, 180)

	kTextureHandle = LCARS.LoadIconTexture('Data/Icons/gamespy.tga')
	LCARS.SetIconLocation(621, kTextureHandle, 0, 0, 128, 32)

	kTextureHandle = LCARS.LoadIconTexture('Data/Icons/bink.tga')
	LCARS.SetIconLocation(622, kTextureHandle, 0, 0, 99, 99)

	kTextureHandle = LCARS.LoadIconTexture('Data/Icons/miles.tga')
	LCARS.SetIconLocation(623, kTextureHandle, 0, 0, 100, 112)

	# Divider bar icon, for sorted region menu
	kTextureHandle = LCARS.LoadIconTexture('Data/Icons/DividerBar.tga')
	LCARS.SetIconLocation(700, kTextureHandle, 0, 0, 8, 8)

	# Multiplayer Icons
	# ------------------
	# System icon
	kTextureHandle = LCARS.LoadIconTexture('Data/Icons/System.tga')
	LCARS.SetIconLocation(800, kTextureHandle, 0, 0, 93, 131)

	# Radar ring bar icon
	kTextureHandle = LCARS.LoadIconTexture('Data/Icons/Bridge/RadarRing.tga')
	LCARS.SetIconLocation(900, kTextureHandle, 0, 0, 128, 128)

	# Numeric bar icons (frame)
	# -------------------------
	kTextureHandle = LCARS.LoadIconTexture("Data/Icons/Bridge/Background/ScreenFrame.tga")
	LCARS.SetIconLocation(2000, kTextureHandle, 18, 0, 7, 6)
	LCARS.SetIconLocation(2001, kTextureHandle, 27, 0, 2, 1)
	LCARS.SetIconLocation(2002, kTextureHandle, 18, 0, 7, 6, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_HORIZONTAL)
	LCARS.SetIconLocation(2003, kTextureHandle, 18, 7, 1, 1)
	LCARS.SetIconLocation(2004, kTextureHandle, 27, 7, 2, 2) # Empty
	LCARS.SetIconLocation(2005, kTextureHandle, 18, 7, 1, 1)
	LCARS.SetIconLocation(2006, kTextureHandle, 18, 0, 7, 6, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_VERTICAL)
	LCARS.SetIconLocation(2007, kTextureHandle, 27, 0, 2, 1)
	LCARS.SetIconLocation(2008, kTextureHandle, 18, 0, 7, 6, App.TGIconGroup.ROTATE_180)

	# Slider
	LCARS.SetIconLocation(2010, kTextureHandle, 0, 11, 6, 21)
	LCARS.SetIconLocation(2011, kTextureHandle, 7, 11, 6, 21)	# chosen

	# Marker
	LCARS.SetIconLocation(2020, kTextureHandle, 14, 11, 4, 19)

	# Menu icons
	# ----------
	kTextureHandle = LCARS.LoadIconTexture("Data/Icons/STMenu.tga")
	
	# Title bar
	LCARS.SetIconLocation(3000, kTextureHandle, 12, 42, 8, 8)
			
	# Highlight Marker
	LCARS.SetIconLocation(3001, kTextureHandle, 12, 42, 8, 8)

	# Left end cap normal
	LCARS.SetIconLocation(3002, kTextureHandle, 1, 32, 26, 28)

	# Right end cap.
	LCARS.SetIconLocation(3003, kTextureHandle, 1, 32, 26, 28, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_HORIZONTAL)

	# Arrows...
	kTextureHandle = LCARS.LoadIconTexture("Data/Icons/Bridge/NormalStyleFrameHigh.tga")
	LCARS.SetIconLocation(3020, kTextureHandle, 0,  68, 8, 13)								# Arrow left
	LCARS.SetIconLocation(3021, kTextureHandle, 0,  68, 8, 13, App.TGIconGroup.ROTATE_180)	# Arrow right
	LCARS.SetIconLocation(3022, kTextureHandle, 0,  68, 8, 13, App.TGIconGroup.ROTATE_90)	# Arrow up
	LCARS.SetIconLocation(3023, kTextureHandle, 0,  68, 8, 13, App.TGIconGroup.ROTATE_270)	# Arrow down
	LCARS.SetIconLocation(3005, kTextureHandle, 11, 68, 13, 13)								# Check button fill

	# Power Icons
	# -----------
	# Power bar overlay
	kTextureHandle = LCARS.LoadIconTexture("Data/Icons/PowerIcons.tga")
	LCARS.SetIconLocation(4000, kTextureHandle, 0, 0, 16, 8)

	# Ruler marks
	kTextureHandle = LCARS.LoadIconTexture("Data/Icons/tilehorizlinehigh.tga")
	LCARS.SetIconLocation(4100, kTextureHandle, 0, 0, 8, 8)

	kTextureHandle = LCARS.LoadIconTexture("Data/Icons/tilevertlinehigh.tga")
	LCARS.SetIconLocation(4101, kTextureHandle, 0, 0, 8, 8)

	# Hazard background
	kTextureHandle = LCARS.LoadIconTexture("Data/Icons/tilehazardhigh.tga")
	LCARS.SetIconLocation(4200, kTextureHandle, 0, 0, 16, 16)

	# Ruler - left closed, right open
	kTextureHandle = LCARS.LoadIconTexture("Data/Icons/Bridge/Background/ScreenFrame.tga")
	LCARS.SetIconLocation(4300, kTextureHandle, 0, 0, 11, 7)
	LCARS.SetIconLocation(4301, kTextureHandle, 12, 0, 2, 7)
	LCARS.SetIconLocation(4302, kTextureHandle, 0, 0, 11, 7, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_HORIZONTAL)
	LCARS.SetIconLocation(4303, kTextureHandle, 0, 8, 9, 2)
	LCARS.SetIconLocation(4304, kTextureHandle, 12, 8, 2, 2)	# empty
	LCARS.SetIconLocation(4305, kTextureHandle, 12, 8, 2, 2)	# empty
	LCARS.SetIconLocation(4306, kTextureHandle, 0, 0, 11, 7, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_VERTICAL)
	LCARS.SetIconLocation(4307, kTextureHandle, 12, 0, 2, 7, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_VERTICAL)
	LCARS.SetIconLocation(4308, kTextureHandle, 0, 0, 11, 7, App.TGIconGroup.ROTATE_180)

	# Ruler - left and right open
	LCARS.SetIconLocation(4310, kTextureHandle, 0, 0, 11, 7)
	LCARS.SetIconLocation(4311, kTextureHandle, 12, 0, 2, 7)
	LCARS.SetIconLocation(4312, kTextureHandle, 0, 0, 11, 7, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_HORIZONTAL)
	LCARS.SetIconLocation(4313, kTextureHandle, 12, 8, 2, 2)	# empty
	LCARS.SetIconLocation(4314, kTextureHandle, 12, 8, 2, 2)	# empty
	LCARS.SetIconLocation(4315, kTextureHandle, 12, 8, 2, 2)	# empty
	LCARS.SetIconLocation(4316, kTextureHandle, 0, 0, 11, 7, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_VERTICAL)
	LCARS.SetIconLocation(4317, kTextureHandle, 12, 0, 2, 7, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_VERTICAL)
	LCARS.SetIconLocation(4318, kTextureHandle, 0, 0, 11, 7, App.TGIconGroup.ROTATE_180)

	# Ruler - left open, right closed
	LCARS.SetIconLocation(4320, kTextureHandle, 0, 0, 11, 7)
	LCARS.SetIconLocation(4321, kTextureHandle, 12, 0, 2, 7)
	LCARS.SetIconLocation(4322, kTextureHandle, 0, 0, 11, 7, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_HORIZONTAL)
	LCARS.SetIconLocation(4323, kTextureHandle, 12, 8, 2, 2)	# empty
	LCARS.SetIconLocation(4324, kTextureHandle, 12, 8, 2, 2)	# empty
	LCARS.SetIconLocation(4325, kTextureHandle, 0, 8, 9, 2)
	LCARS.SetIconLocation(4326, kTextureHandle, 0, 0, 11, 7, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_VERTICAL)
	LCARS.SetIconLocation(4327, kTextureHandle, 12, 0, 2, 7, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_VERTICAL)
	LCARS.SetIconLocation(4328, kTextureHandle, 0, 0, 11, 7, App.TGIconGroup.ROTATE_180)

	# Ruler - left and right closed
	LCARS.SetIconLocation(4330, kTextureHandle, 0, 0, 11, 7)
	LCARS.SetIconLocation(4331, kTextureHandle, 12, 0, 2, 7)
	LCARS.SetIconLocation(4332, kTextureHandle, 0, 0, 11, 7, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_HORIZONTAL)
	LCARS.SetIconLocation(4333, kTextureHandle, 0, 8, 9, 2)
	LCARS.SetIconLocation(4334, kTextureHandle, 12, 8, 2, 2)	# empty
	LCARS.SetIconLocation(4335, kTextureHandle, 0, 8, 9, 2)
	LCARS.SetIconLocation(4336, kTextureHandle, 0, 0, 11, 7, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_VERTICAL)
	LCARS.SetIconLocation(4337, kTextureHandle, 12, 0, 2, 7, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_VERTICAL)
	LCARS.SetIconLocation(4338, kTextureHandle, 0, 0, 11, 7, App.TGIconGroup.ROTATE_180)

	# Special icon for use with power legend elbows
	LCARS.SetIconLocation(4340, kTextureHandle, 19, 11, 2, 7, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_VERTICAL)

###############################################################################
#	Switch()
#	
#	Called when we actually use this resolution. Anything that is changed in
#	the app itself should be set here instead of in the global scope or
#	Load_XYZ function.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def Switch():
	App.globals.DEFAULT_ST_INDENT_HORIZ	= 6		/ SCREEN_PIXEL_WIDTH
	App.globals.DEFAULT_ST_INDENT_VERT	= 3		/ SCREEN_PIXEL_HEIGHT
	App.globals.MARKER_INDENT_HORIZ		= 2		/ SCREEN_PIXEL_WIDTH
	App.globals.TAC_WEAPONS_CTRL_INDENT_HORIZ = 8 / SCREEN_PIXEL_WIDTH
