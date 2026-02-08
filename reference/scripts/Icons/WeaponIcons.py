###############################################################################
#	Filename:	WeaponIcons.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Script file that creates the WeaponIcons icon group.
#	
#	Created:	2/9/2001 -	Erik Novales
###############################################################################

import App

UPPER_LEFT_FIELD_X					= 0
UPPER_LEFT_FIELD_WIDTH				= 34
UPPER_LEFT_FIELD_Y					= 0
UPPER_LEFT_FIELD_HEIGHT				= 37

UPPER_LEFT_CENTER_FIELD_X			= 34
UPPER_LEFT_CENTER_FIELD_WIDTH		= 43
UPPER_LEFT_CENTER_FIELD_Y			= 0
UPPER_LEFT_CENTER_FIELD_HEIGHT		= 32

LOWER_LEFT_FIELD_X					= 0
LOWER_LEFT_FIELD_WIDTH				= 34
LOWER_LEFT_FIELD_Y					= 38
LOWER_LEFT_FIELD_HEIGHT				= 38

LOWER_LEFT_CENTER_FIELD_X			= 34
LOWER_LEFT_CENTER_FIELD_WIDTH		= 43
LOWER_LEFT_CENTER_FIELD_Y			= 39
LOWER_LEFT_CENTER_FIELD_HEIGHT		= 29

LEFT_FIELD_X						= 42
LEFT_FIELD_Y						= 76
LEFT_FIELD_WIDTH					= 20
LEFT_FIELD_HEIGHT					= 42

FORWARD_FIELD_X						= 0
FORWARD_FIELD_Y						= 77
FORWARD_FIELD_WIDTH					= 42
FORWARD_FIELD_HEIGHT				= 20

FORWARD_RIGHT_OVERLAP_FIELD_X		= 66
FORWARD_RIGHT_OVERLAP_FIELD_Y		= 77
FORWARD_RIGHT_OVERLAP_FIELD_WIDTH	= 28
FORWARD_RIGHT_OVERLAP_FIELD_HEIGHT	= 19

def LoadWeaponIcons(kIcons = None):
	if (kIcons == None):
		kIcons = App.g_kIconManager.CreateIconGroup("WeaponIcons")
		App.g_kIconManager.AddIconGroup(kIcons)

	# Default icon. This is here to make all of the ships work, at least until
	# the appropriate icons are set.
	kTextureHandle = kIcons.LoadIconTexture('Data/Icons/Damage/Destroyed.tga')
	kIcons.SetIconLocation(0, kTextureHandle, 0, 0, 16, 16)

	# Phaser Firing Arcs
	# ------------------

	kTextureHandle = kIcons.LoadIconTexture('Data/Icons/PhaserArcs.tga')

	# Top Left
	kIcons.SetIconLocation(330, kTextureHandle, 0, 0, 54, 24)

	# Bottom Left Curve
	kIcons.SetIconLocation(335, kTextureHandle, 0, 0, 54, 24,
								App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_VERTICAL)

	# Bottom Left Hook
	kIcons.SetIconLocation(340, kTextureHandle, 0, 28, 31, 54)

	# Top Right
	kIcons.SetIconLocation(350, kTextureHandle, 0, 0, 54, 24, 
							App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_HORIZONTAL)

	# Bottom Right Curve
	kIcons.SetIconLocation(355, kTextureHandle, 0, 0, 54, 24,
														App.TGIconGroup.ROTATE_180)

	# Bottom Right Hook
	kIcons.SetIconLocation(360, kTextureHandle, 0, 28, 31, 54, 
							App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_HORIZONTAL)

	# Left
	kIcons.SetIconLocation(361, kTextureHandle, 47, 28, 16, 40)

	# Right
	kIcons.SetIconLocation(362, kTextureHandle, 47, 28, 16, 40,
								App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_HORIZONTAL)

	# Rear
	kIcons.SetIconLocation(363, kTextureHandle, 33, 87, 30, 10,
								App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_VERTICAL)

	# Forward
	kIcons.SetIconLocation(364, kTextureHandle, 33, 87, 30, 10)

	# Disrupter Cannon Icons
	# ---------------------

	# Forward
	kIcons.SetIconLocation(365, kTextureHandle, 0, 107, 5, 10)

	# Rear
	kIcons.SetIconLocation(366, kTextureHandle, 0, 107, 5, 10,
								App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_VERTICAL)

	# Torpedo Icons
	# --------------

	# Torpedo icon
	kIcons.SetIconLocation(370, kTextureHandle, 0, 122, 4, 6)

	# Phaser Arc Indicators
	# ---------------------
	kTextureHandle = kIcons.LoadIconTexture('Data/Icons/PhaserFields.tga')

	# Top Left
	kIcons.SetIconLocation(500, kTextureHandle, UPPER_LEFT_FIELD_X, UPPER_LEFT_FIELD_Y,
						  UPPER_LEFT_FIELD_WIDTH, UPPER_LEFT_FIELD_HEIGHT)

	# Top Left Center
	kIcons.SetIconLocation(501, kTextureHandle, UPPER_LEFT_CENTER_FIELD_X, UPPER_LEFT_CENTER_FIELD_Y, 
						  UPPER_LEFT_CENTER_FIELD_WIDTH, UPPER_LEFT_CENTER_FIELD_HEIGHT)

	# Top Right Center
	kIcons.SetIconLocation(502, kTextureHandle, UPPER_LEFT_CENTER_FIELD_X, UPPER_LEFT_CENTER_FIELD_Y, 
						  UPPER_LEFT_CENTER_FIELD_WIDTH, UPPER_LEFT_CENTER_FIELD_HEIGHT, 
						  App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_HORIZONTAL)

	# Top Right
	kIcons.SetIconLocation(503, kTextureHandle, UPPER_LEFT_FIELD_X, UPPER_LEFT_FIELD_Y, 
						  UPPER_LEFT_FIELD_WIDTH, UPPER_LEFT_FIELD_HEIGHT, 
						  App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_HORIZONTAL)

	# Bottom Left
	kIcons.SetIconLocation(504, kTextureHandle, LOWER_LEFT_FIELD_X, LOWER_LEFT_FIELD_Y,
						  LOWER_LEFT_FIELD_WIDTH, LOWER_LEFT_FIELD_HEIGHT)

	# Bottom Left Center
	kIcons.SetIconLocation(505, kTextureHandle, LOWER_LEFT_CENTER_FIELD_X, LOWER_LEFT_CENTER_FIELD_Y,
						  LOWER_LEFT_CENTER_FIELD_WIDTH, LOWER_LEFT_CENTER_FIELD_HEIGHT)

	# Bottom Right Center
	kIcons.SetIconLocation(506, kTextureHandle, LOWER_LEFT_CENTER_FIELD_X, LOWER_LEFT_CENTER_FIELD_Y,
						  LOWER_LEFT_CENTER_FIELD_WIDTH, LOWER_LEFT_CENTER_FIELD_HEIGHT, 
						  App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_HORIZONTAL)

	# Bottom Right
	kIcons.SetIconLocation(507, kTextureHandle, LOWER_LEFT_FIELD_X, LOWER_LEFT_FIELD_Y, 
						  LOWER_LEFT_FIELD_WIDTH, LOWER_LEFT_FIELD_HEIGHT, 
						  App.TGIconGroup.ROTATE_0,
						  App.TGIconGroup.MIRROR_HORIZONTAL)

	# Left
	kIcons.SetIconLocation(508, kTextureHandle, LEFT_FIELD_X, LEFT_FIELD_Y,
												LEFT_FIELD_WIDTH, LEFT_FIELD_HEIGHT)

	# Right
	kIcons.SetIconLocation(509, kTextureHandle, LEFT_FIELD_X, LEFT_FIELD_Y, 
												LEFT_FIELD_WIDTH, LEFT_FIELD_HEIGHT, 
												App.TGIconGroup.ROTATE_0,
												App.TGIconGroup.MIRROR_HORIZONTAL)

	# Rear
	kIcons.SetIconLocation(510, kTextureHandle, FORWARD_FIELD_X, FORWARD_FIELD_Y,
												FORWARD_FIELD_WIDTH, FORWARD_FIELD_HEIGHT)

	# Forward
	kIcons.SetIconLocation(511, kTextureHandle, FORWARD_FIELD_X, FORWARD_FIELD_Y, 
												FORWARD_FIELD_WIDTH, FORWARD_FIELD_HEIGHT, 
												App.TGIconGroup.ROTATE_0,
												App.TGIconGroup.MIRROR_VERTICAL)

	# Upper-left with a bit of forward overlap
	kIcons.SetIconLocation(512, kTextureHandle, FORWARD_RIGHT_OVERLAP_FIELD_X,
			FORWARD_RIGHT_OVERLAP_FIELD_Y, FORWARD_RIGHT_OVERLAP_FIELD_WIDTH,
			FORWARD_RIGHT_OVERLAP_FIELD_HEIGHT, App.TGIconGroup.ROTATE_0,
												App.TGIconGroup.MIRROR_HORIZONTAL)
	
	# Upper-right with a bit of forward overlap
	kIcons.SetIconLocation(513, kTextureHandle, FORWARD_RIGHT_OVERLAP_FIELD_X,
			FORWARD_RIGHT_OVERLAP_FIELD_Y, FORWARD_RIGHT_OVERLAP_FIELD_WIDTH,
			FORWARD_RIGHT_OVERLAP_FIELD_HEIGHT)

	# Lower-left with a bit of rear overlap
	kIcons.SetIconLocation(514, kTextureHandle, FORWARD_RIGHT_OVERLAP_FIELD_X,
			FORWARD_RIGHT_OVERLAP_FIELD_Y, FORWARD_RIGHT_OVERLAP_FIELD_WIDTH,
			FORWARD_RIGHT_OVERLAP_FIELD_HEIGHT, App.TGIconGroup.ROTATE_180)

	# Lower-right with a bit of rear overlap
	kIcons.SetIconLocation(515, kTextureHandle, FORWARD_RIGHT_OVERLAP_FIELD_X,
			FORWARD_RIGHT_OVERLAP_FIELD_Y, FORWARD_RIGHT_OVERLAP_FIELD_WIDTH,
			FORWARD_RIGHT_OVERLAP_FIELD_HEIGHT, App.TGIconGroup.ROTATE_0,
												App.TGIconGroup.MIRROR_VERTICAL)
