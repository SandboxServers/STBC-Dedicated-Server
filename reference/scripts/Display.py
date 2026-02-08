###############################################################################
#	Filename:	Display.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Display-related functions.
#	
#	Created:	2/2/2001 -	Erik Novales
###############################################################################

import App

###############################################################################
#	Initialize()
#	
#	Called when TopWindow initializes. Gives us a chance to do any necessary
#	setup based on graphics resolution before anything is laid out or built.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def Initialize():
	kInfo = App.GraphicsModeInfo_GetCurrentMode()

	SetDefaultFontBasedOnResolution(kInfo.GetCurrentResolution())

###############################################################################
#	SetDefaultFontBasedOnResolution(eResolution)
#	
#	Sets the default font based on the display resolution.
#	
#	Args:	eResolution	- the resolution enum from GraphicsModeInfo
#	
#	Return:	none
###############################################################################
def SetDefaultFontBasedOnResolution(eResolution):
	#print "Setting default font based on resolution."
	#if ((eResolution == App.GraphicsModeInfo.RES_640x480) or 
	#	(eResolution == App.GraphicsModeInfo.RES_800x600)):
	#	print "Using Tahoma."
	#	App.g_kFontManager.SetDefaultFont("Tahoma", 8)
	#else:
	#	print "Using Tahoma 14 point."
	#	App.g_kFontManager.SetDefaultFont("Tahoma", 14)
	pass
