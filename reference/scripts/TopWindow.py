###############################################################################
#	Filename:	TopWindow.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Python setup and handling for the TopWindow.
#	
#	Created:	5/24/2001 -	KDeus
###############################################################################
import App

###############################################################################
#	Initialize()
#	
#	Setup event handlers for TopWindow.
#	
#	Args:	pWindow	- The TopWindow.
#	
#	Return:	none
###############################################################################
def Initialize(pWindow):
	try:
		import Local
		Local.TopWindowInitialized(pWindow)
	except:
		pass
