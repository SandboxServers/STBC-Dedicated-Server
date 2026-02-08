###############################################################################
#	Filename:	CardSpecificSetup.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	!Evil Hack!
#	This file is to deal with the drivers that lie to us about what they can do.
#	
#	Created:	??/??/?? -	James Therien
###############################################################################

import App

def GetMaxRez(sCardString):
	import string

	# Match string MUST be lower case
	lMaxRezNames  = (	
		("tnt2" , 1024), 
		("tnt" , 800), 
		("voodoo2" , 800),
		("voodoo" , 1024),
		("g200" , 800),
		("rage" , 800) )

	# Cycle through all the keys in the dictionary...
	for sKey, iRes in lMaxRezNames:
		# Search for the key as a substring in the driver description.
		if ( string.find(string.lower (sCardString) , sKey) != -1 ):
			# The driver description contains one of the keys we're looking for.
			return iRes

	# Couldn't find any matches.	
	return 0

def ForceZBuffering(sCardString, bHighZBuffer):
	import string

	lForceList = (
		"radeon",
		"voodoo2" )

	for sKey in lForceList:
		# Search for the key as a substring in the driver description.
		if ( string.find(string.lower (sCardString) , sKey) != -1 ):
			# The driver description contains one of the keys we're looking for.
			return 1

	return 0

def CanDoEnhancedGlows(sCardString, bHighColor = 0):
	import string

	# voodoo 5 has problems with enhaqnced glows and high colors
	if (bHighColor == 1 and string.find(string.lower (sCardString) , "voodoo 5") != -1):
		return 0

	lCanDoEnhanced  = (
		"voodoo2",
		"Intel",
		"g200",
		"g400",	
		"g550",	
		"rage",
		"magnum",	
		"xpert128",
		"x99",
		"xpert2000",
		"diamond stealth 3 s540" )

	# Cycle through all the keys in the dictionary...
	for sKey in lCanDoEnhanced:
		# Search for the key as a substring in the driver description.
		if ( string.find(string.lower (sCardString) , sKey) != -1 ):
			# The driver description contains one of the keys we're looking for.
			return 0

	# Couldn't find any matches.
	# assume it can	
	return 1

###############################################################################
#	ResChanged(sCardString)
#	
#	Called when the resolution changes. This allows us to make any necessary
#	changes for the pixel adjustment value.
#	
#	Args:	sCardString	- the 3D card's device string
#	
#	Return:	none
###############################################################################
def ResChanged(sCardString):
	import string
	pMode = App.GraphicsModeInfo_GetCurrentMode()

	# Match string MUST be lower case
	ddPixelAdjValues  = {
		# There is no more need for this. If there are cards that misbehave
		# with regards to pixel centering adjustment, then add them in as
		# named keys, with a dictionary of values to use at different
		# resolutions.
		# Example:
		# "super graphics card":	{ 640:	-.45,
		#							  800:	-.5,
		#							  1024: -.45,
		#							  ...
		#							}
		}

	# Cycle through all the keys in the dictionary...
	for sKey in ddPixelAdjValues.keys():
		# Search for the key as a substring in the driver description.
		if ( string.find(string.lower (sCardString) , sKey) != -1 ):
			# The driver description contains one of the keys we're looking for.
			dCardValues = ddPixelAdjValues[sKey]

			if dCardValues.has_key(pMode.GetWidth()):
				App.g_kIconManager.SetPixelCenterAdj(dCardValues[pMode.GetWidth()])
				return

			# No key? Strange, just use the default.
			App.g_kIconManager.SetPixelCenterAdj(-0.5)
			return

	# Couldn't find it. Use the regular adjustment.
	App.g_kIconManager.SetPixelCenterAdj(-0.5)
	return
