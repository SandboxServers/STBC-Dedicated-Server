###############################################################################
#	Filename:	UIHelpers.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	User interface helper functions.
#	
#	Created:	1/29/2001 -	Erik Novales
###############################################################################

import App

UPPER_LEFT_CURVE	= 0
UPPER_RIGHT_CURVE	= 1
LOWER_LEFT_CURVE	= 2
LOWER_RIGHT_CURVE	= 3

OUTER_CURVE_ICON	= 0
STRIP_1_ICON		= 1
STRIP_2_ICON		= 2
STRIP_3_ICON		= 3
INNER_CURVE_ICON	= 4

# Icon numbers in LCARS group for curve icons. Inner curve icon number is
# first.
g_kUpperLeftCurveIcons		= [140, 141]
g_kUpperRightCurveIcons		= [142, 143]
g_kLowerLeftCurveIcons		= [144, 145]
g_kLowerRightCurveIcons		= [146, 147]

g_kAlternateUpperLeftCurveIcons		= [150, 151]
g_kAlternateUpperRightCurveIcons	= [152, 153]
g_kAlternateLowerLeftCurveIcons		= [154, 155]
g_kAlternateLowerRightCurveIcons	= [156, 157]

g_kDefaultCurveSet =	[g_kUpperLeftCurveIcons, g_kUpperRightCurveIcons, g_kLowerLeftCurveIcons, g_kLowerRightCurveIcons]
g_kAlternateCurveSet =	[g_kAlternateUpperLeftCurveIcons, g_kAlternateUpperRightCurveIcons, g_kAlternateLowerLeftCurveIcons, g_kAlternateLowerRightCurveIcons]

###############################################################################
#	CreateCurve(iCurveType, 
#				fInnerWidth, fTotalWidth, fInnerHeight, fTotalHeight, kColor,
#				fOuterIconWidth)
#	
#	Creates a graphical curve in a TGPane, and returns it.
#
#	  ______________________________	   /=\
#	O/								|		|
#	/								|		|	outer height
#	|								|		|
#	|			____________________|	   \=/
#	|		   /						   /=\
#	|		  / I							|
#	|		 |								|	inner height
#	|		 |								|
#	|________|							   \=/
#
#	<========> inner width
#             <=====================> outer width
#	
#	Args:	iCurveType			- constant from above describing how to rotate
#								  the curve
#			fInnerWidth			- inner width as labeled above
#			fTotalWidth			- total width
#			fInnerHeight		- inner height as labeled above
#			fTotalHeight		- total height
#			kColor				- the color to use
#			fOuterIconWidth		- outer icon width.  Must be greater than outer height
#			kAlternateCurveSet	- other curves to use. See above for definitions.
#	
#	Return:	TGPane * - the pane containing all of the above
###############################################################################
def CreateCurve(iCurveType, fInnerWidth, fTotalWidth, fInnerHeight, 
				fTotalHeight, kColor, fOuterIconWidth = 0.0, 
				kAlternateCurveSet = None):
	# iOuterCurveIconNum	- icon used for O in the above diagram, from
	#						  the LCARS icon group.
	# iInnerCurveIconNum	- icon used for I in the above diagram, from
	#						  the LCARS icon group.

	if (kAlternateCurveSet == None):
		kCurveSet = g_kDefaultCurveSet
	else:
		kCurveSet = kAlternateCurveSet

	if (iCurveType == UPPER_LEFT_CURVE):
		iInnerCurveIconNum = kCurveSet[0][0]
		iOuterCurveIconNum = kCurveSet[0][1]
	elif (iCurveType == UPPER_RIGHT_CURVE):
		iInnerCurveIconNum = kCurveSet[1][0]
		iOuterCurveIconNum = kCurveSet[1][1]
	elif (iCurveType == LOWER_LEFT_CURVE):
		iInnerCurveIconNum = kCurveSet[2][0]
		iOuterCurveIconNum = kCurveSet[2][1]
	elif (iCurveType == LOWER_RIGHT_CURVE):
		iInnerCurveIconNum = kCurveSet[3][0]
		iOuterCurveIconNum = kCurveSet[3][1]

	pPane = App.TGPane_Create()

	# Get LCARS string.
	pGraphicsMode = App.GraphicsModeInfo_GetCurrentMode()
	pcLCARS = pGraphicsMode.GetLcarsString()

	# Create the outer and inner curve icons.
	pOuterCurveIcon = App.TGIcon_Create(pcLCARS, iOuterCurveIconNum, kColor)
	if (fOuterIconWidth == 0.0):
		fOuterIconWidth = pOuterCurveIcon.GetWidth()

	fOWidth = pOuterCurveIcon.GetWidth()
	fOHeight = pOuterCurveIcon.GetHeight()

	pInnerCurveIcon = App.TGIcon_Create(pcLCARS, iInnerCurveIconNum, kColor)
	fIWidth = pInnerCurveIcon.GetWidth()
	fIHeight = pInnerCurveIcon.GetHeight()

	fScreenRatio = App.g_kIconManager.GetScreenWidth () / App.g_kIconManager.GetScreenHeight ()

	fOuterIconHeight = fOuterIconWidth * fScreenRatio

	fOuterHeight = fTotalHeight - fInnerHeight
	fInnerIconHeight = fOuterIconHeight - fOuterHeight
	if (fInnerIconHeight < 0.0):
		fInnerIconHeight = pInnerCurveIcon.GetHeight()
	fStrip1Height = fTotalHeight - fOuterIconHeight
	fStrip2Width = fInnerWidth - fOuterIconWidth
	fInnerIconWidth = fIWidth / fIHeight * fInnerIconHeight
	fOuterWidth = fTotalWidth - fInnerWidth

	pOuterCurveIcon.Resize (fOuterIconWidth, fOuterIconHeight, 0)
	pInnerCurveIcon.Resize (fInnerIconWidth, fInnerIconHeight, 0)
				
	# Create the rest of the components.
	pStrip1 = App.TGIcon_Create(pcLCARS, 200, kColor)
	pStrip2 = App.TGIcon_Create(pcLCARS, 200, kColor)
	pStrip3 = App.TGIcon_Create(pcLCARS, 200, kColor)

	pStrip1.Resize(fInnerWidth, fStrip1Height, 0)
	pStrip2.Resize(fStrip2Width, fOuterIconHeight, 0)
	pStrip3.Resize(fOuterWidth, fOuterHeight, 0)

	# Now, based on the desired curve type, we need to place these in the pane.
	if (iCurveType == UPPER_LEFT_CURVE):
		# Upper left curve.
		pPane.AddChild(pOuterCurveIcon, 0.0, 0.0, 0)
		pPane.AddChild(pStrip1, 0, fStrip1Height, 0)
		pPane.AddChild(pStrip2, fOuterIconHeight, 0, 0)
		pPane.AddChild(pStrip3, fInnerWidth, 0, 0)
		pPane.AddChild(pInnerCurveIcon, fInnerWidth, fOuterHeight, 0)

		pStrip1.AlignTo(pOuterCurveIcon, App.TGUIObject.ALIGN_BL, App.TGUIObject.ALIGN_UL)
		pStrip2.AlignTo(pOuterCurveIcon, App.TGUIObject.ALIGN_UR, App.TGUIObject.ALIGN_UL)
		pStrip3.AlignTo(pStrip2, App.TGUIObject.ALIGN_UR, App.TGUIObject.ALIGN_UL)
		pInnerCurveIcon.AlignTo(pStrip3, App.TGUIObject.ALIGN_BL, App.TGUIObject.ALIGN_UL)

	elif (iCurveType == UPPER_RIGHT_CURVE):
		# Upper right curve.
		pPane.AddChild(pOuterCurveIcon, fOuterWidth + fStrip2Width, 0, 0)
		pPane.AddChild(pStrip1, fOuterWidth, fOuterIconWidth, 0)
		pPane.AddChild(pStrip2, fOuterWidth, 0, 0)
		pPane.AddChild(pStrip3, 0, 0, 0)
		pPane.AddChild(pInnerCurveIcon, fOuterWidth - fInnerIconWidth, fOuterHeight, 0)

		pInnerCurveIcon.AlignTo(pStrip3, App.TGUIObject.ALIGN_BR, App.TGUIObject.ALIGN_UR)
		pStrip2.AlignTo(pStrip3, App.TGUIObject.ALIGN_UR, App.TGUIObject.ALIGN_UL)
		pStrip1.AlignTo(pStrip2, App.TGUIObject.ALIGN_BL, App.TGUIObject.ALIGN_UL)
		pOuterCurveIcon.AlignTo(pStrip2, App.TGUIObject.ALIGN_UR, App.TGUIObject.ALIGN_UL)
	elif (iCurveType == LOWER_LEFT_CURVE):
		# Lower left curve.
		pPane.AddChild(pOuterCurveIcon, 0, fStrip1Height, 0)
		pPane.AddChild(pStrip1, 0, 0, 0)
		pPane.AddChild(pStrip2, fInnerWidth - fStrip2Width, fStrip1Height, 0)
		pPane.AddChild(pStrip3, fInnerWidth, fInnerHeight, 0)
		pPane.AddChild(pInnerCurveIcon, fInnerWidth, fStrip1Height, 0)

		pOuterCurveIcon.AlignTo(pStrip1, App.TGUIObject.ALIGN_BL, App.TGUIObject.ALIGN_UL)
		pStrip2.AlignTo(pOuterCurveIcon, App.TGUIObject.ALIGN_UR, App.TGUIObject.ALIGN_UL)
		pStrip3.AlignTo(pStrip2, App.TGUIObject.ALIGN_BR, App.TGUIObject.ALIGN_BL)
		pInnerCurveIcon.AlignTo(pStrip3, App.TGUIObject.ALIGN_UL, App.TGUIObject.ALIGN_BL)
	elif (iCurveType == LOWER_RIGHT_CURVE):
		# Lower right curve.
		pPane.AddChild(pOuterCurveIcon, fOuterWidth + fStrip2Width, fStrip1Height, 0)
		pPane.AddChild(pStrip1, fOuterWidth, 0, 0)
		pPane.AddChild(pStrip2, fOuterWidth, fStrip1Height, 0)
		pPane.AddChild(pStrip3, 0, fInnerHeight, 0)
		pPane.AddChild(pInnerCurveIcon, fOuterWidth - fInnerIconWidth, fStrip1Height, 0)

		pStrip3.AlignTo(pStrip2, App.TGUIObject.ALIGN_BL, App.TGUIObject.ALIGN_BR)
		pInnerCurveIcon.AlignTo(pStrip3, App.TGUIObject.ALIGN_UR, App.TGUIObject.ALIGN_BR)

# 		pStrip1.AlignTo(pStrip2, App.TGUIObject.ALIGN_UL, App.TGUIObject.ALIGN_BL)
#		pOuterCurveIcon.AlignTo(pStrip1, App.TGUIObject.ALIGN_BR, App.TGUIObject.ALIGN_UR)

	pPane.Resize(fTotalWidth, fTotalHeight)
	pPane.SetNoFocus()

	return(pPane)

def GetOuterHeight (pCurve):
	# Get the appropriate graphical element
	pBar = pCurve.GetNthChild (3)
	return pBar.GetHeight ()

def GetOuterIcon (pCurve):
	# Get the appropriate graphical element
	pBar = pCurve.GetNthChild (3)
	return pBar


###############################################################################
#	CreateRoundedButton(fWidth, fHeight, kColor)
#	Args:	
#			fWidth			- self explanatory
#			fHeight			- self explanatory
#			kColor				- the color to use
#	
#	Return:	TGPane * - the pane containing all of the above
###############################################################################
def CreateRoundedButton(fWidth, fHeight, kColor):

	pPane = App.TGPane_Create()

	# Get LCARS string.
	pGraphicsMode = App.GraphicsModeInfo_GetCurrentMode()
	pcLCARS = pGraphicsMode.GetLcarsString()

	# Calculate the size of the curves based on the height
	fScreenRatio = App.g_kIconManager.GetScreenWidth () / App.g_kIconManager.GetScreenHeight ()
	fCurveHeight = fHeight * 2.0 / 5.0
	fBetweenHeight = fHeight / 5.0
	fCurveWidth = fCurveHeight / fScreenRatio

	# Calculate the size of the square region
	fRectWidth = fWidth - fCurveWidth * 2.0
	if (fRectWidth < 0):
		fRectWidth = 0

	# Create the icons
	pRectRegion = App.TGIcon_Create(pcLCARS, 200, kColor)
	pRectRegion.Resize (fRectWidth, fHeight, 0)
	pPane.AddChild (pRectRegion, fCurveWidth, 0, 0)

	pCurve = App.TGIcon_Create(pcLCARS, g_kUpperLeftCurveIcons[1], kColor)
	pCurve.Resize (fCurveWidth, fCurveHeight, 0)
	pPane.AddChild (pCurve, 0, 0, 0)
	pCurve.AlignTo(pRectRegion, App.TGUIObject.ALIGN_UL, App.TGUIObject.ALIGN_UR)

	pBetweenCurveRegion = App.TGIcon_Create(pcLCARS, 200, kColor)
	pBetweenCurveRegion.Resize (fCurveWidth, fBetweenHeight + 0.00208, 0)
	pPane.AddChild (pBetweenCurveRegion, 0, fCurveHeight, 0)

	pCurve = App.TGIcon_Create(pcLCARS, g_kLowerLeftCurveIcons[1], kColor)
	pCurve.Resize (fCurveWidth, fCurveHeight, 0)
	pPane.AddChild (pCurve, 0, fCurveHeight * 2, 0)
	pCurve.AlignTo(pRectRegion, App.TGUIObject.ALIGN_BL, App.TGUIObject.ALIGN_BR)
	pBetweenCurveRegion.AlignTo(pCurve, App.TGUIObject.ALIGN_UR, App.TGUIObject.ALIGN_BR)

	pCurve = App.TGIcon_Create(pcLCARS, g_kUpperRightCurveIcons[1], kColor)
	pCurve.Resize (fCurveWidth, fCurveHeight, 0)
	pPane.AddChild (pCurve, fRectWidth + fCurveWidth, 0, 0)
	pCurve.AlignTo(pRectRegion, App.TGUIObject.ALIGN_UR, App.TGUIObject.ALIGN_UL)

	pBetweenCurveRegion = App.TGIcon_Create(pcLCARS, 200, kColor)
	pBetweenCurveRegion.Resize (fCurveWidth, fBetweenHeight + 0.00208, 0)
	pPane.AddChild (pBetweenCurveRegion, fRectWidth + fCurveWidth, fCurveHeight, 0)

	pCurve = App.TGIcon_Create(pcLCARS, g_kLowerRightCurveIcons[1], kColor)
	pCurve.Resize (fCurveWidth, fCurveHeight, 0)
	pPane.AddChild (pCurve, fRectWidth + fCurveWidth, fCurveHeight * 2, 0)
	pCurve.AlignTo(pRectRegion, App.TGUIObject.ALIGN_BR, App.TGUIObject.ALIGN_BL)
	pBetweenCurveRegion.AlignTo(pCurve, App.TGUIObject.ALIGN_UL, App.TGUIObject.ALIGN_BL)


	# Resize the pane based on curve and rect size.  Note it is not using the width
	# directly, since it may be different than the calculated widths.
	pPane.Resize(fCurveWidth * 2 + fRectWidth, fHeight)

	return(pPane)

###############################################################################
#	CreateRightRoundedButton(fWidth, fHeight, kColor)
#
#	Creates a button that is rounded only on the right edge
#
#	Args:	
#			fWidth			- self explanatory
#			fHeight			- self explanatory
#			kColor				- the color to use
#	
#	Return:	TGPane * - the pane containing all of the above
###############################################################################
def CreateRightRoundedButton(fWidth, fHeight, kColor):

	pPane = App.TGPane_Create()

	# Get LCARS string.
	pGraphicsMode = App.GraphicsModeInfo_GetCurrentMode()
	pcLCARS = pGraphicsMode.GetLcarsString()

	# Calculate the size of the curves based on the height
	fScreenRatio = App.g_kIconManager.GetScreenWidth () / App.g_kIconManager.GetScreenHeight ()
	fCurveHeight = fHeight * 2.0 / 5.0
	fBetweenHeight = fHeight / 5.0
	fCurveWidth = fCurveHeight / fScreenRatio

	# Calculate the size of the square region
	fRectWidth = fWidth - fCurveWidth
	if (fRectWidth < 0):
		fRectWidth = 0

	# Create the icons
	pRectRegion = App.TGIcon_Create(pcLCARS, 200, kColor)
	pRectRegion.Resize (fRectWidth, fHeight, 0)
	pPane.AddChild (pRectRegion, 0.0, 0.0, 0)

	pCurve = App.TGIcon_Create(pcLCARS, g_kUpperRightCurveIcons[1], kColor)
	pCurve.Resize(fCurveWidth, fCurveHeight, 0)
	pPane.AddChild(pCurve, fRectWidth, 0, 0)
	pCurve.AlignTo(pRectRegion, App.TGUIObject.ALIGN_UR, App.TGUIObject.ALIGN_UL)

	pBetweenCurveRegion = App.TGIcon_Create(pcLCARS, 200, kColor)
	pBetweenCurveRegion.Resize(fCurveWidth, fBetweenHeight + 0.00208, 0)
	pPane.AddChild(pBetweenCurveRegion, fRectWidth, fCurveHeight, 0)

	pCurve = App.TGIcon_Create(pcLCARS, g_kLowerRightCurveIcons[1], kColor)
	pCurve.Resize(fCurveWidth, fCurveHeight, 0)
	pPane.AddChild(pCurve, fRectWidth, fCurveHeight * 2, 0)
	pCurve.AlignTo(pRectRegion, App.TGUIObject.ALIGN_BR, App.TGUIObject.ALIGN_BL)
	pBetweenCurveRegion.AlignTo(pCurve, App.TGUIObject.ALIGN_UL, App.TGUIObject.ALIGN_BL)

	# Resize the pane based on curve and rect size.  Note it is not using the width
	# directly, since it may be different than the calculated widths.
	pPane.Resize(fCurveWidth + fRectWidth, fHeight)

	return pPane

def CreateBracket (fWidth, fHeight, fTabHeight, kColor):
	pPane = App.TGPane_Create(fWidth, fHeight)

	# Get LCARS string.
	pGraphicsMode = App.GraphicsModeInfo_GetCurrentMode()
	pcLCARS = pGraphicsMode.GetLcarsString()

	fScreenRatio = App.g_kIconManager.GetScreenWidth () / App.g_kIconManager.GetScreenHeight ()

	fHBarHeight = 2 / App.g_kIconManager.GetScreenHeight ()
	fVBarWidth = 2 / App.g_kIconManager.GetScreenWidth ()
	
	# Create horizontal bars
	pHBar1 = App.TGIcon_Create(pcLCARS, 200, kColor)
	pHBar1.Resize (fWidth / 2.0, fHBarHeight, 0)
	pPane.AddChild (pHBar1, 0, fTabHeight - (fHBarHeight / 2.0), 0)
	
	pHBar2 = App.TGIcon_Create(pcLCARS, 200, kColor)
	pHBar2.Resize (fWidth / 2.0, fHBarHeight, 0)
	pPane.AddChild (pHBar2, fWidth / 2.0, 0, 0)

	pHBar3 = App.TGIcon_Create(pcLCARS, 200, kColor)
	pHBar3.Resize (fWidth / 2.0, fHBarHeight, 0)
	pPane.AddChild (pHBar3, fWidth / 2.0, fHeight - fHBarHeight, 0)

	# Create Vertical bar
	pVBar = App.TGIcon_Create(pcLCARS, 200, kColor)
	pVBar.Resize (fVBarWidth, fHeight, 0)
	pPane.AddChild (pVBar, (fWidth - fVBarWidth) / 2.0, 0, 0)

	return pPane

def CreateIcon (iIconNum, fWidth, fHeight, kColor):
	# Get LCARS string.
	pGraphicsMode = App.GraphicsModeInfo_GetCurrentMode()
	pcLCARS = pGraphicsMode.GetLcarsString()

	# Create the outer and inner curve icons.
	pIcon = App.TGIcon_Create(pcLCARS, iIconNum, kColor)
	pIcon.Resize (fWidth, fHeight, 0)

	return pIcon

