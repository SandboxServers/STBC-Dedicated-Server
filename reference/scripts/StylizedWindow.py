###############################################################################
#	Filename:	StylizedWindow.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	A bunch of functions for the various styles of STStylizedWindow
#	instances.
#	
#	Created:	5/22/2001 -	KDeus
###############################################################################
import App

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print

g_iAlternateGlass = 121

###############################################################################
#	Miscellaneous functions used by the styles in this file.
###############################################################################
def GetInteriorSize(pInterior):
	if pInterior.IsVisible():
		return ( pInterior.GetWidth(), pInterior.GetHeight() )
	return (pInterior.GetWidth(), 0.0)

def GetChildren(pPane):
	lChildren = []
	pChild = pPane.GetFirstChild()
	while pChild:
		lChildren.append(pChild)
		pChild = pPane.GetNextChild(pChild)
	return lChildren

def SetMinimizeVisibility(pScroll, pMinimize, pRestore):
	# Set either the Minimize or the Restore button visible.
	if pScroll.IsVisible():
		pMinimize.SetVisible(0)
		pRestore.SetNotVisible(0)
	else:
		pMinimize.SetNotVisible(0)
		pRestore.SetVisible(0)

def ResizeIconsToArtwork(*lUIObjects):
	for pObj in lUIObjects:
		pIcon = App.TGIcon_Cast(pObj)
		if pIcon:
			pIcon.SizeToArtwork(0)
		pPane = App.TGPane_Cast(pObj)
		if pPane:
			lNewChildren = GetChildren(pPane)
			apply(ResizeIconsToArtwork, lNewChildren)

		pButton = App.TGButton_Cast(pObj)
		if pButton:
			pChild = pButton.GetFirstChild()
			pButton.Resize(pChild.GetWidth(), pChild.GetHeight(), 0)

###############################################################################
#	Icon groups used by windows in this file.
###############################################################################
def LoadNormalStyleFrame(pGroup = None):
	if pGroup is None:
		pGroup = App.g_kIconManager.CreateIconGroup("NormalStyleFrame")
		App.g_kIconManager.AddIconGroup(pGroup)
	pTexture = pGroup.LoadIconTexture("Data/Icons/Bridge/NormalStyleFrame.tga")
	pGroup.SetIconLocation(0, pTexture, 0, 0, 12, 22)	# Top left curve
	pGroup.SetIconLocation(1, pTexture, 0, 22, 7, 4)	# Left side
	pGroup.SetIconLocation(2, pTexture, 0, 26, 12, 11)	# Bottom left curve
	pGroup.SetIconLocation(3, pTexture, 12, 34, 3, 3)	# Bottom line
	pGroup.SetIconLocation(4, pTexture, 48, 34, 2, 3)	# Bottom line right cap
	pGroup.SetIconLocation(5, pTexture, 12, 0, 2, 14)	# Title bar
	pGroup.SetIconLocation(6, pTexture, 14, 0, 4, 14)	# Pre-title Title bar right cap
	pGroup.SetIconLocation(7, pTexture, 20, 0, 5, 14)	# Post-title Title bar left cap
	pGroup.SetIconLocation(8, pTexture, 26, 0, 1, 14)	# Post-title Title bar right cap

	pGroup.SetIconLocation(9, pTexture, 30, 38, 33, 14)	 # Minimize button pressed
	pGroup.SetIconLocation(10, pTexture, 30, 16, 33, 14) # Minimize button
	pGroup.SetIconLocation(11, pTexture, 30, 53, 33, 14) # Minimize button disabled
	pGroup.SetIconLocation(12, pTexture, 30, 38, 33, 14, App.TGIconGroup.ROTATE_180) # Restore button pressed
	pGroup.SetIconLocation(13, pTexture, 30, 16, 33, 14, App.TGIconGroup.ROTATE_180) # Restore button
	pGroup.SetIconLocation(14, pTexture, 30, 53, 33, 14, App.TGIconGroup.ROTATE_180) # Restore button disabled

	pGroup.SetIconLocation(15, pTexture, 30, 38, 33, 14, App.TGIconGroup.ROTATE_180) # Scroll up button pressed
	pGroup.SetIconLocation(16, pTexture, 30, 16, 33, 14, App.TGIconGroup.ROTATE_180) # Scroll up button
	pGroup.SetIconLocation(17, pTexture, 30, 53, 33, 14, App.TGIconGroup.ROTATE_180) # Scroll up button disabled

	pGroup.SetIconLocation(18, pTexture, 30, 38, 33, 14) # Scroll down button pressed
	pGroup.SetIconLocation(19, pTexture, 30, 16, 33, 14) # Scroll down button
	pGroup.SetIconLocation(20, pTexture, 30, 53, 33, 14) # Scroll down button disabled
	pGroup.SetIconLocation(21, pTexture, 27, 16, 3, 1)	# Pre-button spacing.
	pGroup.SetIconLocation(22, pTexture, 14, 0, 1, 14, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_HORIZONTAL)	# Left cap if minimized.
	pGroup.SetIconLocation(23, pTexture, 12, 14, 1, 4)	# Under-title-bar spacing

	pGroup.SetIconLocation(30, pTexture, 0, 38, 2, 1)	# Thin separator bar top cap
	pGroup.SetIconLocation(31, pTexture, 0, 39, 2, 2)	# Thin separator bar
	pGroup.SetIconLocation(32, pTexture, 0, 41, 2, 1)	# Thin separator bar bottom cap

	pGroup.SetIconLocation(40, pTexture, 0, 42, 11, 22)	# Bottom left if scrollbars needed
	pGroup.SetIconLocation(41, pTexture, 11, 50, 2, 14)	# Bottom line if scrollbars needed
	pGroup.SetIconLocation(42, pTexture, 13, 50, 1, 14)	# Bottom line right cap if scrollbars needed

	pGroup.SetIconLocation(43, pTexture, 0, 0, 12, 22,
		App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_HORIZONTAL)	# Top right curve
	pGroup.SetIconLocation(44, pTexture, 0, 22, 7, 4,
		App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_HORIZONTAL)		# Right side

###############################################################################
#	
#	BaseStyle class.  This shouldn't be used directly, but it
#	provides some basic common functionality between the styles.
#	
###############################################################################
class BaseStyle:
	###############################################################################
	#	UISwitchIconGroups, UIResize, UIReposition
	#	
	#	The screen resolution has changed. Change icon groups, resize, and 
	#	reposition if necessary.
	#	
	#	Args:	pWindow		- the STStylizedWindow
	#			pExterior	- the exterior pane
	#			pScroll		- the scroll window
	#	
	#	Return:	None
	###############################################################################
	def UISwitchIconGroups(self, pWindow, pExterior, pScroll):
		# Resize all our icons to their artwork size...
		lChildren = GetChildren(pExterior)
		apply(ResizeIconsToArtwork, lChildren)
		for pChild in lChildren:
			pChild.Resize(pChild.GetWidth(), pChild.GetHeight(), 1)

	def UIResize(self, pWindow, pExterior, pScroll):
		# And call our Resize function.
		self.Resize(pWindow, pExterior, pScroll)
		pWindow.Layout()

	def UIReposition(self, pWindow, pExterior, pScroll):
		# This is a little bit of a fudge here...basically, the script called
		# by TacticalControlWindow.py will resize things, and then we need to
		# resize the window's bits here.
		self.Resize(pWindow, pExterior, pScroll)
		pWindow.Layout()

	def UpdateMinimize(self, pWindow, pExterior, pScroll):
		return

	def UpdateGlass(self, pWindow, pExterior, pScroll):
		return

###############################################################################
#	
#	NormalStyle style
#	
###############################################################################
class NormalStyle(BaseStyle):
	###############################################################################
	#	Setup
	#	
	#	Create border bits for the "NormalStyle" style of STStylizedWindow.
	#	
	#	Args:	pWindow		- The STStylizedWindow that we're setting up.
	#			pExterior	- The exterior TGPane where all the border goes.
	#			pScroll		- The scroll window for this window.
	#	
	#	Return:	None
	###############################################################################
	def Setup(self, pWindow, pExterior, pScroll):
		# Import resolution dependent LCARS module for size/placement variables.
		pcLCARS = App.GraphicsModeInfo_GetCurrentMode().GetLcarsString()

		# Setup the minimize/restore buttons.
		pMinimize, pRestore = NormalStyleMinimizeRestoreButtons(pWindow)
		pScrollUp, pScrollDown = NormalStyleScrollButtons(pWindow)

		# Create all our little bits and pieces and add them as children.
		pMainColor = App.NiColorA()
		pWindow.GetColor(pMainColor)

		pNamePane = App.TGPane_Create()
		pName = App.TGParagraph_CreateW(pWindow.GetName(), 1.0, App.globals.g_kTitleColor)
		pName.Layout()
		pNamePane.AddChild( pName ) # Name
		pExterior.AddChild( pNamePane ) # Name pane
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 0, pMainColor), 0.0, 0.0, 0 ) # Top left curve
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 1, pMainColor), 0.0, 0.0, 0 ) # Left side
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 2, pMainColor), 0.0, 0.0, 0 ) # Bottom left curve
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 3, pMainColor), 0.0, 0.0, 0 ) # Bottom line
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 4, pMainColor), 0.0, 0.0, 0 ) # Bottom line right cap
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 5, pMainColor), 0.0, 0.0, 0 ) # Pre-title Title bar
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 23, pMainColor), 0.0, 0.0, 0 )# Under-title-bar spacing
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 6, pMainColor), 0.0, 0.0, 0 ) # Pre-title Title bar right cap
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 7, pMainColor), 0.0, 0.0, 0 ) # Post-title Title bar left cap
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 5, pMainColor), 0.0, 0.0, 0 ) # Post-title Title bar
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 8, pMainColor), 0.0, 0.0, 0 ) # Post-title Title bar right cap
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 21, pMainColor), 0.0, 0.0, 0 )# Pre-button spacing
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 22, pMainColor), 0.0, 0.0, 0 )# Left cap if minimized
		pExterior.AddChild( pMinimize, 0.0, 0.0, 0 )
		pExterior.AddChild( pRestore, 0.0, 0.0, 0 )
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 40, pMainColor), 0.0, 0.0, 0 ) # Bottom left curve if scrollbars needed
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 41, pMainColor), 0.0, 0.0, 0 ) # Bottom line if scrollbars needed
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 42, pMainColor), 0.0, 0.0, 0 ) # Bottom line right cap if scrollbars needed
		pExterior.AddChild( pScrollUp, 0.0, 0.0, 0 )
		pExterior.AddChild( pScrollDown, 0.0, 0.0, 0 )

		# Glass background pieces.
		pExterior.AddChild( App.TGIcon_Create(pcLCARS, 120), 0.0, 0.0, 0 )
		pExterior.AddChild( App.TGIcon_Create(pcLCARS, 120), 0.0, 0.0, 0 )
		pExterior.AddChild( App.TGIcon_Create(pcLCARS, 120), 0.0, 0.0, 0 )

		# Resize all our icons to their artwork size...
		lChildren = GetChildren(pExterior)
		apply(ResizeIconsToArtwork, lChildren)

	###############################################################################
	#	Resize
	#	
	#	Size and move border bits for the "Normal" style of STStylizedWindow.
	#	
	#	Args:	pWindow		- The STStylizedWindow that we're setting up.
	#			pExterior	- The exterior TGPane where all the border goes.
	#			pScroll		- The scroll window for this window.
	#	
	#	Return:	None
	###############################################################################
	def Resize(self, pWindow, pExterior, pScroll):
		# Get the width/height of the scroll window.
		fScrollWidth, fScrollHeight = GetInteriorSize(pScroll)

		# Get our important exterior bits, so we can resize and reposition them.
		pNamePane, pTopLeft, pLeft, pBottomLeft, pBottom, pBottomRight, pPreTitle, pVerticalSpacing, pPreTitleCap, pPostTitleLeftCap, pPostTitle, pPostTitleRightCap, pPreButtonSpacing, pLeftCapMinimized, pMinimize, pRestore, pBottomLeftIfScroll, pBottomIfScroll, pBottomRightIfScroll, pScrollUp, pScrollDown, pGlass1, pGlass2, pGlass3 = GetChildren(pExterior)

		pNamePane = App.TGPane_Cast(pNamePane)
		pName = App.TGParagraph_Cast(pNamePane.GetFirstChild())
		pName.SetStringW(pWindow.GetName(), 0)

		#################################
		# Resize everything.
		#################################
		# Fix default icon sizes.
		ResizeIconsToArtwork( pTopLeft, pLeft, pBottomLeft, pBottom, pBottomRight, pPreTitle, pVerticalSpacing, pPreTitleCap, pPostTitleLeftCap, pPostTitle, pPostTitleRightCap, pPreButtonSpacing, pLeftCapMinimized, pMinimize, pRestore, pBottomLeftIfScroll, pBottomIfScroll, pBottomRightIfScroll, pScrollUp, pScrollDown )

		# If we're minimized, things are very different.  Make lists for the
		# things that are visible when minimized or visible when not minimized.
		# Things not in either of these lists are always visible.
		lVisibleWhenMinimized = (pLeftCapMinimized, pRestore)
		lVisibleWhenNotMinimized = (pTopLeft, pLeft, pBottomLeft,
									pBottom, pBottomRight, pVerticalSpacing,
									pMinimize, pBottomLeftIfScroll, pBottomIfScroll,
									pBottomRightIfScroll, pScrollUp, pScrollDown,
									pGlass2, pGlass3)
		if not pScroll.IsVisible():
			# Minimized.  Make sure everything that should be visible
			# is visible.
			for pVisibleIcon in lVisibleWhenMinimized:
				pVisibleIcon.SetVisible(0)
			for pNotVisibleIcon in lVisibleWhenNotMinimized:
				pNotVisibleIcon.SetNotVisible(0)

			# Use minimized layout.
			self.MinimizedLayout(pWindow, pExterior, pScroll)
			return
		else:
			# Not minimized.  Make sure everything that should be
			# visible is visible.
			for pNotVisibleIcon in lVisibleWhenMinimized:
				pNotVisibleIcon.SetNotVisible(0)
			for pVisibleIcon in lVisibleWhenNotMinimized:
				pVisibleIcon.SetVisible(0)

			# If we have a fixed title bar thickness, we have to resize some of our
			# elements to match
			if pWindow.GetTitleBarThickness() <> 0.0:
				fOldTitleHeight = pPostTitle.GetHeight()
				pPreTitle.Resize(pPreTitle.GetWidth(), pWindow.GetTitleBarThickness(), 0)
				pPreTitleCap.Resize(pPreTitleCap.GetWidth(), pWindow.GetTitleBarThickness(), 0)
				pPostTitleLeftCap.Resize(pPostTitleLeftCap.GetWidth(), pWindow.GetTitleBarThickness(), 0)
				pPostTitle.Resize(pPostTitle.GetWidth(), pWindow.GetTitleBarThickness(), 0)
				pPostTitleRightCap.Resize(pPostTitleRightCap.GetWidth(), pWindow.GetTitleBarThickness(), 0)
				pPreButtonSpacing.Resize(pPreButtonSpacing.GetWidth(), pWindow.GetTitleBarThickness(), 0)
				pLeftCapMinimized.Resize(pLeftCapMinimized.GetWidth(), pWindow.GetTitleBarThickness(), 0)
				pMinimize.Resize(pMinimize.GetWidth(), pWindow.GetTitleBarThickness(), 0)
				fNewOldRatio = pPostTitle.GetHeight() / fOldTitleHeight
				pTopLeft.Resize(pTopLeft.GetWidth(), pTopLeft.GetHeight() * fNewOldRatio, 0)


		# Find the overall width and height...
		fHeight = App.TGUIModule_PixelAlignValue(max(pPreTitle.GetHeight() + (2.0 * pVerticalSpacing.GetHeight()) + fScrollHeight + pBottom.GetHeight(), 
													 pTopLeft.GetHeight() + pBottomLeft.GetHeight()), 0)
		if pWindow.IsFixedSize():
			fWidth = App.TGUIModule_PixelAlignValue(pWindow.GetMaximumWidth())
		else:
			fWidth = App.TGUIModule_PixelAlignValue(fScrollWidth + pLeft.GetWidth())

		if fWidth > pWindow.GetMaximumWidth():
			fWidth = pWindow.GetMaximumWidth()

		# If the height is too great, shrink it and add scroll buttons.
		if (fHeight > pWindow.GetMaximumHeight()) and (pWindow.IsUseScrolling() == 1):
			# Need to scroll.  Set the new height to the max height available.
			fHeight = pWindow.GetMaximumHeight()

			# Set the various bottom icons visible/not visible.
			pBottomLeft.SetNotVisible(0)
			pBottom.SetNotVisible(0)
			pBottomRight.SetNotVisible(0)

			pBottomLeftIfScroll.SetVisible(0)
			pBottomIfScroll.SetVisible(0)
			pBottomRightIfScroll.SetVisible(0)
			pScrollUp.SetVisible(0)
			pScrollDown.SetVisible(0)

			# Find out how much room is available for the scroll window now.
			fScrollHeight = max(0, fHeight - pPreTitle.GetHeight() - 2.0 * pVerticalSpacing.GetHeight() - pBottomIfScroll.GetHeight())
			pWindow.SetScrollViewHeight(fScrollHeight)

			# Resize bottom and left pieces.
			pBottomIfScroll.Resize(fWidth - pBottomLeftIfScroll.GetWidth() - pBottomRightIfScroll.GetWidth() - (pPreButtonSpacing.GetWidth() * 2.0) - pScrollUp.GetWidth() - pScrollDown.GetWidth(), pBottomIfScroll.GetHeight(), 0)
			pLeft.Resize(pLeft.GetWidth(), max(0.0, fHeight - pTopLeft.GetHeight() - pBottomLeftIfScroll.GetHeight()), 0)
		else:
			# Not scrolling.  Make sure the appropriate icons are visible.
			if pWindow.IsFixedSize():
				fHeight = pWindow.GetMaximumHeight()

			pBottomLeft.SetVisible(0)
			pBottom.SetVisible(0)
			pBottomRight.SetVisible(0)

			pBottomLeftIfScroll.SetNotVisible(0)
			pBottomIfScroll.SetNotVisible(0)
			pBottomRightIfScroll.SetNotVisible(0)
			pScrollUp.SetNotVisible(0)
			pScrollDown.SetNotVisible(0)

			pWindow.SetScrollViewHeight(-1)

			# Resize bottom and left pieces.
			pBottom.Resize(fWidth - pBottomLeft.GetWidth() - pBottomRight.GetWidth(), pBottom.GetHeight(), 0)
			pLeft.Resize(pLeft.GetWidth(), max(0.0, fHeight - pTopLeft.GetHeight() - pBottomLeft.GetHeight()), 0)

		# Find the maximum width available for the title.
		fMaxTitleWidth = App.TGUIModule_PixelAlignValue(fWidth - pTopLeft.GetWidth() - pPreTitle.GetWidth() - pPreTitleCap.GetWidth() - 
						  pPostTitleLeftCap.GetWidth() - pPostTitleRightCap.GetWidth() - 
						  pPreButtonSpacing.GetWidth() - pMinimize.GetWidth())
		pNamePane.Resize(min(pName.GetWidth(), fMaxTitleWidth), pName.GetHeight(), 0)

		# Because of the minimize button, the top title bar (after the title) is shorter..
		fOtherWidth = App.TGUIModule_PixelAlignValue(fMaxTitleWidth - pNamePane.GetWidth())
		pPostTitle.Resize(fOtherWidth, pPostTitle.GetHeight(), 0)

		#    +-------+
		# +--+       +  Very rough sketch
		# +2 |   1   +  (not to scale)
		# ++-+       +  of how the 3
		#  +-+       +  glass pieces
		#    +-------+  fit together.
		# Glass.  Main piece covers the entire height, and most of the area, from the right.
		pGlass1.Resize(fWidth - pBottomLeft.GetWidth(), fHeight, 0)
		# Second piece covers most of the left, minus a little bit at the bottom.
		pGlass2.Resize(pBottomLeft.GetWidth(), fHeight - pPreTitle.GetHeight() - (pBottomLeft.GetHeight() / 2.0), 0)
		# Final piece covers the little bit in the lower left...
		pGlass3.Resize(pBottomLeft.GetWidth() / 2.0, fHeight - pGlass2.GetHeight() - (pBottomLeft.GetHeight() / 4.0))




		#################################
		# Reposition everything.
		#################################
		pTopLeft.SetPosition			(0.0, 0.0, 0)
		pPreTitle.SetPosition			(pTopLeft.GetRight(), 0.0, 0)
		pPreTitleCap.SetPosition		(pPreTitle.GetRight(), 0.0, 0)
		#pNamePane.SetPosition			(pPreTitleCap.GetRight(), pPreTitle.GetBottom() - pNamePane.GetHeight(), 0)
		pNamePane.SetPosition			(pPreTitleCap.GetRight(), max(pPreTitle.GetBottom() - pNamePane.GetHeight(), -App.globals.DEFAULT_ST_INDENT_VERT), 0)
		pPostTitleLeftCap.SetPosition	(pNamePane.GetRight(), 0.0, 0)
		pPostTitle.SetPosition			(pPostTitleLeftCap.GetRight(), 0.0, 0)
		pPostTitleRightCap.SetPosition	(pPostTitle.GetRight(), 0.0, 0)
		pMinimize.SetPosition			(pPostTitleRightCap.GetRight() + pPreButtonSpacing.GetWidth(), 0.0, 0)
		pRestore.SetPosition			(pMinimize.GetLeft(), pMinimize.GetTop(), 0)
		pLeft.SetPosition				(0.0, pTopLeft.GetBottom(), 0)

		pScroll.SetPosition				(pLeft.GetRight(), pPreTitle.GetBottom() + pVerticalSpacing.GetHeight(), 0)

		pBottomLeft.SetPosition			(0.0, pLeft.GetBottom(), 0)
		pBottom.SetPosition				(pBottomLeft.GetRight(), pBottomLeft.GetBottom() - pBottom.GetHeight(), 0)
		pBottomRight.SetPosition		(pBottom.GetRight(), pBottomLeft.GetBottom() - pBottomRight.GetHeight(), 0)

		pBottomLeftIfScroll.SetPosition	(0.0, pLeft.GetBottom(), 0)
		pBottomIfScroll.SetPosition		(pBottomLeftIfScroll.GetRight(), pBottomLeftIfScroll.GetBottom() - pBottomIfScroll.GetHeight(), 0)
		pBottomRightIfScroll.SetPosition(pBottomIfScroll.GetRight(), pBottomLeftIfScroll.GetBottom() - pBottomRightIfScroll.GetHeight(), 0)
		pScrollUp.SetPosition			(pBottomRightIfScroll.GetRight() + pPreButtonSpacing.GetWidth(), pBottomLeftIfScroll.GetBottom() - pScrollUp.GetHeight(), 0)
		pScrollDown.SetPosition			(pScrollUp.GetRight() + pPreButtonSpacing.GetWidth(), pBottomLeftIfScroll.GetBottom() - pScrollDown.GetHeight(), 0)

		pGlass1.SetPosition				(pBottomLeft.GetRight(), 0.0, 0)
		pGlass2.SetPosition				(0.0, pPreTitle.GetBottom(), 0)
		pGlass3.SetPosition				(pBottomLeft.GetWidth() / 2.0, pGlass2.GetBottom(), 0)

		# Visibility of the minimize/restore buttons...
		#SetMinimizeVisibility(pScroll, pMinimize, pRestore)

		# Overall size of our window.
		pExterior.Resize(fWidth, fHeight, 0)
		pWindow.Resize( pExterior.GetWidth(), pExterior.GetHeight(), 0 )

	###############################################################################
	#	MinimizedLayout
	#	
	#	Resize and reposition everything for the layout when
	#	a NormalStyle window is minimized.
	#	
	#	Args:	pWindow		- The STStylizedWindow that we're setting up.
	#			pExterior	- The exterior TGPane where all the border goes.
	#			pScroll		- The scroll window for this window.
	#	
	#	Return:	None
	###############################################################################
	def MinimizedLayout(self, pWindow, pExterior, pScroll):
		# Get our relevant children.
		(pNamePane, pTopLeft, pLeft, pBottomLeft, pBottom, pBottomRight, pPreTitle, 
		 pVerticalSpacing, pPreTitleCap, pPostTitleLeftCap, pPostTitle, pPostTitleRightCap, 
		 pPreButtonSpacing, pLeftCapMinimized, pMinimize, pRestore, pBottomLeftIfScroll, 
		 pBottomIfScroll, pBottomRightIfScroll, pScrollUp, pScrollDown, pGlass1, 
		 pGlass2, pGlass3) = GetChildren(pExterior)

		pNamePane = App.TGPane_Cast(pNamePane)
		pName = App.TGParagraph_Cast(pNamePane.GetFirstChild())

		fHalfPixelWidth = App.GraphicsModeInfo_GetCurrentMode().GetPixelWidth() / 2.0
		#################################
		# Resize everything.
		#################################
		if (pWindow.GetMaximumWidth() == 1.0):
			# No maximum or fixed size.
			fWidth = App.TGUIModule_PixelAlignValue(pScroll.GetWidth() + pWindow.GetBorderWidth())
		else:
			fWidth = App.TGUIModule_PixelAlignValue(pWindow.GetMaximumWidth())

		fHeight = pPreTitle.GetHeight()

		# Find the maximum width available for the title.
		fMaxTitleWidth = App.TGUIModule_PixelAlignValue(fWidth - pLeftCapMinimized.GetWidth() - pPreTitle.GetWidth() - 
						  pPreTitleCap.GetWidth() - pPostTitleLeftCap.GetWidth() - pPostTitleRightCap.GetWidth() - 
						  pPreButtonSpacing.GetWidth() - pRestore.GetWidth())
		pNamePane.Resize(min(pName.GetWidth(), fMaxTitleWidth), pName.GetHeight(), 0)

		# Resize title bar and glass.
		fOtherWidth = App.TGUIModule_PixelAlignValue(fMaxTitleWidth - pNamePane.GetWidth())
		pPostTitle.Resize(fOtherWidth, pPostTitle.GetHeight(), 0)
		pGlass1.Resize(App.TGUIModule_PixelAlignValue(fWidth - pLeftCapMinimized.GetWidth()), fHeight, 0)

		#################################
		# Reposition everything.
		#################################
		pLeftCapMinimized.SetPosition	(0.0, 0.0, 0)

		# Align from the right.
		pRestore.SetPosition			(fWidth - pRestore.GetWidth(), 0.0, 0)
		pPostTitleRightCap.SetPosition	(pRestore.GetLeft() - pPreButtonSpacing.GetWidth() - pPostTitleRightCap.GetWidth(), 0.0, 0)
		pPostTitle.SetPosition			(pPostTitleRightCap.GetLeft() - pPostTitle.GetWidth(), 0.0, 0)
		pPostTitleLeftCap.SetPosition	(pPostTitle.GetLeft() - pPostTitleLeftCap.GetWidth(), 0.0, 0)
		pNamePane.SetPosition			(pPostTitleLeftCap.GetLeft() - pNamePane.GetWidth(), 0.0, 0)
		pPreTitleCap.SetPosition		(pNamePane.GetLeft() - pPreTitleCap.GetWidth(), 0.0, 0)
		pPreTitle.SetPosition			(pPreTitleCap.GetLeft() - pPreTitle.GetWidth(), 0.0, 0)

		pGlass1.SetPosition				(pLeftCapMinimized.GetRight(), 0.0, 0)

		# Overall size of our window.
		pExterior.Resize(fWidth, fHeight, 0)
		pWindow.Resize( pExterior.GetWidth(), pExterior.GetHeight(), 0 )

	###############################################################################
	#	GetBorderWidth
	#	
	#	Returns the width of the border for this style, assuming the interior
	#	fits nicely inside it (no scrolling).
	#	
	#	Args:	pWindow		- the STStylizedWindow
	#			pExterior	- the exterior pane
	#			pScroll		- the scroll window
	#	
	#	Return:	NiPoint2 - The border width and height
	###############################################################################
	def GetBorderWidth(self, pWindow, pExterior, pScroll):
		# Get our relevant children.
		pNamePane, pTopLeft, pLeft, pBottomLeft, pBottom, pBottomRight, pPreTitle, pVerticalSpacing, pPreTitleCap, pPostTitleLeftCap, pPostTitle, pPostTitleRightCap, pPreButtonSpacing, pLeftCapMinimized, pMinimize, pRestore, pBottomLeftIfScroll, pBottomIfScroll, pBottomRightIfScroll, pScrollUp, pScrollDown, pGlass1, pGlass2, pGlass3 = GetChildren(pExterior)

		#fVerticalSpacing = (pWindow.GetTitleBarThickness() or pPreTitle.GetHeight()) + 2.0 * pVerticalSpacing.GetHeight() + pBottom.GetHeight()
		fVerticalSpacing = max((pWindow.GetTitleBarThickness() or pPreTitle.GetHeight()) + 2.0 * pVerticalSpacing.GetHeight() + pBottom.GetHeight(), 
							   pTopLeft.GetHeight() + pBottomLeft.GetHeight())

		kPoint = App.TGUIModule_PixelAlignPoint(App.NiPoint2(pLeft.GetWidth() + App.globals.DEFAULT_ST_INDENT_HORIZ, 
															 fVerticalSpacing))

		return kPoint

	###############################################################################
	#	UpdateScrollArrows(self, pWindow, pExterior, pScroll)
	#	
	#	Updates the state of the scroll arrows (whether they should be enabled or
	#	disabled).
	#	
	#	Args:	pWindow		- the STStylizedWindow
	#			pExterior	- the exterior pane
	#			pScroll		- the scroll window
	#	
	#	Return:	none
	###############################################################################
	def UpdateScrollArrows(self, pWindow, pExterior, pScroll):
		(pNamePane, pTopLeft, pLeft, pBottomLeft, pBottom, pBottomRight, pPreTitle, 
		 pVerticalSpacing, pPreTitleCap, pPostTitleLeftCap, pPostTitle, pPostTitleRightCap, 
		 pPreButtonSpacing, pLeftCapMinimized, pMinimize, pRestore, pBottomLeftIfScroll, 
		 pBottomIfScroll, pBottomRightIfScroll, pScrollUp, pScrollDown, pGlass1, 
		 pGlass2, pGlass3) = GetChildren(pExterior)

		pInterior = pWindow.GetInteriorPane()

		bSendScrollEndEvent = 0
		pMode = App.GraphicsModeInfo_GetCurrentMode()
		fHalfPixel = pMode.GetPixelHeight() / 2.0
		 
		if (pInterior.GetTop() < -fHalfPixel):
			pScrollUp.SetEnabled()
		else:
			if pWindow.IsScrolling() == App.STStylizedWindow.SCROLL_UP:
				pScrollUp.SetDisabled()
				bSendScrollEndEvent = 1
				App.TGButton_Cast(pScrollUp).ClearMouseDown(0)
			elif pWindow.IsScrolling() == App.STStylizedWindow.NO_SCROLL:
				pScrollUp.SetDisabled()

		if pInterior.GetBottom() > (pScroll.GetHeight() + fHalfPixel):
			pScrollDown.SetEnabled()
		else:
			if pWindow.IsScrolling() == App.STStylizedWindow.SCROLL_DOWN:
				pScrollDown.SetDisabled()
				bSendScrollEndEvent = 1
				App.TGButton_Cast(pScrollDown).ClearMouseDown(0)
			elif pWindow.IsScrolling() == App.STStylizedWindow.NO_SCROLL:
				pScrollDown.SetDisabled()

		if (bSendScrollEndEvent == 1):
			# Send a "stop scrolling" event.
			pEvent = App.TGIntEvent_Create()
			pEvent.SetSource(pWindow)
			pEvent.SetDestination(pWindow)
			pEvent.SetEventType(App.ET_ST_PERIODIC_SCROLL_DOWN)
			pEvent.SetInt(0)
			App.g_kEventManager.AddEvent(pEvent)

		return

	###############################################################################
	#	GetNameParagraph(self, pWindow, pExterior, pScroll)
	#	
	#	Returns the paragraph used for the name.
	#	
	#	Args:	pWindow		- the STStylizedWindow
	#			pExterior	- the exterior pane
	#			pScroll		- the scroll pane
	#	
	#	Return:	TGParagraph * - the name paragraph
	###############################################################################
	def GetNameParagraph(self, pWindow, pExterior, pScroll):
		(pNamePane, pTopLeft, pLeft, pBottomLeft, pBottom, pBottomRight, pPreTitle, 
		 pVerticalSpacing, pPreTitleCap, pPostTitleLeftCap, pPostTitle, pPostTitleRightCap, 
		 pPreButtonSpacing, pLeftCapMinimized, pMinimize, pRestore, pBottomLeftIfScroll, 
		 pBottomIfScroll, pBottomRightIfScroll, pScrollUp, pScrollDown, pGlass1, 
		 pGlass2, pGlass3) = GetChildren(pExterior)

		return(App.TGParagraph_Cast(App.TGPane_Cast(pNamePane).GetFirstChild()))

	###############################################################################
	#	UpdateMinimize(self, pWindow, pExterior, pScroll)
	#	
	#	Called to update the minimize/restore buttons.
	#	
	#	Args:	pWindow		- the stylized window
	#			pExterior	- the exterior pane
	#			pScroll		- the scroll pane
	#	
	#	Return:	none
	###############################################################################
	def UpdateMinimize(self, pWindow, pExterior, pScroll):
		(pNamePane, pTopLeft, pLeft, pBottomLeft, pBottom, pBottomRight, pPreTitle, 
		 pVerticalSpacing, pPreTitleCap, pPostTitleLeftCap, pPostTitle, pPostTitleRightCap, 
		 pPreButtonSpacing, pLeftCapMinimized, pMinimize, pRestore, pBottomLeftIfScroll, 
		 pBottomIfScroll, pBottomRightIfScroll, pScrollUp, pScrollDown, pGlass1, 
		 pGlass2, pGlass3) = GetChildren(pExterior)

		if pWindow.IsMinimizable():
			pMinimize.SetEnabled(0)
			pRestore.SetEnabled(0)
		else:
			pMinimize.SetDisabled(0)
			pRestore.SetDisabled(0)

	###############################################################################
	#	UpdateGlass(self, pWindow, pExterior, pScroll)
	#	
	#	Called to update the glass, if we're using different glass when we have the
	#	true focus path.
	#	
	#	Args:	pWindow		- the stylized window
	#			pExterior	- the exterior pane
	#			pScroll		- the scroll pane
	#	
	#	Return:	none
	###############################################################################
	def UpdateGlass(self, pWindow, pExterior, pScroll):
		(pNamePane, pTopLeft, pLeft, pBottomLeft, pBottom, pBottomRight, pPreTitle, 
		 pVerticalSpacing, pPreTitleCap, pPostTitleLeftCap, pPostTitle, pPostTitleRightCap, 
		 pPreButtonSpacing, pLeftCapMinimized, pMinimize, pRestore, pBottomLeftIfScroll, 
		 pBottomIfScroll, pBottomRightIfScroll, pScrollUp, pScrollDown, pGlass1, 
		 pGlass2, pGlass3) = GetChildren(pExterior)

		pGlass1 = App.TGIcon_Cast(pGlass1)
		pGlass2 = App.TGIcon_Cast(pGlass2)
		pGlass3 = App.TGIcon_Cast(pGlass3)

		if pWindow.IsInTrueFocusPath() and pWindow.IsUseFocusGlass():
			kColor = App.NiColorA()
			kColor.r = 0.0
			kColor.g = 0.0
			kColor.b = 0.0
			kColor.a = 0.9
			kColor = App.NiColorA_WHITE
			for pIcon in [pGlass1, pGlass2, pGlass3]:
				if pIcon.GetIconNum() != g_iAlternateGlass:
					pIcon.SetIconNum(g_iAlternateGlass)
				pIcon.SetColor(kColor)
		else:
			for pIcon in [pGlass1, pGlass2, pGlass3]:
				if pIcon.GetIconNum() != 120:
					pIcon.SetIconNum(120)
				pIcon.SetColor(App.NiColorA_WHITE)
			
		pWindow.Layout()
			
		return

###############################################################################
#	NormalStyleMinimizeRestoreButtons
#	
#	Helper function that creates Minimize and Restore buttons
#	for NormalStyle (and others).
#	
#	Args:	pWindow	- The STStylizedWindow for which we're
#					  creating the icons.  The destination for
#					  the events.
#	
#	Return:	(pMinimize, pRestore) buttons.
###############################################################################
def NormalStyleMinimizeRestoreButtons(pWindow):
	pMinimizeEvent = App.TGBoolEvent_Create()
	pMinimizeEvent.SetEventType(App.ET_ST_MINIMIZE)
	pMinimizeEvent.SetDestination(pWindow)
	pMinimizeEvent.SetBool(1)

	pMinimize = App.TGButton_Create("NormalStyleFrame", 9)
	pMinimize.SetActivationEvent(pMinimizeEvent)

	pRestoreEvent = App.TGBoolEvent_Create()
	pRestoreEvent.SetEventType(App.ET_ST_MINIMIZE)
	pRestoreEvent.SetDestination(pWindow)
	pRestoreEvent.SetBool(0)

	pRestore = App.TGButton_Create("NormalStyleFrame", 12)
	pRestore.SetActivationEvent(pRestoreEvent)

	return (pMinimize, pRestore)

###############################################################################
#	NormalStyleScrollButtons
#	
#	Helper function to create scroll buttons.
#	
#	Args:	pWindow	- The STStylizedWindow for which we're
#					  creating the icons.  The destination for
#					  the events.
#	
#	Return:	(pScrollUp, pScrollDown) buttons.
###############################################################################
def NormalStyleScrollButtons(pWindow):
	pStartScroll = App.TGIntEvent_Create()
	pStartScroll.SetEventType(App.ET_ST_SCROLL)
	pStartScroll.SetDestination(pWindow)
	pStartScroll.SetInt(-1)

	pStopScroll = App.TGIntEvent_Create()
	pStopScroll.SetEventType(App.ET_ST_SCROLL)
	pStopScroll.SetDestination(pWindow)
	pStopScroll.SetInt(0)

	pScrollUp = App.TGButton_Create("NormalStyleFrame", 15)
	pScrollUp.SetMouseDownEvent( pStartScroll )
	pScrollUp.SetMouseUpEvent( pStopScroll )

	pStartScroll = App.TGIntEvent_Create()
	pStartScroll.SetEventType(App.ET_ST_SCROLL)
	pStartScroll.SetDestination(pWindow)
	pStartScroll.SetInt(1)

	pStopScroll = App.TGIntEvent_Create()
	pStopScroll.SetEventType(App.ET_ST_SCROLL)
	pStopScroll.SetDestination(pWindow)
	pStopScroll.SetInt(0)

	pScrollDown = App.TGButton_Create("NormalStyleFrame", 18)
	pScrollDown.SetMouseDownEvent( pStartScroll )
	pScrollDown.SetMouseUpEvent( pStopScroll )

	return (pScrollUp, pScrollDown)



###############################################################################
#	
#	NoMinimize style
#	
###############################################################################
class NoMinimize(BaseStyle):
	###############################################################################
	#	Setup() 
	#	
	#	Setup function for the "NoMinimize" window style.
	#	
	#	Args:	pWindow		- The STStylizedWindow that we're setting up.
	#			pExterior	- The exterior TGPane where all the border goes.
	#			pScroll		- The scroll window for this window.
	#	
	#	Return:	None
	###############################################################################
	def Setup(self, pWindow, pExterior, pScroll):
		# Import resolution dependent LCARS module for size/placement variables.
		pcLCARS = App.GraphicsModeInfo_GetCurrentMode().GetLcarsString()

		# Setup the minimize/restore buttons.
		pScrollUp, pScrollDown = NormalStyleScrollButtons(pWindow)

		# Create all our little bits and pieces and add them as children.
		pMainColor = App.NiColorA()
		pWindow.GetColor(pMainColor)

		pNamePane = App.TGPane_Create()
		pName = App.TGParagraph_CreateW(pWindow.GetName(), 1.0, App.globals.g_kTitleColor)
		pName.Layout()
		pNamePane.AddChild( pName ) # Name
		pExterior.AddChild( pNamePane ) # Name pane
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 0, pMainColor), 0.0, 0.0, 0 ) # Top left curve
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 1, pMainColor), 0.0, 0.0, 0 ) # Left side
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 2, pMainColor), 0.0, 0.0, 0 ) # Bottom left curve
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 3, pMainColor), 0.0, 0.0, 0 ) # Bottom line
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 4, pMainColor), 0.0, 0.0, 0 ) # Bottom line right cap
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 5, pMainColor), 0.0, 0.0, 0 ) # Pre-title Title bar
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 23, pMainColor), 0.0, 0.0, 0 )# Under-title-bar spacing
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 6, pMainColor), 0.0, 0.0, 0 ) # Pre-title Title bar right cap
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 7, pMainColor), 0.0, 0.0, 0 ) # Post-title Title bar left cap
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 5, pMainColor), 0.0, 0.0, 0 ) # Post-title Title bar
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 8, pMainColor), 0.0, 0.0, 0 ) # Post-title Title bar right cap
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 21, pMainColor), 0.0, 0.0, 0 )# Pre-button spacing
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 40, pMainColor), 0.0, 0.0, 0 ) # Bottom left curve if scrollbars needed
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 41, pMainColor), 0.0, 0.0, 0 ) # Bottom line if scrollbars needed
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 42, pMainColor), 0.0, 0.0, 0 ) # Bottom line right cap if scrollbars needed
		pExterior.AddChild( pScrollUp, 0.0, 0.0, 0 )
		pExterior.AddChild( pScrollDown, 0.0, 0.0, 0 )

		# Glass background pieces.
		pExterior.AddChild( App.TGIcon_Create(pcLCARS, 120), 0.0, 0.0, 0 )
		pExterior.AddChild( App.TGIcon_Create(pcLCARS, 120), 0.0, 0.0, 0 )
		pExterior.AddChild( App.TGIcon_Create(pcLCARS, 120), 0.0, 0.0, 0 )

		# Resize all our icons to their artwork size...
		lChildren = GetChildren(pExterior)
		apply(ResizeIconsToArtwork, lChildren)

	###############################################################################
	#	Resize() 
	#	
	#	Resize function for the "NoMinimize" window style.
	#	
	#	Args:	pWindow		- The STStylizedWindow that we're setting up.
	#			pExterior	- The exterior TGPane where all the border goes.
	#			pScroll		- The scroll window for this window.
	#	
	#	Return:	None
	###############################################################################
	def Resize(self, pWindow, pExterior, pScroll):
		# Get the width/height of the scroll window.
		fScrollWidth, fScrollHeight = GetInteriorSize(pScroll)

		# Get our important exterior bits, so we can resize and reposition them.
		pNamePane, pTopLeft, pLeft, pBottomLeft, pBottom, pBottomRight, pPreTitle, pVerticalSpacing, pPreTitleCap, pPostTitleLeftCap, pPostTitle, pPostTitleRightCap, pPreButtonSpacing, pBottomLeftIfScroll, pBottomIfScroll, pBottomRightIfScroll, pScrollUp, pScrollDown, pGlass1, pGlass2, pGlass3 = GetChildren(pExterior)

		pNamePane = App.TGPane_Cast(pNamePane)
		pName = App.TGParagraph_Cast(pNamePane.GetFirstChild())
		pName.SetStringW(pWindow.GetName(), 0)

		#################################
		# Resize everything.
		#################################
		# Fix default icon sizes.
		ResizeIconsToArtwork( pTopLeft, pLeft, pBottomLeft, pBottom, pBottomRight, pPreTitle, pVerticalSpacing, pPreTitleCap, pPostTitleLeftCap, pPostTitle, pPostTitleRightCap, pPreButtonSpacing, pBottomLeftIfScroll, pBottomIfScroll, pBottomRightIfScroll, pScrollUp, pScrollDown )


		lVisible = (pTopLeft, pLeft, pBottomLeft,
					pBottom, pBottomRight, pVerticalSpacing,
					pBottomLeftIfScroll, pBottomIfScroll,
					pBottomRightIfScroll, pScrollUp, pScrollDown,
					pGlass2, pGlass3)
		# Make sure everything that should be
		# visible is visible.
		for pVisibleIcon in lVisible:
			pVisibleIcon.SetVisible(0)

		if pWindow.GetTitleBarThickness() != 0.0:
			fOldTitleHeight = pPostTitle.GetHeight()
			pPreTitle.Resize(pPreTitle.GetWidth(), pWindow.GetTitleBarThickness(), 0)
			pPreTitleCap.Resize(pPreTitleCap.GetWidth(), pWindow.GetTitleBarThickness(), 0)
			pPostTitleLeftCap.Resize(pPostTitleLeftCap.GetWidth(), pWindow.GetTitleBarThickness(), 0)
			pPostTitle.Resize(pPostTitle.GetWidth(), pWindow.GetTitleBarThickness(), 0)
			pPostTitleRightCap.Resize(pPostTitleRightCap.GetWidth(), pWindow.GetTitleBarThickness(), 0)
			pVerticalSpacing.Resize(pVerticalSpacing.GetWidth(), 0.01, 0)
			pPreButtonSpacing.Resize(pPreButtonSpacing.GetWidth(), pWindow.GetTitleBarThickness(), 0)
			fNewOldHeightRatio = pPostTitle.GetHeight() / fOldTitleHeight
			pTopLeft.Resize(pTopLeft.GetWidth(), pTopLeft.GetHeight() * fNewOldHeightRatio, 0)

		# Find the overall width and height...
		if pWindow.IsFixedSize():
			fWidth = pWindow.GetMaximumWidth()
		else:
			fWidth = fScrollWidth + pLeft.GetWidth()
		fHeight = App.TGUIModule_PixelAlignValue(max(pPreTitle.GetHeight() + (2.0 * pVerticalSpacing.GetHeight()) + fScrollHeight + pBottom.GetHeight(), 
													 pTopLeft.GetHeight() + pBottomLeft.GetHeight()), 0)
		
		# If the height is too great, shrink it and add scroll buttons.
		if (fHeight > pWindow.GetMaximumHeight()) and (pWindow.IsUseScrolling() == 1):
			# Need to scroll.  Set the new height to the max height available.
			fHeight = pWindow.GetMaximumHeight()

			# Set the various bottom icons visible/not visible.
			pBottomLeft.SetNotVisible(0)
			pBottom.SetNotVisible(0)
			pBottomRight.SetNotVisible(0)

			pBottomLeftIfScroll.SetVisible(0)
			pBottomIfScroll.SetVisible(0)
			pBottomRightIfScroll.SetVisible(0)
			pScrollUp.SetVisible(0)
			pScrollDown.SetVisible(0)

			# Find out how much room is available for the scroll window now.
			fScrollHeight = max(0, fHeight - pPreTitle.GetHeight() - 2.0 * pVerticalSpacing.GetHeight() - pBottomIfScroll.GetHeight())
			pWindow.SetScrollViewHeight(fScrollHeight)

			# Resize bottom and left pieces.
			pBottomIfScroll.Resize(fWidth - pBottomLeftIfScroll.GetWidth() - pBottomRightIfScroll.GetWidth() - (pPreButtonSpacing.GetWidth() * 2.0) - pScrollUp.GetWidth() - pScrollDown.GetWidth(), pBottomIfScroll.GetHeight(), 0)
			pLeft.Resize(pLeft.GetWidth(), max(0.0, fHeight - pTopLeft.GetHeight() - pBottomLeftIfScroll.GetHeight()), 0)
		else:
			# Not scrolling.  Make sure the appropriate icons are visible.

			if pWindow.IsFixedSize():
				fHeight = pWindow.GetMaximumHeight()

			pBottomLeft.SetVisible(0)
			pBottom.SetVisible(0)
			pBottomRight.SetVisible(0)

			pBottomLeftIfScroll.SetNotVisible(0)
			pBottomIfScroll.SetNotVisible(0)
			pBottomRightIfScroll.SetNotVisible(0)
			pScrollUp.SetNotVisible(0)
			pScrollDown.SetNotVisible(0)

			pWindow.SetScrollViewHeight(-1)

			# Resize bottom and left pieces.
			pBottom.Resize(fWidth - pBottomLeft.GetWidth() - pBottomRight.GetWidth(), pBottom.GetHeight(), 0)
			pLeft.Resize(pLeft.GetWidth(), max(0.0, fHeight - pTopLeft.GetHeight() - pBottomLeft.GetHeight()), 0)

		# Find the maximum width available for the title.
		fMaxTitleWidth = fWidth - pTopLeft.GetWidth() - pPreTitleCap.GetWidth() - pPostTitleLeftCap.GetWidth() - pPostTitleRightCap.GetWidth()
		pNamePane.Resize(min(pName.GetWidth(), fMaxTitleWidth), pName.GetHeight(), 0)

		# Because of the minimize button, the top title bar (after the title) is shorter..
		fOtherWidth = pTopLeft.GetWidth() + pPreTitle.GetWidth() + pPreTitleCap.GetWidth() + pNamePane.GetWidth() + pPostTitleLeftCap.GetWidth() + pPostTitleRightCap.GetWidth()
		pPostTitle.Resize(fWidth - fOtherWidth, pPostTitle.GetHeight(), 0)

		#    +-------+
		# +--+       +  Very rough sketch
		# +2 |   1   +  (not to scale)
		# ++-+       +  of how the 3
		#  +-+       +  glass pieces
		#    +-------+  fit together.
		# Glass.  Main piece covers the entire height, and most of the area, from the right.
		pGlass1.Resize(fWidth - pBottomLeft.GetWidth(), fHeight, 0)
		# Second piece covers most of the left, minus a little bit at the bottom.
		pGlass2.Resize(pBottomLeft.GetWidth(), fHeight - pPreTitle.GetHeight() - (pBottomLeft.GetHeight() / 2.0), 0)
		# Final piece covers the little bit in the lower left...
		pGlass3.Resize(pBottomLeft.GetWidth() / 2.0, fHeight - pGlass2.GetHeight() - (pBottomLeft.GetHeight() / 4.0))


		#################################
		# Reposition everything.
		#################################
		pTopLeft.SetPosition			(0.0, 0.0, 0)
		pPreTitle.SetPosition			(pTopLeft.GetRight(), 0.0, 0)
		pPreTitleCap.SetPosition		(pPreTitle.GetRight(), 0.0, 0)
		#pNamePane.SetPosition			(pPreTitleCap.GetRight(),  pPreTitle.GetTop() - ((pNamePane.GetHeight() - pPreTitle.GetHeight()) / 2.0), 0)
		pNamePane.SetPosition			(pPreTitleCap.GetRight(),  max(pPreTitle.GetBottom() - pNamePane.GetHeight(), -App.globals.DEFAULT_ST_INDENT_VERT), 0)
		pPostTitleLeftCap.SetPosition	(pNamePane.GetRight(), 0.0, 0)
		pPostTitle.SetPosition			(pPostTitleLeftCap.GetRight(), 0.0, 0)
		pPostTitleRightCap.SetPosition	(pPostTitle.GetRight(), 0.0, 0)
		pLeft.SetPosition				(0.0, pTopLeft.GetBottom(), 0)

		pScroll.SetPosition				(pLeft.GetRight(), pPreTitle.GetBottom() + pVerticalSpacing.GetHeight(), 0)

		pBottomLeft.SetPosition			(0.0, pLeft.GetBottom(), 0)
		pBottom.SetPosition				(pBottomLeft.GetRight(), pBottomLeft.GetBottom() - pBottom.GetHeight(), 0)
		pBottomRight.SetPosition		(pBottom.GetRight(), pBottomLeft.GetBottom() - pBottomRight.GetHeight(), 0)

		pBottomLeftIfScroll.SetPosition	(0.0, pLeft.GetBottom(), 0)
		pBottomIfScroll.SetPosition		(pBottomLeftIfScroll.GetRight(), pBottomLeftIfScroll.GetBottom() - pBottomIfScroll.GetHeight(), 0)
		pBottomRightIfScroll.SetPosition(pBottomIfScroll.GetRight(), pBottomLeftIfScroll.GetBottom() - pBottomRightIfScroll.GetHeight(), 0)
		pScrollUp.SetPosition			(pBottomRightIfScroll.GetRight() + pPreButtonSpacing.GetWidth(), pBottomLeftIfScroll.GetBottom() - pScrollUp.GetHeight(), 0)
		pScrollDown.SetPosition			(pScrollUp.GetRight() + pPreButtonSpacing.GetWidth(), pBottomLeftIfScroll.GetBottom() - pScrollDown.GetHeight(), 0)

		pGlass1.SetPosition				(pBottomLeft.GetRight(), 0.0, 0)
		pGlass2.SetPosition				(0.0, pPreTitle.GetBottom(), 0)
		pGlass3.SetPosition				(pBottomLeft.GetWidth() / 2.0, pGlass2.GetBottom(), 0)

		# Overall size of our window.
		pExterior.Resize(fWidth, fHeight, 0)
		pWindow.Resize( pExterior.GetWidth(), pExterior.GetHeight() )

	###############################################################################
	#	GetBorderWidth
	#	
	#	Returns the width of the border for this style, assuming the interior
	#	fits nicely inside it (no scrolling).
	#	
	#	Args:	pWindow		- the STStylizedWindow
	#			pExterior	- the exterior pane
	#			pScroll		- the scroll window
	#	
	#	Return:	NiPoint2 - The border width and height
	###############################################################################
	def GetBorderWidth(self, pWindow, pExterior, pScroll):
		# Get our relevant children.
		pNamePane, pTopLeft, pLeft, pBottomLeft, pBottom, pBottomRight, pPreTitle, pVerticalSpacing, pPreTitleCap, pPostTitleLeftCap, pPostTitle, pPostTitleRightCap, pPreButtonSpacing, pBottomLeftIfScroll, pBottomIfScroll, pBottomRightIfScroll, pScrollUp, pScrollDown, pGlass1, pGlass2, pGlass3 = GetChildren(pExterior)
				
		# Height depends on whether or not the title bar thickness has been specified.
		if pWindow.GetTitleBarThickness():
			# Find the pixel-aligned equivalent to 0.01
			fSpacing = App.TGUIModule_PixelAlignValue(0.01, 0)
			fVerticalSpacing = pWindow.GetTitleBarThickness() + 2.0 * fSpacing + pBottom.GetHeight()
		else:
			fVerticalSpacing = pTopLeft.GetHeight() + (2.0 * pVerticalSpacing.GetHeight() + pBottomLeft.GetHeight())

		#fVerticalSpacing = max((pWindow.GetTitleBarThickness() or pPreTitle.GetHeight()) + 2.0 * pVerticalSpacing.GetHeight() + pBottom.GetHeight(), pTopLeft.GetHeight() + pBottomLeft.GetHeight())

		kPoint = App.TGUIModule_PixelAlignPoint(App.NiPoint2(pLeft.GetWidth() + App.globals.DEFAULT_ST_INDENT_HORIZ, 
															 fVerticalSpacing))

		return kPoint

	###############################################################################
	#	UpdateScrollArrows(self, pWindow, pExterior, pScroll)
	#	
	#	Updates the state of the scroll arrows (whether they should be enabled or
	#	disabled).
	#	
	#	Args:	pWindow		- the STStylizedWindow
	#			pExterior	- the exterior pane
	#			pScroll		- the scroll window
	#	
	#	Return:	none
	###############################################################################
	def UpdateScrollArrows(self, pWindow, pExterior, pScroll):
		(pNamePane, pTopLeft, pLeft, pBottomLeft, pBottom, pBottomRight, pPreTitle, 
		 pVerticalSpacing, pPreTitleCap, pPostTitleLeftCap, pPostTitle, 
		 pPostTitleRightCap, pPreButtonSpacing, pBottomLeftIfScroll, 
		 pBottomIfScroll, pBottomRightIfScroll, pScrollUp, pScrollDown, 
		 pGlass1, pGlass2, pGlass3) = GetChildren(pExterior)
		 
		pInterior = pWindow.GetInteriorPane()

		bSendScrollEndEvent = 0
		pMode = App.GraphicsModeInfo_GetCurrentMode()
		fHalfPixel = pMode.GetPixelHeight() / 2.0
		 		 
		if (pInterior.GetTop() < -fHalfPixel):
			pScrollUp.SetEnabled()
		else:
			if pWindow.IsScrolling() == App.STStylizedWindow.SCROLL_UP:
				pScrollUp.SetDisabled()
				bSendScrollEndEvent = 1
				App.TGButton_Cast(pScrollUp).ClearMouseDown(0)
			elif pWindow.IsScrolling() == App.STStylizedWindow.NO_SCROLL:
				pScrollUp.SetDisabled()

		if (pInterior.GetBottom() > (pScroll.GetHeight() + fHalfPixel)):
			pScrollDown.SetEnabled()
		else:
			if pWindow.IsScrolling() == App.STStylizedWindow.SCROLL_DOWN:
				pScrollDown.SetDisabled()
				bSendScrollEndEvent = 1
				App.TGButton_Cast(pScrollDown).ClearMouseDown(0)
			elif pWindow.IsScrolling() == App.STStylizedWindow.NO_SCROLL:
				pScrollDown.SetDisabled()

		if (bSendScrollEndEvent == 1):
			# Send a "stop scrolling" event.
			pEvent = App.TGIntEvent_Create()
			pEvent.SetSource(pWindow)
			pEvent.SetDestination(pWindow)
			pEvent.SetEventType(App.ET_ST_PERIODIC_SCROLL_DOWN)
			pEvent.SetInt(0)

		return

	###############################################################################
	#	GetNameParagraph(self, pWindow, pExterior, pScroll)
	#	
	#	Returns the paragraph used for the name.
	#	
	#	Args:	pWindow		- the STStylizedWindow
	#			pExterior	- the exterior pane
	#			pScroll		- the scroll pane
	#	
	#	Return:	TGParagraph * - the name paragraph
	###############################################################################
	def GetNameParagraph(self, pWindow, pExterior, pScroll):
		(pNamePane, pTopLeft, pLeft, pBottomLeft, pBottom, pBottomRight, pPreTitle, 
		 pVerticalSpacing, pPreTitleCap, pPostTitleLeftCap, pPostTitle, 
		 pPostTitleRightCap, pPreButtonSpacing, pBottomLeftIfScroll, 
		 pBottomIfScroll, pBottomRightIfScroll, pScrollUp, pScrollDown, 
		 pGlass1, pGlass2, pGlass3) = GetChildren(pExterior)

		return(App.TGParagraph_Cast(App.TGPane_Cast(pNamePane).GetFirstChild()))

	###############################################################################
	#	UpdateMinimize(self, pWindow, pExterior, pScroll)
	#	
	#	Called to update the minimize/restore buttons.
	#	
	#	Args:	pWindow		- the stylized window
	#			pExterior	- the exterior pane
	#			pScroll		- the scroll pane
	#	
	#	Return:	none
	###############################################################################
	def UpdateMinimize(self, pWindow, pExterior, pScroll):
		return

	###############################################################################
	#	UpdateGlass(self, pWindow, pExterior, pScroll)
	#	
	#	Called to update the glass, if we're using different glass when we have the
	#	true focus path.
	#	
	#	Args:	pWindow		- the stylized window
	#			pExterior	- the exterior pane
	#			pScroll		- the scroll pane
	#	
	#	Return:	none
	###############################################################################
	def UpdateGlass(self, pWindow, pExterior, pScroll):
		(pNamePane, pTopLeft, pLeft, pBottomLeft, pBottom, pBottomRight, pPreTitle, 
		 pVerticalSpacing, pPreTitleCap, pPostTitleLeftCap, pPostTitle, 
		 pPostTitleRightCap, pPreButtonSpacing, pBottomLeftIfScroll, 
		 pBottomIfScroll, pBottomRightIfScroll, pScrollUp, pScrollDown, 
		 pGlass1, pGlass2, pGlass3) = GetChildren(pExterior)

		pGlass1 = App.TGIcon_Cast(pGlass1)
		pGlass2 = App.TGIcon_Cast(pGlass2)
		pGlass3 = App.TGIcon_Cast(pGlass3)

		if pWindow.IsInTrueFocusPath() and pWindow.IsUseFocusGlass():
			kColor = App.NiColorA()
			kColor.r = 0.0
			kColor.g = 0.0
			kColor.b = 0.0
			kColor.a = 0.9
			kColor = App.NiColorA_WHITE
			for pIcon in [pGlass1, pGlass2, pGlass3]:
				if pIcon.GetIconNum() != g_iAlternateGlass:
					pIcon.SetIconNum(g_iAlternateGlass)
				pIcon.SetColor(kColor)
		else:
			for pIcon in [pGlass1, pGlass2, pGlass3]:
				if pIcon.GetIconNum() != 120:
					pIcon.SetIconNum(120)
				pIcon.SetColor(App.NiColorA_WHITE)
			
		pWindow.Layout()
			
		return


###############################################################################
#	
#	RightBorder style
#	
###############################################################################
class RightBorder(BaseStyle):
	###############################################################################
	#	Setup() 
	#	
	#	Setup function for the "RightBorder" window style.
	#	
	#	Args:	pWindow		- The STStylizedWindow that we're setting up.
	#			pExterior	- The exterior TGPane where all the border goes.
	#			pScroll		- The scroll window for this window.
	#	
	#	Return:	None
	###############################################################################
	def Setup(self, pWindow, pExterior, pScroll):
		# Import resolution dependent LCARS module for size/placement variables.
		pcLCARS = App.GraphicsModeInfo_GetCurrentMode().GetLcarsString()

		# Setup the minimize/restore buttons.
		pScrollUp, pScrollDown = NormalStyleScrollButtons(pWindow)

		# Create all our little bits and pieces and add them as children.
		pMainColor = App.NiColorA()
		pWindow.GetColor(pMainColor)

		pNamePane = App.TGPane_Create()
		pName = App.TGParagraph_CreateW(pWindow.GetName(), 1.0, App.globals.g_kTitleColor)
		pName.Layout()
		pNamePane.AddChild( pName ) # Name
		pExterior.AddChild( pNamePane ) # Name pane
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 0, pMainColor), 0.0, 0.0, 0 ) # Top left curve
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 1, pMainColor), 0.0, 0.0, 0 ) # Left side
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 2, pMainColor), 0.0, 0.0, 0 ) # Bottom left curve
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 3, pMainColor), 0.0, 0.0, 0 ) # Bottom line
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 4, pMainColor), 0.0, 0.0, 0 ) # Bottom line right cap
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 5, pMainColor), 0.0, 0.0, 0 ) # Pre-title Title bar
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 23, pMainColor), 0.0, 0.0, 0 )# Under-title-bar spacing
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 6, pMainColor), 0.0, 0.0, 0 ) # Pre-title Title bar right cap
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 7, pMainColor), 0.0, 0.0, 0 ) # Post-title Title bar left cap
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 5, pMainColor), 0.0, 0.0, 0 ) # Post-title Title bar
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 8, pMainColor), 0.0, 0.0, 0 ) # Post-title Title bar right cap
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 43, pMainColor), 0.0, 0.0, 0 ) # Top right curve
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 44, pMainColor), 0.0, 0.0, 0 ) # Right side
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 21, pMainColor), 0.0, 0.0, 0 )# Pre-button spacing
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 40, pMainColor), 0.0, 0.0, 0 ) # Bottom left curve if scrollbars needed
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 41, pMainColor), 0.0, 0.0, 0 ) # Bottom line if scrollbars needed
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 42, pMainColor), 0.0, 0.0, 0 ) # Bottom line right cap if scrollbars needed
		pExterior.AddChild( pScrollUp, 0.0, 0.0, 0 )
		pExterior.AddChild( pScrollDown, 0.0, 0.0, 0 )

		# Glass background pieces.
		pExterior.AddChild( App.TGIcon_Create(pcLCARS, 120), 0.0, 0.0, 0 )
		pExterior.AddChild( App.TGIcon_Create(pcLCARS, 120), 0.0, 0.0, 0 )
		pExterior.AddChild( App.TGIcon_Create(pcLCARS, 120), 0.0, 0.0, 0 )

		# Resize all our icons to their artwork size...
		lChildren = GetChildren(pExterior)
		apply(ResizeIconsToArtwork, lChildren)

	###############################################################################
	#	Resize() 
	#	
	#	Resize function for the "RightBorder" window style.
	#	
	#	Args:	pWindow		- The STStylizedWindow that we're setting up.
	#			pExterior	- The exterior TGPane where all the border goes.
	#			pScroll		- The scroll window for this window.
	#	
	#	Return:	None
	###############################################################################
	def Resize(self, pWindow, pExterior, pScroll):
		# Get the width/height of the scroll window.
		fScrollWidth, fScrollHeight = GetInteriorSize(pScroll)

		# Get our important exterior bits, so we can resize and reposition them.
		pNamePane, pTopLeft, pLeft, pBottomLeft, pBottom, pBottomRight, pPreTitle, pVerticalSpacing, pPreTitleCap, pPostTitleLeftCap, pPostTitle, pPostTitleRightCap, pTopRight, pRight, pPreButtonSpacing, pBottomLeftIfScroll, pBottomIfScroll, pBottomRightIfScroll, pScrollUp, pScrollDown, pGlass1, pGlass2, pGlass3 = GetChildren(pExterior)

		pNamePane = App.TGPane_Cast(pNamePane)
		pName = App.TGParagraph_Cast(pNamePane.GetFirstChild())
		pName.SetStringW(pWindow.GetName(), 0)

		#################################
		# Resize everything.
		#################################
		# Fix default icon sizes.
		ResizeIconsToArtwork( pTopLeft, pLeft, pBottomLeft, pBottom, pBottomRight, pPreTitle, pVerticalSpacing, pPreTitleCap, pPostTitleLeftCap, pPostTitle, pPostTitleRightCap, pTopRight, pRight, pPreButtonSpacing, pBottomLeftIfScroll, pBottomIfScroll, pBottomRightIfScroll, pScrollUp, pScrollDown )


		lVisible = (pTopLeft, pLeft, pBottomLeft,
					pBottom, pBottomRight, pVerticalSpacing,
					pTopRight, pRight,
					pBottomLeftIfScroll, pBottomIfScroll,
					pBottomRightIfScroll, pScrollUp, pScrollDown,
					pGlass2, pGlass3)
		# Make sure everything that should be
		# visible is visible.
		for pVisibleIcon in lVisible:
			pVisibleIcon.SetVisible(0)

		if pWindow.GetTitleBarThickness() != 0.0:
			fOldTitleHeight = pPostTitle.GetHeight()
			pPreTitle.Resize(pPreTitle.GetWidth(), pWindow.GetTitleBarThickness(), 0)
			pPreTitleCap.Resize(pPreTitleCap.GetWidth(), pWindow.GetTitleBarThickness(), 0)
			pPostTitleLeftCap.Resize(pPostTitleLeftCap.GetWidth(), pWindow.GetTitleBarThickness(), 0)
			pPostTitle.Resize(pPostTitle.GetWidth(), pWindow.GetTitleBarThickness(), 0)
			pPostTitleRightCap.Resize(pPostTitleRightCap.GetWidth(), pWindow.GetTitleBarThickness(), 0)
			pPreButtonSpacing.Resize(pPreButtonSpacing.GetWidth(), pWindow.GetTitleBarThickness(), 0)
			fNewOldRatio = pPostTitle.GetHeight() / fOldTitleHeight
			pTopLeft.Resize(pTopLeft.GetWidth(), pTopLeft.GetHeight() * fNewOldRatio, 0)
			pTopRight.Resize(pTopRight.GetWidth(), pTopRight.GetHeight() * fNewOldRatio, 0)

		# Find the overall width and height...
		if pWindow.IsFixedSize():
			fWidth = pWindow.GetMaximumWidth()
		else:
			fWidth = fScrollWidth + pLeft.GetWidth() + pRight.GetWidth()
		fHeight = App.TGUIModule_PixelAlignValue(max(pPreTitle.GetHeight() + (2.0 * pVerticalSpacing.GetHeight()) + fScrollHeight + pBottom.GetHeight(), 
													 pTopLeft.GetHeight() + pBottomLeft.GetHeight()), 0)

		# If the height is too great, shrink it and add scroll buttons.
		if (fHeight > pWindow.GetMaximumHeight()) and (pWindow.IsUseScrolling() == 1):
			# Need to scroll.  Set the new height to the max height available.
			fHeight = pWindow.GetMaximumHeight()

			# Set the various bottom icons visible/not visible.
			pBottomLeft.SetNotVisible(0)
			pBottom.SetNotVisible(0)
			pBottomRight.SetNotVisible(0)

			pBottomLeftIfScroll.SetVisible(0)
			pBottomIfScroll.SetVisible(0)
			pBottomRightIfScroll.SetVisible(0)
			pScrollUp.SetVisible(0)
			pScrollDown.SetVisible(0)

			# Find out how much room is available for the scroll window now.
			fScrollHeight = max(0, fHeight - pPreTitle.GetHeight() - 2.0 * pVerticalSpacing.GetHeight() - pBottomIfScroll.GetHeight())
			pWindow.SetScrollViewHeight(fScrollHeight)

			# Resize bottom, right, and left pieces.
			pBottomIfScroll.Resize(fWidth - pBottomLeftIfScroll.GetWidth() - pBottomRightIfScroll.GetWidth() - (pPreButtonSpacing.GetWidth() * 2.0) - pScrollUp.GetWidth() - pScrollDown.GetWidth(), pBottomIfScroll.GetHeight(), 0)
			pLeft.Resize(pLeft.GetWidth(), max(0.0, fHeight - pTopLeft.GetHeight() - pBottomLeftIfScroll.GetHeight()), 0)
			pRight.Resize(pRight.GetWidth(), max(0.0, fHeight - pTopRight.GetHeight() - pBottomIfScroll.GetHeight() - 0.005), 0)
		else:
			# Not scrolling.  Make sure the appropriate icons are visible.

			if pWindow.IsFixedSize():
				fHeight = pWindow.GetMaximumHeight()

			pBottomLeft.SetVisible(0)
			pBottom.SetVisible(0)
			pBottomRight.SetVisible(0)

			pBottomLeftIfScroll.SetNotVisible(0)
			pBottomIfScroll.SetNotVisible(0)
			pBottomRightIfScroll.SetNotVisible(0)
			pScrollUp.SetNotVisible(0)
			pScrollDown.SetNotVisible(0)

			pWindow.SetScrollViewHeight(-1)

			# Resize bottom and left pieces.
			pBottom.Resize(fWidth - pBottomLeft.GetWidth() - pBottomRight.GetWidth(), pBottom.GetHeight(), 0)
			pLeft.Resize(pLeft.GetWidth(), max(0.0, fHeight - pTopLeft.GetHeight() - pBottomLeft.GetHeight()), 0)
			pRight.Resize(pRight.GetWidth(), max(0.0, fHeight - pTopRight.GetHeight() - pBottom.GetHeight() - 0.005), 0)

		# Find the maximum width available for the title.
		fMaxTitleWidth = fWidth - pTopLeft.GetWidth() - pPreTitleCap.GetWidth() - pPostTitleLeftCap.GetWidth() - pPostTitleRightCap.GetWidth()
		pNamePane.Resize(min(pName.GetWidth(), fMaxTitleWidth), pName.GetHeight(), 0)

		# Because of the right border the top title bar (after the title) is shorter..
		fOtherWidth = pTopLeft.GetWidth() + pPreTitle.GetWidth() + pPreTitleCap.GetWidth() + pNamePane.GetWidth() + pPostTitleLeftCap.GetWidth() + pPostTitleRightCap.GetWidth() + pTopRight.GetWidth()
		pPostTitle.Resize(fWidth - fOtherWidth, pPostTitle.GetHeight(), 0)

		#    +-------+
		# +--+       +  Very rough sketch
		# +2 |   1   +  (not to scale)
		# ++-+       +  of how the 3
		#  +-+       +  glass pieces
		#    +-------+  fit together.
		# Glass.  Main piece covers the entire height, and most of the area, from the right.
		pGlass1.Resize(fWidth - pBottomLeft.GetWidth(), fHeight, 0)
		# Second piece covers most of the left, minus a little bit at the bottom.
		pGlass2.Resize(pBottomLeft.GetWidth(), fHeight - pPreTitle.GetHeight() - (pBottomLeft.GetHeight() / 2.0), 0)
		# Final piece covers the little bit in the lower left...
		pGlass3.Resize(pBottomLeft.GetWidth() / 2.0, fHeight - pGlass2.GetHeight() - (pBottomLeft.GetHeight() / 4.0))




		#################################
		# Reposition everything.
		#################################
		pTopLeft.SetPosition			(0.0, 0.0, 0)
		pPreTitle.SetPosition			(pTopLeft.GetRight(), 0.0, 0)
		pPreTitleCap.SetPosition		(pPreTitle.GetRight(), 0.0, 0)
		pNamePane.SetPosition			(pPreTitleCap.GetRight(),  pPreTitle.GetTop() - ((pNamePane.GetHeight() - pPreTitle.GetHeight()) / 2.0), 0)
		pPostTitleLeftCap.SetPosition	(pNamePane.GetRight(), 0.0, 0)
		pPostTitle.SetPosition			(pPostTitleLeftCap.GetRight(), 0.0, 0)
		pPostTitleRightCap.SetPosition	(pPostTitle.GetRight(), 0.0, 0)
		pLeft.SetPosition				(0.0, pTopLeft.GetBottom(), 0)

		pScroll.SetPosition				(pLeft.GetRight(), pPreTitle.GetBottom() + pVerticalSpacing.GetHeight(), 0)

		pBottomLeft.SetPosition			(0.0, pLeft.GetBottom(), 0)
		pBottom.SetPosition				(pBottomLeft.GetRight(), pBottomLeft.GetBottom() - pBottom.GetHeight(), 0)
		pBottomRight.SetPosition		(pBottom.GetRight(), pBottomLeft.GetBottom() - pBottomRight.GetHeight(), 0)

		pBottomLeftIfScroll.SetPosition	(0.0, pLeft.GetBottom(), 0)
		pBottomIfScroll.SetPosition		(pBottomLeftIfScroll.GetRight(), pBottomLeftIfScroll.GetBottom() - pBottomIfScroll.GetHeight(), 0)
		pBottomRightIfScroll.SetPosition(pBottomIfScroll.GetRight(), pBottomLeftIfScroll.GetBottom() - pBottomRightIfScroll.GetHeight(), 0)
		pScrollUp.SetPosition			(pBottomRightIfScroll.GetRight() + pPreButtonSpacing.GetWidth(), pBottomLeftIfScroll.GetBottom() - pScrollUp.GetHeight(), 0)
		pScrollDown.SetPosition			(pScrollUp.GetRight() + pPreButtonSpacing.GetWidth(), pBottomLeftIfScroll.GetBottom() - pScrollDown.GetHeight(), 0)

		pTopRight.SetPosition			(fWidth - pTopRight.GetWidth(), 0.0, 0)
		pRight.SetPosition				(fWidth - pRight.GetWidth(), pTopRight.GetBottom(), 0)

		pGlass1.SetPosition				(pBottomLeft.GetRight(), 0.0, 0)
		pGlass2.SetPosition				(0.0, pPreTitle.GetBottom(), 0)
		pGlass3.SetPosition				(pBottomLeft.GetWidth() / 2.0, pGlass2.GetBottom(), 0)

		# Overall size of our window.
		pExterior.Resize(fWidth, fHeight, 0)
		pWindow.Resize( pExterior.GetWidth(), pExterior.GetHeight() )

	###############################################################################
	#	GetBorderWidth
	#	
	#	Returns the width of the border for this style, assuming the interior
	#	fits nicely inside it (no scrolling).
	#	
	#	Args:	pWindow		- the STStylizedWindow
	#			pExterior	- the exterior pane
	#			pScroll		- the scroll window
	#	
	#	Return:	NiPoint2 - The border width and height
	###############################################################################
	def GetBorderWidth(self, pWindow, pExterior, pScroll):
		# Get our relevant children.
		pNamePane, pTopLeft, pLeft, pBottomLeft, pBottom, pBottomRight, pPreTitle, pVerticalSpacing, pPreTitleCap, pPostTitleLeftCap, pPostTitle, pPostTitleRightCap, pTopRight, pRight, pPreButtonSpacing, pBottomLeftIfScroll, pBottomIfScroll, pBottomRightIfScroll, pScrollUp, pScrollDown, pGlass1, pGlass2, pGlass3 = GetChildren(pExterior)

		fVerticalSpacing =  (pWindow.GetTitleBarThickness() or pPreTitle.GetHeight()) + 2.0 * pVerticalSpacing.GetHeight() + pBottom.GetHeight()

		#fVerticalSpacing = max((pWindow.GetTitleBarThickness() or pPreTitle.GetHeight()) + 2.0 * pVerticalSpacing.GetHeight() + pBottom.GetHeight(), pTopLeft.GetHeight() + pBottomLeft.GetHeight())

		kPoint = App.TGUIModule_PixelAlignPoint(App.NiPoint2(pLeft.GetWidth() + pRight.GetWidth() + App.globals.DEFAULT_ST_INDENT_HORIZ,
															 fVerticalSpacing))

		return kPoint

	###############################################################################
	#	UpdateScrollArrows(self, pWindow, pExterior, pScroll)
	#	
	#	Updates the state of the scroll arrows (whether they should be enabled or
	#	disabled).
	#	
	#	Args:	pWindow		- the STStylizedWindow
	#			pExterior	- the exterior pane
	#			pScroll		- the scroll window
	#	
	#	Return:	none
	###############################################################################
	def UpdateScrollArrows(self, pWindow, pExterior, pScroll):
		(pNamePane, pTopLeft, pLeft, pBottomLeft, pBottom, pBottomRight, pPreTitle, 
		 pVerticalSpacing, pPreTitleCap, pPostTitleLeftCap, pPostTitle, 
		 pPostTitleRightCap, pTopRight, pRight, pPreButtonSpacing, 
		 pBottomLeftIfScroll, pBottomIfScroll, pBottomRightIfScroll, pScrollUp, 
		 pScrollDown, pGlass1, pGlass2, pGlass3) = GetChildren(pExterior)
		 
		pInterior = pWindow.GetInteriorPane()

		bSendScrollEndEvent = 0
		pMode = App.GraphicsModeInfo_GetCurrentMode()
		fHalfPixel = pMode.GetPixelHeight() / 2.0
		 
		if (pInterior.GetTop() < -fHalfPixel):
			pScrollUp.SetEnabled()
		else:
			if pWindow.IsScrolling() == App.STStylizedWindow.SCROLL_UP:
				pScrollUp.SetDisabled()
				bSendScrollEndEvent = 1
				App.TGButton_Cast(pScrollUp).ClearMouseDown(0)
			elif pWindow.IsScrolling() == App.STStylizedWindow.NO_SCROLL:
				pScrollUp.SetDisabled()

		if (pInterior.GetBottom() > (pScroll.GetHeight() + fHalfPixel)):
			pScrollDown.SetEnabled()
		else:
			if pWindow.IsScrolling() == App.STStylizedWindow.SCROLL_DOWN:
				pScrollDown.SetDisabled()
				bSendScrollEndEvent = 1
				App.TGButton_Cast(pScrollDown).ClearMouseDown(0)
			elif pWindow.IsScrolling() == App.STStylizedWindow.NO_SCROLL:
				pScrollDown.SetDisabled()

		if (bSendScrollEndEvent == 1):
			# Send a "stop scrolling" event.
			pEvent = App.TGIntEvent_Create()
			pEvent.SetSource(pWindow)
			pEvent.SetDestination(pWindow)
			pEvent.SetEventType(App.ET_ST_PERIODIC_SCROLL_DOWN)
			pEvent.SetInt(0)

		return

	###############################################################################
	#	GetNameParagraph(self, pWindow, pExterior, pScroll)
	#	
	#	Returns the paragraph used for the name.
	#	
	#	Args:	pWindow		- the STStylizedWindow
	#			pExterior	- the exterior pane
	#			pScroll		- the scroll pane
	#	
	#	Return:	TGParagraph * - the name paragraph
	###############################################################################
	def GetNameParagraph(self, pWindow, pExterior, pScroll):
		(pNamePane, pTopLeft, pLeft, pBottomLeft, pBottom, pBottomRight, pPreTitle, 
		 pVerticalSpacing, pPreTitleCap, pPostTitleLeftCap, pPostTitle, 
		 pPostTitleRightCap, pTopRight, pRight, pPreButtonSpacing, 
		 pBottomLeftIfScroll, pBottomIfScroll, pBottomRightIfScroll, pScrollUp, 
		 pScrollDown, pGlass1, pGlass2, pGlass3) = GetChildren(pExterior)

		return(App.TGParagraph_Cast(App.TGPane_Cast(pNamePane).GetFirstChild()))

	###############################################################################
	#	UpdateGlass(self, pWindow, pExterior, pScroll)
	#	
	#	Called to update the glass, if we're using different glass when we have the
	#	true focus path.
	#	
	#	Args:	pWindow		- the stylized window
	#			pExterior	- the exterior pane
	#			pScroll		- the scroll pane
	#	
	#	Return:	none
	###############################################################################
	def UpdateGlass(self, pWindow, pExterior, pScroll):
		(pNamePane, pTopLeft, pLeft, pBottomLeft, pBottom, pBottomRight, pPreTitle, 
		 pVerticalSpacing, pPreTitleCap, pPostTitleLeftCap, pPostTitle, 
		 pPostTitleRightCap, pTopRight, pRight, pPreButtonSpacing, 
		 pBottomLeftIfScroll, pBottomIfScroll, pBottomRightIfScroll, pScrollUp, 
		 pScrollDown, pGlass1, pGlass2, pGlass3) = GetChildren(pExterior)

		pGlass1 = App.TGIcon_Cast(pGlass1)
		pGlass2 = App.TGIcon_Cast(pGlass2)
		pGlass3 = App.TGIcon_Cast(pGlass3)

		if pWindow.IsInTrueFocusPath() and pWindow.IsUseFocusGlass():
			kColor = App.NiColorA()
			kColor.r = 0.0
			kColor.g = 0.0
			kColor.b = 0.0
			kColor.a = 0.9
			kColor = App.NiColorA_WHITE
			for pIcon in [pGlass1, pGlass2, pGlass3]:
				if pIcon.GetIconNum() != g_iAlternateGlass:
					pIcon.SetIconNum(g_iAlternateGlass)
				pIcon.SetColor(kColor)
		else:
			for pIcon in [pGlass1, pGlass2, pGlass3]:
				if pIcon.GetIconNum() != 120:
					pIcon.SetIconNum(120)
				pIcon.SetColor(App.NiColorA_WHITE)
			
		pWindow.Layout()
			
		return

###############################################################################
#	
#	LeftSeparator style
#	
###############################################################################
class LeftSeparator(BaseStyle):
	###############################################################################
	#	Setup
	#	
	#	Setup function for the "LeftSeparator" window style.  This style
	#	is similar to NormalStyle, but instead of the C along the left
	#	side, it has a vertical purple bar.
	#	
	#	Args:	pWindow		- The STStylizedWindow that we're setting up.
	#			pExterior	- The exterior TGPane where all the border goes.
	#			pScroll		- The scroll window for this window.
	#	
	#	Return:	None
	###############################################################################
	def Setup(self, pWindow, pExterior, pScroll):
		# Import resolution dependent LCARS module for size/placement variables.
		pcLCARS = App.GraphicsModeInfo_GetCurrentMode().GetLcarsString()

		# Setup the minimize/restore buttons.
		pMinimize, pRestore = NormalStyleMinimizeRestoreButtons(pWindow)

		# Create all our little bits and pieces and add them as children.
		pMainColor = App.NiColorA()
		pWindow.GetColor(pMainColor)
		pSeparatorColor = App.globals.g_kLeftSeparatorColor

		pName = App.TGParagraph_CreateW(pWindow.GetName(), 1.0, App.globals.g_kTitleColor)
		pName.Layout()
		pExterior.AddChild( pName ) # Name
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 30, pSeparatorColor), 0.0, 0.0, 0 ) # Thin separator top cap
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 31, pSeparatorColor), 0.0, 0.0, 0 ) # Thin separator
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 32, pSeparatorColor), 0.0, 0.0, 0 ) # Thin separator bottom cap

		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 3, pMainColor), 0.0, 0.0, 0 ) # Bottom line

		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 7, pMainColor), 0.0, 0.0, 0 ) # Pre-title Title bar left cap
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 5, pMainColor), 0.0, 0.0, 0 ) # Pre-title Title bar
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 23, pMainColor), 0.0, 0.0, 0 )# Under-title-bar spacing
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 6, pMainColor), 0.0, 0.0, 0 ) # Pre-title Title bar right cap

		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 7, pMainColor), 0.0, 0.0, 0 ) # Post-title Title bar left cap
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 5, pMainColor), 0.0, 0.0, 0 ) # Post-title Title bar
		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 8, pMainColor), 0.0, 0.0, 0 ) # Post-title Title bar right cap

		pExterior.AddChild( App.TGIcon_Create("NormalStyleFrame", 21, pMainColor), 0.0, 0.0, 0 )# Pre-button spacing

		pExterior.AddChild( pMinimize, 0.0, 0.0, 0 )	# Minimize button
		pExterior.AddChild( pRestore, 0.0, 0.0, 0 )		# Restore button

		# Glass background pieces.
		pExterior.AddChild( App.TGIcon_Create(pcLCARS, 120), 0.0, 0.0, 0 )

		# Resize all our icons to their artwork size...
		lChildren = GetChildren(pExterior)
		apply(ResizeIconsToArtwork, lChildren)

	###############################################################################
	#	Resize
	#	
	#	Size and move border bits for the "LeftSeparator" style of STStylizedWindow.
	#	
	#	Args:	pWindow		- The STStylizedWindow that we're setting up.
	#			pExterior	- The exterior TGPane where all the border goes.
	#			pScroll		- The scroll window for this window.
	#	
	#	Return:	None
	###############################################################################
	def Resize(self, pWindow, pExterior, pScroll):
		# Get the width/height of the scroll window.
		fScrollWidth, fScrollHeight = GetInteriorSize(pScroll)

		# Import resolution dependent LCARS module for size/placement variables.
		pMode = App.GraphicsModeInfo_GetCurrentMode()
		LCARS = __import__(pMode.GetLcarsModule())

		# Get our important exterior bits, so we can resize and reposition them.
		pName, pSepTop, pSep, pSepBottom, pBottom, pPreTitleLeft, pPreTitle, pUnderTitle, pPreTitleRight, pPostTitleLeft, pPostTitle, pPostTitleRight, pPreButtonSpacing, pMinimize, pRestore, pGlass = GetChildren(pExterior)

		pPreButtonSpacing.SetNotVisible(0)

		# Update the name.
		pName = App.TGParagraph_Cast(pName)
		pName.SetStringW(pWindow.GetName(), 0)

		if pName.GetWidth() > 0.0:
			# Title exists.  Size the pre-title stuff.
			pPreTitleLeft.SetVisible(0)
			pPreTitle.SetVisible(0)
			pPreTitleRight.SetVisible(0)
		else:
			# No title.  Don't display pre-title stuff.
			pPreTitleLeft.SetNotVisible(0)
			pPreTitle.SetNotVisible(0)
			pPreTitleRight.SetNotVisible(0)


		# If we're minimized, call the special layout function and return.
		if pWindow.IsMinimized():
			pScroll.SetNotVisible(0)
			self.MinimizedLayout(pWindow, pExterior, pScroll)
			return
		else:
			pScroll.SetVisible(0)


		####################################
		# Resize everything.
		####################################
		# Resize things to their artwork size, to begin with.
		ResizeIconsToArtwork(pSepTop, pSep, pSepBottom, pBottom, pPreTitleLeft, pPreTitle, pUnderTitle, pPreTitleRight, pPostTitleLeft, pPostTitle, pPostTitleRight, pPreButtonSpacing, pMinimize, pRestore, pGlass)

		# Find total dimensions.
		if pWindow.IsFixedSize():
			fWidth = pWindow.GetMaximumWidth()
			fHeight = pWindow.GetMaximumHeight()
		else:
			fWidth = fScrollWidth + pSep.GetWidth()
			fHeight = fScrollHeight + pPreTitle.GetHeight() + pUnderTitle.GetHeight() + pBottom.GetHeight()

		# Resize pieces.
		pSep.Resize(pSep.GetWidth(), fHeight - pBottom.GetHeight() - pSepTop.GetHeight() - pSepBottom.GetHeight() - LCARS.LEFT_SEPARATOR_BOTTOM_GAP, 0)
		pBottom.Resize(fWidth, pBottom.GetHeight(), 0)
		pGlass.Resize(fWidth, fHeight, 0)

		# Pre-Title pieces don't exist if the title doesn't exist.
		if pName.GetWidth() > 0.0:
			pPreTitle.Resize(LCARS.PRETITLE_BAR_WIDTH, pPreTitle.GetHeight(), 0)

			# Post-title pieces are smaller if the title existed.
			fPostTitleWidth = fWidth - pName.GetWidth() - pPreTitleRight.GetWidth() - pPreTitle.GetWidth() - pPreTitleLeft.GetWidth() - pSep.GetWidth()
		else:
			# Post-title space doesn't need to worry about pre-title stuff.
			fPostTitleWidth = fWidth - pSep.GetWidth()

		# Resize post-title pieces.
		pPostTitle.Resize(fPostTitleWidth - pPostTitleLeft.GetWidth() - pPostTitleRight.GetWidth() - pMinimize.GetWidth() - pPreButtonSpacing.GetWidth(), pPostTitle.GetHeight(), 0)


		#####################################
		# Reposition everything.
		####################################
		pSepTop.SetPosition			(0.0, 0.0, 0)
		pSep.SetPosition			(0.0, pSepTop.GetBottom(), 0)
		pSepBottom.SetPosition		(0.0, pSep.GetBottom(), 0)
		pBottom.SetPosition			(0.0, fHeight - pBottom.GetHeight(), 0)
		pPreTitleLeft.SetPosition	(pSep.GetRight(), 0.0, 0)
		pPreTitle.SetPosition		(pPreTitleLeft.GetRight(), 0.0, 0)
		pPreTitleRight.SetPosition	(pPreTitle.GetRight(), 0.0, 0)
		pName.SetPosition			(pPreTitleRight.GetRight(), pPreTitle.GetTop() - ((pName.GetHeight() - pPreTitle.GetHeight()) / 2.0), 0)
		# Post-title things start from the right and go left, since this is easier in
		# case the name and pre-title bar don't exist.
		pMinimize.SetPosition		(fWidth - pMinimize.GetWidth(), 0.0, 0)
		pRestore.SetPosition		(pMinimize.GetLeft(), pMinimize.GetTop(), 0)
		pPreButtonSpacing.SetPosition(pMinimize.GetLeft() - pPreButtonSpacing.GetWidth(), pMinimize.GetTop(), 0)
		pPostTitleRight.SetPosition	(pPreButtonSpacing.GetLeft() - pPostTitleRight.GetWidth(), 0.0, 0)
		pPostTitle.SetPosition		(pPostTitleRight.GetLeft() - pPostTitle.GetWidth(), 0.0, 0)
		pPostTitleLeft.SetPosition	(pPostTitle.GetLeft() - pPostTitleLeft.GetWidth(), 0.0, 0)
		pGlass.SetPosition			(0.0, 0.0, 0)

		pScroll.SetPosition			(pSep.GetRight(), pPostTitle.GetBottom() + pUnderTitle.GetHeight(), 0)

		# Visibility of the minimize/restore buttons...
		SetMinimizeVisibility(pScroll, pMinimize, pRestore)

		# Resize the main windows to fit everything.
		pExterior.Resize(pBottom.GetRight(), pBottom.GetBottom(), 0)
		pWindow.Resize(pExterior.GetWidth(), pExterior.GetHeight())

	###############################################################################
	#	MinimizedLayout(self, pWindow, pExterior, pScroll)
	#	
	#	Called when this window is minimized.
	#	
	#	Args:	self		- the object
	#			pWindow		- the stylized window
	#			pExterior	- the exterior pane
	#			pScroll		- the scroll pane
	#	
	#	Return:	none
	###############################################################################
	def MinimizedLayout(self, pWindow, pExterior, pScroll):
		# Get the width/height of the scroll window.
		fScrollWidth, fScrollHeight = GetInteriorSize(pScroll)

		# Import resolution dependent LCARS module for size/placement variables.
		pMode = App.GraphicsModeInfo_GetCurrentMode()
		LCARS = __import__(pMode.GetLcarsModule())

		# Get our important exterior bits, so we can resize and reposition them.
		pName, pSepTop, pSep, pSepBottom, pBottom, pPreTitleLeft, pPreTitle, pUnderTitle, pPreTitleRight, pPostTitleLeft, pPostTitle, pPostTitleRight, pPreButtonSpacing, pMinimize, pRestore, pGlass = GetChildren(pExterior)

		# Update the name.
		pName = App.TGParagraph_Cast(pName)
		pName.SetStringW(pWindow.GetName(), 0)

		####################################
		# Resize everything.
		####################################
		# Resize things to their artwork size, to begin with.
		ResizeIconsToArtwork(pSepTop, pSep, pSepBottom, pBottom, pPreTitleLeft, pPreTitle, pUnderTitle, pPreTitleRight, pPostTitleLeft, pPostTitle, pPostTitleRight, pPreButtonSpacing, pMinimize, pRestore, pGlass)

		# Find total dimensions.
		if pWindow.IsFixedSize():
			fWidth = pWindow.GetMaximumWidth()
		else:
			fWidth = fScrollWidth + pSep.GetWidth()
		fHeight = pPreTitle.GetHeight() # + pUnderTitle.GetHeight() + pBottom.GetHeight()

		# Resize pieces.
		pSep.Resize(pSep.GetWidth(), fHeight - pBottom.GetHeight() - pSepTop.GetHeight() - pSepBottom.GetHeight() - LCARS.LEFT_SEPARATOR_BOTTOM_GAP, 0)
		pBottom.Resize(fWidth, pBottom.GetHeight(), 0)
		pGlass.Resize(fWidth, fHeight, 0)

		# Pre-Title pieces don't exist if the title doesn't exist.
		if pName.GetWidth() > 0.0:
			pPreTitle.Resize(LCARS.PRETITLE_BAR_WIDTH, pPreTitle.GetHeight(), 0)

			# Post-title pieces are smaller if the title existed.
			fPostTitleWidth = fWidth - pName.GetWidth() - pPreTitleRight.GetWidth() - pPreTitle.GetWidth() - pPreTitleLeft.GetWidth()
		else:
			# Post-title space doesn't need to worry about pre-title stuff.
			fPostTitleWidth = fWidth - pSep.GetWidth()

		# Resize post-title pieces.
		pPostTitle.Resize(fPostTitleWidth - pPostTitleLeft.GetWidth() - pPostTitleRight.GetWidth() - pMinimize.GetWidth() - pPreButtonSpacing.GetWidth(), pPostTitle.GetHeight(), 0)


		#####################################
		# Reposition everything.
		####################################
		pSepTop.SetPosition			(0.0, -1.0, 0)
		pSep.SetPosition			(0.0, -1.0, 0)
		pSepBottom.SetPosition		(0.0, -1.0, 0)
		pBottom.SetPosition			(0.0, -1.0, 0)
		pPreTitleLeft.SetPosition	(0.0, 0.0, 0)
		pPreTitle.SetPosition		(0.0, 0.0, 0)
		pPreTitleRight.SetPosition	(pPreTitle.GetRight(), 0.0, 0)
		pName.SetPosition			(pPreTitleRight.GetRight(), pPreTitle.GetTop() - ((pName.GetHeight() - pPreTitle.GetHeight()) / 2.0), 0)
		# Post-title things start from the right and go left, since this is easier in
		# case the name and pre-title bar don't exist.
		pMinimize.SetPosition		(fWidth - pMinimize.GetWidth(), 0.0, 0)
		pRestore.SetPosition		(pMinimize.GetLeft(), pMinimize.GetTop(), 0)
		pPreButtonSpacing.SetPosition(pMinimize.GetLeft() - pPreButtonSpacing.GetWidth(), pMinimize.GetTop(), 0)
		pPostTitleRight.SetPosition	(pPreButtonSpacing.GetLeft() - pPostTitleRight.GetWidth() - pMode.GetPixelWidth(), 0.0, 0)
		pPostTitle.SetPosition		(pPostTitleRight.GetLeft() - pPostTitle.GetWidth(), 0.0, 0)
		pPostTitleLeft.SetPosition	(pPostTitle.GetLeft() - pPostTitleLeft.GetWidth(), 0.0, 0)
		pGlass.SetPosition			(0.0, 0.0, 0)

		pScroll.SetPosition			(pSep.GetRight(), pPostTitle.GetBottom() + pUnderTitle.GetHeight(), 0)

		# Visibility of the minimize/restore buttons...
		SetMinimizeVisibility(pScroll, pMinimize, pRestore)

		# Resize the main windows to fit everything.
		pExterior.Resize(pBottom.GetRight(), pPreTitle.GetBottom(), 0)
		pWindow.Resize(pExterior.GetWidth(), pExterior.GetHeight())

	###############################################################################
	#	GetBorderWidth
	#	
	#	Returns the width of the border for this style, assuming the interior
	#	fits nicely inside it (no scrolling).
	#	
	#	Args:	pWindow		- the STStylizedWindow
	#			pExterior	- the exterior pane
	#			pScroll		- the scroll window
	#	
	#	Return:	NiPoint2 - The border width and height
	###############################################################################
	def GetBorderWidth(self, pWindow, pExterior, pScroll):
		# Get our relevant children.
		pName, pSepTop, pSep, pSepBottom, pBottom, pPreTitleLeft, pPreTitle, pUnderTitle, pPreTitleRight, pPostTitleLeft, pPostTitle, pPostTitleRight, pPreButtonSpacing, pMinimize, pRestore, pGlass = GetChildren(pExterior)

		kPoint = App.TGUIModule_PixelAlignPoint(App.NiPoint2(pSep.GetWidth() + App.globals.DEFAULT_ST_INDENT_HORIZ,
															 pPreTitle.GetHeight() + pBottom.GetHeight()))

		return(kPoint)

	###############################################################################
	#	UpdateScrollArrows(self, pWindow, pExterior, pScroll)
	#	
	#	Updates the state of the scroll arrows (whether they should be enabled or
	#	disabled).
	#	
	#	Args:	pWindow		- the STStylizedWindow
	#			pExterior	- the exterior pane
	#			pScroll		- the scroll window
	#	
	#	Return:	none
	###############################################################################
	def UpdateScrollArrows(self, pWindow, pExterior, pScroll):
		return

	###############################################################################
	#	GetNameParagraph(self, pWindow, pExterior, pScroll)
	#	
	#	Returns the paragraph used for the name.
	#	
	#	Args:	pWindow		- the STStylizedWindow
	#			pExterior	- the exterior pane
	#			pScroll		- the scroll pane
	#	
	#	Return:	TGParagraph * - the name paragraph
	###############################################################################
	def GetNameParagraph(self, pWindow, pExterior, pScroll):
		pName, pSepTop, pSep, pSepBottom, pBottom, pPreTitleLeft, pPreTitle, pUnderTitle, pPreTitleRight, pPostTitleLeft, pPostTitle, pPostTitleRight, pPreButtonSpacing, pMinimize, pRestore, pGlass = GetChildren(pExterior)

		return(App.TGParagraph_Cast(pName))

	###############################################################################
	#	UpdateMinimize(self, pWindow, pExterior, pScroll)
	#	
	#	Called to update the minimize/restore buttons.
	#	
	#	Args:	pWindow		- the stylized window
	#			pExterior	- the exterior pane
	#			pScroll		- the scroll pane
	#	
	#	Return:	none
	###############################################################################
	def UpdateMinimize(self, pWindow, pExterior, pScroll):
		pName, pSepTop, pSep, pSepBottom, pBottom, pPreTitleLeft, pPreTitle, pUnderTitle, pPreTitleRight, pPostTitleLeft, pPostTitle, pPostTitleRight, pPreButtonSpacing, pMinimize, pRestore, pGlass = GetChildren(pExterior)

		if pWindow.IsMinimizable():
			pMinimize.SetEnabled(0)
			pRestore.SetEnabled(0)
		else:
			pMinimize.SetDisabled(0)
			pRestore.SetDisabled(0)

	###############################################################################
	#	UpdateGlass(self, pWindow, pExterior, pScroll)
	#	
	#	Called to update the glass, if we're using different glass when we have the
	#	true focus path.
	#	
	#	Args:	pWindow		- the stylized window
	#			pExterior	- the exterior pane
	#			pScroll		- the scroll pane
	#	
	#	Return:	none
	###############################################################################
	def UpdateGlass(self, pWindow, pExterior, pScroll):
		pName, pSepTop, pSep, pSepBottom, pBottom, pPreTitleLeft, pPreTitle, pUnderTitle, pPreTitleRight, pPostTitleLeft, pPostTitle, pPostTitleRight, pPreButtonSpacing, pMinimize, pRestore, pGlass = GetChildren(pExterior)

		pGlass = App.TGIcon_Cast(pGlass)

		if pWindow.IsInTrueFocusPath() and pWindow.IsUseFocusGlass():
			kColor = App.NiColorA()
			kColor.r = 0.0
			kColor.g = 0.0
			kColor.b = 0.0
			kColor.a = 0.9
			kColor = App.NiColorA_WHITE
			if pGlass.GetIconNum() != g_iAlternateGlass:
				pGlass.SetIconNum(g_iAlternateGlass)
			pGlass.SetColor(kColor)
		else:
			if pGlass.GetIconNum() != 120:
				pGlass.SetIconNum(120)
			pGlass.SetColor(App.NiColorA_WHITE)

		pWindow.Layout()
			
		return

###############################################################################
#	
#	Radar style
#	
###############################################################################
Radar = NormalStyle

###############################################################################
#
#	WeaponsDisplay style
#	
###############################################################################
class WeaponsDisplay(LeftSeparator):
	###############################################################################
	#	Resize
	#	
	#	Size and move border bits for the "LeftSeparator" style of STStylizedWindow.
	#	
	#	Args:	pWindow		- The STStylizedWindow that we're setting up.
	#			pExterior	- The exterior TGPane where all the border goes.
	#			pScroll		- The scroll window for this window.
	#	
	#	Return:	None
	###############################################################################
	def Resize(self, pWindow, pExterior, pScroll):
		# Get the width/height of the scroll window.
		fScrollWidth, fScrollHeight = GetInteriorSize(pScroll)

		# Import resolution dependent LCARS module for size/placement variables.
		pMode = App.GraphicsModeInfo_GetCurrentMode()
		LCARS = __import__(pMode.GetLcarsModule())

		# Get our important exterior bits, so we can resize and reposition them.
		pName, pSepTop, pSep, pSepBottom, pBottom, pPreTitleLeft, pPreTitle, pUnderTitle, pPreTitleRight, pPostTitleLeft, pPostTitle, pPostTitleRight, pPreButtonSpacing, pMinimize, pRestore, pGlass = GetChildren(pExterior)

		App.TGParagraph_Cast(pName).SetColor(App.NiColorA_BLACK)

		pPreButtonSpacing.SetNotVisible(0)

		# Update the name.
		pName = App.TGParagraph_Cast(pName)
		pName.SetStringW(pWindow.GetName(), 0)

		# Don't display pre-title stuff.
		pPreTitleLeft.SetNotVisible(0)
		pPreTitle.SetNotVisible(0)
		pPreTitleRight.SetNotVisible(0)

		# If we're minimized, call the special layout function and return.
		if pWindow.IsMinimized():
			pScroll.SetNotVisible(0)
			self.MinimizedLayout(pWindow, pExterior, pScroll)
			return
		else:
			pScroll.SetVisible(0)


		####################################
		# Resize everything.
		####################################
		# Resize things to their artwork size, to begin with.
		ResizeIconsToArtwork(pSepTop, pSep, pSepBottom, pBottom, pPreTitleLeft, pPreTitle, pUnderTitle, pPreTitleRight, pPostTitleLeft, pPostTitle, pPostTitleRight, pPreButtonSpacing, pMinimize, pRestore, pGlass)

		# Find total dimensions.
		if pWindow.IsFixedSize():
			fWidth = pWindow.GetMaximumWidth()
			fHeight = pWindow.GetMaximumHeight()
		else:
			fWidth = fScrollWidth + pSep.GetWidth()
			fHeight = fScrollHeight + pPreTitle.GetHeight() + pUnderTitle.GetHeight() + pBottom.GetHeight()

		# Resize pieces.
		pSep.Resize(pSep.GetWidth(), fHeight - pBottom.GetHeight() - pSepTop.GetHeight() - pSepBottom.GetHeight() - LCARS.LEFT_SEPARATOR_BOTTOM_GAP, 0)
		pBottom.Resize(fWidth, pBottom.GetHeight(), 0)
		pGlass.Resize(fWidth, fHeight, 0)

		# Post-title space doesn't need to worry about pre-title stuff.
		fPostTitleWidth = fWidth - pSep.GetWidth()

		# Resize post-title pieces.
		pPostTitle.Resize(fPostTitleWidth - pMinimize.GetWidth() - pPreButtonSpacing.GetWidth(), pPostTitle.GetHeight(), 0)

		#####################################
		# Reposition everything.
		####################################
		pSepTop.SetPosition			(0.0, 0.0, 0)
		pSep.SetPosition			(0.0, pSepTop.GetBottom(), 0)
		pSepBottom.SetPosition		(0.0, pSep.GetBottom(), 0)
		pBottom.SetPosition			(0.0, fHeight - pBottom.GetHeight(), 0)
		pPostTitle.SetPosition		(pSep.GetRight() + pPreButtonSpacing.GetWidth(), 0.0, 0)
		pPreTitleLeft.SetPosition	(pSep.GetRight(), -1.0, 0)
		pPreTitle.SetPosition		(pPreTitleLeft.GetRight(), -1.0, 0)
		pPreTitleRight.SetPosition	(pPreTitle.GetRight(), -1.0, 0)
		pName.SetPosition			(pPostTitle.GetLeft() + App.globals.DEFAULT_ST_INDENT_HORIZ * 2.0, pPostTitle.GetHeight() - pName.GetHeight() - (2.0 * pMode.GetPixelHeight()), 0)
		# Post-title things start from the right and go left, since this is easier in
		# case the name and pre-title bar don't exist.
		pMinimize.SetPosition		(fWidth - pMinimize.GetWidth(), 0.0, 0)
		pRestore.SetPosition		(pMinimize.GetLeft(), pMinimize.GetTop(), 0)
		pPreButtonSpacing.SetPosition(pMinimize.GetLeft() - pPreButtonSpacing.GetWidth(), pMinimize.GetTop(), 0)
		pGlass.SetPosition			(0.0, 0.0, 0)

		pScroll.SetPosition			(pSep.GetRight(), pPostTitle.GetBottom() + pUnderTitle.GetHeight(), 0)

		# Visibility of the minimize/restore buttons...
		SetMinimizeVisibility(pScroll, pMinimize, pRestore)

		# Resize the main windows to fit everything.
		pExterior.Resize(pBottom.GetRight(), pBottom.GetBottom(), 0)
		pWindow.Resize(pExterior.GetWidth(), pExterior.GetHeight())

	###############################################################################
	#	MinimizedLayout(self, pWindow, pExterior, pScroll)
	#	
	#	Called when this window is minimized.
	#	
	#	Args:	self		- the object
	#			pWindow		- the stylized window
	#			pExterior	- the exterior pane
	#			pScroll		- the scroll pane
	#	
	#	Return:	none
	###############################################################################
	def MinimizedLayout(self, pWindow, pExterior, pScroll):
		# Get the width/height of the scroll window.
		fScrollWidth, fScrollHeight = GetInteriorSize(pScroll)

		# Import resolution dependent LCARS module for size/placement variables.
		pMode = App.GraphicsModeInfo_GetCurrentMode()
		LCARS = __import__(pMode.GetLcarsModule())

		# Get our important exterior bits, so we can resize and reposition them.
		pName, pSepTop, pSep, pSepBottom, pBottom, pPreTitleLeft, pPreTitle, pUnderTitle, pPreTitleRight, pPostTitleLeft, pPostTitle, pPostTitleRight, pPreButtonSpacing, pMinimize, pRestore, pGlass = GetChildren(pExterior)

		# Update the name.
		pName = App.TGParagraph_Cast(pName)
		pName.SetStringW(pWindow.GetName(), 0)

		####################################
		# Resize everything.
		####################################
		# Resize things to their artwork size, to begin with.
		ResizeIconsToArtwork(pSepTop, pSep, pSepBottom, pBottom, pPreTitleLeft, pPreTitle, pUnderTitle, pPreTitleRight, pPostTitleLeft, pPostTitle, pPostTitleRight, pPreButtonSpacing, pMinimize, pRestore, pGlass)

		fWidth = pWindow.GetMaximumWidth()
		fHeight = pPreTitle.GetHeight()

		# Resize pieces.
		pSep.Resize(pSep.GetWidth(), fHeight - pBottom.GetHeight() - pSepTop.GetHeight() - pSepBottom.GetHeight() - LCARS.LEFT_SEPARATOR_BOTTOM_GAP, 0)
		pBottom.Resize(fWidth, pBottom.GetHeight(), 0)
		pGlass.Resize(fWidth, fHeight, 0)

		# Post-title space doesn't need to worry about pre-title stuff.
		fPostTitleWidth = fWidth - pMinimize.GetWidth() - pPreButtonSpacing.GetWidth()

		# Resize post-title pieces.
		pPostTitle.Resize(fPostTitleWidth, pPostTitle.GetHeight(), 0)


		#####################################
		# Reposition everything.
		####################################
		pSepTop.SetPosition			(0.0, -1.0, 0)
		pSep.SetPosition			(0.0, -1.0, 0)
		pSepBottom.SetPosition		(0.0, -1.0, 0)
		pBottom.SetPosition			(0.0, -1.0, 0)
		pPreTitleLeft.SetPosition	(0.0, -1.0, 0)
		pPreTitle.SetPosition		(0.0, -1.0, 0)
		pPostTitle.SetPosition		(0.0, 0.0, 0)
		pPreTitleRight.SetPosition	(pPreTitle.GetRight(), -1.0, 0)
		pName.SetPosition			(pPostTitle.GetLeft() + App.globals.DEFAULT_ST_INDENT_HORIZ * 2.0, pPostTitle.GetHeight() - pName.GetHeight() - (2.0 * pMode.GetPixelHeight()), 0)
		# Post-title things start from the right and go left, since this is easier in
		# case the name and pre-title bar don't exist.
		pMinimize.SetPosition		(fWidth - pMinimize.GetWidth(), 0.0, 0)
		pRestore.SetPosition		(pMinimize.GetLeft(), pMinimize.GetTop(), 0)
		pPreButtonSpacing.SetPosition(pMinimize.GetLeft() - pPreButtonSpacing.GetWidth(), pMinimize.GetTop(), 0)
		pPostTitleRight.SetPosition	(pPreButtonSpacing.GetLeft() - pPostTitleRight.GetWidth() - pMode.GetPixelWidth(), -1.0, 0)
		pPostTitleLeft.SetPosition	(pPostTitle.GetLeft() - pPostTitleLeft.GetWidth(), -1.0, 0)
		pGlass.SetPosition			(0.0, 0.0, 0)

		pScroll.SetPosition			(pSep.GetRight(), pPostTitle.GetBottom() + pUnderTitle.GetHeight(), 0)

		# Visibility of the minimize/restore buttons...
		SetMinimizeVisibility(pScroll, pMinimize, pRestore)

		# Resize the main windows to fit everything.
		pExterior.Resize(pBottom.GetRight(), pPostTitle.GetBottom(), 0)
		pWindow.Resize(pExterior.GetWidth(), pExterior.GetHeight())

class MissionLog(NoMinimize):
	###############################################################################
	#	Setup
	#	
	#	Overridden to change the color of the glass pieces.
	#	
	#	Args:	pWindow		- The STStylizedWindow that we're setting up.
	#			pExterior	- The exterior TGPane where all the border goes.
	#			pScroll		- The scroll window for this window.
	#	
	#	Return:	None
	###############################################################################
	def Setup(self, pWindow, pExterior, pScroll):
		NoMinimize.Setup(self, pWindow, pExterior, pScroll)

		# Get our important exterior bits, so we can resize and reposition them.
		pNamePane, pTopLeft, pLeft, pBottomLeft, pBottom, pBottomRight, pPreTitle, pVerticalSpacing, pPreTitleCap, pPostTitleLeftCap, pPostTitle, pPostTitleRightCap, pPreButtonSpacing, pBottomLeftIfScroll, pBottomIfScroll, pBottomRightIfScroll, pScrollUp, pScrollDown, pGlass1, pGlass2, pGlass3 = GetChildren(pExterior)

		pGlass1 = App.TGIcon_Cast(pGlass1)
		pGlass2 = App.TGIcon_Cast(pGlass2)
		pGlass3 = App.TGIcon_Cast(pGlass3)

		pGlass1.SetColor(App.NiColorA_BLACK)
		pGlass2.SetColor(App.NiColorA_BLACK)
		pGlass3.SetColor(App.NiColorA_BLACK)
		pGlass1.SetIconNum(200, 0)
		pGlass2.SetIconNum(200, 0)
		pGlass3.SetIconNum(200, 0)

	###############################################################################
	#	UpdateGlass(self, pWindow, pExterior, pScroll)
	#	
	#	Called to update the glass, if we're using different glass when we have the
	#	true focus path.
	#	
	#	Args:	pWindow		- the stylized window
	#			pExterior	- the exterior pane
	#			pScroll		- the scroll pane
	#	
	#	Return:	none
	###############################################################################
	def UpdateGlass(self, pWindow, pExterior, pScroll):
		pNamePane, pTopLeft, pLeft, pBottomLeft, pBottom, pBottomRight, pPreTitle, pVerticalSpacing, pPreTitleCap, pPostTitleLeftCap, pPostTitle, pPostTitleRightCap, pPreButtonSpacing, pBottomLeftIfScroll, pBottomIfScroll, pBottomRightIfScroll, pScrollUp, pScrollDown, pGlass1, pGlass2, pGlass3 = GetChildren(pExterior)

		pGlass1 = App.TGIcon_Cast(pGlass1)
		pGlass2 = App.TGIcon_Cast(pGlass2)
		pGlass3 = App.TGIcon_Cast(pGlass3)

		if pWindow.IsInTrueFocusPath() and pWindow.IsUseFocusGlass():
			kColor = App.NiColorA()
			kColor.r = 0.0
			kColor.g = 0.0
			kColor.b = 0.0
			kColor.a = 0.9
			kColor = App.NiColorA_WHITE
			for pIcon in [pGlass1, pGlass2, pGlass3]:
				if pIcon.GetIconNum() != g_iAlternateGlass:
					pIcon.SetIconNum(g_iAlternateGlass)
				pIcon.SetColor(kColor)
		else:
			for pIcon in [pGlass1, pGlass2, pGlass3]:
				if pIcon.GetIconNum() != 200:
					pIcon.SetIconNum(200)
				pIcon.SetColor(App.NiColorA_BLACK)
			
		pWindow.Layout()
			
		return


class SolidGlass(NoMinimize):
	###############################################################################
	#	Setup
	#	
	#	Overridden to change the color of the glass pieces.
	#	
	#	Args:	pWindow		- The STStylizedWindow that we're setting up.
	#			pExterior	- The exterior TGPane where all the border goes.
	#			pScroll		- The scroll window for this window.
	#	
	#	Return:	None
	###############################################################################
	def Setup(self, pWindow, pExterior, pScroll):
		NoMinimize.Setup(self, pWindow, pExterior, pScroll)

		# Get our important exterior bits, so we can resize and reposition them.
		pNamePane, pTopLeft, pLeft, pBottomLeft, pBottom, pBottomRight, pPreTitle, pVerticalSpacing, pPreTitleCap, pPostTitleLeftCap, pPostTitle, pPostTitleRightCap, pPreButtonSpacing, pBottomLeftIfScroll, pBottomIfScroll, pBottomRightIfScroll, pScrollUp, pScrollDown, pGlass1, pGlass2, pGlass3 = GetChildren(pExterior)

		pGlass1 = App.TGIcon_Cast(pGlass1)
		pGlass2 = App.TGIcon_Cast(pGlass2)
		pGlass3 = App.TGIcon_Cast(pGlass3)

		pGlass1.SetColor(App.NiColorA_BLACK)
		pGlass2.SetColor(App.NiColorA_BLACK)
		pGlass3.SetColor(App.NiColorA_BLACK)
		pGlass1.SetIconNum(200, 0)
		pGlass2.SetIconNum(200, 0)
		pGlass3.SetIconNum(200, 0)

	###############################################################################
	#	UpdateGlass(self, pWindow, pExterior, pScroll)
	#	
	#	Called to update the glass, if we're using different glass when we have the
	#	true focus path.
	#	
	#	Args:	pWindow		- the stylized window
	#			pExterior	- the exterior pane
	#			pScroll		- the scroll pane
	#	
	#	Return:	none
	###############################################################################
	def UpdateGlass(self, pWindow, pExterior, pScroll):
		pNamePane, pTopLeft, pLeft, pBottomLeft, pBottom, pBottomRight, pPreTitle, pVerticalSpacing, pPreTitleCap, pPostTitleLeftCap, pPostTitle, pPostTitleRightCap, pPreButtonSpacing, pBottomLeftIfScroll, pBottomIfScroll, pBottomRightIfScroll, pScrollUp, pScrollDown, pGlass1, pGlass2, pGlass3 = GetChildren(pExterior)

		pGlass1 = App.TGIcon_Cast(pGlass1)
		pGlass2 = App.TGIcon_Cast(pGlass2)
		pGlass3 = App.TGIcon_Cast(pGlass3)

		for pIcon in [pGlass1, pGlass2, pGlass3]:
			if pIcon.GetIconNum() != 200:
				pIcon.SetIconNum(200)
			pIcon.SetColor(App.NiColorA_BLACK)
			
		pWindow.Layout()
			
		return

class RemapKey(RightBorder):
	###############################################################################
	#	Setup(self, pWindow, pExterior, pScroll)
	#	
	#	Overridden to change the color of the glass pieces.
	#	
	#	Args:	pWindow		- the STStylizedWindow that we're setting up
	#			pExterior	- the exterior TGPane where all the border goes
	#			pScroll		- the scroll window for this window
	#	
	#	Return:	none
	###############################################################################
	def Setup(self, pWindow, pExterior, pScroll):
		RightBorder.Setup(self, pWindow, pExterior, pScroll)

		# Get our important exterior bits, so we can resize and reposition them.
		pNamePane, pTopLeft, pLeft, pBottomLeft, pBottom, pBottomRight, pPreTitle, pVerticalSpacing, pPreTitleCap, pPostTitleLeftCap, pPostTitle, pPostTitleRightCap, pTopRight, pRight, pPreButtonSpacing, pBottomLeftIfScroll, pBottomIfScroll, pBottomRightIfScroll, pScrollUp, pScrollDown, pGlass1, pGlass2, pGlass3 = GetChildren(pExterior)

		pGlass1 = App.TGIcon_Cast(pGlass1)
		pGlass2 = App.TGIcon_Cast(pGlass2)
		pGlass3 = App.TGIcon_Cast(pGlass3)

		pGlass1.SetColor(App.NiColorA_BLACK)
		pGlass2.SetColor(App.NiColorA_BLACK)
		pGlass3.SetColor(App.NiColorA_BLACK)
		pGlass1.SetIconNum(200, 0)
		pGlass2.SetIconNum(200, 0)
		pGlass3.SetIconNum(200, 0)

	###############################################################################
	#	UpdateGlass(self, pWindow, pExterior, pScroll)
	#	
	#	Called to update the glass, if we're using different glass when we have the
	#	true focus path.
	#	
	#	Args:	pWindow		- the stylized window
	#			pExterior	- the exterior pane
	#			pScroll		- the scroll pane
	#	
	#	Return:	none
	###############################################################################
	def UpdateGlass(self, pWindow, pExterior, pScroll):
		pNamePane, pTopLeft, pLeft, pBottomLeft, pBottom, pBottomRight, pPreTitle, pVerticalSpacing, pPreTitleCap, pPostTitleLeftCap, pPostTitle, pPostTitleRightCap, pTopRight, pRight, pPreButtonSpacing, pBottomLeftIfScroll, pBottomIfScroll, pBottomRightIfScroll, pScrollUp, pScrollDown, pGlass1, pGlass2, pGlass3 = GetChildren(pExterior)

		pGlass1 = App.TGIcon_Cast(pGlass1)
		pGlass2 = App.TGIcon_Cast(pGlass2)
		pGlass3 = App.TGIcon_Cast(pGlass3)

		if pWindow.IsInTrueFocusPath() and pWindow.IsUseFocusGlass():
			kColor = App.NiColorA()
			kColor.r = 0.0
			kColor.g = 0.0
			kColor.b = 0.0
			kColor.a = 0.9
			kColor = App.NiColorA_WHITE
			for pIcon in [pGlass1, pGlass2, pGlass3]:
				if pIcon.GetIconNum() != g_iAlternateGlass:
					pIcon.SetIconNum(g_iAlternateGlass)
				pIcon.SetColor(kColor)
		else:
			for pIcon in [pGlass1, pGlass2, pGlass3]:
				if pIcon.GetIconNum() != 200:
					pIcon.SetIconNum(200)
				pIcon.SetColor(App.NiColorA_BLACK)
			
		pWindow.Layout()
			
		return
