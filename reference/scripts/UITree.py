###############################################################################
#	Filename:	UITree.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Script to facilitate creation of the UI tree dialog.
#	
#	Created:	6/15/2001 -	Erik Novales
###############################################################################

import App

###############################################################################
#	CreateTree(pRoot)
#	
#	Creates the UI tree dialog and displays it. Specify a different root
#	for the UI tree if you only want to see part of the UI tree, or a part 
#	that isn't actually attached to the root window.
#	
#	Args:	pRoot	- root of the UI to display
#	
#	Return:	none
###############################################################################
def CreateTree(pRoot = None):
	if (pRoot == None):
		pRoot = App.g_kRootWindow

	pDialog = App.UITreeDialog_Create(__name__, "FillTree", pRoot)

	pDialog.Go()

###############################################################################
#	FillTree(pDialog, pRoot)
#	
#	Called to fill the UI tree dialog with the entries in the UI tree.
#	
#	Args:	pDialog	- the dialog
#			pRoot	- root for the UI tree
#	
#	Return:	none
###############################################################################
def FillTree(pDialog, pRoot):
	ProcessItem(pRoot, pDialog, 0)

###############################################################################
#	ProcessItem(pItem, pDialog, iParent)
#	
#	Recursively processes items in the UI tree.
#	
#	Args:	pItem	- the item to process
#			pDialog	- the UI tree dialog
#			iParent	- handle to parent tree item for this level
#	
#	Return:	none
###############################################################################
def ProcessItem(pItem, pDialog, iParent):
	# Add tree item for this item.
	(pcUIString, pcFlagString) = CreateUITreeString(pItem)

	iHandle = pDialog.AddTreeElement(iParent, pcUIString)
	pDialog.AddTreeElement(iHandle, pcFlagString)

	pPane = App.TGPane_Cast(pItem)
	if (pPane != None):
		bCheckedParent = 0
		for i in range(pPane.GetTrueNumChildren()):
			# Process the next item.
			ProcessItem(pPane.GetTrueNthChild(i), pDialog, iHandle)

###############################################################################
#	CreateUITreeString(pItem)
#	
#	Creates a string based on the item.
#	
#	Args:	pItem	- the UI item
#	
#	Return:	char * - the string describing the item
#			char * - the string describing the item's flags
###############################################################################
def CreateUITreeString(pItem):
	# Try casting the item to various things.
	pTop = App.TopWindow_GetTopWindow()

	kFeatureList = []
	pPane = App.TGPane_Cast(pItem)

	if pPane != None:
		if App.g_kRootWindow.GetObjID() == pPane.GetObjID():
			kFeatureList.append("TGRootPane")

		if ((App.EngPowerCtrl_GetPowerCtrl() != None) and 
			(App.EngPowerCtrl_GetPowerCtrl().GetObjID() == pPane.GetObjID())):
			kFeatureList.append("EngPowerCtrl")

		if ((App.STMissionLog_GetMissionLog() != None) and
			(App.STMissionLog_GetMissionLog().GetObjID() == pPane.GetObjID())):
			kFeatureList.append("STMissionLog")

		if pTop.GetObjID() == pPane.GetObjID():
			kFeatureList.append("TopWindow")

		if ((str(App.TGPane_Cast(pTop.FindMainWindow(App.MWT_BRIDGE))) == str(pPane))
			and (pPane != None)):
			kFeatureList.append("BridgeWindow")

		if ((str(App.TGPane_Cast(pTop.FindMainWindow(App.MWT_TACTICAL))) == str(pPane))
			and (pPane != None)):
			kFeatureList.append("TacticalWindow")

		if ((str(App.TGPane_Cast(pTop.FindMainWindow(App.MWT_CONSOLE))) == str(pPane))
			and (pPane != None)):
			kFeatureList.append("ConsoleWindow")

		if ((str(App.TGPane_Cast(pTop.FindMainWindow(App.MWT_EDITOR))) == str(pPane))
			and (pPane != None)):
			kFeatureList.append("EditorWindow")

		if ((str(App.TGPane_Cast(pTop.FindMainWindow(App.MWT_OPTIONS))) == str(pPane))
			and (pPane != None)):
			kFeatureList.append("OptionsWindow")

		if ((str(App.TGPane_Cast(pTop.FindMainWindow(App.MWT_SUBTITLE))) == str(pPane))
			and (pPane != None)):
			kFeatureList.append("SubtitleWindow")

		if ((str(App.TGPane_Cast(pTop.FindMainWindow(App.MWT_TACTICAL_MAP))) == str(pPane))
			and (pPane != None)):
			kFeatureList.append("MapWindow")

		if ((str(App.TGPane_Cast(pTop.FindMainWindow(App.MWT_CINEMATIC))) == str(pPane))
			and (pPane != None)):
			kFeatureList.append("CinematicWindow")

		if ((str(App.TGPane_Cast(pTop.FindMainWindow(App.MWT_MULTIPLAYER))) == str(pPane))
			and (pPane != None)):
			kFeatureList.append("MultiplayerWindow")

		if ((str(App.TGPane_Cast(pTop.FindMainWindow(App.MWT_CD_CHECK))) == str(pPane))
			and (pPane != None)):
			kFeatureList.append("CDCheckWindow")

		pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
		if (pTCW != None) and (pTCW.GetObjID() == pPane.GetObjID()):
			kFeatureList.append("TacticalControlWindow")

	# Cast tests. More specific items should be towards the beginning of the list,
	# more general items towards the back.
	kCastList = [
					"DamageDisplay",
					"RadarDisplay",
					"ShieldsDisplay",
					"ShipDisplay",
					"TacWeaponsCtrl",
					"WeaponsDisplay",
					"EngRepairPane",
					"STToggle",
					"STButton",
					"STTargetMenu",
					"SortedRegionMenu",
					"STTopLevelMenu",
					"STMenu",
					"STNumericBar",
					"STFillGauge",
					"STStylizedWindow",
					"STSubPane",
					"STRoundedButton",	# not derived from STButton
					"TGWindow",
					"TGButtonBase",
					"TGParagraph",
					"TGPane",
					"TGIcon"
				]

	for kCast in kCastList:
		if (getattr(App, kCast + "_Cast")(pItem) != None):
			kFeatureList.append(kCast)

	kFeatureList.append("TGUIObject")

	# The first entry in the feature list is the object's primary listing.
	kFeatureString = kFeatureList[0]

	kFlagString = ""

	# ***FIXME: ROOT_WINDOW_PARENT should really be a const pointer that's
	# wrapped, so I wouldn't have to use this evil hack.
	if ((pItem.GetParent() != None) and (str(pItem.GetParent()) != "<C TGPane instance at _ffffffff_p_TGPane>")):
		if (pItem.GetParent().GetFocus() != None):
			if (pItem.GetParent().GetFocus().GetObjID() == pItem.GetObjID()):
				kFlagString = kFlagString + "focus "

	if ((App.g_kRootWindow.GetTrueFocus() != None) and
		(str(App.g_kRootWindow.GetTrueFocus()) != "<C TGPane instance at _ffffffff_p_TGPane>")):
		if (App.g_kRootWindow.GetTrueFocus().GetObjID() == pItem.GetObjID()):
			kFlagString = kFlagString + "truefocus "

	if ((App.g_kRootWindow.GetMouseGrabOwner() != None) and
		(App.g_kRootWindow.GetMouseGrabOwner().GetObjID() == pItem.GetObjID())):
		kFlagString = kFlagString + "mousegrab "

	if (pItem.IsEnabled()):
		kFlagString = kFlagString + "Enabled "

	if (pItem.IsSelected()):
		kFlagString = kFlagString + "Selected "

	if (pItem.IsHighlighted()):
		kFlagString = kFlagString + "Highlighted "

	if (pItem.IsVisible()):
		kFlagString = kFlagString + "Visible "

	if (pItem.IsExclusive()):
		kFlagString = kFlagString + "Exclusive "

	if (pItem.IsSkipParent()):
		kFlagString = kFlagString + "SkipParent "

	if (pItem.IsAlwaysHandleEvents()):
		kFlagString = kFlagString + "AlwaysHandleEvents "

	if (pItem.IsUseParentBatch()):
		kFlagString = kFlagString + "UseParentBatch "

	if (pItem.IsBatchChildPolys()):
		kFlagString = kFlagString + "BatchChildPolys "

	if (pItem.IsNoFocus()):
		kFlagString = kFlagString + "NoFocus "

	# Go through the feature list, and add any appropriate comments based on
	# the features. (i.e. number of children if it's a pane, positions, etc.)
	# Also, add anything to the flag string necessary.
	for kFeature in kFeatureList:
		if (kFeature == "STButton"):
			kString = App.TGString()
			pButton = App.STButton_Cast(pItem)
			pButton.GetName(kString)

			kFeatureString = kFeatureString + " (name: " + kString.GetCString() + ")"

			if (pButton.IsAutoChoose()):
				kFlagString = kFlagString + "autochoose "
			if (pButton.IsChoosable()):
				kFlagString = kFlagString + "choosable "
			if (pButton.IsChosen()):
				kFlagString = kFlagString + "chosen "
			if (pButton.IsUsingEndCaps()):
				kFlagString = kFlagString + "endcaps "
			if (pButton.IsUseEndCapSpace() == 0):
				kFlagString = kFlagString + "noendcapspace "

		if (kFeature == "STToggle"):
			pToggle = App.STToggle_Cast(pItem)

			kFeatureString = kFeatureString + " (state: " + str(pToggle.GetState()) + ")"

		if (kFeature == "STMenu"):
			kString = App.TGString()
			pMenu = App.STMenu_Cast(pItem)

			pMenu.GetName(kString)
			kFeatureString = kFeatureString + " (name: " + kString.GetCString() + ")"

			if (pMenu.IsTwoClicks()):
				kFlagString = kFlagString + "twoclicks "
			if (pMenu.IsOpenable()):
				kFlagString = kFlagString + "openable "
			if (pMenu.IsCloseable()):
				kFlagString = kFlagString + "closeable "
			if (pMenu.IsClickedOnce()):
				kFlagString = kFlagString + "clickedonce "
			if (pMenu.IsOpened()):
				kFlagString = kFlagString + "opened "
			if (pMenu.IsUseEndCapSpace() == 0):
				kFlagString = kFlagString + "noendcapspace "

		if (kFeature == "STStylizedWindow"):
			pWindow = App.STStylizedWindow_Cast(pItem)

			kString = pWindow.GetName()
			kFeatureString = kFeatureString + " (name: " + kString.GetCString() + ") "
			kFeatureString = kFeatureString + " (max size: " + str(pWindow.GetMaximumWidth()) + ", " + str(pWindow.GetMaximumHeight()) + ")"
			if (pWindow.IsMinimized()):
				kFlagString = kFlagString + "minimized "

		if (kFeature == "TGIcon"):
			pIcon = App.TGIcon_Cast(pItem)
			kColor = App.NiColorA()
			pIcon.GetColor(kColor)
			kFeatureString = kFeatureString + " (icon: " + pIcon.GetIconGroupName() + ", " + str(pIcon.GetIconNum()) + ")"
			kFeatureString = kFeatureString + " (color: " + str(kColor.r) + ", " + str(kColor.g) + ", " + str(kColor.b) + ", " + str(kColor.a) + ")"

		if (kFeature == "TGParagraph"):
			pPara = App.TGParagraph_Cast(pItem)
			kFeatureString = kFeatureString + " (text: \"" + pPara.GetCString() + "\""

		if (kFeature == "TGPane"):
			pPane = App.TGPane_Cast(pItem)
			kFeatureString = kFeatureString + " (" + str(pPane.GetNumChildren()) + " children)"

		if (kFeature == "TGUIObject"):
			kFeatureString = kFeatureString + " (x,y: " + str(pItem.GetLeft()) + ", " + str(pItem.GetTop())
			kFeatureString = kFeatureString + " w,h: " + str(pItem.GetWidth()) + ", " + str(pItem.GetHeight()) + ")"

	return(kFeatureString, kFlagString)