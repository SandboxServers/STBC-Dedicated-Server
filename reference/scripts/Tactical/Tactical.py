###############################################################################
#	Filename:	Tactical.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Create and position tactical interface objects. (i.e. the tactical
#	screen, not Felix's menu)
#	
#	Created:	8/30/00 -	Alberto Fonseca, David Litwin(Added header)
###############################################################################

import App

def GetEmptyAreaLeft ():
	try:
		import Interface.TacticalControlWindow
		pTacCtrlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
		kInterfacePane = App.TGPane_Cast(pTacCtrlWindow.GetNthChild(Interface.TacticalControlWindow.INTERFACE_PANE))
		pRadarDisplayPane = kInterfacePane.GetNthChild(Interface.TacticalControlWindow.RADAR_DISPLAY)
		return pRadarDisplayPane.GetWidth()
	except AttributeError:
		pass

	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsString())
	return LCARS.RADAR_SCOPE_WIDTH

def GetEmptyAreaBottom ():
	try:
#		print ("Get area bottom")
		import Interface.TacticalControlWindow
		pTacCtrlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
		kInterfacePane = App.TGPane_Cast(pTacCtrlWindow.GetNthChild(Interface.TacticalControlWindow.INTERFACE_PANE))
		pPane = kInterfacePane.GetNthChild(Interface.TacticalControlWindow.SHIP_DISPLAY)
		fHeight = pPane.GetHeight ()
#		print ("Using ship display height")

		pPane = kInterfacePane.GetNthChild(Interface.TacticalControlWindow.WEAPONS_DISPLAY)
		if (pPane.GetHeight () > fHeight):
#			print ("Using weapon display height")

			fHeight = pPane.GetHeight ()

		pPane = kInterfacePane.GetNthChild(Interface.TacticalControlWindow.WEAPONS_CONTROL)
		if (pPane.GetHeight () > fHeight):
#			print ("Using weapon control height")

			fHeight = pPane.GetHeight ()

		return 1.0 - fHeight
	except AttributeError:
		pass

	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsString())
	return 1.0 - LCARS.WEAPONS_PANE_HEIGHT

