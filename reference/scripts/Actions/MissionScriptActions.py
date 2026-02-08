###############################################################################
#	Filename:	MissionScriptActions.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Some useful actions for missions.
#	
#	Created:	1/11/01 -	Bill Morrison & Kevin Deus Ex Machina
###############################################################################

import App
import MissionLib

###############################################################################
#	ChangeToBridge(pTGAction)
#	
#	Forces the current view (Tactical or External view) to the Bridge
#	
#	Args:	pTGAction			- the action, passed in automatically
#			
#	Return:	zero for end.
###############################################################################
def ChangeToBridge(pTGAction = None):
	# Bail if the player is dead or dying
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None) or (pPlayer.IsDying()):
		return 0
		
	pTop = App.TopWindow_GetTopWindow()
	pTop.ForceBridgeVisible()

	return 0

