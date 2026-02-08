import App

def CreateAI(pShip, sPlacementName):

	#########################################
	# Creating PlainAI WarpOut at (56, 162)
	pWarpOut = App.PlainAI_Create(pShip, "WarpOut")
	pWarpOut.SetScriptModule("Warp")
	pWarpOut.SetInterruptable(1)
	pScript = pWarpOut.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Starbase12.Starbase12")
	pScript.SetDestinationPlacementName(sPlacementName)
	# Done creating PlainAI WarpOut
	#########################################
	return pWarpOut
