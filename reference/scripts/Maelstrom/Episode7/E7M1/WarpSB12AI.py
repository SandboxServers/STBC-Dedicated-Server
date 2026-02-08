import App
def CreateAI(pShip):




	#########################################
	# Creating PlainAI WarptoSB12 at (213, 75)
	pWarptoSB12 = App.PlainAI_Create(pShip, "WarptoSB12")
	pWarptoSB12.SetScriptModule("Warp")
	pWarptoSB12.SetInterruptable(1)
	pScript = pWarptoSB12.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Starbase12.Starbase12")
	pScript.SetDestinationPlacementName("Player Start")
	# Done creating PlainAI WarptoSB12
	#########################################
	return pWarptoSB12
