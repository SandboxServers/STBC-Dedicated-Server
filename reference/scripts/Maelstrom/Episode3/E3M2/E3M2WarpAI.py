import App

def CreateAI(pShip, sPlacementName):


	#########################################
	# Creating PlainAI Warp at (210, 124)
	pWarp = App.PlainAI_Create(pShip, "Warp")
	pWarp.SetScriptModule("Warp")
	pWarp.SetInterruptable(1)
	pScript = pWarp.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Vesuvi.Vesuvi4")
	pScript.SetDestinationPlacementName(sPlacementName)
	# Done creating PlainAI Warp
	#########################################
	return pWarp
