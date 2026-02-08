import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI WarpToDeepSpace at (207, 169)
	pWarpToDeepSpace = App.PlainAI_Create(pShip, "WarpToDeepSpace")
	pWarpToDeepSpace.SetScriptModule("Warp")
	pWarpToDeepSpace.SetInterruptable(1)
	pScript = pWarpToDeepSpace.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.DeepSpace.DeepSpace")
	pScript.SetDestinationPlacementName(pShip.GetName())
	# Done creating PlainAI WarpToDeepSpace
	#########################################
	return pWarpToDeepSpace
