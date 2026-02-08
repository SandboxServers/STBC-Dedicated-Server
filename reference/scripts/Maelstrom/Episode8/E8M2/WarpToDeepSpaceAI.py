import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI WarptoDeepSpace at (255, 99)
	pWarptoDeepSpace = App.PlainAI_Create(pShip, "WarptoDeepSpace")
	pWarptoDeepSpace.SetScriptModule("Warp")
	pWarptoDeepSpace.SetInterruptable(1)
	pScript = pWarptoDeepSpace.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.DeepSpace.DeepSpace")
	# Done creating PlainAI WarptoDeepSpace
	#########################################
	return pWarptoDeepSpace
