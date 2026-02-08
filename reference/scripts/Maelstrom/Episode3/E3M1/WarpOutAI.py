import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI WarpOut at (82, 63)
	pWarpOut = App.PlainAI_Create(pShip, "WarpOut")
	pWarpOut.SetScriptModule("Warp")
	pWarpOut.SetInterruptable(1)
	# Done creating PlainAI WarpOut
	#########################################
	return pWarpOut
