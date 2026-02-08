import App

def CreateAI(pShip):



	#########################################
	# Creating PlainAI WarpOut at (248, 127)
	pWarpOut = App.PlainAI_Create(pShip, "WarpOut")
	pWarpOut.SetScriptModule("Warp")
	pWarpOut.SetInterruptable(1)
	# Done creating PlainAI WarpOut
	#########################################
	return pWarpOut
