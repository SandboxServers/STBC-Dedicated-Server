import App
def CreateAI(pShip):







	#########################################
	# Creating PlainAI WarpNowhere at (11, 19)
	pWarpNowhere = App.PlainAI_Create(pShip, "WarpNowhere")
	pWarpNowhere.SetScriptModule("Warp")
	pWarpNowhere.SetInterruptable(1)
	# Done creating PlainAI WarpNowhere
	#########################################
	return pWarpNowhere
