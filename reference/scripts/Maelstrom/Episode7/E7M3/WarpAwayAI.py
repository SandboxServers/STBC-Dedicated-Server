import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI WarpAway at (255, 99)
	pWarpAway = App.PlainAI_Create(pShip, "WarpAway")
	pWarpAway.SetScriptModule("Warp")
	pWarpAway.SetInterruptable(1)
	pScript = pWarpAway.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Serris.Serris2")
	# Done creating PlainAI WarpAway
	#########################################
	return pWarpAway
