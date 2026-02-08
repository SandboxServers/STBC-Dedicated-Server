import App
def CreateAI(pShip, pWarpSequence):
	#########################################
	# Creating PlainAI Warp at (231, 151)
	pWarp = App.PlainAI_Create(pShip, "Warp")
	pWarp.SetScriptModule("Warp")
	pWarp.SetInterruptable(1)
	pScript = pWarp.GetScriptInstance()
	pScript.SetSequence(pWarpSequence)
	# Done creating PlainAI Warp
	#########################################
	return pWarp
