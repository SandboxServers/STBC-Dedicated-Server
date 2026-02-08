import App

def CreateAI(pShip):

	#########################################
	# Creating PlainAI BailDude at (56, 162)
	pBailDude = App.PlainAI_Create(pShip, "BailDude")
	pBailDude.SetScriptModule("Warp")
	pBailDude.SetInterruptable(1)
	pScript = pBailDude.GetScriptInstance()
	pScript.WarpBlindlyNoCollisionsIfImpulseDisabled(bWarpBlindly = 1)
	# Done creating PlainAI BailDude
	#########################################
	return pBailDude
