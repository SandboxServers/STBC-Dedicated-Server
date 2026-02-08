import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI RamStarbase at (193, 59)
	pRamStarbase = App.PlainAI_Create(pShip, "RamStarbase")
	pRamStarbase.SetScriptModule("Ram")
	pRamStarbase.SetInterruptable(1)
	pScript = pRamStarbase.GetScriptInstance()
	pScript.SetTargetObjectName("Starbase 12")
	pScript.SetMaximumSpeed(1.5)
	# Done creating PlainAI RamStarbase
	#########################################
	return pRamStarbase
