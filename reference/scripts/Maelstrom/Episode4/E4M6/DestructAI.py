import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI GoBoom at (50, 50)
	pGoBoom = App.PlainAI_Create(pShip, "GoBoom")
	pGoBoom.SetScriptModule("SelfDestruct")
	pGoBoom.SetInterruptable(1)
	# Done creating PlainAI GoBoom
	#########################################
	return pGoBoom
