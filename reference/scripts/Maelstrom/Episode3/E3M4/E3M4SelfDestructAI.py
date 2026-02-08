import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI SelfDestruct at (50, 50)
	pSelfDestruct = App.PlainAI_Create(pShip, "SelfDestruct")
	pSelfDestruct.SetScriptModule("SelfDestruct")
	pSelfDestruct.SetInterruptable(1)
	# Done creating PlainAI SelfDestruct
	#########################################
	return pSelfDestruct
