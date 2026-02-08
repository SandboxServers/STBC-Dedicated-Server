import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI Stay at (219, 157)
	pStay = App.PlainAI_Create(pShip, "Stay")
	pStay.SetScriptModule("Stay")
	pStay.SetInterruptable(1)
	# Done creating PlainAI Stay
	#########################################
	return pStay
