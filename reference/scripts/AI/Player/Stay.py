import App

def CreateAI(pShip, pTarget = None):
	#########################################
	# Creating PlainAI Stay at (81, 245)
	pStay = App.PlainAI_Create(pShip, "Stay")
	pStay.SetScriptModule("Stay")
	pStay.SetInterruptable(1)
	pShip.CompleteStop ()
	# Done creating PlainAI Stay
	#########################################
	return pStay
