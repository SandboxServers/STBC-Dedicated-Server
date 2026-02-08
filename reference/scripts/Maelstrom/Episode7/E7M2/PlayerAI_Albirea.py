import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI Stay at (219, 139)
	pStay = App.PlainAI_Create(pShip, "Stay")
	pStay.SetScriptModule("Stay")
	# Done creating PlainAI Stay
	#########################################
	return pStay
