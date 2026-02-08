import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI DontMove at (50, 50)
	pDontMove = App.PlainAI_Create(pShip, "DontMove")
	pDontMove.SetScriptModule("Stay")
	pDontMove.SetInterruptable(1)
	# Done creating PlainAI DontMove
	#########################################
	#########################################
	# Creating PreprocessingAI GreenAlert at (49, 109)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.GREEN_ALERT)
	## The PreprocessingAI:
	pGreenAlert = App.PreprocessingAI_Create(pShip, "GreenAlert")
	pGreenAlert.SetInterruptable(1)
	pGreenAlert.SetPreprocessingMethod(pScript, "Update")
	pGreenAlert.SetContainedAI(pDontMove)
	# Done creating PreprocessingAI GreenAlert
	#########################################
	return pGreenAlert
