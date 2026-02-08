import App

def CreateAI(pShip, sName):

	#########################################
	# Creating PlainAI CircleShip at (220, 100)
	pCircleShip = App.PlainAI_Create(pShip, "CircleShip")
	pCircleShip.SetScriptModule("IntelligentCircleObject")
	pCircleShip.SetInterruptable(1)
	pScript = pCircleShip.GetScriptInstance()
	pScript.SetFollowObjectName(sName)
	pScript.SetRoughDistances(100, 150)
	# Done creating PlainAI CircleShip
	#########################################
	#########################################
	# Creating PreprocessingAI GreenAlert at (218, 50)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.GREEN_ALERT)
	## The PreprocessingAI:
	pGreenAlert = App.PreprocessingAI_Create(pShip, "GreenAlert")
	pGreenAlert.SetInterruptable(1)
	pGreenAlert.SetPreprocessingMethod(pScript, "Update")
	pGreenAlert.SetContainedAI(pCircleShip)
	# Done creating PreprocessingAI GreenAlert
	#########################################
	return pGreenAlert
