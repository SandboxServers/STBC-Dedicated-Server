import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI ManeuverLoop at (209, 152)
	pManeuverLoop = App.PlainAI_Create(pShip, "ManeuverLoop")
	pManeuverLoop.SetScriptModule("IntelligentCircleObject")
	pManeuverLoop.SetInterruptable(1)
	pScript = pManeuverLoop.GetScriptInstance()
	pScript.SetFollowObjectName("player")
	pScript.SetRoughDistances(fNearDistance = 50, fFarDistance = 150)
	# Done creating PlainAI ManeuverLoop
	#########################################
	#########################################
	# Creating PreprocessingAI RedAlert at (210, 104)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.RED_ALERT)
	## The PreprocessingAI:
	pRedAlert = App.PreprocessingAI_Create(pShip, "RedAlert")
	pRedAlert.SetInterruptable(1)
	pRedAlert.SetPreprocessingMethod(pScript, "Update")
	pRedAlert.SetContainedAI(pManeuverLoop)
	# Done creating PreprocessingAI RedAlert
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (211, 53)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pRedAlert)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
