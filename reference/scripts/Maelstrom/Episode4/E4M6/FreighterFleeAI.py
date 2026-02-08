import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI Flee at (223, 115)
	pFlee = App.PlainAI_Create(pShip, "Flee")
	pFlee.SetScriptModule("Flee")
	pFlee.SetInterruptable(1)
	pScript = pFlee.GetScriptInstance()
	pScript.SetFleeFromGroup(App.ObjectGroup_FromModule("Maelstrom.Episode4.E4M6.E4M6", "g_pFriendlies"))
	pScript.SetSpeed(1.0)
	# Done creating PlainAI Flee
	#########################################
	#########################################
	# Creating PreprocessingAI RedAlert at (222, 68)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.RED_ALERT)
	## The PreprocessingAI:
	pRedAlert = App.PreprocessingAI_Create(pShip, "RedAlert")
	pRedAlert.SetInterruptable(1)
	pRedAlert.SetPreprocessingMethod(pScript, "Update")
	pRedAlert.SetContainedAI(pFlee)
	# Done creating PreprocessingAI RedAlert
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (219, 20)
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
