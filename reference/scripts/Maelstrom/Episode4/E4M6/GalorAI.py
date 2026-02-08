import App

def CreateAI(pShip, sShipName):

	#########################################
	# Creating CompoundAI AttackKlingons at (103, 229)
	import AI.Compound.BasicAttack
	pAttackKlingons = AI.Compound.BasicAttack.CreateAI(pShip, sShipName, Difficulty = 0.05)
	# Done creating CompoundAI AttackKlingons
	#########################################
	#########################################
	# Creating CompoundAI AttackPlayer at (205, 229)
	import AI.Compound.BasicAttack
	pAttackPlayer = AI.Compound.BasicAttack.CreateAI(pShip, "player")
	# Done creating CompoundAI AttackPlayer
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (146, 145)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (170, 176)
	pPriorityList.AddAI(pAttackKlingons, 1)
	pPriorityList.AddAI(pAttackPlayer, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	return pPriorityList
	#########################################
	# Creating PreprocessingAI RedAlert at (145, 87)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.RED_ALERT)
	## The PreprocessingAI:
	pRedAlert = App.PreprocessingAI_Create(pShip, "RedAlert")
	pRedAlert.SetInterruptable(1)
	pRedAlert.SetPreprocessingMethod(pScript, "Update")
	# Done creating PreprocessingAI RedAlert
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (144, 37)
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
