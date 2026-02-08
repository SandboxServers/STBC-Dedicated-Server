import App

def CreateAI(pShip):



	#########################################
	# Creating CompoundAI CallDamageAI at (84, 319)
	import AI.Compound.CallDamageAI
	pCallDamageAI = AI.Compound.CallDamageAI.CreateAI(pShip)
	# Done creating CompoundAI CallDamageAI
	#########################################
	#########################################
	# Creating CompoundAI Attack at (171, 319)
	import Ai.Compound.BasicAttack
	pAttack = Ai.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode7.E7M6.E7M6", "pHostiles"))
	# Done creating CompoundAI Attack
	#########################################
	#########################################
	# Creating CompoundAI AttackStation at (256, 319)
	import Ai.Compound.BasicAttack
	pAttackStation = Ai.Compound.BasicAttack.CreateAI(pShip, "Litvok Nor", Difficulty = 1.0)
	# Done creating CompoundAI AttackStation
	#########################################
	#########################################
	# Creating PlainAI Stay at (341, 320)
	pStay = App.PlainAI_Create(pShip, "Stay")
	pStay.SetScriptModule("Stay")
	pStay.SetInterruptable(1)
	# Done creating PlainAI Stay
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (210, 148)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (277, 282)
	pPriorityList.AddAI(pCallDamageAI, 1)
	pPriorityList.AddAI(pAttack, 2)
	pPriorityList.AddAI(pAttackStation, 3)
	pPriorityList.AddAI(pStay, 4)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (204, 81)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pPriorityList)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	#########################################
	# Creating PreprocessingAI RedAlert at (204, 32)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.RED_ALERT)
	## The PreprocessingAI:
	pRedAlert = App.PreprocessingAI_Create(pShip, "RedAlert")
	pRedAlert.SetInterruptable(1)
	pRedAlert.SetPreprocessingMethod(pScript, "Update")
	pRedAlert.SetContainedAI(pAvoidObstacles)
	# Done creating PreprocessingAI RedAlert
	#########################################
	return pRedAlert
