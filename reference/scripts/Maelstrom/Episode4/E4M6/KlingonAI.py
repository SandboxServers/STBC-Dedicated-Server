import App

def CreateAI(pShip):


	#########################################
	# Creating CompoundAI NormalAttackGalors at (133, 265)
	import AI.Compound.BasicAttack
	pNormalAttackGalors = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode4.E4M6.E4M6", "g_pRihaGroup1"), Difficulty = 1.0, UseCloaking = 1)
	# Done creating CompoundAI NormalAttackGalors
	#########################################
	#########################################
	# Creating CompoundAI AttackEnemies at (263, 269)
	import AI.Compound.BasicAttack
	pAttackEnemies = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode4.E4M6.E4M6", "g_pRihaHostiles"), Difficulty = 1.0)
	# Done creating CompoundAI AttackEnemies
	#########################################
	#########################################
	# Creating PlainAI Stay at (354, 270)
	pStay = App.PlainAI_Create(pShip, "Stay")
	pStay.SetScriptModule("Stay")
	pStay.SetInterruptable(1)
	# Done creating PlainAI Stay
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList_3 at (307, 217)
	pPriorityList_3 = App.PriorityListAI_Create(pShip, "PriorityList_3")
	pPriorityList_3.SetInterruptable(1)
	# SeqBlock is at (332, 247)
	pPriorityList_3.AddAI(pAttackEnemies, 1)
	pPriorityList_3.AddAI(pStay, 2)
	# Done creating PriorityListAI PriorityList_3
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (214, 130)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (239, 161)
	pPriorityList.AddAI(pNormalAttackGalors, 1)
	pPriorityList.AddAI(pPriorityList_3, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI RedAlert at (213, 87)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.RED_ALERT)
	## The PreprocessingAI:
	pRedAlert = App.PreprocessingAI_Create(pShip, "RedAlert")
	pRedAlert.SetInterruptable(1)
	pRedAlert.SetPreprocessingMethod(pScript, "Update")
	pRedAlert.SetContainedAI(pPriorityList)
	# Done creating PreprocessingAI RedAlert
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (209, 39)
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
