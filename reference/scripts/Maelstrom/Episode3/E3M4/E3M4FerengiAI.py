import App
def CreateAI(pShip):


	#########################################
	# Creating PlainAI FerengiDialog at (119, 233)
	pFerengiDialog = App.PlainAI_Create(pShip, "FerengiDialog")
	pFerengiDialog.SetScriptModule("RunScript")
	pFerengiDialog.SetInterruptable(1)
	pScript = pFerengiDialog.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode3.E3M4.E3M4")
	pScript.SetFunction("FerengiDialog")
	# Done creating PlainAI FerengiDialog
	#########################################
	#########################################
	# Creating ConditionalAI IfNoEnemies at (116, 186)
	## Conditions:
	#### Condition EnemiesInSet
	pEnemiesInSet = App.ConditionScript_Create("Conditions.ConditionAnyInSameSet", "ConditionAnyInSameSet", pShip.GetName (), "Galor 1", "Galor 2", "Galor 3")
	## Evaluation function:
	def EvalFunc(bEnemiesInSet):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (not bEnemiesInSet):
			return ACTIVE
		else:
			return DORMANT
	## The ConditionalAI:
	pIfNoEnemies = App.ConditionalAI_Create(pShip, "IfNoEnemies")
	pIfNoEnemies.SetInterruptable(1)
	pIfNoEnemies.SetContainedAI(pFerengiDialog)
	pIfNoEnemies.AddCondition(pEnemiesInSet)
	pIfNoEnemies.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfNoEnemies
	#########################################
	#########################################
	# Creating CompoundAI AttackGalors at (207, 233)
	import AI.Compound.BasicAttack
	pAttackGalors = AI.Compound.BasicAttack.CreateAI(pShip, "Galor 1", "Galor 2", "Galor 3", Difficulty = 0.75, SmartShields = 1)
	# Done creating CompoundAI AttackGalors
	#########################################
	#########################################
	# Creating ConditionalAI IfPlayerAttacked at (207, 186)
	## Conditions:
	#### Condition PAttackedByG1
	pPAttackedByG1 = App.ConditionScript_Create("Conditions.ConditionAttackedBy", "ConditionAttackedBy", "player", "Galor 1", 0, 0, 0)
	#### Condition PAttackedByG2
	pPAttackedByG2 = App.ConditionScript_Create("Conditions.ConditionAttackedBy", "ConditionAttackedBy", "player", "Galor 2", 0, 0, 0)
	## Evaluation function:
	def EvalFunc(bPAttackedByG1, bPAttackedByG2):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bPAttackedByG1 or bPAttackedByG2):
			return ACTIVE
		else:
			return DORMANT
	## The ConditionalAI:
	pIfPlayerAttacked = App.ConditionalAI_Create(pShip, "IfPlayerAttacked")
	pIfPlayerAttacked.SetInterruptable(1)
	pIfPlayerAttacked.SetContainedAI(pAttackGalors)
	pIfPlayerAttacked.AddCondition(pPAttackedByG1)
	pIfPlayerAttacked.AddCondition(pPAttackedByG2)
	pIfPlayerAttacked.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfPlayerAttacked
	#########################################
	#########################################
	# Creating PlainAI AvoidAttack at (297, 186)
	pAvoidAttack = App.PlainAI_Create(pShip, "AvoidAttack")
	pAvoidAttack.SetScriptModule("Defensive")
	pAvoidAttack.SetInterruptable(1)
	pScript = pAvoidAttack.GetScriptInstance()
	pScript.SetEnemyName("Galor 1")
	# Done creating PlainAI AvoidAttack
	#########################################
	#########################################
	# Creating PlainAI AvoidAttack_2 at (385, 185)
	pAvoidAttack_2 = App.PlainAI_Create(pShip, "AvoidAttack_2")
	pAvoidAttack_2.SetScriptModule("Defensive")
	pAvoidAttack_2.SetInterruptable(1)
	pScript = pAvoidAttack_2.GetScriptInstance()
	pScript.SetEnemyName("Galor 2")
	# Done creating PlainAI AvoidAttack_2
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (116, 121)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (127, 152)
	pPriorityList.AddAI(pIfNoEnemies, 1)
	pPriorityList.AddAI(pIfPlayerAttacked, 2)
	pPriorityList.AddAI(pAvoidAttack, 3)
	pPriorityList.AddAI(pAvoidAttack_2, 4)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (119, 79)
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
	return pAvoidObstacles
