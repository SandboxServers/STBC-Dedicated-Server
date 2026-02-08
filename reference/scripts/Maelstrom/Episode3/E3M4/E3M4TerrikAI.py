import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI AttackEnemies at (228, 203)
	import AI.Compound.BasicAttack
	pAttackEnemies = AI.Compound.BasicAttack.CreateAI(pShip, "Galor 1", "Galor 2", "Galor 3", "Keldon 1", Difficulty = 0.75, UseCloaking = 1)
	# Done creating CompoundAI AttackEnemies
	#########################################
	#########################################
	# Creating PlainAI TerrikApology at (316, 238)
	pTerrikApology = App.PlainAI_Create(pShip, "TerrikApology")
	pTerrikApology.SetScriptModule("RunScript")
	pTerrikApology.SetInterruptable(1)
	pScript = pTerrikApology.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode3.E3M4.E3M4")
	pScript.SetFunction("TerrikApology")
	# Done creating PlainAI TerrikApology
	#########################################
	#########################################
	# Creating ConditionalAI IfWait10Seconds at (316, 203)
	## Conditions:
	#### Condition WaitXSeconds
	pWaitXSeconds = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 6.0)
	#### Condition TerrikDestroyed
	pTerrikDestroyed = App.ConditionScript_Create("Conditions.ConditionDestroyed", "ConditionDestroyed", pShip.GetName ())
	## Evaluation function:
	def EvalFunc(bWaitXSeconds, bTerrikDestroyed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bWaitXSeconds and not bTerrikDestroyed):
			return ACTIVE
		else:
			return DORMANT
	## The ConditionalAI:
	pIfWait10Seconds = App.ConditionalAI_Create(pShip, "IfWait10Seconds")
	pIfWait10Seconds.SetInterruptable(1)
	pIfWait10Seconds.SetContainedAI(pTerrikApology)
	pIfWait10Seconds.AddCondition(pWaitXSeconds)
	pIfWait10Seconds.AddCondition(pTerrikDestroyed)
	pIfWait10Seconds.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfWait10Seconds
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (229, 134)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (261, 177)
	pPriorityList.AddAI(pAttackEnemies, 1)
	pPriorityList.AddAI(pIfWait10Seconds, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (228, 92)
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
