import App
def CreateAI(pShip, pTargetGroup):

	#########################################
	# Creating PlainAI WarpToSavoy3 at (37, 105)
	pWarpToSavoy3 = App.PlainAI_Create(pShip, "WarpToSavoy3")
	pWarpToSavoy3.SetScriptModule("Warp")
	pWarpToSavoy3.SetInterruptable(1)
	pScript = pWarpToSavoy3.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Savoy.Savoy3")
	pScript.SetDestinationPlacementName("SFEnter")
	pScript.SetWarpDuration(10)
	# Done creating PlainAI WarpToSavoy3
	#########################################
	#########################################
	# Creating ConditionalAI NotInSavoy3Set at (61, 233)
	## Conditions:
	#### Condition InSavoy3
	pInSavoy3 = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "San Francisco", "Savoy3")
	## Evaluation function:
	def EvalFunc(bInSavoy3):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bInSavoy3):
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pNotInSavoy3Set = App.ConditionalAI_Create(pShip, "NotInSavoy3Set")
	pNotInSavoy3Set.SetInterruptable(1)
	pNotInSavoy3Set.SetContainedAI(pWarpToSavoy3)
	pNotInSavoy3Set.AddCondition(pInSavoy3)
	pNotInSavoy3Set.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI NotInSavoy3Set
	#########################################
	#########################################
	# Creating PlainAI Call_SFTakingDamage at (171, 102)
	pCall_SFTakingDamage = App.PlainAI_Create(pShip, "Call_SFTakingDamage")
	pCall_SFTakingDamage.SetScriptModule("RunScript")
	pCall_SFTakingDamage.SetInterruptable(1)
	pScript = pCall_SFTakingDamage.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode6.E6M1.E6M1")
	pScript.SetFunction("SFTakingDamage")
	# Done creating PlainAI Call_SFTakingDamage
	#########################################
	#########################################
	# Creating ConditionalAI HullTakingDamage at (180, 228)
	## Conditions:
	#### Condition HullAt80
	pHullAt80 = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", "San Francisco", App.CT_HULL_SUBSYSTEM, 0.80)
	## Evaluation function:
	def EvalFunc(bHullAt80):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bHullAt80):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pHullTakingDamage = App.ConditionalAI_Create(pShip, "HullTakingDamage")
	pHullTakingDamage.SetInterruptable(1)
	pHullTakingDamage.SetContainedAI(pCall_SFTakingDamage)
	pHullTakingDamage.AddCondition(pHullAt80)
	pHullTakingDamage.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI HullTakingDamage
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack at (301, 229)
	import AI.Compound.BasicAttack
	pBasicAttack = AI.Compound.BasicAttack.CreateAI(pShip, pTargetGroup, Difficulty = 0.8)
	# Done creating CompoundAI BasicAttack
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (118, 347)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (261, 351)
	pPriorityList.AddAI(pNotInSavoy3Set, 1)
	pPriorityList.AddAI(pHullTakingDamage, 2)
	pPriorityList.AddAI(pBasicAttack, 3)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (21, 348)
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
