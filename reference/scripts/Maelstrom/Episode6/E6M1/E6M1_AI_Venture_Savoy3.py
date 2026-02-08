import App
def CreateAI(pShip, pTargetGroup):

	#########################################
	# Creating PlainAI WarpToSavoy3 at (65, 182)
	pWarpToSavoy3 = App.PlainAI_Create(pShip, "WarpToSavoy3")
	pWarpToSavoy3.SetScriptModule("Warp")
	pWarpToSavoy3.SetInterruptable(1)
	pScript = pWarpToSavoy3.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Savoy.Savoy3")
	pScript.SetDestinationPlacementName("VentureEnter")
	# Done creating PlainAI WarpToSavoy3
	#########################################
	#########################################
	# Creating ConditionalAI NotInSavoy3 at (64, 262)
	## Conditions:
	#### Condition InSavoy3
	pInSavoy3 = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", pShip.GetName(), "Savoy3")
	## Evaluation function:
	def EvalFunc(bInSavoy3):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bInSavoy3):
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pNotInSavoy3 = App.ConditionalAI_Create(pShip, "NotInSavoy3")
	pNotInSavoy3.SetInterruptable(1)
	pNotInSavoy3.SetContainedAI(pWarpToSavoy3)
	pNotInSavoy3.AddCondition(pInSavoy3)
	pNotInSavoy3.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI NotInSavoy3
	#########################################
	#########################################
	# Creating PlainAI Call_VentureTakingDamage at (166, 181)
	pCall_VentureTakingDamage = App.PlainAI_Create(pShip, "Call_VentureTakingDamage")
	pCall_VentureTakingDamage.SetScriptModule("RunScript")
	pCall_VentureTakingDamage.SetInterruptable(1)
	pScript = pCall_VentureTakingDamage.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode6.E6M1.E6M1")
	pScript.SetFunction("VentureTakingDamage")
	# Done creating PlainAI Call_VentureTakingDamage
	#########################################
	#########################################
	# Creating ConditionalAI HullTakingDamage at (163, 263)
	## Conditions:
	#### Condition HullAt80
	pHullAt80 = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_HULL_SUBSYSTEM, 0.80)
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
	pHullTakingDamage.SetContainedAI(pCall_VentureTakingDamage)
	pHullTakingDamage.AddCondition(pHullAt80)
	pHullTakingDamage.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI HullTakingDamage
	#########################################
	#########################################
	# Creating CompoundAI BasicAttackAllTargets at (270, 266)
	import AI.Compound.BasicAttack
	pBasicAttackAllTargets = AI.Compound.BasicAttack.CreateAI(pShip, pTargetGroup, Difficulty = 0.65)
	# Done creating CompoundAI BasicAttackAllTargets
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (104, 362)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (194, 357)
	pPriorityList.AddAI(pNotInSavoy3, 1)
	pPriorityList.AddAI(pHullTakingDamage, 2)
	pPriorityList.AddAI(pBasicAttackAllTargets, 3)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (11, 356)
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
