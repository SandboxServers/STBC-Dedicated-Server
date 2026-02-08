import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI WarpToSavoy1 at (137, 189)
	pWarpToSavoy1 = App.PlainAI_Create(pShip, "WarpToSavoy1")
	pWarpToSavoy1.SetScriptModule("Warp")
	pWarpToSavoy1.SetInterruptable(1)
	pScript = pWarpToSavoy1.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Savoy.Savoy1")
	pScript.SetDestinationPlacementName("VentureEnter")
	pScript.SetWarpDuration(10)
	# Done creating PlainAI WarpToSavoy1
	#########################################
	#########################################
	# Creating ConditionalAI NotInSavoy1 at (138, 267)
	## Conditions:
	#### Condition InSavoy1
	pInSavoy1 = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", pShip.GetName(), "Savoy1")
	## Evaluation function:
	def EvalFunc(bInSavoy1):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bInSavoy1):
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pNotInSavoy1 = App.ConditionalAI_Create(pShip, "NotInSavoy1")
	pNotInSavoy1.SetInterruptable(1)
	pNotInSavoy1.SetContainedAI(pWarpToSavoy1)
	pNotInSavoy1.AddCondition(pInSavoy1)
	pNotInSavoy1.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI NotInSavoy1
	#########################################
	#########################################
	# Creating PlainAI Call_VentureTakingDamage at (246, 186)
	pCall_VentureTakingDamage = App.PlainAI_Create(pShip, "Call_VentureTakingDamage")
	pCall_VentureTakingDamage.SetScriptModule("RunScript")
	pCall_VentureTakingDamage.SetInterruptable(1)
	pScript = pCall_VentureTakingDamage.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode6.E6M1.E6M1")
	pScript.SetFunction("VentureTakingDamage")
	# Done creating PlainAI Call_VentureTakingDamage
	#########################################
	#########################################
	# Creating ConditionalAI HullTakingDamage at (238, 268)
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
	# Creating CompoundAI BasicAttack3Galors11_12 at (345, 147)
	import AI.Compound.BasicAttack
	pBasicAttack3Galors11_12 = AI.Compound.BasicAttack.CreateAI(pShip, "Galor 11", "Galor 12", Difficulty = 0.65)
	# Done creating CompoundAI BasicAttack3Galors11_12
	#########################################
	#########################################
	# Creating CompoundAI BasicAttackKeldons at (450, 149)
	import AI.Compound.BasicAttack
	pBasicAttackKeldons = AI.Compound.BasicAttack.CreateAI(pShip, "Keldon 5", "Keldon 6", "Keldon 7", Difficulty = 0.65)
	# Done creating CompoundAI BasicAttackKeldons
	#########################################
	#########################################
	# Creating PriorityListAI FirstWaveTargets at (335, 271)
	pFirstWaveTargets = App.PriorityListAI_Create(pShip, "FirstWaveTargets")
	pFirstWaveTargets.SetInterruptable(1)
	# SeqBlock is at (417, 218)
	pFirstWaveTargets.AddAI(pBasicAttack3Galors11_12, 1)
	pFirstWaveTargets.AddAI(pBasicAttackKeldons, 2)
	# Done creating PriorityListAI FirstWaveTargets
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (91, 349)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (246, 355)
	pPriorityList.AddAI(pNotInSavoy1, 1)
	pPriorityList.AddAI(pHullTakingDamage, 2)
	pPriorityList.AddAI(pFirstWaveTargets, 3)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (4, 320)
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
