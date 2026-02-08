import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI WarpToOna at (21, 126)
	pWarpToOna = App.PlainAI_Create(pShip, "WarpToOna")
	pWarpToOna.SetScriptModule("Warp")
	pWarpToOna.SetInterruptable(1)
	pScript = pWarpToOna.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Ona.Ona3")
	pScript.SetDestinationPlacementName("SFEnter")
	pScript.SetWarpDuration(10)
	# Done creating PlainAI WarpToOna
	#########################################
	#########################################
	# Creating ConditionalAI NotInOnaSet at (25, 228)
	## Conditions:
	#### Condition InOna
	pInOna = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "San Francisco", "Ona3")
	## Evaluation function:
	def EvalFunc(bInOna):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bInOna):
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pNotInOnaSet = App.ConditionalAI_Create(pShip, "NotInOnaSet")
	pNotInOnaSet.SetInterruptable(1)
	pNotInOnaSet.SetContainedAI(pWarpToOna)
	pNotInOnaSet.AddCondition(pInOna)
	pNotInOnaSet.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI NotInOnaSet
	#########################################
	#########################################
	# Creating PlainAI Call_SFTakingDamage at (143, 124)
	pCall_SFTakingDamage = App.PlainAI_Create(pShip, "Call_SFTakingDamage")
	pCall_SFTakingDamage.SetScriptModule("RunScript")
	pCall_SFTakingDamage.SetInterruptable(1)
	pScript = pCall_SFTakingDamage.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode6.E6M1.E6M1")
	pScript.SetFunction("SFTakingDamage")
	# Done creating PlainAI Call_SFTakingDamage
	#########################################
	#########################################
	# Creating ConditionalAI HullTakingDamage at (147, 230)
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
	# Creating CompoundAI BasicAttack4AllGalors at (257, 73)
	import AI.Compound.BasicAttack
	pBasicAttack4AllGalors = AI.Compound.BasicAttack.CreateAI(pShip, "Galor 5", "Galor 6", "Galor 7", Difficulty = 0.8)
	# Done creating CompoundAI BasicAttack4AllGalors
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack4Keldon at (359, 72)
	import AI.Compound.BasicAttack
	pBasicAttack4Keldon = AI.Compound.BasicAttack.CreateAI(pShip, "Keldon 2", Difficulty = 0.8)
	# Done creating CompoundAI BasicAttack4Keldon
	#########################################
	#########################################
	# Creating PriorityListAI FirstWaveTargets at (266, 221)
	pFirstWaveTargets = App.PriorityListAI_Create(pShip, "FirstWaveTargets")
	pFirstWaveTargets.SetInterruptable(1)
	# SeqBlock is at (320, 154)
	pFirstWaveTargets.AddAI(pBasicAttack4AllGalors, 1)
	pFirstWaveTargets.AddAI(pBasicAttack4Keldon, 2)
	# Done creating PriorityListAI FirstWaveTargets
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack3Keldon at (413, 128)
	import AI.Compound.BasicAttack
	pBasicAttack3Keldon = AI.Compound.BasicAttack.CreateAI(pShip, "Keldon 3", Difficulty = 0.8)
	# Done creating CompoundAI BasicAttack3Keldon
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack3Galors at (516, 126)
	import AI.Compound.BasicAttack
	pBasicAttack3Galors = AI.Compound.BasicAttack.CreateAI(pShip, "Galor 8", "Galor 9", Difficulty = 0.8)
	# Done creating CompoundAI BasicAttack3Galors
	#########################################
	#########################################
	# Creating PriorityListAI SecondWaveTargets at (416, 286)
	pSecondWaveTargets = App.PriorityListAI_Create(pShip, "SecondWaveTargets")
	pSecondWaveTargets.SetInterruptable(1)
	# SeqBlock is at (504, 226)
	pSecondWaveTargets.AddAI(pBasicAttack3Keldon, 1)
	pSecondWaveTargets.AddAI(pBasicAttack3Galors, 2)
	# Done creating PriorityListAI SecondWaveTargets
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (137, 350)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (243, 333)
	pPriorityList.AddAI(pNotInOnaSet, 1)
	pPriorityList.AddAI(pHullTakingDamage, 2)
	pPriorityList.AddAI(pFirstWaveTargets, 3)
	pPriorityList.AddAI(pSecondWaveTargets, 4)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (13, 359)
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
