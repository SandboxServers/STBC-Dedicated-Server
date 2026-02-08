import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI CallScript at (49, 179)
	pCallScript = App.PlainAI_Create(pShip, "CallScript")
	pCallScript.SetScriptModule("RunScript")
	pCallScript.SetInterruptable(1)
	pScript = pCallScript.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode4.E4M4.E4M4")
	pScript.SetFunction("MavjopDamaged")
	# Done creating PlainAI CallScript
	#########################################
	#########################################
	# Creating ConditionalAI Damaged at (48, 137)
	## Conditions:
	#### Condition HullLow
	pHullLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_HULL_SUBSYSTEM, 0.5)
	#### Condition PowerPlantLow
	pPowerPlantLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_POWER_SUBSYSTEM, 0.5)
	## Evaluation function:
	def EvalFunc(bHullLow, bPowerPlantLow):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bHullLow or bPowerPlantLow:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pDamaged = App.ConditionalAI_Create(pShip, "Damaged")
	pDamaged.SetInterruptable(1)
	pDamaged.SetContainedAI(pCallScript)
	pDamaged.AddCondition(pHullLow)
	pDamaged.AddCondition(pPowerPlantLow)
	pDamaged.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Damaged
	#########################################
	#########################################
	# Creating CompoundAI Attack at (139, 137)
	import AI.Compound.BasicAttack
	pAttack = AI.Compound.BasicAttack.CreateAI(pShip,  App.ObjectGroup_FromModule("Maelstrom.Episode4.E4M4.E4M4", "g_pMavjopTargetGroup2"), Difficulty = 0.8, AggressivePulseWeapons = 1, ChooseSubsystemTargets = 1, SmartShields = 1, UseCloaking = 1)
	# Done creating CompoundAI Attack
	#########################################
	#########################################
	# Creating PlainAI Follow at (225, 174)
	pFollow = App.PlainAI_Create(pShip, "Follow")
	pFollow.SetScriptModule("FollowObject")
	pFollow.SetInterruptable(1)
	pScript = pFollow.GetScriptInstance()
	pScript.SetFollowObjectName("player")
	pScript.SetRoughDistances(10,15,20)
	# Done creating PlainAI Follow
	#########################################
	#########################################
	# Creating ConditionalAI PlayerInSameSet at (225, 137)
	## Conditions:
	#### Condition InSet
	pInSet = App.ConditionScript_Create("Conditions.ConditionAllInSameSet", "ConditionAllInSameSet", pShip.GetName(), "player")
	## Evaluation function:
	def EvalFunc(bInSet):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bInSet:
			# Player is in the same set as we are.
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pPlayerInSameSet = App.ConditionalAI_Create(pShip, "PlayerInSameSet")
	pPlayerInSameSet.SetInterruptable(1)
	pPlayerInSameSet.SetContainedAI(pFollow)
	pPlayerInSameSet.AddCondition(pInSet)
	pPlayerInSameSet.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI PlayerInSameSet
	#########################################
	#########################################
	# Creating CompoundAI FollowWarp at (322, 138)
	import AI.Compound.FollowThroughWarp
	pFollowWarp = AI.Compound.FollowThroughWarp.CreateAI(pShip, "player")
	# Done creating CompoundAI FollowWarp
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (213, 47)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (222, 79)
	pPriorityList.AddAI(pDamaged, 1)
	pPriorityList.AddAI(pAttack, 2)
	pPriorityList.AddAI(pPlayerInSameSet, 3)
	pPriorityList.AddAI(pFollowWarp, 4)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (213, 13)
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
