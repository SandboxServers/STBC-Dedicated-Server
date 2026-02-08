import App

def CreateAI(pShip):
	import Maelstrom.Episode5.E5M4.E5M4
	#########################################
	# Creating CompoundAI Compound_2 at (279, 166)
	import AI.Compound.BasicAttack
	pCompound_2 = AI.Compound.BasicAttack.CreateAI(pShip, "player")
	# Done creating CompoundAI Compound_2
	#########################################
	#########################################
	# Creating ConditionalAI Conditional_2 at (278, 131)
	## Conditions:
	#### Condition Detected
	pDetected = App.ConditionScript_Create("Conditions.ConditionMissionEvent", "ConditionMissionEvent", Maelstrom.Episode5.E5M4.E5M4.ET_PLAYER_DETECTED)
	#### Condition InSet
	pInSet = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "player", "Alioth1")
	## Evaluation function:
	def EvalFunc(bDetected, bInSet):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bDetected and bInSet:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pConditional_2 = App.ConditionalAI_Create(pShip, "Conditional_2")
	pConditional_2.SetInterruptable(1)
	pConditional_2.SetContainedAI(pCompound_2)
	pConditional_2.AddCondition(pDetected)
	pConditional_2.AddCondition(pInSet)
	pConditional_2.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Conditional_2
	#########################################
	#########################################
	# Creating PlainAI PlayerCaught at (431, 158)
	pPlayerCaught = App.PlainAI_Create(pShip, "PlayerCaught")
	pPlayerCaught.SetScriptModule("RunScript")
	pPlayerCaught.SetInterruptable(1)
	pScript = pPlayerCaught.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode5.E5M4.E5M4")
	pScript.SetFunction("PlayerDiscovered")
	# Done creating PlainAI PlayerCaught
	#########################################
	#########################################
	# Creating CompoundAI Compound at (431, 191)
	import AI.Compound.BasicAttack
	pCompound = AI.Compound.BasicAttack.CreateAI(pShip, "player", FollowTargetThroughWarp = 1)
	# Done creating CompoundAI Compound
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (429, 108)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (430, 139)
	pSequence.AddAI(pPlayerCaught)
	pSequence.AddAI(pCompound)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating ConditionalAI Conditional at (429, 76)
	## Conditions:
	#### Condition InRange
	pInRange = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 572, "player", App.ObjectGroup_FromModule("Maelstrom.Episode5.E5M4.E5M4", "pEnemyShips"))
	#### Condition WarpingOut
	pWarpingOut = App.ConditionScript_Create("Conditions.ConditionWarpingToSet", "ConditionWarpingToSet", "player")
	#### Condition LOS
	pLOS = App.ConditionScript_Create("Conditions.ConditionInLineOfSight", "ConditionInLineOfSight", pShip.GetName(), "player", "Alioth 1")
	## Evaluation function:
	def EvalFunc(bInRange, bWarpingOut, bLOS):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if ((bInRange) and (not bLOS)) and not (bWarpingOut):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pConditional = App.ConditionalAI_Create(pShip, "Conditional")
	pConditional.SetInterruptable(1)
	pConditional.SetContainedAI(pSequence)
	pConditional.AddCondition(pInRange)
	pConditional.AddCondition(pWarpingOut)
	pConditional.AddCondition(pLOS)
	pConditional.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Conditional
	#########################################
	#########################################
	# Creating PlainAI Orbit_Alioth1 at (515, 76)
	pOrbit_Alioth1 = App.PlainAI_Create(pShip, "Orbit_Alioth1")
	pOrbit_Alioth1.SetScriptModule("CircleObject")
	pOrbit_Alioth1.SetInterruptable(1)
	pScript = pOrbit_Alioth1.GetScriptInstance()
	pScript.SetFollowObjectName("Alioth 1")
	pScript.SetNearFacingVector(App.TGPoint3_GetModelLeft())
	pScript.SetCircleSpeed(fSpeed = 5.0)
	# Done creating PlainAI Orbit_Alioth1
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (357, 21)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (477, 28)
	pPriorityList.AddAI(pConditional, 1)
	pPriorityList.AddAI(pOrbit_Alioth1, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList_2 at (216, 22)
	pPriorityList_2 = App.PriorityListAI_Create(pShip, "PriorityList_2")
	pPriorityList_2.SetInterruptable(1)
	# SeqBlock is at (313, 32)
	pPriorityList_2.AddAI(pConditional_2, 1)
	pPriorityList_2.AddAI(pPriorityList, 2)
	# Done creating PriorityListAI PriorityList_2
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (129, 23)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pPriorityList_2)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
