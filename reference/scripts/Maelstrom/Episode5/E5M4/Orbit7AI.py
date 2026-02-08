import App

def CreateAI(pShip):
	import Maelstrom.Episode5.E5M4.E5M4
	#########################################
	# Creating CompoundAI Compound_2 at (228, 108)
	import AI.Compound.BasicAttack
	pCompound_2 = AI.Compound.BasicAttack.CreateAI(pShip, "player")
	# Done creating CompoundAI Compound_2
	#########################################
	#########################################
	# Creating ConditionalAI Conditional_2 at (227, 70)
	## Conditions:
	#### Condition Detected
	pDetected = App.ConditionScript_Create("Conditions.ConditionMissionEvent", "ConditionMissionEvent", Maelstrom.Episode5.E5M4.E5M4.ET_PLAYER_DETECTED)
	#### Condition InSet
	pInSet = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "player", "Alioth7")
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
	# Creating PlainAI PlayerCaught at (358, 162)
	pPlayerCaught = App.PlainAI_Create(pShip, "PlayerCaught")
	pPlayerCaught.SetScriptModule("RunScript")
	pPlayerCaught.SetInterruptable(1)
	pScript = pPlayerCaught.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode5.E5M4.E5M4")
	pScript.SetFunction("PlayerDiscovered")
	# Done creating PlainAI PlayerCaught
	#########################################
	#########################################
	# Creating CompoundAI Compound at (357, 194)
	import AI.Compound.BasicAttack
	pCompound = AI.Compound.BasicAttack.CreateAI(pShip, "player")
	# Done creating CompoundAI Compound
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (358, 106)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (358, 142)
	pSequence.AddAI(pPlayerCaught)
	pSequence.AddAI(pCompound)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating ConditionalAI Conditional at (359, 74)
	## Conditions:
	#### Condition InRange
	pInRange = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 572, "player", App.ObjectGroup_FromModule("Maelstrom.Episode5.E5M4.E5M4", "pEnemyShips"))
	#### Condition WarpingOut
	pWarpingOut = App.ConditionScript_Create("Conditions.ConditionWarpingToSet", "ConditionWarpingToSet", "player")
	#### Condition LOS
	pLOS = App.ConditionScript_Create("Conditions.ConditionInLineOfSight", "ConditionInLineOfSight", pShip.GetName(), "player", "Alioth 7")
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
	# Creating PlainAI Orbit_Alioth7 at (450, 49)
	pOrbit_Alioth7 = App.PlainAI_Create(pShip, "Orbit_Alioth7")
	pOrbit_Alioth7.SetScriptModule("CircleObject")
	pOrbit_Alioth7.SetInterruptable(1)
	pScript = pOrbit_Alioth7.GetScriptInstance()
	pScript.SetFollowObjectName("Alioth 7")
	pScript.SetNearFacingVector(App.TGPoint3_GetModelLeft())
	pScript.SetRoughDistances(fNearDistance = 500, fFarDistance = 550)
	pScript.SetCircleSpeed(fSpeed = 5.0)
	# Done creating PlainAI Orbit_Alioth7
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (352, 23)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (356, 56)
	pPriorityList.AddAI(pConditional, 1)
	pPriorityList.AddAI(pOrbit_Alioth7, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList_2 at (166, 12)
	pPriorityList_2 = App.PriorityListAI_Create(pShip, "PriorityList_2")
	pPriorityList_2.SetInterruptable(1)
	# SeqBlock is at (273, 19)
	pPriorityList_2.AddAI(pConditional_2, 1)
	pPriorityList_2.AddAI(pPriorityList, 2)
	# Done creating PriorityListAI PriorityList_2
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (54, 55)
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
