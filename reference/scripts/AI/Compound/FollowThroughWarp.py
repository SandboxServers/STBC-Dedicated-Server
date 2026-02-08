import App

# Info for the AI editor:
# AIFlag(FollowToSB12) OnOff
# AIFlag(FollowThroughMissions) OnOff

def CreateAI(pShip, sTarget, bWarpBlindly = 0, **dKeywords):
	if dKeywords.has_key("Keywords"):
		dKeywords = dKeywords["Keywords"]

	if not dKeywords.has_key("FollowToSB12"):
		# Default value should be true.
		dKeywords["FollowToSB12"] = 1
	if not dKeywords.has_key("FollowThroughMissions"):
		# Default value should be false.
		dKeywords["FollowThroughMissions"] = 0

	#########################################
	# Creating PlainAI WarpFollow at (246, 41)
	pWarpFollow = App.PlainAI_Create(pShip, "WarpFollow")
	pWarpFollow.SetScriptModule("FollowThroughWarp")
	pWarpFollow.SetInterruptable(0)
	pScript = pWarpFollow.GetScriptInstance()
	pScript.SetFollowObjectName(sTarget)
	pScript.WarpBlindly(bWarpBlindly)
	# Done creating PlainAI WarpFollow
	#########################################
	#########################################
	# Creating ConditionalAI CheckMissionWarping at (210, 98)
	## Conditions:
	#### Condition FollowThroughMissions
	pFollowThroughMissions = App.ConditionScript_Create("Conditions.ConditionFlagSet", "ConditionFlagSet", "FollowThroughMissions", dKeywords)
	#### Condition WarpingToMission
	pWarpingToMission = App.ConditionScript_Create("Conditions.ConditionWarpingToMission", "ConditionWarpingToMission", sTarget)
	## Evaluation function:
	def EvalFunc(bFollowThroughMissions, bWarpingToMission):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (not bFollowThroughMissions) and bWarpingToMission:
			return DORMANT
		return ACTIVE
	## The ConditionalAI:
	pCheckMissionWarping = App.ConditionalAI_Create(pShip, "CheckMissionWarping")
	pCheckMissionWarping.SetInterruptable(1)
	pCheckMissionWarping.SetContainedAI(pWarpFollow)
	pCheckMissionWarping.AddCondition(pFollowThroughMissions)
	pCheckMissionWarping.AddCondition(pWarpingToMission)
	pCheckMissionWarping.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI CheckMissionWarping
	#########################################
	#########################################
	# Creating ConditionalAI CheckStarbase12 at (203, 144)
	## Conditions:
	#### Condition FollowIntoSB12Flag
	pFollowIntoSB12Flag = App.ConditionScript_Create("Conditions.ConditionFlagSet", "ConditionFlagSet", "FollowToSB12", dKeywords)
	#### Condition TargetInSB12
	pTargetInSB12 = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", sTarget, "Starbase12", 1)
	#### Condition WarpingIntoSB12
	pWarpingIntoSB12 = App.ConditionScript_Create("Conditions.ConditionWarpingToSet", "ConditionWarpingToSet", sTarget, "Systems.Starbase12.Starbase12")
	## Evaluation function:
	def EvalFunc(bFollowIntoSB12Flag, bTargetInSB12, bWarpingIntoSB12):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (not bFollowIntoSB12Flag)  and  (bTargetInSB12  or  bWarpingIntoSB12):
			return DORMANT
		return ACTIVE
	## The ConditionalAI:
	pCheckStarbase12 = App.ConditionalAI_Create(pShip, "CheckStarbase12")
	pCheckStarbase12.SetInterruptable(1)
	pCheckStarbase12.SetContainedAI(pCheckMissionWarping)
	pCheckStarbase12.AddCondition(pFollowIntoSB12Flag)
	pCheckStarbase12.AddCondition(pTargetInSB12)
	pCheckStarbase12.AddCondition(pWarpingIntoSB12)
	pCheckStarbase12.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI CheckStarbase12
	#########################################
	#########################################
	# Creating ConditionalAI TargetExistsInWrongSet at (203, 205)
	## Conditions:
	#### Condition SameSet
	pSameSet = App.ConditionScript_Create("Conditions.ConditionAnyInSameSet", "ConditionAnyInSameSet", pShip.GetName(), sTarget)
	#### Condition Exists
	pExists = App.ConditionScript_Create("Conditions.ConditionExists", "ConditionExists", sTarget)
	## Evaluation function:
	def EvalFunc(bSameSet, bExists):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bExists  and  (not bSameSet):
			# We're in the wrong set.  Warp.
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pTargetExistsInWrongSet = App.ConditionalAI_Create(pShip, "TargetExistsInWrongSet")
	pTargetExistsInWrongSet.SetInterruptable(1)
	pTargetExistsInWrongSet.SetContainedAI(pCheckStarbase12)
	pTargetExistsInWrongSet.AddCondition(pSameSet)
	pTargetExistsInWrongSet.AddCondition(pExists)
	pTargetExistsInWrongSet.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TargetExistsInWrongSet
	#########################################
	#########################################
	# Creating SequenceAI FollowThroughWarpSequence at (126, 260)
	pFollowThroughWarpSequence = App.SequenceAI_Create(pShip, "FollowThroughWarpSequence")
	pFollowThroughWarpSequence.SetInterruptable(1)
	pFollowThroughWarpSequence.SetLoopCount(-1)
	pFollowThroughWarpSequence.SetResetIfInterrupted(1)
	pFollowThroughWarpSequence.SetDoubleCheckAllDone(1)
	pFollowThroughWarpSequence.SetSkipDormant(1)
	# SeqBlock is at (236, 267)
	pFollowThroughWarpSequence.AddAI(pTargetExistsInWrongSet)
	# Done creating SequenceAI FollowThroughWarpSequence
	#########################################
	return pFollowThroughWarpSequence
