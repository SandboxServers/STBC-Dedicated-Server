import App

def CreateAI(pShip, *lpTargets, **dKeywords):
	# Make a group for all the targets...
	pAllTargetsGroup = App.ObjectGroup_ForceToGroup(lpTargets)
	sInitialTarget = pAllTargetsGroup.GetNameTuple()[0]
	


	#########################################
	# Creating CompoundAI BasicAttackTarget at (128, 78)
	import AI.Compound.BasicAttack
	pBasicAttackTarget = AI.Compound.BasicAttack.CreateAI(pShip, sInitialTarget, Difficulty = 0.4, AvoidTorps = 0, ChooseSubsystemTargets = 1, DisableBeforeDestroy = 1)
	# Done creating CompoundAI BasicAttackTarget
	#########################################
	#########################################
	# Creating ConditionalAI TimerForCloak at (131, 125)
	## Conditions:
	#### Condition Timer
	pTimer = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 50, 1 )
	#### Condition CloakDisabled
	pCloakDisabled = App.ConditionScript_Create("Conditions.ConditionSystemDisabled", "ConditionSystemDisabled", pShip.GetName(), App.CT_CLOAKING_SUBSYSTEM)
	## Evaluation function:
	def EvalFunc(bTimer, bCloakDisabled):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bTimer and not bCloakDisabled:
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pTimerForCloak = App.ConditionalAI_Create(pShip, "TimerForCloak")
	pTimerForCloak.SetInterruptable(1)
	pTimerForCloak.SetContainedAI(pBasicAttackTarget)
	pTimerForCloak.AddCondition(pTimer)
	pTimerForCloak.AddCondition(pCloakDisabled)
	pTimerForCloak.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TimerForCloak
	#########################################
	#########################################
	# Creating PreprocessingAI RedAlert_2 at (134, 176)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.RED_ALERT)
	## The PreprocessingAI:
	pRedAlert_2 = App.PreprocessingAI_Create(pShip, "RedAlert_2")
	pRedAlert_2.SetInterruptable(1)
	pRedAlert_2.SetPreprocessingMethod(pScript, "Update")
	pRedAlert_2.SetContainedAI(pTimerForCloak)
	# Done creating PreprocessingAI RedAlert_2
	#########################################
	#########################################
	# Creating PreprocessingAI Decloak at (136, 220)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.CloakShip(0)
	## The PreprocessingAI:
	pDecloak = App.PreprocessingAI_Create(pShip, "Decloak")
	pDecloak.SetInterruptable(1)
	pDecloak.SetPreprocessingMethod(pScript, "Update")
	pDecloak.SetContainedAI(pRedAlert_2)
	# Done creating PreprocessingAI Decloak
	#########################################
	#########################################
	# Creating PlainAI ICO at (230, 51)
	pICO = App.PlainAI_Create(pShip, "ICO")
	pICO.SetScriptModule("IntelligentCircleObject")
	pICO.SetInterruptable(1)
	pScript = pICO.GetScriptInstance()
	pScript.SetFollowObjectName(sInitialTarget)
	pScript.SetRoughDistances(75, 100)
	# Done creating PlainAI ICO
	#########################################
	#########################################
	# Creating PreprocessingAI GreenAlert at (229, 105)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.GREEN_ALERT)
	## The PreprocessingAI:
	pGreenAlert = App.PreprocessingAI_Create(pShip, "GreenAlert")
	pGreenAlert.SetInterruptable(1)
	pGreenAlert.SetPreprocessingMethod(pScript, "Update")
	pGreenAlert.SetContainedAI(pICO)
	# Done creating PreprocessingAI GreenAlert
	#########################################
	#########################################
	# Creating PreprocessingAI Cloak at (230, 160)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.CloakShip(1)
	## The PreprocessingAI:
	pCloak = App.PreprocessingAI_Create(pShip, "Cloak")
	pCloak.SetInterruptable(1)
	pCloak.SetPreprocessingMethod(pScript, "Update")
	pCloak.SetContainedAI(pGreenAlert)
	# Done creating PreprocessingAI Cloak
	#########################################
	#########################################
	# Creating ConditionalAI Timer2 at (240, 221)
	## Conditions:
	#### Condition TimerTillFire
	pTimerTillFire = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 15, 1)
	## Evaluation function:
	def EvalFunc(bTimerTillFire):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bTimerTillFire):
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pTimer2 = App.ConditionalAI_Create(pShip, "Timer2")
	pTimer2.SetInterruptable(1)
	pTimer2.SetContainedAI(pCloak)
	pTimer2.AddCondition(pTimerTillFire)
	pTimer2.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Timer2
	#########################################
	#########################################
	# Creating SequenceAI CloakSequence at (186, 294)
	pCloakSequence = App.SequenceAI_Create(pShip, "CloakSequence")
	pCloakSequence.SetInterruptable(1)
	pCloakSequence.SetLoopCount(1)
	pCloakSequence.SetResetIfInterrupted(1)
	pCloakSequence.SetDoubleCheckAllDone(0)
	pCloakSequence.SetSkipDormant(0)
	# SeqBlock is at (274, 273)
	pCloakSequence.AddAI(pDecloak)
	pCloakSequence.AddAI(pTimer2)
	# Done creating SequenceAI CloakSequence
	#########################################
	#########################################
	# Creating PlainAI GetBehindTarget at (334, 219)
	pGetBehindTarget = App.PlainAI_Create(pShip, "GetBehindTarget")
	pGetBehindTarget.SetScriptModule("MoveToObjectSide")
	pGetBehindTarget.SetInterruptable(1)
	pScript = pGetBehindTarget.GetScriptInstance()
	pScript.SetObjectSide(App.TGPoint3_GetModelBackward())
	pScript.SetObjectName(sInitialTarget)
	pScript.SetMaxDistance(160)
	# Done creating PlainAI GetBehindTarget
	#########################################
	#########################################
	# Creating ConditionalAI ShortTimer at (328, 276)
	## Conditions:
	#### Condition Timer8
	pTimer8 = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 1, 1)
	## Evaluation function:
	def EvalFunc(bTimer8):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bTimer8):
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pShortTimer = App.ConditionalAI_Create(pShip, "ShortTimer")
	pShortTimer.SetInterruptable(1)
	pShortTimer.SetContainedAI(pGetBehindTarget)
	pShortTimer.AddCondition(pTimer8)
	pShortTimer.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI ShortTimer
	#########################################
	#########################################
	# Creating ConditionalAI TorpsAreReady at (325, 334)
	## Conditions:
	#### Condition TorpsReady
	pTorpsReady = App.ConditionScript_Create("Conditions.ConditionTorpsReady", "ConditionTorpsReady", pShip.GetName())
	## Evaluation function:
	def EvalFunc(bTorpsReady):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bTorpsReady):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pTorpsAreReady = App.ConditionalAI_Create(pShip, "TorpsAreReady")
	pTorpsAreReady.SetInterruptable(1)
	pTorpsAreReady.SetContainedAI(pShortTimer)
	pTorpsAreReady.AddCondition(pTorpsReady)
	pTorpsAreReady.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TorpsAreReady
	#########################################
	#########################################
	# Creating SequenceAI OuterSequence at (25, 265)
	pOuterSequence = App.SequenceAI_Create(pShip, "OuterSequence")
	pOuterSequence.SetInterruptable(1)
	pOuterSequence.SetLoopCount(-1)
	pOuterSequence.SetResetIfInterrupted(1)
	pOuterSequence.SetDoubleCheckAllDone(1)
	pOuterSequence.SetSkipDormant(0)
	# SeqBlock is at (149, 341)
	pOuterSequence.AddAI(pCloakSequence)
	pOuterSequence.AddAI(pTorpsAreReady)
	# Done creating SequenceAI OuterSequence
	#########################################
	#########################################
	# Creating PreprocessingAI SelectTarget at (22, 324)
	## Setup:
	import AI.Preprocessors
	pSelectionPreprocess = AI.Preprocessors.SelectTarget(pAllTargetsGroup)
	## The PreprocessingAI:
	pSelectTarget = App.PreprocessingAI_Create(pShip, "SelectTarget")
	pSelectTarget.SetInterruptable(1)
	pSelectTarget.SetPreprocessingMethod(pSelectionPreprocess, "Update")
	pSelectTarget.SetContainedAI(pOuterSequence)
	# Done creating PreprocessingAI SelectTarget
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (20, 383)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pSelectTarget)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
