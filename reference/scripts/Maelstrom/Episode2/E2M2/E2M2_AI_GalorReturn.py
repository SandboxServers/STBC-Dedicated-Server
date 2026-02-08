import App

def CreateAI(pShip, pTargetGroup):



	#########################################
	# Creating CompoundAI AttackTargets at (116, 161)
	import AI.Compound.BasicAttack
	pAttackTargets = AI.Compound.BasicAttack.CreateAI(pShip, pTargetGroup, Easy_Difficulty = 0.35, Easy_MaxFiringRange = 509.0, Easy_AvoidTorps = 1, Easy_DisableBeforeDestroy = 1, Difficulty = 0.71, MaxFiringRange = 500.0, Hard_Difficulty = 0.9, Hard_MaxFiringRange = 311.0)
	# Done creating CompoundAI AttackTargets
	#########################################
	#########################################
	# Creating ConditionalAI CriticalDamage at (115, 208)
	## Conditions:
	#### Condition ShipCriticalSysDamage
	pShipCriticalSysDamage = App.ConditionScript_Create("Conditions.ConditionCriticalSystemBelow", "ConditionCriticalSystemBelow", pShip.GetName(), 0.35)
	#### Condition ShipWarpDamaged
	pShipWarpDamaged = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_WARP_ENGINE_SUBSYSTEM, 0.50)
	#### Condition KeldonDestroyed
	pKeldonDestroyed = App.ConditionScript_Create("Conditions.ConditionDestroyed", "ConditionDestroyed", "Keldon 1")
	#### Condition GalorDestroyed
	pGalorDestroyed = App.ConditionScript_Create("Conditions.ConditionDestroyed", "ConditionDestroyed", "Galor 2")
	## Evaluation function:
	def EvalFunc(bShipCriticalSysDamage, bShipWarpDamaged, bKeldonDestroyed, bGalorDestroyed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bShipCriticalSysDamage or bShipWarpDamaged) and (bKeldonDestroyed or bGalorDestroyed):
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pCriticalDamage = App.ConditionalAI_Create(pShip, "CriticalDamage")
	pCriticalDamage.SetInterruptable(1)
	pCriticalDamage.SetContainedAI(pAttackTargets)
	pCriticalDamage.AddCondition(pShipCriticalSysDamage)
	pCriticalDamage.AddCondition(pShipWarpDamaged)
	pCriticalDamage.AddCondition(pKeldonDestroyed)
	pCriticalDamage.AddCondition(pGalorDestroyed)
	pCriticalDamage.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI CriticalDamage
	#########################################
	#########################################
	# Creating PlainAI WarpOut at (192, 267)
	pWarpOut = App.PlainAI_Create(pShip, "WarpOut")
	pWarpOut.SetScriptModule("Warp")
	pWarpOut.SetInterruptable(1)
	pScript = pWarpOut.GetScriptInstance()
	pScript.WarpBlindlyNoCollisionsIfImpulseDisabled(1)
	# Done creating PlainAI WarpOut
	#########################################
	#########################################
	# Creating SequenceAI MainSequence at (14, 308)
	pMainSequence = App.SequenceAI_Create(pShip, "MainSequence")
	pMainSequence.SetInterruptable(1)
	pMainSequence.SetLoopCount(1)
	pMainSequence.SetResetIfInterrupted(1)
	pMainSequence.SetDoubleCheckAllDone(0)
	pMainSequence.SetSkipDormant(0)
	# SeqBlock is at (111, 282)
	pMainSequence.AddAI(pCriticalDamage)
	pMainSequence.AddAI(pWarpOut)
	# Done creating SequenceAI MainSequence
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
	pAvoidObstacles.SetContainedAI(pMainSequence)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
