import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI Call_KlingonTakingDamage at (59, 186)
	pCall_KlingonTakingDamage = App.PlainAI_Create(pShip, "Call_KlingonTakingDamage")
	pCall_KlingonTakingDamage.SetScriptModule("RunScript")
	pCall_KlingonTakingDamage.SetInterruptable(1)
	pScript = pCall_KlingonTakingDamage.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode2.E2M0.E2M0")
	pScript.SetFunction("KlingonTakingDamage")
	pScript.SetArguments(pShip.GetName())
	# Done creating PlainAI Call_KlingonTakingDamage
	#########################################
	#########################################
	# Creating ConditionalAI TakingCriticalDamage at (62, 234)
	## Conditions:
	#### Condition CriticalSystemBelow50
	pCriticalSystemBelow50 = App.ConditionScript_Create("Conditions.ConditionCriticalSystemBelow", "ConditionCriticalSystemBelow", pShip.GetName(), 0.5)
	## Evaluation function:
	def EvalFunc(bCriticalSystemBelow50):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bCriticalSystemBelow50:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pTakingCriticalDamage = App.ConditionalAI_Create(pShip, "TakingCriticalDamage")
	pTakingCriticalDamage.SetInterruptable(1)
	pTakingCriticalDamage.SetContainedAI(pCall_KlingonTakingDamage)
	pTakingCriticalDamage.AddCondition(pCriticalSystemBelow50)
	pTakingCriticalDamage.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TakingCriticalDamage
	#########################################
	#########################################
	# Creating CompoundAI CloakingAttack at (178, 245)
	import AI.Compound.BasicAttack
	pCloakingAttack = AI.Compound.BasicAttack.CreateAI(pShip, "Warbird 1", "Warbird 2", MaxFiringRange = 300.0, DisableBeforeDestroy = 1, DumbFireTorps = 1, InaccurateTorps = 1, SmartShields = 1, SmartTorpSelection = 0, UseCloaking = 1)
	# Done creating CompoundAI CloakingAttack
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (25, 296)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (130, 292)
	pPriorityList.AddAI(pTakingCriticalDamage, 1)
	pPriorityList.AddAI(pCloakingAttack, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (24, 348)
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
