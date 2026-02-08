import App

def CreateAI(pShip, *lTargets, **dKeywords):
	# Set the UseCloaking flag to False, so we don't get stuck
	# in an infinite loop.
	for sKey in ( "UseCloaking", "Easy_UseCloaking", "Hard_UseCloaking" ):
		if dKeywords.has_key(sKey):
			dKeywords[sKey] = 0

	#########################################
	# Creating CompoundAI BasicAttack at (169, 60)
	import AI.Compound.BasicAttack
	pBasicAttack = AI.Compound.BasicAttack.CreateAI(pShip, lTargets, Keywords = dKeywords)
	# Done creating CompoundAI BasicAttack
	#########################################
	#########################################
	# Creating ConditionalAI CloakingDisabled at (163, 132)
	## Conditions:
	#### Condition Disabled
	pDisabled = App.ConditionScript_Create("Conditions.ConditionSystemDisabled", "ConditionSystemDisabled", pShip.GetName(), App.CT_CLOAKING_SUBSYSTEM)
	## Evaluation function:
	def EvalFunc(bDisabled):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bDisabled:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pCloakingDisabled = App.ConditionalAI_Create(pShip, "CloakingDisabled")
	pCloakingDisabled.SetInterruptable(1)
	pCloakingDisabled.SetContainedAI(pBasicAttack)
	pCloakingDisabled.AddCondition(pDisabled)
	pCloakingDisabled.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI CloakingDisabled
	#########################################
	#########################################
	# Creating CompoundAI CloakAttack at (286, 135)
	import AI.Compound.CloakAttack
	pCloakAttack = AI.Compound.CloakAttack.CreateAI(pShip, lTargets, Keywords = dKeywords)
	# Done creating CompoundAI CloakAttack
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (57, 211)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (229, 207)
	pPriorityList.AddAI(pCloakingDisabled, 1)
	pPriorityList.AddAI(pCloakAttack, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	return pPriorityList
