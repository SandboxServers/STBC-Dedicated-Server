import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI CallDamageAI at (216, 151)
	import AI.Compound.CallDamageAI
	pCallDamageAI = AI.Compound.CallDamageAI.CreateAI(pShip)
	# Done creating CompoundAI CallDamageAI
	#########################################
	#########################################
	# Creating PlainAI Flee at (334, 95)
	pFlee = App.PlainAI_Create(pShip, "Flee")
	pFlee.SetScriptModule("Flee")
	pFlee.SetInterruptable(1)
	pScript = pFlee.GetScriptInstance()
	pScript.SetFleeFromGroup("Chairo")
	# Done creating PlainAI Flee
	#########################################
	#########################################
	# Creating ConditionalAI Close_To_Warbird at (233, 115)
	## Conditions:
	#### Condition Range1
	pRange1 = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 240, "JonKa", "Chairo")
	## Evaluation function:
	def EvalFunc(bRange1):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bRange1:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pClose_To_Warbird = App.ConditionalAI_Create(pShip, "Close_To_Warbird")
	pClose_To_Warbird.SetInterruptable(1)
	pClose_To_Warbird.SetContainedAI(pFlee)
	pClose_To_Warbird.AddCondition(pRange1)
	pClose_To_Warbird.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Close_To_Warbird
	#########################################
	#########################################
	# Creating PriorityListAI Vorcha_Main at (112, 22)
	pVorcha_Main = App.PriorityListAI_Create(pShip, "Vorcha_Main")
	pVorcha_Main.SetInterruptable(1)
	# SeqBlock is at (209, 29)
	pVorcha_Main.AddAI(pCallDamageAI, 1)
	pVorcha_Main.AddAI(pClose_To_Warbird, 2)
	# Done creating PriorityListAI Vorcha_Main
	#########################################

	#########################################
	# Creating PreprocessingAI AvoidObstacles at (25, 42)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pVorcha_Main)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
