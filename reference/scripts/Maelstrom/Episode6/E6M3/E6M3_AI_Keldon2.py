import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI Call_KeldonAttackingGalor at (291, 30)
	pCall_KeldonAttackingGalor = App.PlainAI_Create(pShip, "Call_KeldonAttackingGalor")
	pCall_KeldonAttackingGalor.SetScriptModule("RunScript")
	pCall_KeldonAttackingGalor.SetInterruptable(1)
	pScript = pCall_KeldonAttackingGalor.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode6.E6M3.E6M3")
	pScript.SetFunction("KeldonAttackingKhitomer")
	# Done creating PlainAI Call_KeldonAttackingGalor
	#########################################
	#########################################
	# Creating CompoundAI BasicAttackKhitomer at (410, 45)
	import AI.Compound.BasicAttack
	pBasicAttackKhitomer = AI.Compound.BasicAttack.CreateAI(pShip, "Khitomer", Easy_Difficulty = 0.22, Difficulty = 0.5, SmartShields = 1)
	# Done creating CompoundAI BasicAttackKhitomer
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (163, 76)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (313, 81)
	pSequence.AddAI(pCall_KeldonAttackingGalor)
	pSequence.AddAI(pBasicAttackKhitomer)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating ConditionalAI FedsClose at (106, 143)
	## Conditions:
	#### Condition FedsInRange150
	pFedsInRange150 = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 150, pShip.GetName(), App.ObjectGroup_FromModule("Maelstrom.Episode6.E6M3.E6M3", "g_pSavoy3GalorTargets"))
	## Evaluation function:
	def EvalFunc(bFedsInRange150):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bFedsInRange150):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pFedsClose = App.ConditionalAI_Create(pShip, "FedsClose")
	pFedsClose.SetInterruptable(1)
	pFedsClose.SetContainedAI(pSequence)
	pFedsClose.AddCondition(pFedsInRange150)
	pFedsClose.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI FedsClose
	#########################################
	#########################################
	# Creating PlainAI InterceptKhitomer at (231, 136)
	pInterceptKhitomer = App.PlainAI_Create(pShip, "InterceptKhitomer")
	pInterceptKhitomer.SetScriptModule("Intercept")
	pInterceptKhitomer.SetInterruptable(1)
	pScript = pInterceptKhitomer.GetScriptInstance()
	pScript.SetTargetObjectName("Khitomer")
	# Done creating PlainAI InterceptKhitomer
	#########################################
	#########################################
	# Creating CompoundAI BasicAttackSavoy3GalorTargets at (340, 167)
	import AI.Compound.BasicAttack
	pBasicAttackSavoy3GalorTargets = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode6.E6M3.E6M3", "g_pSavoy3GalorTargets"), Easy_Difficulty = 0.22, Difficulty = 0.52, Hard_Difficulty = 0.85)
	# Done creating CompoundAI BasicAttackSavoy3GalorTargets
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (46, 210)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (184, 226)
	pPriorityList.AddAI(pFedsClose, 1)
	pPriorityList.AddAI(pInterceptKhitomer, 2)
	pPriorityList.AddAI(pBasicAttackSavoy3GalorTargets, 3)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (66, 330)
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
