import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI Call_VentureTakingDamage at (112, 188)
	pCall_VentureTakingDamage = App.PlainAI_Create(pShip, "Call_VentureTakingDamage")
	pCall_VentureTakingDamage.SetScriptModule("RunScript")
	pCall_VentureTakingDamage.SetInterruptable(1)
	pScript = pCall_VentureTakingDamage.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode6.E6M1.E6M1")
	pScript.SetFunction("VentureTakingDamage")
	# Done creating PlainAI Call_VentureTakingDamage
	#########################################
	#########################################
	# Creating ConditionalAI HullTakingDamage at (114, 265)
	## Conditions:
	#### Condition HullAt80
	pHullAt80 = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_HULL_SUBSYSTEM, 0.50)
	## Evaluation function:
	def EvalFunc(bHullAt80):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bHullAt80):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pHullTakingDamage = App.ConditionalAI_Create(pShip, "HullTakingDamage")
	pHullTakingDamage.SetInterruptable(1)
	pHullTakingDamage.SetContainedAI(pCall_VentureTakingDamage)
	pHullTakingDamage.AddCondition(pHullAt80)
	pHullTakingDamage.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI HullTakingDamage
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack4Galor6 at (127, 77)
	import AI.Compound.BasicAttack
	pBasicAttack4Galor6 = AI.Compound.BasicAttack.CreateAI(pShip, "Galor 6", Difficulty = 0.65)
	# Done creating CompoundAI BasicAttack4Galor6
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack4Galor5 at (213, 78)
	import AI.Compound.BasicAttack
	pBasicAttack4Galor5 = AI.Compound.BasicAttack.CreateAI(pShip, "Galor 5", Difficulty = 0.65)
	# Done creating CompoundAI BasicAttack4Galor5
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack4RemainingTargets at (307, 81)
	import AI.Compound.BasicAttack
	pBasicAttack4RemainingTargets = AI.Compound.BasicAttack.CreateAI(pShip, "Galor 7", "Keldon 2", Difficulty = 0.65)
	# Done creating CompoundAI BasicAttack4RemainingTargets
	#########################################
	#########################################
	# Creating PriorityListAI FirstWaveTargets at (227, 260)
	pFirstWaveTargets = App.PriorityListAI_Create(pShip, "FirstWaveTargets")
	pFirstWaveTargets.SetInterruptable(1)
	# SeqBlock is at (221, 177)
	pFirstWaveTargets.AddAI(pBasicAttack4Galor6, 1)
	pFirstWaveTargets.AddAI(pBasicAttack4Galor5, 2)
	pFirstWaveTargets.AddAI(pBasicAttack4RemainingTargets, 3)
	# Done creating PriorityListAI FirstWaveTargets
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack3Galors at (406, 114)
	import AI.Compound.BasicAttack
	pBasicAttack3Galors = AI.Compound.BasicAttack.CreateAI(pShip, "Galor 8", "Galor 9", Difficulty = 0.65)
	# Done creating CompoundAI BasicAttack3Galors
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack3Keldon at (511, 113)
	import AI.Compound.BasicAttack
	pBasicAttack3Keldon = AI.Compound.BasicAttack.CreateAI(pShip, "Keldon 3", Difficulty = 0.65)
	# Done creating CompoundAI BasicAttack3Keldon
	#########################################
	#########################################
	# Creating PriorityListAI SecondWaveTargets at (340, 254)
	pSecondWaveTargets = App.PriorityListAI_Create(pShip, "SecondWaveTargets")
	pSecondWaveTargets.SetInterruptable(1)
	# SeqBlock is at (462, 204)
	pSecondWaveTargets.AddAI(pBasicAttack3Galors, 1)
	pSecondWaveTargets.AddAI(pBasicAttack3Keldon, 2)
	# Done creating PriorityListAI SecondWaveTargets
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (109, 350)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (241, 357)
	pPriorityList.AddAI(pHullTakingDamage, 1)
	pPriorityList.AddAI(pFirstWaveTargets, 2)
	pPriorityList.AddAI(pSecondWaveTargets, 3)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (17, 355)
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
