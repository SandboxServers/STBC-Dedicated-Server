import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI SetGeronimoDamagedFlag at (222, 168)
	pSetGeronimoDamagedFlag = App.PlainAI_Create(pShip, "SetGeronimoDamagedFlag")
	pSetGeronimoDamagedFlag.SetScriptModule("RunScript")
	pSetGeronimoDamagedFlag.SetInterruptable(1)
	pScript = pSetGeronimoDamagedFlag.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode7.E7M3.E7M3")
	pScript.SetFunction("GeronimoDamaged")
	# Done creating PlainAI SetGeronimoDamagedFlag
	#########################################
	#########################################
	# Creating ConditionalAI GeronimoDamaged at (181, 133)
	## Conditions:
	#### Condition HullDamaged
	pHullDamaged = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_HULL_SUBSYSTEM, 0.75)
	#### Condition ShieldsDamaged
	pShieldsDamaged = App.ConditionScript_Create("Conditions.ConditionSingleShieldBelow", "ConditionSingleShieldBelow", pShip.GetName(), .50, App.ShieldClass.NUM_SHIELDS)
	#### Condition CoreDamaged
	pCoreDamaged = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_POWER_SUBSYSTEM, 0.75)
	## Evaluation function:
	def EvalFunc(bHullDamaged, bShieldsDamaged, bCoreDamaged):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bHullDamaged or bShieldsDamaged or bCoreDamaged:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pGeronimoDamaged = App.ConditionalAI_Create(pShip, "GeronimoDamaged")
	pGeronimoDamaged.SetInterruptable(1)
	pGeronimoDamaged.SetContainedAI(pSetGeronimoDamagedFlag)
	pGeronimoDamaged.AddCondition(pHullDamaged)
	pGeronimoDamaged.AddCondition(pShieldsDamaged)
	pGeronimoDamaged.AddCondition(pCoreDamaged)
	pGeronimoDamaged.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI GeronimoDamaged
	#########################################
	#########################################
	# Creating CompoundAI Basicattack at (197, 90)
	import AI.Compound.BasicAttack
	pBasicattack = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode7.E7M3.E7M3", "pEnemyTargets"), Difficulty = .7)
	# Done creating CompoundAI Basicattack
	#########################################
	#########################################
	# Creating PlainAI Stay at (229, 50)
	pStay = App.PlainAI_Create(pShip, "Stay")
	pStay.SetScriptModule("Stay")
	pStay.SetInterruptable(1)
	# Done creating PlainAI Stay
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (86, 51)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (174, 57)
	pPriorityList.AddAI(pGeronimoDamaged, 1)
	pPriorityList.AddAI(pBasicattack, 2)
	pPriorityList.AddAI(pStay, 3)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (45, 145)
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
