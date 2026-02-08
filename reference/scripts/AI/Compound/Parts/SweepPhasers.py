import App

def CreateAI(pShip, sTarget, fSpeed, dKeywords):

	#########################################
	# Creating PlainAI PhaserSweepWithSideArcs at (293, 277)
	pPhaserSweepWithSideArcs = App.PlainAI_Create(pShip, "PhaserSweepWithSideArcs")
	pPhaserSweepWithSideArcs.SetScriptModule("PhaserSweep")
	pPhaserSweepWithSideArcs.SetInterruptable(1)
	pScript = pPhaserSweepWithSideArcs.GetScriptInstance()
	pScript.SetTargetObjectName(sTarget)
	pScript.SetSweepPhasersDuringRun(180.0)
	pScript.SetSpeedFraction(fSpeed)
	# Done creating PlainAI PhaserSweepWithSideArcs
	#########################################
	#########################################
	# Creating ConditionalAI UseSideArcs at (293, 340)
	## Conditions:
	#### Condition UseSideArcsFlag
	pUseSideArcsFlag = App.ConditionScript_Create("Conditions.ConditionFlagSet", "ConditionFlagSet", "UseSideArcs", dKeywords)
	## Evaluation function:
	def EvalFunc(bUseSideArcsFlag):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bUseSideArcsFlag:
			return ACTIVE
		return DONE
	## The ConditionalAI:
	pUseSideArcs = App.ConditionalAI_Create(pShip, "UseSideArcs")
	pUseSideArcs.SetInterruptable(1)
	pUseSideArcs.SetContainedAI(pPhaserSweepWithSideArcs)
	pUseSideArcs.AddCondition(pUseSideArcsFlag)
	pUseSideArcs.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI UseSideArcs
	#########################################
	#########################################
	# Creating PlainAI PhaserSweep at (400, 373)
	pPhaserSweep = App.PlainAI_Create(pShip, "PhaserSweep")
	pPhaserSweep.SetScriptModule("PhaserSweep")
	pPhaserSweep.SetInterruptable(1)
	pScript = pPhaserSweep.GetScriptInstance()
	pScript.SetTargetObjectName(sTarget)
	pScript.SetSweepPhasersDuringRun(70)
	pScript.SetSpeedFraction(fSpeed)
	pScript.SetPrimaryDirection(App.TGPoint3_GetModelForward())
	# Done creating PlainAI PhaserSweep
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (251, 418)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (370, 426)
	pPriorityList.AddAI(pUseSideArcs, 1)
	pPriorityList.AddAI(pPhaserSweep, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	return pPriorityList
