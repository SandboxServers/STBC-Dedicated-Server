import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI PlayerCaught at (107, 113)
	pPlayerCaught = App.PlainAI_Create(pShip, "PlayerCaught")
	pPlayerCaught.SetScriptModule("RunScript")
	pPlayerCaught.SetInterruptable(1)
	pScript = pPlayerCaught.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode5.E5M4.E5M4")
	pScript.SetFunction("PlayerDiscovered")
	# Done creating PlainAI PlayerCaught
	#########################################
	#########################################
	# Creating ConditionalAI Conditional at (107, 81)
	## Conditions:
	#### Condition InRange
	pInRange = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 286, "player", App.ObjectGroup_FromModule("Maelstrom.Episode5.E5M4.E5M4", "pSatellites"))
	#### Condition WarpingOut
	pWarpingOut = App.ConditionScript_Create("Conditions.ConditionWarpingToSet", "ConditionWarpingToSet", "player")
	#### Condition LOS
	pLOS = App.ConditionScript_Create("Conditions.ConditionInLineOfSight", "ConditionInLineOfSight", pShip.GetName(), "player", "Alioth 6")
	## Evaluation function:
	def EvalFunc(bInRange, bWarpingOut, bLOS):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if ((bInRange) and (not bLOS)) and not (bWarpingOut):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pConditional = App.ConditionalAI_Create(pShip, "Conditional")
	pConditional.SetInterruptable(1)
	pConditional.SetContainedAI(pPlayerCaught)
	pConditional.AddCondition(pInRange)
	pConditional.AddCondition(pWarpingOut)
	pConditional.AddCondition(pLOS)
	pConditional.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Conditional
	#########################################
	#########################################
	# Creating PlainAI Orbit_Alioth6 at (191, 81)
	pOrbit_Alioth6 = App.PlainAI_Create(pShip, "Orbit_Alioth6")
	pOrbit_Alioth6.SetScriptModule("CircleObject")
	pOrbit_Alioth6.SetInterruptable(1)
	pScript = pOrbit_Alioth6.GetScriptInstance()
	pScript.SetFollowObjectName("Alioth 6")
	pScript.SetNearFacingVector(App.TGPoint3_GetModelLeft())
	pScript.SetCircleSpeed(fSpeed = 5.0)
	# Done creating PlainAI Orbit_Alioth6
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (23, 24)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (133, 31)
	pPriorityList.AddAI(pConditional, 1)
	pPriorityList.AddAI(pOrbit_Alioth6, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	return pPriorityList
