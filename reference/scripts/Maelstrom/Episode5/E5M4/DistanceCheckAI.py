import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI PlayerCloseToSats at (55, 117)
	pPlayerCloseToSats = App.PlainAI_Create(pShip, "PlayerCloseToSats")
	pPlayerCloseToSats.SetScriptModule("RunScript")
	pPlayerCloseToSats.SetInterruptable(1)
	pScript = pPlayerCloseToSats.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode5.E5M4.E5M4")
	pScript.SetFunction("CloseToSats")
	# Done creating PlainAI PlayerCloseToSats
	#########################################
	#########################################
	# Creating ConditionalAI Player_Close_Satellite at (54, 80)
	## Conditions:
	#### Condition InRange
	pInRange = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 450, "player", App.ObjectGroup_FromModule("Maelstrom.Episode5.E5M4.E5M4", "pSatellites"))
	#### Condition InWarp
	pInWarp = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "player", "warp")
	## Evaluation function:
	def EvalFunc(bInRange, bInWarp):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bInRange) and not (bInWarp):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pPlayer_Close_Satellite = App.ConditionalAI_Create(pShip, "Player_Close_Satellite")
	pPlayer_Close_Satellite.SetInterruptable(1)
	pPlayer_Close_Satellite.SetContainedAI(pPlayerCloseToSats)
	pPlayer_Close_Satellite.AddCondition(pInRange)
	pPlayer_Close_Satellite.AddCondition(pInWarp)
	pPlayer_Close_Satellite.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Player_Close_Satellite
	#########################################
	#########################################
	# Creating PlainAI PlayerCloseToPatrol at (141, 118)
	pPlayerCloseToPatrol = App.PlainAI_Create(pShip, "PlayerCloseToPatrol")
	pPlayerCloseToPatrol.SetScriptModule("RunScript")
	pPlayerCloseToPatrol.SetInterruptable(1)
	pScript = pPlayerCloseToPatrol.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode5.E5M4.E5M4")
	pScript.SetFunction("CloseToPatrol")
	# Done creating PlainAI PlayerCloseToPatrol
	#########################################
	#########################################
	# Creating ConditionalAI Player_Close_Patrol at (140, 80)
	## Conditions:
	#### Condition InRange2
	pInRange2 = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 715, "player", App.ObjectGroup_FromModule("Maelstrom.Episode5.E5M4.E5M4", "pEnemyShips"))
	#### Condition InWarp2
	pInWarp2 = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "player", "warp")
	## Evaluation function:
	def EvalFunc(bInRange2, bInWarp2):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bInRange2) and not (bInWarp2):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pPlayer_Close_Patrol = App.ConditionalAI_Create(pShip, "Player_Close_Patrol")
	pPlayer_Close_Patrol.SetInterruptable(1)
	pPlayer_Close_Patrol.SetContainedAI(pPlayerCloseToPatrol)
	pPlayer_Close_Patrol.AddCondition(pInRange2)
	pPlayer_Close_Patrol.AddCondition(pInWarp2)
	pPlayer_Close_Patrol.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Player_Close_Patrol
	#########################################
	#########################################
	# Creating PlainAI Scripted_2 at (295, 37)
	pScripted_2 = App.PlainAI_Create(pShip, "Scripted_2")
	pScripted_2.SetScriptModule("Stay")
	pScripted_2.SetInterruptable(1)
	# Done creating PlainAI Scripted_2
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (23, 24)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (192, 20)
	pPriorityList.AddAI(pPlayer_Close_Satellite, 1)
	pPriorityList.AddAI(pPlayer_Close_Patrol, 2)
	pPriorityList.AddAI(pScripted_2, 3)
	# Done creating PriorityListAI PriorityList
	#########################################
	return pPriorityList
