import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI PlayerCaught at (83, 154)
	pPlayerCaught = App.PlainAI_Create(pShip, "PlayerCaught")
	pPlayerCaught.SetScriptModule("RunScript")
	pPlayerCaught.SetInterruptable(1)
	pScript = pPlayerCaught.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode5.E5M4.E5M4")
	pScript.SetFunction("PlayerDiscovered")
	# Done creating PlainAI PlayerCaught
	#########################################
	#########################################
	# Creating CompoundAI AttackPlayer at (81, 190)
	import AI.Compound.BasicAttack
	pAttackPlayer = AI.Compound.BasicAttack.CreateAI(pShip, "player")
	# Done creating CompoundAI AttackPlayer
	#########################################
	#########################################
	# Creating SequenceAI Attack at (84, 96)
	pAttack = App.SequenceAI_Create(pShip, "Attack")
	pAttack.SetInterruptable(1)
	pAttack.SetLoopCount(1)
	pAttack.SetResetIfInterrupted(1)
	pAttack.SetDoubleCheckAllDone(0)
	pAttack.SetSkipDormant(0)
	# SeqBlock is at (83, 132)
	pAttack.AddAI(pPlayerCaught)
	pAttack.AddAI(pAttackPlayer)
	# Done creating SequenceAI Attack
	#########################################
	#########################################
	# Creating ConditionalAI Conditional at (83, 58)
	## Conditions:
	#### Condition InRange
	pInRange = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 572, "player", App.ObjectGroup_FromModule("Maelstrom.Episode5.E5M4.E5M4", "pEnemyShips"))
	#### Condition WarpingOut
	pWarpingOut = App.ConditionScript_Create("Conditions.ConditionWarpingToSet", "ConditionWarpingToSet", "player")
	## Evaluation function:
	def EvalFunc(bInRange, bWarpingOut):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bInRange) and not (bWarpingOut):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pConditional = App.ConditionalAI_Create(pShip, "Conditional")
	pConditional.SetInterruptable(1)
	pConditional.SetContainedAI(pAttack)
	pConditional.AddCondition(pInRange)
	pConditional.AddCondition(pWarpingOut)
	pConditional.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Conditional
	#########################################
	#########################################
	# Creating PlainAI Patrol_Alioth3 at (6, 299)
	pPatrol_Alioth3 = App.PlainAI_Create(pShip, "Patrol_Alioth3")
	pPatrol_Alioth3.SetScriptModule("FollowWaypoints")
	pPatrol_Alioth3.SetInterruptable(1)
	pScript = pPatrol_Alioth3.GetScriptInstance()
	pScript.SetTargetWaypointName("Patrol Start")
	# Done creating PlainAI Patrol_Alioth3
	#########################################
	#########################################
	# Creating PlainAI Warp_Alioth4 at (6, 329)
	pWarp_Alioth4 = App.PlainAI_Create(pShip, "Warp_Alioth4")
	pWarp_Alioth4.SetScriptModule("Warp")
	pWarp_Alioth4.SetInterruptable(1)
	pScript = pWarp_Alioth4.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Alioth.Alioth4")
	pScript.SetDestinationPlacementName("Player Start")
	# Done creating PlainAI Warp_Alioth4
	#########################################
	#########################################
	# Creating SequenceAI Sequence_1 at (4, 250)
	pSequence_1 = App.SequenceAI_Create(pShip, "Sequence_1")
	pSequence_1.SetInterruptable(1)
	pSequence_1.SetLoopCount(1)
	pSequence_1.SetResetIfInterrupted(1)
	pSequence_1.SetDoubleCheckAllDone(0)
	pSequence_1.SetSkipDormant(0)
	# SeqBlock is at (6, 281)
	pSequence_1.AddAI(pPatrol_Alioth3)
	pSequence_1.AddAI(pWarp_Alioth4)
	# Done creating SequenceAI Sequence_1
	#########################################
	#########################################
	# Creating PlainAI Patrol_Alioth4 at (92, 299)
	pPatrol_Alioth4 = App.PlainAI_Create(pShip, "Patrol_Alioth4")
	pPatrol_Alioth4.SetScriptModule("FollowWaypoints")
	pPatrol_Alioth4.SetInterruptable(1)
	pScript = pPatrol_Alioth4.GetScriptInstance()
	pScript.SetTargetWaypointName("Patrol Start")
	# Done creating PlainAI Patrol_Alioth4
	#########################################
	#########################################
	# Creating PlainAI Warp_Alioth5 at (92, 329)
	pWarp_Alioth5 = App.PlainAI_Create(pShip, "Warp_Alioth5")
	pWarp_Alioth5.SetScriptModule("Warp")
	pWarp_Alioth5.SetInterruptable(1)
	pScript = pWarp_Alioth5.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Alioth.Alioth5")
	pScript.SetDestinationPlacementName("Player Start")
	# Done creating PlainAI Warp_Alioth5
	#########################################
	#########################################
	# Creating SequenceAI Sequence_2 at (90, 251)
	pSequence_2 = App.SequenceAI_Create(pShip, "Sequence_2")
	pSequence_2.SetInterruptable(1)
	pSequence_2.SetLoopCount(1)
	pSequence_2.SetResetIfInterrupted(1)
	pSequence_2.SetDoubleCheckAllDone(0)
	pSequence_2.SetSkipDormant(0)
	# SeqBlock is at (92, 281)
	pSequence_2.AddAI(pPatrol_Alioth4)
	pSequence_2.AddAI(pWarp_Alioth5)
	# Done creating SequenceAI Sequence_2
	#########################################
	#########################################
	# Creating PlainAI Patrol_Alioth5 at (176, 299)
	pPatrol_Alioth5 = App.PlainAI_Create(pShip, "Patrol_Alioth5")
	pPatrol_Alioth5.SetScriptModule("FollowWaypoints")
	pPatrol_Alioth5.SetInterruptable(1)
	pScript = pPatrol_Alioth5.GetScriptInstance()
	pScript.SetTargetWaypointName("Patrol Start")
	# Done creating PlainAI Patrol_Alioth5
	#########################################
	#########################################
	# Creating PlainAI Warp_Alioth6 at (176, 330)
	pWarp_Alioth6 = App.PlainAI_Create(pShip, "Warp_Alioth6")
	pWarp_Alioth6.SetScriptModule("Warp")
	pWarp_Alioth6.SetInterruptable(1)
	pScript = pWarp_Alioth6.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Alioth.Alioth6")
	pScript.SetDestinationPlacementName("Player Start")
	# Done creating PlainAI Warp_Alioth6
	#########################################
	#########################################
	# Creating SequenceAI Sequence_3 at (176, 250)
	pSequence_3 = App.SequenceAI_Create(pShip, "Sequence_3")
	pSequence_3.SetInterruptable(1)
	pSequence_3.SetLoopCount(1)
	pSequence_3.SetResetIfInterrupted(1)
	pSequence_3.SetDoubleCheckAllDone(0)
	pSequence_3.SetSkipDormant(0)
	# SeqBlock is at (176, 281)
	pSequence_3.AddAI(pPatrol_Alioth5)
	pSequence_3.AddAI(pWarp_Alioth6)
	# Done creating SequenceAI Sequence_3
	#########################################
	#########################################
	# Creating PlainAI Patro_Alioth6 at (260, 299)
	pPatro_Alioth6 = App.PlainAI_Create(pShip, "Patro_Alioth6")
	pPatro_Alioth6.SetScriptModule("FollowWaypoints")
	pPatro_Alioth6.SetInterruptable(1)
	pScript = pPatro_Alioth6.GetScriptInstance()
	pScript.SetTargetWaypointName("Patrol Start")
	# Done creating PlainAI Patro_Alioth6
	#########################################
	#########################################
	# Creating PlainAI Warp_Alioth7 at (260, 330)
	pWarp_Alioth7 = App.PlainAI_Create(pShip, "Warp_Alioth7")
	pWarp_Alioth7.SetScriptModule("Warp")
	pWarp_Alioth7.SetInterruptable(1)
	pScript = pWarp_Alioth7.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Alioth.Alioth7")
	pScript.SetDestinationPlacementName("Player Start")
	# Done creating PlainAI Warp_Alioth7
	#########################################
	#########################################
	# Creating SequenceAI Sequence_4 at (260, 250)
	pSequence_4 = App.SequenceAI_Create(pShip, "Sequence_4")
	pSequence_4.SetInterruptable(1)
	pSequence_4.SetLoopCount(1)
	pSequence_4.SetResetIfInterrupted(1)
	pSequence_4.SetDoubleCheckAllDone(0)
	pSequence_4.SetSkipDormant(0)
	# SeqBlock is at (261, 282)
	pSequence_4.AddAI(pPatro_Alioth6)
	pSequence_4.AddAI(pWarp_Alioth7)
	# Done creating SequenceAI Sequence_4
	#########################################
	#########################################
	# Creating PlainAI Patrol_Alioth7 at (345, 300)
	pPatrol_Alioth7 = App.PlainAI_Create(pShip, "Patrol_Alioth7")
	pPatrol_Alioth7.SetScriptModule("FollowWaypoints")
	pPatrol_Alioth7.SetInterruptable(1)
	pScript = pPatrol_Alioth7.GetScriptInstance()
	pScript.SetTargetWaypointName("Patrol Start")
	# Done creating PlainAI Patrol_Alioth7
	#########################################
	#########################################
	# Creating PlainAI Warp_Alioth8 at (345, 331)
	pWarp_Alioth8 = App.PlainAI_Create(pShip, "Warp_Alioth8")
	pWarp_Alioth8.SetScriptModule("Warp")
	pWarp_Alioth8.SetInterruptable(1)
	pScript = pWarp_Alioth8.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Alioth.Alioth8")
	pScript.SetDestinationPlacementName("Player Start")
	# Done creating PlainAI Warp_Alioth8
	#########################################
	#########################################
	# Creating SequenceAI Sequence_5 at (344, 250)
	pSequence_5 = App.SequenceAI_Create(pShip, "Sequence_5")
	pSequence_5.SetInterruptable(1)
	pSequence_5.SetLoopCount(1)
	pSequence_5.SetResetIfInterrupted(1)
	pSequence_5.SetDoubleCheckAllDone(0)
	pSequence_5.SetSkipDormant(0)
	# SeqBlock is at (346, 283)
	pSequence_5.AddAI(pPatrol_Alioth7)
	pSequence_5.AddAI(pWarp_Alioth8)
	# Done creating SequenceAI Sequence_5
	#########################################
	#########################################
	# Creating PlainAI Patrol_Alioth8 at (429, 301)
	pPatrol_Alioth8 = App.PlainAI_Create(pShip, "Patrol_Alioth8")
	pPatrol_Alioth8.SetScriptModule("FollowWaypoints")
	pPatrol_Alioth8.SetInterruptable(1)
	pScript = pPatrol_Alioth8.GetScriptInstance()
	pScript.SetTargetWaypointName("Patrol Start")
	# Done creating PlainAI Patrol_Alioth8
	#########################################
	#########################################
	# Creating PlainAI Warp_Alioth3 at (429, 332)
	pWarp_Alioth3 = App.PlainAI_Create(pShip, "Warp_Alioth3")
	pWarp_Alioth3.SetScriptModule("Warp")
	pWarp_Alioth3.SetInterruptable(1)
	pScript = pWarp_Alioth3.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Alioth.Alioth3")
	pScript.SetDestinationPlacementName("Player Start")
	# Done creating PlainAI Warp_Alioth3
	#########################################
	#########################################
	# Creating SequenceAI Sequence_6 at (427, 250)
	pSequence_6 = App.SequenceAI_Create(pShip, "Sequence_6")
	pSequence_6.SetInterruptable(1)
	pSequence_6.SetLoopCount(1)
	pSequence_6.SetResetIfInterrupted(1)
	pSequence_6.SetDoubleCheckAllDone(0)
	pSequence_6.SetSkipDormant(0)
	# SeqBlock is at (428, 282)
	pSequence_6.AddAI(pPatrol_Alioth8)
	pSequence_6.AddAI(pWarp_Alioth3)
	# Done creating SequenceAI Sequence_6
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (220, 186)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(-1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (203, 221)
	pSequence.AddAI(pSequence_1)
	pSequence.AddAI(pSequence_2)
	pSequence.AddAI(pSequence_3)
	pSequence.AddAI(pSequence_4)
	pSequence.AddAI(pSequence_5)
	pSequence.AddAI(pSequence_6)
	# Done creating SequenceAI Sequence
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (85, 14)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (195, 29)
	pPriorityList.AddAI(pConditional, 1)
	pPriorityList.AddAI(pSequence, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (1, 13)
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
