import App
import Maelstrom.Episode3.E3M5.E3M5
def CreateAI(pShip):






	#########################################
	# Creating CompoundAI Attack at (404, 265)
	import AI.Compound.BasicAttack
	pAttack = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode3.E3M5.E3M5", "g_pEnemies"), Difficulty = 0.75, UseCloaking = 1)
	# Done creating CompoundAI Attack
	#########################################
	#########################################
	# Creating ConditionalAI IfMatanInSet at (363, 230)
	## Conditions:
	#### Condition MatanHere
	pMatanHere = App.ConditionScript_Create("Conditions.ConditionAllInSameSet", "ConditionAllInSameSet", "MatanShip")
	## Evaluation function:
	def EvalFunc(bMatanHere):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bMatanHere:
			return ACTIVE
		else:
			return DONE
	## The ConditionalAI:
	pIfMatanInSet = App.ConditionalAI_Create(pShip, "IfMatanInSet")
	pIfMatanInSet.SetInterruptable(1)
	pIfMatanInSet.SetContainedAI(pAttack)
	pIfMatanInSet.AddCondition(pMatanHere)
	pIfMatanInSet.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfMatanInSet
	#########################################
	#########################################
	# Creating PlainAI WarpToB2 at (469, 160)
	pWarpToB2 = App.PlainAI_Create(pShip, "WarpToB2")
	pWarpToB2.SetScriptModule("Warp")
	pWarpToB2.SetInterruptable(1)
	pScript = pWarpToB2.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Belaruz.Belaruz2")
	pScript.SetDestinationPlacementName("BOP3 Enter")
	# Done creating PlainAI WarpToB2
	#########################################
	#########################################
	# Creating ConditionalAI IfWait15Seconds at (379, 180)
	## Conditions:
	#### Condition Wait15Seconds
	pWait15Seconds = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 15.0)
	## Evaluation function:
	def EvalFunc(bWait15Seconds):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bWait15Seconds):
			return ACTIVE
		else:
			return DORMANT
	## The ConditionalAI:
	pIfWait15Seconds = App.ConditionalAI_Create(pShip, "IfWait15Seconds")
	pIfWait15Seconds.SetInterruptable(1)
	pIfWait15Seconds.SetContainedAI(pWarpToB2)
	pIfWait15Seconds.AddCondition(pWait15Seconds)
	pIfWait15Seconds.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfWait15Seconds
	#########################################
	#########################################
	# Creating SequenceAI GoAfterMatan at (244, 144)
	pGoAfterMatan = App.SequenceAI_Create(pShip, "GoAfterMatan")
	pGoAfterMatan.SetInterruptable(1)
	pGoAfterMatan.SetLoopCount(1)
	pGoAfterMatan.SetResetIfInterrupted(1)
	pGoAfterMatan.SetDoubleCheckAllDone(0)
	pGoAfterMatan.SetSkipDormant(0)
	# SeqBlock is at (354, 151)
	pGoAfterMatan.AddAI(pIfMatanInSet)
	pGoAfterMatan.AddAI(pIfWait15Seconds)
	# Done creating SequenceAI GoAfterMatan
	#########################################
	#########################################
	# Creating ConditionalAI IfInBelaruz4 at (203, 99)
	## Conditions:
	#### Condition InBelaruz4
	pInBelaruz4 = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", pShip.GetName (), "Belaruz4")
	## Evaluation function:
	def EvalFunc(bInBelaruz4):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bInBelaruz4):
			return ACTIVE
		else:
			return DONE
	## The ConditionalAI:
	pIfInBelaruz4 = App.ConditionalAI_Create(pShip, "IfInBelaruz4")
	pIfInBelaruz4.SetInterruptable(1)
	pIfInBelaruz4.SetContainedAI(pGoAfterMatan)
	pIfInBelaruz4.AddCondition(pInBelaruz4)
	pIfInBelaruz4.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfInBelaruz4
	#########################################
	#########################################
	# Creating CompoundAI AttackEnemies at (299, 25)
	import AI.Compound.BasicAttack
	pAttackEnemies = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode3.E3M5.E3M5", "g_pEnemies"), Difficulty = 0.85, UseCloaking = 1)
	# Done creating CompoundAI AttackEnemies
	#########################################
	#########################################
	# Creating ConditionalAI InBelaruz2withPlayer at (217, 45)
	## Conditions:
	#### Condition InBelaruz2
	pInBelaruz2 = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", pShip.GetName (), "Belaruz2")
	#### Condition PlayerInSet
	pPlayerInSet = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "player", "Belaruz2")
	## Evaluation function:
	def EvalFunc(bInBelaruz2, bPlayerInSet):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bInBelaruz2 and bPlayerInSet):
			return ACTIVE
		else:
			return DORMANT
	## The ConditionalAI:
	pInBelaruz2withPlayer = App.ConditionalAI_Create(pShip, "InBelaruz2withPlayer")
	pInBelaruz2withPlayer.SetInterruptable(1)
	pInBelaruz2withPlayer.SetContainedAI(pAttackEnemies)
	pInBelaruz2withPlayer.AddCondition(pInBelaruz2)
	pInBelaruz2withPlayer.AddCondition(pPlayerInSet)
	pInBelaruz2withPlayer.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI InBelaruz2withPlayer
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (102, 8)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (194, 14)
	pPriorityList.AddAI(pIfInBelaruz4, 1)
	pPriorityList.AddAI(pInBelaruz2withPlayer, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (18, 28)
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
