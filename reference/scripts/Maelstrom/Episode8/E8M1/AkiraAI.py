import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI FollowPlayer at (47, 101)
	import AI.Compound.FollowThroughWarp
	pFollowPlayer = AI.Compound.FollowThroughWarp.CreateAI(pShip, "player")
	# Done creating CompoundAI FollowPlayer
	#########################################
	#########################################
	# Creating PlainAI Stay at (145, 132)
	pStay = App.PlainAI_Create(pShip, "Stay")
	pStay.SetScriptModule("Stay")
	pStay.SetInterruptable(1)
	# Done creating PlainAI Stay
	#########################################
	#########################################
	# Creating ConditionalAI At_Starbase12 at (145, 99)
	## Conditions:
	#### Condition AtStarbase
	pAtStarbase = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "USS Geronimo", "Starbase12")
	## Evaluation function:
	def EvalFunc(bAtStarbase):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bAtStarbase:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pAt_Starbase12 = App.ConditionalAI_Create(pShip, "At_Starbase12")
	pAt_Starbase12.SetInterruptable(1)
	pAt_Starbase12.SetContainedAI(pStay)
	pAt_Starbase12.AddCondition(pAtStarbase)
	pAt_Starbase12.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI At_Starbase12
	#########################################
	#########################################
	# Creating CompoundAI AttackKessok1 at (231, 188)
	import AI.Compound.BasicAttack
	pAttackKessok1 = AI.Compound.BasicAttack.CreateAI(pShip, "Kessok1", "Kessok2")
	# Done creating CompoundAI AttackKessok1
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (231, 135)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (232, 169)
	pPriorityList.AddAI(pAttackKessok1, 1)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating ConditionalAI At_Riha1 at (232, 99)
	## Conditions:
	#### Condition Riha1
	pRiha1 = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "USS Geronimo", "Riha1")
	## Evaluation function:
	def EvalFunc(bRiha1):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bRiha1:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pAt_Riha1 = App.ConditionalAI_Create(pShip, "At_Riha1")
	pAt_Riha1.SetInterruptable(1)
	pAt_Riha1.SetContainedAI(pPriorityList)
	pAt_Riha1.AddCondition(pRiha1)
	pAt_Riha1.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI At_Riha1
	#########################################
	#########################################
	# Creating CompoundAI AttackKessok2 at (330, 188)
	import Ai.Compound.BasicAttack
	pAttackKessok2 = Ai.Compound.BasicAttack.CreateAI(pShip, "Kessok3", "Kessok4")
	# Done creating CompoundAI AttackKessok2
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList_2 at (333, 134)
	pPriorityList_2 = App.PriorityListAI_Create(pShip, "PriorityList_2")
	pPriorityList_2.SetInterruptable(1)
	# SeqBlock is at (335, 166)
	pPriorityList_2.AddAI(pAttackKessok2, 1)
	# Done creating PriorityListAI PriorityList_2
	#########################################
	#########################################
	# Creating ConditionalAI At_Cebalrai1 at (331, 99)
	## Conditions:
	#### Condition Cebalrai1
	pCebalrai1 = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "USS Geronimo", "Cebalrai1")
	## Evaluation function:
	def EvalFunc(bCebalrai1):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bCebalrai1:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pAt_Cebalrai1 = App.ConditionalAI_Create(pShip, "At_Cebalrai1")
	pAt_Cebalrai1.SetInterruptable(1)
	pAt_Cebalrai1.SetContainedAI(pPriorityList_2)
	pAt_Cebalrai1.AddCondition(pCebalrai1)
	pAt_Cebalrai1.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI At_Cebalrai1
	#########################################
	#########################################
	# Creating CompoundAI AttackKessok3 at (437, 189)
	import Ai.Compound.BasicAttack
	pAttackKessok3 = Ai.Compound.BasicAttack.CreateAI(pShip, "Kessok5", "Kessok6")
	# Done creating CompoundAI AttackKessok3
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList_3 at (434, 134)
	pPriorityList_3 = App.PriorityListAI_Create(pShip, "PriorityList_3")
	pPriorityList_3.SetInterruptable(1)
	# SeqBlock is at (435, 168)
	pPriorityList_3.AddAI(pAttackKessok3, 1)
	# Done creating PriorityListAI PriorityList_3
	#########################################
	#########################################
	# Creating ConditionalAI At_Belaruz1 at (434, 99)
	## Conditions:
	#### Condition Belaruz1
	pBelaruz1 = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "USS Geronimo", "Belaruz1")
	## Evaluation function:
	def EvalFunc(bBelaruz1):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bBelaruz1:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pAt_Belaruz1 = App.ConditionalAI_Create(pShip, "At_Belaruz1")
	pAt_Belaruz1.SetInterruptable(1)
	pAt_Belaruz1.SetContainedAI(pPriorityList_3)
	pAt_Belaruz1.AddCondition(pBelaruz1)
	pAt_Belaruz1.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI At_Belaruz1
	#########################################
	#########################################
	# Creating PriorityListAI MainAI at (129, 12)
	pMainAI = App.PriorityListAI_Create(pShip, "MainAI")
	pMainAI.SetInterruptable(1)
	# SeqBlock is at (255, 25)
	pMainAI.AddAI(pFollowPlayer, 1)
	pMainAI.AddAI(pAt_Starbase12, 2)
	pMainAI.AddAI(pAt_Riha1, 3)
	pMainAI.AddAI(pAt_Cebalrai1, 4)
	pMainAI.AddAI(pAt_Belaruz1, 5)
	# Done creating PriorityListAI MainAI
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (37, 15)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pMainAI)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
