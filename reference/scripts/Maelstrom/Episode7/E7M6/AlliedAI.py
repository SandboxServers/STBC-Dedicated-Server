import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI FollowPlayer at (95, 199)
	import AI.Compound.FollowThroughWarp
	pFollowPlayer = AI.Compound.FollowThroughWarp.CreateAI(pShip, "player")
	# Done creating CompoundAI FollowPlayer
	#########################################
	#########################################
	# Creating PlainAI Stay at (193, 239)
	pStay = App.PlainAI_Create(pShip, "Stay")
	pStay.SetScriptModule("Stay")
	pStay.SetInterruptable(1)
	# Done creating PlainAI Stay
	#########################################
	#########################################
	# Creating ConditionalAI At_Starbase12 at (194, 199)
	## Conditions:
	#### Condition AtStarbase
	pAtStarbase = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "player", "Starbase12")
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
	# Creating CompoundAI AttackEnemies at (254, 314)
	import AI.Compound.BasicAttack
	pAttackEnemies = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode7.E7M6.E7M6", "pHostiles"), UseCloaking = 1)
	# Done creating CompoundAI AttackEnemies
	#########################################
	#########################################
	# Creating CompoundAI AttackBase at (346, 314)
	import AI.Compound.BasicAttack
	pAttackBase = AI.Compound.BasicAttack.CreateAI(pShip, "Litvok Nor", UseCloaking = 1)
	# Done creating CompoundAI AttackBase
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (295, 238)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (317, 268)
	pPriorityList.AddAI(pAttackEnemies, 1)
	pPriorityList.AddAI(pAttackBase, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating ConditionalAI At_Alioth6OrAlioth8 at (296, 200)
	## Conditions:
	#### Condition Alioth6
	pAlioth6 = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "player", "Alioth6")
	#### Condition Alioth8
	pAlioth8 = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "player", "Alioth8")
	## Evaluation function:
	def EvalFunc(bAlioth6, bAlioth8):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bAlioth6 or bAlioth8:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pAt_Alioth6OrAlioth8 = App.ConditionalAI_Create(pShip, "At_Alioth6OrAlioth8")
	pAt_Alioth6OrAlioth8.SetInterruptable(1)
	pAt_Alioth6OrAlioth8.SetContainedAI(pPriorityList)
	pAt_Alioth6OrAlioth8.AddCondition(pAlioth6)
	pAt_Alioth6OrAlioth8.AddCondition(pAlioth8)
	pAt_Alioth6OrAlioth8.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI At_Alioth6OrAlioth8
	#########################################
	#########################################
	# Creating PriorityListAI MainAI at (201, 115)
	pMainAI = App.PriorityListAI_Create(pShip, "MainAI")
	pMainAI.SetInterruptable(1)
	# SeqBlock is at (218, 146)
	pMainAI.AddAI(pFollowPlayer, 1)
	pMainAI.AddAI(pAt_Starbase12, 2)
	pMainAI.AddAI(pAt_Alioth6OrAlioth8, 3)
	# Done creating PriorityListAI MainAI
	#########################################
	#########################################
	# Creating PreprocessingAI RedAlert at (201, 71)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.RED_ALERT)
	## The PreprocessingAI:
	pRedAlert = App.PreprocessingAI_Create(pShip, "RedAlert")
	pRedAlert.SetInterruptable(1)
	pRedAlert.SetPreprocessingMethod(pScript, "Update")
	pRedAlert.SetContainedAI(pMainAI)
	# Done creating PreprocessingAI RedAlert
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (201, 21)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pRedAlert)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
