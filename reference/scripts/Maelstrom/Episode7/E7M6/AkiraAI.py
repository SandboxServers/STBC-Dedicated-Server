import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI CallDamageAI at (28, 203)
	import AI.Compound.CallDamageAI
	pCallDamageAI = AI.Compound.CallDamageAI.CreateAI(pShip)
	# Done creating CompoundAI CallDamageAI
	#########################################
	#########################################
	# Creating CompoundAI FollowPlayer at (129, 201)
	import AI.Compound.FollowThroughWarp
	pFollowPlayer = AI.Compound.FollowThroughWarp.CreateAI(pShip, "player")
	# Done creating CompoundAI FollowPlayer
	#########################################
	#########################################
	# Creating PlainAI Stay at (221, 238)
	pStay = App.PlainAI_Create(pShip, "Stay")
	pStay.SetScriptModule("Stay")
	pStay.SetInterruptable(1)
	# Done creating PlainAI Stay
	#########################################
	#########################################
	# Creating ConditionalAI At_Starbase12 at (220, 199)
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
	# Creating CompoundAI AttackEnemies at (281, 315)
	import AI.Compound.BasicAttack
	pAttackEnemies = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode7.E7M6.E7M6", "pHostiles"), Difficulty = 0.75, SmartTorpSelection = 1)
	# Done creating CompoundAI AttackEnemies
	#########################################
	#########################################
	# Creating CompoundAI AttackBase at (395, 315)
	import AI.Compound.BasicAttack
	pAttackBase = AI.Compound.BasicAttack.CreateAI(pShip, "Litvok Nor", Difficulty = 0.75, SmartTorpSelection = 1)
	# Done creating CompoundAI AttackBase
	#########################################
	#########################################
	# Creating SequenceAI Sequence_2 at (325, 239)
	pSequence_2 = App.SequenceAI_Create(pShip, "Sequence_2")
	pSequence_2.SetInterruptable(1)
	pSequence_2.SetLoopCount(1)
	pSequence_2.SetResetIfInterrupted(1)
	pSequence_2.SetDoubleCheckAllDone(0)
	pSequence_2.SetSkipDormant(0)
	# SeqBlock is at (350, 269)
	pSequence_2.AddAI(pAttackEnemies)
	pSequence_2.AddAI(pAttackBase)
	# Done creating SequenceAI Sequence_2
	#########################################
	#########################################
	# Creating ConditionalAI At_Alioth6OrAlioth8 at (323, 202)
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
	pAt_Alioth6OrAlioth8.SetContainedAI(pSequence_2)
	pAt_Alioth6OrAlioth8.AddCondition(pAlioth6)
	pAt_Alioth6OrAlioth8.AddCondition(pAlioth8)
	pAt_Alioth6OrAlioth8.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI At_Alioth6OrAlioth8
	#########################################
	#########################################
	# Creating PriorityListAI MainAI at (203, 116)
	pMainAI = App.PriorityListAI_Create(pShip, "MainAI")
	pMainAI.SetInterruptable(1)
	# SeqBlock is at (217, 146)
	pMainAI.AddAI(pCallDamageAI, 1)
	pMainAI.AddAI(pFollowPlayer, 2)
	pMainAI.AddAI(pAt_Starbase12, 3)
	pMainAI.AddAI(pAt_Alioth6OrAlioth8, 4)
	# Done creating PriorityListAI MainAI
	#########################################
	#########################################
	# Creating PreprocessingAI RedAlert at (202, 73)
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
	# Creating PreprocessingAI AvoidObstacles at (201, 25)
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
