import App
def CreateAI(pShip, kAllyList):

	#########################################
	# Creating CompoundAI CallDamageAI at (163, 259)
	import AI.Compound.CallDamageAI
	pCallDamageAI = AI.Compound.CallDamageAI.CreateAI(pShip)
	# Done creating CompoundAI CallDamageAI
	#########################################
	#########################################
	# Creating CompoundAI ChainFollowThroughWarp at (179, 211)
	import AI.Compound.ChainFollowThroughWarp
	pChainFollowThroughWarp = AI.Compound.ChainFollowThroughWarp.CreateAI(pShip, kAllyList)
	# Done creating CompoundAI ChainFollowThroughWarp
	#########################################
	#########################################
	# Creating CompoundAI AttackKeldons at (357, 223)
	import AI.Compound.BasicAttack
	pAttackKeldons = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode8.E8M2.E8M2", "pKeldonGroup"), Difficulty = 1.0, SmartTorpSelection = 1)
	# Done creating CompoundAI AttackKeldons
	#########################################
	#########################################
	# Creating CompoundAI AttackAll at (376, 178)
	import AI.Compound.BasicAttack
	pAttackAll = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode8.E8M2.E8M2", "pEnemies"), Difficulty = 1.0, UseCloaking = 1)
	# Done creating CompoundAI AttackAll
	#########################################
	#########################################
	# Creating CompoundAI ChainFollow at (470, 79)
	import AI.Compound.ChainFollow
	pChainFollow = AI.Compound.ChainFollow.CreateAI(pShip, kAllyList)
	# Done creating CompoundAI ChainFollow
	#########################################
	#########################################
	# Creating ConditionalAI PlayerNotInSB12 at (429, 124)
	## Conditions:
	#### Condition PlayerInSB12Set
	pPlayerInSB12Set = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "player", "Starbase12")
	## Evaluation function:
	def EvalFunc(bPlayerInSB12Set):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bPlayerInSB12Set:
			return DORMANT
		return ACTIVE
	## The ConditionalAI:
	pPlayerNotInSB12 = App.ConditionalAI_Create(pShip, "PlayerNotInSB12")
	pPlayerNotInSB12.SetInterruptable(1)
	pPlayerNotInSB12.SetContainedAI(pChainFollow)
	pPlayerNotInSB12.AddCondition(pPlayerInSB12Set)
	pPlayerNotInSB12.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI PlayerNotInSB12
	#########################################
	#########################################
	# Creating PriorityListAI MeatyFlyingStuff at (265, 122)
	pMeatyFlyingStuff = App.PriorityListAI_Create(pShip, "MeatyFlyingStuff")
	pMeatyFlyingStuff.SetInterruptable(1)
	# SeqBlock is at (351, 128)
	pMeatyFlyingStuff.AddAI(pAttackKeldons, 1)
	pMeatyFlyingStuff.AddAI(pAttackAll, 2)
	pMeatyFlyingStuff.AddAI(pPlayerNotInSB12, 3)
	# Done creating PriorityListAI MeatyFlyingStuff
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (195, 172)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pMeatyFlyingStuff)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	#########################################
	# Creating PriorityListAI MainAI at (50, 40)
	pMainAI = App.PriorityListAI_Create(pShip, "MainAI")
	pMainAI.SetInterruptable(1)
	# SeqBlock is at (154, 46)
	pMainAI.AddAI(pCallDamageAI, 1)
	pMainAI.AddAI(pChainFollowThroughWarp, 2)
	pMainAI.AddAI(pAvoidObstacles, 3)
	# Done creating PriorityListAI MainAI
	#########################################
	return pMainAI
