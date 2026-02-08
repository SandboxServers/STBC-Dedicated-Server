import App
def CreateAI(pShip, lAllies):

	#########################################
	# Creating CompoundAI CallDamageAI at (248, 123)
	import AI.Compound.CallDamageAI
	pCallDamageAI = AI.Compound.CallDamageAI.CreateAI(pShip)
	# Done creating CompoundAI CallDamageAI
	#########################################
	#########################################
	# Creating CompoundAI ChainFollowThroughWarp at (265, 86)
	import AI.Compound.ChainFollowThroughWarp
	pChainFollowThroughWarp = AI.Compound.ChainFollowThroughWarp.CreateAI(pShip, lAllies)
	# Done creating CompoundAI ChainFollowThroughWarp
	#########################################
	#########################################
	# Creating CompoundAI AttackKessoks at (279, 52)
	import AI.Compound.BasicAttack
	pAttackKessoks = AI.Compound.BasicAttack.CreateAI(pShip, "Kessok1", "Kessok2", Difficulty = 0.75, SmartTorpSelection = 1)
	# Done creating CompoundAI AttackKessoks
	#########################################
	#########################################
	# Creating CompoundAI ChainFollow at (398, 12)
	import AI.Compound.ChainFollow
	pChainFollow = AI.Compound.ChainFollow.CreateAI(pShip, lAllies)
	# Done creating CompoundAI ChainFollow
	#########################################
	#########################################
	# Creating ConditionalAI PlayerNotInSB12 at (313, 12)
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
	# Creating PriorityListAI MainAI at (129, 12)
	pMainAI = App.PriorityListAI_Create(pShip, "MainAI")
	pMainAI.SetInterruptable(1)
	# SeqBlock is at (239, 19)
	pMainAI.AddAI(pCallDamageAI, 1)
	pMainAI.AddAI(pChainFollowThroughWarp, 2)
	pMainAI.AddAI(pAttackKessoks, 3)
	pMainAI.AddAI(pPlayerNotInSB12, 4)
	# Done creating PriorityListAI MainAI
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (42, 32)
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
