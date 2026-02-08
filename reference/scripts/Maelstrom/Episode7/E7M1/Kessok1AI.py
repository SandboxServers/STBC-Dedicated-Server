import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI AttackStarbase12 at (273, 47)
	import AI.Compound.BasicAttack
	pAttackStarbase12 = AI.Compound.BasicAttack.CreateAI(pShip, "Starbase 12", Difficulty = 1.0, SmartShields = 1, SmartTorpSelection = 1, UseCloaking = 1, WarpOutBeforeDying = 1)
	# Done creating CompoundAI AttackStarbase12
	#########################################
	#########################################
	# Creating CompoundAI Attack at (310, 6)
	import AI.Compound.BasicAttack
	pAttack = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode7.E7M1.E7M1", "pFriendlies"), Difficulty = 1.0, UseCloaking = 1, WarpOutBeforeDying = 1)
	# Done creating CompoundAI Attack
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (138, 6)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (265, 13)
	pPriorityList.AddAI(pAttackStarbase12, 1)
	pPriorityList.AddAI(pAttack, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (46, 26)
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
