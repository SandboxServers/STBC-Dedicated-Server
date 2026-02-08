import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI AttackFriendlies at (46, 74)
	import AI.Compound.BasicAttack
	pAttackFriendlies = AI.Compound.BasicAttack.CreateAI(pShip,  App.ObjectGroup_FromModule("Maelstrom.Episode4.E4M4.E4M4", "g_pFriendlyTargetGroup"), Difficulty = 0.1, InaccurateTorps = 1)
	# Done creating CompoundAI AttackFriendlies
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (42, 24)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pAttackFriendlies)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
