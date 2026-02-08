import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI AttackEnemies at (297, 87)
	import AI.Compound.BasicAttack
	pAttackEnemies = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode8.E8M2.E8M2", "pEnemies"), Difficulty = 1.0)
	# Done creating CompoundAI AttackEnemies
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (209, 107)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pAttackEnemies)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
