import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI FollowPlayer at (234, 182)
	import AI.Compound.FollowThroughWarp
	pFollowPlayer = AI.Compound.FollowThroughWarp.CreateAI(pShip, "player", FollowToSB12 = 1)
	# Done creating CompoundAI FollowPlayer
	#########################################
	#########################################
	# Creating CompoundAI CallDamageAI at (250, 148)
	import AI.Compound.CallDamageAI
	pCallDamageAI = AI.Compound.CallDamageAI.CreateAI(pShip)
	# Done creating CompoundAI CallDamageAI
	#########################################
	#########################################
	# Creating CompoundAI AttackEnemies at (266, 115)
	import AI.Compound.BasicAttack
	pAttackEnemies = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode7.E7M3.E7M3", "pEnemyTargets"), Difficulty = 0.7, SmartTorpSelection = 1)
	# Done creating CompoundAI AttackEnemies
	#########################################
	#########################################
	# Creating CompoundAI AttackStations at (282, 81)
	import AI.Compound.BasicAttack
	pAttackStations = AI.Compound.BasicAttack.CreateAI(pShip, "Sensor Post 1", "Sensor Post 2", "Sensor Post 3", "Sensor Post 4", "Resupply Station", Difficulty = 0.7, SmartTorpSelection = 1)
	# Done creating CompoundAI AttackStations
	#########################################
	#########################################
	# Creating PlainAI FollowPlayer_2 at (298, 47)
	pFollowPlayer_2 = App.PlainAI_Create(pShip, "FollowPlayer_2")
	pFollowPlayer_2.SetScriptModule("FollowObject")
	pFollowPlayer_2.SetInterruptable(1)
	pScript = pFollowPlayer_2.GetScriptInstance()
	pScript.SetFollowObjectName("player")
	# Done creating PlainAI FollowPlayer_2
	#########################################
	#########################################
	# Creating PriorityListAI MainAI at (129, 12)
	pMainAI = App.PriorityListAI_Create(pShip, "MainAI")
	pMainAI.SetInterruptable(1)
	# SeqBlock is at (225, 19)
	pMainAI.AddAI(pFollowPlayer, 1)
	pMainAI.AddAI(pCallDamageAI, 2)
	pMainAI.AddAI(pAttackEnemies, 3)
	pMainAI.AddAI(pAttackStations, 4)
	pMainAI.AddAI(pFollowPlayer_2, 5)
	# Done creating PriorityListAI MainAI
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (40, 32)
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
