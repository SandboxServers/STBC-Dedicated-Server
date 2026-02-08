import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI AttackWarbird2 at (190, 173)
	import AI.Compound.BasicAttack
	pAttackWarbird2 = AI.Compound.BasicAttack.CreateAI(pShip, "T'Awsun", Difficulty = 0.4, AggressivePulseWeapons = 1)
	# Done creating CompoundAI AttackWarbird2
	#########################################
	#########################################
	# Creating CompoundAI Attack at (312, 171)
	import AI.Compound.BasicAttack
	pAttack = AI.Compound.BasicAttack.CreateAI(pShip, "player", "Chairo", Difficulty = 0.3, AvoidTorps = 1, SmartShields = 0)
	# Done creating CompoundAI Attack
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (222, 102)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (248, 142)
	pPriorityList.AddAI(pAttackWarbird2, 1)
	pPriorityList.AddAI(pAttack, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (223, 62)
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
