import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI BasicAttack4Galor1 at (202, 92)
	import AI.Compound.BasicAttack
	pBasicAttack4Galor1 = AI.Compound.BasicAttack.CreateAI(pShip, "Galor 1", Difficulty = 0.8)
	# Done creating CompoundAI BasicAttack4Galor1
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack4Galor2 at (293, 95)
	import AI.Compound.BasicAttack
	pBasicAttack4Galor2 = AI.Compound.BasicAttack.CreateAI(pShip, "Galor 2", Difficulty = 0.8)
	# Done creating CompoundAI BasicAttack4Galor2
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack4SecondWave at (314, 152)
	import AI.Compound.BasicAttack
	pBasicAttack4SecondWave = AI.Compound.BasicAttack.CreateAI(pShip, "Galor 3", "Galor 4", "Keldon 1", Difficulty = 1.0)
	# Done creating CompoundAI BasicAttack4SecondWave
	#########################################
	#########################################
	# Creating PriorityListAI ArtrusPriority at (137, 245)
	pArtrusPriority = App.PriorityListAI_Create(pShip, "ArtrusPriority")
	pArtrusPriority.SetInterruptable(1)
	# SeqBlock is at (243, 213)
	pArtrusPriority.AddAI(pBasicAttack4Galor1, 1)
	pArtrusPriority.AddAI(pBasicAttack4Galor2, 2)
	pArtrusPriority.AddAI(pBasicAttack4SecondWave, 3)
	# Done creating PriorityListAI ArtrusPriority
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (39, 292)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pArtrusPriority)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
