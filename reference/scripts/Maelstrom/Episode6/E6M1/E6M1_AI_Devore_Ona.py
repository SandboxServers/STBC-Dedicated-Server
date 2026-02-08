import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI BasicAttack4Galor6 at (52, 79)
	import AI.Compound.BasicAttack
	pBasicAttack4Galor6 = AI.Compound.BasicAttack.CreateAI(pShip, "Galor 6", Difficulty = 0.8, SmartTorpSelection = 0)
	# Done creating CompoundAI BasicAttack4Galor6
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack4Galor5 at (153, 82)
	import AI.Compound.BasicAttack
	pBasicAttack4Galor5 = AI.Compound.BasicAttack.CreateAI(pShip, "Galor 5", Difficulty = 0.8, SmartTorpSelection = 0)
	# Done creating CompoundAI BasicAttack4Galor5
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack4RemainingTargets at (243, 50)
	import AI.Compound.BasicAttack
	pBasicAttack4RemainingTargets = AI.Compound.BasicAttack.CreateAI(pShip, "Galor 7", "Keldon 2", Difficulty = 0.8, SmartTorpSelection = 0)
	# Done creating CompoundAI BasicAttack4RemainingTargets
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack4ArtrusTargets at (349, 75)
	import AI.Compound.BasicAttack
	pBasicAttack4ArtrusTargets = AI.Compound.BasicAttack.CreateAI(pShip, "Galor 3", "Galor 4", "Keldon 1", Difficulty = 0.8, SmartTorpSelection = 0)
	# Done creating CompoundAI BasicAttack4ArtrusTargets
	#########################################
	#########################################
	# Creating PriorityListAI FirstWaveTargets at (203, 248)
	pFirstWaveTargets = App.PriorityListAI_Create(pShip, "FirstWaveTargets")
	pFirstWaveTargets.SetInterruptable(1)
	# SeqBlock is at (221, 177)
	pFirstWaveTargets.AddAI(pBasicAttack4Galor6, 1)
	pFirstWaveTargets.AddAI(pBasicAttack4Galor5, 2)
	pFirstWaveTargets.AddAI(pBasicAttack4RemainingTargets, 3)
	pFirstWaveTargets.AddAI(pBasicAttack4ArtrusTargets, 4)
	# Done creating PriorityListAI FirstWaveTargets
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack3Galors at (406, 114)
	import AI.Compound.BasicAttack
	pBasicAttack3Galors = AI.Compound.BasicAttack.CreateAI(pShip, "Galor 8", "Galor 9", Difficulty = 0.8, SmartTorpSelection = 0)
	# Done creating CompoundAI BasicAttack3Galors
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack3Keldon at (511, 113)
	import AI.Compound.BasicAttack
	pBasicAttack3Keldon = AI.Compound.BasicAttack.CreateAI(pShip, "Keldon 3", Difficulty = 0.8, SmartTorpSelection = 0)
	# Done creating CompoundAI BasicAttack3Keldon
	#########################################
	#########################################
	# Creating PriorityListAI SecondWaveTargets at (333, 249)
	pSecondWaveTargets = App.PriorityListAI_Create(pShip, "SecondWaveTargets")
	pSecondWaveTargets.SetInterruptable(1)
	# SeqBlock is at (462, 204)
	pSecondWaveTargets.AddAI(pBasicAttack3Galors, 1)
	pSecondWaveTargets.AddAI(pBasicAttack3Keldon, 2)
	# Done creating PriorityListAI SecondWaveTargets
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (120, 324)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (264, 320)
	pPriorityList.AddAI(pFirstWaveTargets, 1)
	pPriorityList.AddAI(pSecondWaveTargets, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (17, 357)
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
