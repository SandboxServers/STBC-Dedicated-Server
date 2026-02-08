import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI CallDamageAI at (227, 106)
	import AI.Compound.CallDamageAI
	pCallDamageAI = AI.Compound.CallDamageAI.CreateAI(pShip)
	# Done creating CompoundAI CallDamageAI
	#########################################
	#########################################
	# Creating CompoundAI Basic_Attack at (241, 54)
	import AI.Compound.BasicAttack
	pBasic_Attack = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode7.E7M2.E7M2", "pEnemies"), Difficulty = 0.7, AvoidTorps = 0, UseCloaking = 1)
	# Done creating CompoundAI Basic_Attack
	#########################################
	#########################################
	# Creating PriorityListAI Warbird_Main at (112, 22)
	pWarbird_Main = App.PriorityListAI_Create(pShip, "Warbird_Main")
	pWarbird_Main.SetInterruptable(1)
	# SeqBlock is at (219, 29)
	pWarbird_Main.AddAI(pCallDamageAI, 1)
	pWarbird_Main.AddAI(pBasic_Attack, 2)
	# Done creating PriorityListAI Warbird_Main
	#########################################

	#########################################
	# Creating PreprocessingAI AvoidObstacles at (25, 42)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pWarbird_Main)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
