import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI CallDamageAI at (234, 109)
	import AI.Compound.CallDamageAI
	pCallDamageAI = AI.Compound.CallDamageAI.CreateAI(pShip)
	# Done creating CompoundAI CallDamageAI
	#########################################
	#########################################
	# Creating CompoundAI Basic_Attack at (250, 56)
	import AI.Compound.BasicAttack
	pBasic_Attack = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode7.E7M2.E7M2", "pEnemies"), Difficulty = 0.7, AvoidTorps = 0, UseCloaking = 1)
	# Done creating CompoundAI Basic_Attack
	#########################################
	#########################################
	# Creating PriorityListAI Vorcha_Main at (112, 22)
	pVorcha_Main = App.PriorityListAI_Create(pShip, "Vorcha_Main")
	pVorcha_Main.SetInterruptable(1)
	# SeqBlock is at (226, 29)
	pVorcha_Main.AddAI(pCallDamageAI, 1)
	pVorcha_Main.AddAI(pBasic_Attack, 2)
	# Done creating PriorityListAI Vorcha_Main
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
	pAvoidObstacles.SetContainedAI(pVorcha_Main)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
