import App
def CreateAI(pShip):


	#########################################
	# Creating PlainAI Follow at (26, 120)
	pFollow = App.PlainAI_Create(pShip, "Follow")
	pFollow.SetScriptModule("FollowWaypoints")
	pFollow.SetInterruptable(1)
	pScript = pFollow.GetScriptInstance()
	pScript.SetTargetWaypointName("Kahless Ro Start Fly")
	# Done creating PlainAI Follow
	#########################################
	#########################################
	# Creating CompoundAI Attack_Galor_1 at (113, 120)
	import AI.Compound.BasicAttack
	pAttack_Galor_1 = AI.Compound.BasicAttack.CreateAI(pShip, "Galor1")
	# Done creating CompoundAI Attack_Galor_1
	#########################################
	#########################################
	# Creating SequenceAI Follow_then_attack_and_die at (28, 55)
	pFollow_then_attack_and_die = App.SequenceAI_Create(pShip, "Follow_then_attack_and_die")
	pFollow_then_attack_and_die.SetInterruptable(1)
	pFollow_then_attack_and_die.SetLoopCount(1)
	pFollow_then_attack_and_die.SetResetIfInterrupted(1)
	pFollow_then_attack_and_die.SetDoubleCheckAllDone(0)
	pFollow_then_attack_and_die.SetSkipDormant(0)
	# SeqBlock is at (50, 95)
	pFollow_then_attack_and_die.AddAI(pFollow)
	pFollow_then_attack_and_die.AddAI(pAttack_Galor_1)
	# Done creating SequenceAI Follow_then_attack_and_die
	#########################################

	#########################################
	# Creating PreprocessingAI AvoidObstacles at (29, 9)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pFollow_then_attack_and_die)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
