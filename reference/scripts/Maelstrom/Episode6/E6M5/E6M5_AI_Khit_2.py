import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI BasicAttack3FedCardTargets at (346, 204)
	import AI.Compound.BasicAttack
	pBasicAttack3FedCardTargets = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode6.E6M5.E6M5", "g_pFedCardTargets"), MaxFiringDistance = 290.0)
	# Done creating CompoundAI BasicAttack3FedCardTargets
	#########################################
	#########################################
	# Creating CompoundAI BasicAttack3FedKessokTargets at (369, 260)
	import AI.Compound.BasicAttack
	pBasicAttack3FedKessokTargets = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode6.E6M5.E6M5", "g_pFedKessokTargets"), MaxFiringDistance = 290.0)
	# Done creating CompoundAI BasicAttack3FedKessokTargets
	#########################################
	#########################################
	# Creating PlainAI Orbit at (383, 323)
	pOrbit = App.PlainAI_Create(pShip, "Orbit")
	pOrbit.SetScriptModule("CircleObject")
	pOrbit.SetInterruptable(1)
	pScript = pOrbit.GetScriptInstance()
	pScript.SetFollowObjectName("Tezle 1")
	pScript.SetNearFacingVector(App.TGPoint3_GetModelRight())
	pScript.SetCircleSpeed(0.75)
	# Done creating PlainAI Orbit
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (221, 447)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (326, 451)
	pPriorityList.AddAI(pBasicAttack3FedCardTargets, 1)
	pPriorityList.AddAI(pBasicAttack3FedKessokTargets, 2)
	pPriorityList.AddAI(pOrbit, 3)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (164, 516)
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
