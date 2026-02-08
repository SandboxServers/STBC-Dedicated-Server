import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI StationaryAttack at (494, 32)
	pStationaryAttack = App.PlainAI_Create(pShip, "StationaryAttack")
	pStationaryAttack.SetScriptModule("StationaryAttack")
	pStationaryAttack.SetInterruptable(1)
	pScript = pStationaryAttack.GetScriptInstance()
	pScript.SetTargetObjectName("JonKa")
	# Done creating PlainAI StationaryAttack
	#########################################
	#########################################
	# Creating PreprocessingAI Fire at (405, 52)
	## Setup:
	import AI.Preprocessors
	pFireScript = AI.Preprocessors.FireScript("JonKa")
	for pSystem in [ pShip.GetTorpedoSystem(), pShip.GetPhaserSystem(), pShip.GetPulseWeaponSystem() ]:
		if pSystem:
			pFireScript.AddWeaponSystem( pSystem )
	## The PreprocessingAI:
	pFire = App.PreprocessingAI_Create(pShip, "Fire")
	pFire.SetInterruptable(1)
	pFire.SetPreprocessingMethod(pFireScript, "Update")
	pFire.SetContainedAI(pStationaryAttack)
	# Done creating PreprocessingAI Fire
	#########################################
	#########################################
	# Creating ConditionalAI Wait_To_Attack at (280, 72)
	## Conditions:
	#### Condition Timer
	pTimer = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 4, 1)
	## Evaluation function:
	def EvalFunc(bTimer):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bTimer:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pWait_To_Attack = App.ConditionalAI_Create(pShip, "Wait_To_Attack")
	pWait_To_Attack.SetInterruptable(1)
	pWait_To_Attack.SetContainedAI(pFire)
	pWait_To_Attack.AddCondition(pTimer)
	pWait_To_Attack.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Wait_To_Attack
	#########################################
	#########################################
	# Creating PlainAI Stay at (320, 20)
	pStay = App.PlainAI_Create(pShip, "Stay")
	pStay.SetScriptModule("Stay")
	pStay.SetInterruptable(1)
	# Done creating PlainAI Stay
	#########################################
	#########################################
	# Creating PriorityListAI Warbird_Main at (112, 22)
	pWarbird_Main = App.PriorityListAI_Create(pShip, "Warbird_Main")
	pWarbird_Main.SetInterruptable(1)
	# SeqBlock is at (270, 29)
	pWarbird_Main.AddAI(pWait_To_Attack, 1)
	pWarbird_Main.AddAI(pStay, 2)
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
