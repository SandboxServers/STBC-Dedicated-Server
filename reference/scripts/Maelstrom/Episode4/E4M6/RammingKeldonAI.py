import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI RamPlayer at (63, 289)
	pRamPlayer = App.PlainAI_Create(pShip, "RamPlayer")
	pRamPlayer.SetScriptModule("Ram")
	pRamPlayer.SetInterruptable(1)
	pScript = pRamPlayer.GetScriptInstance()
	pScript.SetTargetObjectName("player")
	# Done creating PlainAI RamPlayer
	#########################################
	#########################################
	# Creating PreprocessingAI FireOnPlayer at (62, 240)
	## Setup:
	import AI.Preprocessors
	pFireScript = AI.Preprocessors.FireScript("player")
	for pSystem in [ pShip.GetTorpedoSystem(), pShip.GetPhaserSystem(), pShip.GetPulseWeaponSystem() ]:
		if pSystem:
			pFireScript.AddWeaponSystem( pSystem )
	## The PreprocessingAI:
	pFireOnPlayer = App.PreprocessingAI_Create(pShip, "FireOnPlayer")
	pFireOnPlayer.SetInterruptable(1)
	pFireOnPlayer.SetPreprocessingMethod(pFireScript, "Update")
	pFireOnPlayer.SetContainedAI(pRamPlayer)
	# Done creating PreprocessingAI FireOnPlayer
	#########################################
	#########################################
	# Creating ConditionalAI InPlayerSet at (62, 185)
	## Conditions:
	#### Condition SameSet
	pSameSet = App.ConditionScript_Create("Conditions.ConditionAllInSameSet", "ConditionAllInSameSet", pShip.GetName(), "player")
	## Evaluation function:
	def EvalFunc(bSameSet):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bSameSet:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pInPlayerSet = App.ConditionalAI_Create(pShip, "InPlayerSet")
	pInPlayerSet.SetInterruptable(1)
	pInPlayerSet.SetContainedAI(pFireOnPlayer)
	pInPlayerSet.AddCondition(pSameSet)
	pInPlayerSet.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI InPlayerSet
	#########################################
	#########################################
	# Creating ConditionalAI NearPlayer at (65, 132)
	## Conditions:
	#### Condition CloseToPlayer
	pCloseToPlayer = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 60, pShip.GetName(), "player")
	## Evaluation function:
	def EvalFunc(bCloseToPlayer):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bCloseToPlayer):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pNearPlayer = App.ConditionalAI_Create(pShip, "NearPlayer")
	pNearPlayer.SetInterruptable(1)
	pNearPlayer.SetContainedAI(pInPlayerSet)
	pNearPlayer.AddCondition(pCloseToPlayer)
	pNearPlayer.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI NearPlayer
	#########################################
	#########################################
	# Creating PlainAI RamPlayer_2 at (208, 316)
	pRamPlayer_2 = App.PlainAI_Create(pShip, "RamPlayer_2")
	pRamPlayer_2.SetScriptModule("Ram")
	pRamPlayer_2.SetInterruptable(1)
	pScript = pRamPlayer_2.GetScriptInstance()
	pScript.SetTargetObjectName("player")
	# Done creating PlainAI RamPlayer_2
	#########################################
	#########################################
	# Creating PreprocessingAI FireOnPlayer_2 at (207, 266)
	## Setup:
	import AI.Preprocessors
	pFireScript = AI.Preprocessors.FireScript("player")
	for pSystem in [ pShip.GetTorpedoSystem(), pShip.GetPhaserSystem(), pShip.GetPulseWeaponSystem() ]:
		if pSystem:
			pFireScript.AddWeaponSystem( pSystem )
	## The PreprocessingAI:
	pFireOnPlayer_2 = App.PreprocessingAI_Create(pShip, "FireOnPlayer_2")
	pFireOnPlayer_2.SetInterruptable(1)
	pFireOnPlayer_2.SetPreprocessingMethod(pFireScript, "Update")
	pFireOnPlayer_2.SetContainedAI(pRamPlayer_2)
	# Done creating PreprocessingAI FireOnPlayer_2
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (209, 201)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pFireOnPlayer_2)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	#########################################
	# Creating ConditionalAI InPlayerSet_2 at (212, 139)
	## Conditions:
	#### Condition SameSet
	pSameSet = App.ConditionScript_Create("Conditions.ConditionAllInSameSet", "ConditionAllInSameSet", pShip.GetName(), "player")
	## Evaluation function:
	def EvalFunc(bSameSet):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bSameSet:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pInPlayerSet_2 = App.ConditionalAI_Create(pShip, "InPlayerSet_2")
	pInPlayerSet_2.SetInterruptable(1)
	pInPlayerSet_2.SetContainedAI(pAvoidObstacles)
	pInPlayerSet_2.AddCondition(pSameSet)
	pInPlayerSet_2.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI InPlayerSet_2
	#########################################
	#########################################
	# Creating PlainAI Stay at (381, 137)
	pStay = App.PlainAI_Create(pShip, "Stay")
	pStay.SetScriptModule("Stay")
	pStay.SetInterruptable(1)
	# Done creating PlainAI Stay
	#########################################
	#########################################
	# Creating PriorityListAI RammingKeldon at (215, 15)
	pRammingKeldon = App.PriorityListAI_Create(pShip, "RammingKeldon")
	pRammingKeldon.SetInterruptable(1)
	# SeqBlock is at (241, 63)
	pRammingKeldon.AddAI(pNearPlayer, 1)
	pRammingKeldon.AddAI(pInPlayerSet_2, 2)
	pRammingKeldon.AddAI(pStay, 3)
	# Done creating PriorityListAI RammingKeldon
	#########################################
	return pRammingKeldon
