import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI FlyToAsteroid at (117, 44)
	pFlyToAsteroid = App.PlainAI_Create(pShip, "FlyToAsteroid")
	pFlyToAsteroid.SetScriptModule("Intercept")
	pFlyToAsteroid.SetInterruptable(1)
	pScript = pFlyToAsteroid.GetScriptInstance()
	pScript.SetTargetObjectName("Asteroid 3")
	pScript.SetMaximumSpeed(fSpeed = 2.2)
	pScript.SetInterceptDistance(fDistance = 120.0)
	pScript.SetAddObjectRadius(bUseRadius = 1)
	# Done creating PlainAI FlyToAsteroid
	#########################################
	#########################################
	# Creating PreprocessingAI TowKaroon at (117, 93)
	## Setup:
	import AI.Preprocessors
	pTractorScript = AI.Preprocessors.FireScript("Karoon")
	pTractorScript.AddTractorBeam(pShip, App.TractorBeamSystem.TBS_TOW)
	## The PreprocessingAI:
	pTowKaroon = App.PreprocessingAI_Create(pShip, "TowKaroon")
	pTowKaroon.SetInterruptable(1)
	pTowKaroon.SetPreprocessingMethod(pTractorScript, "Update")
	pTowKaroon.SetContainedAI(pFlyToAsteroid)
	# Done creating PreprocessingAI TowKaroon
	#########################################
	#########################################
	# Creating ConditionalAI PlayerOrAsteroidGettingClose at (116, 140)
	## Conditions:
	#### Condition PlayerInRange
	pPlayerInRange = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 300, pShip.GetName(), "player")
	## Evaluation function:
	def EvalFunc(bPlayerInRange):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bPlayerInRange:
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pPlayerOrAsteroidGettingClose = App.ConditionalAI_Create(pShip, "PlayerOrAsteroidGettingClose")
	pPlayerOrAsteroidGettingClose.SetInterruptable(1)
	pPlayerOrAsteroidGettingClose.SetContainedAI(pTowKaroon)
	pPlayerOrAsteroidGettingClose.AddCondition(pPlayerInRange)
	pPlayerOrAsteroidGettingClose.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI PlayerOrAsteroidGettingClose
	#########################################
	#########################################
	# Creating PlainAI GetBehindPlayer at (237, 47)
	pGetBehindPlayer = App.PlainAI_Create(pShip, "GetBehindPlayer")
	pGetBehindPlayer.SetScriptModule("MoveToObjectSide")
	pGetBehindPlayer.SetInterruptable(1)
	pScript = pGetBehindPlayer.GetScriptInstance()
	pScript.SetObjectSide(App.TGPoint3_GetModelBackward())
	pScript.SetObjectName("player")
	pScript.SetMaxDistance(fDist = 150)
	# Done creating PlainAI GetBehindPlayer
	#########################################
	#########################################
	# Creating PreprocessingAI Cloak at (236, 101)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.CloakShip(1)
	## The PreprocessingAI:
	pCloak = App.PreprocessingAI_Create(pShip, "Cloak")
	pCloak.SetInterruptable(1)
	pCloak.SetPreprocessingMethod(pScript, "Update")
	pCloak.SetContainedAI(pGetBehindPlayer)
	# Done creating PreprocessingAI Cloak
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (239, 152)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pCloak)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	#########################################
	# Creating SequenceAI MainSequence at (10, 199)
	pMainSequence = App.SequenceAI_Create(pShip, "MainSequence")
	pMainSequence.SetInterruptable(1)
	pMainSequence.SetLoopCount(1)
	pMainSequence.SetResetIfInterrupted(1)
	pMainSequence.SetDoubleCheckAllDone(0)
	pMainSequence.SetSkipDormant(0)
	# SeqBlock is at (163, 200)
	pMainSequence.AddAI(pPlayerOrAsteroidGettingClose)
	pMainSequence.AddAI(pAvoidObstacles)
	# Done creating SequenceAI MainSequence
	#########################################
	return pMainSequence
