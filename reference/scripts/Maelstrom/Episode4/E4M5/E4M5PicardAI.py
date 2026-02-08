import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI CallDamage at (232, 156)
	import AI.Compound.CallDamageAI
	pCallDamage = AI.Compound.CallDamageAI.CreateAI(pShip)
	# Done creating CompoundAI CallDamage
	#########################################
	#########################################
	# Creating CompoundAI FollowPlayer at (330, 155)
	import AI.Compound.FollowThroughWarp
	pFollowPlayer = AI.Compound.FollowThroughWarp.CreateAI(pShip, "player")
	# Done creating CompoundAI FollowPlayer
	#########################################
	#########################################
	# Creating CompoundAI AttackEverything at (335, 242)
	import AI.Compound.BasicAttack
	pAttackEverything = AI.Compound.BasicAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode4.E4M5.E4M5", "g_pEnemies"), Difficulty = 0.7, DisableBeforeDestroy = 1, SmartShields = 1)
	# Done creating CompoundAI AttackEverything
	#########################################
	#########################################
	# Creating CompoundAI AttackShipyard at (423, 240)
	import AI.Compound.BasicAttack
	pAttackShipyard = AI.Compound.BasicAttack.CreateAI(pShip, "Cardassian Shipyard", Difficulty = 1.0)
	# Done creating CompoundAI AttackShipyard
	#########################################
	#########################################
	# Creating PlainAI FollowPlayerAround at (514, 285)
	pFollowPlayerAround = App.PlainAI_Create(pShip, "FollowPlayerAround")
	pFollowPlayerAround.SetScriptModule("FollowObject")
	pFollowPlayerAround.SetInterruptable(1)
	pScript = pFollowPlayerAround.GetScriptInstance()
	pScript.SetFollowObjectName("player")
	pScript.SetRoughDistances(50, 80, 100)
	# Done creating PlainAI FollowPlayerAround
	#########################################
	#########################################
	# Creating ConditionalAI SameSet at (513, 240)
	## Conditions:
	#### Condition Same
	pSame = App.ConditionScript_Create("Conditions.ConditionAllInSameSet", "ConditionAllInSameSet", "USS Enterprise", "player")
	## Evaluation function:
	def EvalFunc(bSame):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bSame:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pSameSet = App.ConditionalAI_Create(pShip, "SameSet")
	pSameSet.SetInterruptable(1)
	pSameSet.SetContainedAI(pFollowPlayerAround)
	pSameSet.AddCondition(pSame)
	pSameSet.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI SameSet
	#########################################
	#########################################
	# Creating PlainAI Stay at (612, 240)
	pStay = App.PlainAI_Create(pShip, "Stay")
	pStay.SetScriptModule("Stay")
	pStay.SetInterruptable(1)
	# Done creating PlainAI Stay
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (477, 158)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (486, 191)
	pPriorityList.AddAI(pAttackEverything, 1)
	pPriorityList.AddAI(pAttackShipyard, 2)
	pPriorityList.AddAI(pSameSet, 3)
	pPriorityList.AddAI(pStay, 4)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PriorityListAI PicardAI at (360, 75)
	pPicardAI = App.PriorityListAI_Create(pShip, "PicardAI")
	pPicardAI.SetInterruptable(1)
	# SeqBlock is at (373, 106)
	pPicardAI.AddAI(pCallDamage, 1)
	pPicardAI.AddAI(pFollowPlayer, 2)
	pPicardAI.AddAI(pPriorityList, 3)
	# Done creating PriorityListAI PicardAI
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (360, 32)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pPicardAI)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
