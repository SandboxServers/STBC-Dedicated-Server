import App
def CreateAI(pShip, sShipName):
	#########################################
	# Creating PlainAI FlyToTransport at (30, 192)
	pFlyToTransport = App.PlainAI_Create(pShip, "FlyToTransport")
	pFlyToTransport.SetScriptModule("Intercept")
	pFlyToTransport.SetInterruptable(1)
	pScript = pFlyToTransport.GetScriptInstance()
	pScript.SetTargetObjectName(sShipName)
	pScript.SetMaximumSpeed(10)
	pScript.SetInterceptDistance(40)
	# Done creating PlainAI FlyToTransport
	#########################################
	#########################################
	# Creating ConditionalAI FarFromTransport at (34, 239)
	## Conditions:
	#### Condition 50kFromTransport
	p50kFromTransport = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 350, pShip.GetName(), sShipName)
	## Evaluation function:
	def EvalFunc(b50kFromTransport):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (b50kFromTransport):
			return DORMANT
		return ACTIVE
	## The ConditionalAI:
	pFarFromTransport = App.ConditionalAI_Create(pShip, "FarFromTransport")
	pFarFromTransport.SetInterruptable(1)
	pFarFromTransport.SetContainedAI(pFlyToTransport)
	pFarFromTransport.AddCondition(p50kFromTransport)
	pFarFromTransport.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI FarFromTransport
	#########################################
	#########################################
	# Creating CompoundAI BasicAttackPlayer at (34, 75)
	import AI.Compound.BasicAttack
	pBasicAttackPlayer = AI.Compound.BasicAttack.CreateAI(pShip, "player", Easy_Difficulty = 0.22, Difficulty = 0.52, Hard_Difficulty = 0.8)
	# Done creating CompoundAI BasicAttackPlayer
	#########################################
	#########################################
	# Creating ConditionalAI AttackedByPlayer at (32, 140)
	## Conditions:
	#### Condition PlayerAttacksTrans
	pPlayerAttacksTrans = App.ConditionScript_Create("Conditions.ConditionAttackedBy", "ConditionAttackedBy", sShipName, "player", 0.10, 0.01, 60)
	## Evaluation function:
	def EvalFunc(bPlayerAttacksTrans):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bPlayerAttacksTrans):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pAttackedByPlayer = App.ConditionalAI_Create(pShip, "AttackedByPlayer")
	pAttackedByPlayer.SetInterruptable(1)
	pAttackedByPlayer.SetContainedAI(pBasicAttackPlayer)
	pAttackedByPlayer.AddCondition(pPlayerAttacksTrans)
	pAttackedByPlayer.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI AttackedByPlayer
	#########################################
	#########################################
	# Creating CompoundAI BasicAttackVenture at (219, 75)
	import AI.Compound.BasicAttack
	pBasicAttackVenture = AI.Compound.BasicAttack.CreateAI(pShip, "Venture", SmartShields = 1)
	# Done creating CompoundAI BasicAttackVenture
	#########################################
	#########################################
	# Creating ConditionalAI AttackedByVenture at (215, 142)
	## Conditions:
	#### Condition VentureAttacksTrans
	pVentureAttacksTrans = App.ConditionScript_Create("Conditions.ConditionAttackedBy", "ConditionAttackedBy", sShipName, "Venture", 0.10, 0.01, 60)
	## Evaluation function:
	def EvalFunc(bVentureAttacksTrans):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bVentureAttacksTrans):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pAttackedByVenture = App.ConditionalAI_Create(pShip, "AttackedByVenture")
	pAttackedByVenture.SetInterruptable(1)
	pAttackedByVenture.SetContainedAI(pBasicAttackVenture)
	pAttackedByVenture.AddCondition(pVentureAttacksTrans)
	pAttackedByVenture.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI AttackedByVenture
	#########################################
	#########################################
	# Creating CompoundAI BasicAttackSF at (314, 74)
	import AI.Compound.BasicAttack
	pBasicAttackSF = AI.Compound.BasicAttack.CreateAI(pShip, "San Francisco", SmartShields = 1)
	# Done creating CompoundAI BasicAttackSF
	#########################################
	#########################################
	# Creating ConditionalAI AttackedBySF at (311, 138)
	## Conditions:
	#### Condition SFAttacksTrans
	pSFAttacksTrans = App.ConditionScript_Create("Conditions.ConditionAttackedBy", "ConditionAttackedBy", sShipName, "San Francisco", 0.10, 0.01, 60)
	## Evaluation function:
	def EvalFunc(bSFAttacksTrans):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bSFAttacksTrans):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pAttackedBySF = App.ConditionalAI_Create(pShip, "AttackedBySF")
	pAttackedBySF.SetInterruptable(1)
	pAttackedBySF.SetContainedAI(pBasicAttackSF)
	pAttackedBySF.AddCondition(pSFAttacksTrans)
	pAttackedBySF.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI AttackedBySF
	#########################################
	#########################################
	# Creating CompoundAI BasicAttackDevore at (409, 74)
	import AI.Compound.BasicAttack
	pBasicAttackDevore = AI.Compound.BasicAttack.CreateAI(pShip, "Devore", SmartShields = 1)
	# Done creating CompoundAI BasicAttackDevore
	#########################################
	#########################################
	# Creating ConditionalAI AttackedByDevore at (401, 140)
	## Conditions:
	#### Condition DevoreAttacksTrans
	pDevoreAttacksTrans = App.ConditionScript_Create("Conditions.ConditionAttackedBy", "ConditionAttackedBy", sShipName, "Devore", 0.10, 0.01, 60)
	## Evaluation function:
	def EvalFunc(bDevoreAttacksTrans):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bDevoreAttacksTrans):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pAttackedByDevore = App.ConditionalAI_Create(pShip, "AttackedByDevore")
	pAttackedByDevore.SetInterruptable(1)
	pAttackedByDevore.SetContainedAI(pBasicAttackDevore)
	pAttackedByDevore.AddCondition(pDevoreAttacksTrans)
	pAttackedByDevore.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI AttackedByDevore
	#########################################
	#########################################
	# Creating CompoundAI BasicAttackPlayer_2 at (520, 124)
	import AI.Compound.BasicAttack
	pBasicAttackPlayer_2 = AI.Compound.BasicAttack.CreateAI(pShip, "player", Easy_Difficulty = 0.21, Difficulty = 0.49, Hard_Difficulty = 0.71)
	# Done creating CompoundAI BasicAttackPlayer_2
	#########################################
	#########################################
	# Creating ConditionalAI TargetsInRange at (483, 189)
	## Conditions:
	#### Condition FedsInRange
	pFedsInRange = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 240, pShip.GetName(), App.ObjectGroup_FromModule("Maelstrom.Episode6.E6M3.E6M3", "g_pSavoy3GalorTargets"))
	## Evaluation function:
	def EvalFunc(bFedsInRange):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bFedsInRange):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pTargetsInRange = App.ConditionalAI_Create(pShip, "TargetsInRange")
	pTargetsInRange.SetInterruptable(1)
	pTargetsInRange.SetContainedAI(pBasicAttackPlayer_2)
	pTargetsInRange.AddCondition(pFedsInRange)
	pTargetsInRange.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TargetsInRange
	#########################################
	#########################################
	# Creating PriorityListAI TransportAttackedPriorityList at (200, 242)
	pTransportAttackedPriorityList = App.PriorityListAI_Create(pShip, "TransportAttackedPriorityList")
	pTransportAttackedPriorityList.SetInterruptable(1)
	# SeqBlock is at (209, 196)
	pTransportAttackedPriorityList.AddAI(pAttackedByPlayer, 1)
	pTransportAttackedPriorityList.AddAI(pAttackedByVenture, 2)
	pTransportAttackedPriorityList.AddAI(pAttackedBySF, 3)
	pTransportAttackedPriorityList.AddAI(pAttackedByDevore, 4)
	pTransportAttackedPriorityList.AddAI(pTargetsInRange, 5)
	# Done creating PriorityListAI TransportAttackedPriorityList
	#########################################
	#########################################
	# Creating PlainAI FollowTransport at (342, 299)
	pFollowTransport = App.PlainAI_Create(pShip, "FollowTransport")
	pFollowTransport.SetScriptModule("FollowObject")
	pFollowTransport.SetInterruptable(1)
	pScript = pFollowTransport.GetScriptInstance()
	pScript.SetFollowObjectName(sShipName)
	pScript.SetRoughDistances(50, 65, 80)
	# Done creating PlainAI FollowTransport
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (20, 295)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (184, 305)
	pPriorityList.AddAI(pFarFromTransport, 1)
	pPriorityList.AddAI(pTransportAttackedPriorityList, 2)
	pPriorityList.AddAI(pFollowTransport, 3)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (18, 354)
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
	#########################################
	# Creating CompoundAI BasicAttackKhit at (127, 74)
	import AI.Compound.BasicAttack
	pBasicAttackKhit = AI.Compound.BasicAttack.CreateAI(pShip, "Khitomer", SmartShields = 1)
	# Done creating CompoundAI BasicAttackKhit
	#########################################
	#########################################
	# Creating ConditionalAI AttackedByKhit at (125, 140)
	## Conditions:
	#### Condition KhitAttacksTrans
	pKhitAttacksTrans = App.ConditionScript_Create("Conditions.ConditionAttackedBy", "ConditionAttackedBy", sShipName, "Khitomer", 0.10, 0.01, 60)
	## Evaluation function:
	def EvalFunc(bKhitAttacksTrans):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bKhitAttacksTrans):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pAttackedByKhit = App.ConditionalAI_Create(pShip, "AttackedByKhit")
	pAttackedByKhit.SetInterruptable(1)
	pAttackedByKhit.SetContainedAI(pBasicAttackKhit)
	pAttackedByKhit.AddCondition(pKhitAttacksTrans)
	pAttackedByKhit.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI AttackedByKhit
	#########################################
	return pAttackedByKhit
