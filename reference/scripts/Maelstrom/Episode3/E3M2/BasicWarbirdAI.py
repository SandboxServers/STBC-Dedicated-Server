import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI TerrikFleeDialog at (120, 194)
	pTerrikFleeDialog = App.PlainAI_Create(pShip, "TerrikFleeDialog")
	pTerrikFleeDialog.SetScriptModule("RunScript")
	pTerrikFleeDialog.SetInterruptable(1)
	pScript = pTerrikFleeDialog.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode3.E3M2.E3M2")
	pScript.SetFunction("TerrikFleeDialog")
	# Done creating PlainAI TerrikFleeDialog
	#########################################
	#########################################
	# Creating ConditionalAI If_Warbird_Damaged at (119, 145)
	## Conditions:
	#### Condition HullLow
	pHullLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_HULL_SUBSYSTEM, 0.75)
	#### Condition PowerSystemLow
	pPowerSystemLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_POWER_SUBSYSTEM, 0.75)
	#### Condition WarpDamaged
	pWarpDamaged = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_WARP_ENGINE_SUBSYSTEM, 0.75)
	## Evaluation function:
	def EvalFunc(bHullLow, bPowerSystemLow, bWarpDamaged):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bHullLow or bPowerSystemLow or bWarpDamaged:
			return ACTIVE
		else:
			return DORMANT
	## The ConditionalAI:
	pIf_Warbird_Damaged = App.ConditionalAI_Create(pShip, "If_Warbird_Damaged")
	pIf_Warbird_Damaged.SetInterruptable(1)
	pIf_Warbird_Damaged.SetContainedAI(pTerrikFleeDialog)
	pIf_Warbird_Damaged.AddCondition(pHullLow)
	pIf_Warbird_Damaged.AddCondition(pPowerSystemLow)
	pIf_Warbird_Damaged.AddCondition(pWarpDamaged)
	pIf_Warbird_Damaged.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI If_Warbird_Damaged
	#########################################
	#########################################
	# Creating CompoundAI NormalAttackPlayer at (230, 192)
	import Ai.Compound.BasicAttack
	pNormalAttackPlayer = Ai.Compound.BasicAttack.CreateAI(pShip, "player", Difficulty = 0.0, DumbFireTorps = 1, UseCloaking = 0)
	# Done creating CompoundAI NormalAttackPlayer
	#########################################
	#########################################
	# Creating ConditionalAI IfInNebula at (230, 141)
	## Conditions:
	#### Condition InNebula
	pInNebula = App.ConditionScript_Create("Conditions.ConditionInNebula", "ConditionInNebula", pShip.GetName())
	#### Condition PlayerInNebula
	pPlayerInNebula = App.ConditionScript_Create("Conditions.ConditionInNebula", "ConditionInNebula", "player")
	## Evaluation function:
	def EvalFunc(bInNebula, bPlayerInNebula):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bInNebula or bPlayerInNebula:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pIfInNebula = App.ConditionalAI_Create(pShip, "IfInNebula")
	pIfInNebula.SetInterruptable(1)
	pIfInNebula.SetContainedAI(pNormalAttackPlayer)
	pIfInNebula.AddCondition(pInNebula)
	pIfInNebula.AddCondition(pPlayerInNebula)
	pIfInNebula.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfInNebula
	#########################################
	#########################################
	# Creating CompoundAI CloakAttackPlayer at (344, 143)
	import Ai.Compound.BasicAttack
	pCloakAttackPlayer = Ai.Compound.BasicAttack.CreateAI(pShip, "player", Difficulty = 0.3, AggressivePulseWeapons = 1, UseCloaking = 1)
	# Done creating CompoundAI CloakAttackPlayer
	#########################################
	#########################################
	# Creating PriorityListAI WarbirdAI at (215, 59)
	pWarbirdAI = App.PriorityListAI_Create(pShip, "WarbirdAI")
	pWarbirdAI.SetInterruptable(1)
	# SeqBlock is at (236, 90)
	pWarbirdAI.AddAI(pIf_Warbird_Damaged, 1)
	pWarbirdAI.AddAI(pIfInNebula, 2)
	pWarbirdAI.AddAI(pCloakAttackPlayer, 3)
	# Done creating PriorityListAI WarbirdAI
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (218, 13)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pWarbirdAI)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
