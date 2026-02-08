import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI YouWin at (310, 21)
	pYouWin = App.PlainAI_Create(pShip, "YouWin")
	pYouWin.SetScriptModule("RunScript")
	pYouWin.SetInterruptable(1)
	pScript = pYouWin.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode3.E3M1.E3M1")
	pScript.SetFunction("BOPYouWin")
	# Done creating PlainAI YouWin
	#########################################
	#########################################
	# Creating ConditionalAI IfRankufDamaged50 at (225, 23)
	## Conditions:
	#### Condition HullLow
	pHullLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName (),App.CT_HULL_SUBSYSTEM,.5)
	#### Condition PowerSystemLow
	pPowerSystemLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName (), App.CT_POWER_SUBSYSTEM, .5)
	#### Condition WarpDamaged
	pWarpDamaged = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName (), App.CT_WARP_ENGINE_SUBSYSTEM, .5)
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
	pIfRankufDamaged50 = App.ConditionalAI_Create(pShip, "IfRankufDamaged50")
	pIfRankufDamaged50.SetInterruptable(1)
	pIfRankufDamaged50.SetContainedAI(pYouWin)
	pIfRankufDamaged50.AddCondition(pHullLow)
	pIfRankufDamaged50.AddCondition(pPowerSystemLow)
	pIfRankufDamaged50.AddCondition(pWarpDamaged)
	pIfRankufDamaged50.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfRankufDamaged50
	#########################################
	#########################################
	# Creating PlainAI YouLose at (309, 54)
	pYouLose = App.PlainAI_Create(pShip, "YouLose")
	pYouLose.SetScriptModule("RunScript")
	pYouLose.SetInterruptable(1)
	pScript = pYouLose.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode3.E3M1.E3M1")
	pScript.SetFunction("BOPYouLose")
	# Done creating PlainAI YouLose
	#########################################
	#########################################
	# Creating ConditionalAI IfPlayerDamaged25 at (225, 56)
	## Conditions:
	#### Condition HullLow
	pHullLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", "player", App.CT_HULL_SUBSYSTEM,.25)
	#### Condition PowerSystemLow
	pPowerSystemLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", "player", App.CT_POWER_SUBSYSTEM, .25)
	#### Condition WarpDamaged
	pWarpDamaged = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", "player", App.CT_WARP_ENGINE_SUBSYSTEM, .25)
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
	pIfPlayerDamaged25 = App.ConditionalAI_Create(pShip, "IfPlayerDamaged25")
	pIfPlayerDamaged25.SetInterruptable(1)
	pIfPlayerDamaged25.SetContainedAI(pYouLose)
	pIfPlayerDamaged25.AddCondition(pHullLow)
	pIfPlayerDamaged25.AddCondition(pPowerSystemLow)
	pIfPlayerDamaged25.AddCondition(pWarpDamaged)
	pIfPlayerDamaged25.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfPlayerDamaged25
	#########################################
	#########################################
	# Creating PlainAI TriggerDraxonBattleLine at (309, 89)
	pTriggerDraxonBattleLine = App.PlainAI_Create(pShip, "TriggerDraxonBattleLine")
	pTriggerDraxonBattleLine.SetScriptModule("RunScript")
	pTriggerDraxonBattleLine.SetInterruptable(1)
	pScript = pTriggerDraxonBattleLine.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode3.E3M1.E3M1")
	pScript.SetFunction("DraxonBattleLine")
	# Done creating PlainAI TriggerDraxonBattleLine
	#########################################
	#########################################
	# Creating ConditionalAI IfPlayerDamaged50 at (225, 89)
	## Conditions:
	#### Condition HullLow
	pHullLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", "player", App.CT_HULL_SUBSYSTEM,.5)
	#### Condition PowerSystemLow
	pPowerSystemLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", "player", App.CT_POWER_SUBSYSTEM, .5)
	#### Condition WarpDamaged
	pWarpDamaged = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", "player", App.CT_WARP_ENGINE_SUBSYSTEM, .5)
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
	pIfPlayerDamaged50 = App.ConditionalAI_Create(pShip, "IfPlayerDamaged50")
	pIfPlayerDamaged50.SetInterruptable(1)
	pIfPlayerDamaged50.SetContainedAI(pTriggerDraxonBattleLine)
	pIfPlayerDamaged50.AddCondition(pHullLow)
	pIfPlayerDamaged50.AddCondition(pPowerSystemLow)
	pIfPlayerDamaged50.AddCondition(pWarpDamaged)
	pIfPlayerDamaged50.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfPlayerDamaged50
	#########################################
	#########################################
	# Creating PlainAI TriggerMacCrayLine_2 at (308, 121)
	pTriggerMacCrayLine_2 = App.PlainAI_Create(pShip, "TriggerMacCrayLine_2")
	pTriggerMacCrayLine_2.SetScriptModule("RunScript")
	pTriggerMacCrayLine_2.SetInterruptable(1)
	pScript = pTriggerMacCrayLine_2.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode3.E3M1.E3M1")
	pScript.SetFunction("MacCrayBattleLine")
	pScript.SetArguments("E3M1SaveTorps")
	# Done creating PlainAI TriggerMacCrayLine_2
	#########################################
	#########################################
	# Creating ConditionalAI IfBOPDamaged75 at (225, 121)
	## Conditions:
	#### Condition HullLow
	pHullLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName (),App.CT_HULL_SUBSYSTEM,.75)
	#### Condition PowerLow
	pPowerLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName (), App.CT_POWER_SUBSYSTEM, .75)
	#### Condition WarpLow
	pWarpLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName (), App.CT_WARP_ENGINE_SUBSYSTEM, .75)
	#### Condition HullLow2
	pHullLow2 = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", "BolWI'", App.CT_HULL_SUBSYSTEM,.75)
	#### Condition PowerLow2
	pPowerLow2 = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", "BolWI'", App.CT_POWER_SUBSYSTEM, .75)
	#### Condition WarpLow2
	pWarpLow2 = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", "BolWI'", App.CT_WARP_ENGINE_SUBSYSTEM, .75)
	## Evaluation function:
	def EvalFunc(bHullLow, bPowerLow, bWarpLow, bHullLow2, bPowerLow2, bWarpLow2):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bHullLow or bPowerLow or bWarpLow or bHullLow2 or bPowerLow2 or bWarpLow2:
			return ACTIVE
		else:
			return DORMANT
	## The ConditionalAI:
	pIfBOPDamaged75 = App.ConditionalAI_Create(pShip, "IfBOPDamaged75")
	pIfBOPDamaged75.SetInterruptable(1)
	pIfBOPDamaged75.SetContainedAI(pTriggerMacCrayLine_2)
	pIfBOPDamaged75.AddCondition(pHullLow)
	pIfBOPDamaged75.AddCondition(pPowerLow)
	pIfBOPDamaged75.AddCondition(pWarpLow)
	pIfBOPDamaged75.AddCondition(pHullLow2)
	pIfBOPDamaged75.AddCondition(pPowerLow2)
	pIfBOPDamaged75.AddCondition(pWarpLow2)
	pIfBOPDamaged75.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfBOPDamaged75
	#########################################
	#########################################
	# Creating PlainAI TriggerMacCrayLine_4 at (307, 185)
	pTriggerMacCrayLine_4 = App.PlainAI_Create(pShip, "TriggerMacCrayLine_4")
	pTriggerMacCrayLine_4.SetScriptModule("RunScript")
	pTriggerMacCrayLine_4.SetInterruptable(1)
	pScript = pTriggerMacCrayLine_4.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode3.E3M1.E3M1")
	pScript.SetFunction("MacCrayBattleLine")
	pScript.SetArguments("E3M1L147")
	# Done creating PlainAI TriggerMacCrayLine_4
	#########################################
	#########################################
	# Creating ConditionalAI IfPlayerShieldLow at (226, 185)
	## Conditions:
	#### Condition ShieldLow
	pShieldLow = App.ConditionScript_Create("Conditions.ConditionSingleShieldBelow", "ConditionSingleShieldBelow", "player", .25, App.ShieldClass.NUM_SHIELDS)
	## Evaluation function:
	def EvalFunc(bShieldLow):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bShieldLow:
			return ACTIVE
		else:
			return DORMANT
	## The ConditionalAI:
	pIfPlayerShieldLow = App.ConditionalAI_Create(pShip, "IfPlayerShieldLow")
	pIfPlayerShieldLow.SetInterruptable(1)
	pIfPlayerShieldLow.SetContainedAI(pTriggerMacCrayLine_4)
	pIfPlayerShieldLow.AddCondition(pShieldLow)
	pIfPlayerShieldLow.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfPlayerShieldLow
	#########################################
	#########################################
	# Creating PlainAI TriggerMacCrayLine_5 at (309, 217)
	pTriggerMacCrayLine_5 = App.PlainAI_Create(pShip, "TriggerMacCrayLine_5")
	pTriggerMacCrayLine_5.SetScriptModule("RunScript")
	pTriggerMacCrayLine_5.SetInterruptable(1)
	pScript = pTriggerMacCrayLine_5.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode3.E3M1.E3M1")
	pScript.SetFunction("MacCrayBattleLine")
	pScript.SetArguments("E3M1L148")
	# Done creating PlainAI TriggerMacCrayLine_5
	#########################################
	#########################################
	# Creating ConditionalAI IfPlayerDamaged75 at (226, 218)
	## Conditions:
	#### Condition HullLow
	pHullLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", "player", App.CT_HULL_SUBSYSTEM,.75)
	#### Condition PowerSystemLow
	pPowerSystemLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", "player", App.CT_POWER_SUBSYSTEM, .75)
	#### Condition WarpDamaged
	pWarpDamaged = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", "player", App.CT_WARP_ENGINE_SUBSYSTEM, .75)
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
	pIfPlayerDamaged75 = App.ConditionalAI_Create(pShip, "IfPlayerDamaged75")
	pIfPlayerDamaged75.SetInterruptable(1)
	pIfPlayerDamaged75.SetContainedAI(pTriggerMacCrayLine_5)
	pIfPlayerDamaged75.AddCondition(pHullLow)
	pIfPlayerDamaged75.AddCondition(pPowerSystemLow)
	pIfPlayerDamaged75.AddCondition(pWarpDamaged)
	pIfPlayerDamaged75.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfPlayerDamaged75
	#########################################
	#########################################
	# Creating PlainAI TriggerMacCrayLine_6 at (309, 249)
	pTriggerMacCrayLine_6 = App.PlainAI_Create(pShip, "TriggerMacCrayLine_6")
	pTriggerMacCrayLine_6.SetScriptModule("RunScript")
	pTriggerMacCrayLine_6.SetInterruptable(1)
	pScript = pTriggerMacCrayLine_6.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode3.E3M1.E3M1")
	pScript.SetFunction("MacCrayBattleLine")
	pScript.SetArguments("E3M1L144")
	# Done creating PlainAI TriggerMacCrayLine_6
	#########################################
	#########################################
	# Creating ConditionalAI IfPlayerDamaged90 at (226, 249)
	## Conditions:
	#### Condition HullLow
	pHullLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", "player", App.CT_HULL_SUBSYSTEM,.9)
	#### Condition PowerSystemLow
	pPowerSystemLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", "player", App.CT_POWER_SUBSYSTEM, .9)
	#### Condition WarpDamaged
	pWarpDamaged = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", "player", App.CT_WARP_ENGINE_SUBSYSTEM, .9)
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
	pIfPlayerDamaged90 = App.ConditionalAI_Create(pShip, "IfPlayerDamaged90")
	pIfPlayerDamaged90.SetInterruptable(1)
	pIfPlayerDamaged90.SetContainedAI(pTriggerMacCrayLine_6)
	pIfPlayerDamaged90.AddCondition(pHullLow)
	pIfPlayerDamaged90.AddCondition(pPowerSystemLow)
	pIfPlayerDamaged90.AddCondition(pWarpDamaged)
	pIfPlayerDamaged90.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfPlayerDamaged90
	#########################################
	#########################################
	# Creating CompoundAI Attack at (411, 3)
	import AI.Compound.BasicAttack
	pAttack = AI.Compound.BasicAttack.CreateAI(pShip, "player", Difficulty = 0.65, AvoidTorps = 1, ChooseSubsystemTargets = 0, UseCloaking = 1)
	# Done creating CompoundAI Attack
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (5, 3)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (95, 10)
	pPriorityList.AddAI(pIfRankufDamaged50, 1)
	pPriorityList.AddAI(pIfPlayerDamaged25, 2)
	pPriorityList.AddAI(pIfPlayerDamaged50, 3)
	pPriorityList.AddAI(pIfBOPDamaged75, 4)
	pPriorityList.AddAI(pIfPlayerShieldLow, 5)
	pPriorityList.AddAI(pIfPlayerDamaged75, 6)
	pPriorityList.AddAI(pIfPlayerDamaged90, 7)
	pPriorityList.AddAI(pAttack, 8)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (5, 41)
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
	# Creating PlainAI TriggerMacCrayLine_3 at (307, 152)
	pTriggerMacCrayLine_3 = App.PlainAI_Create(pShip, "TriggerMacCrayLine_3")
	pTriggerMacCrayLine_3.SetScriptModule("RunScript")
	pTriggerMacCrayLine_3.SetInterruptable(1)
	pScript = pTriggerMacCrayLine_3.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode3.E3M1.E3M1")
	pScript.SetFunction("MacCrayBattleLine")
	pScript.SetArguments("E3M1L149")
	# Done creating PlainAI TriggerMacCrayLine_3
	#########################################
	#########################################
	# Creating ConditionalAI IfBOPDamaged90 at (225, 153)
	## Conditions:
	#### Condition HullLow
	pHullLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName (),App.CT_HULL_SUBSYSTEM,.9)
	#### Condition PowerLow
	pPowerLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName (), App.CT_POWER_SUBSYSTEM, .9)
	#### Condition WarpLow
	pWarpLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName (), App.CT_WARP_ENGINE_SUBSYSTEM, .9)
	#### Condition HullLow2
	pHullLow2 = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", "BolWI'", App.CT_HULL_SUBSYSTEM,.9)
	#### Condition PowerLow2
	pPowerLow2 = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", "BolWI'", App.CT_POWER_SUBSYSTEM, .9)
	#### Condition WarpLow2
	pWarpLow2 = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", "BolWI'", App.CT_WARP_ENGINE_SUBSYSTEM, .9)
	## Evaluation function:
	def EvalFunc(bHullLow, bPowerLow, bWarpLow, bHullLow2, bPowerLow2, bWarpLow2):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bHullLow or bPowerLow or bWarpLow or bHullLow2 or bPowerLow2 or bWarpLow2:
			return ACTIVE
		else:
			return DORMANT
	## The ConditionalAI:
	pIfBOPDamaged90 = App.ConditionalAI_Create(pShip, "IfBOPDamaged90")
	pIfBOPDamaged90.SetInterruptable(1)
	pIfBOPDamaged90.SetContainedAI(pTriggerMacCrayLine_3)
	pIfBOPDamaged90.AddCondition(pHullLow)
	pIfBOPDamaged90.AddCondition(pPowerLow)
	pIfBOPDamaged90.AddCondition(pWarpLow)
	pIfBOPDamaged90.AddCondition(pHullLow2)
	pIfBOPDamaged90.AddCondition(pPowerLow2)
	pIfBOPDamaged90.AddCondition(pWarpLow2)
	pIfBOPDamaged90.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfBOPDamaged90
	#########################################
	return pIfBOPDamaged90
