import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI TriggerBOPCutscene at (315, 15)
	pTriggerBOPCutscene = App.PlainAI_Create(pShip, "TriggerBOPCutscene")
	pTriggerBOPCutscene.SetScriptModule("RunScript")
	pTriggerBOPCutscene.SetInterruptable(1)
	pScript = pTriggerBOPCutscene.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode3.E3M1.E3M1")
	pScript.SetFunction("BOPCutscene")
	pScript.SetArguments(1)
	# Done creating PlainAI TriggerBOPCutscene
	#########################################
	#########################################
	# Creating ConditionalAI IfGeronimoDamaged25 at (233, 15)
	## Conditions:
	#### Condition HullLow
	pHullLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName (),App.CT_HULL_SUBSYSTEM,.25)
	#### Condition PowerSystemLow
	pPowerSystemLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName (), App.CT_POWER_SUBSYSTEM, .25)
	#### Condition WarpDamaged
	pWarpDamaged = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName (), App.CT_WARP_ENGINE_SUBSYSTEM, .25)
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
	pIfGeronimoDamaged25 = App.ConditionalAI_Create(pShip, "IfGeronimoDamaged25")
	pIfGeronimoDamaged25.SetInterruptable(1)
	pIfGeronimoDamaged25.SetContainedAI(pTriggerBOPCutscene)
	pIfGeronimoDamaged25.AddCondition(pHullLow)
	pIfGeronimoDamaged25.AddCondition(pPowerSystemLow)
	pIfGeronimoDamaged25.AddCondition(pWarpDamaged)
	pIfGeronimoDamaged25.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfGeronimoDamaged25
	#########################################
	#########################################
	# Creating PlainAI TriggerBOPCutscene2 at (318, 48)
	pTriggerBOPCutscene2 = App.PlainAI_Create(pShip, "TriggerBOPCutscene2")
	pTriggerBOPCutscene2.SetScriptModule("RunScript")
	pTriggerBOPCutscene2.SetInterruptable(1)
	pScript = pTriggerBOPCutscene2.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode3.E3M1.E3M1")
	pScript.SetFunction("BOPCutscene")
	pScript.SetArguments(0)
	# Done creating PlainAI TriggerBOPCutscene2
	#########################################
	#########################################
	# Creating ConditionalAI IfPlayerDamaged25 at (234, 48)
	## Conditions:
	#### Condition HullLow
	pHullLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", "player",App.CT_HULL_SUBSYSTEM,.25)
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
	pIfPlayerDamaged25.SetContainedAI(pTriggerBOPCutscene2)
	pIfPlayerDamaged25.AddCondition(pHullLow)
	pIfPlayerDamaged25.AddCondition(pPowerSystemLow)
	pIfPlayerDamaged25.AddCondition(pWarpDamaged)
	pIfPlayerDamaged25.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfPlayerDamaged25
	#########################################
	#########################################
	# Creating PlainAI TriggerFelixLine at (318, 79)
	pTriggerFelixLine = App.PlainAI_Create(pShip, "TriggerFelixLine")
	pTriggerFelixLine.SetScriptModule("RunScript")
	pTriggerFelixLine.SetInterruptable(1)
	pScript = pTriggerFelixLine.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode3.E3M1.E3M1")
	pScript.SetFunction("FelixBattleLine")
	# Done creating PlainAI TriggerFelixLine
	#########################################
	#########################################
	# Creating ConditionalAI IfPlayerHullDamaged50 at (235, 81)
	## Conditions:
	#### Condition HullLow
	pHullLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", "player",App.CT_HULL_SUBSYSTEM,.50)
	## Evaluation function:
	def EvalFunc(bHullLow):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bHullLow:
			return ACTIVE
		else:
			return DORMANT
	## The ConditionalAI:
	pIfPlayerHullDamaged50 = App.ConditionalAI_Create(pShip, "IfPlayerHullDamaged50")
	pIfPlayerHullDamaged50.SetInterruptable(1)
	pIfPlayerHullDamaged50.SetContainedAI(pTriggerFelixLine)
	pIfPlayerHullDamaged50.AddCondition(pHullLow)
	pIfPlayerHullDamaged50.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfPlayerHullDamaged50
	#########################################
	#########################################
	# Creating PlainAI TriggerMacCrayLine at (318, 111)
	pTriggerMacCrayLine = App.PlainAI_Create(pShip, "TriggerMacCrayLine")
	pTriggerMacCrayLine.SetScriptModule("RunScript")
	pTriggerMacCrayLine.SetInterruptable(1)
	pScript = pTriggerMacCrayLine.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode3.E3M1.E3M1")
	pScript.SetFunction("MacCrayBattleLine")
	pScript.SetArguments("E3M1L170")
	# Done creating PlainAI TriggerMacCrayLine
	#########################################
	#########################################
	# Creating ConditionalAI IfPlayerDamaged75 at (235, 113)
	## Conditions:
	#### Condition HullLow
	pHullLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", "player",App.CT_HULL_SUBSYSTEM,.75)
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
	pIfPlayerDamaged75.SetContainedAI(pTriggerMacCrayLine)
	pIfPlayerDamaged75.AddCondition(pHullLow)
	pIfPlayerDamaged75.AddCondition(pPowerSystemLow)
	pIfPlayerDamaged75.AddCondition(pWarpDamaged)
	pIfPlayerDamaged75.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfPlayerDamaged75
	#########################################
	#########################################
	# Creating PlainAI TriggerMacCrayLine2 at (319, 144)
	pTriggerMacCrayLine2 = App.PlainAI_Create(pShip, "TriggerMacCrayLine2")
	pTriggerMacCrayLine2.SetScriptModule("RunScript")
	pTriggerMacCrayLine2.SetInterruptable(1)
	pScript = pTriggerMacCrayLine2.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode3.E3M1.E3M1")
	pScript.SetFunction("MacCrayBattleLine")
	pScript.SetArguments("E3M1L142")
	# Done creating PlainAI TriggerMacCrayLine2
	#########################################
	#########################################
	# Creating ConditionalAI IfGeronimoDamaged50 at (235, 144)
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
	pIfGeronimoDamaged50 = App.ConditionalAI_Create(pShip, "IfGeronimoDamaged50")
	pIfGeronimoDamaged50.SetInterruptable(1)
	pIfGeronimoDamaged50.SetContainedAI(pTriggerMacCrayLine2)
	pIfGeronimoDamaged50.AddCondition(pHullLow)
	pIfGeronimoDamaged50.AddCondition(pPowerSystemLow)
	pIfGeronimoDamaged50.AddCondition(pWarpDamaged)
	pIfGeronimoDamaged50.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfGeronimoDamaged50
	#########################################
	#########################################
	# Creating PlainAI TriggerMacCrayLine3 at (319, 176)
	pTriggerMacCrayLine3 = App.PlainAI_Create(pShip, "TriggerMacCrayLine3")
	pTriggerMacCrayLine3.SetScriptModule("RunScript")
	pTriggerMacCrayLine3.SetInterruptable(1)
	pScript = pTriggerMacCrayLine3.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode3.E3M1.E3M1")
	pScript.SetFunction("MacCrayBattleLine")
	pScript.SetArguments("E3M1L116")
	# Done creating PlainAI TriggerMacCrayLine3
	#########################################
	#########################################
	# Creating ConditionalAI IfGeronimoDamaged75 at (235, 176)
	## Conditions:
	#### Condition HullLow
	pHullLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName (),App.CT_HULL_SUBSYSTEM,.75)
	#### Condition PowerSystemLow
	pPowerSystemLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName (), App.CT_POWER_SUBSYSTEM, .75)
	#### Condition WarpDamaged
	pWarpDamaged = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName (), App.CT_WARP_ENGINE_SUBSYSTEM, .75)
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
	pIfGeronimoDamaged75 = App.ConditionalAI_Create(pShip, "IfGeronimoDamaged75")
	pIfGeronimoDamaged75.SetInterruptable(1)
	pIfGeronimoDamaged75.SetContainedAI(pTriggerMacCrayLine3)
	pIfGeronimoDamaged75.AddCondition(pHullLow)
	pIfGeronimoDamaged75.AddCondition(pPowerSystemLow)
	pIfGeronimoDamaged75.AddCondition(pWarpDamaged)
	pIfGeronimoDamaged75.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfGeronimoDamaged75
	#########################################
	#########################################
	# Creating PlainAI TriggerMacCrayLine4 at (318, 207)
	pTriggerMacCrayLine4 = App.PlainAI_Create(pShip, "TriggerMacCrayLine4")
	pTriggerMacCrayLine4.SetScriptModule("RunScript")
	pTriggerMacCrayLine4.SetInterruptable(1)
	pScript = pTriggerMacCrayLine4.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode3.E3M1.E3M1")
	pScript.SetFunction("MacCrayBattleLine")
	pScript.SetArguments("E3M1L115")
	# Done creating PlainAI TriggerMacCrayLine4
	#########################################
	#########################################
	# Creating ConditionalAI IfGeronimoDamaged90 at (235, 208)
	## Conditions:
	#### Condition HullLow
	pHullLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName (),App.CT_HULL_SUBSYSTEM,.9)
	#### Condition PowerSystemLow
	pPowerSystemLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName (), App.CT_POWER_SUBSYSTEM, .9)
	#### Condition WarpDamaged
	pWarpDamaged = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName (), App.CT_WARP_ENGINE_SUBSYSTEM, .9)
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
	pIfGeronimoDamaged90 = App.ConditionalAI_Create(pShip, "IfGeronimoDamaged90")
	pIfGeronimoDamaged90.SetInterruptable(1)
	pIfGeronimoDamaged90.SetContainedAI(pTriggerMacCrayLine4)
	pIfGeronimoDamaged90.AddCondition(pHullLow)
	pIfGeronimoDamaged90.AddCondition(pPowerSystemLow)
	pIfGeronimoDamaged90.AddCondition(pWarpDamaged)
	pIfGeronimoDamaged90.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfGeronimoDamaged90
	#########################################
	#########################################
	# Creating PlainAI TriggerMacCrayLine5 at (319, 240)
	pTriggerMacCrayLine5 = App.PlainAI_Create(pShip, "TriggerMacCrayLine5")
	pTriggerMacCrayLine5.SetScriptModule("RunScript")
	pTriggerMacCrayLine5.SetInterruptable(1)
	pScript = pTriggerMacCrayLine5.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode3.E3M1.E3M1")
	pScript.SetFunction("MacCrayBattleLine")
	pScript.SetArguments("E3M1L143")
	# Done creating PlainAI TriggerMacCrayLine5
	#########################################
	#########################################
	# Creating ConditionalAI IfPlayerDamaged90 at (235, 241)
	## Conditions:
	#### Condition HullLow
	pHullLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", "player",App.CT_HULL_SUBSYSTEM,.9)
	#### Condition PowerSystemLow
	pPowerSystemLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", "player", App.CT_POWER_SUBSYSTEM, .9)
	#### Condition WarpDamaged
	pWarpDamaged = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", "player", App.CT_WARP_ENGINE_SUBSYSTEM, .9)
	#### Condition ShieldLow
	pShieldLow = App.ConditionScript_Create("Conditions.ConditionSingleShieldBelow", "ConditionSingleShieldBelow", "player", .75, App.ShieldClass.NUM_SHIELDS)
	## Evaluation function:
	def EvalFunc(bHullLow, bPowerSystemLow, bWarpDamaged, bShieldLow):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bHullLow or bPowerSystemLow or bWarpDamaged or bShieldLow:
			return ACTIVE
		else:
			return DORMANT
	## The ConditionalAI:
	pIfPlayerDamaged90 = App.ConditionalAI_Create(pShip, "IfPlayerDamaged90")
	pIfPlayerDamaged90.SetInterruptable(1)
	pIfPlayerDamaged90.SetContainedAI(pTriggerMacCrayLine5)
	pIfPlayerDamaged90.AddCondition(pHullLow)
	pIfPlayerDamaged90.AddCondition(pPowerSystemLow)
	pIfPlayerDamaged90.AddCondition(pWarpDamaged)
	pIfPlayerDamaged90.AddCondition(pShieldLow)
	pIfPlayerDamaged90.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfPlayerDamaged90
	#########################################
	#########################################
	# Creating PlainAI TriggerMacCrayLine6 at (319, 273)
	pTriggerMacCrayLine6 = App.PlainAI_Create(pShip, "TriggerMacCrayLine6")
	pTriggerMacCrayLine6.SetScriptModule("RunScript")
	pTriggerMacCrayLine6.SetInterruptable(1)
	pScript = pTriggerMacCrayLine6.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode3.E3M1.E3M1")
	pScript.SetFunction("MacCrayBattleLine")
	pScript.SetArguments("E3M1L145")
	# Done creating PlainAI TriggerMacCrayLine6
	#########################################
	#########################################
	# Creating ConditionalAI IfPlayerDamaged80 at (235, 274)
	## Conditions:
	#### Condition HullLow
	pHullLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", "player",App.CT_HULL_SUBSYSTEM,.8)
	#### Condition PowerSystemLow
	pPowerSystemLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", "player", App.CT_POWER_SUBSYSTEM, .8)
	#### Condition WarpDamaged
	pWarpDamaged = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", "player", App.CT_WARP_ENGINE_SUBSYSTEM, .8)
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
	pIfPlayerDamaged80 = App.ConditionalAI_Create(pShip, "IfPlayerDamaged80")
	pIfPlayerDamaged80.SetInterruptable(1)
	pIfPlayerDamaged80.SetContainedAI(pTriggerMacCrayLine6)
	pIfPlayerDamaged80.AddCondition(pHullLow)
	pIfPlayerDamaged80.AddCondition(pPowerSystemLow)
	pIfPlayerDamaged80.AddCondition(pWarpDamaged)
	pIfPlayerDamaged80.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfPlayerDamaged80
	#########################################
	#########################################
	# Creating PlainAI TriggerMacCrayLine7 at (318, 306)
	pTriggerMacCrayLine7 = App.PlainAI_Create(pShip, "TriggerMacCrayLine7")
	pTriggerMacCrayLine7.SetScriptModule("RunScript")
	pTriggerMacCrayLine7.SetInterruptable(1)
	pScript = pTriggerMacCrayLine7.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode3.E3M1.E3M1")
	pScript.SetFunction("MacCrayBattleLine")
	pScript.SetArguments("E3M1L114")
	# Done creating PlainAI TriggerMacCrayLine7
	#########################################
	#########################################
	# Creating ConditionalAI IfPlayerRuns at (236, 309)
	## Conditions:
	#### Condition RangeCondition
	pRangeCondition = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 350, pShip.GetName(), "player")
	## Evaluation function:
	def EvalFunc(bRangeCondition):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bRangeCondition:
			return DORMANT
		else:
			return ACTIVE
	## The ConditionalAI:
	pIfPlayerRuns = App.ConditionalAI_Create(pShip, "IfPlayerRuns")
	pIfPlayerRuns.SetInterruptable(1)
	pIfPlayerRuns.SetContainedAI(pTriggerMacCrayLine7)
	pIfPlayerRuns.AddCondition(pRangeCondition)
	pIfPlayerRuns.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IfPlayerRuns
	#########################################
	#########################################
	# Creating CompoundAI MacCrayAttack at (414, -2)
	import AI.Compound.BasicAttack
	pMacCrayAttack = AI.Compound.BasicAttack.CreateAI(pShip, "player", Difficulty = 0.6, ChooseSubsystemTargets = 1, SmartShields = 1, SmartTorpSelection = 1)
	# Done creating CompoundAI MacCrayAttack
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (18, 33)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (50, 4)
	pPriorityList.AddAI(pIfGeronimoDamaged25, 1)
	pPriorityList.AddAI(pIfPlayerDamaged25, 2)
	pPriorityList.AddAI(pIfPlayerHullDamaged50, 3)
	pPriorityList.AddAI(pIfPlayerDamaged75, 4)
	pPriorityList.AddAI(pIfGeronimoDamaged50, 5)
	pPriorityList.AddAI(pIfGeronimoDamaged75, 6)
	pPriorityList.AddAI(pIfGeronimoDamaged90, 7)
	pPriorityList.AddAI(pIfPlayerDamaged90, 8)
	pPriorityList.AddAI(pIfPlayerDamaged80, 9)
	pPriorityList.AddAI(pIfPlayerRuns, 10)
	pPriorityList.AddAI(pMacCrayAttack, 11)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (22, 70)
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
