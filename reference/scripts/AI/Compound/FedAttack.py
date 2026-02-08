	######### AI Builder Begin #########
## BUILDER AI
##  This AI file has been mauled by the MakeBuilderAI script.
##  Modify at your own risk.
##  Or run MakeBuilderAI(filename, 1) to remove the BuilderAI code.
	########## AI Builder End ##########
import App
def CreateAI(pShip, *lpTargets, **dKeywords):
	# Make a group for all the targets...
	pAllTargetsGroup = App.ObjectGroup_ForceToGroup(lpTargets)
	sInitialTarget = pAllTargetsGroup.GetNameTuple()[0]

	Random = lambda fMin, fMax : App.g_kSystemWrapper.GetRandomNumber((fMax-fMin) * 1000.0) / 1000.0 - fMin

	# Range values used in the AI.
	fTooCloseRange = 50.0 + Random(-10, 10)
	fTooFarRange = 100.0 + Random(-15, 10)

	fCloseRange = 150.0 + Random(-5, 15)
	fMidRange = 200.0 + Random(-10, 20)
	fLongRange = 350.0 + Random(-30, 20)

	######### AI Builder Begin #########
	pBuilderAI = App.BuilderAI_Create(pShip, "AlertLevel Builder", __name__)
	pBuilderAI.AddAIBlock("CheckWarpBeforeDeath", "BuilderCreate1")
	pBuilderAI.AddDependencyObject("CheckWarpBeforeDeath", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("NoSensorsEvasive", "BuilderCreate2")
	pBuilderAI.AddAIBlock("TorpRun_3", "BuilderCreate3")
	pBuilderAI.AddDependencyObject("TorpRun_3", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("TorpsReadyNotInterruptable", "BuilderCreate4")
	pBuilderAI.AddDependency("TorpsReadyNotInterruptable", "TorpRun_3")
	pBuilderAI.AddAIBlock("NoStopping", "BuilderCreate5")
	pBuilderAI.AddDependency("NoStopping", "TorpsReadyNotInterruptable")
	pBuilderAI.AddDependencyObject("NoStopping", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("StationaryAttack_2", "BuilderCreate6")
	pBuilderAI.AddDependencyObject("StationaryAttack_2", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("TorpsStillReadyFacingTowardNotInterruptable", "BuilderCreate7")
	pBuilderAI.AddDependency("TorpsStillReadyFacingTowardNotInterruptable", "StationaryAttack_2")
	pBuilderAI.AddDependencyObject("TorpsStillReadyFacingTowardNotInterruptable", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("TurnToAttack", "BuilderCreate8")
	pBuilderAI.AddDependencyObject("TurnToAttack", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("PriorityList_2", "BuilderCreate9")
	pBuilderAI.AddDependency("PriorityList_2", "TorpsStillReadyFacingTowardNotInterruptable")
	pBuilderAI.AddDependency("PriorityList_2", "TurnToAttack")
	pBuilderAI.AddAIBlock("StoppingOk", "BuilderCreate10")
	pBuilderAI.AddDependency("StoppingOk", "PriorityList_2")
	pBuilderAI.AddDependencyObject("StoppingOk", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("PriorityList_3", "BuilderCreate11")
	pBuilderAI.AddDependency("PriorityList_3", "NoStopping")
	pBuilderAI.AddDependency("PriorityList_3", "StoppingOk")
	pBuilderAI.AddAIBlock("TorpsReadyAndNotInEnemyFiringArc", "BuilderCreate12")
	pBuilderAI.AddDependency("TorpsReadyAndNotInEnemyFiringArc", "PriorityList_3")
	pBuilderAI.AddDependencyObject("TorpsReadyAndNotInEnemyFiringArc", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("ICOMoveIn", "BuilderCreate13")
	pBuilderAI.AddDependencyObject("ICOMoveIn", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddDependencyObject("ICOMoveIn", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("FrontShieldLowSidesNotLow", "BuilderCreate14")
	pBuilderAI.AddDependency("FrontShieldLowSidesNotLow", "ICOMoveIn")
	pBuilderAI.AddAIBlock("TorpRun_2", "BuilderCreate15")
	pBuilderAI.AddDependencyObject("TorpRun_2", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("FwdTorpsReady", "BuilderCreate16")
	pBuilderAI.AddDependency("FwdTorpsReady", "TorpRun_2")
	pBuilderAI.AddAIBlock("SweepPhasers", "BuilderCreate17")
	pBuilderAI.AddDependencyObject("SweepPhasers", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddDependencyObject("SweepPhasers", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("TooFarPriorities", "BuilderCreate18")
	pBuilderAI.AddDependency("TooFarPriorities", "TorpsReadyAndNotInEnemyFiringArc")
	pBuilderAI.AddDependency("TooFarPriorities", "FrontShieldLowSidesNotLow")
	pBuilderAI.AddDependency("TooFarPriorities", "FwdTorpsReady")
	pBuilderAI.AddDependency("TooFarPriorities", "SweepPhasers")
	pBuilderAI.AddAIBlock("TooFar", "BuilderCreate19")
	pBuilderAI.AddDependency("TooFar", "TooFarPriorities")
	pBuilderAI.AddDependencyObject("TooFar", "fTooCloseRange", fTooCloseRange)
	pBuilderAI.AddDependencyObject("TooFar", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("RearTorpRun", "BuilderCreate20")
	pBuilderAI.AddDependencyObject("RearTorpRun", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("RearTorpsReadyRearShieldOk", "BuilderCreate21")
	pBuilderAI.AddDependency("RearTorpsReadyRearShieldOk", "RearTorpRun")
	pBuilderAI.AddDependencyObject("RearTorpsReadyRearShieldOk", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("TorpRun_4", "BuilderCreate22")
	pBuilderAI.AddDependencyObject("TorpRun_4", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("SignificantTimePassed", "BuilderCreate23")
	pBuilderAI.AddDependency("SignificantTimePassed", "TorpRun_4")
	pBuilderAI.AddAIBlock("FrontTorpsReadyFrontShieldsOk", "BuilderCreate24")
	pBuilderAI.AddDependency("FrontTorpsReadyFrontShieldsOk", "SignificantTimePassed")
	pBuilderAI.AddDependencyObject("FrontTorpsReadyFrontShieldsOk", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("ICO_WeaponBias", "BuilderCreate25")
	pBuilderAI.AddDependencyObject("ICO_WeaponBias", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("UseSideArcs_ShortTime", "BuilderCreate26")
	pBuilderAI.AddDependency("UseSideArcs_ShortTime", "ICO_WeaponBias")
	pBuilderAI.AddDependencyObject("UseSideArcs_ShortTime", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("ICOMoveOut", "BuilderCreate27")
	pBuilderAI.AddDependencyObject("ICOMoveOut", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddDependencyObject("ICOMoveOut", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("RearShieldLow", "BuilderCreate28")
	pBuilderAI.AddDependency("RearShieldLow", "ICOMoveOut")
	pBuilderAI.AddDependencyObject("RearShieldLow", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("Flee", "BuilderCreate29")
	pBuilderAI.AddDependencyObject("Flee", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("TooClosePriorities", "BuilderCreate30")
	pBuilderAI.AddDependency("TooClosePriorities", "RearTorpsReadyRearShieldOk")
	pBuilderAI.AddDependency("TooClosePriorities", "FrontTorpsReadyFrontShieldsOk")
	pBuilderAI.AddDependency("TooClosePriorities", "UseSideArcs_ShortTime")
	pBuilderAI.AddDependency("TooClosePriorities", "RearShieldLow")
	pBuilderAI.AddDependency("TooClosePriorities", "Flee")
	pBuilderAI.AddAIBlock("TooClose", "BuilderCreate31")
	pBuilderAI.AddDependency("TooClose", "TooClosePriorities")
	pBuilderAI.AddDependencyObject("TooClose", "fTooFarRange", fTooFarRange)
	pBuilderAI.AddDependencyObject("TooClose", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("Sequence", "BuilderCreate32")
	pBuilderAI.AddDependency("Sequence", "TooFar")
	pBuilderAI.AddDependency("Sequence", "TooClose")
	pBuilderAI.AddAIBlock("FireAll", "BuilderCreate33")
	pBuilderAI.AddDependency("FireAll", "Sequence")
	pBuilderAI.AddDependencyObject("FireAll", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddDependencyObject("FireAll", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("CloseRange", "BuilderCreate34")
	pBuilderAI.AddDependency("CloseRange", "FireAll")
	pBuilderAI.AddDependencyObject("CloseRange", "fCloseRange", fCloseRange)
	pBuilderAI.AddDependencyObject("CloseRange", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("EvadeTorps", "BuilderCreate35")
	pBuilderAI.AddDependencyObject("EvadeTorps", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddDependencyObject("EvadeTorps", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("TorpRun", "BuilderCreate36")
	pBuilderAI.AddDependencyObject("TorpRun", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("TorpsReady_FwdShieldStrong", "BuilderCreate37")
	pBuilderAI.AddDependency("TorpsReady_FwdShieldStrong", "TorpRun")
	pBuilderAI.AddAIBlock("ICOMoveIn_2", "BuilderCreate38")
	pBuilderAI.AddDependencyObject("ICOMoveIn_2", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddDependencyObject("ICOMoveIn_2", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("SmartShields_2", "BuilderCreate39")
	pBuilderAI.AddDependency("SmartShields_2", "ICOMoveIn_2")
	pBuilderAI.AddDependencyObject("SmartShields_2", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("MoveIn_2", "BuilderCreate40")
	pBuilderAI.AddDependencyObject("MoveIn_2", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("MidRangePriorities", "BuilderCreate41")
	pBuilderAI.AddDependency("MidRangePriorities", "EvadeTorps")
	pBuilderAI.AddDependency("MidRangePriorities", "TorpsReady_FwdShieldStrong")
	pBuilderAI.AddDependency("MidRangePriorities", "SmartShields_2")
	pBuilderAI.AddDependency("MidRangePriorities", "MoveIn_2")
	pBuilderAI.AddAIBlock("FireAll2", "BuilderCreate42")
	pBuilderAI.AddDependency("FireAll2", "MidRangePriorities")
	pBuilderAI.AddDependencyObject("FireAll2", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddDependencyObject("FireAll2", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("MidRange", "BuilderCreate43")
	pBuilderAI.AddDependency("MidRange", "FireAll2")
	pBuilderAI.AddDependencyObject("MidRange", "fMidRange", fMidRange)
	pBuilderAI.AddDependencyObject("MidRange", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("EvadeTorps_2", "BuilderCreate44")
	pBuilderAI.AddDependencyObject("EvadeTorps_2", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddDependencyObject("EvadeTorps_2", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("MoveIn", "BuilderCreate45")
	pBuilderAI.AddDependencyObject("MoveIn", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("LongRangePriorities", "BuilderCreate46")
	pBuilderAI.AddDependency("LongRangePriorities", "EvadeTorps_2")
	pBuilderAI.AddDependency("LongRangePriorities", "MoveIn")
	pBuilderAI.AddAIBlock("FirePulseOnly", "BuilderCreate47")
	pBuilderAI.AddDependency("FirePulseOnly", "LongRangePriorities")
	pBuilderAI.AddDependencyObject("FirePulseOnly", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddDependencyObject("FirePulseOnly", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("LongRange", "BuilderCreate48")
	pBuilderAI.AddDependency("LongRange", "FirePulseOnly")
	pBuilderAI.AddDependencyObject("LongRange", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("InterceptTarget", "BuilderCreate49")
	pBuilderAI.AddDependencyObject("InterceptTarget", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("PriorityList", "BuilderCreate50")
	pBuilderAI.AddDependency("PriorityList", "CloseRange")
	pBuilderAI.AddDependency("PriorityList", "MidRange")
	pBuilderAI.AddDependency("PriorityList", "LongRange")
	pBuilderAI.AddDependency("PriorityList", "InterceptTarget")
	pBuilderAI.AddAIBlock("SelectTarget", "BuilderCreate51")
	pBuilderAI.AddDependency("SelectTarget", "PriorityList")
	pBuilderAI.AddDependencyObject("SelectTarget", "pAllTargetsGroup", pAllTargetsGroup)
	pBuilderAI.AddDependencyObject("SelectTarget", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("FollowTargetThroughWarp", "BuilderCreate52")
	pBuilderAI.AddDependency("FollowTargetThroughWarp", "SelectTarget")
	pBuilderAI.AddDependencyObject("FollowTargetThroughWarp", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddDependencyObject("FollowTargetThroughWarp", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("FollowThroughWarpFlag", "BuilderCreate53")
	pBuilderAI.AddDependency("FollowThroughWarpFlag", "FollowTargetThroughWarp")
	pBuilderAI.AddDependencyObject("FollowThroughWarpFlag", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("FleeAttackOrFollow", "BuilderCreate54")
	pBuilderAI.AddDependency("FleeAttackOrFollow", "CheckWarpBeforeDeath")
	pBuilderAI.AddDependency("FleeAttackOrFollow", "NoSensorsEvasive")
	pBuilderAI.AddDependency("FleeAttackOrFollow", "SelectTarget")
	pBuilderAI.AddDependency("FleeAttackOrFollow", "FollowThroughWarpFlag")
	pBuilderAI.AddAIBlock("PowerManagement", "BuilderCreate55")
	pBuilderAI.AddDependency("PowerManagement", "FleeAttackOrFollow")
	pBuilderAI.AddDependencyObject("PowerManagement", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("AlertLevel", "BuilderCreate56")
	pBuilderAI.AddDependency("AlertLevel", "PowerManagement")
	return pBuilderAI # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate1(pShip, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating CompoundAI CheckWarpBeforeDeath at (131, 551)
	import AI.Compound.Parts.WarpBeforeDeath
	pCheckWarpBeforeDeath = AI.Compound.Parts.WarpBeforeDeath.CreateAI(pShip, dKeywords)
	# Done creating CompoundAI CheckWarpBeforeDeath
	#########################################
	# Builder AI Dependency Object (dKeywords)
	######### AI Builder Begin #########
	return pCheckWarpBeforeDeath  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate2(pShip):
	########## AI Builder End ##########
	#########################################
	# Creating CompoundAI NoSensorsEvasive at (182, 494)
	import AI.Compound.Parts.NoSensorsEvasive
	pNoSensorsEvasive = AI.Compound.Parts.NoSensorsEvasive.CreateAI(pShip)
	# Done creating CompoundAI NoSensorsEvasive
	#########################################
	######### AI Builder Begin #########
	return pNoSensorsEvasive  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate3(pShip, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating PlainAI TorpRun_3 at (46, 46)
	pTorpRun_3 = App.PlainAI_Create(pShip, "TorpRun_3")
	pTorpRun_3.SetScriptModule("TorpedoRun")
	pTorpRun_3.SetInterruptable(1)
	pScript = pTorpRun_3.GetScriptInstance()
	pScript.SetTargetObjectName(sInitialTarget)
	# Done creating PlainAI TorpRun_3
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	######### AI Builder Begin #########
	return pTorpRun_3  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate4(pShip, pTorpRun_3):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI TorpsReadyNotInterruptable at (50, 95)
	## Conditions:
	#### Condition Ready
	pReady = App.ConditionScript_Create("Conditions.ConditionTorpsReady", "ConditionTorpsReady", pShip.GetName(), App.TGPoint3_GetModelForward())
	#### Condition UsingTorps
	pUsingTorps = App.ConditionScript_Create("Conditions.ConditionUsingWeapon", "ConditionUsingWeapon", App.CT_TORPEDO_SYSTEM)
	## Evaluation function:
	def EvalFunc(bReady, bUsingTorps):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bUsingTorps and bReady:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pTorpsReadyNotInterruptable = App.ConditionalAI_Create(pShip, "TorpsReadyNotInterruptable")
	pTorpsReadyNotInterruptable.SetInterruptable(0)
	pTorpsReadyNotInterruptable.SetContainedAI(pTorpRun_3)
	pTorpsReadyNotInterruptable.AddCondition(pReady)
	pTorpsReadyNotInterruptable.AddCondition(pUsingTorps)
	pTorpsReadyNotInterruptable.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TorpsReadyNotInterruptable
	#########################################
	######### AI Builder Begin #########
	return pTorpsReadyNotInterruptable  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate5(pShip, pTorpsReadyNotInterruptable, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI NoStopping at (54, 149)
	## Conditions:
	#### Condition NeverSitStillFlag
	pNeverSitStillFlag = App.ConditionScript_Create("Conditions.ConditionFlagSet", "ConditionFlagSet", "NeverSitStill", dKeywords)
	## Evaluation function:
	def EvalFunc(bNeverSitStillFlag):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bNeverSitStillFlag:
			return ACTIVE
		return DONE
	## The ConditionalAI:
	pNoStopping = App.ConditionalAI_Create(pShip, "NoStopping")
	pNoStopping.SetInterruptable(1)
	pNoStopping.SetContainedAI(pTorpsReadyNotInterruptable)
	pNoStopping.AddCondition(pNeverSitStillFlag)
	pNoStopping.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI NoStopping
	#########################################
	# Builder AI Dependency Object (dKeywords)
	######### AI Builder Begin #########
	return pNoStopping  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate6(pShip, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating PlainAI StationaryAttack_2 at (210, 16)
	pStationaryAttack_2 = App.PlainAI_Create(pShip, "StationaryAttack_2")
	pStationaryAttack_2.SetScriptModule("StationaryAttack")
	pStationaryAttack_2.SetInterruptable(1)
	pScript = pStationaryAttack_2.GetScriptInstance()
	pScript.SetTargetObjectName(sInitialTarget)
	# Done creating PlainAI StationaryAttack_2
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	######### AI Builder Begin #########
	return pStationaryAttack_2  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate7(pShip, pStationaryAttack_2, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI TorpsStillReadyFacingTowardNotInterruptable at (208, 60)
	## Conditions:
	#### Condition TorpsReady
	pTorpsReady = App.ConditionScript_Create("Conditions.ConditionTorpsReady", "ConditionTorpsReady", pShip.GetName(), App.TGPoint3_GetModelForward())
	#### Condition FacingToward
	pFacingToward = App.ConditionScript_Create("Conditions.ConditionFacingToward", "ConditionFacingToward", pShip.GetName(), sInitialTarget, 45.0, App.TGPoint3_GetModelForward(), 1)
	#### Condition UsingTorps
	pUsingTorps = App.ConditionScript_Create("Conditions.ConditionUsingWeapon", "ConditionUsingWeapon", App.CT_TORPEDO_SYSTEM)
	## Evaluation function:
	def EvalFunc(bTorpsReady, bFacingToward, bUsingTorps):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bUsingTorps and bTorpsReady and bFacingToward:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pTorpsStillReadyFacingTowardNotInterruptable = App.ConditionalAI_Create(pShip, "TorpsStillReadyFacingTowardNotInterruptable")
	pTorpsStillReadyFacingTowardNotInterruptable.SetInterruptable(0)
	pTorpsStillReadyFacingTowardNotInterruptable.SetContainedAI(pStationaryAttack_2)
	pTorpsStillReadyFacingTowardNotInterruptable.AddCondition(pTorpsReady)
	pTorpsStillReadyFacingTowardNotInterruptable.AddCondition(pFacingToward)
	pTorpsStillReadyFacingTowardNotInterruptable.AddCondition(pUsingTorps)
	pTorpsStillReadyFacingTowardNotInterruptable.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TorpsStillReadyFacingTowardNotInterruptable
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	######### AI Builder Begin #########
	return pTorpsStillReadyFacingTowardNotInterruptable  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate8(pShip, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating PlainAI TurnToAttack at (319, 72)
	pTurnToAttack = App.PlainAI_Create(pShip, "TurnToAttack")
	pTurnToAttack.SetScriptModule("StationaryAttack")
	pTurnToAttack.SetInterruptable(1)
	pScript = pTurnToAttack.GetScriptInstance()
	pScript.SetTargetObjectName(sInitialTarget)
	# Done creating PlainAI TurnToAttack
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	######### AI Builder Begin #########
	return pTurnToAttack  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate9(pShip, pTorpsStillReadyFacingTowardNotInterruptable, pTurnToAttack):
	########## AI Builder End ##########
	#########################################
	# Creating PriorityListAI PriorityList_2 at (153, 112)
	pPriorityList_2 = App.PriorityListAI_Create(pShip, "PriorityList_2")
	pPriorityList_2.SetInterruptable(1)
	# SeqBlock is at (244, 102)
	pPriorityList_2.AddAI(pTorpsStillReadyFacingTowardNotInterruptable, 1)
	pPriorityList_2.AddAI(pTurnToAttack, 2)
	# Done creating PriorityListAI PriorityList_2
	#########################################
	######### AI Builder Begin #########
	return pPriorityList_2  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate10(pShip, pPriorityList_2, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI StoppingOk at (147, 159)
	## Conditions:
	#### Condition NeverSitStillFlag
	pNeverSitStillFlag = App.ConditionScript_Create("Conditions.ConditionFlagSet", "ConditionFlagSet", "NeverSitStill", dKeywords)
	## Evaluation function:
	def EvalFunc(bNeverSitStillFlag):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bNeverSitStillFlag:
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pStoppingOk = App.ConditionalAI_Create(pShip, "StoppingOk")
	pStoppingOk.SetInterruptable(1)
	pStoppingOk.SetContainedAI(pPriorityList_2)
	pStoppingOk.AddCondition(pNeverSitStillFlag)
	pStoppingOk.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI StoppingOk
	#########################################
	# Builder AI Dependency Object (dKeywords)
	######### AI Builder Begin #########
	return pStoppingOk  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate11(pShip, pNoStopping, pStoppingOk):
	########## AI Builder End ##########
	#########################################
	# Creating PriorityListAI PriorityList_3 at (27, 202)
	pPriorityList_3 = App.PriorityListAI_Create(pShip, "PriorityList_3")
	pPriorityList_3.SetInterruptable(1)
	# SeqBlock is at (124, 206)
	pPriorityList_3.AddAI(pNoStopping, 1)
	pPriorityList_3.AddAI(pStoppingOk, 2)
	# Done creating PriorityListAI PriorityList_3
	#########################################
	######### AI Builder Begin #########
	return pPriorityList_3  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate12(pShip, pPriorityList_3, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI TorpsReadyAndNotInEnemyFiringArc at (83, 246)
	## Conditions:
	#### Condition TorpsReady
	pTorpsReady = App.ConditionScript_Create("Conditions.ConditionTorpsReady", "ConditionTorpsReady", pShip.GetName(), App.TGPoint3_GetModelForward())
	#### Condition InPhaserArc
	pInPhaserArc = App.ConditionScript_Create("Conditions.ConditionInPhaserFiringArc", "ConditionInPhaserFiringArc", pShip.GetName(), sInitialTarget, 1)
	#### Condition UsingTorps
	pUsingTorps = App.ConditionScript_Create("Conditions.ConditionUsingWeapon", "ConditionUsingWeapon", App.CT_TORPEDO_SYSTEM)
	## Evaluation function:
	def EvalFunc(bTorpsReady, bInPhaserArc, bUsingTorps):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bUsingTorps and bTorpsReady and (not bInPhaserArc):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pTorpsReadyAndNotInEnemyFiringArc = App.ConditionalAI_Create(pShip, "TorpsReadyAndNotInEnemyFiringArc")
	pTorpsReadyAndNotInEnemyFiringArc.SetInterruptable(1)
	pTorpsReadyAndNotInEnemyFiringArc.SetContainedAI(pPriorityList_3)
	pTorpsReadyAndNotInEnemyFiringArc.AddCondition(pTorpsReady)
	pTorpsReadyAndNotInEnemyFiringArc.AddCondition(pInPhaserArc)
	pTorpsReadyAndNotInEnemyFiringArc.AddCondition(pUsingTorps)
	pTorpsReadyAndNotInEnemyFiringArc.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TorpsReadyAndNotInEnemyFiringArc
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	######### AI Builder Begin #########
	return pTorpsReadyAndNotInEnemyFiringArc  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate13(pShip, sInitialTarget, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating CompoundAI ICOMoveIn at (283, 122)
	import AI.Compound.Parts.ICOMove
	pICOMoveIn = AI.Compound.Parts.ICOMove.CreateAI(pShip, sInitialTarget, dKeywords, 0.5)
	# Done creating CompoundAI ICOMoveIn
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	# Builder AI Dependency Object (dKeywords)
	######### AI Builder Begin #########
	return pICOMoveIn  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate14(pShip, pICOMoveIn):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI FrontShieldLowSidesNotLow at (263, 170)
	## Conditions:
	#### Condition FrontLow
	pFrontLow = App.ConditionScript_Create("Conditions.ConditionSingleShieldBelow", "ConditionSingleShieldBelow", pShip.GetName(), 0.7, App.ShieldClass.FRONT_SHIELDS)
	#### Condition LeftLow
	pLeftLow = App.ConditionScript_Create("Conditions.ConditionSingleShieldBelow", "ConditionSingleShieldBelow", pShip.GetName(), 0.3, App.ShieldClass.LEFT_SHIELDS)
	#### Condition RightLow
	pRightLow = App.ConditionScript_Create("Conditions.ConditionSingleShieldBelow", "ConditionSingleShieldBelow", pShip.GetName(), 0.3, App.ShieldClass.RIGHT_SHIELDS)
	#### Condition TopLow
	pTopLow = App.ConditionScript_Create("Conditions.ConditionSingleShieldBelow", "ConditionSingleShieldBelow", pShip.GetName(), 0.3, App.ShieldClass.TOP_SHIELDS)
	#### Condition BottomLow
	pBottomLow = App.ConditionScript_Create("Conditions.ConditionSingleShieldBelow", "ConditionSingleShieldBelow", pShip.GetName(), 0.3, App.ShieldClass.BOTTOM_SHIELDS)
	## Evaluation function:
	def EvalFunc(bFrontLow, bLeftLow, bRightLow, bTopLow, bBottomLow):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bFrontLow and not (bLeftLow and bRightLow and bTopLow and bBottomLow):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pFrontShieldLowSidesNotLow = App.ConditionalAI_Create(pShip, "FrontShieldLowSidesNotLow")
	pFrontShieldLowSidesNotLow.SetInterruptable(1)
	pFrontShieldLowSidesNotLow.SetContainedAI(pICOMoveIn)
	pFrontShieldLowSidesNotLow.AddCondition(pFrontLow)
	pFrontShieldLowSidesNotLow.AddCondition(pLeftLow)
	pFrontShieldLowSidesNotLow.AddCondition(pRightLow)
	pFrontShieldLowSidesNotLow.AddCondition(pTopLow)
	pFrontShieldLowSidesNotLow.AddCondition(pBottomLow)
	pFrontShieldLowSidesNotLow.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI FrontShieldLowSidesNotLow
	#########################################
	######### AI Builder Begin #########
	return pFrontShieldLowSidesNotLow  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate15(pShip, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating PlainAI TorpRun_2 at (296, 208)
	pTorpRun_2 = App.PlainAI_Create(pShip, "TorpRun_2")
	pTorpRun_2.SetScriptModule("TorpedoRun")
	pTorpRun_2.SetInterruptable(1)
	pScript = pTorpRun_2.GetScriptInstance()
	pScript.SetTargetObjectName(sInitialTarget)
	# Done creating PlainAI TorpRun_2
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	######### AI Builder Begin #########
	return pTorpRun_2  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate16(pShip, pTorpRun_2):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI FwdTorpsReady at (293, 253)
	## Conditions:
	#### Condition Ready
	pReady = App.ConditionScript_Create("Conditions.ConditionTorpsReady", "ConditionTorpsReady", pShip.GetName(), App.TGPoint3_GetModelForward())
	#### Condition UsingTorps
	pUsingTorps = App.ConditionScript_Create("Conditions.ConditionUsingWeapon", "ConditionUsingWeapon", App.CT_TORPEDO_SYSTEM)
	## Evaluation function:
	def EvalFunc(bReady, bUsingTorps):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bUsingTorps and bReady:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pFwdTorpsReady = App.ConditionalAI_Create(pShip, "FwdTorpsReady")
	pFwdTorpsReady.SetInterruptable(1)
	pFwdTorpsReady.SetContainedAI(pTorpRun_2)
	pFwdTorpsReady.AddCondition(pReady)
	pFwdTorpsReady.AddCondition(pUsingTorps)
	pFwdTorpsReady.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI FwdTorpsReady
	#########################################
	######### AI Builder Begin #########
	return pFwdTorpsReady  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate17(pShip, sInitialTarget, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating CompoundAI SweepPhasers at (294, 300)
	import AI.Compound.Parts.SweepPhasers
	pSweepPhasers = AI.Compound.Parts.SweepPhasers.CreateAI(pShip, sInitialTarget, 1.0, dKeywords)
	# Done creating CompoundAI SweepPhasers
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	# Builder AI Dependency Object (dKeywords)
	######### AI Builder Begin #########
	return pSweepPhasers  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate18(pShip, pTorpsReadyAndNotInEnemyFiringArc, pFrontShieldLowSidesNotLow, pFwdTorpsReady, pSweepPhasers):
	########## AI Builder End ##########
	#########################################
	# Creating PriorityListAI TooFarPriorities at (59, 299)
	pTooFarPriorities = App.PriorityListAI_Create(pShip, "TooFarPriorities")
	pTooFarPriorities.SetInterruptable(1)
	# SeqBlock is at (190, 299)
	pTooFarPriorities.AddAI(pTorpsReadyAndNotInEnemyFiringArc, 1)
	pTooFarPriorities.AddAI(pFrontShieldLowSidesNotLow, 2)
	pTooFarPriorities.AddAI(pFwdTorpsReady, 3)
	pTooFarPriorities.AddAI(pSweepPhasers, 4)
	# Done creating PriorityListAI TooFarPriorities
	#########################################
	######### AI Builder Begin #########
	return pTooFarPriorities  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate19(pShip, pTooFarPriorities, fTooCloseRange, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI TooFar at (334, 396)
	## Conditions:
	#### Condition InRange
	pInRange = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", fTooCloseRange, sInitialTarget, pShip.GetName())
	## Evaluation function:
	def EvalFunc(bInRange):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bInRange:
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pTooFar = App.ConditionalAI_Create(pShip, "TooFar")
	pTooFar.SetInterruptable(1)
	pTooFar.SetContainedAI(pTooFarPriorities)
	pTooFar.AddCondition(pInRange)
	pTooFar.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TooFar
	#########################################
	# Builder AI Dependency Object (fTooCloseRange)
	# Builder AI Dependency Object (sInitialTarget)
	######### AI Builder Begin #########
	return pTooFar  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate20(pShip, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating PlainAI RearTorpRun at (397, 244)
	pRearTorpRun = App.PlainAI_Create(pShip, "RearTorpRun")
	pRearTorpRun.SetScriptModule("TorpedoRun")
	pRearTorpRun.SetInterruptable(1)
	pScript = pRearTorpRun.GetScriptInstance()
	pScript.SetTargetObjectName(sInitialTarget)
	pScript.SetTorpDirection(App.TGPoint3_GetModelBackward())
	# Done creating PlainAI RearTorpRun
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	######### AI Builder Begin #########
	return pRearTorpRun  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate21(pShip, pRearTorpRun, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI RearTorpsReadyRearShieldOk at (398, 289)
	## Conditions:
	#### Condition TorpsReady
	pTorpsReady = App.ConditionScript_Create("Conditions.ConditionTorpsReady", "ConditionTorpsReady", pShip.GetName(), App.TGPoint3_GetModelBackward())
	#### Condition SmartShieldsFlag
	pSmartShieldsFlag = App.ConditionScript_Create("Conditions.ConditionFlagSet", "ConditionFlagSet", "SmartShields", dKeywords)
	#### Condition RearTorpsFlag
	pRearTorpsFlag = App.ConditionScript_Create("Conditions.ConditionFlagSet", "ConditionFlagSet", "UseRearTorps", dKeywords)
	#### Condition RearShieldsLow
	pRearShieldsLow = App.ConditionScript_Create("Conditions.ConditionSingleShieldBelow", "ConditionSingleShieldBelow", pShip.GetName(), 0.25, App.ShieldClass.REAR_SHIELDS)
	#### Condition UsingTorps
	pUsingTorps = App.ConditionScript_Create("Conditions.ConditionUsingWeapon", "ConditionUsingWeapon", App.CT_TORPEDO_SYSTEM)
	## Evaluation function:
	def EvalFunc(bTorpsReady, bSmartShieldsFlag, bRearTorpsFlag, bRearShieldsLow, bUsingTorps):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if not bRearTorpsFlag:
			return DONE
		if bSmartShieldsFlag and bRearShieldsLow:
			return DORMANT
		if bUsingTorps and bTorpsReady:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pRearTorpsReadyRearShieldOk = App.ConditionalAI_Create(pShip, "RearTorpsReadyRearShieldOk")
	pRearTorpsReadyRearShieldOk.SetInterruptable(1)
	pRearTorpsReadyRearShieldOk.SetContainedAI(pRearTorpRun)
	pRearTorpsReadyRearShieldOk.AddCondition(pTorpsReady)
	pRearTorpsReadyRearShieldOk.AddCondition(pSmartShieldsFlag)
	pRearTorpsReadyRearShieldOk.AddCondition(pRearTorpsFlag)
	pRearTorpsReadyRearShieldOk.AddCondition(pRearShieldsLow)
	pRearTorpsReadyRearShieldOk.AddCondition(pUsingTorps)
	pRearTorpsReadyRearShieldOk.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI RearTorpsReadyRearShieldOk
	#########################################
	# Builder AI Dependency Object (dKeywords)
	######### AI Builder Begin #########
	return pRearTorpsReadyRearShieldOk  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate22(pShip, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating PlainAI TorpRun_4 at (465, 96)
	pTorpRun_4 = App.PlainAI_Create(pShip, "TorpRun_4")
	pTorpRun_4.SetScriptModule("TorpedoRun")
	pTorpRun_4.SetInterruptable(1)
	pScript = pTorpRun_4.GetScriptInstance()
	pScript.SetTargetObjectName(sInitialTarget)
	pScript.SetPerpendicularMovementAdjustment(0.3)
	# Done creating PlainAI TorpRun_4
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	######### AI Builder Begin #########
	return pTorpRun_4  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate23(pShip, pTorpRun_4):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI SignificantTimePassed at (465, 147)
	## Conditions:
	#### Condition TimePassed
	pTimePassed = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 10.0, 1)
	## Evaluation function:
	def EvalFunc(bTimePassed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bTimePassed:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pSignificantTimePassed = App.ConditionalAI_Create(pShip, "SignificantTimePassed")
	pSignificantTimePassed.SetInterruptable(1)
	pSignificantTimePassed.SetContainedAI(pTorpRun_4)
	pSignificantTimePassed.AddCondition(pTimePassed)
	pSignificantTimePassed.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI SignificantTimePassed
	#########################################
	######### AI Builder Begin #########
	return pSignificantTimePassed  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate24(pShip, pSignificantTimePassed, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI FrontTorpsReadyFrontShieldsOk at (465, 195)
	## Conditions:
	#### Condition Ready
	pReady = App.ConditionScript_Create("Conditions.ConditionTorpsReady", "ConditionTorpsReady", pShip.GetName(), App.TGPoint3_GetModelForward())
	#### Condition SmartShields
	pSmartShields = App.ConditionScript_Create("Conditions.ConditionFlagSet", "ConditionFlagSet", "SmartShields", dKeywords)
	#### Condition FrontShieldLow
	pFrontShieldLow = App.ConditionScript_Create("Conditions.ConditionSingleShieldBelow", "ConditionSingleShieldBelow", pShip.GetName(), 0.3, App.ShieldClass.FRONT_SHIELDS)
	#### Condition SmartWeaponBalance
	pSmartWeaponBalance = App.ConditionScript_Create("Conditions.ConditionFlagSet", "ConditionFlagSet", "SmartWeaponBalance", dKeywords)
	## Evaluation function:
	def EvalFunc(bReady, bSmartShields, bFrontShieldLow, bSmartWeaponBalance):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if not bSmartWeaponBalance:
			return DONE
		if bSmartShields and bFrontShieldLow:
			return DORMANT
		if bReady:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pFrontTorpsReadyFrontShieldsOk = App.ConditionalAI_Create(pShip, "FrontTorpsReadyFrontShieldsOk")
	pFrontTorpsReadyFrontShieldsOk.SetInterruptable(1)
	pFrontTorpsReadyFrontShieldsOk.SetContainedAI(pSignificantTimePassed)
	pFrontTorpsReadyFrontShieldsOk.AddCondition(pReady)
	pFrontTorpsReadyFrontShieldsOk.AddCondition(pSmartShields)
	pFrontTorpsReadyFrontShieldsOk.AddCondition(pFrontShieldLow)
	pFrontTorpsReadyFrontShieldsOk.AddCondition(pSmartWeaponBalance)
	pFrontTorpsReadyFrontShieldsOk.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI FrontTorpsReadyFrontShieldsOk
	#########################################
	# Builder AI Dependency Object (dKeywords)
	######### AI Builder Begin #########
	return pFrontTorpsReadyFrontShieldsOk  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate25(pShip, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating PlainAI ICO_WeaponBias at (566, 102)
	pICO_WeaponBias = App.PlainAI_Create(pShip, "ICO_WeaponBias")
	pICO_WeaponBias.SetScriptModule("IntelligentCircleObject")
	pICO_WeaponBias.SetInterruptable(1)
	pScript = pICO_WeaponBias.GetScriptInstance()
	pScript.SetFollowObjectName(sInitialTarget)
	pScript.SetCircleSpeed(1.0)
	pScript.SetShieldAndWeaponImportance(0.1, 0.9)
	pScript.SetForwardBias(-0.5)
	# Done creating PlainAI ICO_WeaponBias
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	######### AI Builder Begin #########
	return pICO_WeaponBias  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate26(pShip, pICO_WeaponBias, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI UseSideArcs_ShortTime at (562, 198)
	## Conditions:
	#### Condition SideArcsFlag
	pSideArcsFlag = App.ConditionScript_Create("Conditions.ConditionFlagSet", "ConditionFlagSet", "UseSideArcs", dKeywords)
	#### Condition TimePassed
	pTimePassed = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 15.0)
	## Evaluation function:
	def EvalFunc(bSideArcsFlag, bTimePassed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bTimePassed:
			return DORMANT
		if bSideArcsFlag:
			return ACTIVE
		return DONE
	## The ConditionalAI:
	pUseSideArcs_ShortTime = App.ConditionalAI_Create(pShip, "UseSideArcs_ShortTime")
	pUseSideArcs_ShortTime.SetInterruptable(1)
	pUseSideArcs_ShortTime.SetContainedAI(pICO_WeaponBias)
	pUseSideArcs_ShortTime.AddCondition(pSideArcsFlag)
	pUseSideArcs_ShortTime.AddCondition(pTimePassed)
	pUseSideArcs_ShortTime.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI UseSideArcs_ShortTime
	#########################################
	# Builder AI Dependency Object (dKeywords)
	######### AI Builder Begin #########
	return pUseSideArcs_ShortTime  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate27(pShip, sInitialTarget, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating CompoundAI ICOMoveOut at (660, 173)
	import AI.Compound.Parts.ICOMove
	pICOMoveOut = AI.Compound.Parts.ICOMove.CreateAI(pShip, sInitialTarget, dKeywords, -1.0)
	# Done creating CompoundAI ICOMoveOut
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	# Builder AI Dependency Object (dKeywords)
	######### AI Builder Begin #########
	return pICOMoveOut  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate28(pShip, pICOMoveOut, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI RearShieldLow at (659, 239)
	## Conditions:
	#### Condition RearLow
	pRearLow = App.ConditionScript_Create("Conditions.ConditionSingleShieldBelow", "ConditionSingleShieldBelow", pShip.GetName(), 0.25, App.ShieldClass.REAR_SHIELDS)
	#### Condition SmartShields
	pSmartShields = App.ConditionScript_Create("Conditions.ConditionFlagSet", "ConditionFlagSet", "SmartShields", dKeywords)
	## Evaluation function:
	def EvalFunc(bRearLow, bSmartShields):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if not bSmartShields:
			return DONE
		if bRearLow:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pRearShieldLow = App.ConditionalAI_Create(pShip, "RearShieldLow")
	pRearShieldLow.SetInterruptable(1)
	pRearShieldLow.SetContainedAI(pICOMoveOut)
	pRearShieldLow.AddCondition(pRearLow)
	pRearShieldLow.AddCondition(pSmartShields)
	pRearShieldLow.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI RearShieldLow
	#########################################
	# Builder AI Dependency Object (dKeywords)
	######### AI Builder Begin #########
	return pRearShieldLow  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate29(pShip, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating PlainAI Flee at (657, 295)
	pFlee = App.PlainAI_Create(pShip, "Flee")
	pFlee.SetScriptModule("Flee")
	pFlee.SetInterruptable(1)
	pScript = pFlee.GetScriptInstance()
	pScript.SetFleeFromGroup(sInitialTarget)
	# Done creating PlainAI Flee
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	######### AI Builder Begin #########
	return pFlee  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate30(pShip, pRearTorpsReadyRearShieldOk, pFrontTorpsReadyFrontShieldsOk, pUseSideArcs_ShortTime, pRearShieldLow, pFlee):
	########## AI Builder End ##########
	#########################################
	# Creating PriorityListAI TooClosePriorities at (464, 354)
	pTooClosePriorities = App.PriorityListAI_Create(pShip, "TooClosePriorities")
	pTooClosePriorities.SetInterruptable(1)
	# SeqBlock is at (562, 350)
	pTooClosePriorities.AddAI(pRearTorpsReadyRearShieldOk, 1)
	pTooClosePriorities.AddAI(pFrontTorpsReadyFrontShieldsOk, 2)
	pTooClosePriorities.AddAI(pUseSideArcs_ShortTime, 3)
	pTooClosePriorities.AddAI(pRearShieldLow, 4)
	pTooClosePriorities.AddAI(pFlee, 5)
	# Done creating PriorityListAI TooClosePriorities
	#########################################
	######### AI Builder Begin #########
	return pTooClosePriorities  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate31(pShip, pTooClosePriorities, fTooFarRange, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI TooClose at (437, 410)
	## Conditions:
	#### Condition InRange
	pInRange = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", fTooFarRange, sInitialTarget, pShip.GetName())
	## Evaluation function:
	def EvalFunc(bInRange):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bInRange:
			return ACTIVE
		return DONE
	## The ConditionalAI:
	pTooClose = App.ConditionalAI_Create(pShip, "TooClose")
	pTooClose.SetInterruptable(1)
	pTooClose.SetContainedAI(pTooClosePriorities)
	pTooClose.AddCondition(pInRange)
	pTooClose.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TooClose
	#########################################
	# Builder AI Dependency Object (fTooFarRange)
	# Builder AI Dependency Object (sInitialTarget)
	######### AI Builder Begin #########
	return pTooClose  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate32(pShip, pTooFar, pTooClose):
	########## AI Builder End ##########
	#########################################
	# Creating SequenceAI Sequence at (303, 447)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(-1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (405, 446)
	pSequence.AddAI(pTooFar)
	pSequence.AddAI(pTooClose)
	# Done creating SequenceAI Sequence
	#########################################
	######### AI Builder Begin #########
	return pSequence  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate33(pShip, pSequence, sInitialTarget, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating PreprocessingAI FireAll at (351, 495)
	## Setup:
	import AI.Preprocessors
	pFireScript = apply(AI.Preprocessors.FireScript, (sInitialTarget,), dKeywords)
	for pSystem in [ pShip.GetTorpedoSystem(), pShip.GetPhaserSystem(), pShip.GetPulseWeaponSystem() ]:
		if not App.IsNull(pSystem):
			pFireScript.AddWeaponSystem( pSystem )
	## The PreprocessingAI:
	pFireAll = App.PreprocessingAI_Create(pShip, "FireAll")
	pFireAll.SetInterruptable(1)
	pFireAll.SetPreprocessingMethod(pFireScript, "Update")
	pFireAll.SetContainedAI(pSequence)
	# Done creating PreprocessingAI FireAll
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	# Builder AI Dependency Object (dKeywords)
	######### AI Builder Begin #########
	return pFireAll  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate34(pShip, pFireAll, fCloseRange, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI CloseRange at (443, 495)
	## Conditions:
	#### Condition InRange
	pInRange = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", fCloseRange, sInitialTarget, pShip.GetName())
	## Evaluation function:
	def EvalFunc(bInRange):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bInRange:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pCloseRange = App.ConditionalAI_Create(pShip, "CloseRange")
	pCloseRange.SetInterruptable(1)
	pCloseRange.SetContainedAI(pFireAll)
	pCloseRange.AddCondition(pInRange)
	pCloseRange.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI CloseRange
	#########################################
	# Builder AI Dependency Object (fCloseRange)
	# Builder AI Dependency Object (sInitialTarget)
	######### AI Builder Begin #########
	return pCloseRange  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate35(pShip, sInitialTarget, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating CompoundAI EvadeTorps at (800, 220)
	import AI.Compound.Parts.EvadeTorps
	pEvadeTorps = AI.Compound.Parts.EvadeTorps.CreateAI(pShip, sInitialTarget, dKeywords)
	# Done creating CompoundAI EvadeTorps
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	# Builder AI Dependency Object (dKeywords)
	######### AI Builder Begin #########
	return pEvadeTorps  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate36(pShip, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating PlainAI TorpRun at (905, 135)
	pTorpRun = App.PlainAI_Create(pShip, "TorpRun")
	pTorpRun.SetScriptModule("TorpedoRun")
	pTorpRun.SetInterruptable(1)
	pScript = pTorpRun.GetScriptInstance()
	pScript.SetTargetObjectName(sInitialTarget)
	pScript.SetPerpendicularMovementAdjustment(0.1)
	# Done creating PlainAI TorpRun
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	######### AI Builder Begin #########
	return pTorpRun  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate37(pShip, pTorpRun):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI TorpsReady_FwdShieldStrong at (895, 194)
	## Conditions:
	#### Condition TorpsReady
	pTorpsReady = App.ConditionScript_Create("Conditions.ConditionTorpsReady", "ConditionTorpsReady", pShip.GetName(), App.TGPoint3_GetModelForward())
	#### Condition FrontLow
	pFrontLow = App.ConditionScript_Create("Conditions.ConditionSingleShieldBelow", "ConditionSingleShieldBelow", pShip.GetName(), 0.4, App.ShieldClass.FRONT_SHIELDS)
	#### Condition UsingTorps
	pUsingTorps = App.ConditionScript_Create("Conditions.ConditionUsingWeapon", "ConditionUsingWeapon", App.CT_TORPEDO_SYSTEM)
	## Evaluation function:
	def EvalFunc(bTorpsReady, bFrontLow, bUsingTorps):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bUsingTorps and bTorpsReady and not bFrontLow:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pTorpsReady_FwdShieldStrong = App.ConditionalAI_Create(pShip, "TorpsReady_FwdShieldStrong")
	pTorpsReady_FwdShieldStrong.SetInterruptable(1)
	pTorpsReady_FwdShieldStrong.SetContainedAI(pTorpRun)
	pTorpsReady_FwdShieldStrong.AddCondition(pTorpsReady)
	pTorpsReady_FwdShieldStrong.AddCondition(pFrontLow)
	pTorpsReady_FwdShieldStrong.AddCondition(pUsingTorps)
	pTorpsReady_FwdShieldStrong.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TorpsReady_FwdShieldStrong
	#########################################
	######### AI Builder Begin #########
	return pTorpsReady_FwdShieldStrong  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate38(pShip, sInitialTarget, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating CompoundAI ICOMoveIn_2 at (994, 185)
	import AI.Compound.Parts.ICOMove
	pICOMoveIn_2 = AI.Compound.Parts.ICOMove.CreateAI(pShip, sInitialTarget, dKeywords, 0.5)
	# Done creating CompoundAI ICOMoveIn_2
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	# Builder AI Dependency Object (dKeywords)
	######### AI Builder Begin #########
	return pICOMoveIn_2  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate39(pShip, pICOMoveIn_2, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI SmartShields_2 at (938, 241)
	## Conditions:
	#### Condition SmartShieldsFlag
	pSmartShieldsFlag = App.ConditionScript_Create("Conditions.ConditionFlagSet", "ConditionFlagSet", "SmartShields", dKeywords)
	## Evaluation function:
	def EvalFunc(bSmartShieldsFlag):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bSmartShieldsFlag:
			return ACTIVE
		return DONE
	## The ConditionalAI:
	pSmartShields_2 = App.ConditionalAI_Create(pShip, "SmartShields_2")
	pSmartShields_2.SetInterruptable(1)
	pSmartShields_2.SetContainedAI(pICOMoveIn_2)
	pSmartShields_2.AddCondition(pSmartShieldsFlag)
	pSmartShields_2.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI SmartShields_2
	#########################################
	# Builder AI Dependency Object (dKeywords)
	######### AI Builder Begin #########
	return pSmartShields_2  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate40(pShip, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating PlainAI MoveIn_2 at (980, 293)
	pMoveIn_2 = App.PlainAI_Create(pShip, "MoveIn_2")
	pMoveIn_2.SetScriptModule("FollowObject")
	pMoveIn_2.SetInterruptable(1)
	pScript = pMoveIn_2.GetScriptInstance()
	pScript.SetFollowObjectName(sInitialTarget)
	# Done creating PlainAI MoveIn_2
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	######### AI Builder Begin #########
	return pMoveIn_2  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate41(pShip, pEvadeTorps, pTorpsReady_FwdShieldStrong, pSmartShields_2, pMoveIn_2):
	########## AI Builder End ##########
	#########################################
	# Creating PriorityListAI MidRangePriorities at (770, 294)
	pMidRangePriorities = App.PriorityListAI_Create(pShip, "MidRangePriorities")
	pMidRangePriorities.SetInterruptable(1)
	# SeqBlock is at (882, 293)
	pMidRangePriorities.AddAI(pEvadeTorps, 1)
	pMidRangePriorities.AddAI(pTorpsReady_FwdShieldStrong, 2)
	pMidRangePriorities.AddAI(pSmartShields_2, 3)
	pMidRangePriorities.AddAI(pMoveIn_2, 4)
	# Done creating PriorityListAI MidRangePriorities
	#########################################
	######### AI Builder Begin #########
	return pMidRangePriorities  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate42(pShip, pMidRangePriorities, sInitialTarget, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating PreprocessingAI FireAll2 at (733, 372)
	## Setup:
	import AI.Preprocessors
	pFireScript = apply(AI.Preprocessors.FireScript, (sInitialTarget,), dKeywords)
	for pSystem in [ pShip.GetTorpedoSystem(), pShip.GetPhaserSystem(), pShip.GetPulseWeaponSystem() ]:
		if not App.IsNull(pSystem):
			pFireScript.AddWeaponSystem( pSystem )
	## The PreprocessingAI:
	pFireAll2 = App.PreprocessingAI_Create(pShip, "FireAll2")
	pFireAll2.SetInterruptable(1)
	pFireAll2.SetPreprocessingMethod(pFireScript, "Update")
	pFireAll2.SetContainedAI(pMidRangePriorities)
	# Done creating PreprocessingAI FireAll2
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	# Builder AI Dependency Object (dKeywords)
	######### AI Builder Begin #########
	return pFireAll2  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate43(pShip, pFireAll2, fMidRange, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI MidRange at (553, 452)
	## Conditions:
	#### Condition InRange
	pInRange = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", fMidRange, sInitialTarget, pShip.GetName())
	## Evaluation function:
	def EvalFunc(bInRange):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bInRange:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pMidRange = App.ConditionalAI_Create(pShip, "MidRange")
	pMidRange.SetInterruptable(1)
	pMidRange.SetContainedAI(pFireAll2)
	pMidRange.AddCondition(pInRange)
	pMidRange.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI MidRange
	#########################################
	# Builder AI Dependency Object (fMidRange)
	# Builder AI Dependency Object (sInitialTarget)
	######### AI Builder Begin #########
	return pMidRange  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate44(pShip, sInitialTarget, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating CompoundAI EvadeTorps_2 at (839, 403)
	import AI.Compound.Parts.EvadeTorps
	pEvadeTorps_2 = AI.Compound.Parts.EvadeTorps.CreateAI(pShip, sInitialTarget, dKeywords)
	# Done creating CompoundAI EvadeTorps_2
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	# Builder AI Dependency Object (dKeywords)
	######### AI Builder Begin #########
	return pEvadeTorps_2  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate45(pShip, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating PlainAI MoveIn at (912, 463)
	pMoveIn = App.PlainAI_Create(pShip, "MoveIn")
	pMoveIn.SetScriptModule("FollowObject")
	pMoveIn.SetInterruptable(1)
	pScript = pMoveIn.GetScriptInstance()
	pScript.SetFollowObjectName(sInitialTarget)
	# Done creating PlainAI MoveIn
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	######### AI Builder Begin #########
	return pMoveIn  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate46(pShip, pEvadeTorps_2, pMoveIn):
	########## AI Builder End ##########
	#########################################
	# Creating PriorityListAI LongRangePriorities at (810, 511)
	pLongRangePriorities = App.PriorityListAI_Create(pShip, "LongRangePriorities")
	pLongRangePriorities.SetInterruptable(1)
	# SeqBlock is at (870, 481)
	pLongRangePriorities.AddAI(pEvadeTorps_2, 1)
	pLongRangePriorities.AddAI(pMoveIn, 2)
	# Done creating PriorityListAI LongRangePriorities
	#########################################
	######### AI Builder Begin #########
	return pLongRangePriorities  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate47(pShip, pLongRangePriorities, sInitialTarget, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating PreprocessingAI FirePulseOnly at (756, 554)
	## Setup:
	import AI.Preprocessors
	pFireScript = apply(AI.Preprocessors.FireScript, (sInitialTarget,), dKeywords)
	for pSystem in [ pShip.GetPulseWeaponSystem() ]:
		if not App.IsNull(pSystem):
			pFireScript.AddWeaponSystem( pSystem )
	## The PreprocessingAI:
	pFirePulseOnly = App.PreprocessingAI_Create(pShip, "FirePulseOnly")
	pFirePulseOnly.SetInterruptable(1)
	pFirePulseOnly.SetPreprocessingMethod(pFireScript, "Update")
	pFirePulseOnly.SetContainedAI(pLongRangePriorities)
	# Done creating PreprocessingAI FirePulseOnly
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	# Builder AI Dependency Object (dKeywords)
	######### AI Builder Begin #########
	return pFirePulseOnly  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate48(pShip, pFirePulseOnly, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI LongRange at (580, 499)
	## Conditions:
	#### Condition InRange
	pInRange = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 350.0, sInitialTarget, pShip.GetName())
	## Evaluation function:
	def EvalFunc(bInRange):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bInRange:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pLongRange = App.ConditionalAI_Create(pShip, "LongRange")
	pLongRange.SetInterruptable(1)
	pLongRange.SetContainedAI(pFirePulseOnly)
	pLongRange.AddCondition(pInRange)
	pLongRange.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI LongRange
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	######### AI Builder Begin #########
	return pLongRange  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate49(pShip, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating PlainAI InterceptTarget at (618, 562)
	pInterceptTarget = App.PlainAI_Create(pShip, "InterceptTarget")
	pInterceptTarget.SetScriptModule("Intercept")
	pInterceptTarget.SetInterruptable(1)
	pScript = pInterceptTarget.GetScriptInstance()
	pScript.SetTargetObjectName(sInitialTarget)
	# Done creating PlainAI InterceptTarget
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	######### AI Builder Begin #########
	return pInterceptTarget  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate50(pShip, pCloseRange, pMidRange, pLongRange, pInterceptTarget):
	########## AI Builder End ##########
	#########################################
	# Creating PriorityListAI PriorityList at (342, 544)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (523, 542)
	pPriorityList.AddAI(pCloseRange, 1)
	pPriorityList.AddAI(pMidRange, 2)
	pPriorityList.AddAI(pLongRange, 3)
	pPriorityList.AddAI(pInterceptTarget, 4)
	# Done creating PriorityListAI PriorityList
	#########################################
	######### AI Builder Begin #########
	return pPriorityList  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate51(pShip, pPriorityList, pAllTargetsGroup, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating PreprocessingAI SelectTarget at (244, 550)
	## Setup:
	import AI.Preprocessors
	pSelectionPreprocess = AI.Preprocessors.SelectTarget(pAllTargetsGroup)
	pSelectionPreprocess.ForceCurrentTargetString(sInitialTarget)
	## The PreprocessingAI:
	pSelectTarget = App.PreprocessingAI_Create(pShip, "SelectTarget")
	pSelectTarget.SetInterruptable(1)
	pSelectTarget.SetPreprocessingMethod(pSelectionPreprocess, "Update")
	pSelectTarget.SetContainedAI(pPriorityList)
	# Done creating PreprocessingAI SelectTarget
	#########################################
	# Builder AI Dependency Object (pAllTargetsGroup)
	# Builder AI Dependency Object (sInitialTarget)
	######### AI Builder Begin #########
	return pSelectTarget  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate52(pShip, pSelectTarget, sInitialTarget, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating CompoundAI FollowTargetThroughWarp at (426, 590)
	import AI.Compound.FollowThroughWarp
	pFollowTargetThroughWarp = AI.Compound.FollowThroughWarp.CreateAI(pShip, sInitialTarget, Keywords = dKeywords)
	# Done creating CompoundAI FollowTargetThroughWarp
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	# Builder AI Dependency Object (dKeywords)
	# Builder AI Dependency AI (SelectTarget)
	pSelectTarget.GetPreprocessingInstance().AddSetTargetTree( pFollowTargetThroughWarp )
	######### AI Builder Begin #########
	return pFollowTargetThroughWarp  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate53(pShip, pFollowTargetThroughWarp, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI FollowThroughWarpFlag at (319, 609)
	## Conditions:
	#### Condition FlagSet
	pFlagSet = App.ConditionScript_Create("Conditions.ConditionFlagSet", "ConditionFlagSet", "FollowTargetThroughWarp", dKeywords)
	## Evaluation function:
	def EvalFunc(bFlagSet):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bFlagSet:
			return ACTIVE
		return DONE
	## The ConditionalAI:
	pFollowThroughWarpFlag = App.ConditionalAI_Create(pShip, "FollowThroughWarpFlag")
	pFollowThroughWarpFlag.SetInterruptable(1)
	pFollowThroughWarpFlag.SetContainedAI(pFollowTargetThroughWarp)
	pFollowThroughWarpFlag.AddCondition(pFlagSet)
	pFollowThroughWarpFlag.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI FollowThroughWarpFlag
	#########################################
	# Builder AI Dependency Object (dKeywords)
	######### AI Builder Begin #########
	return pFollowThroughWarpFlag  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate54(pShip, pCheckWarpBeforeDeath, pNoSensorsEvasive, pSelectTarget, pFollowThroughWarpFlag):
	########## AI Builder End ##########
	#########################################
	# Creating PriorityListAI FleeAttackOrFollow at (96, 617)
	pFleeAttackOrFollow = App.PriorityListAI_Create(pShip, "FleeAttackOrFollow")
	pFleeAttackOrFollow.SetInterruptable(1)
	# SeqBlock is at (203, 616)
	pFleeAttackOrFollow.AddAI(pCheckWarpBeforeDeath, 1)
	pFleeAttackOrFollow.AddAI(pNoSensorsEvasive, 2)
	pFleeAttackOrFollow.AddAI(pSelectTarget, 3)
	pFleeAttackOrFollow.AddAI(pFollowThroughWarpFlag, 4)
	# Done creating PriorityListAI FleeAttackOrFollow
	#########################################
	######### AI Builder Begin #########
	return pFleeAttackOrFollow  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate55(pShip, pFleeAttackOrFollow, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating PreprocessingAI PowerManagement at (7, 567)
	## Setup:
	import AI.Preprocessors
	pPowerManager = AI.Preprocessors.ManagePower(0)
	## The PreprocessingAI:
	pPowerManagement = App.PreprocessingAI_Create(pShip, "PowerManagement")
	pPowerManagement.SetInterruptable(1)
	pPowerManagement.SetPreprocessingMethod(pPowerManager, "Update")
	pPowerManagement.SetContainedAI(pFleeAttackOrFollow)
	# Done creating PreprocessingAI PowerManagement
	#########################################
	# Builder AI Dependency Object (dKeywords)
	######### AI Builder Begin #########
	return pPowerManagement  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate56(pShip, pPowerManagement):
	########## AI Builder End ##########
	#########################################
	# Creating PreprocessingAI AlertLevel at (6, 616)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.RED_ALERT)
	## The PreprocessingAI:
	pAlertLevel = App.PreprocessingAI_Create(pShip, "AlertLevel")
	pAlertLevel.SetInterruptable(1)
	pAlertLevel.SetPreprocessingMethod(pScript, "Update")
	pAlertLevel.SetContainedAI(pPowerManagement)
	# Done creating PreprocessingAI AlertLevel
	#########################################
	return pAlertLevel
	######### AI Builder Begin #########
	return pAlertLevel  # Builder Return
	########## AI Builder End ##########
