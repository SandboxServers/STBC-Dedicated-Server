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

	Random = lambda fMin, fMax : App.g_kSystemWrapper.GetRandomNumber((fMax - fMin) * 1000.0) / 1000.0 - fMin

	# Range values used in the AI.
	fCloseRange = 100.0 + Random(-20, 10)
	fMidRange = 200.0 + Random(-25, 20)
	fLongRange = 350.0 + Random(-20, 10)


	######### AI Builder Begin #########
	pBuilderAI = App.BuilderAI_Create(pShip, "AlertLevel Builder", __name__)
	pBuilderAI.AddAIBlock("CheckWarpBeforeDeath", "BuilderCreate1")
	pBuilderAI.AddDependencyObject("CheckWarpBeforeDeath", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("NoSensorsEvasive", "BuilderCreate2")
	pBuilderAI.AddAIBlock("EvadeTorps_2", "BuilderCreate3")
	pBuilderAI.AddDependencyObject("EvadeTorps_2", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddDependencyObject("EvadeTorps_2", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("TorpRun_2", "BuilderCreate4")
	pBuilderAI.AddDependencyObject("TorpRun_2", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("NoStopping", "BuilderCreate5")
	pBuilderAI.AddDependency("NoStopping", "TorpRun_2")
	pBuilderAI.AddDependencyObject("NoStopping", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("StationaryAttack", "BuilderCreate6")
	pBuilderAI.AddDependencyObject("StationaryAttack", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("PriorityList_2", "BuilderCreate7")
	pBuilderAI.AddDependency("PriorityList_2", "NoStopping")
	pBuilderAI.AddDependency("PriorityList_2", "StationaryAttack")
	pBuilderAI.AddAIBlock("FwdTorpsOrPulseReady", "BuilderCreate8")
	pBuilderAI.AddDependency("FwdTorpsOrPulseReady", "PriorityList_2")
	pBuilderAI.AddDependencyObject("FwdTorpsOrPulseReady", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("RearTorpRun", "BuilderCreate9")
	pBuilderAI.AddDependencyObject("RearTorpRun", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("StillClose", "BuilderCreate10")
	pBuilderAI.AddDependency("StillClose", "RearTorpRun")
	pBuilderAI.AddDependencyObject("StillClose", "fCloseRange", fCloseRange)
	pBuilderAI.AddDependencyObject("StillClose", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("SlowRearTorpRun", "BuilderCreate11")
	pBuilderAI.AddDependencyObject("SlowRearTorpRun", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("PriorityList_3", "BuilderCreate12")
	pBuilderAI.AddDependency("PriorityList_3", "StillClose")
	pBuilderAI.AddDependency("PriorityList_3", "SlowRearTorpRun")
	pBuilderAI.AddAIBlock("RearTorpsReadySortaCloseNotInterruptable", "BuilderCreate13")
	pBuilderAI.AddDependency("RearTorpsReadySortaCloseNotInterruptable", "PriorityList_3")
	pBuilderAI.AddDependencyObject("RearTorpsReadySortaCloseNotInterruptable", "fCloseRange", fCloseRange)
	pBuilderAI.AddDependencyObject("RearTorpsReadySortaCloseNotInterruptable", "fMidRange", fMidRange)
	pBuilderAI.AddDependencyObject("RearTorpsReadySortaCloseNotInterruptable", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddDependencyObject("RearTorpsReadySortaCloseNotInterruptable", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("ICOMoveAround", "BuilderCreate14")
	pBuilderAI.AddDependencyObject("ICOMoveAround", "dKeywords", dKeywords)
	pBuilderAI.AddDependencyObject("ICOMoveAround", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("CloseRangePriorities", "BuilderCreate15")
	pBuilderAI.AddDependency("CloseRangePriorities", "EvadeTorps_2")
	pBuilderAI.AddDependency("CloseRangePriorities", "FwdTorpsOrPulseReady")
	pBuilderAI.AddDependency("CloseRangePriorities", "RearTorpsReadySortaCloseNotInterruptable")
	pBuilderAI.AddDependency("CloseRangePriorities", "ICOMoveAround")
	pBuilderAI.AddAIBlock("FireAll", "BuilderCreate16")
	pBuilderAI.AddDependency("FireAll", "CloseRangePriorities")
	pBuilderAI.AddDependencyObject("FireAll", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddDependencyObject("FireAll", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("CloseRange", "BuilderCreate17")
	pBuilderAI.AddDependency("CloseRange", "FireAll")
	pBuilderAI.AddDependencyObject("CloseRange", "fCloseRange", fCloseRange)
	pBuilderAI.AddDependencyObject("CloseRange", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("EvadeTorps_3", "BuilderCreate18")
	pBuilderAI.AddDependencyObject("EvadeTorps_3", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddDependencyObject("EvadeTorps_3", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("TorpRun", "BuilderCreate19")
	pBuilderAI.AddDependencyObject("TorpRun", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("FwdTorpsOrPulseReady_2", "BuilderCreate20")
	pBuilderAI.AddDependency("FwdTorpsOrPulseReady_2", "TorpRun")
	pBuilderAI.AddDependencyObject("FwdTorpsOrPulseReady_2", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("ICO_ShieldBiasMoveIn", "BuilderCreate21")
	pBuilderAI.AddDependencyObject("ICO_ShieldBiasMoveIn", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("FwdShieldsLow", "BuilderCreate22")
	pBuilderAI.AddDependency("FwdShieldsLow", "ICO_ShieldBiasMoveIn")
	pBuilderAI.AddDependencyObject("FwdShieldsLow", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("Follow", "BuilderCreate23")
	pBuilderAI.AddDependencyObject("Follow", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("MidRangePriorities", "BuilderCreate24")
	pBuilderAI.AddDependency("MidRangePriorities", "EvadeTorps_3")
	pBuilderAI.AddDependency("MidRangePriorities", "FwdTorpsOrPulseReady_2")
	pBuilderAI.AddDependency("MidRangePriorities", "FwdShieldsLow")
	pBuilderAI.AddDependency("MidRangePriorities", "Follow")
	pBuilderAI.AddAIBlock("FireAll2", "BuilderCreate25")
	pBuilderAI.AddDependency("FireAll2", "MidRangePriorities")
	pBuilderAI.AddDependencyObject("FireAll2", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddDependencyObject("FireAll2", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("MidRange", "BuilderCreate26")
	pBuilderAI.AddDependency("MidRange", "FireAll2")
	pBuilderAI.AddDependencyObject("MidRange", "fMidRange", fMidRange)
	pBuilderAI.AddDependencyObject("MidRange", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("EvadeTorps", "BuilderCreate27")
	pBuilderAI.AddDependencyObject("EvadeTorps", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddDependencyObject("EvadeTorps", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("MoveIn", "BuilderCreate28")
	pBuilderAI.AddDependencyObject("MoveIn", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("LongRangePriorities", "BuilderCreate29")
	pBuilderAI.AddDependency("LongRangePriorities", "EvadeTorps")
	pBuilderAI.AddDependency("LongRangePriorities", "MoveIn")
	pBuilderAI.AddAIBlock("FirePulseOnly", "BuilderCreate30")
	pBuilderAI.AddDependency("FirePulseOnly", "LongRangePriorities")
	pBuilderAI.AddDependencyObject("FirePulseOnly", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddDependencyObject("FirePulseOnly", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("LongRange", "BuilderCreate31")
	pBuilderAI.AddDependency("LongRange", "FirePulseOnly")
	pBuilderAI.AddDependencyObject("LongRange", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("InterceptTarget", "BuilderCreate32")
	pBuilderAI.AddDependencyObject("InterceptTarget", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("PriorityList", "BuilderCreate33")
	pBuilderAI.AddDependency("PriorityList", "CloseRange")
	pBuilderAI.AddDependency("PriorityList", "MidRange")
	pBuilderAI.AddDependency("PriorityList", "LongRange")
	pBuilderAI.AddDependency("PriorityList", "InterceptTarget")
	pBuilderAI.AddAIBlock("SelectTarget", "BuilderCreate34")
	pBuilderAI.AddDependency("SelectTarget", "PriorityList")
	pBuilderAI.AddDependencyObject("SelectTarget", "pAllTargetsGroup", pAllTargetsGroup)
	pBuilderAI.AddDependencyObject("SelectTarget", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("FollowTargetThroughWarp", "BuilderCreate35")
	pBuilderAI.AddDependency("FollowTargetThroughWarp", "SelectTarget")
	pBuilderAI.AddDependencyObject("FollowTargetThroughWarp", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddDependencyObject("FollowTargetThroughWarp", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("FollowThroughWarpFlag", "BuilderCreate36")
	pBuilderAI.AddDependency("FollowThroughWarpFlag", "FollowTargetThroughWarp")
	pBuilderAI.AddDependencyObject("FollowThroughWarpFlag", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("FleeAttackOrFollow", "BuilderCreate37")
	pBuilderAI.AddDependency("FleeAttackOrFollow", "CheckWarpBeforeDeath")
	pBuilderAI.AddDependency("FleeAttackOrFollow", "NoSensorsEvasive")
	pBuilderAI.AddDependency("FleeAttackOrFollow", "SelectTarget")
	pBuilderAI.AddDependency("FleeAttackOrFollow", "FollowThroughWarpFlag")
	pBuilderAI.AddAIBlock("PowerManagement", "BuilderCreate38")
	pBuilderAI.AddDependency("PowerManagement", "FleeAttackOrFollow")
	pBuilderAI.AddDependencyObject("PowerManagement", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("AlertLevel", "BuilderCreate39")
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
	# Creating CompoundAI NoSensorsEvasive at (138, 503)
	import AI.Compound.Parts.NoSensorsEvasive
	pNoSensorsEvasive = AI.Compound.Parts.NoSensorsEvasive.CreateAI(pShip)
	# Done creating CompoundAI NoSensorsEvasive
	#########################################
	######### AI Builder Begin #########
	return pNoSensorsEvasive  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate3(pShip, sInitialTarget, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating CompoundAI EvadeTorps_2 at (105, 193)
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
def BuilderCreate4(pShip, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating PlainAI TorpRun_2 at (288, 52)
	pTorpRun_2 = App.PlainAI_Create(pShip, "TorpRun_2")
	pTorpRun_2.SetScriptModule("TorpedoRun")
	pTorpRun_2.SetInterruptable(1)
	pScript = pTorpRun_2.GetScriptInstance()
	pScript.SetTargetObjectName(sInitialTarget)
	pScript.SetPerpendicularMovementAdjustment(0.5)
	# Done creating PlainAI TorpRun_2
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	######### AI Builder Begin #########
	return pTorpRun_2  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate5(pShip, pTorpRun_2, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI NoStopping at (281, 100)
	## Conditions:
	#### Condition FlagSet
	pFlagSet = App.ConditionScript_Create("Conditions.ConditionFlagSet", "ConditionFlagSet", "NeverSitStill", dKeywords)
	## Evaluation function:
	def EvalFunc(bFlagSet):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bFlagSet:
			return ACTIVE
		return DONE
	## The ConditionalAI:
	pNoStopping = App.ConditionalAI_Create(pShip, "NoStopping")
	pNoStopping.SetInterruptable(1)
	pNoStopping.SetContainedAI(pTorpRun_2)
	pNoStopping.AddCondition(pFlagSet)
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
	# Creating PlainAI StationaryAttack at (388, 102)
	pStationaryAttack = App.PlainAI_Create(pShip, "StationaryAttack")
	pStationaryAttack.SetScriptModule("StationaryAttack")
	pStationaryAttack.SetInterruptable(1)
	pScript = pStationaryAttack.GetScriptInstance()
	pScript.SetTargetObjectName(sInitialTarget)
	# Done creating PlainAI StationaryAttack
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	######### AI Builder Begin #########
	return pStationaryAttack  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate7(pShip, pNoStopping, pStationaryAttack):
	########## AI Builder End ##########
	#########################################
	# Creating PriorityListAI PriorityList_2 at (211, 143)
	pPriorityList_2 = App.PriorityListAI_Create(pShip, "PriorityList_2")
	pPriorityList_2.SetInterruptable(1)
	# SeqBlock is at (336, 150)
	pPriorityList_2.AddAI(pNoStopping, 1)
	pPriorityList_2.AddAI(pStationaryAttack, 2)
	# Done creating PriorityListAI PriorityList_2
	#########################################
	######### AI Builder Begin #########
	return pPriorityList_2  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate8(pShip, pPriorityList_2, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI FwdTorpsOrPulseReady at (208, 198)
	## Conditions:
	#### Condition TorpsReady
	pTorpsReady = App.ConditionScript_Create("Conditions.ConditionTorpsReady", "ConditionTorpsReady", pShip.GetName(), App.TGPoint3_GetModelForward())
	#### Condition PulseReady
	pPulseReady = App.ConditionScript_Create("Conditions.ConditionPulseReady", "ConditionPulseReady", pShip.GetName(), App.TGPoint3_GetModelForward())
	#### Condition AggroPulse
	pAggroPulse = App.ConditionScript_Create("Conditions.ConditionFlagSet", "ConditionFlagSet", "AggressivePulseWeapons", dKeywords)
	#### Condition UsingTorps
	pUsingTorps = App.ConditionScript_Create("Conditions.ConditionUsingWeapon", "ConditionUsingWeapon", App.CT_TORPEDO_SYSTEM)
	## Evaluation function:
	def EvalFunc(bTorpsReady, bPulseReady, bAggroPulse, bUsingTorps):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bUsingTorps and bTorpsReady)  or  (bAggroPulse and bPulseReady):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pFwdTorpsOrPulseReady = App.ConditionalAI_Create(pShip, "FwdTorpsOrPulseReady")
	pFwdTorpsOrPulseReady.SetInterruptable(1)
	pFwdTorpsOrPulseReady.SetContainedAI(pPriorityList_2)
	pFwdTorpsOrPulseReady.AddCondition(pTorpsReady)
	pFwdTorpsOrPulseReady.AddCondition(pPulseReady)
	pFwdTorpsOrPulseReady.AddCondition(pAggroPulse)
	pFwdTorpsOrPulseReady.AddCondition(pUsingTorps)
	pFwdTorpsOrPulseReady.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI FwdTorpsOrPulseReady
	#########################################
	# Builder AI Dependency Object (dKeywords)
	######### AI Builder Begin #########
	return pFwdTorpsOrPulseReady  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate9(pShip, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating PlainAI RearTorpRun at (498, 64)
	pRearTorpRun = App.PlainAI_Create(pShip, "RearTorpRun")
	pRearTorpRun.SetScriptModule("TorpedoRun")
	pRearTorpRun.SetInterruptable(1)
	pScript = pRearTorpRun.GetScriptInstance()
	pScript.SetTargetObjectName(sInitialTarget)
	pScript.SetPerpendicularMovementAdjustment(0.3)
	pScript.SetTorpDirection(App.TGPoint3_GetModelBackward())
	# Done creating PlainAI RearTorpRun
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	######### AI Builder Begin #########
	return pRearTorpRun  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate10(pShip, pRearTorpRun, fCloseRange, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI StillClose at (494, 125)
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
	pStillClose = App.ConditionalAI_Create(pShip, "StillClose")
	pStillClose.SetInterruptable(1)
	pStillClose.SetContainedAI(pRearTorpRun)
	pStillClose.AddCondition(pInRange)
	pStillClose.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI StillClose
	#########################################
	# Builder AI Dependency Object (fCloseRange)
	# Builder AI Dependency Object (sInitialTarget)
	######### AI Builder Begin #########
	return pStillClose  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate11(pShip, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating PlainAI SlowRearTorpRun at (598, 151)
	pSlowRearTorpRun = App.PlainAI_Create(pShip, "SlowRearTorpRun")
	pSlowRearTorpRun.SetScriptModule("TorpedoRun")
	pSlowRearTorpRun.SetInterruptable(1)
	pScript = pSlowRearTorpRun.GetScriptInstance()
	pScript.SetTargetObjectName(sInitialTarget)
	pScript.SetPerpendicularMovementAdjustment(0.0)
	pScript.SetTorpDirection(App.TGPoint3_GetModelBackward())
	# Done creating PlainAI SlowRearTorpRun
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	######### AI Builder Begin #########
	return pSlowRearTorpRun  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate12(pShip, pStillClose, pSlowRearTorpRun):
	########## AI Builder End ##########
	#########################################
	# Creating PriorityListAI PriorityList_3 at (383, 176)
	pPriorityList_3 = App.PriorityListAI_Create(pShip, "PriorityList_3")
	pPriorityList_3.SetInterruptable(1)
	# SeqBlock is at (524, 194)
	pPriorityList_3.AddAI(pStillClose, 1)
	pPriorityList_3.AddAI(pSlowRearTorpRun, 2)
	# Done creating PriorityListAI PriorityList_3
	#########################################
	######### AI Builder Begin #########
	return pPriorityList_3  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate13(pShip, pPriorityList_3, fCloseRange, fMidRange, sInitialTarget, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI RearTorpsReadySortaCloseNotInterruptable at (331, 228)
	## Conditions:
	#### Condition FlagSet
	pFlagSet = App.ConditionScript_Create("Conditions.ConditionFlagSet", "ConditionFlagSet", "UseRearTorps", dKeywords)
	#### Condition Ready
	pReady = App.ConditionScript_Create("Conditions.ConditionTorpsReady", "ConditionTorpsReady", pShip.GetName(), App.TGPoint3_GetModelBackward())
	#### Condition SomewhatClose
	pSomewhatClose = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", (fCloseRange + fMidRange) / 2.0, sInitialTarget, pShip.GetName())
	#### Condition UsingTorps
	pUsingTorps = App.ConditionScript_Create("Conditions.ConditionUsingWeapon", "ConditionUsingWeapon", App.CT_TORPEDO_SYSTEM)
	## Evaluation function:
	def EvalFunc(bFlagSet, bReady, bSomewhatClose, bUsingTorps):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if not bFlagSet:
			return DONE
		if bUsingTorps and bReady and bSomewhatClose:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pRearTorpsReadySortaCloseNotInterruptable = App.ConditionalAI_Create(pShip, "RearTorpsReadySortaCloseNotInterruptable")
	pRearTorpsReadySortaCloseNotInterruptable.SetInterruptable(0)
	pRearTorpsReadySortaCloseNotInterruptable.SetContainedAI(pPriorityList_3)
	pRearTorpsReadySortaCloseNotInterruptable.AddCondition(pFlagSet)
	pRearTorpsReadySortaCloseNotInterruptable.AddCondition(pReady)
	pRearTorpsReadySortaCloseNotInterruptable.AddCondition(pSomewhatClose)
	pRearTorpsReadySortaCloseNotInterruptable.AddCondition(pUsingTorps)
	pRearTorpsReadySortaCloseNotInterruptable.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI RearTorpsReadySortaCloseNotInterruptable
	#########################################
	# Builder AI Dependency Object (fCloseRange)
	# Builder AI Dependency Object (fMidRange)
	# Builder AI Dependency Object (sInitialTarget)
	# Builder AI Dependency Object (dKeywords)
	######### AI Builder Begin #########
	return pRearTorpsReadySortaCloseNotInterruptable  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate14(pShip, dKeywords, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating CompoundAI ICOMoveAround at (306, 295)
	import AI.Compound.Parts.ICOMove
	pICOMoveAround = AI.Compound.Parts.ICOMove.CreateAI(pShip, sInitialTarget, dKeywords)
	# Done creating CompoundAI ICOMoveAround
	#########################################
	# Builder AI Dependency Object (dKeywords)
	# Builder AI Dependency Object (sInitialTarget)
	######### AI Builder Begin #########
	return pICOMoveAround  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate15(pShip, pEvadeTorps_2, pFwdTorpsOrPulseReady, pRearTorpsReadySortaCloseNotInterruptable, pICOMoveAround):
	########## AI Builder End ##########
	#########################################
	# Creating PriorityListAI CloseRangePriorities at (30, 326)
	pCloseRangePriorities = App.PriorityListAI_Create(pShip, "CloseRangePriorities")
	pCloseRangePriorities.SetInterruptable(1)
	# SeqBlock is at (205, 287)
	pCloseRangePriorities.AddAI(pEvadeTorps_2, 1)
	pCloseRangePriorities.AddAI(pFwdTorpsOrPulseReady, 2)
	pCloseRangePriorities.AddAI(pRearTorpsReadySortaCloseNotInterruptable, 3)
	pCloseRangePriorities.AddAI(pICOMoveAround, 4)
	# Done creating PriorityListAI CloseRangePriorities
	#########################################
	######### AI Builder Begin #########
	return pCloseRangePriorities  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate16(pShip, pCloseRangePriorities, sInitialTarget, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating PreprocessingAI FireAll at (27, 382)
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
	pFireAll.SetContainedAI(pCloseRangePriorities)
	# Done creating PreprocessingAI FireAll
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	# Builder AI Dependency Object (dKeywords)
	######### AI Builder Begin #########
	return pFireAll  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate17(pShip, pFireAll, fCloseRange, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI CloseRange at (253, 434)
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
def BuilderCreate18(pShip, sInitialTarget, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating CompoundAI EvadeTorps_3 at (721, 211)
	import AI.Compound.Parts.EvadeTorps
	pEvadeTorps_3 = AI.Compound.Parts.EvadeTorps.CreateAI(pShip, sInitialTarget, dKeywords)
	# Done creating CompoundAI EvadeTorps_3
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	# Builder AI Dependency Object (dKeywords)
	######### AI Builder Begin #########
	return pEvadeTorps_3  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate19(pShip, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating PlainAI TorpRun at (814, 157)
	pTorpRun = App.PlainAI_Create(pShip, "TorpRun")
	pTorpRun.SetScriptModule("TorpedoRun")
	pTorpRun.SetInterruptable(1)
	pScript = pTorpRun.GetScriptInstance()
	pScript.SetTargetObjectName(sInitialTarget)
	pScript.SetPerpendicularMovementAdjustment(0.9)
	# Done creating PlainAI TorpRun
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	######### AI Builder Begin #########
	return pTorpRun  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate20(pShip, pTorpRun, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI FwdTorpsOrPulseReady_2 at (817, 212)
	## Conditions:
	#### Condition TorpsReady
	pTorpsReady = App.ConditionScript_Create("Conditions.ConditionTorpsReady", "ConditionTorpsReady", pShip.GetName(), App.TGPoint3_GetModelForward())
	#### Condition PulseReady
	pPulseReady = App.ConditionScript_Create("Conditions.ConditionPulseReady", "ConditionPulseReady", pShip.GetName(), App.TGPoint3_GetModelForward())
	#### Condition AggroPulse
	pAggroPulse = App.ConditionScript_Create("Conditions.ConditionFlagSet", "ConditionFlagSet", "AggressivePulseWeapons", dKeywords)
	#### Condition UsingTorps
	pUsingTorps = App.ConditionScript_Create("Conditions.ConditionUsingWeapon", "ConditionUsingWeapon", App.CT_TORPEDO_SYSTEM)
	## Evaluation function:
	def EvalFunc(bTorpsReady, bPulseReady, bAggroPulse, bUsingTorps):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bUsingTorps and bTorpsReady)  or  (bAggroPulse and bPulseReady):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pFwdTorpsOrPulseReady_2 = App.ConditionalAI_Create(pShip, "FwdTorpsOrPulseReady_2")
	pFwdTorpsOrPulseReady_2.SetInterruptable(1)
	pFwdTorpsOrPulseReady_2.SetContainedAI(pTorpRun)
	pFwdTorpsOrPulseReady_2.AddCondition(pTorpsReady)
	pFwdTorpsOrPulseReady_2.AddCondition(pPulseReady)
	pFwdTorpsOrPulseReady_2.AddCondition(pAggroPulse)
	pFwdTorpsOrPulseReady_2.AddCondition(pUsingTorps)
	pFwdTorpsOrPulseReady_2.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI FwdTorpsOrPulseReady_2
	#########################################
	# Builder AI Dependency Object (dKeywords)
	######### AI Builder Begin #########
	return pFwdTorpsOrPulseReady_2  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate21(pShip, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating PlainAI ICO_ShieldBiasMoveIn at (911, 154)
	pICO_ShieldBiasMoveIn = App.PlainAI_Create(pShip, "ICO_ShieldBiasMoveIn")
	pICO_ShieldBiasMoveIn.SetScriptModule("IntelligentCircleObject")
	pICO_ShieldBiasMoveIn.SetInterruptable(1)
	pScript = pICO_ShieldBiasMoveIn.GetScriptInstance()
	pScript.SetFollowObjectName(sInitialTarget)
	pScript.SetShieldAndWeaponImportance(1.0, 0.0)
	pScript.SetForwardBias(0.5)
	# Done creating PlainAI ICO_ShieldBiasMoveIn
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	######### AI Builder Begin #########
	return pICO_ShieldBiasMoveIn  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate22(pShip, pICO_ShieldBiasMoveIn, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI FwdShieldsLow at (910, 211)
	## Conditions:
	#### Condition ShieldLow
	pShieldLow = App.ConditionScript_Create("Conditions.ConditionSingleShieldBelow", "ConditionSingleShieldBelow", pShip.GetName(), 0.25, App.ShieldClass.FRONT_SHIELDS)
	#### Condition SmartShields
	pSmartShields = App.ConditionScript_Create("Conditions.ConditionFlagSet", "ConditionFlagSet", "SmartShields", dKeywords)
	## Evaluation function:
	def EvalFunc(bShieldLow, bSmartShields):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if not bSmartShields:
			return DONE
		if bShieldLow:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pFwdShieldsLow = App.ConditionalAI_Create(pShip, "FwdShieldsLow")
	pFwdShieldsLow.SetInterruptable(1)
	pFwdShieldsLow.SetContainedAI(pICO_ShieldBiasMoveIn)
	pFwdShieldsLow.AddCondition(pShieldLow)
	pFwdShieldsLow.AddCondition(pSmartShields)
	pFwdShieldsLow.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI FwdShieldsLow
	#########################################
	# Builder AI Dependency Object (dKeywords)
	######### AI Builder Begin #########
	return pFwdShieldsLow  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate23(pShip, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating PlainAI Follow at (958, 309)
	pFollow = App.PlainAI_Create(pShip, "Follow")
	pFollow.SetScriptModule("FollowObject")
	pFollow.SetInterruptable(1)
	pScript = pFollow.GetScriptInstance()
	pScript.SetFollowObjectName(sInitialTarget)
	# Done creating PlainAI Follow
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	######### AI Builder Begin #########
	return pFollow  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate24(pShip, pEvadeTorps_3, pFwdTorpsOrPulseReady_2, pFwdShieldsLow, pFollow):
	########## AI Builder End ##########
	#########################################
	# Creating PriorityListAI MidRangePriorities at (731, 344)
	pMidRangePriorities = App.PriorityListAI_Create(pShip, "MidRangePriorities")
	pMidRangePriorities.SetInterruptable(1)
	# SeqBlock is at (868, 347)
	pMidRangePriorities.AddAI(pEvadeTorps_3, 1)
	pMidRangePriorities.AddAI(pFwdTorpsOrPulseReady_2, 2)
	pMidRangePriorities.AddAI(pFwdShieldsLow, 3)
	pMidRangePriorities.AddAI(pFollow, 4)
	# Done creating PriorityListAI MidRangePriorities
	#########################################
	######### AI Builder Begin #########
	return pMidRangePriorities  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate25(pShip, pMidRangePriorities, sInitialTarget, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating PreprocessingAI FireAll2 at (618, 350)
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
def BuilderCreate26(pShip, pFireAll2, fMidRange, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI MidRange at (366, 380)
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
def BuilderCreate27(pShip, sInitialTarget, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating CompoundAI EvadeTorps at (837, 426)
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
def BuilderCreate28(pShip, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating PlainAI MoveIn at (927, 497)
	pMoveIn = App.PlainAI_Create(pShip, "MoveIn")
	pMoveIn.SetScriptModule("Intercept")
	pMoveIn.SetInterruptable(1)
	pScript = pMoveIn.GetScriptInstance()
	pScript.SetTargetObjectName(sInitialTarget)
	pScript.SetInterceptDistance(0)
	# Done creating PlainAI MoveIn
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	######### AI Builder Begin #########
	return pMoveIn  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate29(pShip, pEvadeTorps, pMoveIn):
	########## AI Builder End ##########
	#########################################
	# Creating PriorityListAI LongRangePriorities at (710, 462)
	pLongRangePriorities = App.PriorityListAI_Create(pShip, "LongRangePriorities")
	pLongRangePriorities.SetInterruptable(1)
	# SeqBlock is at (856, 495)
	pLongRangePriorities.AddAI(pEvadeTorps, 1)
	pLongRangePriorities.AddAI(pMoveIn, 2)
	# Done creating PriorityListAI LongRangePriorities
	#########################################
	######### AI Builder Begin #########
	return pLongRangePriorities  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate30(pShip, pLongRangePriorities, sInitialTarget, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating PreprocessingAI FirePulseOnly at (612, 462)
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
def BuilderCreate31(pShip, pFirePulseOnly, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI LongRange at (380, 441)
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
def BuilderCreate32(pShip, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating PlainAI InterceptTarget at (369, 540)
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
def BuilderCreate33(pShip, pCloseRange, pMidRange, pLongRange, pInterceptTarget):
	########## AI Builder End ##########
	#########################################
	# Creating PriorityListAI PriorityList at (228, 500)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (326, 480)
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
def BuilderCreate34(pShip, pPriorityList, pAllTargetsGroup, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating PreprocessingAI SelectTarget at (226, 550)
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
def BuilderCreate35(pShip, pSelectTarget, sInitialTarget, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating CompoundAI FollowTargetThroughWarp at (424, 589)
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
def BuilderCreate36(pShip, pFollowTargetThroughWarp, dKeywords):
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
def BuilderCreate37(pShip, pCheckWarpBeforeDeath, pNoSensorsEvasive, pSelectTarget, pFollowThroughWarpFlag):
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
def BuilderCreate38(pShip, pFleeAttackOrFollow, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating PreprocessingAI PowerManagement at (5, 566)
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
def BuilderCreate39(pShip, pPowerManagement):
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
