	######### AI Builder Begin #########
## BUILDER AI
##  This AI file has been mauled by the MakeBuilderAI script.
##  Modify at your own risk.
##  Or run MakeBuilderAI(filename, 1) to remove the BuilderAI code.
	########## AI Builder End ##########
import App

def CreateAI(pShip, *lpTargets, **dKeywords):
	# Special handling for the "Keywords" keyword.
	try:
		dKeywords = dKeywords["Keywords"]
	except: pass

	# Make a group for all the targets...
	pAllTargetsGroup = App.ObjectGroup_ForceToGroup(lpTargets)
	sInitialTarget = pAllTargetsGroup.GetNameTuple()[0]

	######### AI Builder Begin #########
	pBuilderAI = App.BuilderAI_Create(pShip, "AlertLevel Builder", __name__)
	pBuilderAI.AddAIBlock("WarpBeforeDeath", "BuilderCreate1")
	pBuilderAI.AddDependencyObject("WarpBeforeDeath", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("NoSensorsEvasive", "BuilderCreate2")
	pBuilderAI.AddAIBlock("EvadeIncomingTorps", "BuilderCreate3")
	pBuilderAI.AddDependencyObject("EvadeIncomingTorps", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("Intercept", "BuilderCreate4")
	pBuilderAI.AddDependencyObject("Intercept", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("WayTooFar", "BuilderCreate5")
	pBuilderAI.AddDependency("WayTooFar", "Intercept")
	pBuilderAI.AddDependencyObject("WayTooFar", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("EvadeTorps", "BuilderCreate6")
	pBuilderAI.AddDependencyObject("EvadeTorps", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddDependencyObject("EvadeTorps", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("Torprun", "BuilderCreate7")
	pBuilderAI.AddDependencyObject("Torprun", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("PriorityList", "BuilderCreate8")
	pBuilderAI.AddDependency("PriorityList", "EvadeTorps")
	pBuilderAI.AddDependency("PriorityList", "Torprun")
	pBuilderAI.AddAIBlock("FarEnough_TimeNotPassed", "BuilderCreate9")
	pBuilderAI.AddDependency("FarEnough_TimeNotPassed", "PriorityList")
	pBuilderAI.AddDependencyObject("FarEnough_TimeNotPassed", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("RearTorpRun", "BuilderCreate10")
	pBuilderAI.AddDependencyObject("RearTorpRun", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("RearTorpsReady", "BuilderCreate11")
	pBuilderAI.AddDependency("RearTorpsReady", "RearTorpRun")
	pBuilderAI.AddDependencyObject("RearTorpsReady", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("EvadeTorps_2_2", "BuilderCreate12")
	pBuilderAI.AddDependencyObject("EvadeTorps_2_2", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddDependencyObject("EvadeTorps_2_2", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("Flee_2", "BuilderCreate13")
	pBuilderAI.AddDependencyObject("Flee_2", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("PriorityList_4_2", "BuilderCreate14")
	pBuilderAI.AddDependency("PriorityList_4_2", "EvadeTorps_2_2")
	pBuilderAI.AddDependency("PriorityList_4_2", "Flee_2")
	pBuilderAI.AddAIBlock("NeedPower_OrTimeShort", "BuilderCreate15")
	pBuilderAI.AddDependency("NeedPower_OrTimeShort", "PriorityList_4_2")
	pBuilderAI.AddAIBlock("EvadeTorps_2", "BuilderCreate16")
	pBuilderAI.AddDependencyObject("EvadeTorps_2", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddDependencyObject("EvadeTorps_2", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("Flee", "BuilderCreate17")
	pBuilderAI.AddDependencyObject("Flee", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("PriorityList_4", "BuilderCreate18")
	pBuilderAI.AddDependency("PriorityList_4", "EvadeTorps_2")
	pBuilderAI.AddDependency("PriorityList_4", "Flee")
	pBuilderAI.AddAIBlock("ShortTime", "BuilderCreate19")
	pBuilderAI.AddDependency("ShortTime", "PriorityList_4")
	pBuilderAI.AddAIBlock("FaceTarget", "BuilderCreate20")
	pBuilderAI.AddDependencyObject("FaceTarget", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("PriorityList_5", "BuilderCreate21")
	pBuilderAI.AddDependency("PriorityList_5", "ShortTime")
	pBuilderAI.AddDependency("PriorityList_5", "FaceTarget")
	pBuilderAI.AddAIBlock("Cloak", "BuilderCreate22")
	pBuilderAI.AddDependency("Cloak", "PriorityList_5")
	pBuilderAI.AddAIBlock("Sequence", "BuilderCreate23")
	pBuilderAI.AddDependency("Sequence", "NeedPower_OrTimeShort")
	pBuilderAI.AddDependency("Sequence", "Cloak")
	pBuilderAI.AddAIBlock("PriorityList_3", "BuilderCreate24")
	pBuilderAI.AddDependency("PriorityList_3", "RearTorpsReady")
	pBuilderAI.AddDependency("PriorityList_3", "Sequence")
	pBuilderAI.AddAIBlock("TooClose_ShortTime", "BuilderCreate25")
	pBuilderAI.AddDependency("TooClose_ShortTime", "PriorityList_3")
	pBuilderAI.AddDependencyObject("TooClose_ShortTime", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("OuterSequence", "BuilderCreate26")
	pBuilderAI.AddDependency("OuterSequence", "FarEnough_TimeNotPassed")
	pBuilderAI.AddDependency("OuterSequence", "TooClose_ShortTime")
	pBuilderAI.AddAIBlock("PriorityList_2", "BuilderCreate27")
	pBuilderAI.AddDependency("PriorityList_2", "EvadeIncomingTorps")
	pBuilderAI.AddDependency("PriorityList_2", "WayTooFar")
	pBuilderAI.AddDependency("PriorityList_2", "OuterSequence")
	pBuilderAI.AddAIBlock("Fire", "BuilderCreate28")
	pBuilderAI.AddDependency("Fire", "PriorityList_2")
	pBuilderAI.AddDependencyObject("Fire", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddDependencyObject("Fire", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("SelectTarget", "BuilderCreate29")
	pBuilderAI.AddDependency("SelectTarget", "Fire")
	pBuilderAI.AddDependencyObject("SelectTarget", "pAllTargetsGroup", pAllTargetsGroup)
	pBuilderAI.AddDependencyObject("SelectTarget", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("FollowTargetThroughWarp", "BuilderCreate30")
	pBuilderAI.AddDependency("FollowTargetThroughWarp", "SelectTarget")
	pBuilderAI.AddDependencyObject("FollowTargetThroughWarp", "dKeywords", dKeywords)
	pBuilderAI.AddDependencyObject("FollowTargetThroughWarp", "sInitialTarget", sInitialTarget)
	pBuilderAI.AddAIBlock("FollowThroughWarpFlag", "BuilderCreate31")
	pBuilderAI.AddDependency("FollowThroughWarpFlag", "FollowTargetThroughWarp")
	pBuilderAI.AddDependencyObject("FollowThroughWarpFlag", "dKeywords", dKeywords)
	pBuilderAI.AddAIBlock("FleeAttackOrFollow", "BuilderCreate32")
	pBuilderAI.AddDependency("FleeAttackOrFollow", "WarpBeforeDeath")
	pBuilderAI.AddDependency("FleeAttackOrFollow", "NoSensorsEvasive")
	pBuilderAI.AddDependency("FleeAttackOrFollow", "SelectTarget")
	pBuilderAI.AddDependency("FleeAttackOrFollow", "FollowThroughWarpFlag")
	pBuilderAI.AddAIBlock("PowerManagement", "BuilderCreate33")
	pBuilderAI.AddDependency("PowerManagement", "FleeAttackOrFollow")
	pBuilderAI.AddAIBlock("AlertLevel", "BuilderCreate34")
	pBuilderAI.AddDependency("AlertLevel", "PowerManagement")
	return pBuilderAI # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate1(pShip, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating CompoundAI WarpBeforeDeath at (26, 406)
	import AI.Compound.Parts.WarpBeforeDeath
	pWarpBeforeDeath = AI.Compound.Parts.WarpBeforeDeath.CreateAI(pShip, dKeywords)
	# Done creating CompoundAI WarpBeforeDeath
	#########################################
	# Builder AI Dependency Object (dKeywords)
	######### AI Builder Begin #########
	return pWarpBeforeDeath  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate2(pShip):
	########## AI Builder End ##########
	#########################################
	# Creating CompoundAI NoSensorsEvasive at (24, 356)
	import AI.Compound.Parts.NoSensorsEvasive
	pNoSensorsEvasive = AI.Compound.Parts.NoSensorsEvasive.CreateAI(pShip)
	# Done creating CompoundAI NoSensorsEvasive
	#########################################
	######### AI Builder Begin #########
	return pNoSensorsEvasive  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate3(pShip, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating CompoundAI EvadeIncomingTorps at (68, 170)
	import AI.Compound.Parts.EvadeTorps
	pEvadeIncomingTorps = AI.Compound.Parts.EvadeTorps.CreateAI(pShip, None, dKeywords)
	# Done creating CompoundAI EvadeIncomingTorps
	#########################################
	# Builder AI Dependency Object (dKeywords)

	######### AI Builder Begin #########
	return pEvadeIncomingTorps  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate4(pShip, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating PlainAI Intercept at (166, 74)
	pIntercept = App.PlainAI_Create(pShip, "Intercept")
	pIntercept.SetScriptModule("Intercept")
	pIntercept.SetInterruptable(1)
	pScript = pIntercept.GetScriptInstance()
	pScript.SetTargetObjectName(sInitialTarget)
	pScript.SetAddObjectRadius(1)
	# Done creating PlainAI Intercept
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	######### AI Builder Begin #########
	return pIntercept  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate5(pShip, pIntercept, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI WayTooFar at (163, 124)
	## Conditions:
	#### Condition Near
	pNear = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 200.0, sInitialTarget, pShip.GetName())
	## Evaluation function:
	def EvalFunc(bNear):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bNear:
			return DORMANT
		return ACTIVE
	## The ConditionalAI:
	pWayTooFar = App.ConditionalAI_Create(pShip, "WayTooFar")
	pWayTooFar.SetInterruptable(1)
	pWayTooFar.SetContainedAI(pIntercept)
	pWayTooFar.AddCondition(pNear)
	pWayTooFar.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI WayTooFar
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	######### AI Builder Begin #########
	return pWayTooFar  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate6(pShip, sInitialTarget, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating CompoundAI EvadeTorps at (391, 25)
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
def BuilderCreate7(pShip, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating PlainAI Torprun at (492, 26)
	pTorprun = App.PlainAI_Create(pShip, "Torprun")
	pTorprun.SetScriptModule("TorpedoRun")
	pTorprun.SetInterruptable(1)
	pScript = pTorprun.GetScriptInstance()
	pScript.SetTargetObjectName(sInitialTarget)
	pScript.SetPerpendicularMovementAdjustment(0.3)
	# Done creating PlainAI Torprun
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	######### AI Builder Begin #########
	return pTorprun  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate8(pShip, pEvadeTorps, pTorprun):
	########## AI Builder End ##########
	#########################################
	# Creating PriorityListAI PriorityList at (272, 108)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (434, 80)
	pPriorityList.AddAI(pEvadeTorps, 1)
	pPriorityList.AddAI(pTorprun, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	######### AI Builder Begin #########
	return pPriorityList  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate9(pShip, pPriorityList, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI FarEnough_TimeNotPassed at (269, 167)
	## Conditions:
	#### Condition InRange
	pInRange = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 50, sInitialTarget, pShip.GetName())
	#### Condition TimePassed
	pTimePassed = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 15.0)
	## Evaluation function:
	def EvalFunc(bInRange, bTimePassed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if not bTimePassed:
			return ACTIVE
		if bInRange:
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pFarEnough_TimeNotPassed = App.ConditionalAI_Create(pShip, "FarEnough_TimeNotPassed")
	pFarEnough_TimeNotPassed.SetInterruptable(1)
	pFarEnough_TimeNotPassed.SetContainedAI(pPriorityList)
	pFarEnough_TimeNotPassed.AddCondition(pInRange)
	pFarEnough_TimeNotPassed.AddCondition(pTimePassed)
	pFarEnough_TimeNotPassed.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI FarEnough_TimeNotPassed
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	######### AI Builder Begin #########
	return pFarEnough_TimeNotPassed  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate10(pShip, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating PlainAI RearTorpRun at (502, 124)
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
def BuilderCreate11(pShip, pRearTorpRun, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI RearTorpsReady at (478, 177)
	## Conditions:
	#### Condition Ready
	pReady = App.ConditionScript_Create("Conditions.ConditionTorpsReady", "ConditionTorpsReady", pShip.GetName(), App.TGPoint3_GetModelBackward())
	#### Condition InUse
	pInUse = App.ConditionScript_Create("Conditions.ConditionUsingWeapon", "ConditionUsingWeapon", App.CT_TORPEDO_SYSTEM)
	#### Condition 
	p = App.ConditionScript_Create("Conditions.ConditionFlagSet", "ConditionFlagSet", "UseRearTorps", dKeywords)
	## Evaluation function:
	def EvalFunc(bReady, bInUse, b):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bReady and bInUse:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pRearTorpsReady = App.ConditionalAI_Create(pShip, "RearTorpsReady")
	pRearTorpsReady.SetInterruptable(1)
	pRearTorpsReady.SetContainedAI(pRearTorpRun)
	pRearTorpsReady.AddCondition(pReady)
	pRearTorpsReady.AddCondition(pInUse)
	pRearTorpsReady.AddCondition(p)
	pRearTorpsReady.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI RearTorpsReady
	#########################################
	# Builder AI Dependency Object (dKeywords)
	######### AI Builder Begin #########
	return pRearTorpsReady  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate12(pShip, sInitialTarget, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating CompoundAI EvadeTorps_2_2 at (611, 73)
	import AI.Compound.Parts.EvadeTorps
	pEvadeTorps_2_2 = AI.Compound.Parts.EvadeTorps.CreateAI(pShip, sInitialTarget, dKeywords)
	# Done creating CompoundAI EvadeTorps_2_2
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	# Builder AI Dependency Object (dKeywords)
	######### AI Builder Begin #########
	return pEvadeTorps_2_2  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate13(pShip, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating PlainAI Flee_2 at (684, 111)
	pFlee_2 = App.PlainAI_Create(pShip, "Flee_2")
	pFlee_2.SetScriptModule("Flee")
	pFlee_2.SetInterruptable(1)
	pScript = pFlee_2.GetScriptInstance()
	pScript.SetFleeFromGroup(sInitialTarget)
	# Done creating PlainAI Flee_2
	#########################################
	# Builder AI Dependency Object (sInitialTarget)

	######### AI Builder Begin #########
	return pFlee_2  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate14(pShip, pEvadeTorps_2_2, pFlee_2):
	########## AI Builder End ##########
	#########################################
	# Creating PriorityListAI PriorityList_4_2 at (596, 180)
	pPriorityList_4_2 = App.PriorityListAI_Create(pShip, "PriorityList_4_2")
	pPriorityList_4_2.SetInterruptable(1)
	# SeqBlock is at (705, 167)
	pPriorityList_4_2.AddAI(pEvadeTorps_2_2, 1)
	pPriorityList_4_2.AddAI(pFlee_2, 2)
	# Done creating PriorityListAI PriorityList_4_2
	#########################################
	######### AI Builder Begin #########
	return pPriorityList_4_2  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate15(pShip, pPriorityList_4_2):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI NeedPower_OrTimeShort at (597, 235)
	## Conditions:
	#### Condition PowerLow
	pPowerLow = App.ConditionScript_Create("Conditions.ConditionPowerBelow", "ConditionPowerBelow", pShip, 1, 0.8)
	#### Condition TimePassed
	pTimePassed = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 55.0)
	## Evaluation function:
	def EvalFunc(bPowerLow, bTimePassed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bTimePassed:
			return ACTIVE
		if bPowerLow:
			return ACTIVE
		return DONE
	## The ConditionalAI:
	pNeedPower_OrTimeShort = App.ConditionalAI_Create(pShip, "NeedPower_OrTimeShort")
	pNeedPower_OrTimeShort.SetInterruptable(1)
	pNeedPower_OrTimeShort.SetContainedAI(pPriorityList_4_2)
	pNeedPower_OrTimeShort.AddCondition(pPowerLow)
	pNeedPower_OrTimeShort.AddCondition(pTimePassed)
	pNeedPower_OrTimeShort.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI NeedPower_OrTimeShort
	#########################################
	######### AI Builder Begin #########
	return pNeedPower_OrTimeShort  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate16(pShip, sInitialTarget, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating CompoundAI EvadeTorps_2 at (779, 102)
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
def BuilderCreate17(pShip, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating PlainAI Flee at (838, 136)
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
def BuilderCreate18(pShip, pEvadeTorps_2, pFlee):
	########## AI Builder End ##########
	#########################################
	# Creating PriorityListAI PriorityList_4 at (733, 204)
	pPriorityList_4 = App.PriorityListAI_Create(pShip, "PriorityList_4")
	pPriorityList_4.SetInterruptable(1)
	# SeqBlock is at (848, 212)
	pPriorityList_4.AddAI(pEvadeTorps_2, 1)
	pPriorityList_4.AddAI(pFlee, 2)
	# Done creating PriorityListAI PriorityList_4
	#########################################
	######### AI Builder Begin #########
	return pPriorityList_4  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate19(pShip, pPriorityList_4):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI ShortTime at (745, 265)
	## Conditions:
	#### Condition TimePassed
	pTimePassed = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 30.0)
	## Evaluation function:
	def EvalFunc(bTimePassed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bTimePassed:
			return DORMANT
		return ACTIVE
	## The ConditionalAI:
	pShortTime = App.ConditionalAI_Create(pShip, "ShortTime")
	pShortTime.SetInterruptable(1)
	pShortTime.SetContainedAI(pPriorityList_4)
	pShortTime.AddCondition(pTimePassed)
	pShortTime.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI ShortTime
	#########################################
	######### AI Builder Begin #########
	return pShortTime  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate20(pShip, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating PlainAI FaceTarget at (836, 291)
	pFaceTarget = App.PlainAI_Create(pShip, "FaceTarget")
	pFaceTarget.SetScriptModule("TurnToOrientation")
	pFaceTarget.SetInterruptable(1)
	pScript = pFaceTarget.GetScriptInstance()
	pScript.SetObjectName(sInitialTarget)
	# Done creating PlainAI FaceTarget
	#########################################
	# Builder AI Dependency Object (sInitialTarget)

	######### AI Builder Begin #########
	return pFaceTarget  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate21(pShip, pShortTime, pFaceTarget):
	########## AI Builder End ##########
	#########################################
	# Creating PriorityListAI PriorityList_5 at (695, 319)
	pPriorityList_5 = App.PriorityListAI_Create(pShip, "PriorityList_5")
	pPriorityList_5.SetInterruptable(1)
	# SeqBlock is at (814, 349)
	pPriorityList_5.AddAI(pShortTime, 1)
	pPriorityList_5.AddAI(pFaceTarget, 2)
	# Done creating PriorityListAI PriorityList_5
	#########################################
	######### AI Builder Begin #########
	return pPriorityList_5  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate22(pShip, pPriorityList_5):
	########## AI Builder End ##########
	#########################################
	# Creating PreprocessingAI Cloak at (636, 366)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.CloakShip(1)
	## The PreprocessingAI:
	pCloak = App.PreprocessingAI_Create(pShip, "Cloak")
	pCloak.SetInterruptable(1)
	pCloak.SetPreprocessingMethod(pScript, "Update")
	pCloak.SetContainedAI(pPriorityList_5)
	# Done creating PreprocessingAI Cloak
	#########################################
	######### AI Builder Begin #########
	return pCloak  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate23(pShip, pNeedPower_OrTimeShort, pCloak):
	########## AI Builder End ##########
	#########################################
	# Creating SequenceAI Sequence at (508, 303)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(-1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (624, 313)
	pSequence.AddAI(pNeedPower_OrTimeShort)
	pSequence.AddAI(pCloak)
	# Done creating SequenceAI Sequence
	#########################################
	######### AI Builder Begin #########
	return pSequence  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate24(pShip, pRearTorpsReady, pSequence):
	########## AI Builder End ##########
	#########################################
	# Creating PriorityListAI PriorityList_3 at (376, 239)
	pPriorityList_3 = App.PriorityListAI_Create(pShip, "PriorityList_3")
	pPriorityList_3.SetInterruptable(1)
	# SeqBlock is at (472, 248)
	pPriorityList_3.AddAI(pRearTorpsReady, 1)
	pPriorityList_3.AddAI(pSequence, 2)
	# Done creating PriorityListAI PriorityList_3
	#########################################
	######### AI Builder Begin #########
	return pPriorityList_3  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate25(pShip, pPriorityList_3, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI TooClose_ShortTime at (368, 298)
	## Conditions:
	#### Condition InRange
	pInRange = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 100, sInitialTarget, pShip.GetName())
	#### Condition TimePassed
	pTimePassed = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 60.0)
	## Evaluation function:
	def EvalFunc(bInRange, bTimePassed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bTimePassed:
			return DONE
		if bInRange:
			return ACTIVE
		return DONE
	## The ConditionalAI:
	pTooClose_ShortTime = App.ConditionalAI_Create(pShip, "TooClose_ShortTime")
	pTooClose_ShortTime.SetInterruptable(1)
	pTooClose_ShortTime.SetContainedAI(pPriorityList_3)
	pTooClose_ShortTime.AddCondition(pInRange)
	pTooClose_ShortTime.AddCondition(pTimePassed)
	pTooClose_ShortTime.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TooClose_ShortTime
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	######### AI Builder Begin #########
	return pTooClose_ShortTime  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate26(pShip, pFarEnough_TimeNotPassed, pTooClose_ShortTime):
	########## AI Builder End ##########
	#########################################
	# Creating SequenceAI OuterSequence at (218, 300)
	pOuterSequence = App.SequenceAI_Create(pShip, "OuterSequence")
	pOuterSequence.SetInterruptable(1)
	pOuterSequence.SetLoopCount(-1)
	pOuterSequence.SetResetIfInterrupted(1)
	pOuterSequence.SetDoubleCheckAllDone(1)
	pOuterSequence.SetSkipDormant(0)
	# SeqBlock is at (321, 305)
	pOuterSequence.AddAI(pFarEnough_TimeNotPassed)
	pOuterSequence.AddAI(pTooClose_ShortTime)
	# Done creating SequenceAI OuterSequence
	#########################################
	######### AI Builder Begin #########
	return pOuterSequence  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate27(pShip, pEvadeIncomingTorps, pWayTooFar, pOuterSequence):
	########## AI Builder End ##########
	#########################################
	# Creating PriorityListAI PriorityList_2 at (43, 252)
	pPriorityList_2 = App.PriorityListAI_Create(pShip, "PriorityList_2")
	pPriorityList_2.SetInterruptable(1)
	# SeqBlock is at (192, 262)
	pPriorityList_2.AddAI(pEvadeIncomingTorps, 1)
	pPriorityList_2.AddAI(pWayTooFar, 2)
	pPriorityList_2.AddAI(pOuterSequence, 3)
	# Done creating PriorityListAI PriorityList_2
	#########################################
	######### AI Builder Begin #########
	return pPriorityList_2  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate28(pShip, pPriorityList_2, sInitialTarget, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating PreprocessingAI Fire at (113, 310)
	## Setup:
	import AI.Preprocessors
	pFiringPreprocess = apply(AI.Preprocessors.FireScript, (sInitialTarget,), dKeywords)
	for pSystem in [ pShip.GetTorpedoSystem(), pShip.GetPhaserSystem(), pShip.GetPulseWeaponSystem() ]:
		if (pSystem != None):
			pFiringPreprocess.AddWeaponSystem( pSystem )
	## The PreprocessingAI:
	pFire = App.PreprocessingAI_Create(pShip, "Fire")
	pFire.SetInterruptable(1)
	pFire.SetPreprocessingMethod(pFiringPreprocess, "Update")
	pFire.SetContainedAI(pPriorityList_2)
	# Done creating PreprocessingAI Fire
	#########################################
	# Builder AI Dependency Object (sInitialTarget)
	# Builder AI Dependency Object (dKeywords)
	######### AI Builder Begin #########
	return pFire  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate29(pShip, pFire, pAllTargetsGroup, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating PreprocessingAI SelectTarget at (111, 359)
	## Setup:
	import AI.Preprocessors
	pSelectionPreprocess = AI.Preprocessors.SelectTarget(pAllTargetsGroup)
	## The PreprocessingAI:
	pSelectTarget = App.PreprocessingAI_Create(pShip, "SelectTarget")
	pSelectTarget.SetInterruptable(1)
	pSelectTarget.SetPreprocessingMethod(pSelectionPreprocess, "Update")
	pSelectTarget.SetContainedAI(pFire)
	# Done creating PreprocessingAI SelectTarget
	#########################################
	# Builder AI Dependency Object (pAllTargetsGroup)
	# Builder AI Dependency Object (sInitialTarget)
	######### AI Builder Begin #########
	return pSelectTarget  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate30(pShip, pSelectTarget, dKeywords, sInitialTarget):
	########## AI Builder End ##########
	#########################################
	# Creating CompoundAI FollowTargetThroughWarp at (258, 384)
	import AI.Compound.FollowThroughWarp
	pFollowTargetThroughWarp = AI.Compound.FollowThroughWarp.CreateAI(pShip, sInitialTarget, Keywords = dKeywords)
	# Done creating CompoundAI FollowTargetThroughWarp
	#########################################
	# Builder AI Dependency Object (dKeywords)
	# Builder AI Dependency Object (sInitialTarget)
	# Builder AI Dependency AI (SelectTarget)
	pSelectTarget.GetPreprocessingInstance().AddSetTargetTree( pFollowTargetThroughWarp )
	######### AI Builder Begin #########
	return pFollowTargetThroughWarp  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate31(pShip, pFollowTargetThroughWarp, dKeywords):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI FollowThroughWarpFlag at (213, 439)
	## Conditions:
	#### Condition Follow
	pFollow = App.ConditionScript_Create("Conditions.ConditionFlagSet", "ConditionFlagSet", "FollowTargetThroughWarp", dKeywords)
	## Evaluation function:
	def EvalFunc(bFollow):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bFollow:
			return ACTIVE
		return DONE
	## The ConditionalAI:
	pFollowThroughWarpFlag = App.ConditionalAI_Create(pShip, "FollowThroughWarpFlag")
	pFollowThroughWarpFlag.SetInterruptable(1)
	pFollowThroughWarpFlag.SetContainedAI(pFollowTargetThroughWarp)
	pFollowThroughWarpFlag.AddCondition(pFollow)
	pFollowThroughWarpFlag.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI FollowThroughWarpFlag
	#########################################
	# Builder AI Dependency Object (dKeywords)
	######### AI Builder Begin #########
	return pFollowThroughWarpFlag  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate32(pShip, pWarpBeforeDeath, pNoSensorsEvasive, pSelectTarget, pFollowThroughWarpFlag):
	########## AI Builder End ##########
	#########################################
	# Creating PriorityListAI FleeAttackOrFollow at (26, 467)
	pFleeAttackOrFollow = App.PriorityListAI_Create(pShip, "FleeAttackOrFollow")
	pFleeAttackOrFollow.SetInterruptable(1)
	# SeqBlock is at (120, 459)
	pFleeAttackOrFollow.AddAI(pWarpBeforeDeath, 1)
	pFleeAttackOrFollow.AddAI(pNoSensorsEvasive, 2)
	pFleeAttackOrFollow.AddAI(pSelectTarget, 3)
	pFleeAttackOrFollow.AddAI(pFollowThroughWarpFlag, 4)
	# Done creating PriorityListAI FleeAttackOrFollow
	#########################################
	######### AI Builder Begin #########
	return pFleeAttackOrFollow  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate33(pShip, pFleeAttackOrFollow):
	########## AI Builder End ##########
	#########################################
	# Creating PreprocessingAI PowerManagement at (29, 519)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.ManagePower(1)
	## The PreprocessingAI:
	pPowerManagement = App.PreprocessingAI_Create(pShip, "PowerManagement")
	pPowerManagement.SetInterruptable(1)
	pPowerManagement.SetPreprocessingMethod(pScript, "Update")
	pPowerManagement.SetContainedAI(pFleeAttackOrFollow)
	# Done creating PreprocessingAI PowerManagement
	#########################################
	######### AI Builder Begin #########
	return pPowerManagement  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate34(pShip, pPowerManagement):
	########## AI Builder End ##########
	#########################################
	# Creating PreprocessingAI AlertLevel at (31, 570)
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
