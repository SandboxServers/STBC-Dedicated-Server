import App
def CreateAI(pShip, sPlacementName, pTargetGroup):


	#########################################
	# Creating PlainAI ICO_Galor1 at (14, 56)
	pICO_Galor1 = App.PlainAI_Create(pShip, "ICO_Galor1")
	pICO_Galor1.SetScriptModule("IntelligentCircleObject")
	pICO_Galor1.SetInterruptable(1)
	pScript = pICO_Galor1.GetScriptInstance()
	pScript.SetFollowObjectName("Galor 1")
	pScript.SetRoughDistances(100, 150)
	pScript.SetCircleSpeed(10)
	pScript.SetShieldAndWeaponImportance(0.1, 0.9)
	# Done creating PlainAI ICO_Galor1
	#########################################
	#########################################
	# Creating PreprocessingAI Cloak at (13, 106)
	## Setup:
	import AI.Preprocessors
	pCloaking = AI.Preprocessors.CloakShip(1)
	## The PreprocessingAI:
	pCloak = App.PreprocessingAI_Create(pShip, "Cloak")
	pCloak.SetInterruptable(1)
	pCloak.SetPreprocessingMethod(pCloaking, "Update")
	pCloak.SetContainedAI(pICO_Galor1)
	# Done creating PreprocessingAI Cloak
	#########################################
	#########################################
	# Creating ConditionalAI TimerForCloak at (11, 157)
	## Conditions:
	#### Condition Timer8
	pTimer8 = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 8)
	## Evaluation function:
	def EvalFunc(bTimer8):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bTimer8:
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pTimerForCloak = App.ConditionalAI_Create(pShip, "TimerForCloak")
	pTimerForCloak.SetInterruptable(1)
	pTimerForCloak.SetContainedAI(pCloak)
	pTimerForCloak.AddCondition(pTimer8)
	pTimerForCloak.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TimerForCloak
	#########################################
	#########################################
	# Creating CompoundAI NoCloakAttack_2 at (199, 5)
	import AI.Compound.BasicAttack
	pNoCloakAttack_2 = AI.Compound.BasicAttack.CreateAI(pShip, pTargetGroup, Difficulty = 0.5, MaxFiringRange = 400.0, SmartTorpSelection = 0)
	# Done creating CompoundAI NoCloakAttack_2
	#########################################
	#########################################
	# Creating ConditionalAI TakingCriticalDamage at (208, 48)
	## Conditions:
	#### Condition CriticalAt50
	pCriticalAt50 = App.ConditionScript_Create("Conditions.ConditionCriticalSystemBelow", "ConditionCriticalSystemBelow", pShip.GetName(), 0.5)
	## Evaluation function:
	def EvalFunc(bCriticalAt50):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bCriticalAt50:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pTakingCriticalDamage = App.ConditionalAI_Create(pShip, "TakingCriticalDamage")
	pTakingCriticalDamage.SetInterruptable(1)
	pTakingCriticalDamage.SetContainedAI(pNoCloakAttack_2)
	pTakingCriticalDamage.AddCondition(pCriticalAt50)
	pTakingCriticalDamage.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TakingCriticalDamage
	#########################################
	#########################################
	# Creating CompoundAI CloakAttack at (306, 50)
	import AI.Compound.BasicAttack
	pCloakAttack = AI.Compound.BasicAttack.CreateAI(pShip, pTargetGroup, Difficulty = 0.5, MaxFiringRange = 400.0, AvoidTorps = 1, InaccurateTorps = 1, SmartTorpSelection = 0, UseCloaking = 1)
	# Done creating CompoundAI CloakAttack
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList_2 at (114, 59)
	pPriorityList_2 = App.PriorityListAI_Create(pShip, "PriorityList_2")
	pPriorityList_2.SetInterruptable(1)
	# SeqBlock is at (247, 90)
	pPriorityList_2.AddAI(pTakingCriticalDamage, 1)
	pPriorityList_2.AddAI(pCloakAttack, 2)
	# Done creating PriorityListAI PriorityList_2
	#########################################
	#########################################
	# Creating ConditionalAI OneCardInBiranu2 at (110, 106)
	## Conditions:
	#### Condition Galor1InWarp
	pGalor1InWarp = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "Galor 1", "warp")
	#### Condition Galor2InWarp
	pGalor2InWarp = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "Galor 2", "warp")
	#### Condition Galor3InWarp
	pGalor3InWarp = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "Galor 3", "warp")
	#### Condition Galor4InWarp
	pGalor4InWarp = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "Galor 4", "warp")
	## Evaluation function:
	def EvalFunc(bGalor1InWarp, bGalor2InWarp, bGalor3InWarp, bGalor4InWarp):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bGalor1InWarp or bGalor2InWarp or bGalor3InWarp or bGalor4InWarp:
			return DONE
		return ACTIVE
	## The ConditionalAI:
	pOneCardInBiranu2 = App.ConditionalAI_Create(pShip, "OneCardInBiranu2")
	pOneCardInBiranu2.SetInterruptable(1)
	pOneCardInBiranu2.SetContainedAI(pPriorityList_2)
	pOneCardInBiranu2.AddCondition(pGalor1InWarp)
	pOneCardInBiranu2.AddCondition(pGalor2InWarp)
	pOneCardInBiranu2.AddCondition(pGalor3InWarp)
	pOneCardInBiranu2.AddCondition(pGalor4InWarp)
	pOneCardInBiranu2.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI OneCardInBiranu2
	#########################################
	#########################################
	# Creating PreprocessingAI Decloak at (110, 157)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.CloakShip(0)
	## The PreprocessingAI:
	pDecloak = App.PreprocessingAI_Create(pShip, "Decloak")
	pDecloak.SetInterruptable(1)
	pDecloak.SetPreprocessingMethod(pScript, "Update")
	pDecloak.SetContainedAI(pOneCardInBiranu2)
	# Done creating PreprocessingAI Decloak
	#########################################
	#########################################
	# Creating PlainAI Call_BOPsChaseGalor at (207, 157)
	pCall_BOPsChaseGalor = App.PlainAI_Create(pShip, "Call_BOPsChaseGalor")
	pCall_BOPsChaseGalor.SetScriptModule("RunScript")
	pCall_BOPsChaseGalor.SetInterruptable(1)
	pScript = pCall_BOPsChaseGalor.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode2.E2M6.E2M6")
	pScript.SetFunction("BOPsChaseGalor")
	# Done creating PlainAI Call_BOPsChaseGalor
	#########################################
	#########################################
	# Creating SequenceAI Biranu2Sequence at (22, 216)
	pBiranu2Sequence = App.SequenceAI_Create(pShip, "Biranu2Sequence")
	pBiranu2Sequence.SetInterruptable(1)
	pBiranu2Sequence.SetLoopCount(1)
	pBiranu2Sequence.SetResetIfInterrupted(1)
	pBiranu2Sequence.SetDoubleCheckAllDone(0)
	pBiranu2Sequence.SetSkipDormant(0)
	# SeqBlock is at (130, 223)
	pBiranu2Sequence.AddAI(pTimerForCloak)
	pBiranu2Sequence.AddAI(pDecloak)
	pBiranu2Sequence.AddAI(pCall_BOPsChaseGalor)
	# Done creating SequenceAI Biranu2Sequence
	#########################################
	#########################################
	# Creating PlainAI WarpToBiranu1 at (244, 197)
	pWarpToBiranu1 = App.PlainAI_Create(pShip, "WarpToBiranu1")
	pWarpToBiranu1.SetScriptModule("Warp")
	pWarpToBiranu1.SetInterruptable(1)
	pScript = pWarpToBiranu1.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Biranu.Biranu1")
	pScript.SetDestinationPlacementName(sPlacementName)
	pScript.SetWarpDuration(10)
	# Done creating PlainAI WarpToBiranu1
	#########################################
	#########################################
	# Creating ConditionalAI TimeToWarp at (251, 240)
	## Conditions:
	#### Condition Timer10
	pTimer10 = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 10)
	## Evaluation function:
	def EvalFunc(bTimer10):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bTimer10:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pTimeToWarp = App.ConditionalAI_Create(pShip, "TimeToWarp")
	pTimeToWarp.SetInterruptable(1)
	pTimeToWarp.SetContainedAI(pWarpToBiranu1)
	pTimeToWarp.AddCondition(pTimer10)
	pTimeToWarp.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TimeToWarp
	#########################################
	#########################################
	# Creating CompoundAI NoCloakAttack at (336, 99)
	import AI.Compound.BasicAttack
	pNoCloakAttack = AI.Compound.BasicAttack.CreateAI(pShip, pTargetGroup, Difficulty = 0.5, MaxFiringRange = 400.0, SmartTorpSelection = 0)
	# Done creating CompoundAI NoCloakAttack
	#########################################
	#########################################
	# Creating ConditionalAI TakingCriticalDamage_2 at (335, 145)
	## Conditions:
	#### Condition CriticalAt50
	pCriticalAt50 = App.ConditionScript_Create("Conditions.ConditionCriticalSystemBelow", "ConditionCriticalSystemBelow", pShip.GetName(), 0.5)
	## Evaluation function:
	def EvalFunc(bCriticalAt50):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bCriticalAt50:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pTakingCriticalDamage_2 = App.ConditionalAI_Create(pShip, "TakingCriticalDamage_2")
	pTakingCriticalDamage_2.SetInterruptable(1)
	pTakingCriticalDamage_2.SetContainedAI(pNoCloakAttack)
	pTakingCriticalDamage_2.AddCondition(pCriticalAt50)
	pTakingCriticalDamage_2.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI TakingCriticalDamage_2
	#########################################
	#########################################
	# Creating CompoundAI CloakAttack_2 at (432, 124)
	import AI.Compound.BasicAttack
	pCloakAttack_2 = AI.Compound.BasicAttack.CreateAI(pShip, pTargetGroup, Difficulty = 0.5, MaxFiringRange = 400.0, SmartTorpSelection = 0, UseCloaking = 1)
	# Done creating CompoundAI CloakAttack_2
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (353, 218)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (427, 191)
	pPriorityList.AddAI(pTakingCriticalDamage_2, 1)
	pPriorityList.AddAI(pCloakAttack_2, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating PlainAI Call_Biranu1Clear at (499, 165)
	pCall_Biranu1Clear = App.PlainAI_Create(pShip, "Call_Biranu1Clear")
	pCall_Biranu1Clear.SetScriptModule("RunScript")
	pCall_Biranu1Clear.SetInterruptable(1)
	pScript = pCall_Biranu1Clear.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode2.E2M6.E2M6")
	pScript.SetFunction("Biranu1Clear")
	# Done creating PlainAI Call_Biranu1Clear
	#########################################
	#########################################
	# Creating ConditionalAI NoCardsInSet at (498, 210)
	## Conditions:
	#### Condition Galor1InBiranu1
	pGalor1InBiranu1 = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "Galor 1", "Biranu1")
	#### Condition SelfInBiranu1
	pSelfInBiranu1 = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", pShip.GetName(), "Biranu1")
	#### Condition Galor2InBiranu1
	pGalor2InBiranu1 = App.ConditionScript_Create("Conditions.ConditionAllInSameSet", "ConditionAllInSameSet", "Galor 2", "Biranu1")
	#### Condition Galor3InBiranu1
	pGalor3InBiranu1 = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "Galor 3", "Biranu1")
	#### Condition Galor4InBiranu1
	pGalor4InBiranu1 = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "Galor 4", "Biranu1")
	## Evaluation function:
	def EvalFunc(bGalor1InBiranu1, bSelfInBiranu1, bGalor2InBiranu1, bGalor3InBiranu1, bGalor4InBiranu1):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bGalor1InBiranu1 or bGalor2InBiranu1 or bGalor3InBiranu1 or bGalor4InBiranu1) and not bSelfInBiranu1:
			return DORMANT
		return ACTIVE
	## The ConditionalAI:
	pNoCardsInSet = App.ConditionalAI_Create(pShip, "NoCardsInSet")
	pNoCardsInSet.SetInterruptable(1)
	pNoCardsInSet.SetContainedAI(pCall_Biranu1Clear)
	pNoCardsInSet.AddCondition(pGalor1InBiranu1)
	pNoCardsInSet.AddCondition(pSelfInBiranu1)
	pNoCardsInSet.AddCondition(pGalor2InBiranu1)
	pNoCardsInSet.AddCondition(pGalor3InBiranu1)
	pNoCardsInSet.AddCondition(pGalor4InBiranu1)
	pNoCardsInSet.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI NoCardsInSet
	#########################################
	#########################################
	# Creating PriorityListAI Biranu1Priority at (359, 295)
	pBiranu1Priority = App.PriorityListAI_Create(pShip, "Biranu1Priority")
	pBiranu1Priority.SetInterruptable(1)
	# SeqBlock is at (469, 276)
	pBiranu1Priority.AddAI(pPriorityList, 1)
	pBiranu1Priority.AddAI(pNoCardsInSet, 2)
	# Done creating PriorityListAI Biranu1Priority
	#########################################
	#########################################
	# Creating SequenceAI Biranu1Sequence at (173, 303)
	pBiranu1Sequence = App.SequenceAI_Create(pShip, "Biranu1Sequence")
	pBiranu1Sequence.SetInterruptable(1)
	pBiranu1Sequence.SetLoopCount(1)
	pBiranu1Sequence.SetResetIfInterrupted(1)
	pBiranu1Sequence.SetDoubleCheckAllDone(0)
	pBiranu1Sequence.SetSkipDormant(0)
	# SeqBlock is at (302, 310)
	pBiranu1Sequence.AddAI(pTimeToWarp)
	pBiranu1Sequence.AddAI(pBiranu1Priority)
	# Done creating SequenceAI Biranu1Sequence
	#########################################
	#########################################
	# Creating SequenceAI MainSequence at (13, 356)
	pMainSequence = App.SequenceAI_Create(pShip, "MainSequence")
	pMainSequence.SetInterruptable(1)
	pMainSequence.SetLoopCount(1)
	pMainSequence.SetResetIfInterrupted(1)
	pMainSequence.SetDoubleCheckAllDone(0)
	pMainSequence.SetSkipDormant(0)
	# SeqBlock is at (113, 310)
	pMainSequence.AddAI(pBiranu2Sequence)
	pMainSequence.AddAI(pBiranu1Sequence)
	# Done creating SequenceAI MainSequence
	#########################################
	return pMainSequence
