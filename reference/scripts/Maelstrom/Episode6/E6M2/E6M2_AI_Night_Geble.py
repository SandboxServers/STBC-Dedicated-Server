import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI WarpToGeble3 at (124, 157)
	pWarpToGeble3 = App.PlainAI_Create(pShip, "WarpToGeble3")
	pWarpToGeble3.SetScriptModule("Warp")
	pWarpToGeble3.SetInterruptable(1)
	pScript = pWarpToGeble3.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Geble.Geble3")
	pScript.SetDestinationPlacementName("NightEnter")
	pScript.SetWarpDuration(10)
	# Done creating PlainAI WarpToGeble3
	#########################################
	#########################################
	# Creating ConditionalAI PlayerInGeble at (123, 204)
	## Conditions:
	#### Condition PlayerInGeble4
	pPlayerInGeble4 = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "player", "Geble4")
	#### Condition PlayerInGeble3
	pPlayerInGeble3 = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", "player", "Geble3")
	## Evaluation function:
	def EvalFunc(bPlayerInGeble4, bPlayerInGeble3):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bPlayerInGeble4 or bPlayerInGeble3):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pPlayerInGeble = App.ConditionalAI_Create(pShip, "PlayerInGeble")
	pPlayerInGeble.SetInterruptable(1)
	pPlayerInGeble.SetContainedAI(pWarpToGeble3)
	pPlayerInGeble.AddCondition(pPlayerInGeble4)
	pPlayerInGeble.AddCondition(pPlayerInGeble3)
	pPlayerInGeble.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI PlayerInGeble
	#########################################
	#########################################
	# Creating PlainAI Call_PlayerArrivesGeble3 at (152, 242)
	pCall_PlayerArrivesGeble3 = App.PlainAI_Create(pShip, "Call_PlayerArrivesGeble3")
	pCall_PlayerArrivesGeble3.SetScriptModule("RunScript")
	pCall_PlayerArrivesGeble3.SetInterruptable(1)
	pScript = pCall_PlayerArrivesGeble3.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode6.E6M2.E6M2")
	pScript.SetFunction("PlayerArrivesGeble3")
	# Done creating PlainAI Call_PlayerArrivesGeble3
	#########################################
	#########################################
	# Creating ConditionalAI PlayerInGelble3 at (149, 290)
	## Conditions:
	#### Condition EveryoneInGeble3
	pEveryoneInGeble3 = App.ConditionScript_Create("Conditions.ConditionAllInSameSet", "ConditionAllInSameSet", "player", "Nightingale", "Escape Pod 1")
	## Evaluation function:
	def EvalFunc(bEveryoneInGeble3):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bEveryoneInGeble3):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pPlayerInGelble3 = App.ConditionalAI_Create(pShip, "PlayerInGelble3")
	pPlayerInGelble3.SetInterruptable(1)
	pPlayerInGelble3.SetContainedAI(pCall_PlayerArrivesGeble3)
	pPlayerInGelble3.AddCondition(pEveryoneInGeble3)
	pPlayerInGelble3.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI PlayerInGelble3
	#########################################
	#########################################
	# Creating PlainAI Call_NightUnderFire at (260, 153)
	pCall_NightUnderFire = App.PlainAI_Create(pShip, "Call_NightUnderFire")
	pCall_NightUnderFire.SetScriptModule("RunScript")
	pCall_NightUnderFire.SetInterruptable(1)
	pScript = pCall_NightUnderFire.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode6.E6M2.E6M2")
	pScript.SetFunction("NightUnderFire")
	# Done creating PlainAI Call_NightUnderFire
	#########################################
	#########################################
	# Creating ConditionalAI Attacked_By_Galor1 at (245, 210)
	## Conditions:
	#### Condition AttackedGalor1
	pAttackedGalor1 = App.ConditionScript_Create("Conditions.ConditionAttackedBy", "ConditionAttackedBy", pShip.GetName(), "Galor 1", 0.01, 0.01, 99)
	## Evaluation function:
	def EvalFunc(bAttackedGalor1):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bAttackedGalor1):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pAttacked_By_Galor1 = App.ConditionalAI_Create(pShip, "Attacked_By_Galor1")
	pAttacked_By_Galor1.SetInterruptable(1)
	pAttacked_By_Galor1.SetContainedAI(pCall_NightUnderFire)
	pAttacked_By_Galor1.AddCondition(pAttackedGalor1)
	pAttacked_By_Galor1.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Attacked_By_Galor1
	#########################################
	#########################################
	# Creating PlainAI Call_NightUnderFire2 at (378, 145)
	pCall_NightUnderFire2 = App.PlainAI_Create(pShip, "Call_NightUnderFire2")
	pCall_NightUnderFire2.SetScriptModule("RunScript")
	pCall_NightUnderFire2.SetInterruptable(1)
	pScript = pCall_NightUnderFire2.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode6.E6M2.E6M2")
	pScript.SetFunction("NightUnderFire2")
	# Done creating PlainAI Call_NightUnderFire2
	#########################################
	#########################################
	# Creating ConditionalAI Attacked_By_Galor2 at (335, 233)
	## Conditions:
	#### Condition AttackedGalor2
	pAttackedGalor2 = App.ConditionScript_Create("Conditions.ConditionAttackedBy", "ConditionAttackedBy", pShip.GetName(), "Galor 2", 0.01, 0.01, 99)
	## Evaluation function:
	def EvalFunc(bAttackedGalor2):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bAttackedGalor2):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pAttacked_By_Galor2 = App.ConditionalAI_Create(pShip, "Attacked_By_Galor2")
	pAttacked_By_Galor2.SetInterruptable(1)
	pAttacked_By_Galor2.SetContainedAI(pCall_NightUnderFire2)
	pAttacked_By_Galor2.AddCondition(pAttackedGalor2)
	pAttacked_By_Galor2.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Attacked_By_Galor2
	#########################################
	#########################################
	# Creating PlainAI Call_NightTakingDamage at (494, 160)
	pCall_NightTakingDamage = App.PlainAI_Create(pShip, "Call_NightTakingDamage")
	pCall_NightTakingDamage.SetScriptModule("RunScript")
	pCall_NightTakingDamage.SetInterruptable(1)
	pScript = pCall_NightTakingDamage.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode6.E6M2.E6M2")
	pScript.SetFunction("NightTakingDamage")
	# Done creating PlainAI Call_NightTakingDamage
	#########################################
	#########################################
	# Creating ConditionalAI HullTakingDamage at (440, 225)
	## Conditions:
	#### Condition HullAt60
	pHullAt60 = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_HULL_SUBSYSTEM, 0.60)
	## Evaluation function:
	def EvalFunc(bHullAt60):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if (bHullAt60):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pHullTakingDamage = App.ConditionalAI_Create(pShip, "HullTakingDamage")
	pHullTakingDamage.SetInterruptable(1)
	pHullTakingDamage.SetContainedAI(pCall_NightTakingDamage)
	pHullTakingDamage.AddCondition(pHullAt60)
	pHullTakingDamage.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI HullTakingDamage
	#########################################
	#########################################
	# Creating CompoundAI TractorPods at (501, 304)
	import AI.Compound.TractorDockTargets
	pTractorPods = AI.Compound.TractorDockTargets.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode6.E6M2.E6M2", "g_pGeblePodTargets"))
	# Done creating CompoundAI TractorPods
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (206, 361)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (338, 343)
	pPriorityList.AddAI(pAttacked_By_Galor1, 1)
	pPriorityList.AddAI(pAttacked_By_Galor2, 2)
	pPriorityList.AddAI(pHullTakingDamage, 3)
	pPriorityList.AddAI(pTractorPods, 4)
	# Done creating PriorityListAI PriorityList
	#########################################
	#########################################
	# Creating SequenceAI GebleSequence at (27, 434)
	pGebleSequence = App.SequenceAI_Create(pShip, "GebleSequence")
	pGebleSequence.SetInterruptable(1)
	pGebleSequence.SetLoopCount(1)
	pGebleSequence.SetResetIfInterrupted(1)
	pGebleSequence.SetDoubleCheckAllDone(0)
	pGebleSequence.SetSkipDormant(0)
	# SeqBlock is at (114, 382)
	pGebleSequence.AddAI(pPlayerInGeble)
	pGebleSequence.AddAI(pPlayerInGelble3)
	pGebleSequence.AddAI(pPriorityList)
	# Done creating SequenceAI GebleSequence
	#########################################
	return pGebleSequence
