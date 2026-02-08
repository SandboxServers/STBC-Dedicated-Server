import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI DistressCall at (266, 84)
	pDistressCall = App.PlainAI_Create(pShip, "DistressCall")
	pDistressCall.SetScriptModule("RunScript")
	pDistressCall.SetInterruptable(1)
	pScript = pDistressCall.GetScriptInstance()
	pScript.SetScriptModule("Maelstrom.Episode7.E7M3.E7M3")
	pScript.SetFunction("DistressCallDialogue")
	# Done creating PlainAI DistressCall
	#########################################
	#########################################
	# Creating ConditionalAI Timer at (148, 104)
	## Conditions:
	#### Condition TimerElapsed
	pTimerElapsed = App.ConditionScript_Create("Conditions.ConditionTimer", "ConditionTimer", 60)
	## Evaluation function:
	def EvalFunc(bTimerElapsed):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if(bTimerElapsed):
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pTimer = App.ConditionalAI_Create(pShip, "Timer")
	pTimer.SetInterruptable(1)
	pTimer.SetContainedAI(pDistressCall)
	pTimer.AddCondition(pTimerElapsed)
	pTimer.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Timer
	#########################################
	#########################################
	# Creating CompoundAI StarbaseAttack at (181, 56)
	import AI.Compound.StarbaseAttack
	pStarbaseAttack = AI.Compound.StarbaseAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode7.E7M3.E7M3", "pFriendlies"))
	# Done creating CompoundAI StarbaseAttack
	#########################################
	#########################################
	# Creating PriorityListAI PriorityList at (44, 56)
	pPriorityList = App.PriorityListAI_Create(pShip, "PriorityList")
	pPriorityList.SetInterruptable(1)
	# SeqBlock is at (140, 63)
	pPriorityList.AddAI(pTimer, 1)
	pPriorityList.AddAI(pStarbaseAttack, 2)
	# Done creating PriorityListAI PriorityList
	#########################################
	return pPriorityList
