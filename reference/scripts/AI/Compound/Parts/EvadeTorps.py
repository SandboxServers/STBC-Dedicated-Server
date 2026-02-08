import App

def CreateAI(pShip, sTorpSource = None, dKeywords = {}):


	#########################################
	# Creating PlainAI EvadeTorps at (302, 203)
	pEvadeTorps = App.PlainAI_Create(pShip, "EvadeTorps")
	pEvadeTorps.SetScriptModule("EvadeTorps")
	pEvadeTorps.SetInterruptable(1)
	# Done creating PlainAI EvadeTorps
	#########################################
	#########################################
	# Creating ConditionalAI IncomingTorps at (301, 261)
	## Conditions:
	#### Condition AvoidTorpsFlag
	pAvoidTorpsFlag = App.ConditionScript_Create("Conditions.ConditionFlagSet", "ConditionFlagSet", "AvoidTorps", dKeywords)
	#### Condition Incoming
	pIncoming = App.ConditionScript_Create("Conditions.ConditionIncomingTorps", "ConditionIncomingTorps", pShip.GetName(), sTorpSource)
	## Evaluation function:
	def EvalFunc(bAvoidTorpsFlag, bIncoming):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if not bAvoidTorpsFlag:
			return DONE
		if bIncoming:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pIncomingTorps = App.ConditionalAI_Create(pShip, "IncomingTorps")
	pIncomingTorps.SetInterruptable(1)
	pIncomingTorps.SetContainedAI(pEvadeTorps)
	pIncomingTorps.AddCondition(pAvoidTorpsFlag)
	pIncomingTorps.AddCondition(pIncoming)
	pIncomingTorps.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI IncomingTorps
	#########################################
	return pIncomingTorps
