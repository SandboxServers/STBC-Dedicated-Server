import App

def CreateAI(pShip, sPlacementName):


	#########################################
	# Creating PlainAI Warp at (59, 159)
	pWarp = App.PlainAI_Create(pShip, "Warp")
	pWarp.SetScriptModule("Warp")
	pWarp.SetInterruptable(1)
	pScript = pWarp.GetScriptInstance()
	pScript.SetDestinationSetName("Systems.Voltair.Voltair1")
	pScript.SetDestinationPlacementName(sPlacementName)
	# Done creating PlainAI Warp
	#########################################
	#########################################
	# Creating PlainAI Stay at (152, 158)
	pStay = App.PlainAI_Create(pShip, "Stay")
	pStay.SetScriptModule("Stay")
	pStay.SetInterruptable(1)
	# Done creating PlainAI Stay
	#########################################
	#########################################
	# Creating SequenceAI Sequence at (62, 91)
	pSequence = App.SequenceAI_Create(pShip, "Sequence")
	pSequence.SetInterruptable(1)
	pSequence.SetLoopCount(1)
	pSequence.SetResetIfInterrupted(1)
	pSequence.SetDoubleCheckAllDone(0)
	pSequence.SetSkipDormant(0)
	# SeqBlock is at (89, 132)
	pSequence.AddAI(pWarp)
	pSequence.AddAI(pStay)
	# Done creating SequenceAI Sequence
	#########################################
	return pSequence
