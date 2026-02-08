import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI ProbeDestruct at (370, 229)
	pProbeDestruct = App.PlainAI_Create(pShip, "ProbeDestruct")
	pProbeDestruct.SetScriptModule("SelfDestruct")
	pProbeDestruct.SetInterruptable(1)
	# Done creating PlainAI ProbeDestruct
	#########################################
	return pProbeDestruct
