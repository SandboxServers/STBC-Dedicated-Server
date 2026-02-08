import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI MacCrayLeaves at (82, 63)
	pMacCrayLeaves = App.PlainAI_Create(pShip, "MacCrayLeaves")
	pMacCrayLeaves.SetScriptModule("Warp")
	pMacCrayLeaves.SetInterruptable(1)
	# Done creating PlainAI MacCrayLeaves
	#########################################
	return pMacCrayLeaves
