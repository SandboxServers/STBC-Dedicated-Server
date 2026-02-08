import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI Scripted at (96, 79)
	pScripted = App.PlainAI_Create(pShip, "Scripted")
	pScripted.SetScriptModule("SelfDestruct")
	pScripted.SetInterruptable(1)
	# Done creating PlainAI Scripted
	#########################################
	return pScripted
