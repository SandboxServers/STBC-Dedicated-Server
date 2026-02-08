import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI Scripted at (50, 50)
	pScripted = App.PlainAI_Create(pShip, "Scripted")
	pScripted.SetScriptModule("Stay")
	pScripted.SetInterruptable(1)
	# Done creating PlainAI Scripted
	#########################################
	return pScripted
