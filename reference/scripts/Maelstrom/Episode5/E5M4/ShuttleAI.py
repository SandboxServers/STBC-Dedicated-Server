import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI Scripted at (176, 108)
	pScripted = App.PlainAI_Create(pShip, "Scripted")
	pScripted.SetScriptModule("Intercept")
	pScripted.SetInterruptable(1)
	pScript = pScripted.GetScriptInstance()
	pScript.SetTargetObjectName("Alioth 6")
	# Done creating PlainAI Scripted
	#########################################
	return pScripted
