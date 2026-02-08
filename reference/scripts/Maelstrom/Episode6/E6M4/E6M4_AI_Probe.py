import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI FlyToTezle1 at (159, 115)
	pFlyToTezle1 = App.PlainAI_Create(pShip, "FlyToTezle1")
	pFlyToTezle1.SetScriptModule("Intercept")
	pScript = pFlyToTezle1.GetScriptInstance()
	pScript.SetTargetObjectName("Tezle 1")
	pScript.SetMaximumSpeed(10)
	pScript.SetInterceptDistance(0)
	# Done creating PlainAI FlyToTezle1
	#########################################
	return pFlyToTezle1
