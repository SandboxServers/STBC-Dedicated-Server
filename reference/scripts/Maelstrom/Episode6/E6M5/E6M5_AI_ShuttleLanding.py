import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI FlyToPlanet at (199, 176)
	pFlyToPlanet = App.PlainAI_Create(pShip, "FlyToPlanet")
	pFlyToPlanet.SetScriptModule("Intercept")
	pFlyToPlanet.SetInterruptable(1)
	pScript = pFlyToPlanet.GetScriptInstance()
	pScript.SetTargetObjectName("Tezle 1")
	pScript.SetMaximumSpeed(5)
	pScript.SetInterceptDistance(20)
	pScript.SetAddObjectRadius(0)
	# Done creating PlainAI FlyToPlanet
	#########################################
	return pFlyToPlanet
