import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI SitGoodDog at (50, 50)
	pSitGoodDog = App.PlainAI_Create(pShip, "SitGoodDog")
	pSitGoodDog.SetScriptModule("Stay")
	pSitGoodDog.SetInterruptable(1)
	# Done creating PlainAI SitGoodDog
	#########################################
	return pSitGoodDog
