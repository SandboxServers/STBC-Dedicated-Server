import App
def CreateAI(pShip):
	#########################################
	# Creating PlainAI Follow at (50, 50)
	pFollow = App.PlainAI_Create(pShip, "Follow")
	pFollow.SetScriptModule("FollowObject")
	pScript = pFollow.GetScriptInstance()
	pScript.SetFollowObjectName("Keldon1")
	# Done creating PlainAI Follow
	#########################################
	return pFollow
