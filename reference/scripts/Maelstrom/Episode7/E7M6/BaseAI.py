import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI StarbaseAttack at (237, 92)
	import AI.Compound.StarbaseAttack
	pStarbaseAttack = AI.Compound.StarbaseAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode7.E7M6.E7M6", "pFriendlies"))
	# Done creating CompoundAI StarbaseAttack
	#########################################
	#########################################
	# Creating PreprocessingAI RedAlert at (151, 112)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AlertLevel(App.ShipClass.RED_ALERT)
	## The PreprocessingAI:
	pRedAlert = App.PreprocessingAI_Create(pShip, "RedAlert")
	pRedAlert.SetInterruptable(1)
	pRedAlert.SetPreprocessingMethod(pScript, "Update")
	pRedAlert.SetContainedAI(pStarbaseAttack)
	# Done creating PreprocessingAI RedAlert
	#########################################
	return pRedAlert
