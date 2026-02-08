import App

def CreateAI(pShip, pTarget = None):
	pTarget = pShip.GetTarget()
	sTarget = ""
	if pTarget:
		sTarget = pTarget.GetName()

	#########################################
	# Creating PlainAI Stay at (42, 219)
	pStay = App.PlainAI_Create(pShip, "Stay")
	pStay.SetScriptModule("Stay")
	pStay.SetInterruptable(1)
	# Done creating PlainAI Stay
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles_DestroyAft at (41, 269)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles_DestroyAft = App.PreprocessingAI_Create(pShip, "AvoidObstacles_DestroyAft")
	pAvoidObstacles_DestroyAft.SetInterruptable(1)
	pAvoidObstacles_DestroyAft.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles_DestroyAft.SetContainedAI(pStay)
	# Done creating PreprocessingAI AvoidObstacles_DestroyAft
	#########################################
	#########################################
	# Creating PreprocessingAI SelectTarget at (34, 328)
	## Setup:
	import AI.Preprocessors
	import MissionLib
	pEnemies = MissionLib.GetMission().GetEnemyGroup()
	pSelectionPreprocess = AI.Preprocessors.SelectTarget(pEnemies)
	if sTarget:
		pSelectionPreprocess.ForceCurrentTargetString(sTarget)
	pSelectionPreprocess.UsePlayerSettings()
	# Always fall through to our contained AI.
	pSelectionPreprocess.SetNoTargetPreprocessStatus( App.PreprocessingAI.PS_NORMAL, App.PreprocessingAI.PS_NORMAL )
	## The PreprocessingAI:
	pSelectTarget = App.PreprocessingAI_Create(pShip, "SelectTarget")
	pSelectTarget.SetInterruptable(1)
	pSelectTarget.SetPreprocessingMethod(pSelectionPreprocess, "Update")
	pSelectTarget.SetContainedAI(pAvoidObstacles_DestroyAft)
	# Done creating PreprocessingAI SelectTarget
	#########################################
	return pSelectTarget
