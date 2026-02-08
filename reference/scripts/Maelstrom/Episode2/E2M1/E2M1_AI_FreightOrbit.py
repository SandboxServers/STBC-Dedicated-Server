import App

def CreateAI(pShip):
	#########################################
	# Creating PlainAI OrbitFacility at (44, 144)
	pOrbitFacility = App.PlainAI_Create(pShip, "OrbitFacility")
	pOrbitFacility.SetScriptModule("CircleObject")
	pOrbitFacility.SetInterruptable(1)
	pScript = pOrbitFacility.GetScriptInstance()
	pScript.SetFollowObjectName("Facility")
	pScript.SetNearFacingVector(App.TGPoint3_GetModelRight())
	pScript.SetRoughDistances(fNearDistance = 100, fFarDistance = 150)
	# Done creating PlainAI OrbitFacility
	#########################################
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (45, 219)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pOrbitFacility)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
