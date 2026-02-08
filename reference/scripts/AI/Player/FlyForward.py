import App

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " Preprocessing module...")

def CreateAI(pShip):
	fImpulse = pShip.GetImpulse()
	if pShip.IsReverse():
		fImpulse = -fImpulse

	# If the impulse setting is 0 or we're inside SB12, we
	# just want the ship to stay.  Don't use an AvoidObstacles
	# preprocess...
	import MissionLib
	if (fImpulse == 0.0)  or  MissionLib.IsPlayerInsideStarbase12():
		fImpulse = 0.0
		return CreatePlain(pShip, fImpulse)

	return CreateWithAvoid(pShip, fImpulse)

def CreatePlain(pShip, fImpulse):
	#########################################
	# Creating PlainAI GoForward at (68, 80)
	pGoForward = App.PlainAI_Create(pShip, "GoForward")
	pGoForward.SetScriptModule("GoForward")
	pGoForward.SetInterruptable(1)
	pScript = pGoForward.GetScriptInstance()
	pScript.SetImpulse(fImpulse)
	# Done creating PlainAI GoForward
	#########################################
	return pGoForward

def CreateWithAvoid(pShip, fImpulse):
	pGoForward = CreatePlain(pShip, fImpulse)
	#########################################
	# Creating PreprocessingAI AvoidObstacles at (56, 139)
	## Setup:
	import AI.Preprocessors
	pScript = AI.Preprocessors.AvoidObstacles()
	## The PreprocessingAI:
	pAvoidObstacles = App.PreprocessingAI_Create(pShip, "AvoidObstacles")
	pAvoidObstacles.SetInterruptable(1)
	pAvoidObstacles.SetPreprocessingMethod(pScript, "Update")
	pAvoidObstacles.SetContainedAI(pGoForward)
	# Done creating PreprocessingAI AvoidObstacles
	#########################################
	return pAvoidObstacles
