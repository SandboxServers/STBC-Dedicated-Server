import App

def CreateSmoke (fDuration):
	# create smoke
	pSet = App.g_kSetManager.GetSet("bridge")
	pBridgeObject = App.BridgeObjectClass_GetObject (pSet, "bridge")
	if (pBridgeObject):
		pAction = App.BridgeEffectAction_CreateSmoke (fDuration, 1.5, 0.01, pBridgeObject, None, "data/sphere.tga")
		pController = pAction.GetController ()

		# Setup some default values for velocity, colors and alpha
		# Time zero.
		pController.AddColorKey (0.0, 0.8, 0.8, 0.8)
		pController.AddAlphaKey (0.0, 0.75)
		pController.AddSizeKey (0.0, 2.5)

		# End of life.
		pController.AddAlphaKey (1.0, 0.0)
		pController.AddSizeKey (1.0, 20.0)
		pController.SetEmitVelocity (40)
		pController.SetAngleVariance (20)
		
		pcHardpointName = pAction.GetHardpointName ()

		pBridgeObject.DoCrewReactions (pcHardpointName)
		pBridgeObject.FlickerLCARs(2.0)

		pAction.Play ()

def CreateSpark (fDuration):
	# create spark
	pSet = App.g_kSetManager.GetSet("bridge")
	pBridgeObject = App.BridgeObjectClass_GetObject (pSet, "bridge")

	if (pBridgeObject):
		pAction = App.BridgeEffectAction_CreateSparks (fDuration, fDuration - 0.005 * 40, 0.005, pBridgeObject, None, "data/spark.tga")
		pController = pAction.GetSparkController ()

		# Setup some default values for velocity, colors and alpha
		pController.AddColorKey (0.0, 1.0, 1.0, 1.0)
		pController.AddColorKey (0.4, 1.0, 1.0, 0.6)
		pController.AddColorKey (1.0, 1.0, 0.7, 0.7)
		
		pController.AddAlphaKey (0.0, 1.0)
		pController.AddAlphaKey (0.95, 1.0)
		pController.AddAlphaKey (1.0, 0.0)

		pController.AddSizeKey (0.0, 0.35)

		pController.SetEmitVelocity (100.0)
		pController.SetGravity (0.0, 0.0, -250.0)
		pController.SetTailLength (5.0)

		pcHardpointName = pAction.GetHardpointName ()

		pBridgeObject.DoCrewReactions (pcHardpointName)
		pBridgeObject.FlickerLCARs(3.0)

		pAction.Play ()

	return

def CreateExplosion (fDuration):
	# Create explosion
	pSet = App.g_kSetManager.GetSet("bridge")
	pBridgeObject = App.BridgeObjectClass_GetObject (pSet, "bridge")

	if (pBridgeObject):
		# Create sequence
		pSequence = App.TGSequence_Create ();
		assert(pSequence)

		pAction = App.BridgeEffectAction_CreateExplosion (fDuration, 2.0, 0.03, pBridgeObject, None, "data/sphere.tga")
		pController = pAction.GetExplosionController ()

		# Setup some default values for velocity, colors and alpha
		pController.AddColorKey (0.0, 0.4, 0.4, 0.4)
		pController.AddColorKey (0.55, 0.4, 0.4, 0.4)
		pController.AddColorKey (0.75, 0.2, 0.2, 0.2)
		pController.AddColorKey (0.9, 0.1, 0.1, 0.1)

		pController.AddAlphaKey (0.0, 0.75)
		pController.AddAlphaKey (0.75, 0.2)
		pController.AddAlphaKey (1.0, 0.0)

		pController.AddSizeKey (0.0, 2.5)
		pController.AddSizeKey (1.0, 30.0)

		pController.AddIntensityKey (0.0, 0.0)
		pController.AddIntensityKey (0.05, 0.5)
		pController.AddIntensityKey (0.1, 0.5)
		pController.AddIntensityKey (0.15, 0.0)

		pController.SetEmitVelocity (35.0)
		pController.SetGravity (0.0, 0.0, 25.0)

		# Get the name of the hardpoint that was used for the explosion.  We will
		# reuse this hardpoint for the sparks and debris as well.
		pcHardpointName = pAction.GetHardpointName ()

		pBridgeObject.DoCrewReactions (pcHardpointName)
		pBridgeObject.FlickerLCARs(4.0)

		# Add action to sequence.
		pSequence.AddAction (pAction)

		###################################################

		#create sparks
		pAction = App.BridgeEffectAction_CreateSparks (1.55, 1.55 - 20 * 0.005, 0.005, pBridgeObject, pcHardpointName, "data/spark.tga")
		pController = pAction.GetSparkController ()

		# Setup some default values for velocity, colors and alpha
		pController.AddColorKey (0.0, 1.0, 1.0, 1.0)
		pController.AddColorKey (1.0, 0.5, 1.0, 1.0)
		
		pController.AddAlphaKey (0.0, 1.0)
		pController.AddAlphaKey (0.8, 1.0)
		pController.AddAlphaKey (1.0, 0.0)

		pController.AddSizeKey (0.0, 0.75)

		pController.SetEmitVelocity (100.0)
		pController.SetGravity (0.0, 0.0, -250.0)
		pController.SetTailLength (3.0)
		pController.SetTailFade (0.1)
		pController.SetAngleVariance (60)

		# Add action to sequence.
		pSequence.AddAction (pAction)

		###################################################

		# create flames
		pAction = App.BridgeEffectAction_Create (fDuration + 1.0, 1.0, 0.1, pBridgeObject, pcHardpointName, "data/spark.tga")
		pController = pAction.GetController ()

		# Setup some default values for velocity, colors and alpha
		pController.AddColorKey (0.0, 0.95, 1.0, 0.6)
		pController.AddColorKey (0.4, 1.0, 1.0, 0.0)
		pController.AddColorKey (1.0, 1.0, 0.4, 0.0)
		
		pController.AddAlphaKey (0.0, 1.0)
		pController.AddAlphaKey (0.5, 1.0)
		pController.AddAlphaKey (1.0, 0.0)

		pController.AddSizeKey (0.0, 2.5)
		pController.AddSizeKey (1.0, 15.0)

		pController.SetGravity (0.0, 0.0, 70.0)
		pController.SetAngleVariance (120)

		# Since the fire is inside the smoke, it gets obscured.  We want it to ignore alpha sorting (kindof)
	#	pController.DontAlphaSort ()

		# Add action to sequence.
		pSequence.AddAction (pAction)

		###################################################

		# create debris.
		pAction = App.BridgeEffectAction_CreateDebris (1.0, 2.0, 0.01, pBridgeObject, pcHardpointName, "data/square.tga")
		pController = pAction.GetController ()

		# Setup some default values for velocity, colors and alpha
		pController.AddColorKey (0.0, 0.5, 0.5, 0.5)
		pController.AddColorKey (0.2, 0.1, 0.1, 0.1)

		pController.AddAlphaKey (0.0, 1.0)

		# Size keys for debris controllers differ a little bit.
		# They are used to randomly generate a size rather than
		# interpolation of sizes.  So you can use keys to 
		# affect the range of sizes that a debris will be.
		pController.AddSizeKey (0.0, 0.5)
		pController.AddSizeKey (0.8, 1.0)	# This says 80% of the particles will be < 1.0 in size
		pController.AddSizeKey (1.0, 2.5)

		pController.SetEmitVelocity (170.0)
		pController.SetGravity (0, 0, -180.0)
		pController.SetAngleVariance (60)

		# Add action to sequence.
		pSequence.AddAction (pAction)

		pSequence.Play ()

	return


def DoHullDamage (fCurHullPercent):
	pSet = App.g_kSetManager.GetSet ("bridge")
	if not pSet:
		return

	pCamera = App.ZoomCameraObjectClass_GetObject (pSet, "maincamera")
	if not pCamera:
		return

	if (fCurHullPercent > 0.85):
		# Light damage.  Do sparks most of the time, occasionally steam
		r = App.g_kSystemWrapper.GetRandomNumber (100)
		if (r < 20):
			CreateSmoke (10)		# 5 seconds of smoke
		else:
			CreateSpark (1.55)
			SparkSound()

		# Shake the camera also.
		pCamera.SetShake (4.0, 2.0)
	elif (fCurHullPercent > 0.50):
		# Moderate damage
		r = App.g_kSystemWrapper.GetRandomNumber (100)
		if (r < 50):
			CreateSmoke (10)

		# always create sparks
		CreateSpark (1.55)
		SparkSound()

		# Shake the camera also.
		pCamera.SetShake (4.0, 2.0)
	else:
		# Heavy damage
		# Do explosions, steam, and sparks.
		CreateSmoke (10)
		CreateSpark (1.55)
		CreateExplosion (15)
		SparkSound()

		# Shake the camera also.
		pCamera.SetShake (5.0, 3.0)

	return

def SparkSound():
	# Don't do anything if the rendered set isn't the bridge.
	try:
		if App.g_kSetManager.GetRenderedSet().GetName() != "bridge":
			return
	except AttributeError:
		return

	# How long has it been since the last spark sound?  These sounds
	# are very distinctive, and we don't want them constantly playing
	# whenever the bridge shows damage.
	global g_fNextSpark
	fCurrentTime = App.g_kUtopiaModule.GetRealTime()
	try:
		if g_fNextSpark > fCurrentTime:
			return
	except NameError:
		pass

	g_fNextSpark = fCurrentTime + (App.g_kSystemWrapper.GetRandomNumber(2000) / 1000.0)

	import LoadTacticalSounds
	sSound = LoadTacticalSounds.GetRandomSound(g_lsSparks)
	pSound = App.g_kSoundManager.GetSound(sSound)
	if pSound:
		pSound.Play()

g_lsSparks = ( "ConsoleExplosion1", "ConsoleExplosion2",
			   "ConsoleExplosion3", "ConsoleExplosion4",
			   "ConsoleExplosion5", "ConsoleExplosion6",
			   "ConsoleExplosion7", "ConsoleExplosion8" )
