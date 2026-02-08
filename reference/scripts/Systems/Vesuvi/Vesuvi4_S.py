import App
import loadspacehelper
import Maelstrom.Maelstrom


def Initialize(pSet):
	# MetaNebula_Create params are:
	# r, g, b : (floats [0.0 , 1.0]) 
	# visibility distance inside the nebula (float in world units)
	# sensor density of nebula(value to scale sensor range by)
    # name of internal texture (needs alpha)
	# name of external texture (no need for alpha)
	pNebula = App.MetaNebula_Create(155.0 / 255.0, 90.0 / 255.0, 185.0 / 255.0, 145.0, 10.5, "data/Backgrounds/nebulaoverlay.tga", "data/Backgrounds/nebulaexternal.tga")

	# Set nebula damage/sec to Hull/Shields.
	pNebula.SetupDamage(150.0, 20.0)

	# Adds a fuzzy sphere at x, y, z (in world coord) of specified size (1000.0 in this case)
	pNebula.AddNebulaSphere(0.0, 1500.0, 0.000000, 1500.0)

	# Puts the nebula in the set
	pSet.AddObjectToSet(pNebula, "my foggy new nebula")

	# place all the asteroids

	# Create object
	# Only create system stuff if not multiplayer or is the host in multiplayer
	if (App.g_kUtopiaModule.IsMultiplayer () == 0 or App.g_kUtopiaModule.IsHost () == 1):
		pObj = loadspacehelper.CreateShip ("Asteroidh1", pSet, "Unknown Debris 1", "AsteroidGroup1 Start 1")
		if (pObj):
			# Set objects Genus to Asteroid.
			pProperty = pObj.GetShipProperty()
			pProperty.SetGenus(App.GENUS_ASTEROID)

			pObj.SetScale (9.0)
			# Rotate object
			vVelocity = App.TGPoint3_GetModelForward()	# Get the vector to rotate around
			vVelocity.Scale( 10.0 * App.PI / 180.0 )		# Scale it to 10 degrees/second (converted to radians)
			pObj.SetAngularVelocity(vVelocity, App.PhysicsObjectClass.DIRECTION_MODEL_SPACE)
			# The Core objects can't take damage from the nebula.
			# Override the Environmental Damage handler for these.
			pObj.AddPythonFuncHandlerForInstance(App.ET_ENVIRONMENT_DAMAGE, "MissionLib.IgnoreEvent")

			# Create object
		pObj = loadspacehelper.CreateShip ("Asteroidh1", pSet, "Unknown Debris 2", "AsteroidGroup1 Start 2")
		if (pObj):
			# Set objects Genus to Asteroid.
			pProperty = pObj.GetShipProperty()
			pProperty.SetGenus(App.GENUS_ASTEROID)

			pObj.SetScale (9.0)
			# Rotate object
			vVelocity = App.TGPoint3_GetModelForward()	# Get the vector to rotate around
			vVelocity.Scale( 10.0 * App.PI / 180.0 )		# Scale it to 10 degrees/second (converted to radians)
			pObj.SetAngularVelocity(vVelocity, App.PhysicsObjectClass.DIRECTION_MODEL_SPACE)
			# The Core objects can't take damage from the nebula.
			# Override the Environmental Damage handler for these.
			pObj.AddPythonFuncHandlerForInstance(App.ET_ENVIRONMENT_DAMAGE, "MissionLib.IgnoreEvent")

			# Create object
		pObj = loadspacehelper.CreateShip ("Asteroidh1", pSet, "Unknown Debris 3", "AsteroidGroup1 Start 3")
		if (pObj):
			# Set objects Genus to Asteroid.
			pProperty = pObj.GetShipProperty()
			pProperty.SetGenus(App.GENUS_ASTEROID)

			pObj.SetScale (9.0)
			# Rotate object
			vVelocity = App.TGPoint3_GetModelForward()	# Get the vector to rotate around
			vVelocity.Scale( 10.0 * App.PI / 180.0 )		# Scale it to 10 degrees/second (converted to radians)
			pObj.SetAngularVelocity(vVelocity, App.PhysicsObjectClass.DIRECTION_MODEL_SPACE)
			# The Core objects can't take damage from the nebula.
			# Override the Environmental Damage handler for these.
			pObj.AddPythonFuncHandlerForInstance(App.ET_ENVIRONMENT_DAMAGE, "MissionLib.IgnoreEvent")

			# Create object
		pObj = loadspacehelper.CreateShip ("Asteroidh1", pSet, "Unknown Debris 4", "AsteroidGroup2 Start 1")
		if (pObj):
			# Set objects Genus to Asteroid.
			pProperty = pObj.GetShipProperty()
			pProperty.SetGenus(App.GENUS_ASTEROID)

			pObj.SetScale (9.0)
			# Rotate object
			vVelocity = App.TGPoint3_GetModelForward()	# Get the vector to rotate around
			vVelocity.Scale( 10.0 * App.PI / 180.0 )		# Scale it to 10 degrees/second (converted to radians)
			pObj.SetAngularVelocity(vVelocity, App.PhysicsObjectClass.DIRECTION_MODEL_SPACE)
			# The Core objects can't take damage from the nebula.
			# Override the Environmental Damage handler for these.
			pObj.AddPythonFuncHandlerForInstance(App.ET_ENVIRONMENT_DAMAGE, "MissionLib.IgnoreEvent")

			# Create object
		pObj = loadspacehelper.CreateShip ("Asteroidh1", pSet, "Unknown Debris 5", "AsteroidGroup2 Start 2")
		if (pObj):
			# Set objects Genus to Asteroid.
			pProperty = pObj.GetShipProperty()
			pProperty.SetGenus(App.GENUS_ASTEROID)

			pObj.SetScale (9.0)
			# Rotate object
			vVelocity = App.TGPoint3_GetModelForward()	# Get the vector to rotate around
			vVelocity.Scale( 10.0 * App.PI / 180.0 )		# Scale it to 10 degrees/second (converted to radians)
			pObj.SetAngularVelocity(vVelocity, App.PhysicsObjectClass.DIRECTION_MODEL_SPACE)
			# The Core objects can't take damage from the nebula.
			# Override the Environmental Damage handler for these.
			pObj.AddPythonFuncHandlerForInstance(App.ET_ENVIRONMENT_DAMAGE, "MissionLib.IgnoreEvent")

			# Create object
		pObj = loadspacehelper.CreateShip ("Asteroidh1", pSet, "Unknown Debris 6", "AsteroidGroup2 Start 3")
		if (pObj):
			# Set objects Genus to Asteroid.
			pProperty = pObj.GetShipProperty()
			pProperty.SetGenus(App.GENUS_ASTEROID)

			pObj.SetScale (9.0)
			# Rotate object
			vVelocity = App.TGPoint3_GetModelForward()	# Get the vector to rotate around
			vVelocity.Scale( 10.0 * App.PI / 180.0 )		# Scale it to 10 degrees/second (converted to radians)
			pObj.SetAngularVelocity(vVelocity, App.PhysicsObjectClass.DIRECTION_MODEL_SPACE)
			# The Core objects can't take damage from the nebula.
			# Override the Environmental Damage handler for these.
			pObj.AddPythonFuncHandlerForInstance(App.ET_ENVIRONMENT_DAMAGE, "MissionLib.IgnoreEvent")

			# Create object
		pObj = loadspacehelper.CreateShip ("Asteroidh1", pSet, "Unknown Debris 7", "AsteroidGroup2 Start 4")
		if (pObj):
			# Set objects Genus to Asteroid.
			pProperty = pObj.GetShipProperty()
			pProperty.SetGenus(App.GENUS_ASTEROID)

			pObj.SetScale (9.0)
			# Rotate object
			vVelocity = App.TGPoint3_GetModelForward()	# Get the vector to rotate around
			vVelocity.Scale( 10.0 * App.PI / 180.0 )		# Scale it to 10 degrees/second (converted to radians)
			pObj.SetAngularVelocity(vVelocity, App.PhysicsObjectClass.DIRECTION_MODEL_SPACE)
			# The Core objects can't take damage from the nebula.
			# Override the Environmental Damage handler for these.
			pObj.AddPythonFuncHandlerForInstance(App.ET_ENVIRONMENT_DAMAGE, "MissionLib.IgnoreEvent")

			# Create object
		pObj = loadspacehelper.CreateShip ("Asteroidh1", pSet, "Unknown Debris 8", "AsteroidGroup3 Start 1")
		if (pObj):
			# Set objects Genus to Asteroid.
			pProperty = pObj.GetShipProperty()
			pProperty.SetGenus(App.GENUS_ASTEROID)

			pObj.SetScale (9.0)
			# Rotate object
			vVelocity = App.TGPoint3_GetModelForward()	# Get the vector to rotate around
			vVelocity.Scale( 10.0 * App.PI / 180.0 )		# Scale it to 10 degrees/second (converted to radians)
			pObj.SetAngularVelocity(vVelocity, App.PhysicsObjectClass.DIRECTION_MODEL_SPACE)
			# The Core objects can't take damage from the nebula.
			# Override the Environmental Damage handler for these.
			pObj.AddPythonFuncHandlerForInstance(App.ET_ENVIRONMENT_DAMAGE, "MissionLib.IgnoreEvent")

			# Create object
		pObj = loadspacehelper.CreateShip ("Asteroidh1", pSet, "Unknown Debris 9", "AsteroidGroup3 Start 2")
		if (pObj):
			# Set objects Genus to Asteroid.
			pProperty = pObj.GetShipProperty()
			pProperty.SetGenus(App.GENUS_ASTEROID)

			pObj.SetScale (9.0)
			# Rotate object
			vVelocity = App.TGPoint3_GetModelForward()	# Get the vector to rotate around
			vVelocity.Scale( 10.0 * App.PI / 180.0 )		# Scale it to 10 degrees/second (converted to radians)
			pObj.SetAngularVelocity(vVelocity, App.PhysicsObjectClass.DIRECTION_MODEL_SPACE)
			# The Core objects can't take damage from the nebula.
			# Override the Environmental Damage handler for these.
			pObj.AddPythonFuncHandlerForInstance(App.ET_ENVIRONMENT_DAMAGE, "MissionLib.IgnoreEvent")

			# Create object
		pObj = loadspacehelper.CreateShip ("Asteroidh1", pSet, "Unknown Debris 10", "AsteroidGroup3 Start 3")
		if (pObj):
			# Set objects Genus to Asteroid.
			pProperty = pObj.GetShipProperty()
			pProperty.SetGenus(App.GENUS_ASTEROID)

			pObj.SetScale (9.0)
			# Rotate object
			vVelocity = App.TGPoint3_GetModelForward()	# Get the vector to rotate around
			vVelocity.Scale( 10.0 * App.PI / 180.0 )		# Scale it to 10 degrees/second (converted to radians)
			pObj.SetAngularVelocity(vVelocity, App.PhysicsObjectClass.DIRECTION_MODEL_SPACE)
			# The Core objects can't take damage from the nebula.
			# Override the Environmental Damage handler for these.
			pObj.AddPythonFuncHandlerForInstance(App.ET_ENVIRONMENT_DAMAGE, "MissionLib.IgnoreEvent")

			# Create object
		pObj = loadspacehelper.CreateShip ("Asteroidh1", pSet, "Unknown Debris 11", "AsteroidGroup4 Start 1")
		if (pObj):
			# Set objects Genus to Asteroid.
			pProperty = pObj.GetShipProperty()
			pProperty.SetGenus(App.GENUS_ASTEROID)

			pObj.SetScale (9.0)
			# Rotate object
			vVelocity = App.TGPoint3_GetModelForward()	# Get the vector to rotate around
			vVelocity.Scale( 10.0 * App.PI / 180.0 )		# Scale it to 10 degrees/second (converted to radians)
			pObj.SetAngularVelocity(vVelocity, App.PhysicsObjectClass.DIRECTION_MODEL_SPACE)
			# The Core objects can't take damage from the nebula.
			# Override the Environmental Damage handler for these.
			pObj.AddPythonFuncHandlerForInstance(App.ET_ENVIRONMENT_DAMAGE, "MissionLib.IgnoreEvent")

			# Create object
		pObj = loadspacehelper.CreateShip ("Asteroidh1", pSet, "Unknown Debris 12", "AsteroidGroup4 Start 2")
		if (pObj):
			# Set objects Genus to Asteroid.
			pProperty = pObj.GetShipProperty()
			pProperty.SetGenus(App.GENUS_ASTEROID)

			pObj.SetScale (9.0)
			# Rotate object
			vVelocity = App.TGPoint3_GetModelForward()	# Get the vector to rotate around
			vVelocity.Scale( 10.0 * App.PI / 180.0 )		# Scale it to 10 degrees/second (converted to radians)
			pObj.SetAngularVelocity(vVelocity, App.PhysicsObjectClass.DIRECTION_MODEL_SPACE)
			# The Core objects can't take damage from the nebula.
			# Override the Environmental Damage handler for these.
			pObj.AddPythonFuncHandlerForInstance(App.ET_ENVIRONMENT_DAMAGE, "MissionLib.IgnoreEvent")





