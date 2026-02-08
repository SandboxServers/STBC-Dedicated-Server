###############################################################################
#	Filename:	Vesuvi5_S.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Creates Vesuvi 5 static objects.  Called by Vesuvi5.py when region is created
#	
#	Created:	12/26/00 -	Jess VanDerwalker
###############################################################################
import App
import loadspacehelper
import MissionLib

def Initialize(pSet):
#	print "Creating static objects for Vesuvi5 region"

	pPlanet = App.Planet_Create(110.0, "data/models/environment/GreenPlanet.nif")
	pSet.AddObjectToSet(pPlanet, "Geki")

	#Place the object at the specified location.
	pPlanet.PlaceObjectByName("Planet Location")
	pPlanet.UpdateNodeOnly()

	# Set the radius on the atomsphere
	pPlanet.SetAtmosphereRadius(120)

	pMoon = App.Planet_Create(85.0, "data/models/environment/RootBeerPlanet.nif")
	pSet.AddObjectToSet(pMoon, "Inyo")

	#Place the object at the specified location.
	pMoon.PlaceObjectByName("Moon1 Location")
	pMoon.UpdateNodeOnly()
	
	# Set the radius on the atomsphere
	pMoon.SetAtmosphereRadius(50)


	pMoon = App.Planet_Create(50.0, "data/models/environment/moon.nif")
	pSet.AddObjectToSet(pMoon, "Mori")

	#Place the object at the specified location.
	pMoon.PlaceObjectByName("Moon2 Location")
	pMoon.UpdateNodeOnly()

	# Set the radius on the atomsphere
	pMoon.SetAtmosphereRadius(50)


	# Create our static stations and such
	pGekiStation	= loadspacehelper.CreateShip("FedOutpost", pSet, "GekiStation", "Station Location")
	if (pGekiStation != None):
		# Damage the Geki station and give it rotation
		MissionLib.SetRandomRotation(pGekiStation, 2.0)
		# Damage it's hull
		pGekiStation.DamageSystem(pGekiStation.GetHull(), pGekiStation.GetHull().GetMaxCondition() * 0.80)
		MissionLib.HideSubsystems(pGekiStation)
		pGekiStation.SetAlertLevel(App.ShipClass.GREEN_ALERT)
	
	pSat1	= loadspacehelper.CreateShip("CommLight", pSet, "GekiSatellite1", "SatelliteStart1")
	pSat2	= loadspacehelper.CreateShip("CommLight", pSet, "GekiSatellite2", "SatelliteStart2")
	# Make the two satellites not hailable
	if (pSat1 != None):
		pSat1.SetHailable(0)
	if (pSat2 != None):
		pSat2.SetHailable(0)