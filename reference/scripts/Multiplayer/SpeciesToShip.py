import App

# types for initializing objects create from C.
UNKNOWN = 0
AKIRA = 1
AMBASSADOR = 2
GALAXY = 3
NEBULA = 4
SOVEREIGN = 5
BIRDOFPREY = 6
VORCHA = 7
WARBIRD = 8
MARAUDER = 9
GALOR = 10
KELDON = 11
CARDHYBRID = 12
KESSOKHEAVY = 13
KESSOKLIGHT = 14
SHUTTLE = 15
CARDFREIGHTER = 16
FREIGHTER = 17
TRANSPORT = 18
SPACEFACILITY = 19
COMMARRAY = 20
COMMLIGHT = 21
DRYDOCK = 22
PROBE = 23
DECOY = 24
SUNBUSTER = 25
CARDOUTPOST = 26
CARDSTARBASE = 27
CARDSTATION = 28
FEDOUTPOST = 29
FEDSTARBASE = 30
ASTEROID = 31
ASTEROID1 = 32
ASTEROID2 = 33
ASTEROID3 = 34
AMAGON = 35
BIRANUSTATION = 36
ENTERPRISE = 37
GERONIMO = 38
PEREGRINE = 39
ASTEROIDH1 = 40
ASTEROIDH2 = 41
ASTEROIDH3 = 42
ESCAPEPOD = 43
KESSOKMINE = 44
BORGCUBE = 45
MAX_SHIPS = 46
MAX_FLYABLE_SHIPS = 16

# Setup tuples
kSpeciesTuple = (
	(None, 0, "Neutral", 0),
	("Akira", App.SPECIES_AKIRA, "Federation", 1),
	("Ambassador", App.SPECIES_AMBASSADOR, "Federation", 1),
	("Galaxy", App.SPECIES_GALAXY, "Federation", 1),
	("Nebula" , App.SPECIES_NEBULA, "Federation", 1),
	("Sovereign" , App.SPECIES_SOVEREIGN, "Federation", 1),
	("BirdOfPrey", App.SPECIES_BIRD_OF_PREY, "Klingon", 1),
	("Vorcha" , App.SPECIES_VORCHA, "Klingon", 1),
	("Warbird" , App.SPECIES_WARBIRD, "Romulan", 1),
	("Marauder" , App.SPECIES_MARAUDER, "Ferengi", 1),
	("Galor" , App.SPECIES_GALOR, "Cardassian", 1),
	("Keldon" , App.SPECIES_KELDON, "Cardassian", 1),
	("CardHybrid", App.SPECIES_CARDHYBRID, "Cardassian", 1),
	("KessokHeavy" , App.SPECIES_KESSOK_HEAVY, "Kessok", 1),
	("KessokLight" , App.SPECIES_KESSOK_LIGHT, "Kessok", 1),  
	("Shuttle" , App.SPECIES_SHUTTLE, "Federation", 1),
	("CardFreighter", "Cardassian Freighter" , App.SPECIES_CARDFREIGHTER, "Cardassian", 1),
	("Freighter" , App.SPECIES_FREIGHTER, "Federation", 1),
	("Transport" , App.SPECIES_TRANSPORT, "Federation", 1),
	("SpaceFacility" , App.SPECIES_SPACE_FACILITY, "Federation", 1),
	("CommArray" , App.SPECIES_COMMARRAY, "Federation", 1),
	("CommLight", App.SPECIES_COMMLIGHT, "Cardassian", 1),
	("DryDock" , App.SPECIES_DRYDOCK, "Federation", 1),
	("Probe" , App.SPECIES_PROBE, "Federation", 1),
	("Decoy" , App.SPECIES_PROBETYPE2, "Federation", 1),
	("Sunbuster" , App.SPECIES_SUNBUSTER, "Kessok", 1),
	("CardOutpost" , App.SPECIES_CARD_OUTPOST, "Cardassian", 1),
	("CardStarbase" , App.SPECIES_CARD_STARBASE, "Cardassian", 1),
	("CardStation" , App.SPECIES_CARD_STATION, "Cardassian", 1),
	("FedOutpost" , App.SPECIES_FED_OUTPOST, "Federation", 1),
	("FedStarbase" , App.SPECIES_FED_STARBASE, "Federation", 1),
	("Asteroid" , App.SPECIES_ASTEROID, "Neutral", 1),
	("Asteroid1" , App.SPECIES_ASTEROID, "Neutral", 1),
	("Asteroid2" , App.SPECIES_ASTEROID, "Neutral", 1),
	("Asteroid3" , App.SPECIES_ASTEROID, "Neutral", 1),
	("Amagon", App.SPECIES_ASTEROID, "Cardassian", 1),
	("BiranuStation", App.SPECIES_SPACE_FACILITY, "Neutral", 1),
	("Enterprise", App.SPECIES_SOVEREIGN, "Federation", 1),
	("Geronimo", App.SPECIES_AKIRA, "Federation", 1),
	("Peregrine", App.SPECIES_NEBULA, "Federation", 1),
	("Asteroidh1" , App.SPECIES_ASTEROID, "Neutral", 1),
	("Asteroidh2" , App.SPECIES_ASTEROID, "Neutral", 1),
	("Asteroidh3" , App.SPECIES_ASTEROID, "Neutral", 1),
	("Escapepod" , App.SPECIES_ESCAPEPOD, "Neutral", 1),
	("KessokMine" , App.SPECIES_KESSOKMINE, "Kessok", 1),
	("BorgCube",	App.SPECIES_BORG,		"Borg", 1),
	(None, 0, "Neutral", 1))


def GetShipFromSpecies (iSpecies):
	if (iSpecies <= 0 or iSpecies >= MAX_SHIPS):
#		print ("Species out of range")
		return None

	pSpecTuple = kSpeciesTuple [iSpecies]
	pcScript = pSpecTuple [0]

	ShipScript = __import__("ships." + pcScript)
	ShipScript.LoadModel ()
	return ShipScript.GetShipStats ()

def GetScriptFromSpecies (iSpecies):
	if (iSpecies <= 0 or iSpecies >= MAX_SHIPS):
		return None

	pSpecTuple = kSpeciesTuple [iSpecies]
	return pSpecTuple [0]

	
# This function is called from code to fill in the spec of
# an object that has been serialized over the net.
def InitObject (self, iType):
	kStats = GetShipFromSpecies (iType)
	if (kStats == None):
		# Failed.  Unknown type. Bail.
		return 0

	# Now that we have the stats, initialize the objects.
	# Initialize the ship's model.
	self.SetupModel (kStats['Name'])

	# Load hardpoints.
	pPropertySet = self.GetPropertySet()
	mod = __import__("ships.Hardpoints." + kStats['HardpointFile'])

	App.g_kModelPropertyManager.ClearLocalTemplates ()
	reload (mod)

	mod.LoadPropertySet(pPropertySet)

	self.SetupProperties()

	self.UpdateNodeOnly()
		
	return 1

def CreateShip (iType):
	# Get ship stats
	kStats = GetShipFromSpecies (iType)

	if (kStats == None):
		# Failed.  Unknown type. Bail.
		return None

#	print ("Creating " + kStats['Name'] + "\n")
	pShip = App.ShipClass_Create (kStats['Name'])

	sModule = "ships." + kSpeciesTuple [iType][0]
#	print ("*** Setting script module " + sModule)
	pShip.SetScript(sModule)

	# Load hardpoints.
	pPropertySet = pShip.GetPropertySet()
	mod = __import__("ships.Hardpoints." + kStats['HardpointFile'])

	App.g_kModelPropertyManager.ClearLocalTemplates ()
	reload(mod)

	mod.LoadPropertySet(pPropertySet)

	pShip.SetupProperties()

	pShip.UpdateNodeOnly()
		
	pShip.SetNetType (iType)

	return pShip

def GetIconNum (iSpecies):
	pSpecTuple = kSpeciesTuple [iSpecies]
	iNum = pSpecTuple [1]

	return iNum

def GetSideFromSpecies (iSpecies):
	pSpecTuple = kSpeciesTuple [iSpecies]
	pcSide = pSpecTuple [2]

	return pcSide

def GetClassFromSpecies (iSpecies):
	pSpecTuple = kSpeciesTuple [iSpecies]
	iClass = pSpecTuple [3]

	return iClass