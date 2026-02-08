import App

# types for initializing objects create from C.
UNKNOWN = 0
MULTI1 = 1
MULTI2 = 2
MULTI3 = 3
MULTI4 = 4
MULTI5 = 5
MULTI6 = 6
MULTI7 = 7
ALBIREA = 8
POSEIDON = 9

MAX_SYSTEMS = 10

# Setup tuple
kSpeciesTuple = (
	(UNKNOWN		, None),
	(MULTI1			, "Multi1"),
	(MULTI2			, "Multi2"),
	(MULTI3			, "Multi3"),
	(MULTI4			, "Multi4"),
	(MULTI5			, "Multi5"),
	(MULTI6			, "Multi6"),
	(MULTI7			, "Multi7"),
	(ALBIREA		, "Albirea"),
	(POSEIDON		, "Poseidon"),
	(MAX_SYSTEMS	, None))



def CreateSystemFromSpecies (iSpecies):
	if (iSpecies <= 0 or iSpecies >= MAX_SYSTEMS):
		return None

	pSpecTuple = kSpeciesTuple [iSpecies]
	pcScript = pSpecTuple [1]

	# import the module.
	pModule = __import__("Systems." + pcScript + "." + pcScript)

	# call CreateMenu function to create the system and setup warp menus
	pCourseMenu = pModule.CreateMenus ()
	pStartingSet = pCourseMenu.InitializeAllSets ()

	return pStartingSet

def GetScriptFromSpecies (iSpecies):
	if (iSpecies <= 0 or iSpecies >= MAX_SYSTEMS):
		return None

	pSpecTuple = kSpeciesTuple [iSpecies]
	return pSpecTuple [1]
	



	
