###############################################################################
#	Filename:	QuickBattle.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	A quick battle, or skirmish mode.
#	
#	Created:	1/10/01 -	Matthew Kagle
###############################################################################
import App
import loadspacehelper
import loadsplash
import MissionLib
import Bridge.TacticalMenuHandlers
#debug = App.CPyDebug(__name__).Print

###############################################################################
# UI Object sizes and positions

PLAYER_BUTTON_X_POS			= 0.21716
PLAYER_BUTTON_Y_POS			= 0.00
PLAYER_BUTTON_WIDTH			= 0.20156			
PLAYER_BUTTON_HEIGHT		= 0.034583

SHIPS_BUTTON_X_POS			= 0.0078
SHIPS_BUTTON_Y_POS			= 0.0
SHIPS_BUTTON_WIDTH			= 0.20156			
SHIPS_BUTTON_HEIGHT			= 0.034583

CLOSE_BUTTON_X_POS			= 0.6352825
CLOSE_BUTTON_Y_POS			= 0.0
CLOSE_BUTTON_WIDTH			= 0.13125
CLOSE_BUTTON_HEIGHT			= 0.034583

TOP_STYLIZED_X_POS			= 0.0
TOP_STYLIZED_Y_POS			= 0.0
TOP_STYLIZED_WIDTH			= 0.78125
TOP_STYLIZED_HEIGHT			= 0.0916667

MAIN_PANE_X_POS				= 0.1016
MAIN_PANE_Y_POS				= 0.0208333
MAIN_PANE_WIDTH				= 0.78125
MAIN_PANE_HEIGHT			= 0.9375

SUB_PANE_X_POS				= 0.0
SUB_PANE_Y_POS				= 0.0916667
SUB_PANE_WIDTH				= 0.78125
SUB_PANE_HEIGHT				= 0.8458333

REGION_MENU_X_POS			= 0.5390625
REGION_MENU_Y_POS			= 0.0083333
REGION_MENU_WIDTH			= 0.2421875
REGION_MENU_HEIGHT			= 0.8375

SHIP_MENU_X_POS				= 0.0
SHIP_MENU_Y_POS				= 0.0083333
SHIP_MENU_WIDTH				= 0.240625
SHIP_MENU_HEIGHT			= 0.8375

BAR_X_POS					= 0.240625
BAR_Y_POS					= 0.0083333
BAR_WIDTH					= 0.2609625
BAR_HEIGHT					= 0.0291666

SHIP_IMAGE_X_POS			= 0.250025
SHIP_IMAGE_Y_POS			= 0.04791657
SHIP_IMAGE_WIDTH			= 0.2515625
SHIP_IMAGE_HEIGHT			= 0.2458333

SHIPS_TEXT_X_POS			= 0.250025
SHIPS_TEXT_Y_POS			= 0.304166537 
SHIPS_TEXT_WIDTH			= 0.2515625
SHIPS_TEXT_HEIGHT			= 0.245833337

ADD_FRIEND_BUTTON_X_POS		= 0.2500257
ADD_FRIEND_BUTTON_Y_POS		= 0.560416537
ADD_FRIEND_BUTTON_WIDTH		= 0.2515625
ADD_FRIEND_BUTTON_HEIGHT	= 0.0354167

ADD_ENEMY_BUTTON_X_POS		= 0.250025
ADD_ENEMY_BUTTON_Y_POS		= 0.60416657
ADD_ENEMY_BUTTON_WIDTH		= 0.2515625
ADD_ENEMY_BUTTON_HEIGHT		= 0.0354167

AI_MENU_X_POS				= 0.250025
AI_MENU_Y_POS				= 0.654583
AI_MENU_WIDTH				= 0.2515625
AI_MENU_HEIGHT				= 0.19125

FRIEND_LIST_X_POS			= 0.5390625
FRIEND_LIST_Y_POS			= 0.0083333
FRIEND_LIST_WIDTH			= 0.2421875
FRIEND_LIST_HEIGHT			= 0.3354167

DOWN_BUTTON_X_POS			= 0.5390625
DOWN_BUTTON_Y_POS			= 0.3666667
DOWN_BUTTON_WIDTH			= 0.2421875
DOWN_BUTTON_HEIGHT			= 0.0291667

DEL_BUTTON_X_POS			= 0.5390625
DEL_BUTTON_Y_POS			= 0.4120834
DEL_BUTTON_WIDTH			= 0.2421875
DEL_BUTTON_HEIGHT			= 0.0291667

UP_BUTTON_X_POS				= 0.5390625
UP_BUTTON_Y_POS				= 0.4575001
UP_BUTTON_WIDTH				= 0.2421875
UP_BUTTON_HEIGHT			= 0.0291667

ENEMY_LIST_X_POS			= 0.5390625 
ENEMY_LIST_Y_POS			= 0.5020835
ENEMY_LIST_WIDTH			= 0.2421875
ENEMY_LIST_HEIGHT			= 0.3437498

PLAYER_TEXT_X_POS			= 0.250025
PLAYER_TEXT_Y_POS			= 0.304166537 
PLAYER_TEXT_WIDTH			= 0.2515625
PLAYER_TEXT_HEIGHT			= 0.274999996

BRIDGE_MENU_X_POS			= 0.250025
BRIDGE_MENU_Y_POS			= 0.5895832
BRIDGE_MENU_WIDTH			= 0.2515625
BRIDGE_MENU_HEIGHT			= 0.15625


###############################################################################
# Event types
ET_START_SIMULATION			= 0
ET_RESTART_SIMULATION		= 0
ET_END_SIMULATION			= 0
ET_OPEN_SHIPS_PANE			= 0
ET_OPEN_PLAYER_PANE			= 0
ET_SELECT_PLAYER_SHIP_TYPE	= 0
ET_SELECT_BRIDGE_TYPE		= 0
ET_SELECT_SHIP_TYPE			= 0
ET_SELECT_REGION_TYPE		= 0
ET_SELECT_AI				= 0
ET_ADD_AS_FRIEND			= 0
ET_ADD_AS_ENEMY				= 0
ET_CHANGE_FRIEND_TO_ENEMY	= 0
ET_CHANGE_ENEMY_TO_FRIEND	= 0
ET_SELECT_FRIEND			= 0
ET_SELECT_ENEMY				= 0
ET_DELETE					= 0
ET_OPEN_DIALOG			= 0
ET_CLOSE_DIALOG			= 0
ET_START_QUICKBATTLE		= 0
ET_PRELOAD_DONE			= 0

###############################################################################
# Levels of AI available for assignment to ships
AI_LOW					= 0.0
AI_MEDIUM				= 0.5
AI_HIGH					= 1.0


###############################################################################
# ship types as specified as accessible in Options.cfg

# Group One
KELDON			= 0x00000001
GALOR			= 0x00000002
WARBIRD			= 0x00000004
VORCHA			= 0x00000008

BOP				= 0x00000010
AMBASSADOR		= 0x00000020
NEBULA			= 0x00000040
AKIRA			= 0x00000080

GALAXY			= 0x00000100
SOVEREIGN		= 0x00000200
AMAGON			= 0x00000400
MARAUDER		= 0x00000800

KESSOK_LIGHT	= 0x00001000
KESSOK_HEAVY	= 0x00002000
HYBRID			= 0x00004000
FED_STARBASE	= 0x00008000

FED_OUTPOST		= 0x00010000
COMM_ARRAY		= 0x00020000
COMM_LIGHT		= 0x00040000
DRY_DOCK		= 0x00080000

SPACE_FACILITY	= 0x00100000
CARD_STARBASE	= 0x00200000
CARD_OUTPOST	= 0x00400000
CARD_STATION	= 0x00800000

ASTEROID		= 0x01000000
FREIGHTER		= 0x02000000
CARD_FREIGHTER	= 0x04000000
DECOY			= 0x08000000

PROBE			= 0x10000000
SHUTTLE			= 0x20000000
SUNBUSTER		= 0x40000000
TRANSPORT		= 0x80000000

# Group Two
BIRANU_STATION	= 0x00000001
BOMB_FREIGHTER	= 0x00000002
CARD_HYBRID		= 0x00000004
E2M0WARBIRD		= 0x00000008

ENTERPRISE		= 0x00000010
GERONIMO		= 0x00000020
MATAN_KELDON	= 0x00000040
PEREGRINE		= 0x00000080

RAN_KUF			= 0x00000100
BORG_CUBE		= 0x00000200
ESCAPE_POD		= 0x00000400
KESSOK_MINE		= 0x00000800

###############################################################################
# Star systems as specified as accessible in Options.cfg

# Group One
ALIOTH			= 0x00000001
ARTRUS			= 0x00000002
ASCELLA			= 0x00000004
BELARUZ			= 0x00000008

BEOL			= 0x00000010
BIRANU			= 0x00000020
CEBALRAI		= 0x00000040
VESUVI			= 0x00000080

CHAMBANA		= 0x00000100
DEEP_SPACE		= 0x00000200
GEBLE			= 0x00000400
ITARI			= 0x00000800

NEPENTHE		= 0x00001000
OMEGA_DRACONIS	= 0x00002000
ONA				= 0x00004000
POSEIDON		= 0x00008000

PRENDEL			= 0x00010000
QUICK_BATTLE	= 0x00020000
RIHA			= 0x00040000
SAVOY			= 0x00080000

SERRIS			= 0x00100000
#SHUBAM			= 0x00200000
#SOL	 		= 0x00400000
STARBASE12		= 0x00800000

#SUHAIL			= 0x01000000		
#TARAZED		= 0x02000000
#TAURUS			= 0x04000000
#TEJAT			= 0x08000000

TEVRON			= 0x10000000
TEZLE			= 0x20000000
VOLTAIR			= 0x40000000
#XAR_NEBULA		= 0x80000000

# Group Two
XI_ENTRADES		= 0x00000001
YILES			= 0x00000002
ALBIREA			= 0x00000004



###############################################################################
# ship types
ST_MARAUDER			= 0
ST_KELDON			= 1
ST_GALOR			= 2
ST_WARBIRD			= 3
ST_VORCHA			= 4
ST_BOP				= 5
ST_AMBASSADOR		= 6
ST_NEBULA			= 7
ST_AKIRA			= 8
ST_GALAXY			= 9
ST_SOVEREIGN		= 10
ST_KESSOK_LIGHT		= 11
ST_KESSOK_HEAVY		= 12
ST_HYBRID			= 13
ST_FED_STARBASE		= 14
ST_FED_OUTPOST		= 15
ST_COMM_ARRAY		= 16
ST_COMM_LIGHT		= 17
ST_DRY_DOCK			= 18
ST_SPACE_FACILITY	= 19
ST_CARD_STARBASE	= 20
ST_CARD_OUTPOST		= 21
ST_CARD_STATION		= 22
ST_ASTEROID			= 23
ST_FREIGHTER		= 24
ST_CARD_FREIGHTER	= 25
ST_DECOY			= 26
ST_PROBE			= 27
ST_SHUTTLE			= 28
ST_SUNBUSTER		= 29
ST_TRANSPORT		= 30
ST_AMAGON			= 31
ST_BIRANU_STATION	= 32
ST_BOMB_FREIGHTER	= 33
ST_CARD_HYBRID		= 34
ST_E2M0WARBIRD		= 35
ST_ENTERPRISE		= 36
ST_GERONIMO			= 37
ST_MATAN_KELDON		= 38
ST_PEREGRINE		= 39
ST_RAN_KUF			= 40
ST_BORG_CUBE		= 41
ST_ESCAPE_POD		= 42
ST_KESSOK_MINE		= 43


###############################################################################
# Global variables

# Make sure none of our global pointers are serialized
NonSerializedObjects = (
"g_pMissionDatabase",
"g_pGeneralDatabase",
"g_pMenusDatabase",
"g_pShipsDatabase",
"g_pOldFocus",
"g_pSet",
"g_pPane",
"g_pPlayerPane",
"g_pShipsPane",
"g_pShipsIcon",
"g_pShipsIconPane",
"g_pPlayerIcon",
"g_pPlayerIconPane",
"g_pShipsText",
"g_pShipsTextWindow",
"g_pPlayerText",
"g_pPlayerTextWindow",
"g_pAIMenu",
"g_pShipsButton",
"g_pPlayerButton",
"g_pAddEnemyButton",
"g_pAddFriendButton",
"g_pFriendMenu",
"g_pEnemyMenu",
"g_pFriendWindow",
"g_pEnemyWindow",
"g_pFriendToEnemyButton",
"g_pEnemyToFriendButton",
"g_pDeleteButton",
"g_pStartButton",
"g_pBridge",
"g_pHelm",
"g_pXO",
"g_pEng",
"g_pSci",
"g_pXOMenu",
"g_pTact",
"pFriendlies",
"pEnemies",
"g_dShipNameToIconNumber",
"g_dShipNameToType",
"g_dFriendlyShipTypeToDetails",
"g_dEnemyShipTypeToDetails",
"g_dShipTypeToIconNumber",
"g_kShips",
"g_kFriendList",
"g_kEnemyList"
#"debug"
)

####################################################
# These initial values are mirrored in Initialize().
####################################################
g_kWinSequenceTriggered = {}
g_kFailSequenceTriggered = {}

g_bDialogUp = 0
g_idTimer = App.NULL_ID
g_sPlayerType = "Galaxy"
g_sBridgeType = "GalaxyBridge"
g_pMissionDatabase = None
g_pGeneralDatabase = None
g_pMenusDatabase = None
g_pShipsDatabase = None
g_iNumFriends = 0
g_iNumEnemies = 0
bInSimulation = 0
bWonOrLost = 0
bInWarp = 0
bDockMenu = 0
g_sSelectedRegion = ""
g_sSelectedShipSide = ""
g_iSelectedShipType = -1
g_iSelectedEnemyShip = -1
g_iSelectedFriendlyShip = -1
g_iCurrentAILevel = -1
g_iSelectedAILevel = AI_MEDIUM
g_kShips = {}
g_kFriendList = []
g_kEnemyList = []
g_pOldFocus = None
g_bAddedUIHandlers = 0
g_pSet = None
g_pPane = None
g_pPlayerPane = None
g_pShipsPane = None
g_pShipsIcon = None
g_pShipsIconPane = None
g_pPlayerIcon = None
g_pPlayerIconPane = None
g_pShipsText = None
g_pShipsTextWindow = None
g_pPlayerText = None
g_pPlayerTextWindow = None
g_pAIMenu = None
g_pShipsButton = None
g_pPlayerButton = None
g_pAddEnemyButton = None
g_pAddFriendButton = None
g_pFriendMenu = None
g_pEnemyMenu = None
g_pFriendWindow = None
g_pEnemyWindow = None
g_pFriendToEnemyButton = None
g_pEnemyToFriendButton = None
g_pDeleteButton = None
g_pStartButton = None

g_pBridge	= None
g_pHelm		= None
g_pXO		= None
g_pEng		= None
g_pSci		= None
g_pXOMenu	= None
g_pTact		= None

pFriendlies	= None
pEnemies	= None

g_dShipNameToIconNumber = {
		"Marauder":			App.SPECIES_MARAUDER,
		"Keldon":			App.SPECIES_KELDON,
		"Galor":			App.SPECIES_GALOR,
		"Warbird":			App.SPECIES_WARBIRD,
		"Vorcha":			App.SPECIES_VORCHA,
		"BirdOfPrey":		App.SPECIES_BIRD_OF_PREY,
		"Ambassador":		App.SPECIES_AMBASSADOR,
		"Nebula":			App.SPECIES_NEBULA,
		"Akira":			App.SPECIES_AKIRA,
		"Galaxy":			App.SPECIES_GALAXY,
		"Sovereign":		App.SPECIES_SOVEREIGN,
		"KessokLight":		App.SPECIES_KESSOK_LIGHT,
		"KessokHeavy":		App.SPECIES_KESSOK_HEAVY,
		"CardHybrid":		App.SPECIES_CARDHYBRID,
		"FedStarbase":		App.SPECIES_FED_STARBASE,
		"FedOutpost":		App.SPECIES_FED_OUTPOST,
		"CommArray":		App.SPECIES_COMMARRAY,
		"CommLight":		App.SPECIES_COMMLIGHT,
		"DryDock":			App.SPECIES_DRYDOCK,
		"SpaceFacility":	App.SPECIES_SPACE_FACILITY,
		"CardStarbase":		App.SPECIES_CARD_STARBASE,
		"CardOutpost":		App.SPECIES_CARD_OUTPOST,
		"CardStation":		App.SPECIES_CARD_STATION,
		"Asteroid":			App.SPECIES_ASTEROID,
		"Freighter":		App.SPECIES_FREIGHTER,
		"CardFreighter":	App.SPECIES_CARDFREIGHTER,
		"Decoy":			App.SPECIES_PROBETYPE2,
		"Probe":			App.SPECIES_PROBE,
		"Shuttle":			App.SPECIES_SHUTTLE,
		"Sunbuster":		App.SPECIES_SUNBUSTER,
		"Transport":		App.SPECIES_TRANSPORT,
		"Amagon":			App.SPECIES_ASTEROID,
		"BiranuStation":	App.SPECIES_SPACE_FACILITY,
		"BombFreighter":	App.SPECIES_CARDFREIGHTER,
		"E2M0Warbird":		App.SPECIES_WARBIRD,
		"Enterprise":		App.SPECIES_SOVEREIGN,
		"Geronimo":			App.SPECIES_AKIRA,
		"MatanKeldon":		App.SPECIES_KELDON,
		"Peregrine":		App.SPECIES_NEBULA,
		"RanKuf":			App.SPECIES_BIRD_OF_PREY,
		"BorgCube":			App.SPECIES_BORG,
		"EscapePod":		App.SPECIES_ESCAPEPOD,
		"KessokMine":		App.SPECIES_KESSOKMINE,
}

g_dShipNameToType = {
		"Marauder":			ST_MARAUDER,
		"Keldon":			ST_KELDON,
		"Galor":			ST_GALOR,
		"Warbird":			ST_WARBIRD,
		"Vorcha":			ST_VORCHA,
		"BirdOfPrey":		ST_BOP,
		"Ambassador":		ST_AMBASSADOR,
		"Nebula":			ST_NEBULA,
		"Akira":			ST_AKIRA,
		"Galaxy":			ST_GALAXY,
		"Sovereign":		ST_SOVEREIGN,
		"KessokLight":		ST_KESSOK_LIGHT,
		"KessokHeavy":		ST_KESSOK_HEAVY,
		"CardHybrid":		ST_HYBRID,
		"FedStarbase":		ST_FED_STARBASE,
		"FedOutpost":		ST_FED_OUTPOST,
		"CommArray":		ST_COMM_ARRAY,
		"CommLight":		ST_COMM_LIGHT,
		"DryDock":			ST_DRY_DOCK,
		"SpaceFacility":	ST_SPACE_FACILITY,
		"CardStarbase":		ST_CARD_STARBASE,
		"CardOutpost":		ST_CARD_OUTPOST,
		"CardStation":		ST_CARD_STATION,
		"Asteroid":			ST_ASTEROID,
		"Freighter":		ST_FREIGHTER,
		"CardFreighter":	ST_CARD_FREIGHTER,
		"Decoy":			ST_DECOY,
		"Probe":			ST_PROBE,
		"Shuttle":			ST_SHUTTLE,
		"Sunbuster":		ST_SUNBUSTER,
		"Transport":		ST_TRANSPORT,
		"Amagon":			ST_AMAGON,
		"BiranuStation":	ST_BIRANU_STATION,
		"BombFreighter":	ST_BOMB_FREIGHTER,
		"CardHybrid":		ST_CARD_HYBRID,
		"E2M0Warbird":		ST_E2M0WARBIRD,
		"Enterprise":		ST_ENTERPRISE,
		"Geronimo":			ST_GERONIMO,
		"MatanKeldon":		ST_MATAN_KELDON,
		"Peregrine":		ST_PEREGRINE,
		"RanKuf":			ST_RAN_KUF,
		"BorgCube":			ST_BORG_CUBE,
		"EscapePod":		ST_ESCAPE_POD,
		"KessokMine":		ST_KESSOK_MINE,
}

g_dFriendlyShipTypeToDetails = {
		ST_SOVEREIGN:		["Sovereign",		"Sovereign",		"QBFriendlySovereignDestroyed",		"QuickBattleFriendlyAI",	"Friendly"],
		ST_GALAXY:			["Galaxy",			"Galaxy",			"QBFriendlyGalaxyDestroyed",		"QuickBattleFriendlyAI",	"Friendly"],
		ST_AKIRA:		    ["Akira",			"Akira",			"QBFriendlyAkiraDestroyed",			"QuickBattleFriendlyAI",	"Friendly"],
		ST_NEBULA:			["Nebula",			"Nebula",			"QBFriendlyNebulaDestroyed",		"QuickBattleFriendlyAI",	"Friendly"],
		ST_MARAUDER:		["Marauder",		"Marauder",			"QBFriendlyMarauderDestroyed",		"QuickBattleFriendlyAI",	"Friendly"],
		ST_WARBIRD:			["Warbird",			"Warbird",			"QBFriendlyWarbirdDestroyed",		"QuickBattleFriendlyAI",	"Friendly"],
		ST_BOP:				["BirdOfPrey",		"BOP",				"QBFriendlyBOPDestroyed",			"QuickBattleFriendlyAI",	"Friendly"],
		ST_VORCHA:			["Vorcha",			"Vorcha",			"QBFriendlyVorchaDestroyed",		"QuickBattleFriendlyAI",	"Friendly"],
		ST_GALOR:		    ["Galor",			"Galor",			"QBFriendlyGalorDestroyed",			"QuickBattleFriendlyAI",	"Friendly"],
		ST_KELDON:			["Keldon",			"Keldon",			"QBFriendlyKeldonDestroyed",		"QuickBattleFriendlyAI",	"Friendly"],
		ST_AMBASSADOR:		["Ambassador",		"Ambassador",		"QBFriendlyAmbassadorDestroyed",	"QuickBattleFriendlyAI",	"Friendly"],
		ST_KESSOK_LIGHT:	["KessokLight",		"Kessok Light",		"QBFriendlyGenericShipDestroyed",   "QuickBattleFriendlyAI",	"Friendly"],
		ST_KESSOK_HEAVY:	["KessokHeavy",		"Kessok Heavy",		"QBFriendlyGenericShipDestroyed",   "QuickBattleFriendlyAI",	"Friendly"],
		ST_FED_STARBASE:	["FedStarbase",		"Fed Starbase",		"QBFriendlyGenericShipDestroyed",   "StarbaseFriendlyAI",		"Friendly"],
		ST_FED_OUTPOST:		["FedOutpost",		"Fed Outpost",		"QBFriendlyGenericShipDestroyed",   "StarbaseFriendlyAI",		"Friendly"],
		ST_COMM_ARRAY:		["CommArray",		"Comm Array",		"QBFriendlyGenericShipDestroyed",   "StarbaseFriendlyAI",		"Friendly"],
		ST_COMM_LIGHT:		["CommLight",		"Comm Light",		"QBFriendlyGenericShipDestroyed",   "StarbaseFriendlyAI",		"Friendly"],
		ST_DRY_DOCK:		["DryDock",			"Dry Dock",			"QBFriendlyGenericShipDestroyed",   "StarbaseFriendlyAI",		"Friendly"],
		ST_SPACE_FACILITY:	["SpaceFacility",	"Space Facility",	"QBFriendlyGenericShipDestroyed",   "StarbaseFriendlyAI",		"Friendly"],
		ST_CARD_STARBASE:	["CardStarbase",	"Card Starbase",	"QBFriendlyGenericShipDestroyed",   "StarbaseFriendlyAI",		"Friendly"],
		ST_CARD_OUTPOST:	["CardOutpost",		"Card Outpost",		"QBFriendlyGenericShipDestroyed",   "StarbaseFriendlyAI",		"Friendly"],
		ST_CARD_STATION:	["CardStation",		"Card Station",		"QBFriendlyGenericShipDestroyed",   "StarbaseFriendlyAI",		"Friendly"],
		ST_ASTEROID:		["Asteroid",		"Asteroid",			"QBFriendlyGenericShipDestroyed",   "QuickBattleFriendlyAI",	"Friendly"],
		ST_FREIGHTER:	    ["Freighter",		"Freighter",		"QBFriendlyGenericShipDestroyed",   "QuickBattleFriendlyAI",	"Friendly"],
		ST_CARD_FREIGHTER:	["CardFreighter",	"Card Freighter",	"QBFriendlyGenericShipDestroyed",   "QuickBattleFriendlyAI",	"Friendly"],
		ST_DECOY:		    ["Decoy",			"Decoy",			"QBFriendlyGenericShipDestroyed",   "QuickBattleFriendlyAI",	"Friendly"],
		ST_PROBE:		    ["Probe",			"Probe",			"QBFriendlyGenericShipDestroyed",   "QuickBattleFriendlyAI",	"Friendly"],
		ST_SHUTTLE:			["Shuttle",			"Shuttle",			"QBFriendlyGenericShipDestroyed",   "QuickBattleFriendlyAI",	"Friendly"],
		ST_SUNBUSTER:	    ["Sunbuster",		"Sun Buster",		"QBFriendlyGenericShipDestroyed",   "QuickBattleFriendlyAI",	"Friendly"],
		ST_TRANSPORT:	    ["Transport",		"Transport",		"QBFriendlyGenericShipDestroyed",   "QuickBattleFriendlyAI",	"Friendly"],
		ST_AMAGON:			["Amagon",			"Amagon",			"QBFriendlyAmagonDestroyed",		"QuickBattleFriendlyAI",	"Friendly"],
		ST_BIRANU_STATION:	["BiranuStation",	"Biranu Station",	"QBFriendlyBiranuStationDestroyed",	"QuickBattleFriendlyAI",	"Friendly"],
		ST_BOMB_FREIGHTER:	["BombFreighter",	"Bomb Freighter",	"QBFriendlyBombFreighterDestroyed", "QuickBattleFriendlyAI",	"Friendly"],
		ST_CARD_HYBRID:		["CardHybrid",		"Card Hybrid",		"QBFriendlyCardHybridDestroyed",	"QuickBattleFriendlyAI",	"Friendly"],
		ST_E2M0WARBIRD:		["E2M0Warbird",		"E2M0Warbird",		"QBFriendlyE2M0WarbirdDestroyed",   "QuickBattleFriendlyAI",	"Friendly"],
		ST_ENTERPRISE:		["Enterprise",		"Enterprise",		"QBFriendlyEnterpriseEnter",	    "QuickBattleFriendlyAI",	"Friendly"],
		ST_GERONIMO:		["Geronimo",		"Geronimo",			"QBFriendlyGeronimoEnter",			"QuickBattleFriendlyAI",	"Friendly"],
		ST_MATAN_KELDON:	["MatanKeldon",		"Matan Keldon",		"QBFriendlyMatanKeldonEnter",		"QuickBattleFriendlyAI",	"Friendly"],
		ST_PEREGRINE:	    ["Peregrine",		"Peregrine",		"QBFriendlyPeregrineEnter",			"QuickBattleFriendlyAI",	"Friendly"],
		ST_RAN_KUF:			["RanKuf",			"Ran Kuf",			"QBFriendlyRanKufEnter",			"QuickBattleFriendlyAI",	"Friendly"],
		ST_BORG_CUBE:		["BorgCube",		"Borg Cube",  		"QBFriendlyGenericShipDestroyed", 	"QuickBattleFriendlyAI",	"Friendly"],
		ST_ESCAPE_POD:		["EscapePod",		"Escape Pod",  		"QBFriendlyGenericShipDestroyed", 	"QuickBattleFriendlyAI",	"Friendly"],
		ST_KESSOK_MINE:		["KessokMine",		"Kessok Mine", 		"QBFriendlyGenericShipDestroyed", 	"QuickBattleFriendlyAI",	"Friendly"],
}

g_dEnemyShipTypeToDetails = {
		ST_SOVEREIGN:		["Sovereign",		"Sovereign",		"QBEnemySovereignDestroyed",	"QuickBattleAI",	"Enemy"],
		ST_GALAXY:			["Galaxy",			"Galaxy",			"QBEnemyGalaxyDestroyed",		"QuickBattleAI",	"Enemy"],
		ST_AKIRA:		    ["Akira",			"Akira",			"QBEnemyAkiraDestroyed",		"QuickBattleAI",	"Enemy"],
		ST_NEBULA:			["Nebula",			"Nebula",			"QBEnemyNebulaDestroyed",		"QuickBattleAI",	"Enemy"],
		ST_MARAUDER:		["Marauder",		"Marauder",			"QBEnemyMarauderDestroyed",		"QuickBattleAI",	"Enemy"],
		ST_WARBIRD:			["Warbird",			"Warbird",			"QBEnemyWarbirdDestroyed",		"QuickBattleAI",	"Enemy"],
		ST_BOP:				["BirdOfPrey",		"BOP",				"QBEnemyBOPDestroyed",			"QuickBattleAI",	"Enemy"],
		ST_VORCHA:			["Vorcha",			"Vorcha",			"QBEnemyVorchaDestroyed",		"QuickBattleAI",	"Enemy"],
		ST_GALOR:		    ["Galor",			"Galor",			"QBEnemyGalorDestroyed",		"QuickBattleAI",	"Enemy"],
		ST_KELDON:			["Keldon",			"Keldon",			"QBEnemyKeldonDestroyed",		"QuickBattleAI",	"Enemy"],
		ST_AMBASSADOR:		["Ambassador",		"Ambassador",		"QBEnemyAmbassadorDestroyed",	"QuickBattleAI",	"Enemy"],
		ST_KESSOK_LIGHT:	["KessokLight",		"Kessok Light",		"QBEnemyGenericShipDestroyed",  "QuickBattleAI",	"Enemy"],
		ST_KESSOK_HEAVY:	["KessokHeavy",		"Kessok Heavy",		"QBEnemyGenericShipDestroyed",  "QuickBattleAI",	"Enemy"],
		ST_FED_STARBASE:	["FedStarbase",		"Fed Starbase",		"QBEnemyGenericShipDestroyed",  "StarbaseAI",		"Enemy"],
		ST_FED_OUTPOST:		["FedOutpost",		"Fed Outpost",		"QBEnemyGenericShipDestroyed",  "StarbaseAI",		"Enemy"],
		ST_COMM_ARRAY:		["CommArray",		"Comm Array",		"QBEnemyGenericShipDestroyed",  "StarbaseAI",		"Enemy"],
		ST_COMM_LIGHT:		["CommLight",		"Comm Light",		"QBEnemyGenericShipDestroyed",  "StarbaseAI",		"Enemy"],
		ST_DRY_DOCK:		["DryDock",			"Dry Dock",			"QBEnemyGenericShipDestroyed",  "StarbaseAI",		"Enemy"],
		ST_SPACE_FACILITY:	["SpaceFacility",	"Space Facility",	"QBEnemyGenericShipDestroyed",  "StarbaseAI",		"Enemy"],
		ST_CARD_STARBASE:	["CardStarbase",	"Card Starbase",	"QBEnemyGenericShipDestroyed",  "StarbaseAI",		"Enemy"],
		ST_CARD_OUTPOST:	["CardOutpost",		"Card Outpost",		"QBEnemyGenericShipDestroyed",  "StarbaseAI",		"Enemy"],
		ST_CARD_STATION:	["CardStation",		"Card Station",		"QBEnemyGenericShipDestroyed",  "StarbaseAI",		"Enemy"],
		ST_ASTEROID:		["Asteroid",		"Asteroid",			"QBEnemyGenericShipDestroyed",  "QuickBattleAI",	"Enemy"],
		ST_FREIGHTER:	    ["Freighter",		"Freighter",		"QBEnemyGenericShipDestroyed",  "QuickBattleAI",	"Enemy"],
		ST_CARD_FREIGHTER:	["CardFreighter",	"Card Freighter",	"QBEnemyGenericShipDestroyed",  "QuickBattleAI",	"Enemy"],
		ST_DECOY:		    ["Decoy",			"Decoy",			"QBEnemyGenericShipDestroyed",  "QuickBattleAI",	"Enemy"],
		ST_PROBE:		    ["Probe",			"Probe",			"QBEnemyGenericShipDestroyed",  "QuickBattleAI",	"Enemy"],
		ST_SHUTTLE:			["Shuttle",			"Shuttle",			"QBEnemyGenericShipDestroyed",  "QuickBattleAI",	"Enemy"],
		ST_SUNBUSTER:	    ["Sunbuster",		"Sun Buster",		"QBEnemyGenericShipDestroyed",  "QuickBattleAI",	"Enemy"],
		ST_TRANSPORT:	    ["Transport",		"Transport",		"QBEnemyGenericShipDestroyed",  "QuickBattleAI",	"Enemy"],
		ST_AMAGON:			["Amagon",			"Amagon",			"QBEnemyAmagonDestroyed",		"QuickBattleAI",	"Enemy"],
		ST_BIRANU_STATION:	["BiranuStation",	"Biranu Station",	"QBEnemyBiranuStationDestroyed","QuickBattleAI",	"Enemy"],
		ST_BOMB_FREIGHTER:	["BombFreighter",	"Bomb Freighter",	"QBEnemyBombFreighterDestroyed","QuickBattleAI",	"Enemy"],
		ST_CARD_HYBRID:		["CardHybrid",		"Card Hybrid",		"QBEnemyCardHybridDestroyed",	"QuickBattleAI",	"Enemy"],
		ST_E2M0WARBIRD:		["E2M0Warbird",		"E2M0Warbird",		"QBEnemyE2M0WarbirdDestroyed",  "QuickBattleAI",	"Enemy"],
		ST_ENTERPRISE:		["Enterprise",		"Enterprise",		"QBEnemyEnterpriseEnter",	    "QuickBattleAI",	"Enemy"],
		ST_GERONIMO:		["Geronimo",		"Geronimo",			"QBEnemyGeronimoEnter",			"QuickBattleAI",	"Enemy"],
		ST_MATAN_KELDON:	["MatanKeldon",		"Matan Keldon",		"QBEnemyMatanKeldonEnter",		"QuickBattleAI",	"Enemy"],
		ST_PEREGRINE:	    ["Peregrine",		"Peregrine",		"QBEnemyPeregrineEnter",		"QuickBattleAI",	"Enemy"],
		ST_RAN_KUF:			["RanKuf",			"Ran Kuf",			"QBEnemyRanKufEnter",			"QuickBattleAI",	"Enemy"],
		ST_BORG_CUBE:		["BorgCube",		"Borg Cube",  		"QBEnemyGenericShipDestroyed",	"QuickBattleAI",	"Enemy"],
		ST_ESCAPE_POD:		["EscapePod",		"Escape Pod",  		"QBEnemyGenericShipDestroyed", 	"QuickBattleAI",	"Enemy"],
		ST_KESSOK_MINE:		["KessokMine",		"Kessok Mine", 		"QBEnemyGenericShipDestroyed", 	"QuickBattleAI",	"Enemy"],
}


g_dShipTypeToIconNumber = {
		ST_MARAUDER:		App.SPECIES_MARAUDER,
		ST_KELDON:			App.SPECIES_KELDON,
		ST_GALOR:			App.SPECIES_GALOR,
		ST_WARBIRD:			App.SPECIES_WARBIRD,
		ST_VORCHA:			App.SPECIES_VORCHA,
		ST_BOP:				App.SPECIES_BIRD_OF_PREY,
		ST_AMBASSADOR:		App.SPECIES_AMBASSADOR,
		ST_NEBULA:			App.SPECIES_NEBULA,
		ST_AKIRA:			App.SPECIES_AKIRA,
		ST_GALAXY:			App.SPECIES_GALAXY,
		ST_SOVEREIGN:		App.SPECIES_SOVEREIGN,
		ST_KESSOK_LIGHT:	App.SPECIES_KESSOK_LIGHT,
		ST_KESSOK_HEAVY:	App.SPECIES_KESSOK_HEAVY,
		ST_HYBRID:			App.SPECIES_CARDHYBRID,
		ST_FED_STARBASE:	App.SPECIES_FED_STARBASE,
		ST_FED_OUTPOST:		App.SPECIES_FED_OUTPOST,
		ST_COMM_ARRAY:		App.SPECIES_COMMARRAY,
		ST_COMM_LIGHT:		App.SPECIES_COMMLIGHT,
		ST_DRY_DOCK:		App.SPECIES_DRYDOCK,
		ST_SPACE_FACILITY:	App.SPECIES_SPACE_FACILITY,
		ST_CARD_STARBASE:	App.SPECIES_CARD_STARBASE,
		ST_CARD_OUTPOST:	App.SPECIES_CARD_OUTPOST,
		ST_CARD_STATION:	App.SPECIES_CARD_STATION,
		ST_ASTEROID:		App.SPECIES_ASTEROID,
		ST_FREIGHTER:		App.SPECIES_FREIGHTER,
		ST_CARD_FREIGHTER:	App.SPECIES_CARDFREIGHTER,
		ST_DECOY:			App.SPECIES_PROBETYPE2,
		ST_PROBE:			App.SPECIES_PROBE,
		ST_SHUTTLE:			App.SPECIES_SHUTTLE,
		ST_SUNBUSTER:		App.SPECIES_SUNBUSTER,
		ST_TRANSPORT:		App.SPECIES_TRANSPORT,
		ST_AMAGON:			App.SPECIES_ASTEROID,
		ST_BIRANU_STATION:	App.SPECIES_SPACE_FACILITY,
		ST_BOMB_FREIGHTER:	App.SPECIES_CARDFREIGHTER,
		ST_CARD_HYBRID:		App.SPECIES_CARDHYBRID,
		ST_E2M0WARBIRD:		App.SPECIES_WARBIRD,
		ST_ENTERPRISE:		App.SPECIES_SOVEREIGN,
		ST_GERONIMO:		App.SPECIES_AKIRA,
		ST_MATAN_KELDON:	App.SPECIES_KELDON,
		ST_PEREGRINE:		App.SPECIES_NEBULA,
		ST_RAN_KUF:			App.SPECIES_BIRD_OF_PREY,
		ST_BORG_CUBE:		App.SPECIES_BORG,
		ST_ESCAPE_POD:		App.SPECIES_ESCAPEPOD,
		ST_KESSOK_MINE:		App.SPECIES_KESSOKMINE,
}


###############################################################################
#	PreLoadAssets()
#	
#	This is called once, at the beginning of the mission before Initialize()
#	to allow us to add models to be pre loaded
#	
#	Args:	pMission	- the Mission object
#	
#	Return:	none
###############################################################################
def PreLoadAssets(pMission):
	import ships.Galaxy
	ships.Galaxy.PreLoadModel()


###############################################################################
#	Initialize()
#	
#	This is called once, at the beginning of the mission
#	
#	Args:	pMission	- the Mission object
#	
#	Return:	none
###############################################################################
def Initialize(pMission):
	# Set the difficulty level.
	App.Game_SetDifficultyMultipliers(1.0, 1.0, 1.0, 1.0, 1.0, 1.0)

	GlobalsForEvents()
	InitGlobals()

	# Get the localization database for the mission, as well as the bridge
	# crew database.
	global g_pMissionDatabase, g_pGeneralDatabase, g_pMenusDatabase, g_pShipsDatabase
	g_pMissionDatabase = pMission.SetDatabase("data/TGL/QuickBattle/QuickBattle.tgl")
	g_pGeneralDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")
	g_pMenusDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	g_pShipsDatabase = App.g_kLocalizationManager.Load("data/TGL/Ships.tgl")

	# Specify (and load if necessary) our bridge
	import LoadBridge
	LoadBridge.Load("GalaxyBridge")

	# Assign global pointers for bridge and bridge crew
	AssignGlobalPointers()

	# Add Quick Battle set
	import Systems.QuickBattle.QuickBattleRegion
	Systems.QuickBattle.QuickBattleRegion.Initialize()
	global g_pSet
	g_pSet = App.g_kSetManager.GetSet("QuickBattleRegion")
	
	# Disable "Contact Starfleet" button
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	pContactButton = g_pXOMenu.GetButtonW(pDatabase.GetString("Contact Starfleet"))
	pContactButton.SetNotVisible()

	###Unload database
	App.g_kLocalizationManager.Unload(pDatabase)

	# Disable "Objectives" menu
	pMenuDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pObjectivesMenu = g_pXOMenu.GetSubmenuW(pMenuDatabase.GetString("Objectives"))
	App.g_kLocalizationManager.Unload(pMenuDatabase)
	pObjectivesMenu.SetNotVisible()
	

	############################
	# Create the starting ships.
	pPlayer = RecreatePlayer()

	# Set up our event handlers, and start the dialogue.
	SetupEventHandlers()
	BuildDialog()
	CreateSimulationMenus()
	QBExposition ()

#	debug("Finished loading " + __name__)


	######################
	# Setup Affiliations #
	global pFriendlies
	global pEnemies
	
	pGame = App.Game_GetCurrentGame()
	pEpisode = pGame.GetCurrentEpisode()
	pMission = pEpisode.GetCurrentMission()
	pEnemies = pMission.GetEnemyGroup()
	pFriendlies = pMission.GetFriendlyGroup()
	pFriendlies.AddName(pPlayer.GetName())

	# Turn on friendly fire warnings
	MissionLib.SetupFriendlyFireNoGameOver()
	App.g_kUtopiaModule.SetCurrentFriendlyFire(0)		# Call this when you re-create the ship, too
	App.g_kUtopiaModule.SetFriendlyFireWarningPoints(300)

	pMission.AddPythonFuncHandlerForInstance(App.ET_FRIENDLY_FIRE_REPORT,	__name__ + ".FriendlyFireWarningHandler")


###############################################################################
#	Terminate()
#	
#	This is called once, at the end of the mission.  Used for freeing any
#	resources that might have been acquired
#	
#	Args:	pMission	- the Mission object
#	
#	Return:	none
###############################################################################
def Terminate(pMission):

	# Turn off friendly fire warnings
	MissionLib.ShutdownFriendlyFireNoGameOver()

	global g_idTimer
	if(g_idTimer != App.NULL_ID):
		App.g_kTimerManager.DeleteTimer(g_idTimer)
		g_idTimer = App.NULL_ID
	
	global g_pMissionDatabase, g_pGeneralDatabase, g_pMenusDatabase, g_pShipsDatabase

	# Re-enable "Contact Starfleet" button
	# Disable "Contact Starfleet" button
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	pContactButton = g_pXOMenu.GetButtonW(pDatabase.GetString("Contact Starfleet"))
	pContactButton.SetVisible()

	###Unload database
	App.g_kLocalizationManager.Unload(pDatabase)

	# Re-enable "Objectives" menu
	# Disable "Objectives" menu
	pObjectivesMenu = g_pXOMenu.GetSubmenuW(g_pMenusDatabase.GetString("Objectives"))
	pObjectivesMenu.SetVisible()

	# Destroy our Dialog box
	# Remove focus objects first.
	App.g_kFocusManager.RemoveAllObjectsUnder (g_pPane)

	pTopWindow = App.TopWindow_GetTopWindow()
	pTopWindow.DeleteChild(g_pPane)
	global g_pPane
	global g_pShipsPane
	global g_pShipsIcon
	global g_pShipsIconPane
	global g_pPlayerIcon
	global g_pPlayerIconPane
	global g_pShipsText
	global g_pShipsTextWindow
	global g_pPlayerText
	global g_pPlayerTextWindow
	global g_pAIMenu
	global g_pShipsButton
	global g_pPlayerButton
	global g_pAddEnemyButton
	global g_pAddFriendButton
	global g_pFriendMenu
	global g_pEnemyMenu
	global g_pFriendWindow
	global g_pEnemyWindow
	global g_pFriendToEnemyButton
	global g_pEnemyToFriendButton
	global g_pDeleteButton

	g_pPane = None
	g_pShipsPane = None
	g_pShipsIcon = None
	g_pShipsIconPane = None
	g_pPlayerIcon = None
	g_pPlayerIconPane = None
	g_pShipsText = None
	g_pShipsTextWindow = None
	g_pPlayerText = None
	g_pPlayerTextWindow = None
	g_pAIMenu = None
	g_pShipsButton = None
	g_pPlayerButton = None
	g_pAddEnemyButton = None
	g_pAddFriendButton = None
	g_pFriendMenu = None
	g_pEnemyMenu = None
	g_pFriendWindow = None
	g_pEnemyWindow = None
	g_pFriendToEnemyButton = None
	g_pEnemyToFriendButton = None
	g_pDeleteButton = None

#	if (g_pMissionDatabase != None):
#		App.g_kLocalizationManager.Unload(g_pMissionDatabase)
	# No need to unload mission database.  That will be done by the mission destructor.
	g_pMissionDatabase = None
	if (g_pGeneralDatabase != None):
		App.g_kLocalizationManager.Unload(g_pGeneralDatabase)
		g_pGeneralDatabase = None
	if (g_pMenusDatabase != None):
		App.g_kLocalizationManager.Unload(g_pMenusDatabase)
		g_pMenusDatabase = None
	if (g_pShipsDatabase != None):
		App.g_kLocalizationManager.Unload(g_pShipsDatabase)
		g_pShipsDatabase = None
	
	# Clear dictionaries
	global g_kWinSequenceTriggered
	global g_kFailSequenceTriggered

	for iKey in g_kWinSequenceTriggered.keys ():
		del g_kWinSequenceTriggered [iKey]		

	for iKey in g_kFailSequenceTriggered.keys ():
		del g_kFailSequenceTriggered [iKey]		

	global g_bDialogUp
	g_bDialogUp = 1

	global pFriendlies
	global pEnemies
	pFriendlies = None
	pEnemies = None

###############################################################################
#	InitGlobals()
#	
#	Initializes global variables.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def InitGlobals():
	global g_kWinSequenceTriggered, g_kFailSequenceTriggered
	global g_idTimer, g_sPlayerType, g_sBridgeType, g_pMissionDatabase, g_pGeneralDatabase, g_pMenusDatabase, g_pShipsDatabase
	global g_iNumFriends, g_iNumEnemies, bInSimulation, bWonOrLost, bInWarp, bDockMenu, g_sSelectedRegion, g_sSelectedShipSide
	global g_iSelectedShipType, g_iSelectedEnemyShip, g_iSelectedFriendlyShip, g_iCurrentAILevel, g_iSelectedAILevel
	global g_kShips, g_kFriendList, g_kEnemyList, g_pOldFocus, g_bAddedUIHandlers, g_pSet, g_pPane, g_pPlayerPane
	global g_pShipsPane, g_pShipsIcon, g_pShipsIconPane, g_pPlayerIcon, g_pPlayerIconPane, g_pShipsText, g_pShipsTextWindow
	global g_pPlayerText, g_pPlayerTextWindow, g_pAIMenu, g_pShipsButton, g_pPlayerButton, g_pAddEnemyButton, g_pAddFriendButton
	global g_pFriendMenu, g_pEnemyMenu, g_pFriendWindow, g_pEnemyWindow, g_pFriendToEnemyButton, g_pEnemyToFriendButton, g_pDeleteButton
	global g_pStartButton, g_pBridge, g_pHelm, g_pXO, g_pEng, g_pSci, g_pXOMenu, g_pTact
	global g_bDialogUp

	g_kWinSequenceTriggered = {}
	g_kFailSequenceTriggered = {}

	g_idTimer = App.NULL_ID
	g_sPlayerType = "Galaxy"
	g_sBridgeType = "GalaxyBridge"
	g_pMissionDatabase = None
	g_pGeneralDatabase = None
	g_pMenusDatabase = None
	g_pShipsDatabase = None
	g_iNumFriends = 0
	g_iNumEnemies = 0
	bInSimulation = 0
	bWonOrLost = 0
	bInWarp = 0
	bDockMenu = 0
	g_sSelectedRegion = ""
	g_sSelectedShipSide = ""
	g_iSelectedShipType = -1
	g_iSelectedEnemyShip = -1
	g_iSelectedFriendlyShip = -1
	g_iCurrentAILevel = -1
	g_iSelectedAILevel = AI_MEDIUM
	g_kShips = {}
	g_kFriendList = []
	g_kEnemyList = []
	g_pOldFocus = None
	g_bAddedUIHandlers = 0
	g_pSet = None
	g_pPane = None
	g_pPlayerPane = None
	g_pShipsPane = None
	g_pShipsIcon = None
	g_pShipsIconPane = None
	g_pPlayerIcon = None
	g_pPlayerIconPane = None
	g_pShipsText = None
	g_pShipsTextWindow = None
	g_pPlayerText = None
	g_pPlayerTextWindow = None
	g_pAIMenu = None
	g_pShipsButton = None
	g_pPlayerButton = None
	g_pAddEnemyButton = None
	g_pAddFriendButton = None
	g_pFriendMenu = None
	g_pEnemyMenu = None
	g_pFriendWindow = None
	g_pEnemyWindow = None
	g_pFriendToEnemyButton = None
	g_pEnemyToFriendButton = None
	g_pDeleteButton = None
	g_pStartButton = None

	g_pBridge	= None
	g_pHelm		= None
	g_pXO		= None
	g_pEng		= None
	g_pSci		= None
	g_pXOMenu	= None
	g_pTact		= None

	g_bDialogUp = 0


###############################################################################
#	GlobalsForEvents()
#	
#	Setup our global event types
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def GlobalsForEvents():
	global ET_RESTART_SIMULATION
	global ET_START_SIMULATION			
	global ET_END_SIMULATION			
	global ET_OPEN_SHIPS_PANE
	global ET_OPEN_PLAYER_PANE
	global ET_SELECT_PLAYER_SHIP_TYPE
	global ET_SELECT_BRIDGE_TYPE
	global ET_SELECT_SHIP_TYPE			
	global ET_SELECT_REGION_TYPE		
	global ET_SELECT_AI					
	global ET_ADD_AS_FRIEND				
	global ET_ADD_AS_ENEMY				
	global ET_CHANGE_FRIEND_TO_ENEMY	
	global ET_CHANGE_ENEMY_TO_FRIEND	
	global ET_SELECT_FRIEND				
	global ET_SELECT_ENEMY				
	global ET_DELETE				
	global ET_OPEN_DIALOG				
	global ET_CLOSE_DIALOG			
	global ET_START_QUICKBATTLE
	global ET_PRELOAD_DONE

	ET_START_SIMULATION			= App.Mission_GetNextEventType()
	ET_END_SIMULATION			= App.Mission_GetNextEventType()
	ET_OPEN_SHIPS_PANE			= App.Mission_GetNextEventType()
	ET_OPEN_PLAYER_PANE			= App.Mission_GetNextEventType()
	ET_SELECT_PLAYER_SHIP_TYPE	= App.Mission_GetNextEventType()
	ET_SELECT_BRIDGE_TYPE		= App.Mission_GetNextEventType()
	ET_SELECT_SHIP_TYPE			= App.Mission_GetNextEventType()
	ET_SELECT_REGION_TYPE		= App.Mission_GetNextEventType()
	ET_SELECT_AI				= App.Mission_GetNextEventType()
	ET_ADD_AS_FRIEND			= App.Mission_GetNextEventType()
	ET_ADD_AS_ENEMY				= App.Mission_GetNextEventType()
	ET_CHANGE_FRIEND_TO_ENEMY	= App.Mission_GetNextEventType()
	ET_CHANGE_ENEMY_TO_FRIEND	= App.Mission_GetNextEventType()
	ET_SELECT_FRIEND			= App.Mission_GetNextEventType()
	ET_SELECT_ENEMY				= App.Mission_GetNextEventType()
	ET_DELETE					= App.Mission_GetNextEventType()
	ET_OPEN_DIALOG			= App.Mission_GetNextEventType()
	ET_CLOSE_DIALOG			= App.Mission_GetNextEventType()
	ET_START_QUICKBATTLE		= App.Mission_GetNextEventType()
	ET_PRELOAD_DONE			= App.Mission_GetNextEventType ()
	ET_RESTART_SIMULATION	= App.Mission_GetNextEventType ()


###############################################################################
#	SetupEventHandlers()
#	
#	This is called from Initialize to set up any event handlers we require.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def SetupEventHandlers():
	pGame = App.Game_GetCurrentGame()
	pEpisode = pGame.GetCurrentEpisode()
	pMission = pEpisode.GetCurrentMission()
	
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_DESTROYED, pMission, __name__ + ".ShipDestroyed")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_EXPLODING, pMission, __name__ + ".ShipExploding")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(ET_PRELOAD_DONE, pMission, __name__ + ".StartSimulation2")



###############################################################################
#	CreateBridgeMenuButton()
#
#	Create a menu button which sends an int event with the passed in event
#	type and int data, to a passed in character.
#
#	Args:	pName		- name of button (string)
#			eType		- event type
#			iSubType	- sub type to be passed in the int of the TGIntEvent
#			pCharacter	- character to which to send the event
#			fWidth		- the width of the button
#			fHeight		- the height of the button
#
#	Return:	none
###############################################################################
def CreateBridgeMenuButton(pName, eType, iSubType, pCharacter, fWidth = 0.0, fHeight = 0.0):
	pEvent = App.TGIntEvent_Create()
	pEvent.SetEventType(eType)
	pEvent.SetDestination(pCharacter)
	pEvent.SetInt(iSubType)
	if fWidth == 0.0:
		return (App.STButton_CreateW(pName, pEvent))
	else:
		return (App.STRoundedButton_CreateW(pName, pEvent, fWidth, fHeight))

###############################################################################
#	CreateRegionMenuButton()
#
#	Create a menu button which sends an int event with the passed in event
#	type and string data, to a passed in character.
#
#	Args:	sName		- name of button (string)
#			eType		- event type
#			sSubType	- sub type to be passed in the string of the TGStringEvent
#			pCharacter	- character to which to send the event
#
#	Return:	none
###############################################################################
def CreateRegionMenuButton(sName, eType, sSubType, pCharacter):
	pEvent = App.TGStringEvent_Create()
	pEvent.SetEventType(eType)
	pEvent.SetDestination(pCharacter)
	pEvent.SetString(sSubType)
	return (App.STButton_Create(sName, pEvent))

###############################################################################
#	CreateFloatButton(pName, eType, fFloat, pCharacter, 
#					  fWidth = 0.0, fHeight = 0.0)
#	
#	Creates a button that sends a float event.
#	
#	Args:	pName		- name of button (string)
#			eType		- event type
#			fFloat		- float to be passed in event
#			pCharacter	- character to which the event will go
#			fWidth		- width
#			fHeight		- height
#	
#	Return:	
###############################################################################
def CreateFloatButton(pName, eType, fFloat, pCharacter, fWidth = 0.0, fHeight = 0.0):
	pEvent = App.TGFloatEvent_Create()
	pEvent.SetEventType(eType)
	pEvent.SetDestination(pCharacter)
	pEvent.SetFloat(fFloat)
	if fWidth == 0.0:
		return (App.STButton_CreateW(pName, pEvent))
	else:
		return (App.STRoundedButton_CreateW(pName, pEvent, fWidth, fHeight))

###############################################################################
#	BuildDialog()
#	
#	Build the Dialog box for quickbattle
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def BuildDialog(bPreservePane = 0):
	
	# Change the font
	import MainMenu.mainmenu
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcSmallFont, MainMenu.mainmenu.g_kSmallFontSize[MainMenu.mainmenu.g_iRes])

	# Add instance handlers.
	global g_bAddedUIHandlers
	if not g_bAddedUIHandlers:
		g_bAddedUIHandlers = 1
		g_pXO.AddPythonFuncHandlerForInstance(ET_START_SIMULATION, __name__ + ".StartSimulation")
		g_pXO.AddPythonFuncHandlerForInstance(ET_RESTART_SIMULATION, __name__ + ".RestartSimulation")
		g_pXO.AddPythonFuncHandlerForInstance(ET_END_SIMULATION, __name__ + ".EndSimulationEvent")
		g_pXO.AddPythonFuncHandlerForInstance(ET_OPEN_SHIPS_PANE, __name__ + ".OpenShipsPane")
		g_pXO.AddPythonFuncHandlerForInstance(ET_OPEN_PLAYER_PANE, __name__ + ".OpenPlayerPane")
		g_pXO.AddPythonFuncHandlerForInstance(ET_SELECT_PLAYER_SHIP_TYPE, __name__ + ".SelectPlayerShip")
		g_pXO.AddPythonFuncHandlerForInstance(ET_SELECT_BRIDGE_TYPE, __name__ + ".SelectBridge")
		g_pXO.AddPythonFuncHandlerForInstance(ET_SELECT_SHIP_TYPE, __name__ + ".SelectShipType")			
		g_pXO.AddPythonFuncHandlerForInstance(ET_SELECT_REGION_TYPE, __name__ + ".SelectRegionType")
		g_pXO.AddPythonFuncHandlerForInstance(ET_SELECT_AI, __name__ + ".SelectAI")
		g_pXO.AddPythonFuncHandlerForInstance(ET_ADD_AS_FRIEND, __name__ + ".AddShipAsFriend")
		g_pXO.AddPythonFuncHandlerForInstance(ET_ADD_AS_ENEMY, __name__ + ".AddShipAsEnemy")
		g_pXO.AddPythonFuncHandlerForInstance(ET_CHANGE_FRIEND_TO_ENEMY, __name__ + ".ChangeFriendToEnemy")
		g_pXO.AddPythonFuncHandlerForInstance(ET_CHANGE_ENEMY_TO_FRIEND, __name__ + ".ChangeEnemyToFriend")
		g_pXO.AddPythonFuncHandlerForInstance(ET_SELECT_FRIEND, __name__ + ".SelectFriend")
		g_pXO.AddPythonFuncHandlerForInstance(ET_SELECT_ENEMY, __name__ + ".SelectEnemy")
		g_pXO.AddPythonFuncHandlerForInstance(ET_DELETE, __name__ + ".Delete")
		g_pXO.AddPythonFuncHandlerForInstance(ET_OPEN_DIALOG, __name__ + ".OpenConfigDialog")			
		g_pXO.AddPythonFuncHandlerForInstance(ET_CLOSE_DIALOG, __name__ + ".CloseConfigDialog")
		g_pXO.AddPythonFuncHandlerForInstance(ET_START_QUICKBATTLE, __name__ + ".StartQuickBattle")
	
	
	# Check the configuration manager to see what ships and regions have been unlocked
	# by the single player campaign
	if (App.g_kConfigMapping.LoadConfigFile("Options.cfg") == 0):
		return

	##############################################
	# NOTE: Temporarily set everything to be
	#		turned on by default 'til proper
	#		triggers in missions exist to turn
	#		thing on for us
	##############################################
	
	
	if (App.g_kConfigMapping.HasValue("QuickBattle", "Ships Unlocked1") == 0):
		App.g_kConfigMapping.SetIntValue("QuickBattle", "Ships Unlocked1", 0xFFFFFFFF)
#		App.g_kConfigMapping.SetIntValue("QuickBattle", "Ships Unlocked1", FED_STARBASE | GALAXY | AMBASSADOR | WARBIRD | MARAUDER | GALOR | BOP | SHUTTLE | ASTEROID | PROBE)
	iShipsUnlocked1 = App.g_kConfigMapping.GetIntValue("QuickBattle", "Ships Unlocked1")

	
	if (App.g_kConfigMapping.HasValue("QuickBattle", "Ships Unlocked2") == 0):
		App.g_kConfigMapping.SetIntValue("QuickBattle", "Ships Unlocked2", 0xFFFFFFFF)
#		App.g_kConfigMapping.SetIntValue("QuickBattle", "Ships Unlocked2", 0)
	iShipsUnlocked2 = App.g_kConfigMapping.GetIntValue("QuickBattle", "Ships Unlocked2")

	if (App.g_kConfigMapping.HasValue("QuickBattle", "Regions Unlocked1") == 0):
		App.g_kConfigMapping.SetIntValue("QuickBattle", "Regions Unlocked1", 0xFFFFFFFF)
#		App.g_kConfigMapping.SetIntValue("QuickBattle", "Regions Unlocked1", 0)
	iRegionsUnlocked1 = App.g_kConfigMapping.GetIntValue("QuickBattle", "Regions Unlocked1")

	if (App.g_kConfigMapping.HasValue("QuickBattle", "Regions Unlocked2") == 0):
		App.g_kConfigMapping.SetIntValue("QuickBattle", "Regions Unlocked2", 0xFFFFFFFF)
#		App.g_kConfigMapping.SetIntValue("QuickBattle", "Regions Unlocked2", 0)
	iRegionsUnlocked2 = App.g_kConfigMapping.GetIntValue("QuickBattle", "Regions Unlocked2")

	App.g_kConfigMapping.SaveConfigFile("Options.cfg")

	# Create the main pane
	global g_pPane
	if (bPreservePane == 0):
		g_pPane = App.TGPane_Create (1.0, 1.0)
		g_pPane.SetNotVisible() # Hide it 'til we need it
		pTopWindow = App.TopWindow_GetTopWindow()
		pTopWindow.AddChild(g_pPane, 0, 0)
	else:
		g_pPane.KillChildren ()

	pMainPane = App.TGPane_Create(MAIN_PANE_WIDTH, MAIN_PANE_HEIGHT)
	g_pPane.AddChild (pMainPane, MAIN_PANE_X_POS, MAIN_PANE_Y_POS)

	# Create a Stylized Window for the top of the screen
	pStylizedWindow = App.STStylizedWindow_CreateW("StylizedWindow", "NoMinimize", g_pMissionDatabase.GetString("QuickBattle Configuration"), 
						0.0, 0.0, None, 1, TOP_STYLIZED_WIDTH, TOP_STYLIZED_HEIGHT, App.g_kMainMenuBorderMainColor)
	pStylizedWindow.SetUseScrolling(0)
	pStylizedWindow.SetTitleBarThickness(BAR_HEIGHT)
	pMainPane.AddChild(pStylizedWindow)
	
	# Create the buttons to switch between the Ships and Player subpanes
	global g_pShipsButton
	g_pShipsButton = CreateBridgeMenuButton(g_pMissionDatabase.GetString("Ships"), ET_OPEN_SHIPS_PANE, 0, g_pXO, SHIPS_BUTTON_WIDTH, SHIPS_BUTTON_HEIGHT)
	g_pShipsButton.SetNormalColor(App.g_kMainMenuButtonColor)
	g_pShipsButton.SetHighlightedColor(App.g_kMainMenuButtonHighlightedColor)
	g_pShipsButton.SetSelectedColor(App.g_kMainMenuButtonSelectedColor)
	g_pShipsButton.SetColorBasedOnFlags()
	g_pShipsButton.SetSelected (0)
	pStylizedWindow.AddChild(g_pShipsButton, SHIPS_BUTTON_X_POS, SHIPS_BUTTON_Y_POS)
	App.g_kFocusManager.AddObjectToTabOrder(g_pShipsButton)

	global g_pPlayerButton
	g_pPlayerButton = CreateBridgeMenuButton(g_pMissionDatabase.GetString("Player and Region"), ET_OPEN_PLAYER_PANE, 0, g_pXO, PLAYER_BUTTON_WIDTH, PLAYER_BUTTON_HEIGHT)
	g_pPlayerButton.SetNormalColor(App.g_kMainMenuButtonColor)
	g_pPlayerButton.SetHighlightedColor(App.g_kMainMenuButtonHighlightedColor)
	g_pPlayerButton.SetSelectedColor(App.g_kMainMenuButtonSelectedColor)
	g_pPlayerButton.SetColorBasedOnFlags()
	pStylizedWindow.AddChild(g_pPlayerButton, PLAYER_BUTTON_X_POS, PLAYER_BUTTON_Y_POS)
	App.g_kFocusManager.AddObjectToTabOrder(g_pPlayerButton)

	# Create a start button to start quick battle
	pStartButton = CreateBridgeMenuButton(g_pMissionDatabase.GetString("Start"), ET_START_QUICKBATTLE, 0, g_pXO, CLOSE_BUTTON_WIDTH, CLOSE_BUTTON_HEIGHT)
	pStartButton.SetNormalColor(App.g_kQuickBattleBrightRed)
	pStartButton.SetHighlightedTextColor (App.g_kSTMenuTextHighlightColor)
	pStartButton.SetDisabled ()
	pStylizedWindow.AddChild(pStartButton, CLOSE_BUTTON_X_POS, CLOSE_BUTTON_Y_POS)
	global g_pStartButton
	g_pStartButton = pStartButton
		
	# Create a button to close the Dialog box
	pCloseButton = CreateBridgeMenuButton(g_pMissionDatabase.GetString("Close"), ET_CLOSE_DIALOG, 0, g_pXO, CLOSE_BUTTON_WIDTH, CLOSE_BUTTON_HEIGHT)
	pCloseButton.SetNormalColor(App.g_kQuickBattleBrightRed)
	pCloseButton.SetHighlightedTextColor (App.g_kSTMenuTextHighlightColor)
	pStylizedWindow.AddChild(pCloseButton, CLOSE_BUTTON_X_POS - g_pStartButton.GetWidth () - 0.01, CLOSE_BUTTON_Y_POS)
	App.g_kFocusManager.AddObjectToTabOrder(pCloseButton)
	App.g_kFocusManager.AddObjectToTabOrder(g_pStartButton)
		
	pStylizedWindow.InteriorChangedSize(1)
	
	# Create the ships subpane
	global g_pShipsPane
	g_pShipsPane = App.TGPane_Create(SUB_PANE_WIDTH, SUB_PANE_HEIGHT)
	pMainPane.AddChild(g_pShipsPane, SUB_PANE_X_POS, SUB_PANE_Y_POS)

	# Create a button to add the currently selected ship to the list of friendlies
	global g_pAddFriendButton
	g_pAddFriendButton = CreateBridgeMenuButton(g_pMissionDatabase.GetString("Add Friend"), ET_ADD_AS_FRIEND, 0, g_pXO, ADD_FRIEND_BUTTON_WIDTH, ADD_FRIEND_BUTTON_HEIGHT)
	g_pAddFriendButton.SetDisabled() # So that you can't add a ship 'til one has been selected
	g_pAddFriendButton.SetNormalColor(App.g_kMainMenuButtonColor)
	g_pAddFriendButton.SetHighlightedColor(App.g_kMainMenuButtonHighlightedColor)
	g_pAddFriendButton.SetSelectedColor(App.g_kMainMenuButtonSelectedColor)
	g_pAddFriendButton.SetColorBasedOnFlags()
	g_pShipsPane.AddChild(g_pAddFriendButton, ADD_FRIEND_BUTTON_X_POS, ADD_FRIEND_BUTTON_Y_POS)

	# Create a button to add the currently selected ship to the list of enemies
	global g_pAddEnemyButton
	g_pAddEnemyButton = CreateBridgeMenuButton(g_pMissionDatabase.GetString("Add Enemy"), ET_ADD_AS_ENEMY, 0, g_pXO, ADD_ENEMY_BUTTON_WIDTH, ADD_ENEMY_BUTTON_HEIGHT)
	g_pAddEnemyButton.SetDisabled() # So that you can't add a ship 'til one has been selected
	g_pAddEnemyButton.SetNormalColor(App.g_kMainMenuButtonColor)
	g_pAddEnemyButton.SetHighlightedColor(App.g_kMainMenuButtonHighlightedColor)
	g_pAddEnemyButton.SetSelectedColor(App.g_kMainMenuButtonSelectedColor)
	g_pAddEnemyButton.SetColorBasedOnFlags()
	g_pShipsPane.AddChild(g_pAddEnemyButton, ADD_ENEMY_BUTTON_X_POS, ADD_ENEMY_BUTTON_Y_POS)

	GenerateFriendMenu()

	GenerateEnemyMenu()

	GenerateShipsPaneShipIcon()
	
	GenerateAIMenu()

	# Go to the small font
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcFlightSmallFont, MainMenu.mainmenu.g_kFlightSmallFontSize[MainMenu.mainmenu.g_iRes])

	# Create a button to move the currently selected enemy ship to the friendly side from the enemy side
	global g_pEnemyToFriendButton
	g_pEnemyToFriendButton = CreateBridgeMenuButton(g_pMissionDatabase.GetString("Up"), ET_CHANGE_ENEMY_TO_FRIEND, 0, g_pXO, UP_BUTTON_WIDTH, UP_BUTTON_HEIGHT)
	g_pEnemyToFriendButton.SetDisabled() # So that you can't move a ship 'til one has been selected
	g_pEnemyToFriendButton.SetNormalColor(App.g_kMainMenuButtonColor)
	g_pEnemyToFriendButton.SetHighlightedColor(App.g_kMainMenuButtonHighlightedColor)
	g_pEnemyToFriendButton.SetSelectedColor(App.g_kMainMenuButtonSelectedColor)
	g_pEnemyToFriendButton.SetColorBasedOnFlags()
	g_pShipsPane.AddChild(g_pEnemyToFriendButton, UP_BUTTON_X_POS, UP_BUTTON_Y_POS)
	
	# Create a button to move the currently selected enemy ship to the enemy side
	global g_pFriendToEnemyButton
	g_pFriendToEnemyButton = CreateBridgeMenuButton(g_pMissionDatabase.GetString("Down"), ET_CHANGE_FRIEND_TO_ENEMY, 0, g_pXO, DOWN_BUTTON_WIDTH, DOWN_BUTTON_HEIGHT)
	g_pFriendToEnemyButton.SetDisabled() # So that you can't move a ship 'til one has been selected
	g_pFriendToEnemyButton.SetNormalColor(App.g_kMainMenuButtonColor)
	g_pFriendToEnemyButton.SetHighlightedColor(App.g_kMainMenuButtonHighlightedColor)
	g_pFriendToEnemyButton.SetSelectedColor(App.g_kMainMenuButtonSelectedColor)
	g_pFriendToEnemyButton.SetColorBasedOnFlags()
	g_pShipsPane.AddChild(g_pFriendToEnemyButton, DOWN_BUTTON_X_POS, DOWN_BUTTON_Y_POS)

	# Create a button to remove the currently selected enemy ship
	global g_pDeleteButton
	g_pDeleteButton = CreateBridgeMenuButton(g_pMissionDatabase.GetString("Delete"), ET_DELETE, 0, g_pXO, DEL_BUTTON_WIDTH, DEL_BUTTON_HEIGHT)
	g_pDeleteButton.SetDisabled() # So that you can't delete a ship 'til one has been selected
	g_pDeleteButton.SetNormalColor(App.g_kQuickBattleBrightRed)
	g_pShipsPane.AddChild(g_pDeleteButton, DEL_BUTTON_X_POS, DEL_BUTTON_Y_POS)

	# Go back to the large font
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcSmallFont, MainMenu.mainmenu.g_kSmallFontSize[MainMenu.mainmenu.g_iRes])

	# Generete the textbox for ship descriptions
	pStylizedWindow = App.STStylizedWindow_CreateW("StylizedWindow", "NoMinimize", g_pMissionDatabase.GetString("Ship Description"))
	pStylizedWindow.SetFixedSize(SHIPS_TEXT_WIDTH, SHIPS_TEXT_HEIGHT)
	pStylizedWindow.SetTitleBarThickness(BAR_HEIGHT)
	global g_pShipsTextWindow
	g_pShipsTextWindow = pStylizedWindow

	# Go to the small font
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcFlightSmallFont, MainMenu.mainmenu.g_kFlightSmallFontSize[MainMenu.mainmenu.g_iRes])

	global g_pShipsText
	g_pShipsText = App.TGParagraph_Create("", pStylizedWindow.GetMaximumInteriorWidth (), None, "", pStylizedWindow.GetMaximumInteriorWidth (), App.TGParagraph.TGPF_WORD_WRAP | App.TGParagraph.TGPF_READ_ONLY)
#	g_pShipsText.Resize(pStylizedWindow.GetMaximumInteriorWidth (), SHIPS_TEXT_HEIGHT)
	pStylizedWindow.AddChild (g_pShipsText, 0, 0, 0)
	g_pShipsPane.AddChild(pStylizedWindow, SHIPS_TEXT_X_POS, SHIPS_TEXT_Y_POS)

	# Go back to the large font
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcSmallFont, MainMenu.mainmenu.g_kSmallFontSize[MainMenu.mainmenu.g_iRes])

	GenerateShipMenu(iShipsUnlocked1, iShipsUnlocked2)

	# Generate the bar that extends out of the STStylizedWindow that surrounds
	# the ShipMenu
	pShipsBar = App.TGIcon_Create("NormalStyleFrame", 5, App.globals.g_kInterfaceBorderColor)
	pShipsBar.SizeToArtwork(0)
	pShipsBar.Resize(BAR_WIDTH, BAR_HEIGHT)
	g_pShipsPane.AddChild(pShipsBar, BAR_X_POS, BAR_Y_POS)

	# Glass background for ships subpane
	pGraphicsMode = App.GraphicsModeInfo_GetCurrentMode()
	pcLCARS = pGraphicsMode.GetLcarsString()
	pGlass = App.TGIcon_Create(pcLCARS, 120)
	pGlass.Resize(g_pShipsPane.GetWidth(), g_pShipsPane.GetHeight())
	g_pShipsPane.AddChild(pGlass, 0, 0)

	# Create the player subpane
	global g_pPlayerPane
	g_pPlayerPane = App.TGPane_Create(SUB_PANE_WIDTH, SUB_PANE_HEIGHT)
	pMainPane.AddChild(g_pPlayerPane, SUB_PANE_X_POS, SUB_PANE_Y_POS)
	g_pPlayerPane.SetNotVisible (0)

	# Generate the bar that extends out of the STStylizedWindow that surrounds
	# the Player Ship Menu
	pPlayerBar = App.TGIcon_Create("NormalStyleFrame", 5, App.globals.g_kInterfaceBorderColor)
	pPlayerBar.SizeToArtwork(0)
	pPlayerBar.Resize(BAR_WIDTH, BAR_HEIGHT)
	g_pPlayerPane.AddChild(pPlayerBar, BAR_X_POS, BAR_Y_POS)

	pMenu1 = GenerateRegionMenu(iRegionsUnlocked1, iRegionsUnlocked2)

	pMenu2 = GeneratePlayerShipMenu(iShipsUnlocked1, iShipsUnlocked2)

	pMenu3 = GeneratePlayerBridgeMenu(iShipsUnlocked1)

	App.g_kFocusManager.AddObjectToTabOrder(pMenu2)
	App.g_kFocusManager.AddObjectToTabOrder(pMenu3)
	if (pMenu1):
		App.g_kFocusManager.AddObjectToTabOrder(pMenu1)

	GeneratePlayerPaneShipIcon()

	# Generate the textbox for player ship descriptions
	pStylizedWindow = App.STStylizedWindow_CreateW("StylizedWindow", "NoMinimize", g_pMissionDatabase.GetString("Ship Description"))
	pStylizedWindow.SetFixedSize(PLAYER_TEXT_WIDTH, PLAYER_TEXT_HEIGHT)
	pStylizedWindow.SetTitleBarThickness(BAR_HEIGHT)
	global g_pPlayerTextWindow
	g_pPlayerTextWindow = pStylizedWindow

	# Go to the small font
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcFlightSmallFont, MainMenu.mainmenu.g_kFlightSmallFontSize[MainMenu.mainmenu.g_iRes])

	global g_pPlayerText
	g_pPlayerText = App.TGParagraph_Create("", pStylizedWindow.GetMaximumInteriorWidth (), None, "", pStylizedWindow.GetMaximumInteriorWidth (), App.TGParagraph.TGPF_WORD_WRAP | App.TGParagraph.TGPF_READ_ONLY)
	pStylizedWindow.AddChild (g_pPlayerText, 0, 0, 0)	
	g_pPlayerPane.AddChild(pStylizedWindow, PLAYER_TEXT_X_POS, PLAYER_TEXT_Y_POS)

	# Go back to the large font
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcSmallFont, MainMenu.mainmenu.g_kSmallFontSize[MainMenu.mainmenu.g_iRes])

	# Glass background for player subpane
	pGraphicsMode = App.GraphicsModeInfo_GetCurrentMode()
	pcLCARS = pGraphicsMode.GetLcarsString()
	pGlass = App.TGIcon_Create(pcLCARS, 120)
	pGlass.Resize(g_pPlayerPane.GetWidth(), g_pPlayerPane.GetHeight())
	g_pPlayerPane.AddChild(pGlass, 0, 0)
	
	# Glass background for the main pane
	pGraphicsMode = App.GraphicsModeInfo_GetCurrentMode()
	pcLCARS = pGraphicsMode.GetLcarsString()
	pGlass = App.TGIcon_Create(pcLCARS, 120)
	pGlass.Resize(pMainPane.GetWidth(), pMainPane.GetHeight())
#	pGlass.AddPythonFuncHandlerForInstance(App.ET_MOUSE, __name__ + ".MouseIgnoreHandler")
	pMainPane.AddChild(pGlass, 0, 0)

	# The player starts out as a Galaxy Class ship
	if (bPreservePane == 0):
		pEvent = App.TGIntEvent_Create()
		pEvent.SetEventType(ET_SELECT_PLAYER_SHIP_TYPE)
		pEvent.SetDestination(g_pXO)
		pEvent.SetInt(ST_GALAXY)
		SelectPlayerShip(None, pEvent)

	# Restore the font
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcFlightSmallFont, MainMenu.mainmenu.g_kFlightSmallFontSize[MainMenu.mainmenu.g_iRes])

###############################################################################
#	GeneratePlayerBridgeMenu()
#	
#	Generates the menus from which the player's ship can be selected
#	
#	Args:	iShipsUnlocked1	-	a bitfield specifying which ships are available
#	
#	Return:	none
###############################################################################
def GeneratePlayerBridgeMenu(iShipsUnlocked1):
	# Create menus for the player's ship
	pShipMenu = App.STSubPane_Create(BRIDGE_MENU_WIDTH, BRIDGE_MENU_HEIGHT, 1)
	
	pStylizedWindow = App.STStylizedWindow_CreateW("StylizedWindow", "NoMinimize", g_pMissionDatabase.GetString("Select Player Bridge"))
	pStylizedWindow.SetUseScrolling(0)
	pStylizedWindow.SetFixedSize(BRIDGE_MENU_WIDTH, BRIDGE_MENU_HEIGHT)
	pStylizedWindow.SetTitleBarThickness(BAR_HEIGHT)
	pStylizedWindow.AddChild(pShipMenu)
	g_pPlayerPane.AddChild(pStylizedWindow, BRIDGE_MENU_X_POS, BRIDGE_MENU_Y_POS)

	if (iShipsUnlocked1 & GALAXY):
		pButton = CreateBridgeMenuButton(g_pMissionDatabase.GetString("Galaxy"), ET_SELECT_BRIDGE_TYPE, ST_GALAXY, g_pXO)
		pShipMenu.AddChild(pButton)
	if (iShipsUnlocked1 & SOVEREIGN):
		pButton = CreateBridgeMenuButton(g_pMissionDatabase.GetString("Sovereign"), ET_SELECT_BRIDGE_TYPE, ST_SOVEREIGN, g_pXO)
		pShipMenu.AddChild(pButton)

	pShipMenu.Resize(pShipMenu.GetWidth(), pShipMenu.GetTotalHeightOfChildren())
	pStylizedWindow.Layout()
	pStylizedWindow.InteriorChangedSize()
	return pStylizedWindow


###############################################################################
#	GenerateEnemyMenu()
#	
#	Generate the menu in which selected enemy ships will be listed
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def GenerateEnemyMenu():
	global g_pEnemyWindow
	global g_pEnemyMenu
	g_pEnemyMenu = App.STSubPane_Create(ENEMY_LIST_WIDTH, ENEMY_LIST_HEIGHT, 1)

	g_pEnemyWindow = App.STStylizedWindow_CreateW("StylizedWindow", "NoMinimize", g_pMissionDatabase.GetString("Enemy Ships"))

	g_pEnemyMenu.Resize(ENEMY_LIST_WIDTH - g_pEnemyWindow.GetBorderWidth(), ENEMY_LIST_HEIGHT - g_pEnemyWindow.GetBorderHeight())
	g_pEnemyWindow.SetFixedSize(ENEMY_LIST_WIDTH, ENEMY_LIST_HEIGHT)
	g_pEnemyWindow.AddChild(g_pEnemyMenu)
	g_pShipsPane.AddChild(g_pEnemyWindow, ENEMY_LIST_X_POS, ENEMY_LIST_Y_POS)

	g_pEnemyMenu.ResizeToContents()

###############################################################################
#	GenerateFriendMenu()
#	
#	Generate the menu in which selected friendly ships will be listed
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def GenerateFriendMenu():
	global g_pFriendWindow
	global g_pFriendMenu
	g_pFriendMenu = App.STSubPane_Create(FRIEND_LIST_WIDTH, FRIEND_LIST_HEIGHT, 1)

	g_pFriendWindow = App.STStylizedWindow_CreateW("StylizedWindow", "NoMinimize", g_pMissionDatabase.GetString("Friendly Ships"))

	g_pFriendMenu.Resize(FRIEND_LIST_WIDTH - g_pFriendWindow.GetBorderWidth(), FRIEND_LIST_HEIGHT - g_pFriendWindow.GetBorderHeight())

	g_pFriendWindow.SetFixedSize(FRIEND_LIST_WIDTH, FRIEND_LIST_HEIGHT)
	g_pFriendWindow.AddChild(g_pFriendMenu)
	g_pShipsPane.AddChild(g_pFriendWindow, FRIEND_LIST_X_POS, FRIEND_LIST_Y_POS)

	g_pFriendMenu.ResizeToContents()

###############################################################################
#	GenerateShipsPaneShipIcon()
#	
#	Generate the icon in which the image of the currently-selected ship will
#	be displayed
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def GenerateShipsPaneShipIcon():
	global g_pShipsIcon
	global g_pShipsIconPane

	g_pShipsIconPane = App.TGPane_Create(SHIP_IMAGE_WIDTH, SHIP_IMAGE_HEIGHT)
	
	g_pShipsIcon = App.TGIcon_Create("ShipIcons", App.SPECIES_UNKNOWN)
	g_pShipsIcon.Resize(SHIP_IMAGE_WIDTH, SHIP_IMAGE_HEIGHT)
	g_pShipsIcon.SetNotVisible ()
	
	g_pShipsIconPane.AddChild(g_pShipsIcon)
	g_pShipsPane.AddChild(g_pShipsIconPane, SHIP_IMAGE_X_POS, SHIP_IMAGE_Y_POS)

	# Glass background
	pGraphicsMode = App.GraphicsModeInfo_GetCurrentMode()
	pcLCARS = pGraphicsMode.GetLcarsString()
	pGlass = App.TGIcon_Create(pcLCARS, 120)
	pGlass.Resize(g_pShipsIconPane.GetWidth(), g_pShipsIconPane.GetHeight())
	g_pShipsIconPane.AddChild(pGlass, 0, 0)


###############################################################################
#	GeneratePlayerPaneShipIcon()
#	
#	Generate the icon in which the image of the currently-selected ship will
#	be displayed
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def GeneratePlayerPaneShipIcon():
	global g_pPlayerIcon
	global g_pPlayerIconPane

	g_pPlayerIconPane = App.TGPane_Create(SHIP_IMAGE_WIDTH, SHIP_IMAGE_HEIGHT)
	
	g_pPlayerIcon = App.TGIcon_Create("ShipIcons", App.SPECIES_UNKNOWN)
	g_pPlayerIcon.Resize(SHIP_IMAGE_WIDTH, SHIP_IMAGE_HEIGHT)

	g_pPlayerIconPane.AddChild(g_pPlayerIcon)
	g_pPlayerPane.AddChild(g_pPlayerIconPane, SHIP_IMAGE_X_POS, SHIP_IMAGE_Y_POS)

	# Glass background
	pGraphicsMode = App.GraphicsModeInfo_GetCurrentMode()
	pcLCARS = pGraphicsMode.GetLcarsString()
	pGlass = App.TGIcon_Create(pcLCARS, 120)
	pGlass.Resize(g_pPlayerIconPane.GetWidth(), g_pPlayerIconPane.GetHeight())
	g_pPlayerIconPane.AddChild(pGlass, 0, 0)


###############################################################################
#	GenerateAIMenu()
#	
#	Generate the menu from which the player can select the AI level for
#	the computer-controlled combatants
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def GenerateAIMenu():
	global g_pAIMenu
	g_pAIMenu = App.STSubPane_Create(AI_MENU_WIDTH, AI_MENU_HEIGHT, 1)
	
	pStylizedWindow = App.STStylizedWindow_CreateW("StylizedWindow", "NoMinimize", g_pMissionDatabase.GetString("AI Level"))
	pStylizedWindow.SetUseScrolling(0)
	pStylizedWindow.SetFixedSize(AI_MENU_WIDTH, AI_MENU_HEIGHT)
	pStylizedWindow.SetTitleBarThickness(BAR_HEIGHT)
	pStylizedWindow.AddChild(g_pAIMenu)
	g_pShipsPane.AddChild(pStylizedWindow, AI_MENU_X_POS, AI_MENU_Y_POS)

	pLow = CreateFloatButton(g_pMissionDatabase.GetString("Low"), ET_SELECT_AI, AI_LOW, g_pXO)
	g_pAIMenu.AddChild(pLow)

	pMedium = CreateFloatButton(g_pMissionDatabase.GetString("Medium"), ET_SELECT_AI, AI_MEDIUM, g_pXO)
	g_pAIMenu.AddChild(pMedium)
	pMedium.SetChosen(1)

	pHigh = CreateFloatButton(g_pMissionDatabase.GetString("High"), ET_SELECT_AI, AI_HIGH, g_pXO)
	g_pAIMenu.AddChild(pHigh)

	global g_iCurrentAILevel
	global g_iSelectedAILevel
	g_iCurrentAILevel = -1
	g_iSelectedAILevel = AI_MEDIUM


###############################################################################
#	GeneratePlayerShipMenu()
#	
#	Generates the menus from which the player's ship can be selected
#	
#	Args:	iShipsUnlocked1	-	a bitfield specifying which ships are available
#			iShipsUnlocked2	-	a bitfield specifying which ships are available
#	
#	Return:	none
###############################################################################
def GeneratePlayerShipMenu(iShipsUnlocked1, iShipsUnlocked2):
	# Create menus for all the sorts of ships that are playable
	pShipMenu = App.STSubPane_Create(SHIP_MENU_WIDTH, SHIP_MENU_HEIGHT, 1)
	
	pStylizedWindow = App.STStylizedWindow_CreateW("StylizedWindow", "NoMinimize", g_pMissionDatabase.GetString("Player and Region"))
	pStylizedWindow.SetFixedSize(SHIP_MENU_WIDTH, SHIP_MENU_HEIGHT);
	pStylizedWindow.SetTitleBarThickness(BAR_HEIGHT)
	pStylizedWindow.AddChild(pShipMenu)
	g_pPlayerPane.AddChild(pStylizedWindow, SHIP_MENU_X_POS, SHIP_MENU_Y_POS)

	if (iShipsUnlocked1 & AKIRA) or (iShipsUnlocked1 & AMBASSADOR) or (iShipsUnlocked1 & GALAXY) or (iShipsUnlocked1 & NEBULA) or (iShipsUnlocked1 & SOVEREIGN):
		# Federation menu
		pFederation = App.STCharacterMenu_CreateW(g_pMissionDatabase.GetString("Fed Ships"))
		pShipMenu.AddChild(pFederation)
		if (iShipsUnlocked1 & AKIRA):
			pFederation.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Akira"), ET_SELECT_PLAYER_SHIP_TYPE, ST_AKIRA, g_pXO))
		if (iShipsUnlocked1 & AMBASSADOR):
			pFederation.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Ambassador"), ET_SELECT_PLAYER_SHIP_TYPE, ST_AMBASSADOR, g_pXO)) 
		if (iShipsUnlocked1 & GALAXY):
			pFederation.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Galaxy"), ET_SELECT_PLAYER_SHIP_TYPE, ST_GALAXY, g_pXO))
		if (iShipsUnlocked1 & NEBULA):
			pFederation.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Nebula"), ET_SELECT_PLAYER_SHIP_TYPE, ST_NEBULA, g_pXO)) 
		if (iShipsUnlocked1 & SOVEREIGN):
			pFederation.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Sovereign"), ET_SELECT_PLAYER_SHIP_TYPE, ST_SOVEREIGN, g_pXO)) 
		pFederation.ForceUpdate (0)

	# Klingon menu
	if (iShipsUnlocked1 & BOP) or (iShipsUnlocked1 & VORCHA):
		pKlingon = App.STCharacterMenu_CreateW(g_pMissionDatabase.GetString("Klingon Ships"))
		pShipMenu.AddChild(pKlingon)
		if (iShipsUnlocked1 & BOP):
			pKlingon.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("BOP"), ET_SELECT_PLAYER_SHIP_TYPE, ST_BOP, g_pXO)) 
		if (iShipsUnlocked1 & VORCHA):
			pKlingon.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Vorcha"), ET_SELECT_PLAYER_SHIP_TYPE, ST_VORCHA, g_pXO)) 
		pKlingon.ForceUpdate (0)

	# Ferengi menu
	if (iShipsUnlocked1 & MARAUDER):
		pFerengi = App.STCharacterMenu_CreateW(g_pMissionDatabase.GetString("Ferengi Ships"))
		pShipMenu.AddChild(pFerengi)
		pFerengi.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Marauder"), ET_SELECT_PLAYER_SHIP_TYPE, ST_MARAUDER, g_pXO)) 
		pFerengi.ForceUpdate (0)

	# Romulan menu
	if (iShipsUnlocked1 & WARBIRD):
		pRomulan = App.STCharacterMenu_CreateW(g_pMissionDatabase.GetString("Romulan Ships"))
		pShipMenu.AddChild(pRomulan)
		pRomulan.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Warbird"), ET_SELECT_PLAYER_SHIP_TYPE, ST_WARBIRD, g_pXO))
		pRomulan.ForceUpdate (0)

	# Cardassian menu
	if (iShipsUnlocked1 & GALOR) or (iShipsUnlocked1 & KELDON) or (iShipsUnlocked1 & CARD_HYBRID): 
		pCardassian = App.STCharacterMenu_CreateW(g_pMissionDatabase.GetString("Card Ships"))
		pShipMenu.AddChild(pCardassian)
		pCardassian.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Galor"), ET_SELECT_PLAYER_SHIP_TYPE, ST_GALOR, g_pXO))
		pCardassian.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Keldon"), ET_SELECT_PLAYER_SHIP_TYPE, ST_KELDON, g_pXO))
		if (iShipsUnlocked1 & CARD_HYBRID):
			pCardassian.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Card Hybrid"), ET_SELECT_PLAYER_SHIP_TYPE, ST_CARD_HYBRID, g_pXO))
		pCardassian.ForceUpdate (0)

	# Kessok menu
	if (iShipsUnlocked1 & KESSOK_LIGHT) or (iShipsUnlocked1 & KESSOK_HEAVY):
		pKessok = App.STCharacterMenu_CreateW(g_pMissionDatabase.GetString("Kessok Ships"))
		pShipMenu.AddChild(pKessok)
		if (iShipsUnlocked1 & KESSOK_LIGHT):
			pKessok.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Kessok Light"), ET_SELECT_PLAYER_SHIP_TYPE, ST_KESSOK_LIGHT, g_pXO))
		if (iShipsUnlocked1 & KESSOK_HEAVY):
			pKessok.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Kessok Heavy"), ET_SELECT_PLAYER_SHIP_TYPE, ST_KESSOK_HEAVY, g_pXO))
		pKessok.ForceUpdate (0)

	# Other ships
	if (iShipsUnlocked1 & ASTEROID) or (iShipsUnlocked1 & FREIGHTER) or (iShipsUnlocked1 & CARD_FREIGHTER) or (iShipsUnlocked1 & DECOY) or (iShipsUnlocked1 & PROBE) or (iShipsUnlocked1 & SHUTTLE)	or (iShipsUnlocked1 & SUNBUSTER) or (iShipsUnlocked1 & TRANSPORT):
		pOther = App.STCharacterMenu_CreateW(g_pMissionDatabase.GetString("Other Ships"))
		pShipMenu.AddChild(pOther)
		if (iShipsUnlocked1 & SHUTTLE):
			pOther.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Shuttle"), ET_SELECT_PLAYER_SHIP_TYPE, ST_SHUTTLE, g_pXO))
		if (iShipsUnlocked1 & TRANSPORT):
			pOther.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Transport"), ET_SELECT_PLAYER_SHIP_TYPE, ST_TRANSPORT, g_pXO))
		pOther.ForceUpdate (0)

	return pStylizedWindow

###############################################################################
#	GenerateShipMenu()
#	
#	Generates the menus from which enemy ships can be selected
#	
#	Args:	iShipsUnlocked1	-	a bitfield specifying which ships are available
#			iShipsUnlocked2	-	a bitfield specifying which ships are available
#	
#	Return:	none
###############################################################################
def GenerateShipMenu(iShipsUnlocked1, iShipsUnlocked2):
	# Create menus for all the sorts of enemy ships
	pShipMenu = App.STSubPane_Create(SHIP_MENU_WIDTH, SHIP_MENU_HEIGHT, 1)
	
	pStylizedWindow = App.STStylizedWindow_CreateW("StylizedWindow", "NoMinimize", g_pMissionDatabase.GetString("Ships"))
	pStylizedWindow.SetFixedSize(SHIP_MENU_WIDTH, SHIP_MENU_HEIGHT);
	pStylizedWindow.SetTitleBarThickness(BAR_HEIGHT)
	pStylizedWindow.AddChild(pShipMenu)
	g_pShipsPane.AddChild(pStylizedWindow, SHIP_MENU_X_POS, SHIP_MENU_Y_POS)
	App.g_kFocusManager.AddObjectToTabOrder(pStylizedWindow)

	if (iShipsUnlocked1 & AKIRA) or (iShipsUnlocked1 & AMBASSADOR) or (iShipsUnlocked1 & GALAXY) or (iShipsUnlocked1 & NEBULA) or (iShipsUnlocked1 & SOVEREIGN):
		# Federation menu
		pFederation = App.STCharacterMenu_CreateW(g_pMissionDatabase.GetString("Fed Ships"))
		pShipMenu.AddChild(pFederation)
		if (iShipsUnlocked1 & AKIRA):
			pFederation.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Akira"), ET_SELECT_SHIP_TYPE, ST_AKIRA, g_pXO))
		if (iShipsUnlocked1 & AMBASSADOR):
			pFederation.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Ambassador"), ET_SELECT_SHIP_TYPE, ST_AMBASSADOR, g_pXO)) 
		if (iShipsUnlocked1 & GALAXY):
			pFederation.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Galaxy"), ET_SELECT_SHIP_TYPE, ST_GALAXY, g_pXO))
		if (iShipsUnlocked1 & NEBULA):
			pFederation.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Nebula"), ET_SELECT_SHIP_TYPE, ST_NEBULA, g_pXO)) 
		if (iShipsUnlocked1 & SOVEREIGN):
			pFederation.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Sovereign"), ET_SELECT_SHIP_TYPE, ST_SOVEREIGN, g_pXO)) 
		pFederation.ForceUpdate (0)

	# Klingon menu
	if (iShipsUnlocked1 & BOP) or (iShipsUnlocked1 & VORCHA):
		pKlingon = App.STCharacterMenu_CreateW(g_pMissionDatabase.GetString("Klingon Ships"))
		pShipMenu.AddChild(pKlingon)
		if (iShipsUnlocked1 & BOP):
			pKlingon.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("BOP"), ET_SELECT_SHIP_TYPE, ST_BOP, g_pXO)) 
		if (iShipsUnlocked1 & VORCHA):
			pKlingon.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Vorcha"), ET_SELECT_SHIP_TYPE, ST_VORCHA, g_pXO)) 
		pKlingon.ForceUpdate (0)

	# Ferengi menu
	if (iShipsUnlocked1 & MARAUDER):
		pFerengi = App.STCharacterMenu_CreateW(g_pMissionDatabase.GetString("Ferengi Ships"))
		pShipMenu.AddChild(pFerengi)
		pFerengi.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Marauder"), ET_SELECT_SHIP_TYPE, ST_MARAUDER, g_pXO)) 
		pFerengi.ForceUpdate (0)

	# Romulan menu
	if (iShipsUnlocked1 & WARBIRD):
		pRomulan = App.STCharacterMenu_CreateW(g_pMissionDatabase.GetString("Romulan Ships"))
		pShipMenu.AddChild(pRomulan)
		pRomulan.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Warbird"), ET_SELECT_SHIP_TYPE, ST_WARBIRD, g_pXO))
		pRomulan.ForceUpdate (0)

	# Cardassian menu
	if (iShipsUnlocked1 & GALOR) or (iShipsUnlocked1 & KELDON) or (iShipsUnlocked1 & CARD_HYBRID):
		pCardassian = App.STCharacterMenu_CreateW(g_pMissionDatabase.GetString("Card Ships"))
		pShipMenu.AddChild(pCardassian)
		pCardassian.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Galor"), ET_SELECT_SHIP_TYPE, ST_GALOR, g_pXO))
		pCardassian.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Keldon"), ET_SELECT_SHIP_TYPE, ST_KELDON, g_pXO))
		if (iShipsUnlocked1 & CARD_HYBRID):
			pCardassian.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Card Hybrid"), ET_SELECT_SHIP_TYPE, ST_CARD_HYBRID, g_pXO))
		pCardassian.ForceUpdate (0)

	# Kessok menu
	if (iShipsUnlocked1 & KESSOK_LIGHT) or (iShipsUnlocked1 & KESSOK_HEAVY):
		pKessok = App.STCharacterMenu_CreateW(g_pMissionDatabase.GetString("Kessok Ships"))
		pShipMenu.AddChild(pKessok)
		if (iShipsUnlocked1 & KESSOK_LIGHT):
			pKessok.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Kessok Light"), ET_SELECT_SHIP_TYPE, ST_KESSOK_LIGHT, g_pXO))
		if (iShipsUnlocked1 & KESSOK_HEAVY):
			pKessok.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Kessok Heavy"), ET_SELECT_SHIP_TYPE, ST_KESSOK_HEAVY, g_pXO))
		if (iShipsUnlocked2 & KESSOK_MINE):
			pKessok.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Kessok Mine"), ET_SELECT_SHIP_TYPE, ST_KESSOK_MINE, g_pXO))
		pKessok.ForceUpdate (0)

	# Other ships
	if (iShipsUnlocked1 & ASTEROID) or (iShipsUnlocked1 & FREIGHTER) or (iShipsUnlocked1 & CARD_FREIGHTER) or (iShipsUnlocked1 & DECOY) or (iShipsUnlocked1 & PROBE) or (iShipsUnlocked1 & SHUTTLE)	or (iShipsUnlocked1 & SUNBUSTER) or (iShipsUnlocked1 & TRANSPORT) or (iShipsUnlocked2 & BORG):
		pOther = App.STCharacterMenu_CreateW(g_pMissionDatabase.GetString("Other Ships"))
		pShipMenu.AddChild(pOther)
		if (iShipsUnlocked1 & ASTEROID):
			pOther.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Asteroid"), ET_SELECT_SHIP_TYPE, ST_ASTEROID, g_pXO))
		if (iShipsUnlocked1 & CARD_FREIGHTER):
			pOther.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Card Freighter"), ET_SELECT_SHIP_TYPE, ST_CARD_FREIGHTER, g_pXO))
		if (iShipsUnlocked1 & DECOY):
			pOther.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Decoy"), ET_SELECT_SHIP_TYPE, ST_DECOY, g_pXO))
		if (iShipsUnlocked2 & ESCAPE_POD):
			pOther.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Escape Pod"), ET_SELECT_SHIP_TYPE, ST_ESCAPE_POD, g_pXO))
		if (iShipsUnlocked1 & FREIGHTER):
			pOther.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Freighter"), ET_SELECT_SHIP_TYPE, ST_FREIGHTER, g_pXO))
		if (iShipsUnlocked1 & PROBE):
			pOther.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Probe"), ET_SELECT_SHIP_TYPE, ST_PROBE, g_pXO))
		if (iShipsUnlocked1 & SHUTTLE):
			pOther.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Shuttle"), ET_SELECT_SHIP_TYPE, ST_SHUTTLE, g_pXO))
		if (iShipsUnlocked1 & SUNBUSTER):
			pOther.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Sun Buster"), ET_SELECT_SHIP_TYPE, ST_SUNBUSTER, g_pXO))
		if (iShipsUnlocked1 & TRANSPORT):
			pOther.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Transport"), ET_SELECT_SHIP_TYPE, ST_TRANSPORT, g_pXO))
		pOther.ForceUpdate (0)


	# Base menu
	if (iShipsUnlocked1 & FED_STARBASE) or (iShipsUnlocked1 & FED_OUTPOST) or (iShipsUnlocked1 & COMM_ARRAY) or (iShipsUnlocked1 & ST_COMM_LIGHT) or (iShipsUnlocked1 & DRY_DOCK) or (iShipsUnlocked1 & SPACE_FACILITY) or (iShipsUnlocked1 & CARD_STARBASE) or (iShipsUnlocked1 & CARD_OUTPOST) or (iShipsUnlocked1 & CARD_STATION):
		pBases = App.STCharacterMenu_CreateW(g_pMissionDatabase.GetString("Bases"))
		pShipMenu.AddChild(pBases)
		if (iShipsUnlocked1 & CARD_STARBASE):
			pBases.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Card Starbase"), ET_SELECT_SHIP_TYPE, ST_CARD_STARBASE, g_pXO))
		if (iShipsUnlocked1 & CARD_STATION):
			pBases.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Card Station"), ET_SELECT_SHIP_TYPE, ST_CARD_STATION, g_pXO))
		if (iShipsUnlocked1 & CARD_OUTPOST):
			pBases.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Card Outpost"), ET_SELECT_SHIP_TYPE, ST_CARD_OUTPOST, g_pXO))
		if (iShipsUnlocked1 & COMM_ARRAY):
			pBases.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Comm Array"), ET_SELECT_SHIP_TYPE, ST_COMM_ARRAY, g_pXO))
		if (iShipsUnlocked1 & COMM_LIGHT):
			pBases.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Comm Light"), ET_SELECT_SHIP_TYPE, ST_COMM_LIGHT, g_pXO))
		if (iShipsUnlocked1 & DRY_DOCK):
			pBases.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Dry Dock"), ET_SELECT_SHIP_TYPE, ST_DRY_DOCK, g_pXO))
		if (iShipsUnlocked1 & FED_STARBASE):
			pBases.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Fed Starbase"), ET_SELECT_SHIP_TYPE, ST_FED_STARBASE, g_pXO))
		if (iShipsUnlocked1 & FED_OUTPOST):
			pBases.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Fed Outpost"), ET_SELECT_SHIP_TYPE, ST_FED_OUTPOST, g_pXO))
		if (iShipsUnlocked1 & SPACE_FACILITY):
			pBases.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Space Facility"), ET_SELECT_SHIP_TYPE, ST_SPACE_FACILITY, g_pXO))
		pBases.ForceUpdate (0)

	pShipMenu.Resize(pShipMenu.GetWidth(), pShipMenu.GetTotalHeightOfChildren())
	pStylizedWindow.Layout()
	pStylizedWindow.InteriorChangedSize()

###############################################################################
#	BuildRegionSubmenu
#	
#	Generates a menu of all the systems in a region
#	
#	Args:	char*	sString - the name of the region
#			int		iNum	- the number of systems in the region
#	
#	Return:	a menu
###############################################################################
def BuildRegionSubmenu(sString, iNum):
	pMenu = App.STCharacterMenu_CreateW(g_pMissionDatabase.GetString(sString))
	for iIndex in range(iNum):
		if (g_pMissionDatabase.HasString (sString + " " + str (iIndex + 1))):
			pString = g_pMissionDatabase.GetString (sString + " " + str (iIndex + 1))
			pMenu.AddChild(CreateRegionMenuButton(pString.GetCString (), ET_SELECT_REGION_TYPE, sString + str(iIndex + 1), g_pXO))
		else:
			pMenu.AddChild(CreateRegionMenuButton(g_pMissionDatabase.GetString(sString).GetCString() + " " + str(iIndex + 1), ET_SELECT_REGION_TYPE, sString + str(iIndex + 1), g_pXO))
	pMenu.ForceUpdate (0)

	return pMenu

###############################################################################
#	GenerateRegionMenu()
#	
#	Generates the menus from which regions in which combat can take place
#	can be selected
#	
#	Args:	iRegionsUnlocked1 - a bitfield specifying which ships are available
#			iRegionsUnlocked2 - a bitfield specifying which ships are available
#	
#	Return:	none
###############################################################################
def GenerateRegionMenu(iRegionsUnlocked1, iRegionsUnlocked2):
	# Create menus for available regions
	if iRegionsUnlocked1 or iRegionsUnlocked2:
		pChangeRegionMenu = App.STSubPane_Create(REGION_MENU_WIDTH, 5.0, 1)

		pStylizedWindow = App.STStylizedWindow_CreateW("StylizedWindow", "NoMinimize", g_pMissionDatabase.GetString("Change Combat Region"))
		pStylizedWindow.SetFixedSize(REGION_MENU_WIDTH, REGION_MENU_HEIGHT)
		pStylizedWindow.SetTitleBarThickness(BAR_HEIGHT)
		pStylizedWindow.AddChild(pChangeRegionMenu)
		g_pPlayerPane.AddChild(pStylizedWindow, REGION_MENU_X_POS, REGION_MENU_Y_POS)

		if iRegionsUnlocked2 & ALBIREA:
			pChangeRegionMenu.AddChild(BuildRegionSubmenu("Albirea", 3))
		if iRegionsUnlocked1 & ALIOTH:
			pChangeRegionMenu.AddChild(BuildRegionSubmenu("Alioth", 8))
		if iRegionsUnlocked1 & ARTRUS:
			pChangeRegionMenu.AddChild(BuildRegionSubmenu("Artrus", 3))
		if iRegionsUnlocked1 & ASCELLA:
			pChangeRegionMenu.AddChild(BuildRegionSubmenu("Ascella", 5))
		if iRegionsUnlocked1 & BELARUZ:
			pChangeRegionMenu.AddChild(BuildRegionSubmenu("Belaruz", 4))
		if iRegionsUnlocked1 & BEOL:
			pChangeRegionMenu.AddChild(BuildRegionSubmenu("Beol", 4))
		if iRegionsUnlocked1 & BIRANU:
			pChangeRegionMenu.AddChild(BuildRegionSubmenu("Biranu", 2))
		if iRegionsUnlocked1 & CEBALRAI:
			pChangeRegionMenu.AddChild(BuildRegionSubmenu("Cebalrai", 3))
		if iRegionsUnlocked1 & CHAMBANA:
			pChangeRegionMenu.AddChild(BuildRegionSubmenu("Chambana", 2))
		if iRegionsUnlocked1 & DEEP_SPACE:
			pChangeRegionMenu.AddChild(CreateRegionMenuButton(g_pMissionDatabase.GetString("DeepSpace").GetCString(), ET_SELECT_REGION_TYPE, "DeepSpace", g_pXO))
		if iRegionsUnlocked1 & GEBLE:
			pChangeRegionMenu.AddChild(BuildRegionSubmenu("Geble", 4))
		if iRegionsUnlocked1 & ITARI:
			pChangeRegionMenu.AddChild(BuildRegionSubmenu("Itari", 8))
		if iRegionsUnlocked1 & NEPENTHE:
			pChangeRegionMenu.AddChild(BuildRegionSubmenu("Nepenthe", 3))
		if iRegionsUnlocked1 & OMEGA_DRACONIS:
			pChangeRegionMenu.AddChild(BuildRegionSubmenu("OmegaDraconis", 5))
		if iRegionsUnlocked1 & ONA:
			pChangeRegionMenu.AddChild(BuildRegionSubmenu("Ona", 3))
		if iRegionsUnlocked1 & POSEIDON:
			pChangeRegionMenu.AddChild(BuildRegionSubmenu("Poseidon", 2))
		if iRegionsUnlocked1 & PRENDEL:
			pChangeRegionMenu.AddChild(BuildRegionSubmenu("Prendel", 5))
		if iRegionsUnlocked1 & RIHA:
			pChangeRegionMenu.AddChild(CreateRegionMenuButton(g_pMissionDatabase.GetString("Riha").GetCString(), ET_SELECT_REGION_TYPE, "Riha1", g_pXO))
		if iRegionsUnlocked1 & SAVOY:
			pChangeRegionMenu.AddChild(BuildRegionSubmenu("Savoy", 3))
		if iRegionsUnlocked1 & SERRIS:
			pChangeRegionMenu.AddChild(BuildRegionSubmenu("Serris", 3))
		if iRegionsUnlocked1 & TEVRON:
			pChangeRegionMenu.AddChild(BuildRegionSubmenu("Tevron", 2))
		if iRegionsUnlocked1 & TEZLE:
			pChangeRegionMenu.AddChild(BuildRegionSubmenu("Tezle", 2))
		if iRegionsUnlocked1 & VESUVI:
			sString = "Vesuvi"
			pMenu = App.STCharacterMenu_CreateW(g_pMissionDatabase.GetString(sString))

			iIndex = 3
			if (g_pMissionDatabase.HasString (sString + " " + str (iIndex + 1))):
				pString = g_pMissionDatabase.GetString (sString + " " + str (iIndex + 1))
				pMenu.AddChild(CreateRegionMenuButton(pString.GetCString (), ET_SELECT_REGION_TYPE, sString + str(iIndex + 1), g_pXO))
			else:
				pMenu.AddChild(CreateRegionMenuButton(g_pMissionDatabase.GetString(sString).GetCString() + " " + str(iIndex + 1), ET_SELECT_REGION_TYPE, sString + str(iIndex + 1), g_pXO))

			iIndex = 4
			if (g_pMissionDatabase.HasString (sString + " " + str (iIndex + 1))):
				pString = g_pMissionDatabase.GetString (sString + " " + str (iIndex + 1))
				pMenu.AddChild(CreateRegionMenuButton(pString.GetCString (), ET_SELECT_REGION_TYPE, sString + str(iIndex + 1), g_pXO))
			else:
				pMenu.AddChild(CreateRegionMenuButton(g_pMissionDatabase.GetString(sString).GetCString() + " " + str(iIndex + 1), ET_SELECT_REGION_TYPE, sString + str(iIndex + 1), g_pXO))

			iIndex = 5
			if (g_pMissionDatabase.HasString (sString + " " + str (iIndex + 1))):
				pString = g_pMissionDatabase.GetString (sString + " " + str (iIndex + 1))
				pMenu.AddChild(CreateRegionMenuButton(pString.GetCString (), ET_SELECT_REGION_TYPE, sString + str(iIndex + 1), g_pXO))
			else:
				pMenu.AddChild(CreateRegionMenuButton(g_pMissionDatabase.GetString(sString).GetCString() + " " + str(iIndex + 1), ET_SELECT_REGION_TYPE, sString + str(iIndex + 1), g_pXO))
			pChangeRegionMenu.AddChild (pMenu)

			pMenu.ForceUpdate (0)
		if iRegionsUnlocked1 & VOLTAIR:
			pChangeRegionMenu.AddChild(BuildRegionSubmenu("Voltair", 2))
		if iRegionsUnlocked2 & XI_ENTRADES:
			pChangeRegionMenu.AddChild(BuildRegionSubmenu("XiEntrades", 5))
		if iRegionsUnlocked2 & YILES:
			pChangeRegionMenu.AddChild(BuildRegionSubmenu("Yiles", 4))
		
		pChangeRegionMenu.Resize(pChangeRegionMenu.GetWidth(), pChangeRegionMenu.GetTotalHeightOfChildren())
		pStylizedWindow.Layout()
		pStylizedWindow.InteriorChangedSize()

		return pStylizedWindow
	return None

###############################################################################
#	CreateSimulationMenus()
#
#	Create the menus that bring in simulated ships for combat.
#
#	Args:	none
#
#	Return:	none
###############################################################################
def CreateSimulationMenus():
	# Add the "QuickBattle Configuration" button
	pConfigButton = CreateBridgeMenuButton(g_pMissionDatabase.GetString("QuickBattle Configuration"), ET_OPEN_DIALOG, 0, g_pXO)
	g_pXOMenu.AddChild(pConfigButton)

	# Add the "Start Combat Simulation" button.
	pStartButton = CreateBridgeMenuButton(g_pMissionDatabase.GetString("Start Simulation"), ET_RESTART_SIMULATION, 0, g_pXO)
	pStartButton.SetDisabled()
	g_pXOMenu.AddChild(pStartButton)

	# Add the "End Combat Simulation" button
	pEndButton = CreateBridgeMenuButton(g_pMissionDatabase.GetString("End Simulation"), ET_END_SIMULATION, 0, g_pXO)
	pEndButton.SetDisabled()
	g_pXOMenu.AddChild(pEndButton)


###############################################################################
#	EnableSimulationMenus()
#
#	Enable our simulation setup controls.
#
#	Args:	none
#
#	Return:	none
###############################################################################
def EnableSimulationMenus():

	g_pStartButton.SetEnabled ()

	pStartButton = g_pXOMenu.GetButtonW(g_pMissionDatabase.GetString("Start Simulation"))
	if (pStartButton == None):
		pStartButton = g_pXOMenu.GetButtonW(g_pMissionDatabase.GetString("Restart Simulation"))

	pStartButton.SetEnabled()

	pConfigButton = g_pXOMenu.GetButtonW(g_pMissionDatabase.GetString("QuickBattle Configuration"))
	pConfigButton.SetEnabled()

###############################################################################
#	DisableSimulationMenus()
#
#	Disable our simulation setup controls.
#
#	Args:	none
#
#	Return:	none
###############################################################################
def DisableSimulationMenus():

	g_pStartButton.SetDisabled ()

	pStartButton = g_pXOMenu.GetButtonW(g_pMissionDatabase.GetString("Start Simulation"))
	if (pStartButton == None):
		pStartButton = g_pXOMenu.GetButtonW(g_pMissionDatabase.GetString("Restart Simulation"))

	pStartButton.SetDisabled()

	pConfigButton = g_pXOMenu.GetButtonW(g_pMissionDatabase.GetString("QuickBattle Configuration"))
	pConfigButton.SetDisabled()

###############################################################################
#	EnableStopMenus()
#
#	Enable our stop simulation button.
#
#	Args:	none
#
#	Return:	none
###############################################################################
def EnableStopMenu():
	pStopButton = g_pXOMenu.GetButtonW(g_pMissionDatabase.GetString("End Simulation"))
	pStopButton.SetEnabled()


###############################################################################
#	DisableStopMenus()
#
#	Disable our stop simulation button.
#
#	Args:	none
#
#	Return:	none
###############################################################################
def DisableStopMenu():
	pStartButton = g_pXOMenu.GetButtonW(g_pMissionDatabase.GetString("End Simulation"))
	pStartButton.SetDisabled()


###############################################################################
#	AddShipAsFriend()
#	
#	Add a ship to the list of friendly ships
#	
#	Args:	TGObject	pObject	- NULL  Don't use this
#			TGIntEvent	pEvent	- ET_ADD_AS_FRIEND event.  The int is
#									not something we care about
#	
#	Return:	none
###############################################################################
def AddShipAsFriend(pObject, pEvent):
	# Get the data about the ship that has been selected and append the level
	# of the AI
	lShipData = g_dFriendlyShipTypeToDetails[g_iSelectedShipType][:]
	lShipData.append(g_iSelectedAILevel)

	# Add this to our list of ship data
	g_kFriendList.append(lShipData)

	# [Re]build our menu
	RebuildFriendMenu()

	pObject.CallNextHandler(pEvent)


###############################################################################
#	RebuildFriendMenu()
#	
#	Rebuild the menu of friends from our list of friends
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def RebuildFriendMenu():
	g_pFriendMenu.KillChildren()
	
	for iIndex in range(len(g_kFriendList)):
		g_pFriendMenu.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString(g_kFriendList[iIndex][1]), ET_SELECT_FRIEND, iIndex, g_pXO), 0.0, 0.0, 0)
	
	if len(g_kEnemyList) > 0 or len (g_kFriendList) > 0:
		EnableSimulationMenus()
	else:
		pStartButton = g_pXOMenu.GetButtonW(g_pMissionDatabase.GetString("Start Simulation"))
		if (pStartButton == None):
			pStartButton = g_pXOMenu.GetButtonW(g_pMissionDatabase.GetString("Restart Simulation"))

		pStartButton.SetDisabled()

	# Resize the pane to fit the menu inside it
	g_pFriendMenu.ResizeToContents()
	g_pFriendWindow.ScrollToBottom()
	g_pFriendWindow.Layout()

	if (len (g_kFriendList) > 0):
		App.g_kFocusManager.AddObjectToTabOrder(g_pFriendWindow)


###############################################################################
#	AddShipAsEnemy()
#	
#	Add a ship to the list of friendly ships
#	
#	Args:	TGObject	pObject	- NULL  Don't use this
#			TGIntEvent	pEvent	- ET_ADD_AS_ENEMY event.  The int is
#									not something we care about
#	
#	Return:	none
###############################################################################
def AddShipAsEnemy(pObject, pEvent):
	# Get the data about the ship that has been selected and append the level
	# of the AI
	lShipData = g_dEnemyShipTypeToDetails[g_iSelectedShipType][:]
	lShipData.append(g_iSelectedAILevel)

	# Add this to our list of ship data
	g_kEnemyList.append(lShipData)

	# [Re]build our menu
	RebuildEnemyMenu()

	pObject.CallNextHandler(pEvent)


###############################################################################
#	RebuildEnemyMenu()
#	
#	Rebuild the menu of enemies from our list of enemies
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def RebuildEnemyMenu():
	g_pEnemyMenu.KillChildren()

	for iIndex in range(len(g_kEnemyList)):
		g_pEnemyMenu.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString(g_kEnemyList[iIndex][1]), ET_SELECT_ENEMY, iIndex, g_pXO))
	
	# Resize the pane to fit the menu inside it
	g_pEnemyMenu.ResizeToContents()
	g_pEnemyWindow.ScrollToBottom()
	g_pEnemyWindow.Layout()
	
	if len(g_kEnemyList) > 0 or len (g_kFriendList) > 0:
		EnableSimulationMenus()
	else:
		pStartButton = g_pXOMenu.GetButtonW(g_pMissionDatabase.GetString("Start Simulation"))
		if (pStartButton == None):
			pStartButton = g_pXOMenu.GetButtonW(g_pMissionDatabase.GetString("Restart Simulation"))

		pStartButton.SetDisabled()

	if (len (g_kEnemyList) > 0):
		App.g_kFocusManager.AddObjectToTabOrder(g_pEnemyWindow)


###############################################################################
#	UpdateIcon()
#	
#	Change an icon as specified and resize appropriatly
#	
#	Args:	int		iIconNumber - the new icon number
#			TGIcon	pIcon		- the icon to change
#			TGPane	pPane		- the parent pane of the icon
#	
#	Return:	none
###############################################################################
def UpdateIcon(iIconNumber, pIcon, pPane):
	pIcon.SetVisible ()
	pIcon.SetIconNum(iIconNumber)
	pIcon.SizeToArtwork()

	# If we're too big, shrink us down
	if (pIcon.GetHeight() > pPane.GetHeight()):
		fRatio = pPane.GetHeight() / pIcon.GetHeight()
		pIcon.Resize(pIcon.GetWidth() * fRatio, pIcon.GetHeight() * fRatio)

	# Center us in our parent pane
	fXPos = (pPane.GetWidth() - pIcon.GetWidth()) / 2.0
	fYPos = (pPane.GetHeight() - pIcon.GetHeight()) / 2.0
	pIcon.SetPosition(fXPos, fYPos)

###############################################################################
#	SelectFriend()
#	
#	Select a friend from the friend menu
#	
#	Args:	TGObject	pObject	- NULL  Don't use this
#			TGIntEvent	pEvent	- ET_SELECT_FRIEND event.  The int is the index
#									of the selected friend on the list
#	
#	Return:	none
###############################################################################
def SelectFriend(pObject, pEvent):
	
	global g_sSelectedShipSide
	g_sSelectedShipSide = "Friend"

	# Update the global number that keeps track of this
	global g_iSelectedFriendlyShip 
	g_iSelectedFriendlyShip = pEvent.GetInt()

	# Update the Ship Icon to reflect this
	# Get the icon number from dictionary with help from the event's int
	iIconNumber = g_dShipNameToIconNumber[g_kFriendList[pEvent.GetInt()][0]]
	UpdateIcon(iIconNumber, g_pShipsIcon, g_pShipsIconPane)

	# Go to the small font
	import MainMenu.mainmenu
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcFlightSmallFont, MainMenu.mainmenu.g_kFlightSmallFontSize[MainMenu.mainmenu.g_iRes])

	# Update the text to reflect this
	g_pShipsText.SetStringW(g_pShipsDatabase.GetString(g_kFriendList[pEvent.GetInt()][0] + " Description"))
	g_pShipsTextWindow.InteriorChangedSize ()
	g_pShipsText.Layout()

	
	# Go back to the large font
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcSmallFont, MainMenu.mainmenu.g_kSmallFontSize[MainMenu.mainmenu.g_iRes])

	# Update the AI Menu to reflect the currently selected ship
	SetAI(g_kFriendList[pEvent.GetInt()][5])
	
	# Enable and disable the appropriate buttons
	g_pAddEnemyButton.SetDisabled()
	g_pAddFriendButton.SetDisabled()
	g_pAIMenu.SetNotVisible()
	g_pFriendToEnemyButton.SetEnabled()
	g_pEnemyToFriendButton.SetDisabled()
	g_pDeleteButton.SetEnabled()

	App.g_kFocusManager.AddObjectToTabOrder(g_pFriendToEnemyButton)
	App.g_kFocusManager.AddObjectToTabOrder(g_pDeleteButton)
	App.g_kFocusManager.RemoveObjectFromTabOrder(g_pEnemyToFriendButton)

	pObject.CallNextHandler(pEvent)



###############################################################################
#	SelectEnemy()
#	
#	Select an enemy from the enemy menu
#	
#	Args:	TGObject	pObject	- NULL  Don't use this
#			TGIntEvent	pEvent	- ET_SELECT_ENEMY event.  The int is the index
#									of the selected enemy on the list
#	
#	Return:	none
###############################################################################
def SelectEnemy(pObject, pEvent):
	
	global g_sSelectedShipSide
	g_sSelectedShipSide = "Enemy"

	# Update the global number that keeps track of this
	global g_iSelectedEnemyShip 
	g_iSelectedEnemyShip = pEvent.GetInt()

	# Update the Ship Icon to reflect this
	# Get the icon number from dictionary with help from the event's int
	iIconNumber = g_dShipNameToIconNumber[g_kEnemyList[pEvent.GetInt()][0]]
	UpdateIcon(iIconNumber, g_pShipsIcon, g_pShipsIconPane)

	# Go to the small font
	import MainMenu.mainmenu
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcFlightSmallFont, MainMenu.mainmenu.g_kFlightSmallFontSize[MainMenu.mainmenu.g_iRes])

	# Update the text to reflect this
	g_pShipsText.SetStringW(g_pShipsDatabase.GetString(g_kEnemyList[pEvent.GetInt()][0] + " Description"))
	g_pShipsTextWindow.InteriorChangedSize ()
	g_pShipsText.Layout()

	# Go back to the large font
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcSmallFont, MainMenu.mainmenu.g_kSmallFontSize[MainMenu.mainmenu.g_iRes])

	# Update the AI Menu to reflect the currently selected ship
	SetAI(g_kEnemyList[pEvent.GetInt()][5])

	# Enable and disable the appropriate buttons
	g_pAddEnemyButton.SetDisabled()
	g_pAddFriendButton.SetDisabled()
	g_pAIMenu.SetNotVisible()
	g_pFriendToEnemyButton.SetDisabled()
	g_pEnemyToFriendButton.SetEnabled()
	g_pDeleteButton.SetEnabled()

	App.g_kFocusManager.RemoveObjectFromTabOrder(g_pFriendToEnemyButton)
	App.g_kFocusManager.AddObjectToTabOrder(g_pDeleteButton)
	App.g_kFocusManager.AddObjectToTabOrder(g_pEnemyToFriendButton)

	pObject.CallNextHandler(pEvent)


###############################################################################
#	ChangeFriendToEnemy()
#	
#	Move the selected friendly ship to the enemy list
#	
#	Args:	TGObject	pObject	- NULL  Don't use this
#			TGIntEvent	pEvent	- ET_CHANGE_FRIEND_TO_ENEMY event.  The int is the index
#									of the selected friend on the list
#	
#	Return:	none
###############################################################################
def ChangeFriendToEnemy(pObject, pEvent):
	global g_kEnemyList
	global g_kFriendList
		
	kShipData = g_kFriendList[g_iSelectedFriendlyShip]
	iAILevel = kShipData[5]
	kShipData = g_dEnemyShipTypeToDetails[g_dShipNameToType[kShipData[0]]][:]
	kShipData.append(iAILevel) 
	
	# Append the ship to the enemy list
	g_kEnemyList.append(kShipData)

	# Remove said ship from the friendly list
	g_kFriendList.pop(g_iSelectedFriendlyShip)

	UpdateAndDisableEverything()

	if (len (g_kFriendList) > g_iSelectedFriendlyShip):
		pButton = g_pFriendMenu.GetNthChild (g_iSelectedFriendlyShip)
		if (pButton):
			App.InterfaceModule_ForceFocusOnObject (pButton)

		pEvent = App.TGIntEvent_Create()
		pEvent.SetEventType(ET_SELECT_FRIEND)
		pEvent.SetDestination(g_pXO)
		pEvent.SetInt(g_iSelectedFriendlyShip)
		App.g_kEventManager.AddEvent (pEvent)

	pObject.CallNextHandler(pEvent)


###############################################################################
#	ChangeEnemyToFriend()
#	
#	Move the selected enemy ship to the friendly list
#	
#	Args:	TGObject	pObject	- NULL  Don't use this
#			TGIntEvent	pEvent	- ET_CHANGE_ENEMY_TO_FRIEND event.  The int is the index
#									of the selected enemy on the list
#	
#	Return:	none
###############################################################################
def ChangeEnemyToFriend(pObject, pEvent):
	global g_kEnemyList
	global g_kFriendList
		
	kShipData = g_kEnemyList[g_iSelectedEnemyShip]
	iAILevel = kShipData[5]
	kShipData = g_dFriendlyShipTypeToDetails[g_dShipNameToType[kShipData[0]]][:]
	kShipData.append(iAILevel) 
	
	# Append the ship to the friend list
	g_kFriendList.append(kShipData)

	# Remove said ship from the enemy list
	g_kEnemyList.pop(g_iSelectedEnemyShip)

	UpdateAndDisableEverything()

	if (len (g_kEnemyList) > g_iSelectedEnemyShip):
		pButton = g_pEnemyMenu.GetNthChild (g_iSelectedEnemyShip)
		if (pButton):
			App.InterfaceModule_ForceFocusOnObject (pButton)

		pEvent = App.TGIntEvent_Create()
		pEvent.SetEventType(ET_SELECT_ENEMY)
		pEvent.SetDestination(g_pXO)
		pEvent.SetInt(g_iSelectedEnemyShip)
		App.g_kEventManager.AddEvent (pEvent)

	pObject.CallNextHandler(pEvent)


###############################################################################
#	DeleteShip()
#	
#	Remove the selected ship from the appropriatelist
#	
#	Args:	TGObject	pObject	- NULL  Don't use this
#			TGIntEvent	pEvent	- ET_DELETE event.  The int is the index
#									of the selected ship on the list
#	
#	Return:	none
###############################################################################
def Delete(pObject, pEvent):
	iSide = 0
		
	global g_sSelectedShipSide
	if g_sSelectedShipSide == "Friend":
		iSide = 1
		# Remove the ship from the friend list
		g_kFriendList.pop(g_iSelectedFriendlyShip)

	elif g_sSelectedShipSide == "Enemy":
		iSide = 2
		# Remove the ship from the enemy list
		g_kEnemyList.pop(g_iSelectedEnemyShip)
	else:
		return

	g_sSelectedShipSide = ""
	UpdateAndDisableEverything()

	if (iSide == 1):
		if (len (g_kFriendList) > g_iSelectedFriendlyShip):
			pButton = g_pFriendMenu.GetNthChild (g_iSelectedFriendlyShip)
			if (pButton):
				App.InterfaceModule_ForceFocusOnObject (pButton)

			pEvent = App.TGIntEvent_Create()
			pEvent.SetEventType(ET_SELECT_FRIEND)
			pEvent.SetDestination(g_pXO)
			pEvent.SetInt(g_iSelectedFriendlyShip)
			App.g_kEventManager.AddEvent (pEvent)
	elif (iSide == 2):
		if (len (g_kEnemyList) > g_iSelectedEnemyShip):
			pButton = g_pEnemyMenu.GetNthChild (g_iSelectedEnemyShip)
			if (pButton):
				App.InterfaceModule_ForceFocusOnObject (pButton)

			pEvent = App.TGIntEvent_Create()
			pEvent.SetEventType(ET_SELECT_ENEMY)
			pEvent.SetDestination(g_pXO)
			pEvent.SetInt(g_iSelectedEnemyShip)
			App.g_kEventManager.AddEvent (pEvent)

	pObject.CallNextHandler(pEvent)



###############################################################################
#	UpdateAndDisableEverything()
#	
#	Put the Dialog into "waiting for menu click" mode
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def UpdateAndDisableEverything():
	# Blank out the Ship Icon 'til something's selected
	g_pShipsIcon.SetIconNum(App.SPECIES_UNKNOWN)
	g_pShipsIcon.SetNotVisible ()

	# Blank out the text 'til something's selected
	g_pShipsText.SetString("")
	g_pShipsTextWindow.InteriorChangedSize()

	# Have our AI Menu reflect that nothing is selected
	pLow	= g_pAIMenu.GetButtonW(g_pMissionDatabase.GetString("Low"))
	pMedium	= g_pAIMenu.GetButtonW(g_pMissionDatabase.GetString("Medium"))
	pHigh	= g_pAIMenu.GetButtonW(g_pMissionDatabase.GetString("High"))
	pMedium.SetChosen(0)
	pHigh.SetChosen(0)
	pLow.SetChosen(0)

	# Disable all buttons 'til something from the menu's selected
	g_pAddEnemyButton.SetDisabled()
	g_pAddFriendButton.SetDisabled()
	g_pAIMenu.SetNotVisible()
	g_pFriendToEnemyButton.SetDisabled()
	g_pEnemyToFriendButton.SetDisabled()
	g_pDeleteButton.SetDisabled()

	App.g_kFocusManager.RemoveObjectFromTabOrder(g_pAddFriendButton)
	App.g_kFocusManager.RemoveObjectFromTabOrder(g_pAddEnemyButton)
	App.g_kFocusManager.RemoveObjectFromTabOrder(g_pAIMenu)
	App.g_kFocusManager.RemoveObjectFromTabOrder(g_pFriendWindow)
	App.g_kFocusManager.RemoveObjectFromTabOrder(g_pFriendToEnemyButton)
	App.g_kFocusManager.RemoveObjectFromTabOrder(g_pDeleteButton)
	App.g_kFocusManager.RemoveObjectFromTabOrder(g_pEnemyToFriendButton)
	App.g_kFocusManager.RemoveObjectFromTabOrder(g_pEnemyWindow)

	# Rebuild the menus of selected friends and enemies to reflect our
	# current lists
	RebuildFriendMenu()
	RebuildEnemyMenu()

	# Disable Start simulation if there are no enemy ships left in the list
	if (len (g_kEnemyList) == 0 and len (g_kFriendList) == 0):
		DisableSimulationMenus ()		

###############################################################################
#	SelectAI()
#	
#	Select the AI level for any ship to be added
#	
#	Args:	pObject	- NULL  Don't use this
#			pEvent	- ET_SELECT_AI event.  The float is our AI level.
#	
#	Return:	none
###############################################################################
def SelectAI(pObject, pEvent):
	SetAI(pEvent.GetFloat())

	pObject.CallNextHandler(pEvent)


###############################################################################
#	SetAI()
#	
#	Set the AI level for any ship to be added
#	
#	Args:	fAI	- the AI level
#	
#	Return:	none
###############################################################################
def SetAI(fAI):
	# Update the appropriate global value
	global g_iSelectedAILevel
	g_iSelectedAILevel = fAI

	pLow	= g_pAIMenu.GetButtonW(g_pMissionDatabase.GetString("Low"))
	pMedium	= g_pAIMenu.GetButtonW(g_pMissionDatabase.GetString("Medium"))
	pHigh	= g_pAIMenu.GetButtonW(g_pMissionDatabase.GetString("High"))
	
	# Even though it will usually be the AI Menu itself that's called us, it
	# won't *always* be -- so we update it to reflect the current level
	if fAI == AI_LOW:
		pLow.SetChosen(1)
		pMedium.SetChosen(0)
		pHigh.SetChosen(0)
	elif fAI == AI_MEDIUM:
		pLow.SetChosen(0)
		pMedium.SetChosen(1)
		pHigh.SetChosen(0)
	else:
		pLow.SetChosen(0)
		pMedium.SetChosen(0)
		pHigh.SetChosen(1)

###############################################################################
#	SelectShipType()
#	
#	Select the type of ship to be added
#	
#	Args:	TGObject	pObject	- NULL  Don't use this
#			TGIntEvent	pEvent	- ET_SELECT_SHIP_TYPE event.  The int is
#									our ship type
#	
#	Return:	none
###############################################################################
def SelectShipType(pObject, pEvent):
	
	# Update the appropriate global value
	global g_iSelectedShipType
	g_iSelectedShipType = pEvent.GetInt()

	# We must update the Ship Icon with the image of the currently selected ship
	# Get the icon number from dictionary with help from the event's int
	iIconNumber = g_dShipTypeToIconNumber[pEvent.GetInt()]
	UpdateIcon(iIconNumber, g_pShipsIcon, g_pShipsIconPane)

	# Go to the small font
	import MainMenu.mainmenu
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcFlightSmallFont, MainMenu.mainmenu.g_kFlightSmallFontSize[MainMenu.mainmenu.g_iRes])

	# Update the text to reflect this
	g_pShipsText.SetStringW(g_pShipsDatabase.GetString(g_dFriendlyShipTypeToDetails[pEvent.GetInt()][0] + " Description"))
	g_pShipsTextWindow.InteriorChangedSize ()
	g_pShipsTextWindow.ScrollToTop ()
	g_pShipsTextWindow.Layout ()

	# Go back to the large font
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcSmallFont, MainMenu.mainmenu.g_kSmallFontSize[MainMenu.mainmenu.g_iRes])

	# Update the AI Menu to reflect what the ship will be when added
	SetAI(g_iSelectedAILevel)

	# Now that a ship has been selected, we can enable the buttons that will
	# add it to our list of friends and enemies and disable the buttons that
	# shouldn't be operable at the moment
	g_pAddEnemyButton.SetEnabled()
	g_pAddFriendButton.SetEnabled()
	g_pAIMenu.SetVisible()
	g_pFriendToEnemyButton.SetDisabled()
	g_pEnemyToFriendButton.SetDisabled()
	g_pDeleteButton.SetDisabled()
	g_pPane.Layout()


	App.g_kFocusManager.RemoveObjectFromTabOrder(g_pFriendWindow)
	App.g_kFocusManager.RemoveObjectFromTabOrder(g_pEnemyWindow)
	App.g_kFocusManager.AddObjectToTabOrder(g_pAddFriendButton)
	App.g_kFocusManager.AddObjectToTabOrder(g_pAddEnemyButton)
	App.g_kFocusManager.AddObjectToTabOrder(g_pAIMenu)

	if (len (g_kFriendList) > 0):
		App.g_kFocusManager.AddObjectToTabOrder(g_pFriendWindow)
	if (len (g_kEnemyList) > 0):
		App.g_kFocusManager.AddObjectToTabOrder(g_pEnemyWindow)


	pObject.CallNextHandler(pEvent)

###############################################################################
#	SelectRegionType()
#	
#	Select the type of region to switch to
#	
#	Args:	TGObject	pObject	- NULL  Don't use this
#			TGIntEvent	pEvent	- ET_SELECT_REGION_TYPE event.  The int is
#									our region type
#	
#	Return:	none
###############################################################################
def SelectRegionType(pObject, pEvent):
	global g_sSelectedRegion
	g_sSelectedRegion = pEvent.GetCString()

	pObject.CallNextHandler(pEvent)

###############################################################################
#	ChangeRegion()
#
#	Move all ships over to a different region
#
#	Args:	none
#
#	Return:	none
###############################################################################
def ChangeRegion():
	global g_sSelectedRegion
	global g_pSet
#	print ("Change region: " + g_sSelectedRegion)

	bDupeRegion = 0
	if (g_sSelectedRegion == "Sol1" or g_sSelectedRegion == "Cebalrai1" or g_sSelectedRegion == "Vesuvi5" or g_sSelectedRegion == "Vesuvi6" or g_sSelectedRegion == "Belaruz4"):
		bDupeRegion = 1
	elif g_sSelectedRegion == g_pSet.GetName():
		return
	
	if g_sSelectedRegion == "":
		return
	
	# Get the old set
	pGame = App.Game_GetCurrentGame()
	pPlayer = pGame.GetPlayer()
	pOldSet = pPlayer.GetContainingSet()

	pcOldSetName = pOldSet.GetName ()

	if (bDupeRegion):	
		# Same region but this set needs to be reloaded.  We need to rename the old set so that
		# inserting the new set won't delete the old set.
		pcOldSetName = pcOldSetName + "Dupe"
		pOldSet.SetName (pcOldSetName)

	# Import the region module and initialize the new set
	if (g_sSelectedRegion == "Starbase12" or g_sSelectedRegion == "DeepSpace"):
		# Starbase 12's and Deep Space's region files use a different naming scheme
		pModule = __import__("Systems." + g_sSelectedRegion + "." + g_sSelectedRegion)
		pModule.Initialize()
		g_pSet = App.g_kSetManager.GetSet(g_sSelectedRegion)
	elif (g_sSelectedRegion == "DryDock"):
		# Dry dock's region files use a different naming scheme
		pModule = __import__("Systems.DryDock.DryDock")
		pModule.Initialize()
		g_pSet = App.g_kSetManager.GetSet("DryDock")
	else:
		# Get the name of the region module
		sRegionName = g_sSelectedRegion
		pModule = __import__("Systems." + g_sSelectedRegion[:-1] + "." + g_sSelectedRegion)
		pModule.Initialize()
		g_pSet = App.g_kSetManager.GetSet(g_sSelectedRegion)

	# Take all ships from the old set and put them in the new one
	for kShip in pOldSet.GetClassObjectList(App.CT_SHIP):
		pOldSet.RemoveObjectFromSet(kShip.GetName())
		g_pSet.AddObjectToSet(kShip, kShip.GetName())

		# Reposition the ship...
		vLocation = kShip.GetWorldLocation()
		vForward = kShip.GetWorldForwardTG()

		kPoint = App.TGPoint3 ()
		kPoint.Set(vLocation)

		fRadius = kShip.GetRadius () * 2.0

		while g_pSet.IsLocationEmptyTG(kPoint, fRadius, 1) == 0:
			ChooseNewLocation(vLocation, vForward)
			kPoint.Set(vLocation)
			kPoint.Add(vForward)

		kShip.SetTranslate(kPoint)

		# Update the ship with its new positional information...
		kShip.UpdateNodeOnly()

		# update the proximity manager with this object's new position.
		pProximityManager = g_pSet.GetProximityManager()
		if (pProximityManager):
			pProximityManager.UpdateObject (kShip)


###############################################################################
#	GenerateShips()
#
#	Summon simulated ships
#
#	Args:	none
#
#	Return:	none
###############################################################################
def GenerateShips():

	global g_iNumFriends, g_iNumEnemies
	global pEnemies
	global pFriendlies
	g_iNumFriends = 0
	g_iNumEnemies = 0

	# remove all names prior to generating the new ships, so we don't get screwed up
	# with ships in the wrong groups leftover from the previous simulation.
	pEnemies.RemoveAllNames ()
	pFriendlies.RemoveAllNames ()

	# Add player back into friendly list.
	pGame = App.Game_GetCurrentGame()
	pPlayer = pGame.GetPlayer()
	pFriendlies.AddName(pPlayer.GetName())

	iNumShips = 0

	kShipList = g_kEnemyList + g_kFriendList
	
	for kShipData in kShipList:
		
		# Get the name of the ship module, from the event type.
		sShipType, sShipName, sDestroyedMessage, sWhichAI, sWhichSide, sAINumber = kShipData

		# Import the ship module.
		pModule = __import__("ships." + sShipType)

		# Create a ship based on this ship module..
		iNumShips = iNumShips + 1
		sRootShipName = sShipName
		if sWhichSide == "Friendly":
			g_iNumFriends = g_iNumFriends + 1
			sShipName = g_pMissionDatabase.GetString(sShipName).GetCString() + "-" + str(iNumShips)
		else:
			g_iNumEnemies = g_iNumEnemies + 1
			sShipName = g_pMissionDatabase.GetString(sShipName).GetCString() + "-" + str(iNumShips)
		
		#Give the ship an affiliation
		if sWhichSide == "Enemy":
			pEnemies.AddName(sShipName)
		else:
			pFriendlies.AddName(sShipName)

		import loadspacehelper
		pShip = loadspacehelper.CreateShip(sShipType, g_pSet, sShipName, "")
		if App.IsNull(pShip):
			# Couldn't create the ship.  =(
			return

		kString = g_pMissionDatabase.GetString(sRootShipName)
		kString2 = App.TGString()
		kString2.SetString("-" + str(iNumShips))

		kString = kString.Append(kString2)

		pShip.SetDisplayName(kString)
		pShip.UpdateNodeOnly ()
		
		# Going to place it in the same set as the player...

		# Reposition the ship...
		vLocation = pPlayer.GetWorldLocation()
		vForward = pPlayer.GetWorldForwardTG()
		vForward.Scale(pPlayer.GetRadius() + pShip.GetRadius() + 200.0)

		# Make sure the ship's location won't overlap any other objects in the world.
		kPoint = App.TGPoint3()
		ChooseNewLocation(vLocation, vForward)
		kPoint.Set(vLocation)
		kPoint.Add(vForward)

		fRadius = pShip.GetRadius () * 2.0

		while g_pSet.IsLocationEmptyTG(kPoint, fRadius, 1) == 0:
			ChooseNewLocation(vLocation, vForward)
			kPoint.Set(vLocation)
			kPoint.Add(vForward)

		pShip.SetTranslate(kPoint)

		# And orient it so it's facing us.
		pShip.AlignToVectors(pPlayer.GetWorldBackwardTG(), pPlayer.GetWorldUpTG())

		# Update the ship with its new positional information...
		pShip.UpdateNodeOnly()

		# update the proximity manager with this object's new position.
		pProximityManager = g_pSet.GetProximityManager()
		if (pProximityManager):
			pProximityManager.UpdateObject (pShip)

		# Add the ship to the global ship mapping, along with the AI to use as well
		# as the voice line to use when the ship is destroyed.
		global g_kShips
		g_kShips[pShip.GetObjID()] = (sWhichAI, sDestroyedMessage, sWhichSide, sAINumber)


###############################################################################
#	ChooseNewLocation(vOrigin, vOffset)
#	
#	Chooses a location for an incoming ship.
#	
#	Args:	vOrigin		- the origin -- input parameter
#			vOffset		- the offset -- returns the location for the ship
#	
#	Return:	zero
###############################################################################
def ChooseNewLocation(vOrigin, vOffset):
	# Add some random amount to vOffset
	fUnitRandom = (App.g_kSystemWrapper.GetRandomNumber(10001) - 5000.0) / 5000.0
	fUnitRandom = fUnitRandom * (App.g_kSystemWrapper.GetRandomNumber (50) + 1)

	vOffset.SetX( vOffset.GetX() + fUnitRandom )


	fUnitRandom = (App.g_kSystemWrapper.GetRandomNumber(10001) - 5000.0) / 5000.0
	fUnitRandom = fUnitRandom * (App.g_kSystemWrapper.GetRandomNumber (50) + 1)

	vOffset.SetY( vOffset.GetY() + fUnitRandom )

	fUnitRandom = (App.g_kSystemWrapper.GetRandomNumber(10001) - 5000.0) / 5000.0
	fUnitRandom = fUnitRandom * (App.g_kSystemWrapper.GetRandomNumber (50) + 1)

	vOffset.SetZ( vOffset.GetZ() + fUnitRandom )

	return 0

###############################################################################
#	RecreatePlayer()
#	
#	Recreate the player if necessary.
#	
#	Args:	none
#	
#	Return:	pPlayer	- the player's ship object
###############################################################################
def RecreatePlayer():
	pPlayer = MissionLib.GetPlayer()
	pSet = None
	if pPlayer:
		pSet = pPlayer.GetContainingSet()
		pPlayer.SetDead()
		pSet.DeleteObjectFromSet(pPlayer.GetName())
	if not pSet:
		pSet = g_pSet

	global g_sPlayerType
	pPlayer = MissionLib.CreatePlayerShip(g_sPlayerType, pSet, "Player", "")

	# Reposition the ship...
	vLocation = pPlayer.GetWorldLocation()
	vForward = pPlayer.GetWorldForwardTG()

	# Make sure the ship's location won't overlap any other objects in the world.
	kPoint = App.TGPoint3()
	ChooseNewLocation(vLocation, vForward)
	kPoint.Set(vLocation)
	kPoint.Add(vForward)

	fRadius = pPlayer.GetRadius () * 2.0

	while pSet.IsLocationEmptyTG(kPoint, fRadius, 1) == 0:
		ChooseNewLocation(vLocation, vForward)
		kPoint.Set(vLocation)
		kPoint.Add(vForward)

	pPlayer.SetTranslate(kPoint)

	# Update the ship with its new positional information...
	pPlayer.UpdateNodeOnly()

	# update the proximity manager with this object's new position.
	pProximityManager = g_pSet.GetProximityManager()
	if (pProximityManager):
		pProximityManager.UpdateObject (pPlayer)

	# Remove plasmas.
	pTorpSys = pPlayer.GetTorpedoSystem()
	if(pTorpSys):
		# Forcibly unload all torps past quantums (Type 2)
		iNumTypes = pTorpSys.GetNumAmmoTypes()
		for iType in range(iNumTypes):
			if (iType >= 2):
				pTorpSys.RemoveAmmoType (iType);

	# Reload our bridge, just in case
	import LoadBridge
	LoadBridge.Load(g_sBridgeType)

	# Reassign global pointers
	AssignGlobalPointers()

	return pPlayer



###############################################################################
#	SelectBridge(pObject, pEvent)
#	
#	Event handler for when the bridge selection changes.
#	
#	Args:	TGObject	pObject	- NULL  Don't use this
#			TGIntEvent	pEvent	- ET_SWITCH_BRIDGE event.  The int is
#									the type of bridge we're switching to
#
#	Return:	none
###############################################################################
def SelectBridge(pObject, pEvent):
	# Specify our new bridge
	global g_sBridgeType
	if (pEvent.GetInt() == ST_GALAXY):
		g_sBridgeType = "GalaxyBridge"
	else:
		g_sBridgeType = "SovereignBridge"

	pObject.CallNextHandler(pEvent)


###############################################################################
#	SelectPlayerShip(pObject, pEvent)
#	
#	Event handler for when the player's ship is selected.
#	
#	Args:	TGObject	pObject	- NULL  Don't use this
#			TGIntEvent	pEvent	- ET_SELECT_PLAYER_SHIP_TYPE event.  The int is
#									the type of bridge we're switching to
#
#	Return:	none
###############################################################################
def SelectPlayerShip(pObject, pEvent):
	# Specify our new ship
	global g_sPlayerType
	g_sPlayerType = g_dFriendlyShipTypeToDetails[pEvent.GetInt()][0]

	# Change the icon to reflect the selection
	UpdateIcon(g_dShipTypeToIconNumber[pEvent.GetInt()], g_pPlayerIcon, g_pPlayerIconPane)

	# Go to the small font
	import MainMenu.mainmenu
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcFlightSmallFont, MainMenu.mainmenu.g_kFlightSmallFontSize[MainMenu.mainmenu.g_iRes])

	# Update the text to reflect this
	g_pPlayerText.SetStringW(g_pShipsDatabase.GetString(g_sPlayerType + " Description"))
	g_pPlayerTextWindow.InteriorChangedSize ()
	g_pPlayerTextWindow.ScrollToTop ()
	g_pPlayerTextWindow.Layout ()

	# Go back to the large font
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcSmallFont, MainMenu.mainmenu.g_kSmallFontSize[MainMenu.mainmenu.g_iRes])

	if pObject != None:
		pObject.CallNextHandler(pEvent)

###############################################################################
#	AssignGlobalPointers()
#	
#	Assignes the global pointers for bridge and bridge crew
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def AssignGlobalPointers():
	pTop = App.TopWindow_GetTopWindow()
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()

	global g_pBridge, g_pHelm, g_pEng, g_pSci, g_pXO, g_pXOMenu, g_pTact
	g_pBridge = App.BridgeSet_Cast(App.g_kSetManager.GetSet("bridge"))
	g_pHelm = App.CharacterClass_GetObject(g_pBridge, "Helm")
	g_pXO = App.CharacterClass_GetObject(g_pBridge, "XO")
	g_pEng = App.CharacterClass_GetObject(g_pBridge, "Engineer")
	g_pSci = App.CharacterClass_GetObject(g_pBridge, "Science")
	g_pXOMenu = pTacticalControlWindow.FindMenu(g_pMenusDatabase.GetString("Commander"))
	g_pTact = App.CharacterClass_GetObject(g_pBridge, "Tactical")


###############################################################################
#	StartSimulation(pObject, pEvent)
#	
#	Starts the combat simulation. Adds the AI for enemy ships.
#	
#	Args:	pObject	- the XO
#			pEvent	- the event
#	
#	Return:	none
###############################################################################
def StartSimulation (pObject, pEvent):
	pTopWindow = App.TopWindow_GetTopWindow()
	if (not pTopWindow.IsBridgeVisible()):
		# Force bridge visible and hide cursor if we were 
		# previously in tactical mode so players can see
		# the loading screen.
		pTopWindow.ForceBridgeVisible()

	# Disable mouse move and keyboard
	pTopWindow.AllowKeyboardInput(0)
	pTopWindow.AllowMouseInput(0)

	# Switch to ingame loading viewscreen
	MissionLib.ShowLoadingText (None)

	# Lower Saffi's Menu
	App.CharacterAction_Create(g_pXO, App.CharacterAction.AT_MENU_DOWN).Play()

	# Disable the simulation menus.
	DisableSimulationMenus()

	pObject.CallNextHandler(pEvent)

	# Create the action to actually start loading stuff, delayed by a bit.
	pSequence = App.TGSequence_Create ()
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "StartSimulationAction"), 2.0)
	pSequence.Play ()

def StartSimulationAction (pAction):
	kShipList = g_kEnemyList + g_kFriendList
	
	for kShipData in kShipList:
		# Get the name of the ship module, from the event type.
		sShipType, sShipName, sDestroyedMessage, sWhichAI, sWhichSide, sAINumber = kShipData

		# Import the ship module.
		pModule = __import__("ships." + sShipType)
		pModule.PreLoadModel ()

	# Add a preload done event
	pGame = App.Game_GetCurrentGame()
	pEpisode = pGame.GetCurrentEpisode()
	pMission = pEpisode.GetCurrentMission()
	pEvent = App.TGEvent_Create ()
	pEvent.SetEventType (ET_PRELOAD_DONE)
	pEvent.SetDestination (pMission)
	pGame.SetPreLoadDoneEvent (pEvent)

	return 0
	
def StartSimulation2(pObject, pEvent):
	MissionLib.EndLoadingText (None, None)

	pTopWindow = App.TopWindow_GetTopWindow()
	pTopWindow.AllowKeyboardInput(1)
	pTopWindow.AllowMouseInput(1)

	EnableStopMenu()

	# Reset friendly fire warning points so that friendly fire will be enabled again.
	App.g_kUtopiaModule.SetCurrentFriendlyFire(0)		# Call this when you re-create the ship, too

	global bInSimulation
	bInSimulation = 1

	# Suppress win/loss message during startup
	global bWonOrLost
	bWonOrLost = 1

	# Lower Saffi's Menu
	App.CharacterAction_Create(g_pXO, App.CharacterAction.AT_MENU_DOWN).Play()

	RecreatePlayer()

	# Generate the necessary ships
	GenerateShips()

	# If pEnemies has no names in it, just make one up.
	if not pEnemies.GetNameTuple():
		pEnemies.AddName("This ship probably wont exist")

	# Change the region appropriately
	ChangeRegion()

	# Begin the simulation. Take each ship in the global ship mapping, and
	# assign its AI.
	global g_kShips
	for kShip in g_kShips.items():
		iShipID, kTuple = kShip
		pcWhichAI, pcDestroyedSound, sWhichSide, sAINumber = kTuple

		global g_iCurrentAILevel
		g_iCurrentAILevel = sAINumber
		
		pShip = App.ShipClass_Cast(App.TGObject_GetTGObjectPtr(iShipID))
		if (pShip != None) and (pcWhichAI != None):
			pAIModule = __import__(pcWhichAI)
			pShip.SetAI(pAIModule.CreateAI(pShip), 0, 0)

	# Force tactical view
	pTopWindow = App.TopWindow_GetTopWindow()
	pTopWindow.ForceBridgeVisible()	# Hack. Doing this somehow prevents the
									# occasionally tendancy of the game to
									# stop drawing frames at this point.
	pTopWindow.ForceTacticalVisible()

	# Switch us to red alert
	pAlertEvent = App.TGIntEvent_Create()
	pAlertEvent.SetDestination(App.Game_GetCurrentGame().GetPlayer())
	pAlertEvent.SetEventType(App.ET_SET_ALERT_LEVEL)
	pAlertEvent.SetInt(App.Game_GetCurrentGame().GetPlayer().RED_ALERT)
	App.g_kEventManager.AddEvent(pAlertEvent)

	# Change text of start button to restart
	pStartButton = g_pXOMenu.GetButtonW(g_pMissionDatabase.GetString("Start Simulation"))
	if (pStartButton):
		pStartButton.SetName(g_pMissionDatabase.GetString("Restart Simulation"))

	App.g_kLODModelManager.Purge()

	# Reset flag after startup for win/loss message only if there is an enemy ship.
	if (len (g_kEnemyList) > 0):
		bWonOrLost = 0

	pObject.CallNextHandler(pEvent)

def RestartSimulation (pObject, pEvent):
	# First end the previous simulation
	EndSimulation ()

	# Then send start simulation event
	pEvent = App.TGEvent_Create ()
	pEvent.SetEventType (ET_START_SIMULATION)
	pEvent.SetDestination (g_pXO)
	App.g_kEventManager.AddEvent (pEvent)

	pObject.CallNextHandler (pEvent)

###############################################################################
#	EndSimulation()
#	
#	End the simulation by enabling the simulation menus (they are disabled
#	when in the sim) and recreating the player if necessary.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def EndSimulationEvent(pObject, pEvent):
	EndSimulation()

	global g_idTimer
	if(g_idTimer != App.NULL_ID):
		App.g_kTimerManager.DeleteTimer(g_idTimer)
		g_idTimer = App.NULL_ID

	if pEvent.GetInt() == 2:	# Player won
		GenerateWinSequence()
		# Play the failure fanfare
		import DynamicMusic
		DynamicMusic.PlayFanfare("Win")
	elif pEvent.GetInt() == 1:	# Player lost
		GenerateLoseSequence()
		# Play the failure fanfare
		import DynamicMusic
		DynamicMusic.PlayFanfare("Lose")

	pObject.CallNextHandler(pEvent)

def EndSimulationAction(pAction):
	EndSimulation()
	return 0

def EndSimulation():
	# clear felix menus
	Bridge.TacticalMenuHandlers.ClearOrderMenus ()

	DisableStopMenu()
	EnableSimulationMenus()

	# Kill all simulated ships that are left.
	global g_kShips
	g_kShips.clear()
	for kShip in g_pSet.GetClassObjectList(App.CT_DAMAGEABLE_OBJECT):
		if kShip != MissionLib.GetPlayer():
			kShip.SetDeleteMe(1)
	for kTorp in g_pSet.GetClassObjectList(App.CT_TORPEDO):
			kTorp.SetDeleteMe(1)

	global bInSimulation
	bInSimulation = 0

	global bWonOrLost
	bWonOrLost = 0

	global g_iNumEnemies
	g_iNumEnemies = 0

	RecreatePlayer()

	# Switch us to green alert
	pAlertEvent = App.TGIntEvent_Create()
	pAlertEvent.SetDestination(App.Game_GetCurrentGame().GetPlayer())
	pAlertEvent.SetEventType(App.ET_SET_ALERT_LEVEL)
	pAlertEvent.SetInt(App.Game_GetCurrentGame().GetPlayer().GREEN_ALERT)
	App.g_kEventManager.AddEvent(pAlertEvent)

	# dump the unused models
	App.g_kLODModelManager.Purge()

###############################################################################
#	ShipExploding()
#	
#	Called any time an object is exploding.  It happens that in this mission
#	we know that we have only ships that will be destroyed
#	
#	Args:	pObject		- Null.  Don't use this
#			pEvent		- event's destination is the ship that was
#						  destroyed
#	
#	Return:	none
###############################################################################
def ShipExploding(pObject, pEvent):
#	debug("Ship exploding handler")
	# Get the ship that was destroyed.
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	if (pShip != None):
		iShipID = pShip.GetObjID()
		if pShip.GetName() == "Player":
#			debug("QuickBattle Lost")
			# Play the player-is-dying fanfare
			import DynamicMusic
			DynamicMusic.PlayFanfare("PlayerBlewUp")

		else:
			# Get the ship from the mapping, and then find the appropriate
			# voice line to play.
			global g_kShips

			if g_kShips.has_key(iShipID) == 0:
				return

			kShip = g_kShips[iShipID]
			sWhichAI, sDestroyedMessage, sWhichSide, sAINumber = kShip

			if (sWhichSide == "Enemy"):
				
				# Play the bad-guy-exploding-fanfare
				import DynamicMusic
				DynamicMusic.PlayFanfare("EnemyBlewUp")


###############################################################################
#	ShipDestroyed()
#	
#	Called any time an object is destroyed.  It happens that in this mission
#	we know that we have only ships that will be destroyed
#	
#	Args:	pObject		- Null.  Don't use this
#			pEvent		- event's destination is the ship that was
#						  destroyed
#	
#	Return:	none
###############################################################################
def ShipDestroyed(pObject, pEvent):
#	debug("Ship destroyed handler")

	pPlayer = App.Game_GetCurrentGame().GetPlayer()

	# Get the ship that was destroyed.
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	if (pShip != None):
		iShipID = pShip.GetObjID()
		if pPlayer and pShip.GetName() == pPlayer.GetName():
#			debug("QuickBattle Lost")

			if bInSimulation:
				global g_idTimer
				pEvent = App.TGIntEvent_Create()
				pEvent.SetInt(1)
				pEvent.SetEventType(ET_END_SIMULATION)
				pEvent.SetDestination(g_pXO)
				pTimer = App.TGTimer_Create()
				pTimer.SetTimerStart(App.g_kUtopiaModule.GetGameTime() + 1.0)
				pTimer.SetDelay(0)
				pTimer.SetDuration(0)
				pTimer.SetEvent(pEvent)
				g_idTimer = pTimer.GetObjID()
				App.g_kTimerManager.AddTimer(pTimer)
			else:
				RecreatePlayer()
				# Force back to the bridge
				pTopWindow = App.TopWindow_GetTopWindow()
				pTopWindow.ForceBridgeVisible()

				# Need to reset interactive mode, otherwise you'll get stuck if you go
				# to this mode.
				pCinematic = App.CinematicWindow_Cast(pTopWindow.FindMainWindow(App.MWT_CINEMATIC))
				if pCinematic:
					pCinematic.SetInteractive(1)

				if App.Game_GetCurrentGame().GetPlayer():
					App.Game_GetCurrentGame().GetPlayer().SetTarget(None)

		else:
			# Get the ship from the mapping, and then find the appropriate
			# voice line to play.
			global g_kShips
			global g_iNumEnemies

			if g_kShips.has_key(iShipID) == 0:
				return

			kShip = g_kShips[iShipID]
			sWhichAI, sDestroyedMessage, sWhichSide, sAINumber = kShip

			del g_kShips[iShipID]

			if (sWhichSide == "Enemy"):
				g_iNumEnemies = g_iNumEnemies - 1
				
			pLine1 = App.CharacterAction_Create(g_pTact, App.CharacterAction.AT_SAY_LINE, sDestroyedMessage, "Captain", 1, g_pMissionDatabase)

			pSequence = App.TGSequence_Create()
			pSequence.AddAction(pLine1)
			pSequence.Play()
			
#			debug("Ship destroyed handler " + str (g_iNumEnemies) + ", " + str (bInSimulation) + ", " + str (bWonOrLost))
			# If all enemies are gone, and we're in the simulation, then say we're ending it.
			if ((g_iNumEnemies == 0) and (bInSimulation) and (bWonOrLost == 0)):
#				debug("QuickBattle won")
				global bWonOrLost
				bWonOrLost = 1

				# Don't force ending of simulation, but play lines to that effect.
				GenerateWinSequence()

				import BridgeHandlers
				BridgeHandlers.DropMenusTurnBack()

				# Bring up saffi's menu
				g_pXO.MenuUp ()
				

###############################################################################
#	GenerateLoseSequence()
#	
#	Generate the sequence of stuff to happen after QuickBattle is lost
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def GenerateLoseSequence():
	# Force back to the bridge
	pTopWindow = App.TopWindow_GetTopWindow()
	pTopWindow.ForceBridgeVisible()

	pSequence = App.TGSequence_Create()

	# Create an action to enter Cinematic Mode.
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "StartCutscene"))

	pSequence.AppendAction(App.CharacterAction_Create(g_pXO, App.CharacterAction.AT_LOOK_AT_ME))
	pLine = App.CharacterAction_Create(g_pXO, App.CharacterAction.AT_SPEAK_LINE, "QBComputerLose", "Captain", 0, g_pMissionDatabase)
	pSequence.AppendAction(pLine)

#	pSequence.AppendAction(App.CharacterAction_Create(g_pTact, App.CharacterAction.AT_LOOK_AT_ME))
#	pLine = App.CharacterAction_Create(g_pTact, App.CharacterAction.AT_SAY_LINE_AFTER_TURN, "QBFelixLose", "Captain", 0, g_pMissionDatabase)
#	pSequence.AppendAction(pLine)

#	pSequence.AppendAction(App.CharacterAction_Create(g_pXO, App.CharacterAction.AT_TURN_BACK))

	pAction = App.CharacterAction_Create(g_pXO, App.CharacterAction.AT_LOOK_AT_ME)
	pSequence.AppendAction(pAction)

	# An action to exit out of cinematic mode, once this is done.
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "EndCutscene"))

	pAction = App.CharacterAction_Create(g_pXO, App.CharacterAction.AT_MENU_UP)
	pSequence.AppendAction(pAction, 1.0)

	pButton = g_pXOMenu.GetButtonW(g_pMissionDatabase.GetString("Start Simulation"))
	if (pButton == None):
		pButton = g_pXOMenu.GetButtonW(g_pMissionDatabase.GetString("Restart Simulation"))
	pAction = App.TGScriptAction_Create(__name__, "MoveMouseToButton", pButton, 1)
	pSequence.AppendAction (pAction)

	pSequence.Play()



###############################################################################
#	GenerateWinSequence()
#	
#	Generate the sequence of stuff to happen after QuickBattle is Won
#	
#	Args:	TGSequence pSequence - a sequence that may be passed to us for us
#			to build on		
#	
#	Return:	none
###############################################################################
def GenerateWinSequence(pSequence = None):
	if pSequence == None:
		pSequence = App.TGSequence_Create()

	pLine = App.CharacterAction_Create(g_pTact, App.CharacterAction.AT_SAY_LINE, "QBFelixWin", "Captain", 1, g_pMissionDatabase)
	pSequence.AppendAction(pLine)

	pSequence.Play ()
	
###############################################################################
#	OpenShipsPane()
#	
#	Show the ships subpane and hide the player subpane
#	
#	Args:	TGObject	pObject	- NULL  Don't use this
#			TGIntEvent	pEvent	- ET_OPEN_DIALOG event
#
#	Return:	none
###############################################################################
def OpenShipsPane(pObject, pEvent):
	g_pPlayerPane.SetNotVisible()
	g_pShipsPane.SetVisible()
	g_pShipsButton.SetSelected ()
	g_pPlayerButton.SetNotSelected ()

###############################################################################
#	OpenPlayerPane()
#	
#	Show the player subpane and hide the ships subpane
#	
#	Args:	TGObject	pObject	- NULL  Don't use this
#			TGIntEvent	pEvent	- ET_OPEN_DIALOG event
#
#	Return:	none
###############################################################################
def OpenPlayerPane(pObject, pEvent):
	g_pShipsPane.SetNotVisible()
	g_pPlayerPane.SetVisible()
	g_pShipsButton.SetNotSelected ()
	g_pPlayerButton.SetSelected ()



###############################################################################
#	OpenConfigDialog()
#	
#	Show the QuickBatttle Configuration Dialog
#	
#	Args:	TGObject	pObject	- NULL  Don't use this
#			TGIntEvent	pEvent	- ET_OPEN_DIALOG event
#
#	Return:	none
###############################################################################
def OpenConfigDialog(pObject, pEvent):

	# Change the font
	import MainMenu.mainmenu
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcSmallFont, MainMenu.mainmenu.g_kSmallFontSize[MainMenu.mainmenu.g_iRes])

	g_pPane.SetVisible()
	g_pPane.SetEnabled()

	pTopWindow = App.TopWindow_GetTopWindow()
	# Store topwindow's old focus
	global g_pOldFocus
	g_pOldFocus = pTopWindow.GetFocus()
	
	# Don't allow us to switch to the main menu
#	pTopWindow.AllowShowOptionsWindow(0)

	pTopWindow.MoveToFront(g_pPane)
	pTopWindow.SetFocus(g_pPane)

	g_pPane.SetAlwaysHandleEvents()

	UpdateAndDisableEverything()

#	g_pPlayerPane.SetNotVisible()
#	g_pShipsPane.SetVisible()

	global g_bDialogUp
	g_bDialogUp = 1

	if (pObject):
		pObject.CallNextHandler(pEvent)


###############################################################################
#	CloseConfigDialog()
#	
#	Close the QuickBatttle Configuration Dialog
#	
#	Args:	TGObject	pObject	- NULL  Don't use this
#			TGIntEvent	pEvent	- ET_CLOSE_DIALOG event
#
#	Return:	none
###############################################################################
def CloseConfigDialog(pObject, pEvent):
	g_pPane.SetNotVisible()

	# Restore topwindow's old focus
	pTopWindow = App.TopWindow_GetTopWindow()
	pTopWindow.MoveToBack(g_pPane)
	pTopWindow.SetFocus(g_pOldFocus)

	g_pPane.SetNotAlwaysHandleEvents()

	# Allow options window to come up
#	pTopWindow.AllowShowOptionsWindow(1)
	
	# Restore the font
	import MainMenu.mainmenu
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcFlightSmallFont, MainMenu.mainmenu.g_kFlightSmallFontSize[MainMenu.mainmenu.g_iRes])

	pConfigButton = g_pXOMenu.GetButtonW(g_pMissionDatabase.GetString("QuickBattle Configuration"))
	pConfigButton.SetEnabled()

#	pStartButton = g_pXOMenu.GetButtonW(g_pMissionDatabase.GetString("Start Simulation"))
#	if (pStartButton):
#		pStartButton.SetDisabled()

	# Send start simulation event
#	pEvent = App.TGEvent_Create ()
#	pEvent.SetEventType (ET_START_SIMULATION)
#	pEvent.SetDestination (g_pXO)
#	App.g_kEventManager.AddEvent (pEvent)

	global g_bDialogUp
	g_bDialogUp = 0

	if (pObject):
		pObject.CallNextHandler(pEvent)




###############################################################################
#	StartQuickBattle()
#	
#	Close the QuickBatttle Configuration Dialog and start the mission
#	
#	Args:	TGObject	pObject	- NULL  Don't use this
#			TGIntEvent	pEvent	- ET_START_QUICKBATTLE event
#
#	Return:	none
###############################################################################
def StartQuickBattle(pObject, pEvent):
	g_pPane.SetNotVisible()

	# Restore topwindow's old focus
	pTopWindow = App.TopWindow_GetTopWindow()
	pTopWindow.MoveToBack(g_pPane)
	pTopWindow.SetFocus(g_pOldFocus)

	g_pPane.SetNotAlwaysHandleEvents()

	# Allow options window to come up
#	pTopWindow.AllowShowOptionsWindow(1)
	
	pObject.CallNextHandler(pEvent)

	# Restore the font
	import MainMenu.mainmenu
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcFlightSmallFont, MainMenu.mainmenu.g_kFlightSmallFontSize[MainMenu.mainmenu.g_iRes])

	# Send start simulation event
	pEvent = App.TGEvent_Create ()
	pEvent.SetEventType (ET_START_SIMULATION)
	pEvent.SetDestination (g_pXO)
	App.g_kEventManager.AddEvent (pEvent)


###############################################################################
#	GetCurrentAILevel()
#	
#	Returns the current AI Level
#	
#	Args:	none
#	
#	Return:	the current AI Level, a float between 0 and 1
###############################################################################
def GetCurrentAILevel():
	return g_iCurrentAILevel


###############################################################################
#	QBExposition()
#	
#	Say the "We're now in a simulation." stuff.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def QBExposition():
	pSequence = App.TGSequence_Create()

	# Create an action to enter Cinematic Mode.
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "StartCutscene"))

	pSubSequence = App.TGSequence_Create()
	pAction1 = App.CharacterAction_Create(g_pXO, App.CharacterAction.AT_LOOK_AT_ME)
	pAction2 = App.CharacterAction_Create(g_pXO, App.CharacterAction.AT_SAY_LINE, "QBExposition", "Captain", 0, g_pMissionDatabase)
	pAction3 = App.CharacterAction_Create(g_pXO, App.CharacterAction.AT_MENU_UP)

	# wait just a bit so we don't warp the camera wrong because Kiska isn't in her seat at time 0
	pSubSequence.AddAction(pAction1, App.TGAction_CreateNull(), 0.5)
	pSubSequence.AddAction(pAction2, pAction1)
	pSubSequence.AddAction(pAction3, pAction2)

	pSequence.AppendAction (pSubSequence)

	# An action to exit out of cinematic mode, once this is done.
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "EndCutscene"))

	pButton = g_pXOMenu.GetButtonW(g_pMissionDatabase.GetString("QuickBattle Configuration"))
	pAction = App.TGScriptAction_Create(__name__, "MoveMouseToButton", pButton, 1.0)
	pSequence.AppendAction (pAction)
	pSequence.Play()

################################################################################
##	MoveMouseToButton()
##
##	Script action that moves the mouse to the center of the button that is
##	passed in.
##
##	Args:	pTGAction	- The script action object.
##			pObject		- The UI object to move to.
##			fTime		- Amount of time movement will take. Default 0.5 sec
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def MoveMouseToButton(pTGAction, pObject, fTime = 0.5):
	# Make sure the button still exists
	if (pObject != None):	
		MissionLib.MoveMouseCursorToUIObject(pObject, fTime)
	
	return 0

###############################################################################
#	FriendlyFireWarningHandler()
#	
#	You have hurt a friendly craft - say so
#	
#	Args:	pObject, pEvent	- the object and event that called us
#	
#	Return:	none
###############################################################################
def FriendlyFireWarningHandler(pObject, pEvent):
	if not (g_pXO):
		pObject.CallNextHandler(pEvent)
		return

	fTimeSinceTalk = App.g_kUtopiaModule.GetGameTime() - g_pXO.GetLastTalkTime()
	if (fTimeSinceTalk < 5.0):
		pObject.CallNextHandler(pEvent)
		return

	App.g_kUtopiaModule.SetCurrentFriendlyFire(0)		# Clear this out so friendly fire warning will continue to happen.

	pAction = App.CharacterAction_Create(g_pXO, App.CharacterAction.AT_SAY_LINE, "DontShoot4", "Captain", 1)
	App.TGActionManager_RegisterAction(pAction, "FriendlyFireWarning")
	pAction.Play()

	# Don't call next handler, since we don't want it to do what it would normally do.
