import App

# types for initializing torps create from C.
UNKNOWN = 0
DISRUPTOR = 1
PHOTON = 2
QUANTUM = 3
ANTIMATTER = 4
CARDTORP = 5
KLINGONTORP = 6
POSITRON = 7
PULSEDISRUPT = 8
FUSIONBOLT = 9
CARDASSIANDISRUPTOR = 10
KESSOKDISRUPTOR = 11
PHASEDPLASMA = 12
POSITRON2 = 13
PHOTON2 = 14
ROMULANCANNON = 15
MAX_TORPS = 16

# Setup tuples
kSpeciesTuple = ((UNKNOWN, None),
	(DISRUPTOR, "Disruptor"),
	(PHOTON, "PhotonTorpedo"),
	(QUANTUM, "QuantumTorpedo"),
	(ANTIMATTER, "AntimatterTorpedo"),
	(CARDTORP, "CardassianTorpedo"),
	(KLINGONTORP, "KlingonTorpedo"),
	(POSITRON, "PositronTorpedo"),
	(PULSEDISRUPT, "PulseDisruptor"),
	(FUSIONBOLT, "FusionBolt"),
	(CARDASSIANDISRUPTOR, "CardassianDisruptor"),
	(KESSOKDISRUPTOR, "KessokDisruptor"),
	(PHASEDPLASMA, "PhasedPlasma"),
	(POSITRON2, "Positron2"),
	(PHOTON2, "PhotonTorpedo2"),
	(ROMULANCANNON, "RomulanCannon"),
	(MAX_TORPS, None))

def CreateTorpedoFromSpecies (iSpecies):
	if (iSpecies <= 0 or iSpecies >= MAX_TORPS):
		return None

	pSpecTuple = kSpeciesTuple [iSpecies]
	pcScript = pSpecTuple [1]

	pTorp = App.Torpedo_Create (pcScript)
	return pTorp

def GetScriptFromSpecies (iSpecies):
	if (iSpecies <= 0 or iSpecies >= MAX_TORPS):
		return None

	pSpecTuple = kSpeciesTuple [iSpecies]
	return pSpecTuple [1]
	
def InitObject (self, iType):
	# Get the script
	pcScript = GetScriptFromSpecies (iType)
	if (pcScript == None):
		return 0

	# call create function to initialize the torp.
	mod = __import__("Tactical.Projectiles." + pcScript)
	mod.Create(self)	

	self.UpdateNodeOnly ()

	return 1;
	
