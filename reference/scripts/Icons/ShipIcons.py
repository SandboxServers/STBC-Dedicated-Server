# ShipIcons.py
#
# Load Ship Icons for interface.
# 
#

import App

# Function to load LCARS icon group
def LoadShipIcons(ShipIcons = None):
	
	if ShipIcons is None:
		ShipIcons = App.g_kIconManager.CreateIconGroup("ShipIcons")
		# Add LCARS icon group to IconManager
		App.g_kIconManager.AddIconGroup(ShipIcons)
	
	
	# Glass for when no ship is selected
	TextureHandle = ShipIcons.LoadIconTexture('Data/Icons/Bridge/Background/ScreenBlock.tga')
	ShipIcons.SetIconLocation(App.SPECIES_UNKNOWN, TextureHandle, 0, 0, 8, 8)

	# Federation
	#---------------

	# Galaxy
	TextureHandle = ShipIcons.LoadIconTexture('Data/Icons/Ships/Galaxy.tga')
	ShipIcons.SetIconLocation(App.SPECIES_GALAXY, TextureHandle, 0, 0, 128, 128)

	# Sovereign
	TextureHandle = ShipIcons.LoadIconTexture('Data/Icons/Ships/Sovereign.tga')
	ShipIcons.SetIconLocation(App.SPECIES_SOVEREIGN, TextureHandle, 0, 0, 128, 128)

	# Akira
	TextureHandle = ShipIcons.LoadIconTexture('Data/Icons/Ships/Akira.tga')
	ShipIcons.SetIconLocation(App.SPECIES_AKIRA, TextureHandle, 0, 0, 128, 128)

	# Ambassador
	TextureHandle = ShipIcons.LoadIconTexture('Data/Icons/Ships/Ambassador.tga')
	ShipIcons.SetIconLocation(App.SPECIES_AMBASSADOR, TextureHandle, 0, 0, 128, 128)

	# Nebula
	TextureHandle = ShipIcons.LoadIconTexture('Data/Icons/Ships/Nebula.tga')
	ShipIcons.SetIconLocation(App.SPECIES_NEBULA, TextureHandle, 0, 0, 128, 128)

	# Shuttle
	TextureHandle = ShipIcons.LoadIconTexture('Data/Icons/Ships/FedShuttle.tga')
	ShipIcons.SetIconLocation(App.SPECIES_SHUTTLE, TextureHandle, 0, 0, 128, 128)

	# Transport
	TextureHandle = ShipIcons.LoadIconTexture('Data/Icons/Ships/Transport.tga')
	ShipIcons.SetIconLocation(App.SPECIES_TRANSPORT, TextureHandle, 0, 0, 128, 128)

	# Freighter
	TextureHandle = ShipIcons.LoadIconTexture('Data/Icons/Ships/Freighter.tga')
	ShipIcons.SetIconLocation(App.SPECIES_FREIGHTER, TextureHandle, 0, 0, 128, 128)

	# Cardassian
	#---------------

	# Galor
	TextureHandle = ShipIcons.LoadIconTexture('Data/Icons/Ships/Galor.tga')
	ShipIcons.SetIconLocation(App.SPECIES_GALOR, TextureHandle, 0, 0, 128, 128)

	# Keldon
	TextureHandle = ShipIcons.LoadIconTexture('Data/Icons/Ships/Keldon.tga')
	ShipIcons.SetIconLocation(App.SPECIES_KELDON, TextureHandle, 0, 0, 128, 128)

	# CardFreighter
	TextureHandle = ShipIcons.LoadIconTexture('Data/Icons/Ships/CardFreighter.tga')
	ShipIcons.SetIconLocation(App.SPECIES_CARDFREIGHTER, TextureHandle, 0, 0, 128, 128)

	# CardHybrid
	TextureHandle = ShipIcons.LoadIconTexture('Data/Icons/Ships/Hybrid.tga')
	ShipIcons.SetIconLocation(App.SPECIES_CARDHYBRID, TextureHandle, 0, 0, 128, 128)

	# Romulan
	#---------------

	# Warbird
	TextureHandle = ShipIcons.LoadIconTexture('Data/Icons/Ships/Warbird.tga')
	ShipIcons.SetIconLocation(App.SPECIES_WARBIRD, TextureHandle, 0, 0, 128, 128)

	# Klingon
	#---------------

	# Bird of Prey
	TextureHandle = ShipIcons.LoadIconTexture('Data/Icons/Ships/BirdOfPrey.tga')
	ShipIcons.SetIconLocation(App.SPECIES_BIRD_OF_PREY, TextureHandle, 0, 0, 128, 128)

	# Vorcha
	TextureHandle = ShipIcons.LoadIconTexture('Data/Icons/Ships/Vorcha.tga')
	ShipIcons.SetIconLocation(App.SPECIES_VORCHA, TextureHandle, 0, 0, 128, 128)

	# Kessok
	#---------------

	# Kessok Heavy
	TextureHandle = ShipIcons.LoadIconTexture('Data/Icons/Ships/KessokHeavy.tga')
	ShipIcons.SetIconLocation(App.SPECIES_KESSOK_HEAVY, TextureHandle, 0, 0, 128, 128)

	# Kessok Light
	TextureHandle = ShipIcons.LoadIconTexture('Data/Icons/Ships/KessokLight.tga')
	ShipIcons.SetIconLocation(App.SPECIES_KESSOK_LIGHT, TextureHandle, 0, 0, 128, 128)

	# Kessok Mine
	TextureHandle = ShipIcons.LoadIconTexture('Data/Icons/Ships/KessokMine.tga')
	ShipIcons.SetIconLocation(App.SPECIES_KESSOKMINE, TextureHandle, 0, 0, 128, 128)

	# Ferengi
	#---------------

	# Marauder
	TextureHandle = ShipIcons.LoadIconTexture('Data/Icons/Ships/Marauder.tga')
	ShipIcons.SetIconLocation(App.SPECIES_MARAUDER, TextureHandle, 0, 0, 128, 128)

	# Other
	#---------------

	# FedStarbase
	TextureHandle = ShipIcons.LoadIconTexture('Data/Icons/Ships/FedStarbase.tga')
	ShipIcons.SetIconLocation(App.SPECIES_FED_STARBASE, TextureHandle, 0, 0, 128, 128)

	# FedOutpost
	TextureHandle = ShipIcons.LoadIconTexture('Data/Icons/Ships/FedOutpost.tga')
	ShipIcons.SetIconLocation(App.SPECIES_FED_OUTPOST, TextureHandle, 0, 0, 128, 128)

	# CardStarbase
	TextureHandle = ShipIcons.LoadIconTexture('Data/Icons/Ships/CardStarbase.tga')
	ShipIcons.SetIconLocation(App.SPECIES_CARD_STARBASE, TextureHandle, 0, 0, 128, 128)

	# CardOutpost
	TextureHandle = ShipIcons.LoadIconTexture('Data/Icons/Ships/CardOutpost.tga')
	ShipIcons.SetIconLocation(App.SPECIES_CARD_OUTPOST, TextureHandle, 0, 0, 128, 128)

	# CardStation
	TextureHandle = ShipIcons.LoadIconTexture('Data/Icons/Ships/CardStation.tga')
	ShipIcons.SetIconLocation(App.SPECIES_CARD_STATION, TextureHandle, 0, 0, 128, 128)

	# DryDock
	TextureHandle = ShipIcons.LoadIconTexture('Data/Icons/Ships/DryDock.tga')
	ShipIcons.SetIconLocation(App.SPECIES_DRYDOCK, TextureHandle, 0, 0, 128, 128)

	# SpaceFacility
	TextureHandle = ShipIcons.LoadIconTexture('Data/Icons/Ships/SpaceFacility.tga')
	ShipIcons.SetIconLocation(App.SPECIES_SPACE_FACILITY, TextureHandle, 0, 0, 128, 128)

	# CommArray
	TextureHandle = ShipIcons.LoadIconTexture('Data/Icons/Ships/CommArray.tga')
	ShipIcons.SetIconLocation(App.SPECIES_COMMARRAY, TextureHandle, 0, 0, 128, 128)

	# CommLight
	TextureHandle = ShipIcons.LoadIconTexture('Data/Icons/Ships/CommLight.tga')
	ShipIcons.SetIconLocation(App.SPECIES_COMMLIGHT, TextureHandle, 0, 0, 128, 128)

	# Probe
	TextureHandle = ShipIcons.LoadIconTexture('Data/Icons/Ships/Probe.tga')
	ShipIcons.SetIconLocation(App.SPECIES_PROBE, TextureHandle, 0, 0, 128, 128)

	# ProbeTpe2
	TextureHandle = ShipIcons.LoadIconTexture('Data/Icons/Ships/ProbeType2.tga')
	ShipIcons.SetIconLocation(App.SPECIES_PROBETYPE2, TextureHandle, 0, 0, 128, 128)

	# Asteroid
	TextureHandle = ShipIcons.LoadIconTexture('Data/Icons/Ships/Asteroid.tga')
	ShipIcons.SetIconLocation(App.SPECIES_ASTEROID, TextureHandle, 0, 0, 128, 128)
	
	# SunBuster
	TextureHandle = ShipIcons.LoadIconTexture('Data/Icons/Ships/Sunbuster.tga')
	ShipIcons.SetIconLocation(App.SPECIES_SUNBUSTER, TextureHandle, 0, 0, 128, 128)

	# Escape Pod
	TextureHandle = ShipIcons.LoadIconTexture('Data/Icons/Ships/LifeBoat.tga')
	ShipIcons.SetIconLocation(App.SPECIES_ESCAPEPOD, TextureHandle, 0, 0, 128, 128)





