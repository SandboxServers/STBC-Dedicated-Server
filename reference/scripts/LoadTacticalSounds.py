##############################################################################
#	Filename:	LoadTacticalSounds.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	This contains the code to load tactical sounds.
#
#	Created:	9/12/00 -	DLitwin
###############################################################################
import App

###############################################################################
#	LoadSounds()
#
#	Load sounds that are needed throughout the game, in tactical.
#
#	Args:	none
#
#	Return:	none
###############################################################################
def LoadSounds():
	pGame = App.Game_GetCurrentGame()
	pGame.LoadSound("sfx/Weapons/federation_phaser_a.wav",	"Enterprise D Phaser Start",	App.TGSound.LS_3D).SetVolume(0.7)
	pGame.LoadSound("sfx/Weapons/federation_phaser_b.wav",	"Enterprise D Phaser Loop",		App.TGSound.LS_3D)

	pGame.LoadSound("sfx/Weapons/ambassador_phaser_a.wav",	"Ambassador Phaser Start",		App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Weapons/ambassador_phaser_b.wav",	"Ambassador Phaser Loop",		App.TGSound.LS_3D)

	pGame.LoadSound("sfx/Weapons/federation_phaser2_a.wav",	"Akira Phaser Start",			App.TGSound.LS_3D).SetVolume(0.7)
	pGame.LoadSound("sfx/Weapons/federation_phaser2_b.wav",	"Akira Phaser Loop",			App.TGSound.LS_3D)

	pGame.LoadSound("sfx/Weapons/galaxy_phaser_a.wav",		"Galaxy Phaser Start",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Weapons/galaxy_phaser_b.wav",		"Galaxy Phaser Loop",			App.TGSound.LS_3D)

	pGame.LoadSound("sfx/Weapons/ferengi_phaser_a.wav",		"Marauder Phaser Start",		App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Weapons/ferengi_phaser_b.wav",		"Marauder Phaser Loop",			App.TGSound.LS_3D)

	pGame.LoadSound("sfx/Weapons/cardassian_phaser_a.wav",	"Card Phaser Start",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Weapons/cardassian_phaser_b.wav",	"Card Phaser Loop",				App.TGSound.LS_3D)

	pGame.LoadSound("sfx/Weapons/galor_phaser_a.wav",		"Galor Phaser Start",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Weapons/galor_phaser_b.wav",		"Galor Phaser Loop",				App.TGSound.LS_3D)

	pGame.LoadSound("sfx/Weapons/klingon_beam_a.wav",		"Vorcha Phaser Start",			App.TGSound.LS_3D)	
	pGame.LoadSound("sfx/Weapons/klingon_beam_b.wav",		"Vorcha Phaser Loop",			App.TGSound.LS_3D)	

	pGame.LoadSound("sfx/Weapons/romulan phaser_a.wav",		"Warbird Phaser Start",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Weapons/romulan phaser_b.wav",		"Warbird Phaser Loop",			App.TGSound.LS_3D)

	pGame.LoadSound("sfx/Weapons/kessock beam_a.wav",		"Kessok Phaser Start",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Weapons/kessock beam_b.wav",		"Kessok Phaser Loop",			App.TGSound.LS_3D)

	pGame.LoadSound("sfx/Weapons/kessock beam2_a.wav",		"Kessok Phaser2 Start",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Weapons/kessock beam2_b.wav",		"Kessok Phaser2 Loop",			App.TGSound.LS_3D)

	pGame.LoadSound("sfx/Weapons/Photon Torp.wav",			"Enterprise D Torpedo",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Weapons/Photon Torp.wav",			"Akira Torpedo",				App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Weapons/Photon Torp.wav",			"Photon Torpedo",				App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Weapons/Klingon Torp.wav",			"Klingon Torpedo",				App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Weapons/Positron Torp.wav",		"Positron Torpedo",				App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Weapons/Cardassian Torp.wav",		"Cardassian Torpedo",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Weapons/Quantum Torp.wav",			"Quantum Torpedo",				App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Weapons/AntiMatter Torp.wav",		"Antimatter Torpedo",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Weapons/Disruptor Cannon.wav",		"Klingon Disruptor",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Weapons/Cardassian Cannon.wav",	"Disruptor",					App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Weapons/Pulse Disruptor.wav",		"Pulse Disruptor",				App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Weapons/Plasma Bolt.wav",			"Plasma Bolt",					App.TGSound.LS_3D)

	pGame.LoadSound("sfx/Weapons/tractor.wav",				"Tractor Beam",					App.TGSound.LS_3D)

	# Engine noises.
	pGame.LoadSound("sfx/engine1.wav",					"Federation Engines",	App.TGSound.LS_3D)
	pGame.LoadSound("sfx/engine2.wav",					"Klingon Engines",		App.TGSound.LS_3D)
	pGame.LoadSound("sfx/engine2.wav",					"Romulan Engines",		App.TGSound.LS_3D)
	pGame.LoadSound("sfx/engine2.wav",					"Ferengi Engines",		App.TGSound.LS_3D)
	pGame.LoadSound("sfx/engine2.wav",					"Cardassian Engines",	App.TGSound.LS_3D)
	pGame.LoadSound("sfx/engine1.wav",					"Kessok Engines",		App.TGSound.LS_3D)

	pGame.LoadSound("sfx/enter warp.wav",				"Enter Warp",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/exit warp.wav",				"Exit Warp",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/warp flash.wav",				"Warp Flash",			0)

	pGame.LoadSound("sfx/Explosions/explo1.WAV",		"Explosion 1",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/explo2.WAV",		"Explosion 2",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/explo3.WAV",		"Explosion 3",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/explo4.WAV",		"Explosion 4",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/explo5.WAV",		"Explosion 5",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/explo6.WAV",		"Explosion 6",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/explo7.WAV",		"Explosion 7",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/explo8.WAV",		"Explosion 8",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/explo9.WAV",		"Explosion 9",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/explo10.WAV",		"Explosion 10",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/explo11.WAV",		"Explosion 11",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/explo12.WAV",		"Explosion 12",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/explo13.WAV",		"Explosion 13",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/explo14.WAV",		"Explosion 14",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/explo15.WAV",		"Explosion 15",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/explo16.WAV",		"Explosion 16",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/explo17.WAV",		"Explosion 17",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/explo18.WAV",		"Explosion 18",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/explo19.WAV",		"Explosion 19",			App.TGSound.LS_3D)

	pGame.LoadSound("sfx/Explosions/explo_flame_01.WAV","Death Explosion 1",	App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/explo_flame_02.WAV","Death Explosion 2",	App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/explo_flame_03.WAV","Death Explosion 3",	App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/explo_flame_04.WAV","Death Explosion 4",	App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/explo_flame_05.WAV","Death Explosion 5",	App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/explo_flame_06.WAV","Death Explosion 6",	App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/explo_flame_07.WAV","Death Explosion 7",	App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/explo_flame_08.WAV","Death Explosion 8",	App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/explo_flame_09.WAV","Death Explosion 9",	App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/explo_flame_10.WAV","Death Explosion 10",	App.TGSound.LS_3D)

	pGame.LoadSound("sfx/Explosions/explo_large_01.WAV","Big Death Explosion 1",App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/explo_large_02.WAV","Big Death Explosion 2",App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/explo_large_03.WAV","Big Death Explosion 3",App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/explo_large_04.WAV","Big Death Explosion 4",App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/explo_large_05.WAV","Big Death Explosion 5",App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/explo_large_06.WAV","Big Death Explosion 6",App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/explo_large_07.WAV","Big Death Explosion 7",App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/explo_large_08.WAV","Big Death Explosion 8",App.TGSound.LS_3D)

	pGame.LoadSound("sfx/Explosions/collision1.wav",	"Collision 1",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/collision2.wav",	"Collision 2",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/collision3.wav",	"Collision 3",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/collision4.wav",	"Collision 4",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/collision5.wav",	"Collision 5",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/collision6.wav",	"Collision 6",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/collision7.wav",	"Collision 7",			App.TGSound.LS_3D)
	pGame.LoadSound("sfx/Explosions/collision8.wav",	"Collision 8",			App.TGSound.LS_3D)

	pGame.LoadSound("sfx/cloak on.wav",					"Cloak",				App.TGSound.LS_3D)
	pGame.LoadSound("sfx/cloak off.wav",				"Uncloak",				App.TGSound.LS_3D)

	pGame.LoadSound("sfx/re-entry_rumble.wav",			"AtmosphereRumble",		App.TGSound.LS_3D)
	pGame.LoadSound("sfx/probe launch.wav",				"Probe Launch",			App.TGSound.LS_3D)

###############################################################################
#	GetRandomSound
#	
#	Get a random sound from the given list of sound names.  This tries
#	not to return the same sound more than once every 3 calls.
#	
#	Args:	lsSoundList	- A list of sound names to choose from (such
#						  as g_lsDeathExplosions, below)
#	
#	Return:	One of the sounds in lsSoundList
###############################################################################
g_dRecentSounds = {}
def GetRandomSound(lsSoundList):
	global g_dRecentSounds
	try:
		lRecent = g_dRecentSounds[lsSoundList]
	except KeyError:
		lRecent = []
		g_dRecentSounds[lsSoundList] = lRecent

	# Randomly choose a sound from lsSoundList that isn't in lRecent.
	lsAvailableSounds = list(lsSoundList[:])
	for sSound in lRecent:
		lsAvailableSounds.remove(sSound)
	if not lsAvailableSounds:
		lsAvailableSounds = lsSoundList

	sSound = lsAvailableSounds[ App.g_kSystemWrapper.GetRandomNumber( len(lsAvailableSounds) ) ]

	# If there's more than 1 sound in the Recent Sounds list, remove the oldest one.
	if len(lRecent) > 1:
		lRecent.pop(0)
	# Add sSound to the list.
	lRecent.append(sSound)

	return sSound

g_lsDeathExplosions = (
	"Death Explosion 1",
	"Death Explosion 2",
	"Death Explosion 3",
	"Death Explosion 4",
	"Death Explosion 5",
	"Death Explosion 6",
	"Death Explosion 7",
	"Death Explosion 8",
	"Death Explosion 9",
	"Death Explosion 10",
	)

g_lsBigDeathExplosions = (
	"Big Death Explosion 1",
	"Big Death Explosion 2",
	"Big Death Explosion 3",
	"Big Death Explosion 4",
	"Big Death Explosion 5",
	"Big Death Explosion 6",
	"Big Death Explosion 7",
	"Big Death Explosion 8",
	)

g_lsWeaponExplosions = (
	"Explosion 1",
	"Explosion 2",
	"Explosion 3",
	"Explosion 4",
	"Explosion 5",
	"Explosion 6",
	"Explosion 7",
	"Explosion 8",
	"Explosion 9",
	"Explosion 10",
	"Explosion 11",
	"Explosion 12",
	"Explosion 13",
	"Explosion 14",
	"Explosion 15",
	"Explosion 16",
	"Explosion 17",
	"Explosion 18",
	"Explosion 19",
	)

g_lsCollisionSounds = (
	"Collision 1",
	"Collision 2",
	"Collision 3",
	"Collision 4",
	"Collision 5",
	"Collision 6",
	"Collision 7",
	"Collision 8",
	)
