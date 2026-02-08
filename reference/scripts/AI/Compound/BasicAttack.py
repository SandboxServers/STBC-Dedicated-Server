try:
	import App
except ImportError:
	# Need this here so the editor can import this file.
	App = None

if App  and  hasattr(App, "CPyDebug"):
	NonSerializedObjects = ( "debug", )

	debug = App.CPyDebug(__name__).Print
#	debug("Loading " + __name__ + " compound AI...")
else:
	# Needed for the editor.
	def debug(s):
		print s

def CreateAI(pShip, *lpTargets, **dKeywords):
	# BasicAttack AI's can only be given to ships.
	pShip = App.ShipClass_Cast(pShip)
	if not pShip:
		return None

	# If dKeywords has a "Keywords" entry, use that entry instead of dKeywords.
	try:
		dKeywords = dKeywords["Keywords"]
	except: pass

	# Before we actually create the AI, setup the various flags that
	# determine what happen at various difficulty levels.
	sGameDifficultyPrefix = ("Easy_", "", "Hard_")[App.Game_GetDifficulty()]
	SetFlagsFromDifficulty(sGameDifficultyPrefix, dKeywords)

	# If the "UseCloaking" flag is set and this ship has a cloaking device,
	# use the CloakAttack AI.
	if dKeywords["UseCloaking"]  and  pShip.GetCloakingSubsystem():
		sAttackModule = "CloakAttackWrapper"
	else:
		# Check what type of ship this is.  Certain types of ships
		# have different basic attack AI's.
		sAttackModule = "NonFedAttack"
		eSpecies = pShip.GetShipProperty().GetSpecies()
		if (eSpecies >= App.SPECIES_FEDERATION_START)  and  (eSpecies < App.SPECIES_CARDASSIAN_START):
			# It's a fed ship.  Use fed attack AI.
			sAttackModule = "FedAttack"

	#debug("Chose attack module %s" % sAttackModule)

	pModule = __import__(sAttackModule)
	return apply(pModule.CreateAI, (pShip,) + lpTargets, dKeywords)

def SetFlagsFromDifficulty(sKeyPrefix, dKeywords):
	# Check if there are any keywords that match the Game Difficulty Prefix..
	# If none are defined, just use the default keys.  If any are defined,
	# only use the prefixed keys.
	bUsePrefix = 0
	if sKeyPrefix:
		for sKey in dKeywords.keys():
			if sKey[:len(sKeyPrefix)] == sKeyPrefix:
				# Found a key for this prefix.  Use the prefix.
				bUsePrefix = 1

	if bUsePrefix:
		# Replace non-prefixed flags with prefixed ones.
		for sFlag in g_lAllFlags + ["Difficulty"]:
			# Remove unprefixed flags...
			if dKeywords.has_key(sFlag):
				del dKeywords[sFlag]

			# Copy over prefixed flags.
			if dKeywords.has_key(sKeyPrefix + sFlag):
				dKeywords[sFlag] = dKeywords[sKeyPrefix + sFlag]

	if not dKeywords.has_key("Difficulty"):
		# Default difficulty is 0.5.
		dKeywords["Difficulty"] = 0.5
	fDifficulty = dKeywords["Difficulty"]

	# Difficulty level is a float from 0.0 to 1.0
	if fDifficulty < 0.0:
		fDifficulty = 0.0
	elif fDifficulty > 1.0:
		fDifficulty = 1.0

	for fFloor, lEnabledFlags in g_lFlagThresholds:
		if fDifficulty >= fFloor:
			# Found a match for our difficulty level.
			# Set all flags that aren't specified in dKeywords
			for sFlag in g_lAllFlags:
				if not dKeywords.has_key(sFlag):
					# This flag hasn't been specified yet.  If it's in the
					# Enabled Flags list, set it true.  Otherwise, it's false.
					if sFlag in lEnabledFlags:
						dKeywords[sFlag] = 1	# Don't use prefix when setting values.
					else:
						dKeywords[sFlag] = 0	# Don't use prefix when setting values.
			break

	#debug("Set keywords for difficulty %f to:\n%s" % (fDifficulty, dKeywords))

# All possible flags that affect difficulty level.
# All of these default to 0.  Valid values are 0 or 1.
g_lAllFlags = [
	"AvoidTorps",					# If 0 torps have no effect on its maneuvers.
	"AggressivePulseWeapons",		# If 1, pulse weapons will be lined up more often when they can fire.
	"ChooseSubsystemTargets",		# If 0 will just aim at the target, not a specific subsystem on it.
	"DisableBeforeDestroy",			# If 1, will stop firing at disabled systems in the target subsystem list until all subsystems in the list are disabled.  Then it'll destroy them.
	"DisableOnly",					# If 1, will stop when the ship has been disabled.  Will try not to destroy the ship.
	"DumbFireTorps",				# If 1, all torps are fired with no target set.
	"FollowTargetThroughWarp",		# If no other targets are available...
	"FollowToSB12",					# If FollowTargetThroughWarp is set, follow the target even to the Starbase12 set.
	"InaccurateTorps",				# If 1, torps are fired with less accuracy.
	"NeverSitStill",				# If 0 may sit still to line up a shot.
	"PowerManagement",				# If 1 will regulate power levels.
	"SmartPhasers",					# If 1 may hold phasers for a good shot.
	"SmartShields",					# If 0, shield status is completely ignored.
	"SmartTorpSelection",			# If 1, will choose between torp types.
	"SmartWeaponBalance",			# Affects when it decides to switch between torps and other weapons.
	"UseCloaking",					# If 1 may use cloaking device during combat.
	"UseRearTorps",					# If 0 won't explicitly aim rear torps.
	"UseSideArcs",					# If 0 won't explicitly sweep through side arcs.
	"WarpOutBeforeDying",			# THIS IS NOT A GUARANTEE.
	]

# Info for the AI editor:
# AIGroupTab(Easy:GeneralSettings)
# AIGroupTab(Normal:GeneralSettings) Default
# AIGroupTab(Hard:GeneralSettings)

# AIGroup(GeneralSettings) Begin
# AIFlag(Difficulty) Range 0.0 1.0
# AIFlag(MaxFiringRange) Range 0.0 1000.0
# AIFlag(AvoidTorps) OnOff
# AIFlag(AggressivePulseWeapons) OnOff
# AIFlag(ChooseSubsystemTargets) OnOff
# AIFlag(DisableBeforeDestroy) OnOff
# AIFlag(DisableOnly) OnOff
# AIFlag(DumbFireTorps) OnOff
# AIFlag(FollowTargetThroughWarp) OnOff
# AIFlag(FollowToSB12) OnOff
# AIFlag(HighPower) OnOff Advanced
# AIFlag(InaccurateTorps) OnOff
# AIFlag(NeverSitStill) OnOff Advanced
# AIFlag(PowerManagement) OnOff Advanced
# AIFlag(SmartPhasers) OnOff
# AIFlag(SmartShields) OnOff
# AIFlag(SmartTorpSelection) OnOff
# AIFlag(SmartWeaponBalance) OnOff Advanced
# AIFlag(UseCloaking) OnOff
# AIFlag(UseRearTorps) OnOff Advanced
# AIFlag(UseSideArcs) OnOff Advanced
# AIFlag(WarpOutBeforeDying) OnOff
# AIGroup(GeneralSettings) End

# Various flags turn on/off at different thresholds.  This is a list
# of which flags are on in each range..  Not all flags are used here.
# If a flag isn't used here, it needs to be set specifically, passed in
# when the AI is created.
# This list must be in descending order, for the difficulty thresholds.
g_lFlagThresholds = [
	(1.0, [ "UseRearTorps", "UseSideArcs", "SmartShields", "ChooseSubsystemTargets",
			"AvoidTorps", "NeverSitStill", "PowerManagement", "SmartWeaponBalance",
			"SmartPhasers", "SmartTorpSelection", "DisableBeforeDestroy",
			"AggressivePulseWeapons" ]),
	(0.7, [ "UseRearTorps", "UseSideArcs", "SmartShields", "ChooseSubsystemTargets",
			"AvoidTorps", "NeverSitStill", "PowerManagement", "SmartWeaponBalance",
			"DisableBeforeDestroy", "AggressivePulseWeapons", "SmartTorpSelection" ]),
	(0.6, [ "UseRearTorps", "UseSideArcs", "SmartShields", "ChooseSubsystemTargets",
			"AvoidTorps", "NeverSitStill", "PowerManagement", "SmartWeaponBalance",
			"AggressivePulseWeapons", "SmartTorpSelection"]),
	(0.5, [ "UseRearTorps", "UseSideArcs", "SmartShields", "ChooseSubsystemTargets",
			"AvoidTorps", "NeverSitStill", "PowerManagement", "SmartTorpSelection" ]),
	(0.4, [ "UseRearTorps", "UseSideArcs", "SmartShields", "ChooseSubsystemTargets",
			"AvoidTorps", "PowerManagement" ]),
	(0.35,[ "UseRearTorps", "UseSideArcs", "SmartShields", "ChooseSubsystemTargets",
			"PowerManagement" ]),
	(0.3, [ "UseRearTorps", "UseSideArcs", "SmartShields", "PowerManagement" ]),
	(0.25,[ "UseRearTorps", "UseSideArcs", "PowerManagement" ]),
	(0.2, [ "InaccurateTorps", "UseRearTorps", "UseSideArcs" ]),
	(0.1, [ "InaccurateTorps", "UseSideArcs" ]),
	(0.05,[ "InaccurateTorps" ]),
	(0.0, [ "InaccurateTorps", "DumbFireTorps" ]),
	]

###############################################################################
#	GetKeyColors
#	
#	Used by the AI Editor to determine what colors to display
#	various keys in, in the Compound AI configuration dialog.
#	
#	Args:	dKeywords	- Current settings of the keys.
#	
#	Return:	A dictionary of Key:color matches.
###############################################################################
def GetKeyColors(dKeywords):
	sEnabledOnColor = "blue"
	sDisabledOnColor = "blue"
	sEnabledOffColor = "darkred"
	sDisabledOffColor = "darkred"
	sUnsetColor = "black"

	if not dKeywords.has_key("Difficulty"):
		dKeywords["Difficulty"] = 0.5

	dColors = {}

	# Set colors based on the various difficulty settings.
	for sDifficulty, sPrefix in (
		( "Easy", "Easy_" ),
		( "Normal", "" ),
		( "Hard", "Hard_" )
		):
		if not dKeywords.has_key(sPrefix + "Difficulty"):
			for sFlag in g_lAllFlags:
				dColors[sPrefix + sFlag] = ( sUnsetColor, sUnsetColor )
			continue

		for fFloor, lEnabledFlags in g_lFlagThresholds:
			if fFloor > dKeywords[sPrefix + "Difficulty"]:
				continue

			# Found a match for our difficulty level.
			# Set the colors for all flags at this level.
			for sFlag in g_lAllFlags:
				# If this flag is in the lEnabledFlags list, it is the
				# enabled color.
				if sFlag in lEnabledFlags:
					dColors[sPrefix + sFlag] = ( sEnabledOnColor, sDisabledOnColor )
				else:
					dColors[sPrefix + sFlag] = ( sEnabledOffColor, sDisabledOffColor )

			break

	return dColors
