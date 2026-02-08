import App

# n x n table of modifiers for ship classes
# Class zero is unknown class, which always has 1.0 modifiers
# All other class always has 1.0 as the first entry, which
# is the modifier for killing and unknown class of ship.

g_kModifierTable = (
	(1.0, 1.0, 1.0),		# Class 0
	(1.0, 1.0, 1.0),		# Class 1
	(1.0, 3.0, 1.0))		# Class 2


def GetModifier (iAttackerClass, iKilledClass):
	global g_kModifierTable

	# Loop up the modifier in the table
	kModTable = g_kModifierTable [iAttackerClass]

	return kModTable [iKilledClass]