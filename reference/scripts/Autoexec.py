###############################################################################
##	Filename:	Autoexec.py
##	
##	Confidential and Proprietary, Copyright 1999 by Totally Games
##	
##	Autoexec file used by the user interface to load scripts.
##	
##	Created:	12/1/1999 -		Alberto Fonseca
###############################################################################
import App

# Enable profiling:
#App.TGProfilingInfo_EnableProfiling()

# This is needed for save/load, since the program has problems
# importing cPickle internally..
import cPickle

# Log the AI tree.
#App.ArtificialIntelligence_LogAITree("AITree.txt")

# Add scripts/Icons to the script path
import sys
sys.path.append("scripts/Icons")

# Set the interpreter so it checks threads and events less often.  Threads
# and events aren't even used in BC's python code...
sys.setcheckinterval(200)

import FontsAndIcons
import Tactical.TacticalIcons
import UITheme
import LoadInterface

LoadInterface.SetupColors()

try:
	import Local
except:
	pass

# Make sure that the keyboard bindings are valid.
try:
	import KeyboardBinding

	# Check the version of the keyboard bindings.
	if KeyboardBinding.g_pcVersion != App.UtopiaModule_GetGameVersion():
		# The bindings are not from this version. Recreate them.
		App.g_kKeyboardBinding.RebuildMappingFromFile("DefaultKeyboardBinding")
		App.g_kKeyboardBinding.GenerateMappingFile()
		reload(KeyboardBinding)
except:
	# Could not load keyboard bindings. Generate them from the default.
	App.g_kKeyboardBinding.RebuildMappingFromFile("DefaultKeyboardBinding")
	App.g_kKeyboardBinding.GenerateMappingFile()

# Terminate function is called on UtopiaModule::Terminate.
def Terminate():
	# Shut down AI tree logging, so it writes its final data.
	App.ArtificialIntelligence_LogAITree(None)
