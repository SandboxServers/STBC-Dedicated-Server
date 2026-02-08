import App
import loadspacehelper


def Initialize(pSet):
#	print ("Creating Multi5 Nebulae")


	import Systems.Multi5.Multi5
	pSet = Systems.Multi5.Multi5.GetSet()

	################
	# Create the nebulae
	################
	
	# MetaNebula_Create params are:
	# r, g, b : (floats [0.0 , 1.0]) 
	# visibility distance inside the nebula (float in world units)
	# scale factor for sensors in the nebula [0.0, 1.0] where 1.0 is normal range and 0.0 is no sensors
	# name of internal texture (needs alpha)
	# name of external texture (no need for alpha)

	# NOTE: There is currently a problem with MetaNebulae; if they are to certain colors,
	# the entire region will be filled with nebulous substance. Until this is fixed,
	# all MetaNebulae will be temporarily set to a color that we know works.
	# The lines with the correct colors are commented out for now.
		
	####
	# First nebula
	####
	pNebula = App.MetaNebula_Create(0.125, 0.75, 0.125, 143.0, 0.5, 
		"data/Backgrounds/nebulaoverlaygreen.tga", "data/Backgrounds/nebulaexternalgreen.tga")
	# Adds a fuzzy sphere at x, y, z (in world coord) of specified size
	pNebula.AddNebulaSphere(200.0, 0.0, 0.0, 200.0)
	# Puts the nebula in the set
	pSet.AddObjectToSet(pNebula, "Nebula1")

	####
	# Second nebula
	####
	pNebula = App.MetaNebula_Create(0.125, 0.75, 0.125, 143.0, 0.5, 
		"data/Backgrounds/nebulaoverlaygreen.tga", "data/Backgrounds/nebulaexternalgreen.tga")
	# Adds a fuzzy sphere at x, y, z (in world coord) of specified size
	pNebula.AddNebulaSphere(310.0, -125.0, -125.0, 150.0)
	pNebula.AddNebulaSphere(230.0, 125.0, 125.0, 150.0)
	pNebula.AddNebulaSphere(290.0, -125.0, 125.0, 150.0)
	pNebula.AddNebulaSphere(310.0, 125.0, -125.0, 150.0)
	# Puts the nebula in the set
	pSet.AddObjectToSet(pNebula, "Nebula2")

	####
	# Third nebula
	####
	pNebula = App.MetaNebula_Create(0.75, 0.75, 0.125, 143.0, 0.5, 
		"data/Backgrounds/nebulaoverlayyellow.tga", "data/Backgrounds/nebulaexternalyellow.tga")
	# Adds a fuzzy sphere at x, y, z (in world coord) of specified size
	pNebula.AddNebulaSphere(301.0, 125.0, 0.0, 150.0)
	pNebula.AddNebulaSphere(302.0, -125.0, 0.0, 150.0)
	pNebula.AddNebulaSphere(240.0, 0.0, 125.0, 150.0)
	pNebula.AddNebulaSphere(305.0, 0.0, -125.0, 150.0)
	# Puts the nebula in the set
	pSet.AddObjectToSet(pNebula, "Nebula3")

	####
	# Fourth nebula
	####
	pNebula = App.MetaNebula_Create(0.75, 0.75, 0.125, 143.0, 0.5, 
		"data/Backgrounds/nebulaoverlayyellow.tga", "data/Backgrounds/nebulaexternalyellow.tga")
	# Adds a fuzzy sphere at x, y, z (in world coord) of specified size
	pNebula.AddNebulaSphere(315.0, 225.0, 0.0, 150.0)
	pNebula.AddNebulaSphere(315.0, -245.0, 0.0, 150.0)
	pNebula.AddNebulaSphere(270.0, 0.0, 175.0, 130.0)
	pNebula.AddNebulaSphere(330.0, 0.0, -200.0, 150.0)
	# Puts the nebula in the set
	pSet.AddObjectToSet(pNebula, "Nebula4")

