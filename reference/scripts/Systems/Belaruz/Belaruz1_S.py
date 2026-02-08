import App
import loadspacehelper

def Initialize(pSet):

	#Add Nebular
	# name of external texture (no need for alpha)
#	print("Building nebula")
	pNebula = App.MetaNebula_Create(100.0 / 255.0, 99.0 / 255.0, 146.0 / 255.0, 200.0, 6.5, "data/Backgrounds/nebulaoverlay.tga", "data/Backgrounds/nebulaexternal.tga")

	# Adds a fuzzy sphere at x, y, z (in world coord) of specified size 
	pNebula.AddNebulaSphere(-17.139893, 844.691284, -30.296316, 900.0)

	# Puts the nebula in the set
	pSet.AddObjectToSet(pNebula, "Belaruz 1 Nebula")
