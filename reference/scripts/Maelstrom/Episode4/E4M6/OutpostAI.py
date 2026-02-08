import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI StarbaseAttack at (159, 176)
	import AI.Compound.StarbaseAttack
	pStarbaseAttack = AI.Compound.StarbaseAttack.CreateAI(pShip, "player")
	# Done creating CompoundAI StarbaseAttack
	#########################################
	return pStarbaseAttack
