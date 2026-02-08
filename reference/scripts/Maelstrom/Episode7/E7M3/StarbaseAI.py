import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI StarbaseAttack at (260, 55)
	import AI.Compound.StarbaseAttack
	pStarbaseAttack = AI.Compound.StarbaseAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode7.E7M3.E7M3", "pEnemyTargets"))
	# Done creating CompoundAI StarbaseAttack
	#########################################
	return pStarbaseAttack
