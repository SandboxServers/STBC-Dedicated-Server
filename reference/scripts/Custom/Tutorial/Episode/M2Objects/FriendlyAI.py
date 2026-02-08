import App

def CreateAI(pShip):
	#########################################
	# Creating CompoundAI AttackEnemies at (50, 50)
	import AI.Compound.BasicAttack
	pAttackEnemies = AI.Compound.BasicAttack.CreateAI(pShip, ["Galaxy 2"])
	# Done creating CompoundAI AttackEnemies
	#########################################
	return pAttackEnemies
