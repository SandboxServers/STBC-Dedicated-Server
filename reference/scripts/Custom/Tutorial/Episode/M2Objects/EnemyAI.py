import App

def CreateAI(pShip):
	#########################################
	# Creating CompoundAI AttackFriendlies at (50, 50)
	import AI.Compound.BasicAttack
	pAttackFriendlies = AI.Compound.BasicAttack.CreateAI(pShip, ["player", "Galaxy 1"])
	# Done creating CompoundAI AttackFriendlies
	#########################################
	return pAttackFriendlies
