import App

def CreateAI(pShip):
	#########################################
	# Creating CompoundAI BasicAttack at (130, 75)
	import AI.Compound.BasicAttack
	pBasicAttack = AI.Compound.BasicAttack.CreateAI(pShip, "G5", "Galor1", "Keldon1","Galor2")
	# Done creating CompoundAI BasicAttack
	#########################################
	return pBasicAttack
