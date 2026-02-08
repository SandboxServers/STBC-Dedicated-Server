import App
def CreateAI(pShip):
	#########################################
	# Creating CompoundAI CallDamageAI at (242, 97)
	import AI.Compound.CallDamageAI
	pCallDamageAI = AI.Compound.CallDamageAI.CreateAI(pShip)
	# Done creating CompoundAI CallDamageAI
	#########################################
	#########################################
	# Creating CompoundAI StarbaseAttack at (267, 54)
	import AI.Compound.StarbaseAttack
	pStarbaseAttack = AI.Compound.StarbaseAttack.CreateAI(pShip, App.ObjectGroup_FromModule("Maelstrom.Episode7.E7M1.E7M1", "pEnemies"))
	# Done creating CompoundAI StarbaseAttack
	#########################################
	#########################################
	# Creating PriorityListAI Starbase12AI at (128, 18)
	pStarbase12AI = App.PriorityListAI_Create(pShip, "Starbase12AI")
	pStarbase12AI.SetInterruptable(1)
	# SeqBlock is at (235, 25)
	pStarbase12AI.AddAI(pCallDamageAI, 1)
	pStarbase12AI.AddAI(pStarbaseAttack, 2)
	# Done creating PriorityListAI Starbase12AI
	#########################################
	return pStarbase12AI
