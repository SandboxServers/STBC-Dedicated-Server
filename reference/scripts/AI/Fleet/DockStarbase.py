import App

def CreateAI(idShip, idStarbase, pGraffAction, **dKeywords):
	pShip = App.ShipClass_GetObjectByID(None, idShip)
	pStarbase = App.ShipClass_GetObjectByID(None, idStarbase)

	if (not pShip)  or  (not pStarbase):
		return None

	import AI.Compound.DockWithStarbase
	return apply(getattr(AI.Compound.DockWithStarbase, "CreateAI"), (pShip, pStarbase, pGraffAction), dKeywords)
