	######### AI Builder Begin #########
## BUILDER AI
##  This AI file has been mauled by the MakeBuilderAI script.
##  Modify at your own risk.
##  Or run MakeBuilderAI(filename, 1) to remove the BuilderAI code.
	########## AI Builder End ##########
import App
def CreateAI(pShip):
	# We need to get the current mission's script name.
	# Get the mission...
	pGame = App.Game_GetCurrentGame()
	pEpisode = pGame.GetCurrentEpisode()
	pMission = pEpisode.GetCurrentMission()

	sMissionModuleName = pMission.GetScript()

	######### AI Builder Begin #########
	pBuilderAI = App.BuilderAI_Create(pShip, "ShieldDamage Builder", __name__)
	pBuilderAI.AddAIBlock("Call1Damage", "BuilderCreate1")
	pBuilderAI.AddDependencyObject("Call1Damage", "sMissionModuleName", sMissionModuleName)
	pBuilderAI.AddAIBlock("1PercentDamage", "BuilderCreate2")
	pBuilderAI.AddDependency("1PercentDamage", "Call1Damage")
	pBuilderAI.AddAIBlock("Call10Damage", "BuilderCreate3")
	pBuilderAI.AddDependencyObject("Call10Damage", "sMissionModuleName", sMissionModuleName)
	pBuilderAI.AddAIBlock("10PercentDamage", "BuilderCreate4")
	pBuilderAI.AddDependency("10PercentDamage", "Call10Damage")
	pBuilderAI.AddAIBlock("Call25Damage", "BuilderCreate5")
	pBuilderAI.AddDependencyObject("Call25Damage", "sMissionModuleName", sMissionModuleName)
	pBuilderAI.AddAIBlock("25PercentDamage", "BuilderCreate6")
	pBuilderAI.AddDependency("25PercentDamage", "Call25Damage")
	pBuilderAI.AddAIBlock("Call50Damage", "BuilderCreate7")
	pBuilderAI.AddDependencyObject("Call50Damage", "sMissionModuleName", sMissionModuleName)
	pBuilderAI.AddAIBlock("50PercentDamage", "BuilderCreate8")
	pBuilderAI.AddDependency("50PercentDamage", "Call50Damage")
	pBuilderAI.AddAIBlock("Call75Damage", "BuilderCreate9")
	pBuilderAI.AddDependencyObject("Call75Damage", "sMissionModuleName", sMissionModuleName)
	pBuilderAI.AddAIBlock("75PercentDamage", "BuilderCreate10")
	pBuilderAI.AddDependency("75PercentDamage", "Call75Damage")
	pBuilderAI.AddAIBlock("Call90Damage", "BuilderCreate11")
	pBuilderAI.AddDependencyObject("Call90Damage", "sMissionModuleName", sMissionModuleName)
	pBuilderAI.AddAIBlock("90PercentDamage", "BuilderCreate12")
	pBuilderAI.AddDependency("90PercentDamage", "Call90Damage")
	pBuilderAI.AddAIBlock("HullOrPowerDamage", "BuilderCreate13")
	pBuilderAI.AddDependency("HullOrPowerDamage", "1PercentDamage")
	pBuilderAI.AddDependency("HullOrPowerDamage", "10PercentDamage")
	pBuilderAI.AddDependency("HullOrPowerDamage", "25PercentDamage")
	pBuilderAI.AddDependency("HullOrPowerDamage", "50PercentDamage")
	pBuilderAI.AddDependency("HullOrPowerDamage", "75PercentDamage")
	pBuilderAI.AddDependency("HullOrPowerDamage", "90PercentDamage")
	pBuilderAI.AddAIBlock("CallShieldGone", "BuilderCreate14")
	pBuilderAI.AddDependencyObject("CallShieldGone", "sMissionModuleName", sMissionModuleName)
	pBuilderAI.AddAIBlock("ShieldGone", "BuilderCreate15")
	pBuilderAI.AddDependency("ShieldGone", "CallShieldGone")
	pBuilderAI.AddAIBlock("CallShield25", "BuilderCreate16")
	pBuilderAI.AddDependencyObject("CallShield25", "sMissionModuleName", sMissionModuleName)
	pBuilderAI.AddAIBlock("Shield25Damage", "BuilderCreate17")
	pBuilderAI.AddDependency("Shield25Damage", "CallShield25")
	pBuilderAI.AddAIBlock("CallShield50", "BuilderCreate18")
	pBuilderAI.AddDependencyObject("CallShield50", "sMissionModuleName", sMissionModuleName)
	pBuilderAI.AddAIBlock("Shield50Damage", "BuilderCreate19")
	pBuilderAI.AddDependency("Shield50Damage", "CallShield50")
	pBuilderAI.AddAIBlock("CallShield75", "BuilderCreate20")
	pBuilderAI.AddDependencyObject("CallShield75", "sMissionModuleName", sMissionModuleName)
	pBuilderAI.AddAIBlock("Shield75Damage", "BuilderCreate21")
	pBuilderAI.AddDependency("Shield75Damage", "CallShield75")
	pBuilderAI.AddAIBlock("ShieldDamage", "BuilderCreate22")
	pBuilderAI.AddDependency("ShieldDamage", "HullOrPowerDamage")
	pBuilderAI.AddDependency("ShieldDamage", "ShieldGone")
	pBuilderAI.AddDependency("ShieldDamage", "Shield25Damage")
	pBuilderAI.AddDependency("ShieldDamage", "Shield50Damage")
	pBuilderAI.AddDependency("ShieldDamage", "Shield75Damage")
	return pBuilderAI # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate1(pShip, sMissionModuleName):
	########## AI Builder End ##########
	#########################################
	# Creating PlainAI Call1Damage at (8, 327)
	pCall1Damage = App.PlainAI_Create(pShip, "Call1Damage")
	pCall1Damage.SetScriptModule("RunScript")
	pCall1Damage.SetInterruptable(1)
	pScript = pCall1Damage.GetScriptInstance()
	pScript.SetArguments(pShip.GetName(), "HullPower",1)
	pScript.SetScriptModule(sMissionModuleName)
	pScript.SetFunction("CallDamage")
	# Done creating PlainAI Call1Damage
	#########################################
	# Builder AI Dependency Object (sMissionModuleName)
	######### AI Builder Begin #########
	return pCall1Damage  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate2(pShip, pCall1Damage):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI 1PercentDamage at (7, 280)
	## Conditions:
	#### Condition HullLow
	pHullLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_HULL_SUBSYSTEM, 0.01)
	#### Condition PowerPlantLow
	pPowerPlantLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_POWER_SUBSYSTEM, 0.01)
	## Evaluation function:
	def EvalFunc(bHullLow, bPowerPlantLow):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bHullLow or bPowerPlantLow:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	p1PercentDamage = App.ConditionalAI_Create(pShip, "1PercentDamage")
	p1PercentDamage.SetInterruptable(1)
	p1PercentDamage.SetContainedAI(pCall1Damage)
	p1PercentDamage.AddCondition(pHullLow)
	p1PercentDamage.AddCondition(pPowerPlantLow)
	p1PercentDamage.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI 1PercentDamage
	#########################################
	######### AI Builder Begin #########
	return p1PercentDamage  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate3(pShip, sMissionModuleName):
	########## AI Builder End ##########
	#########################################
	# Creating PlainAI Call10Damage at (97, 327)
	pCall10Damage = App.PlainAI_Create(pShip, "Call10Damage")
	pCall10Damage.SetScriptModule("RunScript")
	pCall10Damage.SetInterruptable(1)
	pScript = pCall10Damage.GetScriptInstance()
	pScript.SetArguments(pShip.GetName(), "HullPower",10)
	pScript.SetScriptModule(sMissionModuleName)
	pScript.SetFunction("CallDamage")
	# Done creating PlainAI Call10Damage
	#########################################
	# Builder AI Dependency Object (sMissionModuleName)
	######### AI Builder Begin #########
	return pCall10Damage  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate4(pShip, pCall10Damage):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI 10PercentDamage at (94, 279)
	## Conditions:
	#### Condition HullLow
	pHullLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_HULL_SUBSYSTEM, 0.10)
	#### Condition PowerPlantLow
	pPowerPlantLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_POWER_SUBSYSTEM, 0.10)
	## Evaluation function:
	def EvalFunc(bHullLow, bPowerPlantLow):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bHullLow or bPowerPlantLow:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	p10PercentDamage = App.ConditionalAI_Create(pShip, "10PercentDamage")
	p10PercentDamage.SetInterruptable(1)
	p10PercentDamage.SetContainedAI(pCall10Damage)
	p10PercentDamage.AddCondition(pHullLow)
	p10PercentDamage.AddCondition(pPowerPlantLow)
	p10PercentDamage.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI 10PercentDamage
	#########################################
	######### AI Builder Begin #########
	return p10PercentDamage  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate5(pShip, sMissionModuleName):
	########## AI Builder End ##########
	#########################################
	# Creating PlainAI Call25Damage at (190, 328)
	pCall25Damage = App.PlainAI_Create(pShip, "Call25Damage")
	pCall25Damage.SetScriptModule("RunScript")
	pCall25Damage.SetInterruptable(1)
	pScript = pCall25Damage.GetScriptInstance()
	pScript.SetArguments(pShip.GetName(), "HullPower",25)
	pScript.SetScriptModule(sMissionModuleName)
	pScript.SetFunction("CallDamage")
	# Done creating PlainAI Call25Damage
	#########################################
	# Builder AI Dependency Object (sMissionModuleName)
	######### AI Builder Begin #########
	return pCall25Damage  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate6(pShip, pCall25Damage):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI 25PercentDamage at (184, 279)
	## Conditions:
	#### Condition HullLow
	pHullLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_HULL_SUBSYSTEM, 0.25)
	#### Condition PowerPlantLow
	pPowerPlantLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_POWER_SUBSYSTEM, 0.25)
	## Evaluation function:
	def EvalFunc(bHullLow, bPowerPlantLow):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bHullLow or bPowerPlantLow:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	p25PercentDamage = App.ConditionalAI_Create(pShip, "25PercentDamage")
	p25PercentDamage.SetInterruptable(1)
	p25PercentDamage.SetContainedAI(pCall25Damage)
	p25PercentDamage.AddCondition(pHullLow)
	p25PercentDamage.AddCondition(pPowerPlantLow)
	p25PercentDamage.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI 25PercentDamage
	#########################################
	######### AI Builder Begin #########
	return p25PercentDamage  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate7(pShip, sMissionModuleName):
	########## AI Builder End ##########
	#########################################
	# Creating PlainAI Call50Damage at (280, 327)
	pCall50Damage = App.PlainAI_Create(pShip, "Call50Damage")
	pCall50Damage.SetScriptModule("RunScript")
	pCall50Damage.SetInterruptable(1)
	pScript = pCall50Damage.GetScriptInstance()
	pScript.SetArguments(pShip.GetName(), "HullPower",50)
	pScript.SetScriptModule(sMissionModuleName)
	pScript.SetFunction("CallDamage")
	# Done creating PlainAI Call50Damage
	#########################################
	# Builder AI Dependency Object (sMissionModuleName)
	######### AI Builder Begin #########
	return pCall50Damage  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate8(pShip, pCall50Damage):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI 50PercentDamage at (274, 279)
	## Conditions:
	#### Condition HullLow
	pHullLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_HULL_SUBSYSTEM, 0.50)
	#### Condition PowerPlantLow
	pPowerPlantLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_POWER_SUBSYSTEM, 0.50)
	## Evaluation function:
	def EvalFunc(bHullLow, bPowerPlantLow):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bHullLow or bPowerPlantLow:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	p50PercentDamage = App.ConditionalAI_Create(pShip, "50PercentDamage")
	p50PercentDamage.SetInterruptable(1)
	p50PercentDamage.SetContainedAI(pCall50Damage)
	p50PercentDamage.AddCondition(pHullLow)
	p50PercentDamage.AddCondition(pPowerPlantLow)
	p50PercentDamage.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI 50PercentDamage
	#########################################
	######### AI Builder Begin #########
	return p50PercentDamage  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate9(pShip, sMissionModuleName):
	########## AI Builder End ##########
	#########################################
	# Creating PlainAI Call75Damage at (373, 328)
	pCall75Damage = App.PlainAI_Create(pShip, "Call75Damage")
	pCall75Damage.SetScriptModule("RunScript")
	pCall75Damage.SetInterruptable(1)
	pScript = pCall75Damage.GetScriptInstance()
	pScript.SetArguments(pShip.GetName(), "HullPower",75)
	pScript.SetScriptModule(sMissionModuleName)
	pScript.SetFunction("CallDamage")
	# Done creating PlainAI Call75Damage
	#########################################
	# Builder AI Dependency Object (sMissionModuleName)
	######### AI Builder Begin #########
	return pCall75Damage  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate10(pShip, pCall75Damage):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI 75PercentDamage at (369, 278)
	## Conditions:
	#### Condition HullLow
	pHullLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_HULL_SUBSYSTEM, 0.75)
	#### Condition PowerPlantLow
	pPowerPlantLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_POWER_SUBSYSTEM, 0.75)
	## Evaluation function:
	def EvalFunc(bHullLow, bPowerPlantLow):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bHullLow or bPowerPlantLow:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	p75PercentDamage = App.ConditionalAI_Create(pShip, "75PercentDamage")
	p75PercentDamage.SetInterruptable(1)
	p75PercentDamage.SetContainedAI(pCall75Damage)
	p75PercentDamage.AddCondition(pHullLow)
	p75PercentDamage.AddCondition(pPowerPlantLow)
	p75PercentDamage.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI 75PercentDamage
	#########################################
	######### AI Builder Begin #########
	return p75PercentDamage  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate11(pShip, sMissionModuleName):
	########## AI Builder End ##########
	#########################################
	# Creating PlainAI Call90Damage at (475, 327)
	pCall90Damage = App.PlainAI_Create(pShip, "Call90Damage")
	pCall90Damage.SetScriptModule("RunScript")
	pCall90Damage.SetInterruptable(1)
	pScript = pCall90Damage.GetScriptInstance()
	pScript.SetArguments(pShip.GetName(), "HullPower",90)
	pScript.SetScriptModule(sMissionModuleName)
	pScript.SetFunction("CallDamage")
	# Done creating PlainAI Call90Damage
	#########################################
	# Builder AI Dependency Object (sMissionModuleName)
	######### AI Builder Begin #########
	return pCall90Damage  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate12(pShip, pCall90Damage):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI 90PercentDamage at (473, 278)
	## Conditions:
	#### Condition HullLow
	pHullLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_HULL_SUBSYSTEM, 0.9)
	#### Condition PowerPlantLow
	pPowerPlantLow = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", pShip.GetName(), App.CT_POWER_SUBSYSTEM, 0.90)
	## Evaluation function:
	def EvalFunc(bHullLow, bPowerPlantLow):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bHullLow or bPowerPlantLow:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	p90PercentDamage = App.ConditionalAI_Create(pShip, "90PercentDamage")
	p90PercentDamage.SetInterruptable(1)
	p90PercentDamage.SetContainedAI(pCall90Damage)
	p90PercentDamage.AddCondition(pHullLow)
	p90PercentDamage.AddCondition(pPowerPlantLow)
	p90PercentDamage.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI 90PercentDamage
	#########################################
	######### AI Builder Begin #########
	return p90PercentDamage  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate13(pShip, p1PercentDamage, p10PercentDamage, p25PercentDamage, p50PercentDamage, p75PercentDamage, p90PercentDamage):
	########## AI Builder End ##########
	#########################################
	# Creating PriorityListAI HullOrPowerDamage at (58, 181)
	pHullOrPowerDamage = App.PriorityListAI_Create(pShip, "HullOrPowerDamage")
	pHullOrPowerDamage.SetInterruptable(1)
	# SeqBlock is at (55, 226)
	pHullOrPowerDamage.AddAI(p1PercentDamage, 1)
	pHullOrPowerDamage.AddAI(p10PercentDamage, 2)
	pHullOrPowerDamage.AddAI(p25PercentDamage, 3)
	pHullOrPowerDamage.AddAI(p50PercentDamage, 4)
	pHullOrPowerDamage.AddAI(p75PercentDamage, 5)
	pHullOrPowerDamage.AddAI(p90PercentDamage, 6)
	# Done creating PriorityListAI HullOrPowerDamage
	#########################################
	######### AI Builder Begin #########
	return pHullOrPowerDamage  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate14(pShip, sMissionModuleName):
	########## AI Builder End ##########
	#########################################
	# Creating PlainAI CallShieldGone at (68, 133)
	pCallShieldGone = App.PlainAI_Create(pShip, "CallShieldGone")
	pCallShieldGone.SetScriptModule("RunScript")
	pCallShieldGone.SetInterruptable(1)
	pScript = pCallShieldGone.GetScriptInstance()
	pScript.SetArguments(pShip.GetName(), "Shield", 0)
	pScript.SetScriptModule(sMissionModuleName)
	pScript.SetFunction("CallDamage")
	# Done creating PlainAI CallShieldGone
	#########################################
	# Builder AI Dependency Object (sMissionModuleName)
	######### AI Builder Begin #########
	return pCallShieldGone  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate15(pShip, pCallShieldGone):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI ShieldGone at (67, 90)
	## Conditions:
	#### Condition ShieldLow
	pShieldLow = App.ConditionScript_Create("Conditions.ConditionSingleShieldBelow", "ConditionSingleShieldBelow", pShip.GetName(), .01, App.ShieldClass.NUM_SHIELDS)
	## Evaluation function:
	def EvalFunc(bShieldLow):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bShieldLow:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pShieldGone = App.ConditionalAI_Create(pShip, "ShieldGone")
	pShieldGone.SetInterruptable(1)
	pShieldGone.SetContainedAI(pCallShieldGone)
	pShieldGone.AddCondition(pShieldLow)
	pShieldGone.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI ShieldGone
	#########################################
	######### AI Builder Begin #########
	return pShieldGone  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate16(pShip, sMissionModuleName):
	########## AI Builder End ##########
	#########################################
	# Creating PlainAI CallShield25 at (164, 134)
	pCallShield25 = App.PlainAI_Create(pShip, "CallShield25")
	pCallShield25.SetScriptModule("RunScript")
	pCallShield25.SetInterruptable(1)
	pScript = pCallShield25.GetScriptInstance()
	pScript.SetArguments(pShip.GetName(), "Shields", 25)
	pScript.SetScriptModule(sMissionModuleName)
	pScript.SetFunction("CallDamage")
	# Done creating PlainAI CallShield25
	#########################################
	# Builder AI Dependency Object (sMissionModuleName)
	######### AI Builder Begin #########
	return pCallShield25  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate17(pShip, pCallShield25):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI Shield25Damage at (163, 89)
	## Conditions:
	#### Condition ShieldLow
	pShieldLow = App.ConditionScript_Create("Conditions.ConditionSingleShieldBelow", "ConditionSingleShieldBelow", pShip.GetName(), .25, App.ShieldClass.NUM_SHIELDS)
	## Evaluation function:
	def EvalFunc(bShieldLow):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bShieldLow:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pShield25Damage = App.ConditionalAI_Create(pShip, "Shield25Damage")
	pShield25Damage.SetInterruptable(1)
	pShield25Damage.SetContainedAI(pCallShield25)
	pShield25Damage.AddCondition(pShieldLow)
	pShield25Damage.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Shield25Damage
	#########################################
	######### AI Builder Begin #########
	return pShield25Damage  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate18(pShip, sMissionModuleName):
	########## AI Builder End ##########
	#########################################
	# Creating PlainAI CallShield50 at (268, 135)
	pCallShield50 = App.PlainAI_Create(pShip, "CallShield50")
	pCallShield50.SetScriptModule("RunScript")
	pCallShield50.SetInterruptable(1)
	pScript = pCallShield50.GetScriptInstance()
	pScript.SetArguments(pShip.GetName(), "Shields", 50)
	pScript.SetScriptModule(sMissionModuleName)
	pScript.SetFunction("CallDamage")
	# Done creating PlainAI CallShield50
	#########################################
	# Builder AI Dependency Object (sMissionModuleName)
	######### AI Builder Begin #########
	return pCallShield50  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate19(pShip, pCallShield50):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI Shield50Damage at (266, 89)
	## Conditions:
	#### Condition ShieldLow
	pShieldLow = App.ConditionScript_Create("Conditions.ConditionSingleShieldBelow", "ConditionSingleShieldBelow", pShip.GetName(), .50, App.ShieldClass.NUM_SHIELDS)
	## Evaluation function:
	def EvalFunc(bShieldLow):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bShieldLow:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pShield50Damage = App.ConditionalAI_Create(pShip, "Shield50Damage")
	pShield50Damage.SetInterruptable(1)
	pShield50Damage.SetContainedAI(pCallShield50)
	pShield50Damage.AddCondition(pShieldLow)
	pShield50Damage.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Shield50Damage
	#########################################
	######### AI Builder Begin #########
	return pShield50Damage  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate20(pShip, sMissionModuleName):
	########## AI Builder End ##########
	#########################################
	# Creating PlainAI CallShield75 at (379, 134)
	pCallShield75 = App.PlainAI_Create(pShip, "CallShield75")
	pCallShield75.SetScriptModule("RunScript")
	pCallShield75.SetInterruptable(1)
	pScript = pCallShield75.GetScriptInstance()
	pScript.SetArguments(pShip.GetName(), "Shields", 75)
	pScript.SetScriptModule(sMissionModuleName)
	pScript.SetFunction("CallDamage")
	# Done creating PlainAI CallShield75
	#########################################
	# Builder AI Dependency Object (sMissionModuleName)
	######### AI Builder Begin #########
	return pCallShield75  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate21(pShip, pCallShield75):
	########## AI Builder End ##########
	#########################################
	# Creating ConditionalAI Shield75Damage at (376, 90)
	## Conditions:
	#### Condition ShieldLow
	pShieldLow = App.ConditionScript_Create("Conditions.ConditionSingleShieldBelow", "ConditionSingleShieldBelow", pShip.GetName(), .75, App.ShieldClass.NUM_SHIELDS)
	## Evaluation function:
	def EvalFunc(bShieldLow):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bShieldLow:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pShield75Damage = App.ConditionalAI_Create(pShip, "Shield75Damage")
	pShield75Damage.SetInterruptable(1)
	pShield75Damage.SetContainedAI(pCallShield75)
	pShield75Damage.AddCondition(pShieldLow)
	pShield75Damage.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI Shield75Damage
	#########################################
	######### AI Builder Begin #########
	return pShield75Damage  # Builder Return
	########## AI Builder End ##########
	######### AI Builder Begin #########
def BuilderCreate22(pShip, pHullOrPowerDamage, pShieldGone, pShield25Damage, pShield50Damage, pShield75Damage):
	########## AI Builder End ##########
	#########################################
	# Creating PriorityListAI ShieldDamage at (47, 11)
	pShieldDamage = App.PriorityListAI_Create(pShip, "ShieldDamage")
	pShieldDamage.SetInterruptable(1)
	# SeqBlock is at (47, 52)
	pShieldDamage.AddAI(pHullOrPowerDamage, 1)
	pShieldDamage.AddAI(pShieldGone, 2)
	pShieldDamage.AddAI(pShield25Damage, 3)
	pShieldDamage.AddAI(pShield50Damage, 4)
	pShieldDamage.AddAI(pShield75Damage, 5)
	# Done creating PriorityListAI ShieldDamage
	#########################################
	return pShieldDamage
	######### AI Builder Begin #########
	return pShieldDamage  # Builder Return
	########## AI Builder End ##########
