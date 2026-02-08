import App

class TargetListPerparer:
	def __init__(self, pAttackGroup):
		self.pAttackers = pAttackGroup

	def SetAttackedCondition(self, pCondition):
		self.pAttackedCondition = pCondition

	def GetNextUpdateTime(self):
		return 5.0

	def Update(self, dEndTime):
		import MissionLib
		pFriendlies = MissionLib.GetFriendlyGroup()

		# Update the list of attackers from the condition.
		pScript = self.pAttackedCondition.GetConditionScript()
		lsAttackers = pScript.GetTargetList()

		if lsAttackers:
			for sAttacker in lsAttackers:
				# If this attacker is a Friendly object, don't add it to the
				# list of targets.
				if pFriendlies and pFriendlies.IsNameInGroup(sAttacker):
					continue

				try:
					fShieldDamage = pScript.dfShieldDamage[sAttacker]
				except KeyError:
					fShieldDamage = 0.0

				try:
					fHullDamage = pScript.dfDamageDamage[sAttacker]
				except KeyError:
					fHullDamage = 0.0

				fPriority = fShieldDamage + fHullDamage
				self.pAttackers[sAttacker] = { "Priority" : fPriority }

		return App.PreprocessingAI.PS_NORMAL



def CreateAI(pShip, sDefendee):
	pAttackGroup = App.ObjectGroupWithInfo()
	pAttackGroup[pShip.GetName()] = { "Priority" : -1000.0 }

	#########################################
	# Creating CompoundAI Attack at (120, 106)
	import AI.Compound.BasicAttack
	pAttack = AI.Compound.BasicAttack.CreateAI(pShip, pAttackGroup)
	# Done creating CompoundAI Attack
	#########################################
	#########################################
	# Creating PreprocessingAI PrepTargetList at (118, 154)
	## Setup:
	pTargetPrep = TargetListPerparer(pAttackGroup)
	## The PreprocessingAI:
	pPrepTargetList = App.PreprocessingAI_Create(pShip, "PrepTargetList")
	pPrepTargetList.SetInterruptable(1)
	pPrepTargetList.SetPreprocessingMethod(pTargetPrep, "Update")
	pPrepTargetList.SetContainedAI(pAttack)
	# Done creating PreprocessingAI PrepTargetList
	#########################################
	#########################################
	# Creating ConditionalAI DefendeeAttacked at (117, 201)
	## Conditions:
	#### Condition Attacked
	pAttacked = App.ConditionScript_Create("Conditions.ConditionAttacked", "ConditionAttacked", sDefendee, 0.001, 0.001, 30.0)
	## Evaluation function:
	def EvalFunc(bAttacked):
		ACTIVE = App.ArtificialIntelligence.US_ACTIVE
		DORMANT = App.ArtificialIntelligence.US_DORMANT
		DONE = App.ArtificialIntelligence.US_DONE
		if bAttacked:
			return ACTIVE
		return DORMANT
	## The ConditionalAI:
	pDefendeeAttacked = App.ConditionalAI_Create(pShip, "DefendeeAttacked")
	pDefendeeAttacked.SetInterruptable(1)
	pDefendeeAttacked.SetContainedAI(pPrepTargetList)
	pDefendeeAttacked.AddCondition(pAttacked)
	pDefendeeAttacked.SetEvaluationFunction(EvalFunc)
	# Done creating ConditionalAI DefendeeAttacked
	#########################################
	pTargetPrep.SetAttackedCondition(pAttacked)
	#########################################
	# Creating PlainAI CircleDefendee at (218, 201)
	pCircleDefendee = App.PlainAI_Create(pShip, "CircleDefendee")
	pCircleDefendee.SetScriptModule("IntelligentCircleObject")
	pCircleDefendee.SetInterruptable(1)
	pScript = pCircleDefendee.GetScriptInstance()
	pScript.SetFollowObjectName(sDefendee)
	# Done creating PlainAI CircleDefendee
	#########################################
	#########################################
	# Creating PriorityListAI DefendPriorityList at (34, 251)
	pDefendPriorityList = App.PriorityListAI_Create(pShip, "DefendPriorityList")
	pDefendPriorityList.SetInterruptable(1)
	# SeqBlock is at (189, 261)
	pDefendPriorityList.AddAI(pDefendeeAttacked, 1)
	pDefendPriorityList.AddAI(pCircleDefendee, 2)
	# Done creating PriorityListAI DefendPriorityList
	#########################################
	return pDefendPriorityList
