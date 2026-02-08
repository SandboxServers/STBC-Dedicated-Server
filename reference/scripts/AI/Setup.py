###############################################################################
#	Filename:	Setup.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Setup code for AI.
#	
#	Created:	5/24/2001 -	KDeus
###############################################################################

###############################################################################
#	GameInit
#	
#	Load the basic AI scripts into memory, so they don't hitch
#	the game while it's playing.  Also load all the Condition scripts.
#	
#	Args:	None
#	
#	Return:	None
###############################################################################
def GameInit():
	lsErrors = []

	# Big monstrous list of AI and Condition files.
	for sModule in (
		"AI.Preprocessors",
		"AI.Compound.BasicAttack",
		"AI.Compound.CallDamageAI",
		"AI.Compound.ChainFollow",
		"AI.Compound.ChainFollowThroughWarp",
		"AI.Compound.CloakAttack",
		"AI.Compound.CloakAttackWrapper",
		"AI.Compound.Defend",
		"AI.Compound.DockWithStarbase",
		"AI.Compound.FedAttack",
		"AI.Compound.FollowThroughWarp",
		"AI.Compound.NonFedAttack",
		"AI.Compound.StarbaseAttack",
		"AI.Compound.TractorDockTargets",
		"AI.Compound.UndockFromStarbase",
		"AI.Compound.Parts.EvadeTorps",
		"AI.Compound.Parts.ICOMove",
		"AI.Compound.Parts.SweepPhasers",
		"AI.Compound.Parts.WarpBeforeDeath",
		"AI.Compound.Parts.NoSensorsEvasive",
		"AI.PlainAI.BaseAI",
		"AI.PlainAI.CircleObject",
		"AI.PlainAI.Defensive",
		"AI.PlainAI.EvadeTorps",
		"AI.PlainAI.EvilShuttleDocking",
		"AI.PlainAI.Flee",
		"AI.PlainAI.FollowObject",
		"AI.PlainAI.FollowThroughWarp",
		"AI.PlainAI.FollowWaypoints",
		"AI.PlainAI.GoForward",
		"AI.PlainAI.IntelligentCircleObject",
		"AI.PlainAI.Intercept",
		"AI.PlainAI.ManeuverLoop",
		"AI.PlainAI.MoveToObjectSide",
		"AI.PlainAI.PhaserSweep",
		"AI.PlainAI.Ram",
		"AI.PlainAI.RunAction",
		"AI.PlainAI.RunScript",
		"AI.PlainAI.SelfDestruct",
		"AI.PlainAI.StarbaseAttack",
		"AI.PlainAI.StationaryAttack",
		"AI.PlainAI.Stay",
		"AI.PlainAI.TorpedoRun",
		"AI.PlainAI.TriggerEvent",
		"AI.PlainAI.TurnToOrientation",
		"AI.PlainAI.Warp",
		"AI.Fleet.DefendTarget",
		"AI.Fleet.DestroyTarget",
		"AI.Fleet.DisableTarget",
		"AI.Fleet.HelpMe",
		"AI.Player.Defense",
		"AI.Player.DefenseNoTarget",
		"AI.Player.DestroyAft",
		"AI.Player.DestroyAftSeparate",
		"AI.Player.DestroyFaceSide",
		"AI.Player.DestroyFore",
		"AI.Player.DestroyForeClose",
		"AI.Player.DestroyFreely",
		"AI.Player.DestroyFreelyClose",
		"AI.Player.DestroyFreelyMaintain",
		"AI.Player.DestroyFreelySeparate",
		"AI.Player.DestroyFromSide",
		"AI.Player.DisableAft",
		"AI.Player.DisableAftSeparate",
		"AI.Player.DisableFaceSide",
		"AI.Player.DisableFore",
		"AI.Player.DisableForeClose",
		"AI.Player.DisableFreely",
		"AI.Player.DisableFreelyClose",
		"AI.Player.DisableFreelyMaintain",
		"AI.Player.DisableFreelySeparate",
		"AI.Player.DisableFromSide",
		"AI.Player.FlyForward",
		"AI.Player.InterceptTarget",
		"AI.Player.OrbitPlanet",
		"AI.Player.PlayerWarp",
		"AI.Player.Stay",
		"AI.Player.StaySelectTarget",
		"Conditions.ConditionAllInSameSet",
		"Conditions.ConditionAnyInSameSet",
		"Conditions.ConditionAttacked",
		"Conditions.ConditionAttackedBy",
		"Conditions.ConditionCriticalSystemBelow",
		"Conditions.ConditionDestroyed",
		"Conditions.ConditionDifficultyAt",
		"Conditions.ConditionExists",
		"Conditions.ConditionFacingToward",
		"Conditions.ConditionFiringTractorBeam",
		"Conditions.ConditionFlagSet",
		"Conditions.ConditionIncomingTorps",
		"Conditions.ConditionInLineOfSight",
		"Conditions.ConditionInNebula",
		"Conditions.ConditionInPhaserFiringArc",
		"Conditions.ConditionInRange",
		"Conditions.ConditionInSet",
		"Conditions.ConditionMissionEvent",
		"Conditions.ConditionPlayerOrbitting",
		"Conditions.ConditionPowerBelow",
		"Conditions.ConditionPulseReady",
		"Conditions.ConditionReachedWaypoint",
		"Conditions.ConditionShipDisabled",
		"Conditions.ConditionSingleShieldBelow",
		"Conditions.ConditionSystemBelow",
		"Conditions.ConditionSystemDestroyed",
		"Conditions.ConditionSystemDisabled",
		"Conditions.ConditionTimer",
		"Conditions.ConditionTorpsReady",
		"Conditions.ConditionUsingWeapon",
		"Conditions.ConditionWarpingToSet",
		"Conditions.ConditionWarpingToMission",
		"Conditions.FriendliesInPlayerSetStronger",
		):
		try:
			__import__(sModule)
		except:
			lsErrors.append(sModule)

	if lsErrors:
		raise ImportError, "Error preloading modules: " + str(lsErrors)
