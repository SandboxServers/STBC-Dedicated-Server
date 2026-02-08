# PicardAnimations.py
# This file includes all animations shared by medium characters

import App
import Bridge.Characters.CommonAnimations

def PlaceAtL1(self):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/db_L1toG1_S.nif", "db_L1toG1_S")
	pCharacter = App.CharacterClass_Cast(self)
	pSequence = App.TGSequence_Create()
	pOpenEyes = Bridge.Characters.CommonAnimations.EyesOpenMouthClosed(self)
	pSequence.AddAction(pOpenEyes)
	pAnimNode = pCharacter.GetAnimNode()
	pAction = App.TGAnimPosition_Create(pAnimNode, "db_L1toG1_S")
	pSequence.AddAction(pAction, pOpenEyes)
	return pSequence

def PlaceAtP(self):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/db_stand_P.NIF", "db_stand_P")
	pCharacter = App.CharacterClass_Cast(self)
	pSequence = App.TGSequence_Create()
	pOpenEyes = Bridge.Characters.CommonAnimations.EyesOpenMouthClosed(self)
	pSequence.AddAction(pOpenEyes)
	pAnimNode = pCharacter.GetAnimNode()
	pAction = App.TGAnimPosition_Create(pAnimNode, "db_stand_P")
	pSequence.AddAction(pAction, pOpenEyes)
	return pSequence

def SeatedP(self):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/db_seated_P.nif", "db_seated_P")
	pCharacter = App.CharacterClass_Cast(self)
	pSequence = App.TGSequence_Create()
	pAnimNode = pCharacter.GetAnimNode()
	pAction = App.TGAnimAction_Create(pAnimNode, "db_seated_P", 0, 0)
	pSequence.AddAction(pAction)
	return pSequence

def TurnAtCTowardsCaptain(self):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/db_face_capt_c.nif", "db_face_capt_c")
	pCharacter = App.CharacterClass_Cast(self)
	pSequence = App.TGSequence_Create()
	pOpenEyes = Bridge.Characters.CommonAnimations.EyesOpenMouthClosed(self)
	pSequence.AddAction(pOpenEyes)
	pAction = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "db_face_capt_c", 0, 0)
	pSequence.AddAction(pAction, pOpenEyes)
	return pSequence

def TurnBackAtCFromCaptain(self):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/db_seated_c_m.NIF", "db_seated_c_m")
	pCharacter = App.CharacterClass_Cast(self)
	pSequence = App.TGSequence_Create()
	pOpenEyes = Bridge.Characters.CommonAnimations.EyesOpenMouthClosed(self)
	pSequence.AddAction(pOpenEyes)
	pAction = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "db_seated_c_m", 0, 0)
	pSequence.AddAction(pAction, pOpenEyes)
	return pSequence

def TurnAtC1TowardsCaptain(self):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/db_face_capt_c1.nif", "db_face_capt_c1")
	pCharacter = App.CharacterClass_Cast(self)
	pSequence = App.TGSequence_Create()
	pOpenEyes = Bridge.Characters.CommonAnimations.EyesOpenMouthClosed(self)
	pSequence.AddAction(pOpenEyes)
	pAction = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "db_face_capt_c1", 0, 0)
	pSequence.AddAction(pAction, pOpenEyes)
	return pSequence

def TurnBackAtC1FromCaptain(self):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/db_face_capt_c1_reverse.NIF", "db_face_capt_c1_reverse")
	pCharacter = App.CharacterClass_Cast(self)
	pSequence = App.TGSequence_Create()
	pOpenEyes = Bridge.Characters.CommonAnimations.EyesOpenMouthClosed(self)
	pSequence.AddAction(pOpenEyes)
	pAction = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "db_face_capt_c1_reverse", 0, 0)
	pSequence.AddAction(pAction, pOpenEyes)
	return pSequence

	# L1 to P medium
def MoveFromL1ToP1(self):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/db_L1toP_P.nif", "db_L1toP_P")
	pSet = App.g_kSetManager.GetSet("bridge")
	pBridge = pSet.GetObject("bridge")
	pBridgeNode = pBridge.GetAnimNode()
	pCharacter = App.CharacterClass_Cast(self)
	pSequence = App.TGSequence_Create()
	pOpenEyes = Bridge.Characters.CommonAnimations.EyesOpenMouthClosed(self)
	pSequence.AddAction(pOpenEyes)
	pAnimAction_WalkFromLift = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "db_L1toP_P", 0, 0)
	pSequence.AddAction(pAnimAction_WalkFromLift, pOpenEyes)
	pDoorAction = App.TGScriptAction_Create("Actions.EffectScriptActions", "LiftDoorAction", pBridge, "doorl1", "LiftDoor")
	pSequence.AddAction(pDoorAction, pOpenEyes, 0.125)
	pEvent = App.TGIntEvent_Create()
	pEvent.SetEventType(App.ET_CHARACTER_ANIMATION_DONE)
	pEvent.SetDestination(pCharacter)
	pEvent.SetInt(App.CharacterClass.CS_STANDING)
	pSequence.AddCompletedEvent(pEvent)
	pSequence.AppendAction(App.CharacterAction_Create(pCharacter, App.CharacterAction.AT_SET_LOCATION_NAME, "DBGuest1"))
	return pSequence	

def MoveFromP1ToP(self):
	kAM = App.g_kAnimationManager

	kAM.LoadAnimation ("data/animations/db_sit_P.nif", "db_sit_P")
	pSet = App.g_kSetManager.GetSet("bridge")
	pBridge = pSet.GetObject("bridge")
	pBridgeNode = pBridge.GetAnimNode()
	pCharacter = App.CharacterClass_Cast(self)
	pSequence = App.TGSequence_Create()
	pOpenEyes = Bridge.Characters.CommonAnimations.EyesOpenMouthClosed(self)
	pSequence.AddAction(pOpenEyes)
	pAnimAction = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "db_sit_P", 0, 0)
	pEvent = App.TGIntEvent_Create()
	pEvent.SetEventType(App.ET_CHARACTER_ANIMATION_DONE)
	pEvent.SetDestination(pCharacter)
	pEvent.SetInt(App.CharacterClass.CS_SEATED)
	pAnimAction.AddCompletedEvent(pEvent)
	pSequence.AddAction(pAnimAction)
	pSequence.AppendAction(App.CharacterAction_Create(pCharacter, App.CharacterAction.AT_SET_LOCATION_NAME, "DBGuest"))
	return pSequence	


def MoveFromPToL1(self):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/db_stand_P.nif", "db_stand_P")
	kAM.LoadAnimation ("data/animations/db_PtoL1_P.nif", "db_PtoL1_P")
	pSet = App.g_kSetManager.GetSet("bridge")
	pBridge = pSet.GetObject("bridge")
	pBridgeNode = pBridge.GetAnimNode()
	pCharacter = App.CharacterClass_Cast(self)
	pSequence = App.TGSequence_Create()
	pOpenEyes = Bridge.Characters.CommonAnimations.EyesOpenMouthClosed(self)
	pSequence.AddAction(pOpenEyes)
	pAnimAction_Stand = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "db_stand_P", 0, 0)
	pSequence.AddAction(pAnimAction_Stand, pOpenEyes)
	pAnimAction_WalkToLift = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "db_PtoL1_P", 0, 0)
	pSequence.AddAction(pAnimAction_WalkToLift, pAnimAction_Stand)
	fTime = kAM.GetAnimationLength("db_PtoL1_P")

	pDoorAction = App.TGScriptAction_Create("Actions.EffectScriptActions", "LiftDoorAction", pBridge, "doorl1", "LiftDoor")
	pSequence.AddAction(pDoorAction, pAnimAction_Stand, fTime - 1.25)

	pEvent = App.TGIntEvent_Create()		# Add event to hide character after it gets into the turbolift
	pEvent.SetEventType(App.ET_CHARACTER_ANIMATION_DONE)
	pEvent.SetDestination(pCharacter)
	pEvent.SetInt(App.CharacterClass.CS_HIDDEN)
	pSequence.AddCompletedEvent(pEvent)
	pSequence.AppendAction(App.CharacterAction_Create(pCharacter, App.CharacterAction.AT_SET_LOCATION_NAME, "DBL1M"))
	return pSequence


def MoveFromPToH(self):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/db_stand_P.NIF", "db_stand_P")
	kAM.LoadAnimation ("data/animations/DB_PtoH_P.NIF", "DB_PtoH_P")
	pCharacter = App.CharacterClass_Cast(self)
	pSequence = App.TGSequence_Create()
	pOpenEyes = Bridge.Characters.CommonAnimations.EyesOpenMouthClosed(self)
	pSequence.AddAction(pOpenEyes)
	pAnimAction_Stand = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "db_stand_P", 0, 0)
	pSequence.AddAction(pAnimAction_Stand, pOpenEyes)
	pAnimAction_Walk = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "DB_PtoH_P", 0, 0)
	pSequence.AddAction(pAnimAction_Walk, pAnimAction_Stand, 0.0)
	pEvent = App.TGIntEvent_Create()
	pEvent.SetEventType(App.ET_CHARACTER_ANIMATION_DONE)
	pEvent.SetDestination(pCharacter)
	pEvent.SetInt(App.CharacterClass.CS_STANDING)
	pSequence.AddCompletedEvent(pEvent)
	pSequence.AppendAction(App.CharacterAction_Create(pCharacter, App.CharacterAction.AT_SET_LOCATION_NAME, "DBGuestH"))
	return pSequence

def MoveFromHToT(self):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/DB_HtoT_P.NIF", "DB_HtoT_P")
	pCharacter = App.CharacterClass_Cast(self)
	pSequence = App.TGSequence_Create()
	pOpenEyes = Bridge.Characters.CommonAnimations.EyesOpenMouthClosed(self)
	pSequence.AddAction(pOpenEyes)
	pAnimAction_Walk = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "DB_HtoT_P", 0, 0)
	pSequence.AddAction(pAnimAction_Walk, pOpenEyes)
	pSequence.AppendAction(App.CharacterAction_Create(pCharacter, App.CharacterAction.AT_SET_LOCATION_NAME, "DBGuestT"))
	return pSequence

def MoveFromTToC1(self):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/DB_TtoC1_P.NIF", "DB_TtoC1_P")
	pCharacter = App.CharacterClass_Cast(self)
	pSequence = App.TGSequence_Create()
	pOpenEyes = Bridge.Characters.CommonAnimations.EyesOpenMouthClosed(self)
	pSequence.AddAction(pOpenEyes)
	pAnimAction_Walk = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "DB_TtoC1_P", 0, 0)
	pSequence.AddAction(pAnimAction_Walk, pOpenEyes)
	pSequence.AppendAction(App.CharacterAction_Create(pCharacter, App.CharacterAction.AT_SET_LOCATION_NAME, "DBGuestC1"))
	return pSequence

def MoveFromC1ToP(self):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/db_C1toP_P.nif", "db_C1toP_P")
	pSet = App.g_kSetManager.GetSet("bridge")
	pBridge = pSet.GetObject("bridge")
	pBridgeNode = pBridge.GetAnimNode()
	pCharacter = App.CharacterClass_Cast(self)
	pSequence = App.TGSequence_Create()
	pOpenEyes = Bridge.Characters.CommonAnimations.EyesOpenMouthClosed(self)
	pSequence.AddAction(pOpenEyes)
	pAnimAction_WalkFromLift = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "db_C1toP_P", 0, 0)
	pSequence.AddAction(pAnimAction_WalkFromLift, pOpenEyes)
	pEvent = App.TGIntEvent_Create()
	pEvent.SetEventType(App.ET_CHARACTER_ANIMATION_DONE)
	pEvent.SetDestination(pCharacter)
	pEvent.SetInt(App.CharacterClass.CS_SEATED)
	pSequence.AddCompletedEvent(pEvent)
	pSequence.AppendAction(App.CharacterAction_Create(pCharacter, App.CharacterAction.AT_SET_LOCATION_NAME, "DBGuest"))
	return pSequence

def TurnAtHTowardsCaptain(self):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/db_H_Turn_C_P.nif", "db_H_Turn_C_P")
	pSet = App.g_kSetManager.GetSet("bridge")
	pBridge = pSet.GetObject("bridge")
	pBridgeNode = pBridge.GetAnimNode()
	pCharacter = App.CharacterClass_Cast(self)
	pSequence = App.TGSequence_Create()
	pAction = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "db_H_Turn_C_P", 0, 0)
	pSequence.AddAction(pAction)
	return pSequence
	
def TurnAtHTowardsHelm(self):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/db_H_Turn_H_P.nif", "db_H_Turn_H_P")
	pSet = App.g_kSetManager.GetSet("bridge")
	pBridge = pSet.GetObject("bridge")
	pBridgeNode = pBridge.GetAnimNode()
	pCharacter = App.CharacterClass_Cast(self)
	pSequence = App.TGSequence_Create()
	pAction = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "db_H_Turn_H_P", 0, 0)
	pSequence.AddAction(pAction)
	return pSequence


def PHit(self):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/db_hit_p.NIF", "db_hit_p")
	pCharacter = App.CharacterClass_Cast(self)
	pSequence = App.TGSequence_Create()
	pAnimNode = pCharacter.GetAnimNode()

	# Lean
	pAction = App.TGAnimAction_Create(pAnimNode, "db_hit_p", 0, 0)
	pSequence.AddAction(pAction)

	# open eyes and close mouth
	pOpenEyes = Bridge.Characters.CommonAnimations.EyesOpenMouthClosed(self)
	pSequence.AddAction(pOpenEyes, pAction)

	return pSequence

	# lean hard left animation
def PHitHard(self):
	return PHit (self)

