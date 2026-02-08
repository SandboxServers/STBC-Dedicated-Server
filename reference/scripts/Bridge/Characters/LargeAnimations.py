# LargeAnimations.py
# This file includes all animations shared by large characters

import App
import Bridge.Characters.CommonAnimations

	# Place at T
def PlaceAtT(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/db_stand_t_l.nif", "db_stand_t_l")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pAnimNode = pCharacter.GetAnimNode()
	pAction = App.TGAnimPosition_Create(pAnimNode, "db_stand_t_l")
	pSequence.AddAction(pAction)
	return pSequence

	# Seat at T
def SeatedT(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/db_seated_t_l.nif", "db_seated_t_l")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pAnimNode = pCharacter.GetAnimNode()
	pAction = App.TGAnimAction_Create(pAnimNode, "db_seated_t_l", 0, 0, 1)
	pSequence.AddAction(pAction)
	return pSequence

	# Turn T towards captain large
def TurnAtTTowardsCaptain(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/db_face_capt_t.nif", "db_face_capt_t")
	kAM.LoadAnimation ("data/animations/db_chair_T_face_capt.nif", "db_chair_T_face_capt")
	pSet = App.g_kSetManager.GetSet("bridge")
	pBridge = pSet.GetObject("bridge")
	pBridgeNode = pBridge.GetAnimNode()
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pOpenEyes = Bridge.Characters.CommonAnimations.EyesOpenMouthClosed(pCharacter)
	pSequence.AddAction(pOpenEyes)
	pSequence.AddAction(App.TGAnimAction_Create(pCharacter.GetAnimNode(), "db_face_capt_t", 0, 0, 1), pOpenEyes)
	pSequence.AddAction(App.TGAnimAction_Create(pBridgeNode, "db_chair_T_face_capt", 0, 0), pOpenEyes)
	return pSequence

	# Turn back T from looking at captain
def TurnBackAtTFromCaptain(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/db_face_capt_t_reverse.nif", "db_face_capt_t_reverse")
	kAM.LoadAnimation ("data/animations/db_chair_T_face_capt_reverse.nif", "db_chair_T_face_capt_reverse")
	pSet = App.g_kSetManager.GetSet("bridge")
	pBridge = pSet.GetObject("bridge")
	pBridgeNode = pBridge.GetAnimNode()
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pOpenEyes = Bridge.Characters.CommonAnimations.EyesOpenMouthClosed(pCharacter)
	pSequence.AddAction(pOpenEyes)
	pSequence.AddAction(App.TGAnimAction_Create(pCharacter.GetAnimNode(), "db_face_capt_t_reverse", 0, 0, 1), pOpenEyes)
	pSequence.AddAction(App.TGAnimAction_Create(pBridgeNode, "db_chair_T_face_capt_reverse", 0, 0), pOpenEyes)
	return pSequence

	# From L1 to T
def MoveFromL1ToT(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/db_L1toT_l.nif", "db_L1toT_l")
	kAM.LoadAnimation ("data/animations/DB_sit_T_l.nif", "db_sit_T_l")
	kAM.LoadAnimation ("data/animations/db_chair_T_in.nif", "db_chair_T_in")
	kAM.LoadAnimation ("data/animations/db_door_l1.nif", "doorl1")
	pSet = App.g_kSetManager.GetSet("bridge")
	pBridge = pSet.GetObject("bridge")
	pBridgeNode = pBridge.GetAnimNode()
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pOpenEyes = Bridge.Characters.CommonAnimations.EyesOpenMouthClosed(pCharacter)
	pSequence.AddAction(pOpenEyes)
	pAnimAction_WalkFromLift = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "db_L1toT_l", 0, 0, 1)
	pSequence.AddAction(pAnimAction_WalkFromLift, pOpenEyes)
	pSequence.AddAction(App.TGAnimAction_Create(pBridgeNode, "doorl1", 0, 0), pOpenEyes, 0.125)
	pAnimAction_Sit = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "db_sit_T_l", 0, 0)
	pSequence.AddAction(pAnimAction_Sit, pAnimAction_WalkFromLift, 0.0)
	fTime = kAM.GetAnimationLength("db_sit_T_l")
	pAnimAction = App.TGAnimAction_Create(pBridgeNode, "db_chair_T_in", 0, 0)
	pSequence.AddAction(pAnimAction, pAnimAction_WalkFromLift, 0.0)
	pSequence.AppendAction(App.CharacterAction_Create(pCharacter, App.CharacterAction.AT_SET_LOCATION_NAME, "DBTactical"))
	pEvent = App.TGIntEvent_Create ()
	pEvent.SetEventType (App.ET_CHARACTER_ANIMATION_DONE)
	pEvent.SetDestination (pCharacter)
	pEvent.SetInt (App.CharacterClass.CS_SEATED)
	pSequence.AddCompletedEvent(pEvent)
	return pSequence

	# From T to L1
def MoveFromTToL1(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/db_stand_t_l.nif", "db_stand_t_l")
	kAM.LoadAnimation ("data/animations/DB_chair_T_out.nif", "DB_chair_T_out")
	kAM.LoadAnimation ("data/animations/db_TtoL1_l.nif", "db_TtoL1_l")
	kAM.LoadAnimation ("data/animations/db_door_l1.nif", "doorl1")
	pSet = App.g_kSetManager.GetSet("bridge")
	pBridge = pSet.GetObject("bridge")
	pBridgeNode = pBridge.GetAnimNode()
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pOpenEyes = Bridge.Characters.CommonAnimations.EyesOpenMouthClosed(pCharacter)
	pSequence.AddAction(pOpenEyes)
	pAnimAction_Stand = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "db_stand_t_l", 0, 0, 1)
	pSequence.AddAction(pAnimAction_Stand, pOpenEyes)
	fTime = kAM.GetAnimationLength("db_stand_t_l")
	pSequence.AddAction(App.TGAnimAction_Create(pBridgeNode, "DB_chair_T_out", 0, 0), pOpenEyes)
	pAnimAction_WalkToLift = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "db_TtoL1_l", 0, 0)
	pSequence.AddAction(pAnimAction_WalkToLift, pAnimAction_Stand, 0.0)
	fTime = fTime + kAM.GetAnimationLength("db_TtoL1_l")
	pAnimAction = App.TGAnimAction_Create(pBridgeNode, "doorl1", 0, 0)
	pSequence.AppendAction(App.CharacterAction_Create(pCharacter, App.CharacterAction.AT_SET_LOCATION_NAME, "DBL1L"))
	pEvent = App.TGIntEvent_Create ()		# Add event to hide character after it gets into the turbolift
	pEvent.SetEventType (App.ET_CHARACTER_ANIMATION_DONE)
	pEvent.SetDestination (pCharacter)
	pEvent.SetInt (App.CharacterClass.CS_HIDDEN)
	pAnimAction.AddCompletedEvent(pEvent)
	pSequence.AddAction(pAnimAction, pOpenEyes, fTime - 1.7)	
	return pSequence

	# lean left animation
def THit(pCharacter):
	#print("Hit T")
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/db_hit_t.NIF", "db_hit_t")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pAnimNode = pCharacter.GetAnimNode()

	# Lean
	pLeanAction = App.TGAnimAction_Create(pAnimNode, "db_hit_t", 0, 0)
	pSequence.AddAction(pLeanAction)

#	if (App.g_kSystemWrapper.GetRandomNumber(5) == 3):
#		if (pCharacter.GetGender() == 0):
#			pSequence.AddAction(App.TGSoundAction_Create("MaleEek"+ str(App.g_kSystemWrapper.GetRandomNumber(7)+1)))
#		else:
#			pSequence.AddAction(App.TGSoundAction_Create("FemaleEek"+ str(App.g_kSystemWrapper.GetRandomNumber(7)+1)))

	return pSequence

	# lean hard left animation
def THitHard(pCharacter):
	return THit (pCharacter)

####################################################
# E-Bridge Animations
####################################################

	# Place at T
def EBPlaceAtT(pCharacter):
#	print("Place T")
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/EB_stand_t_l.nif", "EB_stand_t_l")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pAnimNode = pCharacter.GetAnimNode()
	pAction = App.TGAnimPosition_Create(pAnimNode, "EB_stand_t_l")
	pSequence.AddAction(pAction)
	return pSequence

	# Place at L1
def EBPlaceAtL1(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/eb_L1toT_l.nif", "eb_L1toT_l")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pAnimNode = pCharacter.GetAnimNode()
	pAction = App.TGAnimPosition_Create(pAnimNode, "eb_L1toTt_l")
	pSequence.AddAction(pAction)
	return pSequence

	# Seat at T
def EBSeatedT(pCharacter):
#	print("Seated T")
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/EB_seated_t_l.nif", "EB_seated_t_l")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pAnimNode = pCharacter.GetAnimNode()
	pAction = App.TGAnimAction_Create(pAnimNode, "EB_seated_t_l", 0, 0, 1)
	pSequence.AddAction(pAction)
	return pSequence

	# Turn T towards captain large
def EBTurnAtTTowardsCaptain(pCharacter):
#	print("Turn T")
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/EB_face_capt_t.nif", "EB_face_capt_t")
	kAM.LoadAnimation ("data/animations/EB_chair_T_face_capt.nif", "EB_chair_T_face_capt")
	pSet = App.g_kSetManager.GetSet("bridge")
	pBridge = pSet.GetObject("bridge")
	pBridgeNode = pBridge.GetAnimNode()
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pOpenEyes = Bridge.Characters.CommonAnimations.EyesOpenMouthClosed(pCharacter)
	pSequence.AddAction(pOpenEyes)
	pSequence.AddAction(App.TGAnimAction_Create(pCharacter.GetAnimNode(), "EB_face_capt_t", 0, 0, 1), pOpenEyes)
	pSequence.AddAction(App.TGAnimAction_Create(pBridgeNode, "EB_chair_T_face_capt", 0, 0), pOpenEyes)
	return pSequence

	# Turn back T from looking at captain
def EBTurnBackAtTFromCaptain(pCharacter):
#	print("Turn Back T")
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/EB_face_capt_t_reverse.nif", "EB_face_capt_t_reverse")
	kAM.LoadAnimation ("data/animations/EB_chair_T_face_capt_reverse.nif", "EB_chair_T_face_capt_reverse")
	pSet = App.g_kSetManager.GetSet("bridge")
	pBridge = pSet.GetObject("bridge")
	pBridgeNode = pBridge.GetAnimNode()
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pOpenEyes = Bridge.Characters.CommonAnimations.EyesOpenMouthClosed(pCharacter)
	pSequence.AddAction(pOpenEyes)
	pSequence.AddAction(App.TGAnimAction_Create(pCharacter.GetAnimNode(), "EB_face_capt_t_reverse", 0, 0, 1), pOpenEyes)
	pSequence.AddAction(App.TGAnimAction_Create(pBridgeNode, "EB_chair_T_face_capt_reverse", 0, 0), pOpenEyes)
	return pSequence

	# From L1 to T
def EBMoveFromL1ToT(pCharacter):
#	print("Move to L1 T")
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/EB_L1toT_l.nif", "EB_L1toT_l")
	kAM.LoadAnimation ("data/animations/EB_sit_T_l.nif", "EB_sit_T_l")
	kAM.LoadAnimation ("data/animations/EB_chair_T_in.nif", "EB_chair_T_in")
	kAM.LoadAnimation ("data/animations/EB_door_l1.nif", "EB_Door_L1")
	pSet = App.g_kSetManager.GetSet("bridge")
	pBridge = pSet.GetObject("bridge")
	pBridgeNode = pBridge.GetAnimNode()
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pAnimAction_WalkFromLift = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "EB_L1toT_l", 0, 0, 1)
	pSequence.AddAction(pAnimAction_WalkFromLift)
	pSequence.AddAction(App.TGAnimAction_Create(pBridgeNode, "EB_Door_L1", 0, 0), App.TGAction_CreateNull(), 0.125)
	pAnimAction_Sit = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "EB_sit_T_l", 0, 0)
	pSequence.AddAction(pAnimAction_Sit, pAnimAction_WalkFromLift, 0.0)
	fTime = kAM.GetAnimationLength("EB_sit_T_l")
	pAnimAction = App.TGAnimAction_Create(pBridgeNode, "EB_chair_T_in", 0, 0)
	pSequence.AddAction(pAnimAction, pAnimAction_WalkFromLift)
	pSequence.AppendAction(App.CharacterAction_Create(pCharacter, App.CharacterAction.AT_SET_LOCATION_NAME, "EBTactical"))
	pEvent = App.TGIntEvent_Create ()
	pEvent.SetEventType (App.ET_CHARACTER_ANIMATION_DONE)
	pEvent.SetDestination (pCharacter)
	pEvent.SetInt (App.CharacterClass.CS_SEATED)
	pSequence.AddCompletedEvent(pEvent)
	return pSequence

	# From T to L1
def EBMoveFromTToL1(pCharacter):
#	print("Move to T")
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/EB_stand_t_l.nif", "EB_stand_t_l")
	kAM.LoadAnimation ("data/animations/EB_chair_T_out.nif", "EB_chair_T_out")
	kAM.LoadAnimation ("data/animations/EB_TtoL1_l.nif", "EB_TtoL1_l")
	kAM.LoadAnimation ("data/animations/EB_door_l1.nif", "EB_Door_L1")
	pSet = App.g_kSetManager.GetSet("bridge")
	pBridge = pSet.GetObject("bridge")
	pBridgeNode = pBridge.GetAnimNode()
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pAnimAction_Stand = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "EB_stand_t_l", 0, 0, 1)
	pSequence.AddAction(pAnimAction_Stand)
	fTime = kAM.GetAnimationLength("EB_stand_t_l")
	pSequence.AddAction(App.TGAnimAction_Create(pBridgeNode, "EB_chair_T_out", 0, 0))
	pAnimAction_WalkToLift = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "EB_TtoL1_l", 0, 0)
	pSequence.AddAction(pAnimAction_WalkToLift, pAnimAction_Stand)
	fTime = fTime + kAM.GetAnimationLength("EB_TtoL1_l")
	pAnimAction = App.TGAnimAction_Create(pBridgeNode, "EB_Door_L1", 0, 0)
	pSequence.AppendAction(App.CharacterAction_Create(pCharacter, App.CharacterAction.AT_SET_LOCATION_NAME, "EBL1L"))
	pEvent = App.TGIntEvent_Create ()		# Add event to hide character after it gets into the turbolift
	pEvent.SetEventType (App.ET_CHARACTER_ANIMATION_DONE)
	pEvent.SetDestination (pCharacter)
	pEvent.SetInt (App.CharacterClass.CS_HIDDEN)
	pAnimAction.AddCompletedEvent(pEvent)
	pSequence.AddAction(pAnimAction, App.TGAction_CreateNull(), fTime - 1.7)	
	return pSequence

	# lean left animation
def EBTHit(pCharacter):
	return None
	#print("Hit T - animation doesn't exist")
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/EB_hit_t.NIF", "EB_hit_t")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pAnimNode = pCharacter.GetAnimNode()

	# Lean
	pLeanAction = App.TGAnimAction_Create(pAnimNode, "EB_hit_t", 0, 0)
	pSequence.AddAction(pLeanAction)

	# open eyes and close mouth
	pOpenEyes = Bridge.Characters.CommonAnimations.EyesOpenMouthClosed(pCharacter)
	pSequence.AddAction(pOpenEyes)

	# Return to default.
	pAction = App.CharacterAction_Create (pCharacter, App.CharacterAction.AT_DEFAULT);
	pSequence.AddAction (pAction, pLeanAction)

#	if (App.g_kSystemWrapper.GetRandomNumber(5) == 3):
#		if (pCharacter.GetGender() == 0):
#			pSequence.AddAction(App.TGSoundAction_Create("MaleEek"+ str(App.g_kSystemWrapper.GetRandomNumber(7)+1)))
#		else:
#			pSequence.AddAction(App.TGSoundAction_Create("FemaleEek"+ str(App.g_kSystemWrapper.GetRandomNumber(7)+1)))

	return pSequence

	# lean hard left animation
def EBTHitHard(pCharacter):
	return THit (pCharacter)

# Looking at the other stations
def DBTTalkC(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/DB_T_Talk_to_C_L.NIF", "DB_T_Talk_to_C_L")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "DB_T_Talk_to_C_L", 0, 0, 1)
	return pAnimAction1

def DBTTalkE(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/DB_T_Talk_to_E_L.NIF", "DB_T_Talk_to_E_L")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "DB_T_Talk_to_E_L", 0, 0, 1)
	return pAnimAction1

def DBTTalkH(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/DB_T_Talk_to_H_L.NIF", "DB_T_Talk_to_H_L")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "DB_T_Talk_to_H_L", 0, 0, 1)
	return pAnimAction1

def DBTTalkS(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/DB_T_Talk_to_S_L.NIF", "DB_T_Talk_to_S_L")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "DB_T_Talk_to_S_L", 0, 0, 1)
	pAnimAction1.SetDuration(0.5)
	return pAnimAction1

def DBTTalkX(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/DB_T_Talk_X_L.NIF", "DB_T_Talk_X_L")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "DB_T_Talk_X_L", 0, 0, 1)
	pAnimAction1.SetDuration(0.5)
	return pAnimAction1

def DBTTalkFinC(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/DB_T_Talk_fin_C_L.NIF", "DB_T_Talk_fin_C_L")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "DB_T_Talk_fin_C_L", 0, 0, 1)
	pAnimAction1.SetDuration(0.5)
	return pAnimAction1

def DBTTalkFinE(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/DB_T_Talk_fin_E_L.NIF", "DB_T_Talk_fin_E_L")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "DB_T_Talk_fin_E_L", 0, 0, 1)
	pAnimAction1.SetDuration(0.5)
	return pAnimAction1

def DBTTalkFinH(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/DB_T_Talk_fin_H_L.NIF", "DB_T_Talk_fin_H_L")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "DB_T_Talk_fin_H_L", 0, 0, 1)
	return pAnimAction1

def DBTTalkFinS(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/DB_T_Talk_fin_S_L.NIF", "DB_T_Talk_fin_S_L")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "DB_T_Talk_fin_S_L", 0, 0, 1)
	pAnimAction1.SetDuration(0.5)
	return pAnimAction1

def DBTTalkFinX(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/DB_T_Talk_X_L_reverse.NIF", "DB_T_Talk_X_L_reverse")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "DB_T_Talk_X_L_reverse", 0, 0, 1)
	pAnimAction1.SetDuration(0.5)
	return pAnimAction1

# E-Bridge looks
def EBTTalkC(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/EB_T_Talk_to_G2_L.NIF", "EB_T_Talk_to_G2_L")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "EB_T_Talk_to_G2_L", 0, 0, 1)
	pAnimAction1.SetDuration(0.5)
	return pAnimAction1

def EBTTalkE(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/EB_T_Talk_to_G3_L.NIF", "EB_T_Talk_to_G3_L")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "EB_T_Talk_to_G3_L", 0, 0, 1)
	pAnimAction1.SetDuration(0.5)
	return pAnimAction1

def EBTTalkH(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/EB_T_Talk_to_H_L.NIF", "EB_T_Talk_to_H_L")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "EB_T_Talk_to_H_L", 0, 0, 1)
	return pAnimAction1

def EBTTalkS(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/EB_T_Talk_to_G2_L.NIF", "EB_T_Talk_to_G2_L")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "EB_T_Talk_to_G2_L", 0, 0, 1)
	pAnimAction1.SetDuration(0.5)
	return pAnimAction1

def EBTTalkFinC(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/EB_T_Talk_fin_G2_L.NIF", "EB_T_Talk_fin_G2_L")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "EB_T_Talk_fin_G2_L", 0, 0, 1)
	pAnimAction1.SetDuration(0.5)
	return pAnimAction1

def EBTTalkFinE(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/EB_T_Talk_fin_G3_L.NIF", "EB_T_Talk_fin_G3_L")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "EB_T_Talk_fin_G3_L", 0, 0, 1)
	pAnimAction1.SetDuration(0.5)
	return pAnimAction1

def EBTTalkFinH(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/EB_T_Talk_fin_H_L.NIF", "EB_T_Talk_fin_H_L")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "EB_T_Talk_fin_H_L", 0, 0, 1)
	return pAnimAction1

def EBTTalkFinS(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/EB_T_Talk_fin_G2_L.NIF", "EB_T_Talk_fin_G2_L")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "EB_T_Talk_fin_G2_L", 0, 0, 1)
	pAnimAction1.SetDuration(0.5)
	return pAnimAction1

###############################################################################
#	TLookAroundConsoleDown, TConsoleInteraction
#	
#	Tactical-specific definitions for these functions
#	
#	Args:	pCharacter		- the character to call on
#	
#	Return:	pSequence	- the created sequence
###############################################################################
def TLookAroundConsoleDown(pCharacter):
	pCharacter = App.CharacterClass_Cast(pCharacter)
	if not (pCharacter):
		return None

	# Look forward, fore right, and right
	iNumLooks = App.g_kSystemWrapper.GetRandomNumber(4)+2
	pSequence = App.TGSequence_Create()
	pLastAction = App.TGAction_CreateNull()

	for i in range (iNumLooks):
		iRandAction = App.g_kSystemWrapper.GetRandomNumber(4)

		if (iRandAction == 0):
			pNextAction = Bridge.Characters.CommonAnimations.ConsoleLookDown(pCharacter)
		elif (iRandAction == 1):
			pNextAction = Bridge.Characters.CommonAnimations.ConsoleLookDownForeLeft(pCharacter)
		elif (iRandAction == 2):
			pNextAction = Bridge.Characters.CommonAnimations.ConsoleLookDownForeRight(pCharacter)
		elif (iRandAction == 3):
			pNextAction = Bridge.Characters.CommonAnimations.ConsoleLookDownRight(pCharacter)

		pSequence.AddAction(pNextAction, pLastAction)
		pLastAction = pNextAction

	pSequence.AppendAction(App.CharacterAction_Create(pCharacter, App.CharacterAction.AT_BREATHE))

	return pSequence


def DBTConsoleInteraction(pCharacter):
	pCharacter = App.CharacterClass_Cast(pCharacter)
	if not (pCharacter):
		return None

	iNumPresses = App.g_kSystemWrapper.GetRandomNumber(6)+3
	pSequence = App.TGSequence_Create()
	pLastAction = App.TGAction_CreateNull()

	for i in range (iNumPresses):
		iRandAction = App.g_kSystemWrapper.GetRandomNumber(10)

		if (iRandAction == 0):
			pNextAction = Bridge.Characters.CommonAnimations.PushingButtons(pCharacter, "DB_T", "A")
		elif (iRandAction == 1):
			pNextAction = Bridge.Characters.CommonAnimations.PushingButtons(pCharacter, "DB_T", "B")
		elif (iRandAction == 2):
			pNextAction = Bridge.Characters.CommonAnimations.PushingButtons(pCharacter, "DB_T", "C")
		elif (iRandAction == 3):
			pNextAction = Bridge.Characters.CommonAnimations.PushingButtons(pCharacter, "DB_T", "D")
		elif (iRandAction == 4):
			pNextAction = Bridge.Characters.CommonAnimations.PushingButtons(pCharacter, "DB_T", "E")
		elif (iRandAction == 5):
			pNextAction = Bridge.Characters.CommonAnimations.PushingButtons(pCharacter, "DB_T", "F")
		elif (iRandAction == 6):
			pNextAction = Bridge.Characters.CommonAnimations.ConsoleSlide(pCharacter, "DB_T", "A")
		elif (iRandAction == 7):
			pNextAction = Bridge.Characters.CommonAnimations.ConsoleSlide(pCharacter, "DB_T", "B")
		elif (iRandAction == 8):
			pNextAction = Bridge.Characters.CommonAnimations.ConsoleSlide(pCharacter, "DB_T", "C")
		elif (iRandAction == 9):
			pNextAction = Bridge.Characters.CommonAnimations.ConsoleSlide(pCharacter, "DB_T", "D")

		pSequence.AddAction(pNextAction, pLastAction)
		pLastAction = pNextAction

	pSequence.AppendAction(App.CharacterAction_Create(pCharacter, App.CharacterAction.AT_BREATHE))

	return pSequence

def EBTConsoleInteraction(pCharacter):
	pCharacter = App.CharacterClass_Cast(pCharacter)
	if not (pCharacter):
		return None

	iNumPresses = App.g_kSystemWrapper.GetRandomNumber(6)+3
	pSequence = App.TGSequence_Create()
	pLastAction = App.TGAction_CreateNull()

	for i in range (iNumPresses):
		iRandAction = App.g_kSystemWrapper.GetRandomNumber(10)

		if (iRandAction == 0):
			pNextAction = Bridge.Characters.CommonAnimations.PushingButtons(pCharacter, "EB_T", "A")
		elif (iRandAction == 1):
			pNextAction = Bridge.Characters.CommonAnimations.PushingButtons(pCharacter, "EB_T", "B")
		elif (iRandAction == 2):
			pNextAction = Bridge.Characters.CommonAnimations.PushingButtons(pCharacter, "EB_T", "C")
		elif (iRandAction == 3):
			pNextAction = Bridge.Characters.CommonAnimations.PushingButtons(pCharacter, "EB_T", "D")
		elif (iRandAction == 4):
			pNextAction = Bridge.Characters.CommonAnimations.PushingButtons(pCharacter, "EB_T", "E")
		elif (iRandAction == 5):
			pNextAction = Bridge.Characters.CommonAnimations.PushingButtons(pCharacter, "EB_T", "F")
		elif (iRandAction == 6):
			pNextAction = Bridge.Characters.CommonAnimations.ConsoleSlide(pCharacter, "EB_T", "A")
		elif (iRandAction == 7):
			pNextAction = Bridge.Characters.CommonAnimations.ConsoleSlide(pCharacter, "EB_T", "B")
		elif (iRandAction == 8):
			pNextAction = Bridge.Characters.CommonAnimations.ConsoleSlide(pCharacter, "EB_T", "C")
		elif (iRandAction == 9):
			pNextAction = Bridge.Characters.CommonAnimations.ConsoleSlide(pCharacter, "EB_T", "D")

		pSequence.AddAction(pNextAction, pLastAction)
		pLastAction = pNextAction

	pSequence.AppendAction(App.CharacterAction_Create(pCharacter, App.CharacterAction.AT_BREATHE))

	return pSequence



