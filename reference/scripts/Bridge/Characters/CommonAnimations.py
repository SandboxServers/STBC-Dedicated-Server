# CommonAnimations.py
# This file includes all animations shared by multiple character sizes

import App

###############################################################################
#	NothingToAdd()
#	
#	The default handler for characters Communicate
#	
#	Args:	pObject	- the object that called this
#			pEvent	- the event that was generated
#	
#	Return:	none
###############################################################################
def NothingToAdd(pObject, pEvent):
	# First, see if we should work with the thing that sent the event
	pCharacter = App.CharacterClass_Cast(pObject)
	if not (pCharacter):
		# Next, try the event as a string event
		pBridge = App.g_kSetManager.GetSet("bridge")
		pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
		kString = pDatabase.GetString("Communicate")
		App.g_kLocalizationManager.Unload(pDatabase)
		pEvent.GetString(kString)
		pCharacter = App.CharacterClass_GetObject(pBridge, kString.GetCString())
		if not (pCharacter):
			# Try in Engineering...
			pBridge = App.g_kSetManager.GetSet("Engineering")
			pCharacter = App.CharacterClass_GetObject(pBridge, kString.GetCString())

		if not (pCharacter):
			# No character of that name, give up
			pObject.CallNextHandler(pEvent)
			return

	# Have the character say "Nothing to add"
	pCharacter.SpeakLine(pCharacter.GetDatabase(), pCharacter.GetCharacterName() + "NothingToAdd")


	
	# Walk camera to captains chair on the D
def WalkCameraToCaptOnD(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation("data/animations/db_camera_walk_capt.nif", "WalkCameraToCaptD")
	kAM.LoadAnimation("data/animations/DB_Door_L1.nif", "DB_Door_L1")

	pSequence = App.TGSequence_Create()

	# Camera move.
	pCamera = App.CameraObjectClass_Cast(pCharacter)
	pAnimNode = pCamera.GetAnimNode()
	pAnimNode.UseAnimationPosition("WalkCameraToCaptD")
	pAnimAction = App.TGAnimAction_Create(pAnimNode, "WalkCameraToCaptD", 1, 0, 0, 0)
	pSequence.AddAction(pAnimAction)

	# Open L1 door.	
	pSet = App.g_kSetManager.GetSet("bridge")
	pBridge = pSet.GetObject("bridge")
	pDoorAction = App.TGScriptAction_Create("Actions.EffectScriptActions", "LiftDoorAction", pBridge, "DB_Door_L1", "LiftDoor")
	pSequence.AddAction (pDoorAction)

	pEvent = App.TGEvent_Create()
	pEvent.SetDestination(pCamera)
	pEvent.SetEventType(App.ET_CAMERA_ANIMATION_DONE)
	
	pSequence.AddCompletedEvent (pEvent)

	return pSequence

def DBCaptainStand(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation("data/animations/DB_Camera_Stand_Up.nif", "DBCameraStandUp")

	pSequence = App.TGSequence_Create()

	# Camera move.
	pCamera = App.CameraObjectClass_Cast(pCharacter)
	pAnimNode = pCamera.GetAnimNode()
	pAnimAction = App.TGAnimAction_Create(pAnimNode, "DBCameraStandUp", 1, 0, 0, 0)
	pSequence.AddAction(pAnimAction)

	pEvent = App.TGEvent_Create()
	pEvent.SetDestination(pCamera)
	pEvent.SetEventType(App.ET_CAMERA_ANIMATION_DONE)
	
	pSequence.AddCompletedEvent (pEvent)

	return pSequence

def DBCaptainSit(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation("data/animations/DB_Camera_Sit_Down.nif", "DBCameraSitDown")

	pSequence = App.TGSequence_Create()

	# Camera move.
	pCamera = App.CameraObjectClass_Cast(pCharacter)
	pAnimNode = pCamera.GetAnimNode()
	pAnimAction = App.TGAnimAction_Create(pAnimNode, "DBCameraSitDown", 1, 0, 0, 0)
	pSequence.AddAction(pAnimAction)

	pEvent = App.TGEvent_Create()
	pEvent.SetDestination(pCamera)
	pEvent.SetEventType(App.ET_CAMERA_ANIMATION_DONE)
	
	pSequence.AddCompletedEvent (pEvent)

	return pSequence

	# Walk camera to captains chair on the E
def WalkCameraToCaptOnE(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation("data/animations/eb_camera_capt_walk.nif", "WalkCameraToCaptE")
	kAM.LoadAnimation("data/animations/EB_Door_L1.nif", "EB_Door_L1")

	pSequence = App.TGSequence_Create()

	# Camera move.
	pCamera = App.CameraObjectClass_Cast (pCharacter)
	pAnimNode = pCamera.GetAnimNode()
	pAnimNode.UseAnimationPosition("WalkCameraToCaptE")
	pAnimAction = App.TGAnimAction_Create(pAnimNode, "WalkCameraToCaptE", 1, 0, 0, 0)
	pSequence.AddAction(pAnimAction)

	# Open L1 door.	
	pSet = App.g_kSetManager.GetSet("bridge")
	pBridge = pSet.GetObject("bridge")
	pDoorAction = App.TGScriptAction_Create("Actions.EffectScriptActions", "LiftDoorAction", pBridge, "EB_Door_L1", "LiftDoor")
	pSequence.AddAction (pDoorAction)

	pEvent = App.TGEvent_Create()
	pEvent.SetDestination(pCamera)
	pEvent.SetEventType(App.ET_CAMERA_ANIMATION_DONE)
	
	pSequence.AddCompletedEvent (pEvent)

	return pSequence

###############################################################################
#	SetPosition()
#	
#	Sets the position of any character
#	
#	Args:	pCharacter	- character to set up
#	
#	Return:	pSequence
###############################################################################
def SetPosition(pCharacter):
	kAM = App.g_kAnimationManager

	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pAnimNode = pCharacter.GetAnimNode()

	# D-Bridge Locations
	if (pCharacter.GetLocation() == "DBHelm"):
		kAM.LoadAnimation ("data/animations/db_stand_h_m.nif", "db_stand_h_m")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "db_stand_h_m"))
	if (pCharacter.GetLocation() == "DBTactical"):
		kAM.LoadAnimation ("data/animations/db_stand_t_l.nif", "db_stand_t_l")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "db_stand_t_l"))
	if (pCharacter.GetLocation() == "DBCommander"):
		kAM.LoadAnimation ("data/animations/db_stand_c_m.nif", "db_stand_c_m")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "db_stand_c_m"))
	if (pCharacter.GetLocation() == "DBCommander1"):
		kAM.LoadAnimation ("data/animations/DB_C1toC_M.nif", "DB_C1toC_M")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "DB_C1toC_M"))
	if (pCharacter.GetLocation() == "DBScience"):
		kAM.LoadAnimation ("data/animations/db_StoL1_S.nif", "db_StoL1_S")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "db_StoL1_S"))
	if (pCharacter.GetLocation() == "DBEngineer"):
		kAM.LoadAnimation ("data/animations/db_EtoL1_s.nif", "db_EtoL1_s")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "db_EtoL1_s"))
	if (pCharacter.GetLocation() == "DBGuest"):
		kAM.LoadAnimation ("data/animations/Seated_P.nif", "Seated_P")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "Seated_P"))
	if (pCharacter.GetLocation() == "DBL1S"):
		kAM.LoadAnimation ("data/animations/DB_L1toE_S.nif", "DB_L1toE_S")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "DB_L1toE_S"))
		pCharacter.SetHidden(1)
	if (pCharacter.GetLocation() == "DBL1M"):
		kAM.LoadAnimation ("data/animations/DB_L1toG1_M.nif", "DB_L1toG1_M")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "DB_L1toG1_M"))
		pCharacter.SetHidden(1)
	if (pCharacter.GetLocation() == "DBL1L"):
		kAM.LoadAnimation ("data/animations/DB_L1toT_L.nif", "DB_L1toT_L")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "DB_L1toT_L"))
		pCharacter.SetHidden(1)

	# E-Bridge Locations
	if (pCharacter.GetLocation() == "EBHelm"):
		kAM.LoadAnimation ("data/animations/EB_stand_h_m.nif", "EB_stand_h_m")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "EB_stand_h_m"))
	if (pCharacter.GetLocation() == "EBTactical"):
		kAM.LoadAnimation ("data/animations/EB_stand_t_l.nif", "EB_stand_t_l")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "EB_stand_t_l"))
	if (pCharacter.GetLocation() == "EBCommander"):
		kAM.LoadAnimation ("data/animations/EB_stand_c_m.nif", "EB_stand_c_m")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "EB_stand_c_m"))
	if (pCharacter.GetLocation() == "EBCommander1"):
		kAM.LoadAnimation ("data/animations/EB_C1toC_M.nif", "EB_C1toC_M")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "EB_C1toC_M"))
	if (pCharacter.GetLocation() == "EBScience"):
		kAM.LoadAnimation ("data/animations/EB_stand_s_s.nif", "EB_stand_s_s")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "EB_stand_s_s"))
	if (pCharacter.GetLocation() == "EBEngineer"):
		kAM.LoadAnimation ("data/animations/EB_stand_e_s.nif", "EB_stand_e_s")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "EB_stand_e_s"))
	if (pCharacter.GetLocation() == "EBGuest"):
		kAM.LoadAnimation ("data/animations/EB_stand_X_m.nif", "EB_stand_X_m")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "EB_stand_X_m"))
	if (pCharacter.GetLocation() == "EBL1S"):
		kAM.LoadAnimation ("data/animations/EB_L1toE_S.nif", "EB_L1toE_S")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "EB_L1toE_S"))
		pCharacter.SetHidden(1)
	if (pCharacter.GetLocation() == "EBL1M"):
		kAM.LoadAnimation ("data/animations/EB_L1toH_M.nif", "EB_L1toH_M")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "EB_L1toH_M"))
		pCharacter.SetHidden(1)
	if (pCharacter.GetLocation() == "EBL1L"):
		kAM.LoadAnimation ("data/animations/EB_L1toT_L.nif", "EB_L1toT_L")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "EB_L1toT_L"))
		pCharacter.SetHidden(1)
	if (pCharacter.GetLocation() == "EBL2M"):
		kAM.LoadAnimation ("data/animations/EB_L2toG2_M.nif", "EB_L2toG2_M")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "EB_L2toG2_M"))
		pCharacter.SetHidden(1)
	if (pCharacter.GetLocation() == "EBG1M"):
		kAM.LoadAnimation ("data/animations/EB_G1toL2_M.nif", "EB_G1toL2_M")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "EB_G1toL2_M"))
	if (pCharacter.GetLocation() == "EBG2M"):
		kAM.LoadAnimation ("data/animations/EB_G2toL2_M.nif", "EB_G2toL2_M")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "EB_G2toL2_M"))
	if (pCharacter.GetLocation() == "EBG3M"):
		kAM.LoadAnimation ("data/animations/EB_G32toL1_M.nif", "EB_G3toL1_M")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "EB_G3toL1_M"))


	# Partial Set Locations
	if (pCharacter.GetLocation() == "CardassianSeated"):
		kAM.LoadAnimation ("data/animations/CardassianSeated01.NIF", "CardassianSeated01")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "CardassianSeated01"))
	if (pCharacter.GetLocation() == "CardassianStationSeated"):
		kAM.LoadAnimation ("data/animations/CardStationSeated01.NIF", "CardStationSeated01")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "CardStationSeated01"))
	if (pCharacter.GetLocation() == "FederationOutpostSeated"):
		kAM.LoadAnimation ("data/animations/FedOutpostSeated01.NIF", "FederationOutpostSeated01")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "FederationOutpostSeated01"))
	if (pCharacter.GetLocation() == "FederationOutpostSeated2"):
		kAM.LoadAnimation ("data/animations/FedOutpostSeated02.NIF", "FederationOutpostSeated02")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "FederationOutpostSeated02"))
	if (pCharacter.GetLocation() == "FederationOutpostSeated3"):
		kAM.LoadAnimation ("data/animations/FedOutpostSeated03.NIF", "FederationOutpostSeated03")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "FederationOutpostSeated03"))
	if (pCharacter.GetLocation() == "FerengiSeated"):
		kAM.LoadAnimation ("data/animations/FerengiSeated01.NIF", "FerengiSeated01")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "FerengiSeated01"))
	if (pCharacter.GetLocation() == "GalaxyEngSeated"):
		kAM.LoadAnimation ("data/animations/GalaxyEngSeated01.NIF", "GalaxyEngSeated01")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "GalaxyEngSeated01"))
	if (pCharacter.GetLocation() == "GalaxySeated"):
		kAM.LoadAnimation ("data/animations/GalaxySeated01.NIF", "GalaxySeated01")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "GalaxySeated01"))
	if (pCharacter.GetLocation() == "KessokSeated"):
		kAM.LoadAnimation ("data/animations/KessokSeated01.NIF", "KessokSeated01")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "KessokSeated01"))
	if (pCharacter.GetLocation() == "KlingonSeated"):
		kAM.LoadAnimation ("data/animations/KlingonSeated01.NIF", "KlingonSeated01")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "KlingonSeated01"))
	if (pCharacter.GetLocation() == "MiscEngSeated"):
		kAM.LoadAnimation ("data/animations/MiscEng01.NIF", "MiscEngSeated01")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "MiscEngSeated01"))
	if (pCharacter.GetLocation() == "MiscEngSeated2"):
		kAM.LoadAnimation ("data/animations/MiscEng02.NIF", "MiscEngSeated02")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "MiscEngSeated02"))
	if (pCharacter.GetLocation() == "RomulanSeated"):
		kAM.LoadAnimation ("data/animations/RomulanSeated01.NIF", "RomulanSeated01")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "RomulanSeated01"))
	if (pCharacter.GetLocation() == "ShuttleSeated"):
		kAM.LoadAnimation ("data/animations/ShuttleSeated01.NIF", "ShuttleSeated01")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "ShuttleSeated01"))
	if (pCharacter.GetLocation() == "ShuttleSeated2"):
		kAM.LoadAnimation ("data/animations/ShuttleSeated02.NIF", "ShuttleSeated02")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "ShuttleSeated02"))
	if (pCharacter.GetLocation() == "SovereignEngSeated"):
		kAM.LoadAnimation ("data/animations/SovereignEngSeated01.NIF", "SovereignEngSeated01")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "SovereignEngSeated01"))
	if (pCharacter.GetLocation() == "SovereignSeated"):
		kAM.LoadAnimation ("data/animations/SovereignSeated01.NIF", "SovereignSeated01")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "SovereignSeated01"))
	if (pCharacter.GetLocation() == "StarbaseSeated"):
		kAM.LoadAnimation ("data/animations/StarbaseSeated01.NIF", "StarbaseSeated01")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "StarbaseSeated01"))
	if (pCharacter.GetLocation() == "StarbaseSeated2"):
		kAM.LoadAnimation ("data/animations/StarbaseSeated02.NIF", "StarbaseSeated02")
		pSequence.AppendAction(App.TGAnimPosition_Create(pAnimNode, "StarbaseSeated02"))

	return pSequence

	# open eyes and close mouth
def EyesOpenMouthClosed(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/eyes_open_mouth_close.nif", "eyes_open_mouth_close")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimNode = pCharacter.GetAnimNode()
	pAnimAction = App.TGAnimAction_Create(pAnimNode, "eyes_open_mouth_close", 0, 0, 0, 0)
	pAnimAction.SetDuration(0.1)
	return pAnimAction

def Twitch(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/twitch.NIF", "twitch")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pAnimNode = pCharacter.GetAnimNode()
	pAction = App.TGAnimAction_Create(pAnimNode, "twitch", 0, 0)
	pSequence.AddAction(pAction)
	return pSequence

	# default standing animation
def Standing(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/standing.NIF", "standing")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pAnimNode = pCharacter.GetAnimNode()
	pAction = App.TGAnimAction_Create(pAnimNode, "standing", 0, 0)
	pSequence.AddAction(pAction)
	return pSequence

def StandingConsole(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/standing_console.NIF", "standing_console")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pAnimNode = pCharacter.GetAnimNode()
	pOpenEyes = EyesOpenMouthClosed(pCharacter)
	pSequence.AddAction(pOpenEyes)
	pAction = App.TGAnimAction_Create(pAnimNode, "standing_console", 0, 0)
	pSequence.AddAction(pAction, pOpenEyes)
	return pSequence

def SeatedS(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/seated_S.nif", "seated_S")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pAnimNode = pCharacter.GetAnimNode()
	pAction = App.TGAnimAction_Create(pAnimNode, "seated_S", 0, 0)
	pSequence.AddAction(pAction)
	return pSequence

def SeatedM(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/seated_M.nif", "seated_M")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pAnimNode = pCharacter.GetAnimNode()
	pAction = App.TGAnimAction_Create(pAnimNode, "seated_M", 0, 0)
	pSequence.AddAction(pAction)
	return pSequence

def SeatedL(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/seated_L.nif", "seated_L")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pAnimNode = pCharacter.GetAnimNode()
	pAction = App.TGAnimAction_Create(pAnimNode, "seated_L", 0, 0)
	pSequence.AddAction(pAction)
	return pSequence

def BreathingTurned(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/breathing.NIF", "breathing")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pAnimNode = pCharacter.GetAnimNode()
	pOpenEyes = EyesOpenMouthClosed(pCharacter)
	pSequence.AddAction(pOpenEyes)
	pAction = App.TGAnimAction_Create(pAnimNode, "breathing", 0, 0)
	pSequence.AddAction(pAction, pOpenEyes)
	return pSequence

	# Nodding
def Nod(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/nod.NIF", "nod")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pOpenEyes = EyesOpenMouthClosed(pCharacter)
	pSequence.AddAction(pOpenEyes)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "nod", 0, 0)
	pSequence.AddAction(pAnimAction1, pOpenEyes)
	return pSequence

def TiltHeadLeft(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/tilt_head_left.NIF", "tilt_head_left")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "tilt_head_left", 0, 0)
	pSequence.AddAction(pAnimAction1)
	return pSequence

def TiltHeadRight(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/tilt_head_right.NIF", "tilt_head_right")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "tilt_head_right", 0, 0)
	pSequence.AddAction(pAnimAction1)
	return pSequence

	# Clapping
def Clapping(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/clapping.NIF", "clapping")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pOpenEyes = EyesOpenMouthClosed(pCharacter)
	pSequence.AddAction(pOpenEyes)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "clapping", 0, 0)
	pSequence.AddAction(pAnimAction1, pOpenEyes)
	return pSequence

	# At Ease
def AtEase(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/at_ease.NIF", "at_ease")
	kAM.LoadAnimation ("data/animations/_standing_to_at_ease.NIF", "standing_to_at_ease")
	kAM.LoadAnimation ("data/animations/_at_ease_to_standing.NIF", "at_ease_to_standing")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pOpenEyes = EyesOpenMouthClosed(pCharacter)
	pSequence.AddAction(pOpenEyes)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "standing_to_at_ease", 0, 0)
	pSequence.AddAction(pAnimAction1, pOpenEyes)
	pAnimAction2 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "at_ease", 0, 0)
	pSequence.AddAction(pAnimAction2, pAnimAction1)
	pAnimAction3 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "at_ease_to_standing", 0, 0)
	pSequence.AddAction(pAnimAction3, pAnimAction2)
	return pSequence

	# Point left small
def PointLeft(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/pointing_left.NIF", "pointing_left")			
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pOpenEyes = EyesOpenMouthClosed(pCharacter)
	pSequence.AddAction(pOpenEyes)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "pointing_left", 0, 0)
	pSequence.AddAction(pAnimAction1, pOpenEyes)
	return pSequence
	
	# Point right small
def PointRight(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/pointing_right.NIF", "pointing_right")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pOpenEyes = EyesOpenMouthClosed(pCharacter)
	pSequence.AddAction(pOpenEyes)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "pointing_right", 0, 0)
	pSequence.AddAction(pAnimAction1, pOpenEyes)
	return pSequence
	
	# WipingBrow left small
def WipingBrowLeft(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/Wiping_Brow_left.NIF", "Wiping_Brow_left")			
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pOpenEyes = EyesOpenMouthClosed(pCharacter)
	pSequence.AddAction(pOpenEyes)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "Wiping_Brow_left", 0, 0)
	pSequence.AddAction(pAnimAction1, pOpenEyes)
	return pSequence
	
	# WipingBrow right small
def WipingBrowRight(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/Wiping_Brow_right.NIF", "Wiping_Brow_right")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pOpenEyes = EyesOpenMouthClosed(pCharacter)
	pSequence.AddAction(pOpenEyes)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "Wiping_Brow_right", 0, 0)
	pSequence.AddAction(pAnimAction1, pOpenEyes)
	return pSequence
	
def LookLeft(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/looking_left.NIF", "looking_left")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pOpenEyes = EyesOpenMouthClosed(pCharacter)
	pSequence.AddAction(pOpenEyes)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "looking_left", 0, 0)
	pSequence.AddAction(pAnimAction1, pOpenEyes)
	return pSequence

def LookRight(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/looking_right.NIF", "looking_right")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pOpenEyes = EyesOpenMouthClosed(pCharacter)
	pSequence.AddAction(pOpenEyes)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "looking_right", 0, 0)
	pSequence.AddAction(pAnimAction1, pOpenEyes)
	return pSequence

def LookUp(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/looking_up.NIF", "looking_up")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "looking_up", 0, 0)
	pSequence.AddAction(pAnimAction1)
	return pSequence

def LookDown(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/looking_down.NIF", "looking_down")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pOpenEyes = EyesOpenMouthClosed(pCharacter)
	pSequence.AddAction(pOpenEyes)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "looking_down", 0, 0)
	pSequence.AddAction(pAnimAction1, pOpenEyes)
	return pSequence

def HitCommunicator(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/hitting_communicator.NIF", "hitting_communicator")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "hitting_communicator", 0, 0)
	pSequence.AddAction(pAnimAction1)
	return pSequence

def Yawn(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/Yawn_M.NIF", "Yawn")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "Yawn", 0, 0)
	pSequence.AddAction(pAnimAction1)
	return pSequence

def Sigh(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/Sigh_M.NIF", "Sigh")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "Sigh", 0, 0)
	pSequence.AddAction(pAnimAction1)
	return pSequence

def Stretch(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/Stretch_M.NIF", "Stretch")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "Stretch", 0, 0)
	pSequence.AddAction(pAnimAction1)
	return pSequence

def Shrug_Right(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/Shrug_Right_M.NIF", "Shrug_Right")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "Shrug_Right", 0, 0)
	pAnimAction1.SetDuration(1.0)
	pSequence.AddAction(pAnimAction1)
	return pSequence

def Neck_Rub(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/Neck_Rub_M.NIF", "Neck_Rub")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "Neck_Rub", 0, 0)
	pSequence.AddAction(pAnimAction1)
	return pSequence

def Laugh(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/Laugh_M.NIF", "Laugh")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "Laugh", 0, 0)
	pSequence.AddAction(pAnimAction1)
	return pSequence

def Lean(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/Lean_M.NIF", "Lean")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "Lean", 0, 0)
	pSequence.AddAction(pAnimAction1)
	return pSequence

def Head_Scratch(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/Head_Scratch_M.NIF", "Head_Scratch")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "Head_Scratch", 0, 0)
	pSequence.AddAction(pAnimAction1)
	return pSequence

def Head_Nod(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/Head_Nod_M.NIF", "Head_Nod")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "Head_Nod", 0, 0)
	pSequence.AddAction(pAnimAction1)
	return pSequence

def Hair_Wipe(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/Hair_Wipe_M.NIF", "Hair_Wipe")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "Hair_Wipe", 0, 0)
	pSequence.AddAction(pAnimAction1)
	return pSequence

def ConsoleLookDown(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/Console_Look_Down.NIF", "console_down")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "console_down", 0, 0)
	pAnimAction1.SetDuration(0.5)
	return pAnimAction1

def ConsoleSlide(pCharacter, pcLocation, pcAnim):
	kAM = App.g_kAnimationManager
	pcAnimName = pcLocation + "_console_slide_" + pcAnim
	kAM.LoadAnimation ("data/animations/" + pcAnimName, pcAnimName)
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), pcAnimName, 0, 0)
	return pAnimAction1

def PushingButtons(pCharacter, pcLocation, pcAnim):
	kAM = App.g_kAnimationManager
	pcAnimName = pcLocation + "_pushing_buttons_" + pcAnim
	kAM.LoadAnimation ("data/animations/" + pcAnimName, pcAnimName)
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), pcAnimName, 0, 0)
	return pAnimAction1

def WallSlides(pCharacter):
	iNumLooks = App.g_kSystemWrapper.GetRandomNumber(3)+1
	pSequence = App.TGSequence_Create()
	pLastAction = App.TGAction_CreateNull()

	for i in range (iNumLooks):
		iRandAction = App.g_kSystemWrapper.GetRandomNumber(2)

		if (iRandAction == 0):
			pNextAction = WallSlideLeft(pCharacter)
		elif (iRandAction == 1):
			pNextAction = WallSlideRight(pCharacter)

		pSequence.AddAction(pNextAction, pLastAction)
		pLastAction = pNextAction

	return pSequence
def WallSlideLeft(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/Wall_Slide_Left.NIF", "Wall_slide_left")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "Wall_slide_left", 0, 0)
	return pAnimAction1

def WallSlideRight(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/Wall_Slide_Right.NIF", "Wall_slide_right")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "Wall_slide_right", 0, 0)
	return pAnimAction1

def WallButtonPresses(pCharacter):
	iNumLooks = App.g_kSystemWrapper.GetRandomNumber(3)+2
	pSequence = App.TGSequence_Create()
	pLastAction = App.TGAction_CreateNull()

	for i in range (iNumLooks):
		iRandAction = App.g_kSystemWrapper.GetRandomNumber(4)

		if (iRandAction == 0):
			pNextAction = WallPressLowLeft(pCharacter)
		elif (iRandAction == 1):
			pNextAction = WallPressLowRight(pCharacter)
		elif (iRandAction == 2):
			pNextAction = WallPressLeft(pCharacter)
		elif (iRandAction == 3):
			pNextAction = WallPressRight(pCharacter)

		pSequence.AddAction(pNextAction, pLastAction)
		pLastAction = pNextAction

	return pSequence

def WallPressLowLeft(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/Wall_Press_Left_Low.NIF", "Wall_Press_Low_left")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "Wall_Press_Low_left", 0, 0)
	pAnimAction1.SetDuration((App.g_kSystemWrapper.GetRandomNumber(30)+1.0)/10.0 + 0.5)
	return pAnimAction1

def WallPressLowRight(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/Wall_Press_Right_Low.NIF", "Wall_Press_Low_right")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "Wall_Press_Low_right", 0, 0)
	pAnimAction1.SetDuration((App.g_kSystemWrapper.GetRandomNumber(30)+1.0)/10.0 + 0.5)
	return pAnimAction1

def WallPressLeft(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/Wall_Press_Left.NIF", "Wall_Press_left")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "Wall_Press_left", 0, 0)
	pAnimAction1.SetDuration((App.g_kSystemWrapper.GetRandomNumber(30)+1.0)/10.0 + 0.5)
	return pAnimAction1

def WallPressRight(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/Wall_Press_Right.NIF", "Wall_Press_right")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "Wall_Press_right", 0, 0)
	pAnimAction1.SetDuration((App.g_kSystemWrapper.GetRandomNumber(30)+1.0)/10.0 + 0.5)
	return pAnimAction1

def ConsoleLookDownForeLeft(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/Console_Look_Down_Fore_Left.NIF", "console_down_fore_left")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "console_down_fore_left", 0, 0)
	pAnimAction1.SetDuration((App.g_kSystemWrapper.GetRandomNumber(30)+1.0)/10.0 + 0.5)
	return pAnimAction1

def ConsoleLookDownForeRight(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/Console_Look_Down_Fore_Right.NIF", "console_down_fore_right")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "console_down_fore_right", 0, 0)
	pAnimAction1.SetDuration((App.g_kSystemWrapper.GetRandomNumber(30)+1.0)/10.0 + 0.5)
	return pAnimAction1

def ConsoleLookDownLeft(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/Console_Look_Down_Left.NIF", "console_down_left")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "console_down_left", 0, 0)
	pAnimAction1.SetDuration((App.g_kSystemWrapper.GetRandomNumber(30)+1.0)/10.0 + 0.5)
	return pAnimAction1

def ConsoleLookDownRight(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/Console_Look_Down_Right.NIF", "console_down_right")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "console_down_right", 0, 0)
	pAnimAction1.SetDuration((App.g_kSystemWrapper.GetRandomNumber(30)+1.0)/10.0 + 0.5)
	return pAnimAction1

def ConsoleLookUp(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/Console_Look_Up.NIF", "console_up")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "console_up", 0, 0)
	pAnimAction1.SetDuration((App.g_kSystemWrapper.GetRandomNumber(30)+1.0)/10.0 + 0.5)
	return pAnimAction1

def ConsoleLookUpForeLeft(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/Console_Look_Up_Fore_Left.NIF", "console_up_fore_left")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "console_up_fore_left", 0, 0)
	pAnimAction1.SetDuration((App.g_kSystemWrapper.GetRandomNumber(30)+1.0)/10.0 + 0.5)
	return pAnimAction1

def ConsoleLookUpForeRight(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/Console_Look_Up_Fore_Right.NIF", "console_up_fore_right")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "console_up_fore_right", 0, 0)
	pAnimAction1.SetDuration((App.g_kSystemWrapper.GetRandomNumber(30)+1.0)/10.0 + 0.5)
	return pAnimAction1

def ConsoleLookUpLeft(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/Console_Look_Up_Left.NIF", "console_up_left")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "console_up_left", 0, 0)
	pAnimAction1.SetDuration((App.g_kSystemWrapper.GetRandomNumber(30)+1.0)/10.0 + 0.5)
	return pAnimAction1

def ConsoleLookUpRight(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/Console_Look_Up_Right.NIF", "console_up_right")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "console_up_right", 0, 0)
	pAnimAction1.SetDuration((App.g_kSystemWrapper.GetRandomNumber(30)+1.0)/10.0 + 0.5)
	return pAnimAction1

def LookAroundConsoleDown(pCharacter):
	iNumLooks = App.g_kSystemWrapper.GetRandomNumber(4)+2
	pSequence = App.TGSequence_Create()
	pLastAction = App.TGAction_CreateNull()

	for i in range (iNumLooks):
		iRandAction = App.g_kSystemWrapper.GetRandomNumber(5)

		if (iRandAction == 0):
			pNextAction = ConsoleLookDown(pCharacter)
		elif (iRandAction == 1):
			pNextAction = ConsoleLookDownForeLeft(pCharacter)
		elif (iRandAction == 2):
			pNextAction = ConsoleLookDownForeRight(pCharacter)
		elif (iRandAction == 3):
			pNextAction = ConsoleLookDownLeft(pCharacter)
		elif (iRandAction == 4):
			pNextAction = ConsoleLookDownRight(pCharacter)

		pSequence.AddAction(pNextAction, pLastAction)
		pLastAction = pNextAction

	return pSequence

def LookAroundConsoleUp(pCharacter):
	iNumLooks = App.g_kSystemWrapper.GetRandomNumber(2)+2
	pSequence = App.TGSequence_Create()
	pLastAction = App.TGAction_CreateNull()

	for i in range (iNumLooks):
		iRandAction = App.g_kSystemWrapper.GetRandomNumber(5)

		if (iRandAction == 0):
			pNextAction = ConsoleLookUp(pCharacter)
		elif (iRandAction == 1):
			pNextAction = ConsoleLookUpForeLeft(pCharacter)
		elif (iRandAction == 2):
			pNextAction = ConsoleLookUpForeRight(pCharacter)
		elif (iRandAction == 3):
			pNextAction = ConsoleLookUpLeft(pCharacter)
		elif (iRandAction == 4):
			pNextAction = ConsoleLookUpRight(pCharacter)

		pSequence.AddAction(pNextAction, pLastAction)
		pLastAction = pNextAction

	return pSequence

def LookAroundConsole(pCharacter):
	iNumLooks = App.g_kSystemWrapper.GetRandomNumber(4)+2
	pSequence = App.TGSequence_Create()
	pLastAction = App.TGAction_CreateNull()

	for i in range (iNumLooks):
		iRandAction = App.g_kSystemWrapper.GetRandomNumber(10)

		if (iRandAction == 0):
			pNextAction = ConsoleLookDown(pCharacter)
		elif (iRandAction == 1):
			pNextAction = ConsoleLookDownForeLeft(pCharacter)
		elif (iRandAction == 2):
			pNextAction = ConsoleLookDownForeRight(pCharacter)
		elif (iRandAction == 3):
			pNextAction = ConsoleLookDownLeft(pCharacter)
		elif (iRandAction == 4):
			pNextAction = ConsoleLookDownRight(pCharacter)
		elif (iRandAction == 5):
			pNextAction = ConsoleLookUp(pCharacter)
		elif (iRandAction == 6):
			pNextAction = ConsoleLookUpForeLeft(pCharacter)
		elif (iRandAction == 7):
			pNextAction = ConsoleLookUpForeRight(pCharacter)
		elif (iRandAction == 8):
			pNextAction = ConsoleLookUpLeft(pCharacter)
		elif (iRandAction == 9):
			pNextAction = ConsoleLookUpRight(pCharacter)
		else:
			return pSequence

		pSequence.AddAction(pNextAction, pLastAction)
		pLastAction = pNextAction

	return pSequence

def Blast(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation("data/animations/EB_G2_Hit_Hard_Flat_Walk_M.NIF", "blast_away")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "blast_away", 0, 0)

	pSequence = App.TGSequence_Create()
	pSequence.AddAction(pAnimAction1)

	return pSequence

def Blast2(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation("data/Animations/EB_G3_Hit_Hard_Flat_Walk_M.NIF", "blast_away2")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pAnimAction1 = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "blast_away2", 0, 0)
 
	pSequence = App.TGSequence_Create()
	pSequence.AddAction(pAnimAction1)

	return pSequence

	# hit left animation
def HitStanding(pCharacter):
	kAM = App.g_kAnimationManager
	r = App.g_kSystemWrapper.GetRandomNumber (2)

	if (r == 0):
		kAM.LoadAnimation ("data/animations/_lean_a.NIF", "lean_a")
	else:
		kAM.LoadAnimation ("data/animations/_lean_b.NIF", "lean_b")

	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pAnimNode = pCharacter.GetAnimNode()

	# Lean
	if (r == 0):
		pLeanAction = App.TGAnimAction_Create(pAnimNode, "lean_a", 0, 0)
	else:
		pLeanAction = App.TGAnimAction_Create(pAnimNode, "lean_b", 0, 0)

	pSequence.AddAction(pLeanAction)

	# open eyes and close mouth
	pOpenEyes = EyesOpenMouthClosed(pCharacter)
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

	# hard lean left animation
def HitHardStanding(pCharacter):
	kAM = App.g_kAnimationManager
	r = App.g_kSystemWrapper.GetRandomNumber (2)

	if (r == 0):
		kAM.LoadAnimation ("data/animations/_hit_hard_a.NIF", "hit_hard_a")
	else:
		kAM.LoadAnimation ("data/animations/_hit_hard_b.NIF", "hit_hard_b")

	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pAnimNode = pCharacter.GetAnimNode()

	# Lean
	if (r == 0):
		pLeanAction = App.TGAnimAction_Create(pAnimNode, "hit_hard_a", 0, 0)
	else:
		pLeanAction = App.TGAnimAction_Create(pAnimNode, "hit_hard_b", 0, 0)
	pSequence.AddAction(pLeanAction)

	# open eyes and close mouth
	pOpenEyes = EyesOpenMouthClosed(pCharacter)
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

	# lean left animation
def ReactLeft(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/react_console_left.NIF", "react_console_left")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pAnimNode = pCharacter.GetAnimNode()

	# Lean
	pLeanAction = App.TGAnimAction_Create(pAnimNode, "react_console_left", 0, 0)
	pSequence.AddAction(pLeanAction)

	# open eyes and close mouth
	pOpenEyes = EyesOpenMouthClosed(pCharacter)
	pSequence.AddAction(pOpenEyes)

	# Return to default.
	pAction = App.CharacterAction_Create (pCharacter, App.CharacterAction.AT_DEFAULT);
	pSequence.AddAction (pAction, pLeanAction)

#	if (App.g_kSystemWrapper.GetRandomNumber(5) == 3):
#		if (pCharacter.GetGender() == App.CharacterClass.CharacterGender.MALE):
#			pSequence.AddAction(App.TGSoundAction_Create("MaleEek"+ str(App.g_kSystemWrapper.GetRandomNumber(7)+1)))
#		else:
#			pSequence.AddAction(App.TGSoundAction_Create("FemaleEek"+ str(App.g_kSystemWrapper.GetRandomNumber(7)+1)))

	return pSequence

	# lean left animation
def ReactRight(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/react_console_right.NIF", "react_console_right")
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pAnimNode = pCharacter.GetAnimNode()

	# Lean
	pLeanAction = App.TGAnimAction_Create(pAnimNode, "react_console_right", 0, 0)
	pSequence.AddAction(pLeanAction)

	# open eyes and close mouth
	pOpenEyes = EyesOpenMouthClosed(pCharacter)
	pSequence.AddAction(pOpenEyes)

	# Return to default.
	pAction = App.CharacterAction_Create (pCharacter, App.CharacterAction.AT_DEFAULT);
	pSequence.AddAction (pAction, pLeanAction)

#	if (App.g_kSystemWrapper.GetRandomNumber(5) == 3):
#		if (pCharacter.GetGender() == App.CharacterClass.CharacterGender.MALE):
#			pSequence.AddAction(App.TGSoundAction_Create("MaleEek"+ str(App.g_kSystemWrapper.GetRandomNumber(7)+1)))
#		else:
#			pSequence.AddAction(App.TGSoundAction_Create("FemaleEek"+ str(App.g_kSystemWrapper.GetRandomNumber(7)+1)))

	return pSequence

def GlanceLeft(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/MouseOver_Left.NIF", "LookCaptLeft")
	pSet = App.g_kSetManager.GetSet("bridge")
	pBridge = pSet.GetObject("bridge")
	pBridgeNode = pBridge.GetAnimNode()
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pOpenEyes = EyesOpenMouthClosed(pCharacter)
	pSequence.AddAction(pOpenEyes)
	pAnimAction_Walk = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "LookCaptLeft", 0, 0)
	pSequence.AddAction(pAnimAction_Walk, pOpenEyes, 0.0)
	return pSequence

def GlanceRight(pCharacter):
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/MouseOver_Right.NIF", "LookCaptRight")
	pSet = App.g_kSetManager.GetSet("bridge")
	pBridge = pSet.GetObject("bridge")
	pBridgeNode = pBridge.GetAnimNode()
	pCharacter = App.CharacterClass_Cast(pCharacter)
	pSequence = App.TGSequence_Create()
	pOpenEyes = EyesOpenMouthClosed(pCharacter)
	pSequence.AddAction(pOpenEyes)
	pAnimAction_Walk = App.TGAnimAction_Create(pCharacter.GetAnimNode(), "LookCaptRight", 0, 0)
	pSequence.AddAction(pAnimAction_Walk, pOpenEyes, 0.0)
	return pSequence

def PutGuestChairOut():
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/EB_chair_X_in.nif", "EB_chair_X_in")
	pSet = App.g_kSetManager.GetSet("bridge")
	pBridge = pSet.GetObject("bridge")
	pBridgeNode = pBridge.GetAnimNode()
	pAction = App.TGAnimPosition_Create(pBridgeNode, "EB_chair_X_in")
	pAction.Play()

def PutGuestChairIn():
	kAM = App.g_kAnimationManager
	kAM.LoadAnimation ("data/animations/EB_chair_X_out.nif", "EB_chair_X_out")
	pSet = App.g_kSetManager.GetSet("bridge")
	pBridge = pSet.GetObject("bridge")
	pBridgeNode = pBridge.GetAnimNode()
	pAction = App.TGAnimPosition_Create(pBridgeNode, "EB_chair_X_out")
	pAction.Play()
