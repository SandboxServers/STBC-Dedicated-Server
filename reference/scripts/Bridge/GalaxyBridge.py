##############################################################################
#	Filename:	GalaxyBridge.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	This contains the code to create and configure the Galaxy class bridge.
#	It is only called by LoadBridge.Initialize("GalaxyBridge"), so don't
#	call these functions directly
#
#	Created:	9/12/00 -	DLitwin
###############################################################################
import App

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " module...")


###############################################################################
#	CreateBridgeModel()
#
#	Create the Galaxy bridge model, viewscreen and main camera, attaching them
#	to the Set passed in.
#
#	Args:	pBridgeSet	- The Bridge set
#
#	Return:	none
###############################################################################
def CreateBridgeModel(pBridgeSet):

	iDetail = App.g_kImageManager.GetImageDetail()
	pcDetail = [ "Low/", "Medium/", "High/" ]
	pcEnvPath = "data/Models/Sets/DBridge/" + pcDetail[iDetail]

	# Pre-load the Bridge model and viewscreen model with our env path
	App.g_kModelManager.LoadModel("data/Models/Sets/DBridge/DBridge.nif", None, pcEnvPath)
	App.g_kModelManager.LoadModel("data/Models/Sets/DBridge/DBridgeViewScreen.nif", None, pcEnvPath)

	# Load the viewscreen and set it up specially with SetViewScreen()
	pViewScreen = App.ViewScreenObject_Create("data/Models/Sets/DBridge/DBridgeViewScreen.nif")
	pBridgeSet.SetViewScreen(pViewScreen, "viewscreen")

	# Setup bridge object
	pBridgeObject = App.BridgeObjectClass_Create("data/Models/Sets/DBridge/DBridge.nif")
	pBridgeSet.AddObjectToSet(pBridgeObject, "bridge")
	pBridgeObject.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	pBridgeObject.SetAngleAxisRotation(0.000000, 1.000000, 0.000000, 0.000000)

	# setup hardpoints for dbridge.
	pPropertySet = pBridgeObject.GetPropertySet()
	import DBridgeProperties
	App.g_kModelPropertyManager.ClearLocalTemplates()
	reload(DBridgeProperties)
	DBridgeProperties.LoadPropertySet(pPropertySet)

	# Create camera
	lPos = GetBaseCameraPosition()
	pCamera = App.ZoomCameraObjectClass_Create(lPos[0], lPos[1], lPos[2], 1.570796, -0.000665, -0.087559, 0.996159, "maincamera")
	pCamera.SetMinZoom(0.64)
	pCamera.SetMaxZoom(1.0)
	pCamera.SetZoomTime(0.375)
	pBridgeSet.AddCameraToSet(pCamera, "maincamera")

	# Put the GalaxyBridgeCaptain mode on this camera.
	pCamera.PushCameraMode( pCamera.GetNamedCameraMode("GalaxyBridgeCaptain") )

	pCamera.Update( App.g_kUtopiaModule.GetGameTime() )
	App.g_kVarManager.SetFloatVariable("global", "fZoomTuneState", 0)

	# Load any Galaxy bridge specific sounds.
	LoadSounds()

###############################################################################
#	GetBaseCameraPosition
#	
#	Get the normal camera position for this bridge.
#	
#	Args:	None
#	
#	Return:	A tuple with the (x,y,z) location for the base camera position.
###############################################################################
def GetBaseCameraPosition():
	return (0.683736, 86.978439, 50.0)

###############################################################################
#	AdjustCameraPositionForBridge
#	
#	Adjust the position of the camera, based on the horizontal
#	angle it's facing, based on the bridge that it's on.
#	
#	Args:	fHorizAngle
#	
#	Return:	The adjusted camera position
###############################################################################
def AdjustCameraPositionForBridge(pCamera, fHorizAngle):
	vLocation = App.TGPoint3()
	apply(vLocation.SetXYZ, GetBaseCameraPosition())

	# As the horizontal angle approaches PI (or -PI), move the
	# camera position out..
	fStartAngle = 1.25
	fEndAngle = 2.5
	vMovement = App.TGPoint3()
	vMovement.SetXYZ(0.0, -15.0, 15.0)
	if abs(fHorizAngle) > fEndAngle:
		# All the way out to the altered position.
		vLocation.Add(vMovement)
	elif abs(fHorizAngle) > fStartAngle:
		# Move from the normal position to the altered position in a smooth curve...
		import math
		fSmoothFraction = 0.5 - 0.5 * math.cos(App.PI * (abs(fHorizAngle) - fStartAngle) / (fEndAngle - fStartAngle))
		vMovement.Scale(fSmoothFraction)
		vLocation.Add(vMovement)

	return vLocation

###############################################################################
#	ConfigureCharacters()
#
#	Configure the bridge crew to the set, which adds bridge specific animations
#	to them.
#
#	Args:	pBridgeSet	- The Bridge set
#
#	Return:	none
###############################################################################
def ConfigureCharacters(pBridgeSet):
	# Configure bridge characters to our bridge
	import Bridge.Characters.Felix
	import Bridge.Characters.Kiska
	import Bridge.Characters.Saffi
	import Bridge.Characters.Miguel
	import Bridge.Characters.Brex

	pFelix = App.CharacterClass_Cast(pBridgeSet.GetObject("Tactical"))
	pKiska = App.CharacterClass_Cast(pBridgeSet.GetObject("Helm"))
	pSaffi = App.CharacterClass_Cast(pBridgeSet.GetObject("XO"))
	pMiguel = App.CharacterClass_Cast(pBridgeSet.GetObject("Science"))
	pBrex = App.CharacterClass_Cast(pBridgeSet.GetObject("Engineer"))

	Bridge.Characters.Felix.ConfigureForGalaxy(pFelix)
	Bridge.Characters.Kiska.ConfigureForGalaxy(pKiska)
	Bridge.Characters.Saffi.ConfigureForGalaxy(pSaffi)
	Bridge.Characters.Miguel.ConfigureForGalaxy(pMiguel)
	Bridge.Characters.Brex.ConfigureForGalaxy(pBrex)

	pCamera = App.ZoomCameraObjectClass_GetObject(pBridgeSet, "maincamera")
	pCamera.SetTranslateXYZ(0.683736, 86.978439, 61.934944)

###############################################################################
#	LoadSounds()
#
#	Load any Galaxy bridge specific sounds
#
#	Args:	none
#
#	Return:	none
###############################################################################
def LoadSounds():

	pGame = App.Game_GetCurrentGame()
	pGame.LoadSoundInGroup("sfx/door.wav",  "LiftDoor", "BridgeGeneric")


###############################################################################
#	UnloadSounds()
#
#	Unload any Galaxy bridge specific sounds
#
#	Args:	none
#
#	Return:	none
###############################################################################
def UnloadSounds():
	App.g_kSoundManager.DeleteSound("LiftDoor")


###############################################################################
#	PreloadAnimations ()
#
#	Load any Galaxy bridge specific animations that are common
#
#	Args:	none
#
#	Return:	none
###############################################################################
def PreloadAnimations ():
#	debug("Preload DB animations")
	kAM = App.g_kAnimationManager

	kAM.LoadAnimation("data/animations/DB_Camera_Stand_Up.nif", "DBCameraStandUp")
	kAM.LoadAnimation("data/animations/DB_Camera_Sit_Downp.nif", "DBCameraSitDown")

	# Small animations
	# Science Movement
	kAM.LoadAnimation("data/animations/db_StoL1_S.nif", "db_StoL1_S")
	kAM.LoadAnimation("data/animations/db_face_capt_s.nif", "db_face_capt_s")

	# Science Console Slides and Button Pushes
	kAM.LoadAnimation("data/animations/DB_S_pushing_buttons_A.NIF", "DB_S_pushing_buttons_A")
	kAM.LoadAnimation("data/animations/DB_S_pushing_buttons_B.NIF", "DB_S_pushing_buttons_B")
	kAM.LoadAnimation("data/animations/DB_S_pushing_buttons_C.NIF", "DB_S_pushing_buttons_C")
	kAM.LoadAnimation("data/animations/DB_S_pushing_buttons_D.NIF", "DB_S_pushing_buttons_D")

	# Talking to other stations
	kAM.LoadAnimation("data/animations/DB_S_Talk_C_S.NIF", "DB_S_Talk_C_S")
	kAM.LoadAnimation("data/animations/DB_S_Talk_H_S.NIF", "DB_S_Talk_H_S")
	kAM.LoadAnimation("data/animations/DB_S_Talk_E_S.NIF", "DB_S_Talk_E_S")
	kAM.LoadAnimation("data/animations/DB_S_Talk_T_S.NIF", "DB_S_Talk_T_S")
	kAM.LoadAnimation("data/animations/DB_S_Talk_X_S.NIF", "DB_S_Talk_X_S")

	# Engineering Movement
	kAM.LoadAnimation("data/animations/db_EtoL1_s.nif", "db_EtoL1_s")
	kAM.LoadAnimation("data/animations/db_face_capt_e.nif", "db_face_capt_e")

	# Engineering Console Slides and Button Pushes
	kAM.LoadAnimation("data/animations/DB_E_pushing_buttons_A.NIF", "DB_E_pushing_buttons_A")
	kAM.LoadAnimation("data/animations/DB_E_pushing_buttons_B.NIF", "DB_E_pushing_buttons_B")
	kAM.LoadAnimation("data/animations/DB_E_pushing_buttons_C.NIF", "DB_E_pushing_buttons_C")
	kAM.LoadAnimation("data/animations/DB_E_pushing_buttons_D.NIF", "DB_E_pushing_buttons_D")

	# Talking to other stations
	kAM.LoadAnimation("data/animations/DB_E_Talk_C_S.NIF", "DB_E_Talk_C_S")
	kAM.LoadAnimation("data/animations/DB_E_Talk_H_S.NIF", "DB_E_Talk_H_S")
	kAM.LoadAnimation("data/animations/DB_E_Talk_E_S.NIF", "DB_E_Talk_E_S")
	kAM.LoadAnimation("data/animations/DB_E_Talk_T_S.NIF", "DB_E_Talk_T_S")
	kAM.LoadAnimation("data/animations/DB_E_Talk_X_S.NIF", "DB_E_Talk_X_S")

	# medium animations
	kAM.LoadAnimation("data/animations/db_L1toG1_S.nif", "db_L1toG1_S")
	kAM.LoadAnimation("data/animations/db_L2toG2_S.nif", "db_L2toG2_S")
	kAM.LoadAnimation("data/animations/db_L3toG3_S.nif", "db_L3toG3_S")
	kAM.LoadAnimation("data/animations/DB_L1toG1_S.nif", "DB_L1toG1_S")
	kAM.LoadAnimation("data/animations/DB_G1toL1_S.nif", "DB_G1toL1_S")
	kAM.LoadAnimation("data/animations/db_L2toG2_S.nif", "db_L2toG2_S")
	kAM.LoadAnimation("data/animations/db_G2toL2_S.nif", "db_G2toL2_S")
	kAM.LoadAnimation("data/animations/db_L3toG3_S.nif", "db_L3toG3_S")
	kAM.LoadAnimation("data/animations/db_G3toL3_S.nif", "db_G3toL3_S")

	kAM.LoadAnimation("data/animations/db_stand_h_m.nif", "db_stand_h_m")
	kAM.LoadAnimation("data/animations/db_seated_h_m.nif", "db_seated_h_m")
	kAM.LoadAnimation("data/animations/db_face_capt_h.nif", "db_face_capt_h")
	kAM.LoadAnimation("data/animations/db_chair_H_face_capt.nif", "db_chair_H_face_capt")
	kAM.LoadAnimation("data/animations/db_chair_H_face_capt_reverse.nif", "db_chair_H_face_capt_reverse")

	kAM.LoadAnimation("data/animations/db_stand_c_m.nif", "db_stand_c_m")
	kAM.LoadAnimation("data/animations/db_seated_c_m.nif", "db_seated_c_m")
	kAM.LoadAnimation("data/animations/db_face_capt_c1.nif", "db_face_capt_c1")
	kAM.LoadAnimation("data/animations/db_face_capt_c.nif", "db_face_capt_c")
	kAM.LoadAnimation("data/animations/db_face_capt_c1_reverse.NIF", "db_face_capt_c1_reverse")
	kAM.LoadAnimation("data/animations/db_face_capt_h_reverse.nif", "db_face_capt_h_reverse")

	kAM.LoadAnimation("data/animations/db_hit_h.NIF", "db_hit_h")
	kAM.LoadAnimation("data/animations/db_hit_c.NIF", "db_hit_c")
	kAM.LoadAnimation("data/animations/db_hit_x.NIF", "db_hit_x")

	# Helm Console Slides and Button Pushes
	kAM.LoadAnimation("data/animations/DB_H_Console_Slide_A.NIF", "DB_H_console_slide_A")
	kAM.LoadAnimation("data/animations/DB_H_Console_Slide_B.NIF", "DB_H_console_slide_B")
	kAM.LoadAnimation("data/animations/DB_H_Console_Slide_C.NIF", "DB_H_console_slide_C")
	kAM.LoadAnimation("data/animations/DB_H_Console_Slide_D.NIF", "DB_H_console_slide_D")

	kAM.LoadAnimation("data/animations/DB_H_pushing_buttons_A.NIF", "DB_H_pushing_buttons_A")
	kAM.LoadAnimation("data/animations/DB_H_pushing_buttons_B.NIF", "DB_H_pushing_buttons_B")
	kAM.LoadAnimation("data/animations/DB_H_pushing_buttons_C.NIF", "DB_H_pushing_buttons_C")
	kAM.LoadAnimation("data/animations/DB_H_pushing_buttons_D.NIF", "DB_H_pushing_buttons_D")
	kAM.LoadAnimation("data/animations/DB_H_pushing_buttons_E.NIF", "DB_H_pushing_buttons_E")
	kAM.LoadAnimation("data/animations/DB_H_pushing_buttons_F.NIF", "DB_H_pushing_buttons_F")

	# Talking to other stations
	kAM.LoadAnimation("data/animations/DB_H_Talk_to_C_M.NIF", "H_Talk_to_C_M")
	kAM.LoadAnimation("data/animations/DB_H_Talk_to_E_M.NIF", "H_Talk_to_E_M")
	kAM.LoadAnimation("data/animations/DB_H_Talk_to_S_M.NIF", "H_Talk_to_S_M")
	kAM.LoadAnimation("data/animations/DB_H_Talk_to_T_M.NIF", "H_Talk_to_T_M")

	kAM.LoadAnimation("data/animations/DB_H_Talk_fin_C_M.NIF", "H_Talk_fin_C_M")
	kAM.LoadAnimation("data/animations/DB_H_Talk_fin_S_M.NIF", "H_Talk_fin_E_M")
	kAM.LoadAnimation("data/animations/DB_H_Talk_fin_E_M.NIF", "H_Talk_fin_S_M")
	kAM.LoadAnimation("data/animations/DB_H_Talk_fin_T_M.NIF", "H_Talk_fin_T_M")

	# XO Console Slides and Button Pushes
	kAM.LoadAnimation("data/animations/DB_C_pushingbuttons_A.NIF", "DB_C_pushingbuttons_A")

	# Talking to other stations
	kAM.LoadAnimation("data/animations/DB_C_Talk_E_M.NIF", "H_Talk_E_M")
	kAM.LoadAnimation("data/animations/DB_C_Talk_S_M.NIF", "H_Talk_E_M")
	kAM.LoadAnimation("data/animations/DB_C_Talk_TH_M.NIF", "H_Talk_TH_M")
	kAM.LoadAnimation("data/animations/DB_C_Talk_X_M.NIF", "H_Talk_X_M")

	# Large animations
	kAM.LoadAnimation("data/animations/db_stand_t_l.nif", "db_stand_t_l")
	kAM.LoadAnimation("data/animations/db_seated_t_l.nif", "db_seated_t_l")
	kAM.LoadAnimation("data/animations/db_face_capt_t.nif", "db_face_capt_t")
	kAM.LoadAnimation("data/animations/db_chair_T_face_capt.nif", "db_chair_T_face_capt")
	kAM.LoadAnimation("data/animations/db_face_capt_t_reverse.nif", "db_face_capt_t_reverse")
	kAM.LoadAnimation("data/animations/db_chair_T_face_capt_reverse.nif", "db_chair_T_face_capt_reverse")
	kAM.LoadAnimation("data/animations/db_hit_t.NIF", "db_hit_t")

	# Tactical Console Slides and Button Pushes
	kAM.LoadAnimation("data/animations/DB_T_Console_Slide_A.NIF", "DB_T_console_slide_A")
	kAM.LoadAnimation("data/animations/DB_T_Console_Slide_B.NIF", "DB_T_console_slide_B")
	kAM.LoadAnimation("data/animations/DB_T_Console_Slide_C.NIF", "DB_T_console_slide_C")
	kAM.LoadAnimation("data/animations/DB_T_Console_Slide_D.NIF", "DB_T_console_slide_D")

	kAM.LoadAnimation("data/animations/DB_T_pushing_buttons_A.NIF", "DB_T_pushing_buttons_A")
	kAM.LoadAnimation("data/animations/DB_T_pushing_buttons_B.NIF", "DB_T_pushing_buttons_B")
	kAM.LoadAnimation("data/animations/DB_T_pushing_buttons_C.NIF", "DB_T_pushing_buttons_C")
	kAM.LoadAnimation("data/animations/DB_T_pushing_buttons_D.NIF", "DB_T_pushing_buttons_D")
	kAM.LoadAnimation("data/animations/DB_T_pushing_buttons_E.NIF", "DB_T_pushing_buttons_E")
	kAM.LoadAnimation("data/animations/DB_T_pushing_buttons_F.NIF", "DB_T_pushing_buttons_F")

	# Talking to other stations
	kAM.LoadAnimation("data/animations/DB_T_Talk_to_C_L.NIF", "T_Talk_to_C_L")
	kAM.LoadAnimation("data/animations/DB_T_Talk_to_E_L.NIF", "T_Talk_to_E_L")
	kAM.LoadAnimation("data/animations/DB_T_Talk_to_S_L.NIF", "T_Talk_to_S_L")
	kAM.LoadAnimation("data/animations/DB_T_Talk_to_H_L.NIF", "T_Talk_to_H_L")
	kAM.LoadAnimation("data/animations/DB_T_Talk_X_L.NIF", "T_Talk_X_L")

	kAM.LoadAnimation("data/animations/DB_T_Talk_fin_C_L.NIF", "T_Talk_fin_C_L")
	kAM.LoadAnimation("data/animations/DB_T_Talk_fin_S_L.NIF", "T_Talk_fin_E_L")
	kAM.LoadAnimation("data/animations/DB_T_Talk_fin_E_L.NIF", "T_Talk_fin_S_L")
	kAM.LoadAnimation("data/animations/DB_T_Talk_fin_H_L.NIF", "T_Talk_fin_H_L")
	kAM.LoadAnimation("data/animations/DB_T_Talk_X_L_reverse.NIF", "T_Talk_X_L_reverse")

	# Door animations
	kAM.LoadAnimation("data/animations/db_door_l1.nif", "doorl1")
	kAM.LoadAnimation("data/animations/db_door_l2.nif", "doorl2")
	kAM.LoadAnimation("data/animations/db_door_l3.nif", "doorl3")

	#kAM.LoadAnimation("data/animations/anim.nif", "anim")

	return

###############################################################################
#	UnloadAnimations ()
#
#	Unload any Galaxy bridge specific animations that are common
#
#	Args:	none
#
#	Return:	none
###############################################################################
def UnloadAnimations ():
#	debug("Unload DB animations")
	kAM = App.g_kAnimationManager

	kAM.FreeAnimation("DBCameraStandUp")
	kAM.FreeAnimation("DBCameraSitDown")

	# Small animations
	# Science Movement
	kAM.FreeAnimation("db_StoL1_S")
	kAM.FreeAnimation("db_face_capt_s")

	# Science Console Slides and Button Pushes
	kAM.FreeAnimation("DB_S_pushing_buttons_A")
	kAM.FreeAnimation("DB_S_pushing_buttons_B")
	kAM.FreeAnimation("DB_S_pushing_buttons_C")
	kAM.FreeAnimation("DB_S_pushing_buttons_D")

	# Talking to other stations
	kAM.FreeAnimation("DB_S_Talk_C_S")
	kAM.FreeAnimation("DB_S_Talk_H_S")
	kAM.FreeAnimation("DB_S_Talk_E_S")
	kAM.FreeAnimation("DB_S_Talk_T_S")
	kAM.FreeAnimation("DB_S_Talk_X_S")

	# Engineering Movement
	kAM.FreeAnimation("db_EtoL1_s")
	kAM.FreeAnimation("db_face_capt_e")

	# Engineering Console Slides and Button Pushes
	kAM.FreeAnimation("DB_E_pushing_buttons_A")
	kAM.FreeAnimation("DB_E_pushing_buttons_B")
	kAM.FreeAnimation("DB_E_pushing_buttons_C")
	kAM.FreeAnimation("DB_E_pushing_buttons_D")

	# Talking to other stations
	kAM.FreeAnimation("DB_E_Talk_C_S")
	kAM.FreeAnimation("DB_E_Talk_H_S")
	kAM.FreeAnimation("DB_E_Talk_E_S")
	kAM.FreeAnimation("DB_E_Talk_T_S")
	kAM.FreeAnimation("DB_E_Talk_X_S")

	# medium animations
	kAM.FreeAnimation("db_L1toG1_S")
	kAM.FreeAnimation("db_L2toG2_S")
	kAM.FreeAnimation("db_L3toG3_S")
	kAM.FreeAnimation("DB_L1toG1_S")
	kAM.FreeAnimation("DB_G1toL1_S")
	kAM.FreeAnimation("db_L2toG2_S")
	kAM.FreeAnimation("db_G2toL2_S")
	kAM.FreeAnimation("db_L3toG3_S")
	kAM.FreeAnimation("db_G3toL3_S")

	kAM.FreeAnimation("db_stand_h_m")
	kAM.FreeAnimation("db_seated_h_m")
	kAM.FreeAnimation("db_face_capt_h")
	kAM.FreeAnimation("db_chair_H_face_capt")
	kAM.FreeAnimation("db_chair_H_face_capt_reverse")

	kAM.FreeAnimation("db_stand_c_m")
	kAM.FreeAnimation("db_seated_c_m")
	kAM.FreeAnimation("db_face_capt_c1")
	kAM.FreeAnimation("db_face_capt_c")
	kAM.FreeAnimation("db_face_capt_c1_reverse")
	kAM.FreeAnimation("db_face_capt_h_reverse")

	kAM.FreeAnimation("db_hit_h")
	kAM.FreeAnimation("db_hit_c")
	kAM.FreeAnimation("db_hit_x")

	# Helm Console Slides and Button Pushes
	kAM.FreeAnimation("DB_H_console_slide_A")
	kAM.FreeAnimation("DB_H_console_slide_B")
	kAM.FreeAnimation("DB_H_console_slide_C")
	kAM.FreeAnimation("DB_H_console_slide_D")

	kAM.FreeAnimation("DB_H_pushing_buttons_A")
	kAM.FreeAnimation("DB_H_pushing_buttons_B")
	kAM.FreeAnimation("DB_H_pushing_buttons_C")
	kAM.FreeAnimation("DB_H_pushing_buttons_D")
	kAM.FreeAnimation("DB_H_pushing_buttons_E")
	kAM.FreeAnimation("DB_H_pushing_buttons_F")

	# Talking to other stations
	kAM.FreeAnimation("H_Talk_to_C_M")
	kAM.FreeAnimation("H_Talk_to_E_M")
	kAM.FreeAnimation("H_Talk_to_S_M")
	kAM.FreeAnimation("H_Talk_to_T_M")

	kAM.FreeAnimation("H_Talk_fin_C_M")
	kAM.FreeAnimation("H_Talk_fin_E_M")
	kAM.FreeAnimation("H_Talk_fin_S_M")
	kAM.FreeAnimation("H_Talk_fin_T_M")

	# XO Console Slides and Button Pushes
	kAM.FreeAnimation("DB_C_pushingbuttons_A")

	# Talking to other stations
	kAM.FreeAnimation("H_Talk_E_M")
	kAM.FreeAnimation("H_Talk_E_M")
	kAM.FreeAnimation("H_Talk_TH_M")
	kAM.FreeAnimation("H_Talk_X_M")

	# Large animations
	kAM.FreeAnimation("db_stand_t_l")
	kAM.FreeAnimation("db_seated_t_l")
	kAM.FreeAnimation("db_face_capt_t")
	kAM.FreeAnimation("db_chair_T_face_capt")
	kAM.FreeAnimation("db_face_capt_t_reverse")
	kAM.FreeAnimation("db_chair_T_face_capt_reverse")
	kAM.FreeAnimation("db_hit_t")

	# Tactical Console Slides and Button Pushes
	kAM.FreeAnimation("DB_T_console_slide_A")
	kAM.FreeAnimation("DB_T_console_slide_B")
	kAM.FreeAnimation("DB_T_console_slide_C")
	kAM.FreeAnimation("DB_T_console_slide_D")

	kAM.FreeAnimation("DB_T_pushing_buttons_A")
	kAM.FreeAnimation("DB_T_pushing_buttons_B")
	kAM.FreeAnimation("DB_T_pushing_buttons_C")
	kAM.FreeAnimation("DB_T_pushing_buttons_D")
	kAM.FreeAnimation("DB_T_pushing_buttons_E")
	kAM.FreeAnimation("DB_T_pushing_buttons_F")

	# Talking to other stations
	kAM.FreeAnimation("T_Talk_to_C_L")
	kAM.FreeAnimation("T_Talk_to_E_L")
	kAM.FreeAnimation("T_Talk_to_S_L")
	kAM.FreeAnimation("T_Talk_to_H_L")
	kAM.FreeAnimation("T_Talk_X_L")

	kAM.FreeAnimation("T_Talk_fin_C_L")
	kAM.FreeAnimation("T_Talk_fin_E_L")
	kAM.FreeAnimation("T_Talk_fin_S_L")
	kAM.FreeAnimation("T_Talk_fin_H_L")
	kAM.FreeAnimation("T_Talk_X_L_reverse")

	# Door animations
	kAM.FreeAnimation("doorl1")
	kAM.FreeAnimation("doorl2")
	kAM.FreeAnimation("doorl3")

	#kAM.FreeAnimation("anim")

	return
