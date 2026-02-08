###############################################################################
#	Filename:	PowerDisplay.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Script file to construct the power display's UI elements
#	
#	Created:	4/17/2001 -	Erik Novales
###############################################################################

import App
import MissionLib
import UIHelpers

# We're one of those modules that shouldn't be unloaded until the game
# is gone.  During serialization/unserialization, the current game will
# be None, and we don't want to call AddPersistentModule then anyways.
if App.Game_GetCurrentGame():
	App.Game_GetCurrentGame().AddPersistentModule(__name__)

NonSerializedObjects = ( "debug", )

debug = App.CPyDebug(__name__).Print
debug("Loading " + __name__ + " module...")

g_idPowerDisplay = App.NULL_ID

g_fRefreshTime = 0.5

# power display child list
POWER_USED_TEXT				= 0
POWER_USED_MARKS			= 1
POWER_USED_BAR				= 2
WARP_CORE_REGION			= 3
MAIN_REGION					= 4
BACKUP_REGION				= 5
POWER_CONTROL				= 6
WARP_CORE_GAUGE_PANE		= 7
MAIN_GAUGE_PANE				= 8
BACKUP_GAUGE_PANE			= 9
HAZARD_BAR					= 10
TRACTOR_TEXT				= 11
CLOAK_TEXT					= 12
WARP_CORE_PERCENTAGE		= 13
MAIN_PERCENTAGE				= 14
BACKUP_PERCENTAGE			= 15
WARP_CORE_CURVE				= 16
MAIN_GAUGE_CURVE			= 17
BACKUP_GAUGE_CURVE			= 18
WARP_CORE_CURVE_TEXT		= 19
MAIN_CURVE_TEXT				= 20
BACKUP_CURVE_TEXT			= 21
TRACTOR_BAR					= 22
CLOAK_BAR					= 23

# Gauge pane list
GAUGE_PANE_MARKS			= 0
GAUGE_PANE_GAUGE			= 1

# Power used child list
ENGINES				= 0
SHIELDS				= 1
WEAPONS				= 2
SENSORS				= 3

g_fPowerUsedBarHeight = 0.0

#
# ProcessWrapper
#
# PythonMethodProcess objects can't be saved directly.  This allows them to be saved
# and wraps the functionality we want in the constructor.
class ProcessWrapper:
	def __init__(self, sFunctionName, fDelay, ePriority):
		self.sFunctionName = sFunctionName
		self.fDelay = fDelay
		self.ePriority = ePriority

		self.SetupProcess()

	def __getstate__(self):
		dState = self.__dict__.copy()
		del dState["pProcess"]
		return dState

	def __setstate__(self, dict):
		self.__dict__ = dict
		self.SetupProcess()

	def SetupProcess(self):
		self.pProcess = App.PythonMethodProcess()
		self.pProcess.SetInstance(self)
		self.pProcess.SetFunction("ProcessFunc")
		self.pProcess.SetDelay( self.fDelay )
		self.pProcess.SetPriority( self.ePriority )

	def ProcessFunc(self, dTimeAvailable):
		# Call our function.
		pFunc = globals()[self.sFunctionName]
		pFunc(dTimeAvailable)

g_pPowerRefreshProcess = None

###############################################################################
#	Init(pPowerDisplay)
#	
#	Initializes the power display.
#	
#	Args:	pPowerDisplay	- the display
#	
#	Return:	none
###############################################################################
def Init(pPowerDisplay):
	global g_idPowerDisplay
	if (g_idPowerDisplay != App.NULL_ID):
		RemoveEventHandlers()
	g_idPowerDisplay = pPowerDisplay.GetObjID()

	AddEventHandlers()
	
	pMode = App.GraphicsModeInfo_GetCurrentMode()
	pcLCARS = pMode.GetLcarsString()
	LCARS = __import__(pMode.GetLcarsModule())

	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
	pPower = pPlayer.GetPowerSubsystem()
	if (pPower == None):
		return

	pPowerDisplay.KillChildren()

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	fCombinedBandwidth = pPower.GetMaxMainConduitCapacity() + pPower.GetBackupConduitCapacity()
	fMainPct = pPower.GetMaxMainConduitCapacity() / fCombinedBandwidth
	fBackupPct = pPower.GetBackupConduitCapacity() / fCombinedBandwidth
	fGaugeBaseWidth = LCARS.POWER_GAUGE_WIDTH
	fGaugeBaseHeight = LCARS.POWER_GAUGE_HEIGHT

	pPowerUsedText = App.TGParagraph_CreateW(pDatabase.GetString("Power used"))
	pPowerUsedText.SetColor(App.NiColorA_WHITE)
	pPowerUsedText.Layout()
	pPowerDisplay.AddChild(pPowerUsedText, 2.0 * App.globals.DEFAULT_ST_INDENT_HORIZ, 0.0, 0)

	pPowerUsedMarks = App.STTiledIcon_Create(pcLCARS, 4101, App.NiColorA_BLACK)
	pPowerDisplay.AddChild(pPowerUsedMarks, 0.0, 0.0, 0)
	pPowerUsedMarks.SetTiling(App.STTiledIcon.DIRECTION_X, 1)
	pPowerUsedMarks.SetTileSize(App.STTiledIcon.DIRECTION_X, 1)

	# Now, create the "power used" bar. Don't add it yet, though.
	pPowerUsedBar = CreatePowerUsedBar()
	pPowerDisplay.AddChild(pPowerUsedBar, 0.0, 0.0, 0)

	# Create the power rulers.
	CreatePowerRulers(pPowerDisplay, pPowerUsedBar)

	pWarpCoreRuler = App.TGFrame_Cast(pPowerDisplay.GetNthChild(WARP_CORE_REGION))

	# Now, position the "power used" bar, the text, and the tick marks.
	kRulerInterior = pWarpCoreRuler.GetInnerRect()
	fNotchThickness = kRulerInterior.GetLeft() - pWarpCoreRuler.GetLeft()
	fBarHeight = kRulerInterior.GetTop()

	pPowerUsedBar.SetPosition(pWarpCoreRuler.GetLeft() + fNotchThickness, 
							  pWarpCoreRuler.GetTop() + kRulerInterior.GetTop(), 0)
	pPowerUsedMarks.SetPosition(pPowerUsedBar.GetLeft(), pPowerUsedBar.GetTop(), 0)
	pPowerUsedMarks.Resize(pPowerUsedBar.GetWidth(), pPowerUsedBar.GetHeight(), 0)

	# Add power control to the power pane.
	fPowerControlWidth = pPowerDisplay.GetWidth() - (3.0 * fGaugeBaseWidth) - (3.0 * (2.0 * App.globals.DEFAULT_ST_INDENT_HORIZ))
	pPowerControl = App.EngPowerCtrl_Create(fPowerControlWidth)
	pPowerDisplay.AddChild(pPowerControl, 0.0, pWarpCoreRuler.GetBottom() + (2.0 * App.globals.DEFAULT_ST_INDENT_VERT), 0)

	# Create the backgrounds for the gauges.
	pWarpCoreGaugePane	= App.TGPane_Create(fGaugeBaseWidth, fGaugeBaseHeight)
	pMainGaugePane		= App.TGPane_Create(fGaugeBaseWidth, fGaugeBaseHeight)
	pBackupGaugePane	= App.TGPane_Create(fGaugeBaseWidth, fGaugeBaseHeight)

	pPowerDisplay.AddChild(pWarpCoreGaugePane, 
						   pPowerControl.GetRight() + App.globals.DEFAULT_ST_INDENT_HORIZ, 
						   pPowerControl.GetTop(), 0)
	pPowerDisplay.AddChild(pMainGaugePane, pWarpCoreGaugePane.GetRight() + (2.0 * App.globals.DEFAULT_ST_INDENT_HORIZ), pWarpCoreGaugePane.GetTop(), 0)
	pPowerDisplay.AddChild(pBackupGaugePane, pMainGaugePane.GetRight() + (2.0 * App.globals.DEFAULT_ST_INDENT_HORIZ), pMainGaugePane.GetTop(), 0)

	# Create the ruler marks.
	pMainMarks = App.STTiledIcon_Create(pcLCARS, 4100, App.NiColorA_BLACK)
	pBackupMarks = App.STTiledIcon_Create(pcLCARS, 4100, App.NiColorA_BLACK)
	pWarpCoreMarks = App.STTiledIcon_Create(pcLCARS, 4100, App.NiColorA_BLACK)

	pMainMarks.SetTiling(App.STTiledIcon.DIRECTION_Y, 1)
	pMainMarks.SetTileSize(App.STTiledIcon.DIRECTION_Y, 1)
	pBackupMarks.SetTiling(App.STTiledIcon.DIRECTION_Y, 1)
	pBackupMarks.SetTileSize(App.STTiledIcon.DIRECTION_Y, 1)
	pWarpCoreMarks.SetTiling(App.STTiledIcon.DIRECTION_Y, 1)
	pWarpCoreMarks.SetTileSize(App.STTiledIcon.DIRECTION_Y, 1)

	pMainMarks.Resize(pMainGaugePane.GetWidth(), pMainGaugePane.GetHeight(), 0)
	pBackupMarks.Resize(pBackupGaugePane.GetWidth(), pBackupGaugePane.GetHeight(), 0)
	pWarpCoreMarks.Resize(pWarpCoreGaugePane.GetWidth(), pWarpCoreGaugePane.GetHeight(), 0)

	pWarpCoreGaugePane.AddChild(pWarpCoreMarks, 0.0, 0.0, 0)
	pMainGaugePane.AddChild(pMainMarks, 0.0, 0.0, 0)
	pBackupGaugePane.AddChild(pBackupMarks, 0.0, 0.0, 0)

	# Create the battery gauges.
	pMainGauge = pPowerDisplay.CreateBatteryGauge(App.EngPowerDisplay.MAIN)
	kMainEmptyColor = App.TGColorA()
	kMainEmptyColor.SetRGBA(91.0 / 255.0, 85.0 / 255.0, 53.0 / 255.0, 1.0)
	pMainGauge.SetEmptyColor(kMainEmptyColor)
	pMainGauge.Resize(pMainGaugePane.GetWidth(), 
					  pMainGaugePane.GetHeight(), 0)
	
	pBackupGauge = pPowerDisplay.CreateBatteryGauge(App.EngPowerDisplay.BACKUP)
	kBackupEmptyColor = App.TGColorA()
	kBackupEmptyColor.SetRGBA(118.0 / 255.0, 75.0 / 255.0, 58.0 / 255.0, 1.0)
	pBackupGauge.SetEmptyColor(kBackupEmptyColor)
	pBackupGauge.Resize(pBackupGaugePane.GetWidth(), 
						pBackupGaugePane.GetHeight(), 0)

	pWarpCoreGauge = pPowerDisplay.CreateBatteryGauge(App.EngPowerDisplay.WARP_CORE)
	kWarpCoreEmptyColor = App.TGColorA()
	kWarpCoreEmptyColor.SetRGBA(84.0 / 255.0, 119.0 / 255.0, 153.0 / 255.0, 1.0)
	pWarpCoreGauge.SetEmptyColor(kWarpCoreEmptyColor)
	pWarpCoreGauge.Resize(pWarpCoreGaugePane.GetWidth(), 
						  pWarpCoreGaugePane.GetHeight(), 0)

	pWarpCoreGaugePane.AddChild(pWarpCoreGauge, 0.0, 0.0, 0)
	pMainGaugePane.AddChild(pMainGauge, 0.0, 0.0, 0)
	pBackupGaugePane.AddChild(pBackupGauge, 0.0, 0.0, 0)

	# Add the hazard icon.
	pHazardIcon = App.STTiledIcon_Create(pcLCARS, 4200)
	pHazardIcon.SetTiling(App.STTiledIcon.DIRECTION_X, 1)
	pHazardIcon.SetTileSize(App.STTiledIcon.DIRECTION_X, 1)
	pHazardIcon.SetTiling(App.STTiledIcon.DIRECTION_Y, 1)
	pHazardIcon.SetTileSize(App.STTiledIcon.DIRECTION_Y, 1)
	pHazardIcon.Resize(pPowerDisplay.GetWidth(), pPowerUsedBar.GetHeight(), 0)

	pPowerDisplay.AddChild(pHazardIcon, pWarpCoreRuler.GetLeft() + pMode.GetPixelWidth(), pPowerUsedBar.GetTop(), 0)

	# These are the text labels that tell the user whether the tractor
	# beam or the cloaking subsystem are using power.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTractorText = App.TGParagraph_CreateW(pDatabase.GetString("Tractor: Off"))
	pTractorText.SetColor(App.g_kEngineeringTractorColor)
	pCloakText = App.TGParagraph_CreateW(pDatabase.GetString("Cloak: Off"))
	pCloakText.SetColor(App.g_kEngineeringCloakColor)
	App.g_kLocalizationManager.Unload(pDatabase)

	pPowerDisplay.AddChild(pTractorText, pPowerControl.GetLeft(), pPowerControl.GetBottom() + App.globals.DEFAULT_ST_INDENT_VERT, 0)
	pTractorText.Layout()
	pPowerDisplay.AddChild(pCloakText, pTractorText.GetLeft(), pTractorText.GetTop() + App.globals.DEFAULT_ST_INDENT_VERT, 0)

	# Add legend elbows and text.
	CreateLegendElbows(pPowerDisplay)

	UpdateRulers()

	global g_fPowerUsedBarWidth
	global g_fPowerUsedBarHeight
	g_fPowerUsedBarHeight = LCARS.POWER_USED_BAR_HEIGHT

	FixTractorAndCloakText(pPowerDisplay)

	pCloakBar = pPowerDisplay.GetNthChild(CLOAK_BAR)
	pBackupElbow = pPowerDisplay.GetNthChild(BACKUP_GAUGE_CURVE)
	if (pCloakBar.IsVisible()):
		pPowerDisplay.Resize(pPowerDisplay.GetWidth(), pCloakBar.GetBottom() + (2.0 * App.globals.DEFAULT_ST_INDENT_VERT), 0)
	else:
		pPowerDisplay.Resize(pPowerDisplay.GetWidth(), pBackupElbow.GetBottom() + (2.0 * App.globals.DEFAULT_ST_INDENT_VERT), 0)
	pPowerDisplay.Layout()

	pPowerDisplay.GetParent().Resize(pPowerDisplay.GetWidth(), pPowerDisplay.GetHeight(), 0)
	pWindow = App.STStylizedWindow_Cast(pPowerDisplay.GetConceptualParent())
	if pWindow:
		pWindow.InteriorChangedSize()

	App.g_kLocalizationManager.Unload(pDatabase)

###############################################################################
#	UIFixPowerDisplay()
#	
#	Fixes the power display when the resolution is changed.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def UIFixPowerDisplay():
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	pPowerDisplay = App.EngPowerDisplay_GetPowerDisplay()
	if (pPowerDisplay != None):
		pPowerDisplay.Resize(LCARS.POWER_AREA_WIDTH, LCARS.POWER_AREA_HEIGHT)
		pPowerWindow = App.STStylizedWindow_Cast(pPowerDisplay.GetConceptualParent())
		pPowerWindow.SetMaximumSize(LCARS.POWER_AREA_WIDTH + pPowerWindow.GetBorderWidth(), 1.0)

		pParent = pPowerWindow.GetParent()
		Init(pPowerDisplay)

		# Reposition power window.
		pPowerWindow.SetPosition(pParent.GetWidth() - pPowerWindow.GetMaximumWidth() - (2.0 * App.globals.DEFAULT_ST_INDENT_HORIZ),
								2.0 * App.globals.DEFAULT_ST_INDENT_VERT, 0)

		Update(1)

###############################################################################
#	AddEventHandlers()
#	
#	Adds event handlers for the power display.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def AddEventHandlers():
	pPowerDisplay = App.EngPowerDisplay_Cast(App.TGObject_GetTGObjectPtr(g_idPowerDisplay))

	if (pPowerDisplay == None):
		return

	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_SET_PLAYER, pPowerDisplay, __name__ + ".HandleSetPlayer")
	pPowerDisplay.AddPythonFuncHandlerForInstance(App.ET_DELETE_OBJECT_PUBLIC, __name__ + ".HandleDeleteDisplay")

	# Setup a periodic process to call our RefreshTimer function.
	global g_pPowerRefreshProcess
	g_pPowerRefreshProcess = ProcessWrapper("RefreshTimer", g_fRefreshTime, App.TimeSliceProcess.LOW)

	pPlayer = MissionLib.GetPlayer()
	if (pPlayer != None):
		pTractors = pPlayer.GetTractorBeamSystem()
		pCloak = pPlayer.GetCloakingSubsystem()

		if (pTractors != None):
			App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_TRACTOR_BEAM_STARTED_FIRING, pPowerDisplay, __name__ + ".HandleTractor", pPlayer)
			App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_TRACTOR_BEAM_STOPPED_FIRING, pPowerDisplay, __name__ + ".HandleTractor", pPlayer)
		if (pCloak != None):
			App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_CLOAK_BEGINNING, pPowerDisplay, __name__ + ".HandleCloak", pPlayer)
			App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_DECLOAK_COMPLETED, pPowerDisplay, __name__ + ".HandleCloak", pPlayer)

###############################################################################
#	RemoveEventHandlers()
#	
#	Removes event handlers for the power display.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def RemoveEventHandlers():
	pPowerDisplay = App.EngPowerDisplay_Cast(App.TGObject_GetTGObjectPtr(g_idPowerDisplay))

	if (pPowerDisplay == None):
		return

	App.g_kEventManager.RemoveBroadcastHandler(App.ET_SET_PLAYER, pPowerDisplay, __name__ + ".HandleSetPlayer")
	pPowerDisplay.RemoveHandlerForInstance(App.ET_DELETE_OBJECT_PUBLIC, __name__ + ".HandleDeleteDisplay")

	# Kill our refresh process.
	global g_pPowerRefreshProcess
	g_pPowerRefreshProcess = None

	pPlayer = MissionLib.GetPlayer()
	if (pPlayer != None):
		pTractors = pPlayer.GetTractorBeamSystem()
		pCloak = pPlayer.GetCloakingSubsystem()

		if (pTractors != None):
			App.g_kEventManager.RemoveBroadcastHandler(App.ET_TRACTOR_BEAM_STARTED_FIRING, pPowerDisplay, __name__ + ".HandleTractor", pPlayer)
			App.g_kEventManager.RemoveBroadcastHandler(App.ET_TRACTOR_BEAM_STOPPED_FIRING, pPowerDisplay, __name__ + ".HandleTractor", pPlayer)
		if (pCloak != None):
			App.g_kEventManager.RemoveBroadcastHandler(App.ET_CLOAK_BEGINNING, pPowerDisplay, __name__ + ".HandleCloak", pPlayer)
			App.g_kEventManager.RemoveBroadcastHandler(App.ET_DECLOAK_COMPLETED, pPowerDisplay, __name__ + ".HandleCloak", pPlayer)

###############################################################################
#	CreatePowerUsedBar()
#	
#	Creates the pane containing the icons for each of the systems on the
#	ship.
#	
#	Args:	none
#	
#	Return:	TGPane * - the new power used bar
###############################################################################
def CreatePowerUsedBar():
	pPane = App.TGPane_Create()

	pShip = MissionLib.GetPlayer()
	if (pShip == None):
		return(pPane)

	# Get string for LCARS icon group.
	pGraphicsMode = App.GraphicsModeInfo_GetCurrentMode()
	pcLCARS = pGraphicsMode.GetLcarsString()
	LCARS = __import__(pGraphicsMode.GetLcarsModule())

	pPane.Resize(LCARS.POWER_USED_BAR_WIDTH, LCARS.POWER_USED_BAR_HEIGHT, 0)
	# We'll make icons for everything, even if the ship doesn't have
	# a particular system -- it will preserve the child ordering in the
	# power used bar.
	pEngines = App.TGIcon_Create(pcLCARS, 200, App.g_kEngineeringEnginesColor)
	pShields = App.TGIcon_Create(pcLCARS, 200, App.g_kEngineeringShieldsColor)
	pWeapons = App.TGIcon_Create(pcLCARS, 200, App.g_kEngineeringWeaponsColor)
	pSensors = App.TGIcon_Create(pcLCARS, 200, App.g_kEngineeringSensorsColor)

	pPane.AddChild(pEngines, 0.0, 0.0, 0)
	pPane.AddChild(pShields, 0.0, 0.0, 0)
	pPane.AddChild(pWeapons, 0.0, 0.0, 0)
	pPane.AddChild(pSensors, 0.0, 0.0, 0)

	pPane.Layout()

	return(pPane)

###############################################################################
#	CreatePowerRulers(pPowerDisplay, pPowerUsedBar)
#	
#	Creates the power rulers for the display, and adds them.
#	
#	Args:	pPowerDisplay	- the display
#			pPowerUsedBar	- the power used bar, needed since some things
#							  size to it, and it's not already in the display
#	
#	Return:	none
###############################################################################
def CreatePowerRulers(pPowerDisplay, pPowerUsedBar):
	pMode = App.GraphicsModeInfo_GetCurrentMode()
	pcLCARS = pMode.GetLcarsString()
	LCARS = __import__(pMode.GetLcarsModule())
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
	pPower = pPlayer.GetPowerSubsystem()
	if (pPower == None):
		return

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	pPowerIcons = App.g_kIconManager.GetIconGroup(pcLCARS)
	fRulerCapsHeight = 2.0 * pPowerIcons.GetIconScreenHeight(4300)

	# Create the power rulers for the main and backup conduits.
	fTotalBandwidth = pPower.GetMaxMainConduitCapacity() + pPower.GetBackupConduitCapacity()
	fBackupPercentage = pPower.GetBackupConduitCapacity() / fTotalBandwidth
	fMainPercentage = pPower.GetMainConduitCapacity() / fTotalBandwidth
	fGenerationPercentage = pPower.GetPowerOutput() / fTotalBandwidth

	pWarpCoreRuler = App.TGFrame_Create(pcLCARS, 4300)
	pWarpCoreRuler.Resize(pPowerDisplay.GetWidth(), pPowerUsedBar.GetHeight() + fRulerCapsHeight)
	pWarpCoreRuler.SetNiColor(App.g_kEngineeringWarpCoreColor.r, App.g_kEngineeringWarpCoreColor.g,
							  App.g_kEngineeringWarpCoreColor.b, App.g_kEngineeringWarpCoreColor.a)
	pWarpCoreRuler.SetEdgeStretch(App.TGFrame.NO_STRETCH_LR)
	pWarpCoreRuler.SetNoFocus()

	pMainRuler = App.TGFrame_Create(pcLCARS, 4310)
	pMainRuler.Resize(pPowerDisplay.GetWidth(), pPowerUsedBar.GetHeight() + fRulerCapsHeight)
	pMainRuler.SetNiColor(App.g_kEngineeringMainPowerColor.r, App.g_kEngineeringMainPowerColor.g,
						  App.g_kEngineeringMainPowerColor.b, App.g_kEngineeringMainPowerColor.a)
	pMainRuler.SetEdgeStretch(App.TGFrame.NO_STRETCH_LR)
	pMainRuler.SetNoFocus()

	pBackupRuler = App.TGFrame_Create(pcLCARS, 4320)
	pBackupRuler.Resize(pPowerDisplay.GetWidth(), pPowerUsedBar.GetHeight() + fRulerCapsHeight)
	pBackupRuler.SetNiColor(App.g_kEngineeringBackupPowerColor.r, App.g_kEngineeringBackupPowerColor.g,
							App.g_kEngineeringBackupPowerColor.b, App.g_kEngineeringBackupPowerColor.a)
	pBackupRuler.SetEdgeStretch(App.TGFrame.NO_STRETCH_LR)
	pBackupRuler.SetNoFocus()

	pPowerUsedText = pPowerDisplay.GetNthChild(POWER_USED_TEXT)

	pPowerDisplay.AddChild(pWarpCoreRuler, 0.0, pPowerUsedText.GetBottom() + App.globals.DEFAULT_ST_INDENT_VERT, 0)
	pPowerDisplay.AddChild(pMainRuler, 0.0, pWarpCoreRuler.GetTop(), 0)
	pPowerDisplay.AddChild(pBackupRuler, 0.0, pWarpCoreRuler.GetTop(), 0)

	App.g_kLocalizationManager.Unload(pDatabase)

###############################################################################
#	CreateLegendElbows(pPowerDisplay)
#	
#	Creates the little elbows that say stuff like "warp core", 
#	"main battery", etc.
#	
#	Args:	pPowerDisplay	- the power display
#	
#	Return:	none
###############################################################################
def CreateLegendElbows(pPowerDisplay):
	pWCGauge = App.TGPane_Cast(pPowerDisplay.GetNthChild(WARP_CORE_GAUGE_PANE))
	pMGauge = App.TGPane_Cast(pPowerDisplay.GetNthChild(MAIN_GAUGE_PANE))
	pBGauge = App.TGPane_Cast(pPowerDisplay.GetNthChild(BACKUP_GAUGE_PANE))
	pPowerCtrl = App.EngPowerCtrl_GetPowerCtrl()

	pWCPercentText = App.TGParagraph_Create("100%")
	pWCPercentText.SetColor(App.NiColorA_BLACK)
	pWCPercentText.Layout()

	pMPercentText = App.TGParagraph_Create("100%")
	pMPercentText.SetColor(App.NiColorA_BLACK)
	pMPercentText.Layout()

	pBPercentText = App.TGParagraph_Create("100%")
	pBPercentText.SetColor(App.NiColorA_BLACK)
	pBPercentText.Layout()

	pPowerDisplay.AddChild(pWCPercentText, 0.0, 0.0, 0)
	pPowerDisplay.AddChild(pMPercentText, 0.0, 0.0, 0)
	pPowerDisplay.AddChild(pBPercentText, 0.0, 0.0, 0)

	fInnerHeight = max(pPowerCtrl.GetBottom() - pWCGauge.GetBottom(), pWCPercentText.GetHeight())
	fInnerHeight = App.TGUIModule_PixelAlignValue(fInnerHeight + (2.0 * App.globals.DEFAULT_ST_INDENT_VERT), 0)
	fInnerWidth = pWCGauge.GetWidth()
	fOuterHeight = App.TGUIModule_PixelAlignValue(pWCPercentText.GetHeight() * 0.7, 0)
	fOuterWidth = App.TGUIModule_PixelAlignValue(pPowerCtrl.GetWidth() * 0.1)

	pWCCurve = UIHelpers.CreateCurve(UIHelpers.LOWER_RIGHT_CURVE, fInnerWidth, fInnerWidth + fOuterWidth,
									 fInnerHeight, fInnerHeight + fOuterHeight, App.g_kEngineeringWarpCoreColor, 
									 0.0, UIHelpers.g_kAlternateCurveSet)

	pPowerDisplay.AddChild(pWCCurve, pWCGauge.GetRight() - pWCCurve.GetWidth(),
						   pWCGauge.GetBottom() + App.globals.DEFAULT_ST_INDENT_VERT)

	fInnerHeight = fInnerHeight + fOuterHeight + (2.0 * App.globals.DEFAULT_ST_INDENT_VERT)
	fOuterWidth = fOuterWidth + pWCGauge.GetWidth() + (2.0 * App.globals.DEFAULT_ST_INDENT_HORIZ)
	pMCurve = UIHelpers.CreateCurve(UIHelpers.LOWER_RIGHT_CURVE, fInnerWidth, fInnerWidth + fOuterWidth,
									fInnerHeight, fInnerHeight + fOuterHeight, App.g_kEngineeringMainPowerColor,
									0.0, UIHelpers.g_kAlternateCurveSet)
	pPowerDisplay.AddChild(pMCurve, pMGauge.GetRight() - pMCurve.GetWidth(),
						   pMGauge.GetBottom() + App.globals.DEFAULT_ST_INDENT_VERT)

	fInnerHeight = fInnerHeight + fOuterHeight + (2.0 * App.globals.DEFAULT_ST_INDENT_VERT)
	pPlayer = App.Game_GetCurrentPlayer()
	if (pPlayer.GetTractorBeamSystem() != None):
		# Add space for tractor beam siphon.
		pIconGroup = App.g_kIconManager.GetIconGroup(App.GraphicsModeInfo_GetCurrentMode().GetLcarsString())
		fInnerHeight = fInnerHeight + pIconGroup.GetIconScreenHeight(4308)
	fOuterWidth = fOuterWidth + pMGauge.GetWidth() + (2.0 * App.globals.DEFAULT_ST_INDENT_HORIZ)
	pBCurve = UIHelpers.CreateCurve(UIHelpers.LOWER_RIGHT_CURVE, fInnerWidth, fInnerWidth + fOuterWidth,
									fInnerHeight, fInnerHeight + fOuterHeight, App.g_kEngineeringBackupPowerColor,
									0.0, UIHelpers.g_kAlternateCurveSet)
	pPowerDisplay.AddChild(pBCurve, pBGauge.GetRight() - pBCurve.GetWidth(),
						   pBGauge.GetBottom() + App.globals.DEFAULT_ST_INDENT_VERT)

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pWCText = App.TGParagraph_CreateW(pDatabase.GetString("Warp Core"))
	pWCText.SetColor(App.NiColorA_WHITE)
	pWCText.Layout()
	pMText = App.TGParagraph_CreateW(pDatabase.GetString("Main Battery"))
	pMText.SetColor(App.NiColorA_WHITE)
	pMText.Layout()
	pBText = App.TGParagraph_CreateW(pDatabase.GetString("Reserve Power"))
	pBText.SetColor(App.NiColorA_WHITE)
	pBText.Layout()
	App.g_kLocalizationManager.Unload(pDatabase)

	pPowerDisplay.AddChild(pWCText, pWCCurve.GetLeft() - (2.0 * App.globals.DEFAULT_ST_INDENT_HORIZ) - pWCText.GetWidth(),
						   pWCCurve.GetBottom() - pWCText.GetHeight(), 0)
	pPowerDisplay.AddChild(pMText, pMCurve.GetLeft() - (2.0 * App.globals.DEFAULT_ST_INDENT_HORIZ) - pMText.GetWidth(),
						   pMCurve.GetBottom() - pMText.GetHeight(), 0)
	pPowerDisplay.AddChild(pBText, pBCurve.GetLeft() - (2.0 * App.globals.DEFAULT_ST_INDENT_HORIZ) - pBText.GetWidth(),
						   pBCurve.GetBottom() - pBText.GetHeight(), 0)

	# Move percentage text into the correct place.
	pWCStrip = pWCCurve.GetNthChild(UIHelpers.STRIP_1_ICON)
	pMStrip = pMCurve.GetNthChild(UIHelpers.STRIP_1_ICON)
	pBStrip = pBCurve.GetNthChild(UIHelpers.STRIP_1_ICON)

	pWCPercentText.SetPosition(pWCCurve.GetLeft() + pWCStrip.GetLeft() + ((pWCStrip.GetWidth() / 2.0) - (pWCPercentText.GetWidth() / 2.0)),
							   pWCCurve.GetTop() - App.globals.DEFAULT_ST_INDENT_VERT, 0)
	pMPercentText.SetPosition(pMCurve.GetLeft() + pMStrip.GetLeft() + ((pMStrip.GetWidth() / 2.0) - (pMPercentText.GetWidth() / 2.0)),
							  pMCurve.GetTop() - App.globals.DEFAULT_ST_INDENT_VERT, 0)
	pBPercentText.SetPosition(pBCurve.GetLeft() + pBStrip.GetLeft() + ((pBStrip.GetWidth() / 2.0) - (pBPercentText.GetWidth() / 2.0)),
							  pBCurve.GetTop() - App.globals.DEFAULT_ST_INDENT_VERT, 0)

###############################################################################
#	FixTractorAndCloakText(pPowerDisplay)
#	
#	Aligns the tractor and cloak text, and creates the bars between them and
#	the legend elbows.
#	
#	Args:	pPowerDisplay	- the power display
#	
#	Return:	none
###############################################################################
def FixTractorAndCloakText(pPowerDisplay):
	pMainCurve = pPowerDisplay.GetNthChild(MAIN_GAUGE_CURVE)
	pBackupCurve = pPowerDisplay.GetNthChild(BACKUP_GAUGE_CURVE)
	pMainElbowText = pPowerDisplay.GetNthChild(MAIN_CURVE_TEXT)
	pBackupElbowText = pPowerDisplay.GetNthChild(BACKUP_CURVE_TEXT)
	pBackupElbow = pPowerDisplay.GetNthChild(BACKUP_GAUGE_CURVE)
	pTractorText = pPowerDisplay.GetNthChild(TRACTOR_TEXT)
	pCloakText = pPowerDisplay.GetNthChild(CLOAK_TEXT)
	pMode = App.GraphicsModeInfo_GetCurrentMode()
	pcLCARS = pMode.GetLcarsString()

	pTractorText.SetPosition(pTractorText.GetLeft(), pMainElbowText.GetTop(), 0)
	pCloakText.SetPosition(pCloakText.GetLeft(), pBackupElbowText.GetTop(), 0)

	# Create the tractor and cloak bars.
	pTractorBar = App.TGPane_Create()
	pCloakBar = App.TGPane_Create()

	pTractorBar.SetNoFocus()
	pCloakBar.SetNoFocus()

	pDisabledColor = App.NiColorA()
	pDisabledColor.r = pDisabledColor.g = pDisabledColor.b = 0.25
	pDisabledColor.a = 1.0

	pTractorFlatIcon = App.TGIcon_Create(pcLCARS, 4340, pDisabledColor)
	pTractorCurveIcon = App.TGIcon_Create(pcLCARS, 4308, pDisabledColor)
	pCloakFlatIcon = App.TGIcon_Create(pcLCARS, 4340, pDisabledColor)
	pCloakCurveIcon = App.TGIcon_Create(pcLCARS, 4308, pDisabledColor)

	pTractorBar.AddChild(pTractorFlatIcon, 0.0, 0.0, 0)
	pTractorBar.AddChild(pTractorCurveIcon, 0.0, 0.0, 0)
	pCloakBar.AddChild(pCloakFlatIcon, 0.0, 0.0, 0)
	pCloakBar.AddChild(pCloakCurveIcon, 0.0, 0.0, 0)

	fWidth1 = (pMainCurve.GetLeft() + (pMainCurve.GetWidth() * 0.7)) - pTractorText.GetRight() - (2.0 * App.globals.DEFAULT_ST_INDENT_HORIZ)
	pTractorBar.Resize(fWidth1, pTractorCurveIcon.GetHeight(), 0)
	pTractorFlatIcon.SetPosition(0.0, 0.0, 0)
	pTractorFlatIcon.Resize(fWidth1 - pTractorCurveIcon.GetWidth(), pTractorFlatIcon.GetHeight(), 0)
	pTractorCurveIcon.SetPosition(pTractorFlatIcon.GetRight(), 0.0, 0)
	pTractorBar.SetPosition(pTractorText.GetRight() + (2.0 * App.globals.DEFAULT_ST_INDENT_HORIZ), pMainCurve.GetBottom(), 0)

	fWidth2 = (pBackupCurve.GetLeft() + (pBackupCurve.GetWidth() * 0.7)) - pCloakText.GetRight() - (2.0 * App.globals.DEFAULT_ST_INDENT_HORIZ)
	pCloakBar.Resize(fWidth2, pCloakCurveIcon.GetHeight(), 0)
	pCloakFlatIcon.SetPosition(0.0, 0.0, 0)
	pCloakFlatIcon.Resize(fWidth2 - pCloakCurveIcon.GetWidth(), pCloakFlatIcon.GetHeight(), 0)
	pCloakCurveIcon.SetPosition(pCloakFlatIcon.GetRight(), 0.0, 0)
	pCloakBar.SetPosition(pCloakText.GetRight() + (2.0 * App.globals.DEFAULT_ST_INDENT_HORIZ), pBackupCurve.GetBottom(), 0)

	pPowerDisplay.AddChild(pTractorBar, pTractorText.GetRight() + (2.0 * App.globals.DEFAULT_ST_INDENT_HORIZ), pMainCurve.GetBottom() - (2.0 * pMode.GetPixelHeight()), 0)
	pPowerDisplay.AddChild(pCloakBar, pCloakText.GetRight() + (2.0 * App.globals.DEFAULT_ST_INDENT_HORIZ), pBackupCurve.GetBottom() - (2.0 * pMode.GetPixelHeight()), 0)

	pTractorText.SetPosition(pTractorText.GetLeft(), pTractorBar.GetBottom() - (pTractorText.GetHeight() / 2.0) - (3.0 * pMode.GetPixelHeight()), 0)
	pCloakText.SetPosition(pCloakText.GetLeft(), pCloakBar.GetBottom() - (pCloakText.GetHeight() / 2.0) - (3.0 * pMode.GetPixelHeight()), 0)

	pPlayer = App.Game_GetCurrentPlayer()
	if (pPlayer.GetTractorBeamSystem() == None):
		pTractorText.SetNotVisible(0)
		pTractorBar.SetNotVisible(0)
	if (pPlayer.GetCloakingSubsystem() == None):
		pCloakText.SetNotVisible(0)
		pCloakBar.SetNotVisible(0)

###############################################################################
#	UpdateRulers()
#	
#	Updates the rulers and elbows on the display.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def UpdateRulers():
	pPowerDisplay = App.EngPowerDisplay_Cast(App.TGObject_GetTGObjectPtr(g_idPowerDisplay))
	pPlayer = MissionLib.GetPlayer()
	if (pPowerDisplay == None) or (pPlayer == None):
		return

	pPower = pPlayer.GetPowerSubsystem()
	pMode = App.GraphicsModeInfo_GetCurrentMode()
	if (pPower == None) or (pMode == None):
		return

	pcLCARS = pMode.GetLcarsString()
	LCARS = __import__(pMode.GetLcarsModule())


	pWarpCoreRuler = App.TGFrame_Cast(pPowerDisplay.GetNthChild(WARP_CORE_REGION))
	pMainRuler = App.TGFrame_Cast(pPowerDisplay.GetNthChild(MAIN_REGION))
	pBackupRuler = App.TGFrame_Cast(pPowerDisplay.GetNthChild(BACKUP_REGION))

	kRulerInterior = pWarpCoreRuler.GetInnerRect()
	fNotchThickness = kRulerInterior.GetLeft() - pWarpCoreRuler.GetLeft()

	fPowerGaugeCombinedWidth = pPowerDisplay.GetWidth() - (2.0 * fNotchThickness)
	fCombinedBandwidth = pPower.GetMaxMainConduitCapacity() + pPower.GetBackupConduitCapacity()
	fWarpCorePct = pPower.GetPowerOutput() / fCombinedBandwidth
	fMainPct = pPower.GetMainConduitCapacity() / fCombinedBandwidth
	fBackupPct = pPower.GetBackupConduitCapacity() / fCombinedBandwidth
	fWarpCoreBaseWidth = fWarpCorePct * fPowerGaugeCombinedWidth

	pWarpCoreRuler.Resize(fWarpCorePct * fPowerGaugeCombinedWidth + fNotchThickness, pWarpCoreRuler.GetHeight())
	pMainRuler.Resize((fMainPct - fWarpCorePct) * fPowerGaugeCombinedWidth, pMainRuler.GetHeight())
	pBackupRuler.Resize(fBackupPct * fPowerGaugeCombinedWidth + fNotchThickness, pBackupRuler.GetHeight())

	fPowerGaugeCombinedWidth = pPowerDisplay.GetWidth()

	# Figure out where the rulers should be.
	pBackupRuler.SetPosition(fPowerGaugeCombinedWidth - pBackupRuler.GetWidth(), pBackupRuler.GetTop(), 0)
	pMainRuler.SetPosition(pBackupRuler.GetLeft() - pMainRuler.GetWidth(), pMainRuler.GetTop(), 0)
	pWarpCoreRuler.SetPosition(pMainRuler.GetLeft() - pWarpCoreRuler.GetWidth(), pWarpCoreRuler.GetTop(), 0)

	pPowerDisplay.Layout()

###############################################################################
#	Update(bForce)
#	
#	Updates the power display.
#	
#	Args:	bForce - forces an update even if not visible
#	
#	Return:	none
###############################################################################
def Update(bForce = 0):
	pPowerDisplay = App.EngPowerDisplay_Cast(App.TGObject_GetTGObjectPtr(g_idPowerDisplay))
	if (pPowerDisplay == None):
		return
	if (pPowerDisplay.IsCompletelyVisible() == 0) and not bForce:
		return

	pPlayer = App.Game_GetCurrentPlayer()
	if (pPlayer == None):
		return

	pWarpCoreRuler = App.TGFrame_Cast(pPowerDisplay.GetNthChild(WARP_CORE_REGION))
	if not pWarpCoreRuler:
		return

	kRulerInterior = pWarpCoreRuler.GetInnerRect()
	fNotchThickness = kRulerInterior.GetLeft() - pWarpCoreRuler.GetLeft()
	fBarWidth = App.TGUIModule_PixelAlignValue(pPowerDisplay.GetWidth() - (fNotchThickness * 2.0))

	pShip = MissionLib.GetPlayer()
	if (pShip == None):
		return
	pPower = pShip.GetPowerSubsystem()
	if (pPower == None):
		return
	fMaxBandwidth = pPower.GetMaxMainConduitCapacity() + pPower.GetBackupConduitCapacity()

	# Get the icons for these things.
	pUsedPane = App.TGPane_Cast(pPowerDisplay.GetNthChild(POWER_USED_BAR))
	if (pUsedPane == None):
		return

	pImpulse = pShip.GetImpulseEngineSubsystem()
	pWarp = pShip.GetWarpEngineSubsystem()
	pShields = pShip.GetShields()
	pPhasers = pShip.GetPhaserSystem()
	pTorps = pShip.GetTorpedoSystem()
	pDisruptors = pShip.GetPulseWeaponSystem()
	pSensors = pShip.GetSensorSubsystem()

	AdjustPower([pImpulse, pWarp, pShields, pPhasers, pTorps, pDisruptors, pSensors])

	fTotalPower = 0.0
	if (pImpulse != None):
		fTotalPower = fTotalPower + pImpulse.GetPowerPercentageWanted() * pImpulse.GetNormalPowerWanted()
	if (pWarp != None):
		fTotalPower = fTotalPower + pWarp.GetPowerPercentageWanted() * pImpulse.GetNormalPowerWanted()
	if (pShields != None):
		fTotalPower = fTotalPower + pShields.GetPowerPercentageWanted() * pShields.GetNormalPowerWanted()
	if (pPhasers != None):
		fTotalPower = fTotalPower + pPhasers.GetPowerPercentageWanted() * pPhasers.GetNormalPowerWanted()
	if (pTorps != None):
		fTotalPower = fTotalPower + pTorps.GetPowerPercentageWanted() * pTorps.GetNormalPowerWanted()
	if (pDisruptors != None):
		fTotalPower = fTotalPower + pDisruptors.GetPowerPercentageWanted() * pDisruptors.GetNormalPowerWanted()
	if (pSensors != None):
		fTotalPower = fTotalPower + pSensors.GetPowerPercentageWanted() * pSensors.GetNormalPowerWanted()

	pEnginesIcon = App.TGIcon_Cast(pUsedPane.GetNthChild(ENGINES))
	pShieldsIcon = App.TGIcon_Cast(pUsedPane.GetNthChild(SHIELDS))
	pWeaponsIcon = App.TGIcon_Cast(pUsedPane.GetNthChild(WEAPONS))
	pSensorsIcon = App.TGIcon_Cast(pUsedPane.GetNthChild(SENSORS))
	pLastIcon = None

	if ((pImpulse != None) and (pImpulse.IsOn() == 1)):
		pEnginesIcon.SetVisible(0)
		fEnginePower = pImpulse.GetPowerPercentageWanted() * pImpulse.GetNormalPowerWanted()

		if (pWarp != None):
			fEnginePower = fEnginePower + (pWarp.GetPowerPercentageWanted() * pWarp.GetNormalPowerWanted())

		pEnginesIcon.Resize(fBarWidth * (fEnginePower / fMaxBandwidth), g_fPowerUsedBarHeight, 0)
		pEnginesIcon.SetPosition(0.0, 0.0, 0)
		pLastIcon = pEnginesIcon
	elif ((pWarp != None) and (pWarp.IsOn() == 1)):
		pEnginesIcon.SetVisible(0)
		# Impulse does not exist or isn't drawing power, so we don't need to check it.
		fEnginePower = pWarp.GetPowerPercentageWanted() * pWarp.GetNormalPowerWanted()
		
		pEnginesIcon.Resize(fBarWidth * (fEnginePower / fMaxBandwidth), g_fPowerUsedBarHeight, 0)
		pEnginesIcon.SetPosition(0.0, 0.0, 0)
		pLastIcon = pEnginesIcon
	else:
		pEnginesIcon.SetNotVisible(0)

	if ((pShields != None) and (pShields.IsOn() == 1)):
		pShieldsIcon.SetVisible(0)
		pShieldsIcon.Resize(fBarWidth * (pShields.GetPowerPercentageWanted() * pShields.GetNormalPowerWanted() / fMaxBandwidth), g_fPowerUsedBarHeight, 0)

		if (pLastIcon != None):
			pShieldsIcon.SetPosition(pLastIcon.GetRight(), 0.0, 0)
		else:
			pShieldsIcon.SetPosition(0.0, 0.0, 0)
		pLastIcon = pShieldsIcon
	else:
		pShieldsIcon.SetNotVisible(0)

	# Weapons are trickier.
	if ((pPhasers != None) or (pTorps != None) or (pDisruptors != None)):
		fTotalWeaponsPower = 0.0

		if (pPhasers != None):
			fTotalWeaponsPower = fTotalWeaponsPower + pPhasers.GetPowerPercentageWanted() * pPhasers.GetNormalPowerWanted()
		if (pTorps != None):
			fTotalWeaponsPower = fTotalWeaponsPower + pTorps.GetPowerPercentageWanted() * pTorps.GetNormalPowerWanted()
		if (pDisruptors != None):
			fTotalWeaponsPower = fTotalWeaponsPower + pDisruptors.GetPowerPercentageWanted() * pDisruptors.GetNormalPowerWanted()

		pWeaponsIcon.SetVisible(0)
		pWeaponsIcon.Resize(fBarWidth * (fTotalWeaponsPower / fMaxBandwidth), g_fPowerUsedBarHeight, 0)

		if (pLastIcon != None):
			pWeaponsIcon.SetPosition(pLastIcon.GetRight(), 0.0, 0)
		else:
			pWeaponsIcon.SetPosition(0.0, 0.0, 0)
		pLastIcon = pWeaponsIcon
	else:
		pWeaponsIcon.SetNotVisible(0)
	
	if ((pSensors != None) and (pSensors.IsOn() == 1)):
		pSensorsIcon.SetVisible(0)
		pSensorsIcon.Resize(fBarWidth * (pSensors.GetPowerPercentageWanted() * pSensors.GetNormalPowerWanted() / fMaxBandwidth), g_fPowerUsedBarHeight, 0)

		if (pLastIcon != None):
			pSensorsIcon.SetPosition(pLastIcon.GetRight(), 0.0, 0)
		else:
			pSensorsIcon.SetPosition(0.0, 0.0, 0)
		pLastIcon = pSensorsIcon
	else:
		pSensorsIcon.SetNotVisible(0)

	UpdateRulers()

	# Move the "power used" bar so that it's aligned with the left-most ruler.
	pBackupRuler = App.TGFrame_Cast(pPowerDisplay.GetNthChild(BACKUP_REGION))
	pPowerUsedMarks = App.STTiledIcon_Cast(pPowerDisplay.GetNthChild(POWER_USED_MARKS))
	kRulerInterior = pWarpCoreRuler.GetInnerRect()
	fNotchThickness = kRulerInterior.GetLeft() - pWarpCoreRuler.GetLeft()
	pMode = App.GraphicsModeInfo_GetCurrentMode()
	pUsedPane.SetPosition(pWarpCoreRuler.GetLeft() + fNotchThickness, pUsedPane.GetTop(), 0)
	pUsedPane.Resize(pBackupRuler.GetRight() - pWarpCoreRuler.GetLeft() - (2.0 * fNotchThickness), pUsedPane.GetHeight(), 0)
	pPowerUsedMarks.SetPosition(pUsedPane.GetLeft(), pUsedPane.GetTop(), 0)
	pPowerUsedMarks.Resize(pUsedPane.GetWidth(), pUsedPane.GetHeight(), 0)

	# Update the percentage texts.
	pWCPercentage = App.TGParagraph_Cast(pPowerDisplay.GetNthChild(WARP_CORE_PERCENTAGE))
	pMPercentage = App.TGParagraph_Cast(pPowerDisplay.GetNthChild(MAIN_PERCENTAGE))
	pBPercentage = App.TGParagraph_Cast(pPowerDisplay.GetNthChild(BACKUP_PERCENTAGE))

	pPowerProp = pPower.GetProperty()

	pWCPercentage.SetString(str(int(pPower.GetConditionPercentage() * 100.0)) + "%")
	pMPercentage.SetString(str(int(pPower.GetMainBatteryPower() / pPowerProp.GetMainBatteryLimit() * 100.0)) + "%")
	pBPercentage.SetString(str(int(pPower.GetBackupBatteryPower() / pPowerProp.GetBackupBatteryLimit() * 100.0)) + "%")

	pPowerDisplay.Layout()

###############################################################################
#	AdjustPower(lSystems)
#	
#	Adjusts the power of the systems if the total power used is over the
#	ship's maximum.
#	
#	Args:	lSystems	- systems to adjust
#	
#	Return:	none
###############################################################################
def AdjustPower(lSystems):
	# Build a dictionary of the systems, along with the percentage of the total
	# amount of power they take.
	dPower = {}
	fNormTotalPower = 0.0
	fTotalPower = 0.0
	pPlayer = App.Game_GetCurrentPlayer()
	pCtrl = App.EngPowerCtrl_GetPowerCtrl()

	if not pPlayer:
		#debug("AdjustPower(): no player")
		return

	pPower = pPlayer.GetPowerSubsystem()
	if not pPower:
		#debug("AdjustPower(): no power")
		return

	for pSystem in lSystems:
		if pSystem:
			pBar = pCtrl.GetBarForSubsystem(pSystem)
			if pBar:
				dPower[pSystem] = pSystem.GetNormalPowerWanted()
				fNormTotalPower = fNormTotalPower + dPower[pSystem]

			fTotalPower = fTotalPower + (pSystem.GetNormalPowerWanted() * pSystem.GetPowerPercentageWanted())

	if fNormTotalPower == 0.0:
		#debug("AdjustPower(): no normal total power")
		return

	for pSystem in lSystems:
		if pSystem:
			if dPower.has_key(pSystem):
				dPower[pSystem] = dPower[pSystem] / fNormTotalPower

	# If the total amount of power wanted is greater than the amount of power
	# that is available, then we need to reduce the power percentage of each
	# of the systems in proportion to the amount of power each one takes.
	fPowerDeficit = fTotalPower - (pPower.GetMainConduitCapacity() + pPower.GetBackupConduitCapacity())
	#debug("AdjustPower(): power deficit = " + str(fPowerDeficit))
	if fPowerDeficit > (fTotalPower * 0.01):
		# There is a power deficit. Now, go through the systems, and adjust their
		# power percentage accordingly.
		for pSystem in lSystems:
			pBar = pCtrl.GetBarForSubsystem(pSystem)
			if (not pSystem) or (not pBar):
				continue

			#debug("% of system " + pSystem.GetName() + ": " + str(dPower[pSystem]))
			fPowerReduction = dPower[pSystem] * fPowerDeficit
			fNewPower = max((pSystem.GetNormalPowerWanted() * pSystem.GetNormalPowerPercentage()) - fPowerReduction, 0.0)

			if pSystem.GetNormalPowerWanted() > 0.0:
				# Never go below 20%, or the desired setting.
				pSystem.SetPowerPercentageWanted(max(fNewPower / pSystem.GetNormalPowerWanted(), min(0.2, pSystem.GetPowerPercentageWanted())))

		# Ensure that weapons are set to the highest percentage value. Same for engines.
		pPhasers = pPlayer.GetPhaserSystem()
		pTorps = pPlayer.GetTorpedoSystem()
		pDisruptors = pPlayer.GetPulseWeaponSystem()
		pStandard = None
		if pPhasers:
			pStandard = pPhasers
		elif pTorps:
			pStandard = pTorps
		elif pDisruptors:
			pStandard = pDisruptors

		if pStandard:
			if pTorps:
				pTorps.SetPowerPercentageWanted(pStandard.GetPowerPercentageWanted())
			if pDisruptors:
				pDisruptors.SetPowerPercentageWanted(pStandard.GetPowerPercentageWanted())

		pImpulse = pPlayer.GetImpulseEngineSubsystem()
		pWarp = pPlayer.GetWarpEngineSubsystem()

		if pImpulse and pWarp:
			pWarp.SetPowerPercentageWanted(pImpulse.GetPowerPercentageWanted())
			

###############################################################################
#	HandleSetPlayer(pPowerDisplay, pEvent)
#	
#	Event handler for when the player is changed.
#	
#	Args:	pPowerDisplay	- the power display
#			pEvent			- the event
#	
#	Return:	none
###############################################################################
def HandleSetPlayer(pPowerDisplay, pEvent):
	Init(pPowerDisplay)

###############################################################################
#	RefreshTimer(dTimeLeft)
#	
#	Timer refresh for the power display.
#	
#	Args:	dTimeLeft	- ?
#	
#	Return:	none
###############################################################################
def RefreshTimer(dTimeLeft):
	kProfiling = App.TGProfilingInfo("PowerDisplay.RefreshTimer")
	Update()

###############################################################################
#	HandleDeleteDisplay(pPowerDisplay, pEvent)
#	
#	Handles the delete event for the power display.
#	
#	Args:	pPowerDisplay	- the power display
#			pEvent			- the delete event
#	
#	Return:	none
###############################################################################
def HandleDeleteDisplay(pPowerDisplay, pEvent):
	RemoveEventHandlers()
	g_idPowerDisplay = None
	pPowerDisplay.CallNextHandler(pEvent)

###############################################################################
#	HandleTractor(pPowerDisplay, pEvent)
#	
#	Event handler for when the tractor beam starts/stops firing. Used to 
#	change the text that appears for the tractor beam in the power display.
#	
#	Args:	pPowerDisplay	- the power display
#			pEvent			- the event
#	
#	Return:	none
###############################################################################
def HandleTractor(pPowerDisplay, pEvent):
	pTractorText = App.TGParagraph_Cast(pPowerDisplay.GetNthChild(TRACTOR_TEXT))

	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	if (pShip == None):
		return

	pTractors = pShip.GetTractorBeamSystem()
	if (pTractors == None):
		return

	bFiring = 0
	for i in range(pTractors.GetNumChildSubsystems()):
		pTractor = pTractors.GetWeapon(i)
		if (pTractor.IsFiring()):
			bFiring = 1
			break

	pTractorBar = App.TGPane_Cast(pPowerDisplay.GetNthChild(TRACTOR_BAR))
	pTractorFlatIcon = App.TGIcon_Cast(pTractorBar.GetFirstChild())
	pTractorCurveIcon = App.TGIcon_Cast(pTractorBar.GetLastChild())

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	if (bFiring == 1):
		pTractorText.SetStringW(pDatabase.GetString("Tractor: On"))
		pTractorFlatIcon.SetColor(App.globals.g_kEngineeringMainPowerColor)
		pTractorCurveIcon.SetColor(App.globals.g_kEngineeringMainPowerColor)
	else:
		kColor = App.NiColorA()
		kColor.r = kColor.g = kColor.b = 0.25
		kColor.a = 1.0

		pTractorText.SetStringW(pDatabase.GetString("Tractor: Off"))
		pTractorFlatIcon.SetColor(kColor)
		pTractorCurveIcon.SetColor(kColor)

	App.g_kLocalizationManager.Unload(pDatabase)

###############################################################################
#	HandleCloak(pPowerDisplay, pEvent)
#	
#	Event handler for when the cloaking subsystem is turned on/off. Used to
#	change the text that appears for the cloaking subsystem in the power
#	display.
#	
#	Args:	pPowerDisplay	- the power display
#			pEvent			- the event
#	
#	Return:	none
###############################################################################
def HandleCloak(pPowerDisplay, pEvent):
	pCloakText = App.TGParagraph_Cast(pPowerDisplay.GetNthChild(CLOAK_TEXT))

	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	if (pShip == None):
		return

	pCloak = pShip.GetCloakingSubsystem()
	if (pCloak == None):
		return

	pCloakBar = App.TGPane_Cast(pPowerDisplay.GetNthChild(CLOAK_BAR))
	pCloakFlatIcon = App.TGIcon_Cast(pCloakBar.GetFirstChild())
	pCloakCurveIcon = App.TGIcon_Cast(pCloakBar.GetLastChild())

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	if (pCloak.IsOn()):
		pCloakText.SetStringW(pDatabase.GetString("Cloak: On"))
		pCloakFlatIcon.SetColor(App.globals.g_kEngineeringBackupPowerColor)
		pCloakCurveIcon.SetColor(App.globals.g_kEngineeringBackupPowerColor)
	else:
		kColor = App.NiColorA()
		kColor.r = kColor.g = kColor.b = 0.25
		kColor.a = 1.0

		pCloakText.SetStringW(pDatabase.GetString("Cloak: Off"))
		pCloakFlatIcon.SetColor(kColor)
		pCloakCurveIcon.SetColor(kColor)

	App.g_kLocalizationManager.Unload(pDatabase)
